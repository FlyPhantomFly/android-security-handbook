#!/usr/bin/env python3
# =============================================================================
#  find-dynamic-loading.py  —  Chapter 11, Android Runtime
# =============================================================================
#
#  WHAT THIS DOES
#  --------------
#  Static scanner. Given an APK, it looks for the fingerprints of DYNAMIC CODE
#  LOADING and of the runtime escape hatches that surround it:
#
#      DexClassLoader / InMemoryDexClassLoader / DelegateLastClassLoader /
#      PathClassLoader / DexFile, ClassLoader.loadClass, Class.forName,
#      getDeclaredMethod, Method.invoke, Runtime.exec, ProcessBuilder,
#      System.load / System.loadLibrary, VMRuntime.setHiddenApiExemptions,
#      reflection on BaseDexClassLoader.pathList / DexPathList.dexElements,
#      AssetManager.addAssetPath,
#
#  plus payload staging evidence inside the APK itself: secondary .dex files,
#  .jar/.apk/.zip files hiding in assets/, and bundled native libraries.
#
#  It then prints a grouped report ranked by severity, so you know where to
#  point JADX first.
#
#  It works in two modes and picks automatically:
#
#    APKTOOL MODE  (preferred)  If `apktool` is on PATH, the APK is unpacked and
#                  every .smali file is scanned line by line. You get exact
#                  file:line locations you can open immediately.
#
#    RAW DEX MODE  (fallback)   If apktool is missing, fails, or you pass
#                  --no-apktool, the script opens the APK as a ZIP with the
#                  standard library, pulls out every classes*.dex, parses the
#                  DEX string table and matches the indicators against it. You
#                  lose line numbers but you still get a reliable inventory,
#                  with no third-party dependency at all.
#
#  HOW TO RUN IT
#  -------------
#      # host shell
#      python3 find-dynamic-loading.py target.apk
#
#      # skip apktool even if it is installed (fast, no temp files)
#      python3 find-dynamic-loading.py --no-apktool target.apk
#
#      # keep the unpacked tree so you can grep it yourself afterwards
#      python3 find-dynamic-loading.py --keep target.apk
#
#      # show more example hits per indicator (default 5)
#      python3 find-dynamic-loading.py --examples 20 target.apk
#
#      # machine-readable output for a pipeline
#      python3 find-dynamic-loading.py --json target.apk > findings.json
#
#      # exit non-zero when anything HIGH is present (for CI)
#      python3 find-dynamic-loading.py --fail-on-high target.apk
#
#  PREREQUISITES
#  -------------
#   - Python 3.7 or newer. Standard library only.
#   - apktool is OPTIONAL. Install it for file:line precision:
#         https://apktool.org/  (then make sure `apktool` runs from your shell)
#
#  WHAT THE OUTPUT MEANS - AND WHAT IT DOES NOT
#  ---------------------------------------------
#  Every indicator here is DUAL USE. Reflection, loadClass and even
#  DexClassLoader appear in enormous amounts of completely benign code: the
#  legacy multidex support library, dependency-injection frameworks, plugin
#  systems, A/B testing SDKs and Google Play's own libraries all use them. A hit
#  is a QUESTION, not a verdict. The questions worth asking, in order:
#
#    1. Where do the bytes being loaded come from - the APK's own assets, the
#       network, external storage, or an IPC caller?
#    2. Is the payload authenticated before it is loaded, with a key that ships
#       inside the APK?
#    3. Can any other app or any attacker influence the path or the bytes?
#
#  If the answer to 3 is yes, you have arbitrary code execution in the app's UID
#  and the finding writes itself. If the payload is a signed blob from the app's
#  own assets, it is usually just a packer or a plugin framework, and your next
#  job is to dump the second stage at runtime - see
#  ../examples/hook-classloaders.js in this chapter.
#
#  This script deliberately does NOT try to decide for you. It finds the seams.
# =============================================================================

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from collections import OrderedDict

# ---------------------------------------------------------------------------
#  Indicator table
#
#  Each entry carries:
#    key       stable identifier used in --json output
#    title     human-readable name
#    severity  HIGH / MEDIUM / LOW
#    category  grouping for the report
#    smali     regex matched against each line of disassembled smali
#    dex       literal string matched against the DEX string table; None means
#              "not reliably detectable in raw mode" (usually because the string
#              alone would be far too generic)
#    why       one or two sentences explaining what it means and why it matters
# ---------------------------------------------------------------------------
INDICATORS = [
    # ---------------- class loading -------------------------------------
    {
        "key": "inmemory_dex_classloader",
        "title": "InMemoryDexClassLoader",
        "severity": "HIGH",
        "category": "Dynamic class loading",
        "smali": r"Ldalvik/system/InMemoryDexClassLoader;",
        "dex": "Ldalvik/system/InMemoryDexClassLoader;",
        "why": "Loads DEX straight from a ByteBuffer - the code never touches the "
               "filesystem, so nothing on disk represents it and no static tool can "
               "see it. API 26+. This is the signature of a modern packer. Dump the "
               "payload by hooking the constructor at runtime.",
    },
    {
        "key": "dex_classloader",
        "title": "DexClassLoader",
        "severity": "HIGH",
        "category": "Dynamic class loading",
        "smali": r"Ldalvik/system/DexClassLoader;",
        "dex": "Ldalvik/system/DexClassLoader;",
        "why": "Loads DEX/JAR/APK from a file path. Trace where that path comes "
               "from: a world-writable or attacker-influenced path means arbitrary "
               "code execution inside the app's UID.",
    },
    {
        "key": "dex_file",
        "title": "dalvik.system.DexFile",
        "severity": "HIGH",
        "category": "Dynamic class loading",
        "smali": r"Ldalvik/system/DexFile;",
        "dex": "Ldalvik/system/DexFile;",
        "why": "The low-level DEX handle underneath every loader. Direct use "
               "(loadDex, openDexFile, entries) usually means the app is doing "
               "something more deliberate than ordinary class loading.",
    },
    {
        "key": "delegate_last_classloader",
        "title": "DelegateLastClassLoader",
        "severity": "MEDIUM",
        "category": "Dynamic class loading",
        "smali": r"Ldalvik/system/DelegateLastClassLoader;",
        "dex": "Ldalvik/system/DelegateLastClassLoader;",
        "why": "Inverts parent delegation: this loader searches itself FIRST. A "
               "class it carries can shadow one of the app's own classes. API 27+.",
    },
    {
        "key": "path_classloader",
        "title": "PathClassLoader",
        "severity": "MEDIUM",
        "category": "Dynamic class loading",
        "smali": r"Ldalvik/system/PathClassLoader;",
        "dex": "Ldalvik/system/PathClassLoader;",
        "why": "The standard app loader. Every app has one already, so a reference "
               "in app code means the app is CREATING an extra one, or reflecting "
               "on the existing one.",
    },
    {
        "key": "base_dex_classloader",
        "title": "BaseDexClassLoader",
        "severity": "MEDIUM",
        "category": "Dynamic class loading",
        "smali": r"Ldalvik/system/BaseDexClassLoader;",
        "dex": "Ldalvik/system/BaseDexClassLoader;",
        "why": "The common superclass holding the DexPathList. Referenced by name "
               "when code reflects into loader internals.",
    },
    {
        "key": "load_class",
        "title": "ClassLoader.loadClass()",
        "severity": "MEDIUM",
        "category": "Dynamic class loading",
        "smali": r"->loadClass\(Ljava/lang/String;",
        "dex": "loadClass",
        "why": "Resolving a class by name at runtime. Harmless on its own; the "
               "interesting case is a name that is decrypted or downloaded rather "
               "than a literal.",
    },

    # ---------------- loader internals / hijacking ----------------------
    {
        "key": "path_list_field",
        "title": "reflection on BaseDexClassLoader.pathList",
        "severity": "HIGH",
        "category": "ClassLoader internals",
        "smali": r'"pathList"',
        "dex": "pathList",
        "why": "The private field holding the DexPathList. Code that names this "
               "string is reflecting into loader internals - the technique behind "
               "DEX injection, hot-patching frameworks and multidex hijacking.",
    },
    {
        "key": "dex_elements_field",
        "title": "reflection on DexPathList.dexElements",
        "severity": "HIGH",
        "category": "ClassLoader internals",
        "smali": r'"dexElements"',
        "dex": "dexElements",
        "why": "The ordered array searched during class lookup. Prepending an entry "
               "makes your DEX win over the app's own classes. Naming this field is "
               "a very strong signal of deliberate loader manipulation.",
    },
    {
        "key": "make_dex_elements",
        "title": "DexPathList.makeDexElements / makePathElements",
        "severity": "HIGH",
        "category": "ClassLoader internals",
        "smali": r"make(Dex|Path)Elements",
        "dex": "makeDexElements",
        "why": "The private factory used to build new dexElements entries. Called "
               "reflectively by every framework that injects a DEX into a live "
               "loader.",
    },
    {
        "key": "add_asset_path",
        "title": "AssetManager.addAssetPath",
        "severity": "MEDIUM",
        "category": "ClassLoader internals",
        "smali": r"->addAssetPath\(",
        "dex": "addAssetPath",
        "why": "Adds a resource package at runtime, the resource-side counterpart "
               "of DEX injection. Plugin frameworks pair it with a new loader.",
    },

    # ---------------- reflection ----------------------------------------
    {
        "key": "class_for_name",
        "title": "Class.forName()",
        "severity": "MEDIUM",
        "category": "Reflection",
        "smali": r"Ljava/lang/Class;->forName\(",
        "dex": "forName",
        "why": "Name-based class lookup. Ubiquitous and mostly benign, but it is "
               "how code reaches classes that are not linked at compile time - "
               "including hidden platform classes.",
    },
    {
        "key": "get_declared_method",
        "title": "Class.getDeclaredMethod / getMethod",
        "severity": "MEDIUM",
        "category": "Reflection",
        "smali": r"->get(Declared)?Method\(",
        "dex": "getDeclaredMethod",
        "why": "Name-based method lookup, the step before Method.invoke. Also the "
               "operation that hidden API enforcement gates on API 28+.",
    },
    {
        "key": "method_invoke",
        "title": "Method.invoke()",
        "severity": "MEDIUM",
        "category": "Reflection",
        "smali": r"Ljava/lang/reflect/Method;->invoke\(",
        "dex": "Ljava/lang/reflect/Method;",
        "why": "The actual reflective call. Paired with loadClass it marks the "
               "boundary where control leaves the code you can read.",
    },
    {
        "key": "set_accessible",
        "title": "AccessibleObject.setAccessible(true)",
        "severity": "LOW",
        "category": "Reflection",
        "smali": r"->setAccessible\(Z\)",
        "dex": "setAccessible",
        "why": "Disables the language-level access check so private members can be "
               "touched. Very common; interesting only in context.",
    },

    # ---------------- hidden API ----------------------------------------
    {
        "key": "hidden_api_exemptions",
        "title": "VMRuntime.setHiddenApiExemptions",
        "severity": "HIGH",
        "category": "Hidden API enforcement",
        "smali": r"setHiddenApiExemptions",
        "dex": "setHiddenApiExemptions",
        "why": "Turns off hidden API enforcement for the whole process. The app is "
               "deliberately reaching non-SDK platform internals. Not a "
               "vulnerability by itself - find out WHAT it reaches.",
    },
    {
        "key": "vmruntime",
        "title": "dalvik.system.VMRuntime",
        "severity": "MEDIUM",
        "category": "Hidden API enforcement",
        "smali": r"Ldalvik/system/VMRuntime;",
        "dex": "Ldalvik/system/VMRuntime;",
        "why": "Hidden runtime control surface (exemptions, heap tuning, "
               "target SDK version). Its presence means the app reflects into ART "
               "itself.",
    },
    {
        "key": "system_properties",
        "title": "android.os.SystemProperties",
        "severity": "LOW",
        "category": "Hidden API enforcement",
        "smali": r"Landroid/os/SystemProperties;",
        "dex": "Landroid/os/SystemProperties;",
        "why": "A hidden platform class reached by reflection to read ro.* "
               "properties, typically for root/emulator detection.",
    },

    # ---------------- native process execution --------------------------
    {
        "key": "runtime_exec",
        "title": "Runtime.exec()",
        "severity": "HIGH",
        "category": "Process execution",
        "smali": r"Ljava/lang/Runtime;->exec\(",
        "dex": "Ljava/lang/Runtime;",
        "why": "Spawns a child process. If any part of the command string is "
               "attacker-influenced and a shell is involved, this is command "
               "injection. The child runs as the app's UID.",
    },
    {
        "key": "process_builder",
        "title": "ProcessBuilder",
        "severity": "MEDIUM",
        "category": "Process execution",
        "smali": r"Ljava/lang/ProcessBuilder;",
        "dex": "Ljava/lang/ProcessBuilder;",
        "why": "The other door to fork/exec. Safe when given an argv array with no "
               "shell; exactly as injectable as Runtime.exec when given sh -c.",
    },
    {
        "key": "shell_binary",
        "title": "literal reference to a shell binary",
        "severity": "HIGH",
        "category": "Process execution",
        "smali": r'"/system/bin/sh"|"/system/xbin/sh"|"sh -c"|"/bin/sh"',
        "dex": "/system/bin/sh",
        "why": "A shell is being invoked. Every metacharacter in the command string "
               "becomes an operator, so any interpolated value is an injection "
               "point.",
    },
    {
        "key": "su_binary",
        "title": "literal reference to su",
        "severity": "LOW",
        "category": "Process execution",
        "smali": r'"/system/bin/su"|"/system/xbin/su"|"which su"|"su"',
        "dex": "/system/xbin/su",
        "why": "Root detection by attempting to run su. Trivially hooked and "
               "unreliable; report it as an ineffective control, not as a "
               "vulnerability.",
    },

    # ---------------- native code ---------------------------------------
    {
        "key": "system_loadlibrary",
        "title": "System.loadLibrary()",
        "severity": "MEDIUM",
        "category": "Native code",
        "smali": r"Ljava/lang/System;->loadLibrary\(",
        "dex": "loadLibrary",
        "why": "Loads a bundled .so. Native code is not subject to hidden API "
               "enforcement and can manipulate ART directly, so it is where the "
               "serious packers and the serious anti-tamper logic live.",
    },
    {
        "key": "system_load",
        "title": "System.load() with an absolute path",
        "severity": "HIGH",
        "category": "Native code",
        "smali": r"Ljava/lang/System;->load\(Ljava/lang/String;\)",
        "dex": None,   # the bare string "load" is far too generic in raw mode
        "why": "Loads a native library from an arbitrary path rather than from the "
               "APK's lib/ directory. If that path is attacker-influenceable this "
               "is native code execution.",
    },
]

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


# ---------------------------------------------------------------------------
#  Colour handling. Kept trivially simple: enabled only for a TTY, and always
#  disableable, because half of these reports get piped into a file.
# ---------------------------------------------------------------------------
class Colour:
    def __init__(self, enabled):
        self.enabled = enabled

    def _wrap(self, code, text):
        if not self.enabled:
            return text
        return "\033[" + code + "m" + text + "\033[0m"

    def high(self, t):
        return self._wrap("1;31", t)

    def medium(self, t):
        return self._wrap("1;33", t)

    def low(self, t):
        return self._wrap("36", t)

    def bold(self, t):
        return self._wrap("1", t)

    def dim(self, t):
        return self._wrap("2", t)

    def by_severity(self, sev, text):
        if sev == "HIGH":
            return self.high(text)
        if sev == "MEDIUM":
            return self.medium(text)
        return self.low(text)


# ---------------------------------------------------------------------------
#  DEX string-table parsing
#
#  We only need the string pool, so this stays tiny. The full container format
#  is chapter 12's subject; the four numbers used here are:
#
#      offset 0x00  magic          8 bytes, "dex\n" + version + NUL
#      offset 0x28  endian_tag     0x12345678 little-endian on every real DEX
#      offset 0x38  string_ids_size   uint32, number of strings
#      offset 0x3C  string_ids_off    uint32, file offset of the id array
#
#  Each string_id is a uint32 offset to a string_data_item, which is a ULEB128
#  length (in UTF-16 code units, which we ignore) followed by MUTF-8 bytes
#  terminated by a NUL. Reading to the NUL and decoding as UTF-8 with
#  replacement is accurate enough for indicator matching; MUTF-8 differs from
#  UTF-8 only for NUL and for supplementary characters, neither of which appear
#  in the identifiers we look for.
# ---------------------------------------------------------------------------
DEX_MAGIC = b"dex\n"


def read_uleb128(data, offset):
    """Return (value, new_offset). ULEB128: 7 bits per byte, high bit = continue."""
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated ULEB128")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            break
        shift += 7
        if shift > 35:
            raise ValueError("ULEB128 too long")
    return result, offset


def parse_dex_strings(data):
    """Extract the string pool from DEX bytes.

    Returns a list of str. Raises ValueError if this does not look like a DEX,
    so the caller can fall back to a raw byte scan.
    """
    if len(data) < 0x70 or data[0:4] != DEX_MAGIC:
        raise ValueError("not a DEX file (bad magic)")

    endian_tag = struct.unpack_from("<I", data, 0x28)[0]
    if endian_tag != 0x12345678:
        # Big-endian DEX is legal in the spec and has never been seen in the
        # wild on Android. Refuse rather than silently misparse.
        raise ValueError("unsupported endianness 0x%08x" % endian_tag)

    string_ids_size = struct.unpack_from("<I", data, 0x38)[0]
    string_ids_off = struct.unpack_from("<I", data, 0x3C)[0]

    if string_ids_off + 4 * string_ids_size > len(data):
        raise ValueError("string_ids table out of bounds")

    strings = []
    for i in range(string_ids_size):
        item_off = struct.unpack_from("<I", data, string_ids_off + 4 * i)[0]
        if item_off >= len(data):
            continue
        try:
            _utf16_len, data_off = read_uleb128(data, item_off)
        except ValueError:
            continue
        end = data.find(b"\x00", data_off)
        if end < 0:
            end = len(data)
        strings.append(data[data_off:end].decode("utf-8", errors="replace"))
    return strings


# ---------------------------------------------------------------------------
#  Finding accumulation
# ---------------------------------------------------------------------------
class Findings:
    def __init__(self):
        # key -> {"indicator": dict, "count": int, "examples": [str, ...]}
        self.by_key = OrderedDict()
        self.notes = []

    def add(self, indicator, example, max_examples):
        entry = self.by_key.get(indicator["key"])
        if entry is None:
            entry = {"indicator": indicator, "count": 0, "examples": []}
            self.by_key[indicator["key"]] = entry
        entry["count"] += 1
        if example is not None and len(entry["examples"]) < max_examples:
            entry["examples"].append(example)

    def note(self, severity, category, title, detail):
        self.notes.append({
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
        })

    def count_severity(self, severity):
        n = 0
        for entry in self.by_key.values():
            if entry["indicator"]["severity"] == severity:
                n += 1
        for note in self.notes:
            if note["severity"] == severity:
                n += 1
        return n


# ---------------------------------------------------------------------------
#  Mode 1 - apktool
# ---------------------------------------------------------------------------
def run_apktool(apktool_bin, apk_path, out_dir):
    """Unpack the APK. Returns True on success."""
    cmd = [apktool_bin, "d", "-f", "-o", out_dir, apk_path]
    sys.stderr.write("[*] running: %s\n" % " ".join(cmd))
    try:
        proc = subprocess.run(cmd,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,
                              timeout=900)
    except FileNotFoundError:
        sys.stderr.write("[!] apktool not found\n")
        return False
    except subprocess.TimeoutExpired:
        sys.stderr.write("[!] apktool timed out after 900s\n")
        return False
    if proc.returncode != 0:
        sys.stderr.write("[!] apktool failed (exit %d):\n%s\n"
                         % (proc.returncode,
                            proc.stdout.decode("utf-8", errors="replace")[-2000:]))
        return False
    return True


def scan_smali_tree(root, findings, max_examples):
    """Walk every .smali file and match each indicator regex line by line."""
    compiled = []
    for ind in INDICATORS:
        compiled.append((ind, re.compile(ind["smali"])))

    files_scanned = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if not name.endswith(".smali"):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            files_scanned += 1
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        # Cheap pre-filter: smali lines that matter are almost
                        # always invoke-*, const-string or a field reference.
                        # Running 20-odd regexes over every blank line and
                        # comment is what makes naive scanners slow.
                        stripped = line.strip()
                        if not stripped or stripped.startswith("#"):
                            continue
                        for ind, rx in compiled:
                            if rx.search(stripped):
                                findings.add(
                                    ind,
                                    "%s:%d: %s" % (rel, lineno, stripped[:160]),
                                    max_examples)
            except OSError as exc:
                sys.stderr.write("[!] could not read %s: %s\n" % (rel, exc))
    return files_scanned


# ---------------------------------------------------------------------------
#  Mode 2 - raw DEX inside the ZIP
# ---------------------------------------------------------------------------
def scan_raw_dex(apk_path, findings, max_examples):
    """Scan every classes*.dex in the APK without unpacking anything."""
    dex_names = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        for info in zf.infolist():
            if info.filename.endswith(".dex"):
                dex_names.append(info.filename)

        if not dex_names:
            sys.stderr.write("[!] no .dex entries found in the APK\n")
            return 0

        for dex_name in dex_names:
            data = zf.read(dex_name)
            sys.stderr.write("[*] scanning %s (%d bytes)\n" % (dex_name, len(data)))

            try:
                strings = parse_dex_strings(data)
                mode = "string table (%d strings)" % len(strings)
                haystack = None
            except ValueError as exc:
                # Encrypted, packed, or a non-standard container. Fall back to a
                # raw byte search: the identifiers are stored as plain ASCII, so
                # a substring search still finds them whenever they are present
                # in cleartext anywhere in the file.
                sys.stderr.write("[!] %s: %s - falling back to a raw byte scan\n"
                                 % (dex_name, exc))
                strings = None
                haystack = data
                mode = "raw byte scan"
                findings.note(
                    "MEDIUM", "Container",
                    "%s is not a parseable DEX" % dex_name,
                    "The header did not validate (%s). That happens with "
                    "encrypted or custom-packed payloads - which is itself "
                    "worth investigating. Falling back to a raw byte scan, so "
                    "results for this file may be incomplete." % exc)

            for ind in INDICATORS:
                pattern = ind["dex"]
                if pattern is None:
                    continue
                if strings is not None:
                    hits = [s for s in strings if pattern in s]
                    for hit in hits:
                        findings.add(ind, "%s: string %r" % (dex_name, hit[:160]),
                                     max_examples)
                else:
                    needle = pattern.encode("utf-8")
                    start = 0
                    while True:
                        idx = haystack.find(needle, start)
                        if idx < 0:
                            break
                        findings.add(ind,
                                     "%s: byte offset 0x%x" % (dex_name, idx),
                                     max_examples)
                        start = idx + len(needle)
            sys.stderr.write("[*] %s: matched via %s\n" % (dex_name, mode))
    return len(dex_names)


# ---------------------------------------------------------------------------
#  Payload staging evidence in the ZIP itself
#
#  Independent of any bytecode analysis: what EXTRA code-bearing files are
#  shipped inside the APK? A second-stage DEX sitting in assets/ is often the
#  fastest possible win - you can extract and decompile it in ten seconds.
# ---------------------------------------------------------------------------
def scan_container(apk_path, findings):
    with zipfile.ZipFile(apk_path, "r") as zf:
        infos = zf.infolist()

    dex_entries = []
    staged = []
    natives = []

    for info in infos:
        name = info.filename
        lower = name.lower()
        if lower.endswith(".dex"):
            dex_entries.append(name)
        if lower.endswith((".jar", ".apk", ".zip")) or (
                lower.endswith(".bin") and "assets/" in lower):
            staged.append("%s (%d bytes)" % (name, info.file_size))
        if lower.endswith(".so"):
            natives.append(name)

    # classes.dex, classes2.dex, ... are the normal multidex names. Anything
    # else with a .dex extension is a payload the app intends to load itself.
    normal = re.compile(r"^classes\d*\.dex$")
    extra_dex = [d for d in dex_entries if not normal.match(d)]

    if extra_dex:
        findings.note(
            "HIGH", "Payload staging",
            "%d non-standard .dex file(s) inside the APK" % len(extra_dex),
            "These are not part of the multidex set the runtime loads "
            "automatically, so the app must load them itself:\n    "
            + "\n    ".join(extra_dex)
            + "\n  Extract and decompile them directly:\n"
            "    unzip -o target.apk '" + extra_dex[0] + "' -d extracted/\n"
            "    jadx -d out extracted/" + extra_dex[0])

    if staged:
        findings.note(
            "MEDIUM", "Payload staging",
            "%d archive/blob file(s) bundled as assets" % len(staged),
            "A .jar/.apk/.zip inside an APK is frequently a second stage that "
            "gets copied to the files directory and loaded:\n    "
            + "\n    ".join(staged[:20])
            + ("\n    ... and %d more" % (len(staged) - 20) if len(staged) > 20 else ""))

    if natives:
        findings.note(
            "LOW", "Native code",
            "%d native library file(s)" % len(natives),
            "Native code is outside hidden API enforcement and can drive ART "
            "directly, so a packer's real logic often lives here:\n    "
            + "\n    ".join(sorted(set(natives))[:20])
            + ("\n    ... and more" if len(natives) > 20 else ""))

    findings.note(
        "LOW", "Container",
        "%d DEX file(s) in the APK" % len(dex_entries),
        ", ".join(dex_entries) if dex_entries else "(none)")


# ---------------------------------------------------------------------------
#  Reporting
# ---------------------------------------------------------------------------
def print_report(apk_path, findings, mode, colour, max_examples):
    c = colour
    print("")
    print(c.bold("=" * 75))
    print(c.bold("  Dynamic code loading scan"))
    print(c.bold("=" * 75))
    print("  target : %s" % apk_path)
    print("  size   : %d bytes" % os.path.getsize(apk_path))
    print("  mode   : %s" % mode)
    print("")

    hi = findings.count_severity("HIGH")
    med = findings.count_severity("MEDIUM")
    low = findings.count_severity("LOW")
    print("  %s  %s  %s" % (c.high("HIGH: %d" % hi),
                            c.medium("MEDIUM: %d" % med),
                            c.low("LOW: %d" % low)))

    if hi == 0 and med == 0:
        print("")
        print("  No dynamic-loading indicators found. Two honest caveats:")
        print("   - a packed app can hide the loader in native code, where this")
        print("     scanner cannot see it. Check the .so inventory below and")
        print("     confirm at runtime with ../examples/hook-classloaders.js;")
        print("   - class and method names can be built at runtime from")
        print("     encrypted strings, which defeats every static string match.")

    # Group by category, ordered by the worst severity in each category.
    categories = OrderedDict()
    for entry in findings.by_key.values():
        cat = entry["indicator"]["category"]
        categories.setdefault(cat, []).append(entry)
    for note in findings.notes:
        categories.setdefault(note["category"], [])

    def category_rank(name):
        best = 3
        for entry in categories.get(name, []):
            best = min(best, SEVERITY_ORDER[entry["indicator"]["severity"]])
        for note in findings.notes:
            if note["category"] == name:
                best = min(best, SEVERITY_ORDER[note["severity"]])
        return best

    for cat in sorted(categories.keys(), key=category_rank):
        print("")
        print(c.bold("-" * 75))
        print(c.bold("  " + cat))
        print(c.bold("-" * 75))

        entries = sorted(categories[cat],
                         key=lambda e: (SEVERITY_ORDER[e["indicator"]["severity"]],
                                        -e["count"]))
        for entry in entries:
            ind = entry["indicator"]
            print("")
            print("  [%s] %s   (%d hit%s)"
                  % (c.by_severity(ind["severity"], ind["severity"]),
                     c.bold(ind["title"]),
                     entry["count"],
                     "" if entry["count"] == 1 else "s"))
            for wrapped in wrap(ind["why"], 68):
                print("        " + wrapped)
            if entry["examples"]:
                print("        " + c.dim("examples:"))
                for ex in entry["examples"]:
                    print("          " + c.dim(ex))
                if entry["count"] > len(entry["examples"]):
                    print("          " + c.dim("... %d more (raise --examples)"
                                               % (entry["count"] - len(entry["examples"]))))

        for note in findings.notes:
            if note["category"] != cat:
                continue
            print("")
            print("  [%s] %s"
                  % (c.by_severity(note["severity"], note["severity"]),
                     c.bold(note["title"])))
            for para in note["detail"].split("\n"):
                print("        " + para)

    print("")
    print(c.bold("-" * 75))
    print("  next steps")
    print(c.bold("-" * 75))
    print("   1. For each HIGH hit, open the location in JADX and answer:")
    print("      where do the loaded bytes come from, and can anyone else")
    print("      influence them?")
    print("   2. Confirm dynamically - static analysis cannot see a payload")
    print("      that is decrypted at runtime:")
    print("        frida -U -f <pkg> -l ../examples/hook-classloaders.js")
    print("   3. Check the compilation state and the process model:")
    print("        ./dexopt-inspect.sh <pkg>")
    print("        frida -U -f <pkg> -l ./runtime-recon.js")
    print("")


def wrap(text, width):
    """Tiny greedy word-wrap. Avoids importing textwrap for one call and keeps
    the output width predictable in a terminal."""
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def to_json(apk_path, findings, mode):
    out = {
        "target": apk_path,
        "size": os.path.getsize(apk_path),
        "mode": mode,
        "findings": [],
        "notes": findings.notes,
        "summary": {
            "high": findings.count_severity("HIGH"),
            "medium": findings.count_severity("MEDIUM"),
            "low": findings.count_severity("LOW"),
        },
    }
    for entry in findings.by_key.values():
        ind = entry["indicator"]
        out["findings"].append({
            "key": ind["key"],
            "title": ind["title"],
            "severity": ind["severity"],
            "category": ind["category"],
            "why": ind["why"],
            "count": entry["count"],
            "examples": entry["examples"],
        })
    return json.dumps(out, indent=2)


# ---------------------------------------------------------------------------
#  main
# ---------------------------------------------------------------------------
def main(argv):
    parser = argparse.ArgumentParser(
        description="Find dynamic code loading indicators in an APK.",
        epilog="Every indicator is dual use. A hit is a question, not a verdict.")
    parser.add_argument("apk", help="path to the .apk (or .dex) to scan")
    parser.add_argument("--no-apktool", action="store_true",
                        help="skip apktool and scan the raw DEX only")
    parser.add_argument("--apktool", default="apktool",
                        help="apktool executable to use (default: apktool)")
    parser.add_argument("--keep", action="store_true",
                        help="keep the unpacked apktool output and print its path")
    parser.add_argument("--examples", type=int, default=5,
                        help="max example hits shown per indicator (default 5)")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of the human report")
    parser.add_argument("--no-colour", "--no-color", dest="no_colour",
                        action="store_true", help="disable ANSI colour")
    parser.add_argument("--fail-on-high", action="store_true",
                        help="exit 2 when at least one HIGH indicator is present")
    args = parser.parse_args(argv)

    apk_path = args.apk
    if not os.path.isfile(apk_path):
        sys.stderr.write("[!] no such file: %s\n" % apk_path)
        return 1

    colour = Colour(enabled=(not args.no_colour) and sys.stdout.isatty()
                    and not args.json)
    findings = Findings()

    is_zip = zipfile.is_zipfile(apk_path)

    # Container inventory first - it is cheap and works on any APK.
    if is_zip:
        scan_container(apk_path, findings)
    else:
        findings.note("LOW", "Container", "input is not a ZIP",
                      "Treating the file as a bare DEX image.")

    mode = None
    apktool_dir = None

    # ---- try apktool unless told not to -----------------------------------
    if not args.no_apktool and is_zip:
        apktool_bin = shutil.which(args.apktool)
        if apktool_bin is None:
            sys.stderr.write("[*] apktool not on PATH - using the raw DEX scanner\n")
        else:
            apktool_dir = tempfile.mkdtemp(prefix="fdl-apktool-")
            target = os.path.join(apktool_dir, "unpacked")
            if run_apktool(apktool_bin, apk_path, target):
                n = scan_smali_tree(target, findings, args.examples)
                mode = "apktool + smali (%d .smali files)" % n
                if args.keep:
                    sys.stderr.write("[*] unpacked tree kept at: %s\n" % target)
                else:
                    shutil.rmtree(apktool_dir, ignore_errors=True)
                    apktool_dir = None
            else:
                sys.stderr.write("[*] falling back to the raw DEX scanner\n")
                shutil.rmtree(apktool_dir, ignore_errors=True)
                apktool_dir = None

    # ---- raw DEX fallback / primary ---------------------------------------
    if mode is None:
        if is_zip:
            n = scan_raw_dex(apk_path, findings, args.examples)
            mode = "raw DEX string scan (%d dex file(s))" % n
        else:
            with open(apk_path, "rb") as fh:
                data = fh.read()
            try:
                strings = parse_dex_strings(data)
            except ValueError as exc:
                sys.stderr.write("[!] %s\n" % exc)
                return 1
            for ind in INDICATORS:
                if ind["dex"] is None:
                    continue
                for s in strings:
                    if ind["dex"] in s:
                        findings.add(ind, "string %r" % s[:160], args.examples)
            mode = "raw DEX string scan (single file, %d strings)" % len(strings)

    if args.json:
        print(to_json(apk_path, findings, mode))
    else:
        print_report(apk_path, findings, mode, colour, args.examples)

    if args.fail_on_high and findings.count_severity("HIGH") > 0:
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        sys.exit(130)
