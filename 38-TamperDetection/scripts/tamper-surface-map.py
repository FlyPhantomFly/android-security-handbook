#!/usr/bin/env python3
# scripts/tamper-surface-map.py
#
# PURPOSE
#   Report which tamper-detection and anti-analysis controls an APK appears to
#   implement, and -- the part that actually saves you time -- AT WHICH TIER
#   each one runs. Run it BEFORE you attempt any bypass.
#
#   The tier is the whole point. "This app has anti-Frida" tells you nothing
#   useful. "This app has anti-Frida strings in classes.dex AND in an ELF
#   constructor in libfoo.so" tells you that a Java hook installed at
#   Java.perform time is already too late, and that you need to be attached
#   before the linker runs the constructor. That single fact is the difference
#   between a twenty-minute job and a wasted afternoon.
#
#   The five tiers this script assigns, earliest-running first:
#
#     T0  CONTAINER    Signing schemes present, zip-level anomalies. Not a
#                      runtime check at all: it constrains what a repackager
#                      must do, which is what makes every other tier meaningful.
#     T3  NATIVE-EARLY .init_array constructors in a shared object. These run
#                      inside dlopen(), BEFORE JNI_OnLoad and before any Java
#                      code in the app. See 17-Libraries for the mechanism.
#     T2  NATIVE-JNI   JNI_OnLoad and exported Java_* functions. Runs at
#                      System.loadLibrary() time, before the calling Java class
#                      finishes its static initialiser.
#     T1  JAVA         Checks implemented in DEX. The cheapest tier to defeat
#                      and by far the most common.
#     T4  REMOTE       Play Integrity / attestation / a server round trip. The
#                      only tier whose decision is not made on hardware the
#                      attacker owns.
#
# USAGE
#   # host -- one APK
#   python3 -B tamper-surface-map.py app.apk
#
#   # host -- several, or a directory of them
#   python3 -B tamper-surface-map.py /path/to/apks/*.apk
#   python3 -B tamper-surface-map.py /path/to/apks/
#
#   # host -- machine-readable, for diffing two versions of the same app
#   python3 -B tamper-surface-map.py --json app.apk > surface.json
#
#   # host -- show every matched string, not just the summary
#   python3 -B tamper-surface-map.py --verbose app.apk
#
#   Pull an APK off a device first with:
#     adb shell pm path <package>
#     adb pull /data/app/.../base.apk
#
#   Always invoke Python with -B. This script does not import anything
#   dynamically, but the repository rule is -B everywhere so that no
#   __pycache__ directory is ever created next to a script.
#
# REQUIREMENTS
#   Python 3.8+. Standard library only -- zipfile, struct, re, json, argparse.
#   No androguard, no apktool, no aapt2, no network. That is deliberate: this
#   script must run on a locked-down analysis box and must never modify the APK.
#
# WHAT THIS WILL *NOT* TELL YOU
#   * It will NOT tell you the app performs a check. It tells you the app
#     CONTAINS THE INGREDIENTS of a check. A string "/proc/self/status" in a
#     DEX may be a crash reporter reading memory statistics. Treat every row as
#     a LEAD, not a finding -- the same discipline chapters 33, 36 and 52
#     measured the hard way.
#   * It will NOT find a check whose strings are encrypted, computed, or split.
#     A single obfuscated app can produce a completely empty report while
#     implementing every control in the catalogue. An EMPTY REPORT IS NOT
#     EVIDENCE OF ABSENCE, and section 8.6 of the chapter README explains how to
#     tell an honestly-empty app from a hidden one.
#   * It will NOT tell you which check fired at runtime. Nothing static can.
#     That is scripts/which-check-fired.js's job, and you should run it second.
#   * It will NOT parse AndroidManifest.xml. Binary AXML parsing lives in
#     10-APK-Internals; for the debuggable flag use that chapter's parser or
#     `aapt2 dump xmltree`. This script deliberately does not duplicate it.
#   * It will NOT detect ROOT detection. That is chapter 37's subject and it has
#     its own tooling. Where a root-ish string is unavoidable, the row is
#     labelled CH37 so you know to look there instead.
#   * It will NOT bypass anything. It never writes to the APK and never touches
#     a device.
#
# AUTHORISED TESTING ONLY. Mapping an APK you were not asked to assess is still
# reverse engineering someone else's software.

import argparse
import json
import os
import re
import struct
import sys
import zipfile

# --------------------------------------------------------------------------- #
# The catalogue.
# --------------------------------------------------------------------------- #

# Each entry is:
#     (control-id, human name, confidence, what a hit ACTUALLY proves, [patterns])
#
# CONFIDENCE is the field that makes this script worth running twice, and it was
# added because the first version of it lied. Run against an 18-APK corpus, the
# self-signature row matched 18 of 18 apps -- including a 0.3 MB stub whose only
# hit was the string "getPackageInfo", which every analytics SDK on earth calls
# to read its own versionName. A checker that flags everything flags nothing.
#
#   STRONG  the pattern has essentially one reason to be present.
#           GET_SIGNING_CERTIFICATES is not called by accident.
#   WEAK    the pattern is an INGREDIENT. It is consistent with the control and
#           consistent with a dozen innocent uses. Never report a WEAK row as a
#           finding; use it to decide where to look next.
#
# Patterns are matched case-insensitively against extracted strings. Several are
# anchored with ^...$ deliberately: an unanchored "frida" matches a package
# called "fridayplanner", and an unanchored "getPackageInfo" matches a Kotlin
# lambda class name such as CoreFeature$getPackageInfo$2, which was a real
# false positive in the corpus.

DEX_SIGNALS = [
    ("SIG-SELF", "self-signature verification", "STRONG",
     "the app reads its own signing certificate at runtime; it can compare it "
     "against a baseline, which is the strongest local anti-repackaging control "
     "there is",
     [r"GET_SIGNING_CERTIFICATES", r"getApkContentsSigners",
      r"getSigningCertificateHistory", r"hasSigningCertificate",
      r"Landroid/content/pm/SigningInfo;"]),

    ("SIG-INGREDIENT", "PackageInfo/Signature use", "WEAK",
     "the app touches the signature APIs at all. Measured: this row matched 18 "
     "of 18 apps in the corpus this script was built against, because "
     "getPackageInfo is how every SDK reads its own versionName. It is a "
     "pointer, not a finding",
     [r"^getPackageInfo$", r"^Landroid/content/pm/Signature;$",
      r"^\[Landroid/content/pm/Signature;$"]),

    ("SIG-PEER", "peer-app signature verification", "STRONG",
     "the app checks ANOTHER package's certificate, usually to trust a sibling "
     "app or an IPC caller; this is an authorisation control, not an "
     "anti-tamper one",
     [r"checkSignatures", r"CERT_INPUT_RAW_X509", r"CERT_INPUT_SHA256"]),

    ("INT-DEX", "APK / DEX self-hashing", "STRONG",
     "the app locates its own APK on disk, which is the first move of anyone "
     "intending to digest it; against a re-signer this adds nothing beyond "
     "SIG-SELF, but it does catch a zip-level patch of a v1-only APK",
     [r"getPackageCodePath", r"publicSourceDir", r"^sourceDir$",
      r"^classes\.dex$"]),

    ("INT-INGREDIENT", "zip/CRC machinery", "WEAK",
     "the app can read zips and compute CRCs. So can every app that opens a "
     "downloaded file",
     [r"java/util/zip/ZipFile", r"^CRC32$", r"^getCrc$"]),

    ("DBG-FLAG", "debuggable flag self-check", "STRONG",
     "the app reads FLAG_DEBUGGABLE on ITSELF; a repackager who added the "
     "debuggable attribute to the manifest trips it, but a device with "
     "ro.debuggable=1 does not",
     [r"FLAG_DEBUGGABLE"]),

    ("DBG-JDWP", "Java debugger attach check", "STRONG",
     "the app asks ART whether a JDWP debugger is connected; this is a "
     "DIFFERENT question from TracerPid and catches Android Studio, which "
     "TracerPid provably does not -- see README 3.8",
     [r"isDebuggerConnected", r"waitingForDebugger", r"waitForDebugger"]),

    ("DBG-TRACER", "TracerPid check", "STRONG",
     "the app reads /proc/self/status looking for a ptrace attach; proves only "
     "that somebody is ptracing RIGHT NOW",
     [r"/proc/self/status", r"/proc/%d/status", r"TracerPid"]),

    ("ANA-MAPS", "address-space scan", "STRONG",
     "the app reads its own memory map looking for injected libraries; more "
     "expensive to evade than a port scan, still a two-line hook",
     [r"/proc/self/maps", r"/proc/%d/maps", r"/proc/self/task",
      r"/proc/self/mem"]),

    ("ANA-FRIDA", "Frida-specific artefact hunting", "STRONG",
     "the app looks for Frida's default port, pipe names or thread names; every "
     "one of these costs the attacker a command-line flag, not an afternoon",
     [r"^27042$", r"^27043$", r"^27047$", r"gum-js-loop", r"linjector",
      r"frida-agent", r"frida-gadget", r"re\.frida", r"LIBFRIDA",
      r"/data/local/tmp/frida", r"^frida$", r"frida-server"]),

    ("ANA-HOOK", "hooking-framework detection", "STRONG",
     "the app looks for Xposed/LSPosed/Substrate artefacts; distinct from Frida "
     "detection because these leave class-loader and stack-trace evidence "
     "rather than sockets",
     [r"de/robv/android/xposed", r"XposedBridge", r"XposedHelpers",
      r"LSPosed", r"EdXposed", r"com/saurik/substrate"]),

    ("INS-SOURCE", "installer / install-source check", "STRONG",
     "the app asks which package installed it; anti-fraud telemetry, not a "
     "security control -- pm install -i sets it to anything",
     [r"getInstallerPackageName", r"getInstallSourceInfo",
      r"getInitiatingPackageName"]),

    ("INS-INGREDIENT", "Play package name present", "WEAK",
     "the string com.android.vending appears. So does it in every app that "
     "links a Play billing or install-referrer library",
     [r"com\.android\.vending"]),

    ("ATT-REMOTE", "remote attestation", "STRONG",
     "the app requests a signed device-integrity verdict; the ONLY tier whose "
     "decision can be made off the device -- but only if the verdict is "
     "verified server-side, which this script cannot see",
     [r"IntegrityManager", r"requestIntegrityToken", r"StandardIntegrityManager",
      r"IntegrityTokenRequest", r"SafetyNetApi",
      r"com/google/android/play/core/integrity"]),

    ("ATT-KEY", "hardware key attestation", "STRONG",
     "the app generates a Keystore key with an attestation challenge; the "
     "certificate chain proves boot state to a SERVER, see 49-KeyStore",
     [r"setAttestationChallenge", r"1\.3\.6\.1\.4\.1\.11129\.2\.1\.17"]),

    ("ATT-INGREDIENT", "Keystore use", "WEAK",
     "AndroidKeyStore is used. Overwhelmingly this is ordinary key storage, "
     "not attestation. See 49-KeyStore",
     [r"^AndroidKeyStore$", r"KeyGenParameterSpec"]),

    ("ENV-ROOT", "root detection (chapter 37 owns this)", "STRONG",
     "reported here only so you know the app bundles root checks with its "
     "integrity checks -- go to 37-RootDetection for the catalogue and bypass",
     [r"/system/bin/su", r"/system/xbin/su", r"rootbeer", r"magisk",
      r"^test-keys$", r"busybox", r"eu/chainfire/libsuperuser"]),

    ("ENV-EMU", "emulator detection (chapter 39 owns this)", "STRONG",
     "reported for the same reason as ENV-ROOT; the detectors travel together",
     [r"goldfish", r"ranchu", r"generic_x86", r"vbox86", r"qemu\.hw",
      r"Genymotion"]),
]

# ELF symbol names, split into imports (what the library CALLS) and exports
# (what it OFFERS). The distinction matters enormously: an imported ptrace is a
# library that ptraces something; an exported JNI_OnLoad is a library with a
# guaranteed entry point that runs at load time. This is why the script parses
# the ELF instead of running `strings` over it -- "the word ptrace appears in
# this file" and "this library imports ptrace" are different claims, and only
# the second is worth acting on.
ELF_IMPORT_SIGNALS = [
    ("NAT-PTRACE", "ptrace self-attach or child-trace", "STRONG",
     "PTRACE_TRACEME makes the process its own tracer so nothing else can "
     "attach; a forked watchdog that ptraces the parent achieves the same and "
     "survives a hook on ptrace() in the parent",
     [r"^ptrace$"]),
    ("NAT-FORK", "watchdog process", "WEAK",
     "fork/waitpid in an anti-analysis library usually means a second process "
     "is watching the first -- but these are also the most ordinary libc calls "
     "there are. Confirm before believing",
     [r"^fork$", r"^vfork$", r"^waitpid$", r"^wait4$", r"^getppid$"]),
    ("NAT-PROC", "procfs reads from native code", "WEAK",
     "the native tier can read /proc directly, in which case a Java-level hook "
     "sees nothing. But fopen and openat are in every library ever written; "
     "pair this with NAT-TRACER or NAT-MAPS before believing it",
     [r"^fopen$", r"^openat$", r"^opendir$", r"^readdir$", r"^faccessat$"]),
    ("NAT-SYSCALL", "raw syscall use", "WEAK",
     "syscall() bypasses the libc wrapper you were planning to hook -- but it "
     "is also how half of libc's own helpers are written",
     [r"^syscall$"]),
    ("NAT-SELFMAP", "self-inspection of loaded modules", "WEAK",
     "dl_iterate_phdr and dladdr enumerate loaded objects from inside the "
     "process without touching /proc, so a /proc hook misses them. They are "
     "also how every stack unwinder and crash reporter works",
     [r"^dl_iterate_phdr$", r"^dladdr$"]),
    ("NAT-CRYPTO", "in-library digesting", "WEAK",
     "a hash function in an anti-tamper library is sometimes hashing the "
     "library's own .text or the APK. It is far more often just doing "
     "cryptography",
     [r"^SHA256_Init$", r"^SHA1_Init$", r"^MD5_Init$", r"^CC_SHA256$"]),
    ("NAT-MPROTECT", "page-permission manipulation", "WEAK",
     "mprotect in an anti-tamper library is either self-modifying code, an "
     "unpacking stub, or a check that its own .text is still read-only. It is "
     "also how every JIT and every garbage collector works",
     [r"^mprotect$"]),
    ("NAT-SIG", "signal-based anti-debug", "WEAK",
     "installing a SIGTRAP/SIGSEGV handler and deliberately faulting is a "
     "classic debugger trap: a debugger swallows the signal, so the handler NOT "
     "running is the detection. Also what every crash reporter does",
     [r"^sigaction$", r"^sigprocmask$", r"^raise$"]),
]

ELF_EXPORT_SIGNALS = [
    ("NAT-JNIONLOAD", "JNI_OnLoad present", "STRONG",
     "guaranteed to run at System.loadLibrary() time, before the loading "
     "class's static initialiser completes -- the earliest tier reachable "
     "without an ELF constructor",
     [r"^JNI_OnLoad$"]),
    ("NAT-JNIFUNC", "exported JNI functions", "WEAK",
     "the Java to native boundary. Present in every JNI library; listed because "
     "these names survive R8 (the runtime resolves them by name), which makes "
     "them the best hook anchors in an obfuscated app",
     [r"^Java_"]),
]

ELF_STRING_SIGNALS = [
    ("NAT-TRACER", "TracerPid string in native code", "STRONG",
     "the TracerPid check reimplemented below the Java layer, where a "
     "Java.perform hook cannot reach it",
     [r"/proc/self/status", r"TracerPid"]),
    ("NAT-MAPS", "maps string in native code", "STRONG",
     "address-space scanning below the Java layer",
     [r"/proc/self/maps", r"/proc/self/task", r"/proc/self/mem"]),
    ("NAT-FRIDA", "Frida artefacts in native code", "STRONG",
     "anti-Frida in the native tier; usually inside JNI_OnLoad or a "
     "constructor. Note that Frida's own gadget, if bundled, matches this too "
     "-- check WHICH library the hit came from",
     [r"frida-agent", r"frida-gadget", r"gum-js-loop", r"re\.frida",
      r"linjector", r"LIBFRIDA"]),
    ("NAT-APKPATH", "APK path handling in native code", "WEAK",
     "a native library that knows where the APK is may intend to hash it, or to "
     "read its signing block itself rather than trust PackageManager. It may "
     "equally just be loading an asset",
     [r"/data/app/", r"base\.apk", r"AndroidManifest\.xml", r"META-INF/"]),
]

TIER_ORDER = ["T0-CONTAINER", "T3-NATIVE-EARLY", "T2-NATIVE-JNI", "T1-JAVA", "T4-REMOTE"]

TIER_NOTE = {
    "T0-CONTAINER":
        "not a runtime check; it constrains what a repackager must do",
    "T3-NATIVE-EARLY":
        "runs inside dlopen(), before JNI_OnLoad and before any app Java code. "
        "You must be attached before System.loadLibrary() to see it at all",
    "T2-NATIVE-JNI":
        "runs at System.loadLibrary() time. Spawn-and-hold; attaching later is "
        "too late",
    "T1-JAVA":
        "runs whenever the app calls it. Cheapest tier to defeat",
    "T4-REMOTE":
        "the decision may be made off-device. Test the SERVER, not the check",
}


# --------------------------------------------------------------------------- #
# DEX string extraction
#
# We parse the string_ids table properly rather than running `strings` over the
# file. It costs forty lines and buys precision: every item we return really is
# a string the DEX declares, so a match is a match rather than a coincidence in
# the middle of a bytecode array.
#
# Layout (see 12-DEX-Internals for the full header):
#   0x00  magic "dex\n0??\0"
#   0x38  string_ids_size   (u32)
#   0x3C  string_ids_off    (u32)
# Each string_id_item is a u32 offset to a string_data_item:
#   ULEB128 utf16_size, then MUTF-8 bytes, then a 0x00 terminator.
# --------------------------------------------------------------------------- #

def _uleb128(buf, off):
    """Decode an unsigned LEB128. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while True:
        if off >= len(buf):
            raise ValueError("truncated uleb128")
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7
        if shift > 28:
            raise ValueError("oversized uleb128")


def dex_strings(data):
    """Yield every string declared in a DEX file. Tolerant of damage."""
    if len(data) < 0x70 or data[:4] != b"dex\n":
        return
    try:
        n_str, off_str = struct.unpack_from("<II", data, 0x38)
    except struct.error:
        return
    # A malformed or hostile header can claim an absurd count. Cap it against
    # the file size rather than trusting the field -- a packer that inflates
    # string_ids_size is a known anti-analysis trick.
    if off_str + 4 * n_str > len(data):
        n_str = max(0, (len(data) - off_str) // 4)
    for i in range(n_str):
        try:
            (data_off,) = struct.unpack_from("<I", data, off_str + 4 * i)
            if data_off >= len(data):
                continue
            _, p = _uleb128(data, data_off)
            end = data.find(b"\x00", p)
            if end < 0:
                continue
            raw = data[p:end]
        except (struct.error, ValueError):
            continue
        # MUTF-8 is close enough to UTF-8 for pattern matching; surrogate pairs
        # and the two-byte NUL are the only differences and neither affects a
        # substring search. Decode leniently rather than dropping the string.
        yield raw.decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# Minimal ELF reader
#
# We want three things and nothing else: the dynamic symbol table split into
# imports and exports, whether .init_array exists and how many entries it has,
# and the printable strings. Parsing rather than `strings`-ing matters here:
# "ptrace appears somewhere in the file" and "this library imports ptrace" are
# very different claims, and only the second is worth acting on.
# --------------------------------------------------------------------------- #

SHT_DYNSYM = 11
SHT_SYMTAB = 2


class Elf(object):
    def __init__(self, data):
        self.ok = False
        self.imports = []
        self.exports = []
        self.init_array_entries = 0
        self.has_init_array = False
        self.machine = None
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return
        self.data = data
        self.is64 = data[4] == 2
        little = data[5] == 1
        self.end = "<" if little else ">"
        try:
            self._parse()
            self.ok = True
        except (struct.error, ValueError, IndexError):
            # A deliberately corrupted section header table is itself an
            # anti-analysis signal; report what we got rather than crashing.
            self.ok = False

    def _parse(self):
        d, e = self.data, self.end
        if self.is64:
            (self.machine,) = struct.unpack_from(e + "H", d, 0x12)
            e_shoff, = struct.unpack_from(e + "Q", d, 0x28)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(e + "HHH", d, 0x3A)
            shdr_fmt, name_o, type_o, off_o, size_o, link_o, entsz_o = \
                e + "IIQQQQIIQQ", 0, 1, 4, 5, 6, 9
        else:
            (self.machine,) = struct.unpack_from(e + "H", d, 0x12)
            e_shoff, = struct.unpack_from(e + "I", d, 0x20)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(e + "HHH", d, 0x2E)
            shdr_fmt, name_o, type_o, off_o, size_o, link_o, entsz_o = \
                e + "IIIIIIIIII", 0, 1, 4, 5, 6, 9

        sections = []
        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            if base + e_shentsize > len(d):
                break
            f = struct.unpack_from(shdr_fmt, d, base)
            sections.append({
                "name_off": f[name_o], "type": f[type_o], "off": f[off_o],
                "size": f[size_o], "link": f[link_o], "entsize": f[entsz_o],
            })

        # Section names
        names = {}
        if 0 <= e_shstrndx < len(sections):
            st = sections[e_shstrndx]
            blob = d[st["off"]:st["off"] + st["size"]]
            for idx, s in enumerate(sections):
                end = blob.find(b"\x00", s["name_off"])
                names[idx] = blob[s["name_off"]:end].decode("ascii", "replace") \
                    if end >= 0 else ""

        for idx, s in enumerate(sections):
            nm = names.get(idx, "")
            if nm in (".init_array", ".preinit_array"):
                self.has_init_array = True
                ptr = 8 if self.is64 else 4
                if s["size"] and ptr:
                    self.init_array_entries += s["size"] // ptr

            if s["type"] in (SHT_DYNSYM, SHT_SYMTAB):
                strtab = sections[s["link"]] if 0 <= s["link"] < len(sections) else None
                if not strtab:
                    continue
                sblob = d[strtab["off"]:strtab["off"] + strtab["size"]]
                symsz = 24 if self.is64 else 16
                count = s["size"] // symsz if symsz else 0
                for k in range(count):
                    b = s["off"] + k * symsz
                    if b + symsz > len(d):
                        break
                    if self.is64:
                        st_name, _info, _other, st_shndx = \
                            struct.unpack_from(e + "IBBH", d, b)
                    else:
                        st_name, = struct.unpack_from(e + "I", d, b)
                        st_shndx, = struct.unpack_from(e + "H", d, b + 14)
                    end = sblob.find(b"\x00", st_name)
                    if end < 0:
                        continue
                    name = sblob[st_name:end].decode("ascii", "replace")
                    if not name:
                        continue
                    # st_shndx == SHN_UNDEF (0) means the symbol is referenced
                    # but not defined here: an import.
                    (self.imports if st_shndx == 0 else self.exports).append(name)

        self.imports = sorted(set(self.imports))
        self.exports = sorted(set(self.exports))


PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def elf_strings(data, limit=200000):
    """Printable ASCII runs. Capped so a 40 MB library does not stall the run."""
    out = []
    for m in PRINTABLE.finditer(data):
        out.append(m.group().decode("ascii", "replace"))
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------- #
# Signing block
#
# The APK Signing Block lives between the last local file entry and the central
# directory, and is NOT a zip entry -- which is why rewriting a zip silently
# discards it. Layout and ID meanings are chapter 10's subject; we look up the
# magic and read the ID-value pair IDs only.
# --------------------------------------------------------------------------- #

APK_SIG_MAGIC = b"APK Sig Block 42"

BLOCK_IDS = {
    0x7109871A: "v2 (APK Signature Scheme v2)",
    0xF05368C0: "v3 (v3, key rotation)",
    0x1B93AD61: "v3.1 (rotation gated to newer platforms)",
    0x42726577: "verity padding",
    0x2146444E: "SourceStamp",
    0x6DFF800D: "dependency info (Play)",
}


def signing_block_ids(path):
    """Return (list of human names, raw ids). Empty list means v1-only or none."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return [], []
    idx = data.rfind(APK_SIG_MAGIC)
    if idx < 0:
        return [], []
    # The magic is preceded by the block size (u64) which repeats the size that
    # sits at the very start of the block.
    try:
        (size_at_end,) = struct.unpack_from("<Q", data, idx - 8)
    except struct.error:
        return [], []
    start = idx + 16 - 8 - size_at_end
    if start < 0 or start + 8 > len(data):
        return [], []
    p = start + 8
    end = idx - 8
    names, ids = [], []
    while p + 12 <= end:
        (plen,) = struct.unpack_from("<Q", data, p)
        if plen < 4 or p + 8 + plen > len(data):
            break
        (pid,) = struct.unpack_from("<I", data, p + 8)
        ids.append(pid)
        names.append(BLOCK_IDS.get(pid, "unknown id 0x%08x" % pid))
        p += 8 + plen
    return names, ids


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #

def match_signals(strings, signals, verbose_cap=6):
    """Return {control_id: {"name":..,"proves":..,"hits":[..],"count":n}}."""
    compiled = [(cid, nm, conf, proves, [re.compile(p, re.I) for p in pats])
                for cid, nm, conf, proves, pats in signals]
    found = {}
    for s in strings:
        for cid, nm, conf, proves, regs in compiled:
            for r in regs:
                if r.search(s):
                    e = found.setdefault(cid, {"name": nm, "conf": conf,
                                               "proves": proves,
                                               "hits": [], "count": 0})
                    e["count"] += 1
                    if len(e["hits"]) < verbose_cap and s not in e["hits"]:
                        e["hits"].append(s if len(s) <= 120 else s[:117] + "...")
                    break
    return found


# --------------------------------------------------------------------------- #
# Per-APK analysis
# --------------------------------------------------------------------------- #

def analyse(path):
    rep = {
        "apk": os.path.basename(path),
        "path": os.path.abspath(path),
        "size": os.path.getsize(path),
        "tiers": {},
        "dex": {"count": 0, "strings": 0},
        "libs": [],
        "notes": [],
    }

    names, _ids = signing_block_ids(path)
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        rep["notes"].append("cannot open as zip: %s" % exc)
        return rep

    with zf:
        entries = zf.namelist()
        v1 = [n for n in entries
              if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]

        container = {}
        if names:
            container["SIGBLOCK"] = {
                "name": "APK Signing Block present",
                "proves": "the file is covered end to end by a v2 or later "
                          "signature, so ANY byte change forces a re-sign and "
                          "changes the certificate the app sees at runtime",
                "conf": "STRONG", "hits": names, "count": len(names),
            }
        if v1 and not names:
            container["V1ONLY"] = {
                "name": "v1 (JAR) signing only",
                "proves": "the zip STRUCTURE is not signed, so entries can be "
                          "added and the central directory rewritten without "
                          "invalidating anything -- a DEX/asset hash check is "
                          "worth real money on this app, unlike on a v2+ one",
                "conf": "STRONG", "hits": v1, "count": len(v1),
            }
        if not v1 and not names:
            container["UNSIGNED"] = {
                "name": "no signature found",
                "proves": "this file cannot be installed as-is; you are almost "
                          "certainly looking at an intermediate build artefact",
                "conf": "STRONG", "hits": [], "count": 0,
            }

        odd = [n for n in entries
               if n.startswith("META-INF/")
               and not n.upper().endswith((".RSA", ".DSA", ".EC", ".SF", ".MF"))
               and not n.endswith("/")]
        if odd:
            container["METAINF-EXTRA"] = {
                "name": "extra files under META-INF/",
                "proves": "entries under META-INF are NOT covered by v1 signing; "
                          "a payload hidden here survives a v1-only signature "
                          "check. On a v2+ APK it is usually just Kotlin metadata",
                "conf": "WEAK", "hits": odd[:8], "count": len(odd),
            }
        if container:
            rep["tiers"]["T0-CONTAINER"] = container

        # ---- DEX ------------------------------------------------------------
        all_dex_strings = []
        for n in entries:
            if n.startswith("classes") and n.endswith(".dex"):
                rep["dex"]["count"] += 1
                try:
                    all_dex_strings.extend(dex_strings(zf.read(n)))
                except (KeyError, RuntimeError, zipfile.BadZipFile) as exc:
                    rep["notes"].append("%s unreadable: %s" % (n, exc))
        rep["dex"]["strings"] = len(all_dex_strings)

        java = match_signals(all_dex_strings, DEX_SIGNALS)
        remote = {k: v for k, v in java.items() if k in ("ATT-REMOTE", "ATT-KEY")}
        for k in remote:
            java.pop(k)
        if java:
            rep["tiers"]["T1-JAVA"] = java
        if remote:
            rep["tiers"]["T4-REMOTE"] = remote

        # ---- native ---------------------------------------------------------
        jni, early = {}, {}
        for n in entries:
            if not (n.startswith("lib/") and n.endswith(".so")):
                continue
            try:
                blob = zf.read(n)
            except (KeyError, RuntimeError, zipfile.BadZipFile):
                continue
            elf = Elf(blob)
            libinfo = {
                "name": n, "size": len(blob), "parsed": elf.ok,
                "init_array": elf.init_array_entries,
                "imports": len(elf.imports), "exports": len(elf.exports),
            }
            rep["libs"].append(libinfo)
            if not elf.ok:
                rep["notes"].append("%s: ELF headers unparsable (packed?)" % n)
                continue

            imp = match_signals(elf.imports, ELF_IMPORT_SIGNALS)
            exp = match_signals(elf.exports, ELF_EXPORT_SIGNALS)
            strs = match_signals(elf_strings(blob), ELF_STRING_SIGNALS)

            for src in (imp, exp, strs):
                for cid, v in src.items():
                    tgt = jni.setdefault(cid, {"name": v["name"], "conf": v["conf"],
                                               "proves": v["proves"],
                                               "hits": [], "count": 0})
                    tgt["count"] += v["count"]
                    for h in v["hits"]:
                        tag = "%s: %s" % (os.path.basename(n), h)
                        if len(tgt["hits"]) < 8 and tag not in tgt["hits"]:
                            tgt["hits"].append(tag)

            if elf.has_init_array and elf.init_array_entries:
                e = early.setdefault("NAT-INITARRAY", {
                    "name": ".init_array constructors",
                    "conf": "WEAK",
                    "proves": "code that runs INSIDE dlopen(), before JNI_OnLoad "
                              "and before any app Java code. If a check lives "
                              "here, a Frida script loaded at Java.perform time "
                              "has already lost. See 17-Libraries",
                    "hits": [], "count": 0})
                e["count"] += elf.init_array_entries
                e["hits"].append("%s: %d entries" % (os.path.basename(n),
                                                     elf.init_array_entries))

        if early:
            rep["tiers"]["T3-NATIVE-EARLY"] = early
        if jni:
            rep["tiers"]["T2-NATIVE-JNI"] = jni

    return rep


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def emit_text(rep, verbose):
    w = sys.stdout.write
    w("=" * 78 + "\n")
    w("%s   (%.1f MB)\n" % (rep["apk"], rep["size"] / 1048576.0))
    w("=" * 78 + "\n")
    w("  %d DEX file(s), %d declared strings, %d native librar%s\n"
      % (rep["dex"]["count"], rep["dex"]["strings"], len(rep["libs"]),
         "y" if len(rep["libs"]) == 1 else "ies"))
    for n in rep["notes"]:
        w("  ! %s\n" % n)
    w("\n")

    if not rep["tiers"]:
        w("  NO TAMPER-DETECTION SURFACE FOUND.\n")
        w("  Read that carefully: it means no MATCHING STRINGS, which is not the\n")
        w("  same as no checks. An obfuscated or packed app produces this output\n")
        w("  while implementing everything in the catalogue.\n\n")
        return

    for tier in TIER_ORDER:
        if tier not in rep["tiers"]:
            continue
        w("-- %s %s\n" % (tier, "-" * (74 - len(tier))))
        w("   (%s)\n\n" % TIER_NOTE[tier])
        rows = rep["tiers"][tier]
        for conf in ("STRONG", "WEAK"):
            ids = [c for c in sorted(rows) if rows[c].get("conf", "STRONG") == conf]
            if not ids:
                continue
            if conf == "WEAK":
                w("   ---- WEAK signals below. These are INGREDIENTS, not\n")
                w("        findings. Do not put one in a report.\n\n")
            for cid in ids:
                e = rows[cid]
                w("   [%s] %-34s x%d\n" % (cid, e["name"], e["count"]))
                w("        proves: %s\n" % _wrap(e["proves"], 66, " " * 16))
                if verbose and e["hits"]:
                    for h in e["hits"]:
                        w("        - %s\n" % h)
                w("\n")

    present = [t for t in TIER_ORDER if t in rep["tiers"]]
    strong = sum(1 for t in present for c in rep["tiers"][t]
                 if rep["tiers"][t][c].get("conf", "STRONG") == "STRONG")
    weak = sum(1 for t in present for c in rep["tiers"][t]
               if rep["tiers"][t][c].get("conf", "STRONG") == "WEAK")
    w("   %d STRONG signal(s), %d WEAK.\n" % (strong, weak))
    w("   EARLIEST RUNTIME TIER PRESENT: %s\n"
      % next((t for t in ["T3-NATIVE-EARLY", "T2-NATIVE-JNI", "T1-JAVA"]
              if t in present), "none"))
    w("   Attach BEFORE that tier runs, or you will be measuring an app that\n")
    w("   already decided what it thinks of you.\n\n")


def _wrap(text, width, indent):
    words, lines, cur = text.split(), [], ""
    for word in words:
        if len(cur) + len(word) + 1 > width:
            lines.append(cur)
            cur = word
        else:
            cur = (cur + " " + word).strip()
    if cur:
        lines.append(cur)
    return ("\n" + indent).join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Map an APK's tamper-detection surface by tier. "
                    "Produces LEADS, not findings.")
    ap.add_argument("targets", nargs="+", help="APK files or directories of them")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="print the matched strings, not just the summary")
    args = ap.parse_args(argv)

    paths = []
    for t in args.targets:
        if os.path.isdir(t):
            for root, _dirs, files in os.walk(t):
                paths.extend(os.path.join(root, f) for f in files
                             if f.lower().endswith((".apk", ".apks")))
        else:
            paths.append(t)

    reports = []
    for pth in paths:
        if not os.path.isfile(pth):
            sys.stderr.write("skipping %s: not a file\n" % pth)
            continue
        try:
            reports.append(analyse(pth))
        except Exception as exc:                      # noqa: BLE001 - keep going
            sys.stderr.write("error analysing %s: %r\n" % (pth, exc))

    if args.json:
        json.dump(reports, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        for r in reports:
            emit_text(r, args.verbose)
    return 0 if reports else 1


if __name__ == "__main__":
    sys.exit(main())
