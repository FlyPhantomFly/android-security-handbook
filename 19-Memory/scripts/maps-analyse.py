#!/usr/bin/env python3
"""
maps-analyse.py -- read a process's address space and say what is unusual
                   about it, WITHOUT root and WITHOUT any third-party module.

WHAT IT DOES
    Parses /proc/<pid>/maps or /proc/<pid>/smaps and produces four things:

        SUMMARY     how much address space, how much of it is executable,
                    writable, or both; how many mappings; the page size
                    implied by the boundaries
        ALLOCATOR   which native allocator and which memory checker this
                    process is actually running, inferred from the names the
                    allocators give their own anonymous mappings -- Scudo,
                    jemalloc, GWP-ASan, HWASan and ASan each name theirs
                    differently, so this is evidence rather than guesswork
        MODULES     every mapped file, its LOAD BASE (the lowest mapping whose
                    file offset is zero, which is the number you add to a
                    static address from Ghidra), its segment count and the
                    permission set across those segments
        FINDINGS    the regions that deserve a second look, each with the
                    evidence that produced it and an explicit note on what it
                    does NOT prove

    In --smaps mode it additionally reports resident and private-dirty totals
    per module, which is the only honest way to answer "how much memory is
    this library actually costing", and which tells you which regions are
    resident and therefore worth dumping.

HOW TO RUN
    # a saved capture (the usual case on Windows, where /proc does not exist)
    python3 maps-analyse.py maps.txt

    # straight off a device, no root needed for your own shell processes
    adb shell cat /proc/self/maps > maps.txt
    python3 maps-analyse.py maps.txt

    # from a pipe
    adb shell cat /proc/12345/maps | python3 maps-analyse.py -

    # a local Linux or WSL process, by pid
    python3 maps-analyse.py --pid 1234
    python3 maps-analyse.py --pid self

    # smaps, for resident-size and dirty-page accounting
    adb shell cat /proc/self/smaps > smaps.txt
    python3 maps-analyse.py smaps.txt --smaps

    # other modes
    python3 maps-analyse.py maps.txt --all              # every region, in order
    python3 maps-analyse.py maps.txt --module libc.so   # just one file
    python3 maps-analyse.py maps.txt --gaps             # unmapped holes
    python3 maps-analyse.py maps.txt --json             # machine-readable
    python3 maps-analyse.py maps.txt --strict           # exit 1 if any finding

REQUIREMENTS
    Python 3.6 or newer. Standard library only. No root, no frida, no adb
    module, no pyelftools. It runs on a locked-down laptop against a text file
    somebody pasted into a ticket, which is the common case.

WHAT THIS SCRIPT WILL *NOT* TELL YOU
    - Whether anything here is a vulnerability. Every line of output is a
      PROPERTY OF A PROCESS AT ONE INSTANT. An RWX page is not a finding; it
      is a question. ART's JIT holds RWX pages on every Android device ever
      shipped. The script prints "RWX" and never "VULNERABLE", for the same
      reason 15-Native-Code's elf-harden-check.py prints "MISSING" and never
      "INSECURE".
    - What is IN any of these regions. maps is an index, not contents. Reading
      the bytes needs /proc/<pid>/mem plus ptrace permission, or Frida, or a
      core dump. See scripts/enumerate-ranges.js and README section 7.
    - Whether ASLR is working. One snapshot cannot show randomisation; you
      need several, from separate process launches. examples/mem-landmarks.c
      and labs/lab-02 do that properly. A single capture that "looks random"
      proves nothing at all.
    - Anything about the Java heap. `[anon:dalvik-main space]` is reported as
      one region with a size; what is inside it is 13-ART's subject, and a
      heap dump, not a maps read, is the tool for it.
    - Whether a module is vulnerable, or even which version it is. That is
      17-Libraries. This script identifies WHERE a file is mapped, never WHAT
      it is.
    - Kernel memory. kptr_restrict hides kernel pointers from unprivileged
      readers and nothing here tries to defeat that.

ACCURACY NOTES
    - The anonymous-mapping names it keys on are set by the allocators
      themselves through prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...) and
      appear in maps as [anon:NAME]. The Scudo, GWP-ASan and HWASan strings
      below were confirmed against live output from an Android 13 arm64 device
      running the fixtures in ../examples/, not from memory.
    - "Load base" is the lowest mapping of a file whose FILE OFFSET is zero.
      Using the lowest mapping regardless of offset is wrong for any library
      whose first segment is not at offset 0, and produces a base that is off
      by one segment. That error is silent and costs hours.
    - Page size is inferred from the greatest common divisor of the region
      boundaries, so a 16 KiB-page device reports 16384. It is an inference,
      and the script says so rather than asserting 4096.
"""

from __future__ import print_function

import argparse
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# 7bd5393000-7bd5395000 r--p 00000000 fc:07 2179108   /data/local/tmp/x
MAPS_RE = re.compile(
    r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+"     # start-end
    r"([rwxsp\-]{4})\s+"                     # perms
    r"([0-9a-fA-F]+)\s+"                     # file offset
    r"([0-9a-fA-F]+:[0-9a-fA-F]+)\s+"        # device major:minor
    r"(\d+)"                                 # inode
    r"(?:\s+(.*))?$"                         # pathname (optional)
)

# smaps detail lines:  "Rss:                   4 kB"  /  "VmFlags: rd ex mr mw"
SMAPS_KV_RE = re.compile(r"^([A-Z][A-Za-z_]*):\s+(\d+)\s*kB\s*$")
SMAPS_FLAGS_RE = re.compile(r"^VmFlags:\s*(.*)$")


class Region(object):
    """One line of /proc/<pid>/maps, plus any smaps detail that followed it."""

    __slots__ = ("start", "end", "perms", "offset", "dev", "inode", "path",
                 "detail", "vmflags", "lineno")

    def __init__(self, start, end, perms, offset, dev, inode, path, lineno):
        self.start = start
        self.end = end
        self.perms = perms
        self.offset = offset
        self.dev = dev
        self.inode = inode
        self.path = path or ""
        self.detail = {}          # smaps counters, in kB
        self.vmflags = []
        self.lineno = lineno

    # -- derived properties -------------------------------------------------

    @property
    def size(self):
        return self.end - self.start

    @property
    def readable(self):
        return self.perms[0] == "r"

    @property
    def writable(self):
        return self.perms[1] == "w"

    @property
    def executable(self):
        return self.perms[2] == "x"

    @property
    def shared(self):
        # Position 3 is 's' for MAP_SHARED and 'p' for MAP_PRIVATE. A private
        # mapping is copy-on-write: your writes are yours alone. A shared one
        # is visible to every other process mapping the same object, which is
        # why it matters for anything crossing a process boundary.
        return self.perms[3] == "s"

    @property
    def is_file(self):
        """Backed by something with a path. Includes /dev, /memfd and apk."""
        return bool(self.path) and not self.path.startswith("[")

    @property
    def is_deleted(self):
        # The kernel appends " (deleted)" when the file has been unlinked but
        # the mapping survives. Legitimate for tmpfiles; also exactly what a
        # dropper does to make its payload unrecoverable from disk.
        return self.path.endswith("(deleted)")

    @property
    def anon_name(self):
        """The NAME of a named anonymous region, or None.

        Android names anonymous VMAs with prctl(PR_SET_VMA_ANON_NAME); they
        show up as [anon:whatever]. That name is the single most informative
        field in the whole file, because the allocators and the runtime label
        their own memory with it.
        """
        if self.path.startswith("[anon:"):
            return self.path[len("[anon:"):].rstrip("]")
        return None

    @property
    def kind(self):
        if self.path == "":
            return "anonymous"
        if self.anon_name is not None:
            return "anon-named"
        if self.path.startswith("["):
            return "special"
        return "file"

    def clean_path(self):
        p = self.path
        if p.endswith(" (deleted)"):
            p = p[: -len(" (deleted)")]
        return p

    def to_dict(self):
        d = {
            "start": "%x" % self.start,
            "end": "%x" % self.end,
            "size": self.size,
            "perms": self.perms,
            "offset": "%x" % self.offset,
            "dev": self.dev,
            "inode": self.inode,
            "path": self.path,
            "kind": self.kind,
        }
        if self.detail:
            d["smaps"] = dict(self.detail)
        if self.vmflags:
            d["vmflags"] = self.vmflags
        return d


def parse(lines):
    """Parse maps or smaps text into a list of Region.

    smaps is maps with detail lines interleaved, so one parser handles both:
    a line that matches the maps shape starts a new region, anything else is
    detail attached to the region above it.
    """
    regions = []
    skipped = 0
    for n, raw in enumerate(lines, 1):
        line = raw.rstrip("\n").rstrip("\r")
        if not line.strip():
            continue
        # A real /proc file never contains comments. Saved fixtures do, and a
        # capture is far more useful when it can say where it came from, so
        # lines beginning with '#' are skipped rather than counted as garbage.
        if line.lstrip().startswith("#"):
            continue
        m = MAPS_RE.match(line)
        if m:
            regions.append(Region(
                int(m.group(1), 16), int(m.group(2), 16),
                m.group(3), int(m.group(4), 16),
                m.group(5), int(m.group(6)),
                (m.group(7) or "").strip(), n))
            continue
        if regions:
            kv = SMAPS_KV_RE.match(line)
            if kv:
                regions[-1].detail[kv.group(1)] = int(kv.group(2))
                continue
            fl = SMAPS_FLAGS_RE.match(line)
            if fl:
                regions[-1].vmflags = fl.group(1).split()
                continue
            if line.startswith(("THPeligible", "ProtectionKey", "Name:")):
                continue
        skipped += 1
    return regions, skipped


# ---------------------------------------------------------------------------
# Allocator and checker fingerprints
#
# Every entry below was observed in real /proc/<pid>/maps output, not recalled.
# The Scudo and HWASan strings come from the fixtures in ../examples/ run on an
# Android 13 arm64 device; the jemalloc and ART ones from older captures and
# from AOSP's own use of the same names.
# ---------------------------------------------------------------------------

ALLOCATOR_SIGNS = [
    # (substring to look for in the anon name, label, note)
    ("scudo:primary",   "Scudo",
     "small and medium allocations, carved from per-size-class regions"),
    ("scudo:secondary", "Scudo",
     "large allocations, mapped individually and guarded"),
    ("scudo",           "Scudo",
     "the default native allocator on Android 11 and later"),
    ("libc_malloc",     "jemalloc or the generic bionic heap",
     "the name bionic used before Scudo; also used by the generic path"),
    ("GWP-ASan",        "GWP-ASan",
     "sampled guard-page allocator; on by default for apps since Android 14"),
    ("SizeClassAllocator", "HWAddressSanitizer or AddressSanitizer",
     "the sanitizer_common allocator; this process is running instrumented"),
    ("LargeMmapAllocator", "HWAddressSanitizer or AddressSanitizer",
     "the sanitizer_common large-allocation path"),
    ("hwasan",          "HWAddressSanitizer",
     "HWASan shadow or bookkeeping"),
    ("bionic_alloc",    "bionic internal",
     "bionic's own small internal allocations, not the app heap"),
]

RUNTIME_SIGNS = [
    ("dalvik-main space",       "ART managed heap (main space)"),
    ("dalvik-large object",     "ART large-object space"),
    ("dalvik-non moving space", "ART non-moving space"),
    ("dalvik-zygote space",     "ART Zygote space, shared copy-on-write"),
    ("dalvik-free list large",  "ART large-object free list"),
    ("dalvik-CompilerMetadata", "ART compiler metadata"),
    ("dalvik-indirect ref",     "ART indirect reference table (JNI refs)"),
    ("dalvik-jit-code-cache",   "ART JIT code cache -- expect executable pages"),
    ("dalvik",                  "ART runtime region"),
    ("stack_and_tls",           "a thread stack plus its thread-local storage"),
    ("thread signal stack",     "an alternate signal stack"),
    ("linker_alloc",            "the dynamic linker's own allocations"),
    ("arc4random",              "bionic's RNG state"),
    ("System.map",              "a mapped file, not kernel symbols"),
]


def fingerprint(regions):
    """Which allocator and which checker is this process running?"""
    found = {}
    runtime = {}
    for r in regions:
        name = r.anon_name
        if name is None:
            continue
        for needle, label, note in ALLOCATOR_SIGNS:
            if needle.lower() in name.lower():
                entry = found.setdefault(label, {"note": note, "bytes": 0,
                                                 "count": 0, "examples": []})
                entry["bytes"] += r.size
                entry["count"] += 1
                if len(entry["examples"]) < 3 and name not in entry["examples"]:
                    entry["examples"].append(name)
                break
        for needle, label in RUNTIME_SIGNS:
            if needle.lower() in name.lower():
                e = runtime.setdefault(label, {"bytes": 0, "count": 0})
                e["bytes"] += r.size
                e["count"] += 1
                break
    return found, runtime


# ---------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------

class Module(object):
    def __init__(self, path):
        self.path = path
        self.regions = []

    @property
    def base(self):
        """Load base: the LOWEST mapping of this file whose file offset is 0.

        Not simply the lowest mapping. A library's first PT_LOAD is normally at
        offset 0, but an APK-embedded .so is mapped from a non-zero offset
        inside the ZIP, and taking the lowest mapping there gives an answer
        that is wrong by however far into the APK the library sits.
        """
        zeros = [r.start for r in self.regions if r.offset == 0]
        if zeros:
            return min(zeros)
        return min(r.start for r in self.regions)

    @property
    def base_is_exact(self):
        return any(r.offset == 0 for r in self.regions)

    @property
    def span(self):
        return max(r.end for r in self.regions) - min(r.start for r in self.regions)

    @property
    def mapped_bytes(self):
        return sum(r.size for r in self.regions)

    @property
    def permset(self):
        seen = []
        for r in self.regions:
            if r.perms not in seen:
                seen.append(r.perms)
        return seen

    def rss(self):
        if not any(r.detail for r in self.regions):
            return None
        return sum(r.detail.get("Rss", 0) for r in self.regions)

    def private_dirty(self):
        if not any(r.detail for r in self.regions):
            return None
        return sum(r.detail.get("Private_Dirty", 0) for r in self.regions)


def build_modules(regions):
    mods = {}
    for r in regions:
        if not r.is_file:
            continue
        mods.setdefault(r.clean_path(), Module(r.clean_path())).regions.append(r)
    return mods


# ---------------------------------------------------------------------------
# Findings
#
# House rule, from the repository style guide: evidence, not verdict. Each
# finding states what was observed, and then what that observation does NOT
# establish. A tool that says "VULNERABLE" trains its user to stop thinking.
# ---------------------------------------------------------------------------

class Finding(object):
    def __init__(self, tag, region, what, not_what):
        self.tag = tag
        self.region = region
        self.what = what
        self.not_what = not_what

    def to_dict(self):
        return {
            "tag": self.tag,
            "region": "%x-%x" % (self.region.start, self.region.end),
            "perms": self.region.perms,
            "path": self.region.path,
            "size": self.region.size,
            "observation": self.what,
            "does_not_prove": self.not_what,
        }


# Paths where an executable mapping is expected and boring.
SYSTEM_CODE_PREFIXES = (
    "/system/", "/apex/", "/vendor/", "/product/", "/system_ext/",
    "/odm/", "/lib/", "/usr/lib/", "/bin/", "/usr/bin/", "/sbin/",
)

# Names that are RWX by design on Android and should not be shouted about.
KNOWN_RWX_NAMES = (
    "dalvik-jit-code-cache",
    "jit-code-cache",
    "dalvik-CompilerMetadata",
)

# Kernel-provided pseudo-mappings. Every one of these is executable, present in
# every process, and has no file behind it -- so a naive "executable anonymous
# mapping" rule flags all of them. It is a false positive, it fires on every
# single capture, and a check that always fires is a check nobody reads.
KERNEL_PSEUDO = ("[vdso]", "[vsyscall]", "[vectors]", "[sigpage]", "[vvar]",
                 "[vvar_vclock]", "[uprobes]")


def analyse(regions):
    findings = []

    for r in regions:
        name = r.anon_name or ""

        # 0. Execute-only memory. Read permission REMOVED from a code segment,
        #    so the CPU may run it and nothing may read it. This is a
        #    mitigation, not a problem: it defeats the "read the code to find
        #    ROP gadgets" step. Android uses it for some system libraries on
        #    hardware that supports it. Reported so that a reader who sees the
        #    unusual `--xp` string is not left guessing.
        if r.executable and not r.readable:
            findings.append(Finding(
                "XOM",
                r,
                "execute-only: the CPU may run these bytes and nothing may "
                "read them (%s)" % (r.clean_path() or "anonymous"),
                "a problem. It is the opposite -- execute-only memory is a "
                "hardening feature. It does mean a memory-disclosure primitive "
                "cannot be pointed at this region to harvest ROP gadgets, and "
                "that a naive dumper will get EFAULT rather than bytes."))

        if r.path in KERNEL_PSEUDO:
            continue

        # 1. Writable AND executable at the same instant. The strongest single
        #    signal in the whole file, and still not a verdict.
        if r.writable and r.executable:
            expected = any(k in name for k in KNOWN_RWX_NAMES)
            findings.append(Finding(
                "RWX",
                r,
                "writable and executable simultaneously"
                + (" (a known JIT region)" if expected else ""),
                "that code was injected. ART's JIT, every other JIT, and some "
                "packers all need this. Ask WHO mapped it and whether "
                "attacker-controlled bytes ever reach it."))

        # 2. Executable memory with no file behind it. Code that came from
        #    somewhere other than a file on disk: a JIT, a runtime-decrypted
        #    payload, or an injected agent.
        elif r.executable and not r.is_file:
            expected = any(k in name for k in KNOWN_RWX_NAMES) or "jit" in name.lower()
            findings.append(Finding(
                "ANON-EXEC",
                r,
                "executable anonymous mapping"
                + (" named %r" % name if name else " with no name")
                + (" (a known JIT region)" if expected else ""),
                "anything malicious. It does mean the bytes there came from "
                "memory rather than from a file, so no on-disk artefact "
                "explains them and static analysis of the APK will not show "
                "them."))

        # 3. The file is gone but the mapping is not. Legitimate for temp
        #    files; also precisely how a dropper removes its own evidence.
        if r.is_deleted:
            findings.append(Finding(
                "DELETED",
                r,
                "mapped from a file that has been unlinked: %s" % r.path,
                "the deletion was hostile. Many runtimes unlink a temp file "
                "immediately after mapping it. It does mean the bytes cannot "
                "be recovered from the filesystem, only from this process."))

        # 4. Executable code loaded from writable app-private storage. This is
        #    what dynamic code loading looks like from the outside.
        if r.executable and r.is_file:
            p = r.clean_path()
            if p.startswith("/data/") and ".apk" not in p:
                findings.append(Finding(
                    "DATA-EXEC",
                    r,
                    "executable mapping backed by %s, under writable app "
                    "storage rather than a read-only system partition" % p,
                    "that the code is untrusted. Every app's own native "
                    "libraries live under /data/app/. It is worth checking "
                    "that the file was not written at RUN TIME -- that is the "
                    "dynamic-code-loading pattern 40-Obfuscation covers."))
            elif p.startswith("/memfd:") or p.startswith("/dev/ashmem"):
                findings.append(Finding(
                    "MEMFD-EXEC",
                    r,
                    "executable mapping backed by an anonymous file object "
                    "(%s), which never existed on any filesystem" % p,
                    "anything on its own. It does mean there is no path you "
                    "can pull the code from; you have to dump it from memory."))

        # 5. NX off. Should never happen on a modern device.
        if r.path == "[stack]" and r.executable:
            findings.append(Finding(
                "EXEC-STACK",
                r,
                "the main thread stack is EXECUTABLE",
                "an exploit exists, but it removes the single mitigation that "
                "makes classic stack shellcode useless. On any Android since "
                "2.3 this is abnormal and worth explaining."))
        if r.path == "[heap]" and r.executable:
            findings.append(Finding(
                "EXEC-HEAP",
                r,
                "the brk heap is EXECUTABLE",
                "an exploit exists. Same reasoning as EXEC-STACK."))

        # 6. Shared and writable. Two processes can both write these bytes,
        #    which turns a memory bug in one into a bug affecting both.
        if r.shared and r.writable and r.is_file:
            findings.append(Finding(
                "SHARED-RW",
                r,
                "MAP_SHARED and writable, backed by %s" % r.clean_path(),
                "a boundary is crossed. Ashmem and graphics buffers are "
                "shared and writable by design. It does mean the contents are "
                "not exclusively this process's, so 'only we can corrupt it' "
                "is not true here."))

    return findings


# ---------------------------------------------------------------------------
# Derived facts
# ---------------------------------------------------------------------------

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def infer_page_size(regions):
    """Greatest common divisor of every boundary. 4096 or 16384 in practice."""
    g = 0
    for r in regions:
        g = gcd(g, r.start)
        g = gcd(g, r.end)
        if g == 4096:
            # Cannot go below the architectural minimum in any useful sense;
            # stop early rather than letting one odd boundary drag it to 1.
            break
    return g


def gaps(regions, min_size):
    out = []
    ordered = sorted(regions, key=lambda r: r.start)
    for a, b in zip(ordered, ordered[1:]):
        if b.start > a.end and (b.start - a.end) >= min_size:
            out.append((a.end, b.start, b.start - a.end, a.path, b.path))
    return out


def human(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            if unit == "B":
                return "%d B" % n
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return str(n)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def report(regions, args):
    out = []
    w = out.append

    total = sum(r.size for r in regions)
    exec_bytes = sum(r.size for r in regions if r.executable)
    write_bytes = sum(r.size for r in regions if r.writable)
    rwx_bytes = sum(r.size for r in regions if r.writable and r.executable)
    anon_bytes = sum(r.size for r in regions if not r.is_file)
    file_bytes = total - anon_bytes
    page = infer_page_size(regions)

    w("=" * 78)
    w("SUMMARY")
    w("=" * 78)
    w("  mappings                 %d" % len(regions))
    w("  address space reserved   %s" % human(total))
    w("      file-backed          %s" % human(file_bytes))
    w("      anonymous            %s" % human(anon_bytes))
    w("  executable               %s" % human(exec_bytes))
    w("  writable                 %s" % human(write_bytes))
    w("  writable AND executable  %s%s" % (
        human(rwx_bytes), "" if rwx_bytes == 0 else "   <- see FINDINGS"))
    if regions:
        w("  lowest address           %012x" % min(r.start for r in regions))
        w("  highest address          %012x" % max(r.end for r in regions))
    if page:
        w("  page size (inferred)     %d bytes%s" % (
            page, " -- a 16 KiB-page device" if page == 16384 else ""))
        w("      inferred from the greatest common divisor of every region")
        w("      boundary. It is an inference; ask the device with")
        w("      `getconf PAGESIZE` if it matters.")
    w("")
    w("  'Address space reserved' is not memory used. A mapping is a promise")
    w("  from the kernel, and pages are only backed by physical memory when")
    w("  they are first touched. Run with --smaps against a smaps capture for")
    w("  the resident numbers, which are the ones that mean something.")
    w("")

    # -- allocator and checker ---------------------------------------------
    alloc, runtime = fingerprint(regions)
    w("=" * 78)
    w("ALLOCATOR AND CHECKER")
    w("=" * 78)
    if alloc:
        for label in sorted(alloc):
            e = alloc[label]
            w("  %-38s %s across %d mapping(s)"
              % (label, human(e["bytes"]), e["count"]))
            w("      %s" % e["note"])
            w("      evidence: %s" % ", ".join("[anon:%s]" % x
                                               for x in e["examples"]))
    else:
        w("  No named allocator regions found.")
        w("      Either this is not an Android process, or the kernel does not")
        w("      support named anonymous VMAs, or the capture is from a")
        w("      release old enough that bionic did not name them. Absence")
        w("      here is not evidence that Scudo is absent.")
    w("")
    if runtime:
        w("  Runtime regions:")
        for label in sorted(runtime, key=lambda k: -runtime[k]["bytes"]):
            e = runtime[label]
            w("      %-46s %10s  (%d)"
              % (label, human(e["bytes"]), e["count"]))
        w("")
        w("      Everything above with 'ART' in it is the MANAGED heap, and")
        w("      what lives inside it is chapter 13's subject, not this one.")
        w("      A maps read tells you how big it is and where; only a heap")
        w("      dump tells you what objects are in it.")
        w("")

    # -- modules ------------------------------------------------------------
    mods = build_modules(regions)
    if args.module:
        mods = {k: v for k, v in mods.items() if args.module.lower() in k.lower()}
    w("=" * 78)
    w("MODULES  (%d mapped file%s)" % (len(mods), "" if len(mods) == 1 else "s"))
    w("=" * 78)
    if mods:
        has_smaps = any(m.rss() is not None for m in mods.values())
        if has_smaps:
            w("  %-14s %4s %10s %9s %9s  %s"
              % ("LOAD BASE", "SEG", "SPAN", "RSS", "PRIV_DTY", "PATH"))
        else:
            w("  %-14s %4s %10s  %-24s %s"
              % ("LOAD BASE", "SEG", "SPAN", "PERMISSIONS", "PATH"))
        for path in sorted(mods, key=lambda p: mods[p].base):
            m = mods[path]
            flag = "" if m.base_is_exact else "?"
            if has_smaps:
                w("  %012x%1s %4d %10s %9s %9s  %s"
                  % (m.base, flag, len(m.regions), human(m.span),
                     "%d kB" % (m.rss() or 0),
                     "%d kB" % (m.private_dirty() or 0), path))
            else:
                w("  %012x%1s %4d %10s  %-24s %s"
                  % (m.base, flag, len(m.regions), human(m.span),
                     " ".join(m.permset)[:24], path))
        w("")
        w("  LOAD BASE is the address you ADD to a static offset from Ghidra,")
        w("  IDA or radare2 to get a runtime address. It is the lowest mapping")
        w("  of the file whose FILE OFFSET is 00000000 -- not simply its lowest")
        w("  mapping. A '?' after the base means no zero-offset mapping was")
        w("  found, so the number shown is the lowest mapping and may be wrong")
        w("  by one segment. That happens for a library mapped straight out of")
        w("  an APK, where the .so begins part way into the ZIP.")
        w("")
        w("  SEG is how many separate mappings one file occupies. Four is")
        w("  typical for a shared object: r--p for read-only data, r-xp for")
        w("  code, r--p for the RELRO region after the linker locks it, rw-p")
        w("  for writable data. That is one file, one load base, four rows in")
        w("  maps -- which is why a library appears several times and is not a")
        w("  sign of anything being wrong.")
    else:
        w("  none")
    w("")

    # -- findings -----------------------------------------------------------
    findings = analyse(regions)
    w("=" * 78)
    w("FINDINGS  (%d)" % len(findings))
    w("=" * 78)
    if not findings:
        w("  Nothing flagged. That is not a clean bill of health: this script")
        w("  looks at page protections and mapping provenance, and a process")
        w("  can be thoroughly compromised without either looking odd.")
    else:
        by_tag = {}
        for f in findings:
            by_tag.setdefault(f.tag, []).append(f)
        for tag in sorted(by_tag):
            group = by_tag[tag]
            w("")
            w("  [%s] x%d" % (tag, len(group)))
            for f in group[: args.limit]:
                r = f.region
                w("      %012x-%012x %s %9s  %s"
                  % (r.start, r.end, r.perms, human(r.size),
                     r.path or "(anonymous)"))
                w("          observed: %s" % f.what)
            if len(group) > args.limit:
                w("      ... and %d more (raise --limit to see them)"
                  % (len(group) - args.limit))
            w("      does NOT prove %s" % group[0].not_what)
    w("")

    # -- gaps ---------------------------------------------------------------
    if args.gaps:
        holes = gaps(regions, args.min_gap)
        w("=" * 78)
        w("UNMAPPED GAPS  (>= %s)" % human(args.min_gap))
        w("=" * 78)
        for lo, hi, sz, before, after in holes[: args.limit]:
            w("  %012x-%012x %12s   between %s and %s"
              % (lo, hi, human(sz), before or "(anon)", after or "(anon)"))
        w("")
        w("  A gap is address space nothing has claimed. It matters for two")
        w("  reasons. First, an mmap with no fixed address lands in one of")
        w("  them, so the sizes and positions of the gaps are what ASLR is")
        w("  randomising within. Second, a deliberate gap next to a mapping is")
        w("  a guard region: an overflow that walks into one faults at once")
        w("  instead of quietly corrupting the next allocation.")
        w("")

    # -- every region -------------------------------------------------------
    if args.all:
        w("=" * 78)
        w("ALL REGIONS")
        w("=" * 78)
        for r in regions:
            extra = ""
            if r.detail:
                extra = "  rss=%dkB pd=%dkB" % (r.detail.get("Rss", 0),
                                                r.detail.get("Private_Dirty", 0))
            w("  %012x-%012x %s %10s %-10s %s%s"
              % (r.start, r.end, r.perms, human(r.size), r.kind,
                 r.path or "", extra))
        w("")

    return "\n".join(out), findings


def report_smaps(regions):
    """Resident-memory accounting. Only meaningful for a smaps capture."""
    out = []
    w = out.append
    if not any(r.detail for r in regions):
        return ("\nNo smaps detail lines found. --smaps needs a capture of\n"
                "/proc/<pid>/smaps, not /proc/<pid>/maps. They look similar;\n"
                "smaps has around twenty extra lines per region.\n")

    def tot(key):
        return sum(r.detail.get(key, 0) for r in regions)

    w("=" * 78)
    w("RESIDENT MEMORY  (from smaps; all values kB)")
    w("=" * 78)
    for key, meaning in (
            ("Rss", "resident: pages actually in physical memory right now"),
            ("Pss", "proportional: shared pages divided by their sharer count"),
            ("Shared_Clean", "shared, unmodified -- the file can be re-read"),
            ("Shared_Dirty", "shared, modified"),
            ("Private_Clean", "yours alone, unmodified"),
            ("Private_Dirty", "yours alone, modified: the true cost of this process"),
            ("Referenced", "touched recently enough that the kernel noticed"),
            ("Anonymous", "not backed by any file"),
            ("Swap", "paged out"),
            ("SwapPss", "paged out, proportional"),
            ("Locked", "pinned by mlock and never swappable")):
        v = tot(key)
        w("  %-16s %10d   %s" % (key, v, meaning))
    w("")
    w("  Private_Dirty is the number to quote when someone asks how much")
    w("  memory a process costs. Rss double-counts every page shared with the")
    w("  Zygote, and on Android that is most of the framework.")
    w("")
    w("  Largest regions by Private_Dirty:")
    ranked = sorted((r for r in regions if r.detail),
                    key=lambda r: -r.detail.get("Private_Dirty", 0))
    for r in ranked[:15]:
        w("      %8d kB  %012x-%012x %s  %s"
          % (r.detail.get("Private_Dirty", 0), r.start, r.end, r.perms,
             r.path or "(anonymous)"))
    w("")
    w("  Those are the pages a memory dump would actually find content in.")
    w("  A region with Rss 0 is reserved address space with nothing behind it;")
    w("  dumping it yields zeros or a read error, not data.")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def read_input(args):
    if args.pid:
        which = "smaps" if args.smaps else "maps"
        path = "/proc/%s/%s" % (args.pid, which)
        if not os.path.exists(path):
            sys.stderr.write(
                "cannot open %s\n"
                "  --pid reads the LOCAL /proc, which exists on Linux and in\n"
                "  WSL but not on Windows and not for a process on a phone.\n"
                "  For a device, capture first:\n"
                "      adb shell cat /proc/<pid>/%s > %s.txt\n"
                "      python3 maps-analyse.py %s.txt\n" % (path, which, which, which))
            return None
        try:
            with open(path, "r") as fh:
                return fh.readlines()
        except IOError as exc:
            sys.stderr.write(
                "cannot read %s: %s\n"
                "  Reading another process's maps needs the same uid or\n"
                "  CAP_SYS_PTRACE. On Android 13, SELinux denies the shell\n"
                "  user access to an app's /proc entries outright, so this\n"
                "  fails even as uid 2000. See faq.md.\n" % (path, exc))
            return None

    if args.path == "-":
        return sys.stdin.readlines()
    try:
        with open(args.path, "r") as fh:
            return fh.readlines()
    except IOError as exc:
        sys.stderr.write("cannot read %s: %s\n" % (args.path, exc))
        return None


def main(argv):
    ap = argparse.ArgumentParser(
        description="Summarise and triage a process address space from "
                    "/proc/<pid>/maps or /proc/<pid>/smaps.")
    ap.add_argument("path", nargs="?", default=None,
                    help="a maps or smaps capture, or - for stdin")
    ap.add_argument("--pid", help="read /proc/<pid>/maps on THIS machine "
                                  "(Linux or WSL only)")
    ap.add_argument("--smaps", action="store_true",
                    help="input is smaps; also print resident-memory accounting")
    ap.add_argument("--all", action="store_true", help="list every region")
    ap.add_argument("--module", help="restrict the module table to paths "
                                     "containing this substring")
    ap.add_argument("--gaps", action="store_true",
                    help="report unmapped holes in the address space")
    ap.add_argument("--min-gap", type=lambda s: int(s, 0), default=1 << 30,
                    help="smallest gap to report (default 1 GiB)")
    ap.add_argument("--limit", type=int, default=12,
                    help="max rows per finding group (default 12)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if there is any finding. For CI. Do NOT use "
                         "it to decide severity -- see the header.")
    args = ap.parse_args(argv[1:])

    if not args.path and not args.pid:
        ap.print_help()
        return 2

    lines = read_input(args)
    if lines is None:
        return 2

    regions, skipped = parse(lines)
    if not regions:
        sys.stderr.write(
            "no map lines parsed.\n"
            "  Expected lines shaped like:\n"
            "      7bd5393000-7bd5395000 r--p 00000000 fc:07 2179108 /path\n"
            "  If you captured with `adb shell cat ... > file` on Windows,\n"
            "  the file may have CRLF line endings and a UTF-16 BOM from\n"
            "  PowerShell redirection. Use `adb shell cat ... | Out-File\n"
            "  -Encoding ascii` or capture through Git Bash.\n")
        return 2

    findings_list = []
    if args.json:
        text, findings_list = report(regions, args)
        alloc, runtime = fingerprint(regions)
        mods = build_modules(regions)
        doc = {
            "regions": len(regions),
            "unparsed_lines": skipped,
            "total_bytes": sum(r.size for r in regions),
            "exec_bytes": sum(r.size for r in regions if r.executable),
            "rwx_bytes": sum(r.size for r in regions
                             if r.executable and r.writable),
            "page_size_inferred": infer_page_size(regions),
            "allocators": {k: {"bytes": v["bytes"], "count": v["count"],
                               "examples": v["examples"]}
                           for k, v in alloc.items()},
            "runtime": runtime,
            "modules": [{"path": p, "base": "%x" % m.base,
                         "base_exact": m.base_is_exact,
                         "segments": len(m.regions), "span": m.span}
                        for p, m in sorted(mods.items())],
            "findings": [f.to_dict() for f in findings_list],
        }
        if args.all:
            doc["all_regions"] = [r.to_dict() for r in regions]
        print(json.dumps(doc, indent=2, sort_keys=True))
    else:
        text, findings_list = report(regions, args)
        print(text)
        if args.smaps:
            print(report_smaps(regions))
        if skipped:
            print("note: %d input line(s) did not match any expected shape."
                  % skipped)
            print("      For a maps capture that should be zero. For smaps it")
            print("      just means a counter this script does not know about.")

    if args.strict and findings_list:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
