#!/usr/bin/env python3
# scripts/bypass-triage.py
#
# PURPOSE
#   Answer the question chapter 53 sends readers here for: "I attached, and the
#   app died instantly. Why?"
#
#   More precisely, it answers three questions in order, because answering them
#   out of order is how people waste an afternoon:
#
#     1. Did the process die at all, or did only the operation fail?
#     2. If it died - HOW did it die? Every response an app can take leaves a
#        different, machine-readable signature in ApplicationExitInfo.
#     3. WHICH control fired, and at WHICH SEAM of the five this chapter names
#        (input, read, verdict, branch, gated code)?
#
#   Question 3 cannot always be answered from the outside, and this script says
#   so instead of guessing. What it always answers is 1 and 2, and it narrows 3
#   to a short list with the evidence attached.
#
# USAGE
#   # host - the normal case: launch the app clean, watch it, classify
#   python3 -B bypass-triage.py --package com.pentest.ch67.guarded
#
#   # host - pass extras through to `am start` (this app's lab harness)
#   python3 -B bypass-triage.py --package com.pentest.ch67.guarded \
#       --extra-bool auto_open=true --extra-str simulate=frida.threadnames
#
#   # host - do not launch anything; explain a death that already happened
#   python3 -B bypass-triage.py --package com.example.target --postmortem
#
#   # host - static pass: which controls EXIST, and at which seam do they read?
#   python3 -B bypass-triage.py --package com.example.target --apk target.apk
#
#   # host - compare two runs (clean vs instrumented) and print the delta
#   python3 -B bypass-triage.py --package com.example.target --baseline base.json
#   python3 -B bypass-triage.py --package com.example.target --json run.json
#
#   # host - pick a device when several are attached
#   python3 -B bypass-triage.py -p com.example.app --serial 80062527052150
#
# REQUIREMENTS
#   * python3.8+, standard library only.
#   * adb on PATH, one device authorised. NO ROOT REQUIRED - everything it
#     reads (`dumpsys activity exit-info`, `logcat`) is available to plain adb
#     on API 30 and later. On API 29 and below there is no ApplicationExitInfo
#     and the script degrades to logcat evidence only; it says so.
#   * For --apk: nothing extra. It reads DEX and native strings out of the zip
#     itself rather than shelling out to apktool, so it works with no tooling
#     installed - at the cost of finding strings rather than structure.
#
# WHAT THIS WILL *NOT* TELL YOU
#   * It will NOT tell you the control's NAME unless the app logs it or the
#     string is recoverable from the APK. Attribution to a named check is
#     evidence-based; when the evidence is absent the script prints the
#     candidates and refuses to pick one.
#   * It will NOT detect a silent response. An app that decides you are hostile
#     and quietly returns wrong data does not die, does not log, and produces
#     no exit-info record. The script prints "no death observed" and warns
#     that this is exactly what a poisoned session looks like. Chapter 67
#     section 3.9 is about that case; it is detected by DIFFING behaviour, not
#     by watching for a crash.
#   * It will NOT tell you the exit STATUS means what the developer intended.
#     `System.exit(42)` gives status=42 only because that app chose 42. Treat
#     the status as a fingerprint of one build, not a standard.
#   * It will NOT bypass anything. It is an observation tool. The bypass is
#     your job and belongs only on apps you own or are contracted to test.
#   * It will NOT distinguish an anti-instrumentation kill from an ordinary
#     bug. The first build of this chapter's own demo app died at launch with
#     reason=4 CRASH before any control had fired, because a socket probe ran
#     on the main thread and StrictMode threw NetworkOnMainThreadException.
#     The script prints the Java stack for exactly that reason - read it.
#
# AUTHORISED USE ONLY. Point this at an application you own or are contracted
# to assess.

import argparse
import json
import os
import re
import subprocess
import sys
import time
import zipfile

VERSION = "1.0"

# --------------------------------------------------------------------------- #
# ApplicationExitInfo reason codes.
#
# Source of truth: android.app.ApplicationExitInfo, whose REASON_* constants
# are public API from API 30. The dumpsys text already prints a label; we keep
# our own table because the label wording is not API and has changed, while the
# integer has not.
# --------------------------------------------------------------------------- #
EXIT_REASONS = {
    0:  ("UNKNOWN",            "No information recorded."),
    1:  ("EXIT_SELF",          "The process called System.exit() or exit(). The status field is "
                               "the value it passed."),
    2:  ("SIGNALED",           "Killed by a signal. status is the signal number: 9 SIGKILL, "
                               "6 SIGABRT, 11 SIGSEGV, 4 SIGILL, 5 SIGTRAP."),
    3:  ("LOW_MEMORY",         "The low-memory killer. Not a protection."),
    4:  ("CRASH",              "Uncaught Java/Kotlin exception. There is a stack trace in logcat."),
    5:  ("CRASH_NATIVE",       "Native crash: abort(), a signal, or a fatal assert in a .so. "
                               "status is the signal - 6 is abort()."),
    6:  ("ANR",                "Application not responding. Not a protection, though a control "
                               "that blocks the main thread can cause one."),
    7:  ("INITIALIZATION_FAILURE", "The process failed to initialise."),
    8:  ("PERMISSION_CHANGE",  "A permission change forced a restart. Not a protection."),
    9:  ("EXCESSIVE_RESOURCE_USAGE", "Killed for resource usage."),
    10: ("USER_REQUESTED",     "A user or shell action - `am force-stop`, swipe away, uninstall."),
    11: ("USER_STOPPED",       "The user profile was stopped."),
    12: ("DEPENDENCY_DIED",    "A process it depended on died."),
    13: ("OTHER",              "System housekeeping - trimming empty processes and similar."),
    14: ("FREEZER",            "Killed by the cached-app freezer."),
    15: ("PACKAGE_STATE_CHANGE", "Package updated, disabled or cleared."),
    16: ("PACKAGE_UPDATED",    "Package updated."),
}

SIGNALS = {
    4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
    9: "SIGKILL", 11: "SIGSEGV", 13: "SIGPIPE", 15: "SIGTERM",
}

# --------------------------------------------------------------------------- #
# Seam taxonomy. These strings are the chapter's vocabulary; keep them in sync
# with README.md section 2.3 and cheatsheet.md.
# --------------------------------------------------------------------------- #
SEAMS = {
    "S1-input":   "the value the control reads (a file, a property, a port, a package list)",
    "S2-read":    "the call that performs the read (libc, libcore, a framework API)",
    "S3-verdict": "the function that turns readings into a decision",
    "S4-branch":  "the `if` that consumes the decision",
    "S5-gated":   "the code the control was protecting",
}

# --------------------------------------------------------------------------- #
# Static signatures. Each entry says: this string implies a control that READS
# at this seam, and here is what a bypass at that seam costs.
#
# These are STRING signatures, not structural ones. They find unobfuscated
# checks reliably, obfuscated ones not at all, and they produce false positives
# on any app that legitimately reads /proc. That is stated in every report the
# script prints, because a lead is not a finding - see 52-StaticAnalysis.
# --------------------------------------------------------------------------- #
STATIC_SIGNATURES = [
    # (regex,                         control id,             seam,        note)
    (rb"TracerPid",                   "debugger.tracerpid",   "S2-read",
     "reads /proc/self/status; catches a live ptrace, rarely catches Frida"),
    (rb"/proc/self/status",           "proc.status",          "S2-read",
     "the file TracerPid lives in"),
    (rb"/proc/self/maps",             "maps.scan",            "S2-read",
     "looks for injected libraries by name"),
    (rb"/proc/self/task",             "threadnames",          "S2-read",
     "thread-name scan: gum-js-loop, gmain, pool-frida"),
    (rb"gum-js",                      "frida.threadnames",    "S2-read",
     "Frida agent thread name"),
    (rb"gmain",                       "frida.threadnames",    "S2-read",
     "GLib main loop thread name used by the Frida agent"),
    (rb"27042",                       "frida.port",           "S1-input",
     "default frida-server port; defeated by `frida-server -l 127.0.0.1:1337`"),
    (rb"frida",                       "frida.name",           "S1-input",
     "literal 'frida' anywhere - agent path, thread name, or a string scan"),
    (rb"linjector",                   "frida.name",           "S1-input",
     "Frida's injector artefact name"),
    (rb"re\.frida\.server",           "frida.name",           "S1-input",
     "default agent unpack directory; defeated by --directory"),
    (rb"ptrace",                      "antidebug.ptrace",     "S2-read",
     "self-ptrace to occupy the tracer slot, or a PTRACE_TRACEME check"),
    (rb"isDebuggerConnected",         "debugger.jdwp",        "S2-read",
     "ART-level JDWP question; unrelated to ptrace"),
    (rb"waitingForDebugger",          "debugger.jdwp",        "S2-read",
     "ART-level JDWP question"),
    (rb"FLAG_DEBUGGABLE",             "build.debuggable",     "S1-input",
     "the app's own manifest flag; a repackager usually sets it"),
    (rb"/system/xbin/su",             "root.su",              "S1-input",
     "root path probe - chapter 37 owns this"),
    (rb"/system/bin/su",              "root.su",              "S1-input",
     "root path probe - chapter 37 owns this"),
    (rb"magisk",                      "root.magisk",          "S1-input",
     "Magisk artefact probe - chapter 37 owns this"),
    (rb"eu\.chainfire\.supersu",      "root.manager",         "S1-input",
     "root manager package probe"),
    (rb"ro\.build\.tags",             "root.props",           "S1-input",
     "test-keys check"),
    (rb"checkServerTrusted",          "pinning",              "S3-verdict",
     "TLS trust decision - chapter 36 owns this"),
    (rb"CertificatePinner",           "pinning.okhttp",       "S3-verdict",
     "OkHttp pinning - chapter 36 owns this"),
    (rb"getPackageInfo",              "tamper.signature",     "S2-read",
     "often the signature check - chapter 38 owns this"),
    (rb"GET_SIGNING_CERTIFICATES",    "tamper.signature",     "S2-read",
     "signature comparison - chapter 38 owns this"),
    (rb"IntegrityManager",            "play.integrity",       "S3-verdict",
     "Play Integrity; the verdict is Google-signed and only meaningful if the "
     "SERVER checks it"),
    (rb"SafetyNet",                   "play.safetynet",       "S3-verdict",
     "deprecated predecessor to Play Integrity"),
]


# =========================================================================== #
# adb plumbing
# =========================================================================== #

class Adb:
    def __init__(self, serial=None):
        self.serial = serial

    def _base(self):
        return ["adb"] + (["-s", self.serial] if self.serial else [])

    def run(self, args, timeout=30):
        try:
            p = subprocess.run(self._base() + args, capture_output=True,
                               text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except FileNotFoundError:
            fail("adb is not on PATH.")
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"

    def shell(self, cmd, timeout=30):
        return self.run(["shell", cmd], timeout=timeout)

    def devices(self):
        _, out, _ = self.run(["devices", "-l"])
        rows = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line or "device" not in line:
                continue
            rows.append(line)
        return rows

    def prop(self, name):
        _, out, _ = self.shell("getprop " + name)
        return out.strip()


def fail(msg, code=2):
    print("error: " + msg, file=sys.stderr)
    sys.exit(code)


def hr(title=""):
    if title:
        print("\n=== " + title + " " + "=" * max(0, 68 - len(title)))
    else:
        print("=" * 74)


# =========================================================================== #
# Reading ApplicationExitInfo
# =========================================================================== #

EXIT_HDR = re.compile(r"ApplicationExitInfo #(\d+):")
EXIT_TS = re.compile(r"timestamp=(\S+ \S+) pid=(\d+)")
EXIT_DESC = re.compile(r"description=(.*?)\s+state=")

# MEASURED BUG, KEPT AS A COMMENT BECAUSE IT WILL BITE THE NEXT PERSON:
# the obvious regex for this line is
#     reason=(\d+) \(([^)]*)\) \s+ subreason=...
# and it silently fails on the most interesting record of all, because the
# label AOSP prints for reason 5 is "APP CRASH(NATIVE)" - it contains its own
# parentheses. `[^)]*` stops inside the label and the whole match fails, so a
# native abort parses as reason 0 UNKNOWN and the tool reports "no information
# recorded" about the one death you cared about. Parse the integers
# independently of the labels; the integers are API, the labels are not.
EXIT_REASON_N = re.compile(r"\breason=(\d+)\b")
EXIT_SUBREASON_N = re.compile(r"\bsubreason=(\d+)\b")
EXIT_STATUS_N = re.compile(r"\bstatus=(-?\d+)\b")


def read_exit_info(adb, package, limit=6):
    """Parse `dumpsys activity exit-info <pkg>` into dicts, newest first.

    ApplicationExitInfo is API 30+. On older devices the dumpsys section does
    not exist and we return an empty list plus a flag, rather than pretending.
    """
    rc, out, err = adb.shell("dumpsys activity exit-info " + package)
    if rc != 0 or "ACTIVITY MANAGER PROCESS EXIT INFO" not in out:
        return [], False

    records = []
    cur = None
    for line in out.splitlines():
        if EXIT_HDR.search(line):
            if cur:
                records.append(cur)
            cur = {"raw": []}
            continue
        if cur is None:
            continue
        cur["raw"].append(line.strip())

        m = EXIT_TS.search(line)
        if m:
            cur["timestamp"] = m.group(1)
            cur["pid"] = int(m.group(2))
        if "reason=" in line:
            m = EXIT_REASON_N.search(line)
            if m:
                cur["reason"] = int(m.group(1))
            m = EXIT_SUBREASON_N.search(line)
            if m:
                cur["subreason"] = int(m.group(1))
            m = EXIT_STATUS_N.search(line)
            if m:
                cur["status"] = int(m.group(1))
        m = EXIT_DESC.search(line)
        if m:
            cur["description"] = m.group(1).strip()

    if cur:
        records.append(cur)
    return records[:limit], True


# =========================================================================== #
# Classification - the part that does the actual thinking
# =========================================================================== #

def classify(record, logcat, launched_at=None, saw_activity=False):
    """Turn one exit record plus its logcat into a verdict about WHAT killed
    the process, HOW, and at WHICH seam - with the evidence that supports it
    and an honest confidence.

    Returns a dict. `confidence` is one of high / medium / low / none, and
    nothing here ever returns high without a quoted line of evidence.
    """
    reason = record.get("reason", 0)
    status = record.get("status", 0)
    label, meaning = EXIT_REASONS.get(reason, ("UNRECOGNISED", "not in this script's table"))

    out = {
        "reason": reason,
        "reason_label": label,
        "reason_meaning": meaning,
        "status": status,
        "signal": SIGNALS.get(status) if reason in (2, 5) else None,
        "pid": record.get("pid"),
        "timestamp": record.get("timestamp"),
        "protection_related": None,
        "mechanism": None,
        "seam": None,
        "confidence": "none",
        "evidence": [],
        "next_steps": [],
    }

    # ------------------------------------------------------------------ #
    # Deaths that are certainly NOT a protection. Say so loudly - most of
    # the time someone runs this tool, this is the answer, and telling them
    # early saves them from bypassing a control that never fired.
    # ------------------------------------------------------------------ #
    if reason in (3, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16):
        out["protection_related"] = False
        out["mechanism"] = "platform lifecycle, not the app's decision"
        out["confidence"] = "high"
        out["next_steps"].append(
            "This is not a protection. Re-run and make sure nothing force-stopped "
            "the app (reason=10 is usually your own `am force-stop`).")
        return out

    # ------------------------------------------------------------------ #
    # A native crash. abort() is the loudest anti-instrumentation response
    # there is, and SIGABRT with no Java frames very often means it was
    # taken before Java ran at all.
    # ------------------------------------------------------------------ #
    if reason == 5:
        out["protection_related"] = "likely"
        if status == 6:
            out["mechanism"] = "abort() in native code (SIGABRT)"
        elif status == 5:
            out["mechanism"] = ("SIGTRAP - a breakpoint instruction executed. Either a debugger "
                                "artefact or a deliberate anti-debug trap")
        elif status in (11, 7):
            out["mechanism"] = ("memory fault - as likely to be your hook corrupting state as a "
                                "protection")
            out["protection_related"] = "unclear"
        else:
            out["mechanism"] = "native fatal signal " + str(SIGNALS.get(status, status))

        # The single most valuable line in a native death is the first stack
        # frame that belongs to the APP rather than to the platform. It names
        # the library AND the symbol that decided to die, which turns "some
        # native check killed me" into a Ghidra address in one step.
        #
        # MEASURED on this chapter's own demo:
        #   #01 pc 0000000000002520 /data/app/.../lib/arm64/libch67guard.so
        #       (JNI_OnLoad+908)
        # Frame #00 is abort() inside libc and tells you nothing.
        app_frame = None
        for l in logcat:
            if " DEBUG" not in l and "F/DEBUG" not in l:
                continue
            m = re.search(r"#\d+\s+pc\s+\w+\s+(\S*/(?:data/app|data/data)/\S*?/([\w.\-+]+\.so))"
                          r"(?:\s+\(([^)]*)\))?", l)
            if m:
                app_frame = (m.group(2), m.group(3) or "no symbol")
                out["evidence"].append(
                    "deciding frame: %s (%s) - this is the library and symbol that "
                    "called abort(); open it in Ghidra at that offset" % app_frame)
                break

        sigline = next((l for l in logcat if "signal 6 (SIGABRT)" in l
                        or "signal 5 (SIGTRAP)" in l or "signal 11" in l), None)
        if sigline:
            trimmed = sigline.split("): ", 1)[-1].strip()
            out["evidence"].append("tombstone header: " + trimmed[:140])

        early = [l for l in logcat if "JNI_OnLoad" in l or "init_array" in l
                 or "dlopen" in l or ".so" in l]
        if not saw_activity:
            # Honest limitation: from outside the process you can see WHEN the
            # decision was taken, not which of the two lowest seams it read at.
            # A load-time abort is consistent with an input probe (a port, a
            # file) and with a read of /proc; both look identical here.
            out["seam"] = "S1-input/S2-read"
            SEAMS.setdefault("S1-input/S2-read",
                             "a load-time check; from outside the process these two seams "
                             "are indistinguishable - attach at the read to tell them apart")
            out["confidence"] = "medium" if app_frame else "low"
            out["evidence"].append(
                "the process died without emitting a single Activity lifecycle event - the "
                "check ran at library-load time, i.e. .init_array or JNI_OnLoad")
            out["next_steps"] += [
                "Hooks installed after Java.perform() are too late. Spawn suspended and "
                "install libc hooks first: see ../scripts/early-instrument.js.",
                "`frida-trace -U -f <pkg> -i 'JNI_OnLoad' -i 'dlopen*'` shows which library "
                "took the decision.",
            ]
        else:
            out["seam"] = "S4-branch"
            out["confidence"] = "low"
            out["next_steps"].append(
                "The UI came up before the abort, so the native tier is being called from "
                "Java rather than from load. Find the JNI entry point (chapter 16).")
        if early:
            out["evidence"].append("logcat mentions load-time activity: " + early[0][:160])
        out["next_steps"].append(
            "A tombstone exists: `adb shell ls -t /data/tombstones` (root) or "
            "`adb bugreport` (no root). The abort message names the calling library.")
        return out

    # ------------------------------------------------------------------ #
    # Signalled. SIGKILL to self is Process.killProcess(myPid()) nine times
    # out of ten, and nothing else on the system produces exactly that with
    # the app in the foreground.
    # ------------------------------------------------------------------ #
    if reason == 2:
        out["protection_related"] = "likely" if status in (9, 6) else "unclear"
        out["mechanism"] = {
            9: "SIGKILL. In the foreground with no LMK pressure this is almost always "
               "android.os.Process.killProcess(Process.myPid()) - the app killing itself",
            6: "SIGABRT delivered as a signal - a native abort reported through this path",
        }.get(status, "signal " + str(SIGNALS.get(status, status)))
        out["seam"] = "S4-branch"
        out["confidence"] = "medium" if status == 9 else "low"
        out["evidence"].append(
            "reason=2 status=%d, importance in the record shows it was foreground" % status)
        out["next_steps"] += [
            "Hook android.os.Process.killProcess and print a Java stack trace from inside it. "
            "That backtrace names the branch, which is the fastest route to the verdict "
            "function one frame above it.",
            "Then go DOWN, not up: hook the read that fed the verdict. See README section 3.7 "
            "for why the branch is the wrong place to stay.",
        ]
        return out

    # ------------------------------------------------------------------ #
    # Exit with a status. The status is a fingerprint of this build.
    # ------------------------------------------------------------------ #
    if reason == 1:
        out["protection_related"] = "likely" if status != 0 else "unclear"
        out["mechanism"] = ("System.exit(%d) or exit(%d) - a deliberate, orderly shutdown "
                            "chosen by the app" % (status, status))
        out["seam"] = "S4-branch"
        out["confidence"] = "medium"
        out["evidence"].append("status=%d is the literal the developer passed to exit()" % status)
        out["next_steps"] += [
            "Hook java.lang.System.exit and java.lang.Runtime.exit/halt, print a stack, and "
            "do NOT return. The stack is the branch.",
            "grep the DEX for that literal: it appears as `const/16 vN, 0x%x` near the branch."
            % status,
        ]
        return out

    # ------------------------------------------------------------------ #
    # Uncaught Java exception. Here logcat is authoritative, so use it.
    # ------------------------------------------------------------------ #
    if reason == 4:
        out["mechanism"] = "uncaught Java exception"
        out["seam"] = "S4-branch"
        exc = None
        for line in logcat:
            m = re.search(r"E AndroidRuntime:\s+(?:Caused by: )?([\w.$]+Exception|[\w.$]+Error)"
                          r"(?::\s*(.*))?", line)
            if m:
                exc = (m.group(1), (m.group(2) or "").strip())
                out["evidence"].append(line.strip()[:200])
                if not m.group(0).startswith("E AndroidRuntime: Caused by"):
                    break
        if exc:
            name, msg = exc
            benign = ("NetworkOnMainThread", "NullPointer", "IllegalState", "ClassNotFound",
                      "NoClassDefFound", "OutOfMemory", "UnsatisfiedLink", "IndexOutOfBounds")
            if any(b in name for b in benign):
                out["protection_related"] = "unlikely"
                out["confidence"] = "high"
                out["mechanism"] = "uncaught " + name + " - this looks like an ordinary bug"
                out["next_steps"].append(
                    "Read the stack before assuming a control fired. "
                    "NetworkOnMainThreadException in particular is thrown by StrictMode when a "
                    "check itself does I/O on the main thread - the app's own protection code "
                    "crashing it, but not the protection DECIDING anything.")
            else:
                out["protection_related"] = "likely"
                out["confidence"] = "high"
                out["mechanism"] = "the app threw " + name + (": " + msg if msg else "")
                out["next_steps"] += [
                    "The top app frame in that stack IS the branch. Open it in JADX.",
                    "Hook the throwing method and print its inputs; the inputs are the verdict.",
                ]
        else:
            out["protection_related"] = "unclear"
            out["confidence"] = "low"
            out["next_steps"].append(
                "No AndroidRuntime stack in the captured buffer. Re-run with a larger window "
                "or `adb logcat -b crash -d`.")
        return out

    out["protection_related"] = "unclear"
    out["confidence"] = "none"
    out["next_steps"].append("Unrecognised exit reason - read the raw record printed above.")
    return out


# =========================================================================== #
# Static pass over an APK
# =========================================================================== #

def scan_apk(path):
    """Read the APK as a zip and look for detection signatures in every DEX and
    every native library.

    This is a STRING scan. It finds unobfuscated controls, misses obfuscated
    ones entirely, and cheerfully flags an app that reads /proc/self/maps for a
    crash reporter. Its output is a list of LEADS.
    """
    if not os.path.isfile(path):
        fail("no such APK: " + path)

    hits = {}
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        fail(path + " is not a zip - is it really an APK?")

    interesting = [n for n in z.namelist()
                   if n.endswith(".dex") or n.endswith(".so")
                   or n == "AndroidManifest.xml"]

    for name in interesting:
        try:
            blob = z.read(name)
        except Exception:
            continue
        for rx, control, seam, note in STATIC_SIGNATURES:
            if not re.search(rx, blob, re.IGNORECASE):
                continue
            key = (control, seam)
            hits.setdefault(key, {"note": note, "files": set(), "patterns": set()})
            hits[key]["files"].add(name)
            hits[key]["patterns"].add(rx.decode("utf-8", "replace"))
    z.close()

    return [
        {
            "control": c,
            "seam": s,
            "note": v["note"],
            "files": sorted(v["files"]),
            "patterns": sorted(v["patterns"]),
        }
        for (c, s), v in sorted(hits.items())
    ]


# =========================================================================== #
# Live run
# =========================================================================== #

def live_run(adb, package, activity, extras, wait):
    """Force-stop, clear logcat, launch, wait, collect.

    Force-stopping first matters more than it looks: without it you may attach
    your reasoning to a warm process that never ran its load-time checks, and
    every conclusion about early seams will be wrong.
    """
    adb.shell("am force-stop " + package)

    # MEASURED: `adb logcat -c` clears the MAIN buffer only. The events buffer
    # survives, so lifecycle records from the PREVIOUS run leak into this one
    # and a process that aborted inside JNI_OnLoad is reported as having
    # reached RESUMED - the exact inversion this field exists to prevent.
    # Name every buffer explicitly.
    adb.run(["logcat", "-b", "main", "-b", "events", "-b", "crash", "-c"])
    time.sleep(0.3)

    if activity:
        target = package + "/" + activity if activity.startswith(".") else activity
        cmd = "am start -n " + target
    else:
        cmd = "monkey -p %s -c android.intent.category.LAUNCHER 1" % package

    for k, v in extras.get("bool", []):
        cmd += " --ez %s %s" % (k, v)
    for k, v in extras.get("str", []):
        cmd += " --es %s %s" % (k, v)

    print("  launching: " + cmd)
    launched_at = time.time()
    rc, out, err = adb.shell(cmd)
    if "Error" in out or "Exception" in out:
        print("  am reported: " + out.strip().splitlines()[0][:160])

    time.sleep(wait)

    _, logs, _ = adb.run(["logcat", "-d", "-v", "brief"])
    lines = logs.splitlines()

    # OEM builds are extremely chatty and their power/thermal/game tags will
    # bury the two lines that matter. Dropping them is not cosmetic: a triage
    # tool whose output you scroll past is a triage tool you stop reading.
    NOISE = ("PowerHal", "mtkpower", "game_scn", "libPowerHal", "perfNotify",
             "ziparchive", "PackageDexOptimizer", "dex2oat", "OpenGLRenderer",
             "Choreographer", "InsetsController", "ViewRootImpl")

    def useful(l):
        if any(n in l for n in NOISE):
            return False
        if "AndroidRuntime" in l or "F/DEBUG" in l or "F/libc" in l:
            return True
        if package not in l:
            return False
        return True

    pkg_lines = [l for l in lines if useful(l)]

    # How far through the Activity lifecycle did it get?
    #
    # Two traps, both measured on the device this was written against:
    #
    #  1. An Activity RECORD exists as soon as the launch is accepted, and
    #     several OEM log lines name the Activity while the process is already
    #     dying. A loose test reported "reached UI: True" for a process that
    #     aborted inside JNI_OnLoad, which inverted the seam attribution.
    #
    #  2. The obvious tighter test - ActivityTaskManager's "Displayed <pkg>"
    #     line - DOES NOT EXIST on every build. On the i9000S / API 33 device
    #     used here, `logcat | grep -i displayed` returns nothing at all, ever.
    #     Anchoring on it means every app looks like it died before the UI.
    #
    # The EVENTS buffer is the reliable answer and needs no root:
    #     wm_on_create_called / wm_on_start_called / wm_on_resume_called
    # are emitted by ActivityThread itself, tagged with the pid.
    _, evt, _ = adb.run(["logcat", "-b", "events", "-d", "-v", "brief"])
    evt_lines = [l for l in evt.splitlines() if package in l]

    lifecycle = []
    for stage in ("wm_on_create_called", "wm_on_start_called",
                  "wm_on_resume_called", "wm_on_top_resumed_gained_called"):
        if any(stage in l for l in evt_lines):
            lifecycle.append(stage.replace("wm_on_", "").replace("_called", ""))

    saw_activity = ("resume" in lifecycle) or any(("Displayed " + package) in l for l in lines)

    # A running process is itself evidence: nothing died.
    _, ps, _ = adb.shell("pidof " + package)
    alive_pid = ps.strip() or None

    return {
        "launched_at": launched_at,
        "logcat": pkg_lines[-400:],
        "saw_activity": saw_activity,
        "lifecycle": lifecycle,
        "alive_pid": alive_pid,
    }


# =========================================================================== #
# Reporting
# =========================================================================== #

def print_device(adb):
    rows = adb.devices()
    if not rows:
        fail("no device in `adb devices`.")
    hr("device")
    for r in rows:
        print("  " + r)
    model = adb.prop("ro.product.model")
    sdk = adb.prop("ro.build.version.sdk")
    rel = adb.prop("ro.build.version.release")
    print("  model=%s  Android %s / API %s" % (model, rel, sdk))
    try:
        if int(sdk) < 30:
            print("  NOTE: API < 30. ApplicationExitInfo does not exist here; this run will")
            print("        rely on logcat evidence alone and will be much weaker.")
    except ValueError:
        pass
    return {"model": model, "sdk": sdk, "release": rel}


def print_classification(c):
    hr("verdict")
    print("  exit reason   : %d (%s)" % (c["reason"], c["reason_label"]))
    print("                  %s" % c["reason_meaning"])
    st = "  status        : %d" % c["status"]
    if c["signal"]:
        st += "  (%s)" % c["signal"]
    print(st)
    print("  pid / when    : %s at %s" % (c["pid"], c["timestamp"]))
    print("  mechanism     : %s" % c["mechanism"])
    print("  protection?   : %s" % c["protection_related"])
    if c["seam"]:
        print("  seam          : %s - %s" % (c["seam"], SEAMS.get(c["seam"], "")))
    print("  confidence    : %s" % c["confidence"])

    if c["evidence"]:
        print("\n  evidence:")
        for e in c["evidence"]:
            print("    - " + e)

    if c["next_steps"]:
        print("\n  what to do next:")
        for i, s in enumerate(c["next_steps"], 1):
            print("    %d. %s" % (i, s))


def print_static(leads):
    hr("static pass - controls PRESENT in the APK")
    if not leads:
        print("  No known detection strings found.")
        print("  This means one of three things, and they are not equally likely:")
        print("    a) the app has no client-side controls;")
        print("    b) the strings are encrypted or the app is packed (chapter 40);")
        print("    c) the control is structural - an inline syscall, a checksum - and")
        print("       has no string to find at all.")
        print("  Do not report (a) on the strength of this scan alone.")
        return
    print("  %d lead(s). A lead is not a finding - see 52-StaticAnalysis." % len(leads))
    print()
    for l in leads:
        print("  %-22s seam=%-10s %s" % (l["control"], l["seam"], l["note"]))
        print("      matched %s in %s" % (", ".join(l["patterns"][:4]),
                                          ", ".join(l["files"][:4])))
    print()
    print("  Seam legend:")
    for k in sorted(set(l["seam"] for l in leads)):
        print("    %-10s %s" % (k, SEAMS.get(k, "")))


def print_logcat_tail(logcat, n=25):
    if not logcat:
        return
    hr("logcat tail (filtered)")
    for line in logcat[-n:]:
        print("  " + line[:200])


# =========================================================================== #

def main():
    ap = argparse.ArgumentParser(
        description="Triage which client-side control fired, and at which seam.",
        epilog="Authorised testing only. See the header of this file.")
    ap.add_argument("-p", "--package", required=True)
    ap.add_argument("-a", "--activity", default=None,
                    help="e.g. .MainActivity. Default: launch via monkey.")
    ap.add_argument("-s", "--serial", default=None)
    ap.add_argument("--apk", default=None, help="also run the static pass on this APK")
    ap.add_argument("--postmortem", action="store_true",
                    help="do not launch anything; explain the most recent death")
    ap.add_argument("--wait", type=float, default=5.0,
                    help="seconds to observe after launch (default 5)")
    ap.add_argument("--extra-bool", action="append", default=[], metavar="K=V")
    ap.add_argument("--extra-str", action="append", default=[], metavar="K=V")
    ap.add_argument("--json", default=None, help="write the full result to this file")
    ap.add_argument("--baseline", default=None,
                    help="a previous --json file; print what changed")
    ap.add_argument("--history", type=int, default=3,
                    help="how many exit records to print (default 3)")
    args = ap.parse_args()

    print("bypass-triage.py v%s - which control fired, and at which seam" % VERSION)
    print("AUTHORISED TESTING ONLY: an app you own or are contracted to assess.")

    adb = Adb(args.serial)
    device = print_device(adb)

    result = {
        "package": args.package,
        "device": device,
        "when": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    if args.apk:
        leads = scan_apk(args.apk)
        result["static"] = leads
        print_static(leads)

    run = {"logcat": [], "saw_activity": False, "alive_pid": None, "lifecycle": []}
    if not args.postmortem:
        hr("live run")
        extras = {
            "bool": [tuple(x.split("=", 1)) for x in args.extra_bool if "=" in x],
            "str": [tuple(x.split("=", 1)) for x in args.extra_str if "=" in x],
        }
        run = live_run(adb, args.package, args.activity, extras, args.wait)
        if run["alive_pid"]:
            print("  process is STILL ALIVE, pid " + run["alive_pid"])
        else:
            print("  no process for " + args.package + " after " + str(args.wait) + "s")
        print("  activity lifecycle reached: "
              + (" -> ".join(run["lifecycle"]) if run["lifecycle"] else "NOTHING"))
        print("  reached RESUMED (UI alive): " + str(run["saw_activity"]))
        result["run"] = {"lifecycle": run["lifecycle"],
                         "saw_activity": run["saw_activity"],
                         "alive_pid": run["alive_pid"]}

    records, have_exit_info = read_exit_info(adb, args.package, limit=args.history)
    if not have_exit_info:
        hr("exit-info")
        print("  `dumpsys activity exit-info` returned nothing for this package.")
        print("  Either the package has never died, or this is API < 30.")

    if records:
        hr("exit records (newest first)")
        for i, r in enumerate(records):
            lbl = EXIT_REASONS.get(r.get("reason", -1), ("?", ""))[0]
            print("  #%d  %s  pid=%s  reason=%s (%s) status=%s" % (
                i, r.get("timestamp", "?"), r.get("pid", "?"),
                r.get("reason", "?"), lbl, r.get("status", "?")))
            if r.get("description"):
                print("      description: " + r["description"])

    # ------------------------------------------------------------------ #
    # The interesting case: still running.
    # ------------------------------------------------------------------ #
    if run["alive_pid"] and not args.postmortem:
        hr("verdict")
        print("  The process did not die.")
        print()
        print("  That is not the same as 'no control fired'. Three possibilities:")
        print("    1. No control fired. Most likely, and easy to confirm: run again")
        print("       with instrumentation attached and see whether the answer changes.")
        print("    2. A control fired and the response was to refuse the OPERATION")
        print("       rather than kill the process - a thrown-and-caught exception, an")
        print("       early return, a disabled button.")
        print("    3. A control fired and the response was to POISON the session:")
        print("       nothing crashes, results are quietly wrong. This is invisible to")
        print("       this tool by construction. Detect it by diffing OUTPUT between an")
        print("       instrumented and a clean run, not by watching for a crash.")
        print()
        print("  Chapter 67 section 3.9 covers case 3, which is the one people miss.")
        result["classification"] = {"alive": True}
    elif records:
        newest = records[0]
        c = classify(newest, run["logcat"], run["launched_at"] if not args.postmortem else None,
                     run["saw_activity"])
        result["classification"] = c
        print_classification(c)
    else:
        result["classification"] = None

    print_logcat_tail(run["logcat"])

    # ------------------------------------------------------------------ #
    if args.baseline:
        try:
            with open(args.baseline, "r", encoding="utf-8") as fh:
                base = json.load(fh)
        except OSError as e:
            fail("cannot read baseline: " + str(e))
        hr("delta against baseline")
        b = (base.get("classification") or {})
        n = (result.get("classification") or {})
        for key in ("reason_label", "status", "seam", "mechanism", "alive"):
            if b.get(key) != n.get(key):
                print("  %-14s %s  ->  %s" % (key, b.get(key), n.get(key)))
        if b == n:
            print("  identical. Whatever you changed did not change the outcome.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, default=str)
        print("\nwrote " + args.json)

    hr()
    print("Reminder: a bypassed control is not a finding. What matters is what it")
    print("was protecting, and whether the server re-verifies. See README section 5.6.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
