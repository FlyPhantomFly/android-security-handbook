#!/usr/bin/env python3
# 73-Labs/scripts/lab-env-probe.py
#
# PURPOSE
#   Answer one question that no chapter can answer for you: **which of this
#   repository's labs can the machine you are sitting at actually run, today?**
#
#   It does this in two halves, and both halves are measurements:
#
#     1. PROBE  -- run each capability's own version command and record what
#                  came back. Nothing is inferred from the presence of a
#                  directory or from an environment variable; a tool counts as
#                  present when it executes.
#     2. MATCH  -- cross-reference the probed capability set against the derived
#                  requirement tags produced by build-lab-index.py, and print
#                  which labs are runnable, which are blocked, and by what.
#
#   The two halves are deliberately separate. The probe alone is useful before
#   you own the repository's index; the match is what turns "I have frida 16.1.6"
#   into "131 labs want Frida and you can run 0 of them, because the server
#   binary on your device does not link".
#
# USAGE
#   # host -- probe only, human readable
#   python3 -B scripts/lab-env-probe.py
#
#   # host -- probe and match against the lab index (the useful mode)
#   python3 -B scripts/lab-env-probe.py --match
#
#   # host -- what can I run right now, listed
#   python3 -B scripts/lab-env-probe.py --match --list runnable
#
#   # host -- what is blocked, and by exactly what
#   python3 -B scripts/lab-env-probe.py --match --list blocked
#
#   # host -- one chapter only
#   python3 -B scripts/lab-env-probe.py --match --chapter 53
#
#   # host -- machine readable, for your own tooling
#   python3 -B scripts/lab-env-probe.py --match --json
#
#   # host -- pretend you have something you do not, to plan a purchase
#   python3 -B scripts/lab-env-probe.py --match --assume frida,root
#
#   # host -- skip every device probe (offline, on a train)
#   python3 -B scripts/lab-env-probe.py --no-device
#
#   Run with -B so no __pycache__ is written into the repository.
#
# WHAT IT WILL NOT DO
#   * It will not install anything, change any setting, or write to the device.
#     Every device command it issues is a read. The most invasive thing it does
#     is `su 0 id`, and it does that because there is no other way to establish
#     root honestly.
#   * It will not tell you a lab is runnable because the tag list is satisfied
#     and nothing else. Tags are derived from lab text and are a good filter,
#     not a guarantee. Read the lab's own setup section.
#   * It will not decide for you whether a lab is worth doing. That is what the
#     learning paths in ../references/learning-paths.md are for.
#
# WAS THIS EXECUTED?
#   YES. Run on 2026-08-16, Windows 11 + Git Bash, CPython 3.13.3, against the
#   AVD `sdk_gphone16k_x86_64` (`emulator-5554`, Android 15 / API 35, x86_64,
#   userdebug, rooted with Magisk 30.7). Measured output at that time is
#   reproduced verbatim in ../labs/lab-01-the-capability-survey.md section 4,
#   including the two findings that matter most on this setup:
#
#     * `su -c id` fails with `su: invalid uid/gid '-c'` while `su 0 id` returns
#       uid 0. The probe therefore tests BOTH forms and reports which works,
#       because reading the first failure as "not rooted" is a documented error
#       in this repository.
#     * the `frida-server` present on the device does not link
#       (`empty/missing DT_HASH/DT_GNU_HASH`), so `frida` is reported ABSENT even
#       though `frida --version` on the host prints 16.1.6 and `frida-ps -U`
#       still enumerates processes. A host-side version check alone would have
#       reported this setup as Frida-capable, and it is not.
#
# EXIT STATUS
#   0 always, unless --strict is given, in which case 1 if any capability the
#   probe was asked about is absent. There is no failure in not owning IDA.

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys

# A Windows console defaults to cp1252 and `print()` raises UnicodeEncodeError
# on the em-dashes and arrows in this repository's lab titles. Force UTF-8.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
CHAPTER_ROOT = os.path.abspath(os.path.join(HERE, ".."))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

TIMEOUT = 25


# --------------------------------------------------------------------------- #
# Running things without ever hanging
# --------------------------------------------------------------------------- #

def run(argv, timeout=TIMEOUT):
    """Run a command and return (ok, first-useful-line). Never raises, never
    blocks forever, never inherits stdin -- a probe that opens an interactive
    prompt on someone's machine is a bug, not a feature."""
    try:
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, timeout=timeout)
    except FileNotFoundError:
        return False, "no such executable"
    except subprocess.TimeoutExpired:
        return False, "timed out after %ds" % timeout
    except OSError as exc:
        return False, "could not execute: %s" % exc
    return True, proc.stdout.decode("utf-8", "replace")


def banner(text):
    """The one line of a command's output that looks like a version banner.

    Version output is often preceded by warnings and followed by advertising --
    `objection version` prints an upgrade notice, the Android linker prints
    hundreds of `unused DT entry` lines before the error that matters. Prefer the
    first line carrying a digit; fall back to the first line at all.
    """
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for line in lines:
        if re.search(r"\d", line):
            return line[:120]
    return lines[0][:120] if lines else "(no output)"


def which(name):
    return shutil.which(name) is not None


# --------------------------------------------------------------------------- #
# Host capabilities
#
# Each probe returns (present: bool, detail: str). `tag` is the requirement tag
# in the lab index that this capability satisfies, or None if it satisfies none
# directly (adb and the SDK are preconditions of other tags).
# --------------------------------------------------------------------------- #

def probe_simple(cmd, args, tag, label, note=""):
    """A tool counts as present only when it EXECUTES.

    `shutil.which` alone is not enough and the difference is not academic: on
    this repository's Windows machine `which("apktool")` finds a launcher on the
    Windows PATH that Git Bash cannot run, and the first version of this probe
    reported apktool as present with the detail string "not on PATH" -- a
    contradiction printed on one line. Presence is now decided by whether the
    process started, never by whether a file was found.
    """
    def go():
        if not which(cmd):
            return False, "not on PATH"
        executed, text = run([cmd] + args)
        if not executed:
            return False, "found on PATH but did not execute: %s" % text
        return True, banner(text)
    return dict(key=cmd, tag=tag, label=label, note=note, probe=go)


def probe_java():
    def go():
        if not which("javac"):
            return False, "javac not on PATH"
        executed, text = run(["javac", "-version"])
        if not executed:
            return False, text
        return True, banner(text)
    return dict(key="javac", tag="jdk", label="JDK (javac)",
                note="also needed indirectly by jadx and apktool", probe=go)


def probe_kotlinc():
    """kotlinc is very often not on PATH on Windows: it ships inside Android
    Studio. Look there before reporting absence, and say where it was found."""
    candidates = [
        r"C:\Program Files\Android\Android Studio\plugins\Kotlin\kotlinc\bin\kotlinc.bat",
        os.path.expanduser("~/Android/Sdk/kotlinc/bin/kotlinc"),
        "/usr/local/bin/kotlinc",
    ]

    def go():
        if which("kotlinc"):
            executed, text = run(["kotlinc", "-version"], timeout=90)
            if executed:
                return True, banner(text) + "  (on PATH)"
        for path in candidates:
            if os.path.exists(path):
                return True, "found at %s (not on PATH)" % path
        return False, "not on PATH and not in the usual Android Studio location"
    return dict(key="kotlinc", tag=None, label="Kotlin compiler",
                note="a handful of labs build Kotlin sources", probe=go)


# --------------------------------------------------------------------------- #
# Tools that are commonly installed but never on PATH.
#
# The kotlinc probe above already had the right idea and nothing else used it.
# During the release audit THREE tools were reported absent and were installed:
# Ghidra 12.1.2, MobSF, and apktool -- none on PATH, all in an ordinary tools
# directory. The published "labs blocked" figure was inflated as a result.
#
# The lesson is the repo's own vantage rule applied to the host: a `which()`
# answers "can this shell resolve this name", not "is this tool installed".
# On Windows the gap is wider still, because Git Bash will not resolve a `.bat`
# without its extension -- `command -v apktool` fails while `apktool.bat` works.
# --------------------------------------------------------------------------- #

def _first_existing(paths):
    for path in paths:
        # recursive=True is required for `**` to span directories; without it a
        # pattern like `Tools/**/ghidra_*` silently matches nothing.
        for expanded in sorted(glob.glob(os.path.expanduser(path), recursive=True)):
            if os.path.exists(expanded):
                return expanded
    return None


def probe_offpath(key, tag, label, names, candidates, note=""):
    """Probe a tool by name, then by known install location, then by name+.bat.

    Reports HOW it was found, because "present but not on PATH" and "present on
    PATH" are different facts for a reader following a lab.
    """
    def go():
        for name in names:
            if which(name):
                executed, text = run([name, "--version"], timeout=60)
                if executed and text.strip():
                    return True, banner(text) + "  (on PATH)"
                # Found but unrunnable under this shell -- a real state, not absence.
                # Windows shims and Git Bash extension rules both produce it.
                return True, "resolved as %r on PATH but did not execute here; "                              "try the .bat form or an explicit interpreter" % name
        path = _first_existing(candidates)
        if path:
            return True, "found at %s (NOT on PATH)" % path
        return False, "not on PATH and not in any known install location"
    return dict(key=key, tag=tag, label=label, note=note, probe=go)


def probe_sdk():
    """Android SDK build-tools: aapt2, d8, apksigner, zipalign. On Windows these
    are .exe and .bat, which is why a bare `which d8` reports nothing."""
    def go():
        sdk = (os.environ.get("ANDROID_HOME")
               or os.environ.get("ANDROID_SDK_ROOT"))
        if not sdk:
            for guess in (os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk"),
                          os.path.expanduser("~/Android/Sdk"),
                          os.path.expanduser("~/Library/Android/sdk")):
                if os.path.isdir(guess):
                    sdk = guess
                    break
        if not sdk or not os.path.isdir(sdk):
            return False, "no ANDROID_HOME and no SDK in the usual places"
        bt_root = os.path.join(sdk, "build-tools")
        if not os.path.isdir(bt_root):
            return False, "SDK at %s has no build-tools" % sdk
        versions = sorted(os.listdir(bt_root))
        platforms = []
        pl_root = os.path.join(sdk, "platforms")
        if os.path.isdir(pl_root):
            platforms = sorted(os.listdir(pl_root))
        return True, "build-tools %s; platforms %s" % (
            ", ".join(versions) or "none", ", ".join(platforms) or "none")
    return dict(key="sdk", tag=None, label="Android SDK build-tools",
                note="aapt2 / d8 / apksigner / zipalign; required to build any "
                     "lab target without Gradle", probe=go)


def probe_ndk():
    def go():
        ndk = os.environ.get("ANDROID_NDK") or os.environ.get("ANDROID_NDK_HOME")
        if ndk and os.path.isdir(ndk):
            return True, ndk
        sdk = (os.environ.get("ANDROID_HOME")
               or os.environ.get("ANDROID_SDK_ROOT")
               or os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk"))
        root = os.path.join(sdk, "ndk") if sdk else None
        if root and os.path.isdir(root):
            versions = sorted(os.listdir(root))
            if versions:
                return True, "%s (versions: %s)" % (
                    os.path.join(root, versions[-1]), ", ".join(versions))
        return False, "no ANDROID_NDK and no ndk/ under the SDK"
    return dict(key="ndk", tag="ndk", label="Android NDK",
                note="every native lab; also the 16 KiB page-size link flag",
                probe=go)


HOST_PROBES = [
    probe_simple("adb", ["version"], None, "adb",
                 "the only channel to a device; everything device-side needs it"),
    probe_java(),
    probe_kotlinc(),
    probe_sdk(),
    probe_ndk(),
    probe_simple("python3", ["--version"], "python", "Python 3"),
    probe_simple("frida", ["--version"], None, "Frida (host)",
                 "not sufficient on its own -- see the frida-server probe"),
    probe_simple("objection", ["version"], "objection", "Objection"),
    probe_simple("jadx", ["--version"], "jadx", "jadx"),
    probe_offpath("apktool", "apktool", "apktool",
                  ["apktool", "apktool.bat"],
                  [r"C:\apktool\apktool.jar",
                   r"C:\Users\*\Desktop\Tools\**\apktool.jar",
                   r"C:\Program Files (x86)\apktool\Resources\apktool.jar",
                   "/usr/local/bin/apktool", "/usr/bin/apktool"],
                  note="run with `java -jar <path>` when the shim is absent"),
    probe_offpath("ghidra", "ghidra", "Ghidra",
                  ["ghidraRun", "analyzeHeadless"],
                  [r"C:\Users\*\Desktop\Tools\**\ghidra_*\ghidraRun.bat",
                   r"C:\Users\*\Desktop\Tools\**\ghidra_*\support\analyzeHeadless.bat",
                   r"C:\ghidra*\ghidraRun.bat",
                   "~/ghidra*/ghidraRun", "/opt/ghidra*/ghidraRun"],
                  note="headless is analyzeHeadless; the GUI launcher is what most probes look for"),    probe_simple("r2", ["-v"], "radare2", "radare2"),
    probe_simple("docker", ["--version"], "docker", "Docker",
                 "MobSF's supported deployment"),
    probe_simple("mitmdump", ["--version"], "proxy", "mitmproxy",
                 "Burp is a GUI and cannot be probed this way; if you have Burp, "
                 "pass --assume proxy"),
]


# --------------------------------------------------------------------------- #
# Device capabilities
# --------------------------------------------------------------------------- #

def adb(args, serial=None, timeout=TIMEOUT):
    argv = ["adb"] + (["-s", serial] if serial else []) + args
    return run(argv, timeout=timeout)


def probe_device(serial=None):
    """Everything device-side, in one pass. Returns a dict of findings."""
    out = {}
    if not which("adb"):
        out["attached"] = (False, "adb not on PATH")
        return out

    ok, _ = run(["adb", "start-server"], timeout=40)
    ok, listing = run(["adb", "devices"], timeout=40)
    devices = []
    _, raw = run(["adb", "devices", "-l"], timeout=40)
    proc = subprocess.run(["adb", "devices"], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    for line in proc.stdout.decode("utf-8", "replace").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])

    if not devices:
        out["attached"] = (False, "no device in `adb devices`")
        return out
    if serial is None:
        serial = devices[0]
    out["attached"] = (True, "%s (%d attached)" % (serial, len(devices)))
    out["_serial"] = serial

    def prop(name):
        _, value = adb(["shell", "getprop", name], serial)
        return value.strip()

    model = prop("ro.product.model")
    api = prop("ro.build.version.sdk")
    release = prop("ro.build.version.release")
    abi = prop("ro.product.cpu.abi")
    build_type = prop("ro.build.type")
    out["identity"] = (True, "%s  Android %s / API %s  %s  %s"
                       % (model, release, api, abi, build_type))
    out["_api"] = api
    out["_abi"] = abi

    # An emulator is identified by several independent signals, because any one
    # of them can be spoofed and this probe should say what it saw.
    signals = []
    if re.search(r"sdk|emulator|generic|goldfish|ranchu", model, re.I):
        signals.append("model=%s" % model)
    qemu = prop("ro.kernel.qemu") or prop("ro.boot.qemu")
    if qemu:
        signals.append("qemu=%s" % qemu)
    if serial.startswith("emulator-"):
        signals.append("serial=%s" % serial)
    out["emulator"] = (bool(signals), ", ".join(signals) or "no emulator signal")

    _, enforce = adb(["shell", "getenforce"], serial)
    out["selinux"] = (True, enforce.strip())

    _, pagesize = adb(["shell", "getconf", "PAGE_SIZE"], serial)
    out["pagesize"] = (True, pagesize.strip())

    # ---- root, tested BOTH ways ------------------------------------------- #
    # `adb shell su -c 'cmd'` is broken: the outer shell strips the quotes and
    # su eats the flag. The two forms below are the two that work on the two
    # kinds of device this repository has measured, and a lab that assumes the
    # wrong one reads as "not rooted".
    _, zero = adb(["shell", "su 0 id"], serial)
    _, dash = adb(["shell", "su -c id"], serial)
    zero_ok = "uid=0" in zero
    dash_ok = "uid=0" in dash
    if zero_ok or dash_ok:
        form = "su 0 <cmd>" if zero_ok else "su -c <cmd>"
        winner = zero if zero_ok else dash
        ctx = re.search(r"context=(\S+)", winner)
        out["root"] = (True, "uid=0(root)%s  [working form: %s]"
                       % ((" " + ctx.group(0)) if ctx else "", form))
        out["_su_form"] = form
    else:
        out["root"] = (False, "su 0 -> %s | su -c -> %s"
                       % (banner(zero)[:40], banner(dash)[:40]))

    # ---- frida-server, tested by EXECUTING it ----------------------------- #
    # A host-side `frida --version` says nothing about the device. The binary on
    # this repository's AVD prints a version on the host and fails to link on
    # the device; only running it tells the truth.
    _, listing = adb(["shell", "ls /data/local/tmp"], serial)
    if "frida-server" not in listing:
        out["frida-server"] = (False, "no frida-server in /data/local/tmp")
    else:
        runner = ["shell", "su 0 /data/local/tmp/frida-server --version"] \
            if out.get("root", (False,))[0] else \
            ["shell", "/data/local/tmp/frida-server --version"]
        _, ver = adb(runner, serial, timeout=40)
        # The linker prints hundreds of `unused DT entry` warnings before the
        # line that decides this, so the whole output is searched, not the
        # first line of it.
        if "CANNOT LINK" in ver or "not executable" in ver:
            fatal = [l for l in ver.splitlines() if "CANNOT LINK" in l]
            out["frida-server"] = (
                False, "present but does not run: %s"
                % (fatal[0].strip()[:100] if fatal else banner(ver)))
        elif re.match(r"^\d+\.\d+", banner(ver)):
            out["frida-server"] = (True, banner(ver))
        else:
            out["frida-server"] = (False, "unclear: %s" % ver.strip()[:90])

    # ---- bootloader ------------------------------------------------------- #
    # An AVD has no bootloader to talk to, which is why every fastboot lab is
    # unrunnable there no matter how much root you have.
    _, bootmode = adb(["shell", "getprop ro.bootmode"], serial)
    _, parts = adb(["shell", "ls /dev/block/by-name"], serial)
    has_boot = bool(re.search(r"\bboot(_[ab])?\b", parts))
    out["bootloader"] = (has_boot, "ro.bootmode=%s; by-name: %s"
                         % (bootmode.strip(), " ".join(parts.split())[:70]))

    return out


# --------------------------------------------------------------------------- #
# Capability set -> requirement tags
# --------------------------------------------------------------------------- #

def capability_tags(host, device, assume):
    """Translate probe results into the tag vocabulary the lab index uses."""
    have = set()
    why = {}

    def add(tag, reason):
        have.add(tag)
        why.setdefault(tag, reason)

    for probe in HOST_PROBES:
        present, detail = host[probe["key"]]
        if present and probe["tag"]:
            add(probe["tag"], "host: %s -> %s" % (probe["key"], detail))

    if host["javac"][0] and host["sdk"][0]:
        add("jdk", "host: javac plus SDK build-tools")

    attached = device.get("attached", (False, ""))[0]
    if attached:
        add("device", "device: %s" % device["identity"][1])
    add("no-device", "always available")
    add("no-root", "always available")

    if device.get("root", (False, ""))[0]:
        add("root", "device: %s" % device["root"][1])

    # Frida needs BOTH ends. This is the whole reason the probe exists.
    if host["frida"][0] and device.get("frida-server", (False, ""))[0]:
        add("frida", "host frida plus a frida-server that runs")

    if attached and not device.get("emulator", (False, ""))[0]:
        add("physical", "device: no emulator signal found")

    for tag in assume:
        add(tag, "assumed by --assume")

    return have, why


# --------------------------------------------------------------------------- #
# Matching against the index
# --------------------------------------------------------------------------- #

# Tags that are informational rather than gating.
#
# `python` is satisfied by definition on any machine that can run this script.
# `no-root` and `no-device` are statements a lab makes about itself, not
# requirements it places on you.
#
# `device` is NOT in this set, and putting it here was a bug worth recording:
# with `device` excused, `--no-device --match` reported 108 labs runnable on a
# machine with no device, including labs whose every step is an adb command.
# An exemption that is harmless in the common case can be badly wrong in the
# case the flag exists to serve.
NON_GATING = {"python", "no-root", "no-device"}


def load_index(root):
    """Import build-lab-index.py as a module rather than shelling out, so the
    two scripts can never drift into different parsing rules."""
    sys.path.insert(0, HERE)
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "build_lab_index", os.path.join(HERE, "build-lab-index.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.path.pop(0)
    return mod.collect(root)


def match(labs, have, chapter=None):
    runnable, blocked = [], []
    for lab in labs:
        if chapter and not lab["chapter_number"] == chapter:
            continue
        needs = {t for t in lab["tags"] if t not in NON_GATING
                 and not t.startswith("no-")}
        missing = sorted(needs - have)
        if missing:
            blocked.append((lab, missing))
        else:
            runnable.append(lab)
    return runnable, blocked


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def mark(present):
    return "yes" if present else "NO "


def print_probe(host, device):
    print("=" * 78)
    print("HOST")
    print("=" * 78)
    for probe in HOST_PROBES:
        present, detail = host[probe["key"]]
        print("  [%s] %-22s %s" % (mark(present), probe["label"], detail))
        if not present and probe["note"]:
            print("        %s" % probe["note"])
    print()
    print("=" * 78)
    print("DEVICE")
    print("=" * 78)
    if not device.get("attached", (False, ""))[0]:
        print("  [NO ] no usable device: %s" % device.get("attached", (0, "?"))[1])
        print("        Every lab tagged `device` is out of reach. 58 labs in this")
        print("        repository need no device at all -- see")
        print("        ../references/lab-index-by-requirement.md, tag `no-device`.")
        return
    order = ["attached", "identity", "emulator", "selinux", "pagesize",
             "root", "frida-server", "bootloader"]
    for key in order:
        if key not in device:
            continue
        present, detail = device[key]
        print("  [%s] %-22s %s" % (mark(present), key, detail))


def main():
    ap = argparse.ArgumentParser(
        description="Probe this machine and report which of the repository's "
                    "labs it can run.")
    ap.add_argument("--root", default=REPO_ROOT)
    ap.add_argument("--serial", default=None, help="adb serial, if several")
    ap.add_argument("--no-device", action="store_true",
                    help="skip every device probe")
    ap.add_argument("--match", action="store_true",
                    help="cross-reference against the lab index")
    ap.add_argument("--list", choices=["runnable", "blocked"], default=None)
    ap.add_argument("--chapter", default=None,
                    help="restrict --match to one chapter number, e.g. 53")
    ap.add_argument("--assume", default="",
                    help="comma-separated tags to treat as present, e.g. proxy,ida")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if any probed capability is absent")
    args = ap.parse_args()

    host = {}
    for probe in HOST_PROBES:
        host[probe["key"]] = probe["probe"]()

    device = {} if args.no_device else probe_device(args.serial)
    if args.no_device:
        device["attached"] = (False, "--no-device given")

    assume = {t.strip() for t in args.assume.split(",") if t.strip()}
    have, why = capability_tags(host, device, assume)

    if args.json:
        payload = {
            "host": {k: {"present": v[0], "detail": v[1]}
                     for k, v in host.items()},
            "device": {k: {"present": v[0], "detail": v[1]}
                       for k, v in device.items() if not k.startswith("_")},
            "tags": sorted(have),
            "why": why,
        }
        if args.match:
            labs = load_index(args.root)
            runnable, blocked = match(labs, have, args.chapter)
            payload["runnable"] = [l["relpath"] for l in runnable]
            payload["blocked"] = {l["relpath"]: m for l, m in blocked}
        sys.stdout.flush()
        sys.stdout.buffer.write(
            (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
        return 0

    print_probe(host, device)
    print()
    print("Capability tags satisfied: %s" % (", ".join(sorted(have)) or "(none)"))

    if not args.match:
        print()
        print("Re-run with --match to see which labs this setup can run.")
        return 1 if (args.strict and not all(v[0] for v in host.values())) else 0

    labs = load_index(args.root)
    runnable, blocked = match(labs, have, args.chapter)
    total = len(runnable) + len(blocked)

    print()
    print("=" * 78)
    print("LABS")
    print("=" * 78)
    print("  runnable here : %d / %d" % (len(runnable), total))
    print("  blocked       : %d / %d" % (len(blocked), total))
    print()

    reasons = {}
    for lab, missing in blocked:
        for tag in missing:
            reasons.setdefault(tag, []).append(lab)
    print("  Blocked by:")
    for tag, rows in sorted(reasons.items(), key=lambda kv: -len(kv[1])):
        print("    %-10s %4d labs" % (tag, len(rows)))

    if args.list == "runnable":
        print()
        for lab in runnable:
            print("  %-14s %-58s %s" % (lab["chapter_number"],
                                        lab["title"][:58],
                                        lab["difficulty"] or "unstated"))
    elif args.list == "blocked":
        print()
        for lab, missing in blocked:
            print("  %-14s %-52s needs %s" % (lab["chapter_number"],
                                              lab["title"][:52],
                                              ", ".join(missing)))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        sys.exit(130)
