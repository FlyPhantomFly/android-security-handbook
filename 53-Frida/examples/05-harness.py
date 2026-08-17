#!/usr/bin/env python3
"""
05-harness.py — a reproducible, auditable Frida harness.

WHAT IT DOES
    Runs a fixed agent against a fixed APK for a fixed duration, on a device
    whose state is recorded, and writes:

        runs/<timestamp>/manifest.json   APK hash, agent hash, device fingerprint,
                                         Android release, ART Mainline version,
                                         SELinux mode, compiler filter, counts
        runs/<timestamp>/events.jsonl    one timestamped JSON object per message
        runs/<timestamp>/blob-*.bin      binary payloads referenced from events

WHY THE MANIFEST MATTERS
    The difference between a test and an experiment is the manifest. A test
    tells you what happened once. An experiment records the conditions
    precisely enough that someone else — or you, three app versions later — can
    reproduce it or explain why it no longer reproduces.

    On Android specifically, TWO facts belong in that record because both change
    whether a hook fires at all:
      - the compiler filter (verify vs speed vs speed-profile)
      - the ART Mainline module version
    See ../../13-ART/README.md section 3.26.

    A harness that omits these produces findings nobody can reproduce, which is
    the most common reason a real vulnerability gets closed as "cannot
    reproduce".

USAGE
    python3 05-harness.py --apk app-release.apk \
                          --agent _agent.js \
                          --package com.example.app \
                          --duration 120 \
                          --modules pinning,crypto,network \
                          --compile-filter verify \
                          --out runs/

    # The second run that makes the finding credible:
    python3 05-harness.py ... --compile-filter reset

REQUIREMENTS
    pip install frida frida-tools
    adb on PATH, a rooted device with a version-matched frida-server running.

EXIT CODE
    0 if the agent produced no errors, 1 otherwise — so CI notices.

AUTHORISED TESTING ONLY.
"""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time

try:
    import frida
except ImportError:
    sys.exit("frida is not installed:  python3 -m pip install frida frida-tools")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def sha256(path):
    """Hash a file in chunks so a 200 MB APK does not sit in memory."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def adb(*args, timeout=30):
    """Run an adb command and return stripped stdout. Never raises."""
    try:
        r = subprocess.run(["adb", *args], capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return f"<adb error: {e}>"


def environment():
    """
    Everything needed to explain a result to someone six months from now.

    Note ro.build.fingerprint rather than just the release number: two devices
    reporting "Android 14" can differ in ways that matter.
    """
    return {
        "host_os":            platform.platform(),
        "host_python":        platform.python_version(),
        "frida_python":       frida.__version__,
        "device_serial":      adb("get-serialno"),
        "android_release":    adb("shell", "getprop", "ro.build.version.release"),
        "android_sdk":        adb("shell", "getprop", "ro.build.version.sdk"),
        "security_patch":     adb("shell", "getprop", "ro.build.version.security_patch"),
        "build_fingerprint":  adb("shell", "getprop", "ro.build.fingerprint"),
        "cpu_abi":            adb("shell", "getprop", "ro.product.cpu.abi"),
        "cpu_abilist":        adb("shell", "getprop", "ro.product.cpu.abilist"),
        # ART is a Mainline module: two devices on the same Android release can
        # run different runtimes, which changes hook behaviour.
        "art_module":         adb("shell", "cmd", "package", "list", "packages",
                                  "--show-versioncode", "com.google.android.art"),
        "selinux":            adb("shell", "getenforce"),
        "device_frida":       adb("shell", "su", "-c",
                                  "/data/local/tmp/frida-server --version"),
    }


def check_version_match(env):
    """
    The single most common first-day failure. Catch it before spawning rather
    than letting frida raise a message the operator will misread.
    """
    host = frida.__version__
    device = env.get("device_frida", "")
    if not device or device.startswith("<"):
        print("[!] Could not determine the device frida-server version.")
        print("    If the run fails with 'major versions match', that is why.")
        return
    if device.split(".")[0] != host.split(".")[0]:
        print(f"[!] VERSION MISMATCH: host frida={host}  device frida-server={device}")
        print("    Major versions must match exactly. Fix this before continuing.")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="Reproducible Frida harness")
    ap.add_argument("--apk", required=True,
                    help="the APK under test (hashed into the manifest)")
    ap.add_argument("--agent", required=True,
                    help="compiled agent .js (frida-compile output)")
    ap.add_argument("--package", required=True)
    ap.add_argument("--duration", type=int, default=60,
                    help="seconds to run before tearing down")
    ap.add_argument("--modules", default="",
                    help="comma-separated rpc.exports.enable() names")
    ap.add_argument("--out", default="runs")
    ap.add_argument("--compile-filter", default="verify",
                    help="'verify' makes hooks reliable; 'reset' restores the "
                         "app's normal state — run BOTH before reporting")
    ap.add_argument("--params", default="{}",
                    help="JSON passed to rpc.exports.init as `parameters`")
    args = ap.parse_args()

    for path in (args.apk, args.agent):
        if not os.path.isfile(path):
            sys.exit(f"not found: {path}")

    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    run_dir = os.path.join(args.out, run_id)
    os.makedirs(run_dir, exist_ok=True)

    print(f"[*] run {run_id} -> {run_dir}")

    env = environment()
    check_version_match(env)

    # ---- 1. put the device in a KNOWN state, and record that we did ------- #
    if args.compile_filter == "reset":
        adb("shell", "cmd", "package", "compile", "--reset", args.package)
        print("[*] compiler filter RESET to the app's normal state")
    else:
        adb("shell", "cmd", "package", "compile",
            "-m", args.compile_filter, "-f", args.package, timeout=180)
        print(f"[*] compiler filter forced to {args.compile_filter}")
    adb("shell", "am", "force-stop", args.package)

    dexopt = adb("shell", "dumpsys", "package", "dexopt")
    # Keep only the lines about our package; the full dump is enormous.
    dexopt_lines = []
    capture = False
    for line in dexopt.splitlines():
        if line.strip().startswith(f"[{args.package}]"):
            capture = True
        elif capture and line.startswith("["):
            break
        if capture:
            dexopt_lines.append(line)

    manifest = {
        "run_id": run_id,
        "package": args.package,
        "apk":   {"path": os.path.abspath(args.apk),   "sha256": sha256(args.apk)},
        "agent": {"path": os.path.abspath(args.agent), "sha256": sha256(args.agent)},
        "modules": [m for m in args.modules.split(",") if m],
        "compile_filter": args.compile_filter,
        "duration_requested": args.duration,
        "environment": env,
        "dexopt_state": dexopt_lines,
        "started_utc": run_id,
    }

    # ---- 2. message routing ------------------------------------------------ #
    events_path = os.path.join(run_dir, "events.jsonl")
    events = open(events_path, "w", encoding="utf-8")
    counts = {"log": 0, "blob": 0, "key": 0, "error": 0, "other": 0}

    def on_message(message, data):
        record = {"t": time.time(), "raw": message}

        if message["type"] == "error":
            counts["error"] += 1
            # frida-compile source maps make `stack` point at .ts line numbers,
            # which is the whole reason to build with a source map.
            print(f"[!] {message.get('description')}")
            if message.get("stack"):
                print(message["stack"])
        else:
            payload = message.get("payload")
            kind = payload.get("kind") if isinstance(payload, dict) else None
            counts[kind if kind in counts else "other"] += 1

            if kind == "log":
                print(f"[{payload.get('level','i')[0].upper()}] {payload.get('msg')}")
            elif data is not None:
                idx = counts["blob"] + counts["key"]
                blob_path = os.path.join(run_dir, f"blob-{idx:05d}.bin")
                with open(blob_path, "wb") as fh:
                    fh.write(data)
                record["blob_file"] = os.path.basename(blob_path)
                print(f"[+] {len(data)} bytes -> {os.path.basename(blob_path)}")
            else:
                print(f"[*] {json.dumps(payload)[:200]}")

        events.write(json.dumps(record, default=str) + "\n")
        events.flush()

    agent_source = open(args.agent, encoding="utf-8").read()
    children = []

    def instrument(pid, label):
        session = device.attach(pid)
        session.on("detached",
                   lambda reason, *a: print(f"[-] {label} detached: {reason}"))
        script = session.create_script(agent_source, name=os.path.basename(args.agent))
        script.on("message", on_message)
        # `init` runs before load() returns, so hooks are in place before we
        # resume the process. That ordering is the entire value of spawning.
        script.load()
        return session, script

    # ---- 3. spawn, gate children, run -------------------------------------- #
    device = frida.get_usb_device(timeout=10)

    # Child gating catches :remote services, WebView renderers, and separate
    # -process Activities. Without it you instrument the main process only.
    device.enable_child_gating()

    def on_child(child):
        label = child.identifier or str(child.pid)
        print(f"[+] child pid={child.pid} id={label}")
        children.append({"pid": child.pid, "identifier": child.identifier})
        try:
            instrument(child.pid, label)
        except Exception as e:      # a child may die before we attach
            print(f"[-] could not instrument child {child.pid}: {e}")
        finally:
            device.resume(child.pid)

    device.on("child-added", on_child)

    pid = device.spawn([args.package])
    session, script = instrument(pid, args.package)
    device.resume(pid)              # app code starts running only NOW
    print(f"[*] spawned pid={pid}")

    try:
        available = script.exports_sync.list()
        print(f"[*] agent modules available: {available}")
    except Exception:
        available = None            # agent may not expose list()

    for m in manifest["modules"]:
        try:
            script.exports_sync.enable(m)
            print(f"[*] enabled {m}")
        except Exception as e:
            print(f"[-] could not enable {m}: {e}")

    started = time.time()
    try:
        while time.time() - started < args.duration:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] interrupted")
    finally:
        try:
            script.unload()         # triggers rpc.exports.dispose()
            session.detach()
        except frida.InvalidOperationError:
            pass                    # process already gone
        except Exception as e:
            print(f"[-] teardown: {e}")
        events.close()

    # ---- 4. finish the manifest -------------------------------------------- #
    manifest["finished_utc"] = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    manifest["duration_actual"] = round(time.time() - started, 1)
    manifest["children"] = children
    manifest["counts"] = counts
    manifest["agent_modules_available"] = available

    with open(os.path.join(run_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, default=str)

    print()
    print(f"[+] run {run_id} complete: {counts}")
    print(f"    {os.path.join(run_dir, 'manifest.json')}")
    print(f"    {events_path}")

    if args.compile_filter != "reset":
        print()
        print("[!] This run used a FORCED compiler filter. Before reporting any")
        print("    finding, re-run with --compile-filter reset and confirm it")
        print("    still reproduces in the app's normal state.")

    sys.exit(1 if counts["error"] else 0)


if __name__ == "__main__":
    main()
