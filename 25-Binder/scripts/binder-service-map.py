#!/usr/bin/env python3
"""
binder-service-map.py -- build the map you actually need before attacking a
                         Binder service: NAME -> INTERFACE -> OWNING PROCESS
                         -> SELINUX DOMAIN, with the MAC gate that guards it.

WHAT IT DOES
    `service list` gives you two of the four columns and stops. That is not
    enough to decide whether a service is worth an hour of your time. This
    script joins four sources into one table:

        service list                    name  ->  interface descriptor
        *_service_contexts              name  ->  the SELinux TYPE of the NAME,
                                        which is the target of the
                                        service_manager:find check -- MAC
                                        stage 1, see 22-SELinux section 3.15
        ps -A -Z                        pid   ->  process name + SELinux domain
        name/descriptor/type matching   name  ->  the owning process

    and prints, per service:

        NAME          the string you pass to `service call`
        INTERFACE     the descriptor string, i.e. the interface token any
                      caller must write into the parcel or be refused
        SVC TYPE      SELinux type of the NAME. This decides whether your
                      domain may even LOOK the service up
        OWNER         pid and process name that published it
        DOMAIN        the owner's SELinux domain, which is the target of the
                      binder:call check -- MAC stage 2
        HOW           how the owner was attributed, and how much to trust it

    It also flags three things worth a second look:

        UNLABELLED    a registered name with no service_contexts entry. It
                      falls through to default_android_service, and on many
                      builds untrusted_app is granted find on that type. An
                      OEM service that nobody labelled is a recurring finding.
        NO-INTERFACE  a service that returns an empty descriptor. Usually a
                      raw BBinder with a hand-written onTransact, which is
                      exactly where undocumented transaction codes live.
        VENDOR        registered in vndservice_contexts, i.e. on
                      /dev/vndbinder, which apps cannot open at all.

HOW TO RUN
    # host, device attached over adb
    python3 binder-service-map.py

    # only services your SELinux domain could plausibly reach
    python3 binder-service-map.py --domain untrusted_app

    # the interesting ones only
    python3 binder-service-map.py --unlabelled
    python3 binder-service-map.py --no-interface

    # machine readable, for diffing two devices or two ROM versions
    python3 binder-service-map.py --json  > stock.json
    python3 binder-service-map.py --csv   > stock.csv

    # work offline from captured files (see --capture)
    python3 binder-service-map.py --capture ./snap     # collect, then
    python3 binder-service-map.py --fixture ./snap     # analyse anywhere

    # one service, in detail, with the two allow rules it needs
    python3 binder-service-map.py --explain notification

REQUIREMENTS
    Python 3.6+ and standard library only. `adb` on PATH and one device
    attached, UNLESS --fixture is used, in which case nothing is needed.
    NO ROOT: every source it reads is world-readable to the shell domain.
    Tested against Android 11 / API 30 arm64 and written to degrade rather
    than crash on other versions.

WHAT THIS WILL *NOT* TELL YOU
    - Whether a service is VULNERABLE. It tells you what exists and who owns
      it. Every actual finding comes from what the service's onTransact does
      with your parcel, which is README sections 5 and 7, not from this table.
    - The transaction codes. Binder carries no schema and the device holds no
      .aidl files. A code is a bare integer whose meaning lives in AOSP source
      or in the framework's own DEX. This script deliberately prints no codes
      rather than guessing them.
    - Whether YOUR domain is allowed service_manager:find. It prints the type
      you would need a rule for and the rule's exact text, but only the binary
      policy can answer whether that rule exists. Use `sesearch` on the policy,
      or just try the call and read the avc record. See 22-SELinux.
    - A trustworthy owner for every service. Attribution below root is
      inference, and the script says so in the HOW column on every single row.
      `exact` and `hal` are rule-based and checkable. `framework` is a genuine
      guess -- most unmatched framework services are published by system_server,
      but "most" is not "all", and an OEM service published by an OEM daemon
      will be mis-attributed. Treat `framework` as a hypothesis to confirm.
      Android 11+ servicemanager does hold the true answer, in
      IServiceManager.getServiceDebugInfo(), which returns each name with the
      pid that registered it. This script does not call it, because doing so
      by hand requires a transaction code this author has not verified against
      the AOSP tree for every release, and a wrong guess would print confident
      nonsense. If you need certainty, get it from that call, not from here.
    - Anything about /dev/hwbinder. HIDL services are enumerated with `lshal`,
      which reports pids properly, and they are a separate namespace with a
      separate manager. This script reports vndservice names because they show
      up in the same contexts files, but does not enumerate hwservices.
    - Anything about services that are registered LAZILY. A service that is
      declared but not yet started does not appear in `service list` at all.
      `--unlabelled` will therefore under-report on builds that use
      lazy HALs and dynamic service registration.
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys

# --------------------------------------------------------------------------
# Device access
# --------------------------------------------------------------------------

# Every path this script reads. All are world-readable; none require root.
SOURCES = {
    "service_list": "service list",
    "ps": "ps -A -o PID,USER,LABEL,NAME",
    "plat_service_contexts": "cat /system/etc/selinux/plat_service_contexts",
    "vnd_service_contexts": "cat /vendor/etc/selinux/vndservice_contexts",
    "system_ext_service_contexts":
        "cat /system_ext/etc/selinux/system_ext_service_contexts",
    "product_service_contexts":
        "cat /product/etc/selinux/product_service_contexts",
    "getprop": "getprop ro.build.version.release; getprop ro.build.version.sdk; "
               "getprop ro.product.model; getprop ro.product.cpu.abi",
}


class Device(object):
    """Runs commands on the device, or serves them from a captured directory."""

    def __init__(self, fixture=None, serial=None):
        self.fixture = fixture
        self.serial = serial

    def get(self, key):
        if self.fixture:
            path = os.path.join(self.fixture, key + ".txt")
            if not os.path.exists(path):
                return ""
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        cmd += ["shell", SOURCES[key]]
        try:
            out = subprocess.run(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            sys.stderr.write("adb failed for %s: %s\n" % (key, exc))
            return ""
        return out.stdout.decode("utf-8", "replace")


def capture(dev, outdir):
    """Save every source to a directory so the analysis can run offline."""
    os.makedirs(outdir, exist_ok=True)
    for key in SOURCES:
        text = dev.get(key)
        path = os.path.join(outdir, key + ".txt")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        sys.stderr.write("wrote %-32s %6d bytes\n" % (path, len(text)))


# --------------------------------------------------------------------------
# Parsers -- each one tolerant of the formats seen across API 26..34
# --------------------------------------------------------------------------

# `0<TAB>activity: [android.app.IActivityManager]`
RE_SERVICE = re.compile(r"^\s*\d+\s+(?P<name>[^:]+):\s*\[(?P<iface>[^\]]*)\]\s*$")

# `u:object_r:activity_service:s0` preceded by the service name
RE_CONTEXT = re.compile(r"^(?P<name>\S+)\s+(?P<ctx>u:object_r:\S+)\s*$")

# `  606 system       u:r:servicemanager:s0          servicemanager`
RE_PS = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<user>\S+)\s+(?P<label>u:r:\S+)\s+(?P<name>.+?)\s*$")


def parse_service_list(text):
    """-> [(name, interface)] in the order servicemanager returned them."""
    out = []
    for line in text.splitlines():
        m = RE_SERVICE.match(line)
        if m:
            out.append((m.group("name").strip(), m.group("iface").strip()))
    return out


def parse_contexts(text, origin):
    """-> {service_name: (selinux_type, origin)}"""
    out = {}
    for line in text.splitlines():
        line = line.split("#")[0].rstrip()
        if not line or line.startswith("#line"):
            continue
        m = RE_CONTEXT.match(line)
        if not m:
            continue
        ctx = m.group("ctx")
        parts = ctx.split(":")
        # u:object_r:TYPE:s0  ->  TYPE
        stype = parts[2] if len(parts) >= 3 else ctx
        out[m.group("name")] = (stype, origin)
    return out


def parse_ps(text):
    """-> [{pid, user, domain, name}]"""
    procs = []
    for line in text.splitlines():
        if line.lstrip().startswith("LABEL") or line.lstrip().startswith("PID"):
            continue
        m = RE_PS.match(line)
        if not m:
            continue
        label = m.group("label")
        parts = label.split(":")
        domain = parts[2] if len(parts) >= 3 else label
        procs.append({
            "pid": int(m.group("pid")),
            "user": m.group("user"),
            "domain": domain,
            "name": m.group("name").strip(),
        })
    return procs


# --------------------------------------------------------------------------
# Owner attribution
#
# Read the HOW column before believing the OWNER column. Only `exact` and
# `hal` are rules; `framework` is a hypothesis.
# --------------------------------------------------------------------------

def _norm(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def attribute_owner(name, iface, stype, procs):
    """-> (proc_or_None, how)"""
    by_norm = {}
    for p in procs:
        by_norm.setdefault(_norm(p["name"]), p)

    # 1. exact: the service name IS a process name. SurfaceFlinger, and every
    #    native daemon that names its service after itself.
    p = by_norm.get(_norm(name))
    if p:
        return p, "exact"

    # 2. exact on the last dotted component -- `media.player` -> mediaserver
    #    style names, and `foo.bar.Baz` -> Baz.
    tail = name.split(".")[-1].split("/")[0]
    if tail and tail != name:
        p = by_norm.get(_norm(tail))
        if p:
            return p, "exact"

    # 3. hal: `hal_light_service` is, by AOSP convention, added by a domain
    #    called hal_light_default or vendor_hal_light_<vendor>. This is a
    #    naming rule in system/sepolicy, not a guess, but a vendor is free to
    #    break it -- hence it is reported separately from `exact`.
    m = re.match(r"^(?:vendor_)?hal_(?P<mid>.+?)_service$", stype or "")
    if m:
        want = m.group("mid")
        cands = [q for q in procs
                 if re.match(r"^(?:vendor_)?hal_%s(?:_|$)" % re.escape(want),
                             q["domain"])]
        if len(cands) == 1:
            return cands[0], "hal"
        if cands:
            return cands[0], "hal?"

    # 4. descriptor: an AIDL HAL name like
    #    `android.hardware.light.ILights/default` is served by a process whose
    #    name usually contains `android.hardware.light`.
    if "/" in name:
        stem = name.split("/")[0]
        stem_n = _norm(stem)
        for q in procs:
            if stem_n and stem_n in _norm(q["name"]):
                return q, "descriptor"

    # 5. framework: a plain framework interface with no better match is very
    #    probably system_server. VERY PROBABLY. This is the guess.
    if iface.startswith(("android.", "com.android.internal.")):
        for q in procs:
            if q["name"] == "system_server":
                return q, "framework?"

    return None, "unknown"


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def build(dev):
    services = parse_service_list(dev.get("service_list"))
    procs = parse_ps(dev.get("ps"))

    ctxs = {}
    for key, origin in (("plat_service_contexts", "plat"),
                        ("system_ext_service_contexts", "system_ext"),
                        ("product_service_contexts", "product"),
                        ("vnd_service_contexts", "vendor(vndbinder)")):
        ctxs.update(parse_contexts(dev.get(key), origin))

    rows = []
    for name, iface in services:
        stype, origin = ctxs.get(name, (None, None))
        owner, how = attribute_owner(name, iface, stype, procs)
        flags = []
        if stype is None:
            flags.append("UNLABELLED")
        if not iface:
            flags.append("NO-INTERFACE")
        if origin and origin.startswith("vendor"):
            flags.append("VENDOR")
        rows.append({
            "name": name,
            "interface": iface,
            "selinux_type": stype or "default_android_service (implied)",
            "context_origin": origin or "-",
            "owner_pid": owner["pid"] if owner else None,
            "owner_name": owner["name"] if owner else "?",
            "owner_domain": owner["domain"] if owner else "?",
            "owner_user": owner["user"] if owner else "?",
            "attribution": how,
            "flags": flags,
        })
    return rows, procs, ctxs


def device_banner(dev):
    text = dev.get("getprop")
    vals = [v.strip() for v in text.splitlines() if v.strip()]
    while len(vals) < 4:
        vals.append("?")
    return "device: %s  Android %s (API %s)  %s" % (vals[2], vals[0], vals[1], vals[3])


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def print_table(rows, show_flags_only=None):
    if show_flags_only:
        rows = [r for r in rows if show_flags_only in r["flags"]]
    if not rows:
        print("(no matching services)")
        return

    def w(key, minimum):
        return max(minimum, max(len(str(r[key])) for r in rows))

    wn = min(w("name", 4), 44)
    wi = min(w("interface", 9), 46)
    wt = min(w("selinux_type", 8), 34)
    wo = min(w("owner_name", 5), 26)

    hdr = ("%-*s  %-*s  %-*s  %-*s  %-7s  %s"
           % (wn, "SERVICE", wi, "INTERFACE", wt, "SVC TYPE",
              wo, "OWNER", "PID", "DOMAIN / HOW"))
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        marks = ("  [" + ",".join(r["flags"]) + "]") if r["flags"] else ""
        print("%-*s  %-*s  %-*s  %-*s  %-7s  %s (%s)%s"
              % (wn, r["name"][:wn],
                 wi, (r["interface"] or "-")[:wi],
                 wt, r["selinux_type"][:wt],
                 wo, r["owner_name"][:wo],
                 r["owner_pid"] if r["owner_pid"] else "-",
                 r["owner_domain"], r["attribution"], marks))


def print_summary(rows, procs):
    unlabelled = [r for r in rows if "UNLABELLED" in r["flags"]]
    nointf = [r for r in rows if "NO-INTERFACE" in r["flags"]]
    vendor = [r for r in rows if "VENDOR" in r["flags"]]
    unknown = [r for r in rows if r["attribution"] == "unknown"]
    guessed = [r for r in rows if r["attribution"].endswith("?")]

    print("")
    print("SUMMARY")
    print("  services registered              : %d" % len(rows))
    print("  processes seen                   : %d" % len(procs))
    print("  with an explicit SELinux label   : %d" % (len(rows) - len(unlabelled)))
    print("  UNLABELLED (default type)        : %d" % len(unlabelled))
    print("  NO-INTERFACE (raw onTransact)    : %d" % len(nointf))
    print("  vndservice (apps cannot reach)   : %d" % len(vendor))
    print("  owner attributed by a rule       : %d"
          % len([r for r in rows if r["attribution"] in ("exact", "hal", "descriptor")]))
    print("  owner GUESSED (verify these)     : %d" % len(guessed))
    print("  owner unknown                    : %d" % len(unknown))
    print("")
    print("  Read the HOW column. Only exact/hal/descriptor are rules.")
    print("  A trailing '?' means the script is guessing and you should not")
    print("  quote the owner in a report without confirming it.")


def print_explain(rows, name):
    match = [r for r in rows if r["name"] == name]
    if not match:
        print("no registered service called %r" % name)
        near = [r["name"] for r in rows if name.lower() in r["name"].lower()]
        if near:
            print("did you mean: %s" % ", ".join(near[:10]))
        return
    r = match[0]
    print("SERVICE        %s" % r["name"])
    print("INTERFACE      %s" % (r["interface"] or "(none -- raw BBinder)"))
    print("SVC TYPE       %s   [from %s]" % (r["selinux_type"], r["context_origin"]))
    print("OWNER          pid %s  %s  running as %s"
          % (r["owner_pid"], r["owner_name"], r["owner_user"]))
    print("OWNER DOMAIN   %s" % r["owner_domain"])
    print("ATTRIBUTION    %s%s" % (r["attribution"],
          "   <-- a guess, confirm it" if r["attribution"].endswith("?") else ""))
    print("")
    print("REACHING IT IS TWO SEPARATE MAC DECISIONS (see 22-SELinux 3.15):")
    stype = r["selinux_type"].split()[0]
    print("  stage 1, looking the name up:")
    print("      allow YOUR_DOMAIN %s:service_manager find;" % stype)
    print("      a denial here says   tclass=service_manager   and NAMES the service")
    print("  stage 2, sending the transaction:")
    print("      allow YOUR_DOMAIN %s:binder call;" % r["owner_domain"])
    print("      a denial here says   tclass=binder   and names NO service at all")
    print("")
    print("THEN, and only then, the service's own check runs. That is chapter 23.")
    print("")
    print("NEXT STEPS")
    print("  # confirm it is alive and answering")
    print("  adb shell service check %s" % r["name"])
    print("  # ask the object what interface it claims -- code 1598968902 is '_NTF'")
    print("  adb shell service call %s 1598968902" % r["name"])
    if r["interface"]:
        print("  # find its transaction codes: they are the order of the methods in")
        print("  #   %s.aidl, starting at 1" % r["interface"].replace(".", "/"))
    else:
        print("  # NO DESCRIPTOR. Nothing enforces an interface token here, so")
        print("  #   every transaction code is reachable with an empty parcel.")
        print("  #   This is the interesting case. Sweep codes carefully and on a")
        print("  #   device you can afford to reboot.")
    print("  # dump its state, if it implements '_DMP' (1598311760)")
    print("  adb shell dumpsys %s" % r["name"])


def main():
    ap = argparse.ArgumentParser(
        description="Map Binder services to interfaces, owners and SELinux types.")
    ap.add_argument("--fixture", help="analyse a directory made by --capture")
    ap.add_argument("--capture", metavar="DIR",
                    help="save every source file to DIR and exit")
    ap.add_argument("-s", "--serial", help="adb device serial")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--csv", action="store_true", help="emit CSV")
    ap.add_argument("--unlabelled", action="store_true",
                    help="only services with no service_contexts entry")
    ap.add_argument("--no-interface", action="store_true",
                    help="only services with an empty interface descriptor")
    ap.add_argument("--vendor", action="store_true",
                    help="only vndservice_contexts entries")
    ap.add_argument("--explain", metavar="NAME",
                    help="everything known about one service, plus its MAC rules")
    ap.add_argument("--sort", choices=("name", "owner", "type"), default="name")
    args = ap.parse_args()

    dev = Device(fixture=args.fixture, serial=args.serial)

    if args.capture:
        capture(dev, args.capture)
        return 0

    rows, procs, _ = build(dev)
    if not rows:
        sys.stderr.write(
            "No services parsed. Check that a device is attached "
            "(adb devices) or that --fixture points at a --capture directory.\n")
        return 1

    if args.sort == "owner":
        rows.sort(key=lambda r: (r["owner_name"], r["name"]))
    elif args.sort == "type":
        rows.sort(key=lambda r: (r["selinux_type"], r["name"]))
    else:
        rows.sort(key=lambda r: r["name"])

    if args.explain:
        print_explain(rows, args.explain)
        return 0

    subset = rows
    if args.unlabelled:
        subset = [r for r in rows if "UNLABELLED" in r["flags"]]
    elif args.no_interface:
        subset = [r for r in rows if "NO-INTERFACE" in r["flags"]]
    elif args.vendor:
        subset = [r for r in rows if "VENDOR" in r["flags"]]

    if args.json:
        json.dump(subset, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    if args.csv:
        wr = csv.DictWriter(
            sys.stdout,
            fieldnames=["name", "interface", "selinux_type", "context_origin",
                        "owner_pid", "owner_name", "owner_domain", "owner_user",
                        "attribution", "flags"],
            lineterminator="\n")
        wr.writeheader()
        for r in subset:
            row = dict(r)
            row["flags"] = ";".join(r["flags"])
            wr.writerow(row)
        return 0

    print(device_banner(dev))
    print("")
    print_table(subset)
    print_summary(rows, procs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
