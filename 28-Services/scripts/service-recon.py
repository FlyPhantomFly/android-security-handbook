#!/usr/bin/env python3
"""
service-recon.py -- answer the only question that matters before you write an
                    attacker app: WHICH SERVICES ON THIS DEVICE CAN AN ORDINARY
                    APP BIND, AND WHAT DO THEY EXPOSE?

WHAT IT DOES
    `dumpsys package r` lists which services answer which intent action, and
    stops. `pm query-services` gives you exported= and permission= for one
    action at a time, and stops. Neither tells you whether the permission it
    names is a real gate -- and that is the whole question, because a service
    guarded by a `normal` permission is guarded by nothing.

    This script joins three device sources into one ranked table:

        dumpsys package r        Service Resolver Table
                                 action / scheme / MIME  ->  components
        pm query-services -a     per service: exported, permission,
                                 processName, enabled, directBootAware
        pm list permissions -f   permission  ->  protectionLevel

    and prints, per service, a VERDICT that says what an unprivileged
    third-party app would actually meet:

        OPEN          exported, no permission at all. Anyone can bind.
        WEAK-PERM     exported behind a `normal` permission. Any app can hold
                      it by asking; this is not a gate. android.permission.
                      INTERNET as a service guard lands here, and it is a real
                      pattern in the field.
        DANGEROUS     exported behind a `dangerous` permission. A user prompt
                      stands in the way, which is a speed bump, not a wall.
        SIGNATURE     exported behind a signature-level permission. You need
                      the vendor's signing key. Usually the end of the road.
        SYSTEM-BIND   guarded by a BIND_* permission only the system holds
                      (BIND_ACCESSIBILITY_SERVICE and friends). Correctly
                      built; not a finding. Report it as a control observed.
        DISABLED      enabled=false. Can be flipped by the owning app.
        NOT-EXPORTED  only same-uid callers.

    It also flags:

        DIRECT-BOOT   directBootAware=true -- reachable BEFORE first unlock,
                      when much less of the system is up.
        OWN-PROCESS   android:process is not the app's main process. Killing
                      the app's main process does not stop it, and you must
                      attach a debugger to a different pid.

HOW TO RUN
    # host, device attached over adb. Sweep the whole device.
    python3 service-recon.py

    # only the interesting ones
    python3 service-recon.py --open
    python3 service-recon.py --weak

    # scope to one target
    python3 service-recon.py --package com.example.target

    # a component you already know about, including one with NO intent filter
    # (those are invisible to the resolver table -- see the caveats)
    python3 service-recon.py --component com.example.target/.VaultService

    # machine readable, for diffing two devices or two app versions
    python3 service-recon.py --json > device.json
    python3 service-recon.py --csv  > device.csv

    # capture once, analyse offline forever
    python3 service-recon.py --capture ./snap
    python3 service-recon.py --fixture ./snap --open

REQUIREMENTS
    Python 3.6+, standard library only. `adb` on PATH and one device attached,
    unless --fixture is used, in which case nothing is needed.
    NO ROOT. Every source it reads is available to the shell user.
    Measured against Android 11 / API 30 arm64; written to degrade rather than
    crash on other releases.

WHAT THIS WILL *NOT* TELL YOU
    - Whether a service is VULNERABLE. It tells you what you can REACH. Every
      actual finding comes from what the service does with your transaction,
      which means binding it and calling it -- README sections 5 and 7, and
      examples/attacker-app/. A table of OPEN services is a work queue, not a
      report.
    - Services with NO INTENT FILTER. The Service Resolver Table only knows
      about components that declared a filter. A service with
      android:exported="true" and no filter is fully reachable by explicit
      component name and does NOT appear here. Get those from the manifest
      (README section 8) and feed them back in with --component.
    - Whether YOUR app can see the package at all. From API 30, package
      visibility filtering hides most packages from an app with targetSdk 30+.
      This script runs as the shell user, which is exempt, so it sees more than
      your attacker app will. If a bind fails with `false` and no exception,
      that is visibility, not a control -- README section 3.6.1.
    - Whether onBind() will actually return a binder. A service can accept the
      bind and return null for an Intent it does not recognise. Measured on the
      test device: KeyChainService returns true from bindService and never
      connects. Only onServiceConnected proves reachability.
    - The transaction codes or the method names. Binder carries no schema. Bind
      it and ask the object for its descriptor -- that is free and it is what
      examples/attacker-app/ does.
    - Whether SELinux will let your domain call it. A `binder:call` denial is
      decided in the kernel before any of this matters. See 22-SELinux.
    - Anything about the platform's own /dev/binder services (the ones in
      `service list`). Those are a different namespace with a different manager;
      use 25-Binder/scripts/binder-service-map.py for them. This script is about
      APP services -- the ones you reach with bindService(), not with
      ServiceManager.getService().
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

SOURCES = {
    "resolver": "dumpsys package r",
    # -g as well as -f. Without -g, permissions that belong to a permission
    # GROUP are printed indented under their group heading and were being
    # missed: android.permission.RECORD_AUDIO was reported as "not declared on
    # this device", which is both wrong and alarming. -g makes the grouping
    # explicit and the indented form is handled below.
    "permissions": "pm list permissions -f -g",
    "getprop": ("getprop ro.build.version.release; getprop ro.build.version.sdk; "
                "getprop ro.product.model; getprop ro.product.cpu.abi"),
}

# Actions are used unquoted inside a device-side shell loop, so anything outside
# this character class is refused rather than interpolated. Real intent actions
# are dotted identifiers; anything else is either a scheme or something odd.
SAFE_ACTION = re.compile(r"^[A-Za-z0-9._\-]+$")


class Device(object):
    """Runs commands on the device, or serves them from a captured directory."""

    def __init__(self, fixture=None, serial=None):
        self.fixture = fixture
        self.serial = serial

    def _adb(self, shell_cmd, timeout=180):
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        cmd += ["shell", shell_cmd]
        try:
            out = subprocess.run(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            sys.stderr.write("adb failed: %s\n" % exc)
            return ""
        # adb's shell service translates LF to CRLF, and on a Windows host you
        # get CRLF back for every line. Normalise once, here, rather than
        # sprinkling \r into every regex downstream.
        return out.stdout.decode("utf-8", "replace").replace("\r\n", "\n")

    def get(self, key):
        if self.fixture:
            path = os.path.join(self.fixture, key + ".txt")
            if not os.path.exists(path):
                return ""
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        return self._adb(SOURCES[key])

    def query_actions(self, actions, batch=30):
        """Run `cmd package query-services -a ACTION` for many actions.

        Batched into one adb invocation per `batch` actions: a single query
        measured at about 30 ms on device, but a fresh adb round trip costs far
        more, so batching is what makes an 800-action sweep take seconds.
        """
        if self.fixture:
            path = os.path.join(self.fixture, "queries.txt")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            return ""
        chunks = []
        safe = [a for a in actions if SAFE_ACTION.match(a)]
        for i in range(0, len(safe), batch):
            group = safe[i:i + batch]
            script = "; ".join(
                'echo "@@ACTION %s"; cmd package query-services -a %s 2>/dev/null'
                % (a, a) for a in group)
            chunks.append(self._adb(script))
            sys.stderr.write("\r  queried %d/%d actions" % (min(i + batch, len(safe)),
                                                            len(safe)))
            sys.stderr.flush()
        sys.stderr.write("\n")
        return "\n".join(chunks)

    def query_component(self, comp):
        if self.fixture:
            return ""
        return self._adb('cmd package query-services -n %s 2>/dev/null' % comp)


def capture(dev, outdir):
    os.makedirs(outdir, exist_ok=True)
    for key in SOURCES:
        text = dev.get(key)
        with open(os.path.join(outdir, key + ".txt"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        sys.stderr.write("wrote %-24s %8d bytes\n" % (key + ".txt", len(text)))
    actions = parse_resolver_keys(dev.get("resolver"))
    text = dev.query_actions(actions)
    with open(os.path.join(outdir, "queries.txt"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    sys.stderr.write("wrote %-24s %8d bytes\n" % ("queries.txt", len(text)))


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------

# The Service Resolver Table groups components under a key, indented six spaces
# and ending in a colon; each component line is indented eight and carries a hex
# id then pkg/class.
RE_KEY = re.compile(r"^      (\S+):\s*$")
RE_COMP = re.compile(r"^        [0-9a-f]+ (\S+)\s*$")

# Inside `query-services`, ServiceInfo fields sit at EXACTLY six spaces and the
# nested ApplicationInfo fields at eight. That indent difference is the only
# thing separating "the service is enabled" from "the application is enabled",
# and both lines say `enabled=`. Anchor on the indent or you will report the
# application's flags as the service's.
RE_SVC_FIELD = re.compile(r"^      (\w+)=(.*)$")
RE_EXPORTED = re.compile(r"exported=(\w+)")
RE_ENABLED = re.compile(r"enabled=(\w+)")
RE_DBA = re.compile(r"directBootAware=(\w+)")

RE_PERM = re.compile(r"^\s*\+ permission:(\S+)\s*$")
RE_PROT = re.compile(r"^\s*protectionLevel:(\S+)\s*$")


def parse_resolver_keys(text):
    """-> the list of intent ACTIONS the Service Resolver Table knows about."""
    m = re.search(r"^Service Resolver Table:(.*?)^Provider Resolver Table:",
                  text, re.S | re.M)
    if not m:
        # Older dumps end the section differently; fall back to end of text.
        m = re.search(r"^Service Resolver Table:(.*)", text, re.S | re.M)
        if not m:
            return []
    section = m.group(1)
    # Only the "Non-Data Actions" group is queryable with `-a`. Schemes and MIME
    # types need `-d` / `-t` and are reported separately.
    nda = re.search(r"^  Non-Data Actions:(.*?)(?=^  \S|\Z)", section, re.S | re.M)
    body = nda.group(1) if nda else section
    # Line by line, not finditer: RE_KEY is anchored with ^ and is deliberately
    # NOT compiled with re.MULTILINE, because every other user of it matches a
    # single line at a time.
    out = []
    for line in body.splitlines():
        mk = RE_KEY.match(line)
        if mk:
            out.append(mk.group(1))
    return out


def parse_resolver_components(text):
    """-> {key: [component, ...]} across the whole Service Resolver Table."""
    m = re.search(r"^Service Resolver Table:(.*?)^Provider Resolver Table:",
                  text, re.S | re.M)
    if not m:
        return {}
    out = {}
    key = None
    for line in m.group(1).splitlines():
        mk = RE_KEY.match(line)
        if mk:
            key = mk.group(1)
            out.setdefault(key, [])
            continue
        mc = RE_COMP.match(line)
        if mc and key is not None:
            out[key].append(mc.group(1))
    return out


def parse_permissions(text):
    """-> {permission_name: protectionLevel}"""
    out = {}
    name = None
    for line in text.splitlines():
        mp = RE_PERM.match(line)
        if mp:
            name = mp.group(1)
            continue
        if name:
            ml = RE_PROT.match(line)
            if ml:
                out[name] = ml.group(1)
                name = None
    return out


def parse_queries(text):
    """-> {pkg/class: record} from batched `query-services` output."""
    svcs = {}
    action = None
    cur = None
    for line in text.splitlines():
        if line.startswith("@@ACTION "):
            action = line[9:].strip()
            cur = None
            continue
        if line.strip() == "ServiceInfo:":
            cur = {}
            continue
        if cur is None:
            continue
        m = RE_SVC_FIELD.match(line)
        if not m:
            # Indent changed: we have left the ServiceInfo block.
            if line.strip() and not line.startswith("        "):
                cur = None
            continue
        field, value = m.group(1), m.group(2)
        if field == "name":
            cur["name"] = value.strip()
        elif field == "packageName":
            cur["pkg"] = value.strip()
            key = cur["pkg"] + "/" + cur.get("name", "?")
            rec = svcs.setdefault(key, {
                "pkg": cur["pkg"], "name": cur.get("name", "?"),
                "actions": set(), "perm": None, "exported": None,
                "enabled": None, "directBootAware": None, "process": None,
            })
            if action:
                rec["actions"].add(action)
            cur = rec
        elif field == "processName":
            cur["process"] = value.strip()
        elif field == "permission":
            v = value.strip()
            cur["perm"] = None if v in ("null", "") else v
        elif field == "enabled":
            me = RE_ENABLED.search(line)
            mx = RE_EXPORTED.search(line)
            md = RE_DBA.search(line)
            if me:
                cur["enabled"] = me.group(1)
            if mx:
                cur["exported"] = mx.group(1)
            if md:
                cur["directBootAware"] = md.group(1)
    return svcs


# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------

# Permissions whose whole purpose is "only the platform may bind me". Seeing one
# of these is a sign the developer used the intended pattern.
SYSTEM_BIND = re.compile(r"^android\.permission\.BIND_")


def verdict(rec, prot_levels):
    if rec.get("enabled") == "false":
        return "DISABLED", "enabled=false; the owning app can turn it back on"
    if rec.get("exported") != "true":
        return "NOT-EXPORTED", "same-uid callers only"

    perm = rec.get("perm")
    if not perm:
        return "OPEN", "exported with no permission -- any app can bind"

    if SYSTEM_BIND.match(perm):
        return "SYSTEM-BIND", ("guarded by %s, which only the system holds. "
                               "This is the correct pattern" % perm)

    level = prot_levels.get(perm)
    if level is None:
        return "UNKNOWN-PERM", ("permission %s is not declared on this device "
                                "-- the declaring app is not installed, so "
                                "NOBODY can hold it here" % perm)

    base = level.split("|")[0]
    if base == "normal":
        return "WEAK-PERM", ("%s is protectionLevel=%s -- granted at install to "
                             "any app that asks. Not a gate" % (perm, level))
    if base == "dangerous":
        return "DANGEROUS", ("%s is protectionLevel=%s -- a runtime prompt, not "
                             "a wall" % (perm, level))
    if base == "signature":
        return "SIGNATURE", "%s is protectionLevel=%s" % (perm, level)
    return "OTHER-PERM", "%s is protectionLevel=%s" % (perm, level)


ORDER = {"OPEN": 0, "WEAK-PERM": 1, "DANGEROUS": 2, "UNKNOWN-PERM": 3,
         "OTHER-PERM": 4, "SIGNATURE": 5, "SYSTEM-BIND": 6,
         "NOT-EXPORTED": 7, "DISABLED": 8}


def build(dev, only_component=None):
    resolver = dev.get("resolver")
    prot = parse_permissions(dev.get("permissions"))

    if only_component:
        text = dev.query_component(only_component)
        svcs = parse_queries("@@ACTION (explicit)\n" + text)
    else:
        actions = parse_resolver_keys(resolver)
        sys.stderr.write("Service Resolver Table: %d queryable actions\n"
                         % len(actions))
        svcs = parse_queries(dev.query_actions(actions))

    rows = []
    for key, rec in svcs.items():
        v, why = verdict(rec, prot)
        flags = []
        if rec.get("directBootAware") == "true":
            flags.append("DIRECT-BOOT")
        proc = rec.get("process")
        if proc and proc != rec["pkg"]:
            flags.append("OWN-PROCESS")
        rows.append({
            "component": key,
            "pkg": rec["pkg"],
            "name": rec["name"],
            "exported": rec.get("exported"),
            "enabled": rec.get("enabled"),
            "permission": rec.get("perm") or "",
            "protection": prot.get(rec.get("perm") or "", ""),
            "process": proc or "",
            "actions": sorted(rec["actions"]),
            "verdict": v,
            "why": why,
            "flags": flags,
        })
    rows.sort(key=lambda r: (ORDER.get(r["verdict"], 9), r["pkg"], r["name"]))
    return rows, prot


def device_banner(dev):
    vals = [v.strip() for v in dev.get("getprop").splitlines() if v.strip()]
    while len(vals) < 4:
        vals.append("?")
    return "device: %s  Android %s (API %s)  %s" % (vals[2], vals[0], vals[1], vals[3])


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def print_table(rows):
    if not rows:
        print("(nothing matched)")
        return

    def w(key, minimum):
        return max(minimum, max(len(str(r[key])) for r in rows))

    wc = min(w("component", 9), 76)
    wv = min(w("verdict", 7), 13)
    wp = min(w("permission", 10), 52)

    hdr = "%-*s  %-*s  %-*s  %s" % (wv, "VERDICT", wc, "COMPONENT",
                                    wp, "PERMISSION", "FLAGS")
    print(hdr)
    print("-" * min(len(hdr), 160))
    for r in rows:
        print("%-*s  %-*s  %-*s  %s"
              % (wv, r["verdict"], wc, r["component"][:wc],
                 wp, (r["permission"] or "-")[:wp],
                 ",".join(r["flags"])))


def print_summary(rows):
    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    pkgs = sorted(set(r["pkg"] for r in rows if r["verdict"] == "OPEN"))
    print("")
    print("SUMMARY")
    print("  services seen via an intent action : %d" % len(rows))
    for v in sorted(counts, key=lambda k: ORDER.get(k, 9)):
        print("  %-33s : %d" % (v, counts[v]))
    print("  distinct packages with an OPEN one : %d" % len(pkgs))
    print("")
    print("  OPEN is a WORK QUEUE, not a finding. Bind each one, read the")
    print("  descriptor off the binder, and show what a method actually does.")
    print("  An exported service with an inert interface is not a bug.")


def print_explain(rows, component):
    hit = [r for r in rows if r["component"] == component
           or r["component"].endswith("/" + component)]
    if not hit:
        near = [r["component"] for r in rows
                if component.lower() in r["component"].lower()]
        print("no service matching %r" % component)
        if near:
            print("did you mean:")
            for n in near[:12]:
                print("  " + n)
        return
    r = hit[0]
    print("COMPONENT     %s" % r["component"])
    print("VERDICT       %s" % r["verdict"])
    print("WHY           %s" % r["why"])
    print("EXPORTED      %s" % r["exported"])
    print("ENABLED       %s" % r["enabled"])
    print("PERMISSION    %s" % (r["permission"] or "(none)"))
    print("PROTECTION    %s" % (r["protection"] or "-"))
    print("PROCESS       %s" % (r["process"] or "(app main process)"))
    print("FLAGS         %s" % (",".join(r["flags"]) or "-"))
    print("ACTIONS       %s" % (", ".join(r["actions"]) or "(none seen)"))
    print("")
    print("NEXT STEPS")
    print("  # 1. Prove it is reachable. bindService() returning true is NOT")
    print("  #    enough -- wait for onServiceConnected. See")
    print("  #    examples/attacker-app/ProbeActivity.java")
    print("  adb shell am start -n com.pentest.ch28probe/.ProbeActivity \\")
    print("      --es targets '%s'" % r["component"])
    print("  # 2. Read the interface descriptor off the binder you were given.")
    print("  #    That is IBinder.getInterfaceDescriptor(), transaction code")
    print("  #    1598968902 ('_NTF'). It is free and it names the AIDL")
    print("  #    interface, which is where the method names live.")
    print("  # 3. Only then go looking for the code:")
    print("  adb shell pm path %s" % r["pkg"])
    print("  #    jadx the APK and read the Stub, README section 6.")
    if r["verdict"] in ("SIGNATURE", "SYSTEM-BIND"):
        print("")
        print("  This one is GATED. Write it up as a control observed, not a")
        print("  finding, and move on.")


def main():
    ap = argparse.ArgumentParser(
        description="Rank app services by what an unprivileged app can reach.")
    ap.add_argument("--fixture", help="analyse a directory made by --capture")
    ap.add_argument("--capture", metavar="DIR",
                    help="save every source to DIR and exit")
    ap.add_argument("-s", "--serial", help="adb device serial")
    ap.add_argument("--package", help="only services in this package")
    ap.add_argument("--component", metavar="PKG/CLS",
                    help="query one component directly. Use this for a service "
                         "with NO intent filter, which the resolver table "
                         "cannot see")
    ap.add_argument("--explain", metavar="PKG/CLS",
                    help="everything known about one service, plus next steps")
    ap.add_argument("--open", action="store_true",
                    help="only OPEN (exported, no permission)")
    ap.add_argument("--weak", action="store_true",
                    help="only OPEN, WEAK-PERM, DANGEROUS and UNKNOWN-PERM")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--csv", action="store_true")
    args = ap.parse_args()

    dev = Device(fixture=args.fixture, serial=args.serial)

    if args.capture:
        capture(dev, args.capture)
        return 0

    rows, _ = build(dev, only_component=args.component)
    if not rows:
        sys.stderr.write(
            "No services parsed. Check a device is attached (adb devices), or "
            "that --fixture points at a --capture directory.\n")
        return 1

    if args.package:
        rows = [r for r in rows if r["pkg"] == args.package]

    if args.explain:
        print_explain(rows, args.explain)
        return 0

    subset = rows
    if args.open:
        subset = [r for r in rows if r["verdict"] == "OPEN"]
    elif args.weak:
        subset = [r for r in rows if r["verdict"] in
                  ("OPEN", "WEAK-PERM", "DANGEROUS", "UNKNOWN-PERM")]

    if args.json:
        json.dump(subset, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    if args.csv:
        wr = csv.DictWriter(
            sys.stdout,
            fieldnames=["verdict", "component", "pkg", "name", "exported",
                        "enabled", "permission", "protection", "process",
                        "flags", "actions", "why"],
            lineterminator="\n")
        wr.writeheader()
        for r in subset:
            row = dict(r)
            row["flags"] = ";".join(r["flags"])
            row["actions"] = ";".join(r["actions"])
            wr.writerow(row)
        return 0

    print(device_banner(dev))
    print("")
    print_table(subset)
    print_summary(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
