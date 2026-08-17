#!/usr/bin/env python3
"""
coverage-reporter.py -- say which of an application's components you ACTUALLY
                        REACHED during a dynamic pass, and which you did not.

WHAT IT DOES
    A dynamic finding is bounded by what you exercised. A clean dynamic pass
    proves that nothing bad happened on the paths you drove; it proves nothing
    at all about the paths you never touched. That distinction is the single
    most common lie in mobile reporting, and it is invisible unless somebody
    writes the coverage down.

    This script writes it down. Given

      * a COMPONENT INVENTORY   -- what the app could do, and
      * an EVIDENCE SET         -- what the device recorded while you drove it,

    it prints, per component, REACHED or NOT REACHED, with the specific line of
    evidence that settled it, and a summary you can paste into a report's
    limits section verbatim.

    The inventory comes from one of two places, and they are not equivalent:

      --components FILE   the entry-point list from your STATIC pass. This is
                          the right source. 52-StaticAnalysis section 3.4
                          produces exactly this file with one awk command, and
                          it includes components that have no intent-filter --
                          which the device cannot tell you about.
      (default)           the device's own resolver tables, via
                          `dumpsys package <pkg>`. Requires no APK and no
                          static pass, and is INCOMPLETE BY CONSTRUCTION: the
                          resolver tables list only components carrying an
                          intent-filter. A non-exported Activity started by
                          explicit Intent from inside the app appears nowhere.
                          The script says so in its output every single time,
                          because a coverage figure computed against an
                          incomplete denominator flatters you.

    The evidence comes from any combination of:

      --logcat FILE       a log capture covering the window. `session-recorder.sh`
                          writes one at <evidence>/09-logcat.txt.
      --dumpsys-dir DIR   captured dumpsys output (see --capture).
      (default)           live `dumpsys` on the attached device, which reflects
                          the CURRENT state plus whatever history AMS retains.

WHAT THIS WILL *NOT* TELL YOU
    - Code coverage. This measures COMPONENTS, which is the coarsest useful
      unit on Android. Reaching `CheckoutActivity` says nothing about whether
      you reached the refund branch inside it. Component coverage is a floor,
      not a ceiling: 100% here is entirely compatible with having exercised a
      small fraction of the code. For instruction-level coverage you need
      Stalker (53-Frida section 7.9) or a coverage-instrumented build.
    - Anything about code with no component at all. A library that runs from a
      `ContentProvider` initialiser, a JNI function, a thread started in
      `Application.onCreate` -- none of these are components and none appear
      below. The denominator is not the program.
    - Whether reaching a component achieved anything. `START ... cmp=X` in
      logcat proves the platform was ASKED to start X. It does not prove X ran
      to completion, and on the test device a launch was measured that logged
      START and then showed a permission dialog instead -- see README section
      3.6.4. Read the evidence line, do not trust the tick.
    - Who reached it. A component you reached from `adb shell` was reached by
      uid 2000, which holds capabilities no ordinary app has. Chapter 60
      measured that `com.android.shell` requests 200 permissions, 16 of them
      pre-granted SYSTEM_FIXED. Reachability from the shell is not reachability
      from an app.
    - Anything about a component that was reached before your capture started,
      or after it ended.

HOW TO RUN
    # host -- the normal case: static inventory, dynamic evidence
    python3 -B coverage-reporter.py --package com.example.target \\
            --components entrypoints.txt --logcat ./evidence/s01/09-logcat.txt

    # host -- no static pass yet: derive the inventory from the device
    python3 -B coverage-reporter.py --package com.example.target \\
            --logcat ./evidence/s01/09-logcat.txt

    # host -- capture the dumpsys evidence now, analyse later or offline
    python3 -B coverage-reporter.py --package com.example.target --capture ./ev/dump

    # host -- markdown for the report, and JSON for the pipeline
    python3 -B coverage-reporter.py -p com.example.target -c entrypoints.txt \\
            --logcat ev/09-logcat.txt --markdown coverage.md --json coverage.json

REQUIREMENTS
    Python 3.8 or newer, standard library only.
    `adb` on PATH for live modes; nothing at all for --components + --logcat.
    No root, no frida-server, no instrumentation on the device.

RELATED
    ../README.md section 3.7          coverage, and why it is stage zero
    ../README.md section 7.7          writing the coverage statement
    ./session-recorder.sh             produces the logcat this reads
    ../examples/coverage-ledger.md    a worked ledger with real numbers
    ../../52-StaticAnalysis/README.md section 3.4
                                      produces the --components file
    ../../53-Frida/README.md section 7.9
                                      instruction-level coverage, when this is
                                      too coarse to answer your question

AUTHORISED TESTING ONLY. Only run this against applications you own or have
written permission to test. This script is read-only: it starts nothing on the
device, installs nothing and changes no state.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import OrderedDict

VERSION = "1.0"

# ---------------------------------------------------------------------------
# adb plumbing.
#
# Every device command is passed as ONE argument to `adb shell`, already quoted
# the way the DEVICE's /system/bin/sh will read it. `adb shell` does not
# preserve host quoting -- it joins argv with spaces -- and forgetting that has
# silently broken scripts elsewhere in this repository.
# ---------------------------------------------------------------------------


class Adb:
    def __init__(self, serial=None):
        self.base = ["adb"] + (["-s", serial] if serial else [])
        self.available = None

    def check(self):
        if self.available is not None:
            return self.available
        try:
            out = subprocess.run(self.base + ["get-state"], capture_output=True,
                                 text=True, timeout=15)
            self.available = (out.returncode == 0 and "device" in out.stdout)
        except Exception:
            self.available = False
        return self.available

    def shell(self, cmd, timeout=120):
        try:
            out = subprocess.run(self.base + ["shell", cmd], capture_output=True,
                                 text=True, timeout=timeout, errors="replace")
            return out.stdout.replace("\r\n", "\n")
        except Exception as exc:                       # pragma: no cover
            sys.stderr.write("adb shell failed (%s): %s\n" % (cmd, exc))
            return ""


# ---------------------------------------------------------------------------
# The inventory -- the denominator.
# ---------------------------------------------------------------------------

KIND_ORDER = ["activity", "service", "receiver", "provider", "unknown"]


def load_components_file(path, pkg):
    """Read an entry-point list, one component per line.

    Accepts every form these lists come in, because the file usually arrives
    from somebody else's awk:

        com.example.target.MainActivity
        .MainActivity
        com.example.target/com.example.target.MainActivity
        com.example.target/.MainActivity

    Lines beginning with '#' and blank lines are ignored. A trailing
    ``kind=activity`` token, if present, is honoured; otherwise the kind is
    inferred from the class name and marked as inferred, because guessing that
    ``FooService`` is a service is a convenience, not a fact.
    """
    comps = OrderedDict()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            kind = None
            m = re.search(r"\bkind=(activity|service|receiver|provider)\b", line)
            if m:
                kind = m.group(1)
                line = line[:m.start()].strip()
            if "/" in line:
                _, _, line = line.partition("/")
                line = line.strip()
            if line.startswith("."):
                line = pkg + line
            if not line:
                continue
            if kind is None:
                kind = infer_kind(line)
            comps.setdefault(line, {"kind": kind, "source": "static",
                                    "inferred_kind": bool(m is None)})
    return comps


def infer_kind(cls):
    low = cls.lower()
    if low.endswith("activity") or "activity" in low.rsplit(".", 1)[-1]:
        return "activity"
    if low.endswith("service"):
        return "service"
    if low.endswith("receiver") or low.endswith("broadcastreceiver"):
        return "receiver"
    if low.endswith("provider") or low.endswith("contentprovider"):
        return "provider"
    return "unknown"


SECTION_KIND = {
    "Activity Resolver Table": "activity",
    "Receiver Resolver Table": "receiver",
    "Service Resolver Table": "service",
    "Provider Resolver Table": "provider",
    "Registered ContentProviders": "provider",
    "ContentProvider Authorities": "provider",
}


def inventory_from_device(adb, pkg):
    """Derive the inventory from the platform's own resolver tables.

    INCOMPLETE BY CONSTRUCTION. `dumpsys package` lists a component in a
    resolver table only if it carries an intent-filter, because the resolver
    tables exist to answer "which component would win this Intent". A component
    with no filter is still a component -- it is simply not resolvable by
    Intent, so PackageManager has no reason to index it.

    The consequence for you is direct: any coverage percentage computed against
    this denominator is computed against a subset, and is therefore optimistic.
    The report says so.
    """
    dump = adb.shell("dumpsys package %s" % pkg)
    comps = OrderedDict()
    kind = "unknown"
    pat = re.compile(re.escape(pkg) + r"/([A-Za-z0-9_$.]+)")
    for line in dump.split("\n"):
        stripped = line.strip().rstrip(":")
        if stripped in SECTION_KIND:
            kind = SECTION_KIND[stripped]
            continue
        if line and not line[0].isspace() and line.endswith(":"):
            kind = SECTION_KIND.get(stripped, "unknown")
            continue
        for m in pat.finditer(line):
            cls = m.group(1)
            if cls.startswith("."):
                cls = pkg + cls
            if not re.match(r"^[A-Za-z_$]", cls) or cls.startswith("u0a"):
                continue
            comps.setdefault(cls, {"kind": kind, "source": "device",
                                   "inferred_kind": False})
    return comps, dump


# ---------------------------------------------------------------------------
# The evidence -- the numerator.
#
# Every rule below is a pair: a regex, and a plain-English sentence saying what
# a match PROVES. The second half is the important one. "START ... cmp=X" does
# not prove X ran; it proves the platform was asked to start it. Anything that
# collapses those two into a green tick will eventually let somebody write
# "fully covered" about a screen that crashed on entry.
# ---------------------------------------------------------------------------

EVIDENCE_RULES = [
    ("logcat", r"ActivityTaskManager:\s*START\b[^\n]*cmp=%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)",
     "the platform was asked to start this Activity"),
    ("logcat", r"ActivityManager:\s*START\b[^\n]*cmp=%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)",
     "the platform was asked to start this Activity"),
    ("logcat", r"Displayed\s+%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)",
     "the Activity was drawn -- the strongest Activity evidence there is"),
    ("logcat", r"ActivityRecord\{[^}]*\s%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)",
     "an ActivityRecord existed for this Activity"),
    ("logcat", r"ServiceRecord\{[^}]*\s%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)",
     "a ServiceRecord existed for this Service"),
    ("logcat", r"(?:Start|Bind)ing service[^\n]*%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)",
     "the platform started or bound this Service"),
    # AMS announces a process spawn caused by a service in this shape, and it is
    # the most common Service evidence there is:
    #   Start proc 22140:pkg:sync/u0a214 for service {pkg/.sync.SyncService}
    # It matches none of the ServiceRecord patterns, and missing it silently
    # under-counts Service coverage -- which flatters nobody but is still wrong.
    ("logcat", r"for service \{%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)\}",
     "a process was started to host this Service"),
    ("logcat", r"for (?:restart of )?service \{%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)\}",
     "a process was started to host this Service"),
    ("logcat", r"BroadcastRecord\{[^}]*\}[^\n]*%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)",
     "a broadcast was dispatched to this Receiver"),
    ("dumpsys-activities", r"ActivityRecord\{[^}]*\s%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)",
     "the Activity is in the current task stack or recent history"),
    ("dumpsys-services", r"ServiceRecord\{[^}]*\s%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)",
     "the Service is running or was recently"),
    ("dumpsys-providers", r"ContentProviderRecord\{[^}]*\s%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)",
     "the ContentProvider was published into a process"),
    ("dumpsys-broadcasts", r"BroadcastRecord\{[^}]*\}[^\n]*%(pkg)s/(?P<cls>[A-Za-z0-9_$.]+)",
     "a broadcast reached this Receiver within AMS's retained history"),
]


def gather_evidence(pkg, sources):
    """Return {class: [(source, proves, sample_line), ...]}."""
    hits = {}
    for src_name, text in sources.items():
        if not text:
            continue
        lines = text.split("\n")
        for rule_src, pattern, proves in EVIDENCE_RULES:
            if rule_src != src_name and not (rule_src == "logcat" and src_name == "logcat"):
                continue
            rx = re.compile(pattern % {"pkg": re.escape(pkg)})
            for line in lines:
                m = rx.search(line)
                if not m:
                    continue
                cls = m.group("cls")
                if cls.startswith("."):
                    cls = pkg + cls
                hits.setdefault(cls, [])
                if not any(h[0] == src_name and h[1] == proves for h in hits[cls]):
                    hits[cls].append((src_name, proves, line.strip()[:200]))
    return hits


# ---------------------------------------------------------------------------
# Reporting.
# ---------------------------------------------------------------------------

def build_rows(comps, hits):
    rows = []
    for cls, meta in comps.items():
        ev = hits.get(cls, [])
        rows.append({
            "component": cls,
            "short": cls.rsplit(".", 1)[-1],
            "kind": meta["kind"],
            "inventory_source": meta["source"],
            "inferred_kind": meta.get("inferred_kind", False),
            "reached": bool(ev),
            "evidence": [{"source": s, "proves": p, "line": l} for s, p, l in ev],
        })
    rows.sort(key=lambda r: (KIND_ORDER.index(r["kind"]) if r["kind"] in KIND_ORDER else 9,
                             not r["reached"], r["component"]))
    return rows


def orphan_hits(comps, hits):
    """Components the evidence names that the inventory does not contain.

    This set is never empty on a real app and it is not noise -- it is the
    denominator being wrong. Each orphan is either a component your static pass
    missed, an inner class, or a component of a different package that happened
    to match. Reading it is how you discover that your entry-point list was
    built from the wrong split.
    """
    return sorted(c for c in hits if c not in comps)


def render_markdown(pkg, rows, orphans, meta):
    L = []
    a = L.append
    total = len(rows)
    reached = sum(1 for r in rows if r["reached"])
    pct = (100.0 * reached / total) if total else 0.0

    a("# Coverage -- `%s`" % pkg)
    a("")
    a("Produced by `coverage-reporter.py %s`. This is a record of **what was"
      % VERSION)
    a("exercised**, not a record of what was found. Attach it to any dynamic")
    a("finding, and to any statement that begins \"we did not observe\".")
    a("")
    a("| | |")
    a("|---|---|")
    a("| Package | `%s` |" % pkg)
    a("| Inventory source | %s |" % meta["inventory_source"])
    a("| Evidence sources | %s |" % (", ".join(meta["evidence_sources"]) or "none"))
    a("| Components in inventory | %d |" % total)
    a("| Reached | **%d (%.0f%%)** |" % (reached, pct))
    a("| Not reached | %d |" % (total - reached))
    if meta["device"]:
        a("| Device | %s |" % meta["device"])
    a("")
    if meta["inventory_source"].startswith("device"):
        a("> **The denominator is incomplete.** It was derived from the platform's"
          " resolver")
        a("> tables, which index only components that carry an intent-filter. Components")
        a("> started by explicit Intent from inside the app are missing from it, so the")
        a("> percentage above is an **upper bound on your true coverage**. Re-run with")
        a("> `--components` from a static pass before quoting the figure.")
        a("")
    a("---")
    a("")

    for kind in KIND_ORDER:
        group = [r for r in rows if r["kind"] == kind]
        if not group:
            continue
        gr = sum(1 for r in group if r["reached"])
        plural = {"activity": "Activities", "service": "Services",
                  "receiver": "Receivers", "provider": "Providers",
                  "unknown": "Unclassified components"}[kind]
        a("## %s (%d of %d reached)" % (plural, gr, len(group)))
        a("")
        a("| Component | Reached | What the evidence proves |")
        a("|---|---|---|")
        for r in group:
            if r["reached"]:
                best = r["evidence"][0]
                a("| `%s` | yes | %s (`%s`) |" % (r["short"], best["proves"], best["source"]))
            else:
                a("| `%s` | **no** | -- |" % r["short"])
        a("")

    if orphans:
        a("## Reached, but not in the inventory (%d)" % len(orphans))
        a("")
        a("Each of these is a component the evidence names and the inventory does not.")
        a("That is a defect in the **denominator**, and it is worth ten minutes: the")
        a("usual causes are an entry-point list built from `base.apk` without its")
        a("splits, an inner or synthetic class, or a component contributed by a library")
        a("manifest at merge time.")
        a("")
        for c in orphans:
            a("- `%s`" % c)
        a("")

    a("---")
    a("")
    a("## The statement to put in the report")
    a("")
    a("```")
    a("COVERAGE OF THE DYNAMIC PASS")
    a("")
    a("Of %d components enumerated for %s, %d (%.0f%%) were" % (total, pkg, reached, pct))
    a("reached during the observation window. The remaining %d were not"
      % (total - reached))
    a("exercised, and no statement in this report -- positive or negative --")
    a("applies to them.")
    a("")
    a("Components NOT exercised:")
    for r in rows:
        if not r["reached"]:
            a("  - %s (%s)" % (r["component"], r["kind"]))
    a("")
    a("Component coverage is not code coverage. Reaching a component says")
    a("nothing about which branches inside it executed.")
    a("```")
    a("")
    a("> **A dynamic pass that reached 100% of components is still not a clean bill of")
    a("> health.** It is a statement that you drove every front door. The branches")
    a("> behind each door are a separate question, and 52-StaticAnalysis is what")
    a("> enumerates them.")
    return "\n".join(L)


def main():
    p = argparse.ArgumentParser(
        prog="coverage-reporter.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Report which components a dynamic pass actually reached.",
        epilog="Coverage is not a finding and 100%% is not a clean bill of health. "
               "Component coverage is a floor; code coverage is a different question.")
    p.add_argument("-p", "--package", required=True, help="applicationId of the target")
    p.add_argument("-c", "--components", metavar="FILE",
                   help="entry-point list from the static pass (one component per line)")
    p.add_argument("--logcat", metavar="FILE", action="append", default=[],
                   help="log capture covering the window; repeatable")
    p.add_argument("--dumpsys-dir", metavar="DIR",
                   help="directory of captured dumpsys output (see --capture)")
    p.add_argument("--capture", metavar="DIR",
                   help="capture the dumpsys evidence to DIR and exit")
    p.add_argument("-s", "--serial", help="adb device serial")
    p.add_argument("--no-device", action="store_true",
                   help="never touch a device; use only --components and files")
    p.add_argument("--markdown", metavar="FILE", help="write the report to FILE")
    p.add_argument("--json", metavar="FILE", help="write machine-readable output to FILE")
    p.add_argument("--version", action="version", version="coverage-reporter.py " + VERSION)
    args = p.parse_args()

    pkg = args.package
    adb = Adb(args.serial)
    live = (not args.no_device) and adb.check()

    DUMPS = {
        "dumpsys-activities": ("dumpsys activity activities", "activities.txt"),
        "dumpsys-services": ("dumpsys activity services %s" % pkg, "services.txt"),
        "dumpsys-providers": ("dumpsys activity providers", "providers.txt"),
        "dumpsys-broadcasts": ("dumpsys activity broadcasts", "broadcasts.txt"),
    }

    if args.capture:
        if not live:
            sys.exit("coverage-reporter: --capture needs a device")
        os.makedirs(args.capture, exist_ok=True)
        for key, (cmd, fname) in DUMPS.items():
            with open(os.path.join(args.capture, fname), "w",
                      encoding="utf-8") as fh:
                fh.write(adb.shell(cmd))
        with open(os.path.join(args.capture, "package.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write(adb.shell("dumpsys package %s" % pkg))
        print("captured to %s" % args.capture)
        return 0

    # ---- inventory --------------------------------------------------------
    if args.components:
        comps = load_components_file(args.components, pkg)
        inv_source = "static pass (`%s`), %d component(s)" % (args.components, len(comps))
    elif live:
        comps, _ = inventory_from_device(adb, pkg)
        inv_source = "device resolver tables -- **incomplete, see the note below**"
    else:
        sys.exit("coverage-reporter: give --components FILE, or attach a device")

    if not comps:
        sys.exit("coverage-reporter: inventory is empty -- is the package name right?")

    # ---- evidence ---------------------------------------------------------
    sources = {}
    used = []
    logtext = []
    for f in args.logcat:
        try:
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                logtext.append(fh.read())
            used.append("logcat `%s`" % os.path.basename(f))
        except OSError as exc:
            sys.stderr.write("cannot read %s: %s\n" % (f, exc))
    if logtext:
        sources["logcat"] = "\n".join(logtext)

    if args.dumpsys_dir:
        for key, (_, fname) in DUMPS.items():
            path = os.path.join(args.dumpsys_dir, fname)
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    sources[key] = fh.read()
                used.append("captured `%s`" % fname)
    elif live:
        for key, (cmd, _) in DUMPS.items():
            sources[key] = adb.shell(cmd)
        used.append("live dumpsys (4 sections)")

    if not sources:
        sys.exit("coverage-reporter: no evidence. Give --logcat and/or attach a device.")

    device = ""
    if live:
        device = "%s / API %s" % (adb.shell("getprop ro.product.model").strip(),
                                  adb.shell("getprop ro.build.version.sdk").strip())

    hits = gather_evidence(pkg, sources)
    rows = build_rows(comps, hits)
    orphans = orphan_hits(comps, hits)
    meta = {"inventory_source": inv_source, "evidence_sources": used, "device": device}

    md = render_markdown(pkg, rows, orphans, meta)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(md + "\n")
        sys.stderr.write("report written: %s\n" % args.markdown)
    else:
        print(md)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"version": VERSION, "package": pkg, "meta": meta,
                       "components": rows, "orphans": orphans}, fh, indent=2)
        sys.stderr.write("json written: %s\n" % args.json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
