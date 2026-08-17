#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
intent-surface-map.py — map an application's RUNTIME Intent surface from a device.

PURPOSE
    Answer three questions that a manifest cannot answer, because they are
    properties of the platform's live resolver tables rather than of an APK:

      1. Which components would actually RESOLVE for a given Intent, device-wide?
         (`--action/--data/--type/--category`)

      2. For one package, which of its declared filters are reachable by an
         IMPLICIT Intent from another app, and what is the full cross product of
         scheme x host x path x mimeType that each filter accepts?
         (`--package PKG --components`)

      3. In a decompiled tree, where are the two code-level primitives this
         chapter owns — an Intent taken out of an extra and started (intent
         redirection), and a PendingIntent created without FLAG_IMMUTABLE?
         (`--pending DIR`, `--redirect DIR`)

WHY THIS IS NOT ANOTHER MANIFEST SCANNER
    32-Manifest/scripts/manifest-audit.py already audits the DECLARATION: it
    parses AndroidManifest.xml (text or `aapt2 dump xmltree`), applies the
    targetSdk export-default matrix, resolves protectionLevels and rates
    severity. It is the right tool for an APK on disk and this script does not
    duplicate one line of it. Run it first.

    This script starts where that ends. It reads what the PLATFORM recorded
    after parsing, merging and resolving that manifest — `dumpsys package`
    resolver tables and `cmd package query-*` — so it sees library-injected
    filters, resolved resource references, obfuscated final class names, and the
    live `exported` flag as PackageManagerService holds it. It never opens an
    APK and never parses AndroidManifest.xml.

WHAT THIS WILL *NOT* TELL YOU
    * Whether anything here is a vulnerability. Every line of output is a LEAD.
      An exported component is a precondition, never a finding. You still need
      (a) reachability from an UNPRIVILEGED APP -- not from adb shell, which
      runs as uid 2000 and is privileged -- and (b) a demonstrated consequence.
    * What a component DOES with the Intent. Read the code, or hook it with
      scripts/intent-monitor.js.
    * Whether a deep link is exclusive. Verification state is a separate
      question with a version-dependent answer; use scripts/appstate-linkcheck.sh.
    * Dynamically registered BroadcastReceivers. They are not in any manifest
      and not in the static resolver tables. Hook registerReceiver instead.
    * What the TARGET APP can see. From targetSdk 30 an app's own
      queryIntentActivities is filtered by package visibility; `adb shell` is
      not. A device-wide result set is the PLATFORM's view, not the app's.
      The script warns about this whenever it prints a device-wide query.
    * Anything about a component's permission protectionLevel -- resolve those
      with `adb shell pm list permissions -f`, or with manifest-audit.py.

HOW TO RUN
    # host -- everything that would receive a deep link, device-wide
    python3 intent-surface-map.py --action android.intent.action.VIEW \
        --category android.intent.category.BROWSABLE \
        --data 'https://app.example.com/open/1'

    # host -- MIME-typed query
    python3 intent-surface-map.py --action android.intent.action.SEND --type 'text/plain'

    # host -- one package's filters, with the data cross product
    python3 intent-surface-map.py --package com.example.target --components

    # host -- same, but confirm each filter really resolves and read `exported`
    python3 intent-surface-map.py --package com.example.target --components --verify

    # host -- probe every exported activity of a package with an empty Intent
    python3 intent-surface-map.py --package com.example.target --probe --dry-run
    python3 intent-surface-map.py --package com.example.target --probe      # authorised targets only

    # host -- code-level primitives in a decompiled tree (jadx -d out, apktool d -o work)
    python3 intent-surface-map.py --redirect work/          # smali or java
    python3 intent-surface-map.py --pending  out/sources/

    # offline: feed a captured dumpsys instead of talking to a device
    adb shell "dumpsys package com.example.target" > fixture.txt
    python3 intent-surface-map.py --package com.example.target --components \
        --dumpsys-file fixture.txt

    # machine-readable
    python3 intent-surface-map.py --package com.example.target --components --json

REQUIREMENTS
    Python 3.7+, standard library only. `adb` on PATH and a device attached for
    the device modes; nothing at all for --redirect / --pending / --dumpsys-file.
    Never writes files next to itself. Run it as a script (python3 -B if you are
    worried about __pycache__; this script imports nothing that would create one).

EXIT CODES
    0  ran successfully
    1  nothing found / no device
    2  bad usage or unparseable input

AUTHORISED TESTING ONLY. Probing components changes application state.
"""

import argparse
import json
import os
import re
import subprocess
import sys

# --------------------------------------------------------------------------- #
#  IntentFilter.match() return-value decoding
#  frameworks/base/core/java/android/content/IntentFilter.java
# --------------------------------------------------------------------------- #

MATCH_CATEGORY_MASK = 0x0FFF0000
MATCH_ADJUSTMENT_MASK = 0x0000FFFF

MATCH_CATEGORIES = {
    0x00100000: "EMPTY (action/category only, no data)",
    0x00200000: "SCHEME",
    0x00300000: "HOST (scheme + host)",
    0x00400000: "PORT (scheme + host + port)",
    0x00500000: "PATH (scheme + host + path)",
    0x00580000: "SCHEME_SPECIFIC_PART",
    0x00600000: "TYPE (mime)",
}

NO_MATCH = {
    -1: "NO_MATCH_TYPE      — the MIME test failed",
    -2: "NO_MATCH_DATA      — the URI test failed",
    -3: "NO_MATCH_ACTION    — the filter does not list this action",
    -4: "NO_MATCH_CATEGORY  — a category on the Intent is missing from the filter",
}


def decode_match(value):
    """Turn a raw match int into something a human can act on."""
    if value in NO_MATCH:
        return NO_MATCH[value]
    cat = value & MATCH_CATEGORY_MASK
    adj = value & MATCH_ADJUSTMENT_MASK
    name = MATCH_CATEGORIES.get(cat, "UNKNOWN(0x%08x)" % cat)
    extra = "" if adj == 0x8000 else "  adjustment=0x%04x" % adj
    return "%s%s" % (name, extra)


# --------------------------------------------------------------------------- #
#  adb plumbing
# --------------------------------------------------------------------------- #

class Adb(object):
    def __init__(self, serial=None):
        self.serial = serial
        self.sdk = None

    def _base(self):
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def shell(self, device_cmd):
        """
        Run one command on the device.

        The whole command is passed as ONE argument, because `adb shell`
        concatenates its arguments and hands the result to the device's sh.
        Callers must quote arguments for THAT shell themselves -- '*/*' and
        'intent:...;end' both break otherwise. This is not theoretical; both
        failures are reproduced in README section 3.4 and section 3.10.
        """
        try:
            p = subprocess.run(self._base() + ["shell", device_cmd],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=90)
        except FileNotFoundError:
            die("adb not found on PATH", 1)
        except subprocess.TimeoutExpired:
            return ""
        return p.stdout.decode("utf-8", "replace")

    def api_level(self):
        if self.sdk is None:
            out = self.shell("getprop ro.build.version.sdk").strip()
            try:
                self.sdk = int(out)
            except ValueError:
                self.sdk = 0
        return self.sdk

    def available(self):
        try:
            p = subprocess.run(self._base() + ["get-state"],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=20)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return b"device" in p.stdout


def die(msg, code=2):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(code)


def shquote(s):
    """Quote one argument for the DEVICE's shell."""
    return "'" + str(s).replace("'", "'\\''") + "'"


# --------------------------------------------------------------------------- #
#  Mode 1 — device-wide resolution query
# --------------------------------------------------------------------------- #

_Q_HEADER = re.compile(r"^(\d+)\s+(activities|receivers|services|providers)\s+found", re.M)
_Q_PRIO = re.compile(
    r"priority=(-?\d+)\s+preferredOrder=(-?\d+)\s+match=(0x[0-9a-fA-F]+|-?\d+)")
_Q_NAME = re.compile(r"^\s+name=(\S+)\s*$", re.M)
_Q_PKG = re.compile(r"^\s+packageName=(\S+)\s*$", re.M)
_Q_EXPORTED = re.compile(r"enabled=(\w+)\s+exported=(\w+)")
_Q_PERM = re.compile(r"^\s+permission=(\S+)\s*$", re.M)


def build_query(kind, action, data, mime, categories, package):
    parts = ["cmd package query-%s" % kind]
    if action:
        parts += ["-a", shquote(action)]
    for c in categories or []:
        parts += ["-c", shquote(c)]
    if data:
        parts += ["-d", shquote(data)]
    if mime:
        parts += ["-t", shquote(mime)]
    if package:
        parts += [shquote(package)]
    return " ".join(parts)


def parse_query(text):
    """
    Split `cmd package query-*` output into one record per candidate.

    The output is a flat, indentation-based dump; each candidate begins with the
    priority/preferredOrder/match line. Splitting on that line is far more robust
    than trying to track indentation, because ApplicationInfo blocks nest.
    """
    records = []
    starts = [m.start() for m in _Q_PRIO.finditer(text)]
    for i, s in enumerate(starts):
        e = starts[i + 1] if i + 1 < len(starts) else len(text)
        block = text[s:e]
        pm = _Q_PRIO.search(block)
        raw = pm.group(3)
        try:
            match_val = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        except ValueError:
            match_val = 0
        names = _Q_NAME.findall(block)
        pkgs = _Q_PKG.findall(block)
        exp = _Q_EXPORTED.search(block)
        perms = _Q_PERM.findall(block)
        records.append({
            "priority": int(pm.group(1)),
            "preferredOrder": int(pm.group(2)),
            "match": match_val,
            "match_decoded": decode_match(match_val),
            # the FIRST name= is the component; later ones belong to ApplicationInfo
            "component": names[0] if names else "?",
            "package": pkgs[0] if pkgs else "?",
            "enabled": exp.group(1) if exp else "?",
            "exported": exp.group(2) if exp else "?",
            # `cmd package query-*` prints the literal string "null" when a
            # component declares no permission. Treat it as absent, or every
            # unprotected component looks protected in the output.
            "permission": (perms[0] if perms and perms[0] != "null" else None),
        })
    return records


def cmd_query(adb, args):
    kinds = args.kind or ["activities"]
    all_out = {}
    any_found = False
    for kind in kinds:
        q = build_query(kind, args.action, args.data, args.type,
                        args.category, args.package)
        text = adb.shell(q)
        recs = parse_query(text)
        all_out[kind] = recs
        if recs:
            any_found = True

        if not args.json:
            print("=" * 78)
            print("query-%s" % kind)
            print("  device command: %s" % q)
            print("=" * 78)
            if not recs:
                print("  no candidates")
                print("")
                continue
            for r in recs:
                flag = ""
                if r["exported"] == "true" and r["permission"] is None:
                    flag = "   <-- EXPORTED, NO PERMISSION"
                print("  %s/%s%s" % (r["package"], r["component"], flag))
                print("      exported=%s enabled=%s permission=%s"
                      % (r["exported"], r["enabled"], r["permission"] or "-"))
                print("      priority=%d preferredOrder=%d match=0x%06x  (%s)"
                      % (r["priority"], r["preferredOrder"], r["match"],
                         r["match_decoded"]))
            print("")
            if len(recs) > 1:
                print("  NOTE: %d candidates. An implicit Intent here is CONTESTED --"
                      % len(recs))
                print("        a chooser, a recorded preference, or a verified App Link")
                print("        decides the winner. See README section 3.11.")
                print("")

    if not args.json and adb.api_level() >= 30:
        print("  WARNING: this device is API %d. Package-visibility filtering applies to"
              % adb.api_level())
        print("           APPS from targetSdk 30, but NOT to `adb shell`. This result set")
        print("           is the PLATFORM's view. Before claiming app A can send to app B,")
        print("           check A's <queries> declaration. README section 7.7.")
        print("")

    if args.json:
        print(json.dumps(all_out, indent=2))
    return 0 if any_found else 1


# --------------------------------------------------------------------------- #
#  Mode 2 — one package's filters, from the resolver tables
# --------------------------------------------------------------------------- #

_TABLE_RE = re.compile(r"^(Activity|Receiver|Service|Provider) Resolver Table:", re.M)
_ENTRY_RE = re.compile(r"^\s+[0-9a-f]+\s+(\S+?)/(\S+)\s+filter\s+([0-9a-f]+)\s*$")
_PROP_RE = re.compile(r"^\s+(Action|Category|Scheme|Authority|Path|StaticType|Type):\s+(.*?)\s*$")
_MPRI_RE = re.compile(r"^\s+mPriority=(-?\d+)")
_AUTOV_RE = re.compile(r"AutoVerify=(\w+)")

# dumpsys prints each set member in its own dialect. Measured on Android 11:
#     Scheme:     "https"
#     Authority:  "www.example.com": -1            (-1 means "no port")
#     Authority:  "example.com": -1 WILD           (a leading *. wildcard)
#     Path:       "PatternMatcher{LITERAL: /open}" (also PREFIX, GLOB, ADVANCED)
#     StaticType: "text/html"  /  "audio"  /  "*"  (a bare base means base/*,
#                                                   and "*" means */*)
_AUTH_RE = re.compile(r'^"(?P<host>[^"]*)":\s*(?P<port>-?\d+)(?P<wild>\s+WILD)?')
_PATH_RE = re.compile(r'^"?PatternMatcher\{(?P<kind>[A-Z_]+):\s*(?P<pat>.*?)\}"?$')


def _clean_prop(key, raw):
    """Normalise one property line's value into the form a tester wants to read."""
    if key in ("Action", "Category", "Scheme"):
        return raw.strip().strip('"')
    if key == "Authority":
        m = _AUTH_RE.match(raw.strip())
        if not m:
            return raw.strip().strip('"')
        host = m.group("host")
        if m.group("wild"):
            host = "*." + host
        port = m.group("port")
        return host if port == "-1" else "%s:%s" % (host, port)
    if key == "Path":
        m = _PATH_RE.match(raw.strip())
        if not m:
            return raw.strip().strip('"')
        kind = m.group("kind")
        pat = m.group("pat")
        return pat if kind == "LITERAL" else "%s[%s]" % (pat, kind.lower())
    # StaticType / Type
    v = raw.strip().strip('"')
    if v == "*":
        return "*/*"
    if "/" not in v:
        return v + "/*"
    return v


def parse_dumpsys(text):
    """
    Parse `dumpsys package <pkg>` resolver tables into filter records.

    The tables are grouped into the IntentResolver buckets (Non-Data Actions,
    Full/Base/Wild MIME Types, Schemes, ...). We do not care about the bucket --
    we care about each `<hash> pkg/cls filter <hash>` entry and the property
    lines indented beneath it, because those ARE the filter's independent sets.
    """
    tables = {}
    current_table = None
    current = None

    for line in text.splitlines():
        m = _TABLE_RE.match(line)
        if m:
            current_table = m.group(1).lower()
            tables.setdefault(current_table, [])
            current = None
            continue
        if current_table is None:
            continue
        # A new table-less section ends the resolver dump.
        if line and not line.startswith(" ") and line.rstrip().endswith(":") \
                and "Resolver Table" not in line:
            current_table = None
            current = None
            continue

        m = _ENTRY_RE.match(line)
        if m:
            # dumpsys prints the class relative to the package when it can
            # (".cal.CalculatorActivity"); `cmd package query-*` always prints it
            # fully qualified. Normalise here or the two can never be joined.
            pkg, cls = m.group(1), m.group(2)
            if cls.startswith("."):
                cls = pkg + cls
            current = {
                "package": pkg,
                "component": cls,
                "filter_id": m.group(3),
                "actions": [], "categories": [], "schemes": [],
                "authorities": [], "paths": [], "types": [],
                "priority": 0, "autoVerify": False,
            }
            tables[current_table].append(current)
            continue

        if current is None:
            continue

        m = _PROP_RE.match(line)
        if m:
            key = m.group(1)
            val = _clean_prop(key, m.group(2))
            bucket = {
                "Action": "actions", "Category": "categories", "Scheme": "schemes",
                "Authority": "authorities", "Path": "paths",
                "StaticType": "types", "Type": "types",
            }[key]
            if val and val not in current[bucket]:
                current[bucket].append(val)
            continue

        m = _MPRI_RE.match(line)
        if m:
            current["priority"] = int(m.group(1))
        if _AUTOV_RE.search(line):
            current["autoVerify"] = _AUTOV_RE.search(line).group(1) == "true"

    return tables


def cross_product(f, limit=40):
    """
    Enumerate what a filter's <data> sets actually accept.

    This is the point of the whole function: a filter does NOT hold a list of
    <data> tuples. It holds independent SETS -- schemes, authorities, paths,
    types -- and matching tests each set separately. Two <data> elements
    declaring https://a and myapp://b therefore also accept myapp://a and
    https://b. Developers write the first two and the platform reads all four.
    """
    schemes = f["schemes"] or ([] if not (f["authorities"] or f["paths"]) else ["<any>"])
    hosts = f["authorities"] or [""]
    paths = f["paths"] or [""]
    out = []
    for s in schemes:
        for h in hosts:
            for p in paths:
                if not s and not h and not p:
                    continue
                uri = "%s://%s%s" % (s or "<scheme>", h, p if p else "")
                out.append(uri)
                if len(out) >= limit:
                    return out, True
    return out, False


def cmd_components(adb, args):
    if args.dumpsys_file:
        with open(args.dumpsys_file, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
    else:
        if not args.package:
            die("--components needs --package PKG (or --dumpsys-file)")
        text = adb.shell("dumpsys package %s" % shquote(args.package))
    if "Resolver Table" not in text:
        die("no resolver tables in the input -- is the package installed, and "
            "did you capture `dumpsys package <pkg>` rather than `dumpsys package`?", 2)

    tables = parse_dumpsys(text)
    pkg_filter = args.package

    # exported/permission are NOT in the resolver tables. Recover them by asking
    # the resolver to actually resolve each filter's first action, which is also
    # a real reachability check rather than a claim.
    exported_cache = {}
    if args.verify and not args.dumpsys_file:
        for kind, entries in tables.items():
            qkind = {"activity": "activities", "receiver": "receivers",
                     "service": "services", "provider": "providers"}.get(kind)
            if qkind is None:
                continue
            for f in entries:
                if not f["actions"]:
                    continue
                key = (f["package"], f["component"])
                if key in exported_cache:
                    continue
                data = None
                cp, _ = cross_product(f, limit=1)
                if cp and "<scheme>" not in cp[0]:
                    data = cp[0]
                q = build_query(qkind, f["actions"][0], data,
                                f["types"][0] if f["types"] else None,
                                f["categories"], f["package"])
                recs = parse_query(adb.shell(q))
                for r in recs:
                    exported_cache[(r["package"], r["component"])] = (
                        r["exported"], r["permission"])

    result = {}
    found = False
    for kind in ("activity", "receiver", "service", "provider"):
        entries = [f for f in tables.get(kind, [])
                   if not pkg_filter or f["package"] == pkg_filter]
        if not entries:
            continue
        found = True
        result[kind] = entries
        if args.json:
            continue

        print("=" * 78)
        print("%s filters" % kind.upper())
        print("=" * 78)
        by_comp = {}
        for f in entries:
            by_comp.setdefault((f["package"], f["component"]), []).append(f)

        for (pkg, comp), fs in sorted(by_comp.items()):
            exp, perm = exported_cache.get((pkg, comp), (None, None))
            expstr = "" if exp is None else "  exported=%s  permission=%s" % (exp, perm or "-")
            print("")
            print("%s/%s   filters=%d%s" % (pkg, comp, len(fs), expstr))
            for f in fs:
                implicit_ok = ("android.intent.category.DEFAULT" in f["categories"]
                               or kind != "activity")
                browsable = "android.intent.category.BROWSABLE" in f["categories"]
                marks = []
                if implicit_ok:
                    marks.append("IMPLICIT-REACHABLE")
                else:
                    marks.append("no DEFAULT: explicit only")
                if browsable:
                    marks.append("BROWSABLE (a web page reaches this)")
                if f["autoVerify"]:
                    marks.append("autoVerify REQUESTED (state is NOT in this output)")
                if f["priority"]:
                    marks.append("priority=%d" % f["priority"])
                if "*" in f["authorities"]:
                    marks.append("WILDCARD HOST")
                if "*/*" in f["types"]:
                    marks.append("ACCEPTS ANY MIME TYPE")
                print("    filter %s   [%s]" % (f["filter_id"], ", ".join(marks)))
                for a in f["actions"]:
                    print("        action    %s" % a)
                for c in f["categories"]:
                    print("        category  %s" % c)
                for t in f["types"]:
                    print("        mimeType  %s" % t)
                combos, truncated = cross_product(f)
                if combos:
                    n = len(f["schemes"] or [1]) * len(f["authorities"] or [1]) \
                        * len(f["paths"] or [1])
                    print("        data cross product (%d combination%s%s):"
                          % (n, "" if n == 1 else "s", ", truncated" if truncated else ""))
                    for u in combos:
                        print("            %s" % u)
                    if n > 1:
                        print("        ^ these are SETS, not tuples. Test the combinations")
                        print("          the developer did not intend. README section 3.4.")
        print("")

    if not args.json:
        print("-" * 78)
        print("Every line above is a LEAD, not a finding. You still owe two proofs:")
        print("  1. reachability from an UNPRIVILEGED APP (adb shell is uid 2000);")
        print("  2. a demonstrated consequence of what the component does with the Intent.")
        print("For deep-link exclusivity run scripts/appstate-linkcheck.sh -- an")
        print("autoVerify REQUEST is not a verification STATE.")
        print("-" * 78)
    else:
        print(json.dumps(result, indent=2))
    return 0 if found else 1


# --------------------------------------------------------------------------- #
#  Mode 3 — probe exported activities
# --------------------------------------------------------------------------- #

def cmd_probe(adb, args):
    if not args.package:
        die("--probe needs --package PKG")
    text = adb.shell("dumpsys package %s" % shquote(args.package))
    tables = parse_dumpsys(text)
    comps = sorted({(f["package"], f["component"])
                    for f in tables.get("activity", [])
                    if f["package"] == args.package})
    if not comps:
        print("no activity filters found for %s" % args.package)
        return 1

    print("probing %d activities of %s" % (len(comps), args.package))
    print("NOTE: this runs as uid 2000 (shell), which is PRIVILEGED. A component you")
    print("      reach here may be unreachable from a real app. This step proves the")
    print("      component EXISTS and DOES something -- nothing more. README section 7.6.")
    print("")
    if not args.dry_run:
        adb.shell("logcat -c")

    for pkg, cls in comps:
        cmd = "am start -n %s" % shquote("%s/%s" % (pkg, cls))
        if args.dry_run:
            print("  would run: adb shell \"%s\"" % cmd)
            continue
        out = adb.shell(cmd).strip()
        verdict = "started"
        if "Permission Denial" in out:
            verdict = "DENIED"
        elif "Error" in out or "does not exist" in out:
            verdict = "error"
        print("  %-60s %s" % ("%s/%s" % (pkg, cls), verdict))
        for line in out.splitlines():
            if line.strip() and not line.startswith("Starting:"):
                print("      %s" % line.strip())

    if not args.dry_run:
        print("")
        print("crashes and denials in logcat:")
        log = adb.shell("logcat -d -t 400")
        pat = re.compile(r"Permission Denial|FATAL EXCEPTION|SecurityException|"
                         r"ActivityNotFoundException")
        for line in log.splitlines():
            if pat.search(line):
                print("  %s" % line.strip())
        print("")
        print("A crash is not a dead end. It means the component ACCEPTED your Intent")
        print("and dereferenced your value. Add the extra it wanted and go further.")
    return 0


# --------------------------------------------------------------------------- #
#  Mode 4 — code-level primitives in a decompiled tree
# --------------------------------------------------------------------------- #

# The obfuscation-proof redirection signature: getParcelableExtra is declared to
# return Landroid/os/Parcelable;, so any code that wants an Intent out of it MUST
# emit a check-cast to Landroid/content/Intent; immediately afterwards. Framework
# descriptors cannot be renamed by R8, so this survives obfuscation.
SMALI_GETPX = re.compile(
    r"Landroid/content/Intent;->getParcelableExtra\(Ljava/lang/String;"
    r"(?:Ljava/lang/Class;)?\)")
SMALI_CAST_INTENT = re.compile(r"check-cast\s+[vp]\d+,\s*Landroid/content/Intent;")
SMALI_SEND = re.compile(
    r"->(startActivity|startActivityForResult|startService|startForegroundService|"
    r"bindService|sendBroadcast|sendOrderedBroadcast|setResult)\(")
JAVA_GETPX = re.compile(r"getParcelableExtra\s*\(")
JAVA_PARSEURI = re.compile(r"Intent\s*\.\s*parseUri\s*\(|->parseUri\(")

PI_CREATE = re.compile(
    r"PendingIntent\s*\.\s*get(Activity|Activities|Broadcast|Service|ForegroundService)\s*\("
    r"|Landroid/app/PendingIntent;->get(Activity|Activities|Broadcast|Service|"
    r"ForegroundService)\(")
PI_IMMUTABLE = re.compile(r"FLAG_IMMUTABLE|0x4000000\b|67108864\b")
PI_MUTABLE = re.compile(r"FLAG_MUTABLE|0x2000000\b|33554432\b")

TEXT_EXT = (".java", ".kt", ".smali", ".txt")


def walk_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", ".git")]
        for fn in filenames:
            if fn.endswith(TEXT_EXT):
                yield os.path.join(dirpath, fn)


def read_lines(path):
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []


def cmd_redirect(args):
    root = args.redirect
    if not os.path.isdir(root):
        die("--redirect wants a directory (jadx -d out, or apktool d -o work)")
    hits = 0
    for path in walk_files(root):
        lines = read_lines(path)
        for i, line in enumerate(lines):
            window = lines[i:i + 12]
            joined = "\n".join(window)

            if SMALI_GETPX.search(line):
                cast = any(SMALI_CAST_INTENT.search(w) for w in window[:4])
                send = SMALI_SEND.search(joined)
                if cast:
                    hits += 1
                    print("[REDIRECT-CANDIDATE] %s:%d" % (path, i + 1))
                    print("    getParcelableExtra -> check-cast Landroid/content/Intent;")
                    if send:
                        print("    ...and a send within 12 instructions: %s"
                              % send.group(1))
                        print("    ^ this is the Parcelable flavour. It needs an ATTACKER APK")
                        print("      to trigger -- `am` has no Parcelable extra type.")
                    else:
                        print("    no send nearby; follow the register manually")
            elif JAVA_GETPX.search(line) and "Intent" in joined:
                # The negative lookbehind matters: `PendingIntent pi = ...
                # getParcelableExtra("callback")` contains the substring "Intent"
                # and is a completely different thing -- a received PendingIntent
                # is a token, not a redirection primitive. Without (?<!Pending)
                # this heuristic reports every PendingIntent receiver as a
                # redirection candidate, and a checker that cries wolf gets
                # skimmed.
                if re.search(r"\(\s*(?<!Pending)Intent\s*\)\s*.*getParcelableExtra|"
                             r"(?<!Pending)\bIntent\s+\w+\s*=.*getParcelableExtra",
                             joined):
                    hits += 1
                    print("[REDIRECT-CANDIDATE] %s:%d" % (path, i + 1))
                    print("    %s" % line.strip()[:150])

            if JAVA_PARSEURI.search(line):
                hits += 1
                print("[REDIRECT-CANDIDATE/STRING] %s:%d" % (path, i + 1))
                print("    %s" % line.strip()[:150])
                print("    ^ the STRING flavour. Reachable from `am` AND from a web page")
                print("      if the entry filter carries CATEGORY_BROWSABLE. Higher severity.")
    print("")
    print("%d candidate site%s. None of these is a finding yet: read the validation."
          % (hits, "" if hits == 1 else "s"))
    print("A correct deputy resolves the component, checks the package is its own,")
    print("checks the class against a closed allow-list, and strips FLAG_GRANT_* and")
    print("FLAG_ACTIVITY_FORWARD_RESULT. See examples/RedirectorActivityFixed.java.")
    return 0 if hits else 1


def cmd_pending(args):
    root = args.pending
    if not os.path.isdir(root):
        die("--pending wants a directory")
    hits = 0
    for path in walk_files(root):
        lines = read_lines(path)
        for i, line in enumerate(lines):
            if not PI_CREATE.search(line):
                continue
            window = "\n".join(lines[max(0, i - 6):i + 6])
            immutable = PI_IMMUTABLE.search(window)
            mutable = PI_MUTABLE.search(window)
            blank = re.search(r"new\s+Intent\s*\(\s*\)|"
                              r"Landroid/content/Intent;-><init>\(\)V", window)
            if immutable and not mutable:
                continue
            hits += 1
            sev = "REVIEW"
            if not immutable and blank:
                sev = "CRITICAL-CANDIDATE"
            elif not immutable:
                sev = "HIGH-CANDIDATE"
            print("[PENDINGINTENT/%s] %s:%d" % (sev, path, i + 1))
            print("    %s" % line.strip()[:150])
            if blank:
                print("    the wrapped Intent looks BLANK (no component). A mutable token")
                print("    with a blank component lets the holder choose the target and")
                print("    fire it as this app. README section 3.9.")
            if mutable:
                print("    FLAG_MUTABLE is explicit -- somebody decided this. Verify the")
                print("    wrapped Intent has its component set.")
    print("")
    print("%d site%s to review. Three questions decide each one: (1) is it mutable? "
          % (hits, "" if hits == 1 else "s"))
    print("(2) does the wrapped Intent lack a component (or lack data, for a grant")
    print("attack)? (3) does the token LEAVE the app -- notification, extra, widget,")
    print("callback? Only yes/yes/yes is a finding.")
    return 0 if hits else 1


# --------------------------------------------------------------------------- #
#  main
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="intent-surface-map.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Map an application's runtime Intent surface from a device.",
        epilog="Every result is a lead. Reachability from an unprivileged app and a "
               "demonstrated consequence are still yours to prove.")

    ap.add_argument("-s", "--serial", help="adb device serial")

    g = ap.add_argument_group("device-wide resolution query")
    g.add_argument("-a", "--action", help="Intent action")
    g.add_argument("-d", "--data", help="data URI")
    g.add_argument("-t", "--type", help="MIME type (quote it: */* is a glob to the device sh)")
    g.add_argument("-c", "--category", action="append", help="category (repeatable)")
    g.add_argument("--kind", action="append",
                   choices=["activities", "receivers", "services", "providers"],
                   help="what to query (default: activities)")

    g2 = ap.add_argument_group("per-package modes")
    g2.add_argument("-p", "--package", help="target package name")
    g2.add_argument("--components", action="store_true",
                    help="list the package's filters and their data cross products")
    g2.add_argument("--verify", action="store_true",
                    help="with --components: resolve each filter to read exported/permission")
    g2.add_argument("--probe", action="store_true",
                    help="start every exported activity with an empty Intent")
    g2.add_argument("--dry-run", action="store_true",
                    help="with --probe: print the commands, do not run them")
    g2.add_argument("--dumpsys-file",
                    help="read a captured `dumpsys package <pkg>` instead of a device")

    g3 = ap.add_argument_group("decompiled-tree modes (no device needed)")
    g3.add_argument("--redirect", metavar="DIR",
                    help="find intent-redirection primitives in a jadx/apktool tree")
    g3.add_argument("--pending", metavar="DIR",
                    help="find PendingIntent creations that are not immutable")

    ap.add_argument("--json", action="store_true", help="machine-readable output")

    args = ap.parse_args(argv)

    if args.redirect:
        return cmd_redirect(args)
    if args.pending:
        return cmd_pending(args)

    adb = Adb(args.serial)
    needs_device = not args.dumpsys_file
    if needs_device and not adb.available():
        die("no device -- attach one, or use --dumpsys-file for offline analysis", 1)

    if args.components:
        return cmd_components(adb, args)
    if args.probe:
        return cmd_probe(adb, args)
    if args.action or args.data or args.type or args.category:
        return cmd_query(adb, args)

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
