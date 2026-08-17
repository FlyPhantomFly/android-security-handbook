#!/usr/bin/env python3
"""
manifest-corpus-sweep.py -- measure finding-class BASE RATES across a corpus of
                            Android applications, and print the adjudication
                            funnel rather than the raw hit count.

WHAT IT DOES
    Reads AndroidManifest.xml from every application in a corpus and reports,
    for each manifest-visible finding class:

      * the raw count            (what a naive scanner would report)
      * the count after each mechanical adjudication step
      * the denominator, printed next to every numerator

    The point is the funnel, not the endpoint. Chapter 72 section 3.5 measured
    2,674 exported components collapsing to 404 through two steps that require
    no judgement at all -- an 85% reduction that any scanner could perform and
    most do not.

    It deliberately does NOT emit severities. Severity is an argument from the
    threat model (chapter 72 section 3.7, and 80-Appendix sections 5-6); a tool
    that prints one is inviting you to inherit it.

USAGE
    # pull every installed package's manifest from a connected device
    python3 -B manifest-corpus-sweep.py --from-device --out ./sweep-out

    # sweep APKs you already have on disk
    python3 -B manifest-corpus-sweep.py --apk-dir ~/corpus --out ./sweep-out

    # re-run over manifests extracted by an earlier --from-device run
    python3 -B manifest-corpus-sweep.py --manifest-dir ./sweep-out/manifests

    # subtract your own instrumentation before counting (see section 3.5:
    # the single debuggable hit in the reference corpus was the tester's own app)
    python3 -B manifest-corpus-sweep.py --from-device --exclude com.you.testapp

    # funnel only, no per-class detail
    python3 -B manifest-corpus-sweep.py --manifest-dir ./sweep-out/manifests --funnel-only

    # write a machine-readable ledger for the labs
    python3 -B manifest-corpus-sweep.py --manifest-dir ./m --json ledger.json

REQUIREMENTS
    Python 3.8+, standard library only, plus this repository's own binary-XML
    reader at ../../10-APK-Internals/examples/parse_axml.py. Pass --parser to
    point somewhere else. `--from-device` additionally needs `adb` on PATH.

    Nothing is ever written to the device. --from-device streams each manifest
    out through `adb exec-out unzip -p` and keeps it on the host.

WAS THIS EXECUTED?
    YES. Run on 2026-08-16 against AVD `sdk_gphone16k_x86_64` (emulator-5554),
    Android 15 / API 35, x86_64, rooted with Magisk 30.7, Zygisk off -- the only
    device attached at the time. 243 packages listed, 243 manifests extracted,
    243 parsed. Every number in chapter 72 section 3.5 is this script's output.

    Read the denominator before the numbers: FOUR of those 243 packages are
    third-party. This is a PLATFORM corpus. It supports statements about how
    Android and its bundled applications are built and supports nothing about
    banking, retail or any category a commercial assessment targets.

BEFORE YOU COMMIT ITS OUTPUT -- READ THIS
    This tool prints real package names, because that is what a sweep is for and
    you cannot adjudicate a lead you cannot name. That is correct at the console
    and wrong in a published repository.

    Every corpus figure in this repository is published; no assessed third-party
    application is named. Commercial apps are written `com.vendor.<category>` and
    the pseudonym is stable across chapters -- see
    ../references/README.md section 4 for the table and for the three classes of
    name (platform, library, published detection signature) that are deliberately
    NOT pseudonymised.

    So: if you re-run this script and commit the result over
    ../examples/corpus-sweep-output.txt, substitute the package names first, or
    you will undo that. The counts, ratios and denominators are the value here;
    the identities are the liability. Anonymise consistently -- one pseudonym per
    real app, everywhere -- or the cross-chapter references stop lining up.
"""

import argparse
import collections
import json
import os
import re
import subprocess
import sys
import zipfile

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

# android.content.pm.PermissionInfo base protection levels. Note PROTECTION_INTERNAL
# (4) arrived in API 31 -- a level table written before that release has a hole
# exactly where four of this chapter's eleven cross-check disagreements landed.
PROTECTION_BASE = {
    0: "normal",
    1: "dangerous",
    2: "signature",
    3: "signatureOrSystem",   # deprecated; the platform reports signature|privileged
    4: "internal",
}

# Guards at these levels are not reachable by an ordinary third-party app, so a
# component carrying one leaves the funnel at step 2.
STRONG_GUARDS = {"signature", "signatureOrSystem", "internal", "dangerous"}


# ----------------------------------------------------------------------
# parser loading
# ----------------------------------------------------------------------

def load_parser(explicit):
    """Import 10-APK-Internals' AXML reader, or die with a useful message."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = []
    if explicit:
        candidates.append(explicit)
    candidates.append(os.path.normpath(
        os.path.join(here, "..", "..", "10-APK-Internals", "examples", "parse_axml.py")))
    for c in candidates:
        if os.path.isfile(c):
            sys.path.insert(0, os.path.dirname(c))
            import parse_axml
            return parse_axml
    sys.exit("error: could not find parse_axml.py. Looked in:\n  " +
             "\n  ".join(candidates) + "\nPass --parser /path/to/parse_axml.py")


# ----------------------------------------------------------------------
# corpus acquisition
# ----------------------------------------------------------------------

def manifests_from_device(outdir, serial=None):
    """Stream AndroidManifest.xml out of every installed package. Writes nothing
    to the device."""
    os.makedirs(outdir, exist_ok=True)
    base = ["adb"] + (["-s", serial] if serial else [])
    listing = subprocess.run(base + ["shell", "pm", "list", "packages", "-f"],
                             capture_output=True, text=True).stdout
    pairs = []
    for line in listing.splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        body = line[len("package:"):]
        i = body.rfind("=")
        if i > 0:
            pairs.append((body[:i], body[i + 1:]))
    if not pairs:
        sys.exit("error: `adb shell pm list packages -f` returned nothing. "
                 "Is a device attached? Try `adb devices -l`.")

    print(f"[*] {len(pairs)} packages listed by the device")
    index, missed = [], 0
    for apkpath, pkg in pairs:
        # NOTE: `adb` inherits stdin. Inside a shell `while read` loop that
        # silently eats the loop's input and you get one row of a long table
        # (64-Xposed measured exactly this). Using subprocess avoids it entirely.
        proc = subprocess.run(base + ["exec-out", "unzip", "-p", apkpath,
                                      "AndroidManifest.xml"],
                              capture_output=True)
        data = proc.stdout
        if len(data) < 8 or data[:2] != b"\x03\x00":
            missed += 1
            continue
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", pkg) + ".axml"
        with open(os.path.join(outdir, safe), "wb") as fh:
            fh.write(data)
        index.append({"pkg": pkg, "source": apkpath, "file": safe})
    with open(os.path.join(outdir, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=1)
    print(f"[*] extracted {len(index)} manifests, {missed} unreadable")
    return index, outdir


def manifests_from_apks(apkdir, outdir):
    os.makedirs(outdir, exist_ok=True)
    index = []
    for name in sorted(os.listdir(apkdir)):
        if not name.lower().endswith(".apk"):
            continue
        path = os.path.join(apkdir, name)
        try:
            with zipfile.ZipFile(path) as z:
                data = z.read("AndroidManifest.xml")
        except (zipfile.BadZipFile, KeyError, OSError) as exc:
            print(f"    skip {name}: {exc}")
            continue
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", name) + ".axml"
        with open(os.path.join(outdir, safe), "wb") as fh:
            fh.write(data)
        index.append({"pkg": name[:-4], "source": path, "file": safe})
    with open(os.path.join(outdir, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=1)
    print(f"[*] extracted {len(index)} manifests from {apkdir}")
    return index, outdir


def load_index(mdir):
    """Accept an index.json written by this script, or fall back to listing the
    directory. Tolerates a few key spellings so a hand-made index still works."""
    ipath = os.path.join(mdir, "index.json")
    if os.path.isfile(ipath):
        with open(ipath, encoding="utf-8") as fh:
            raw = json.load(fh)
        rows = []
        for r in raw:
            f = r.get("file") or r.get("axml") or r.get("manifest")
            if not f:
                continue
            rows.append({"pkg": r.get("pkg", f), "source": r.get("source",
                         r.get("apk", "?")), "file": f})
        if rows:
            return rows
    return [{"pkg": n[:-5], "source": "?", "file": n}
            for n in sorted(os.listdir(mdir)) if n.endswith(".axml")]


# ----------------------------------------------------------------------
# manifest reading
# ----------------------------------------------------------------------

def build_tree(doc):
    """parse_axml gives a flat event stream; components need nesting, because
    'has an <intent-filter>' is the whole of adjudication step 3."""
    root = {"name": "#root", "attrs": {}, "children": []}
    stack = [root]
    for ev in doc.events:
        if ev["kind"] == "startElement":
            attrs = {}
            for a in ev["attributes"]:
                attrs[a["name"] if a["ns"] else "_" + a["name"]] = a
            node = {"name": ev["name"], "attrs": attrs, "children": []}
            stack[-1]["children"].append(node)
            stack.append(node)
        elif ev["kind"] == "endElement" and len(stack) > 1:
            stack.pop()
    return root


def kids(node, name):
    return [c for c in node["children"] if c["name"] == name]


def attr(node, key):
    """Typed attribute read. Returns UNRESOLVED_REF for TYPE_REFERENCE, because
    silently printing the integer produces a nonsense value -- section 8.2."""
    a = node["attrs"].get(key)
    if a is None:
        return None
    t = a["type"]
    if t == 3:                       # TYPE_STRING
        return a["raw"]
    if t == 18:                      # TYPE_INT_BOOLEAN
        return bool(a["data"] & 0xFFFFFFFF)
    if t == 1:                       # TYPE_REFERENCE -- needs resources.arsc
        return f"@ref/0x{a['data']:08x}"
    if t in (16, 17, 11):            # TYPE_INT_DEC / HEX / etc.
        return a["data"]
    return a.get("typed")


# ----------------------------------------------------------------------
# device cross-check
# ----------------------------------------------------------------------

def device_protection_levels(serial=None):
    """Second, independent reading of every permission's protection level.
    When this and the manifests disagree, the DEVICE is right -- it reports what
    PackageManagerService actually stored."""
    base = ["adb"] + (["-s", serial] if serial else [])
    try:
        out = subprocess.run(base + ["shell", "dumpsys", "package", "permissions"],
                             capture_output=True, text=True, timeout=120).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    levels, cur = {}, None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Permission [") and "]" in s:
            cur = s[len("Permission ["):s.index("]")]
        elif cur:
            m = re.search(r"prot=(\S+)", s)
            if m:
                levels[cur] = m.group(1)
                cur = None
    return levels


# ----------------------------------------------------------------------
# the sweep
# ----------------------------------------------------------------------

def sweep(index, mdir, parse_axml, exclude):
    apps, declared_perms, failures = [], {}, []
    for row in index:
        if row["pkg"] in exclude:
            continue
        path = os.path.join(mdir, row["file"])
        try:
            with open(path, "rb") as fh:
                doc = parse_axml.Axml(fh.read(), row["pkg"])
        except Exception as exc:                       # noqa: BLE001
            failures.append((row["pkg"], str(exc)[:90]))
            continue
        man = kids(build_tree(doc), "manifest")
        if not man:
            failures.append((row["pkg"], "no <manifest> element"))
            continue
        man = man[0]

        for p in kids(man, "permission"):
            name, lvl = attr(p, "name"), attr(p, "protectionLevel")
            if name:
                declared_perms[name] = lvl if isinstance(lvl, int) else 0

        target = None
        for u in kids(man, "uses-sdk"):
            target = attr(u, "targetSdkVersion")

        rec = {
            "pkg": row["pkg"], "source": row.get("source", "?"),
            "targetSdk": target,
            "sharedUserId": attr(man, "sharedUserId"),
            "components": 0, "exported": [],
            "no_exported_attr": 0, "no_exported_attr_with_filter": 0,
        }

        app = kids(man, "application")
        if app:
            app = app[0]
            for k in ("debuggable", "allowBackup", "usesCleartextTraffic",
                      "testOnly", "networkSecurityConfig", "dataExtractionRules",
                      "fullBackupContent"):
                rec[k] = attr(app, k)
            for tag in COMPONENT_TAGS:
                for c in kids(app, tag):
                    rec["components"] += 1
                    has_filter = bool(kids(c, "intent-filter"))
                    exported = attr(c, "exported")
                    if exported is None:
                        rec["no_exported_attr"] += 1
                        if has_filter:
                            rec["no_exported_attr_with_filter"] += 1
                        # legacy implicit-export rule
                        effective, explicit = has_filter, False
                    else:
                        effective, explicit = bool(exported), True
                    if not effective:
                        continue
                    # A provider has THREE guards and they are not interchangeable.
                    # `readPermission` gates query(); `writePermission` gates
                    # insert/update/delete; `permission` sets both unless
                    # overridden. Folding writePermission into a single "guard"
                    # field hides the case that matters most for a read probe: a
                    # provider with a write guard and NO read guard is readable by
                    # anyone. This script made exactly that mistake once, and it
                    # silently excluded the only provider in the reference corpus
                    # that returned rows. Keep them separate.
                    guard_common = attr(c, "permission")
                    guard_read = guard_write = guard_common
                    if tag == "provider":
                        guard_read = attr(c, "readPermission") or guard_common
                        guard_write = attr(c, "writePermission") or guard_common
                    rec["exported"].append({
                        "kind": tag,
                        "name": attr(c, "name"),
                        "authorities": attr(c, "authorities") if tag == "provider" else None,
                        "guard": guard_read,
                        "guard_read": guard_read,
                        "guard_write": guard_write,
                        "explicit": explicit,
                        "has_filter": has_filter,
                        "grantUri": bool(attr(c, "grantUriPermissions")),
                        "browsable": any(
                            any(attr(cat, "name") == "android.intent.category.BROWSABLE"
                                for cat in kids(f, "category"))
                            for f in kids(c, "intent-filter")),
                    })
        apps.append(rec)
    return apps, declared_perms, failures


def resolve_level(name, declared, device):
    """Return (base_level, which_reading). Device wins on conflict."""
    if name in device:
        return device[name].split("|")[0], "device"
    v = declared.get(name)
    if isinstance(v, int):
        return PROTECTION_BASE.get(v & 0xF, f"0x{v & 0xF:x}"), "manifest"
    return None, None


# ----------------------------------------------------------------------
# reporting
# ----------------------------------------------------------------------

def pct(n, d):
    return f"{100.0 * n / d:5.1f}%" if d else "    -"


def report(apps, declared, device, failures, funnel_only, third_party_hint):
    n = len(apps)
    if not n:
        sys.exit("error: no manifests parsed")
    line = "-" * 74

    print(f"\n{line}\nCORPUS\n{line}")
    print(f"  applications analysed                  {n}")
    if failures:
        print(f"  manifests that would not parse         {len(failures)}")
        for pkg, why in failures[:5]:
            print(f"      {pkg}: {why}")
    tp = [a for a in apps if a["pkg"] in third_party_hint] if third_party_hint else []
    if third_party_hint:
        print(f"  of which THIRD-PARTY                   {len(tp)}")
        print("  >> every conclusion below is bounded by that ratio. A corpus")
        print("     dominated by platform packages says how the PLATFORM is")
        print("     built and nothing about commercially assessed apps.")

    comps = sum(a["components"] for a in apps)
    exported = [(a, e) for a in apps for e in a["exported"]]
    print(f"\n  declared components                    {comps}")
    print(f"  components declared exported           {len(exported)}  "
          f"({pct(len(exported), comps)} of components)")
    print(f"  apps with >=1 exported component       "
          f"{len({a['pkg'] for a, _ in exported})}  of {n}")

    # ---- guard distribution -------------------------------------------
    print(f"\n{line}\nADJUDICATION STEP 1 -- what guards the export?\n{line}")
    bands, unresolved = collections.Counter(), collections.Counter()
    for _, e in exported:
        if not e["guard"]:
            bands["no guard at all"] += 1
            continue
        lvl, _src = resolve_level(e["guard"], declared, device)
        if lvl is None:
            bands["guard named but unresolvable on this device"] += 1
            unresolved[e["guard"]] += 1
        else:
            bands[lvl] += 1
    for k, v in bands.most_common():
        print(f"  {k:<44} {v:>5}  {pct(v, len(exported))}")
    if unresolved:
        print(f"\n  unresolvable guard names ({len(unresolved)} distinct) -- a component")
        print("  guarded by a permission no installed package declares is, on THIS")
        print("  device, effectively unguarded:")
        for name, c in unresolved.most_common(8):
            print(f"      {c:>3}  {name}")

    # ---- static vs device cross-check ---------------------------------
    if device:
        print(f"\n{line}\nCROSS-CHECK -- two independent readings of every guard\n{line}")
        names = {e["guard"] for _, e in exported if e["guard"]}
        agree = differ = only_one = neither = 0
        diffs = []
        for nm in names:
            d = device.get(nm, "").split("|")[0] or None
            s = PROTECTION_BASE.get(declared[nm] & 0xF) if isinstance(declared.get(nm), int) else None
            if d and s:
                if d == s:
                    agree += 1
                else:
                    differ += 1
                    diffs.append((nm, s, d))
            elif d or s:
                only_one += 1
            else:
                neither += 1
        print(f"  distinct guard permissions referenced  {len(names)}")
        print(f"    resolved by BOTH, agreeing           {agree}")
        print(f"    resolved by BOTH, DIFFERING          {differ}")
        print(f"    resolved by one reading only         {only_one}")
        print(f"    resolved by neither                  {neither}")
        for nm, s, d in diffs[:10]:
            print(f"      manifest={s:<18} device={d:<12} {nm}")
        if differ:
            print("  >> Chase every one. In this chapter's reference run all 11")
            print("     differences were defects in the STATIC reader, not the apps.")
            print("     The device wins: it reports what PackageManagerService stored.")

    if funnel_only:
        print_funnel(apps, exported, declared, device, line)
        return

    print_funnel(apps, exported, declared, device, line)
    print_app_flags(apps, n, line)
    print_extinct(apps, comps, n, line)


def print_funnel(apps, exported, declared, device, line):
    print(f"\n{line}\nTHE FUNNEL -- mechanical steps only, no judgement applied\n{line}")
    s1 = exported
    s2 = []
    for a, e in s1:
        lvl, _ = resolve_level(e["guard"], declared, device) if e["guard"] else (None, None)
        if e["guard"] and lvl in STRONG_GUARDS:
            continue
        s2.append((a, e))
    s3 = [(a, e) for a, e in s2 if not e["has_filter"]]
    s4 = [(a, e) for a, e in s3 if e["kind"] == "provider"]

    rows = [
        ("1. declared exported", s1),
        ("2. ...and not strongly guarded", s2),
        ("3. ...and carrying no <intent-filter>", s3),
        ("4. ...and being a ContentProvider", s4),
    ]
    print(f"  {'stage':<44} {'components':>10} {'apps':>6}")
    for label, rowset in rows:
        print(f"  {label:<44} {len(rowset):>10} {len({a['pkg'] for a, _ in rowset}):>6}")
    if s1:
        print(f"\n  steps 2-3 shed {pct(len(s1) - len(s3), len(s1))} of the class without a"
              " single judgement call.")
    print("  Survivors by kind: " +
          ", ".join(f"{k}={v}" for k, v in
                    collections.Counter(e["kind"] for _, e in s3).most_common()))
    gu = sum(1 for _, e in s4 if e["grantUri"])
    print(f"  Of the step-4 providers, {gu} declare grantUriPermissions -- a path to")
    print("  the data that does not require the guard permission at all.")
    print("\n  NOTE: step 4 is where the human work BEGINS. These are leads.")


def print_app_flags(apps, n, line):
    print(f"\n{line}\nAPPLICATION-LEVEL CLASSES -- and the default that adjudicates them\n{line}")

    def tri(key):
        t = sum(1 for a in apps if a.get(key) is True)
        f = sum(1 for a in apps if a.get(key) is False)
        return t, f, n - t - f

    ct, cf, ca = tri("usesCleartextTraffic")
    safe_default = sum(1 for a in apps
                       if a.get("usesCleartextTraffic") is None
                       and isinstance(a.get("targetSdk"), int)
                       and a["targetSdk"] >= 28)
    print(f"  usesCleartextTraffic  true={ct}  false={cf}  ABSENT={ca}  (of {n})")
    print(f"      of the {ca} absent, {safe_default} target API 28+ where the default is")
    print("      ALREADY false. A 'cleartext not disabled' check fires " + str(ca) +
          " times")
    print(f"      and is wrong {safe_default} of them -- {pct(safe_default, ca)} false positive.")

    bt, bf, ba = tri("allowBackup")
    print(f"\n  allowBackup           true={bt}  false={bf}  ABSENT={ba}  (of {n})")
    print(f"      counting the default as a finding reports {bt + ba} of {n} apps.")
    der = sum(1 for a in apps if a.get("dataExtractionRules") is not None)
    fbc = sum(1 for a in apps if a.get("fullBackupContent") is not None)
    print(f"      dataExtractionRules (API 31+) declared by {der}; "
          f"fullBackupContent by {fbc}")

    nsc = sum(1 for a in apps if a.get("networkSecurityConfig") is not None)
    dbg = [a["pkg"] for a in apps if a.get("debuggable") is True]
    tst = [a["pkg"] for a in apps if a.get("testOnly") is True]
    sui = sum(1 for a in apps if a.get("sharedUserId"))
    print(f"\n  networkSecurityConfig declared         {nsc:>4}  of {n}")
    print(f"  sharedUserId declared                  {sui:>4}  of {n}")
    print(f"  android:debuggable=true                {len(dbg):>4}  of {n}")
    for p in dbg:
        print(f"      {p}")
    if dbg:
        print("      >> check this list against what YOU installed before counting it.")
    print(f"  android:testOnly=true                  {len(tst):>4}  of {n}")


def print_extinct(apps, comps, n, line):
    print(f"\n{line}\nIMPLICIT EXPORT -- the classic class, measured\n{line}")
    absent = sum(a["no_exported_attr"] for a in apps)
    absent_f = sum(a["no_exported_attr_with_filter"] for a in apps)
    t31 = sum(1 for a in apps
              if isinstance(a.get("targetSdk"), int) and a["targetSdk"] >= 31)
    print(f"  components with android:exported ABSENT        {absent}  of {comps}")
    print(f"    ...of those, carrying an <intent-filter>     {absent_f}")
    print(f"  apps targeting API 31+                         {t31}  of {n}")
    if absent_f == 0 and t31:
        print("  >> ZERO. Android 12 made an intent-filter without an explicit")
        print("     android:exported a BUILD ERROR. On a modern-targetSdk corpus this")
        print("     finding class -- the defining Android finding of the 2010s -- has")
        print("     been engineered out of existence. Delete the check.")


# ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Corpus sweep for manifest-visible finding classes, "
                    "reporting the adjudication funnel and every denominator.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-device", action="store_true",
                     help="pull every installed package's manifest over adb")
    src.add_argument("--apk-dir", help="directory of .apk files")
    src.add_argument("--manifest-dir", help="directory of .axml files already extracted")
    ap.add_argument("--out", default="./sweep-out", help="working directory")
    ap.add_argument("--serial", help="adb device serial")
    ap.add_argument("--parser", help="path to parse_axml.py")
    ap.add_argument("--exclude", action="append", default=[],
                    metavar="PKG", help="package to subtract (your own test apps)")
    ap.add_argument("--third-party", action="append", default=[], metavar="PKG",
                    help="mark a package third-party, so the corpus caveat is printed")
    ap.add_argument("--no-device-check", action="store_true",
                    help="skip the dumpsys cross-check")
    ap.add_argument("--funnel-only", action="store_true")
    ap.add_argument("--json", metavar="FILE", help="write a machine-readable ledger")
    args = ap.parse_args()

    parse_axml = load_parser(args.parser)

    if args.from_device:
        index, mdir = manifests_from_device(os.path.join(args.out, "manifests"),
                                            args.serial)
    elif args.apk_dir:
        index, mdir = manifests_from_apks(args.apk_dir,
                                          os.path.join(args.out, "manifests"))
    else:
        mdir = args.manifest_dir
        index = load_index(mdir)

    apps, declared, failures = sweep(index, mdir, parse_axml, set(args.exclude))
    device = {} if args.no_device_check else device_protection_levels(args.serial)
    if device:
        print(f"[*] device reported protection levels for {len(device)} permissions")
    elif not args.no_device_check:
        print("[!] no device cross-check available -- guard levels come from the")
        print("    manifests alone, which is one reading, not two.")

    report(apps, declared, device, failures, args.funnel_only, set(args.third_party))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"corpus": len(apps), "apps": apps}, fh, indent=1)
        print(f"\n[*] ledger written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
