#!/usr/bin/env python3
"""
manifest-merge-diff.py — show exactly what third-party libraries injected into
an Android app's manifest.

PURPOSE
    The manifest merger combines the application's own AndroidManifest.xml with
    the manifest of every library in the dependency graph. Components,
    providers, <queries> entries and <uses-permission> declarations that the
    application's developers never wrote end up in the shipped APK, exported and
    reachable by any other app on the device. This is one of the most productive
    sources of genuine findings in Android testing, and it is invisible unless
    you diff.

    This script produces that diff in three modes:

      1. source vs merged   — the developer's manifest against the merged one
      2. source vs apk      — the developer's manifest against the shipped APK
      3. report             — parse the merger's own provenance report and
                              attribute every addition to a Maven coordinate

USAGE
    # 1. after a build: source manifest vs the merged manifest AGP produced
    python3 manifest-merge-diff.py \
        --source app/src/main/AndroidManifest.xml \
        --merged app/build/intermediates/merged_manifests/release/AndroidManifest.xml

    # 2. no build required: source manifest vs the manifest inside a shipped APK
    #    (requires apktool or aapt2 on PATH)
    python3 manifest-merge-diff.py \
        --source app/src/main/AndroidManifest.xml \
        --apk app-release.apk

    # 3. attribute every addition to the library that made it
    python3 manifest-merge-diff.py \
        --report app/build/outputs/logs/manifest-merger-release-report.txt

    # combine: full picture, with am commands for every injected component
    python3 manifest-merge-diff.py \
        --source app/src/main/AndroidManifest.xml \
        --apk app-release.apk \
        --report app/build/outputs/logs/manifest-merger-release-report.txt \
        --emit-am-commands

REQUIREMENTS
    Python 3.8+, standard library only.
    Optional external tools for --apk: `apktool` (preferred) or `aapt2`.

EXIT CODES
    0  no injected exported components found
    1  injected exported components found
    2  usage / input error

SEE ALSO
    ../README.md sections 3.10, 5.3.2 and 9.2.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict

ANDROID_NS = "http://schemas.android.com/apk/res/android"
A = "{%s}" % ANDROID_NS

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


# --------------------------------------------------------------------------
# Manifest parsing
# --------------------------------------------------------------------------

def parse_manifest(path):
    """
    Return a dict describing the manifest:
      {
        "package":     str,
        "components":  { "activity|com.foo.Bar": {"exported": bool,
                                                  "filters": [action, ...]} },
        "permissions": set(str),
        "features":    set(str),
        "queries":     set(str),
        "appAttrs":    { "android:allowBackup": "true", ... },
      }
    """
    tree = ET.parse(path)
    root = tree.getroot()

    out = {
        "package": root.get("package", ""),
        "components": {},
        "permissions": set(),
        "features": set(),
        "queries": set(),
        "appAttrs": {},
    }

    for up in root.findall("uses-permission"):
        name = up.get(A + "name")
        if name:
            out["permissions"].add(name)
    for up in root.findall("uses-permission-sdk-23"):
        name = up.get(A + "name")
        if name:
            out["permissions"].add(name + " (sdk-23)")

    for uf in root.findall("uses-feature"):
        name = uf.get(A + "name")
        if name:
            out["features"].add(name)

    q = root.find("queries")
    if q is not None:
        for child in q:
            if child.tag == "package":
                out["queries"].add("package:" + (child.get(A + "name") or "?"))
            elif child.tag == "intent":
                acts = [a.get(A + "name") for a in child.findall("action")]
                out["queries"].add("intent:" + ",".join(x for x in acts if x))
            elif child.tag == "provider":
                out["queries"].add(
                    "provider:" + (child.get(A + "authorities") or "?"))

    app = root.find("application")
    if app is None:
        return out

    for k, v in app.attrib.items():
        pretty = k.replace(A, "android:")
        out["appAttrs"][pretty] = v

    for tag in COMPONENT_TAGS:
        for comp in app.findall(tag):
            name = comp.get(A + "name")
            if not name:
                continue
            # Resolve the leading-dot shorthand against the package.
            if name.startswith("."):
                name = out["package"] + name
            elif "." not in name and out["package"]:
                name = out["package"] + "." + name

            filters = []
            for intent_filter in comp.findall("intent-filter"):
                for act in intent_filter.findall("action"):
                    an = act.get(A + "name")
                    if an:
                        filters.append("action:" + an)
                for cat in intent_filter.findall("category"):
                    cn = cat.get(A + "name")
                    if cn:
                        filters.append("category:" + cn)
                for data in intent_filter.findall("data"):
                    scheme = data.get(A + "scheme")
                    host = data.get(A + "host")
                    if scheme:
                        filters.append("data:" + scheme +
                                       ("://" + host if host else "://"))

            exported_attr = comp.get(A + "exported")
            if exported_attr is not None:
                exported = exported_attr.lower() == "true"
            else:
                # Pre-API-31 implicit rule: an intent-filter implies exported.
                exported = bool(filters)

            out["components"][f"{tag}|{name}"] = {
                "exported": exported,
                "exported_explicit": exported_attr is not None,
                "filters": filters,
                "permission": comp.get(A + "permission"),
                "authorities": comp.get(A + "authorities"),
            }

    return out


# --------------------------------------------------------------------------
# Extracting the manifest from an APK
# --------------------------------------------------------------------------

def manifest_from_apk(apk_path, workdir):
    """Decode the binary manifest out of an APK. Returns a path to XML."""
    if shutil.which("apktool"):
        out = os.path.join(workdir, "decoded")
        subprocess.run(
            ["apktool", "d", "-f", "-s", apk_path, "-o", out],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        man = os.path.join(out, "AndroidManifest.xml")
        if os.path.exists(man):
            return man

    if shutil.which("aapt2"):
        # aapt2 can print the XML tree but not valid XML; fall back to a
        # tree-to-XML conversion good enough for names and attributes.
        proc = subprocess.run(
            ["aapt2", "dump", "xmltree", apk_path, "--file",
             "AndroidManifest.xml"],
            check=True, capture_output=True, text=True,
        )
        man = os.path.join(workdir, "from_aapt2.xml")
        with open(man, "w", encoding="utf-8") as fh:
            fh.write(_xmltree_to_xml(proc.stdout))
        return man

    raise RuntimeError(
        "Neither apktool nor aapt2 was found on PATH. Install one of them, or "
        "pass --merged with a manifest you extracted yourself."
    )


def _xmltree_to_xml(tree_text):
    """
    Convert `aapt2 dump xmltree` output into parseable XML.
    Handles the common shape:
        E: application (line=12)
          A: android:label(0x01010001)="App" (Raw: "App")
    """
    lines = tree_text.splitlines()
    out = ['<?xml version="1.0" encoding="utf-8"?>']
    stack = []   # (indent, tagname)
    pending_attrs = []
    pending_tag = None
    pending_indent = 0

    def flush(open_tag=True):
        nonlocal pending_tag, pending_attrs
        if pending_tag is None:
            return
        attrs = " ".join(pending_attrs)
        out.append(f"<{pending_tag}{(' ' + attrs) if attrs else ''}>")
        pending_attrs = []
        pending_tag = None

    for raw in lines:
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())

        m = re.match(r"E:\s*([\w:.-]+)", stripped)
        if m:
            flush()
            while stack and stack[-1][0] >= indent:
                _, closing = stack.pop()
                out.append(f"</{closing}>")
            tag = m.group(1)
            pending_tag = tag
            pending_indent = indent
            stack.append((indent, tag))
            continue

        m = re.match(r'A:\s*([\w:.-]+)\([^)]*\)=(?:\([^)]*\))?"?([^"]*)"?', stripped)
        if not m:
            m = re.match(r'A:\s*([\w:.-]+)=(?:\([^)]*\))?"?([^"]*)"?', stripped)
        if m and pending_tag is not None:
            name, value = m.group(1), m.group(2)
            value = value.split(" (Raw:")[0].strip().strip('"')
            value = (value.replace("&", "&amp;").replace("<", "&lt;")
                          .replace(">", "&gt;").replace('"', "&quot;"))
            if ":" in name and not name.startswith("android:"):
                name = name.split(":")[-1]
            pending_attrs.append(f'{name}="{value}"')
            continue

    flush()
    while stack:
        _, closing = stack.pop()
        out.append(f"</{closing}>")

    body = "\n".join(out)
    # Ensure the android namespace is declared on the root element.
    body = body.replace(
        "<manifest", f'<manifest xmlns:android="{ANDROID_NS}"', 1
    )
    return body


# --------------------------------------------------------------------------
# Merger report parsing
# --------------------------------------------------------------------------

RE_REPORT_ELEMENT = re.compile(r"^([\w-]+)#([\w.$]+)\s*$")
RE_REPORT_ADDED = re.compile(r"^\s*(ADDED|MERGED|INJECTED|IMPLIED)\s+from\s+(.+?)(?::\d+.*)?$")


def parse_merger_report(path):
    """
    Parse manifest-merger-<variant>-report.txt.
    Returns { "receiver#com.foo.Bar": [(action, source), ...] }
    """
    result = defaultdict(list)
    current = None
    for raw in open(path, "r", encoding="utf-8", errors="replace"):
        line = raw.rstrip("\n")
        m = RE_REPORT_ELEMENT.match(line)
        if m:
            current = f"{m.group(1)}#{m.group(2)}"
            continue
        m = RE_REPORT_ADDED.match(line)
        if m and current:
            action, source = m.group(1), m.group(2).strip()
            result[current].append((action, source))
    return result


def coordinate_of(source_string):
    """Extract a Maven coordinate like [com.vendor:sdk:2.7.0] from a source."""
    m = re.search(r"\[([^\]]+)\]", source_string)
    if m:
        return m.group(1)
    return source_string


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

BOLD, RED, YEL, CYA, RST = "\033[1m", "\033[0;31m", "\033[0;33m", "\033[0;36m", "\033[0m"


def hdr(title, colour=True):
    bar = "=" * 74
    if colour:
        print(f"\n{BOLD}{bar}\n  {title}\n{bar}{RST}")
    else:
        print(f"\n{bar}\n  {title}\n{bar}")


def diff_manifests(source, merged, colour=True, emit_am=False):
    injected_exported = []

    hdr("Components added by libraries", colour)
    added = sorted(set(merged["components"]) - set(source["components"]))
    if not added:
        print("  none")
    for key in added:
        tag, name = key.split("|", 1)
        info = merged["components"][key]
        mark = "EXPORTED" if info["exported"] else "internal"
        flag = f"{RED}{mark}{RST}" if (colour and info["exported"]) else mark
        print(f"\n  [{flag}] <{tag}> {name}")
        if not info["exported_explicit"]:
            print("      android:exported was NOT declared — value implied by "
                  "the presence of an intent-filter (pre-API-31 rule)")
        if info["permission"]:
            print(f"      guarded by permission: {info['permission']}")
        if info["authorities"]:
            print(f"      authorities: {info['authorities']}")
        for f in info["filters"]:
            print(f"      {f}")
        if info["exported"]:
            injected_exported.append((tag, name, info))

    hdr("Components whose exported state CHANGED", colour)
    changed = False
    for key in sorted(set(source["components"]) & set(merged["components"])):
        s, m = source["components"][key], merged["components"][key]
        if s["exported"] != m["exported"]:
            changed = True
            tag, name = key.split("|", 1)
            print(f"  <{tag}> {name}: source={s['exported']} "
                  f"merged={m['exported']}")
    if not changed:
        print("  none")

    hdr("Permissions added by libraries", colour)
    perm_added = sorted(merged["permissions"] - source["permissions"])
    if not perm_added:
        print("  none")
    for p in perm_added:
        dangerous = any(t in p for t in (
            "LOCATION", "CAMERA", "RECORD_AUDIO", "READ_CONTACTS",
            "READ_SMS", "READ_PHONE_STATE", "READ_EXTERNAL_STORAGE",
            "BODY_SENSORS", "READ_CALENDAR", "CALL_LOG",
        ))
        prefix = f"{YEL}[user-visible]{RST} " if (colour and dangerous) else \
                 ("[user-visible] " if dangerous else "               ")
        print(f"  {prefix}{p}")

    hdr("<queries> entries added by libraries", colour)
    q_added = sorted(merged["queries"] - source["queries"])
    print("  none" if not q_added else "")
    for q in q_added:
        print(f"  {q}")

    hdr("<application> attributes in the merged manifest", colour)
    for k in sorted(merged["appAttrs"]):
        v = merged["appAttrs"][k]
        note = ""
        if k == "android:allowBackup" and v == "true":
            note = "  <-- adb backup / cloud backup of private data"
        if k == "android:debuggable" and v == "true":
            note = "  <-- run-as and JDWP for any user"
        if k == "android:usesCleartextTraffic" and v == "true":
            note = "  <-- plaintext HTTP permitted"
        if k not in source["appAttrs"]:
            note += "  [added by a library or by injection]"
        print(f"  {k} = {v}{note}")

    if emit_am and injected_exported:
        hdr("Reachability commands for injected exported components", colour)
        pkg = merged["package"] or source["package"] or "<applicationId>"
        print("  # adb shell — run each of these and observe what happens.")
        print("  # Reaching a component is not a finding; what it DOES is.\n")
        for tag, name, info in injected_exported:
            if tag in ("activity", "activity-alias"):
                print(f"  am start -n {pkg}/{name}")
                for f in info["filters"]:
                    if f.startswith("data:"):
                        print(f"  am start -a android.intent.action.VIEW "
                              f"-d \"{f[5:]}example\"")
            elif tag == "receiver":
                acts = [f[7:] for f in info["filters"] if f.startswith("action:")]
                for act in acts or ["<action>"]:
                    print(f"  am broadcast -a {act} -n {pkg}/{name}")
            elif tag == "service":
                print(f"  am startservice -n {pkg}/{name}")
            elif tag == "provider":
                auth = info["authorities"] or "<authority>"
                for a in auth.split(";"):
                    print(f"  content query --uri content://{a}/")
            print()

    return injected_exported


def report_attribution(report_map, colour=True):
    hdr("Provenance — who added what (from the merger report)", colour)
    by_coord = defaultdict(list)
    for element, entries in report_map.items():
        for action, source in entries:
            if action in ("ADDED", "INJECTED", "IMPLIED"):
                by_coord[coordinate_of(source)].append((action, element))

    if not by_coord:
        print("  no ADDED/INJECTED entries found — is this the right report file?")
        return

    for coord in sorted(by_coord, key=lambda c: -len(by_coord[c])):
        entries = by_coord[coord]
        label = f"{CYA}{coord}{RST}" if colour else coord
        print(f"\n  {label}  ({len(entries)} elements)")
        for action, element in sorted(set(entries))[:40]:
            print(f"      {action:<9} {element}")
        if len(set(entries)) > 40:
            print(f"      ... and {len(set(entries)) - 40} more")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Diff an Android app's own manifest against the merged one, "
                    "and attribute every injected element to its library."
    )
    ap.add_argument("--source", help="path to app/src/main/AndroidManifest.xml")
    ap.add_argument("--merged", help="path to the merged AndroidManifest.xml")
    ap.add_argument("--apk", help="APK to extract the shipped manifest from")
    ap.add_argument("--report",
                    help="manifest-merger-<variant>-report.txt")
    ap.add_argument("--emit-am-commands", action="store_true",
                    help="print adb commands to reach each injected component")
    ap.add_argument("--no-colour", action="store_true")
    args = ap.parse_args()

    colour = (not args.no_colour) and sys.stdout.isatty()

    if not (args.report or (args.source and (args.merged or args.apk))):
        ap.print_help()
        return 2

    injected = []

    if args.source and (args.merged or args.apk):
        with tempfile.TemporaryDirectory() as tmp:
            merged_path = args.merged
            if args.apk:
                try:
                    merged_path = manifest_from_apk(args.apk, tmp)
                except Exception as exc:      # noqa: BLE001
                    print(f"error: {exc}", file=sys.stderr)
                    return 2

            try:
                source = parse_manifest(args.source)
                merged = parse_manifest(merged_path)
            except ET.ParseError as exc:
                print(f"error: could not parse a manifest: {exc}",
                      file=sys.stderr)
                return 2

            print(f"\n  source package : {source['package']}")
            print(f"  merged package : {merged['package']}")
            print(f"  source components: {len(source['components'])}")
            print(f"  merged components: {len(merged['components'])}")

            injected = diff_manifests(source, merged, colour,
                                      args.emit_am_commands)

    if args.report:
        if not os.path.exists(args.report):
            print(f"error: {args.report} not found", file=sys.stderr)
            return 2
        report_attribution(parse_merger_report(args.report), colour)

    if injected:
        hdr("Summary", colour)
        print(f"  {len(injected)} EXPORTED components were injected by "
              f"dependencies.")
        print("  Reach each one and record what it does before reporting "
              "anything.")
        print("  See ../README.md section 5.3.2 for the severity table and the")
        print("  tools:node=\"remove\" remediation.\n")
        return 1

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
