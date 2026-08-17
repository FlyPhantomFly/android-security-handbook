#!/usr/bin/env python3
# scripts/uid-map.py
#
# WHAT IT DOES
#   Builds the complete UID -> package map for an Android device and reports every group of
#   two or more packages that share one Linux UID, which is the only definition of "shared
#   sandbox" the kernel actually implements.
#
#   It parses /data/system/packages.list properly — space-separated, field 6 optionally
#   "none", trailing columns tolerated because AOSP has added them over releases — instead
#   of the `pm list packages -U | awk` one-liner in faq.md question 5, which loses the debug
#   flag, the seinfo string and the GID list.
#
#   It can also read /data/system/packages.xml, which is where <shared-user> elements live.
#   packages.list has no notion of a shared user; it only records the resulting UID. Feeding
#   both files in gives you the shared user's NAME (android.uid.system, com.example.shared)
#   next to the number.
#
#   Platform shared users are excluded from the findings by design. Every Android device has
#   android.uid.system (1000), android.uid.phone (1001), android.uid.bluetooth (1002) and
#   friends. Reporting those is a false positive, and reporting it confidently is worse. The
#   rule used here is arithmetic, not a hardcoded allowlist: any UID below
#   Process.FIRST_APPLICATION_UID (10000) is a platform AID assigned in
#   system/core/libcutils/include/private/android_filesystem_config.h, not an installed
#   third-party app. Use --all to see them anyway.
#
# HOW TO RUN
#   # host, device connected, root on the device (best: full fidelity)
#   ./uid-map.py
#   ./uid-map.py --with-xml                 # also pull packages.xml for shared-user names
#   ./uid-map.py -s emulator-5554 --all --json
#
#   # host, no root on the device (degraded: package+uid only)
#   ./uid-map.py --no-root
#
#   # offline, against files you already pulled or carved out of an image
#   ./uid-map.py --list ./packages.list
#   ./uid-map.py --list ./packages.list --xml ./packages.xml
#   adb shell "su -c 'cat /data/system/packages.list'" | ./uid-map.py --list -
#   # note the OUTER quotes: adb shell joins its arguments with spaces before the
#   # device sees them, so `adb shell su -c 'cat FILE'` arrives as
#   # `su -c cat FILE` and su -c runs only `cat`. See the note in
#   # app-identity-dump.sh, which lost an afternoon to exactly this.
#
# REQUIREMENTS
#   Python 3.7+, standard library only. adb on PATH only for the device modes. Read-only:
#   nothing is installed, written or modified on the device.
#
# EXIT CODES
#   0  parsed successfully, no third-party shared-UID group found
#   1  usage error, no device, or the input could not be read/parsed
#   2  at least one third-party shared-UID group found
#
# WHAT THIS WILL NOT TELL YOU
#   - Whether a shared group is actually DANGEROUS. Sharing a UID is a fact; whether it is a
#     finding depends on what the weakest member exposes. Read the members' manifests.
#   - Who signed the packages. Members of a shared user must share a signing certificate, so
#     an OEM's own preloads can legitimately share an app-range UID and will be reported here
#     as third-party candidates. Confirm with `apksigner verify --print-certs` before writing
#     anything down. This script has no access to certificates at all.
#   - HOW the sharing was declared. android:sharedUserId, an inherited shared user from an
#     upgrade, and android:sharedUserMaxSdkVersion all produce the same UID. Only
#     packages.xml (--xml) distinguishes them, and only partially. See faq.md question 4.
#   - Anything about enforcement. That two packages share a UID means the kernel cannot tell
#     them apart; what an attacker can then reach is chapter 21's subject, not this one.
#     See ../../21-App-Sandbox/README.md.
#   - Work-profile relationships. UID 1010234 (user 10) and UID 10234 (user 0) are the same
#     appId in two Android users. They are NOT a shared-UID group, they never appear in one
#     together, and this script deliberately does not merge them. See faq.md question 16.
#   - Packages uninstalled with `pm uninstall -k`. Their records can survive in packages.xml
#     while being absent from packages.list; the two inputs may legitimately disagree.
#
# AUTHORISED TESTING ONLY.

import argparse
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

# frameworks/base/core/java/android/os/Process.java
FIRST_APPLICATION_UID = 10000
LAST_APPLICATION_UID = 19999
# Two adjacent isolated spans: app-zygote isolated UIDs sit below the plain isolated ones.
# The chapter quotes the union, 90000-99999, which is what matters when reading a UID.
FIRST_APP_ZYGOTE_ISOLATED_UID = 90000
FIRST_ISOLATED_UID = 99000
LAST_ISOLATED_UID = 99999
# The "app id" half of a UID; a UID is userId * PER_USER_RANGE + appId.
PER_USER_RANGE = 100000

# Common platform AIDs, for annotation only. Deliberately NOT the exclusion mechanism —
# exclusion is "appId < FIRST_APPLICATION_UID" — and deliberately not exhaustive.
KNOWN_AIDS = {
    0: "root",
    1000: "system (android.uid.system)",
    1001: "radio/phone (android.uid.phone)",
    1002: "bluetooth (android.uid.bluetooth)",
    1010: "wifi (android.uid.wifi)",
    1013: "media (android.uid.media)",
    1027: "nfc (android.uid.nfc)",
    2000: "shell",
    9999: "nobody",
}


class Entry(object):
    """One package record. Fields absent from the input stay None rather than guessing."""

    __slots__ = ("pkg", "uid", "debug", "data_dir", "seinfo", "gids",
                 "profileable", "version_code", "source")

    def __init__(self, pkg, uid, source):
        self.pkg = pkg
        self.uid = uid
        self.source = source
        self.debug = None
        self.data_dir = None
        self.seinfo = None
        self.gids = None
        self.profileable = None
        self.version_code = None

    @property
    def user_id(self):
        return self.uid // PER_USER_RANGE

    @property
    def app_id(self):
        return self.uid % PER_USER_RANGE

    def as_dict(self):
        return {
            "package": self.pkg,
            "uid": self.uid,
            "userId": self.user_id,
            "appId": self.app_id,
            "debuggable": self.debug,
            "dataDir": self.data_dir,
            "seinfo": self.seinfo,
            "gids": self.gids,
            "profileableByShell": self.profileable,
            "longVersionCode": self.version_code,
            "source": self.source,
        }


# --------------------------------------------------------------------------- parsing


def parse_packages_list(text):
    """Parse /data/system/packages.list.

    Field order, from Settings.writeLPr() (see
    frameworks/base/services/core/java/com/android/server/pm/Settings.java):

        1 package name
        2 uid
        3 debug flag          <- the byte run-as reads
        4 data directory
        5 seinfo
        6 gid list, comma separated, or the literal "none"
        7 profileableByShell flag
        8 longVersionCode
        9+ columns added in later releases

    Anything past field 8 is ignored on purpose: AOSP appends columns, and a parser that
    demands an exact field count breaks on the next Android release.
    """
    entries, problems = [], []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        f = line.split()
        if len(f) < 2:
            problems.append("line %d: fewer than 2 fields: %r" % (lineno, raw))
            continue
        try:
            uid = int(f[1])
        except ValueError:
            problems.append("line %d: field 2 is not an integer: %r" % (lineno, f[1]))
            continue
        e = Entry(f[0], uid, "packages.list")
        if len(f) >= 3 and f[2] in ("0", "1"):
            e.debug = f[2] == "1"
        if len(f) >= 4:
            e.data_dir = f[3]
        if len(f) >= 5 and f[4] != "null":
            e.seinfo = f[4]
        if len(f) >= 6:
            e.gids = [] if f[5] in ("none", "null") else [
                g for g in f[5].split(",") if g
            ]
        if len(f) >= 7 and f[6] in ("0", "1"):
            e.profileable = f[6] == "1"
        if len(f) >= 8:
            try:
                e.version_code = int(f[7])
            except ValueError:
                pass
        entries.append(e)
    return entries, problems


PM_LIST_RE = re.compile(r"^package:(\S+?)\s+uid:(\d+)\s*$")


def parse_pm_list_u(text):
    """Parse `pm list packages -U` output: 'package:com.example.app uid:10234'.

    This is the unrooted fallback. It carries no debug flag, no seinfo and no GIDs, so
    every corresponding field stays None and the report says so.
    """
    entries, problems = [], []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        m = PM_LIST_RE.match(line)
        if not m:
            problems.append("line %d: unrecognised pm output: %r" % (lineno, raw))
            continue
        entries.append(Entry(m.group(1), int(m.group(2)), "pm list packages -U"))
    return entries, problems


def parse_packages_xml(text):
    """Extract shared-user information from /data/system/packages.xml.

    Two things are wanted:
      * <shared-user name="com.example.shared" userId="10234"> -> the group's NAME.
      * <package name="..." sharedUserId="10234"> -> membership as PMS recorded it, which
        is authoritative in a way that "these two happen to have the same number" is not.

    Note the trap documented in README section 3.4: on a <package> element the attribute
    userId= is the appId, NOT the Android user id.
    """
    shared_names = {}     # uid -> shared user name
    pkg_shared = {}       # package -> uid, only for packages PMS records as shared
    problems = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return shared_names, pkg_shared, ["packages.xml did not parse: %s" % exc]

    for el in root.iter():
        tag = el.tag
        if tag in ("shared-user", "shared-users"):
            name = el.get("name")
            uid = el.get("userId") or el.get("appId") or el.get("uid")
            if name and uid and uid.isdigit():
                shared_names[int(uid)] = name
        elif tag == "package":
            name = el.get("name")
            suid = el.get("sharedUserId")
            if name and suid and suid.isdigit():
                pkg_shared[name] = int(suid)
    if not shared_names and not pkg_shared:
        problems.append(
            "packages.xml parsed but contained no <shared-user> or sharedUserId= data"
        )
    return shared_names, pkg_shared, problems


def sniff(text):
    """Guess which of the three accepted formats this text is."""
    head = text.lstrip()[:400]
    if head.startswith("<?xml") or "<packages" in head or "<package " in head:
        return "xml"
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        return "pm" if line.startswith("package:") else "list"
    return "list"


# ----------------------------------------------------------------------------- input


def read_source(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def adb(args, serial):
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        raise SystemExit("error: adb not found on PATH. Use --list to work offline.")
    return proc.returncode, proc.stdout.decode("utf-8", "replace").replace("\r", "")


def pull_from_device(serial, want_xml, allow_root):
    """Fetch packages.list (and optionally packages.xml), degrading honestly."""
    notes = []
    text = None

    if allow_root:
        # The whole `su -c '...'` invocation must reach the device as ONE argv element,
        # otherwise adb re-joins the words and su -c receives only "cat".
        rc, out = adb(["shell", "su -c 'cat /data/system/packages.list'"], serial)
        if rc == 0 and out.strip() and "Permission denied" not in out:
            text = out
            notes.append("source: /data/system/packages.list via su")
        if text is None:
            rc, out = adb(["shell", "cat /data/system/packages.list"], serial)
            if rc == 0 and out.strip() and "Permission denied" not in out:
                text = out
                notes.append("source: /data/system/packages.list via adb root")

    if text is None:
        rc, out = adb(["shell", "pm list packages -U"], serial)
        if rc != 0 or not out.strip():
            raise SystemExit(
                "error: could not read packages.list or run `pm list packages -U`.\n"
                "       Check `adb devices`, then try --list with a pulled file."
            )
        text = out
        notes.append(
            "source: `pm list packages -U` (DEGRADED — no debug flag, seinfo or GIDs; "
            "packages.list needs root)"
        )

    xml_text = None
    if want_xml:
        rc, out = adb(["shell", "su -c 'cat /data/system/packages.xml'"], serial)
        if rc == 0 and out.lstrip().startswith("<"):
            xml_text = out
            notes.append("source: /data/system/packages.xml via su")
        else:
            notes.append("packages.xml unavailable (needs root) — shared-user names omitted")
    return text, xml_text, notes


# --------------------------------------------------------------------------- analysis


def classify(uid):
    """Return (bucket, note) for a UID. Buckets drive the report and the exit code."""
    app_id = uid % PER_USER_RANGE
    if app_id < FIRST_APPLICATION_UID:
        return "platform", KNOWN_AIDS.get(app_id, "platform AID")
    if FIRST_APP_ZYGOTE_ISOLATED_UID <= app_id <= LAST_ISOLATED_UID:
        kind = ("isolated process UID" if app_id >= FIRST_ISOLATED_UID
                else "app-zygote isolated process UID")
        # Isolated UIDs are transient and never recorded in packages.list; seeing one here
        # means the input is not what it claims to be.
        return "isolated", kind
    if app_id > LAST_APPLICATION_UID:
        return "other", "outside the documented application range"
    return "app", "application appId"


def build_groups(entries, shared_names, pkg_shared):
    groups = {}
    for e in entries:
        groups.setdefault(e.uid, []).append(e)

    out = []
    for uid in sorted(groups):
        members = sorted(groups[uid], key=lambda x: x.pkg)
        bucket, note = classify(uid)
        name = shared_names.get(uid) or shared_names.get(uid % PER_USER_RANGE)
        declared = sorted(m.pkg for m in members if pkg_shared.get(m.pkg) is not None)
        out.append({
            "uid": uid,
            "userId": uid // PER_USER_RANGE,
            "appId": uid % PER_USER_RANGE,
            "bucket": bucket,
            "note": note,
            "sharedUserName": name,
            "declaredSharedMembers": declared,
            "shared": len(members) > 1,
            # A platform group is never a finding; see the header.
            "thirdPartyShared": len(members) > 1 and bucket == "app",
            "anyDebuggable": any(m.debug for m in members if m.debug is not None),
            "members": [m.as_dict() for m in members],
        })
    return out


# ----------------------------------------------------------------------------- output


def render(groups, notes, problems, show_all, degraded):
    lines = []
    add = lines.append

    add("=" * 78)
    add("  uid-map.py - UID to package map")
    add("=" * 78)
    for n in notes:
        add("  " + n)
    add("  packages parsed : %d" % sum(len(g["members"]) for g in groups))
    add("  distinct UIDs   : %d" % len(groups))
    add("")

    findings = [g for g in groups if g["thirdPartyShared"]]
    platform_shared = [g for g in groups if g["shared"] and not g["thirdPartyShared"]]

    add("--- third-party shared-UID groups " + "-" * 43)
    if not findings:
        add("  none. Every package in the 10000-19999 appId range has a UID to itself.")
    for g in findings:
        add("")
        title = "  UID %d  (userId=%d appId=%d)" % (g["uid"], g["userId"], g["appId"])
        if g["sharedUserName"]:
            title += "  sharedUser=%s" % g["sharedUserName"]
        add(title)
        add("  " + "-" * 74)
        for m in g["members"]:
            flags = []
            if m["debuggable"] is True:
                flags.append("DEBUGGABLE")
            if m["package"] in g["declaredSharedMembers"]:
                flags.append("declared in packages.xml")
            add("    %-52s %s" % (m["package"], " ".join(flags)))
            if m["dataDir"]:
                add("      dataDir : %s" % m["dataDir"])
            if m["seinfo"]:
                add("      seinfo  : %s" % m["seinfo"])
            if m["gids"]:
                add("      gids    : %s" % ",".join(m["gids"]))
        add("")
        add("    CONSEQUENCE: these %d packages are one principal to the kernel. Any of them"
            % len(g["members"]))
        add("    can open any other's files under /data/user/<N>/, and the permission-derived")
        add("    supplementary GIDs are the union across the group. The blast radius of a bug")
        add("    in the least important member is the most important member's private data.")
        if g["anyDebuggable"]:
            add("    ESCALATION: at least one member is DEBUGGABLE, so `run-as <that package>`")
            add("    gives an ordinary adb shell read/write access to the WHOLE group's data.")
        add("    VERIFY BEFORE REPORTING: confirm the signer with")
        add("      apksigner verify --print-certs <each base.apk>")
        add("    A shared OEM signing key is a legitimate, if unlovely, configuration.")

    add("")
    add("--- platform shared UIDs (excluded from findings) " + "-" * 27)
    if not platform_shared:
        add("  none seen.")
    for g in platform_shared:
        name = g["sharedUserName"] or g["note"]
        add("  UID %-8d %-34s %d packages" % (g["uid"], name, len(g["members"])))
        if show_all:
            for m in g["members"]:
                add("      %s" % m["package"])
    add("")
    add("  These are platform components signed with the platform key. Finding them is")
    add("  expected on every device; reporting them is a false positive.")

    if show_all:
        add("")
        add("--- every UID " + "-" * 63)
        for g in groups:
            mark = "*" if g["thirdPartyShared"] else " "
            add("%s UID %-8d %-10s %s" % (
                mark, g["uid"], g["bucket"],
                ", ".join(m["package"] for m in g["members"])))

    if degraded:
        add("")
        add("  NOTE: input was `pm list packages -U`, so the debug flag, seinfo and GID")
        add("  columns are unavailable. Shared-UID detection itself is unaffected (it only")
        add("  needs package and uid), but re-run with root for the rest.")

    if problems:
        add("")
        add("--- input problems " + "-" * 58)
        for p in problems[:20]:
            add("  " + p)
        if len(problems) > 20:
            add("  ... and %d more" % (len(problems) - 20))

    add("")
    add("  Findings: %d third-party shared-UID group(s)." % len(findings))
    return "\n".join(lines), len(findings)


# ------------------------------------------------------------------------------ main


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Map Android UIDs to packages and flag third-party shared-UID groups.",
        epilog="See 09-Android-App-Internals/faq.md question 5 and "
               "labs/lab-03-ctf-the-shared-uid-heist.md.",
    )
    ap.add_argument("--list", metavar="FILE",
                    help="read packages.list (or `pm list packages -U` output) from FILE, "
                         "or '-' for stdin, instead of querying a device")
    ap.add_argument("--xml", metavar="FILE",
                    help="additionally read packages.xml from FILE for <shared-user> names")
    ap.add_argument("--with-xml", action="store_true",
                    help="also pull packages.xml from the device (needs root)")
    ap.add_argument("--no-root", action="store_true",
                    help="skip the packages.list attempt and use `pm list packages -U`")
    ap.add_argument("-s", "--serial", metavar="SERIAL", help="adb device serial")
    ap.add_argument("--all", action="store_true",
                    help="print every UID, including platform and non-shared ones")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    args = ap.parse_args(argv)

    notes, problems = [], []
    xml_text = None

    if args.list:
        try:
            text = read_source(args.list)
        except OSError as exc:
            raise SystemExit("error: cannot read %s: %s" % (args.list, exc))
        notes.append("source: %s" % ("stdin" if args.list == "-" else args.list))
    else:
        text, xml_text, dev_notes = pull_from_device(
            args.serial, args.with_xml, not args.no_root)
        notes.extend(dev_notes)

    if args.xml:
        try:
            xml_text = read_source(args.xml)
            notes.append("source: %s" % args.xml)
        except OSError as exc:
            problems.append("cannot read %s: %s" % (args.xml, exc))

    fmt = sniff(text)
    if fmt == "xml":
        raise SystemExit(
            "error: that looks like packages.xml. Pass it with --xml and supply a "
            "packages.list (or a device) as the primary source."
        )
    if fmt == "pm":
        entries, probs = parse_pm_list_u(text)
    else:
        entries, probs = parse_packages_list(text)
    problems.extend(probs)

    if not entries:
        raise SystemExit("error: no package records parsed from the input.")

    shared_names, pkg_shared = {}, {}
    if xml_text:
        shared_names, pkg_shared, probs = parse_packages_xml(xml_text)
        problems.extend(probs)

    groups = build_groups(entries, shared_names, pkg_shared)
    findings = [g for g in groups if g["thirdPartyShared"]]

    if args.json:
        print(json.dumps({
            "notes": notes,
            "problems": problems,
            "packages": sum(len(g["members"]) for g in groups),
            "groups": groups if args.all else [g for g in groups if g["shared"]],
            "findings": len(findings),
        }, indent=2, sort_keys=True))
    else:
        report, _ = render(groups, notes, problems, args.all, fmt == "pm")
        print(report)

    return 2 if findings else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
