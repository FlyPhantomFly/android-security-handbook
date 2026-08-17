#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
receiver-surface.py -- enumerate the RUNTIME broadcast-receiver surface of a device.

PURPOSE
    Show the receivers that no static tool can see.

    A BroadcastReceiver declared in AndroidManifest.xml is visible to apktool,
    to aapt2, to jadx, to `dumpsys package`, and to every manifest auditor ever
    written. A receiver created by `Context.registerReceiver()` at runtime is in
    none of those places. It exists only as an entry in
    ActivityManagerService's in-memory registration table, and the only reader
    of that table is `dumpsys activity broadcasts`.

    This script parses that dump and answers four questions:

      1. Which receivers are registered RIGHT NOW, in which process, under which
         UID, for which actions, and behind which sender permission (if any)?
         (default mode, `--registered`)

      2. Which of those actions have NO manifest-declared receiver anywhere on
         the device -- i.e. which parts of the surface are runtime-only and
         therefore invisible to static analysis?
         (`--runtime-only`)

      3. Which broadcasts were recently dispatched, by which UID, carrying which
         extras? The historical log records the SENDER, which `onReceive` never
         sees. It also records extras in cleartext.
         (`--history`)

      4. Which actions can an unprivileged sender actually forge? A
         `<protected-broadcast>` action is refused by ActivityManagerService for
         any sender that is not the system. Rather than trusting a list copied
         out of a framework manifest, this asks the device.
         (`--probe-protected`)

WHY THIS IS NOT ANOTHER MANIFEST SCANNER, AND NOT 26'S SCRIPT
    32-Manifest/scripts/manifest-audit.py audits the DECLARATION -- it parses
    AndroidManifest.xml, applies the targetSdk export-default matrix and rates
    the static component surface. It is the right tool for an APK on disk, and
    a manifest-declared receiver is entirely its business. This script does not
    parse a manifest at all and never opens an APK.

    26-Intent/scripts/intent-surface-map.py reads PackageManagerService's
    RESOLVER tables -- `dumpsys package` and `cmd package query-*` -- to answer
    "which component would win this Intent". Its own header says, explicitly,
    that dynamically registered receivers are outside its scope, because they
    are not in the static resolver tables. This script is the tool it points at.

    The two views are complementary and this script uses BOTH: it reads the AMS
    runtime table for what exists, and calls `cmd package query-receivers` only
    to SUBTRACT the statically declared actions, so that what remains is the
    runtime-only residue.

WHAT THIS WILL *NOT* TELL YOU
    * Whether anything here is a vulnerability. Every line is a LEAD. A
      registered receiver with no sender permission is a precondition, never a
      finding. You still need (a) reachability from an UNPRIVILEGED APP -- not
      from `adb shell`, which is uid 2000 and holds capabilities an ordinary app
      does not -- and (b) a demonstrated state change.
    * What the receiver DOES with the broadcast. Nothing in the dump describes
      behaviour. Decompile the class, or hook it with scripts/hook-broadcast.js.
    * The receiver CLASS NAME. The dump names the process and a ReceiverList
      identity hash, not the Java class. Hooking is the only way to get the
      class. This is the single biggest limitation of the dumpsys approach and
      the reason the Frida script exists.
    * LocalBroadcastManager receivers. They never reach AMS -- the whole point of
      LocalBroadcastManager is that delivery is in-process -- so they are absent
      here AND absent from the manifest. Only a hook finds them.
    * Receivers in a process that is not currently running. Registration dies
      with the process. A receiver registered in an Activity's onResume is gone
      the moment the Activity is destroyed. The surface is a snapshot, not an
      inventory: run this repeatedly while exercising the target.
    * The export state on API 33+. Below API 33 there is no export flag at all
      in the dump, because there was no such concept for runtime receivers --
      they were unconditionally reachable unless a sender permission was set.
      This script reports what the dump on YOUR device provides and says so.
    * Anything about protectionLevel. Resolve a requiredPermission with
      `adb shell pm list permissions -f`, or with 32-Manifest's auditor.

HOW TO RUN
    # host -- every runtime registration on the device, grouped by package
    python3 receiver-surface.py

    # host -- one package
    python3 receiver-surface.py --package com.example.target

    # host -- who is listening for one action, right now
    python3 receiver-surface.py --action android.intent.action.SCREEN_ON

    # host -- only third-party apps, only registrations with no sender permission
    python3 receiver-surface.py --third-party --unprotected

    # host -- THE HEADLINE: actions live at runtime with no manifest declaration
    python3 receiver-surface.py --runtime-only

    # host -- recent broadcasts, with sender UID and extras
    python3 receiver-surface.py --history
    python3 receiver-surface.py --history --with-extras

    # host -- is this action forgeable by a non-system sender? (SENDS nothing)
    python3 receiver-surface.py --probe-protected android.intent.action.BOOT_COMPLETED

    # host -- probe a list, ACTUALLY SENDING the ones that turn out unprotected
    python3 receiver-surface.py --probe-protected-file actions.txt --i-will-send

    # offline: analyse a dump captured earlier
    adb shell dumpsys activity broadcasts > bc.txt
    python3 receiver-surface.py --dumpsys-file bc.txt --runtime-only

    # machine readable
    python3 receiver-surface.py --json > surface.json

REQUIREMENTS
    Python 3.7+, standard library only. `adb` on PATH with a device attached for
    every device mode; nothing at all for --dumpsys-file. No root required --
    `dumpsys activity broadcasts` is readable by uid 2000 (shell). Run with
    `python3 -B` if you want to be certain no __pycache__ appears; this script
    imports nothing that would create one.

    Never writes a file next to itself.

EXIT CODES
    0  ran successfully and found something
    1  ran successfully and found nothing, or no device
    2  bad usage, or a dump this parser could not make sense of

AUTHORISED TESTING ONLY. --probe-protected --i-will-send DISPATCHES REAL
BROADCASTS to every app on the device. That changes application state.
"""

import argparse
import json
import re
import subprocess
import sys

# --------------------------------------------------------------------------- #
#  UID arithmetic
#  frameworks/base/core/java/android/os/UserHandle.java
# --------------------------------------------------------------------------- #

PER_USER_RANGE = 100000
FIRST_APPLICATION_UID = 10000
LAST_APPLICATION_UID = 19999

WELL_KNOWN_UIDS = {
    0: "root",
    1000: "system",
    1001: "phone (radio)",
    1002: "bluetooth",
    1013: "media",
    1017: "keystore",
    1027: "nfc",
    2000: "shell (adb)",
}


def uid_kind(uid):
    """Classify a raw uid the way the platform does."""
    if uid is None:
        return "unknown"
    app_id = uid % PER_USER_RANGE
    if app_id in WELL_KNOWN_UIDS:
        return WELL_KNOWN_UIDS[app_id]
    if FIRST_APPLICATION_UID <= app_id <= LAST_APPLICATION_UID:
        return "third-party app"
    if app_id < FIRST_APPLICATION_UID:
        return "platform uid %d" % app_id
    return "isolated/other %d" % app_id


def is_third_party(uid):
    if uid is None:
        return False
    app_id = uid % PER_USER_RANGE
    return FIRST_APPLICATION_UID <= app_id <= LAST_APPLICATION_UID


# --------------------------------------------------------------------------- #
#  adb plumbing
# --------------------------------------------------------------------------- #


def adb(args, serial=None, timeout=90):
    """Run one adb command and return (rc, stdout, stderr) with CR stripped."""
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return 127, "", "adb not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", "adb timed out after %ds" % timeout
    out = p.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
    err = p.stderr.decode("utf-8", "replace").replace("\r\n", "\n")
    return p.returncode, out, err


def device_facts(serial=None):
    """Release and API level. Every version-gated claim below depends on these."""
    facts = {}
    for key, prop in (("release", "ro.build.version.release"),
                      ("sdk", "ro.build.version.sdk"),
                      ("model", "ro.product.model")):
        rc, out, _ = adb(["shell", "getprop", prop], serial)
        facts[key] = out.strip() if rc == 0 else "?"
    try:
        facts["sdk_int"] = int(facts["sdk"])
    except (TypeError, ValueError):
        facts["sdk_int"] = 0
    return facts


def get_dump(serial=None, path=None):
    if path:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().replace("\r\n", "\n")
    rc, out, err = adb(["shell", "dumpsys", "activity", "broadcasts"], serial)
    if rc != 0 or not out.strip():
        sys.stderr.write("[-] could not read `dumpsys activity broadcasts`: %s\n"
                         % (err.strip() or "empty output"))
        return None
    return out


# --------------------------------------------------------------------------- #
#  Parsing the Registered Receivers section
#
#  The shape, from
#  frameworks/base/services/core/java/com/android/server/am/
#      ActivityManagerService.dumpBroadcastsLocked() and
#      ReceiverList.dump() / BroadcastFilter.dumpInReceiverList():
#
#    Registered Receivers:
#      * ReceiverList{<hash> <pid> <process>/<uid>/<userId> remote:<hash>}
#        app=<pid>:<process>/<uid-name> pid=<pid> uid=<uid> user=<userId>
#        Filter #0: BroadcastFilter{<hash>}
#          Action: "..."
#          Category: "..."
#          Scheme: "..."
#          Type: "..."
#          requiredPermission=<permission>
#
#  Everything after `Registered Receivers:` and before `Receiver Resolver Table:`
#  belongs to this section. The resolver table that follows lists the same
#  filters again, indexed by scheme/type, and is not re-parsed here.
# --------------------------------------------------------------------------- #

RE_RECEIVER_LIST = re.compile(
    r"^\s*\*\s*ReceiverList\{(?P<hash>[0-9a-f]+)\s+(?P<pid>\d+)\s+"
    r"(?P<process>\S+?)/(?P<uid>\d+)/u(?P<user>-?\d+)\s+(?P<link>\S+?)\}\s*$"
)
RE_APP_LINE = re.compile(
    r"^\s*app=(?P<pid>\d+):(?P<process>\S+?)/(?P<uidname>\S+)\s+"
    r"pid=(?P<pid2>\d+)\s+uid=(?P<uid>\d+)\s+user=(?P<user>-?\d+)"
)
RE_FILTER = re.compile(r"^\s*Filter #(?P<n>\d+): BroadcastFilter\{(?P<hash>[0-9a-f]+)\}")
RE_ACTION = re.compile(r'^\s*Action: "(?P<v>.*)"\s*$')
RE_CATEGORY = re.compile(r'^\s*Category: "(?P<v>.*)"\s*$')
RE_SCHEME = re.compile(r'^\s*Scheme: "(?P<v>.*)"\s*$')
RE_TYPE = re.compile(r'^\s*Type: "(?P<v>.*)"\s*$')
RE_REQPERM = re.compile(r"^\s*requiredPermission=(?P<v>\S+)")
RE_PRIORITY = re.compile(r"^\s*(?:mPriority|priority)=(?P<v>-?\d+)")

SECTION_START = "Registered Receivers:"
SECTION_END = "Receiver Resolver Table:"

# The AndroidX shim. ContextCompat.registerReceiver() cannot use
# RECEIVER_NOT_EXPORTED below API 33 because the flag does not exist, so it
# emulates it: it registers with a self-defined signature permission whose name
# is <package>.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION. Seeing it means the
# developer asked for NOT_EXPORTED and the library honoured it on an old device.
ANDROIDX_NOT_EXPORTED = "DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"


def parse_registered(text):
    """Return a list of receiver-list records from the Registered Receivers block."""
    start = text.find(SECTION_START)
    if start < 0:
        return []
    end = text.find(SECTION_END, start)
    body = text[start + len(SECTION_START):end if end > 0 else len(text)]

    records = []
    cur = None
    filt = None

    for line in body.split("\n"):
        m = RE_RECEIVER_LIST.match(line)
        if m:
            cur = {
                "hash": m.group("hash"),
                "pid": int(m.group("pid")),
                "process": m.group("process"),
                "uid": int(m.group("uid")),
                "user": int(m.group("user")),
                "link": m.group("link"),
                "uid_name": None,
                "filters": [],
            }
            records.append(cur)
            filt = None
            continue

        if cur is None:
            continue

        m = RE_APP_LINE.match(line)
        if m:
            cur["uid_name"] = m.group("uidname")
            # The app= line carries the authoritative numeric uid; the header
            # sometimes prints the process's uid name instead.
            cur["uid"] = int(m.group("uid"))
            continue

        m = RE_FILTER.match(line)
        if m:
            filt = {
                "index": int(m.group("n")),
                "hash": m.group("hash"),
                "actions": [],
                "categories": [],
                "schemes": [],
                "types": [],
                "requiredPermission": None,
                "priority": None,
            }
            cur["filters"].append(filt)
            continue

        if filt is None:
            continue

        for rx, key in ((RE_ACTION, "actions"), (RE_CATEGORY, "categories"),
                        (RE_SCHEME, "schemes"), (RE_TYPE, "types")):
            m = rx.match(line)
            if m:
                filt[key].append(m.group("v"))
                break
        else:
            m = RE_REQPERM.match(line)
            if m:
                filt["requiredPermission"] = m.group("v")
                continue
            m = RE_PRIORITY.match(line)
            if m:
                filt["priority"] = int(m.group("v"))

    return records


def package_of(rec):
    """Process name minus any :subprocess suffix. Not always the package name."""
    proc = rec.get("process") or "?"
    return proc.split(":", 1)[0]


# --------------------------------------------------------------------------- #
#  Parsing the historical broadcast log
#
#  Historical Broadcast <queue> #N:
#    BroadcastRecord{<hash> u<user> <action>} to user <n>
#    Intent { act=<action> flg=0x... (has extras) }
#      extras: Bundle[{...}]
#    caller=<pkg> <pid>:<proc>/<uid> pid=<pid> uid=<uid>
#    resultTo=... resultCode=N resultData=...
#    resultAbort=<bool> ordered=<bool> sticky=<bool> initialSticky=<bool>
# --------------------------------------------------------------------------- #

RE_HIST_HDR = re.compile(r"^\s*Historical Broadcast (?P<queue>\w+) #(?P<n>\d+):")
RE_HIST_REC = re.compile(r"^\s*BroadcastRecord\{\S+ u(?P<user>-?\d+) (?P<action>.*)\} to user")
RE_HIST_INTENT = re.compile(r"^\s*Intent \{ (?P<body>.*) \}\s*$")
RE_HIST_EXTRAS = re.compile(r"^\s*extras: (?P<v>.*)$")
RE_HIST_CALLER = re.compile(r"^\s*caller=(?P<caller>\S+)\s+(?P<rest>.*?)\s*uid=(?P<uid>\d+)\s*$")
RE_HIST_FLAGS = re.compile(
    r"^\s*resultAbort=(?P<abort>\w+) ordered=(?P<ordered>\w+) "
    r"sticky=(?P<sticky>\w+) initialSticky=(?P<isticky>\w+)"
)
RE_HIST_RESULT = re.compile(
    r"^\s*resultTo=(?P<to>\S+) resultCode=(?P<code>-?\d+) resultData=(?P<data>.*)$"
)


def parse_history(text):
    """Return historical broadcast records, newest first as the dump orders them."""
    records = []
    cur = None
    for line in text.split("\n"):
        m = RE_HIST_HDR.match(line)
        if m:
            cur = {"queue": m.group("queue"), "index": int(m.group("n")),
                   "action": None, "intent": None, "extras": None,
                   "caller": None, "caller_uid": None, "ordered": None,
                   "sticky": None, "initialSticky": None, "abort": None,
                   "resultCode": None, "resultData": None, "deliveries": 0}
            records.append(cur)
            continue
        if cur is None:
            continue
        m = RE_HIST_REC.match(line)
        if m:
            cur["action"] = m.group("action")
            continue
        m = RE_HIST_INTENT.match(line)
        if m and cur["intent"] is None:
            cur["intent"] = m.group("body")
            continue
        m = RE_HIST_EXTRAS.match(line)
        if m:
            cur["extras"] = m.group("v")
            continue
        m = RE_HIST_CALLER.match(line)
        if m:
            cur["caller"] = m.group("caller")
            cur["caller_uid"] = int(m.group("uid"))
            continue
        m = RE_HIST_FLAGS.match(line)
        if m:
            cur["abort"] = m.group("abort") == "true"
            cur["ordered"] = m.group("ordered") == "true"
            cur["sticky"] = m.group("sticky") == "true"
            cur["initialSticky"] = m.group("isticky") == "true"
            continue
        m = RE_HIST_RESULT.match(line)
        if m:
            cur["resultCode"] = int(m.group("code"))
            cur["resultData"] = m.group("data")
            continue
        if line.lstrip().startswith("Deliver "):
            cur["deliveries"] += 1
    return records


SECRETISH = re.compile(
    r"token|secret|password|passwd|api[_.-]?key|apikey|auth|session|cookie|"
    r"bearer|jwt|otp|pin|credential|private",
    re.I,
)


# --------------------------------------------------------------------------- #
#  The static half: what PackageManager knows
# --------------------------------------------------------------------------- #


def static_receivers_for(action, serial=None):
    """
    Manifest-declared receivers for one action, via PackageManagerService.

    `cmd package query-receivers` exists from API 29. It reads the same resolver
    tables `dumpsys package` prints, so it sees manifest declarations ONLY. That
    is precisely why it is useful here: subtracting it from the AMS runtime
    table leaves the runtime-only residue.
    """
    rc, out, err = adb(["shell", "cmd", "package", "query-receivers",
                        "--brief", "-a", action], serial)
    if rc != 0:
        return None, (err.strip() or out.strip())
    if "No receivers found" in out:
        return [], None
    if "Unknown command" in out or "Error" in out[:80]:
        return None, out.strip().split("\n")[0]
    comps = []
    for line in out.split("\n"):
        line = line.strip()
        if "/" in line and " " not in line and line and not line.startswith("Receiver"):
            comps.append(line)
    return comps, None


# --------------------------------------------------------------------------- #
#  Protected-broadcast probing
# --------------------------------------------------------------------------- #

PROTECTED_MARKER = "not allowed to send broadcast"


def probe_protected(action, serial=None, really_send=False):
    """
    Ask the device whether a non-system sender may send this action.

    ActivityManagerService.broadcastIntentLocked() checks the action against the
    set built from every <protected-broadcast> element in every installed
    package's manifest (only the platform and other system packages contribute).
    A non-system caller sending a protected action gets a SecurityException
    BEFORE any receiver is consulted.

    THE CATCH, AND IT IS A BIG ONE: the only way to find out is to try, and a
    successful try DELIVERS THE BROADCAST to every registered receiver on the
    device. Without --i-will-send this function refuses to run and returns
    "unknown", because a reconnaissance tool must not have side effects by
    default.

    THE SECOND CATCH: `adb shell` is uid 2000, not an ordinary app. Shell holds
    permissions an app does not. An action that shell CAN send is definitely
    forgeable by shell; whether it is forgeable by an unprivileged app still has
    to be confirmed from an app. Protected-broadcast enforcement itself does not
    distinguish -- it allows only the system uid and packages holding
    the platform signature -- so a shell "denied" is a reliable "protected", and
    a shell "allowed" is a reliable "not protected". The uid-2000 caveat matters
    for the RECEIVER-side permission check, not this one.
    """
    if not really_send:
        return "unknown", "refused: --i-will-send not given (this test DISPATCHES)"
    rc, out, err = adb(["shell", "am", "broadcast", "-a", action], serial)
    blob = out + "\n" + err
    if PROTECTED_MARKER in blob:
        return "protected", blob.strip().split("\n")[-1].strip()
    if "Broadcast completed" in blob:
        m = re.search(r"Broadcast completed: result=(-?\d+)", blob)
        return "forgeable", "delivered, result=%s" % (m.group(1) if m else "?")
    if "SecurityException" in blob:
        return "denied-other", blob.strip().split("\n")[-1].strip()
    return "unknown", blob.strip()[:200]


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #


def hr(title):
    print("")
    print("=== " + title + " " + "=" * max(2, 74 - len(title)))


def fmt_receiver(rec, static_index=None, show_all_actions=True):
    lines = []
    pkg = package_of(rec)
    kind = uid_kind(rec["uid"])
    lines.append("  %s   pid=%d uid=%d (%s) user=%d  [%s]"
                 % (rec["process"], rec["pid"], rec["uid"], kind, rec["user"],
                    "local" if rec["link"].startswith("local") else "remote"))
    for f in rec["filters"]:
        perm = f["requiredPermission"]
        if perm and ANDROIDX_NOT_EXPORTED in perm:
            guard = ("sender must hold %s\n           <-- AndroidX RECEIVER_NOT_EXPORTED "
                     "backport: a self-defined signature permission standing in for a\n"
                     "               flag that does not exist below API 33. Effectively "
                     "NOT exported." % perm)
        elif perm:
            guard = ("sender must hold %s\n           <-- resolve its protectionLevel: "
                     "`adb shell pm list permissions -f | grep -A2 %s`" % (perm, perm))
        else:
            guard = ("NO sender permission  <-- any app that can name the action reaches "
                     "this receiver")
        lines.append("    Filter #%d: %s" % (f["index"], guard))
        acts = f["actions"] if show_all_actions else f["actions"][:6]
        for a in acts:
            mark = ""
            if static_index is not None:
                if a in static_index and static_index[a] == 0:
                    mark = "   <-- RUNTIME-ONLY: no manifest anywhere declares it"
            lines.append("        action: %s%s" % (a, mark))
        if not show_all_actions and len(f["actions"]) > 6:
            lines.append("        ... and %d more actions" % (len(f["actions"]) - 6))
        for c in f["categories"]:
            lines.append("        category: %s" % c)
        for s in f["schemes"]:
            lines.append("        scheme: %s" % s)
        for t in f["types"]:
            lines.append("        type: %s" % t)
        if f["priority"] is not None:
            lines.append("        priority: %d" % f["priority"])
    return "\n".join(lines)


def report_registered(records, args, static_index=None):
    hr("RUNTIME-REGISTERED RECEIVERS (AMS in-memory table)")
    print("  These exist only while their process lives. None of them is in any")
    print("  manifest. No static tool can enumerate them.")
    print("")

    by_pkg = {}
    for r in records:
        by_pkg.setdefault(package_of(r), []).append(r)

    shown = 0
    for pkg in sorted(by_pkg):
        group = by_pkg[pkg]
        print("")
        print("--- %s  (%d registration%s, uid %s)"
              % (pkg, len(group), "" if len(group) == 1 else "s",
                 ", ".join(sorted({str(g["uid"]) for g in group}))))
        for r in group:
            print(fmt_receiver(r, static_index, show_all_actions=not args.brief))
            shown += 1
    return shown


def summarise(records):
    hr("SUMMARY")
    total_lists = len(records)
    total_filters = sum(len(r["filters"]) for r in records)
    total_actions = sum(len(f["actions"]) for r in records for f in r["filters"])
    distinct_actions = {a for r in records for f in r["filters"] for a in f["actions"]}
    with_perm = sum(1 for r in records for f in r["filters"] if f["requiredPermission"])
    androidx = sum(1 for r in records for f in r["filters"]
                   if f["requiredPermission"] and ANDROIDX_NOT_EXPORTED in f["requiredPermission"])
    tp = [r for r in records if is_third_party(r["uid"])]
    tp_unprot = [r for r in tp if any(f["requiredPermission"] is None for f in r["filters"])]

    rows = [
        ("ReceiverList registrations", total_lists),
        ("IntentFilters across them", total_filters),
        ("action strings (with duplicates)", total_actions),
        ("distinct action strings", len(distinct_actions)),
        ("filters WITH a sender permission", with_perm),
        ("  of which AndroidX NOT_EXPORTED backport", androidx),
        ("filters with NO sender permission", total_filters - with_perm),
        ("registrations owned by third-party apps", len(tp)),
        ("  third-party AND at least one unguarded filter", len(tp_unprot)),
    ]
    width = max(len(r[0]) for r in rows)
    for name, val in rows:
        print("  %-*s : %d" % (width, name, val))
    print("")
    print("  A filter with no sender permission is reachable by any app that can")
    print("  name its action -- IF the action is not a protected broadcast. Check")
    print("  with --probe-protected before you call anything a finding.")
    return {
        "receiverLists": total_lists,
        "filters": total_filters,
        "actionStrings": total_actions,
        "distinctActions": len(distinct_actions),
        "filtersWithPermission": with_perm,
        "androidxNotExportedBackport": androidx,
        "thirdPartyRegistrations": len(tp),
        "thirdPartyUnguarded": len(tp_unprot),
    }


def report_runtime_only(records, args):
    """The headline: actions that live only in the AMS table."""
    hr("RUNTIME-ONLY ACTIONS -- live registrations with no manifest declaration")
    print("  For each distinct action in the AMS table, ask PackageManager whether")
    print("  ANY installed package declares a manifest receiver for it. An action")
    print("  with live registrations and zero manifest receivers is a piece of")
    print("  attack surface that apktool, jadx, aapt2 and every manifest auditor")
    print("  will report as not existing.")
    print("")

    actions = {}
    for r in records:
        for f in r["filters"]:
            for a in f["actions"]:
                actions.setdefault(a, []).append((r, f))

    if args.action:
        actions = {k: v for k, v in actions.items() if k == args.action}

    ordered = sorted(actions)
    if args.limit:
        ordered = ordered[:args.limit]

    print("  querying PackageManager for %d distinct action(s)..." % len(ordered))
    print("")

    index = {}
    runtime_only = []
    errors = 0
    for a in ordered:
        comps, err = static_receivers_for(a, args.serial)
        if comps is None:
            errors += 1
            index[a] = None
            continue
        index[a] = len(comps)
        if len(comps) == 0:
            runtime_only.append(a)

    print("  %-70s %s" % ("ACTION", "runtime / manifest"))
    print("  " + "-" * 90)
    for a in ordered:
        n_runtime = len(actions[a])
        n_static = index.get(a)
        flag = ""
        if n_static == 0:
            flag = "   <-- RUNTIME-ONLY"
        shown = a if len(a) <= 70 else a[:67] + "..."
        print("  %-70s %4d / %s%s"
              % (shown, n_runtime,
                 "err" if n_static is None else str(n_static), flag))

    print("")
    print("  %d of %d distinct actions have live runtime registrations and NO"
          % (len(runtime_only), len(ordered)))
    print("  manifest-declared receiver anywhere on this device.")
    if errors:
        print("  %d action(s) could not be queried (cmd package query-receivers "
              "failed)." % errors)
    print("")
    print("  Reading this correctly: a manifest count of 0 does not mean the")
    print("  action is undocumented or private. It means that on THIS device, at")
    print("  THIS moment, the only listeners are runtime registrations, so a")
    print("  static audit of any APK on the device would have missed all of them.")
    return index, runtime_only


def report_history(records, args):
    hr("HISTORICAL BROADCASTS -- the only record of WHO sent what")
    print("  onReceive() cannot tell you who sent a broadcast: by the time it runs,")
    print("  the sender's Binder identity is gone and Binder.getCallingUid() returns")
    print("  your OWN uid. This log is the exception. It records the caller and, if")
    print("  the sender attached any, the extras -- in cleartext.")
    print("")

    n = 0
    leaks = 0
    for h in records:
        if args.action and h["action"] != args.action:
            continue
        if args.limit and n >= args.limit:
            break
        n += 1
        kind = uid_kind(h["caller_uid"]) if h["caller_uid"] is not None else "?"
        print("  [%s #%d] %s" % (h["queue"], h["index"], h["action"]))
        print("      caller=%s uid=%s (%s)"
              % (h["caller"], h["caller_uid"], kind))
        flags = []
        if h["ordered"]:
            flags.append("ordered")
        if h["sticky"]:
            flags.append("STICKY")
        if h["initialSticky"]:
            flags.append("initialSticky")
        if h["abort"]:
            flags.append("ABORTED")
        print("      %s  resultCode=%s  deliveries=%d"
              % (", ".join(flags) if flags else "unordered",
                 h["resultCode"], h["deliveries"]))
        if h["extras"]:
            mark = ""
            if SECRETISH.search(h["extras"]):
                mark = "   <-- CANDIDATE SECRET in a broadcast extra"
                leaks += 1
            if args.with_extras:
                print("      extras: %s%s" % (h["extras"], mark))
            else:
                print("      extras: (%d chars, use --with-extras to print)%s"
                      % (len(h["extras"]), mark))
    print("")
    print("  %d record(s) shown; %d carried an extra whose KEY looks credential-like."
          % (n, leaks))
    print("  A key named `token` is a lead, not a secret. Read the value before")
    print("  reporting anything -- and note that this log is readable by anyone with")
    print("  shell or the DUMP permission, which is why a secret must never travel")
    print("  in a broadcast extra in the first place.")
    return n


def report_probe(actions, args):
    hr("PROTECTED-BROADCAST PROBE")
    print("  A <protected-broadcast> action is refused by ActivityManagerService")
    print("  for any sender that is not the system. This asks the device instead of")
    print("  trusting a list typed from memory -- OEM framework builds add their own.")
    print("")
    if not args.i_will_send:
        print("  !! --i-will-send was NOT given. Nothing will be sent, and every")
        print("     result will be `unknown`. That is deliberate: the only way to")
        print("     learn whether an action is protected is to attempt it, and an")
        print("     unprotected attempt is DELIVERED to every registered receiver")
        print("     on the device.")
        print("")

    results = {}
    for a in actions:
        verdict, detail = probe_protected(a, args.serial, args.i_will_send)
        results[a] = {"verdict": verdict, "detail": detail}
        mark = {"protected": "PROTECTED  (cannot be forged)",
                "forgeable": "FORGEABLE  (any sender may dispatch it)",
                "denied-other": "DENIED, different reason",
                "unknown": "unknown"}[verdict]
        print("  %-58s %s" % (a, mark))
        if verdict in ("protected", "denied-other") and args.verbose:
            print("      %s" % detail)
    print("")
    print("  FORGEABLE plus a receiver that acts on the broadcast is the whole")
    print("  vulnerability class. FORGEABLE on its own is not a finding.")
    return results


# --------------------------------------------------------------------------- #
#  main
# --------------------------------------------------------------------------- #


def build_parser():
    p = argparse.ArgumentParser(
        prog="receiver-surface.py",
        description="Enumerate runtime-registered BroadcastReceivers from "
                    "`dumpsys activity broadcasts` -- the surface no static "
                    "tool can see.",
        epilog="AUTHORISED TESTING ONLY.",
    )
    p.add_argument("-s", "--serial", help="adb device serial")
    p.add_argument("--dumpsys-file", help="parse a captured dump instead of a device")
    p.add_argument("--package", help="only registrations whose process starts with this")
    p.add_argument("--action", help="only this action")
    p.add_argument("--third-party", action="store_true",
                   help="only uids in [10000,19999]")
    p.add_argument("--unprotected", action="store_true",
                   help="only registrations with at least one filter that has no "
                        "requiredPermission")
    p.add_argument("--brief", action="store_true",
                   help="truncate long action lists")
    p.add_argument("--limit", type=int, default=0, help="cap rows / queries")
    p.add_argument("--verbose", action="store_true")

    mode = p.add_argument_group("modes (default: --registered)")
    mode.add_argument("--registered", action="store_true",
                      help="list runtime registrations (default)")
    mode.add_argument("--runtime-only", action="store_true",
                      help="cross-check every action against PackageManager and "
                           "report those with no manifest declaration anywhere")
    mode.add_argument("--history", action="store_true",
                      help="recent broadcasts with sender uid and extras")
    mode.add_argument("--with-extras", action="store_true",
                      help="print extras values in --history")
    mode.add_argument("--probe-protected", metavar="ACTION", action="append",
                      default=[], help="probe one action (repeatable)")
    mode.add_argument("--probe-protected-file", metavar="FILE",
                      help="probe every action listed one-per-line in FILE")
    mode.add_argument("--i-will-send", action="store_true",
                      help="required for --probe-protected to actually dispatch")
    mode.add_argument("--json", action="store_true", help="machine-readable output")
    return p


def main(argv):
    args = build_parser().parse_args(argv)

    probe_list = list(args.probe_protected)
    if args.probe_protected_file:
        try:
            with open(args.probe_protected_file, "r", encoding="utf-8") as fh:
                probe_list += [ln.strip() for ln in fh
                               if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            sys.stderr.write("[-] %s\n" % e)
            return 2

    facts = {"release": "?", "sdk": "?", "model": "?", "sdk_int": 0}
    if not args.dumpsys_file:
        facts = device_facts(args.serial)
        if facts["sdk"] == "?":
            sys.stderr.write("[-] no device. Use --dumpsys-file to work offline.\n")
            return 1

    if probe_list:
        results = report_probe(probe_list, args)
        if args.json:
            print(json.dumps({"device": facts, "probe": results}, indent=2))
        return 0 if results else 1

    text = get_dump(args.serial, args.dumpsys_file)
    if text is None:
        return 1
    if SECTION_START not in text:
        sys.stderr.write("[-] this does not look like `dumpsys activity broadcasts` "
                         "output: no `Registered Receivers:` section.\n")
        return 2

    records = parse_registered(text)
    if not records:
        sys.stderr.write("[-] parsed zero registrations. The dump format may differ "
                         "on this release -- re-check the ReceiverList regex.\n")
        return 2

    if args.package:
        records = [r for r in records if package_of(r).startswith(args.package)]
    if args.third_party:
        records = [r for r in records if is_third_party(r["uid"])]
    if args.unprotected:
        records = [r for r in records
                   if any(f["requiredPermission"] is None for f in r["filters"])]
    if args.action:
        records = [r for r in records
                   if any(args.action in f["actions"] for f in r["filters"])]

    if not args.json:
        hr("DEVICE")
        print("  model=%s  Android %s  API %s"
              % (facts["model"], facts["release"], facts["sdk"]))
        if facts["sdk_int"] and facts["sdk_int"] < 33:
            print("  API < 33: runtime-registered receivers have NO export flag.")
            print("  Every registration below is reachable by any sender unless a")
            print("  requiredPermission is shown. RECEIVER_EXPORTED /")
            print("  RECEIVER_NOT_EXPORTED do not exist on this release; the")
            print("  AndroidX shim permission is how NOT_EXPORTED is emulated.")
        elif facts["sdk_int"] >= 33:
            print("  API >= 33: a targetSdk-33 app MUST pass RECEIVER_EXPORTED or")
            print("  RECEIVER_NOT_EXPORTED to registerReceiver for a non-system")
            print("  action, or the platform throws. Check whether your dump prints")
            print("  the flag -- if it does not, hook registerReceiver instead.")

    static_index = None
    runtime_only = []
    if args.runtime_only:
        static_index, runtime_only = report_runtime_only(records, args)

    shown = 0
    if args.registered or not (args.runtime_only or args.history):
        shown = report_registered(records, args, static_index)

    hist = []
    if args.history:
        hist = parse_history(text)
        report_history(hist, args)

    stats = summarise(records) if not args.json else None

    if args.json:
        out = {
            "device": facts,
            "receivers": records,
            "runtimeOnlyActions": runtime_only,
            "history": hist if args.history else [],
        }
        print(json.dumps(out, indent=2))

    if not args.json:
        hr("BEFORE YOU CALL ANY OF THIS A FINDING")
        print("  1. This dump is a SNAPSHOT. A receiver registered in onResume is")
        print("     gone when the Activity is destroyed. Re-run while exercising")
        print("     the target.")
        print("  2. The dump does not name the receiver CLASS. Hook")
        print("     registerReceiver with scripts/hook-broadcast.js to get it.")
        print("  3. `adb shell` is uid 2000 and is privileged. Reachability must be")
        print("     proven from an ordinary, unprivileged app.")
        print("  4. An unguarded receiver is a precondition. Show a forged")
        print("     broadcast changing observable state before you report it.")

    return 0 if (shown or runtime_only or hist) else 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(130)
