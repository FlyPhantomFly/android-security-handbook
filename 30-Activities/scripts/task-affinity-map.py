#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
task-affinity-map.py -- read the LIVE task graph off a device and flag the
                        task-hijacking configurations that a manifest cannot show.

PURPOSE
    `dumpsys activity activities` is the only place the platform tells you what
    it ACTUALLY DID with every android:taskAffinity and android:launchMode on the
    device. This script parses that dump into a task graph and answers four
    questions:

      1. Is this platform UID-NAMESPACING task affinities?
         The single most important question in the whole task-hijacking story,
         and the one nobody should assert from an Android version number. If the
         effective affinity of every activity is printed as "<uid>:<name>", two
         different apps can never share an affinity, and the classic
         StrandHogg configuration cannot work. If affinities are printed bare,
         it can. The script reports which, from evidence.
         (--check / included in the default report)

      2. Which activities declare an affinity naming SOMEBODY ELSE'S package?
         That is affinity squatting, and it is the attacker's half of the
         classic attack. It is visible at runtime even when the manifest is
         obfuscated or unavailable.

      3. Which tasks contain activities from MORE THAN ONE package?
         A mixed-package task means the user's Back button walks across a trust
         boundary. This happens for an entirely separate reason from affinity --
         a cross-app startActivity() without FLAG_ACTIVITY_NEW_TASK puts the
         callee in the CALLER's task -- and it is not mitigated by uid
         namespacing. Measured live on API 30; see README section 3.8.

      4. Which live activities combine a risky launchMode with a shared affinity?

WHY THIS IS NOT ANOTHER MANIFEST SCANNER
    32-Manifest/scripts/manifest-audit.py already audits the DECLARATION:
    it parses AndroidManifest.xml, applies the targetSdk export matrix, resolves
    protectionLevels and rates severity. Run it first; this script does not
    duplicate a line of it and never opens an APK.

    A manifest cannot tell you any of the four things above, because all four are
    properties of what the platform DID with the declaration:
      * the manifest says taskAffinity="com.victim"; only the runtime tells you
        whether the platform turned that into "10312:com.victim";
      * the manifest cannot show a task at all, because tasks are created by
        starts, not by declarations;
      * a mixed-package task exists only after a particular sequence of starts.

    Nor is it 26-Intent/scripts/intent-surface-map.py, which maps the RESOLVER
    tables -- which components would receive which Intent. This script maps the
    TASK tables -- where activities that already started ended up.

WHAT THIS WILL *NOT* TELL YOU
    * Whether anything here is a vulnerability. Every line is a LEAD. A squatted
      affinity on a uid-namespacing platform is a dead attack, and the script
      says so rather than crying wolf.
    * Anything about apps that are not running and have no task. The task graph
      is a snapshot of history, not an inventory. Use --recents to widen it to
      tasks whose process has died, and accept that a freshly booted device shows
      almost nothing. Launch the apps you care about first.
    * The DECLARED taskAffinity of an activity that has never run. That is a
      manifest question -- use manifest-audit.py or `aapt2 dump xmltree`.
    * Whether task hijacking would actually FOOL A USER. Task placement is
      necessary, not sufficient: the attacker still has to imitate the victim's
      UI convincingly, and the user still has to not notice. Severity is a
      judgement, and section 5.4 of the README argues it honestly.
    * Anything about overlays or tapjacking. Different subsystem
      (WindowManagerService, not ActivityTaskManagerService); use
      `dumpsys window windows` and README section 3.9.
    * Whether the attacker app could be installed at all. Task hijacking is a
      LOCAL attack that presupposes malware on the device. Say so in the report.

HOW TO RUN
    # host -- the default report against the attached device
    python3 -B task-affinity-map.py

    # host -- just the mitigation question, as a one-line verdict
    python3 -B task-affinity-map.py --check

    # host -- include tasks in Recents whose process has died
    python3 -B task-affinity-map.py --recents

    # host -- narrow to one package's tasks
    python3 -B task-affinity-map.py --package com.example.target

    # host -- machine-readable
    python3 -B task-affinity-map.py --json

    # offline: analyse a captured dump instead of talking to a device
    adb shell "dumpsys activity activities" > tasks.txt
    python3 -B task-affinity-map.py --dumpsys-file tasks.txt

REQUIREMENTS
    Python 3.7+, standard library only. `adb` on PATH and a device attached,
    except with --dumpsys-file. Writes nothing anywhere. Run with `python3 -B`
    as a habit; this script imports nothing that would create __pycache__, but
    the habit is what keeps the repository clean.

EXIT CODES
    0  ran, and no finding above INFO was raised
    1  ran, and at least one finding was raised (or no device)
    2  bad usage / unparseable input

AUTHORISED TESTING ONLY. This script only reads; it starts nothing and changes
nothing. The labs that go with it do start activities, and those change
application state.
"""

import argparse
import json
import re
import subprocess
import sys

# --------------------------------------------------------------------------- #
#  Launch modes.
#  ActivityInfo.LAUNCH_* in frameworks/base/core/java/android/content/pm/ActivityInfo.java
#  `dumpsys` prints the raw int on the ActivityRecord's "launchMode=" line.
# --------------------------------------------------------------------------- #

LAUNCH_MODES = {
    0: "standard",
    1: "singleTop",
    2: "singleTask",
    3: "singleInstance",
    4: "singleInstancePerTask",   # API 31+
}

# The two modes that make an activity the OWNER of a task rather than a member
# of one. These are the modes that matter for hijacking, because they are what
# lets an attacker's activity be the thing a task resolves to.
TASK_OWNING_MODES = {2, 3, 4}


# --------------------------------------------------------------------------- #
#  adb plumbing
# --------------------------------------------------------------------------- #

def die(msg, code=2):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(code)


class Adb(object):
    def __init__(self, serial=None):
        self.serial = serial

    def _base(self):
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def shell(self, device_cmd):
        # The whole command goes as ONE argument: `adb shell` concatenates its
        # arguments and hands the result to the device's sh, so anything the
        # device shell would glob must be quoted for THAT shell, not this one.
        try:
            p = subprocess.run(self._base() + ["shell", device_cmd],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=90)
        except FileNotFoundError:
            die("adb not found on PATH", 1)
        except subprocess.TimeoutExpired:
            return ""
        return p.stdout.decode("utf-8", "replace")

    def available(self):
        try:
            p = subprocess.run(self._base() + ["get-state"],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=20)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return b"device" in p.stdout

    def api_level(self):
        out = self.shell("getprop ro.build.version.sdk").strip()
        try:
            return int(out)
        except ValueError:
            return 0

    def release(self):
        return self.shell("getprop ro.build.version.release").strip()


# --------------------------------------------------------------------------- #
#  Parsing `dumpsys activity activities`
#
#  Measured shapes, Android 11 / API 30 (MIUI 12.5), and stable enough on
#  9 through 14 that the regexes are written to tolerate the differences:
#
#    * Task{e002411 #258 visible=true type=standard mode=fullscreen ...
#            A=10196:com.android.chrome U=0 StackId=258 sz=1}
#        affinity=10196:com.android.chrome
#        * Hist #0: ActivityRecord{1ea7c38 u0 com.android.chrome/...Main t258}
#            taskAffinity=10196:com.android.chrome
#            launchedFromUid=1000 launchedFromPackage=android
#            occludesParent=true noDisplay=false immersive=false launchMode=2
#
#  Notes that matter for parsing:
#    * A task with no affinity prints `I=<component>` instead of `A=<affinity>`
#      in the Task{} line (home/launcher tasks do this), and its activities
#      print `taskAffinity=null`.
#    * Android 9 and earlier print "Stack #n" / "TaskRecord{...}" and the
#      affinity without a uid prefix. Both are handled.
#    * The dump lists each task TWICE -- once per display, once in the summary
#      block at the end. Tasks are keyed by id so duplicates collapse.
# --------------------------------------------------------------------------- #

RE_TASK = re.compile(
    r"^\s*\*+\s*Task(?:Record)?\{(?P<hash>[0-9a-f]+)\s+#(?P<id>-?\d+)"
    r"(?P<rest>.*?)\}\s*$")
RE_TASK_A = re.compile(r"\bA=(?P<affinity>\S+?)\s+U=")
RE_TASK_I = re.compile(r"\bI=(?P<intent>\S+?)\s+U=")
RE_TASK_SZ = re.compile(r"\bsz=(?P<sz>\d+)")
RE_TASK_TYPE = re.compile(r"\btype=(?P<type>\w+)")
RE_AFFINITY = re.compile(r"^\s*affinity=(?P<affinity>.*?)\s*$")
RE_ROOTAFF = re.compile(r"^\s*rootAffinity=(?P<affinity>.*?)\s*$")
RE_HIST = re.compile(
    r"^\s*\*+\s*Hist\s+#(?P<idx>\d+):\s+ActivityRecord\{(?P<hash>[0-9a-f]+)\s+"
    r"u(?P<user>\d+)\s+(?P<pkg>[^/\s]+)/(?P<cls>\S+?)\s+t(?P<task>-?\d+)")
RE_ACT_AFF = re.compile(r"^\s*taskAffinity=(?P<affinity>.*?)\s*$")
RE_LAUNCHMODE = re.compile(r"\blaunchMode=(?P<mode>\d+)")
RE_FROMUID = re.compile(r"\blaunchedFromUid=(?P<uid>\d+)")
RE_FROMPKG = re.compile(r"\blaunchedFromPackage=(?P<pkg>\S+)")
RE_REALACT = re.compile(r"^\s*realActivity=\{?(?P<pkg>[^/\s{]+)/(?P<cls>[^}\s]+)\}?")

# An affinity the platform has namespaced looks like "10312:com.example".
RE_NAMESPACED = re.compile(r"^(?P<uid>\d+):(?P<name>.*)$")


def norm_class(pkg, cls):
    """dumpsys abbreviates a class in its own package to '.Foo'. Expand it."""
    if cls.startswith("."):
        return pkg + cls
    return cls


def parse_activities_dump(text):
    """
    Parse `dumpsys activity activities` into {task_id: task_dict}.

    Deliberately line-oriented and forgiving: OEM builds insert their own lines
    (MIUI adds mMiuiConfigFlag, realComponentName and several others) and a
    parser that assumes fixed structure breaks on every second device.
    """
    tasks = {}
    cur_task = None
    cur_act = None

    for raw in text.splitlines():
        m = RE_TASK.match(raw)
        if m:
            tid = int(m.group("id"))
            rest = m.group("rest")
            t = tasks.get(tid)
            if t is None:
                t = {
                    "id": tid,
                    "affinity": None,
                    "root_affinity": None,
                    "type": None,
                    "size": None,
                    "activities": [],
                    "real_activity": None,
                }
                tasks[tid] = t
            ma = RE_TASK_A.search(rest)
            if ma and not t["affinity"]:
                t["affinity"] = ma.group("affinity")
            mt = RE_TASK_TYPE.search(rest)
            if mt:
                t["type"] = mt.group("type")
            ms = RE_TASK_SZ.search(rest)
            if ms:
                t["size"] = int(ms.group("sz"))
            cur_task = t
            cur_act = None
            continue

        if cur_task is None:
            continue

        m = RE_HIST.match(raw)
        if m:
            pkg = m.group("pkg")
            act = {
                "index": int(m.group("idx")),
                "package": pkg,
                "component": norm_class(pkg, m.group("cls")),
                "task": int(m.group("task")),
                "affinity": None,
                "launch_mode": None,
                "launched_from_uid": None,
                "launched_from_package": None,
            }
            # The dump prints the whole graph twice; do not duplicate activities.
            key = (act["package"], act["component"], act["index"])
            if not any((a["package"], a["component"], a["index"]) == key
                       for a in cur_task["activities"]):
                cur_task["activities"].append(act)
                cur_act = act
            else:
                cur_act = next(a for a in cur_task["activities"]
                               if (a["package"], a["component"], a["index"]) == key)
            continue

        if cur_act is not None:
            m = RE_ACT_AFF.match(raw)
            if m:
                cur_act["affinity"] = m.group("affinity")
                continue
            m = RE_LAUNCHMODE.search(raw)
            if m:
                cur_act["launch_mode"] = int(m.group("mode"))
            m = RE_FROMUID.search(raw)
            if m:
                cur_act["launched_from_uid"] = int(m.group("uid"))
            m = RE_FROMPKG.search(raw)
            if m:
                cur_act["launched_from_package"] = m.group("pkg")
            continue

        m = RE_AFFINITY.match(raw)
        if m and cur_task["affinity"] in (None, ""):
            cur_task["affinity"] = m.group("affinity")
            continue
        m = RE_ROOTAFF.match(raw)
        if m:
            cur_task["root_affinity"] = m.group("affinity")
            continue
        m = RE_REALACT.match(raw)
        if m:
            cur_task["real_activity"] = "%s/%s" % (
                m.group("pkg"), norm_class(m.group("pkg"), m.group("cls")))

    return tasks


def parse_recents_dump(text, tasks):
    """
    Fold `dumpsys activity recents` into the task map.

    Worth doing because a task survives its process: a task whose app was killed
    still appears in Recents with its affinity intact, and that is exactly the
    state a parked hijack task sits in. Recents gives no activity list, so these
    tasks contribute an affinity and a realActivity and nothing else.
    """
    cur = None
    for raw in text.splitlines():
        m = RE_TASK.match(raw)
        if m:
            tid = int(m.group("id"))
            t = tasks.get(tid)
            if t is None:
                t = {"id": tid, "affinity": None, "root_affinity": None,
                     "type": None, "size": None, "activities": [],
                     "real_activity": None, "from_recents": True}
                tasks[tid] = t
            ma = RE_TASK_A.search(m.group("rest"))
            if ma and not t["affinity"]:
                t["affinity"] = ma.group("affinity")
            cur = t
            continue
        if cur is None:
            continue
        m = RE_AFFINITY.match(raw)
        if m and not cur["affinity"]:
            cur["affinity"] = m.group("affinity")
            continue
        m = RE_REALACT.match(raw)
        if m and not cur["real_activity"]:
            cur["real_activity"] = "%s/%s" % (
                m.group("pkg"), norm_class(m.group("pkg"), m.group("cls")))
    return tasks


# --------------------------------------------------------------------------- #
#  Analysis
# --------------------------------------------------------------------------- #

def split_affinity(aff):
    """
    ('10312', 'com.example')  for a uid-namespaced affinity
    (None,    'com.example')  for a bare one
    (None,    None)           for no affinity at all ('null', '', or absent)
    """
    if aff is None:
        return None, None
    aff = aff.strip()
    if aff in ("", "null", "None"):
        return None, None
    m = RE_NAMESPACED.match(aff)
    if m:
        return m.group("uid"), m.group("name")
    return None, aff


def namespacing_verdict(tasks):
    """
    Decide, from evidence on this device, whether the platform uid-namespaces
    task affinities -- the empirical form of the question "is the classic
    StrandHogg configuration mitigated here?".

    The test is deliberately conservative. A single bare affinity among many
    namespaced ones is not enough to call the platform unmitigated, because a
    task can legitimately carry no affinity. What matters is whether affinities
    that EXIST carry a uid prefix.
    """
    seen = 0
    namespaced = 0
    for t in tasks.values():
        uid, name = split_affinity(t["affinity"])
        if name is None:
            continue
        seen += 1
        if uid is not None:
            namespaced += 1
        for a in t["activities"]:
            auid, aname = split_affinity(a["affinity"])
            if aname is None:
                continue
            seen += 1
            if auid is not None:
                namespaced += 1

    if seen == 0:
        return {
            "verdict": "UNKNOWN",
            "seen": 0, "namespaced": 0,
            "detail": "no affinity strings in the dump -- launch a few apps and "
                      "re-run, or pass --recents",
        }
    if namespaced == seen:
        return {
            "verdict": "NAMESPACED",
            "seen": seen, "namespaced": namespaced,
            "detail": "every affinity carries a '<uid>:' prefix, so two packages "
                      "can never share an effective affinity. The classic "
                      "taskAffinity + singleTask hijack CANNOT work on this "
                      "platform build.",
        }
    if namespaced == 0:
        return {
            "verdict": "NOT-NAMESPACED",
            "seen": seen, "namespaced": namespaced,
            "detail": "affinities are bare strings. Two packages CAN share an "
                      "effective affinity, so the classic hijack is live here. "
                      "Test it with examples/hijacker-app and labs/lab-02.",
        }
    return {
        "verdict": "MIXED",
        "seen": seen, "namespaced": namespaced,
        "detail": "some affinities are namespaced and some are not. Investigate "
                  "the bare ones individually before concluding anything -- an "
                  "OEM fork is the usual explanation.",
    }


def analyse(tasks, ns):
    """Produce a list of findings. Every finding is a lead, never a verdict."""
    findings = []
    namespaced_platform = ns["verdict"] == "NAMESPACED"

    for tid in sorted(tasks):
        t = tasks[tid]
        t_uid, t_name = split_affinity(t["affinity"])

        # ---- F3: more than one package inside one task -------------------- #
        pkgs = sorted({a["package"] for a in t["activities"]})
        if len(pkgs) > 1:
            findings.append({
                "id": "MIXED-PACKAGE-TASK",
                "severity": "HIGH",
                "task": tid,
                "packages": pkgs,
                "text": "task %d contains activities from %d packages: %s. The "
                        "user's Back button walks across a trust boundary here. "
                        "This is NOT an affinity effect and uid namespacing does "
                        "not prevent it -- it is what a cross-app startActivity() "
                        "WITHOUT FLAG_ACTIVITY_NEW_TASK produces."
                        % (tid, len(pkgs), ", ".join(pkgs)),
            })

        # ---- F6: the task's affinity names a package that is not its root -- #
        root_pkg = None
        if t["activities"]:
            root = min(t["activities"], key=lambda a: a["index"])
            root_pkg = root["package"]
        elif t["real_activity"]:
            root_pkg = t["real_activity"].split("/")[0]
        if t_name and root_pkg and t_name != root_pkg \
                and not t_name.startswith(root_pkg + "."):
            findings.append({
                "id": "TASK-AFFINITY-MISMATCH",
                "severity": "MEDIUM" if not namespaced_platform else "INFO",
                "task": tid,
                "affinity": t["affinity"],
                "root_package": root_pkg,
                "text": "task %d has affinity '%s' but its root activity belongs "
                        "to '%s'. Benign when an app declares a custom affinity "
                        "for its own screens; a red flag when the affinity names "
                        "ANOTHER installed package."
                        % (tid, t["affinity"], root_pkg),
            })

        # ---- per-activity checks ------------------------------------------ #
        for a in t["activities"]:
            a_uid, a_name = split_affinity(a["affinity"])
            lm = a["launch_mode"]
            lm_name = LAUNCH_MODES.get(lm, "?" if lm is None else str(lm))

            # F5 -- the hardening value.
            if a["affinity"] is not None and a_name is None:
                findings.append({
                    "id": "AFFINITY-EMPTY",
                    "severity": "INFO",
                    "task": tid,
                    "component": "%s/%s" % (a["package"], a["component"]),
                    "text": "%s/%s has NO task affinity (android:taskAffinity=\"\"). "
                            "This is the hardening value -- there is no affinity "
                            "string for another app to claim. Note it as good "
                            "practice, not as a finding."
                            % (a["package"], a["component"]),
                })
                continue

            if a_name is None:
                continue

            # F2 -- the squat. The activity's effective affinity names a package
            # that is not its own. On a namespacing platform this is inert, and
            # the script says so rather than inflating it.
            if a_name != a["package"] and not a_name.startswith(a["package"] + "."):
                sev = "INFO" if namespaced_platform else "HIGH"
                extra = (" The platform uid-namespaces affinities, so this "
                         "cannot collide with %s's own task -- the declaration "
                         "is still worth reporting as INTENT, but it is not a "
                         "working attack here." % a_name) if namespaced_platform \
                    else (" Affinities are NOT namespaced on this platform, so "
                          "this activity's task and %s's task are the same task. "
                          "Verify with lab-02 and report it." % a_name)
                findings.append({
                    "id": "AFFINITY-SQUAT",
                    "severity": sev,
                    "task": tid,
                    "component": "%s/%s" % (a["package"], a["component"]),
                    "affinity": a["affinity"],
                    "claims": a_name,
                    "launch_mode": lm_name,
                    "text": "%s/%s declares an affinity naming '%s', which is not "
                            "its own package. launchMode=%s.%s"
                            % (a["package"], a["component"], a_name, lm_name, extra),
                })

            # F4 -- the classic pairing, reported at its honest weight.
            elif lm in TASK_OWNING_MODES and a_name == a["package"]:
                findings.append({
                    "id": "TASK-OWNING-LAUNCHMODE",
                    "severity": "INFO",
                    "task": tid,
                    "component": "%s/%s" % (a["package"], a["component"]),
                    "launch_mode": lm_name,
                    "text": "%s/%s uses launchMode=%s with its DEFAULT affinity "
                            "('%s'). This is the configuration the classic hijack "
                            "targets: the app's task carries a guessable name. "
                            "The hardening is android:taskAffinity=\"\". Whether "
                            "it is exploitable depends on the namespacing verdict "
                            "above, not on this line."
                            % (a["package"], a["component"], lm_name, a_name),
                })

    return findings


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def print_graph(tasks, package=None):
    print("=" * 78)
    print("TASK GRAPH")
    print("=" * 78)
    shown = 0
    for tid in sorted(tasks, reverse=True):
        t = tasks[tid]
        pkgs = {a["package"] for a in t["activities"]}
        if package and package not in pkgs and \
                not (t["real_activity"] or "").startswith(package + "/"):
            continue
        shown += 1
        uid, name = split_affinity(t["affinity"])
        aff = t["affinity"] or "(none)"
        ns = "uid-namespaced" if uid else ("bare" if name else "no affinity")
        print("")
        print("  Task #%d   type=%s  sz=%s" % (tid, t["type"] or "?",
                                               t["size"] if t["size"] is not None else "?"))
        print("      affinity : %s   [%s]" % (aff, ns))
        if t["real_activity"]:
            print("      realActivity: %s" % t["real_activity"])
        if not t["activities"]:
            print("      (no live activities -- process died; task survives in Recents)")
        for a in sorted(t["activities"], key=lambda x: -x["index"]):
            lm = LAUNCH_MODES.get(a["launch_mode"], "?")
            mark = "  <- ROOT" if a["index"] == 0 else ""
            print("      [%d] %s/%s%s" % (a["index"], a["package"], a["component"], mark))
            print("          launchMode=%s  affinity=%s"
                  % (lm, a["affinity"] if a["affinity"] is not None else "?"))
            if a["launched_from_package"]:
                print("          launchedFrom=%s (uid %s)"
                      % (a["launched_from_package"], a["launched_from_uid"]))
    if shown == 0:
        print("  no tasks matched")
    print("")


def print_findings(findings):
    print("=" * 78)
    print("FINDINGS")
    print("=" * 78)
    if not findings:
        print("  none")
        print("")
        return
    for f in sorted(findings, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["id"])):
        print("")
        print("  [%-6s] %s   (task %s)" % (f["severity"], f["id"], f.get("task", "-")))
        # Wrap the prose at 74 columns without importing textwrap for one call.
        words = f["text"].split()
        line = "     "
        for w in words:
            if len(line) + len(w) + 1 > 74:
                print(line)
                line = "     "
            line += (" " if line.strip() else "") + w
        if line.strip():
            print(line)
    print("")


def print_verdict(ns):
    print("=" * 78)
    print("AFFINITY NAMESPACING -- the task-hijacking mitigation, measured")
    print("=" * 78)
    print("  verdict  : %s   (%d of %d affinity strings carry a uid prefix)"
          % (ns["verdict"], ns["namespaced"], ns["seen"]))
    words = ns["detail"].split()
    line = "  detail   :"
    for w in words:
        if len(line) + len(w) + 1 > 76:
            print(line)
            line = "            "
        line += " " + w
    print(line)
    print("")
    print("  This is EVIDENCE, not a version lookup. Report it as 'measured on")
    print("  <device>, <release>/<api>' -- OEM forks differ, and a claim keyed to")
    print("  an Android version number has been wrong in this repository before.")
    print("")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="task-affinity-map.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Map the live Activity task graph and flag task-hijacking "
                    "configurations.",
        epilog="Every finding is a lead. Task hijacking additionally presupposes "
               "that the attacker's app is already installed -- weigh severity "
               "accordingly.")
    ap.add_argument("-s", "--serial", help="adb device serial")
    ap.add_argument("-p", "--package", help="only show tasks involving this package")
    ap.add_argument("--recents", action="store_true",
                    help="also fold in `dumpsys activity recents` (tasks whose "
                         "process has died but which survive in Recents)")
    ap.add_argument("--check", action="store_true",
                    help="print only the namespacing verdict")
    ap.add_argument("--no-graph", action="store_true", help="skip the task graph")
    ap.add_argument("--dumpsys-file",
                    help="read a captured `dumpsys activity activities` instead "
                         "of talking to a device")
    ap.add_argument("--recents-file",
                    help="with --dumpsys-file: a captured `dumpsys activity recents`")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    header = {}
    if args.dumpsys_file:
        with open(args.dumpsys_file, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
        recents_text = ""
        if args.recents_file:
            with open(args.recents_file, "rb") as fh:
                recents_text = fh.read().decode("utf-8", "replace")
    else:
        adb = Adb(args.serial)
        if not adb.available():
            die("no device -- attach one, or use --dumpsys-file", 1)
        header = {"release": adb.release(), "api": adb.api_level()}
        text = adb.shell("dumpsys activity activities")
        recents_text = adb.shell("dumpsys activity recents") if args.recents else ""

    if "Task" not in text and "TaskRecord" not in text:
        die("no tasks in the input -- did you capture `dumpsys activity activities`?", 2)

    tasks = parse_activities_dump(text)
    if recents_text:
        tasks = parse_recents_dump(recents_text, tasks)

    ns = namespacing_verdict(tasks)
    findings = analyse(tasks, ns)

    if args.json:
        print(json.dumps({
            "device": header,
            "namespacing": ns,
            "tasks": [tasks[k] for k in sorted(tasks)],
            "findings": findings,
        }, indent=2))
    else:
        if header:
            print("device: Android %s / API %s" % (header.get("release", "?"),
                                                   header.get("api", "?")))
            print("")
        print_verdict(ns)
        if args.check:
            return 0
        if not args.no_graph:
            print_graph(tasks, args.package)
        print_findings(findings)
        print("-" * 78)
        print("Every line above is a LEAD. Two things this tool cannot weigh for you:")
        print("  1. Task hijacking requires the attacker's app to be INSTALLED already.")
        print("     That is a real precondition and it caps the severity -- README 5.4.")
        print("  2. A task placement is not a deception. The attacker still has to")
        print("     imitate the victim convincingly. Screenshot it or do not claim it.")
        print("-" * 78)

    return 1 if any(f["severity"] in ("HIGH", "MEDIUM") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
