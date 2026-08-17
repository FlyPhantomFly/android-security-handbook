#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
grant-state.py -- separate what an app REQUESTED from what it actually HOLDS.

WHAT IT DOES
    `adb shell dumpsys package <pkg>` prints three permission blocks one after
    another with almost no visual separation, and they mean three completely
    different things:

        requested permissions:   developer INTENT. A line of manifest XML.
        install permissions:     a decision the platform took at install.
        runtime permissions:     a decision the USER took, per Android user,
                                 revocable at any moment.

    Only the last two carry a `granted=` suffix. A tester who reads the first
    block and reports from it is reporting a wish list. This script reads all
    three, prints them as separate, labelled sets, and -- the part that is the
    whole reason it exists -- computes and prints the FOURTH set:

        UNACCOUNTED:  requested, and present in NEITHER grant block.

    Those are permissions the app asked for and did not receive. On a real
    device that set is often large. Measured on the test device, Chrome
    requested 59 permissions, held 37, and 34 were unaccounted for -- mostly
    other vendors' signature permissions it does not qualify for. Reporting any
    of those 34 as "held" is a fabrication that the client can disprove in ten
    seconds.

    It also prints, per Android user:
        - the permission-derived supplementary GID list (`gids=`)
        - the runtime permission FLAGS, which carry USER_FIXED, POLICY_FIXED,
          GRANTED_BY_DEFAULT and AUTO_REVOKED -- each of which changes the
          finding
        - the permissions this package DECLARES, with their protection levels

    And it flags every permission whose level is known to carry the `appop`
    flag, because for those `dumpsys package` alone gives the wrong answer.

WHAT THIS IS NOT -- the boundary with chapters 21 and 32
    This script does NOT read a manifest. It is a device-state reader, and that
    is deliberate.

    32-Manifest/scripts/manifest-audit.py owns the DECLARATION AUDIT: the
    severity-rated checklist and the targetSdk version matrix, applied to XML.
    21-App-Sandbox/scripts/manifest-exposure.py owns the SANDBOX view: what a
    manifest does to the UID boundary.

    Neither of them has a device. Neither can tell you whether a permission is
    actually granted, because that is not a property of the APK. This script is
    the third leg, and it needs input the other two never see.

    Its sibling, ./permission-audit.py, is the one that reads a manifest -- and
    it too refuses to restage 32's checklist, restricting itself to the app's
    OWN <permission> declarations and their enforceability.

WHAT THIS WILL *NOT* TELL YOU
    - Whether the app USES a permission it holds. A granted permission with no
      code path behind it is over-privilege, not exposure. Cross-reference
      against the DEX; see README.md section 8.3.
    - The effective state of an appop-flagged permission. `dumpsys package` and
      `cmd appops get` are two independent state machines and the answer is a
      function of BOTH. Measured on the test device:
      REQUEST_INSTALL_PACKAGES was `granted=false` in dumpsys and `allow` in
      appops at the same instant. This script FLAGS those rows and tells you
      the command to run; it cannot run it for you from a capture file.
    - Whether an UNACCOUNTED permission is a finding. It almost never is. It
      usually means the declaring app is not installed, or the permission is
      signature-level and belongs to somebody else. The set is printed so that
      you do not silently report it as held.
    - Why a permission appears as granted that the manifest never requested.
      That is usually <split-permission> in
      /system/etc/permissions/platform.xml, not an anomaly. Check there before
      you write it up. See README.md section 3.5.
    - Anything about protection levels beyond what dumpsys states. Resolve them
      with `adb shell pm list permissions -f -g`, or feed a capture of that to
      ./permission-audit.py.
    - Anything about a device you do not have. A capture is a snapshot; runtime
      permissions change between the capture and your reading it.

HOW TO RUN
    # host -- capture, then read
    adb shell dumpsys package com.target.app > dump.txt
    python3 grant-state.py dump.txt

    # host -- capture and read in one step (needs adb on PATH and one device)
    python3 grant-state.py --pkg com.target.app

    # host -- only the gap between requested and granted
    python3 grant-state.py dump.txt --unaccounted-only

    # host -- straight into a report
    python3 grant-state.py dump.txt --markdown > grants.md

    # host -- machine-readable, for diffing two captures
    python3 grant-state.py before.txt --json > before.json
    python3 grant-state.py after.txt  --json > after.json

    # host -- from stdin
    adb shell dumpsys package com.target.app | python3 grant-state.py -

REQUIREMENTS
    Python 3.6+. Standard library only. No pip install, so it runs on a
    locked-down assessment laptop.

    Output is deliberately pure ASCII. A Windows console defaults to a codepage
    that cannot encode box-drawing characters, and a UnicodeEncodeError in the
    middle of a report is worse than a plain table.

    The script writes nothing, imports nothing local, and produces no
    __pycache__ beside the repository source. Run it as a script.

EXIT CODES
    0  ran to completion
    2  input unreadable, or no package block found in it
    3  --pkg was used and adb failed

AUTHORISED TESTING ONLY.
"""

import argparse
import json
import os
import re
import subprocess
import sys

# ---------------------------------------------------------------------------
#  Permissions whose protectionLevel carries the `appop` flag on AOSP.
#
#  For these, `dumpsys package` alone is NOT sufficient: the effective answer
#  is a function of the permission grant AND the app-op mode. This list is
#  deliberately short and conservative -- it holds only the ones stable enough
#  to hard-code. Anything not here is resolved on the device, and the script
#  says so rather than guessing.
# ---------------------------------------------------------------------------

APPOP_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW":       "SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES":  "REQUEST_INSTALL_PACKAGES",
    "android.permission.WRITE_SETTINGS":            "WRITE_SETTINGS",
    "android.permission.PACKAGE_USAGE_STATS":       "GET_USAGE_STATS",
    "android.permission.MANAGE_EXTERNAL_STORAGE":   "MANAGE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_NOTIFICATIONS":      "ACCESS_NOTIFICATIONS",
    "android.permission.SCHEDULE_EXACT_ALARM":      "SCHEDULE_EXACT_ALARM",
    "android.permission.USE_EXACT_ALARM":           "USE_EXACT_ALARM",
    "android.permission.LOADER_USAGE_STATS":        "LOADER_USAGE_STATS",
}

# Special-access permissions worth a line in any report, whether or not they
# are appop-flagged. Bound to a one-line reason so the output is usable
# without looking anything up.
HIGH_SIGNAL = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE":
        "Read every window's content and inject events into any app. Treat as "
        "equivalent to holding every dangerous permission -- an accessibility "
        "service can operate the permission dialogs itself.",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
        "Read every notification, including one-time codes.",
    "android.permission.BIND_DEVICE_ADMIN":
        "Lock, wipe, and resist uninstall.",
    "android.permission.SYSTEM_ALERT_WINDOW":
        "Draw over any other app. The tapjacking and overlay-phishing primitive.",
    "android.permission.REQUEST_INSTALL_PACKAGES":
        "Trigger installation of other APKs -- dropper capability.",
    "android.permission.MANAGE_EXTERNAL_STORAGE":
        "Read and write every other app's shared-storage files.",
    "android.permission.QUERY_ALL_PACKAGES":
        "Defeats package-visibility filtering. normal level, so granted on "
        "request -- a privacy signal, not an escalation.",
    "android.permission.PACKAGE_USAGE_STATS":
        "Which apps the user opens, and when.",
    "android.permission.WRITE_SECURE_SETTINGS":
        "Change secure system settings. Not obtainable by an ordinary app.",
    "android.permission.READ_SMS":
        "Read the SMS database, including one-time codes.",
    "android.permission.RECEIVE_SMS":
        "Receive incoming SMS, including one-time codes.",
    "android.permission.RECORD_AUDIO":
        "Microphone.",
    "android.permission.CAMERA":
        "Camera.",
    "android.permission.ACCESS_FINE_LOCATION":
        "Precise location.",
    "android.permission.ACCESS_BACKGROUND_LOCATION":
        "Location while the app is not in use.",
    "android.permission.READ_CONTACTS":
        "Address book.",
    "android.permission.READ_CALL_LOG":
        "Call history.",
    "android.permission.SCHEDULE_EXACT_ALARM":
        "Wake the device on a precise schedule -- a persistence primitive.",
}

# Runtime permission flags whose presence changes the finding.
FLAG_MEANING = {
    "GRANTED_BY_DEFAULT":
        "Pre-granted by the platform or an installer, NOT by the user.",
    "USER_FIXED":
        "The user made a decision the app may not override. This is "
        "'don't ask again' -- the app cannot prompt for it again.",
    "POLICY_FIXED":
        "A device policy controller (MDM) fixed this. The user cannot change "
        "it, and your test device may not match the client's fleet.",
    "AUTO_REVOKED":
        "The permission has been through the unused-app auto-revoke path.",
    "REVOKE_WHEN_REQUESTED":
        "Marked for revocation on the next request.",
    "ONE_TIME":
        "Granted for this session only. It will expire when the app leaves "
        "the foreground.",
}


# ---------------------------------------------------------------------------
#  Model
# ---------------------------------------------------------------------------

class UserState(object):
    """Per-Android-user grant state."""

    __slots__ = ("user_id", "gids", "runtime", "installed", "raw_header")

    def __init__(self, user_id):
        self.user_id = user_id
        self.gids = []
        self.runtime = {}        # perm -> {"granted": bool, "flags": [str]}
        self.installed = None
        self.raw_header = ""


class PackageState(object):

    def __init__(self, name):
        self.name = name
        self.uid = None
        self.min_sdk = None
        self.target_sdk = None
        self.version_name = None
        self.code_path = None
        self.installer = None
        self.signatures = None
        self.flags = []
        self.declared = {}       # perm -> level string
        self.requested = []      # ordered, may contain duplicates in dumpsys
        self.install = {}        # perm -> bool
        self.users = []          # list[UserState]
        self.section = ""        # which dumpsys section this block came from

    # -- derived sets -------------------------------------------------------

    def requested_set(self):
        return set(self.requested)

    def granted_install(self):
        return set(p for p, g in self.install.items() if g)

    def denied_install(self):
        return set(p for p, g in self.install.items() if not g)

    def granted_runtime(self):
        out = set()
        for u in self.users:
            for p, st in u.runtime.items():
                if st["granted"]:
                    out.add(p)
        return out

    def denied_runtime(self):
        out = set()
        for u in self.users:
            for p, st in u.runtime.items():
                if not st["granted"]:
                    out.add(p)
        return out

    def all_listed(self):
        """Every permission that appears in ANY grant block, granted or not."""
        out = set(self.install.keys())
        for u in self.users:
            out |= set(u.runtime.keys())
        return out

    def unaccounted(self):
        """Requested, and in NEITHER grant block. The whole point of the tool."""
        return self.requested_set() - self.all_listed()

    def granted_not_requested(self):
        """
        Granted but never requested in the manifest. Usually <split-permission>
        in platform.xml, NOT an anomaly. See README.md section 3.5.
        """
        return (self.granted_install() | self.granted_runtime()) - self.requested_set()

    def held(self):
        return self.granted_install() | self.granted_runtime()


# ---------------------------------------------------------------------------
#  Parser
#
#  dumpsys output is not a stable machine format. It is indented text that has
#  changed shape between releases. This parser is deliberately tolerant: it
#  anchors on the block headers, tracks indentation only enough to know when a
#  block has ended, and never assumes a fixed column. If a block is missing it
#  is reported as missing rather than silently treated as empty -- an empty set
#  and an unparsed set are different findings.
# ---------------------------------------------------------------------------

RE_PKG_HEADER   = re.compile(r'^\s*Package \[([^\]]+)\]')
RE_SECTION      = re.compile(r'^([A-Z][A-Za-z ]+):\s*$')
RE_USERID       = re.compile(r'^\s*userId=(\d+)')
RE_VERSIONS     = re.compile(r'minSdk=(\d+)\s+targetSdk=(\d+)')
RE_VERSION_NAME = re.compile(r'^\s*versionName=(\S+)')
RE_CODEPATH     = re.compile(r'^\s*codePath=(\S+)')
RE_INSTALLER    = re.compile(r'^\s*installerPackageName=(\S+)')
RE_SIGNATURES   = re.compile(r'^\s*signatures=(\S.*)$')
RE_FLAGS        = re.compile(r'^\s*(?:pkg)?[Ff]lags=\[([^\]]*)\]')
RE_USER_BLOCK   = re.compile(r'^(\s*)User (\d+):(.*)$')
RE_GIDS         = re.compile(r'^\s*gids=\[([^\]]*)\]')

RE_DECLARED_HDR = re.compile(r'^(\s*)declared permissions:\s*$')
RE_REQUEST_HDR  = re.compile(r'^(\s*)requested permissions:\s*$')
RE_INSTALL_HDR  = re.compile(r'^(\s*)install permissions:\s*$')
RE_RUNTIME_HDR  = re.compile(r'^(\s*)runtime permissions:\s*$')

RE_DECLARED_ROW = re.compile(r'^\s*(\S+):\s*prot=(\S+?),?\s*(\w+)?\s*$')
RE_GRANT_ROW    = re.compile(r'^\s*(\S+):\s*granted=(true|false)(?:,\s*flags=\[\s*([^\]]*)\])?')
RE_PLAIN_PERM   = re.compile(r'^\s*([A-Za-z][A-Za-z0-9_.]*\.[A-Za-z0-9_.]+)\s*$')


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def parse_dumpsys(text):
    """Return a list of PackageState, in the order the blocks appeared."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    packages = []
    cur = None
    cur_user = None
    section = ""

    # Which sub-block we are inside, and at what indentation its rows sit.
    mode = None          # None | 'declared' | 'requested' | 'install' | 'runtime'
    mode_indent = -1

    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line.strip():
            # A blank line ends any row block but not the package.
            mode = None
            continue

        m = RE_SECTION.match(line)
        if m:
            section = m.group(1).strip()
            mode = None
            continue

        m = RE_PKG_HEADER.match(line)
        if m:
            cur = PackageState(m.group(1))
            cur.section = section
            packages.append(cur)
            cur_user = None
            mode = None
            continue

        if cur is None:
            continue

        # --- block headers -------------------------------------------------
        for rx, name in ((RE_DECLARED_HDR, "declared"),
                         (RE_REQUEST_HDR, "requested"),
                         (RE_INSTALL_HDR, "install"),
                         (RE_RUNTIME_HDR, "runtime")):
            m = rx.match(line)
            if m:
                mode = name
                mode_indent = len(m.group(1))
                break
        else:
            # --- not a header: either a row, or package metadata -----------
            m = RE_USER_BLOCK.match(line)
            if m:
                cur_user = UserState(int(m.group(2)))
                cur_user.raw_header = m.group(3).strip()
                if "installed=true" in m.group(3):
                    cur_user.installed = True
                elif "installed=false" in m.group(3):
                    cur_user.installed = False
                # dumpsys prints a second, near-empty "User 0:" block in some
                # builds. Merge rather than duplicate.
                existing = [u for u in cur.users if u.user_id == cur_user.user_id]
                if existing:
                    cur_user = existing[0]
                else:
                    cur.users.append(cur_user)
                mode = None
                continue

            m = RE_GIDS.match(line)
            if m:
                gids = [g.strip() for g in m.group(1).split(",") if g.strip()]
                if cur_user is not None:
                    cur_user.gids = gids
                continue

            if mode is not None and _indent(line) > mode_indent:
                _parse_row(cur, cur_user, mode, line)
                continue

            mode = None
            _parse_meta(cur, line)
            continue

        # A header matched; nothing else to do for this line.
        continue

    return packages


def _parse_meta(pkg, line):
    m = RE_USERID.match(line)
    if m and pkg.uid is None:
        pkg.uid = int(m.group(1))
        return
    m = RE_VERSIONS.search(line)
    if m:
        pkg.min_sdk, pkg.target_sdk = m.group(1), m.group(2)
        return
    m = RE_VERSION_NAME.match(line)
    if m:
        pkg.version_name = m.group(1)
        return
    m = RE_CODEPATH.match(line)
    if m:
        pkg.code_path = m.group(1)
        return
    m = RE_INSTALLER.match(line)
    if m:
        pkg.installer = m.group(1)
        return
    m = RE_SIGNATURES.match(line)
    if m and pkg.signatures is None:
        pkg.signatures = m.group(1).strip()
        return
    m = RE_FLAGS.match(line)
    if m and not pkg.flags:
        pkg.flags = [f for f in m.group(1).split() if f]
        return


def _parse_row(pkg, user, mode, line):
    if mode == "declared":
        m = RE_DECLARED_ROW.match(line)
        if m:
            pkg.declared[m.group(1)] = m.group(2)
        return

    if mode == "requested":
        m = RE_PLAIN_PERM.match(line)
        if m:
            pkg.requested.append(m.group(1))
            return
        # Some builds annotate requested rows. Take the leading token.
        tok = line.strip().split(":")[0].split()[0]
        if "." in tok:
            pkg.requested.append(tok)
        return

    m = RE_GRANT_ROW.match(line)
    if not m:
        return
    perm = m.group(1)
    granted = (m.group(2) == "true")
    flags = [f for f in (m.group(3) or "").replace("|", " ").split() if f]

    if mode == "install":
        pkg.install[perm] = granted
    elif mode == "runtime" and user is not None:
        user.runtime[perm] = {"granted": granted, "flags": flags}


# ---------------------------------------------------------------------------
#  Rendering
# ---------------------------------------------------------------------------

def _wrap(text, width, indent=""):
    words = str(text).split()
    out, cur = [], indent
    for w in words:
        if len(cur) + len(w) + 1 > width and cur.strip():
            out.append(cur.rstrip())
            cur = indent + w + " "
        else:
            cur += w + " "
    if cur.strip():
        out.append(cur.rstrip())
    return out or [indent]


def render_text(pkg, width=100, unaccounted_only=False):
    out = []
    bar = "=" * width
    rule = "-" * width

    out.append(bar)
    out.append("  GRANT STATE -- %s" % pkg.name)
    out.append(bar)
    out.append("  uid           : %s" % (pkg.uid if pkg.uid is not None else "?"))
    out.append("  version       : %s (minSdk=%s targetSdk=%s)"
               % (pkg.version_name or "?", pkg.min_sdk or "?", pkg.target_sdk or "?"))
    out.append("  installer     : %s" % (pkg.installer or "?"))
    out.append("  dumpsys block : %s" % (pkg.section or "?"))
    if pkg.flags:
        out.append("  flags         : %s" % " ".join(pkg.flags))
    out.append("")

    req = pkg.requested_set()
    gi, di = pkg.granted_install(), pkg.denied_install()
    gr, dr = pkg.granted_runtime(), pkg.denied_runtime()
    unacc = pkg.unaccounted()
    extra = pkg.granted_not_requested()

    out.append(rule)
    out.append("  THE FOUR SETS")
    out.append(rule)
    out.append("  %-46s %5d" % ("requested (manifest INTENT, not held)", len(req)))
    out.append("  %-46s %5d  (%d granted, %d refused)"
               % ("install permissions", len(pkg.install), len(gi), len(di)))
    nrt = sum(len(u.runtime) for u in pkg.users)
    out.append("  %-46s %5d  (%d granted, %d denied)"
               % ("runtime permissions", nrt, len(gr), len(dr)))
    out.append("  %-46s %5d" % ("UNACCOUNTED -- requested, in NEITHER block", len(unacc)))
    out.append("")
    out.append("  %-46s %5d" % ("TOTAL HELD (granted install + runtime)", len(pkg.held())))
    out.append(rule)
    out.append("")

    if unacc:
        out.append("  UNACCOUNTED -- asked for, never received. NOT a finding.")
        for line in _wrap(
                "These appear only in the 'requested permissions:' block. They were asked "
                "for and the platform did not grant them -- usually because the declaring "
                "app is not installed, or because they are signature-level and belong to "
                "somebody else. Do NOT report any of these as held.", width - 4, "    "):
            out.append(line)
        out.append("")
        for p in sorted(unacc):
            out.append("    %s" % p)
        out.append("")
        out.append(rule)
        out.append("")

    if unaccounted_only:
        return "\n".join(out)

    if pkg.declared:
        out.append("  PERMISSIONS THIS PACKAGE DECLARES (it owns these names, if it")
        out.append("  installed first -- confirm with `dumpsys package permission <name>`)")
        out.append(rule)
        w = max(4, max(len(v) for v in pkg.declared.values()))
        out.append("  %-*s %s" % (w, "PROT", "PERMISSION"))
        for p in sorted(pkg.declared):
            lvl = pkg.declared[p]
            mark = "" if _is_strong(lvl) else "   <-- NOT A BOUNDARY"
            out.append("  %-*s %s%s" % (w, lvl, p, mark))
        out.append("")
        weak = [p for p in pkg.declared if not _is_strong(pkg.declared[p])]
        if weak:
            for line in _wrap(
                    "A permission whose level is normal or dangerous is obtainable by any "
                    "app that asks -- silently for normal, after one dialog for dangerous. "
                    "Anything it guards is reachable. Resolve the OWNER too: if "
                    "sourcePackage is not this package, you have found squatting. See "
                    "README.md section 3.6.", width - 4, "    "):
                out.append(line)
            out.append("")
        out.append(rule)
        out.append("")

    if gi or di:
        out.append("  INSTALL PERMISSIONS -- decided at install, not prompted, not revocable")
        out.append(rule)
        for p in sorted(pkg.install):
            state = "GRANTED" if pkg.install[p] else "REFUSED"
            note = ""
            if p in APPOP_PERMISSIONS:
                note = "  [appop: also run `cmd appops get <pkg> %s`]" % APPOP_PERMISSIONS[p]
            out.append("  %-8s %s%s" % (state, p, note))
        out.append("")
        out.append(rule)
        out.append("")

    for u in pkg.users:
        if not u.runtime and not u.gids:
            continue
        out.append("  USER %d" % u.user_id)
        out.append(rule)
        if u.gids:
            out.append("  permission-derived GIDs : [%s]" % ", ".join(u.gids))
            for line in _wrap(
                    "This is the list computed from the granted install permissions via "
                    "platform.xml. It is NOT the process's live group list -- Zygote adds "
                    "AID_EVERYBODY (9997) and the per-app cache and shared GIDs. For what "
                    "the process can actually do, read "
                    "`grep Groups /proc/<pid>/status`. 3003 is INTERNET.",
                    width - 4, "    "):
                out.append(line)
            out.append("")
        if u.runtime:
            out.append("  %-8s %-52s %s" % ("STATE", "PERMISSION", "FLAGS THAT MATTER"))
            for p in sorted(u.runtime):
                st = u.runtime[p]
                state = "GRANTED" if st["granted"] else "DENIED"
                notable = [f for f in st["flags"] if f in FLAG_MEANING]
                out.append("  %-8s %-52s %s"
                           % (state, p[:52], ",".join(notable) if notable else ""))
            shown = set()
            for p in sorted(u.runtime):
                for f in u.runtime[p]["flags"]:
                    if f in FLAG_MEANING and f not in shown:
                        shown.add(f)
            if shown:
                out.append("")
                for f in sorted(shown):
                    for line in _wrap("%s -- %s" % (f, FLAG_MEANING[f]), width - 4, "    "):
                        out.append(line)
        out.append("")
        out.append(rule)
        out.append("")

    hs = sorted(p for p in pkg.held() if p in HIGH_SIGNAL)
    if hs:
        out.append("  HIGH-SIGNAL PERMISSIONS ACTUALLY HELD")
        out.append(rule)
        for p in hs:
            out.append("  %s" % p)
            for line in _wrap(HIGH_SIGNAL[p], width - 6, "      "):
                out.append(line)
            out.append("")
        out.append(rule)
        out.append("")

    ap = sorted(p for p in pkg.all_listed() if p in APPOP_PERMISSIONS)
    if ap:
        out.append("  APPOP-FLAGGED -- dumpsys package is NOT sufficient for these")
        out.append(rule)
        for line in _wrap(
                "The effective answer for an appop-flagged permission is a function of the "
                "permission grant AND the app-op mode, which is a separate state machine. "
                "Measured on the test device, REQUEST_INSTALL_PACKAGES was granted=false in "
                "dumpsys and 'allow' in appops at the same instant. Run both.",
                width - 4, "    "):
            out.append(line)
        out.append("")
        for p in ap:
            out.append("    adb shell cmd appops get %s %s" % (pkg.name, APPOP_PERMISSIONS[p]))
        out.append("")
        out.append(rule)
        out.append("")

    if extra:
        out.append("  GRANTED BUT NEVER REQUESTED -- almost certainly <split-permission>")
        out.append(rule)
        for line in _wrap(
                "platform.xml maps an old permission onto newer, narrower ones for apps "
                "targeting below a given SDK. An app targeting API 28 that requests "
                "ACCESS_FINE_LOCATION is ALSO given ACCESS_BACKGROUND_LOCATION. Check "
                "`adb shell cat /system/etc/permissions/platform.xml` for a <new-permission> "
                "element naming these before calling it an anomaly.", width - 4, "    "):
            out.append(line)
        out.append("")
        for p in sorted(extra):
            out.append("    %s" % p)
        out.append("")
        out.append(rule)
        out.append("")

    out.append(rule)
    out.append("  Nothing above proves the app USES any of it. A granted permission with no")
    out.append("  code path behind it is over-privilege, not exposure. Cross-reference against")
    out.append("  the DEX before writing severity. And a permission in the requested list and")
    out.append("  nowhere else was asked for and refused -- it is not held.")
    out.append(rule)
    return "\n".join(out)


def _is_strong(level):
    """Only a signature-anchored base level ties a grant to something the attacker
    cannot supply. Flags WIDEN, so their presence never makes a level stronger."""
    low = (level or "").lower()
    base = low.split("|")[0].strip()
    return base in ("signature", "signatureorsystem")


def render_markdown(pkg):
    out = []
    out.append("# Grant state -- `%s`" % pkg.name)
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append("| uid | `%s` |" % (pkg.uid if pkg.uid is not None else "?"))
    out.append("| version | %s (minSdk %s, targetSdk %s) |"
               % (pkg.version_name or "?", pkg.min_sdk or "?", pkg.target_sdk or "?"))
    out.append("| installer | `%s` |" % (pkg.installer or "?"))
    out.append("")
    out.append("## The four sets")
    out.append("")
    out.append("| Set | Count | What it means |")
    out.append("|---|---|---|")
    out.append("| Requested | %d | Manifest intent. **Not held.** |" % len(pkg.requested_set()))
    out.append("| Install permissions | %d | %d granted, %d refused |"
               % (len(pkg.install), len(pkg.granted_install()), len(pkg.denied_install())))
    nrt = sum(len(u.runtime) for u in pkg.users)
    out.append("| Runtime permissions | %d | %d granted, %d denied |"
               % (nrt, len(pkg.granted_runtime()), len(pkg.denied_runtime())))
    out.append("| **Unaccounted** | %d | Requested and in **neither** grant block |"
               % len(pkg.unaccounted()))
    out.append("| **Total held** | %d | |" % len(pkg.held()))
    out.append("")

    if pkg.declared:
        out.append("## Permissions this package declares")
        out.append("")
        out.append("| Permission | protectionLevel | Enforceable? |")
        out.append("|---|---|---|")
        for p in sorted(pkg.declared):
            lvl = pkg.declared[p]
            v = "yes" if _is_strong(lvl) else "**no -- obtainable by any app**"
            # A '|' inside a Markdown table cell splits the column. Escape it,
            # and the level is exactly where '|' appears: signature|privileged.
            out.append("| `%s` | `%s` | %s |" % (p, lvl.replace("|", "\\|"), v))
        out.append("")

    if pkg.unaccounted():
        out.append("## Unaccounted -- requested and never received")
        out.append("")
        out.append("These are **not findings**. They are listed so they are not reported as held.")
        out.append("")
        for p in sorted(pkg.unaccounted()):
            out.append("- `%s`" % p)
        out.append("")

    for u in pkg.users:
        if not u.runtime and not u.gids:
            continue
        out.append("## User %d" % u.user_id)
        out.append("")
        if u.gids:
            out.append("Permission-derived GIDs: `[%s]`" % ", ".join(u.gids))
            out.append("")
        if u.runtime:
            out.append("| Permission | State | Notable flags |")
            out.append("|---|---|---|")
            for p in sorted(u.runtime):
                st = u.runtime[p]
                notable = [f for f in st["flags"] if f in FLAG_MEANING]
                out.append("| `%s` | %s | %s |"
                           % (p, "granted" if st["granted"] else "denied",
                              ", ".join("`%s`" % f for f in notable)))
            out.append("")

    ap = sorted(p for p in pkg.all_listed() if p in APPOP_PERMISSIONS)
    if ap:
        out.append("## App-op flagged -- `dumpsys package` is not sufficient")
        out.append("")
        for p in ap:
            out.append("- `adb shell cmd appops get %s %s`" % (pkg.name, APPOP_PERMISSIONS[p]))
        out.append("")

    out.append("---")
    out.append("")
    out.append("A granted permission with no code path behind it is over-privilege, not "
               "exposure. A permission in the requested list and nowhere else was asked for "
               "and refused.")
    return "\n".join(out)


def render_json(pkg):
    return json.dumps({
        "package": pkg.name,
        "uid": pkg.uid,
        "minSdk": pkg.min_sdk,
        "targetSdk": pkg.target_sdk,
        "versionName": pkg.version_name,
        "installer": pkg.installer,
        "flags": pkg.flags,
        "declared": pkg.declared,
        "requested": sorted(pkg.requested_set()),
        "installPermissions": pkg.install,
        "users": [{
            "userId": u.user_id,
            "gids": u.gids,
            "runtime": u.runtime,
        } for u in pkg.users],
        "derived": {
            "held": sorted(pkg.held()),
            "unaccounted": sorted(pkg.unaccounted()),
            "grantedNotRequested": sorted(pkg.granted_not_requested()),
            "weakDeclared": sorted(p for p in pkg.declared
                                   if not _is_strong(pkg.declared[p])),
            "appopFlagged": sorted(p for p in pkg.all_listed() if p in APPOP_PERMISSIONS),
        },
    }, indent=2, sort_keys=True)


# ---------------------------------------------------------------------------
#  main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Separate what an app REQUESTED from what it actually HOLDS, from a "
                    "`dumpsys package` capture. Prints the gap between the two, which is "
                    "the set most often reported wrongly.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Chapter 23 owns grant state. 32-Manifest/scripts/manifest-audit.py owns the "
               "declaration audit; 21-App-Sandbox/scripts/manifest-exposure.py owns the "
               "sandbox view. Neither has a device. Run all three.")
    ap.add_argument("capture", nargs="?",
                    help="A `dumpsys package <pkg>` capture. '-' for stdin. Omit with --pkg.")
    ap.add_argument("--pkg", help="Run `adb shell dumpsys package <pkg>` directly.")
    ap.add_argument("--serial", help="adb device serial, for --pkg.")
    ap.add_argument("--select", help="If the capture holds several package blocks, "
                                     "report only this one.")
    ap.add_argument("--unaccounted-only", action="store_true",
                    help="Only the requested-but-never-granted set.")
    ap.add_argument("--markdown", action="store_true", help="Emit Markdown.")
    ap.add_argument("--json", action="store_true", help="Emit JSON.")
    ap.add_argument("--width", type=int, default=100, help="Text output width.")
    args = ap.parse_args(argv)

    if args.pkg:
        cmd = ["adb"]
        if args.serial:
            cmd += ["-s", args.serial]
        cmd += ["shell", "dumpsys", "package", args.pkg]
        try:
            data = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except (OSError, subprocess.CalledProcessError) as exc:
            sys.stderr.write("[-] adb failed: %s\n" % exc)
            sys.stderr.write("    Capture manually instead:\n")
            sys.stderr.write("        adb shell dumpsys package %s > dump.txt\n" % args.pkg)
            sys.stderr.write("        python3 grant-state.py dump.txt\n")
            return 3
        text = data.decode("utf-8", "replace")
    elif args.capture == "-":
        text = sys.stdin.read()
    elif args.capture:
        if not os.path.isfile(args.capture):
            sys.stderr.write("[-] no such file: %s\n" % args.capture)
            return 2
        with open(args.capture, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        ap.error("give a capture file, '-' for stdin, or --pkg")
        return 2

    packages = parse_dumpsys(text)
    if not packages:
        sys.stderr.write("[-] no 'Package [<name>]' block found in the input.\n")
        sys.stderr.write("    This reads `adb shell dumpsys package <pkg>` output. If you\n"
                         "    passed `dumpsys package permission <name>` or a manifest, use\n"
                         "    ./permission-audit.py instead.\n")
        return 2

    # dumpsys prints the same package under several headings (Packages,
    # Hidden system packages). Prefer the block with the most grant data.
    by_name = {}
    for p in packages:
        best = by_name.get(p.name)
        if best is None or len(p.all_listed()) > len(best.all_listed()):
            by_name[p.name] = p

    chosen = list(by_name.values())
    if args.select:
        chosen = [p for p in chosen if p.name == args.select]
        if not chosen:
            sys.stderr.write("[-] --select %s not present. Blocks found: %s\n"
                             % (args.select, ", ".join(sorted(by_name))))
            return 2

    chosen.sort(key=lambda p: p.name)

    for n, pkg in enumerate(chosen):
        if args.json:
            print(render_json(pkg))
        elif args.markdown:
            if n:
                print("")
                print("---")
                print("")
            print(render_markdown(pkg))
        else:
            if n:
                print("")
            print(render_text(pkg, width=args.width,
                              unaccounted_only=args.unaccounted_only))
    return 0


if __name__ == "__main__":
    sys.exit(main())
