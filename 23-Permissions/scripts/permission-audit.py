#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
permission-audit.py -- which of an app's OWN permissions are actually enforceable?

WHAT IT DOES
    An app that declares a custom permission believes it has created a boundary.
    Usually it has not. This script answers one question per permission:

        Can an attacker obtain this by acting alone?

    It answers it by counting POPULATIONS. A protectionLevel is a base level
    ORed with zero or more flags, and -- this is the fact the tool exists to
    make unmissable -- every flag ADDS an independent route to obtaining the
    permission. `signature|privileged` is grantable to same-key apps OR to
    allow-listed privileged apps. It is WEAKER than plain `signature`, not
    stronger. A tool that string-matches "signature" gets that backwards.

    For each permission the app DECLARES it prints:
        - the resolved protectionLevel, preferring the DEVICE over the manifest
        - one row per population that can obtain it, and who is in that
          population
        - a verdict: ENFORCEABLE, or NOT-A-BOUNDARY with the reason
        - which of the app's own components rely on it

    For each permission the app USES to guard a component but does NOT declare
    it prints the squatting analysis:
        - UNOWNED      nothing on the device declares it. The component is
                       currently unreachable and the name is free for an
                       attacker to claim at `normal`.
        - SQUATTED     a DIFFERENT package owns the definition. Whatever level
                       that package chose is the level being enforced on this
                       app's component.
        - EXTERNAL     another package owns it and the level is signature-
                       anchored. Probably a legitimate suite or platform
                       permission; confirm the owner is who you expect.

    And it reports <permission-tree>, because a tree means the app's permission
    surface is not fully described by the manifest at all.

WHAT THIS IS NOT -- and this matters, because three chapters ship manifest tools
    This is NOT a third manifest scanner. It deliberately does not:

        - inventory exported components  (21-App-Sandbox/scripts/manifest-exposure.py)
        - apply the targetSdk version matrix (32-Manifest/scripts/manifest-audit.py)
        - rate severity, scan for secrets, analyse deep links, check AXML
          parser differentials, or audit anything that is not a permission

    It reads exactly two kinds of element -- <permission> / <permission-tree>,
    and the android:permission / readPermission / writePermission attributes
    that REFER to a permission -- and it prefers a device answer to an XML one
    wherever it can get both.

    Run all three. They answer different questions:

        python3 ../../32-Manifest/scripts/manifest-audit.py    out/AndroidManifest.xml
        python3 ../../21-App-Sandbox/scripts/manifest-exposure.py out/AndroidManifest.xml
        python3 permission-audit.py --manifest out/AndroidManifest.xml --pm-list perms.txt

    Its sibling ./grant-state.py answers the other half: not "is this permission
    enforceable" but "what does this app actually hold".

WHAT THIS WILL *NOT* TELL YOU
    - Whether anything behind the permission is worth reaching. A NOT-A-BOUNDARY
      verdict on a permission guarding an empty service is not a finding. Read
      the component in JADX before writing severity.
    - Whether a component is exported. It reports the permission posture of
      what it finds; export resolution depends on targetSdk and belongs to
      chapter 32. Where it matters the output says so.
    - Whether the app ALSO checks the caller in code. A signature check with
      PackageManager.checkSignatures cannot be squatted and is the correct
      belt to the manifest's braces -- but it is in the DEX, not the manifest.
      grep for it: `grep -rn "checkSignatures\|Binder.getCallingUid" jadx-out/`
    - The real protectionLevel of a platform permission, unless you feed it a
      `pm list permissions -f -g` capture. Without one it says UNRESOLVED
      rather than guessing. There is a tiny table of stable platform levels
      below and it is deliberately tiny.
    - Who installed first. Install ORDER is what decides ownership, and a
      manifest cannot show it. `dumpsys package permission <name>` shows the
      current owner, which is the outcome of that race.
    - Anything registered at runtime. PackageManager.addPermission is invisible
      here by construction -- that is exactly why <permission-tree> is reported.

HOW TO RUN
    # host -- decode first
    apktool d -f target.apk -o out/

    # host -- manifest only. Levels the manifest states are used; others are UNRESOLVED.
    python3 permission-audit.py --manifest out/AndroidManifest.xml

    # host -- with the device's own answer, which supersedes the manifest
    adb shell pm list permissions -f -g > perms.txt
    python3 permission-audit.py --manifest out/AndroidManifest.xml --pm-list perms.txt

    # host -- add the package record, for the declared-permission levels the platform stores
    adb shell dumpsys package com.target.app > dump.txt
    python3 permission-audit.py --manifest out/AndroidManifest.xml \
            --pm-list perms.txt --dumpsys dump.txt

    # host -- device-only mode: no manifest, just audit every permission a package declares
    python3 permission-audit.py --dumpsys dump.txt --pm-list perms.txt

    # host -- straight into a report
    python3 permission-audit.py --manifest out/AndroidManifest.xml --pm-list perms.txt --markdown

REQUIREMENTS
    Python 3.6+. Standard library only (argparse, json, re, sys, textwrap,
    xml.etree). No pip install.

    Output is pure ASCII on purpose -- a Windows console codepage cannot encode
    box-drawing characters and a UnicodeEncodeError mid-report is worse than a
    plain table.

    Writes nothing, imports nothing local, leaves no __pycache__. Run as a script.

EXIT CODES
    0  ran to completion
    1  at least one NOT-A-BOUNDARY or SQUATTED verdict (use with --fail-on-weak)
    2  no usable input

AUTHORISED TESTING ONLY.
"""

import argparse
import json
import re
import sys
import textwrap
import xml.etree.ElementTree as ET

NS = "{http://schemas.android.com/apk/res/android}"

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

# ---------------------------------------------------------------------------
#  The population model.
#
#  A protectionLevel is base|flag|flag... Each element names an INDEPENDENT
#  population that can obtain the permission. The verdict is a function of the
#  UNION, so one weak population is enough to sink the whole thing.
#
#  "attacker_reachable" means: can an ordinary third-party app, installed by an
#  attacker on a stock device, end up in this population by acting alone?
# ---------------------------------------------------------------------------

BASE_POPULATIONS = {
    "normal": (
        True,
        "Any app that requests it. Granted silently at install, no prompt, no check."),
    "dangerous": (
        True,
        "Any app, after ONE user dialog the attacker chooses the timing and framing of."),
    "signature": (
        False,
        "Only apps signed with the SAME certificate as the declaring app. The attacker "
        "would need the victim's private key."),
    "signatureorsystem": (
        False,
        "Same certificate, OR an app on the system image. Deprecated; the modern "
        "spelling is signature|privileged."),
    "internal": (
        False,
        "Nobody, on the base level alone. Only the flags grant it."),
}

FLAG_POPULATIONS = {
    "privileged": (
        False,
        "Allow-listed apps in /system/priv-app. Not an attacker on a stock device -- but "
        "the population is 'whatever the OEM shipped', and every member is a candidate "
        "confused deputy. See README.md section 3.9."),
    "system": (
        False,
        "Legacy alias for privileged."),
    "preinstalled": (
        False,
        "ANY app on the system image, privileged or not. A wider population than "
        "privileged, and on a bloated vendor build that is a lot of apps."),
    "appop": (
        True,
        "The effective state is governed by an App Op, a separate mutable state machine. "
        "dumpsys package alone gives the wrong answer -- run `cmd appops get`. Treated as "
        "attacker-reachable because the op can be permissive independently of the grant."),
    "development": (
        False,
        "Grantable from the shell with `pm grant`. YOU can grant it during testing; an "
        "attacker cannot. The single largest false-positive source in this area -- if you "
        "granted it to make a test work, that test proves nothing."),
    "instant": (
        True,
        "Grantable to Instant Apps, which run without a full install."),
    "pre23": (
        True,
        "Granted at INSTALL to any app whose targetSdkVersion is below 23. An attacker "
        "sets their own targetSdk."),
    "runtime": (
        False,
        "Only ever granted at runtime, never at install."),
    "installer": (False, "The app holding the installer role. Population of about one."),
    "verifier": (False, "The package verifier. Population of about one."),
    "setup": (False, "The setup wizard. Population of one."),
    "oem": (False, "Allow-listed OEM apps on the OEM partition."),
    "vendorprivileged": (False, "Allow-listed privileged apps on the vendor partition."),
    "module": (False, "An APEX / mainline module."),
    "role": (
        False,
        "Whichever app currently holds a platform Role -- default browser, dialer, SMS "
        "app. The population is USER-CHANGEABLE at runtime, so it is not fixed the way "
        "signature is."),
    "knownsigner": (
        False,
        "Any app signed by a certificate listed in the declaring app's android:knownCerts "
        "resource. 'Signature-level' no longer implies 'same key' -- READ THAT LIST."),
    "companion": (False, "A companion-device manager app."),
    "recents": (False, "The recents / launcher component."),
    "retaildemo": (False, "The retail demo app."),
    "incidentreportapprover": (False, "The incident-report approver."),
    "apppredictor": (False, "The app predictor."),
    "textclassifier": (False, "The system text classifier."),
    "systemtextclassifier": (False, "The system text classifier."),
    "wellbeing": (False, "The digital wellbeing app."),
    "documenter": (False, "The documenter."),
    "configurator": (False, "The device configurator."),
}

# Platform permissions whose level is stable and widely known. Deliberately
# SHORT. Anything not here is resolved from --pm-list or reported UNRESOLVED.
# A tool that guesses a level is a tool that produces a confidently wrong
# finding, and chapter 32's manifest-audit.py already carries the larger table.
STABLE_PLATFORM_LEVELS = {
    "android.permission.INTERNET": "normal",
    "android.permission.ACCESS_NETWORK_STATE": "normal",
    "android.permission.QUERY_ALL_PACKAGES": "normal",
    "android.permission.CAMERA": "dangerous",
    "android.permission.RECORD_AUDIO": "dangerous",
    "android.permission.READ_CONTACTS": "dangerous",
    "android.permission.ACCESS_FINE_LOCATION": "dangerous",
    "android.permission.SYSTEM_ALERT_WINDOW": "signature|preinstalled|appop",
    "android.permission.REQUEST_INSTALL_PACKAGES": "signature|appop",
}

VERDICTS = ["SQUATTED", "NOT-A-BOUNDARY", "UNOWNED", "UNRESOLVED", "EXTERNAL", "ENFORCEABLE"]
VRANK = {v: i for i, v in enumerate(VERDICTS)}


# ---------------------------------------------------------------------------
#  Level parsing
# ---------------------------------------------------------------------------

def split_level(level):
    """'signature|privileged' -> ('signature', ['privileged'])."""
    parts = [p.strip().lower() for p in (level or "").split("|") if p.strip()]
    if not parts:
        return None, []
    return parts[0], parts[1:]


def populations(level):
    """
    Return (rows, reachable, unknown_tokens).

    rows            list of (token, kind, reachable, description)
    reachable       True if ANY population is attacker-reachable
    unknown_tokens  tokens this script does not recognise -- reported, never guessed
    """
    base, flags = split_level(level)
    rows, unknown = [], []
    reachable = False

    if base is None:
        return rows, False, unknown

    if base in BASE_POPULATIONS:
        r, desc = BASE_POPULATIONS[base]
        rows.append((base, "base", r, desc))
        reachable = reachable or r
    else:
        unknown.append(base)
        rows.append((base, "base", False,
                     "UNRECOGNISED base level -- resolve it against PermissionInfo.java "
                     "on the branch you are testing."))

    for f in flags:
        if f in FLAG_POPULATIONS:
            r, desc = FLAG_POPULATIONS[f]
            rows.append((f, "flag", r, desc))
            reachable = reachable or r
        else:
            unknown.append(f)
            rows.append((f, "flag", False,
                         "UNRECOGNISED flag -- the flag set grows at almost every release. "
                         "Resolve it against PermissionInfo.java, and do NOT assume it "
                         "narrows anything: flags only ever ADD a population."))
    return rows, reachable, unknown


# ---------------------------------------------------------------------------
#  Inputs
# ---------------------------------------------------------------------------

RE_PM_PERM  = re.compile(r'^\s*(?:\+\s*)?permission:(\S+)\s*$')
RE_PM_PKG   = re.compile(r'^\s*package:(\S+)\s*$')
RE_PM_PROT  = re.compile(r'^\s*protectionLevel:(\S+)\s*$')
RE_PM_LABEL = re.compile(r'^\s*label:(.*)$')


def parse_pm_list(text):
    """
    Parse `pm list permissions -f -g` into {name: {'package':.., 'level':.., 'label':..}}.

    The record shape is a header line followed by indented key:value lines, and
    a permission with no -f detail simply has no following lines. Missing keys
    are recorded as None rather than defaulted, because 'the device did not say'
    and 'the device said normal' are different answers.
    """
    out = {}
    cur = None
    for line in text.replace("\r\n", "\n").split("\n"):
        m = RE_PM_PERM.match(line)
        if m:
            cur = {"package": None, "level": None, "label": None}
            out[m.group(1)] = cur
            continue
        if cur is None:
            continue
        m = RE_PM_PKG.match(line)
        if m:
            cur["package"] = m.group(1)
            continue
        m = RE_PM_PROT.match(line)
        if m:
            cur["level"] = m.group(1)
            continue
        m = RE_PM_LABEL.match(line)
        if m:
            cur["label"] = m.group(1).strip()
            continue
        if line.strip().startswith("group:") or not line.strip():
            cur = None
    return out


RE_DS_PKG      = re.compile(r'^\s*Package \[([^\]]+)\]')
RE_DS_DECL_HDR = re.compile(r'^\s*declared permissions:\s*$')
RE_DS_DECL_ROW = re.compile(r'^\s*(\S+):\s*prot=(\S+?),?\s*(\w+)?\s*$')
RE_DS_PERMREC  = re.compile(r'^\s*Permission \[([^\]]+)\]')
RE_DS_SRCPKG   = re.compile(r'^\s*sourcePackage=(\S+)')
RE_DS_PROT     = re.compile(r'^\s*uid=\d+\s+gids=\[[^\]]*\]\s+type=\d+\s+prot=(\S+)')


def parse_dumpsys(text):
    """
    Pull two things out of a `dumpsys package` capture:
        declared[pkg][perm]  = level    (what THIS package declares)
        owners[perm]         = (sourcePackage, level)   (who owns it device-wide)
    `dumpsys package permission <name>` output is also accepted -- it carries
    the Permission[] records this reads for `owners`.
    """
    declared, owners = {}, {}
    cur_pkg, in_decl, cur_perm = None, False, None
    for line in text.replace("\r\n", "\n").split("\n"):
        m = RE_DS_PERMREC.match(line)
        if m:
            cur_perm = m.group(1)
            owners.setdefault(cur_perm, [None, None])
            in_decl = False
            continue
        if cur_perm:
            m = RE_DS_SRCPKG.match(line)
            if m:
                owners[cur_perm][0] = m.group(1)
                continue
            m = RE_DS_PROT.match(line)
            if m:
                owners[cur_perm][1] = m.group(1)
                cur_perm = None
                continue

        m = RE_DS_PKG.match(line)
        if m:
            cur_pkg = m.group(1)
            declared.setdefault(cur_pkg, {})
            in_decl = False
            continue
        if RE_DS_DECL_HDR.match(line):
            in_decl = True
            continue
        if in_decl:
            m = RE_DS_DECL_ROW.match(line)
            if m and cur_pkg:
                declared[cur_pkg][m.group(1)] = m.group(2)
                continue
            if line.strip():
                in_decl = False
    return declared, {k: tuple(v) for k, v in owners.items()}


class Manifest(object):

    def __init__(self, root):
        self.root = root
        self.pkg = root.get("package") or "<unknown-package>"
        self.app = root.find("application")
        self.declared = {}     # name -> level string or None
        self.trees = []
        self.guards = {}       # permission name -> [ "tag Name (gate)" ]
        self.requested = []

        for p in root.iter("permission"):
            n = p.get(NS + "name")
            if n:
                self.declared[n] = p.get(NS + "protectionLevel")
        for t in root.iter("permission-tree"):
            n = t.get(NS + "name")
            if n:
                self.trees.append(n)
        for u in root.iter("uses-permission"):
            n = u.get(NS + "name")
            if n:
                self.requested.append(n)
        for u in root.iter("uses-permission-sdk-23"):
            n = u.get(NS + "name")
            if n:
                self.requested.append(n)

        app_perm = self.app.get(NS + "permission") if self.app is not None else None
        if app_perm:
            self.guards.setdefault(app_perm, []).append("<application> (all components)")
        if self.app is not None:
            for tag in COMPONENT_TAGS:
                for el in self.app.iter(tag):
                    name = el.get(NS + "name") or "<unnamed>"
                    if name.startswith("."):
                        name = self.pkg + name
                    base = el.get(NS + "permission") or app_perm
                    if tag == "provider":
                        gates = [("read", el.get(NS + "readPermission") or base),
                                 ("write", el.get(NS + "writePermission") or base)]
                    else:
                        gates = [("call", base)]
                    for label, perm in gates:
                        if perm:
                            self.guards.setdefault(perm, []).append(
                                "%s %s (%s)" % (tag, name, label))


# ---------------------------------------------------------------------------
#  The audit
# ---------------------------------------------------------------------------

class Row(object):
    __slots__ = ("perm", "verdict", "level", "level_src", "owner", "pops",
                 "unknown", "guards", "why", "step")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


def audit(mf, pm_list, ds_declared, ds_owners, pkg_hint):
    rows = []
    pkg = mf.pkg if mf else (pkg_hint or "<unknown-package>")

    declared = dict(mf.declared) if mf else {}
    if ds_declared:
        src = ds_declared.get(pkg)
        if src is None and len(ds_declared) == 1:
            src = list(ds_declared.values())[0]
        if src:
            for n, lvl in src.items():
                # The platform's stored level supersedes the manifest's text.
                declared[n] = lvl

    guards = dict(mf.guards) if mf else {}

    # -- 1. permissions this app DECLARES ----------------------------------
    for name in sorted(declared):
        level, src = _resolve(name, declared.get(name), pm_list, ds_owners,
                              own_declaration=True)
        owner = _owner(name, pm_list, ds_owners)
        pops, reachable, unknown = populations(level)
        g = guards.get(name, [])

        if owner and owner != pkg:
            verdict = "SQUATTED"
            why = ("This app declares %s, but the DEVICE says the definition is owned by %s. "
                   "Ownership goes to whichever package installed FIRST; the loser's "
                   "declaration is not enforced, and on modern Android the loser's install is "
                   "refused outright with INSTALL_FAILED_DUPLICATE_PERMISSION. Whatever level "
                   "%s chose is the level in force." % (name, owner, owner))
            step = ("Confirm and date it: `adb shell dumpsys package permission %s` for the "
                    "owner, then `adb shell dumpsys package %s | grep -E 'firstInstallTime|"
                    "lastUpdateTime'` for BOTH packages. The install ORDER is the evidence."
                    % (name, owner))
        elif level is None:
            verdict = "UNRESOLVED"
            why = ("No protectionLevel anywhere: the manifest omits it and no device capture "
                   "supplies it. An OMITTED attribute in a manifest means `normal`, which is "
                   "the weakest possible value -- but this script will not assume the capture "
                   "would have agreed.")
            step = ("Resolve it: `adb shell pm list permissions -f -g | grep -A4 %s`, and "
                    "re-run with --pm-list." % name)
        elif reachable:
            verdict = "NOT-A-BOUNDARY"
            weak = [t for t, _k, r, _d in pops if r]
            why = ("At least one population that can obtain this permission is reachable by an "
                   "ordinary attacker app: %s. Every '|' in a protectionLevel is an OR that "
                   "ADDS a population, so one weak element sinks the whole level. Anything "
                   "guarded by this is reachable by an app that adds one <uses-permission> "
                   "line." % ", ".join(weak))
            step = ('Recommend android:protectionLevel="signature" AND an in-code caller check '
                    '(PackageManager.checkSignatures against Binder.getCallingUid()), because '
                    'the manifest permission is checked once at entry and can be squatted. '
                    'Prove the current state from an UNPRIVILEGED app, not from adb shell: '
                    'declare <uses-permission android:name="%s" /> in a probe app, install it, '
                    'and call what this guards.' % name)
        else:
            verdict = "ENFORCEABLE"
            why = ("Every population that can obtain this is anchored to something the attacker "
                   "does not control -- a signing key, the system image, or a platform role. "
                   "This is a control observed, and belongs in that section of the report.")
            step = ("Two follow-ups. Enumerate the population: `adb shell dumpsys package %s | "
                    "grep signatures=` and compare across the vendor's suite -- a key shared "
                    "with twenty apps is a boundary around twenty apps. And if the level "
                    "contains knownSigner, read android:knownCerts, because 'signature-level' "
                    "then means 'one of this list of keys'." % pkg)

        rows.append(Row(perm=name, verdict=verdict, level=level, level_src=src,
                        owner=owner, pops=pops, unknown=unknown, guards=g,
                        why=why, step=step))

    # -- 2. permissions this app USES to guard, but does NOT declare --------
    for name in sorted(guards):
        if name in declared:
            continue
        level, src = _resolve(name, None, pm_list, ds_owners)
        owner = _owner(name, pm_list, ds_owners)
        pops, reachable, unknown = populations(level)
        g = guards[name]

        if owner is None and level is None:
            verdict = "UNOWNED"
            why = ("Nothing on the device declares %s, and this app does not declare it "
                   "either. Two consequences, and the second is the finding. The component is "
                   "currently UNREACHABLE, because a permission nobody defines cannot be "
                   "granted. And the NAME IS FREE: an attacker who declares it at `normal` and "
                   "installs becomes its owner, at which point any app on the device can be "
                   "granted it and this component opens. This is the squatting case that still "
                   "works on Android 13 -- measured, see README.md section 3.6." % name)
            step = ("Two things. Confirm no owner on a device that has the app's full suite "
                    "installed: `adb shell pm list permissions -f -g | grep -A4 %s`. Then "
                    "recommend that EVERY app in the suite declares the permission "
                    'identically at protectionLevel="signature", so no install order leaves '
                    "the name unowned." % name)
        elif owner and owner != pkg:
            if reachable:
                verdict = "SQUATTED"
                why = ("A DIFFERENT package (%s) owns this permission, and the level it chose "
                       "(%s) is obtainable by an ordinary app. This app's component is "
                       "therefore guarded by a rule somebody else wrote. Whether %s is "
                       "malicious or merely a sibling that got there first, the effect on this "
                       "component is the same." % (owner, level, owner))
                step = ("Identify %s and decide whether it is the expected suite member. "
                        "`adb shell dumpsys package %s | grep -E 'signatures=|firstInstallTime'`"
                        " and compare its signing certificate to this app's. Different "
                        "certificate plus a weak level is the finding." % (owner, owner))
            else:
                verdict = "EXTERNAL"
                why = ("Another package (%s) owns this permission at a signature-anchored level "
                       "(%s). That is the normal suite or platform arrangement. It is not a "
                       "finding, but it IS a dependency: if %s is ever absent at install time, "
                       "the name is unowned and squattable." % (owner, level, owner))
                step = ("Confirm %s is signed with the same key as this app: `adb shell dumpsys "
                        "package %s | grep signatures=`. Then note the dependency in the report."
                        % (owner, owner))
        elif level is None:
            verdict = "UNRESOLVED"
            why = ("This app guards a component with %s and does not declare it. No device "
                   "capture was supplied, so the owner and level are unknown from this file "
                   "alone -- and the owner is the whole question." % name)
            step = ("Run `adb shell pm list permissions -f -g > perms.txt` and re-run with "
                    "--pm-list perms.txt. Without it this row cannot be decided.")
        elif reachable:
            verdict = "NOT-A-BOUNDARY"
            why = ("The level in force (%s) is obtainable by any app that asks." % level)
            step = ("Prove it from a probe app, then recommend signature level plus an in-code "
                    "caller check.")
        else:
            verdict = "ENFORCEABLE"
            why = "The level in force (%s) is anchored to something the attacker cannot supply." % level
            step = "None. Record as a control observed."

        rows.append(Row(perm=name, verdict=verdict, level=level, level_src=src,
                        owner=owner, pops=pops, unknown=unknown, guards=g,
                        why=why, step=step))

    return rows


def _resolve(name, manifest_level, pm_list, ds_owners, own_declaration=False):
    """
    Device answer beats manifest answer. Returns (level, source).

    `own_declaration` marks a <permission> element in THIS manifest. For those,
    an ABSENT android:protectionLevel is not an unknown -- the platform's rule
    is unambiguous, and it is `normal`, the weakest possible value. Resolving it
    is not a guess; refusing to would hide the single highest-value finding in
    this whole area. For a permission the app merely REFERS to, an absent level
    genuinely is unknown, and stays UNRESOLVED.
    """
    if pm_list and name in pm_list and pm_list[name].get("level"):
        return pm_list[name]["level"], "device (pm list permissions -f)"
    if ds_owners and name in ds_owners and ds_owners[name][1]:
        return ds_owners[name][1], "device (dumpsys Permission record)"
    if manifest_level:
        return manifest_level, "manifest"
    if own_declaration:
        return "normal", ("manifest, android:protectionLevel ABSENT "
                          "-- the platform default is normal")
    if name in STABLE_PLATFORM_LEVELS:
        return STABLE_PLATFORM_LEVELS[name], "stable platform table (verify on device)"
    return None, None


def _owner(name, pm_list, ds_owners):
    if pm_list and name in pm_list and pm_list[name].get("package"):
        return pm_list[name]["package"]
    if ds_owners and name in ds_owners and ds_owners[name][0]:
        return ds_owners[name][0]
    return None


# ---------------------------------------------------------------------------
#  Rendering
# ---------------------------------------------------------------------------

def _fit(s, w):
    s = " ".join(str(s).split())
    return s if len(s) <= w else s[:w - 3] + "..."


def _tail(s, w):
    s = " ".join(str(s).split())
    return s if len(s) <= w else "..." + s[-(w - 3):]


def _wrap(s, w, ind=""):
    return textwrap.wrap(" ".join(str(s).split()), width=w,
                         initial_indent=ind, subsequent_indent=ind) or [ind]


def render_text(rows, mf, width=100, detail=True, trees=None, pkg_name=None):
    out = []
    bar, rule = "=" * width, "-" * width
    pkg = mf.pkg if mf else (pkg_name or "<unknown-package>")

    out.append(bar)
    out.append("  CUSTOM PERMISSION AUDIT -- %s" % pkg)
    out.append(bar)
    out.append("  The question for every row: can an attacker obtain this by acting alone?")
    out.append("")
    tally = {}
    for r in rows:
        tally[r.verdict] = tally.get(r.verdict, 0) + 1
    out.append("  verdicts : " + (", ".join("%s %d" % (v, tally[v])
                                            for v in VERDICTS if v in tally) or "none"))
    out.append("")

    if not rows:
        out.append("  This manifest declares no permissions and guards no component with one.")
        out.append("  That is a complete answer, not an empty one: there is no custom")
        out.append("  permission surface to audit. Exported components with NO permission at")
        out.append("  all are chapter 21's question -- run manifest-exposure.py.")
        out.append(bar)
        return "\n".join(out)

    w_ver, w_lvl = 15, 26
    w_perm = max(24, width - (w_ver + w_lvl + 8))
    out.append(rule)
    out.append("  %-3s %-*s %-*s %s" % ("#", w_ver, "VERDICT", w_lvl, "LEVEL IN FORCE",
                                        "PERMISSION"))
    out.append(rule)
    for i, r in enumerate(rows, 1):
        out.append("  %-3d %-*s %-*s %s"
                   % (i, w_ver, _fit(r.verdict, w_ver),
                      w_lvl, _fit(r.level or "(unresolved)", w_lvl),
                      _tail(r.perm, w_perm)))
    out.append(rule)
    out.append("")

    out.append(rule)
    out.append("  WHO CAN OBTAIN EACH ONE -- one row per POPULATION")
    out.append(rule)
    for i, r in enumerate(rows, 1):
        out.append("  [%d] %s   (%s)" % (i, r.perm, r.level or "unresolved"))
        if r.level_src:
            out.append("      level from : %s" % r.level_src)
        if r.owner:
            out.append("      owned by   : %s" % r.owner)
        if r.guards:
            out.append("      guards     : %s" % "; ".join(r.guards[:4])
                       + ("; and %d more" % (len(r.guards) - 4) if len(r.guards) > 4 else ""))
        if not r.pops:
            out.append("      populations: (none resolved)")
        for tok, kind, reach, desc in r.pops:
            mark = "REACHABLE" if reach else "  anchored"
            out.append("      %s  %-18s %s" % (mark, "%s (%s)" % (tok, kind), ""))
            for line in _wrap(desc, width - 22, ""):
                out.append("                 " + line)
        out.append("")
    out.append(rule)
    out.append("")

    if detail:
        out.append(rule)
        out.append("  WHY, AND WHAT TO DO NEXT")
        out.append(rule)
        for i, r in enumerate(rows, 1):
            out.append("  [%d] %s -- %s" % (i, r.verdict, r.perm))
            for line in _wrap(r.why, width - 6, "      "):
                out.append(line)
            out.append("")
            for line in _wrap("NEXT: " + r.step, width - 6, "      "):
                out.append(line)
            out.append("")
        out.append(rule)
        out.append("")

    unknown = sorted({t for r in rows for t in (r.unknown or [])})
    if unknown:
        out.append("  UNRECOGNISED protectionLevel TOKENS -- resolved by you, not guessed")
        out.append(rule)
        for t in unknown:
            out.append("    %s" % t)
        for line in _wrap(
                "The flag set grows at almost every release. A token this script does not know "
                "is reported, never assumed. Read it in "
                "frameworks/base/core/java/android/content/pm/PermissionInfo.java on the branch "
                "you are testing -- and remember that a flag only ever ADDS a population.",
                width - 4, "    "):
            out.append(line)
        out.append("")
        out.append(rule)
        out.append("")

    if trees:
        out.append("  PERMISSION TREES -- the manifest does NOT describe the whole surface")
        out.append(rule)
        for t in trees:
            out.append("    %s" % t)
        for line in _wrap(
                "A <permission-tree> lets this app add permissions under that prefix at "
                "RUNTIME, with PackageManager.addPermission. Those permissions are invisible to "
                "every manifest-only tool, including this one. They can only be normal or "
                "dangerous -- the platform refuses to add a signature permission dynamically -- "
                "so anything they guard is by construction reachable. Find them: "
                "`grep -rn addPermission jadx-out/`.", width - 4, "    "):
            out.append(line)
        out.append("")
        out.append(rule)
        out.append("")

    out.append(bar)
    out.append("  A NOT-A-BOUNDARY verdict is not yet a finding. It says the gate can be")
    out.append("  opened, not that anything worth having is behind it. Read the component in")
    out.append("  JADX, then prove reachability from an UNPRIVILEGED probe app -- adb shell is")
    out.append("  UID 2000 and holds permissions no app can request.")
    out.append("")
    out.append("  This is the PERMISSION view. For the declaration checklist and the targetSdk")
    out.append("  matrix run 32-Manifest/scripts/manifest-audit.py; for the UID-boundary view")
    out.append("  run 21-App-Sandbox/scripts/manifest-exposure.py. Three tools, three questions.")
    out.append(bar)
    return "\n".join(out)


def render_markdown(rows, mf, trees=None, pkg_name=None):
    out = []
    pkg = mf.pkg if mf else (pkg_name or "<unknown-package>")
    out.append("# Custom permission audit -- `%s`" % pkg)
    out.append("")
    out.append("The question for every row: **can an attacker obtain this by acting alone?**")
    out.append("")
    out.append("| # | Verdict | Level in force | Permission | Guards |")
    out.append("|---|---|---|---|---|")
    for i, r in enumerate(rows, 1):
        out.append("| %d | **%s** | `%s` | `%s` | %s |"
                   % (i, r.verdict, (r.level or "unresolved").replace("|", "\\|"), r.perm,
                      "; ".join(r.guards) if r.guards else "-"))
    out.append("")
    out.append("## Who can obtain each one")
    out.append("")
    for i, r in enumerate(rows, 1):
        out.append("### %d. `%s` -- %s" % (i, r.perm, r.verdict))
        out.append("")
        if r.owner:
            out.append("Owned on the device by `%s`." % r.owner)
            out.append("")
        out.append("| Population | Kind | Attacker-reachable? | Who is in it |")
        out.append("|---|---|---|---|")
        for tok, kind, reach, desc in r.pops:
            out.append("| `%s` | %s | %s | %s |"
                       % (tok, kind, "**yes**" if reach else "no",
                          " ".join(desc.split()).replace("|", "\\|")))
        out.append("")
        out.append(" ".join(r.why.split()))
        out.append("")
        out.append("**Next:** " + " ".join(r.step.split()))
        out.append("")
    if trees:
        out.append("## Permission trees")
        out.append("")
        for t in trees:
            out.append("- `%s`" % t)
        out.append("")
        out.append("A permission tree means the manifest does not describe the whole permission "
                   "surface. Permissions can be added at runtime with `addPermission`, only at "
                   "`normal` or `dangerous` level.")
        out.append("")
    out.append("---")
    out.append("")
    out.append("A `NOT-A-BOUNDARY` verdict says the gate can be opened, not that anything worth "
               "having is behind it. Read the component, then prove reachability from an "
               "unprivileged probe app.")
    return "\n".join(out)


# ---------------------------------------------------------------------------
#  main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit an app's OWN permissions: which are enforceable, which are "
                    "decorative, and which are owned by somebody else.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Chapter 23 owns the permission model. 32-Manifest owns the declaration audit; "
               "21-App-Sandbox owns the sandbox view. Run all three on the same manifest.")
    ap.add_argument("--manifest", help="Decoded AndroidManifest.xml (apktool output).")
    ap.add_argument("--pm-list", help="Capture of `adb shell pm list permissions -f -g`.")
    ap.add_argument("--dumpsys", help="Capture of `adb shell dumpsys package <pkg>`.")
    ap.add_argument("--package", help="Package name, when only --dumpsys is given.")
    ap.add_argument("--markdown", action="store_true", help="Emit Markdown.")
    ap.add_argument("--json", action="store_true", help="Emit JSON.")
    ap.add_argument("--no-detail", action="store_true", help="Tables only.")
    ap.add_argument("--verdict", nargs="+", choices=VERDICTS, help="Only these verdicts.")
    ap.add_argument("--fail-on-weak", action="store_true",
                    help="Exit 1 if any NOT-A-BOUNDARY or SQUATTED row is present.")
    ap.add_argument("--width", type=int, default=100)
    args = ap.parse_args(argv)

    if not args.manifest and not args.dumpsys:
        ap.error("give --manifest, --dumpsys, or both")
        return 2

    mf = None
    if args.manifest:
        try:
            with open(args.manifest, "r", encoding="utf-8", errors="replace") as fh:
                root = ET.fromstring(fh.read())
        except (OSError, ET.ParseError) as exc:
            sys.stderr.write("[-] cannot read %s as XML: %s\n" % (args.manifest, exc))
            sys.stderr.write("    This reads DECODED XML. Decode first: "
                             "apktool d -f target.apk -o out/\n")
            return 2
        if root.tag.split("}")[-1] != "manifest":
            sys.stderr.write("[-] root element is <%s>, expected <manifest>\n"
                             % root.tag.split("}")[-1])
            return 2
        mf = Manifest(root)

    pm_list = {}
    if args.pm_list:
        try:
            with open(args.pm_list, "r", encoding="utf-8", errors="replace") as fh:
                pm_list = parse_pm_list(fh.read())
        except OSError as exc:
            sys.stderr.write("[-] cannot read %s: %s\n" % (args.pm_list, exc))
            return 2

    ds_declared, ds_owners = {}, {}
    if args.dumpsys:
        try:
            with open(args.dumpsys, "r", encoding="utf-8", errors="replace") as fh:
                ds_declared, ds_owners = parse_dumpsys(fh.read())
        except OSError as exc:
            sys.stderr.write("[-] cannot read %s: %s\n" % (args.dumpsys, exc))
            return 2

    rows = audit(mf, pm_list, ds_declared, ds_owners, args.package)
    if args.verdict:
        rows = [r for r in rows if r.verdict in args.verdict]
    rows.sort(key=lambda r: (VRANK.get(r.verdict, 99), r.perm))

    trees = mf.trees if mf else []

    if args.json:
        print(json.dumps({
            "package": mf.pkg if mf else args.package,
            "permissionTrees": trees,
            "rows": [{
                "permission": r.perm,
                "verdict": r.verdict,
                "level": r.level,
                "levelSource": r.level_src,
                "owner": r.owner,
                "guards": r.guards,
                "populations": [{"token": t, "kind": k, "attackerReachable": a,
                                 "who": d} for t, k, a, d in (r.pops or [])],
                "unrecognisedTokens": r.unknown,
                "why": " ".join(r.why.split()),
                "next": " ".join(r.step.split()),
            } for r in rows],
        }, indent=2))
    elif args.markdown:
        print(render_markdown(rows, mf, trees, pkg_name=args.package))
    else:
        print(render_text(rows, mf, width=args.width,
                          detail=not args.no_detail, trees=trees,
                          pkg_name=args.package))

    if args.fail_on_weak and any(r.verdict in ("NOT-A-BOUNDARY", "SQUATTED") for r in rows):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
