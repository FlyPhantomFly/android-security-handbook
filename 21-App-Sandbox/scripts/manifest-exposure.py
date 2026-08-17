#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
manifest-exposure.py -- read a decoded AndroidManifest.xml as a statement about
                        the app sandbox.

WHAT IT DOES
    The sandbox is a UID boundary. Everything in this chapter reduces to one
    question asked of a manifest: does this declaration SHARE the UID, WIDEN
    what can be reached across it, BREACH it outright, or NARROW it?

    This script asks that question of every declaration that can answer it, and
    prints two aligned tables:

        TABLE 1  one row per observation: sandbox effect, verdict, where, what
        TABLE 2  the next step for each row, keyed by the same row number

    It covers the two things README.md promises it covers.

      1. Section 5.3's exported-without-permission analysis. Every activity,
         activity-alias, service, receiver and provider is resolved to an
         effective export state and to the permission a caller must hold --
         including the <application android:permission> fallback and, for
         providers, readPermission / writePermission, which the one-line
         version in the README does not handle and therefore over-reports.

      2. Section 8.1's grep set, structured. Every one of those greps has a
         row here: sharedUserId, sharedUserMaxSdkVersion, allowBackup,
         debuggable, isolatedProcess, android:process, externalService,
         exported="true", grantUriPermissions, requestLegacyExternalStorage,
         MANAGE_EXTERNAL_STORAGE, QUERY_ALL_PACKAGES, <queries>,
         usesCleartextTraffic, networkSecurityConfig, protectionLevel.

    The distinction the greps cannot make, and this script exists to make, is
    the one section 8.1 flags in its own comments: android:isolatedProcess is a
    POSITIVE finding, and android:process is NOT isolation. `grep -n
    'android:process='` and `grep -n 'isolatedProcess'` return two lines that
    look alike. Here they get opposite verdicts, NARROWED and NOT-A-BOUNDARY,
    and NOT-A-BOUNDARY carries the sentence you should paste into the report
    instead of "the app isolates its parsing in a separate process".

WHAT THIS IS NOT -- the boundary with chapter 32
    32-Manifest/scripts/manifest-audit.py owns the DECLARATION AUDIT. It is the
    severity-rated, checklist-complete tool, and it applies the targetSdk
    version matrix: which defaults were in force, what exported meant before
    API 31, when cleartext flipped off, what a low minSdk re-enables.

    This script does none of that on purpose. It has no severity ladder, no
    version matrix, no secret scanning, no deep-link analysis and no AXML
    parser-differential checks. Where an answer genuinely depends on targetSdk
    -- a component with an intent-filter and no android:exported attribute is
    the common case -- it does not guess and does not restage 32's matrix. It
    emits verdict UNRESOLVED and hands you to manifest-audit.py.

    Run both. They answer different questions and their outputs are meant to
    sit side by side:

        python3 ../../32-Manifest/scripts/manifest-audit.py  out/AndroidManifest.xml
        python3 manifest-exposure.py                         out/AndroidManifest.xml

WHAT THIS WILL *NOT* TELL YOU
    - Whether anything here is reachable. Every WIDENED and BREACHED verdict is
      derived from a declaration, not from an experiment. `adb shell` runs as
      UID 2000 with privileges no app holds, so reaching a component from a
      shell proves nothing about an attacker. Build the probe app in
      ../examples/attacker-app/ and re-test. That is the finding; this is the
      shortlist.
    - Whether anything sensitive travels the route. An exported provider that
      returns an empty table is not a data leak. allowBackup is printed as a
      CANDIDATE for exactly this reason: it says data CAN leave by a path that
      is not a UID check, not that anything worth having does.
    - What the code does. isolatedProcess in the manifest does not prove the
      risky parsing actually happens there, and an app can undo its own
      isolation by handing the isolated process a descriptor to its database.
      Confirm on device: `ls -l /proc/<pid>/fd/` is the complete data interface
      of an isolated process.
    - Anything registered at runtime. Context-registered receivers, permissions
      added through PackageManager.addPermission, and components toggled with
      setComponentEnabledSetting are not in this file at all.
    - Anything the decoder lost. This reads ONE decoding of the manifest. A
      crafted APK can make a decoder and the platform disagree; that class of
      trick is chapter 32's, and manifest-audit.py checks for it.
    - The runtime SELinux domain, the seccomp mode, or the supplementary GIDs.
      Those are process facts, not manifest facts. Use ./sandbox-inspect.sh.

HOW TO RUN
    # host -- decode first, then read the decoded XML
    apktool d -f target.apk -o out/
    python3 manifest-exposure.py out/AndroidManifest.xml

    # host -- just section 5.3: exported components and their permission posture
    python3 manifest-exposure.py out/AndroidManifest.xml --exported-only

    # host -- only the rows that change the boundary, for a findings section
    python3 manifest-exposure.py out/AndroidManifest.xml --verdict DISSOLVED BREACHED WIDENED

    # host -- paste straight into a report
    python3 manifest-exposure.py out/AndroidManifest.xml --markdown > exposure.md

    # host -- from stdin
    cat out/AndroidManifest.xml | python3 manifest-exposure.py -

REQUIREMENTS
    Python 3.6+. Standard library only -- xml.etree, argparse, textwrap. No pip
    install, so it runs on a locked-down assessment laptop.

    Output is deliberately pure ASCII: a Windows console defaults to a codepage
    that cannot encode box-drawing characters or typographic dashes, and a
    UnicodeEncodeError in the middle of a report is a worse outcome than a
    plain table. Input is read as UTF-8 with replacement.

    The script writes nothing, imports nothing local, and produces no
    __pycache__ next to the repository source. Run it as a script.

EXIT CODES
    0  ran to completion
    2  input could not be parsed, or the root element is not <manifest>

AUTHORISED TESTING ONLY.
"""

import argparse
import os
import sys
import textwrap
import xml.etree.ElementTree as ET

NS = "{http://schemas.android.com/apk/res/android}"

# ---------------------------------------------------------------------------
#  Verdict vocabulary.
#
#  Deliberately NOT a severity ladder. Chapter 32 rates severity; this chapter
#  answers "what does this do to the UID boundary", and the two are not the
#  same axis. A CANDIDATE here can outrank a WIDENED once you prove what
#  travels the route, and a NARROWED row belongs in the report as a control
#  observed, not as a finding.
# ---------------------------------------------------------------------------

VERDICTS = [
    "DISSOLVED",       # the UID boundary does not exist between this app and another
    "BREACHED",        # a route across the boundary exists for a party that should not have one
    "WIDENED",         # the boundary holds, but more is reachable through it than by default
    "NOT-A-BOUNDARY",  # looks like isolation in a report, provides none
    "CANDIDATE",       # a route may exist; unproven until you inspect what travels it
    "UNRESOLVED",      # cannot be decided from this file alone
    "NARROWED",        # a control that shrinks the boundary -- a positive finding
    "CONTEXT",         # shapes how every other row should be read
]
VRANK = {v: i for i, v in enumerate(VERDICTS)}

# protectionLevel values that are anchored to something an attacker cannot
# supply. Everything else is obtainable by any app that asks.
STRONG_LEVELS = ("signature", "signatureOrSystem", "knownSigner")

HIGH_SIGNAL_PERMISSIONS = {
    "android.permission.MANAGE_EXTERNAL_STORAGE": (
        "All-files access to shared storage. The app opts out of the storage "
        "half of the sandbox for every other app's shared files too."),
    "android.permission.QUERY_ALL_PACKAGES": (
        "Defeats package-visibility filtering, which is one of the sandbox's "
        "seven mechanisms. The app can enumerate every installed package."),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "The app can trigger installation of other APKs -- it can create new "
        "sandboxes, which is dropper capability."),
    "android.permission.WRITE_EXTERNAL_STORAGE": (
        "Writes outside the private data directory, where the UID boundary "
        "does not apply on legacy storage."),
    "android.permission.READ_EXTERNAL_STORAGE": (
        "Reads outside the private data directory."),
}

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


# ---------------------------------------------------------------------------
#  Model
# ---------------------------------------------------------------------------

class Row(object):
    __slots__ = ("effect", "verdict", "where", "what", "why", "step")

    def __init__(self, effect, verdict, where, what, why, step):
        self.effect = effect     # short verb phrase: what it does to the boundary
        self.verdict = verdict   # one of VERDICTS
        self.where = where       # manifest location: element or attribute
        self.what = what         # the observation, one line
        self.why = why           # why it matters to the sandbox, one paragraph
        self.step = step         # the next action, concrete


class Exposure(object):

    def __init__(self, root, path):
        self.root = root
        self.path = path
        self.rows = []
        self.pkg = root.get("package") or "<unknown-package>"
        self.app = root.find("application")
        self.declared_permissions = {}
        for p in root.iter("permission"):
            name = p.get(NS + "name")
            if name:
                self.declared_permissions[name] = p.get(NS + "protectionLevel") or "normal"
        self.counts = {"components": 0, "exported": 0, "unresolved": 0}

    # -- helpers ------------------------------------------------------------

    def add(self, effect, verdict, where, what, why, step):
        self.rows.append(Row(effect, verdict, where, what, why, step))

    @staticmethod
    def a(el, name):
        """An android-namespaced attribute, or None."""
        return el.get(NS + name)

    @staticmethod
    def truthy(value):
        """
        The platform's getAttributeBooleanValue is 'data != 0'. In decoded text
        XML we only have a string, so treat anything that is not an explicit
        false as true, and let the UNRESOLVED rows carry the doubt.
        """
        if value is None:
            return False
        return str(value).strip().lower() not in ("false", "0", "no", "")

    def comp_name(self, el):
        n = self.a(el, "name") or "<unnamed>"
        if n.startswith(".") and self.pkg != "<unknown-package>":
            return self.pkg + n
        return n

    def level_of(self, perm):
        """(protectionLevel or None, source) for a permission name."""
        if perm in self.declared_permissions:
            return self.declared_permissions[perm], "declared in this manifest"
        return None, "not declared here"

    def permission_strength(self, perm):
        """
        Return (strength, note). strength is 'strong', 'weak' or 'unknown'.
        Only a signature-anchored level ties access to a signing key, which is
        the only thing in a manifest that behaves like a UID check.
        """
        level, src = self.level_of(perm)
        if level is None:
            if perm.startswith("android.permission.BIND_"):
                return "strong", ("platform BIND_* permission -- signature-level in AOSP, so a "
                                  "third-party app cannot obtain it; confirm on the device")
            return "unknown", ("protectionLevel not in this manifest (%s); resolve it with "
                               "`adb shell pm list permissions -f -g | grep -A4 %s`" % (src, perm))
        low = level.lower()
        if any(s.lower() in low for s in STRONG_LEVELS):
            return "strong", 'protectionLevel="%s"' % level
        return "weak", 'protectionLevel="%s"' % level

    # -- 1. the manifest root: UID sharing -----------------------------------

    def check_shared_uid(self):
        suid = self.a(self.root, "sharedUserId")
        maxsdk = self.a(self.root, "sharedUserMaxSdkVersion")

        if suid:
            self.add(
                "SHARES UID", "DISSOLVED",
                'manifest android:sharedUserId="%s"' % suid,
                "This app does not have a sandbox of its own on platforms where the "
                "shared UID applies.",
                "Every app installed with this sharedUserId and the same signing key "
                "receives the SAME Linux UID. Same UID means the same data directory "
                "namespace, direct file reads in both directions, and the union of every "
                "permission any member holds. There is no boundary inside the group, so "
                "the group is exactly as strong as its weakest member -- and that member "
                "may be a third-party app you were not scoped to test."
                + (" android.uid.system additionally requires the platform signing key; if "
                   "this APK installs on a stock device, that key has leaked or the build "
                   "is permissive." if suid == "android.uid.system" else ""),
                "Enumerate the group before writing this up, because the finding is the "
                "weakest sibling, not the attribute: `adb shell pm list packages -U | "
                "grep <uid>` then `adb shell dumpsys package %s | grep -i userId`. Write "
                "it as ONE finding with the chain shown." % self.pkg)

            if maxsdk:
                self.add(
                    "SPLITS UID BY API", "CONTEXT",
                    'manifest android:sharedUserMaxSdkVersion="%s"' % maxsdk,
                    "The shared UID applies only at or below API %s; above it this app "
                    "gets its own UID." % maxsdk,
                    "The sandbox boundary of this app is therefore VERSION-DEPENDENT, and "
                    "so is every other row in this report that assumes a shared UID. The "
                    "developer is migrating off the shared UID, which is the correct "
                    "direction and worth saying so.",
                    "Test on a device below and above API %s and record both. A finding "
                    "that only reproduces on one side of that line must say which side."
                    % maxsdk)
            else:
                self.add(
                    "SHARES UID", "CONTEXT",
                    "manifest android:sharedUserMaxSdkVersion (absent)",
                    "No migration path is declared -- the shared UID applies on every "
                    "supported platform.",
                    "sharedUserId is deprecated but cannot simply be removed: removing it "
                    "changes the app's UID and orphans its data directory, so the fix "
                    "needs a migration plan and not just an edit.",
                    'Recommend android:sharedUserMaxSdkVersion="32" plus a data-migration '
                    'plan, so new installs on new platforms land in their own sandbox.')
        else:
            self.add(
                "SHARES UID", "NARROWED",
                "manifest android:sharedUserId (absent)",
                "The app has its own UID. The sandbox boundary exists.",
                "This is the default and the correct state. It is listed because the rest "
                "of this report is only meaningful once it is established.",
                "None. Note it in a controls-observed section if the client has sibling "
                "apps in scope.")

    # -- 2. <application>: routes out of the sandbox --------------------------

    def check_application_flags(self):
        app = self.app
        if app is None:
            self.add("--", "CONTEXT", "<application> (absent)",
                     "No <application> element: this is a library, split or stub manifest.",
                     "Nothing below applies. A split manifest describes a fragment of an "
                     "app, not an app.",
                     "Audit the base APK's manifest instead.")
            return

        # debuggable -- the sandbox handed to anyone with a USB cable.
        dbg = self.a(app, "debuggable")
        if self.truthy(dbg):
            self.add(
                "HANDS OUT UID", "BREACHED",
                'application android:debuggable="true"',
                "`run-as %s` gives a shell the app's own UID." % self.pkg,
                "This is the sandbox's own escape hatch, left open. `adb shell run-as "
                "<pkg>` starts a shell that IS the app's UID with full read/write of the "
                "private data directory; JDWP attaches to the process; Frida and Objection "
                "need no root. Physical or ADB access alone is enough. Note that run-as "
                "runs in a different SELinux domain with no seccomp filter, so it is a "
                "sandbox breach but not a faithful reproduction of what an app can do.",
                "Prove it: `adb shell run-as %s ls -la /data/data/%s/`. Then confirm on "
                "the shipped artefact rather than the source manifest -- `aapt2 dump "
                "badging target.apk | grep -i debug`, or `adb shell dumpsys package %s | "
                "grep flags=` and look for DEBUGGABLE." % (self.pkg, self.pkg, self.pkg))
        elif dbg is None:
            self.add(
                "HANDS OUT UID", "UNRESOLVED",
                "application android:debuggable (absent)",
                "Absence proves nothing about the shipped APK.",
                "Gradle's debug build type injects debuggable during the manifest merge, "
                "so a source manifest is clean while the installed APK is debuggable. This "
                "row is only conclusive when the input came from apktool on the artefact "
                "you were given.",
                "`aapt2 dump badging target.apk | grep -i debug`, or on device `adb shell "
                "dumpsys package %s | grep flags=`." % self.pkg)

        # allowBackup -- data leaving by a path that is not a UID check.
        allow = self.a(app, "allowBackup")
        rules = self.a(app, "dataExtractionRules")
        full = self.a(app, "fullBackupContent")
        agent = self.a(app, "backupAgent")
        enabled = True if allow is None else self.truthy(allow)
        if not enabled:
            self.add(
                "EXPORTS DATA", "NARROWED",
                'application android:allowBackup="false"',
                "Backup is off. This route out of the sandbox is closed.",
                "Auto Backup and `adb backup` both read the private data directory as the "
                "system, not as the app's UID, so backup is a legitimate path around the "
                "UID check. Disabling it closes that path.",
                "None. Record it as a control observed.")
        else:
            basis = "explicit" if allow is not None else "PLATFORM DEFAULT, attribute absent"
            if rules or full:
                self.add(
                    "EXPORTS DATA", "CANDIDATE",
                    "application android:allowBackup (%s) with a rules file" % basis,
                    "Backup is on; %s constrains it."
                    % (("dataExtractionRules=%s" % rules) if rules else ("fullBackupContent=%s" % full)),
                    "Backup copies the private data directory out of the sandbox by a route "
                    "the UID boundary does not police. A rules file narrows it, and anything "
                    "not explicitly excluded still leaves. dataExtractionRules has TWO "
                    "independent rule sets, <cloud-backup> and <device-transfer>; excluding a "
                    "token from one and not the other is an incomplete fix. This is a "
                    "CANDIDATE, not a proven leak: you have not yet shown that anything "
                    "worth having is inside the set that leaves.",
                    "Resolve the referenced XML from out/res/xml/, list the app's actual "
                    "files with `adb shell run-as %s find . -type f` on a debuggable build "
                    "or from a rooted device, and name the specific files that would leave. "
                    "Report those, not the attribute." % self.pkg)
            else:
                self.add(
                    "EXPORTS DATA", "CANDIDATE",
                    "application android:allowBackup (%s), no rules file" % basis,
                    "Backup is on and unconstrained: everything except cache/ and "
                    "no_backup/ is eligible to leave.",
                    "shared_prefs (session tokens, refresh tokens, PII), databases/ and "
                    "files/ are all in scope. On platforms where `adb backup` still "
                    "functions this is extractable over USB with no root at all. It remains "
                    "a CANDIDATE until you open the extracted data and find something: an "
                    "app whose data directory holds nothing sensitive has no finding here, "
                    "and reporting the attribute alone is how a report loses credibility.",
                    "`adb backup -f out.ab %s`, unpack it, and enumerate what you actually "
                    "got. If `adb backup` is a no-op on your test platform, say so and "
                    "report the exposure as unproven rather than dropping it."
                    % self.pkg)
            if agent:
                self.add(
                    "EXPORTS DATA", "CANDIDATE",
                    "application android:backupAgent=%s" % agent,
                    "A hand-written BackupAgent serialises the backup stream itself.",
                    "The rules file does not constrain what a custom agent chooses to "
                    "write. Developers routinely serialise tokens into the stream by hand, "
                    "bypassing every exclusion declared in XML.",
                    "Read %s in JADX -- specifically onBackup/onFullBackup -- and list what "
                    "it writes." % agent)

        # Storage: opting out of the storage half of the sandbox.
        for attr in ("requestLegacyExternalStorage", "preserveLegacyExternalStorage"):
            v = self.a(app, attr)
            if self.truthy(v):
                self.add(
                    "WIDENS REACH", "WIDENED",
                    'application android:%s="%s"' % (attr, v),
                    "The app asks for the pre-scoped-storage view of shared storage.",
                    "Scoped storage is the part of the sandbox that applies to shared "
                    "storage, where UNIX ownership alone never separated apps. Opting out "
                    "restores a world in which this app reads and writes other apps' files "
                    "on the shared volume. Even where the platform now ignores the "
                    "attribute, its presence means the code was written against the old "
                    "model and that code path is still in the APK.",
                    "Grep the decompiled sources for the paths it enables: `grep -rn "
                    "\"getExternalStorage\\|/sdcard\\|Environment.DIRECTORY\" out/sources/`, "
                    "and check what the app writes there with "
                    "`adb shell ls -la /sdcard/Android/data/%s/`." % self.pkg)

        # Network: the sandbox does not police the wire.
        cleartext = self.a(app, "usesCleartextTraffic")
        nsc = self.a(app, "networkSecurityConfig")
        if self.truthy(cleartext):
            self.add(
                "LEAVES THE DEVICE", "WIDENED",
                'application android:usesCleartextTraffic="true"',
                "Plaintext HTTP is permitted.",
                "The sandbox protects data at rest under a UID. It says nothing about data "
                "in flight: once bytes leave the process they are on a network any device "
                "on the path can read. A networkSecurityConfig, when present, SUPERSEDES "
                "this attribute, so read that file before concluding.",
                "Confirm with a real intercept rather than the attribute: proxy the device "
                "through Burp and record an actual plaintext request. See "
                "../../24-IPC/README.md for the same discipline applied to local channels.")
        elif cleartext is not None:
            self.add(
                "LEAVES THE DEVICE", "NARROWED",
                'application android:usesCleartextTraffic="false"',
                "Plaintext HTTP is refused by the platform's network stacks.",
                "An explicit false is better than relying on a targetSdk default, because "
                "it survives a targetSdk downgrade.",
                "None, beyond confirming the networkSecurityConfig does not re-enable "
                "cleartext for named domains.")
        if nsc:
            self.add(
                "LEAVES THE DEVICE", "CANDIDATE",
                "application android:networkSecurityConfig=%s" % nsc,
                "A Network Security Config is present and OVERRIDES the attribute above.",
                "This referenced file is frequently the highest-value single file in the "
                "APK. It can re-enable cleartext for named domains, add the user trust "
                "store as an anchor (which makes an interception CA trusted), ship "
                "<debug-overrides> into production, or pin certificates.",
                "Resolve it: apktool leaves it in out/res/xml/. Read every <domain-config>, "
                "every <trust-anchors>, and check for <debug-overrides>.")
        else:
            self.add(
                "LEAVES THE DEVICE", "CONTEXT",
                "application android:networkSecurityConfig (absent)",
                "No explicit network policy; the platform defaults for this targetSdk apply.",
                "There is no pinning, no per-domain policy, and no explicit statement of "
                "which domains may use cleartext. Which defaults are in force is a "
                "targetSdk question and therefore chapter 32's.",
                "Run 32-Manifest/scripts/manifest-audit.py for the targetSdk-dependent "
                "reading of this.")

        # An application-wide android:process.
        aproc = self.a(app, "process")
        if aproc:
            self.add(
                "NO UID EFFECT", "NOT-A-BOUNDARY",
                'application android:process="%s"' % aproc,
                "Every component runs in this named process. Same UID as always.",
                "A process name without a leading ':' can be shared with another app "
                "signed by the same key, which is a lifecycle and memory arrangement, not "
                "an isolation one." if not aproc.startswith(":")
                else "A private process name. Lifecycle and memory only.",
                "Confirm the UID is unchanged: `adb shell ps -A -o USER,PID,NAME | grep %s`."
                % self.pkg)

    # -- 3. processes: the one attribute that narrows, and its impostor -------

    def check_processes(self):
        if self.app is None:
            return

        isolated, named, external = [], [], []
        for tag in COMPONENT_TAGS:
            for el in self.app.iter(tag):
                name = self.comp_name(el)
                if self.truthy(self.a(el, "isolatedProcess")):
                    isolated.append((tag, name, self.truthy(self.a(el, "useAppZygote"))))
                if self.truthy(self.a(el, "externalService")):
                    external.append((tag, name, self.truthy(self.a(el, "isolatedProcess"))))
                proc = self.a(el, "process")
                if proc:
                    named.append((tag, name, proc))

        for tag, name, zygote in isolated:
            self.add(
                "SHRINKS UID", "NARROWED",
                "%s %s" % (tag, name),
                'android:isolatedProcess="true"%s -- a real security boundary.'
                % (' with useAppZygote="true"' if zygote else ""),
                "This is the strongest sandbox a developer can ask for, and it is the one "
                "row in this report you should put in a controls-observed section. The "
                "process gets a throwaway UID in 99000-99999 (90000-98999 when forked from "
                "an app Zygote), no permissions at all, no data directory, no network, and "
                "the far tighter isolated_app SELinux domain. Code execution inside it is "
                "worth almost nothing on its own." + (
                    " useAppZygote means these processes fork from the app's own Zygote and "
                    "share preloaded pages copy-on-write, which is why the UID range is the "
                    "lower one." if zygote else ""),
                "Verify it is real and then check what was handed in, because a host can "
                "undo its own isolation: `adb shell ps -A -Z | grep isolated` for the "
                "domain and UID, then `adb shell ls -l /proc/<pid>/fd/`. The set of file "
                "descriptors plus the Binder connection IS the complete data interface. A "
                "writable descriptor, a directory descriptor, or a descriptor to the app's "
                "database is a finding.")

        for tag, name, is_iso in external:
            self.add(
                "SHIFTS UID", "CONTEXT" if is_iso else "UNRESOLVED",
                "%s %s" % (tag, name),
                'android:externalService="true"%s'
                % ("" if is_iso else " WITHOUT isolatedProcess -- the platform requires both"),
                "An external service is bound by another app holding "
                "BIND_EXTERNAL_SERVICE, and the resulting isolated process is charged to "
                "and lifetime-tied to that CLIENT app rather than to this one. The code is "
                "this app's; the accounting is the caller's. This is how the WebView "
                "renderer runs: the page's JavaScript executes in an isolated process "
                "associated with the app showing the WebView." + (
                    "" if is_iso else " Declared without isolatedProcess, the platform will "
                    "refuse to start it -- so either the decode dropped an attribute or the "
                    "declaration is dead. Either way, resolve it before reporting."),
                "Identify who binds it and with what: `adb shell dumpsys activity services "
                "%s` while the service is live, and read the interface the client can "
                "reach." % self.pkg)

        if named:
            shown = ", ".join("%s (%s)" % (n, p) for _, n, p in named[:4])
            if len(named) > 4:
                shown += ", and %d more" % (len(named) - 4)
            self.add(
                "NO UID EFFECT", "NOT-A-BOUNDARY",
                "%d component(s) with android:process" % len(named),
                shown,
                "android:process is the trap this chapter exists to disarm. It creates a "
                "separate PROCESS with the SAME UID, the same data directory, the same "
                "granted permissions and the same SELinux context. It is a crash boundary "
                "and a memory-reclaim tool. It is not isolation, and an attacker with code "
                "execution in a :sync process is, to the kernel, the app.",
                "Do not write \"the app isolates X in a separate process\" as a mitigating "
                "control. Write: \"the app splits into multiple processes, which limits "
                "crash blast radius but provides no security isolation, because all "
                "processes share the UID and SELinux context; android:isolatedProcess would "
                "provide isolation and is not used.\" Confirm with `adb shell ps -A -o "
                "USER,PID,NAME | grep %s` -- identical USER on every row is the proof."
                % self.pkg)

    # -- 4. exported components: holes in a boundary that still exists --------

    def effective_export(self, el):
        """(state, basis) where state is True, False or None (=unresolved)."""
        exp = self.a(el, "exported")
        has_filter = el.find("intent-filter") is not None
        if exp is not None:
            return self.truthy(exp), 'android:exported="%s"' % exp
        if el.tag == "provider":
            return None, ("no android:exported; provider defaults changed at targetSdk 17")
        if has_filter:
            return None, ("no android:exported but an intent-filter is present; defaults "
                          "changed at targetSdk 31")
        return False, "no android:exported and no intent-filter"

    def caller_permission(self, el):
        """
        What a caller must hold. Returns a list of (label, permission) pairs;
        the permission may be None, meaning that operation is unguarded.

        A provider has TWO independent gates, and both directions matter. The
        README's one-line version tests android:permission alone, so it
        over-reports a provider whose access control is readPermission (it
        prints "NO PERMISSION" when there is one) and under-reports a provider
        that declares readPermission and no writePermission (it prints nothing
        while the table is world-writable).
        """
        app_perm = self.a(self.app, "permission") if self.app is not None else None
        base = self.a(el, "permission") or app_perm
        if el.tag != "provider":
            return [("call", base)]
        return [("read", self.a(el, "readPermission") or base),
                ("write", self.a(el, "writePermission") or base)]

    def check_components(self):
        if self.app is None:
            return

        for tag in COMPONENT_TAGS:
            for el in self.app.iter(tag):
                self.counts["components"] += 1
                name = self.comp_name(el)
                state, basis = self.effective_export(el)
                gates = self.caller_permission(el)

                # Grants are worth a row whatever the export state: the correct
                # FileProvider pattern is a NON-exported provider plus grants,
                # and that pattern is exactly what you recommend in remediation.
                if tag == "provider":
                    self.check_provider_grants(el, name, state)

                if state is None:
                    self.counts["unresolved"] += 1
                    self.add(
                        "WIDENS REACH", "UNRESOLVED",
                        "%s %s" % (tag, name),
                        basis,
                        "Whether this component is reachable from another UID depends on "
                        "the app's targetSdkVersion, and resolving version defaults is "
                        "chapter 32's job, not this script's. It is listed so it does not "
                        "silently drop out of your count.",
                        "Resolve it, do not guess: `python3 "
                        "../../32-Manifest/scripts/manifest-audit.py out/AndroidManifest.xml` "
                        "applies the version matrix, and `adb shell dumpsys package %s` is "
                        "authoritative on the device in front of you." % self.pkg)
                    continue

                if not state:
                    continue

                self.counts["exported"] += 1

                if not any(p for _, p in gates):
                    self.add(
                        "WIDENS REACH", "WIDENED",
                        "%s %s" % (tag, name),
                        "exported, NO permission (%s)" % basis,
                        "Any UID on the device may reach this component with fully "
                        "attacker-controlled input, with no permission and no user "
                        "prompt. The sandbox is intact -- this is a door the developer "
                        "put in it. What comes through the door decides the severity: a "
                        "provider that returns a table is a data leak, an activity that "
                        "loads a supplied URL into a WebView is something else again.",
                        "Two steps, in order. First read what it does in JADX. Then prove "
                        "reachability from an UNPRIVILEGED app, not from a shell: build "
                        "../examples/attacker-app/ and call it. `adb shell am start` "
                        "succeeds as UID 2000 in cases where an app fails, and a report "
                        "that conflates the two is not defensible.")
                    continue

                for label, perm in gates:
                    if perm is None:
                        # A provider guarded in one direction only. This is the
                        # case the README's one-liner cannot see at all, and it
                        # is common: developers think about reads and forget
                        # that insert/update/delete have their own gate.
                        self.add(
                            "WIDENS REACH", "WIDENED",
                            "%s %s (%s)" % (tag, name, label),
                            "exported, %s is UNGUARDED while the other direction is not"
                            % label,
                            "A provider has two independent gates. This one declares a "
                            "permission for the other direction and none for %s, so any app "
                            "may %s through it. A write-side hole is not the lesser finding: "
                            "an attacker who can insert or update rows can poison the data "
                            "the app itself trusts, and in a provider backed by SQLite the "
                            "selection argument is an injection surface as well." % (
                                label,
                                "read the tables" if label == "read"
                                else "insert, update and delete rows"),
                            "Prove the unguarded direction specifically: `adb shell content "
                            "%s --uri content://<authority>/<path>` from a shell first, then "
                            "the same call from ../examples/attacker-app/, which is the one "
                            "that counts." % ("query" if label == "read" else "insert"))
                        continue
                    strength, note = self.permission_strength(perm)
                    if strength == "strong":
                        self.add(
                            "WIDENS REACH", "NARROWED",
                            "%s %s (%s)" % (tag, name, label),
                            "exported, guarded by %s" % perm,
                            "The gate is anchored to a signing key or to the platform, so "
                            "an ordinary app cannot obtain it by asking. Exported plus "
                            "signature-level is the correct pattern for cross-app access "
                            "and belongs in a controls-observed section. %s" % note,
                            "Confirm the level on the device rather than trusting the "
                            "manifest: `adb shell pm list permissions -f -g | grep -A4 %s`. "
                            "Then check the code also verifies Binder.getCallingUid(), "
                            "because a manifest permission is checked once at entry."
                            % perm)
                    elif strength == "weak":
                        self.add(
                            "WIDENS REACH", "WIDENED",
                            "%s %s (%s)" % (tag, name, label),
                            "exported, guarded by %s (%s)" % (perm, note),
                            "A normal-level permission is granted to any app that requests "
                            "it, silently, at install. A dangerous-level one costs the "
                            "attacker a user prompt. Neither is a UID-anchored control, so "
                            "this component is effectively reachable by an attacker who is "
                            "willing to declare one line in a manifest.",
                            "Declare %s in ../examples/attacker-app/ and re-run the call. "
                            "If it succeeds, report it exactly as you would an unguarded "
                            "component; the permission is a speed bump, not a boundary."
                            % perm)
                    else:
                        self.add(
                            "WIDENS REACH", "UNRESOLVED",
                            "%s %s (%s)" % (tag, name, label),
                            "exported, guarded by %s" % perm,
                            "The permission is not declared in this manifest, so its "
                            "protectionLevel is unknown from this file alone. If it is a "
                            "platform permission the level may still be weak; the script "
                            "refuses to guess.",
                            "Resolve it on device: `adb shell pm list permissions -f -g | "
                            "grep -A4 %s`. %s" % (perm, note))

    def check_provider_grants(self, el, name, exported):
        grant = self.a(el, "grantUriPermissions")
        children = list(el.findall("grant-uri-permission"))
        if not self.truthy(grant) and not children:
            return

        broad = []
        for g in children:
            for attr in ("path", "pathPrefix", "pathPattern"):
                v = self.a(g, attr)
                if v is not None:
                    broad.append("%s=%s" % (attr, v))

        if self.truthy(grant) and not children:
            scope = "the WHOLE provider (no <grant-uri-permission> children to narrow it)"
            verdict = "WIDENED"
        else:
            scope = "; ".join(broad) if broad else "children present but no path attributes"
            verdict = "WIDENED" if any(
                v.endswith("=/") or v.endswith("=.*") or v.endswith("=/.*")
                for v in broad) else "CANDIDATE"

        self.add(
            "PUNCHES A HOLE", verdict,
            "provider %s" % name,
            'android:grantUriPermissions="true" over %s%s'
            % (scope, ", and the provider is exported" if exported else
               ", provider not exported (the FileProvider pattern)"),
            "A URI grant is a per-URI, time-boxed hole punched through the provider's "
            "permission check for one specific caller. Used as intended -- provider not "
            "exported, narrow declared paths, read-only flags -- it is the correct way to "
            "share a file and needs no other access at all. Used broadly it is a standing "
            "invitation: a grant over the whole provider means any URI the app can be "
            "persuaded to emit is readable by the recipient. Remember also that a "
            "descriptor returned by openFile() was opened under THIS app's UID and is "
            "never rechecked afterwards.",
            "Read the openFile()/query() implementation in JADX and look for a path built "
            "from the incoming Uri without canonicalisation -- that is the traversal case. "
            "Then check who receives grants: `grep -rn \"FLAG_GRANT_READ_URI_PERMISSION\\|"
            "FLAG_GRANT_WRITE_URI_PERMISSION\\|FLAG_GRANT_PERSISTABLE\" out/sources/`, and "
            "`adb shell dumpsys activity providers | grep -A10 %s` for live grants." % name)

    # -- 5. permissions the app holds, and permissions it defines ------------

    def check_permissions(self):
        for u in self.root.iter("uses-permission"):
            name = u.get(NS + "name")
            if name in HIGH_SIGNAL_PERMISSIONS:
                self.add(
                    "WIDENS REACH", "WIDENED",
                    "uses-permission %s" % name,
                    "The app asks for a capability that reaches past its own sandbox.",
                    HIGH_SIGNAL_PERMISSIONS[name],
                    "Requesting is not holding. Check the grant state on a device with "
                    "`adb shell dumpsys package %s | grep -A40 'requested permissions'` "
                    "and then find the code that uses it in JADX. A permission requested "
                    "and never used is a supply-chain question, not an exposure."
                    % self.pkg)

        for p in self.root.iter("permission"):
            name = p.get(NS + "name") or "<unnamed>"
            level = p.get(NS + "protectionLevel")
            users = []
            if self.app is not None:
                for tag in COMPONENT_TAGS:
                    for el in self.app.iter(tag):
                        if name in [v for _, v in self.caller_permission(el)]:
                            users.append("%s %s" % (tag, self.comp_name(el)))

            if level is None or not any(s.lower() in level.lower() for s in STRONG_LEVELS):
                self.add(
                    "DEFINES A WEAK GATE", "NOT-A-BOUNDARY",
                    "permission %s" % name,
                    'protectionLevel=%s%s'
                    % ('"%s"' % level if level else '(absent, defaults to "normal")',
                       " -- guards: " + ", ".join(users) if users else " -- guards nothing here"),
                    "A custom permission at normal level is granted silently to any app "
                    "that declares it; at dangerous level it costs one user prompt. Neither "
                    "ties access to an identity the attacker cannot forge, so a component "
                    "behind it is reachable. There is also a first-installer race on custom "
                    "permissions: whichever app defines the permission first owns its "
                    "definition, so a malicious app installed earlier can define this name "
                    "at normal level. See ../../27-ContentProviders/README.md for the "
                    "provider-side consequences.",
                    'Recommend android:protectionLevel="signature", and prove the current '
                    'state: declare <uses-permission android:name="%s" /> in '
                    "../examples/attacker-app/, install it, and call whatever this guards."
                    % name)
            else:
                self.add(
                    "DEFINES A GATE", "NARROWED",
                    "permission %s" % name,
                    'protectionLevel="%s"%s'
                    % (level, " -- guards: " + ", ".join(users) if users else ""),
                    "A signature-anchored custom permission is the correct way to let a "
                    "sibling app in without dissolving the UID boundary with sharedUserId. "
                    "Say so in the report -- it is the remediation you would otherwise be "
                    "recommending.",
                    "Confirm no other app can obtain it: `adb shell pm list permissions -f "
                    "-g | grep -A4 %s`." % name)

    # -- 6. package visibility -----------------------------------------------

    def check_queries(self):
        qs = list(self.root.iter("queries"))
        has_qap = any(u.get(NS + "name") == "android.permission.QUERY_ALL_PACKAGES"
                      for u in self.root.iter("uses-permission"))
        if not qs:
            if not has_qap:
                self.add(
                    "VISIBILITY", "NARROWED",
                    "<queries> (absent)",
                    "The app declares no package-visibility needs.",
                    "Package visibility filtering is one of the sandbox's seven mechanisms: "
                    "an app cannot see what it has not declared an interest in. Declaring "
                    "nothing is the tightest state.",
                    "None. If the app nonetheless enumerates packages at runtime, that is "
                    "the finding -- hook getInstalledPackages and watch.")
            return

        pkgs, intents, auths = [], [], []
        for q in qs:
            for c in q.findall("package"):
                v = c.get(NS + "name")
                if v:
                    pkgs.append(v)
            for c in q.findall("intent"):
                acts = [a.get(NS + "name") for a in c.findall("action") if a.get(NS + "name")]
                intents.extend(acts)
            for c in q.findall("provider"):
                v = c.get(NS + "authorities")
                if v:
                    auths.append(v)

        detail = "packages=%d, intent filters=%d, providers=%d" % (
            len(pkgs), len(intents), len(auths))
        sample = ", ".join(pkgs[:6]) + (", and %d more" % (len(pkgs) - 6) if len(pkgs) > 6 else "")

        self.add(
            "VISIBILITY", "CONTEXT",
            "<queries>",
            "%s%s" % (detail, (" -- " + sample) if sample else ""),
            "This block is a statement of intent and one of the most informative things in "
            "the manifest. It names precisely which other apps this one wants to see "
            "through the visibility filter. A list of root-manager package names is root "
            "detection declared in XML; a list of banking apps in a non-banking app is "
            "something worse; a list of competitors is telemetry. Note the inverse too: an "
            "app that queries a package it never names here cannot see it, which is why a "
            "probe APK that skips <queries> silently returns wrong results.",
            "Read every entry and classify it. Cross-check against the code with `grep -rn "
            "\"getInstalledPackages\\|getPackageInfo\\|resolveActivity\\|queryIntentActivities\" "
            "out/sources/`, and remember to mirror this block into "
            "../examples/attacker-app/ before concluding that a package is invisible.")

        if has_qap:
            self.add(
                "VISIBILITY", "WIDENED",
                "<queries> plus QUERY_ALL_PACKAGES",
                "The declared list is decorative -- the permission supersedes it.",
                "With QUERY_ALL_PACKAGES held, the visibility filter is off entirely and "
                "the <queries> block constrains nothing.",
                "Report the permission, not the block. Confirm it is actually granted: "
                "`adb shell dumpsys package %s | grep QUERY_ALL_PACKAGES`." % self.pkg)

    # -- driver ---------------------------------------------------------------

    def run(self):
        self.check_shared_uid()
        self.check_application_flags()
        self.check_processes()
        self.check_components()
        self.check_permissions()
        self.check_queries()
        return self.rows


# ---------------------------------------------------------------------------
#  Output -- two aligned tables, never a wall of text
# ---------------------------------------------------------------------------

def _fit(text, width):
    text = " ".join(str(text).split())
    if len(text) <= width:
        return text
    return text[:width - 3] + "..."


def _fit_tail(text, width):
    """
    Truncate from the LEFT. A component's identity is its class name, which
    lives at the END of a fully-qualified name, so chopping the tail off
    'activity com.example.target.DeepLinkActivity' makes three different rows
    print identically -- which is exactly the failure this script exists to fix.
    """
    text = " ".join(str(text).split())
    if len(text) <= width:
        return text
    return "..." + text[-(width - 3):]


def _wrap(text, width, indent):
    text = " ".join(str(text).split())
    return textwrap.wrap(text, width=width, initial_indent=indent,
                         subsequent_indent=indent) or [indent]


def render_text(rows, exp, width=100, detail=True):
    out = []
    bar = "=" * width
    rule = "-" * width

    out.append(bar)
    out.append("  SANDBOX EXPOSURE -- %s" % exp.pkg)
    out.append(bar)
    out.append("  manifest   : %s" % exp.path)
    out.append("  components : %d declared, %d exported, %d export state unresolved"
               % (exp.counts["components"], exp.counts["exported"], exp.counts["unresolved"]))
    tally = {}
    for r in rows:
        tally[r.verdict] = tally.get(r.verdict, 0) + 1
    out.append("  verdicts   : " + ", ".join("%s %d" % (v, tally[v])
                                             for v in VERDICTS if v in tally))
    out.append("")

    # Table 1 -- the observation.
    w_eff, w_ver, w_where = 18, 14, 36
    w_what = max(20, width - (w_eff + w_ver + w_where + 4 + 6))
    out.append(rule)
    out.append("  %-3s %-*s %-*s %-*s %s"
               % ("#", w_eff, "SANDBOX EFFECT", w_ver, "VERDICT",
                  w_where, "WHERE", "WHAT WAS SEEN"))
    out.append(rule)
    for i, r in enumerate(rows, 1):
        out.append("  %-3d %-*s %-*s %-*s %s"
                   % (i, w_eff, _fit(r.effect, w_eff), w_ver, _fit(r.verdict, w_ver),
                      w_where, _fit_tail(r.where, w_where), _fit(r.what, w_what)))
    out.append(rule)
    out.append("")

    # Table 2 -- the next step. Same row numbers.
    out.append(rule)
    out.append("  %-3s %-*s %s" % ("#", w_ver, "VERDICT", "NEXT STEP"))
    out.append(rule)
    for i, r in enumerate(rows, 1):
        head = "  %-3d %-*s " % (i, w_ver, _fit(r.verdict, w_ver))
        pad = " " * len(head)
        wrapped = _wrap(r.step, width - len(head), "")
        out.append(head + wrapped[0])
        for line in wrapped[1:]:
            out.append(pad + line)
    out.append(rule)
    out.append("")

    if detail:
        out.append("  WHY EACH ROW MATTERS TO THE BOUNDARY")
        out.append(rule)
        for i, r in enumerate(rows, 1):
            out.append("  [%d] %s -- %s" % (i, r.verdict, r.where))
            out.append("      %s" % _fit(r.what, width - 8))
            for line in _wrap(r.why, width - 6, ""):
                out.append("      " + line)
            out.append("")

    out.append(rule)
    out.append("  Nothing above is proven. Every WIDENED and BREACHED row is a declaration,")
    out.append("  not an experiment. `adb shell` is UID 2000 and holds privileges no app has,")
    out.append("  so reaching a component from a shell is not a finding. Re-test from")
    out.append("  ../examples/attacker-app/ and report the two results as separate claims.")
    out.append("")
    out.append("  This is the SANDBOX view. For the full declaration audit and the targetSdk")
    out.append("  version matrix, run 32-Manifest/scripts/manifest-audit.py on the same file.")
    out.append(rule)
    return "\n".join(out)


def render_markdown(rows, exp):
    out = []
    out.append("# Sandbox exposure -- `%s`" % exp.pkg)
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append("| Manifest | `%s` |" % exp.path)
    out.append("| Components | %d declared, **%d exported**, %d unresolved |"
               % (exp.counts["components"], exp.counts["exported"], exp.counts["unresolved"]))
    out.append("")
    out.append("## What the manifest does to the UID boundary")
    out.append("")
    out.append("| # | Sandbox effect | Verdict | Where | What was seen |")
    out.append("|---|---|---|---|---|")
    for i, r in enumerate(rows, 1):
        out.append("| %d | %s | **%s** | `%s` | %s |"
                   % (i, r.effect, r.verdict, r.where,
                      " ".join(str(r.what).split()).replace("|", "\\|")))
    out.append("")
    out.append("## Next step for each row")
    out.append("")
    out.append("| # | Verdict | Next step |")
    out.append("|---|---|---|")
    for i, r in enumerate(rows, 1):
        out.append("| %d | %s | %s |"
                   % (i, r.verdict, " ".join(str(r.step).split()).replace("|", "\\|")))
    out.append("")
    out.append("## Why each row matters")
    out.append("")
    for i, r in enumerate(rows, 1):
        out.append("**%d. [%s] %s** -- %s"
                   % (i, r.verdict, r.where, " ".join(str(r.what).split())))
        out.append("")
        out.append(" ".join(str(r.why).split()))
        out.append("")
    out.append("---")
    out.append("")
    out.append("Nothing above is proven. Every `WIDENED` and `BREACHED` row is a declaration, "
               "not an experiment, and `adb shell` holds privileges no app does. Re-test from "
               "the probe app before reporting.")
    out.append("")
    out.append("This is the sandbox view of the manifest. For the full declaration audit and "
               "the targetSdk version matrix, run chapter 32's `manifest-audit.py` on the same "
               "file.")
    return "\n".join(out)


# ---------------------------------------------------------------------------
#  main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Read a decoded AndroidManifest.xml as a statement about the app "
                    "sandbox: what shares the UID, what widens reach across the boundary, "
                    "what breaches it, and what narrows it.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Chapter 21 owns the sandbox view. Chapter 32's manifest-audit.py owns the "
               "declaration audit and the targetSdk version matrix. Run both.")
    ap.add_argument("manifest",
                    help="Path to a decoded AndroidManifest.xml (apktool output or Gradle "
                         "source). Use '-' for stdin.")
    ap.add_argument("--exported-only", action="store_true",
                    help="Only the exported-component rows (README section 5.3).")
    ap.add_argument("--verdict", nargs="+", choices=VERDICTS, default=None,
                    help="Only rows with these verdicts.")
    ap.add_argument("--no-detail", action="store_true",
                    help="Tables only; omit the per-row explanation block.")
    ap.add_argument("--markdown", action="store_true", help="Emit Markdown.")
    ap.add_argument("--width", type=int, default=100, help="Text output width.")
    args = ap.parse_args(argv)

    if args.manifest == "-":
        data = sys.stdin.read()
        shown = "<stdin>"
    else:
        if not os.path.isfile(args.manifest):
            sys.stderr.write("[-] no such file: %s\n" % args.manifest)
            return 2
        with open(args.manifest, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
        shown = args.manifest

    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        sys.stderr.write("[-] not parseable as XML: %s\n" % exc)
        sys.stderr.write("    This script reads DECODED XML. If you passed the binary\n"
                         "    AndroidManifest.xml straight out of the APK, decode it first:\n"
                         "        apktool d -f target.apk -o out/\n")
        return 2

    tag = root.tag.split("}")[-1]
    if tag != "manifest":
        sys.stderr.write("[-] root element is <%s>, expected <manifest>\n" % tag)
        return 2

    exp = Exposure(root, shown)
    rows = exp.run()

    if args.exported_only:
        rows = [r for r in rows if r.effect in ("WIDENS REACH",) and
                (" " in r.where and r.where.split(" ")[0] in COMPONENT_TAGS)]
    if args.verdict:
        rows = [r for r in rows if r.verdict in args.verdict]

    rows.sort(key=lambda r: (VRANK[r.verdict], r.where))

    if args.markdown:
        print(render_markdown(rows, exp))
    else:
        print(render_text(rows, exp, width=args.width, detail=not args.no_detail))
    return 0


if __name__ == "__main__":
    sys.exit(main())
