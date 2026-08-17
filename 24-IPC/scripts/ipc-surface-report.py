#!/usr/bin/env python3
"""
ipc-surface-report.py — turn raw IPC enumeration into a prioritised, severity-
rated report.

WHAT IT DOES
    Consumes the output of enumerate-ipc-surface.sh (the combined
    ipc-surface.txt, whose "### SECTION: NAME" markers are its input format),
    optionally cross-checks it against a decompiled AndroidManifest.xml, and
    emits an ordered list of candidate findings. Each one carries:

        severity        rated by what the channel EXPOSES, not by its existence
        prerequisite    what the attacker needs — usually "nothing"
        evidence        the exact lines from the enumeration that support it
        why it happens  the developer mistake behind the pattern
        verify          the command that turns a candidate into a finding
        rule out        what would make this NOT a finding

    Output is Markdown by default, or JSON for pipelines.

WHY IT MATTERS
    An enumeration dump is a wall of text in which the three things that matter
    — an abstract socket, a listener on 0.0.0.0, an exported provider with no
    permission — sit next to two hundred lines of noise. Triage by scrolling is
    slow and it misses things.

    More importantly, this tool is deliberately opinionated about severity in
    the direction of RESTRAINT. It rates a channel by what it exposes, and it
    prints, for every candidate, the specific observation that would demote it
    to "not a finding". Inflating severity is the fastest way to have a whole
    report dismissed, and an abstract socket that returns a version string is
    not Critical however exciting the mechanism is.

    Nothing here is a finding until you have proved reachability from an
    ordinary application. The report says so, on every page, by design.

    See ../README.md sections 3.22 and 8.3.

HOW TO RUN
    # host
    ./enumerate-ipc-surface.sh com.example.target ./out
    python3 ipc-surface-report.py ./out/ipc-surface.txt

    python3 ipc-surface-report.py ./out/ipc-surface.txt --md report.md
    python3 ipc-surface-report.py ./out/ipc-surface.txt --json findings.json
    python3 ipc-surface-report.py ./out/ipc-surface.txt \\
        --manifest work/AndroidManifest.xml
    python3 ipc-surface-report.py ./out/ipc-surface.txt --min-severity High

REQUIREMENTS
    Python 3.8+, standard library only. No third-party modules, so it runs on a
    locked-down engagement laptop.

AUTHORISED TESTING ONLY.
"""

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #

class Finding(object):
    def __init__(self, title, severity, category, prerequisite,
                 why, verify, rule_out, evidence=None, reference=""):
        self.title = title
        self.severity = severity
        self.category = category
        self.prerequisite = prerequisite
        self.why = why
        self.verify = verify
        self.rule_out = rule_out
        self.evidence = evidence or []
        self.reference = reference

    def rank(self):
        try:
            return SEVERITY_ORDER.index(self.severity)
        except ValueError:
            return len(SEVERITY_ORDER)

    def to_dict(self):
        return {
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "prerequisite": self.prerequisite,
            "why_developers_write_it": self.why,
            "verify": self.verify,
            "rule_out": self.rule_out,
            "evidence": self.evidence,
            "reference": self.reference,
        }


# --------------------------------------------------------------------------- #
# Input parsing
# --------------------------------------------------------------------------- #

def parse_sections(path):
    """Split the enumeration output into {SECTION_NAME: [lines]}."""
    sections, current = {}, "PREAMBLE"
    sections[current] = []
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                m = re.match(r"^### SECTION:\s*(\S+)", line)
                if m:
                    current = m.group(1)
                    sections.setdefault(current, [])
                    continue
                if line.startswith("### END"):
                    current = "END"
                    sections.setdefault(current, [])
                    continue
                sections[current].append(line)
    except OSError as exc:
        sys.stderr.write("cannot read %s: %s\n" % (path, exc))
        sys.exit(2)
    return sections


def meta_value(sections, key):
    for line in sections.get("META", []):
        if line.startswith(key):
            return line.split(":", 1)[1].strip() if ":" in line else ""
    return "unknown"


# --------------------------------------------------------------------------- #
# Analysers — one per mechanism
# --------------------------------------------------------------------------- #

def analyse_abstract_sockets(sections):
    """
    Abstract-namespace UNIX sockets.

    Rated High by default, because there is NO access control on them at all:
    no inode, no owner, no group, no mode bits — not even a permission to get
    wrong. Any app in the same network namespace, which is every app on the
    device, can connect if it knows the name.

    Demoted to Low when the protocol turns out to expose nothing. Promoted to
    Critical when it yields auth material or an arbitrary file write. The tool
    cannot know which; it says so and tells you how to find out.
    """
    out = []
    lines = sections.get("UNIX-ABS", []) + sections.get("FINDINGS", [])
    names = set()
    for line in lines:
        for m in re.finditer(r"@([A-Za-z0-9_.:\-]{3,})", line):
            names.add(m.group(1))

    for name in sorted(names):
        low = name.lower()
        if "devtools" in low or "chrome_devtools" in low:
            out.append(Finding(
                title="Chrome DevTools Protocol exposed on abstract socket @%s" % name,
                severity="High",
                category="Abstract UNIX socket",
                prerequisite="Nothing. No permission of any kind.",
                why=("WebView.setWebContentsDebuggingEnabled(true) was called "
                     "unconditionally instead of being gated on "
                     "BuildConfig.DEBUG. It is documented as a developer "
                     "convenience for chrome://inspect over USB, which makes it "
                     "sound harmless. The socket it opens is in the abstract "
                     "namespace, so a malicious app on the same device can "
                     "attach to it too."),
                verify=("python3 abstract-socket-probe.py --name %s "
                        "--send 'GET /json/version HTTP/1.1\\r\\nHost: x\\r\\n'"
                        % name),
                rule_out=("Not a finding if the socket exists only in a debug "
                          "build that is never shipped. Confirm against the "
                          "RELEASE APK from the store, not your local build."),
                evidence=[l for l in lines if name in l][:4],
                reference="README 3.10, 43-WebView"))
        else:
            out.append(Finding(
                title="Abstract-namespace UNIX socket @%s" % name,
                severity="High",
                category="Abstract UNIX socket",
                prerequisite="Nothing. No permission of any kind.",
                why=("android.net.LocalServerSocket's single-string constructor "
                     "selects the ABSTRACT namespace. It is the shortest thing "
                     "that compiles for cross-process IPC, AIDL feels heavy by "
                     "comparison, and nothing in the API, the Javadoc or the "
                     "IDE warns that the name lives in a device-global "
                     "namespace. During development the only client is the "
                     "developer's own code, so nothing contradicts the mental "
                     "model 'this is my app's private channel'."),
                verify=("python3 abstract-socket-probe.py --name %s --probe-all\n"
                        "  then reproduce from ../examples/attacker-app/, which "
                        "runs as an ordinary app UID" % name),
                rule_out=("Demote to Low if the protocol only exposes benign "
                          "data — a version string, a heartbeat. Report it as a "
                          "hardening item, not a vulnerability. Also confirm "
                          "SELinux actually permits untrusted_app -> this "
                          "socket on every Android version in scope; shell can "
                          "reach things an app cannot."),
                evidence=[l for l in lines if name in l][:4],
                reference="README 3.10"))
    return out


def analyse_listeners(sections):
    """Localhost and all-interface TCP listeners."""
    out = []
    seen = set()
    for line in sections.get("TCP", []) + sections.get("FINDINGS", []):
        m = re.search(r"(\d+\.\d+\.\d+\.\d+|\[::\]):(\d+)", line)
        if not m:
            continue
        addr, port = m.group(1), m.group(2)
        key = addr + ":" + port
        if key in seen:
            continue
        seen.add(key)
        uidm = re.search(r"uid=(\d+)", line)
        uid = uidm.group(1) if uidm else "?"

        if addr in ("0.0.0.0", "[::]"):
            out.append(Finding(
                title="Service listening on ALL INTERFACES at %s (uid %s)" % (key, uid),
                severity="High",
                category="Network listener",
                prerequisite=("On-device: the INTERNET permission, which is "
                              "protectionLevel=normal, granted silently at "
                              "install to essentially every app. Off-device: "
                              "presence on the same network. No malicious app "
                              "needed at all."),
                why=("new ServerSocket(port) and NanoHTTPD(int port) both bind "
                     "0.0.0.0 by default. The developer wrote 'it's only local' "
                     "and was wrong twice: loopback is not a trust boundary, "
                     "and this is not even loopback."),
                verify=("# adb shell\n"
                        "  curl -s http://127.0.0.1:%s/\n"
                        "# host — from a laptop on the same WiFi\n"
                        "  curl -s http://<device-ip>:%s/" % (port, port)),
                rule_out=("Demote if the server only serves already-public "
                          "media bytes and has no side-effecting routes. State "
                          "the port, the binding address and the exact request "
                          "you used."),
                evidence=[line.strip()],
                reference="README 3.11"))
        elif addr in ("127.0.0.1", "[::1]"):
            out.append(Finding(
                title="Loopback listener at %s (uid %s)" % (key, uid),
                severity="High",
                category="Network listener",
                prerequisite=("The INTERNET permission — protectionLevel=normal, "
                              "granted silently at install, never shown to the "
                              "user, held by essentially every app. Treat it as "
                              "free."),
                why=("A local HTTP server is a genuinely convenient bridge: it "
                     "lets a WebView load app-generated content over http:// so "
                     "relative URLs and XHR behave normally, it lets ExoPlayer "
                     "consume a stream the app produces, and it lets QA poke at "
                     "internal state from a browser. The failure is the "
                     "assumption that loopback is a trust boundary. It is a "
                     "shared bus."),
                verify=("# adb shell\n"
                        "  curl -s http://127.0.0.1:%s/\n"
                        "  curl -s 'http://127.0.0.1:%s/?path=/data/data/<pkg>/"
                        "shared_prefs/session.xml'\n"
                        "then reproduce from ../examples/attacker-app/ "
                        "(--es only localhost)" % (port, port)),
                rule_out=("Not a finding if every route is authenticated with a "
                          "high-entropy per-launch secret AND the Host header "
                          "is validated. Also check CORS and Host handling: a "
                          "browser-reachable localhost service is exploitable "
                          "by DNS rebinding with no app involved."),
                evidence=[line.strip()],
                reference="README 3.11"))
    return out


def analyse_world_sockets(sections):
    """Filesystem sockets with permissive modes."""
    out = []
    for line in sections.get("FINDINGS", []) + sections.get("UNIX-FS", []):
        if "0666" in line or "rw-rw-rw-" in line:
            path = line.strip().split()[-1]
            out.append(Finding(
                title="World-accessible filesystem UNIX socket (%s)" % path,
                severity="High",
                category="Filesystem UNIX socket",
                prerequisite=("Whatever SELinux permits. The DAC mode bits — "
                              "the only discretionary control a filesystem "
                              "socket has — are wide open."),
                why=("The socket was created outside the app's private data "
                     "directory, often by a native helper binary that chmods "
                     "its own endpoint to 0666 so 'the app can reach it'. That "
                     "also lets everything else reach it."),
                verify=("# adb shell\n  ls -lZ %s\n"
                        "then connect and speak the protocol" % path),
                rule_out=("Check the SELinux label as well as the mode. A "
                          "permissive mode with a restrictive type may still be "
                          "unreachable from untrusted_app — which is exactly "
                          "why the APK test is required."),
                evidence=[line.strip()],
                reference="README 3.9"))
    return out


def analyse_components(sections, manifest_path):
    """Exported components, preferring the manifest when one is supplied."""
    out = []

    if manifest_path and os.path.exists(manifest_path):
        out.extend(analyse_manifest(manifest_path))
        return out

    # Fall back to the dumpsys view captured by the enumeration script.
    comp_lines = sections.get("COMPONENTS", [])
    exported = [l for l in comp_lines if "exported=true" in l]
    if exported:
        no_perm = [l for l in exported if "permission=" not in l]
        out.append(Finding(
            title="%d exported components, %d with no guarding permission"
                  % (len(exported), len(no_perm)),
            severity="High" if no_perm else "Medium",
            category="Exported component",
            prerequisite="Nothing. Any installed app can address them.",
            why=("Components get exported to make something work — a "
                 "SecurityException appears during development, "
                 "android:exported=\"true\" makes it go away, and the component "
                 "is public forever. Adding an intent-filter so the app appears "
                 "in the share sheet has the same effect silently."),
            verify=("Exercise each from adb shell, then reproduce from\n"
                    "  ../examples/attacker-app/ (--es only activities,services,"
                    "receivers,providers)\n"
                    "and build the side-by-side reachability table."),
            rule_out=("A component guarded by a signature-level permission is "
                      "not reachable by a third party. Check the "
                      "protectionLevel of every guard — normal and dangerous "
                      "are not controls."),
            evidence=[l.strip() for l in no_perm[:12]],
            reference="README 3.4, 3.22"))
    return out


def analyse_manifest(path):
    """Static complement: read a decompiled AndroidManifest.xml properly."""
    out = []
    try:
        tree = ET.parse(path)
    except Exception as exc:
        sys.stderr.write("warning: cannot parse %s: %s\n" % (path, exc))
        return out
    root = tree.getroot()
    app = root.find("application")
    if app is None:
        return out

    def attr(el, name):
        return el.get(ANDROID_NS + name)

    perms = {}
    for p in root.findall("permission"):
        perms[attr(p, "name")] = attr(p, "protectionLevel") or "normal"

    for tag, kind in (("activity", "Activity"), ("activity-alias", "Activity alias"),
                      ("service", "Service"), ("receiver", "Receiver"),
                      ("provider", "Provider")):
        for el in app.findall(tag):
            name = attr(el, "name")
            exported = attr(el, "exported")
            guard = attr(el, "permission") or attr(el, "readPermission")
            has_filter = el.find("intent-filter") is not None

            effective = (exported == "true") or (exported is None and has_filter)
            if not effective:
                continue

            level = perms.get(guard, "") if guard else ""
            weak = (guard is None) or ("signature" not in (level or ""))

            if not weak:
                continue

            sev = "High"
            extra = ""
            if tag == "provider":
                sev = "Critical"
                extra = (" A provider usually sits directly on a database, so "
                         "an unguarded one is a direct read of app data, plus "
                         "SQL-injection and openFile-traversal surface.")
                if attr(el, "grantUriPermissions") == "true":
                    extra += (" grantUriPermissions=\"true\" also makes it a "
                              "URI-grant-theft target through any exported "
                              "component that forwards Intents.")

            out.append(Finding(
                title="Exported %s with no effective permission: %s"
                      % (kind, name),
                severity=sev,
                category="Exported component",
                prerequisite="Nothing." + (
                    " (declared permission %s is protectionLevel=%s, which any "
                    "app can hold)" % (guard, level or "unknown")
                    if guard else ""),
                why=("Either exported deliberately for an integration and never "
                     "narrowed, or exported implicitly by the presence of an "
                     "intent-filter on a targetSdk below 31 where an explicit "
                     "attribute was not yet mandatory." + extra),
                verify=("# adb shell\n  am start -n <pkg>/%s --es url "
                        "https://attacker.example/\n"
                        "then the same from ../examples/attacker-app/" % name),
                rule_out=("Not a finding if the component does nothing with its "
                          "input and reaches nothing sensitive. Walk the "
                          "reach-through before assigning severity."),
                evidence=["<%s android:name=\"%s\" android:exported=\"%s\" "
                          "permission=\"%s\">" % (tag, name, exported, guard)],
                reference="README 3.22 step 1"))

    if root.get(ANDROID_NS + "sharedUserId"):
        out.append(Finding(
            title="android:sharedUserId is declared",
            severity="High",
            category="Sandbox",
            prerequisite="Applies to every app in the shared-UID group.",
            why=("Used to solve a data-sharing problem between two apps by the "
                 "same vendor. It removes the sandbox boundary between them "
                 "entirely: same data directory, same permissions, and either "
                 "can load code into the other via createPackageContext with "
                 "CONTEXT_INCLUDE_CODE."),
            verify="# adb shell\n  pm list packages --uid <uid>",
            rule_out=("Not a finding in itself if every app in the group is in "
                      "scope and equally hardened — but say that explicitly, "
                      "and note that removing sharedUserId later is effectively "
                      "impossible without data loss. Deprecated from API 29."),
            evidence=["sharedUserId=" + root.get(ANDROID_NS + "sharedUserId")],
            reference="README 5.2.5"))
    return out


def analyse_files(sections):
    out = []
    body = sections.get("FILES", [])
    for line in body:
        if re.match(r"^\s*-rw.rw.rw-|^\s*-rw.r..r..", line) and "/data/data/" in line:
            out.append(Finding(
                title="World-readable file in the app sandbox: %s"
                      % line.strip().split()[-1],
                severity="High",
                category="Shared file",
                prerequisite=("Another app must be able to traverse the "
                              "directories above it. Check the mode of "
                              "/data/data/<pkg>/ too — 0700 mitigates, 0711 or "
                              "0755 does not."),
                why=("MODE_WORLD_READABLE throws from targetSdk 24, but "
                     "File.setReadable(true, false) and a native chmod() "
                     "produce exactly the same exposure with no exception at "
                     "all, and an app with a low targetSdk still gets the old "
                     "behaviour."),
                verify="# adb shell as root\n  ls -laZ /data/data/<pkg>",
                rule_out=("Low if the file holds only non-sensitive "
                          "configuration. Critical if it holds authentication "
                          "material. Quote the ls -la output as evidence."),
                evidence=[line.strip()],
                reference="README 3.14"))
    return out


def analyse_shm(sections):
    out = []
    body = sections.get("SHM", [])
    hits = [l for l in body if re.search(r"ashmem|memfd|dmabuf", l)]
    if hits:
        out.append(Finding(
            title="Shared memory in use (%d mappings)" % len(hits),
            severity="Informational",
            category="Shared memory",
            prerequisite=("Only a process the app sent the file descriptor to — "
                          "but that includes anyone who received it "
                          "transitively."),
            why=("Every large ContentProvider result travels through a "
                 "CursorWindow, which is ashmem, so seeing this is normal and "
                 "usually benign. It becomes a finding only when the app shares "
                 "a WRITABLE region and then makes a decision by re-reading it."),
            verify=("Look for MemoryFile / SharedMemory / memfd_create in the "
                    "decompiled sources, and check whether any check-then-use "
                    "pattern re-reads the shared bytes after validating them."),
            rule_out=("Not a finding on its own. Framework use of ashmem for "
                      "CursorWindow is expected on every app."),
            evidence=[l.strip() for l in hits[:6]],
            reference="README 3.13"))
    return out


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

PREAMBLE = """\
> **This report lists CANDIDATES, not findings.**
>
> Every observation below was collected from `adb shell`, which runs as UID 2000
> in the SELinux domain `shell` and holds privileges no installed application
> has. It proves that a channel **exists**. It does **not** prove that an
> unprivileged app can **use** it.
>
> Nothing here becomes a finding until it has been reproduced from an ordinary
> application UID — see `../examples/attacker-app/` — and until the
> reach-through has been walked: *what can I make this component do that I could
> not do directly?* A door is only as serious as the room behind it.
"""


def render_markdown(findings, sections, args):
    pkg = meta_value(sections, "package")
    lines = []
    lines.append("# IPC attack surface — %s" % pkg)
    lines.append("")
    lines.append(PREAMBLE)
    lines.append("")
    lines.append("## Ground truth")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    for key in ("package", "uid", "pid", "android release", "sdk",
                "security patch", "fingerprint", "selinux", "root available"):
        lines.append("| %s | `%s` |" % (key, meta_value(sections, key)))
    lines.append("")
    lines.append("Record all of it. The app's `targetSdk` — not the device's "
                 "SDK level — decides which platform mitigations apply, and "
                 "half of Android's IPC hardening is `targetSdk`-gated.")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in SEVERITY_ORDER:
        n = len([f for f in findings if f.severity == sev])
        if n:
            lines.append("| %s | %d |" % (sev, n))
    lines.append("")
    if not findings:
        lines.append("No candidates identified. That is a legitimate result — "
                     "but confirm the app was **running** when the enumeration "
                     "ran, because sockets opened lazily do not exist until the "
                     "code path executes.")
        lines.append("")

    for i, f in enumerate(findings, 1):
        lines.append("---")
        lines.append("")
        lines.append("## %d. %s" % (i, f.title))
        lines.append("")
        lines.append("**Severity (provisional):** %s  " % f.severity)
        lines.append("**Category:** %s  " % f.category)
        lines.append("**Attacker prerequisite:** %s" % f.prerequisite)
        lines.append("")
        if f.evidence:
            lines.append("**Evidence**")
            lines.append("")
            lines.append("```text")
            for e in f.evidence:
                lines.append(e)
            lines.append("```")
            lines.append("")
        lines.append("**Why developers write this**")
        lines.append("")
        lines.append(f.why)
        lines.append("")
        lines.append("**How to verify (this is the step that makes it real)**")
        lines.append("")
        lines.append("```bash")
        for v in f.verify.split("\n"):
            lines.append(v)
        lines.append("```")
        lines.append("")
        lines.append("**What would rule this out**")
        lines.append("")
        lines.append(f.rule_out)
        lines.append("")
        if f.reference:
            lines.append("*Reference: %s*" % f.reference)
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Before you submit")
    lines.append("")
    lines.append("1. Reproduce every candidate from an ordinary app UID and "
                 "record the side-by-side table. Anything reachable only from "
                 "`adb shell` is a shell privilege, not an app vulnerability — "
                 "say so explicitly.")
    lines.append("2. Walk the reach-through for each surviving candidate.")
    lines.append("3. Re-rate severity from what the channel actually exposes. "
                 "An abstract socket that returns a version string is Low. An "
                 "intent redirection that reaches only already-exported "
                 "components is **not a finding**.")
    lines.append("4. Document what you considered and ruled out. The ruling-out "
                 "is what makes the rest of the report believable.")
    lines.append("5. State the `targetSdk`, the device fingerprint and the "
                 "security patch level against which each finding was proved.")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main():
    p = argparse.ArgumentParser(
        description="Turn enumerate-ipc-surface.sh output into a prioritised, "
                    "severity-rated IPC attack-surface report.")
    p.add_argument("input",
                   help="ipc-surface.txt produced by enumerate-ipc-surface.sh")
    p.add_argument("--manifest",
                   help="decompiled AndroidManifest.xml (apktool output) — "
                        "used in preference to the dumpsys view for components")
    p.add_argument("--md", metavar="FILE",
                   help="write Markdown here instead of stdout")
    p.add_argument("--json", metavar="FILE",
                   help="also write the findings as JSON")
    p.add_argument("--min-severity", choices=SEVERITY_ORDER,
                   help="suppress anything below this severity")
    args = p.parse_args()

    sections = parse_sections(args.input)

    findings = []
    findings.extend(analyse_abstract_sockets(sections))
    findings.extend(analyse_listeners(sections))
    findings.extend(analyse_world_sockets(sections))
    findings.extend(analyse_components(sections, args.manifest))
    findings.extend(analyse_files(sections))
    findings.extend(analyse_shm(sections))

    if args.min_severity:
        cutoff = SEVERITY_ORDER.index(args.min_severity)
        findings = [f for f in findings if f.rank() <= cutoff]

    findings.sort(key=lambda f: (f.rank(), f.title))

    md = render_markdown(findings, sections, args)

    if args.md:
        with open(args.md, "w") as fh:
            fh.write(md)
        print("markdown written to %s (%d candidates)" % (args.md, len(findings)))
    else:
        print(md)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([f.to_dict() for f in findings], fh, indent=2)
        print("json written to %s" % args.json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
