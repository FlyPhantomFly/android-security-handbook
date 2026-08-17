#!/usr/bin/env python3
# 55-MobSF/scripts/mobsf-validate.py
#
# PURPOSE
#   Take a MobSF static-analysis JSON report and, for every finding in it, go back to
#   the artefact and gather the evidence that would CONFIRM the finding and the evidence
#   that would KILL it. It does not decide. It produces, per finding, a normalised
#   record, whatever independent evidence it could collect, and the next step a human
#   must take.
#
#   This is stage 7 of 52-StaticAnalysis' pipeline applied to somebody else's stage 5.
#   MobSF has no stage 7. This script is the missing stage, and it is deliberately
#   conservative: the only verdicts it assigns on its own are the ones a measurement
#   settles outright.
#
# USAGE
#   python3 -B mobsf-validate.py --report report.json --apk target.apk
#   python3 -B mobsf-validate.py --report report.json --apk target.apk --tree ./out
#   python3 -B mobsf-validate.py --report report.json --apk target.apk --csv ledger.csv
#   python3 -B mobsf-validate.py --report report.json --apk target.apk --only high,warning
#   python3 -B mobsf-validate.py --report report.json --apk target.apk --quiet   # table only
#
#   A worked fixture ships next door:
#     python3 -B mobsf-validate.py \
#         --report ../examples/synthetic-mobsf-report.json --apk /path/to/CMPen-v1.2.apk
#
# REQUIREMENTS
#   Python 3.8+, standard library only.
#   Optional and used when present, in this order of preference:
#     aapt2  (Android build-tools)      - authoritative manifest parse
#     aapt   (legacy build-tools)       - same, older
#     a decompiled tree from jadx/apktool passed with --tree, for code-location checks
#   With none of the above the script still runs; it says which checks it could not make
#   instead of quietly skipping them.
#
# WHAT THIS WILL NOT TELL YOU
#   * Whether a finding is a VULNERABILITY. It gathers evidence; severity needs the asset
#     behind the construct and no file-reading tool knows the asset.
#   * Whether code is REACHABLE. There is no complete static reachability answer on
#     Android. Use 52-StaticAnalysis/scripts/validate-lead.sh --reach for a caller
#     closure, and read the four holes it prints.
#   * Anything about runtime. Receivers registered with registerReceiver(), natives bound
#     with RegisterNatives, reflective dispatch and dynamically loaded DEX are invisible
#     to the report AND to this script. It prints a blind-spot block so the absence is
#     recorded rather than assumed away.
#   * Whether the report you handed it is complete. If MobSF scanned base.apk of a split
#     application, both the report and this validation cover a fraction of the code.
#   * Whether MobSF's rule identifiers mean what you think. Schema and rule names drift
#     between MobSF versions; this parser is deliberately tolerant and tells you which
#     shape it recognised.

import argparse
import base64
import binascii
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile

# --------------------------------------------------------------------------- #
#  Verdict vocabulary. Note what is NOT here: "FINDING". A finding is written  #
#  by a person who can name the asset. This tool never promotes anything.      #
# --------------------------------------------------------------------------- #
CORROBORATED = "CORROBORATED"   # the artefact independently shows the claimed construct
REFUTED      = "REFUTED"        # a measurement contradicts the report outright
UNSUPPORTED  = "UNSUPPORTED"    # the cited evidence is not where the report says it is
UNDERRATED   = "UNDER-RATED"    # real, and the report's severity is too LOW
OVERRATED    = "OVER-RATED"     # real, and the report's severity is too HIGH
RESTATES     = "RESTATES"       # a scorecard entry duplicating another section - not a lead
NEEDS_HUMAN  = "NEEDS-HUMAN"    # no automated check applies; a next step is printed

SEV_ORDER = {"high": 0, "warning": 1, "hotspot": 2, "info": 3, "secure": 4, "": 5}


# =========================================================================== #
#  Artefact access                                                            #
# =========================================================================== #

class Artefact:
    """Read-only view of the APK plus, optionally, a decompiled tree."""

    def __init__(self, apk_path, tree=None):
        self.path = apk_path
        self.tree = tree
        self.available = os.path.isfile(apk_path) if apk_path else False
        self.notes = []
        self._names = []
        self._dex = b""
        self._manifest_text = None
        self._manifest_source = "none"
        if self.available:
            self._load()

    # -- zip ---------------------------------------------------------------- #
    def _load(self):
        try:
            with zipfile.ZipFile(self.path) as z:
                self._names = z.namelist()
                blobs = []
                for n in self._names:
                    if re.fullmatch(r"classes\d*\.dex", n):
                        blobs.append(z.read(n))
                self._dex = b"".join(blobs)
        except Exception as exc:                      # noqa: BLE001 - report, do not die
            self.notes.append("could not open the APK as a ZIP: %s" % exc)
            self.available = False

    @property
    def entries(self):
        return self._names

    @property
    def dex_bytes(self):
        return self._dex

    def has_entry(self, pattern):
        rx = re.compile(pattern)
        return [n for n in self._names if rx.search(n)]

    def read_entry(self, name):
        try:
            with zipfile.ZipFile(self.path) as z:
                return z.read(name)
        except Exception:                             # noqa: BLE001
            return b""

    # -- manifest ----------------------------------------------------------- #
    def manifest(self):
        """
        Fallback chain, and the chain reports which link answered. Copied in spirit
        from 17-Libraries/scripts/lib-inventory.sh: never assume a tool exists.
        """
        if self._manifest_text is not None:
            return self._manifest_text

        for tool, args in (
            ("aapt2", ["dump", "xmltree", "--file", "AndroidManifest.xml", self.path]),
            ("aapt", ["dump", "xmltree", self.path, "AndroidManifest.xml"]),
        ):
            exe = shutil.which(tool)
            if not exe:
                continue
            try:
                out = subprocess.run([exe] + args, capture_output=True, timeout=120)
                text = out.stdout.decode("utf-8", "replace")
                if "manifest" in text:
                    self._manifest_text = text
                    self._manifest_source = tool
                    return text
            except Exception:                         # noqa: BLE001
                continue

        # Last resort: the raw AXML blob. Strings in the pool are readable as UTF-16
        # or UTF-8 runs, which is enough for PRESENCE checks and nothing more.
        raw = self.read_entry("AndroidManifest.xml")
        if raw:
            try:
                utf16 = raw.decode("utf-16-le", "ignore")
            except Exception:                         # noqa: BLE001
                utf16 = ""
            self._manifest_text = utf16 + "\n" + raw.decode("latin-1", "ignore")
            self._manifest_source = "raw-axml (PRESENCE ONLY - attribute values are NOT parsed)"
            return self._manifest_text

        self._manifest_text = ""
        self._manifest_source = "unavailable"
        return ""

    @property
    def manifest_source(self):
        self.manifest()
        return self._manifest_source

    def manifest_parsed(self):
        """True when the manifest came from a real parser rather than the raw blob."""
        return self.manifest_source in ("aapt2", "aapt")

    # -- tree --------------------------------------------------------------- #
    def source_file(self, rel):
        """Locate a report-cited source path inside the decompiled tree."""
        if not self.tree:
            return None
        rel = rel.replace("\\", "/").lstrip("/")
        candidates = [
            os.path.join(self.tree, rel),
            os.path.join(self.tree, "sources", rel),
            os.path.join(self.tree, "smali", rel),
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
        # jadx sometimes writes .java where the report cites .kt, and vice versa
        base, ext = os.path.splitext(rel)
        for alt in (".java", ".kt", ".smali"):
            if alt == ext:
                continue
            for c in (os.path.join(self.tree, base + alt),
                      os.path.join(self.tree, "sources", base + alt)):
                if os.path.isfile(c):
                    return c
        return None

    def lines_at(self, rel, linespec, context=1):
        """Return [(lineno, text)] for the report's 'line1,line2' notation."""
        path = self.source_file(rel)
        if not path:
            return None, None
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except Exception:                             # noqa: BLE001
            return path, None
        wanted = []
        for tok in re.split(r"[,\s]+", str(linespec or "")):
            if tok.isdigit():
                wanted.append(int(tok))
        picked = []
        for n in wanted:
            lo, hi = max(1, n - context), min(len(lines), n + context)
            for i in range(lo, hi + 1):
                picked.append((i, lines[i - 1]))
        # dedupe, keep order
        seen, out = set(), []
        for i, t in picked:
            if i not in seen:
                seen.add(i)
                out.append((i, t))
        return path, out

    def grep_tree(self, pattern, limit=8):
        """Grep the decompiled tree. Returns [(relpath, lineno, text)]."""
        if not self.tree:
            return []
        rx = re.compile(pattern)
        hits = []
        for root, _dirs, files in os.walk(self.tree):
            for f in files:
                if not f.endswith((".java", ".kt", ".smali", ".xml")):
                    continue
                p = os.path.join(root, f)
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as fh:
                        for n, line in enumerate(fh, 1):
                            if rx.search(line):
                                hits.append((os.path.relpath(p, self.tree), n, line.strip()[:160]))
                                if len(hits) >= limit:
                                    return hits
                except Exception:                     # noqa: BLE001
                    continue
        return hits

    def grep_dex(self, pattern, limit=8):
        """Grep the concatenated DEX blobs. Survives obfuscation; sees no line numbers."""
        if not self._dex:
            return []
        try:
            rx = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
        except re.error:
            return []
        return [m.decode("latin-1") for m in rx.findall(self._dex)][:limit]


# =========================================================================== #
#  Report normalisation                                                       #
# =========================================================================== #

class Finding:
    __slots__ = ("fid", "section", "rule", "title", "severity", "cvss",
                 "components", "locations", "raw")

    def __init__(self, fid, section, rule, title, severity, cvss, components, locations, raw):
        self.fid = fid
        self.section = section
        self.rule = rule
        self.title = title
        self.severity = (severity or "").lower()
        self.cvss = cvss
        self.components = components or []
        self.locations = locations or []      # [(relpath, linespec)]
        self.raw = raw


def _txt(v):
    if isinstance(v, str):
        return v
    if isinstance(v, (list, tuple)):
        return " ".join(_txt(x) for x in v)
    return "" if v is None else str(v)


def normalise(report):
    """
    Flatten a MobSF report into Finding records.

    MobSF's schema has changed shape more than once: manifest_analysis has been a
    bare list and a dict with a 'manifest_anal' key; certificate findings have been
    3-tuples and dicts; code_analysis has been a flat map and a {findings, summary}
    pair. This walker accepts all of those and RECORDS which shape it saw, because
    "the two runs disagree" usually means "the two runs were different versions".
    """
    out, shapes, n = [], [], 0

    def nid():
        nonlocal n
        n += 1
        return "V%03d" % n

    # ---- manifest ---------------------------------------------------------- #
    ma = report.get("manifest_analysis")
    items = []
    if isinstance(ma, dict):
        items = ma.get("manifest_anal") or ma.get("manifest_findings") or []
        shapes.append("manifest_analysis: dict")
    elif isinstance(ma, list):
        items = ma
        shapes.append("manifest_analysis: list")
    for it in items:
        if not isinstance(it, dict):
            continue
        out.append(Finding(
            nid(), "manifest", it.get("rule", ""),
            it.get("title") or it.get("name") or "",
            it.get("severity", ""), None,
            it.get("component") if isinstance(it.get("component"), list) else [_txt(it.get("component"))],
            [], it))

    # ---- certificate ------------------------------------------------------- #
    ca = report.get("certificate_analysis")
    if isinstance(ca, dict):
        cf = ca.get("certificate_findings") or ca.get("certificate_summary_findings") or []
        shapes.append("certificate_analysis: dict")
        for it in cf:
            if isinstance(it, (list, tuple)) and len(it) >= 2:
                sev, desc = it[0], it[1]
                title = it[2] if len(it) > 2 else desc
                out.append(Finding(nid(), "certificate", "", _txt(title), _txt(sev), None, [], [],
                                   {"description": _txt(desc)}))
            elif isinstance(it, dict):
                out.append(Finding(nid(), "certificate", it.get("rule", ""),
                                   it.get("title") or it.get("name") or "",
                                   it.get("severity", ""), None, [], [], it))

    # ---- code -------------------------------------------------------------- #
    ce = report.get("code_analysis")
    findings = {}
    if isinstance(ce, dict):
        findings = ce.get("findings") if isinstance(ce.get("findings"), dict) else \
                   {k: v for k, v in ce.items() if k != "summary"}
        shapes.append("code_analysis: dict")
    for title, body in (findings or {}).items():
        if not isinstance(body, dict):
            continue
        meta = body.get("metadata") if isinstance(body.get("metadata"), dict) else body
        files = body.get("files") if isinstance(body.get("files"), dict) else {}
        locs = [(p, l) for p, l in files.items()]
        out.append(Finding(nid(), "code", meta.get("cwe", ""), title,
                           meta.get("severity", ""), meta.get("cvss"), [], locs, meta))

    # ---- network security config ------------------------------------------- #
    ns = report.get("network_security")
    nf = []
    if isinstance(ns, dict):
        nf = ns.get("network_findings") or []
        shapes.append("network_security: dict")
    elif isinstance(ns, list):
        nf = ns
        shapes.append("network_security: list")
    for it in nf:
        if isinstance(it, dict):
            out.append(Finding(nid(), "network", "", _txt(it.get("description") or it.get("title")),
                               it.get("severity", ""), None, it.get("scope") or [], [], it))

    # ---- binary (native libraries) ----------------------------------------- #
    for it in report.get("binary_analysis") or []:
        if isinstance(it, dict):
            name = it.get("name") or it.get("file") or ""
            for key in ("nx", "pie", "stack_canary", "relro", "rpath", "runpath",
                        "fortify", "symbol"):
                sub = it.get(key)
                if isinstance(sub, dict) and sub.get("severity"):
                    out.append(Finding(nid(), "binary", key,
                                       "%s: %s" % (name, sub.get("description", key)),
                                       sub.get("severity", ""), None, [name], [], sub))

    # ---- secrets ----------------------------------------------------------- #
    for s in report.get("secrets") or []:
        out.append(Finding(nid(), "secrets", "hardcoded-secret",
                           _txt(s), "warning", None, [], [], {"value": _txt(s)}))

    # ---- appsec scorecard -------------------------------------------------- #
    ap = report.get("appsec")
    if isinstance(ap, dict):
        shapes.append("appsec: dict")
        for band in ("high", "warning", "info", "secure", "hotspot"):
            for it in ap.get(band) or []:
                if isinstance(it, dict):
                    out.append(Finding(nid(), "appsec:" + (it.get("section") or "?"),
                                       "", it.get("title", ""), band, None, [], [], it))

    return out, shapes


# =========================================================================== #
#  Evidence gatherers                                                         #
# =========================================================================== #

class Evidence:
    def __init__(self):
        self.for_ = []
        self.against = []
        self.verdict = NEEDS_HUMAN
        self.next_step = ""
        self.note = ""

    def yes(self, s):
        self.for_.append(s)

    def no(self, s):
        self.against.append(s)


B64_RX = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
PIN_RX = r"sha256/[A-Za-z0-9+/]{43}="
HEX_RX = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


def classify_secret(value):
    """
    Say what a 'hardcoded secret' string ACTUALLY is. This single function kills
    more MobSF secret findings than every other check in this file combined.
    """
    v = value.strip().strip('"').strip("'")
    if re.fullmatch(PIN_RX, v):
        return ("SPKI pin", "a base64 SHA-256 of a public key. Public by construction: "
                            "it is published in every TLS handshake. Not a secret.")
    if v.startswith(("http://", "https://")):
        return ("URL", "an endpoint, not a credential. Belongs in the endpoint inventory.")
    if HEX_RX.fullmatch(v):
        bits = len(v) * 4
        return ("%d-bit hex" % bits,
                "hex of that length is usually a DIGEST, not a key. If it is a password "
                "hash, the finding is the algorithm and the absence of a salt, not the value.")
    if B64_RX.fullmatch(v) and len(v) % 4 == 0:
        try:
            dec = base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError):
            return ("base64-shaped", "does not decode. Shape only.")
        printable = sum(1 for b in dec if 32 <= b < 127 or b in (9, 10, 13))
        ratio = printable / max(1, len(dec))
        if ratio > 0.9:
            try:
                text = dec.decode("utf-8", "replace")
            except Exception:                         # noqa: BLE001
                text = ""
            return ("base64 of TEXT", "decodes to: %r - read it before you name it." % text[:90])
        return ("base64 of BINARY",
                "decodes to %d high-entropy bytes; probably ciphertext or a key blob. "
                "Ciphertext in the artefact is only a finding if the key is too." % len(dec))
    if len(v) < 8:
        return ("short literal", "too short to be a credential of any kind.")
    return ("unclassified", "no automatic classification; open the site and read it.")


def check_manifest_claim(f, art, ev):
    """Re-derive a manifest claim from the platform's own parser."""
    m = art.manifest()
    if not m:
        ev.note = "no manifest available"
        ev.next_step = "aapt2 dump xmltree --file AndroidManifest.xml <apk>"
        return
    if not art.manifest_parsed():
        ev.note = ("manifest read as raw AXML (%s); presence checks only"
                   % art.manifest_source)

    t = f.title.lower()

    # allowBackup ---------------------------------------------------------- #
    if "backed up" in t or "allowbackup" in t:
        if re.search(r"allowBackup\S*\)?=true", m) or re.search(r"allowBackup.*0xffffffff", m):
            ev.yes("aapt2: android:allowBackup=true")
            ev.verdict = CORROBORATED
        elif "allowBackup" in m:
            ev.no("allowBackup present but not true in the parsed manifest")
            ev.verdict = UNSUPPORTED
        has_rules = ("dataExtractionRules" in m) or ("fullBackupContent" in m)
        ev.yes("dataExtractionRules/fullBackupContent present" if has_rules
               else "no dataExtractionRules and no fullBackupContent: EVERYTHING is in scope")
        ev.next_step = ("Name the file that leaves the device. 33-Storage tells you where the "
                        "credential store is; without that sentence this is a config note, "
                        "not a finding.")
        return

    # cleartext ------------------------------------------------------------- #
    if "clear text" in t or "cleartext" in t:
        if re.search(r"usesCleartextTraffic\S*\)?=true", m):
            ev.yes("aapt2: android:usesCleartextTraffic=true")
            ev.verdict = CORROBORATED
        if "networkSecurityConfig" in m:
            ev.no("a networkSecurityConfig is declared and SUPERSEDES this attribute "
                  "- read res/xml/ before reporting")
            ev.verdict = NEEDS_HUMAN
        else:
            ev.yes("no networkSecurityConfig: the attribute is the whole policy")
        ev.next_step = ("Find an actual http:// endpoint the app contacts. The flag permits "
                        "cleartext; it does not prove any is sent. See 44-NetworkSecurityConfig.")
        return

    # debuggable ------------------------------------------------------------ #
    if "debug" in t and "certificate" not in t:
        if re.search(r"debuggable\S*\)?=true", m):
            ev.yes("aapt2: android:debuggable=true")
            ev.verdict = CORROBORATED
            ev.next_step = ("Confirm on the platform: adb shell dumpsys package <pkg> | grep flags= "
                            "should show DEBUGGABLE. Then demonstrate run-as.")
        else:
            ev.no("no android:debuggable=true in the parsed manifest")
            ev.verdict = REFUTED
        return

    # provider protected by a permission ------------------------------------ #
    # This MUST be tested before the generic exported branch: MobSF's title for a
    # permission-protected component also contains the word "exported", so a
    # naive ordering swallows the one check that matters here.
    if "protected by a permission" in t or "readpermission" in t.replace(" ", ""):
        lvl = _permission_levels(m)
        ev.yes("provider declares a permission")
        if not lvl:
            ev.note = "no <permission> element in this manifest: the level is defined elsewhere"
            ev.next_step = ("Resolve the protectionLevel wherever the permission is DECLARED. "
                            "adb shell dumpsys package permission <name>")
        for name, level in lvl.items():
            if level.startswith("normal") or level.startswith("dangerous") \
                    or level.startswith("ABSENT"):
                ev.no("permission %s has protectionLevel=%s - ANY app can hold it, so the "
                      "provider is effectively unprotected" % (name, level))
                ev.verdict = UNDERRATED
                ev.next_step = ("Write this UP, not down. Install an unprivileged app that "
                                "<uses-permission> the name and query the authority. "
                                "23-Permissions owns the level semantics.")
            else:
                ev.yes("permission %s has protectionLevel=%s" % (name, level))
                if ev.verdict == NEEDS_HUMAN:
                    ev.verdict = CORROBORATED
        return

    # exported components --------------------------------------------------- #
    if "not protected" in t or "exported" in t:
        comp = (f.components or [""])[0]
        short = comp.split(".")[-1] if comp else ""
        if short and short in m:
            ev.yes("component %s is present in the manifest" % comp)
            ev.verdict = CORROBORATED
        elif short:
            ev.no("component %s not found in the parsed manifest" % comp)
            ev.verdict = UNSUPPORTED
        if "MAIN" in m and short and _is_launcher(m, short):
            ev.no("this is the LAUNCHER activity. It is exported because it must be; "
                  "reporting it as an exposure is the single most common scanner artefact")
            ev.verdict = OVERRATED
        ev.next_step = ("Reachability is the finding, not export. Start it from another uid: "
                        "adb shell am start -n <pkg>/%s  and record what an unprivileged caller "
                        "achieves. 32-Manifest owns the semantics; 30-Activities owns the proof."
                        % (comp or "<component>"))
        return

    # browsable / deep link -------------------------------------------------- #
    if "browsable" in t or "deeplink" in t or "deep link" in t:
        ev.yes("browsable filter present in the manifest")
        ev.verdict = CORROBORATED
        ev.next_step = ("Fire it: adb shell am start -a android.intent.action.VIEW -d "
                        "'<scheme>://<host><path>' and read what the Activity does with the "
                        "URI parameters. A browsable Activity that ignores its data is nothing.")
        return

    # minSdk ----------------------------------------------------------------- #
    if "vulnerable android version" in t or "minsdk" in t.replace(" ", ""):
        # Tight, line-anchored. A loose [^)]* here will happily cross newlines and
        # report a digit from somewhere else in the file - which it did, once.
        mm = re.search(r"minSdkVersion[^=\n]*=[^\d\n]*(\d+)", m) or \
             re.search(r"minSdk[^\d\n]{0,12}(\d+)", m)
        val = mm.group(1) if mm else "?"
        ev.yes("minSdkVersion=%s" % val)
        ev.no("this rule fires on a NUMBER, not on a vulnerability. It names no CVE, no "
              "reachable weakness and no platform behaviour this app depends on")
        ev.verdict = OVERRATED
        ev.next_step = ("Either name a platform weakness the app is exposed to at API %s and "
                        "why it matters here, or drop the item. 'Old minSdk' is a support "
                        "decision, not a finding." % val)
        return

    ev.next_step = "No automated manifest check for this rule. Read the manifest and decide."


def _is_launcher(manifest_text, short_name):
    """Crude but effective: is the named activity in the same block as LAUNCHER?"""
    idx = manifest_text.find(short_name)
    if idx < 0:
        return False
    window = manifest_text[idx: idx + 1200]
    return "LAUNCHER" in window


def _permission_levels(manifest_text):
    """
    Pull declared custom permissions and their protectionLevel out of an aapt2 dump.
    protectionLevel arrives as an int: 0=normal, 1=dangerous, 2=signature,
    3=signatureOrSystem. Anything else is a flag combination worth reading by hand.
    """
    levels = {}
    inside, name, raw = False, None, None
    for line in manifest_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("E: "):
            # a new element closes the previous <permission> block
            if inside and name:
                levels[name] = _level_name(raw)
            inside = stripped.startswith("E: permission ") or stripped == "E: permission"
            name, raw = None, None
            continue
        if not inside or not stripped.startswith("A: "):
            continue
        m = re.search(r'android:name\S*="([^"]+)"', stripped)
        if m:
            name = m.group(1)
        m = re.search(r"android:protectionLevel\S*=(0x[0-9a-fA-F]+|\d+)", stripped)
        if m:
            raw = m.group(1)
    if inside and name:
        levels[name] = _level_name(raw)
    return levels


def _level_name(raw):
    """
    protectionLevel is an int whose low nibble is the base level and whose high
    bits are flags (privileged, instant, appop, ...). Only the base decides who
    may hold the permission on an ordinary device.
    """
    if raw is None:
        return "ABSENT (defaults to normal)"
    try:
        val = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    except ValueError:
        return raw
    base = {0: "normal", 1: "dangerous", 2: "signature",
            3: "signatureOrSystem"}.get(val & 0xF, "0x%x" % val)
    return base if val <= 0xF else "%s|flags=0x%x" % (base, val & ~0xF)


def check_code_claim(f, art, ev):
    """Open the file at the cited line and read what is actually there."""
    if not f.locations:
        ev.next_step = "The report cites no file. Nothing to open."
        return
    if not art.tree:
        ev.note = "no --tree given; cited lines were not opened"
        ev.next_step = ("jadx -d out <apk> and re-run with --tree ./out. A code finding you "
                        "have not read is a rumour.")
        # DEX-level corroboration is still possible for a few rules
        _code_dex_fallback(f, art, ev)
        return

    seen_any = False
    for rel, spec in f.locations[:6]:
        path, lines = art.lines_at(rel, spec, context=0)
        if path is None:
            ev.no("cited file not in the tree: %s" % rel)
            continue
        if not lines:
            ev.no("%s exists but line %s is empty or out of range" % (rel, spec))
            continue
        seen_any = True
        for n, text in lines[:3]:
            ev.yes("%s:%d  %s" % (rel, n, text.strip()[:120]))

    if not seen_any:
        ev.verdict = UNSUPPORTED
        ev.next_step = ("The report's own citation does not resolve. Either the tree is from a "
                        "different build than the scan, or the rule fired on smali the tool "
                        "renders differently. Settle it before quoting the report.")
        return

    ev.verdict = CORROBORATED
    t = f.title.lower()
    if "ecb" in t:
        ev.next_step = ("Read the KEY too, not only the mode. Where does the SecretKeySpec come "
                        "from? A single-round hash of a literal is a worse problem than ECB and "
                        "no scanner rule covers it. 34-Cryptography rates it.")
    elif "addjavascriptinterface" in t.replace(" ", ""):
        ev.next_step = ("Two more questions decide severity: (1) what does the exposed object's "
                        "@JavascriptInterface method return, and (2) can an attacker control the "
                        "URL loaded into that WebView? Without (2) it is not remote. 43-WebView.")
    elif "javascript" in t:
        ev.next_step = ("setJavaScriptEnabled alone is not a finding - most apps need it. It is "
                        "an aggravator for a URL-control or bridge finding. Merge it, or drop it.")
    elif "hardcoded" in t or "secret" in t:
        ev.next_step = ("Extract each literal and classify it: hash, ciphertext, public key pin, "
                        "or credential. Run this script's secret classifier over the report's "
                        "secrets section; then decode what decodes.")
    elif "temporary file" in t or "world" in t:
        ev.next_step = ("Name the file and its mode on a device: adb shell run-as <pkg> ls -l. "
                        "33-Storage owns whether it is reachable.")
    else:
        ev.next_step = ("Construct confirmed at the cited line. Now answer 52's four questions: "
                        "real, reachable, reachable by whom, and what it gets them.")


def _code_dex_fallback(f, art, ev):
    t = f.title.lower()
    probes = []
    if "ecb" in t:
        probes.append((r"AES/ECB/[A-Za-z0-9]+", "ECB transform string in the DEX"))
    if "addjavascriptinterface" in t.replace(" ", ""):
        probes.append((r"addJavascriptInterface", "addJavascriptInterface in the DEX"))
    if "javascript" in t:
        probes.append((r"setJavaScriptEnabled", "setJavaScriptEnabled in the DEX"))
    for rx, label in probes:
        hits = art.grep_dex(rx, limit=3)
        if hits:
            ev.yes("%s: %s" % (label, ", ".join(sorted(set(hits))[:3])))
            ev.verdict = CORROBORATED


def check_certificate_claim(f, art, ev):
    t = f.title.lower()
    certs = art.has_entry(r"^META-INF/.*\.(RSA|DSA|EC)$")
    blob = b"".join(art.read_entry(c) for c in certs)
    if not blob:
        # v2/v3-only signing puts the certificate in the APK Signing Block, which
        # sits between the last entry and the central directory and is therefore
        # invisible to zipfile. Read the file itself.
        try:
            with open(art.path, "rb") as fh:
                blob = fh.read()
            if blob:
                ev.note = ("no META-INF signature files: v2/v3-only signing, so the DN was "
                           "searched for in the raw APK bytes instead")
        except Exception:                             # noqa: BLE001
            blob = b""
    if "debug certificate" in t:
        if b"Android Debug" in blob:
            ev.yes("the signing certificate carries the subject string 'Android Debug'")
            ev.verdict = CORROBORATED
            ev.next_step = ("This one is usually right and usually High. Confirm the DN with "
                            "apksigner verify -v --print-certs, and say the consequence out "
                            "loud: the debug private key ships with the SDK, so anyone can "
                            "sign an update-compatible package.")
        elif blob:
            ev.no("no 'Android Debug' subject string anywhere in the artefact")
            ev.verdict = UNSUPPORTED
        else:
            ev.no("could not read any signing material")
            ev.next_step = "apksigner verify -v --print-certs <apk>"
        return
    if "v1" in t or "janus" in t:
        v1 = art.has_entry(r"^META-INF/.*\.(SF)$")
        ev.yes("v1 (JAR) signature present" if v1 else "no v1 signature files in META-INF")
        ev.next_step = ("apksigner verify -v prints which schemes verified. A missing v1 on a "
                        "minSdk>=24 app is a compatibility note, not a security finding; a "
                        "PRESENT v1 with no v2 is the Janus exposure. Get the direction right.")
        return
    ev.next_step = "apksigner verify -v --print-certs <apk>, and read the DN yourself."


def check_secret_claim(f, art, ev):
    value = _txt(f.raw.get("value") if isinstance(f.raw, dict) else f.title)
    kind, why = classify_secret(value)
    ev.yes("classified as: %s" % kind)
    ev.note = why
    if kind in ("SPKI pin", "URL", "short literal"):
        ev.verdict = REFUTED
        ev.next_step = "Remove from the secrets list. Move it to the inventory it belongs in."
    elif kind.endswith("hex"):
        ev.verdict = OVERRATED
        ev.next_step = ("Decide what the digest protects. If it is a password verifier, the "
                        "finding is 'unsalted single-round SHA-256 used as a password check', "
                        "which is about the ALGORITHM. Quote the comparison site.")
    elif kind == "base64 of TEXT":
        ev.verdict = CORROBORATED
        ev.next_step = ("It decoded. Now say what it is and what it protects - encoding is not "
                        "encryption, and a decoded UI string is Informational, not a credential.")
    elif kind == "base64 of BINARY":
        ev.next_step = ("Ciphertext is only a finding when the key is also in the artefact. "
                        "Find the key derivation and follow it.")
    else:
        ev.next_step = "Open the site the value was read from and read the surrounding code."
    # Does the value even appear in the artefact?
    probe = value.strip().strip('"')[:32]
    if probe and art.dex_bytes:
        try:
            if probe.encode("latin-1", "ignore") in art.dex_bytes:
                ev.yes("value is present in the DEX string data")
            else:
                ev.no("value NOT found in the DEX - it came from resources, assets, or a "
                      "different artefact than the one you handed me")
        except Exception:                             # noqa: BLE001
            pass


def check_appsec_claim(f, art, ev):
    """
    The scorecard is where MobSF makes its most quotable and least defensible
    statements, including NEGATIVE ones. A negative claim is a claim.
    """
    t = f.title.lower()

    if "pinning" in t:
        pins = sorted(set(art.grep_dex(PIN_RX, limit=6)))
        nsc = [n for n in art.entries if re.search(r"res/xml/.*\.xml$", n)]
        pinner = art.grep_dex(r"CertificatePinner", limit=2)
        okhttp_msg = art.grep_dex(r"Certificate pinning failure", limit=1)
        negative_claim = ("does not" in t) or ("not implement" in t) or ("no certificate" in t)

        if pins:
            ev.yes("configured SPKI pin value(s) in the DEX: %s" % ", ".join(pins))
            if negative_claim:
                ev.verdict = REFUTED
                ev.next_step = ("The report is WRONG in the dangerous direction. The scanner "
                                "looked for a class name; R8 renamed the class. Grep for the "
                                "43-character pin instead - see 36-CertificatePinning section 8.2.")
            else:
                ev.verdict = CORROBORATED
                ev.next_step = ("A pin value exists. That is still not 'the app pins': show a "
                                "handshake being REJECTED. 36-CertificatePinning/scripts/"
                                "pin-attribution.js attributes the rejection.")
        else:
            ev.no("no 43-character SPKI pin value anywhere in the DEX")
            if pinner:
                ev.no("but okhttp3.CertificatePinner IS on the classpath - that is SURFACE, not "
                      "a pin. 12 of 14 measured apps had surface; 4 had a pin")
            if okhttp_msg:
                ev.no("OkHttp's own pin-failure message string is present and ships "
                      "unconditionally with the library")
            if nsc:
                ev.note = ("%d res/xml file(s) present - check every one for <pin-set> before "
                           "making a negative claim" % len(nsc))
            ev.verdict = CORROBORATED if negative_claim else UNSUPPORTED
            ev.next_step = ("Check all four layers before writing either sentence: DEX pin value, "
                            "<pin-set> in the NSC, custom TrustManager, native. "
                            "python3 -B ../../36-CertificatePinning/scripts/pinning-surface.py --apk <apk>")
        return

    if "root" in t or "tamper" in t or "emulator" in t:
        ev.next_step = ("Presence of a check is not enforcement. 38-TamperDetection measured "
                        "13/18 apps performing a self-signature check and only 1/18 importing "
                        "ptrace. Show the app REFUSING to run, or drop the claim.")
        return

    if "obfusc" in t:
        ev.next_step = ("40-Obfuscation: 'is obfuscated' is not a security property. Ask what it "
                        "costs an attacker in hours, and note that strings survive R8 entirely.")
        return

    ev.verdict = RESTATES
    ev.next_step = ("Scorecard entries restate other sections. Trace this to the underlying "
                    "manifest or code finding and validate THAT; do not report the scorecard.")


def check_binary_claim(f, art, ev):
    libs = art.has_entry(r"^lib/.*\.so$")
    if not libs:
        ev.no("no .so files in this APK at all")
        ev.verdict = UNSUPPORTED
        ev.next_step = ("If the report names a native library the artefact does not contain, you "
                        "scanned a different file - or the code ships in a SPLIT. 38-TamperDetection "
                        "measured one app with zero controls in base.apk for exactly this reason.")
        return
    ev.yes("%d native library/libraries present" % len(libs))
    ev.next_step = ("Hardening flags (NX, PIE, RELRO, canary) are properties of a BUILD, not "
                    "vulnerabilities. Report them as a hardening table, and check "
                    "JNI_OnLoad-vs-Java_ exports: no Java_ symbols means the native surface is "
                    "registered at runtime and neither MobSF nor you can enumerate it. 16-JNI.")


# =========================================================================== #
#  Blind spots - what no report of this kind can contain                      #
# =========================================================================== #

def blind_spots(art):
    out = []
    tree_probe = art.grep_tree(r"\bregisterReceiver\s*\(", limit=3) if art.tree else []
    dex_probe = art.grep_dex(r"registerReceiver", limit=1)
    if tree_probe or dex_probe:
        out.append(("runtime-registered receivers",
                    "registerReceiver() builds an IntentFilter at runtime and writes nothing to "
                    "the manifest. 29-BroadcastReceivers measured 299 of 431 distinct actions "
                    "(69%) with no manifest-declared receiver anywhere on the device. Enumerate "
                    "with: adb shell dumpsys activity broadcasts"))
    if art.grep_dex(r"DexClassLoader|InMemoryDexClassLoader|PathClassLoader", limit=1):
        out.append(("dynamically loaded code",
                    "a class loader that can take code the artefact does not contain. If it "
                    "fires, everything in this report describes a stub. 40-Obfuscation 3.7"))
    if art.grep_dex(r"java/lang/reflect/Method", limit=1) or art.grep_dex(r"getDeclaredMethod", limit=1):
        out.append(("reflective dispatch",
                    "a reflected call creates no textual edge, so no static reachability answer "
                    "covers it. Hook Method.invoke to enumerate."))
    libs = art.has_entry(r"^lib/.*\.so$")
    if libs:
        out.append(("native surface",
                    "%d .so file(s). If JNI_OnLoad is present and no Java_ symbols are exported, "
                    "the native methods are bound with RegisterNatives and are not enumerable "
                    "from the file. 16-JNI, 52-StaticAnalysis 4.4" % len(libs)))
    base = os.path.basename(art.path or "")
    if base.startswith("base"):
        out.append(("split APKs",
                    "the artefact is named base.apk. Splits carry code, native libraries and "
                    "manifest contributions. Confirm with: adb shell pm path <pkg>"))
    out.append(("server-side behaviour",
                "no artefact analysis observes what the backend enforces, or what a remote "
                "config flag turns off after you finish testing."))
    return out


# =========================================================================== #
#  Driver                                                                     #
# =========================================================================== #

DISPATCH = {
    "manifest": check_manifest_claim,
    "certificate": check_certificate_claim,
    "code": check_code_claim,
    "secrets": check_secret_claim,
    "binary": check_binary_claim,
    "network": lambda f, a, e: e.__setattr__(
        "next_step", "Open res/xml/ and read the network security config yourself. "
                     "44-NetworkSecurityConfig section 7.8 lists the two false positives "
                     "this section reliably produces."),
}


def validate(f, art):
    ev = Evidence()
    if f.section.startswith("appsec"):
        check_appsec_claim(f, art, ev)
    else:
        fn = DISPATCH.get(f.section)
        if fn:
            fn(f, art, ev)
        else:
            ev.next_step = "No gatherer for section %r." % f.section
    return ev


BAR = "=" * 78
SUB = "-" * 78


def main():
    ap = argparse.ArgumentParser(
        description="Gather the evidence that would confirm or kill every finding in a "
                    "MobSF JSON report. Assigns no findings.")
    ap.add_argument("--report", required=True, help="MobSF JSON report (or the shipped fixture)")
    ap.add_argument("--apk", required=True, help="the artefact the report describes")
    ap.add_argument("--tree", help="decompiled tree (jadx -d out) for code-location checks")
    ap.add_argument("--csv", help="write the ledger here")
    ap.add_argument("--only", help="comma-separated severities to work, e.g. high,warning")
    ap.add_argument("--quiet", action="store_true", help="summary table only")
    args = ap.parse_args()

    try:
        with open(args.report, "r", encoding="utf-8") as fh:
            report = json.load(fh)
    except Exception as exc:                          # noqa: BLE001
        sys.exit("cannot read report: %s" % exc)

    art = Artefact(args.apk, args.tree)
    findings, shapes = normalise(report)

    if args.only:
        want = {s.strip().lower() for s in args.only.split(",")}
        findings = [f for f in findings if f.severity in want]

    findings.sort(key=lambda f: (SEV_ORDER.get(f.severity, 5), f.section, f.fid))

    print(BAR)
    print("  MobSF finding validation")
    print(BAR)
    print("  report      : %s" % args.report)
    print("  artefact    : %s%s" % (args.apk, "" if art.available else "   [NOT READABLE]"))
    print("  tree        : %s" % (args.tree or "(none - code citations will not be opened)"))
    print("  manifest via: %s" % art.manifest_source)
    print("  schema seen : %s" % ("; ".join(shapes) or "unrecognised"))
    if report.get("_fixture"):
        print("  NOTE        : this report is a SHIPPED FIXTURE, not MobSF output. See its")
        print("                _fixture block before quoting anything from it.")
    for n in art.notes:
        print("  warning     : %s" % n)
    print("  findings    : %d" % len(findings))
    print(BAR)

    rows, tally = [], {}
    for f in findings:
        ev = validate(f, art)
        tally[ev.verdict] = tally.get(ev.verdict, 0) + 1
        rows.append((f, ev))

        if args.quiet:
            continue
        print()
        print("%s  [%s]  %s" % (f.fid, (f.severity or "?").upper(), f.section))
        print("  claim     %s" % f.title.strip()[:150])
        if f.cvss:
            print("  cvss      %s   <- rule metadata, constant for every app. Not YOUR severity."
                  % f.cvss)
        if f.components:
            print("  component %s" % ", ".join(x for x in f.components if x)[:150])
        for rel, spec in f.locations[:4]:
            print("  cites     %s:%s" % (rel, spec))
        for e in ev.for_:
            print("    FOR     %s" % e)
        for e in ev.against:
            print("    AGAINST %s" % e)
        if ev.note:
            print("    note    %s" % ev.note)
        print("  VERDICT   %s" % ev.verdict)
        if ev.next_step:
            for i, chunk in enumerate(_wrap(ev.next_step, 68)):
                print("  %s %s" % ("NEXT STEP" if i == 0 else "         ", chunk))

    print()
    print(BAR)
    print("  SUMMARY")
    print(SUB)
    total = len(rows)
    for k in (CORROBORATED, UNDERRATED, OVERRATED, REFUTED, UNSUPPORTED, RESTATES, NEEDS_HUMAN):
        n = tally.get(k, 0)
        if n:
            print("  %-14s %4d   (%4.1f%%)" % (k, n, 100.0 * n / max(1, total)))

    distinct = [(f, e) for f, e in rows if not f.section.startswith("appsec")]
    d_survive = sum(1 for _f, e in distinct if e.verdict in (CORROBORATED, UNDERRATED))
    survive = tally.get(CORROBORATED, 0) + tally.get(UNDERRATED, 0)
    print(SUB)
    print("  all items          : %d of %d survived first-pass corroboration (%.1f%%)"
          % (survive, total, 100.0 * survive / max(1, total)))
    print("  excluding scorecard: %d of %d (%.1f%%)"
          % (d_survive, len(distinct), 100.0 * d_survive / max(1, len(distinct))))
    print("  The two numbers differ because the appsec scorecard RESTATES the manifest,")
    print("  code and certificate sections. Counting a report's own summary as extra")
    print("  findings is how a 12-item scan becomes a 39-item 'report'.")
    print(SUB)
    print("  Survival is NOT a finding count. Every survivor still needs reachability and")
    print("  an asset before it may be written up. 52-StaticAnalysis section 3.7.")
    print(BAR)

    bs = blind_spots(art)
    print()
    print("  BLIND SPOTS - present in the artefact, absent from any report of this kind")
    print(SUB)
    for name, why in bs:
        print("  * %s" % name)
        for chunk in _wrap(why, 72):
            print("      %s" % chunk)
    print(BAR)

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["id", "section", "mobsf_severity", "cvss", "claim",
                        "component", "cites", "verdict", "evidence_for",
                        "evidence_against", "next_step", "human_verdict", "human_reason"])
            for f, ev in rows:
                w.writerow([f.fid, f.section, f.severity, f.cvss or "",
                            f.title.strip()[:300],
                            "; ".join(x for x in f.components if x),
                            "; ".join("%s:%s" % (a, b) for a, b in f.locations),
                            ev.verdict, " | ".join(ev.for_), " | ".join(ev.against),
                            ev.next_step, "", ""])
        print("  ledger written: %s   (two columns are blank ON PURPOSE)" % args.csv)


def _wrap(s, width):
    words, line, out = s.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return out


if __name__ == "__main__":
    main()
