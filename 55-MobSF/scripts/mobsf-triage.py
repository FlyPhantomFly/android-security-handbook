#!/usr/bin/env python3
# 55-MobSF/scripts/mobsf-triage.py
#
# PURPOSE
#   Drive MobSF's REST API over a DIRECTORY of APKs and produce a TRIAGE RANKING:
#   which of these applications deserves a human's next four hours, and what the
#   first three things to look at are. It deliberately does NOT emit a verdict dump.
#
#   MobSF is at its best exactly here - breadth. Twenty APKs, one command, an
#   inventory of every component, permission, endpoint and pattern hit in each.
#   What MobSF will not do is tell you which of the twenty matters, because its
#   security_score is computed from rule metadata and rule metadata is a property
#   of the RULE, not of the application. This script computes a different number,
#   from signals that predict where analyst time pays, and it PRINTS EVERY TERM so
#   you can disagree with the model instead of obeying it.
#
# USAGE
#   # online: scan a directory against a running MobSF
#   export MOBSF_API_KEY=<the key MobSF prints at startup / shows in the web UI>
#   python3 -B mobsf-triage.py --dir ./apks --server http://127.0.0.1:8000 \
#           --cache ./reports
#
#   # offline: rank reports you already have (works with the shipped fixture)
#   python3 -B mobsf-triage.py --from-reports ../examples/
#
#   # machine-readable
#   python3 -B mobsf-triage.py --from-reports ./reports --csv triage.csv
#
#   # see the ranking arithmetic for every app, not just the top ones
#   python3 -B mobsf-triage.py --from-reports ./reports --explain
#
# REQUIREMENTS
#   Python 3.8+, standard library only (urllib, no requests).
#   For --dir: a reachable MobSF instance and its API key. MobSF itself is a large
#   Docker/Python service; see 55-MobSF/README.md section 1.6 for the install, and
#   for an honest statement of the fact that it was NOT run while this chapter was
#   written. Everything below works offline against saved reports.
#
# WHAT THIS WILL NOT TELL YOU
#   * Which app is VULNERABLE. It ranks where to look. Ranking is not adjudication;
#     run mobsf-validate.py on the winner and then read the code yourself.
#   * Anything MobSF did not see: runtime-registered receivers, RegisterNatives
#     bindings, reflection targets, code loaded after install, or the contents of a
#     split it was not given. The blind-spot block is printed with every run.
#   * Whether MobSF's own numbers are right. It consumes them; mobsf-validate.py
#     is the script that argues with them.
#   * Whether two scans of the same file are comparable. They are not, across MobSF
#     versions - rule sets and schema both move. The report's version string is
#     printed for exactly this reason.
#
# NOTE ON DUPLICATION
#   The secret classifier below is a copy of the one in mobsf-validate.py rather than
#   an import. That is deliberate: importing a module whose filename contains a hyphen
#   needs importlib, and importlib.util.module_from_spec writes __pycache__ even under
#   PYTHONDONTWRITEBYTECODE. Twenty duplicated lines beat a build artefact in a repo.

import argparse
import base64
import binascii
import csv
import glob
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

PIN_RX = re.compile(r"^sha256/[A-Za-z0-9+/]{43}=$")
HEX_RX = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
B64_RX = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")


# =========================================================================== #
#  REST client                                                                #
# =========================================================================== #

class MobSF:
    """
    The four endpoints that matter. MobSF's API is form-encoded, authenticated by a
    bare Authorization header (no 'Bearer'), and returns JSON.

        POST /api/v1/upload       multipart 'file'      -> {hash, scan_type, file_name}
        POST /api/v1/scan         hash,scan_type,file_name -> the full report
        POST /api/v1/report_json  hash                  -> the full report
        POST /api/v1/delete_scan  hash                  -> {deleted: yes}

    Endpoint paths and field names are read off MobSF's own API documentation. If a
    call 404s, your instance is a different major version: open /api_docs on the
    server and read what it actually exposes rather than trusting this comment.
    """

    def __init__(self, base, api_key, timeout=900):
        self.base = base.rstrip("/")
        self.key = api_key
        self.timeout = timeout

    def _post(self, path, fields=None, filepath=None):
        url = self.base + path
        if filepath:
            boundary = uuid.uuid4().hex
            name = os.path.basename(filepath)
            with open(filepath, "rb") as fh:
                blob = fh.read()
            parts = [
                ("--%s\r\n" % boundary).encode(),
                ('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % name).encode(),
                b"Content-Type: application/octet-stream\r\n\r\n",
                blob,
                ("\r\n--%s--\r\n" % boundary).encode(),
            ]
            body = b"".join(parts)
            ctype = "multipart/form-data; boundary=%s" % boundary
        else:
            body = urllib.parse.urlencode(fields or {}).encode()
            ctype = "application/x-www-form-urlencoded"

        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Authorization", self.key)
        req.add_header("Content-Type", ctype)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise RuntimeError("%s returned non-JSON (%d bytes). First 200 chars: %s"
                               % (path, len(raw), raw[:200]))

    def upload(self, path):
        return self._post("/api/v1/upload", filepath=path)

    def scan(self, meta):
        return self._post("/api/v1/scan", fields={
            "hash": meta["hash"],
            "scan_type": meta.get("scan_type", "apk"),
            "file_name": meta.get("file_name", ""),
        })

    def report_json(self, sha):
        return self._post("/api/v1/report_json", fields={"hash": sha})


# =========================================================================== #
#  Signal extraction - tolerant to schema drift                               #
# =========================================================================== #

def classify_secret(value):
    v = value.strip().strip('"').strip("'")
    if PIN_RX.fullmatch(v):
        return "pin"
    if v.startswith(("http://", "https://")):
        return "url"
    if HEX_RX.fullmatch(v):
        return "digest"
    if B64_RX.fullmatch(v) and len(v) % 4 == 0:
        try:
            dec = base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError):
            return "shape"
        printable = sum(1 for b in dec if 32 <= b < 127 or b in (9, 10, 13))
        return "plaintext" if printable / max(1, len(dec)) > 0.9 else "ciphertext"
    if len(v) < 8:
        return "short"
    return "unknown"


def _iter_manifest(report):
    ma = report.get("manifest_analysis")
    if isinstance(ma, dict):
        items = ma.get("manifest_anal") or ma.get("manifest_findings") or []
    elif isinstance(ma, list):
        items = ma
    else:
        items = []
    for it in items:
        if isinstance(it, dict):
            yield it


def _iter_code(report):
    ce = report.get("code_analysis")
    if not isinstance(ce, dict):
        return
    findings = ce.get("findings") if isinstance(ce.get("findings"), dict) else \
               {k: v for k, v in ce.items() if k != "summary"}
    for title, body in (findings or {}).items():
        if isinstance(body, dict):
            yield title, body


def _all_urls(report):
    out = []
    for entry in report.get("urls") or []:
        if isinstance(entry, dict):
            out.extend(entry.get("urls") or [])
        elif isinstance(entry, str):
            out.append(entry)
    return out


def signals(report):
    """Everything the ranker needs, pulled once, defensively."""
    s = {
        "package": report.get("package_name") or "?",
        "app_name": report.get("app_name") or "",
        "file": report.get("file_name") or "",
        "sha256": report.get("sha256") or "",
        "version": str(report.get("version") or "?"),
        "min_sdk": str(report.get("min_sdk") or "?"),
        "target_sdk": str(report.get("target_sdk") or "?"),
        "size": report.get("size") or "",
        "version_name": str(report.get("version_name") or "?"),
        "average_cvss": report.get("average_cvss"),
        "is_fixture": bool(report.get("_fixture")),
        "mobsf_score": None,
        "mobsf_high": 0,
        "mobsf_warning": 0,
    }

    ap = report.get("appsec") if isinstance(report.get("appsec"), dict) else {}
    if ap:
        s["mobsf_score"] = ap.get("security_score")
        s["mobsf_high"] = len(ap.get("high") or [])
        s["mobsf_warning"] = len(ap.get("warning") or [])

    ec = report.get("exported_count") if isinstance(report.get("exported_count"), dict) else {}
    s["exported_activities"] = ec.get("exported_activities", len(report.get("exported_activities") or []))
    s["exported_providers"] = ec.get("exported_providers", 0)
    s["exported_services"] = ec.get("exported_services", 0)
    s["exported_receivers"] = ec.get("exported_receivers", 0)

    s["browsable"] = len(report.get("browsable_activities") or {})
    s["native_libs"] = len(report.get("libraries") or []) + len(report.get("binary_analysis") or [])
    s["trackers"] = (report.get("trackers") or {}).get("detected_trackers", 0) \
        if isinstance(report.get("trackers"), dict) else 0

    # manifest-derived booleans
    s["debuggable"] = False
    s["unprotected_provider"] = 0
    s["permission_level_unknown"] = 0
    s["cleartext"] = False
    s["backup"] = False
    for it in _iter_manifest(report):
        t = (it.get("title") or it.get("name") or "").lower()
        if "debuggable" in t and "true" in t:
            s["debuggable"] = True
        if "content provider" in t and "not protected" in t:
            s["unprotected_provider"] += 1
        if "protected by a permission" in t:
            s["permission_level_unknown"] += 1
        if "clear text" in t or "cleartext" in t:
            s["cleartext"] = True
        if "backed up" in t or "allowbackup" in t:
            s["backup"] = True

    # certificate
    s["debug_cert"] = False
    ca = report.get("certificate_analysis")
    blob = json.dumps(ca) if ca else ""
    if "debug certificate" in blob.lower() or "cn=android debug" in blob.lower():
        s["debug_cert"] = True

    # code-derived booleans
    s["js_bridge"] = False
    s["webview_js"] = False
    s["weak_crypto"] = False
    s["code_high"] = 0
    for title, body in _iter_code(report):
        t = title.lower()
        meta = body.get("metadata") if isinstance(body.get("metadata"), dict) else body
        if (meta.get("severity") or "").lower() == "high":
            s["code_high"] += 1
        if "addjavascriptinterface" in t.replace(" ", ""):
            s["js_bridge"] = True
        if "javascript" in t and "webview" in t:
            s["webview_js"] = True
        if "ecb" in t or "md5" in t or "sha-1" in t or "insecure random" in t:
            s["weak_crypto"] = True

    # endpoints
    urls = _all_urls(report)
    s["urls"] = len(urls)
    s["http_urls"] = sum(1 for u in urls if u.lower().startswith("http://"))
    s["nonprod_urls"] = sum(
        1 for u in urls
        if re.search(r"(^|[./-])(dev|test|qa|uat|stg|stage|staging|preprod|sandbox|internal)"
                     r"[0-9]*([./-]|$)", u.lower()))

    # secrets, classified rather than counted
    kinds = {}
    for raw in report.get("secrets") or []:
        kinds[classify_secret(str(raw))] = kinds.get(classify_secret(str(raw)), 0) + 1
    s["secrets_raw"] = len(report.get("secrets") or [])
    s["secrets_kinds"] = kinds
    s["secrets_interesting"] = kinds.get("plaintext", 0) + kinds.get("unknown", 0)
    s["secrets_noise"] = kinds.get("pin", 0) + kinds.get("url", 0) + kinds.get("short", 0)

    # pinning: a hardening signal, not a finding
    s["pin_claimed"] = "pin" in kinds
    return s


# =========================================================================== #
#  The ranking model - small enough to argue with                             #
# =========================================================================== #
#
#  Every weight is a JUDGEMENT, not a measurement, exactly as 52-StaticAnalysis
#  says of its own confidence model. What must not change is that the terms are
#  printed. A ranking you cannot reconstruct is a ranking you will either obey or
#  ignore, and both are worse than no ranking.
#
#  The model answers ONE question: "where will an analyst's next four hours produce
#  the most defensible sentences?" It is explicitly NOT a severity model.

WEIGHTS = [
    # (key, points, why this predicts analyst value)
    ("debuggable", 30, "run-as reads the private data directory with no root. Demonstrable in one command"),
    ("debug_cert", 12, "the debug private key ships with the SDK; anyone can sign an update"),
    ("unprotected_provider", 14, "a reachable data surface an ordinary app can call TODAY (per provider)"),
    ("permission_level_unknown", 10, "a component whose guard is a permission whose LEVEL nobody resolved (per provider)"),
    ("js_bridge", 16, "addJavascriptInterface plus attacker-influenced URL is remote code in the app's uid"),
    ("browsable", 9, "an entry point reachable from a web page, per deep-linked activity"),
    ("http_urls", 8, "a real cleartext endpoint, per URL. Worth ten of any cleartext FLAG"),
    ("nonprod_urls", 11, "non-production hostnames in a shipped build; the finding only static analysis produces"),
    ("secrets_interesting", 6, "secret candidates that survived classification, per value"),
    ("exported_activities", 2, "surface, per activity. Cheap to enumerate, usually nothing"),
    ("exported_services", 3, "per service; a bound service is a richer surface than an activity"),
    ("exported_receivers", 2, "per receiver, and remember the manifest shows a minority of them"),
    ("native_libs", 4, "per native object: expands scope, and MobSF barely reads it"),
    ("weak_crypto", 5, "a specific API with specific arguments; fast to confirm, often Informational"),
    ("cleartext", 3, "the FLAG alone. Permits cleartext; proves none is sent"),
    ("backup", 3, "config note until you name the file that leaves the device"),
]

# Signals that REDUCE expected yield, and why. A hardened app is not a safe app,
# but it is a slower app, and a triage ranking that ignores cost is not a triage.
PENALTIES = [
    ("pin_claimed", -6, "a configured pin: budget an extra session for interception before you see traffic"),
]


def rank(s):
    total, terms = 0.0, []
    for key, pts, why in WEIGHTS:
        v = s.get(key)
        if not v:
            continue
        n = int(v) if not isinstance(v, bool) else 1
        n = min(n, 8)                      # cap: 40 exported activities is not 20x one
        gained = pts * n
        total += gained
        terms.append(("+%d" % gained, "%s x%d" % (key, n), why))
    for key, pts, why in PENALTIES:
        if s.get(key):
            total += pts
            terms.append(("%d" % pts, key, why))
    return total, terms


def first_moves(s):
    """The three things to do first. A rank with no next step is a number."""
    moves = []
    if s["debuggable"]:
        moves.append("adb shell run-as <pkg> ls -la /data/data/<pkg>/shared_prefs   (33-Storage)")
    if s["js_bridge"]:
        moves.append("read the @JavascriptInterface methods, then find who controls the loaded URL (43-WebView)")
    if s["unprotected_provider"] or s["permission_level_unknown"]:
        moves.append("resolve every provider's protectionLevel, then query the authority from an "
                     "unprivileged app (27-ContentProviders, 23-Permissions)")
    if s["nonprod_urls"]:
        moves.append("list the non-production hostnames and ask the client which are reachable (52 section 9.4)")
    if s["browsable"]:
        moves.append("adb shell am start -a android.intent.action.VIEW -d '<scheme>://...' (26-Intent)")
    if s["http_urls"]:
        moves.append("proxy the app and confirm a cleartext request is actually made (44-NetworkSecurityConfig)")
    if s["secrets_interesting"]:
        moves.append("decode and classify each surviving secret candidate before naming any of them")
    if s["pin_claimed"]:
        moves.append("map the pinning surface BEFORE bypassing: pinning-surface.py (36-CertificatePinning)")
    if not moves:
        moves.append("nothing above threshold. Say 'the scan produced no leads above threshold', "
                     "never 'no issues found', and put the blind-spot statement underneath")
    return moves[:3]


# =========================================================================== #
#  Driver                                                                     #
# =========================================================================== #

BAR = "=" * 78
SUB = "-" * 78


def load_reports(paths):
    out = []
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:                      # noqa: BLE001
            print("  skipped %s: %s" % (os.path.basename(p), exc), file=sys.stderr)
            continue
        if not isinstance(data, dict) or "package_name" not in data:
            continue
        out.append((p, data))
    return out


def scan_directory(apk_dir, client, cache):
    """Upload, scan, fetch, cache. Returns [(path, report)]."""
    results = []
    apks = sorted(glob.glob(os.path.join(apk_dir, "*.apk")) +
                  glob.glob(os.path.join(apk_dir, "*.xapk")) +
                  glob.glob(os.path.join(apk_dir, "*.apkm")))
    if not apks:
        print("  no APKs in %s" % apk_dir, file=sys.stderr)
        return results
    if cache:
        os.makedirs(cache, exist_ok=True)

    for i, apk in enumerate(apks, 1):
        name = os.path.basename(apk)
        sha = hashlib.sha256(open(apk, "rb").read()).hexdigest()
        cached = os.path.join(cache, sha + ".json") if cache else None
        if cached and os.path.isfile(cached):
            print("  [%d/%d] %-40s cached" % (i, len(apks), name[:40]))
            with open(cached, "r", encoding="utf-8") as fh:
                results.append((cached, json.load(fh)))
            continue

        print("  [%d/%d] %-40s uploading..." % (i, len(apks), name[:40]), end="", flush=True)
        t0 = time.time()
        try:
            meta = client.upload(apk)
            print(" scanning...", end="", flush=True)
            client.scan(meta)
            report = client.report_json(meta["hash"])
        except urllib.error.HTTPError as exc:
            print(" HTTP %s - %s" % (exc.code, exc.reason))
            print("        401 means a wrong or missing API key; 404 means a different "
                  "MobSF major version. Open %s/api_docs" % client.base)
            continue
        except Exception as exc:                      # noqa: BLE001
            print(" failed: %s" % exc)
            continue
        print(" %.0fs" % (time.time() - t0))
        if cached:
            with open(cached, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=1)
        results.append((cached or apk, report))
    return results


def main():
    ap = argparse.ArgumentParser(
        description="Rank a corpus of APKs by where an analyst's time will pay, using "
                    "MobSF for breadth and a printed model for the ranking.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--dir", help="directory of APKs to scan through the REST API")
    src.add_argument("--from-reports", help="directory of saved MobSF JSON reports")
    ap.add_argument("--server", default=os.environ.get("MOBSF_SERVER", "http://127.0.0.1:8000"))
    ap.add_argument("--api-key", default=os.environ.get("MOBSF_API_KEY", ""))
    ap.add_argument("--cache", default="./mobsf-reports", help="where scanned reports are kept")
    ap.add_argument("--csv", help="write the ranking here")
    ap.add_argument("--explain", action="store_true", help="print the arithmetic for every app")
    ap.add_argument("--top", type=int, default=0, help="only detail the top N")
    args = ap.parse_args()

    if args.dir:
        if not args.api_key:
            sys.exit("--dir needs an API key. export MOBSF_API_KEY=... (MobSF prints it at "
                     "startup and shows it in the web UI under the API docs).")
        client = MobSF(args.server, args.api_key)
        print(BAR)
        print("  scanning %s against %s" % (args.dir, args.server))
        print(BAR)
        reports = scan_directory(args.dir, client, args.cache)
    else:
        paths = sorted(glob.glob(os.path.join(args.from_reports, "*.json")))
        reports = load_reports(paths)

    if not reports:
        sys.exit("no usable reports. A MobSF Android report has a 'package_name' key.")

    rows = []
    for path, rep in reports:
        s = signals(rep)
        score, terms = rank(s)
        rows.append((score, s, terms, path, rep))
    rows.sort(key=lambda r: -r[0])

    print()
    print(BAR)
    print("  TRIAGE RANKING - where the next four hours go")
    print(BAR)
    print("  %-4s %-30s %-9s %6s %6s %5s  %s"
          % ("#", "package", "version", "triage", "MobSF", "cvss", "top signal"))
    print(SUB)
    for i, (score, s, terms, _p, _r) in enumerate(rows, 1):
        top = terms[0][1] if terms else "-"
        print("  %-4d %-30s %-9s %6.0f %6s %5s  %s"
              % (i, s["package"][:30], (s.get("version_name") or "?")[:9], score,
                 s["mobsf_score"] if s["mobsf_score"] is not None else "-",
                 s.get("average_cvss") if s.get("average_cvss") is not None else "-", top))
    print(SUB)
    print("  'MobSF' is MobSF's own security_score. It is shown so you can see that the")
    print("  two columns do not have to agree - and when they disagree, ask which one")
    print("  knows what the application is FOR. Neither does; only one pretends to.")
    print(BAR)

    limit = args.top or len(rows)
    for i, (score, s, terms, path, _rep) in enumerate(rows[:limit], 1):
        print()
        print("  %d. %s   [triage %.0f]" % (i, s["package"], score))
        print("     %s  %s  minSdk %s / targetSdk %s   report from MobSF %s"
              % (s["file"][:44], s["size"], s["min_sdk"], s["target_sdk"], s["version"]))
        if s["is_fixture"]:
            print("     *** this report is a shipped FIXTURE, not MobSF output ***")
        if args.explain or i <= 3:
            print("     ranking terms:")
            for pts, key, why in terms:
                print("       %5s  %-28s %s" % (pts, key, why[:60]))
        if s["secrets_raw"]:
            kinds = ", ".join("%s=%d" % (k, v) for k, v in sorted(s["secrets_kinds"].items()))
            print("     secrets: %d raw -> %s" % (s["secrets_raw"], kinds))
            print("              %d are noise by classification alone (pin / URL / too short)"
                  % s["secrets_noise"])
        print("     first three moves:")
        for m in first_moves(s):
            print("       - %s" % m)

    print()
    print(BAR)
    print("  WHAT NO RANKING OF REPORTS CAN SEE")
    print(SUB)
    for line in [
        "runtime-registered receivers - 29-BroadcastReceivers measured 299 of 431 distinct",
        "  actions (69%) with no manifest-declared receiver anywhere on the device.",
        "RegisterNatives bindings - a .so with JNI_OnLoad and no Java_ exports has a native",
        "  surface that is not enumerable from the file at all (16-JNI).",
        "reflection and dynamically loaded DEX - the code may not be in the artefact.",
        "splits - a scan of base.apk alone can report ZERO controls for an app whose code",
        "  ships in split_config APKs. 38-TamperDetection measured exactly that.",
        "server-side enforcement and remote config - not on the device.",
    ]:
        print("  %s" % line)
    print(BAR)

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["rank", "package", "triage_score", "mobsf_security_score",
                        "file", "sha256", "min_sdk", "target_sdk",
                        "exported_activities", "exported_providers", "browsable",
                        "debuggable", "debug_cert", "js_bridge", "http_urls",
                        "nonprod_urls", "secrets_raw", "secrets_interesting",
                        "pin_claimed", "terms"])
            for i, (score, s, terms, _p, _r) in enumerate(rows, 1):
                w.writerow([i, s["package"], "%.0f" % score, s["mobsf_score"], s["file"],
                            s["sha256"], s["min_sdk"], s["target_sdk"],
                            s["exported_activities"], s["exported_providers"], s["browsable"],
                            s["debuggable"], s["debug_cert"], s["js_bridge"], s["http_urls"],
                            s["nonprod_urls"], s["secrets_raw"], s["secrets_interesting"],
                            s["pin_claimed"],
                            "; ".join("%s %s" % (p, k) for p, k, _w in terms)])
        print("  ranking written: %s" % args.csv)


if __name__ == "__main__":
    main()
