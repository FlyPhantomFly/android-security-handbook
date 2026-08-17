#!/usr/bin/env python3
"""
examples/server-app/server.py

PURPOSE
    The other half of the control-group experiment in chapter 67.

    ../guarded-app takes every decision on the device. This server takes the
    decision instead, and the secret only exists on the device if this process
    chose to send it. The app that talks to it is server-app/MainActivity.java.

    The whole argument of the chapter's section 5 is contained in the
    difference between the two, so this file is written to be read, not just
    run. Every design decision below has a comment saying which client-side
    attack it is or is not resistant to.

USAGE
    # host - start the server
    python3 -B server.py                 # 127.0.0.1:8767
    python3 -B server.py --port 9000     # somewhere else

    # host - make the device's loopback reach it. adb reverse creates a real
    # listener ON THE DEVICE, so no root and no network config are needed.
    adb reverse tcp:8767 tcp:8767

    # host - tear the tunnel down when you are finished
    adb reverse --remove tcp:8767

REQUIREMENTS
    Python 3.8+. Standard library only. No Android tooling.

WHAT THIS WILL *NOT* TELL YOU
    * It will NOT tell you that server-side decisions are safe. It tells you
      that this particular secret is not extractable from the APK. A server
      that trusts the client's self-report, or that issues a bearer token an
      attacker can replay, is exactly as broken as the client-side version and
      considerably harder to audit. Read handle_unlock() with that in mind.
    * It will NOT model a real attestation service. Play Integrity involves a
      Google-signed verdict about the device, checked against a nonce, and is
      described in ../../37-RootDetection/README.md section 3.15. Here the
      "attestation" is a plaintext string the client can write whatever it
      likes into - on purpose, so you can watch it not help.
    * It will NOT authenticate anybody. There is no login. Authentication is
      chapter 47's subject.

AUTHORISED USE. Runs on your own machine, talks to your own test app.
"""

import argparse
import http.server
import json
import os
import secrets
import sys
import time

# --------------------------------------------------------------------------- #
# The secret. Note where it lives: here, in a process on your machine, and
# never in the APK. That single fact is what survives every technique in
# chapter 67.
# --------------------------------------------------------------------------- #
SECRET = "CH67{the_only_check_that_held_ran_somewhere_else}"

# Nonces this server has issued and not yet consumed. A nonce is the minimum
# machinery that turns a replayable answer into a single-use one. Without it,
# an attacker captures one successful response and replays it forever, and the
# server-side decision buys nothing at all.
_NONCES = {}
NONCE_TTL_SECONDS = 60

# Session log, printed at exit. The point of a server-side control is that YOU
# get the telemetry; make that visible.
_LOG = []


def _log(kind, detail):
    entry = {"t": round(time.time(), 3), "kind": kind, "detail": detail}
    _LOG.append(entry)
    print("  [{}] {}".format(kind, detail), flush=True)


def parse_report(body: str) -> dict:
    """Parse `k=v;k=v` into a dict. Deliberately forgiving: the client is
    hostile, and a parser that throws on malformed input hands the attacker a
    denial of service."""
    out = {}
    for pair in body.split(";"):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        out[k.strip()] = v.strip()
    return out


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "CH67Ref/1.0"

    # Quieter default logging; we do our own.
    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path.startswith("/nonce"):
            n = secrets.token_hex(16)
            _NONCES[n] = time.time()
            _log("nonce", "issued {}".format(n))
            self._send(200, json.dumps({"nonce": n}), "application/json")
            return
        self._send(404, "no such endpoint\n")

    def do_POST(self):
        if not self.path.startswith("/unlock"):
            self._send(404, "no such endpoint\n")
            return

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        self.handle_unlock(body)

    # ------------------------------------------------------------------ #
    def handle_unlock(self, body: str):
        """
        THE POINT OF THE WHOLE FILE.

        Read the three blocks below in order. They are three different
        relationships a server can have with a client's self-report, and only
        the third one is defensible.
        """
        report = parse_report(body)
        _log("report", body if body else "(empty)")

        # ---------------------------------------------------------------- #
        # Block 1 - what a NAIVE server does, and why it is worthless.
        #
        # If the server refused when the client admitted to being instrumented,
        # the attacker's job would be to flip one boolean in the client - which
        # is the same one-line hook that defeats the client-side version. The
        # decision would have moved to the server in name only.
        #
        # We therefore RECORD the self-report and never GATE on it.
        # ---------------------------------------------------------------- #
        suspicious = [k for k, v in report.items()
                      if k != "forged" and v not in ("false", "0", "-1")]
        if suspicious:
            _log("telemetry",
                 "client self-reports these signals: {} - recorded, NOT acted on"
                 .format(", ".join(suspicious)))
        if report.get("forged") == "true":
            _log("telemetry",
                 "client openly declared a forged report - which changes nothing,"
                 " because the report was never load-bearing")

        # ---------------------------------------------------------------- #
        # Block 2 - what actually gates the response.
        #
        # Nothing about the device. The server checks something only IT knows:
        # a nonce it issued, within its lifetime, not previously consumed.
        # A client cannot forge this, hook it, or patch it, because none of it
        # runs on the client.
        #
        # For the demonstration app there is no login flow, so a missing nonce
        # is permitted once and loudly annotated. In anything real, absence of
        # a nonce is a refusal.
        # ---------------------------------------------------------------- #
        nonce = report.get("nonce")
        if nonce is not None:
            issued = _NONCES.pop(nonce, None)
            if issued is None:
                _log("deny", "unknown or already-consumed nonce {}".format(nonce))
                self._send(403, "denied: nonce not recognised\n")
                return
            if time.time() - issued > NONCE_TTL_SECONDS:
                _log("deny", "nonce {} expired".format(nonce))
                self._send(403, "denied: nonce expired\n")
                return
            _log("allow", "nonce {} consumed".format(nonce))
        else:
            _log("allow",
                 "no nonce supplied - permitted because this demo has no login."
                 " In production this branch is a refusal.")

        # ---------------------------------------------------------------- #
        # Block 3 - what is actually sent.
        #
        # The secret itself, not a boolean saying the client may show a secret
        # it already had. If the response were {"allowed": true} the attacker
        # would flip THAT, and we would be back to a client-side decision with
        # extra latency.
        #
        # This is the whole design rule: send the CAPABILITY, never the
        # PERMISSION.
        # ---------------------------------------------------------------- #
        payload = {
            "secret": SECRET,
            "note": ("You are reading this because the server chose to send it."
                     " No hook on the device could have produced these bytes.")
        }
        _log("send", "secret released")
        self._send(200, json.dumps(payload, indent=2) + "\n", "application/json")


def main():
    ap = argparse.ArgumentParser(description="CH67 reference decision server")
    ap.add_argument("--port", type=int, default=8767)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    httpd = http.server.ThreadingHTTPServer((args.host, args.port), Handler)
    print("CH67 reference server on http://{}:{}".format(args.host, args.port))
    print("endpoints: GET /nonce, POST /unlock")
    print("device side: adb reverse tcp:{} tcp:{}".format(args.port, args.port))
    print("Ctrl-C to stop.\n", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n--- session log ---")
        for e in _LOG:
            print(json.dumps(e))
        print("{} events".format(len(_LOG)))
    finally:
        httpd.server_close()


if __name__ == "__main__":
    sys.exit(main())
