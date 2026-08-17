#!/usr/bin/env python3
# 36-CertificatePinning/labs/ctf-pin-that-moved/challenge_server.py
#
# PURPOSE
#   The server side of the "pin that moved" CTF. It is a TLS server, a key
#   rotation schedule, and a flag oracle in about three hundred lines.
#
#   What makes it a challenge rather than an exercise is the oracle rule:
#
#       The flag is released ONLY to a request that arrives over a connection
#       whose certificate the CLIENT should have refused.
#
#   That is deliberately backwards from how these things usually work, and it is
#   the whole design. You cannot win by disabling every check with a universal
#   bypass, because the server needs to see evidence that the client accepted a
#   specific, wrong certificate -- the one for the ROTATED key. A client with all
#   verification switched off proves nothing, and the oracle says so.
#
#   To get the flag you must make the app accept exactly one certificate you
#   choose, while its pins say otherwise, and prove which one it accepted.
#
# USAGE
#   # 1. generate the CA, the two server keys, and the pins the app will embed
#   python3 -B challenge_server.py --setup
#
#   # 2. print the pin values to compile into the app (see README.md)
#   python3 -B challenge_server.py --pins
#
#   # 3. run the server. It starts on the ORIGINAL key.
#   python3 -B challenge_server.py --serve --port 8443
#
#   # 4. at any point, rotate. Connected clients see the new key on reconnect.
#   python3 -B challenge_server.py --rotate
#
# REQUIREMENTS
#   Python 3.8+, standard library only (ssl, http.server, hashlib, base64,
#   subprocess). `openssl` on PATH for --setup.
#   Everything is written to ./ctf-state/ which must NOT be committed.
#
# WHAT THIS WILL NOT TELL YOU
#   * How to solve the challenge. It is the oracle, not a hint system, and its
#     error strings are deliberately terse.
#   * Whether your bypass is "correct". It only checks the one property the
#     flag depends on.
#   * Anything about the client. It cannot see your hooks and does not try.
#   * It is NOT a hardened server. It binds all interfaces, it has no
#     authentication beyond the oracle rule, and it prints secrets to stdout on
#     request. Run it on a lab network and stop it afterwards.
#
# AUTHORISED TESTING ONLY. Everything here is yours.

import argparse
import base64
import hashlib
import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading
import time

STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ctf-state")
CURRENT = os.path.join(STATE, "current.json")

# The flag. Plain ASCII, no control characters, no fabricated identifiers.
FLAG = "CTF{pins_move_and_so_must_your_assumptions}"

# The decoy flag, served on the path a naive solver will try first. It is
# deliberately shaped like the real one so that "I got a flag" is not the same
# as "I got THE flag".
DECOY = "CTF{you_disabled_everything_which_proves_nothing}"


# --------------------------------------------------------------------- setup

def sh(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True)
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode("utf-8", "replace"))
        raise SystemExit("command failed: %s" % " ".join(cmd))
    return p.stdout


def spki_pin(cert_path):
    """base64(SHA-256(DER SubjectPublicKeyInfo)) -- the same value OkHttp uses."""
    pem = sh(["openssl", "x509", "-in", cert_path, "-pubkey", "-noout"])
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"],
                         input=pem, capture_output=True).stdout
    return base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")


def setup(cn="lab.local"):
    if os.path.isdir(STATE):
        print("state directory already exists: %s" % STATE)
        print("delete it to regenerate (this invalidates the pins in the app)")
        return
    os.makedirs(STATE)

    def keypair(name):
        key = os.path.join(STATE, name + ".key")
        csr = os.path.join(STATE, name + ".csr")
        crt = os.path.join(STATE, name + ".pem")
        sh(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", key])
        sh(["openssl", "req", "-new", "-key", key, "-subj", "/CN=" + cn, "-out", csr])
        sh(["openssl", "x509", "-req", "-in", csr,
            "-CA", os.path.join(STATE, "ca.pem"),
            "-CAkey", os.path.join(STATE, "ca.key"),
            "-CAcreateserial", "-days", "365", "-sha256", "-out", crt])
        return key, crt

    # CA
    sh(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout",
        "-out", os.path.join(STATE, "ca.key")])
    sh(["openssl", "req", "-x509", "-new", "-key", os.path.join(STATE, "ca.key"),
        "-sha256", "-days", "3650", "-subj", "/CN=ch36 ctf CA",
        "-out", os.path.join(STATE, "ca.pem")])

    # Three keys, and the whole puzzle is in what the app is told about them.
    #
    #   original : the key the app is pinned to, and the one it will meet first.
    #   rotated  : the key the server moves to. The app is NOT pinned to it in
    #              its Java pin set -- but its NATIVE pin set contains it, XORed.
    #   decoy    : never served. Its pin is the loudest string in the APK.
    k1, c1 = keypair("original")
    k2, c2 = keypair("rotated")
    k3, c3 = keypair("decoy")

    state = {
        "cn": cn,
        "active": "original",
        "pins": {
            "original": spki_pin(c1),
            "rotated": spki_pin(c2),
            "decoy": spki_pin(c3),
        },
    }
    with open(CURRENT, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

    print("setup complete in %s" % STATE)
    print("")
    print("NOTE: ctf-state/ contains private keys. It is git-ignored by this")
    print("repository's artefact policy and must never be committed.")
    print("")
    show_pins()


def load_state():
    if not os.path.exists(CURRENT):
        raise SystemExit("no state: run --setup first")
    with open(CURRENT, encoding="utf-8") as f:
        return json.load(f)


def save_state(s):
    with open(CURRENT, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2)


def show_pins():
    s = load_state()
    print("pins for %s   (active key: %s)" % (s["cn"], s["active"]))
    print("")
    for name in ("original", "rotated", "decoy"):
        print("  %-9s sha256/%s" % (name, s["pins"][name]))
    print("")
    print("Compile into the app as described in README.md:")
    print("  Java  CertificatePinner : original + decoy")
    print("  native pin_gate.c       : rotated, XOR-obfuscated")
    print("")


def rotate(to=None):
    s = load_state()
    order = ["original", "rotated"]
    if to is None:
        to = order[(order.index(s["active"]) + 1) % len(order)] \
             if s["active"] in order else "rotated"
    if to not in s["pins"]:
        raise SystemExit("unknown key: %s" % to)
    s["active"] = to
    save_state(s)
    print("active key is now: %s (sha256/%s)" % (to, s["pins"][to]))
    print("restart --serve for it to take effect")


# --------------------------------------------------------------------- oracle

class Handler(http.server.BaseHTTPRequestHandler):

    server_version = "ch36-ctf/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        state = self.server.ctf_state
        active = state["active"]
        active_pin = state["pins"][active]

        # ---------------------------------------------------------------
        # /ping -- always works. Confirms the client reached the server at
        # all, which is the observation people skip when a bypass "fails".
        # ---------------------------------------------------------------
        if self.path.startswith("/ping"):
            self._send(200, "pong\nactive-key=%s\n" % active)
            return

        # ---------------------------------------------------------------
        # /flag -- the decoy. Anyone who gets a TLS connection up gets this,
        # including a client with all verification disabled. It is a real
        # response and a real flag-shaped string and it is worth nothing.
        # ---------------------------------------------------------------
        if self.path.startswith("/flag"):
            self._send(200, DECOY + "\n")
            return

        # ---------------------------------------------------------------
        # /claim -- the oracle.
        #
        # The client must present a header proving WHICH certificate its
        # pinning layer accepted:
        #
        #     X-Accepted-Pin: sha256/<base64>
        #
        # and that value must equal the pin of the key the server is CURRENTLY
        # serving. The app computes this header itself, from the certificate
        # its own pinning code approved -- so a client that accepted nothing,
        # or that had its verification turned off wholesale, cannot fill it in
        # correctly.
        #
        # This is why "disable everything" does not win. The header has to be
        # right, and it is only right if a specific pin accepted a specific
        # key.
        # ---------------------------------------------------------------
        if self.path.startswith("/claim"):
            claimed = self.headers.get("X-Accepted-Pin", "")
            if not claimed:
                self._send(400, "no X-Accepted-Pin header\n")
                return
            if not claimed.startswith("sha256/"):
                self._send(400, "malformed pin: expected sha256/<base64>\n")
                return

            value = claimed[len("sha256/"):]

            if value == state["pins"]["decoy"]:
                self._send(403, "that pin belongs to a key this server has "
                                "never served. Where did you get it?\n")
                return

            if value != active_pin:
                self._send(403, "pin mismatch: the server is not serving that "
                                "key right now\n")
                return

            if active != "rotated":
                self._send(403, "correct, but this is the key you were already "
                                "pinned to. Nothing has been demonstrated.\n")
                return

            self._send(200, FLAG + "\n")
            return

        self._send(404, "not found\n")


def serve(port, host="0.0.0.0"):
    state = load_state()
    cert = os.path.join(STATE, state["active"] + ".pem")
    key = os.path.join(STATE, state["active"] + ".key")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)

    httpd = http.server.ThreadingHTTPServer((host, port), Handler)
    httpd.ctf_state = state
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print("serving https://%s:%d" % (host, port))
    print("active key : %s  sha256/%s" % (state["active"], state["pins"][state["active"]]))
    print("endpoints  : /ping  /flag (decoy)  /claim (oracle)")
    print("")
    print("CA to install on the device (or not -- that is part of the puzzle):")
    print("  %s" % os.path.join(STATE, "ca.pem"))
    print("")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
        httpd.server_close()


# ----------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="ch36 CTF server: the pin that moved")
    ap.add_argument("--setup", action="store_true", help="generate CA and keys")
    ap.add_argument("--pins", action="store_true", help="print the pin values")
    ap.add_argument("--rotate", action="store_true", help="switch the served key")
    ap.add_argument("--to", help="rotate to a specific key (original|rotated)")
    ap.add_argument("--serve", action="store_true", help="run the server")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cn", default="lab.local", help="common name for the certs")
    ap.add_argument("--clean", action="store_true", help="delete ctf-state/")
    args = ap.parse_args()

    if args.clean:
        shutil.rmtree(STATE, ignore_errors=True)
        print("removed %s" % STATE)
        return 0
    if args.setup:
        setup(args.cn)
        return 0
    if args.pins:
        show_pins()
        return 0
    if args.rotate or args.to:
        rotate(args.to)
        return 0
    if args.serve:
        serve(args.port)
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
