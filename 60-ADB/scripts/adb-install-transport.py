#!/usr/bin/env python3
"""
adb-install-transport.py -- perform a complete `adb install` over the raw ADB
                            wire protocol, with no `adb` binary anywhere, to
                            show that `adb install` is not one operation but
                            three ordinary streams driving the PackageInstaller
                            session API.

WHY THIS EXISTS
    `adb install app.apk` looks atomic. It is not, and believing it is will
    mislead you about where an install can be observed, intercepted or fail.
    What actually happens is:

        stream 1   exec:cmd package install-create -r -S <bytes>
                   -> "Success: created install session [1234567]"
        stream 2   exec:cmd package install-write -S <bytes> <session> base -
                   <- the APK bytes, as ordinary A_WRTE payloads on that stream
                   -> "Success: streamed <bytes> bytes"
        stream 3   exec:cmd package install-commit <session>
                   -> "Success"   or a Failure[...] you have to read carefully

    Three separate streams, three separate service strings, one session id
    tying them together. The APK never travels as a special message type. It
    is A_WRTE payloads, chunked to the peer's maxdata, exactly like the output
    of `ls`. The package manager half of this lives in chapter 09; this script
    owns the transport half.

    The intermediate state is real and observable: between install-create and
    install-commit there is a staging directory on the device
    (/data/app/vmdl<session>.tmp) holding a partially written APK that no
    installed-package query will ever show you.

WHAT IT DOES
    Connects to an adbd listening on TCP, authenticates if asked, then runs
    the three streams above and prints each service string, each stream-id
    pair, and each response verbatim. With --abb it uses the abb_exec service
    instead, where the arguments are NUL-delimited and never pass through a
    shell -- which is what a modern `adb` client actually does when the device
    advertises the `abb_exec` feature.

HOW TO RUN
    # An emulator is the right target: it listens on TCP already and you can
    # throw it away. emulator-5554 is 127.0.0.1:5555.
    python3 -B adb-install-transport.py --port 5555 --apk ./probe.apk

    # the modern path, no shell involved
    python3 -B adb-install-transport.py --port 5555 --apk ./probe.apk --abb

    # show every message on the wire
    python3 -B adb-install-transport.py --port 5555 --apk ./probe.apk -v

    # stop after install-write so you can go and look at the staging dir
    python3 -B adb-install-transport.py --port 5555 --apk ./probe.apk --no-commit

    # clean up a session you abandoned
    python3 -B adb-install-transport.py --port 5555 --abandon 1234567

REQUIREMENTS
    Python 3.6+, standard library only. An adbd reachable over TCP whose
    banner advertises `cmd` (every build since API 24 does). A private key at
    ~/.android/adbkey if the target enforces authentication.

    Build a throwaway APK to install with, out of tree, in one command chain:
        aapt2 link -o u.apk --manifest AndroidManifest.xml -I android.jar
        zipalign -p -f 4 u.apk a.apk
        apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android \\
            --out probe.apk a.apk
    A manifest with android:hasCode="false" and no components is enough; the
    point here is the transport, not the app.

WHAT THIS WILL *NOT* TELL YOU
    - Why an install was REFUSED. This script prints the exact string the
      package manager returned and stops there. INSTALL_FAILED_USER_RESTRICTED
      in particular is an OEM policy decision made far above the transport --
      on the MIUI device this repository uses, the same three streams driven by
      root (`su -c 'pm install'`) succeed while the shell user's do not, which
      proves the transport was never the problem.
    - Anything about verification. Play Protect, the install verifier and
      signature checking all run inside PackageManagerService after commit.
      They are chapter 09 and chapter 10, not this file.
    - How split APKs are staged. The mechanism is identical -- one
      install-write stream per split, each with its own name in place of
      "base" -- but this script writes a single base APK and does not pretend
      to handle a bundle.
    - Whether the device kept the staging directory. If commit fails, the
      session may or may not be cleaned up automatically; use --abandon.
    - The `sync:` file-transfer protocol. `adb push` uses a completely
      different sub-protocol (SEND/RECV/STAT/DONE over one stream, documented
      in AOSP SYNC.TXT). This script deliberately does not push the APK to
      /data/local/tmp first -- it streams the bytes into install-write, which
      is what `adb install` does and is why a push is not required.
"""

import argparse
import base64
import os
import re
import socket
import struct
import sys
import time

# --------------------------------------------------------------------------
# Framing. Kept deliberately short and duplicated from adb-mini-client.py so
# this file runs on its own, with no sibling import and therefore no
# __pycache__ to sweep up afterwards.
# --------------------------------------------------------------------------

A_CNXN = 0x4E584E43
A_OPEN = 0x4E45504F
A_OKAY = 0x59414B4F
A_CLSE = 0x45534C43
A_WRTE = 0x45545257
A_AUTH = 0x48545541
A_STLS = 0x534C5453

NAMES = {A_CNXN: "A_CNXN", A_OPEN: "A_OPEN", A_OKAY: "A_OKAY",
         A_CLSE: "A_CLSE", A_WRTE: "A_WRTE", A_AUTH: "A_AUTH",
         A_STLS: "A_STLS"}

ADB_AUTH_TOKEN = 1
ADB_AUTH_SIGNATURE = 2
ADB_AUTH_RSAPUBLICKEY = 3

A_VERSION = 0x01000001
MAX_PAYLOAD = 256 * 1024

SHA1_DIGESTINFO = bytes([
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
    0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
])


def cmd_name(c):
    return NAMES.get(c, "0x%08x(?)" % c)


class Wire(object):
    def __init__(self, sock, verbose=False):
        self.sock = sock
        self.verbose = verbose
        self.peer_maxdata = 4096

    def _exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("adbd closed the connection")
            buf += chunk
        return buf

    def send(self, command, arg0, arg1, payload=b""):
        head = struct.pack("<6I", command, arg0, arg1, len(payload),
                           sum(payload) & 0xFFFFFFFF, command ^ 0xFFFFFFFF)
        if self.verbose:
            sys.stderr.write(">> %-7s arg0=%d arg1=%d len=%d\n"
                             % (cmd_name(command), arg0, arg1, len(payload)))
        self.sock.sendall(head + payload)

    def recv(self):
        head = self._exact(24)
        command, arg0, arg1, length, _csum, magic = struct.unpack("<6I", head)
        if magic != (command ^ 0xFFFFFFFF):
            raise IOError("framing lost on %s" % cmd_name(command))
        payload = self._exact(length) if length else b""
        if self.verbose:
            sys.stderr.write("<< %-7s arg0=%d arg1=%d len=%d\n"
                             % (cmd_name(command), arg0, arg1, length))
        return command, arg0, arg1, payload


# --------------------------------------------------------------------------
# Key handling. See adb-mini-client.py for the annotated version; the private
# key is used to produce one signature and is never printed or stored.
# --------------------------------------------------------------------------

def _der_read(buf, pos):
    tag = buf[pos]; pos += 1
    first = buf[pos]; pos += 1
    if first & 0x80:
        nb = first & 0x7F
        length = int.from_bytes(buf[pos:pos + nb], "big")
        pos += nb
    else:
        length = first
    return tag, buf[pos:pos + length], pos + length


def _der_ints(seq):
    out, pos = [], 0
    while pos < len(seq):
        tag, body, pos = _der_read(seq, pos)
        out.append(int.from_bytes(body, "big") if tag == 0x02 else None)
    return out


def load_private_key(path):
    with open(path, "rb") as fh:
        pem = fh.read()
    der = base64.b64decode(b"".join(
        l for l in pem.split(b"\n") if l and not l.startswith(b"-----")))
    _tag, outer, _ = _der_read(der, 0)
    ints = _der_ints(outer)
    if len(ints) >= 9 and ints[0] == 0 and ints[1] and ints[1] > 255:
        return ints[1], ints[3]
    pos = 0
    _t, _v, pos = _der_read(outer, pos)
    _t, _a, pos = _der_read(outer, pos)
    _t, inner, pos = _der_read(outer, pos)
    _t, pk1, _ = _der_read(inner, 0)
    ints = _der_ints(pk1)
    return ints[1], ints[3]


def sign_token(token, n, d):
    k = (n.bit_length() + 7) // 8
    t = SHA1_DIGESTINFO + token
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


# --------------------------------------------------------------------------

def connect(wire, keypath, features="cmd,abb_exec,stat_v2"):
    wire.send(A_CNXN, A_VERSION, MAX_PAYLOAD,
              ("host::features=%s" % features).encode() + b"\x00")
    signed = False
    while True:
        command, arg0, arg1, payload = wire.recv()
        if command == A_CNXN:
            wire.peer_maxdata = min(arg1, MAX_PAYLOAD) if arg1 else 4096
            banner = payload.rstrip(b"\x00").decode("utf-8", "replace")
            feats = ""
            m = re.search(r"features=([^;]*)", banner)
            if m:
                feats = m.group(1)
            return banner, feats
        if command == A_STLS:
            raise RuntimeError(
                "adbd wants TLS (wireless debugging). Not supported here.")
        if command == A_AUTH and arg0 == ADB_AUTH_TOKEN:
            if signed:
                raise RuntimeError(
                    "signature rejected: this host key is not in "
                    "/data/misc/adb/adb_keys on the target. Authorise it with "
                    "the real adb client once, on a device you own.")
            n, d = load_private_key(keypath)
            wire.send(A_AUTH, ADB_AUTH_SIGNATURE, 0, sign_token(payload, n, d))
            signed = True
            continue
        raise IOError("unexpected %s during connect" % cmd_name(command))


class Stream(object):
    """One A_OPEN..A_CLSE conversation, with the flow control adb requires."""

    def __init__(self, wire, local_id):
        self.wire = wire
        self.local_id = local_id
        self.remote_id = None
        self.closed = False
        self.collected = b""

    def _next_for_me(self):
        """Read until a message addressed to THIS stream arrives.

        This loop is the whole reason stream ids exist. adbd is free to send
        the A_CLSE that finishes stream 1 after we have already sent the
        A_OPEN for stream 2, and a client that assumes the next message
        belongs to the stream it just opened will misread a stale close as a
        refusal. It is a one-connection multiplexer, and arg1 -- our own local
        id, echoed back -- is the only demultiplexing key there is.
        """
        while True:
            command, arg0, arg1, payload = self.wire.recv()
            if arg1 == self.local_id or command == A_CNXN:
                return command, arg0, arg1, payload
            if self.wire.verbose:
                sys.stderr.write("   (message for stream %d, not %d -- "
                                 "ignored)\n" % (arg1, self.local_id))

    def open(self, service):
        printable = service.replace("\x00", " \\x00 ")
        print("  A_OPEN local-id=%d  %s" % (self.local_id, printable))
        self.wire.send(A_OPEN, self.local_id, 0,
                       service.encode("utf-8") + b"\x00")
        command, arg0, arg1, _ = self._next_for_me()
        if command == A_CLSE:
            self.closed = True
            raise RuntimeError(
                "adbd refused the service outright (A_CLSE with remote-id=%d). "
                "That is what an unknown or unavailable service looks like."
                % arg0)
        if command != A_OKAY:
            raise IOError("expected A_OKAY, got %s" % cmd_name(command))
        self.remote_id = arg0
        print("  A_OKAY remote-id=%d  (stream up)" % self.remote_id)
        return self

    def write(self, data, label=""):
        """Chunk to the peer's maxdata and wait for the A_OKAY on each chunk.

        The wait is not optional. adb's flow control is exactly one
        outstanding A_WRTE per stream: send a second before the first is
        acknowledged and a strict peer drops the connection.
        """
        maxd = self.wire.peer_maxdata
        sent = 0
        chunks = 0
        while sent < len(data):
            chunk = data[sent:sent + maxd]
            self.wire.send(A_WRTE, self.local_id, self.remote_id, chunk)
            sent += len(chunk)
            chunks += 1
            while True:
                command, arg0, arg1, payload = self._next_for_me()
                if command == A_OKAY:
                    break
                if command == A_WRTE:
                    self.collected += payload
                    self.wire.send(A_OKAY, self.local_id, self.remote_id)
                    continue
                if command == A_CLSE:
                    self.closed = True
                    raise RuntimeError(
                        "device closed the stream after %d of %d bytes"
                        % (sent, len(data)))
        if label:
            print("  A_WRTE %s: %d bytes in %d chunk(s) of at most %d"
                  % (label, sent, chunks, maxd))
        return sent

    def drain(self, timeout=20.0):
        deadline = time.time() + timeout
        self.wire.sock.settimeout(0.5)
        try:
            while time.time() < deadline and not self.closed:
                try:
                    command, arg0, arg1, payload = self._next_for_me()
                except socket.timeout:
                    continue
                except EOFError:
                    break
                if command == A_WRTE:
                    self.collected += payload
                    self.wire.send(A_OKAY, self.local_id, self.remote_id)
                elif command == A_CLSE:
                    self.closed = True
                    self.wire.send(A_CLSE, self.local_id, arg0)
        finally:
            self.wire.sock.settimeout(None)
        return self.collected.decode("utf-8", "replace").strip()

    def close(self):
        if not self.closed and self.remote_id is not None:
            self.wire.send(A_CLSE, self.local_id, self.remote_id)
            self.closed = True


def build_service(use_abb, argv):
    """`exec:` runs the command through a shell; `abb_exec:` does not.

    That difference is not cosmetic. With `exec:cmd package install-write ...`
    every argument is subject to one round of shell word-splitting and
    quoting on the device -- the same trap that produced a real bug elsewhere
    in this repository, where `su -c "ls -l x"` reached the device as
    `su -c ls -l x`. With `abb_exec:` the arguments are NUL-delimited in the
    service string itself, `cmd` is already running inside system_server, and
    no shell exists to mangle anything.
    """
    if use_abb:
        return "abb_exec:" + "\x00".join(argv[1:])   # drop the leading "cmd"
    return "exec:" + " ".join(argv)


def main():
    home = os.path.expanduser("~")
    ap = argparse.ArgumentParser(
        description="Drive the PackageInstaller session API over raw ADB.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--apk", help="APK to install")
    ap.add_argument("--key", default=os.path.join(home, ".android", "adbkey"))
    ap.add_argument("--abb", action="store_true",
                    help="use abb_exec instead of exec (no shell involved)")
    ap.add_argument("--reinstall", action="store_true", default=True,
                    help="pass -r to install-create (default)")
    ap.add_argument("--no-commit", action="store_true",
                    help="stop after install-write, leaving the session open")
    ap.add_argument("--abandon", type=int, metavar="SESSION",
                    help="abandon a session id and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if not args.abandon and not args.apk:
        ap.error("--apk is required unless --abandon is used")

    try:
        sock = socket.create_connection((args.host, args.port), timeout=10)
    except OSError as exc:
        sys.stderr.write(
            "cannot reach adbd at %s:%d (%s). A physical device only listens "
            "on TCP after `adb tcpip`; use an emulator instead.\n"
            % (args.host, args.port, exc))
        return 2

    wire = Wire(sock, verbose=args.verbose)
    try:
        banner, feats = connect(wire, args.key)
    except (RuntimeError, IOError, EOFError) as exc:
        sys.stderr.write("handshake failed: %s\n" % exc)
        return 1

    print("connected. maxdata=%d" % wire.peer_maxdata)
    if args.abb and "abb_exec" not in feats:
        print("WARNING: adbd did not advertise abb_exec. Falling back to exec.")
        args.abb = False
    print("transport: %s" % ("abb_exec (no shell)" if args.abb else "exec (via sh)"))
    print("")

    next_id = [1]

    def stream(argv):
        sid = next_id[0]
        next_id[0] += 1
        return Stream(wire, sid).open(build_service(args.abb, argv))

    if args.abandon:
        st = stream(["cmd", "package", "install-abandon", str(args.abandon)])
        print("  reply: %s" % st.drain())
        st.close()
        sock.close()
        return 0

    size = os.path.getsize(args.apk)
    with open(args.apk, "rb") as fh:
        blob = fh.read()
    print("APK: %s  (%d bytes)" % (args.apk, size))
    print("")

    # ---- stream 1: create the session -----------------------------------
    print("STREAM 1 -- install-create")
    argv = ["cmd", "package", "install-create"]
    if args.reinstall:
        argv.append("-r")
    argv += ["-S", str(size)]
    st1 = stream(argv)
    reply = st1.drain()
    st1.close()
    print("  reply: %s" % reply)
    m = re.search(r"\[(\d+)\]", reply)
    if not m:
        sys.stderr.write("could not parse a session id out of that reply.\n")
        sock.close()
        return 1
    session = m.group(1)
    print("  session id: %s" % session)
    print("  a staging directory now exists at /data/app/vmdl%s.tmp" % session)
    print("")

    # ---- stream 2: stream the bytes in ----------------------------------
    print("STREAM 2 -- install-write  (the APK travels as A_WRTE payloads)")
    st2 = stream(["cmd", "package", "install-write",
                  "-S", str(size), session, "base", "-"])
    st2.write(blob, label="APK body")
    reply2 = st2.drain()
    st2.close()
    print("  reply: %s" % reply2)
    print("")

    if args.no_commit:
        print("--no-commit: session %s left open." % session)
        print("Look at it now, then clean up:")
        print("  adb shell ls -l /data/app/vmdl%s.tmp" % session)
        print("  python3 -B %s --port %d --abandon %s"
              % (os.path.basename(sys.argv[0]), args.port, session))
        sock.close()
        return 0

    # ---- stream 3: commit ------------------------------------------------
    print("STREAM 3 -- install-commit")
    st3 = stream(["cmd", "package", "install-commit", session])
    reply3 = st3.drain(timeout=60.0)
    st3.close()
    print("  reply: %s" % reply3)
    print("")

    ok = reply3.startswith("Success")
    print("RESULT: %s" % ("installed" if ok else "NOT installed"))
    if not ok:
        print("The transport did its job -- every byte arrived and the session")
        print("was committed. What you are reading is PackageManagerService's")
        print("verdict, and it is a package-manager question, not an adb one.")
    sock.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
