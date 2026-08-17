#!/usr/bin/env python3
"""
adb-mini-client.py -- speak the ADB wire protocol to adbd with no `adb` client,
                      no `adb` server, and no third-party Python packages.

WHY THIS EXISTS
    You cannot understand a protocol you have only ever driven through a tool
    that hides it. `adb shell id` is four protocol messages and a stream-id
    pair; the client makes it look like a function call. This script removes
    the client. It builds each 24-byte header by hand, signs the authentication
    token with the RSA key already in ~/.android/, opens one stream, and prints
    every message that crosses the wire in both directions.

    Everything it does is described in AOSP `packages/modules/adb/protocol.txt`.
    Nothing here is a trick; it is the same handshake `adb` performs, written
    small enough to read in one sitting.

WHAT IT DOES
    1.  Opens a TCP socket to an adbd that is listening on TCP.
    2.  Sends  A_CNXN(version, maxdata, "host::features=...").
    3.  If adbd answers A_AUTH(TOKEN) -- which it will whenever
        ro.adb.secure=1 -- it signs the 20-byte token with the PRIVATE key at
        ~/.android/adbkey using RSA PKCS#1 v1.5 over a SHA-1 DigestInfo, and
        replies A_AUTH(SIGNATURE). If adbd rejects the signature (your key is
        not in /data/misc/adb/adb_keys) it optionally offers the PUBLIC key
        with A_AUTH(RSAPUBLICKEY), which is what makes the "Allow USB
        debugging?" dialog appear ON THE DEVICE SCREEN.
    4.  On A_CNXN back, prints the device banner and the feature set adbd
        advertised -- the real, negotiated capability list for this session.
    5.  Sends A_OPEN(local-id, 0, "<service>\\x00"), waits for
        A_OKAY(remote-id, local-id), pumps A_WRTE payloads, and closes with
        A_CLSE. The stream ids it prints are the actual multiplexing keys.

HOW TO RUN
    # A device that is listening on TCP. An emulator always is, on
    # 127.0.0.1:5555 for emulator-5554, 5557 for -5556, and so on.
    python3 -B adb-mini-client.py --host 127.0.0.1 --port 5555

    # A different service. Anything adbd exposes is fair game.
    python3 -B adb-mini-client.py --port 5555 --service "shell:id"
    python3 -B adb-mini-client.py --port 5555 --service "shell:getprop ro.build.version.sdk"
    python3 -B adb-mini-client.py --port 5555 --service "sync:"     --raw
    python3 -B adb-mini-client.py --port 5555 --service "reverse:list-forward"

    # Show every byte of every header, and hexdump payloads.
    python3 -B adb-mini-client.py --port 5555 --verbose

    # Handshake only. Connect, authenticate, print the banner, disconnect.
    python3 -B adb-mini-client.py --port 5555 --handshake-only

    # Do NOT offer the public key even if the signature is rejected. Use this
    # on a device you do not own: without it, a rejected signature raises a
    # consent dialog on someone else's screen.
    python3 -B adb-mini-client.py --port 5555 --no-offer-key

REQUIREMENTS
    Python 3.6+. Standard library only -- no pyasn1, no cryptography, no
    pyusb. RSA is done with int arithmetic and pow(); DER is parsed by hand.
    An adbd reachable over TCP. A private key at ~/.android/adbkey if the
    target enforces authentication (pass --key to point elsewhere).

SAFETY
    This script NEVER prints, copies, logs or transmits your private key. It
    reads ~/.android/adbkey into memory, uses it to produce one 256-byte
    signature, and that is all. The only thing it can put on the wire that is
    derived from your identity is the PUBLIC key, and only when you have not
    passed --no-offer-key and the device rejected your signature.

    It does not enable TCP mode on anything. If a device is not already
    listening on TCP, this script cannot reach it and says so. Turning USB
    debugging into a network service is a decision with real consequences and
    it is not one a script should make for you.

WHAT THIS WILL *NOT* TELL YOU
    - Anything over USB. On USB the transport is FunctionFS bulk endpoints
      (/dev/usb-ffs/adb/ep1 and ep2 on the device side), reached through a
      kernel USB host stack that already has the interface claimed by your
      running `adb` server. Talking to it needs libusb and an exclusive claim;
      that is a different program. The MESSAGES are byte-identical -- only the
      pipe under them changes -- which is exactly why TCP is the right place
      to learn them.
    - Anything about a device using TLS (wireless debugging pairing, Android
      11+). If adbd answers A_STLS this script reports it and stops, because
      completing that handshake needs the pairing-derived certificate, not the
      adbkey. It will not pretend to have succeeded.
    - Whether your key is authorised, until you try. There is no query for
      "is this key trusted"; the protocol answers by either completing the
      handshake or asking again.
    - The shell v2 framing. This client deliberately does NOT advertise
      `shell_v2` in its banner, so adbd falls back to the v1 shell service and
      A_WRTE payloads are raw bytes with stdout and stderr merged and no exit
      code. That is a simplification, and it is visible in the banner this
      script prints -- compare it with `adb host-features`.
    - Whether a payload arrived intact. The checksum field is computed here
      (see checksum() below) but modern adbd does not verify it, so a wrong
      value is not an error you will observe.
"""

import argparse
import base64
import hashlib
import os
import socket
import struct
import sys
import time

# ---------------------------------------------------------------------------
# The message types. Each is four ASCII characters read as a little-endian
# uint32, which is why the constants look arbitrary and are not.
#
#   "CNXN" = 43 4e 58 4e  ->  read LE  ->  0x4e584e43
#
# The 24-byte header is six little-endian uint32 fields:
#
#   command | arg0 | arg1 | data_length | data_checksum | magic
#
# where magic is always command XOR 0xffffffff. A receiver that reads a header
# whose magic does not match the command has lost framing, and the only
# recovery is to drop the connection.
# ---------------------------------------------------------------------------

A_SYNC = 0x434E5953
A_CNXN = 0x4E584E43
A_OPEN = 0x4E45504F
A_OKAY = 0x59414B4F
A_CLSE = 0x45534C43
A_WRTE = 0x45545257
A_AUTH = 0x48545541
A_STLS = 0x534C5453

NAMES = {
    A_SYNC: "A_SYNC",
    A_CNXN: "A_CNXN",
    A_OPEN: "A_OPEN",
    A_OKAY: "A_OKAY",
    A_CLSE: "A_CLSE",
    A_WRTE: "A_WRTE",
    A_AUTH: "A_AUTH",
    A_STLS: "A_STLS",
}

# A_AUTH arg0 values.
ADB_AUTH_TOKEN = 1        # device -> host: here is a 20-byte challenge
ADB_AUTH_SIGNATURE = 2    # host -> device: here is that challenge, signed
ADB_AUTH_RSAPUBLICKEY = 3 # host -> device: here is my public key, ask the user

# Protocol version. 0x01000000 is the original; 0x01000001 raised the maximum
# payload from 4 KiB to 256 KiB and stopped anyone verifying the checksum.
A_VERSION = 0x01000001
MAX_PAYLOAD = 256 * 1024

# The device sends exactly this many bytes as its challenge. adbd treats them
# as an already-computed SHA-1 digest -- it is not, it is 20 random bytes, but
# it is fed to RSA_sign(NID_sha1, ...) as though it were.
TOKEN_SIZE = 20

# ASN.1 DigestInfo prefix for SHA-1, prepended before PKCS#1 v1.5 padding.
# 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14
SHA1_DIGESTINFO = bytes([
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
    0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
])


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

def checksum(payload):
    """The 'data_crc32' field.

    protocol.txt calls this a CRC32. The implementation
    (packages/modules/adb/types.h, calculate_apacket_checksum) is a plain sum
    of the payload bytes truncated to 32 bits, and since A_VERSION 0x01000001
    nothing verifies it at all. Both facts are worth knowing: the name in the
    documentation and the behaviour of the code disagree, and neither matters
    to a receiver.
    """
    return sum(payload) & 0xFFFFFFFF


def pack(command, arg0, arg1, payload=b""):
    return struct.pack(
        "<6I", command, arg0, arg1, len(payload),
        checksum(payload), command ^ 0xFFFFFFFF) + payload


def cmd_name(command):
    return NAMES.get(command, "0x%08x(?)" % command)


class Wire(object):
    """A framed message channel over one TCP socket."""

    def __init__(self, sock, verbose=False):
        self.sock = sock
        self.verbose = verbose
        self.peer_maxdata = MAX_PAYLOAD

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise EOFError(
                    "adbd closed the connection after %d of %d bytes. "
                    "That is what a refused handshake looks like." % (len(buf), n))
            buf += chunk
        return buf

    def send(self, command, arg0, arg1, payload=b""):
        if len(payload) > self.peer_maxdata:
            raise ValueError(
                "payload %d exceeds the peer's advertised maxdata %d"
                % (len(payload), self.peer_maxdata))
        raw = pack(command, arg0, arg1, payload)
        if self.verbose:
            self._trace(">>", raw[:24], payload)
        self.sock.sendall(raw)

    def recv(self):
        head = self._recv_exact(24)
        command, arg0, arg1, length, csum, magic = struct.unpack("<6I", head)
        if magic != (command ^ 0xFFFFFFFF):
            raise IOError(
                "framing lost: command=0x%08x magic=0x%08x (expected 0x%08x)"
                % (command, magic, command ^ 0xFFFFFFFF))
        payload = self._recv_exact(length) if length else b""
        if self.verbose:
            self._trace("<<", head, payload)
        return command, arg0, arg1, payload

    def _trace(self, direction, head, payload):
        command, arg0, arg1, length, csum, magic = struct.unpack("<6I", head)
        sys.stderr.write(
            "%s %-7s arg0=0x%08x arg1=0x%08x len=%-6d cksum=0x%08x magic=0x%08x\n"
            % (direction, cmd_name(command), arg0, arg1, length, csum, magic))
        sys.stderr.write("   header bytes: %s\n" % head.hex())
        if payload:
            sys.stderr.write(hexdump(payload[:96], indent="   "))
            if len(payload) > 96:
                sys.stderr.write("   ... %d more payload bytes\n"
                                 % (len(payload) - 96))


def hexdump(data, indent=""):
    out = []
    for off in range(0, len(data), 16):
        row = data[off:off + 16]
        hexpart = " ".join("%02x" % b for b in row)
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append("%s%04x  %-47s  |%s|\n" % (indent, off, hexpart, txt))
    return "".join(out)


# ---------------------------------------------------------------------------
# The key. Parsed by hand so this file has no dependencies.
#
# ~/.android/adbkey is an UNENCRYPTED PKCS#8 PEM. That is worth sitting with
# for a moment: it is a private key, on disk, with no passphrase, and any
# device that has ever shown you "Always allow from this computer" will accept
# it for as long as the entry survives in /data/misc/adb/adb_keys.
# ---------------------------------------------------------------------------

def _der_read(buf, pos):
    """Read one TLV. -> (tag, contents_bytes, next_pos)"""
    tag = buf[pos]
    pos += 1
    first = buf[pos]
    pos += 1
    if first & 0x80:
        nbytes = first & 0x7F
        if nbytes == 0 or nbytes > 4:
            raise ValueError("unsupported DER length form")
        length = int.from_bytes(buf[pos:pos + nbytes], "big")
        pos += nbytes
    else:
        length = first
    return tag, buf[pos:pos + length], pos + length


def _der_ints(seq):
    """Every INTEGER inside a SEQUENCE body, in order, as Python ints."""
    out = []
    pos = 0
    while pos < len(seq):
        tag, body, pos = _der_read(seq, pos)
        if tag == 0x02:
            out.append(int.from_bytes(body, "big"))
        elif tag == 0x30:
            out.append(None)  # nested SEQUENCE (AlgorithmIdentifier)
        else:
            out.append(None)
    return out


def load_private_key(path):
    """-> (n, d, bits). Accepts PKCS#8 or PKCS#1 PEM. Never returns the file."""
    with open(path, "rb") as fh:
        pem = fh.read()
    body = b"".join(
        line for line in pem.split(b"\n")
        if line and not line.startswith(b"-----"))
    der = base64.b64decode(body)

    tag, outer, _ = _der_read(der, 0)
    if tag != 0x30:
        raise ValueError("%s: not a DER SEQUENCE" % path)

    # PKCS#1 "RSA PRIVATE KEY": version, n, e, d, p, q, dp, dq, qinv
    ints = _der_ints(outer)
    if len(ints) >= 9 and ints[0] == 0 and ints[1] is not None and ints[1] > 255:
        n, d = ints[1], ints[3]
        return n, d, n.bit_length()

    # PKCS#8 "PRIVATE KEY": version, AlgorithmIdentifier, OCTET STRING(pkcs1)
    pos = 0
    tag, _ver, pos = _der_read(outer, pos)      # INTEGER 0
    tag, _alg, pos = _der_read(outer, pos)      # SEQUENCE AlgorithmIdentifier
    tag, inner, pos = _der_read(outer, pos)     # OCTET STRING
    if tag != 0x04:
        raise ValueError("%s: expected an OCTET STRING at PKCS#8 offset" % path)
    tag, pk1, _ = _der_read(inner, 0)
    ints = _der_ints(pk1)
    if len(ints) < 4:
        raise ValueError("%s: RSAPrivateKey has too few components" % path)
    n, d = ints[1], ints[3]
    return n, d, n.bit_length()


def sign_token(token, n, d):
    """RSA PKCS#1 v1.5 signature over SHA1-DigestInfo(token).

    adbd's host side calls RSA_sign(NID_sha1, token, 20, ...). RSA_sign with
    NID_sha1 does NOT hash its input -- it expects a 20-byte digest and wraps
    it in the DigestInfo above. The token is 20 bytes, so it is fed straight
    in. The device is therefore verifying a signature over a value that was
    never hashed by anybody, which works fine and surprises everybody.
    """
    if len(token) != TOKEN_SIZE:
        raise ValueError("token is %d bytes, expected %d" % (len(token), TOKEN_SIZE))
    k = (n.bit_length() + 7) // 8
    t = SHA1_DIGESTINFO + token
    if k < len(t) + 11:
        raise ValueError("key too small for a PKCS#1 v1.5 signature")
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    m = int.from_bytes(em, "big")
    s = pow(m, d, n)
    return s.to_bytes(k, "big")


def load_public_key(path):
    """The exact bytes adbd wants in A_AUTH(RSAPUBLICKEY): base64 blob, space,
    comment, and a terminating NUL.

    The blob decodes to a 524-byte C struct, not an SPKI:

        uint32 len          modulus size in 32-bit words (64 for RSA-2048)
        uint32 n0inv        -R^-1 mod 2^32, a Montgomery constant
        uint32 n[len]       modulus,   little-endian words
        uint32 rr[len]      R^2 mod n, little-endian words
        int32  exponent     3 or 65537

        4 + 4 + 256 + 256 + 4 = 524

    It is the layout of the old `mincrypt` verifier that the bootloader and
    recovery also used, which is why it is a bare struct rather than any
    standard encoding.
    """
    with open(path, "rb") as fh:
        data = fh.read().strip()
    return data + b"\x00"


# ---------------------------------------------------------------------------
# The handshake
# ---------------------------------------------------------------------------

def banner_for_host(features):
    """'<systemtype>:<serialno>:<banner>'.

    Deliberately modest: we do not claim shell_v2, so adbd gives us the v1
    shell service and A_WRTE payloads are raw terminal bytes. Claim shell_v2
    here and every payload arrives packetised with a one-byte stream id and a
    four-byte length, and this client's output handling would be wrong.
    """
    return ("host::features=%s" % features).encode("utf-8") + b"\x00"


def parse_banner(payload):
    text = payload.rstrip(b"\x00").decode("utf-8", "replace")
    systemtype, _, rest = text.partition(":")
    serial, _, banner = rest.partition(":")
    props = {}
    for item in banner.split(";"):
        if "=" in item:
            k, v = item.split("=", 1)
            props[k.strip()] = v
    return systemtype, serial, banner, props


def do_connect(wire, keypath, pubpath, offer_key, features):
    """Drive A_CNXN / A_AUTH to completion. -> (banner_text, props)"""
    wire.send(A_CNXN, A_VERSION, MAX_PAYLOAD, banner_for_host(features))

    tries = 0
    while True:
        command, arg0, arg1, payload = wire.recv()

        if command == A_CNXN:
            wire.peer_maxdata = min(arg1, MAX_PAYLOAD) if arg1 else 4096
            systemtype, serial, banner, props = parse_banner(payload)
            print("  <- A_CNXN  version=0x%08x maxdata=%d" % (arg0, arg1))
            print("     systemtype : %s" % systemtype)
            print("     serial     : %s" % (serial or "(empty)"))
            print("     banner     : %s" % banner)
            for k in sorted(props):
                print("       %-12s %s" % (k, props[k]))
            return banner, props

        if command == A_STLS:
            raise RuntimeError(
                "adbd answered A_STLS (version 0x%08x): this connection "
                "requires TLS, which means wireless debugging with a paired "
                "certificate. The adbkey cannot complete it and this client "
                "does not pretend otherwise." % arg0)

        if command == A_AUTH and arg0 == ADB_AUTH_TOKEN:
            tries += 1
            print("  <- A_AUTH  TOKEN, %d bytes  (challenge #%d)"
                  % (len(payload), tries))
            if tries == 1:
                if not os.path.exists(keypath):
                    raise RuntimeError(
                        "no private key at %s and the device demands one. "
                        "Run `adb devices` once to have the adb client "
                        "generate a key pair, or pass --key." % keypath)
                n, d, bits = load_private_key(keypath)
                print("     signing with the %d-bit key at %s"
                      % (bits, keypath))
                sig = sign_token(payload, n, d)
                print("  -> A_AUTH  SIGNATURE, %d bytes" % len(sig))
                wire.send(A_AUTH, ADB_AUTH_SIGNATURE, 0, sig)
                continue

            # A second TOKEN means the first signature did not verify: this
            # host key is not in /data/misc/adb/adb_keys.
            print("     the device asked again -- the signature was REJECTED,")
            print("     i.e. this host key is not in /data/misc/adb/adb_keys.")
            if not offer_key:
                raise RuntimeError(
                    "signature rejected and --no-offer-key is set, so no "
                    "consent prompt was raised on the device. Stopping.")
            pub = load_public_key(pubpath)
            print("  -> A_AUTH  RSAPUBLICKEY, %d bytes" % len(pub))
            print("     WATCH THE DEVICE SCREEN. This is the message that")
            print("     raises 'Allow USB debugging?'. Nothing proceeds until")
            print("     a human touches the phone.")
            wire.send(A_AUTH, ADB_AUTH_RSAPUBLICKEY, 0, pub)
            continue

        raise IOError("unexpected %s during connect" % cmd_name(command))


def run_service(wire, service, local_id=1, timeout=8.0, raw=False):
    """A_OPEN a service, pump it, A_CLSE. -> (remote_id, collected_bytes)"""
    payload = service.encode("utf-8") + b"\x00"
    print("  -> A_OPEN  local-id=%d  service=%r" % (local_id, service))
    wire.send(A_OPEN, local_id, 0, payload)

    remote_id = None
    collected = b""
    deadline = time.time() + timeout
    wire.sock.settimeout(1.0)

    while time.time() < deadline:
        try:
            command, arg0, arg1, data = wire.recv()
        except socket.timeout:
            continue
        except EOFError:
            break

        if command == A_OKAY:
            # arg0 is the DEVICE's id for this stream, arg1 is ours echoed
            # back. From here every message about this stream carries the
            # pair, and that pair is the whole of adb's multiplexing.
            if remote_id is None:
                remote_id = arg0
                print("  <- A_OKAY  remote-id=%d  local-id=%d  "
                      "(stream established)" % (arg0, arg1))
            continue

        if command == A_WRTE:
            collected += data
            # Every A_WRTE must be acknowledged with A_OKAY or the peer stops
            # sending. This one line is adb's entire flow control.
            wire.send(A_OKAY, local_id, remote_id if remote_id else arg0)
            continue

        if command == A_CLSE:
            print("  <- A_CLSE  remote-id=%d  local-id=%d  (device closed)"
                  % (arg0, arg1))
            wire.send(A_CLSE, local_id, arg0)
            break

        print("  <- %s (ignored on this stream)" % cmd_name(command))

    wire.sock.settimeout(None)
    return remote_id, collected


# ---------------------------------------------------------------------------

def main():
    home = os.path.expanduser("~")
    ap = argparse.ArgumentParser(
        description="Speak the ADB wire protocol without the adb client.")
    ap.add_argument("--host", default="127.0.0.1",
                    help="adbd host (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=5555,
                    help="adbd TCP port (default 5555, the emulator's)")
    ap.add_argument("--service", default="shell:id",
                    help="service string to A_OPEN (default 'shell:id')")
    ap.add_argument("--abb", metavar="ARGS",
                    help="use the abb_exec service instead: ARGS is split on "
                         "spaces and rejoined with NUL bytes, e.g. "
                         "--abb 'package list packages -3'. A shell never sees "
                         "these, so nothing is quoted or word-split twice. "
                         "Needs the 'abb_exec' feature in the banner")
    ap.add_argument("--abb-service", default="abb_exec",
                    choices=("abb_exec", "abb"),
                    help="abb_exec is raw stdio; abb uses the shell-v2 framing")
    ap.add_argument("--key", default=os.path.join(home, ".android", "adbkey"),
                    help="private key used to sign the auth token")
    ap.add_argument("--pubkey", default=None,
                    help="public key offered if the signature is rejected "
                         "(default: <key>.pub)")
    ap.add_argument("--features", default="cmd,stat_v2,ls_v2",
                    help="features to advertise in our banner. shell_v2 is "
                         "deliberately absent -- see the header")
    ap.add_argument("--no-offer-key", action="store_true",
                    help="never send A_AUTH(RSAPUBLICKEY); do not raise a "
                         "consent dialog on a device you do not own")
    ap.add_argument("--handshake-only", action="store_true",
                    help="connect, authenticate, print the banner, stop")
    ap.add_argument("--local-id", type=int, default=1,
                    help="the stream id WE choose (default 1)")
    ap.add_argument("--timeout", type=float, default=8.0,
                    help="seconds to pump the stream (default 8)")
    ap.add_argument("--raw", action="store_true",
                    help="write collected stream bytes to stdout unmodified")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="trace every header and hexdump every payload")
    args = ap.parse_args()

    pubpath = args.pubkey or (args.key + ".pub")

    print("adb-mini-client -> %s:%d" % (args.host, args.port))
    try:
        sock = socket.create_connection((args.host, args.port), timeout=10)
    except OSError as exc:
        sys.stderr.write(
            "cannot reach adbd at %s:%d (%s).\n"
            "Nothing is listening there. A physical device only listens on TCP "
            "after `adb tcpip`, which this script will not do for you -- see "
            "section 5 of the chapter for why that matters.\n"
            % (args.host, args.port, exc))
        return 2

    wire = Wire(sock, verbose=args.verbose)
    print("  -> A_CNXN  version=0x%08x maxdata=%d" % (A_VERSION, MAX_PAYLOAD))
    try:
        banner, props = do_connect(
            wire, args.key, pubpath, not args.no_offer_key, args.features)
    except (RuntimeError, IOError, EOFError) as exc:
        sys.stderr.write("handshake failed: %s\n" % exc)
        sock.close()
        return 1

    feats = props.get("features", "")
    print("")
    print("  negotiated features (%d):" % len(
        [f for f in feats.split(",") if f]))
    for f in sorted(f for f in feats.split(",") if f):
        print("    %s" % f)
    print("  our maxdata=%d, theirs=%d, effective=%d"
          % (MAX_PAYLOAD, wire.peer_maxdata, wire.peer_maxdata))
    print("")

    if args.handshake_only:
        sock.close()
        print("  handshake only; socket closed without opening a stream.")
        return 0

    service = args.service
    if args.abb:
        if "abb_exec" not in feats and "abb" not in feats:
            print("  NOTE: adbd did not advertise abb_exec; this will fail.")
        # argv cannot carry a NUL byte, which is why the delimiter is built
        # here rather than accepted on the command line.
        service = args.abb_service + ":" + "\x00".join(args.abb.split())

    remote_id, data = run_service(
        wire, service, local_id=args.local_id, timeout=args.timeout)

    print("")
    print("  stream pair: local-id=%d  remote-id=%s"
          % (args.local_id, remote_id if remote_id is not None else "(never established)"))
    print("  %d bytes received on the stream" % len(data))
    print("  ---- service output ----")
    if args.raw:
        sys.stdout.flush()
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        sys.stdout.write(data.decode("utf-8", "replace"))
    print("  ---- end ----")

    sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
