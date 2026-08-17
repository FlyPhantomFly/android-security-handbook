#!/usr/bin/env python3
"""
decode_header.py -- turn 24 bytes of hex into a readable ADB message header.

WHY THIS EXISTS
    The fastest way to stop being frightened of a binary protocol is to decode
    one message by hand, and then have something check your working. Paste the
    hex you copied out of a hexdump, a Wireshark "follow stream" pane, or the
    -v output of adb-mini-client.py, and this prints every field, verifies the
    magic, and tells you what the message means in context.

    It also decodes the payload when it is a service string, a connect banner,
    or a shell-v2 packet -- the three payloads you will actually meet.

HOW TO RUN
    # host -- one header, spaces optional
    python3 -B decode_header.py 4f50454e01000000000000001100000025060000b0afbab1

    # with its payload, as a second argument
    python3 -B decode_header.py 4f50454e0100000000000000110000002506  \\
        73 68 65 6c 6c 3a 65 63 68 6f 20 68 65 6c 6c 6f 00

    # a whole hexdump on stdin: every 24-byte-looking line is tried
    python3 -B adb-mini-client.py --port 5555 -v 2>&1 \\
        | grep 'header bytes' | awk '{print $3}' \\
        | python3 -B decode_header.py

    # show the working: which byte is which field
    python3 -B decode_header.py --explain 434e584e010000010000040021000000030c0000bcb1a7b1

REQUIREMENTS
    Python 3.6+, standard library only. No device needed -- this is pure
    decoding, so it works on a captured file, a screenshot you retyped, or a
    header you invented to check your understanding.

WHAT THIS WILL *NOT* TELL YOU
    - Whether the header is genuine. It verifies the magic field, which is
      command XOR 0xffffffff and is the only self-check the protocol has. A
      forged header passes trivially; magic detects lost framing, not attack.
    - What a stream is doing. Ids are per-connection and meaningless in
      isolation -- (1, 15) tells you two endpoints are talking, not what about.
    - Whether a checksum is right. adbd does not compute it and does not check
      it; every real header this repository captured carried 0x00000000. The
      tool prints the field and says so rather than warning you about a
      mismatch that means nothing.
    - Anything about a payload it does not recognise. It will hexdump bytes it
      cannot interpret rather than guessing.
"""

import argparse
import re
import sys

COMMANDS = {
    0x434E5953: ("A_SYNC", "legacy keepalive; not seen on modern wires"),
    0x4E584E43: ("A_CNXN", "connect: arg0=version, arg1=maxdata, payload=banner"),
    0x48545541: ("A_AUTH", "authentication: arg0 = 1 TOKEN, 2 SIGNATURE, 3 RSAPUBLICKEY"),
    0x534C5453: ("A_STLS", "this connection must be upgraded to TLS"),
    0x4E45504F: ("A_OPEN", "open a stream: arg0=local-id, payload=service string"),
    0x59414B4F: ("A_OKAY", "stream ready, or acknowledgement of one A_WRTE"),
    0x45545257: ("A_WRTE", "stream data"),
    0x45534C43: ("A_CLSE", "stream closed; arg0=0 means the service was refused"),
}

AUTH_TYPES = {1: "ADB_AUTH_TOKEN", 2: "ADB_AUTH_SIGNATURE", 3: "ADB_AUTH_RSAPUBLICKEY"}

SHELL_V2_IDS = {
    0: "stdin", 1: "stdout", 2: "stderr",
    3: "exit code", 4: "close stdin", 5: "window size",
}


def unhex(text):
    cleaned = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(cleaned) % 2:
        raise ValueError("odd number of hex digits (%d)" % len(cleaned))
    return bytes.fromhex(cleaned)


def u32(buf, off):
    return int.from_bytes(buf[off:off + 4], "little")


def hexdump(data, indent="    "):
    out = []
    for off in range(0, len(data), 16):
        row = data[off:off + 16]
        h = " ".join("%02x" % b for b in row)
        t = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append("%s%04x  %-47s  |%s|" % (indent, off, h, t))
    return "\n".join(out)


def describe_banner(payload):
    text = payload.rstrip(b"\x00").decode("utf-8", "replace")
    parts = text.split(":", 2)
    if len(parts) != 3:
        return ["  banner is not <type>:<serial>:<props> -- printing raw:",
                "    %r" % text]
    out = ["  systemtype : %s" % parts[0],
           "  serial     : %s" % (parts[1] or "(empty)")]
    for item in parts[2].split(";"):
        if not item:
            continue
        if "=" in item:
            k, v = item.split("=", 1)
            if k == "features":
                feats = [f for f in v.split(",") if f]
                out.append("  features   : %d advertised" % len(feats))
                for f in sorted(feats):
                    out.append("      %s" % f)
            else:
                out.append("  %-10s : %s" % (k, v))
        else:
            out.append("  %s" % item)
    return out


def describe_shell_v2(payload):
    out = []
    off = 0
    while off + 5 <= len(payload):
        pid = payload[off]
        length = int.from_bytes(payload[off + 1:off + 5], "little")
        body = payload[off + 5:off + 5 + length]
        name = SHELL_V2_IDS.get(pid)
        if name is None:
            return None                      # not shell-v2 framing after all
        if pid == 3 and len(body) == 1:
            out.append("  packet id=%d (%s) length=%d  ->  exit status %d"
                       % (pid, name, length, body[0]))
        else:
            out.append("  packet id=%d (%s) length=%d  ->  %r"
                       % (pid, name, length, body))
        off += 5 + length
    return out if out else None


def describe_payload(command, payload):
    if not payload:
        return []
    if command == 0x4E584E43:                        # A_CNXN
        return describe_banner(payload)
    if command == 0x4E45504F:                        # A_OPEN
        svc = payload.rstrip(b"\x00").decode("utf-8", "replace")
        lines = ["  service string: %r" % svc]
        if "\x00" in svc:
            lines.append("  NUL-delimited arguments (abb / abb_exec):")
            for a in svc.split("\x00"):
                lines.append("      %r" % a)
        return lines
    if command == 0x48545541:                        # A_AUTH
        return ["  %d bytes of authentication material -- not decoded here."
                % len(payload),
                "  20 bytes = a token. 256 = an RSA-2048 signature.",
                "  ~709 = the public key blob (524 bytes base64 + comment)."]
    if command == 0x45545257:                        # A_WRTE
        v2 = describe_shell_v2(payload)
        if v2:
            return ["  looks like shell-v2 framing:"] + v2
        try:
            text = payload.decode("utf-8")
            if all(c == "\n" or c == "\t" or 32 <= ord(c) < 127 for c in text):
                return ["  printable payload:"] + \
                       ["    %s" % l for l in text.rstrip("\n").split("\n")]
        except UnicodeDecodeError:
            pass
        return ["  payload:", hexdump(payload)]
    return ["  payload:", hexdump(payload)]


def decode(raw, explain=False):
    if len(raw) < 24:
        print("need at least 24 bytes, got %d" % len(raw))
        return 1

    head, payload = raw[:24], raw[24:]
    command = u32(head, 0)
    arg0 = u32(head, 4)
    arg1 = u32(head, 8)
    length = u32(head, 12)
    check = u32(head, 16)
    magic = u32(head, 20)

    name, meaning = COMMANDS.get(command, ("UNKNOWN", "not an ADB command"))
    ascii4 = "".join(chr(b) if 32 <= b < 127 else "." for b in head[0:4])

    print("command      0x%08x  %-8s  (%r on the wire)" % (command, name, ascii4))
    print("arg0         0x%08x  = %d" % (arg0, arg0))
    print("arg1         0x%08x  = %d" % (arg1, arg1))
    print("data_length  0x%08x  = %d" % (length, length))
    print("data_check   0x%08x  (documented CRC32; implemented byte-sum; "
          "verified by nobody)" % check)
    expected = (command ^ 0xFFFFFFFF) & 0xFFFFFFFF
    ok = "OK" if magic == expected else "MISMATCH -- framing is lost"
    print("magic        0x%08x  expected 0x%08x  %s" % (magic, expected, ok))
    print("")
    print("meaning      %s" % meaning)

    if command == 0x48545541 and arg0 in AUTH_TYPES:
        print("auth type    %s" % AUTH_TYPES[arg0])
    if command in (0x4E45504F, 0x59414B4F, 0x45545257, 0x45534C43):
        print("stream       sender's id=%d, peer's id=%d" % (arg0, arg1))
        if command == 0x45534C43 and arg0 == 0:
            print("             arg0 is 0 -- the service was REFUSED. There is no")
            print("             error message and no error code in this protocol.")
    if command == 0x4E584E43:
        print("version      0x%08x   maxdata %d bytes" % (arg0, arg1))

    if explain:
        print("")
        print("byte layout:")
        fields = [(0, 4, "command"), (4, 4, "arg0"), (8, 4, "arg1"),
                  (12, 4, "data_length"), (16, 4, "data_check"),
                  (20, 4, "magic")]
        for off, size, fname in fields:
            chunk = head[off:off + size]
            print("  %2d..%2d  %s  %-12s  little-endian -> 0x%08x"
                  % (off, off + size - 1, chunk.hex(), fname, u32(head, off)))

    if payload:
        print("")
        if len(payload) != length:
            print("NOTE: you supplied %d payload bytes but the header says %d."
                  % (len(payload), length))
        for line in describe_payload(command, payload):
            print(line)
    elif length:
        print("")
        print("(header says %d payload bytes follow; none were supplied)" % length)

    return 0 if magic == expected else 1


def main():
    ap = argparse.ArgumentParser(
        description="Decode an ADB 24-byte message header from hex.")
    ap.add_argument("hex", nargs="*",
                    help="hex bytes; spaces optional. Omit to read stdin")
    ap.add_argument("--explain", action="store_true",
                    help="show which bytes make up which field")
    args = ap.parse_args()

    if args.hex:
        try:
            return decode(unhex("".join(args.hex)), args.explain)
        except ValueError as exc:
            sys.stderr.write("%s\n" % exc)
            return 2

    rc = 0
    for lineno, line in enumerate(sys.stdin, 1):
        line = line.strip()
        if not line:
            continue
        try:
            raw = unhex(line)
        except ValueError:
            continue
        if len(raw) < 24:
            continue
        print("=== stdin line %d ===" % lineno)
        rc |= decode(raw, args.explain)
        print("")
    return rc


if __name__ == "__main__":
    sys.exit(main())
