#!/usr/bin/env python3
"""
decode-proc-net.py -- decode /proc/net/tcp, tcp6, udp and udp6 into readable form
Chapter 02 -- Linux Basics

PURPOSE
    The kernel's socket tables under /proc/net/ are hex, and the address field
    is byte-reversed while the port field is not. That trips up everyone the
    first time. Lab 03 part C teaches you to decode a line by hand, on paper,
    because on a stripped-down device that is the only option you have.

    This script exists so you can CHECK your hand decoding, not replace it.
    Do the arithmetic yourself first, then run this and compare.

    It decodes, for every row:
        local address and port      (IPv4 or IPv6, byte order handled)
        remote address and port
        TCP connection state        (the hex st column, as a name)
        owning UID                  (and the user name, when resolvable)
        socket inode                (the link back to /proc/<pid>/fd/)
    and, with --pids, tries to name the process that owns each socket.

USAGE
    # decode this machine's tables
    python3 decode-proc-net.py

    # decode specific tables, or files you captured earlier
    python3 decode-proc-net.py /proc/net/tcp /proc/net/tcp6
    python3 decode-proc-net.py captured-tcp.txt

    # capture from a device and decode on your host -- no Python on the device
    adb shell cat /proc/net/tcp  > tcp.txt
    adb shell cat /proc/net/tcp6 > tcp6.txt
    python3 decode-proc-net.py tcp.txt tcp6.txt

    # run it on the device itself, if it has Python
    adb push decode-proc-net.py /data/local/tmp/
    adb shell python3 /data/local/tmp/decode-proc-net.py

    Options:
        --listen        show only sockets in the LISTEN state
        --uid N         show only sockets owned by UID N
        --pids          resolve socket inodes to PIDs by scanning /proc/*/fd
        --raw           also print the original hex fields, for checking
        --no-color      plain output (colour is already off when not a tty)
        -h, --help      this help

REQUIREMENTS
    Python 3.6 or later. Standard library only -- no pip, no venv, no network.
    Reading is the only thing it does; it opens no sockets and writes no files.

    Permissions: /proc/net/* is world-readable, so the decoding itself needs
    no privilege. --pids walks /proc/<pid>/fd/, which needs the owning UID or
    root, so on an unprivileged Android shell it will resolve your own
    processes and silently skip everyone else's.

WHAT THIS SCRIPT WILL NOT TELL YOU
    - It will not tell you what the traffic CONTAINS. It reads a table of
      socket metadata. For payloads you need a proxy or a capture.
    - It will not see QUIC/HTTP3 as connections. QUIC runs over UDP, so a
      modern app's traffic may appear only as a UDP entry on port 443, or
      barely at all. Check udp and udp6 as well as tcp and tcp6.
    - It will not tell you which app a UID belongs to on Android. Ask the
      device: `cmd package list packages --uid <n>`.
    - It will not find sockets in another network namespace. /proc/net/* is
      namespace-scoped, so a process in its own net namespace has its own
      tables; read them via /proc/<pid>/net/tcp instead.
    - It will not detect Frida for you. It will show you a listener on
      127.0.0.1:27042 if there is one; deciding what that means is your job,
      and a server started with `-l 127.0.0.1:1337` will not look special.
    - It does not replace the hand-decoding skill. If you cannot do a line on
      paper, you are one missing interpreter away from being stuck.

SEE ALSO
    ../labs/lab-03-ipc-sockets-and-namespaces.md   -- decode by hand first
    ../labs/lab-02-processes-proc-and-signals.md   -- /proc/<pid>/fd
    ../references/README.md                        -- proc(5), and RFC 9293
"""

import os
import sys

# -----------------------------------------------------------------------------
# TCP states, as the kernel writes them in the `st` column (hex, no 0x prefix).
# Source of truth: include/net/tcp_states.h in the Linux kernel.
# -----------------------------------------------------------------------------

TCP_STATES = {
    0x01: "ESTABLISHED",
    0x02: "SYN_SENT",
    0x03: "SYN_RECV",
    0x04: "FIN_WAIT1",
    0x05: "FIN_WAIT2",
    0x06: "TIME_WAIT",
    0x07: "CLOSE",
    0x08: "CLOSE_WAIT",
    0x09: "LAST_ACK",
    0x0A: "LISTEN",
    0x0B: "CLOSING",
    0x0C: "NEW_SYN_RECV",
}

# Ports worth recognising on sight. Purely informational.
NOTABLE_PORTS = {
    22: "ssh",
    53: "dns",
    80: "http",
    443: "https/quic",
    5037: "adb server (host side)",
    5555: "adbd over TCP -- wireless debugging",
    8080: "common proxy (Burp, mitmproxy)",
    8081: "common proxy, secondary",
    23946: "IDA debug server default",
    27042: "frida-server default",
    27043: "frida-server secondary",
}


# -----------------------------------------------------------------------------
# Address decoding -- the part Lab 03 makes you do on paper
# -----------------------------------------------------------------------------

def decode_ipv4(hex8):
    """
    '0100007F' -> '127.0.0.1'

    Eight hex digits are four bytes, holding the 32-bit address as it sits in
    memory on a little-endian machine: least significant byte first. Reverse
    the byte order, then print each byte in decimal.
    """
    if len(hex8) != 8:
        raise ValueError("expected 8 hex digits, got %r" % hex8)
    b = [int(hex8[i:i + 2], 16) for i in range(0, 8, 2)]   # 01 00 00 7F
    b.reverse()                                            # 7F 00 00 01
    return ".".join(str(x) for x in b)


def decode_ipv6(hex32):
    """
    32 hex digits -> an IPv6 address string.

    The 16 bytes are printed as FOUR 32-bit words, and each word individually
    is in host (little-endian) byte order. So reverse the bytes WITHIN each
    group of eight hex digits, then concatenate all sixteen bytes.

        00000000000000000000000001000000 -> ::1
        0000000000000000FFFF00000100007F -> ::ffff:127.0.0.1
    """
    if len(hex32) != 32:
        raise ValueError("expected 32 hex digits, got %r" % hex32)
    raw = bytearray()
    for w in range(4):
        word = hex32[w * 8:(w + 1) * 8]
        wb = [int(word[i:i + 2], 16) for i in range(0, 8, 2)]
        wb.reverse()
        raw.extend(wb)

    groups = ["%x" % ((raw[i] << 8) | raw[i + 1]) for i in range(0, 16, 2)]

    # IPv4-mapped, ::ffff:a.b.c.d -- render it the way people expect to read it
    if groups[:5] == ["0", "0", "0", "0", "0"] and groups[5] == "ffff":
        return "::ffff:%d.%d.%d.%d" % (raw[12], raw[13], raw[14], raw[15])

    return compress_ipv6(groups)


def compress_ipv6(groups):
    """Apply the '::' longest-run-of-zeros rule to eight hex groups."""
    best_start, best_len = -1, 0
    cur_start, cur_len = -1, 0
    for i, g in enumerate(groups):
        if g == "0":
            if cur_start < 0:
                cur_start, cur_len = i, 0
            cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
        else:
            cur_start, cur_len = -1, 0

    if best_len < 2:
        return ":".join(groups)

    head = groups[:best_start]
    tail = groups[best_start + best_len:]
    return ":".join(head) + "::" + ":".join(tail)


def decode_port(hex4):
    """
    '1F90' -> 8080

    The port is written in network byte order (big-endian) and is NOT
    reversed. This asymmetry with the address field is the single most common
    hand-decoding mistake.
    """
    return int(hex4, 16)


def decode_endpoint(field):
    """'0100007F:1F90' -> ('127.0.0.1', 8080)"""
    addr_hex, _, port_hex = field.partition(":")
    if len(addr_hex) == 8:
        addr = decode_ipv4(addr_hex)
    elif len(addr_hex) == 32:
        addr = decode_ipv6(addr_hex)
    else:
        addr = "?" + addr_hex
    return addr, decode_port(port_hex)


def fmt_endpoint(addr, port):
    if ":" in addr and not addr.startswith("::ffff:"):
        return "[%s]:%d" % (addr, port)
    return "%s:%d" % (addr, port)


# -----------------------------------------------------------------------------
# Reading the tables
# -----------------------------------------------------------------------------

def parse_table(path):
    """Yield a dict per data row. Returns [] and warns if the file is unusable."""
    rows = []
    try:
        with open(path, "r", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        sys.stderr.write("  cannot read %s: %s\n" % (path, exc))
        return rows

    for line in lines:
        parts = line.split()
        if len(parts) < 10:
            continue
        if not parts[0].rstrip(":").isdigit():
            continue          # the header line, or something unexpected
        try:
            local_a, local_p = decode_endpoint(parts[1])
            rem_a, rem_p = decode_endpoint(parts[2])
            state = int(parts[3], 16)
            uid = int(parts[7])
            inode = int(parts[9])
        except (ValueError, IndexError):
            sys.stderr.write("  skipping unparseable line: %r\n" % line[:70])
            continue

        rows.append({
            "local": (local_a, local_p),
            "remote": (rem_a, rem_p),
            "state": state,
            "uid": uid,
            "inode": inode,
            "raw_local": parts[1],
            "raw_remote": parts[2],
            "raw_state": parts[3],
        })
    return rows


def uid_name(uid):
    """Best-effort UID -> name. Android's table is not in /etc/passwd."""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except Exception:
        pass
    if uid == 0:
        return "root"
    if uid == 1000:
        return "system on Android / first user on desktop Linux"
    if uid == 2000:
        return "shell"       # Android's adb shell user
    if 10000 <= uid <= 19999:
        return "app_%d" % (uid - 10000)
    if uid >= 100000:
        return "u%d_app_%d" % (uid // 100000, (uid % 100000) - 10000)
    return ""


def map_inodes_to_pids():
    """
    Walk /proc/<pid>/fd and build {socket_inode: 'pid/comm'}.

    Needs the owning UID or root for each process, so an unprivileged run
    resolves your own processes and quietly skips the rest. That is expected,
    not an error.
    """
    table = {}
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        return table

    for pid in pids:
        fddir = os.path.join("/proc", pid, "fd")
        try:
            entries = os.listdir(fddir)
        except OSError:
            continue                      # not ours, and we are not root
        comm = "?"
        try:
            with open(os.path.join("/proc", pid, "comm")) as fh:
                comm = fh.read().strip()
        except OSError:
            pass
        for fd in entries:
            try:
                target = os.readlink(os.path.join(fddir, fd))
            except OSError:
                continue
            if target.startswith("socket:["):
                try:
                    ino = int(target[8:-1])
                except ValueError:
                    continue
                table[ino] = "%s/%s" % (pid, comm)
    return table


# -----------------------------------------------------------------------------
# Output
# -----------------------------------------------------------------------------

def print_table(path, rows, opts, inode_map):
    # Decide IPv4 vs IPv6 from the data, not from the filename: a table
    # captured with `adb shell cat /proc/net/tcp6 > tcp6.txt` has an extension
    # on it, and a file called `capture.txt` has no hint at all.
    if rows and len(rows[0]["raw_local"].partition(":")[0]) == 32:
        kind = "IPv6"
    elif rows:
        kind = "IPv4"
    else:
        kind = "IPv6" if "6" in os.path.basename(path) else "IPv4"
    proto = "UDP" if "udp" in os.path.basename(path).lower() else "TCP"

    print("")
    print("=" * 78)
    print(" %s   (%s, %s)   %d row(s)" % (path, proto, kind, len(rows)))
    print("=" * 78)

    if not rows:
        print("  (nothing to show)")
        return

    header = "  %-26s %-26s %-12s %8s %10s" % (
        "LOCAL", "REMOTE", "STATE", "UID", "INODE")
    if opts["pids"]:
        header += "  %s" % "PID/COMM"
    print(header)
    print("  " + "-" * 74)

    shown = 0
    for r in rows:
        if opts["listen"] and r["state"] != 0x0A:
            continue
        if opts["uid"] is not None and r["uid"] != opts["uid"]:
            continue
        shown += 1

        state = TCP_STATES.get(r["state"], "0x%02X" % r["state"])
        if proto == "UDP":
            # UDP has no connection state; the kernel still fills the column.
            state = state if r["state"] != 0x07 else "-"

        name = uid_name(r["uid"])
        uid_s = "%d" % r["uid"]

        line = "  %-26s %-26s %-12s %8s %10d" % (
            fmt_endpoint(*r["local"]),
            fmt_endpoint(*r["remote"]),
            state,
            uid_s,
            r["inode"],
        )
        if opts["pids"]:
            line += "  %s" % inode_map.get(r["inode"], "-")
        print(line)

        notes = []
        if name:
            notes.append("uid %s = %s" % (uid_s, name))
        lp = r["local"][1]
        rp = r["remote"][1]
        if lp in NOTABLE_PORTS:
            notes.append("local port %d: %s" % (lp, NOTABLE_PORTS[lp]))
        if rp in NOTABLE_PORTS and rp != lp:
            notes.append("remote port %d: %s" % (rp, NOTABLE_PORTS[rp]))
        if r["state"] == 0x0A and r["local"][0] in ("0.0.0.0", "::"):
            notes.append("listening on ALL interfaces, not just localhost")
        if notes:
            print("       note: " + "; ".join(notes))

        if opts["raw"]:
            print("       raw:  local=%s remote=%s st=%s"
                  % (r["raw_local"], r["raw_remote"], r["raw_state"]))

    if shown == 0:
        print("  (all rows filtered out)")


def print_primer():
    print("""
How to decode one of these lines by hand -- do this before trusting any tool:

    0100007F:1F90

  1. Split at the colon:            address 0100007F   port 1F90
  2. Address, as bytes:             01 00 00 7F
  3. REVERSE the byte order:        7F 00 00 01
  4. Each byte to decimal:          127 . 0 . 0 . 1
  5. Port: do NOT reverse it.       0x1F90
  6. Hex to decimal:                1*4096 + 15*256 + 9*16 + 0 = 8080
  7. Result:                        127.0.0.1:8080

  IPv6 is the same idea with 32 hex digits read as four 8-digit words, each
  word byte-reversed on its own, then all sixteen bytes joined.

  The st column is a state, in hex: 0A = LISTEN, 01 = ESTABLISHED,
  06 = TIME_WAIT. The uid column is decimal. The inode column matches the
  socket:[N] entries in /proc/<pid>/fd/.
""")


def usage(code=0):
    print(__doc__)
    sys.exit(code)


def main(argv):
    opts = {"listen": False, "uid": None, "pids": False, "raw": False}
    paths = []

    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            usage(0)
        elif a == "--listen":
            opts["listen"] = True
        elif a == "--pids":
            opts["pids"] = True
        elif a == "--raw":
            opts["raw"] = True
        elif a == "--no-color":
            pass                      # accepted and ignored; output is plain
        elif a == "--uid":
            i += 1
            if i >= len(argv):
                sys.stderr.write("--uid needs a number\n")
                return 2
            try:
                opts["uid"] = int(argv[i])
            except ValueError:
                sys.stderr.write("--uid needs a number, got %r\n" % argv[i])
                return 2
        elif a.startswith("-"):
            sys.stderr.write("unknown option: %s\n" % a)
            return 2
        else:
            paths.append(a)
        i += 1

    if not paths:
        for candidate in ("/proc/net/tcp", "/proc/net/tcp6",
                          "/proc/net/udp", "/proc/net/udp6"):
            if os.path.exists(candidate):
                paths.append(candidate)

    if not paths:
        sys.stderr.write(
            "No socket tables found. This machine has no /proc/net/tcp,\n"
            "which means it is not Linux. Capture the files from a device:\n"
            "  adb shell cat /proc/net/tcp > tcp.txt\n"
            "and pass them as arguments.\n")
        return 1

    inode_map = map_inodes_to_pids() if opts["pids"] else {}

    print_primer()
    total = 0
    for p in paths:
        rows = parse_table(p)
        total += len(rows)
        print_table(p, rows, opts, inode_map)

    print("")
    print("  %d row(s) across %d table(s)." % (total, len(paths)))
    if opts["pids"] and not inode_map:
        print("  --pids resolved nothing: you are not root and own none of "
              "these sockets.")
    print("  Cross-check any inode against /proc/<pid>/fd/ to find its owner,")
    print("  and any Android uid against: cmd package list packages --uid <n>")
    print("")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        sys.exit(130)
