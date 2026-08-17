#!/usr/bin/env python3
"""
abstract-socket-probe.py — enumerate and speak to Android abstract-namespace
UNIX sockets.

WHAT IT DOES
    Lists every abstract-namespace AF_UNIX socket on a device (from
    /proc/net/unix), generates likely names for a target package, connects to
    them, and speaks a small library of probe protocols to find out what each
    endpoint actually does. Works three ways:

      * on the device, from a pushed python3 (the authoritative mode);
      * on your workstation, listing over `adb shell` and connecting through
        `adb forward tcp:<port> localabstract:<name>`;
      * on the device from inside an app-like context, if you have one.

WHY IT MATTERS — READ THIS PART
    An abstract-namespace UNIX socket is the single most underappreciated piece
    of attack surface on Android, and the reason is structural rather than
    incidental.

    A normal, filesystem-named UNIX socket is a file. It has an inode. It has an
    owner, a group and mode bits. Linux discretionary access control applies to
    it, SELinux labels it, and the permissions of every directory on the path to
    it apply too. A socket created inside /data/data/<pkg>/ is genuinely private,
    because no other app can traverse that directory.

    An abstract socket is not a file. If the first byte of sun_path in the
    sockaddr_un structure is NUL, the kernel treats the remainder as an opaque
    name in a kernel-global namespace with NO FILESYSTEM REPRESENTATION
    WHATSOEVER. Conventionally these are written with a leading '@'.

        THERE IS NO INODE.
        THERE IS NO OWNER AND NO GROUP.
        THERE ARE NO MODE BITS — there is not even a permission to get WRONG.
        THERE IS NOTHING FOR chmod TO CHANGE.
        NO DIRECTORY PERMISSION PROTECTS IT, BECAUSE IT IS IN NO DIRECTORY.

    The only thing standing between an abstract socket and any process on the
    device is (a) knowing the name and (b) SELinux policy, which for
    app-to-app abstract socket connections has historically been permissive.
    Every app on Android shares one network namespace, so "every process in the
    same network namespace" means "every app on the phone".

    And the Android SDK makes this the DEFAULT. android.net.LocalSocketAddress
    has three namespaces — ABSTRACT, RESERVED, FILESYSTEM — and the
    single-argument constructor selects ABSTRACT:

        LocalServerSocket server = new LocalServerSocket("com.example.app.ipc");
        // ^ ABSTRACT. Reachable by every app on the device. No warning
        //   anywhere in the API, the Javadoc, or the IDE.

    A developer reads "LocalServerSocket" and reasonably concludes that "local"
    implies "private". It does not. The shortest thing that compiles is the most
    exposed thing they could have written, and during development nothing
    contradicts them, because during development the only client is their own
    code.

    That combination — invisible in the manifest, invisible to every
    manifest-driven scanner, no permission model at all, and the SDK default —
    is why this script exists as a separate tool rather than a footnote.

    See ../README.md section 3.10 for the full treatment.

HOW TO RUN
    # host — list what is out there, over adb
    python3 abstract-socket-probe.py --list

    # host — generate and try candidate names for a package, via adb forward
    python3 abstract-socket-probe.py --package com.example.target --via-adb

    # host — talk to one socket
    python3 abstract-socket-probe.py --via-adb \\
        --name com.example.target.ipc --send '{"cmd":"get_token"}'

    # device — the authoritative mode (push python3 or use a Termux/root shell)
    adb push abstract-socket-probe.py /data/local/tmp/
    adb shell "cd /data/local/tmp && python3 abstract-socket-probe.py --list"
    adb shell "cd /data/local/tmp && python3 abstract-socket-probe.py \\
        --name com.example.target.ipc --probe-all"

    # device — brute-force a wordlist of names
    adb shell "cd /data/local/tmp && python3 abstract-socket-probe.py \\
        --wordlist names.txt"

REQUIREMENTS
    Python 3.8+, standard library only. AF_UNIX with a NUL-prefixed address is
    a Linux feature; this script will refuse to run its connect modes on a
    non-Linux host and tell you to use --via-adb instead.
    adb on PATH for --list without --local and for --via-adb.

REACHABILITY CAVEAT — DO NOT SKIP THIS
    Connecting from `adb shell` or through `adb forward` proves the socket
    EXISTS and SPEAKS. It does not prove a third-party app can reach it. Both
    of those paths run as UID 2000 in the SELinux domain `shell`, or as adbd,
    and both hold privileges an application does not. SELinux may permit
    shell -> app_socket while denying untrusted_app -> app_socket.

    To claim "any app the user installs can do this", reproduce from a real APK:
    ../examples/attacker-app/ has an abstract-socket probe built in. That is the
    only evidence that supports the sentence you want to write.

AUTHORISED TESTING ONLY.
"""

import argparse
import os
import platform
import re
import socket
import subprocess
import sys
import time

# --------------------------------------------------------------------------- #
# Probe protocols.
#
# An endpoint that accepts a connection but says nothing is not necessarily
# inert. Hand-rolled IPC protocols on Android are usually one of a small number
# of shapes, so we try each in turn rather than concluding "silent" after one
# JSON ping. The comment on each says which real-world pattern it targets.
# --------------------------------------------------------------------------- #
PROBES = [
    ("newline",   b"\n",
     "bare newline — line-oriented text protocols that echo a prompt or error"),
    ("json-ping", b'{"cmd":"ping"}\n',
     "JSON-over-socket, the most common hand-rolled app IPC protocol"),
    ("json-help", b'{"cmd":"help"}\n',
     "many debug servers implement a help/list-commands verb"),
    ("text-ping", b"PING\n",
     "plain text command protocols (media players, control channels)"),
    ("http-get",  b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
     "an HTTP server bound to a UNIX socket instead of a TCP port"),
    ("cdp",       b"GET /json/version HTTP/1.1\r\nHost: localhost\r\n\r\n",
     "Chrome DevTools Protocol — @chrome_devtools_remote and WebView "
     "inspector sockets. A hit here means full JS execution, DOM, cookies "
     "and localStorage inside the app's WebView."),
    ("len-frame", b"\x00\x00\x00\x04ping",
     "4-byte big-endian length prefix, the usual shape for native helpers"),
]

# Name templates that cover most real-world abstract sockets. See README 3.10.1.
NAME_TEMPLATES = [
    "{pkg}",
    "{pkg}.ipc",
    "{pkg}_ipc",
    "{pkg}.sock",
    "{pkg}.socket",
    "{pkg}.bridge",
    "{pkg}.server",
    "{pkg}.service",
    "{pkg}.daemon",
    "{pkg}_worker",
    "{pkg}_remote",
    "{pkg}_player",
    "{pkg}.devtools",
    "{tail}",
    "{tail}_ipc",
    "{tail}.ipc",
    "{tail}_sock",
    "webview_devtools_remote_{pkg}",
]

# Names that are worth trying against every target, regardless of package.
UNIVERSAL_NAMES = [
    # The WebView inspector. setWebContentsDebuggingEnabled(true) left in a
    # release build opens this, and it is a full Chrome DevTools endpoint.
    "chrome_devtools_remote",
    "webview_devtools_remote",
    # Frameworks and engines that ship their own IPC.
    "unity_ipc",
    "flutter_devtools",
]


# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #

def on_linux() -> bool:
    return platform.system() == "Linux"


def running_on_device() -> bool:
    """Crude but reliable: Android has /system/build.prop and /proc/net/unix."""
    return os.path.exists("/system/build.prop") or os.path.exists("/system/bin/app_process")


def adb(args, check=False):
    """Run an adb command and return stdout as text, or '' on failure."""
    try:
        p = subprocess.run(["adb"] + args, capture_output=True, text=True, timeout=25)
        if check and p.returncode != 0:
            sys.stderr.write("adb %s failed: %s\n" % (" ".join(args), p.stderr.strip()))
        return p.stdout.replace("\r", "")
    except FileNotFoundError:
        sys.stderr.write("error: adb not found on PATH\n")
        return ""
    except subprocess.TimeoutExpired:
        sys.stderr.write("error: adb %s timed out\n" % " ".join(args))
        return ""


# --------------------------------------------------------------------------- #
# Enumeration
# --------------------------------------------------------------------------- #

PROC_NET_UNIX_RE = re.compile(
    r"^\s*[0-9a-fA-F]+:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*(.*)$"
)


def read_proc_net_unix(local: bool):
    """
    Return the raw text of /proc/net/unix, from this machine or over adb.

    /proc/net/unix is world-readable on Android and lists every AF_UNIX socket
    in the system. Abstract sockets appear in the Path column with a leading
    '@'. The file does NOT name the owning process — the Inode column is your
    only link, and you resolve it by walking /proc/<pid>/fd, which needs root.
    """
    if local:
        try:
            with open("/proc/net/unix", "r") as fh:
                return fh.read()
        except OSError as exc:
            sys.stderr.write("cannot read /proc/net/unix: %s\n" % exc)
            return ""
    return adb(["shell", "cat", "/proc/net/unix"])


def parse_unix(text):
    """Yield dicts for every socket line, with abstract ones marked."""
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("Num") or not line.strip():
            continue
        m = PROC_NET_UNIX_RE.match(line)
        if not m:
            continue
        refcount, proto, flags, stype, state, inode, path = m.groups()
        path = path.strip()
        if not path:
            continue
        out.append({
            "inode": inode,
            "type": stype,
            "state": state,
            "path": path,
            "abstract": path.startswith("@"),
            "name": path[1:] if path.startswith("@") else path,
        })
    return out


def cmd_list(args):
    text = read_proc_net_unix(args.local)
    if not text:
        return 1
    socks = parse_unix(text)
    abstract = [s for s in socks if s["abstract"]]
    fs = [s for s in socks if not s["abstract"]]

    print("=" * 74)
    print(" ABSTRACT-NAMESPACE SOCKETS  (%d)" % len(abstract))
    print("=" * 74)
    print(" These have NO inode-backed file, NO owner, NO group and NO mode")
    print(" bits. Nothing in the filesystem protects them. Any app that knows")
    print(" the name can connect, subject only to SELinux.")
    print()
    if not abstract:
        print("  none found")
    for s in abstract:
        flag = ""
        low = s["name"].lower()
        if "devtools" in low or "chrome" in low:
            flag = "   <<< WebView inspector — full Chrome DevTools Protocol"
        elif any(k in low for k in ("ipc", "bridge", "cmd", "control", "debug")):
            flag = "   <<< control-channel shaped name"
        print("  @%-52s inode=%-9s%s" % (s["name"], s["inode"], flag))

    print()
    print("=" * 74)
    print(" FILESYSTEM-NAMED SOCKETS  (%d)" % len(fs))
    print("=" * 74)
    print(" These are real files. DAC (owner/group/mode) and SELinux apply, and")
    print(" so do the permissions of every directory on the path. Check the")
    print(" modes — a socket at 0666 has no DAC protection left.")
    print()
    for s in fs[: args.max_list]:
        print("  %-53s inode=%s" % (s["path"], s["inode"]))
    if len(fs) > args.max_list:
        print("  ... %d more (raise --max-list)" % (len(fs) - args.max_list))

    print()
    print("-" * 74)
    print("NEXT STEPS")
    print("-" * 74)
    print("  1. Check the mode bits of the filesystem sockets:")
    print("       # adb shell")
    print("       ls -lZ /dev/socket")
    print("  2. Attribute an abstract socket to a process by matching its inode:")
    print("       # adb shell as root")
    print("       ls -l /proc/<pid>/fd | grep socket    # look for socket:[INODE]")
    print("  3. Talk to the interesting ones:")
    print("       python3 %s --name <name> --probe-all" % os.path.basename(__file__))
    print("  4. Then PROVE app-reachability from ../examples/attacker-app/,")
    print("     because this listing came from a privileged shell.")
    return 0


# --------------------------------------------------------------------------- #
# Connecting
# --------------------------------------------------------------------------- #

def connect_abstract(name: str, timeout: float):
    """
    Connect to an abstract-namespace socket on THIS machine.

    The entire trick is the leading NUL byte in the address. Python accepts a
    bytes address for AF_UNIX; a str address starting with '\\0' works too. The
    address length the kernel sees is 1 + len(name), which is what selects the
    abstract namespace.
    """
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect("\0" + name)          # <-- the leading NUL IS the mechanism
    return s


def connect_via_adb(name: str, timeout: float, port: int):
    """
    Connect from the host, by asking adb to forward a local TCP port to a
    device-side abstract socket.

        adb forward tcp:<port> localabstract:<name>

    Convenient, and it works from Windows and macOS where AF_UNIX abstract
    addresses do not exist at all.

    CAVEAT, and it is a big one: the forward is created by adbd on the device,
    which runs as `shell` (or root). Success proves the socket exists and
    accepts connections FROM THAT CONTEXT. It says nothing about whether
    SELinux would permit untrusted_app -> the same socket. Never write up an
    adb-forward result as app reachability.
    """
    spec_local = "tcp:%d" % port
    spec_remote = "localabstract:%s" % name
    out = adb(["forward", spec_local, spec_remote])
    if out is None:
        raise OSError("adb forward failed")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
    except Exception:
        adb(["forward", "--remove", spec_local])
        raise
    return s, spec_local


def speak(sock, payload: bytes, timeout: float):
    """Send a payload and read whatever comes back within the timeout."""
    try:
        if payload:
            sock.sendall(payload)
        sock.settimeout(timeout)
        chunks = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            if len(b"".join(chunks)) > 65536:
                break
        return b"".join(chunks)
    except OSError:
        return b""


def render(data: bytes, as_hex: bool) -> str:
    if not data:
        return "<no reply>"
    if as_hex:
        return data[:512].hex()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "<binary, %d bytes> %s" % (len(data), data[:64].hex())
    printable = "".join(c if 32 <= ord(c) < 127 or c in "\r\n\t" else "." for c in text)
    return printable[:2000]


def probe_one(name, args):
    """Connect to one name and run either --send or the full probe library."""
    forward_spec = None
    try:
        if args.via_adb:
            sock, forward_spec = connect_via_adb(name, args.timeout, args.forward_port)
        else:
            if not on_linux():
                raise OSError(
                    "abstract AF_UNIX addresses are a Linux feature; this host "
                    "is %s. Use --via-adb, or push this script to the device."
                    % platform.system())
            sock = connect_abstract(name, args.timeout)
    except (OSError, socket.error) as exc:
        if args.verbose:
            print("  [-] @%-40s %s" % (name, exc))
        return False

    print()
    print("  [+] CONNECTED  @%s" % name)
    print("      No permission was required to reach this endpoint. There are")
    print("      no mode bits on an abstract socket to have prevented it.")

    try:
        if args.send is not None:
            payload = args.send.encode("utf-8")
            if not payload.endswith(b"\n"):
                payload += b"\n"
            reply = speak(sock, payload, args.timeout)
            print("      --> %s" % args.send)
            print("      <-- %s" % render(reply, args.hex))
        elif args.probe_all:
            for label, payload, why in PROBES:
                try:
                    if args.via_adb:
                        sock.close()
                        adb(["forward", "--remove", forward_spec])
                        sock, forward_spec = connect_via_adb(
                            name, args.timeout, args.forward_port)
                    else:
                        sock.close()
                        sock = connect_abstract(name, args.timeout)
                except OSError:
                    print("      [%s] reconnect failed — endpoint is one-shot"
                          % label)
                    break
                reply = speak(sock, payload, args.timeout)
                status = "REPLY" if reply else "silent"
                print("      [%-9s] %-6s  (%s)" % (label, status, why))
                if reply:
                    print("           <-- %s" % render(reply, args.hex))
        else:
            reply = speak(sock, b"", args.timeout)
            if reply:
                print("      banner: %s" % render(reply, args.hex))
            else:
                print("      (connected, no unsolicited banner — try --probe-all)")
    finally:
        try:
            sock.close()
        except OSError:
            pass
        if forward_spec:
            adb(["forward", "--remove", forward_spec])

    return True


def candidates(args):
    """Build the list of names to try."""
    names = []
    if args.name:
        names.extend(args.name)
    if args.package:
        tail = args.package.rsplit(".", 1)[-1]
        for tpl in NAME_TEMPLATES:
            names.append(tpl.format(pkg=args.package, tail=tail))
        names.extend(UNIVERSAL_NAMES)
    if args.wordlist:
        try:
            with open(args.wordlist, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        names.append(line.lstrip("@"))
        except OSError as exc:
            sys.stderr.write("cannot read wordlist: %s\n" % exc)
    if args.from_proc:
        text = read_proc_net_unix(args.local)
        for s in parse_unix(text):
            if s["abstract"]:
                names.append(s["name"])
    # de-duplicate, preserve order
    seen, ordered = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    return ordered


def cmd_probe(args):
    names = candidates(args)
    if not names:
        sys.stderr.write(
            "nothing to probe. Give --name, --package, --wordlist or --from-proc.\n")
        return 1

    print("=" * 74)
    print(" PROBING %d ABSTRACT-NAMESPACE NAMES" % len(names))
    print("=" * 74)
    print(" mode: %s" % ("adb forward (host)" if args.via_adb
                         else "direct AF_UNIX (device)"))
    print()

    hits = 0
    for n in names:
        if probe_one(n, args):
            hits += 1

    print()
    print("-" * 74)
    print(" %d of %d names accepted a connection" % (hits, len(names)))
    print("-" * 74)
    if hits:
        print()
        print(" SEVERITY IS DECIDED BY THE PROTOCOL, NOT BY THE CONNECTION.")
        print("   * a version string or heartbeat            -> Low, hardening item")
        print("   * a command channel that reads app files   -> High")
        print("   * anything returning auth material, or an")
        print("     arbitrary-file-write verb                -> Critical")
        print("   * a Chrome DevTools endpoint               -> High/Critical:")
        print("     JS execution, DOM, cookies and localStorage in the WebView")
        print()
        print(" AND THEN PROVE IT FROM AN APP. This connection came from a")
        print(" privileged context. SELinux may permit shell -> app_socket while")
        print(" denying untrusted_app -> app_socket. Build the APK:")
        print("   ../examples/attacker-app/  (it has an abstract-socket probe)")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main():
    p = argparse.ArgumentParser(
        description="Enumerate and speak to Android abstract-namespace UNIX "
                    "sockets — the @name form, which has no filesystem "
                    "permissions of any kind.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("HOW TO RUN")[1].split("REQUIREMENTS")[0])

    p.add_argument("--list", action="store_true",
                   help="list all UNIX sockets, abstract ones first")
    p.add_argument("--local", action="store_true",
                   help="read /proc/net/unix from THIS machine "
                        "(use when the script is running on the device)")
    p.add_argument("--max-list", type=int, default=40,
                   help="cap on filesystem sockets printed by --list")

    p.add_argument("--name", action="append",
                   help="abstract socket name to probe, without the '@'. "
                        "Repeatable.")
    p.add_argument("--package",
                   help="generate likely names for this package name")
    p.add_argument("--wordlist",
                   help="file of candidate names, one per line")
    p.add_argument("--from-proc", action="store_true",
                   help="probe every abstract socket found in /proc/net/unix")

    p.add_argument("--send",
                   help="send this string (a newline is appended) and print "
                        "the reply")
    p.add_argument("--probe-all", action="store_true",
                   help="try every protocol in the built-in probe library")
    p.add_argument("--hex", action="store_true",
                   help="render replies as hex rather than text")

    p.add_argument("--via-adb", action="store_true",
                   help="connect from the host through "
                        "`adb forward tcp:N localabstract:NAME`. Works on "
                        "Windows and macOS. See the reachability caveat.")
    p.add_argument("--forward-port", type=int, default=28900,
                   help="local TCP port used by --via-adb")
    p.add_argument("--timeout", type=float, default=2.0,
                   help="socket timeout in seconds")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="print failed connection attempts too")

    args = p.parse_args()

    if args.local and running_on_device():
        pass  # the expected combination

    if args.list:
        return cmd_list(args)
    if args.name or args.package or args.wordlist or args.from_proc:
        return cmd_probe(args)

    p.print_help()
    print()
    print("Start here:")
    print("  python3 %s --list" % os.path.basename(__file__))
    return 1


if __name__ == "__main__":
    sys.exit(main())
