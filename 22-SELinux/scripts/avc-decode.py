#!/usr/bin/env python3
"""
avc-decode.py -- turn an `avc: denied` line into WHO, WHAT, WHICH CLASS,
                 WHICH PERMISSION, and the allow rule that would permit it.

WHAT IT DOES
    Reads SELinux audit records from logcat, dmesg, /proc/kmsg, an auditd
    audit.log, or a saved file, and for every record prints:

        WHO         the subject context, split into user:role:type:level,
                    with the MCS categories decoded back into the Android
                    appId and user id they encode
        WHAT        the object -- a path, a service name, a property name, a
                    socket address, a capability, or a key namespace,
                    whichever this class actually uses
        CLASS       the object class, with a one-line reminder of what kind
                    of thing that class is
        PERMISSION  every permission in the { } set, each with a one-line
                    explanation drawn from the class's own semantics
        RULE        the allow rule that would permit exactly this operation,
                    in both source policy (.te) and CIL syntax
        VERDICT     enforced / permissive / granted, and a blunt note on
                    whether this shape is usually noise

    It also decodes the two encodings that trip up hand-written parsers:
    audit hex-encoding of any field value containing whitespace (comm= and
    path= in particular), and the type=1107 wrapper that init puts around
    property_service denials, where the real scontext is inside a quoted msg.

HOW TO RUN
    # from a file
    python3 avc-decode.py ../examples/avc-denials-measured.log

    # straight off a device
    adb logcat -d -b all | python3 avc-decode.py -
    adb shell "su -c dmesg" | python3 avc-decode.py -

    # just the rules, ready to paste into a .te file
    python3 avc-decode.py denials.log --rules-only

    # collapse repeats -- the single most useful flag on a real device, where
    # 6,000 lines are usually 12 distinct denials
    python3 avc-decode.py denials.log --group

    # machine readable
    python3 avc-decode.py denials.log --json

    # only records whose subject type matches
    python3 avc-decode.py denials.log --scontext untrusted_app

REQUIREMENTS
    Python 3.6 or newer. Standard library only. No adb, no device, no
    libselinux, no network. Runs on Windows, on a locked-down laptop, and in
    a container with nothing installed.

WHAT THIS WILL *NOT* TELL YOU
    - Whether the denial is a security finding. It is almost certainly not.
      A stock, healthy Android 13 device produced 6,101 avc records in a
      single uptime during the writing of this chapter, and every one of them
      was benign. See README section 5.9. The script prints DENIAL, never
      VULNERABILITY, and says NOISE where the shape is a known benign probe.
    - Whether the printed rule is the rule you should ship. It is the
      MINIMAL rule that would permit the logged operation, which is what you
      want for understanding and usually NOT what you want in policy: real
      policy uses macros, attributes and neverallow-safe forms. Treat the
      output as a diagnosis, not a patch.
    - Whether the operation was refused by TYPE ENFORCEMENT or by an MLS/MCS
      CONSTRAINT. The audit record does not say, and this is the single most
      important thing an avc line cannot tell you. The script flags records
      where the category sets do not dominate, because that is *evidence for*
      a constraint denial, but it cannot be certain. Only `sepolicy-analyze`
      or `audit2why` against the actual binary policy can settle it.
    - Whether a matching allow rule already exists. That needs the policy.
      Use `sesearch` / `sepolicy-analyze` on the binary policy for that.
    - Whether adding the rule would violate a neverallow. It might. Compiling
      the policy is the only way to know, and AOSP's CTS will tell you loudly.
    - Anything about DAC. If the operation would also fail on Unix
      permissions, no SELinux rule will help. Check `ls -l` as well as
      `ls -Z`. DAC is 21-App-Sandbox.

ACCURACY NOTES
    The class and permission tables below were taken from a live device, by
    reading /sys/fs/selinux/class/<name>/perms on an Android 13 arm64 handset,
    not from memory. Where a permission is absent from the tables the script
    says "no gloss available" rather than guessing. The MCS arithmetic was
    verified against two independently-observed contexts on that same device:
    uid 10156 -> c156,c256 and uid 1068 -> c44,c260.
"""

from __future__ import print_function

import argparse
import json
import os
import re
import sys
from collections import OrderedDict

# ---------------------------------------------------------------------------
# Android UID arithmetic. These constants are from
# system/core/libcutils/include/private/android_filesystem_config.h
# ---------------------------------------------------------------------------

AID_USER_OFFSET = 100000
AID_APP_START = 10000
AID_APP_END = 19999
AID_SDK_SANDBOX_PROCESS_START = 20000
AID_ISOLATED_START = 90000
AID_ISOLATED_END = 99999

# ---------------------------------------------------------------------------
# Object classes. "kind" is what the object actually IS, which decides which
# field of the audit record names it. Measured from
# /sys/fs/selinux/class/ on Android 13 (105 classes present).
# ---------------------------------------------------------------------------

CLASS_KIND = {
    "file": "a regular file on a filesystem",
    "dir": "a directory",
    "lnk_file": "a symbolic link",
    "chr_file": "a character device node",
    "blk_file": "a block device node",
    "sock_file": "a socket node in the filesystem (a path, not a socket)",
    "fifo_file": "a named pipe",
    "fd": "a file descriptor being passed between processes",
    "filesystem": "a whole mounted filesystem",
    "process": "another process, or the calling process itself",
    "process2": "process operations added after the process class filled up",
    "capability": "a Linux capability, bits 0-31",
    "capability2": "a Linux capability, bits 32+",
    "cap_userns": "a capability inside a user namespace",
    "cap2_userns": "a capability inside a user namespace, bits 32+",
    "security": "the SELinux security server itself (/sys/fs/selinux)",
    "binder": "a Binder transaction between two processes",
    "service_manager": "a named entry in servicemanager's registry",
    "hwservice_manager": "a named entry in hwservicemanager's registry",
    "property_service": "a system property, via init's property setter",
    "keystore_key": "a Keystore key namespace (legacy Keystore)",
    "keystore2_key": "a Keystore key namespace (Keystore 2.0)",
    "keystore2": "the Keystore 2.0 service itself",
    "diced": "the DICE (Device Identifier Composition Engine) service",
    "unix_stream_socket": "a SOCK_STREAM AF_UNIX socket, filesystem or abstract",
    "unix_dgram_socket": "a SOCK_DGRAM AF_UNIX socket, filesystem or abstract",
    "tcp_socket": "a TCP socket",
    "udp_socket": "a UDP socket",
    "rawip_socket": "a raw IP socket",
    "netlink_socket": "a netlink socket",
    "netlink_route_socket": "a NETLINK_ROUTE socket",
    "netlink_kobject_uevent_socket": "a uevent netlink socket",
    "socket": "a socket of a family with no more specific class",
    "packet_socket": "an AF_PACKET socket",
    "anon_inode": "an anonymous inode (userfaultfd, memfd, eventfd, ...)",
    "bpf": "an eBPF map or program",
    "perf_event": "a perf_event_open object",
    "lockdown": "the kernel lockdown LSM",
    "system": "a whole-system operation (ipc_lock, syslog, module_request)",
    "memprotect": "memory protection (mmap_zero)",
    "key": "a kernel keyring key",
    "msg": "a System V message",
    "msgq": "a System V message queue",
    "sem": "a System V semaphore",
    "shm": "a System V shared memory segment",
    "netif": "a network interface",
    "node": "a network node (an address)",
    "association": "an IPsec security association",
    "peer": "a labelled network peer",
    "kernel_service": "a kernel-provided service (use_as_override)",
    "drmservice": "the legacy DRM service",
}

# Permission glosses. Only entries that are actually true of that class on
# Android are present; the script refuses to guess for anything else.
PERM_GLOSS = {
    ("file", "read"): "read the contents",
    ("file", "write"): "write the contents",
    ("file", "append"): "write, but only at the end",
    ("file", "open"): "obtain a descriptor at all -- checked in addition to read/write",
    ("file", "getattr"): "stat() it: size, mode, owner, times",
    ("file", "setattr"): "chmod/chown/utime it",
    ("file", "ioctl"): "issue an ioctl -- see ioctlcmd= for which one; needs allowxperm",
    ("file", "lock"): "flock/fcntl lock it",
    ("file", "map"): "mmap it -- separate from read since Android 8",
    ("file", "execute"): "mmap it PROT_EXEC, i.e. dlopen/System.load it",
    ("file", "execute_no_trans"): "execve() it WITHOUT changing domain",
    ("file", "entrypoint"): "be the binary that a domain transition enters through",
    ("file", "execmod"): "execute a private, MODIFIED file mapping -- text relocations",
    ("file", "unlink"): "delete it (also needs remove_name on the parent dir)",
    ("file", "link"): "make a hard link to it",
    ("file", "rename"): "rename it",
    ("file", "create"): "create it",
    ("file", "relabelfrom"): "change its label, starting from this type",
    ("file", "relabelto"): "change its label, ending at this type",
    ("file", "audit_access"): "be audited on access even when allowed",
    ("file", "watch"): "set an inotify/fanotify watch on it",
    ("file", "mounton"): "use it as a mount point",
    ("dir", "search"): "traverse it, i.e. use it as a path component",
    ("dir", "read"): "list its entries (readdir)",
    ("dir", "write"): "modify it -- implied by add_name/remove_name",
    ("dir", "open"): "obtain a descriptor on it",
    ("dir", "getattr"): "stat() it",
    ("dir", "add_name"): "create an entry in it",
    ("dir", "remove_name"): "delete an entry from it",
    ("dir", "rmdir"): "remove the directory itself",
    ("dir", "reparent"): "be the destination of a rename that moves an entry in",
    ("dir", "setattr"): "chmod/chown it",
    ("dir", "mounton"): "use it as a mount point",
    ("lnk_file", "read"): "readlink() it -- following a symlink needs this",
    ("lnk_file", "getattr"): "lstat() it",
    ("sock_file", "write"): "connect to the socket this node names",
    ("sock_file", "read"): "read from the socket this node names",
    ("sock_file", "getattr"): "stat() the node",
    ("fd", "use"): "use a descriptor received from another domain",
    ("process", "transition"): "change domain across execve()",
    ("process", "dyntransition"): "change domain WITHOUT execve, via setcon()",
    ("process", "setcurrent"): "write to /proc/self/attr/current at all",
    ("process", "execmem"): "make anonymous memory writable AND executable",
    ("process", "execstack"): "make the stack executable",
    ("process", "execheap"): "make the heap executable",
    ("process", "ptrace"): "attach a debugger to it",
    ("process", "signal"): "send it an ordinary signal",
    ("process", "sigkill"): "send it SIGKILL",
    ("process", "sigstop"): "send it SIGSTOP",
    ("process", "signull"): "probe its existence with signal 0",
    ("process", "getattr"): "read /proc/<pid>/ attributes",
    ("process", "getsched"): "read its scheduling parameters",
    ("process", "setsched"): "change its scheduling parameters",
    ("process", "fork"): "fork",
    ("process", "share"): "share address space or fd table with it (CLONE_VM)",
    ("process", "setrlimit"): "change its resource limits",
    ("process", "noatsecure"): "skip AT_SECURE hardening across exec",
    ("process", "setexec"): "preset the domain of the next execve",
    ("process", "setfscreate"): "preset the label of files it creates next",
    ("service_manager", "find"): "look up this service and get its Binder handle",
    ("service_manager", "add"): "register a Binder under this name",
    ("service_manager", "list"): "enumerate registered service names",
    ("hwservice_manager", "find"): "look up this HIDL service",
    ("hwservice_manager", "add"): "register this HIDL service",
    ("binder", "call"): "make a Binder call into that process",
    ("binder", "transfer"): "pass a Binder reference to that process",
    ("binder", "impersonate"): "make a call on another process's behalf",
    ("binder", "set_context_mgr"): "become the context manager (servicemanager only)",
    ("property_service", "set"): "set this system property",
    ("security", "setenforce"): "switch global enforcing/permissive",
    ("security", "read_policy"): "read the binary policy out of selinuxfs",
    ("security", "load_policy"): "load a new binary policy",
    ("security", "setbool"): "flip a policy boolean",
    ("security", "setcheckreqprot"): "change checkreqprot",
    ("security", "compute_av"): "ask the security server for an access vector",
    ("security", "compute_create"): "ask for a type_transition result",
    ("security", "check_context"): "validate a context string",
    ("unix_stream_socket", "connectto"): "connect to a LISTENING socket in that domain",
    ("unix_stream_socket", "create"): "create the socket",
    ("unix_stream_socket", "bind"): "bind it to a name (path or abstract)",
    ("unix_stream_socket", "listen"): "listen on it",
    ("unix_stream_socket", "accept"): "accept a connection",
    ("unix_stream_socket", "read"): "read from it",
    ("unix_stream_socket", "write"): "write to it",
    ("unix_stream_socket", "name_bind"): "bind to a labelled abstract name",
    ("unix_dgram_socket", "sendto"): "send a datagram to it",
    ("unix_dgram_socket", "write"): "write to it",
    ("tcp_socket", "name_connect"): "connect to a labelled port",
    ("tcp_socket", "node_bind"): "bind to a labelled address",
    ("keystore2_key", "use"): "perform a cryptographic operation with a key here",
    ("keystore2_key", "get_info"): "read a key's metadata and characteristics",
    ("keystore2_key", "delete"): "delete a key in this namespace",
    ("keystore2_key", "rebind"): "replace an existing alias, deleting the old key",
    ("keystore2_key", "grant"): "hand another uid access to a key",
    ("keystore2_key", "update"): "update the key's subcomponents (cert chain)",
    ("keystore2_key", "manage_blob"): "supply or retrieve a raw KeyMint blob",
    ("keystore2_key", "use_dev_id"): "include device identifiers in an attestation",
    ("keystore2_key", "gen_unique_id"): "request the attestation unique ID",
    ("keystore2_key", "req_forced_op"): "reserve an operation slot by force",
    ("keystore2_key", "convert_storage_key_to_ephemeral"): "derive an ephemeral storage key",
    ("keystore_key", "get"): "retrieve a key blob (legacy Keystore)",
    ("keystore_key", "insert"): "store a key (legacy Keystore)",
    ("keystore_key", "sign"): "sign with a key (legacy Keystore)",
    ("keystore_key", "verify"): "verify with a key (legacy Keystore)",
    ("keystore_key", "delete"): "delete a key (legacy Keystore)",
    ("keystore_key", "grant"): "grant another uid access (legacy Keystore)",
    ("keystore_key", "list"): "list aliases (legacy Keystore)",
    ("capability", "dac_override"): "ignore file permission bits entirely",
    ("capability", "dac_read_search"): "ignore read and search permission bits",
    ("capability", "sys_admin"): "the grab-bag capability -- mount, and much else",
    ("capability", "sys_module"): "load a kernel module",
    ("capability", "sys_ptrace"): "ptrace any process",
    ("capability", "setuid"): "change uid",
    ("capability", "setgid"): "change gid",
    ("capability", "net_raw"): "open raw and packet sockets",
    ("capability", "net_admin"): "configure networking",
    ("capability", "chown"): "change file ownership arbitrarily",
    ("capability", "fowner"): "bypass ownership checks on files",
    ("capability", "kill"): "signal any process",
    ("capability", "sys_boot"): "reboot the machine",
    ("capability", "sys_rawio"): "raw I/O port and /dev/mem access",
    ("anon_inode", "create"): "create the anonymous inode",
    ("anon_inode", "read"): "read it",
    ("anon_inode", "write"): "write it",
    ("anon_inode", "ioctl"): "ioctl it -- userfaultfd uses this heavily",
    ("bpf", "map_create"): "create an eBPF map",
    ("bpf", "map_read"): "read an eBPF map",
    ("bpf", "map_write"): "write an eBPF map",
    ("bpf", "prog_load"): "load an eBPF program",
    ("bpf", "prog_run"): "attach and run an eBPF program",
    ("system", "syslog_read"): "read the kernel ring buffer (dmesg)",
    ("system", "syslog_mod"): "clear or change the kernel ring buffer",
    ("system", "module_request"): "trigger automatic module loading",
    ("system", "ipc_lock"): "mlock memory",
}

# Which audit field names the object, per class. Falls back to a search order.
OBJECT_FIELD_BY_CLASS = {
    "property_service": ["property"],
    "service_manager": ["name"],
    "hwservice_manager": ["name"],
    "capability": ["capability"],
    "capability2": ["capability"],
    "keystore_key": ["name"],
    "keystore2_key": ["name"],
    "unix_stream_socket": ["path", "name", "laddr"],
    "unix_dgram_socket": ["path", "name", "laddr"],
    "tcp_socket": ["laddr", "lport", "saddr", "dest"],
    "udp_socket": ["laddr", "lport", "saddr", "dest"],
}
OBJECT_FIELD_DEFAULT = ["path", "name", "dev"]

# Shapes that a healthy device produces constantly. Not an exhaustive list --
# it is a starting point so the tool does not present noise as signal.
KNOWN_NOISE = [
    ("gmscore_app", None, None,
     "Google Play Services probes dozens of paths and properties it is not "
     "allowed to reach. Fires on every healthy device, constantly."),
    (None, "traced_producer_socket", None,
     "Perfetto producer socket probing. Benign; the caller handles the failure."),
    (None, "oem_unlock_prop", None,
     "A bootloader-unlock-state probe, i.e. root/tamper detection. Benign as a "
     "denial; interesting as an indicator of what the app is doing. See ch. 37."),
    (None, "proc_security", None,
     "Reading /proc/sys/kernel/{kptr_restrict,randomize_va_space,...}. "
     "Denied to almost everything by design."),
    ("dexoptanalyzer", None, None,
     "dexoptanalyzer walking app data directories it has no MCS categories "
     "for. Expected: it is handed descriptors by installd instead."),
    ("system_suspend", "sysfs", None,
     "The suspend HAL enumerating wakeup sources it cannot all read. Benign."),
    (None, None, "netlink_kobject_uevent_socket",
     "Uevent socket probing during device enumeration. Usually benign."),
]

CTX_RE = re.compile(
    r"^(?P<user>[A-Za-z0-9_.-]+):(?P<role>[A-Za-z0-9_.-]+):(?P<type>[A-Za-z0-9_.-]+)"
    r"(?::(?P<level>.+))?$"
)

# The permission set: `{ read write }` or `{read write}` or `{ read }`.
PERMS_RE = re.compile(r"\{\s*([^}]*?)\s*\}")

# key=value where the value is quoted, hex, or bare.
KV_RE = re.compile(r'\b([a-z_][a-z0-9_]*)=("(?:[^"\\]|\\.)*"|[^\s\'"]+)')

AVC_LINE_RE = re.compile(r"avc:\s*(?P<verdict>denied|granted)\s*\{")

# The init wrapper: type=1107 ... msg='avc: denied { set } for property=... '
MSG_WRAP_RE = re.compile(r"msg='(?P<inner>avc:.*?)'\s*$")


# Fields whose value is a STRING and which the audit subsystem may therefore
# hex-encode. Everything else -- ino, pid, uid, gid, dev, ioctlcmd, capability
# -- is numeric and must never be hex-decoded, or `ino=2037` silently becomes
# the two-character string " 7". That bug was in this script's first draft and
# is exactly the class of error the fixture file exists to catch.
HEXABLE_FIELDS = frozenset((
    "comm", "path", "name", "exe", "cwd", "proctitle", "key", "property",
    "laddr", "saddr", "src", "dest", "obj", "file",
))


def unquote(value, field=None):
    """Strip audit quoting and, for string-valued fields, decode hex.

    The audit subsystem quotes a field value if it is a plain string, and
    HEX-ENCODES it instead if it contains whitespace, a quote, or a control
    character. `comm=73796E6320737663203238` is not a corrupt field; it is
    "sync svc 28". A quoted value is never hex-encoded, and a numeric field is
    never hex-encoded either -- hence the field whitelist.
    """
    if value is None:
        return None
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    if field is not None and field not in HEXABLE_FIELDS:
        return value
    if len(value) >= 4 and len(value) % 2 == 0 and re.match(r"^[0-9A-Fa-f]+$", value):
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            return value
        # Abstract-namespace socket names begin with a NUL byte. The kernel
        # convention is to render that leading NUL as '@'.
        text = raw.decode("utf-8", "replace")
        if text.startswith("\x00"):
            text = "@" + text[1:]
        text = text.replace("\x00", "")
        printable = all((c == "\t") or (0x20 <= ord(c) < 0x7F) or ord(c) > 0x7F
                        for c in text)
        if printable and text:
            return text
        return value
    return value


def parse_level(level):
    """Split an MLS level `s0:c107,c256,c512,c768` into sensitivity + cats."""
    if not level:
        return None, []
    parts = level.split(":")
    sens = parts[0]
    cats = []
    if len(parts) > 1:
        for chunk in parts[1].split(","):
            chunk = chunk.strip()
            m = re.match(r"^c(\d+)(?:\.c(\d+))?$", chunk)
            if not m:
                continue
            lo = int(m.group(1))
            hi = int(m.group(2)) if m.group(2) else lo
            cats.extend(range(lo, hi + 1))
    return sens, sorted(set(cats))


def decode_categories(cats):
    """Reverse Android's MCS encoding.

    AOSP libselinux (external/selinux/libselinux/src/android/android_platform.c)
    builds the level in seapp_context_lookup as:

        levelFrom=app   ->  s0:c(appid & 0xff),c(256 + (appid >> 8))
        levelFrom=user  ->  s0:c(512 + (userid & 0xff)),c(768 + (userid >> 8))
        levelFrom=all   ->  both pairs, app first

    where `appid` is uid % AID_USER_OFFSET, minus AID_APP_START for ordinary
    apps (or minus AID_SDK_SANDBOX_PROCESS_START / AID_ISOLATED_START for
    those ranges), and `userid` is uid / AID_USER_OFFSET.

    Verified on a physical Android 13 device against two independent
    observations: uid 10156 produced c156,c256 (156 & 0xff = 156, 156 >> 8 = 0)
    and uid 1068 produced c44,c260 (1068 & 0xff = 44, 1068 >> 8 = 4).
    """
    out = {"app_pair": None, "user_pair": None, "appid": None, "userid": None,
           "notes": []}
    low = [c for c in cats if c < 256]
    mid = [c for c in cats if 256 <= c < 512]
    ulo = [c for c in cats if 512 <= c < 768]
    uhi = [c for c in cats if 768 <= c < 1024]

    if len(low) == 1 and len(mid) == 1:
        appid = low[0] | ((mid[0] - 256) << 8)
        out["app_pair"] = (low[0], mid[0])
        out["appid"] = appid
    elif low or mid:
        out["notes"].append(
            "app category pair is malformed: expected exactly one category "
            "below c256 and exactly one in c256-c511")

    if len(ulo) == 1 and len(uhi) == 1:
        userid = (ulo[0] - 512) | ((uhi[0] - 768) << 8)
        out["user_pair"] = (ulo[0], uhi[0])
        out["userid"] = userid
    elif ulo or uhi:
        out["notes"].append(
            "user category pair is malformed: expected exactly one category "
            "in c512-c767 and exactly one in c768-c1023")
    return out


# Domains whose subjects are always ordinary installed apps, so the decoded
# appid can be resolved to exactly one uid instead of three candidates.
APP_DOMAINS = frozenset((
    "untrusted_app", "untrusted_app_25", "untrusted_app_27", "untrusted_app_29",
    "untrusted_app_30", "untrusted_app_32", "priv_app", "platform_app",
    "system_app", "ephemeral_app", "gmscore_app", "runas_app",
    "mediaprovider_app", "permissioncontroller_app", "traceur_app",
    "remote_prov_app", "vzwomatrigger_app",
))
ISOLATED_DOMAINS = frozenset(("isolated_app", "isolated_app_all", "app_zygote"))
SANDBOX_DOMAINS = frozenset(("sdk_sandbox", "sdk_sandbox_next"))


def describe_appid(appid, domain=None):
    """Turn a decoded appid back into the uid ranges it could have come from.

    The category pair encodes only the OFFSET, never which range it was
    subtracted from, so without more information three answers are possible.
    The subject's domain usually settles it, and when it does the script says
    so rather than printing three lines of maybe.
    """
    if appid is None:
        return []
    if domain in APP_DOMAINS:
        return ["app uid %d for Android user 0 (AID_APP_START + %d) -- the "
                "domain settles it" % (AID_APP_START + appid, appid)]
    if domain in ISOLATED_DOMAINS:
        return ["isolated-process uid %d (AID_ISOLATED_START + %d) -- the "
                "domain settles it" % (AID_ISOLATED_START + appid, appid)]
    if domain in SANDBOX_DOMAINS:
        return ["SDK sandbox uid %d (AID_SDK_SANDBOX_PROCESS_START + %d) -- "
                "the domain settles it"
                % (AID_SDK_SANDBOX_PROCESS_START + appid, appid)]
    candidates = []
    if 0 <= appid <= 9999:
        candidates.append("a system/native uid %d (below AID_APP_START), "
                          "e.g. an AID from android_filesystem_config.h" % appid)
    if appid <= (AID_APP_END - AID_APP_START):
        candidates.append("app uid %d for Android user 0 (AID_APP_START + %d)"
                          % (AID_APP_START + appid, appid))
    if appid <= (AID_ISOLATED_END - AID_ISOLATED_START):
        candidates.append("isolated-process uid %d (AID_ISOLATED_START + %d)"
                          % (AID_ISOLATED_START + appid, appid))
    return candidates


def class_kind(cls):
    return CLASS_KIND.get(cls, "no description available for this class")


def perm_gloss(cls, perm):
    g = PERM_GLOSS.get((cls, perm))
    if g:
        return g
    # File-like classes share the `common file` permission set.
    if cls in ("lnk_file", "chr_file", "blk_file", "sock_file", "fifo_file"):
        g = PERM_GLOSS.get(("file", perm))
        if g:
            return g
    if cls == "capability2":
        g = PERM_GLOSS.get(("capability", perm))
        if g:
            return g
    return "no gloss available -- read the class definition in "\
           "system/sepolicy/private/access_vectors"


class Denial(object):
    __slots__ = ("verdict", "perms", "fields", "scontext", "tcontext",
                 "tclass", "permissive", "raw", "wrapped")

    def __init__(self):
        self.verdict = "denied"
        self.perms = []
        self.fields = OrderedDict()
        self.scontext = None
        self.tcontext = None
        self.tclass = None
        self.permissive = None
        self.raw = ""
        self.wrapped = False

    # -- derived ----------------------------------------------------------

    def split_context(self, ctx):
        if not ctx:
            return None
        m = CTX_RE.match(ctx)
        if not m:
            return None
        d = m.groupdict()
        sens, cats = parse_level(d.get("level"))
        d["sens"] = sens
        d["cats"] = cats
        d["mcs"] = decode_categories(cats) if cats else None
        return d

    @property
    def subject(self):
        return self.split_context(self.scontext)

    @property
    def target(self):
        return self.split_context(self.tcontext)

    def object_name(self):
        order = OBJECT_FIELD_BY_CLASS.get(self.tclass, OBJECT_FIELD_DEFAULT)
        for key in order:
            if key in self.fields and self.fields[key]:
                return key, self.fields[key]
        for key in OBJECT_FIELD_DEFAULT:
            if key in self.fields and self.fields[key]:
                return key, self.fields[key]
        return None, None

    def rule_te(self):
        s = self.subject
        t = self.target
        if not s or not t or not self.tclass:
            return None
        stype = s["type"]
        ttype = t["type"]
        # Rules for a subject acting on itself are written `self` by convention.
        if self.tcontext == self.scontext and self.tclass in (
                "process", "capability", "capability2", "process2",
                "cap_userns", "cap2_userns"):
            ttype = "self"
        perms = " ".join(self.perms)
        if len(self.perms) == 1:
            return "allow %s %s:%s %s;" % (stype, ttype, self.tclass, perms)
        return "allow %s %s:%s { %s };" % (stype, ttype, self.tclass, perms)

    def rule_cil(self):
        s = self.subject
        t = self.target
        if not s or not t or not self.tclass:
            return None
        ttype = t["type"]
        if self.tcontext == self.scontext and self.tclass in (
                "process", "capability", "capability2", "process2"):
            ttype = "self"
        return "(allow %s %s (%s (%s)))" % (
            s["type"], ttype, self.tclass, " ".join(self.perms))

    def xperm_note(self):
        if "ioctl" in self.perms and "ioctlcmd" in self.fields:
            cmd = self.fields["ioctlcmd"]
            s = self.subject
            t = self.target
            if s and t:
                return ("allowxperm %s %s:%s ioctl { %s };"
                        % (s["type"], t["type"], self.tclass, cmd))
        return None

    def dominates(self):
        """Does the subject's category set contain the object's?

        MLS `dom` on Android reduces to sensitivity comparison plus category
        superset. Both are s0 in practice, so this is a set containment test.
        Returns True, False, or None when there is nothing to compare.
        """
        s = self.subject
        t = self.target
        if not s or not t:
            return None
        if not t["cats"]:
            return None
        return set(t["cats"]).issubset(set(s["cats"]))

    def noise_note(self):
        s = self.subject
        t = self.target
        stype = s["type"] if s else None
        ttype = t["type"] if t else None
        for want_s, want_t, want_c, note in KNOWN_NOISE:
            if want_s and want_s != stype:
                continue
            if want_t and want_t != ttype:
                continue
            if want_c and want_c != self.tclass:
                continue
            return note
        return None

    def key(self):
        return (self.verdict, tuple(sorted(self.perms)), self.scontext,
                self.tcontext, self.tclass)


def parse_line(line):
    """Return a Denial or None."""
    if "avc:" not in line:
        return None
    m = AVC_LINE_RE.search(line)
    if not m:
        return None

    d = Denial()
    d.raw = line.rstrip("\r\n")
    d.verdict = m.group("verdict")

    # An init-wrapped property denial puts the real record inside msg='...'.
    work = line
    wrap = MSG_WRAP_RE.search(line)
    if wrap:
        work = wrap.group("inner")
        d.wrapped = True

    pm = PERMS_RE.search(work[m.start():] if not d.wrapped else work)
    if not pm:
        pm = PERMS_RE.search(work)
    if pm:
        d.perms = [p for p in pm.group(1).split() if p]

    for k, v in KV_RE.findall(work):
        if k in ("msg",):
            continue
        d.fields.setdefault(k, unquote(v, k))

    d.scontext = d.fields.get("scontext")
    d.tcontext = d.fields.get("tcontext")
    d.tclass = d.fields.get("tclass")
    if "permissive" in d.fields:
        try:
            d.permissive = int(d.fields["permissive"])
        except ValueError:
            d.permissive = None

    # An init-wrapped record also carries the OUTER subj=, which is init's own
    # context, not the denied process's. Keep it, clearly named.
    if d.wrapped and "subj" in d.fields:
        d.fields["_reporter_context"] = d.fields.pop("subj")

    if not d.scontext or not d.tclass:
        return None
    return d


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

BAR = "=" * 78
SUB = "-" * 78


def render(d, index, total, show_raw=True):
    out = []
    out.append(BAR)
    out.append("DENIAL %d of %d" % (index, total))
    if show_raw:
        out.append(SUB)
        out.append("RAW    " + d.raw)
    out.append(SUB)

    s = d.subject
    t = d.target

    # WHO
    if s:
        out.append("WHO    %s" % d.scontext)
        out.append("       user=%-8s role=%-10s type=%s"
                   % (s["user"], s["role"], s["type"]))
        if s["cats"]:
            mcs = s["mcs"]
            out.append("       level=%s  categories=%s"
                       % (s["sens"], ",".join("c%d" % c for c in s["cats"])))
            if mcs["appid"] is not None:
                cands = describe_appid(mcs["appid"], s["type"])
                out.append("       MCS app pair  c%d,c%d -> appid %d"
                           % (mcs["app_pair"][0], mcs["app_pair"][1], mcs["appid"]))
                for c in cands:
                    out.append("           could be %s" % c)
            if mcs["userid"] is not None:
                out.append("       MCS user pair c%d,c%d -> Android user %d"
                           % (mcs["user_pair"][0], mcs["user_pair"][1], mcs["userid"]))
            for n in mcs["notes"]:
                out.append("       NOTE %s" % n)
        else:
            out.append("       level=%s  (no MCS categories -- this subject is "
                       "not category-isolated)" % (s["sens"] or "s0"))
    if "pid" in d.fields:
        out.append("       pid=%s%s" % (
            d.fields["pid"],
            "  comm=%s" % d.fields["comm"] if "comm" in d.fields else ""))
    elif "comm" in d.fields:
        out.append("       comm=%s" % d.fields["comm"])
    if "uid" in d.fields:
        out.append("       uid=%s (the DAC identity -- orthogonal to the "
                   "context above)" % d.fields["uid"])
    if "app" in d.fields:
        out.append("       app=%s (logd's annotation, not an audit field)"
                   % d.fields["app"])
    if "_reporter_context" in d.fields:
        out.append("       reported by %s (init wraps property denials; this "
                   "is NOT the denied process)" % d.fields["_reporter_context"])

    # WHAT
    out.append(SUB)
    field, value = d.object_name()
    if t:
        out.append("WHAT   %s" % d.tcontext)
        out.append("       type=%s" % t["type"])
        if t["cats"]:
            tm = t["mcs"]
            out.append("       categories=%s"
                       % ",".join("c%d" % c for c in t["cats"]))
            if tm["appid"] is not None:
                out.append("       MCS app pair  c%d,c%d -> appid %d"
                           % (tm["app_pair"][0], tm["app_pair"][1], tm["appid"]))
            if tm["userid"] is not None:
                out.append("       MCS user pair c%d,c%d -> Android user %d"
                           % (tm["user_pair"][0], tm["user_pair"][1], tm["userid"]))
    if field:
        out.append("       %s=%s" % (field, value))
    else:
        out.append("       (this record names no object -- normal for "
                   "process, capability and security classes)")
    for extra in ("dev", "ino", "ioctlcmd", "capability", "laddr", "lport",
                  "dest", "saddr", "src"):
        if extra in d.fields and extra != field:
            out.append("       %s=%s" % (extra, d.fields[extra]))

    # CLASS
    out.append(SUB)
    out.append("CLASS  %s -- %s" % (d.tclass, class_kind(d.tclass)))

    # PERMISSIONS
    out.append(SUB)
    out.append("PERMS  %s" % (", ".join(d.perms) if d.perms else "(none parsed)"))
    for p in d.perms:
        out.append("       %-20s %s" % (p, perm_gloss(d.tclass, p)))

    # RULE
    out.append(SUB)
    rule = d.rule_te()
    cil = d.rule_cil()
    if rule:
        out.append("RULE   source policy (.te, what you write in system/sepolicy):")
        out.append("           " + rule)
        out.append("       compiled policy (CIL, what you read in plat_sepolicy.cil):")
        out.append("           " + cil)
    else:
        out.append("RULE   could not derive -- context or class missing")
    x = d.xperm_note()
    if x:
        out.append("       ioctl is an EXTENDED permission. The allow above is "
                   "necessary but")
        out.append("       not sufficient; you also need:")
        out.append("           " + x)

    dom = d.dominates()
    if dom is False:
        out.append("       WARNING the subject's categories do NOT contain the "
                   "object's.")
        out.append("               Even with the allow rule above this may "
                   "still be refused by")
        out.append("               an MLS constraint. The audit record cannot "
                   "tell you which")
        out.append("               of the two refused it. See README section 3.7.")

    # VERDICT
    out.append(SUB)
    if d.verdict == "granted":
        out.append("VERDICT GRANTED and logged. The operation SUCCEEDED. This "
                   "record exists")
        out.append("        because the rule carries `auditallow`. Grepping for "
                   "'denied' misses it.")
    elif d.permissive == 1:
        out.append("VERDICT PERMISSIVE. The operation SUCCEEDED. Policy would "
                   "have refused it,")
        out.append("        but this domain is permissive so the kernel logged "
                   "and allowed.")
        out.append("        Do not read this as 'blocked'. On a production "
                   "build, a permissive")
        out.append("        domain is itself worth a finding -- see README "
                   "section 5.4.")
    elif d.permissive == 0:
        out.append("VERDICT ENFORCED. The operation FAILED, almost always with "
                   "EACCES.")
    else:
        out.append("VERDICT unknown -- no permissive= field. Older kernels omit "
                   "it; assume enforced")
        out.append("        only after checking `getenforce` and the domain's "
                   "permissive status.")

    note = d.noise_note()
    if note:
        out.append("        NOISE  " + note)
    return "\n".join(out)


def to_dict(d):
    s = d.subject
    t = d.target
    return {
        "verdict": d.verdict,
        "permissive": d.permissive,
        "permissions": d.perms,
        "tclass": d.tclass,
        "class_kind": class_kind(d.tclass),
        "scontext": d.scontext,
        "tcontext": d.tcontext,
        "subject": {"user": s["user"], "role": s["role"], "type": s["type"],
                    "sens": s["sens"], "categories": s["cats"],
                    "mcs": s["mcs"]} if s else None,
        "target": {"user": t["user"], "role": t["role"], "type": t["type"],
                   "sens": t["sens"], "categories": t["cats"],
                   "mcs": t["mcs"]} if t else None,
        "object_field": d.object_name()[0],
        "object_value": d.object_name()[1],
        "fields": dict(d.fields),
        "rule_te": d.rule_te(),
        "rule_cil": d.rule_cil(),
        "xperm": d.xperm_note(),
        "categories_dominate": d.dominates(),
        "noise_note": d.noise_note(),
        "raw": d.raw,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Decode SELinux avc records into who/what/class/permission "
                    "and the allow rule that would permit them.",
        epilog="Read the WHAT THIS WILL NOT TELL YOU block at the top of this "
               "file before using any output in a report.")
    ap.add_argument("input", nargs="?", default="-",
                    help="file of audit records, or - for stdin")
    ap.add_argument("--rules-only", action="store_true",
                    help="print only the deduplicated allow rules")
    ap.add_argument("--group", action="store_true",
                    help="collapse identical denials and show a count")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="machine-readable output")
    ap.add_argument("--scontext", metavar="TYPE",
                    help="only records whose subject type equals TYPE")
    ap.add_argument("--tcontext", metavar="TYPE",
                    help="only records whose target type equals TYPE")
    ap.add_argument("--tclass", metavar="CLASS",
                    help="only records of this object class")
    ap.add_argument("--no-raw", action="store_true",
                    help="omit the RAW line from each report")
    ap.add_argument("--quiet-noise", action="store_true",
                    help="drop records that match a known-benign shape")
    args = ap.parse_args(argv)

    if args.input == "-":
        stream = sys.stdin
    else:
        if not os.path.exists(args.input):
            sys.stderr.write("avc-decode: no such file: %s\n" % args.input)
            return 2
        stream = open(args.input, "r", encoding="utf-8", errors="replace")

    denials = []
    total_lines = 0
    try:
        for line in stream:
            total_lines += 1
            d = parse_line(line)
            if d is None:
                continue
            if args.scontext:
                s = d.subject
                if not s or s["type"] != args.scontext:
                    continue
            if args.tcontext:
                t = d.target
                if not t or t["type"] != args.tcontext:
                    continue
            if args.tclass and d.tclass != args.tclass:
                continue
            if args.quiet_noise and d.noise_note():
                continue
            denials.append(d)
    finally:
        if stream is not sys.stdin:
            stream.close()

    if args.group:
        seen = OrderedDict()
        for d in denials:
            k = d.key()
            if k in seen:
                seen[k][1] += 1
            else:
                seen[k] = [d, 1]
        grouped = list(seen.values())
    else:
        grouped = [[d, 1] for d in denials]

    if args.as_json:
        payload = []
        for d, count in grouped:
            item = to_dict(d)
            item["count"] = count
            payload.append(item)
        print(json.dumps({"lines_read": total_lines,
                          "records": len(denials),
                          "distinct": len(grouped),
                          "denials": payload}, indent=2))
        return 0

    if args.rules_only:
        rules = OrderedDict()
        for d, count in grouped:
            r = d.rule_te()
            if r:
                rules[r] = rules.get(r, 0) + count
            x = d.xperm_note()
            if x:
                rules[x] = rules.get(x, 0) + count
        print("# %d distinct rules from %d records in %d lines."
              % (len(rules), len(denials), total_lines))
        print("# These are MINIMAL rules that permit exactly what was logged.")
        print("# They are a diagnosis. Do not paste them into policy unchecked:")
        print("# real policy uses macros and attributes, and some of these would")
        print("# violate a neverallow and fail to compile. See the header.")
        for r, n in rules.items():
            print("%-72s # x%d" % (r, n))
        return 0

    if not denials:
        print("No avc records found in %d lines." % total_lines)
        print("Things that produce zero: the wrong logcat buffer (use -b all),")
        print("a device where auditd is not forwarding to logcat (use dmesg,")
        print("which needs root), or a genuinely quiet device (unlikely).")
        return 0

    for i, (d, count) in enumerate(grouped, 1):
        print(render(d, i, len(grouped), show_raw=not args.no_raw))
        if count > 1:
            print("        REPEATS x%d -- a repeating denial is a loop, not an "
                  "escalation." % count)
    print(BAR)
    print("%d records in %d lines, %d distinct shapes."
          % (len(denials), total_lines, len(grouped)))
    enforced = sum(1 for d, _ in grouped if d.permissive == 0)
    permissive = sum(1 for d, _ in grouped if d.permissive == 1)
    granted = sum(1 for d, _ in grouped if d.verdict == "granted")
    noisy = sum(1 for d, _ in grouped if d.noise_note())
    print("  enforced: %d   permissive: %d   granted: %d   known-benign shape: %d"
          % (enforced, permissive, granted, noisy))
    if permissive:
        print("  A permissive record means the operation SUCCEEDED. Check "
              "whether that domain")
        print("  is permissive on a production build -- that is the finding, "
              "not the denial.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
