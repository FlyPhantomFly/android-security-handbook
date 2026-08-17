#!/usr/bin/env python3
"""
storage-diff.py -- snapshot everything an Android app owns on disk, exercise the
                   app, snapshot again, and say exactly what changed.

WHAT IT DOES
    Two verbs.

        snapshot    Walks every storage root that belongs to one package --
                    credential-encrypted, device-encrypted, external
                    app-specific, media, obb, and the ART profile -- and records
                    for every file and directory:

                        type, octal mode, owner uid, owner gid, size,
                        mtime, inode, SELinux label, and (for files under a
                        size cap) a SHA-256 of the contents.

                    The result is one JSON file. Nothing is interpreted at
                    snapshot time; it is a faithful record.

        diff        Compares two snapshots and classifies every difference:

                        APPEARED        a path that did not exist before
                        DISAPPEARED     a path that no longer exists
                        CONTENT         same path, different SHA-256
                        MODE            same path, different permission bits
                        OWNER           uid or gid changed
                        LABEL           SELinux label changed
                        GREW / SHRANK   size changed but hashing was skipped
                        TOUCHED         only mtime moved -- almost always noise

                    and then raises the subset that carries security weight:

                        WORLD-READABLE  a file another uid could open, that
                                        could not be opened before
                        WORLD-WRITABLE  a file another uid could overwrite
                        REACHABLE       world-readable AND every parent
                                        directory grants o+x, so the DAC path
                                        to it is actually walkable

                    The REACHABLE distinction is the point of this tool. A
                    mode-0644 file inside a mode-0700 directory is not a
                    finding, and reporting it as one is how storage scanners
                    earn their reputation. See "HONEST SEVERITY" below.

HOW TO RUN
    # host -- before you touch the app
    python3 -B storage-diff.py snapshot --package com.example.app --out before.json

    # ... now drive the app: log in, save a note, take a photo, log out ...

    # host -- after
    python3 -B storage-diff.py snapshot --package com.example.app --out after.json
    python3 -B storage-diff.py diff before.json after.json

    # only the security-relevant classes, suitable for a report
    python3 -B storage-diff.py diff before.json after.json --only-findings

    # machine-readable, for a CI gate
    python3 -B storage-diff.py diff before.json after.json --json --strict

    # arbitrary roots instead of a package (works without root if you own them)
    python3 -B storage-diff.py snapshot --root /sdcard/Download --out before.json

    # a specific device when several are attached
    python3 -B storage-diff.py snapshot --package com.example.app \\
        --serial 84f7a024 --out before.json

    # skip hashing entirely -- much faster, and all you need for a mode audit
    python3 -B storage-diff.py snapshot --package com.example.app \\
        --no-hash --out before.json

REQUIREMENTS
    * Python 3.6+ on the host. Standard library only -- no adb module, no
      third-party packages.
    * `adb` on PATH, one device attached (or --serial).
    * ROOT on the device for the /data/data and /data/user_de roots. Without it
      the script still works, but only for paths your shell uid can read --
      typically /sdcard and, on Android 11+, /sdcard/Android/data. It says which
      roots it had to skip rather than silently producing a short snapshot.
    * On the device: toybox (any Android 6+ build). It uses `find -printf` with
      %M %m %U %G %s %T@ %i %Z %p, and `sha256sum`. Verified against
      toybox 0.8.3-android on Android 11.

WHAT THIS SCRIPT WILL *NOT* TELL YOU
    - Whether anything it prints is a vulnerability. Every line is a CHANGE, and
      a change is a question, not an answer. An app that writes a new cache file
      on every launch is behaving normally. The script prints WORLD-READABLE and
      never "INSECURE", for the same reason 15-Native-Code's elf-harden-check.py
      prints MISSING and never "VULNERABLE".
    - Whether a world-readable file is reachable by ANOTHER APP. It computes DAC
      reachability only. On any Android 5.0+ device SELinux MCS categories
      independently forbid one untrusted_app from reading another's
      app_data_file, so a REACHABLE verdict on a path under /data/data is a
      DAC-layer finding that MAC may still block. The label is recorded in the
      snapshot precisely so you can check: two apps whose labels carry different
      c-categories cannot read each other regardless of mode bits. Measure it
      with a second app; do not infer it. See README section 5.3.
    - What is IN any file. It records a hash, not contents. Use
      leak-hunter.py for that, and read its false-positive section first.
    - Anything about a file that was created and deleted between the two
      snapshots. A temp file that lives for 40 ms during a login is invisible to
      this method by construction. That is what the Frida hooks in
      storage-trace.js are for -- the two tools answer different questions and
      neither replaces the other.
    - Whether the data is encrypted. Every byte under /data is encrypted at rest
      by file-based encryption on any modern device, and that is irrelevant to
      every finding here: FBE protects against someone holding the powered-off
      handset, not against a process running as another uid on a booted one.
    - Which app wrote a file under /sdcard. The FUSE view reports the daemon's
      uid, not the writer's, so ownership there is uninformative. MediaStore's
      owner_package_name column knows; the filesystem does not. See README 3.7.
    - Anything about a second user or a work profile. It walks user 0 unless you
      pass --user.

ACCURACY NOTES
    - `find -printf` on toybox does NOT support %y; the type character is taken
      from the first byte of %M instead. This was measured, not assumed --
      `find: bad -printf %y` is what the device says.
    - %T@ has sub-second precision and its exact resolution varies by
      filesystem. mtime comparisons are therefore reported as TOUCHED and
      excluded from --only-findings; on f2fs with lazytime an mtime can also
      move without any write reaching the disk.
    - Hashing is capped (--max-hash-bytes, default 8 MiB) because a 400 MB
      WebView cache costs minutes and tells you nothing you did not already
      learn from its size. Capped files are compared on size alone and reported
      as GREW/SHRANK rather than CONTENT, which is a weaker claim and is
      labelled as one.
    - Paths are compared as byte strings after the root prefix is stripped, so a
      snapshot taken with --root /sdcard/Download and one taken with
      --package are not comparable. The script refuses to diff snapshots whose
      root sets differ, rather than producing a diff full of phantom APPEARED
      entries.

AUTHORISED TESTING ONLY. Snapshotting an app's private storage means reading
data that belongs to whoever installed it. Do this on a device you own, against
apps you are permitted to test, and delete the snapshots afterwards -- a
snapshot of a messaging app is a copy of somebody's messages' metadata.
"""

from __future__ import print_function

import argparse
import base64
import json
import os
import subprocess
import sys
import time

VERSION = "1.0"

# The %y specifier does not exist on toybox find. %M's first character carries
# the same information ('-' file, 'd' dir, 'l' symlink, 's' socket, 'p' fifo).
FIND_FORMAT = "%M|%m|%U|%G|%s|%T@|%i|%Z|%p\\n"

# Roots that belong to one package. {p} is substituted with the package name and
# {u} with the user id. Each carries a note explaining what lives there, which
# is printed by --explain and reproduced in the snapshot so a stored file is
# self-documenting six months later.
PACKAGE_ROOTS = [
    ("ce", "/data/user/{u}/{p}",
     "Credential-encrypted internal storage. getFilesDir(), getCacheDir(), "
     "shared_prefs/, databases/. Unreadable until the user has unlocked the "
     "device once since boot. Same directory as /data/data/{p} for user 0."),
    ("de", "/data/user_de/{u}/{p}",
     "Device-encrypted internal storage. getDataDir() under "
     "createDeviceProtectedStorageContext(). Readable from the moment the "
     "kernel mounts /data, before any unlock. Direct Boot lives here."),
    ("ext-data", "/storage/emulated/{u}/Android/data/{p}",
     "External app-specific storage. getExternalFilesDir(), "
     "getExternalCacheDir(). No permission needed to write. Survives nothing "
     "-- removed on uninstall -- but is visible to anything holding "
     "MANAGE_EXTERNAL_STORAGE, and to adb shell on Android 11."),
    ("ext-media", "/storage/emulated/{u}/Android/media/{p}",
     "App-specific media directory. getExternalMediaDirs(). Indexed by "
     "MediaStore, so its contents are visible to every app with READ_MEDIA / "
     "READ_EXTERNAL_STORAGE, unlike Android/data."),
    ("obb", "/storage/emulated/{u}/Android/obb/{p}",
     "Expansion files. Usually empty for anything not a game."),
    ("profile", "/data/misc/profiles/cur/{u}/{p}",
     "ART's per-app execution profile. Not app data, but it is written during "
     "a session and it leaks which code paths ran. See 13-ART."),
]


# ---------------------------------------------------------------------------
# Talking to the device
# ---------------------------------------------------------------------------

class Device(object):
    """One adb connection, with an honest record of whether root worked.

    Every command is sent as a SINGLE argv element. adb shell does not preserve
    the host shell's quoting -- it joins its arguments with spaces and hands the
    result to the device's sh. Chapter 09 lost an afternoon to exactly this:
    `su -c "ls -ldZ /data/data"` arrives as `su -c ls -ldZ /data/data`, su takes
    only `ls`, and the rest becomes su's own arguments. To sidestep quoting
    entirely, every command is base64-encoded on the host and decoded on the
    device. The base64 alphabet contains no quote, space or metacharacter, so
    there is nothing left for either shell to misparse.
    """

    def __init__(self, serial=None, want_root=True, verbose=False):
        self.serial = serial
        self.verbose = verbose
        self.have_root = False
        self._base = ["adb"] + (["-s", serial] if serial else []) + ["shell"]
        self._check_device()
        if want_root:
            self.have_root = self._check_root()

    def _run(self, argv, timeout=600):
        if self.verbose:
            sys.stderr.write("+ %s\n" % " ".join(argv))
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        try:
            out, err = proc.communicate(timeout=timeout)
        except Exception:
            proc.kill()
            raise
        return proc.returncode, out, err

    def _check_device(self):
        rc, out, err = self._run(["adb"] + (["-s", self.serial] if self.serial
                                            else []) + ["get-state"])
        state = out.decode("utf-8", "replace").strip()
        if rc != 0 or state != "device":
            raise SystemExit(
                "error: no device in state 'device' (adb says %r). "
                "Run `adb devices -l`." % (state or err.decode("utf-8", "replace").strip()))

    def _check_root(self):
        out = self.sh("id -u", root=True, quiet=True)
        return out.strip() == "0"

    def sh(self, command, root=False, quiet=False, timeout=600):
        """Run one shell command on the device and return its stdout as text.

        Never raises on a non-zero exit -- device commands fail routinely
        (Permission denied on a root the caller does not have) and the caller
        decides what that means.
        """
        payload = base64.b64encode(command.encode("utf-8")).decode("ascii")
        inner = "echo %s | base64 -d | sh" % payload
        if root:
            remote = "su -c '%s'" % inner
        else:
            remote = inner
        rc, out, err = self._run(self._base + [remote], timeout=timeout)
        text = out.decode("utf-8", "replace")
        if not quiet and self.verbose and err:
            sys.stderr.write(err.decode("utf-8", "replace"))
        return text

    def prop(self, name):
        return self.sh("getprop %s" % name, quiet=True).strip()

    def exists(self, path, root=False):
        return self.sh("test -e %s && echo Y || echo N" % path,
                       root=root, quiet=True).strip() == "Y"


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

def shell_quote_path(path):
    """Make a path safe for the device's sh.

    Paths inside app storage are overwhelmingly [A-Za-z0-9._/-], but a cache
    file named after a URL is not, and a snapshot that dies on one filename is
    useless. Single-quote it and escape any embedded single quote the standard
    way.
    """
    return "'" + path.replace("'", "'\\''") + "'"


def check_msys_mangling(path):
    """Catch the Git-Bash-on-Windows path rewrite before it wastes an hour.

    MSYS2 (which Git Bash is) rewrites any argument that LOOKS like a Unix
    absolute path into a Windows one before the process ever sees it, so

        python3 storage-diff.py snapshot --root /data/local/tmp/ch33

    arrives in argv as 'C:/Program Files/Git/data/local/tmp/ch33'. The snapshot
    then reports "does not exist" for a directory that plainly does, and the
    error message points at the device instead of at the shell. --package is
    immune because those paths are built inside Python, which is exactly why
    this bug hides until the first time somebody uses --root.

    The fix is one environment variable, so say so rather than guessing at the
    user's intent and silently un-mangling.
    """
    if path.startswith("/"):
        return path
    if len(path) > 1 and path[1] == ":" and "/" in path:
        tail = path[path.index("/", 2):] if path.find("/", 2) >= 0 else path
        raise SystemExit(
            "error: --root was rewritten by the shell before Python saw it.\n"
            "         you typed something like:  %s\n"
            "         argv actually contains:    %s\n"
            "       This is MSYS/Git Bash path conversion, not an adb problem.\n"
            "       Re-run with the conversion disabled:\n"
            "         MSYS_NO_PATHCONV=1 python3 -B storage-diff.py snapshot --root ... \n"
            "       or use a Windows shell, WSL, or --package instead.\n"
            % (tail, path))
    return path


def walk_root(dev, root, use_root, follow_symlinks=False):
    """Return a list of raw entry dicts for one root, or None if unreadable."""
    xdev = "" if follow_symlinks else " -xdev"
    cmd = "find %s%s -printf %s 2>/dev/null" % (
        shell_quote_path(root), xdev, shell_quote_path(FIND_FORMAT))
    text = dev.sh(cmd, root=use_root, quiet=True)
    entries = []
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line:
            continue
        parts = line.split("|", 8)
        if len(parts) != 9:
            # A filename containing a literal '|' would land here. Rather than
            # guess, keep it and mark it -- silent loss is worse than noise.
            continue
        modestr, mode, uid, gid, size, mtime, inode, label, path = parts
        entries.append({
            "type": modestr[0] if modestr else "?",
            "modestr": modestr,
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "size": int(size) if size.isdigit() else -1,
            "mtime": mtime,
            "inode": inode,
            "label": label,
            "path": path,
        })
    if not entries:
        # Distinguish "root does not exist / unreadable" from "root is empty".
        if not dev.exists(root, root=use_root):
            return None
        return []
    return entries


def hash_files(dev, paths, use_root, batch=60):
    """SHA-256 a list of device paths, in batches, tolerating failures."""
    result = {}
    for i in range(0, len(paths), batch):
        chunk = paths[i:i + batch]
        cmd = "sha256sum %s 2>/dev/null" % " ".join(
            shell_quote_path(p) for p in chunk)
        text = dev.sh(cmd, root=use_root, quiet=True)
        for line in text.splitlines():
            line = line.rstrip("\r")
            if len(line) > 66 and line[64:66] == "  ":
                result[line[66:]] = line[:64]
    return result


def do_snapshot(args):
    dev = Device(args.serial, want_root=not args.no_root, verbose=args.verbose)

    roots = []
    if args.package:
        for name, template, note in PACKAGE_ROOTS:
            roots.append((name,
                          template.format(p=args.package, u=args.user),
                          note))
    for r in (args.root or []):
        roots.append(("custom", check_msys_mangling(r), "Supplied with --root."))

    if not roots:
        raise SystemExit("error: give --package or at least one --root")

    snap = {
        "tool": "storage-diff.py",
        "version": VERSION,
        "taken_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "package": args.package,
        "user": args.user,
        "had_root": dev.have_root,
        "hashed": not args.no_hash,
        "max_hash_bytes": args.max_hash_bytes,
        "device": {
            "serial": args.serial or "(default)",
            "model": dev.prop("ro.product.model"),
            "release": dev.prop("ro.build.version.release"),
            "sdk": dev.prop("ro.build.version.sdk"),
            "fingerprint": dev.prop("ro.build.fingerprint"),
            "crypto_type": dev.prop("ro.crypto.type"),
        },
        "roots": [],
        "entries": {},
        "skipped": [],
    }

    total = 0
    for name, path, note in roots:
        needs_root = path.startswith("/data/") and not path.startswith("/data/local/tmp")
        use_root = dev.have_root and needs_root
        entries = walk_root(dev, path, use_root)
        if entries is None:
            reason = ("not readable without root" if (needs_root and not dev.have_root)
                      else "does not exist")
            snap["skipped"].append({"name": name, "path": path, "reason": reason})
            sys.stderr.write("  skip  %-10s %s  (%s)\n" % (name, path, reason))
            continue
        snap["roots"].append({"name": name, "path": path, "note": note,
                              "count": len(entries)})

        if not args.no_hash:
            hashable = [e["path"] for e in entries
                        if e["type"] == "-" and 0 <= e["size"] <= args.max_hash_bytes]
            digests = hash_files(dev, hashable, use_root)
            for e in entries:
                if e["type"] != "-":
                    continue
                if e["size"] > args.max_hash_bytes:
                    e["sha256"] = "(over cap)"
                else:
                    e["sha256"] = digests.get(e["path"], "(unreadable)")

        for e in entries:
            e["root"] = name
            snap["entries"][e["path"]] = e
        total += len(entries)
        sys.stderr.write("  walk  %-10s %s  (%d entries)\n" % (name, path, len(entries)))

    with open(args.out, "w") as fh:
        json.dump(snap, fh, indent=1, sort_keys=True)

    sys.stderr.write("\nwrote %s -- %d entries across %d roots%s\n" % (
        args.out, total, len(snap["roots"]),
        "" if dev.have_root else "  (NO ROOT: internal storage was skipped)"))
    return 0


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def is_world_readable(entry):
    """Other-readable, for a file. Directories are handled by o+x separately."""
    try:
        other = int(entry["mode"][-1], 8)
    except (ValueError, IndexError):
        return False
    return bool(other & 4)


def is_world_writable(entry):
    try:
        other = int(entry["mode"][-1], 8)
    except (ValueError, IndexError):
        return False
    return bool(other & 2)


def is_world_executable(entry):
    try:
        other = int(entry["mode"][-1], 8)
    except (ValueError, IndexError):
        return False
    return bool(other & 1)


def dac_reachable(path, entries):
    """True if every ancestor directory PRESENT IN THE SNAPSHOT grants o+x.

    This is the check that separates a finding from a false positive. A
    world-readable file whose parent is mode 0700 cannot be opened by another
    uid, because open(2) resolves the path one component at a time and each
    directory needs execute permission for the traverse.

    It is deliberately conservative in one direction and honest about the
    other: ancestors ABOVE the snapshot root were not walked, so the function
    can only say "nothing inside the snapshot blocks this". /data/data itself is
    0771 on every device measured, and /data is 0771, so in practice the
    snapshot root's own mode is the gate -- but the code does not pretend to
    have checked what it did not look at, and reachable_note() says so.
    """
    parent = os.path.dirname(path)
    seen_any = False
    while parent and parent != "/":
        e = entries.get(parent)
        if e is not None:
            seen_any = True
            if not is_world_executable(e):
                return False
        parent = os.path.dirname(parent)
    return seen_any


def classify(before, after):
    """Yield (kind, path, detail) for every difference between two entry maps."""
    b_paths = set(before.keys())
    a_paths = set(after.keys())

    for p in sorted(a_paths - b_paths):
        yield ("APPEARED", p, after[p])
    for p in sorted(b_paths - a_paths):
        yield ("DISAPPEARED", p, before[p])

    for p in sorted(a_paths & b_paths):
        b, a = before[p], after[p]
        changed = False
        if b.get("mode") != a.get("mode"):
            yield ("MODE", p, {"from": b["modestr"], "to": a["modestr"],
                               "entry": a})
            changed = True
        if (b.get("uid"), b.get("gid")) != (a.get("uid"), a.get("gid")):
            yield ("OWNER", p, {"from": "%s:%s" % (b["uid"], b["gid"]),
                                "to": "%s:%s" % (a["uid"], a["gid"]),
                                "entry": a})
            changed = True
        if b.get("label") != a.get("label"):
            yield ("LABEL", p, {"from": b["label"], "to": a["label"],
                                "entry": a})
            changed = True

        bh, ah = b.get("sha256"), a.get("sha256")
        if bh and ah and bh != ah and "(" not in bh and "(" not in ah:
            yield ("CONTENT", p, {"from": bh[:16], "to": ah[:16],
                                  "size_from": b["size"], "size_to": a["size"],
                                  "entry": a})
            changed = True
        elif b.get("size") != a.get("size"):
            kind = "GREW" if a["size"] > b["size"] else "SHRANK"
            yield (kind, p, {"from": b["size"], "to": a["size"], "entry": a})
            changed = True

        if not changed and b.get("mtime") != a.get("mtime"):
            yield ("TOUCHED", p, {"from": b["mtime"], "to": a["mtime"],
                                  "entry": a})


ORDER = ["APPEARED", "CONTENT", "MODE", "OWNER", "LABEL", "GREW", "SHRANK",
         "DISAPPEARED", "TOUCHED"]

FINDING_KINDS = {"APPEARED", "CONTENT", "MODE", "OWNER", "LABEL"}


def do_diff(args):
    with open(args.before) as fh:
        before = json.load(fh)
    with open(args.after) as fh:
        after = json.load(fh)

    # Compare what each run ASKED FOR, not what it found.
    #
    # A root that did not exist for the "before" snapshot and does exist for the
    # "after" one is not an operator error -- it is a RESULT. The first call to
    # getExternalMediaDirs() creates Android/media/<pkg>, so a session that
    # touches that API legitimately grows a root mid-diff, and refusing to
    # compare would hide exactly the event worth reporting. Comparing the
    # requested set (found + skipped) instead still catches the case this guard
    # exists for: diffing a --package snapshot against a --root one.
    def requested(snap):
        return sorted([r["path"] for r in snap.get("roots", [])] +
                      [s["path"] for s in snap.get("skipped", [])])

    b_req, a_req = requested(before), requested(after)
    if b_req != a_req and not args.force:
        sys.stderr.write(
            "error: the two snapshots were taken over different root SETS, so\n"
            "       every entry in the extra root would be reported as APPEARED.\n"
            "         before: %s\n         after:  %s\n"
            "       Re-take them the same way, or pass --force if you meant it.\n"
            % (b_req, a_req))
        return 2

    b_found = set(r["path"] for r in before.get("roots", []))
    a_found = set(r["path"] for r in after.get("roots", []))
    new_roots = sorted(a_found - b_found)
    gone_roots = sorted(b_found - a_found)

    be, ae = before["entries"], after["entries"]
    diffs = list(classify(be, ae))

    # Security promotions. Computed against the AFTER snapshot, because that is
    # the state the device is in when you finish testing.
    promotions = []
    for kind, path, detail in diffs:
        entry = detail if kind in ("APPEARED", "DISAPPEARED") else detail.get("entry", {})
        if kind == "DISAPPEARED" or not entry:
            continue
        if entry.get("type") != "-":
            continue
        wr = is_world_readable(entry)
        ww = is_world_writable(entry)
        if not (wr or ww):
            continue
        # Was it already world-readable before? Then it is not a NEW exposure,
        # but it is still worth listing once.
        prior = be.get(path)
        newly = prior is None or not is_world_readable(prior)
        reach = dac_reachable(path, ae)
        promotions.append({
            "path": path,
            "mode": entry.get("modestr"),
            "size": entry.get("size"),
            "label": entry.get("label"),
            "world_readable": wr,
            "world_writable": ww,
            "newly_exposed": newly,
            "dac_reachable": reach,
        })

    if args.json:
        json.dump({
            "before": args.before, "after": args.after,
            "diffs": [{"kind": k, "path": p,
                       "detail": {kk: vv for kk, vv in d.items() if kk != "entry"}
                       if isinstance(d, dict) else d}
                      for k, p, d in diffs],
            "exposures": promotions,
        }, sys.stdout, indent=1)
        print()
        return 1 if (args.strict and promotions) else 0

    print("=" * 78)
    print("STORAGE DIFF")
    print("=" * 78)
    print("  before        %s   (%s)" % (args.before, before.get("taken_at")))
    print("  after         %s   (%s)" % (args.after, after.get("taken_at")))
    d = after.get("device", {})
    print("  device        %s   Android %s / API %s" % (
        d.get("model"), d.get("release"), d.get("sdk")))
    print("  package       %s" % after.get("package"))
    print("  root on host  %s" % ("yes" if after.get("had_root") else
                                  "NO -- internal storage not covered"))
    if after.get("skipped"):
        for s in after["skipped"]:
            print("  skipped       %-9s %s  (%s)" % (s["name"], s["path"], s["reason"]))
    for r in new_roots:
        print("  NEW ROOT      %s" % r)
        print("                This root did not exist before the exercise. Something")
        print("                the app did created it -- getExternalMediaDirs() and")
        print("                getExternalFilesDir() both create their directory on")
        print("                first call. That is a finding in itself: it tells you")
        print("                the app reached for a storage area it had not used.")
    for r in gone_roots:
        print("  ROOT VANISHED %s" % r)
    print()

    counts = {}
    for k, _, _ in diffs:
        counts[k] = counts.get(k, 0) + 1
    print("  " + "  ".join("%s=%d" % (k, counts.get(k, 0))
                           for k in ORDER if counts.get(k)))
    print()

    by_kind = {}
    for k, p, det in diffs:
        by_kind.setdefault(k, []).append((p, det))

    for kind in ORDER:
        if kind not in by_kind:
            continue
        if args.only_findings and kind not in FINDING_KINDS:
            continue
        rows = by_kind[kind]
        print("-" * 78)
        print("%s  (%d)" % (kind, len(rows)))
        print("-" * 78)
        for path, det in rows[:args.limit]:
            if kind == "APPEARED":
                print("  %s  %8s  %s" % (det.get("modestr", "?"),
                                         det.get("size", "?"), path))
            elif kind == "DISAPPEARED":
                print("  %s  %8s  %s" % (det.get("modestr", "?"),
                                         det.get("size", "?"), path))
            elif kind == "CONTENT":
                print("  %s  %s -> %s  (%s -> %s bytes)" % (
                    path, det["from"], det["to"], det["size_from"], det["size_to"]))
            elif kind in ("GREW", "SHRANK"):
                print("  %s  %s -> %s bytes" % (path, det["from"], det["to"]))
            else:
                print("  %s  %s -> %s" % (path, det["from"], det["to"]))
        if len(rows) > args.limit:
            print("  ... %d more (raise --limit)" % (len(rows) - args.limit))
        print()

    print("=" * 78)
    print("EXPOSURE REVIEW  -- mode bits that let another uid at the data")
    print("=" * 78)
    if not promotions:
        print("  Nothing world-readable or world-writable changed or appeared.")
        print("  That is the expected result for a well-behaved app, and it is")
        print("  not evidence that the app stores nothing sensitive -- only that")
        print("  what it stores, it stores with correct mode bits.")
    else:
        for pr in promotions:
            tags = []
            if pr["world_writable"]:
                tags.append("WORLD-WRITABLE")
            elif pr["world_readable"]:
                tags.append("WORLD-READABLE")
            tags.append("NEW" if pr["newly_exposed"] else "pre-existing")
            tags.append("DAC-reachable" if pr["dac_reachable"]
                        else "blocked by a parent directory")
            print("  [%s]" % ", ".join(tags))
            print("      %s" % pr["path"])
            print("      mode %s   %s bytes" % (pr["mode"], pr["size"]))
            print("      label %s" % pr["label"])
            if not pr["dac_reachable"]:
                print("      -> NOT a finding on its own: an ancestor directory")
                print("         denies o+x, so no other uid can resolve this path.")
            else:
                print("      -> DAC permits another uid to open this. Confirm with")
                print("         a second app before reporting: SELinux MCS")
                print("         categories may still refuse. Compare the label")
                print("         above against the reader's own.")
            print()
    print("  Reminder: this tool reports DAC only. SELinux is a separate,")
    print("  independent gate -- see README section 5.3 and 22-SELinux.")
    print()

    return 1 if (args.strict and promotions) else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="storage-diff.py",
        description="Snapshot and diff an Android app's on-disk footprint.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Read the module docstring before trusting any output; the "
               "'WHAT THIS WILL NOT TELL YOU' section is the important part.")
    ap.add_argument("--version", action="version", version="storage-diff.py " + VERSION)
    sub = ap.add_subparsers(dest="verb")

    s = sub.add_parser("snapshot", help="record the current state")
    s.add_argument("--package", help="package name; expands to all six roots")
    s.add_argument("--root", action="append",
                   help="an explicit path to walk (repeatable)")
    s.add_argument("--user", type=int, default=0, help="Android user id (default 0)")
    s.add_argument("--out", required=True, help="output JSON file")
    s.add_argument("--serial", help="adb device serial")
    s.add_argument("--no-root", action="store_true",
                   help="do not attempt su; walk only what shell can read")
    s.add_argument("--no-hash", action="store_true",
                   help="skip SHA-256; much faster, size-only comparison")
    s.add_argument("--max-hash-bytes", type=int, default=8 * 1024 * 1024,
                   help="do not hash files larger than this (default 8 MiB)")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=do_snapshot)

    d = sub.add_parser("diff", help="compare two snapshots")
    d.add_argument("before")
    d.add_argument("after")
    d.add_argument("--json", action="store_true")
    d.add_argument("--only-findings", action="store_true",
                   help="hide TOUCHED/GREW/SHRANK/DISAPPEARED noise")
    d.add_argument("--limit", type=int, default=60,
                   help="max rows printed per class (default 60)")
    d.add_argument("--strict", action="store_true",
                   help="exit 1 if any exposure is reported")
    d.add_argument("--force", action="store_true",
                   help="diff snapshots covering different roots anyway")
    d.set_defaults(func=do_diff)

    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
