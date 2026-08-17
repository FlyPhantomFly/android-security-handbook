#!/usr/bin/env python3
"""
mountinfo-diff.py -- structured diff of two Linux mountinfo captures.

Purpose
    /proc/<pid>/mountinfo is the ground truth for what a process can see at a
    path. Comparing two captures -- typically the global namespace against a
    Magisk DenyList'ed app's namespace -- tells you exactly which mounts were
    removed, which were added, and which changed. A plain `diff` of the two files
    is unreadable, because fields 1 and 2 (mount id and parent id) legitimately
    differ between namespaces for reasons that carry no meaning. This tool
    compares the fields that do carry meaning and classifies the result.

    It also flags mounts whose source or target looks like Magisk's work, so you
    can separate "Magisk's overlay" from "Android's storage mounts" without
    reading 200 lines by hand.

Usage
    Capture on the device, analyse on the host:

        adb shell "su -c 'cat /proc/1/mountinfo'"           > global.txt
        PID=$(adb shell pidof -s com.example.target | tr -d '\\r')
        adb shell "su -c 'cat /proc/$PID/mountinfo'"        > target.txt
        python3 mountinfo-diff.py global.txt target.txt

    The OUTER quotes are load-bearing. adb shell joins its arguments with spaces
    and hands the result to the device's sh, so `adb shell su -c 'cat FILE'`
    arrives as `su -c cat FILE`; su -c then runs only `cat`, reading stdin
    instead of FILE, and you get an empty capture with no error.

    Options:
        --all           do not summarise; print every changed mount in full
        --json          machine-readable output, for diffing across devices
        --quiet         suppress the explanatory notes

    Exit status is 0 whenever the files parsed, whatever the diff shows. This is
    a measurement tool, not a test, and it deliberately has no notion of pass.

Requirements
    Python 3.8+ on the host. No third-party packages. Nothing is written to disk
    and no bytecode cache is produced when run as a script.

What this will NOT tell you
    * Whether a device is rooted. A mount table with no Magisk mounts in it is
      exactly what a DenyList'ed process is supposed to look like, and also
      exactly what a stock device looks like. The tool reports differences
      between two captures; it does not know which capture is "normal".
    * Whether the target namespace resembles a genuinely stock device. Removing
      a mount leaves traces -- ordering, mount id ranges, propagation state --
      that this tool does not attempt to model, and that you cannot evaluate
      without a stock capture from the same build.
    * Anything outside the mount table: properties, SELinux policy contents,
      loaded libraries, package visibility, or hardware attestation. DenyList
      does not touch any of those, so neither does this.
    * Why a mount is there. The MAGISK_HINTS below are substring heuristics.
      A module can name its files anything; a vendor can legitimately use the
      word "overlay". Read the full lines before drawing a conclusion.
"""

import argparse
import json
import sys

# Substrings that suggest a mount is Magisk's rather than Android's. Heuristic,
# deliberately conservative, and explicitly not a verdict -- see the module
# docstring.
MAGISK_HINTS = (
    "magisk",
    "/data/adb",
    "debug_ramdisk",
    "worker",
    ".magisk",
)

# Mount points that routinely differ between an app's namespace and init's for
# reasons that have nothing to do with root: Android gives each app process its
# own storage view.
BENIGN_PREFIXES = (
    "/storage",
    "/mnt/user",
    "/mnt/installer",
    "/mnt/androidwritable",
    "/mnt/runtime",
    "/data/media",
)


class Mount(object):
    """One parsed line of /proc/<pid>/mountinfo.

    Field layout (kernel Documentation/filesystems/proc.rst):

        36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw
        1  2  3    4     5     6          7        8 9    10        11

    1  mount id       -- unique per mount, DIFFERS between namespaces
    2  parent id      -- likewise
    3  major:minor    -- the backing device
    4  root           -- subtree of the filesystem mounted; a bind mount's source
    5  mount point    -- the path, as seen in THIS namespace
    6  mount options
    7  optional fields, terminated by a single '-'
    9  filesystem type
    10 mount source
    11 superblock options
    """

    __slots__ = ("mount_id", "parent_id", "dev", "root", "point",
                 "opts", "fstype", "source", "sb_opts", "raw")

    def __init__(self, line):
        self.raw = line.rstrip("\n")
        parts = self.raw.split()
        if len(parts) < 10:
            raise ValueError("not a mountinfo line: %r" % (self.raw,))
        self.mount_id = parts[0]
        self.parent_id = parts[1]
        self.dev = parts[2]
        self.root = parts[3]
        self.point = parts[4]
        self.opts = parts[5]
        try:
            sep = parts.index("-", 6)
        except ValueError:
            raise ValueError("no '-' separator in mountinfo line: %r" % (self.raw,))
        self.fstype = parts[sep + 1] if len(parts) > sep + 1 else ""
        self.source = parts[sep + 2] if len(parts) > sep + 2 else ""
        self.sb_opts = parts[sep + 3] if len(parts) > sep + 3 else ""

    def key(self):
        """Identity that is stable across namespaces.

        Mount id and parent id are excluded on purpose: they are per-namespace
        and including them makes every line differ.
        """
        return (self.point, self.root, self.fstype, self.source)

    def looks_magisk(self):
        blob = (self.point + " " + self.root + " " + self.source + " " + self.fstype).lower()
        return any(h in blob for h in MAGISK_HINTS)

    def looks_benign_storage(self):
        return any(self.point.startswith(p) for p in BENIGN_PREFIXES)

    def to_dict(self):
        return {
            "point": self.point,
            "root": self.root,
            "fstype": self.fstype,
            "source": self.source,
            "opts": self.opts,
            "magisk_hint": self.looks_magisk(),
            "benign_storage": self.looks_benign_storage(),
        }

    def short(self):
        return "%-45s  fs=%-12s src=%-28s root=%s" % (
            self.point[:45], self.fstype[:12], self.source[:28], self.root)


def parse(path):
    mounts = []
    bad = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                mounts.append(Mount(line))
            except ValueError:
                bad += 1
    return mounts, bad


def bucket(mounts):
    """Group by stable key. A path can be mounted more than once (stacked mounts),
    so the value is a list rather than a single Mount."""
    out = {}
    for m in mounts:
        out.setdefault(m.key(), []).append(m)
    return out


def classify(mount_list):
    magisk = [m for m in mount_list if m.looks_magisk()]
    benign = [m for m in mount_list if m.looks_benign_storage() and not m.looks_magisk()]
    other = [m for m in mount_list
             if not m.looks_magisk() and not m.looks_benign_storage()]
    return magisk, benign, other


def report_group(title, mounts, show_all, note=None):
    print("== %s (%d) ==" % (title, len(mounts)))
    if not mounts:
        print("   (none)")
        print("")
        return
    magisk, benign, other = classify(mounts)
    for label, group in (("magisk-shaped", magisk),
                         ("android storage", benign),
                         ("other", other)):
        if not group:
            continue
        print("   -- %s (%d)" % (label, len(group)))
        limit = len(group) if show_all else min(len(group), 25)
        for m in group[:limit]:
            print("      " + m.short())
        if limit < len(group):
            print("      ... %d more (use --all)" % (len(group) - limit))
    if note:
        print("")
        print("   " + note)
    print("")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Structured diff of two /proc/<pid>/mountinfo captures.")
    ap.add_argument("baseline", help="mountinfo from the reference namespace, e.g. /proc/1")
    ap.add_argument("target", help="mountinfo from the process under investigation")
    ap.add_argument("--all", action="store_true", help="print every entry, not the first 25")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--quiet", action="store_true", help="omit the explanatory notes")
    args = ap.parse_args(argv)

    base, base_bad = parse(args.baseline)
    targ, targ_bad = parse(args.target)

    bb = bucket(base)
    tb = bucket(targ)

    removed = [m for k, v in bb.items() if k not in tb for m in v]
    added = [m for k, v in tb.items() if k not in bb for m in v]
    common_keys = [k for k in bb if k in tb]

    # Same identity, different mount options -- worth seeing, rarely important.
    changed = []
    for k in common_keys:
        b_opts = sorted(m.opts for m in bb[k])
        t_opts = sorted(m.opts for m in tb[k])
        if b_opts != t_opts:
            changed.append((bb[k][0], tb[k][0]))

    if args.json:
        print(json.dumps({
            "baseline": {"file": args.baseline, "count": len(base), "unparsed": base_bad},
            "target": {"file": args.target, "count": len(targ), "unparsed": targ_bad},
            "removed": [m.to_dict() for m in removed],
            "added": [m.to_dict() for m in added],
            "changed": [{"baseline": b.to_dict(), "target": t.to_dict()} for b, t in changed],
        }, indent=2))
        return 0

    print("=" * 70)
    print(" mountinfo-diff")
    print("   baseline : %s  (%d mounts, %d unparsed)" % (args.baseline, len(base), base_bad))
    print("   target   : %s  (%d mounts, %d unparsed)" % (args.target, len(targ), targ_bad))
    print("=" * 70)
    print("")

    report_group(
        "present in baseline, ABSENT in target", removed, args.all,
        None if args.quiet else
        "These are the mounts the target process cannot see. If the target is on\n"
        "   Magisk's DenyList, the magisk-shaped rows here are what DenyList removed.\n"
        "   Every module overlay in this list is invisible to that process -- which is\n"
        "   why a system-CA module and DenyList cannot both work for the same app.")

    report_group(
        "present in target, ABSENT in baseline", added, args.all,
        None if args.quiet else
        "Android gives each app process its own storage view, so /storage and /mnt/user\n"
        "   entries here are normal and are NOT findings. Anything else is worth reading.")

    print("== same mount, different options (%d) ==" % len(changed))
    if not changed:
        print("   (none)")
    else:
        limit = len(changed) if args.all else min(len(changed), 15)
        for b, t in changed[:limit]:
            print("   %s" % b.point)
            print("      baseline: %s" % b.opts)
            print("      target  : %s" % t.opts)
        if limit < len(changed):
            print("   ... %d more (use --all)" % (len(changed) - limit))
    print("")

    m_removed = [m for m in removed if m.looks_magisk()]
    print("== summary ==")
    print("   removed: %d   (magisk-shaped: %d)" % (len(removed), len(m_removed)))
    print("   added  : %d" % len(added))
    print("   changed: %d" % len(changed))
    if not args.quiet:
        print("")
        print("   A magisk-shaped removal count of 0 means one of three things, and this")
        print("   tool cannot distinguish them: the process is not on the DenyList; Magisk")
        print("   has no mounts to remove (no modules installed); or the process was forked")
        print("   before it was added to the list. Force-stop it, restart it, re-capture.")
        print("")
        print("   Nothing here speaks to properties, SELinux policy, loaded libraries or")
        print("   attestation. DenyList does not touch them, and neither does this tool.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
