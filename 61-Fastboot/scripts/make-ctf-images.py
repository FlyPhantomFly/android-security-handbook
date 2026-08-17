#!/usr/bin/env python3
# scripts/make-ctf-images.py
#
# PURPOSE
#   Generate the artefacts for lab 04, "The Bricked Vault" -- a CTF that runs
#   entirely on files. It produces a plausible-looking set of firmware images
#   with a four-stage flag hidden across them, each stage requiring one skill
#   the chapter teaches:
#
#     Stage 1  sparse image format          -> expand recovery.simg
#     Stage 2  the vbmeta flags field       -> read byte 123 of vbmeta.img
#     Stage 3  liblp 1 MiB extent alignment -> carve a partition out of super.img
#     Stage 4  the lock state machine       -> read a fastboot session log
#
#   Everything it writes is a FILE. Nothing here can be flashed to anything,
#   and none of the images is bootable or signed with any real key.
#
# USAGE
#   python3 -B scripts/make-ctf-images.py /tmp/ctf-vault
#   python3 -B scripts/make-ctf-images.py /tmp/ctf-vault --solve     # print the answers
#   python3 -B scripts/make-ctf-images.py --selftest                 # verify the generator
#
#   Run with `python3 -B` so no __pycache__ is written.
#
# FOR INSTRUCTORS
#   `--solve` prints every stage answer and the assembled flag. Run the
#   generator once without it, hand out the directory, and keep the solve
#   output. The artefacts are deterministic: the same output directory name
#   always yields the same bytes, so two students' images are identical and
#   answers are comparable.
#
# EXIT CODES
#   0 generated (or selftest passed)
#   1 usage error
#   2 selftest failed

import argparse
import hashlib
import os
import struct
import sys

# ---------------------------------------------------------------------------
# The flag
# ---------------------------------------------------------------------------

FLAG_PREFIX = "APN61"
STAGE_TOKENS = ["SPARSE", "BYTE123", "ALIGNED", "RELOCK"]
FULL_FLAG = "%s{%s}" % (FLAG_PREFIX, "_".join(STAGE_TOKENS))

# ---------------------------------------------------------------------------
# Stage 1 -- a sparse image whose expansion reveals the first token
# ---------------------------------------------------------------------------

SPARSE_MAGIC = 0xED26FF3A
CHUNK_RAW, CHUNK_FILL, CHUNK_DONT_CARE = 0xCAC1, 0xCAC2, 0xCAC3
BLK = 4096


def build_stage1(path):
    """A sparse image whose RAW chunk sits behind 128 blocks of FILL.

    The point: `strings` on the SPARSE file finds the token trivially, which is
    the wrong lesson. The intended solve EXPANDS it and finds the token at a
    specific OFFSET -- which is the number stage 3 needs. A solver who greps
    the sparse file gets the token and misses the offset.
    """
    note = (
        b"# recovery partition, salvaged\n"
        b"# stage 1 token: " + STAGE_TOKENS[0].encode() + b"\n"
        b"# the offset at which you found this line is the seed for stage 3.\n"
    )
    payload = note + b"\x00" * (BLK - len(note))
    assert len(payload) == BLK

    total_blocks = 128 + 1 + 64          # FILL, RAW, DONT_CARE
    header = struct.pack("<IHHHHIIII",
                         SPARSE_MAGIC, 1, 0, 28, 12, BLK, total_blocks, 3, 0)
    fill = struct.pack("<HHII", CHUNK_FILL, 0, 128, 12 + 4) + struct.pack("<I", 0)
    raw = struct.pack("<HHII", CHUNK_RAW, 0, 1, 12 + BLK) + payload
    dc = struct.pack("<HHII", CHUNK_DONT_CARE, 0, 64, 12)

    blob = header + fill + raw + dc
    with open(path, "wb") as f:
        f.write(blob)

    expanded_offset = 128 * BLK          # 524288
    return {"file": os.path.basename(path),
            "sparse_bytes": len(blob),
            "expanded_bytes": total_blocks * BLK,
            "token_offset_in_expanded": expanded_offset,
            "token": STAGE_TOKENS[0]}


# ---------------------------------------------------------------------------
# Stage 2 -- a vbmeta with the hashtree-disabled flag set
# ---------------------------------------------------------------------------

AVB_MAGIC = b"AVB0"
AVB_HEADER_LEN = 256
AVB_FLAGS_OFFSET = 120
FLAG_HASHTREE_DISABLED = 1 << 0


def build_stage2(path):
    """A structurally valid vbmeta with flags = 1 and a BROKEN integrity hash.

    The stored hash is the one for flags = 0. Setting the flag afterwards is
    exactly what `fastboot --disable-verity` does, and it leaves the image
    failing its own check. A solver who only reads the flag gets half the
    answer; the other half is noticing the MISMATCH and knowing what it implies
    about the bootloader that accepted this image.
    """
    aux = (b"stage2:" + STAGE_TOKENS[1].encode() + b";").ljust(512, b"\xA5")
    auth_size = 32 + 512

    header = bytearray(AVB_HEADER_LEN)
    header[0:4] = AVB_MAGIC
    struct.pack_into(">II", header, 4, 1, 0)
    struct.pack_into(">QQ", header, 12, auth_size, len(aux))
    struct.pack_into(">I", header, 28, 2)                 # SHA256_RSA4096
    struct.pack_into(">11Q", header, 32,
                     0, 32,          # hash offset / size
                     32, 512,        # signature offset / size
                     0, 0,           # public key offset / size
                     0, 0,           # public key metadata offset / size
                     0, len(aux),    # descriptors offset / size
                     11)             # rollback_index -- a red herring, see below
    struct.pack_into(">II", header, AVB_FLAGS_OFFSET, 0, 0)
    header[128:128 + 13] = b"avbtool 1.3.0"

    # Hash computed with flags = 0, exactly as a legitimate signer would.
    digest = hashlib.sha256(bytes(header) + aux).digest()
    auth = digest + (b"\x00" * 512)

    # NOW set the flag -- the post-signing edit. One byte.
    struct.pack_into(">I", header, AVB_FLAGS_OFFSET, FLAG_HASHTREE_DISABLED)

    with open(path, "wb") as f:
        f.write(bytes(header) + auth + aux)

    return {"file": os.path.basename(path),
            "flags": FLAG_HASHTREE_DISABLED,
            "changed_byte_offset": AVB_FLAGS_OFFSET + 3,
            "integrity": "MISMATCH (deliberate)",
            "rollback_index_red_herring": 11,
            "token": STAGE_TOKENS[1]}


# ---------------------------------------------------------------------------
# Stage 3 -- a super image with 1 MiB-aligned logical partitions
# ---------------------------------------------------------------------------

SECTOR = 512
ALIGN_SECTORS = 2048                     # 1 MiB


def build_stage3(path, seed_offset):
    """A 'super' container holding three logical partitions.

    A partition table is shipped alongside, in the SAME dm-table notation the
    chapter uses, giving lengths and offsets in 512-byte sectors. The solver
    must convert sectors to bytes and carve. The alignment is genuine: every
    partition starts on a 2048-sector boundary, with gaps between them.

    The trap: the accompanying table lists offsets that are correct, but a
    solver who assumes the partitions are contiguous (offset = sum of previous
    lengths) lands in the gaps and extracts padding.
    """
    parts = [
        ("system_ext", 2048, 512),        # start sector, length in sectors
        ("vendor", 2048 + 2048, 256),
        ("vault", 2048 + 2048 + 2048, 1024),
    ]

    total_sectors = 2048 * 5
    img = bytearray(b"\xEE" * (total_sectors * SECTOR))   # 0xEE = "not a partition"

    for name, start, length in parts:
        off = start * SECTOR
        size = length * SECTOR
        if name == "vault":
            body = (b"stage3:" + STAGE_TOKENS[2].encode() + b";\n" +
                    b"seed=" + str(seed_offset).encode() + b"\n" +
                    b"# every logical partition starts on a 1 MiB boundary.\n")
            body = body.ljust(size, b"\x00")
        else:
            body = (("[%s]\n" % name).encode() +
                    b"# nothing here. check the alignment, not the order.\n"
                    ).ljust(size, b"\x11")
        img[off:off + size] = body[:size]

    with open(path, "wb") as f:
        f.write(bytes(img))

    table_path = os.path.join(os.path.dirname(path), "super-dm-table.txt")
    with open(table_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("# `dmctl table <name>` output, salvaged from the device.\n")
        f.write("# format:  0-LENGTH: linear, MAJOR:MINOR START\n")
        f.write("# both numbers are in 512-byte sectors.\n\n")
        for name, start, length in parts:
            f.write("%-12s 0-%d: linear, 253:2 %d\n" % (name, length, start))

    return {"file": os.path.basename(path),
            "table": os.path.basename(table_path),
            "vault_start_sector": parts[2][1],
            "vault_offset_bytes": parts[2][1] * SECTOR,
            "vault_length_bytes": parts[2][2] * SECTOR,
            "token": STAGE_TOKENS[2]}


# ---------------------------------------------------------------------------
# Stage 4 -- the session log with the fatal command in it
# ---------------------------------------------------------------------------

SESSION_LOG = """\
# fastboot-session.log
# Recovered from a technician's terminal. The device has not booted since.
# Timestamps are relative. Host output only; device screen not recorded.

[00:00:04] $ fastboot devices
[00:00:04] 1A2B3C4D5E6F   fastboot

[00:00:11] $ fastboot getvar unlocked
[00:00:11] unlocked: yes
[00:00:11] Finished. Total time: 0.004s

[00:00:19] $ fastboot getvar current-slot
[00:00:19] current-slot: a

[00:00:26] $ fastboot getvar snapshot-update-status
[00:00:26] snapshot-update-status: none

[00:01:02] $ fastboot flash boot_a magisk_patched-27000_aBcDe.img
[00:01:02] Sending 'boot_a' (33554432 KB)
[00:01:09] Writing 'boot_a'
[00:01:11] OKAY [  2.104s]
[00:01:11] Finished. Total time: 9.331s

[00:01:40] $ fastboot --disable-verity flash vbmeta vbmeta.img
[00:01:40] Rewriting vbmeta struct at offset: 0
[00:01:41] Sending 'vbmeta' (7 KB)
[00:01:41] Writing 'vbmeta'
[00:01:41] OKAY [  0.101s]

[00:02:15] $ fastboot reboot
[00:02:15] Rebooting
[00:02:15] Finished. Total time: 0.052s

[00:04:50] # device booted. root confirmed. work completed.
[00:04:50] # customer asked for the device to be "put back to normal".

[00:31:02] $ adb reboot bootloader

[00:31:20] $ fastboot flashing lock
[00:31:20] < waiting for device >
[00:31:24] OKAY [  4.002s]
[00:31:24] Finished. Total time: 4.114s

[00:31:29] $ fastboot reboot
[00:31:29] Rebooting

[00:33:00] # device shows: "Your device is corrupt. It can't be trusted
[00:33:00] #                and will not boot."
[00:33:00] # power cycle -> same screen.
[00:33:00] # volume-down+power -> fastboot mode reachable.

[00:35:11] $ fastboot getvar unlocked
[00:35:11] unlocked: no

[00:35:40] $ fastboot flashing unlock
[00:35:40] FAILED (remote: 'oem unlock is not allowed')

[00:36:02] $ fastboot flash boot_a stock_boot.img
[00:36:02] FAILED (remote: 'Device is locked. Cannot flash images')

[00:37:15] # stuck.

# ---------------------------------------------------------------------------
# stage 4 answer format: the single command that made this unrecoverable,
# by its timestamp. Then read the note below.
#
# stage 4 token, revealed once you can name that command without looking:
#   the verb of that command, upper-cased.
# ---------------------------------------------------------------------------
"""


def build_stage4(path):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(SESSION_LOG)
    return {"file": os.path.basename(path),
            "fatal_command_timestamp": "00:31:20",
            "fatal_command": "fastboot flashing lock",
            "token": STAGE_TOKENS[3]}


# ---------------------------------------------------------------------------
# The briefing handed to the solver
# ---------------------------------------------------------------------------

BRIEF = """\
THE BRICKED VAULT
=================

A repair shop sends you a bag of files and a dead phone.

The technician rooted the device for a customer, then tried to "put it back to
normal" and produced a phone that shows "Your device is corrupt" and will not
boot. Before it died, they salvaged four artefacts off their workstation. The
customer's recovery passphrase was stored on the device and is gone -- but the
technician swears fragments of it are recoverable from these files.

Your job: recover the flag.

    APN61{PART1_PART2_PART3_PART4}

FILES
-----
  recovery.simg          a partition image, salvaged
  vbmeta.img             pulled off the device before the last reboot
  super.img              a container, partially readable
  super-dm-table.txt     `dmctl table` output for the above
  fastboot-session.log   the technician's terminal history

RULES
-----
  Everything is offline. Do not connect a device. Do not flash anything.
  Nothing in this directory is bootable, signed, or dangerous.

  You need: python3, and the chapter's scripts/ directory.

WHAT EACH PART IS
-----------------
  PART1  a token stored inside a partition image. Getting the token is easy.
         Getting the OFFSET you found it at is the part stage 3 needs.
  PART2  a token, plus a byte offset you must be able to name. One field in
         one image tells you what the technician did AND why it was
         recoverable right up until it wasn't.
  PART3  a token inside a container. The table tells you where. Read it in the
         right units, and do not assume the partitions are packed end to end.
  PART4  not stored anywhere. It is the verb of the one command in the session
         log that turned a recoverable situation into an unrecoverable one.

  Tokens are upper-case. Join them with underscores in order.
"""


def write_brief(outdir):
    p = os.path.join(outdir, "BRIEFING.txt")
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(BRIEF)
    return p


# ---------------------------------------------------------------------------

def generate(outdir):
    os.makedirs(outdir, exist_ok=True)
    s1 = build_stage1(os.path.join(outdir, "recovery.simg"))
    s2 = build_stage2(os.path.join(outdir, "vbmeta.img"))
    s3 = build_stage3(os.path.join(outdir, "super.img"),
                      s1["token_offset_in_expanded"])
    s4 = build_stage4(os.path.join(outdir, "fastboot-session.log"))
    write_brief(outdir)
    return [s1, s2, s3, s4]


def cmd_generate(args):
    stages = generate(args.outdir)
    print("wrote CTF artefacts to %s" % args.outdir)
    for name in sorted(os.listdir(args.outdir)):
        p = os.path.join(args.outdir, name)
        print("  %-24s %8d bytes" % (name, os.path.getsize(p)))
    if args.solve:
        print()
        print("=========== SOLUTION -- instructors only ===========")
        for i, s in enumerate(stages, 1):
            print("stage %d:" % i)
            for k, v in s.items():
                print("    %-28s %s" % (k, v))
        print()
        print("FLAG: %s" % FULL_FLAG)
        print("===================================================")
    else:
        print()
        print("Read BRIEFING.txt. Solve with labs/lab-04-ctf-bricked-vault.md.")
    return 0


# ---------------------------------------------------------------------------
# Self-test: generate into a scratch directory and SOLVE it programmatically,
# so the challenge is proven solvable rather than assumed to be.
# ---------------------------------------------------------------------------

def cmd_selftest(_args):
    import tempfile
    failures = []

    def check(name, cond, detail=""):
        if cond:
            print("  PASS  %s" % name)
        else:
            print("  FAIL  %s   %s" % (name, detail))
            failures.append(name)

    tmp = tempfile.mkdtemp(prefix="ctf-selftest-")
    stages = generate(tmp)
    print("generated into %s" % tmp)

    print("stage 1 -- expand the sparse image and find the token")
    blob = open(os.path.join(tmp, "recovery.simg"), "rb").read()
    magic, = struct.unpack("<I", blob[:4])
    check("sparse magic", magic == SPARSE_MAGIC)
    (_m, _M, _mi, fh, ch, blk, tb, tc, _cs) = struct.unpack("<IHHHHIIII", blob[:28])
    out = bytearray()
    off = fh
    for _ in range(tc):
        ctype, _r, csz, tsz = struct.unpack("<HHII", blob[off:off + ch])
        body = blob[off + ch:off + tsz]
        if ctype == CHUNK_RAW:
            out += body
        elif ctype == CHUNK_FILL:
            out += body * (csz * blk // 4)
        elif ctype == CHUNK_DONT_CARE:
            out += b"\x00" * (csz * blk)
        off += tsz
    check("expanded length", len(out) == tb * blk,
          "%d vs %d" % (len(out), tb * blk))
    idx = bytes(out).find(STAGE_TOKENS[0].encode())
    check("token 1 found in the expansion", idx != -1)
    found_off = (idx // blk) * blk
    check("token sits at the documented offset",
          found_off == stages[0]["token_offset_in_expanded"],
          "%d vs %d" % (found_off, stages[0]["token_offset_in_expanded"]))

    print("stage 2 -- read the flags field and the broken hash")
    vb = open(os.path.join(tmp, "vbmeta.img"), "rb").read()
    check("vbmeta magic", vb[:4] == AVB_MAGIC)
    flags, = struct.unpack(">I", vb[AVB_FLAGS_OFFSET:AVB_FLAGS_OFFSET + 4])
    check("hashtree-disabled flag is set", bool(flags & FLAG_HASHTREE_DISABLED))
    auth_sz, aux_sz = struct.unpack(">QQ", vb[12:28])
    stored = vb[256:288]
    calc = hashlib.sha256(vb[:256] + vb[256 + auth_sz:256 + auth_sz + aux_sz]).digest()
    check("integrity hash MISMATCHES, as designed", stored != calc)
    # And confirm the intended story: clearing the flag restores the hash.
    fixed = bytearray(vb)
    struct.pack_into(">I", fixed, AVB_FLAGS_OFFSET, 0)
    calc2 = hashlib.sha256(bytes(fixed[:256]) +
                           vb[256 + auth_sz:256 + auth_sz + aux_sz]).digest()
    check("clearing byte 123 makes the hash valid again", calc2 == stored)
    check("token 2 present in the aux block",
          STAGE_TOKENS[1].encode() in vb)

    print("stage 3 -- carve the vault partition using the table")
    sup = open(os.path.join(tmp, "super.img"), "rb").read()
    table = open(os.path.join(tmp, "super-dm-table.txt"), encoding="utf-8").read()
    row = [ln for ln in table.splitlines() if ln.startswith("vault")][0]
    length_sectors = int(row.split("0-")[1].split(":")[0])
    start_sectors = int(row.strip().split()[-1])
    carved = sup[start_sectors * SECTOR:
                 start_sectors * SECTOR + length_sectors * SECTOR]
    check("carved region contains token 3", STAGE_TOKENS[2].encode() in carved)
    check("start offset is 1 MiB aligned", (start_sectors % ALIGN_SECTORS) == 0,
          str(start_sectors))
    # The trap: a solver assuming contiguous packing lands in a gap.
    naive = (512 + 256) * SECTOR
    check("naive contiguous assumption FAILS (the trap works)",
          STAGE_TOKENS[2].encode() not in sup[naive:naive + length_sectors * SECTOR])

    print("stage 4 -- the fatal command is present and identifiable")
    log = open(os.path.join(tmp, "fastboot-session.log"), encoding="utf-8").read()
    check("the fatal command is in the log", "fastboot flashing lock" in log)
    check("the failed recovery attempt is in the log",
          "oem unlock is not allowed" in log)
    check("the corrupt-device symptom is in the log",
          "Your device is corrupt" in log)
    check("token 4 is NOT stored anywhere in the artefacts",
          all(STAGE_TOKENS[3].encode() not in open(os.path.join(tmp, f), "rb").read()
              for f in os.listdir(tmp) if f != "BRIEFING.txt"))

    print("assembly")
    check("flag assembles correctly",
          FULL_FLAG == "APN61{SPARSE_BYTE123_ALIGNED_RELOCK}", FULL_FLAG)

    # Clean up so the selftest leaves nothing behind.
    for f in os.listdir(tmp):
        os.remove(os.path.join(tmp, f))
    os.rmdir(tmp)
    print("scratch directory removed")

    print()
    if failures:
        print("%d FAILURE(S): %s" % (len(failures), ", ".join(failures)))
        return 2
    print("all self-tests passed -- the challenge is solvable as designed")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Generate the lab 04 CTF artefacts (chapter 61 -- Fastboot). "
                    "Writes files only; nothing here touches a device.")
    ap.add_argument("outdir", nargs="?", help="directory to write artefacts into")
    ap.add_argument("--solve", action="store_true",
                    help="also print the answers (instructors)")
    ap.add_argument("--selftest", action="store_true",
                    help="generate and programmatically solve, then clean up")
    args = ap.parse_args(argv)

    if args.selftest:
        return cmd_selftest(args)
    if not args.outdir:
        ap.print_help()
        return 1
    return cmd_generate(args)


if __name__ == "__main__":
    sys.exit(main())
