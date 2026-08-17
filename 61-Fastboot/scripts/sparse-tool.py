#!/usr/bin/env python3
# scripts/sparse-tool.py
#
# PURPOSE
#   A complete, dependency-free implementation of the Android sparse image format
#   -- the format `fastboot` uses to push multi-gigabyte partition images through a
#   bootloader download buffer of a few hundred megabytes.
#
#   It does four things:
#     info    -- describe a sparse image's header and every chunk
#     verify  -- check the image for the malformed-input classes a privileged
#                parser must reject (see chapter 61 section 5.4, class 4)
#     expand  -- turn a sparse image back into the raw image it describes
#     create  -- turn a raw image into a sparse image
#
#   The format is defined in AOSP at
#     system/core/libsparse/include/sparse/sparse_format.h
#   All fields are LITTLE-endian (unlike AVB's vbmeta, which is big-endian -- a
#   trap worth remembering if you write both parsers in one sitting).
#
# USAGE
#   python3 -B scripts/sparse-tool.py info    IMAGE.simg
#   python3 -B scripts/sparse-tool.py verify  IMAGE.simg
#   python3 -B scripts/sparse-tool.py expand  IMAGE.simg OUT.img
#   python3 -B scripts/sparse-tool.py create  IN.img OUT.simg [--block-size 4096]
#   python3 -B scripts/sparse-tool.py selftest
#
#   Run with `python3 -B` so no __pycache__ is written into the repository.
#
# SAFETY
#   This script never talks to a device. It reads and writes files only. Nothing
#   here can brick anything.
#
# EXIT CODES
#   0 success / image valid
#   1 usage error
#   2 image is malformed (verify), or a selftest case failed

import argparse
import struct
import sys

SPARSE_MAGIC = 0xED26FF3A

CHUNK_RAW = 0xCAC1
CHUNK_FILL = 0xCAC2
CHUNK_DONT_CARE = 0xCAC3
CHUNK_CRC32 = 0xCAC4

CHUNK_NAMES = {
    CHUNK_RAW: "RAW",
    CHUNK_FILL: "FILL",
    CHUNK_DONT_CARE: "DONT_CARE",
    CHUNK_CRC32: "CRC32",
}

FILE_HDR_FMT = "<IHHHHIIII"   # magic, maj, min, file_hdr_sz, chunk_hdr_sz,
                              # blk_sz, total_blks, total_chunks, image_checksum
FILE_HDR_LEN = struct.calcsize(FILE_HDR_FMT)          # 28
CHUNK_HDR_FMT = "<HHII"       # chunk_type, reserved, chunk_sz, total_sz
CHUNK_HDR_LEN = struct.calcsize(CHUNK_HDR_FMT)        # 12

# A single chunk describing more than this many blocks is treated as hostile
# rather than merely large. 2^32 blocks at 4 KiB is 16 TiB; no real partition
# comes close, and accepting it is how an integer overflow gets reached.
SANE_MAX_BLOCKS = 1 << 32


class SparseError(Exception):
    """Raised for any structurally invalid sparse image."""


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class SparseHeader(object):
    def __init__(self, blob):
        if len(blob) < FILE_HDR_LEN:
            raise SparseError(
                "file is %d bytes; a sparse header is %d" % (len(blob), FILE_HDR_LEN))
        fields = struct.unpack(FILE_HDR_FMT, blob[:FILE_HDR_LEN])
        (self.magic, self.major, self.minor, self.file_hdr_sz,
         self.chunk_hdr_sz, self.blk_sz, self.total_blks,
         self.total_chunks, self.image_checksum) = fields

        if self.magic != SPARSE_MAGIC:
            raise SparseError(
                "bad magic 0x%08x (expected 0x%08x) -- is this a raw image?"
                % (self.magic, SPARSE_MAGIC))

    def describe(self):
        return "\n".join([
            "magic           0x%08x" % self.magic,
            "version         %d.%d" % (self.major, self.minor),
            "file_hdr_sz     %d" % self.file_hdr_sz,
            "chunk_hdr_sz    %d" % self.chunk_hdr_sz,
            "blk_sz          %d" % self.blk_sz,
            "total_blks      %d  (expanded size %d bytes)"
            % (self.total_blks, self.total_blks * self.blk_sz),
            "total_chunks    %d" % self.total_chunks,
            "image_checksum  0x%08x%s"
            % (self.image_checksum, "  (0 = not computed)"
               if self.image_checksum == 0 else ""),
        ])


class Chunk(object):
    def __init__(self, index, offset, chunk_type, chunk_sz, total_sz, body):
        self.index = index
        self.offset = offset
        self.chunk_type = chunk_type
        self.chunk_sz = chunk_sz        # size in BLOCKS of the expanded output
        self.total_sz = total_sz        # size in BYTES of this chunk on disk
        self.body = body                # payload bytes (may be empty)

    @property
    def name(self):
        return CHUNK_NAMES.get(self.chunk_type, "UNKNOWN(0x%04x)" % self.chunk_type)


def parse(blob, strict=True):
    """Parse a sparse image. Returns (SparseHeader, [Chunk]).

    strict=True applies every validity check. strict=False parses as far as it
    can, which is what `info` wants when you are looking at a damaged image.
    """
    hdr = SparseHeader(blob)

    if hdr.file_hdr_sz < FILE_HDR_LEN:
        raise SparseError(
            "file_hdr_sz %d is smaller than the defined header (%d)"
            % (hdr.file_hdr_sz, FILE_HDR_LEN))
    if hdr.chunk_hdr_sz < CHUNK_HDR_LEN:
        raise SparseError(
            "chunk_hdr_sz %d is smaller than the defined chunk header (%d)"
            % (hdr.chunk_hdr_sz, CHUNK_HDR_LEN))
    if hdr.blk_sz == 0 or hdr.blk_sz % 4 != 0:
        raise SparseError(
            "blk_sz %d must be non-zero and a multiple of 4" % hdr.blk_sz)

    chunks = []
    off = hdr.file_hdr_sz
    blocks_seen = 0

    for i in range(hdr.total_chunks):
        if off + CHUNK_HDR_LEN > len(blob):
            raise SparseError(
                "chunk %d header runs past end of file (offset %d, file %d bytes)"
                % (i, off, len(blob)))

        ctype, _reserved, csz, tsz = struct.unpack(
            CHUNK_HDR_FMT, blob[off:off + CHUNK_HDR_LEN])

        if tsz < hdr.chunk_hdr_sz:
            raise SparseError(
                "chunk %d: total_sz %d is smaller than chunk_hdr_sz %d"
                % (i, tsz, hdr.chunk_hdr_sz))
        if off + tsz > len(blob):
            raise SparseError(
                "chunk %d: total_sz %d runs past end of file "
                "(offset %d + %d > %d)" % (i, tsz, off, tsz, len(blob)))
        if csz > SANE_MAX_BLOCKS:
            raise SparseError("chunk %d: chunk_sz %d is implausible" % (i, csz))

        body = blob[off + hdr.chunk_hdr_sz:off + tsz]
        payload_len = tsz - hdr.chunk_hdr_sz

        if ctype == CHUNK_RAW:
            expected = csz * hdr.blk_sz
            if strict and payload_len != expected:
                raise SparseError(
                    "chunk %d RAW: payload is %d bytes, but chunk_sz %d blocks "
                    "of %d bytes needs %d" % (i, payload_len, csz, hdr.blk_sz, expected))
        elif ctype == CHUNK_FILL:
            if strict and payload_len != 4:
                raise SparseError(
                    "chunk %d FILL: payload is %d bytes, must be exactly 4"
                    % (i, payload_len))
        elif ctype == CHUNK_DONT_CARE:
            if strict and payload_len != 0:
                raise SparseError(
                    "chunk %d DONT_CARE: payload is %d bytes, must be 0"
                    % (i, payload_len))
        elif ctype == CHUNK_CRC32:
            if strict and payload_len != 4:
                raise SparseError(
                    "chunk %d CRC32: payload is %d bytes, must be exactly 4"
                    % (i, payload_len))
        else:
            raise SparseError(
                "chunk %d: unknown chunk_type 0x%04x" % (i, ctype))

        if ctype != CHUNK_CRC32:
            blocks_seen += csz
            if blocks_seen > SANE_MAX_BLOCKS:
                raise SparseError(
                    "cumulative block count overflowed at chunk %d" % i)

        chunks.append(Chunk(i, off, ctype, csz, tsz, body))
        off += tsz

    if strict and blocks_seen != hdr.total_blks:
        raise SparseError(
            "chunks describe %d blocks but the header says total_blks = %d"
            % (blocks_seen, hdr.total_blks))
    if strict and off != len(blob):
        raise SparseError(
            "%d trailing bytes after the last chunk" % (len(blob) - off))

    return hdr, chunks


def expand(hdr, chunks):
    """Return the raw image the sparse image describes, as bytes."""
    out = bytearray()
    for c in chunks:
        if c.chunk_type == CHUNK_RAW:
            out += c.body
        elif c.chunk_type == CHUNK_FILL:
            out += c.body * (c.chunk_sz * hdr.blk_sz // 4)
        elif c.chunk_type == CHUNK_DONT_CARE:
            # "I decline to describe this range." The DEVICE may legitimately
            # skip it, leaving whatever was on flash before. When we expand to a
            # file we have to write something, and zeros are the conventional
            # choice -- but see the warning in chapter 61 section 3.5: this is
            # exactly where an expanded image and the real post-flash partition
            # can differ.
            out += b"\x00" * (c.chunk_sz * hdr.blk_sz)
        elif c.chunk_type == CHUNK_CRC32:
            pass
    return bytes(out)


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------


def create(raw, blk_sz=4096):
    """Turn a raw image into a sparse image.

    The algorithm is the obvious one and matches libsparse's behaviour closely
    enough to be instructive: walk the image a block at a time, emit a FILL
    chunk for any run of blocks that consist of one repeated 4-byte pattern,
    and a RAW chunk for everything else. Adjacent chunks of the same kind are
    merged.
    """
    if blk_sz <= 0 or blk_sz % 4 != 0:
        raise SparseError("block size must be positive and a multiple of 4")
    if len(raw) % blk_sz != 0:
        pad = blk_sz - (len(raw) % blk_sz)
        raw = raw + b"\x00" * pad

    nblocks = len(raw) // blk_sz

    def fill_pattern(block):
        pat = block[:4]
        return pat if block == pat * (blk_sz // 4) else None

    # Classify every block, then run-length encode the classification.
    runs = []   # list of (kind, pattern_or_None, start_block, count)
    i = 0
    while i < nblocks:
        block = raw[i * blk_sz:(i + 1) * blk_sz]
        pat = fill_pattern(block)
        if pat is not None:
            j = i + 1
            while j < nblocks:
                nxt = raw[j * blk_sz:(j + 1) * blk_sz]
                if fill_pattern(nxt) != pat:
                    break
                j += 1
            runs.append(("FILL", pat, i, j - i))
            i = j
        else:
            j = i + 1
            while j < nblocks:
                nxt = raw[j * blk_sz:(j + 1) * blk_sz]
                if fill_pattern(nxt) is not None:
                    break
                j += 1
            runs.append(("RAW", None, i, j - i))
            i = j

    body = bytearray()
    for kind, pat, start, count in runs:
        if kind == "FILL":
            body += struct.pack(CHUNK_HDR_FMT, CHUNK_FILL, 0, count,
                                CHUNK_HDR_LEN + 4)
            body += pat
        else:
            payload = raw[start * blk_sz:(start + count) * blk_sz]
            body += struct.pack(CHUNK_HDR_FMT, CHUNK_RAW, 0, count,
                                CHUNK_HDR_LEN + len(payload))
            body += payload

    header = struct.pack(FILE_HDR_FMT, SPARSE_MAGIC, 1, 0,
                         FILE_HDR_LEN, CHUNK_HDR_LEN,
                         blk_sz, nblocks, len(runs), 0)
    return header + bytes(body)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_info(args):
    blob = open(args.image, "rb").read()
    try:
        hdr, chunks = parse(blob, strict=False)
    except SparseError as exc:
        print("MALFORMED: %s" % exc, file=sys.stderr)
        return 2

    print(hdr.describe())
    print()
    print("%-5s %-10s %-12s %12s %12s  %s"
          % ("idx", "type", "offset", "blocks", "on-disk", "note"))
    on_disk = FILE_HDR_LEN
    expanded = 0
    for c in chunks:
        note = ""
        if c.chunk_type == CHUNK_FILL:
            note = "pattern %s" % c.body.hex()
        elif c.chunk_type == CHUNK_DONT_CARE:
            note = "skipped by the device -- old contents survive"
        elif c.chunk_type == CHUNK_CRC32:
            note = "running checksum"
        print("%-5d %-10s %-12d %12d %12d  %s"
              % (c.index, c.name, c.offset, c.chunk_sz, c.total_sz, note))
        on_disk += c.total_sz
        if c.chunk_type != CHUNK_CRC32:
            expanded += c.chunk_sz * hdr.blk_sz

    print()
    print("on disk         %d bytes" % len(blob))
    print("expands to      %d bytes" % expanded)
    if expanded and len(blob):
        print("ratio           %.1f : 1" % (expanded / float(len(blob))))
    return 0


def cmd_verify(args):
    blob = open(args.image, "rb").read()
    try:
        hdr, chunks = parse(blob, strict=True)
    except SparseError as exc:
        print("INVALID: %s" % exc)
        return 2

    counts = {}
    for c in chunks:
        counts[c.name] = counts.get(c.name, 0) + 1
    print("VALID")
    print("  block size    %d" % hdr.blk_sz)
    print("  expands to    %d bytes" % (hdr.total_blks * hdr.blk_sz))
    print("  chunks        %s"
          % ", ".join("%s=%d" % (k, v) for k, v in sorted(counts.items())))
    return 0


def cmd_expand(args):
    blob = open(args.image, "rb").read()
    hdr, chunks = parse(blob, strict=True)
    raw = expand(hdr, chunks)
    open(args.output, "wb").write(raw)
    print("wrote %s: %d bytes (from %d bytes sparse)"
          % (args.output, len(raw), len(blob)))
    return 0


def cmd_create(args):
    raw = open(args.image, "rb").read()
    simg = create(raw, args.block_size)
    open(args.output, "wb").write(simg)
    ratio = (len(raw) / float(len(simg))) if simg else 0.0
    print("wrote %s: %d bytes sparse (from %d bytes raw, ratio %.1f : 1)"
          % (args.output, len(simg), len(raw), ratio))
    return 0


# ---------------------------------------------------------------------------
# Self-test -- runs without any input file, so the script is verifiable anywhere
# ---------------------------------------------------------------------------


def cmd_selftest(_args):
    failures = []

    def check(name, condition, detail=""):
        if condition:
            print("  PASS  %s" % name)
        else:
            print("  FAIL  %s   %s" % (name, detail))
            failures.append(name)

    print("round trip")
    blk = 4096
    raw = (b"FASTBOOT" * (blk // 8)) + (b"\x00" * blk * 255)
    simg = create(raw, blk)
    hdr, chunks = parse(simg, strict=True)
    back = expand(hdr, chunks)
    check("create/parse/expand is byte-identical", back == raw,
          "%d vs %d bytes" % (len(back), len(raw)))
    check("256 blocks became %d chunks" % len(chunks), len(chunks) == 2)
    check("sparse is much smaller than raw", len(simg) < len(raw) // 100,
          "%d vs %d" % (len(simg), len(raw)))

    print("fill detection")
    raw2 = b"\xde\xad\xbe\xef" * (blk // 4) * 64
    simg2 = create(raw2, blk)
    hdr2, chunks2 = parse(simg2, strict=True)
    check("a 256 KiB repeated pattern is one FILL chunk",
          len(chunks2) == 1 and chunks2[0].chunk_type == CHUNK_FILL)
    check("that FILL expands correctly", expand(hdr2, chunks2) == raw2)

    print("malformed input is rejected")

    def expect_reject(name, mutate):
        good = create(b"\x00" * blk * 4, blk)
        bad = bytearray(good)
        mutate(bad)
        try:
            parse(bytes(bad), strict=True)
        except SparseError:
            print("  PASS  %s" % name)
            return
        print("  FAIL  %s   (accepted a malformed image)" % name)
        failures.append(name)

    expect_reject("bad magic",
                  lambda b: b.__setitem__(slice(0, 4), b"\x00\x00\x00\x00"))
    expect_reject("blk_sz = 0",
                  lambda b: b.__setitem__(slice(12, 16), struct.pack("<I", 0)))
    expect_reject("total_blks disagrees with the chunks",
                  lambda b: b.__setitem__(slice(16, 20), struct.pack("<I", 999)))
    expect_reject("chunk total_sz runs past end of file",
                  lambda b: b.__setitem__(slice(FILE_HDR_LEN + 8,
                                                FILE_HDR_LEN + 12),
                                          struct.pack("<I", 0x7FFFFFFF)))
    expect_reject("chunk total_sz smaller than the chunk header",
                  lambda b: b.__setitem__(slice(FILE_HDR_LEN + 8,
                                                FILE_HDR_LEN + 12),
                                          struct.pack("<I", 3)))
    expect_reject("unknown chunk type",
                  lambda b: b.__setitem__(slice(FILE_HDR_LEN,
                                                FILE_HDR_LEN + 2),
                                          struct.pack("<H", 0xDEAD)))
    expect_reject("chunk_hdr_sz below the defined size",
                  lambda b: b.__setitem__(slice(10, 12), struct.pack("<H", 2)))

    print("DONT_CARE handling")
    hdrbytes = struct.pack(FILE_HDR_FMT, SPARSE_MAGIC, 1, 0,
                           FILE_HDR_LEN, CHUNK_HDR_LEN, blk, 8, 2, 0)
    dc = struct.pack(CHUNK_HDR_FMT, CHUNK_DONT_CARE, 0, 4, CHUNK_HDR_LEN)
    rawc = struct.pack(CHUNK_HDR_FMT, CHUNK_RAW, 0, 4,
                       CHUNK_HDR_LEN + 4 * blk) + (b"A" * blk * 4)
    img = hdrbytes + dc + rawc
    h3, c3 = parse(img, strict=True)
    out = expand(h3, c3)
    check("DONT_CARE costs 0 payload bytes on disk",
          c3[0].total_sz == CHUNK_HDR_LEN)
    check("DONT_CARE expands to the right length",
          len(out) == 8 * blk and out[:4 * blk] == b"\x00" * (4 * blk))

    print()
    if failures:
        print("%d FAILURE(S): %s" % (len(failures), ", ".join(failures)))
        return 2
    print("all self-tests passed")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Android sparse image tool (chapter 61 -- Fastboot). "
                    "Reads and writes files only; never touches a device.")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("info", help="describe a sparse image")
    p.add_argument("image")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("verify", help="strict validity check")
    p.add_argument("image")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("expand", help="sparse image -> raw image")
    p.add_argument("image")
    p.add_argument("output")
    p.set_defaults(func=cmd_expand)

    p = sub.add_parser("create", help="raw image -> sparse image")
    p.add_argument("image")
    p.add_argument("output")
    p.add_argument("--block-size", type=int, default=4096)
    p.set_defaults(func=cmd_create)

    p = sub.add_parser("selftest", help="run the built-in test suite")
    p.set_defaults(func=cmd_selftest)

    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 1
    try:
        return args.func(args)
    except SparseError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
