#!/usr/bin/env python3
# scripts/parse-vbmeta.py
#
# PURPOSE
#   Parse an Android Verified Boot 2.0 `vbmeta` image and print every field and
#   descriptor it contains -- header, algorithm, rollback index, flags, and each
#   hash / hashtree / chain-partition / kernel-cmdline / property descriptor.
#
#   This exists so that Lab 02 can be done with NO NETWORK ACCESS and NO AOSP
#   CHECKOUT. `avbtool` is the canonical tool and you should use it when you
#   can, but it lives in an AOSP git repository, and a lab that begins with
#   "git clone from googlesource" is a lab that half its readers cannot start.
#
#   There is a second, better reason. avbtool prints an answer; this prints the
#   answer AND the byte offsets it came from. The whole point of Lab 02 is that
#   vbmeta stops being mysterious once you have seen that it is a 256-byte
#   big-endian header followed by a packed list of tagged records. You cannot
#   learn that from a tool that hides the layout.
#
# USAGE
#   # host -- parse an image file
#   python3 -B parse-vbmeta.py vbmeta.img
#
#   # host -- also print the raw header bytes with field boundaries marked
#   python3 -B parse-vbmeta.py --hex vbmeta.img
#
#   # host -- machine-readable, for diffing two devices or two firmware builds
#   python3 -B parse-vbmeta.py --json vbmeta.img
#
#   # host -- pull one off a device you own and parse it (root required to read
#   #         the block device; the read is non-destructive)
#   adb shell "su -c 'dd if=/dev/block/by-name/vbmeta of=/data/local/tmp/vbmeta.img'"
#   adb pull /data/local/tmp/vbmeta.img
#   adb shell "su -c 'rm -f /data/local/tmp/vbmeta.img'"
#   python3 -B parse-vbmeta.py vbmeta.img
#
# REQUIREMENTS
#   Python 3.7+. Standard library only -- no cryptography package, no avbtool.
#
# WHAT THIS DOES NOT DO, AND WHY THAT MATTERS
#   It does NOT verify the signature. It parses and prints; it does not tell you
#   the image is authentic. Verifying would require the RSA public modulus from
#   the auxiliary block, a PKCS#1 v1.5 implementation, and -- critically -- the
#   OEM's *expected* key, which is fused into the device, not stored in the
#   image. An image is self-consistent by construction; self-consistency proves
#   nothing. That gap IS the lesson of Lab 02 Step 8, so the script is silent
#   about authenticity rather than implying it.
#
#   It also does not chase chain-partition descriptors automatically. When it
#   finds one it tells you which partition to parse next and you run it again.
#   Following the chain by hand is how you learn that the chain exists.
#
# AUTHORISED USE ONLY. Read images from devices you own.

import argparse
import binascii
import hashlib
import json
import struct
import sys

MAGIC = b"AVB0"
HEADER_SIZE = 256

# From external/avb/libavb/avb_vbmeta_image.h. The comment beside each entry is
# the field's byte offset inside the 256-byte header, which is what you want
# when you are staring at a hexdump.
HEADER_FIELDS = [
    ("magic", "4s"),                              # 0x00
    ("required_libavb_version_major", "I"),       # 0x04
    ("required_libavb_version_minor", "I"),       # 0x08
    ("authentication_data_block_size", "Q"),      # 0x0c
    ("auxiliary_data_block_size", "Q"),           # 0x14
    ("algorithm_type", "I"),                      # 0x1c
    ("hash_offset", "Q"),                         # 0x20
    ("hash_size", "Q"),                           # 0x28
    ("signature_offset", "Q"),                    # 0x30
    ("signature_size", "Q"),                      # 0x38
    ("public_key_offset", "Q"),                   # 0x40
    ("public_key_size", "Q"),                      # 0x48
    ("public_key_metadata_offset", "Q"),          # 0x50
    ("public_key_metadata_size", "Q"),            # 0x58
    ("descriptors_offset", "Q"),                  # 0x60
    ("descriptors_size", "Q"),                    # 0x68
    ("rollback_index", "Q"),                      # 0x70
    ("flags", "I"),                               # 0x78
    ("rollback_index_location", "I"),             # 0x7c
    ("release_string", "48s"),                    # 0x80
]

# AvbAlgorithmType. The number in the header is an index into this table, not a
# bit field -- there is exactly one algorithm per vbmeta.
ALGORITHMS = {
    0: ("NONE", "unsigned -- see the warning this script prints"),
    1: ("SHA256_RSA2048", "SHA-256 digest, RSA-2048 PKCS#1 v1.5 signature"),
    2: ("SHA256_RSA4096", "SHA-256 digest, RSA-4096 PKCS#1 v1.5 signature"),
    3: ("SHA256_RSA8192", "SHA-256 digest, RSA-8192 PKCS#1 v1.5 signature"),
    4: ("SHA512_RSA2048", "SHA-512 digest, RSA-2048 PKCS#1 v1.5 signature"),
    5: ("SHA512_RSA4096", "SHA-512 digest, RSA-4096 PKCS#1 v1.5 signature"),
    6: ("SHA512_RSA8192", "SHA-512 digest, RSA-8192 PKCS#1 v1.5 signature"),
}

# AvbDescriptorTag.
TAG_PROPERTY = 0
TAG_HASHTREE = 1
TAG_HASH = 2
TAG_KERNEL_CMDLINE = 3
TAG_CHAIN_PARTITION = 4

TAG_NAMES = {
    TAG_PROPERTY: "Property descriptor",
    TAG_HASHTREE: "Hashtree descriptor",
    TAG_HASH: "Hash descriptor",
    TAG_KERNEL_CMDLINE: "Kernel Cmdline descriptor",
    TAG_CHAIN_PARTITION: "Chain Partition descriptor",
}

# AvbVBMetaImageFlags.
FLAG_BITS = {
    0x1: "AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED",
    0x2: "AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED",
}

# AvbKernelCmdlineFlags -- which boot states this cmdline fragment applies to.
CMDLINE_FLAG_BITS = {
    0x1: "USE_ONLY_IF_HASHTREE_NOT_DISABLED",
    0x2: "USE_ONLY_IF_HASHTREE_DISABLED",
}


class VbmetaError(Exception):
    pass


def parse_header(blob):
    """Unpack the 256-byte big-endian header. AVB is big-endian throughout."""
    if len(blob) < HEADER_SIZE:
        raise VbmetaError(
            "file is %d bytes; a vbmeta header alone is %d" % (len(blob), HEADER_SIZE))
    if blob[:4] != MAGIC:
        raise VbmetaError(
            "bad magic %r -- expected %r.\n"
            "        If you dumped a whole partition this is still the right\n"
            "        file; AVB0 must be at offset 0. If it is not, you may have\n"
            "        a sparse image (run simg2img first) or the wrong partition."
            % (blob[:4], MAGIC))

    fmt = ">" + "".join(f for _, f in HEADER_FIELDS)
    size = struct.calcsize(fmt)
    values = struct.unpack(fmt, blob[:size])
    hdr = dict(zip([n for n, _ in HEADER_FIELDS], values))
    hdr["magic"] = hdr["magic"].decode("ascii", "replace")
    hdr["release_string"] = hdr["release_string"].split(b"\0", 1)[0].decode(
        "utf-8", "replace")
    return hdr


def iter_descriptors(blob, hdr):
    """Walk the descriptor list.

    Every descriptor begins with an 8-byte tag and an 8-byte
    num_bytes_following, and is padded to a 8-byte boundary. That uniform
    prefix is what lets a parser skip a descriptor type it does not understand
    -- which is how AVB adds descriptor types without breaking old bootloaders.
    """
    base = HEADER_SIZE + hdr["authentication_data_block_size"] + hdr["descriptors_offset"]
    end = base + hdr["descriptors_size"]
    if end > len(blob):
        raise VbmetaError(
            "descriptor block runs to offset %d but the file is %d bytes.\n"
            "        The image is truncated. If you used `dd count=N`, raise N."
            % (end, len(blob)))

    off = base
    while off < end:
        if off + 16 > end:
            break
        tag, nbf = struct.unpack(">QQ", blob[off:off + 16])
        body = blob[off + 16:off + 16 + nbf]
        yield off, tag, body
        step = 16 + nbf
        step += (-step) % 8          # descriptors are 8-byte aligned
        off += step


def _tail(body, fixed_size, reserved, lengths):
    """Slice the variable-length fields that follow a descriptor's fixed part.

    Every AVB descriptor except the kernel-cmdline and property ones ends its
    fixed part with a `uint8_t reserved[N]` block, and the variable-length data
    (partition name, salt, digest) starts AFTER that block. Forgetting the
    reserved bytes is the single easiest way to write a vbmeta parser that
    silently returns an empty partition name -- which is exactly the bug this
    helper exists to make impossible to reintroduce.
    """
    pos = fixed_size + reserved
    out = []
    for ln in lengths:
        out.append(body[pos:pos + ln])
        pos += ln
    return out


def decode_descriptor(tag, body):
    """Return an ordered list of (label, value) pairs for one descriptor."""
    hx = lambda b: binascii.hexlify(b).decode()

    if tag == TAG_HASH:
        # AvbHashDescriptor, from external/avb/libavb/avb_hash_descriptor.h:
        #   uint64_t image_size; uint8_t hash_algorithm[32];
        #   uint32_t partition_name_len, salt_len, digest_len, flags;
        #   uint8_t reserved[60];
        fmt = ">Q32sIIII"
        img_size, hash_alg, name_len, salt_len, digest_len, flags = \
            struct.unpack(fmt, body[:struct.calcsize(fmt)])
        name, salt, digest = _tail(body, struct.calcsize(fmt), 60,
                                   (name_len, salt_len, digest_len))
        return [
            ("Partition Name", name.decode("utf-8", "replace")),
            ("Image Size", "%d bytes" % img_size),
            ("Hash Algorithm", hash_alg.split(b"\0", 1)[0].decode()),
            ("Salt", hx(salt)),
            ("Digest", hx(digest)),
            ("Flags", "0x%x" % flags),
        ]

    if tag == TAG_HASHTREE:
        # AvbHashtreeDescriptor. Note fec_num_roots is a uint32 sitting between
        # two uint32s and two uint64s -- the struct is AVB_ATTR_PACKED, so there
        # is no alignment padding anywhere and ">" (no native alignment) is the
        # correct struct prefix.
        fmt = ">IQQQIIIQQ32sIIII"
        (dm_ver, image_size, tree_offset, tree_size, data_block_size,
         hash_block_size, fec_num_roots, fec_offset, fec_size, hash_alg,
         name_len, salt_len, root_len, flags) = struct.unpack(
            fmt, body[:struct.calcsize(fmt)])
        name, salt, root = _tail(body, struct.calcsize(fmt), 60,
                                 (name_len, salt_len, root_len))
        return [
            ("Partition Name", name.decode("utf-8", "replace")),
            ("Version of dm-verity", str(dm_ver)),
            ("Image Size", "%d bytes" % image_size),
            ("Tree Offset", str(tree_offset)),
            ("Tree Size", "%d bytes" % tree_size),
            ("Data Block Size", "%d bytes" % data_block_size),
            ("Hash Block Size", "%d bytes" % hash_block_size),
            ("FEC num roots", str(fec_num_roots)),
            ("FEC offset", str(fec_offset)),
            ("FEC size", "%d bytes" % fec_size),
            ("Hash Algorithm", hash_alg.split(b"\0", 1)[0].decode()),
            ("Salt", hx(salt)),
            ("Root Digest", hx(root)),
            ("Flags", "0x%x" % flags),
        ]

    if tag == TAG_CHAIN_PARTITION:
        # AvbChainPartitionDescriptor:
        #   uint32_t rollback_index_location, partition_name_len, public_key_len;
        #   uint8_t reserved[64];
        fmt = ">III"
        rollback_loc, name_len, key_len = struct.unpack(
            fmt, body[:struct.calcsize(fmt)])
        name, key = _tail(body, struct.calcsize(fmt), 64, (name_len, key_len))
        return [
            ("Partition Name", name.decode("utf-8", "replace")),
            ("Rollback Index Location", str(rollback_loc)),
            ("Public key size", "%d bytes" % len(key)),
            ("Public key SHA-1", hashlib.sha1(key).hexdigest()),
        ]

    if tag == TAG_KERNEL_CMDLINE:
        flags, cmdline_len = struct.unpack(">II", body[:8])
        cmdline = body[8:8 + cmdline_len].decode("utf-8", "replace")
        names = [v for k, v in CMDLINE_FLAG_BITS.items() if flags & k] or ["(none)"]
        return [
            ("Flags", "0x%x  %s" % (flags, ", ".join(names))),
            ("Kernel Cmdline", cmdline),
        ]

    if tag == TAG_PROPERTY:
        key_len, val_len = struct.unpack(">QQ", body[:16])
        key = body[16:16 + key_len]
        val = body[16 + key_len + 1:16 + key_len + 1 + val_len]
        return [("Key", key.decode("utf-8", "replace")),
                ("Value", val.decode("utf-8", "replace"))]

    return [("Raw", hx(body[:64]) + ("..." if len(body) > 64 else ""))]


def hexdump_header(blob):
    print("Raw header bytes, with the field boundaries that matter:")
    marks = {
        0x00: "magic 'AVB0'",
        0x04: "required libavb major/minor",
        0x0c: "authentication_data_block_size",
        0x14: "auxiliary_data_block_size",
        0x1c: "algorithm_type",
        0x60: "descriptors_offset / descriptors_size",
        0x70: "rollback_index",
        0x78: "flags / rollback_index_location",
        0x80: "release_string",
    }
    for off in range(0, HEADER_SIZE, 16):
        row = blob[off:off + 16]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        note = "   <- " + marks[off] if off in marks else ""
        print("  0x%04x  %-32s  %s%s"
              % (off, binascii.hexlify(row).decode(), text, note))
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Parse an Android Verified Boot 2.0 vbmeta image.")
    ap.add_argument("image", help="path to vbmeta.img (or a raw partition dump)")
    ap.add_argument("--hex", action="store_true",
                    help="also print the raw 256-byte header with field markers")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output, for diffing two images")
    args = ap.parse_args(argv)

    try:
        blob = open(args.image, "rb").read()
    except OSError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2

    try:
        hdr = parse_header(blob)
    except VbmetaError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1

    alg_name, alg_note = ALGORITHMS.get(
        hdr["algorithm_type"], ("UNKNOWN(%d)" % hdr["algorithm_type"], ""))
    flag_names = [v for k, v in FLAG_BITS.items() if hdr["flags"] & k]

    descriptors = []
    try:
        for off, tag, body in iter_descriptors(blob, hdr):
            descriptors.append({
                "file_offset": off,
                "tag": tag,
                "type": TAG_NAMES.get(tag, "Unknown descriptor (tag %d)" % tag),
                "fields": decode_descriptor(tag, body),
            })
    except VbmetaError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"header": hdr, "descriptors": descriptors},
                         indent=2, default=str))
        return 0

    if args.hex:
        hexdump_header(blob)

    print("Header")
    print("  Magic                        : %s" % hdr["magic"])
    print("  Required libavb version      : %d.%d"
          % (hdr["required_libavb_version_major"],
             hdr["required_libavb_version_minor"]))
    print("  Authentication block size    : %d bytes"
          % hdr["authentication_data_block_size"])
    print("  Auxiliary block size         : %d bytes"
          % hdr["auxiliary_data_block_size"])
    print("  Algorithm                    : %s   (%s)" % (alg_name, alg_note))
    print("  Public key size              : %d bytes" % hdr["public_key_size"])
    print("  Rollback Index               : %d" % hdr["rollback_index"])
    print("  Rollback Index Location      : %d" % hdr["rollback_index_location"])
    print("  Flags                        : 0x%x%s"
          % (hdr["flags"], ("  " + ", ".join(flag_names)) if flag_names else ""))
    print("  Release String               : '%s'" % hdr["release_string"])
    print()

    if hdr["algorithm_type"] == 0:
        print("  *** algorithm_type is NONE: this vbmeta is UNSIGNED. ***")
        print("      A bootloader with a locked state rejects it. Seeing this on")
        print("      a device that reports 'green' means the property is lying,")
        print("      not that unsigned images are accepted.")
        print()
    if hdr["flags"] & 0x2:
        print("  *** VERIFICATION_DISABLED is set: this vbmeta asks the")
        print("      bootloader NOT to verify anything below it. ***")
        print()
    elif hdr["flags"] & 0x1:
        print("  *** HASHTREE_DISABLED is set: dm-verity will not be set up. ***")
        print()

    print("Descriptors: %d" % len(descriptors))
    for i, d in enumerate(descriptors):
        print()
        print("  [%d] %s   (tag %d, at file offset 0x%x)"
              % (i, d["type"], d["tag"], d["file_offset"]))
        for label, value in d["fields"]:
            if len(str(value)) > 96:
                print("      %-24s:" % label)
                s = str(value)
                for j in range(0, len(s), 88):
                    print("        %s" % s[j:j + 88])
            else:
                print("      %-24s: %s" % (label, value))

    chains = [d for d in descriptors if d["tag"] == TAG_CHAIN_PARTITION]
    if chains:
        print()
        print("This vbmeta CHAINS to %d other partition(s). Parse each of them"
              % len(chains))
        print("too -- each has its own key and its own rollback index:")
        for d in chains:
            name = dict(d["fields"]).get("Partition Name", "?")
            print("    adb shell \"su -c 'dd if=/dev/block/by-name/%s "
                  "of=/data/local/tmp/%s.img'\"" % (name, name))
            print("    python3 -B %s %s.img" % (sys.argv[0], name))

    print()
    print("NOT VERIFIED: this tool parses, it does not check the signature.")
    print("An image is self-consistent by construction. Only the bootloader,")
    print("holding the OEM key in fuses, can tell you it is authentic -- and on")
    print("an unlocked device it does not bother. See Lab 02 Step 8.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
