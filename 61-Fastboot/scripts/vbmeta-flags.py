#!/usr/bin/env python3
# scripts/vbmeta-flags.py
#
# PURPOSE
#   Answer one question about a vbmeta image, definitively, from bytes rather
#   than from a device property:
#
#       "Is dm-verity, or AVB verification as a whole, disabled on this image?"
#
#   and demonstrate the consequence that `fastboot --help` does not mention:
#   setting either flag INVALIDATES the image's own integrity hash, because the
#   flags field is inside the region AVB hashes. That is why `--disable-verity`
#   only works on an unlocked bootloader -- see chapter 61 section 3.8.
#
#   Chapter 20 owns full vbmeta parsing and ships a complete parser at
#     ../20-Security-Architecture/scripts/parse-vbmeta.py
#   This script is deliberately narrow: the flags, the hash invariant, and the
#   ability to set or clear the flags so you can see the effect for yourself.
#
#   Format reference: external/avb/libavb/avb_vbmeta_image.h  (ALL BIG-ENDIAN).
#
# USAGE
#   python3 -B scripts/vbmeta-flags.py show     vbmeta.img
#   python3 -B scripts/vbmeta-flags.py set      vbmeta.img OUT.img --disable-verity
#   python3 -B scripts/vbmeta-flags.py set      vbmeta.img OUT.img --disable-verification
#   python3 -B scripts/vbmeta-flags.py clear    vbmeta.img OUT.img
#   python3 -B scripts/vbmeta-flags.py diff     original.img modified.img
#   python3 -B scripts/vbmeta-flags.py selftest
#
#   Get a vbmeta.img either from an OEM factory image, or from a device you own:
#     adb shell 'su 0 dd if=/dev/block/by-name/vbmeta bs=1 count=$SIZE 2>/dev/null | base64' \
#       | base64 -d > vbmeta.img
#   where $SIZE is `getprop ro.boot.vbmeta.size`.
#
# SAFETY
#   Files only. This script never contacts a device and never flashes anything.
#   Writing an output image here does NOT modify your device; flashing that
#   image would, and this script will not do it for you. That is deliberate.
#
# EXIT CODES
#   0 success
#   1 usage or input error
#   2 selftest failure

import argparse
import hashlib
import struct
import sys

MAGIC = b"AVB0"
HEADER_LEN = 256
FLAGS_OFFSET = 120          # uint32, big-endian -- so the low byte is at 123

FLAG_HASHTREE_DISABLED = 1 << 0
FLAG_VERIFICATION_DISABLED = 1 << 1

FLAG_NAMES = [
    (FLAG_HASHTREE_DISABLED, "AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED",
     "every AvbHashtreeDescriptor is ignored -- dm-verity is never set up"),
    (FLAG_VERIFICATION_DISABLED, "AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED",
     "the entire vbmeta chain is skipped -- nothing is verified at all"),
]

# AVB algorithm_type values, from external/avb/libavb/avb_crypto.h
ALGORITHMS = {
    0: "NONE (unsigned)",
    1: "SHA256_RSA2048",
    2: "SHA256_RSA4096",
    3: "SHA256_RSA8192",
    4: "SHA512_RSA2048",
    5: "SHA512_RSA4096",
    6: "SHA512_RSA8192",
}

DIGEST_LEN = {1: 32, 2: 32, 3: 32, 4: 64, 5: 64, 6: 64}


class VbmetaError(Exception):
    pass


class Vbmeta(object):
    def __init__(self, blob):
        if len(blob) < HEADER_LEN:
            raise VbmetaError(
                "file is %d bytes; an AVB header is %d" % (len(blob), HEADER_LEN))
        if blob[:4] != MAGIC:
            raise VbmetaError(
                "bad magic %r (expected %r) -- not a vbmeta image"
                % (blob[:4], MAGIC))
        self.blob = blob

        (self.ver_major, self.ver_minor) = struct.unpack(">II", blob[4:12])
        (self.auth_size, self.aux_size) = struct.unpack(">QQ", blob[12:28])
        (self.algorithm,) = struct.unpack(">I", blob[28:32])
        (self.hash_off, self.hash_size,
         self.sig_off, self.sig_size,
         self.pk_off, self.pk_size,
         self.pkm_off, self.pkm_size,
         self.desc_off, self.desc_size,
         self.rollback_index) = struct.unpack(">11Q", blob[32:120])
        (self.flags, self.rbi_location) = struct.unpack(">II", blob[120:128])
        self.release = blob[128:176].rstrip(b"\x00").decode("ascii", "replace")

        if HEADER_LEN + self.auth_size + self.aux_size > len(blob):
            raise VbmetaError(
                "header claims %d bytes of auth+aux but the file is only %d"
                % (HEADER_LEN + self.auth_size + self.aux_size, len(blob)))

    # -- the integrity invariant -------------------------------------------

    def auth_block(self):
        return self.blob[HEADER_LEN:HEADER_LEN + self.auth_size]

    def aux_block(self):
        start = HEADER_LEN + self.auth_size
        return self.blob[start:start + self.aux_size]

    def stored_hash(self):
        """The hash AVB recorded inside the authentication block."""
        n = DIGEST_LEN.get(self.algorithm)
        if n is None or self.auth_size == 0:
            return None
        auth = self.auth_block()
        if self.hash_off + n > len(auth):
            return None
        return auth[self.hash_off:self.hash_off + n]

    def computed_hash(self):
        """Recompute what AVB would compute: sha over header || aux block.

        This is the shape of avb_vbmeta_image_verify() in
        external/avb/libavb/avb_vbmeta_image.c. The header is hashed AS IT
        APPEARS ON DISK -- which is precisely why the flags field, at offset
        120, is covered by it.
        """
        if self.algorithm in (1, 2, 3):
            h = hashlib.sha256()
        elif self.algorithm in (4, 5, 6):
            h = hashlib.sha512()
        else:
            return None
        h.update(self.blob[:HEADER_LEN])
        h.update(self.aux_block())
        return h.digest()

    def integrity_ok(self):
        stored, calc = self.stored_hash(), self.computed_hash()
        if stored is None or calc is None:
            return None
        return stored == calc

    # -- reporting ----------------------------------------------------------

    def describe(self):
        lines = [
            "magic                     %s" % MAGIC.decode(),
            "required libavb version   %d.%d" % (self.ver_major, self.ver_minor),
            "authentication block      %d bytes" % self.auth_size,
            "auxiliary block           %d bytes" % self.aux_size,
            "algorithm_type            %d  (%s)"
            % (self.algorithm, ALGORITHMS.get(self.algorithm, "unknown")),
            "descriptors               offset %d, %d bytes"
            % (self.desc_off, self.desc_size),
            "rollback_index            %d" % self.rollback_index,
            "rollback_index_location   %d" % self.rbi_location,
            "release_string            %r" % self.release,
            "",
            "flags                     0x%08x   (uint32 big-endian at offset %d;"
            % (self.flags, FLAGS_OFFSET),
            "                                       low byte therefore at offset %d)"
            % (FLAGS_OFFSET + 3),
        ]
        for bit, name, effect in FLAG_NAMES:
            state = "SET  " if self.flags & bit else "clear"
            lines.append("  bit %d  %s  %s" % (bit.bit_length() - 1, state, name))
            lines.append("           %s" % effect)
        unknown = self.flags & ~(FLAG_HASHTREE_DISABLED | FLAG_VERIFICATION_DISABLED)
        if unknown:
            lines.append("  WARNING: undefined flag bits set: 0x%08x" % unknown)

        ok = self.integrity_ok()
        lines.append("")
        if ok is None:
            lines.append("integrity hash            not checkable "
                         "(unsigned image or unknown algorithm)")
        elif ok:
            lines.append("integrity hash            MATCH -- this image is internally consistent")
        else:
            lines.append("integrity hash            MISMATCH -- the header has been edited")
            lines.append("                          after signing. A LOCKED bootloader will")
            lines.append("                          refuse this image (boot state RED).")
        return "\n".join(lines)

    def verdict(self):
        if self.flags & FLAG_VERIFICATION_DISABLED:
            return ("ALL AVB VERIFICATION DISABLED -- nothing on this device is "
                    "verified at boot")
        if self.flags & FLAG_HASHTREE_DISABLED:
            return ("dm-verity DISABLED -- partitions with hashtree descriptors "
                    "are not integrity-checked on read")
        return "no disable flags set -- AVB will enforce as configured"


def set_flags(blob, add=0, clear_all=False):
    """Return a copy of blob with the flags field modified."""
    out = bytearray(blob)
    (cur,) = struct.unpack(">I", out[FLAGS_OFFSET:FLAGS_OFFSET + 4])
    new = 0 if clear_all else (cur | add)
    out[FLAGS_OFFSET:FLAGS_OFFSET + 4] = struct.pack(">I", new)
    return bytes(out), cur, new


def byte_diff(a, b):
    n = min(len(a), len(b))
    return [i for i in range(n) if a[i] != b[i]]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_show(args):
    v = Vbmeta(open(args.image, "rb").read())
    print(v.describe())
    print()
    print("VERDICT: %s" % v.verdict())
    return 0


def cmd_set(args):
    blob = open(args.image, "rb").read()
    Vbmeta(blob)                      # validate before writing anything
    add = 0
    if args.disable_verity:
        add |= FLAG_HASHTREE_DISABLED
    if args.disable_verification:
        add |= FLAG_VERIFICATION_DISABLED
    if not add:
        print("error: give --disable-verity and/or --disable-verification",
              file=sys.stderr)
        return 1

    out, before, after = set_flags(blob, add=add)
    open(args.output, "wb").write(out)
    changed = byte_diff(blob, out)

    print("flags 0x%08x -> 0x%08x" % (before, after))
    print("bytes changed: %s" % (changed if changed else "none"))
    v2 = Vbmeta(out)
    ok = v2.integrity_ok()
    print("integrity hash after edit: %s"
          % ("MATCH" if ok else "MISMATCH" if ok is False else "not checkable"))
    if ok is False:
        print()
        print("This is the point of the exercise. The flags field is inside the")
        print("region AVB hashes, so editing it breaks the image's own integrity")
        print("check and therefore its signature. Only an UNLOCKED bootloader")
        print("will boot from this. Flashing it to a locked device produces boot")
        print("state RED and a device that will not start.")
    return 0


def cmd_clear(args):
    blob = open(args.image, "rb").read()
    Vbmeta(blob)
    out, before, after = set_flags(blob, clear_all=True)
    open(args.output, "wb").write(out)
    print("flags 0x%08x -> 0x%08x" % (before, after))
    print("bytes changed: %s" % byte_diff(blob, out))
    return 0


def cmd_diff(args):
    a = open(args.original, "rb").read()
    b = open(args.modified, "rb").read()
    if len(a) != len(b):
        print("sizes differ: %d vs %d" % (len(a), len(b)))
    changed = byte_diff(a, b)
    print("bytes changed: %d" % len(changed))
    if changed:
        print("offsets: %s%s"
              % (changed[:32], " ..." if len(changed) > 32 else ""))
    for off in changed[:32]:
        where = "FLAGS FIELD" if FLAGS_OFFSET <= off < FLAGS_OFFSET + 4 else ""
        print("  %6d: %02x -> %02x  %s" % (off, a[off], b[off], where))
    try:
        va, vb = Vbmeta(a), Vbmeta(b)
        print()
        print("original flags 0x%08x  integrity %s"
              % (va.flags, va.integrity_ok()))
        print("modified flags 0x%08x  integrity %s"
              % (vb.flags, vb.integrity_ok()))
    except VbmetaError as exc:
        print("(could not parse one side as vbmeta: %s)" % exc)
    return 0


# ---------------------------------------------------------------------------
# Self-test -- builds a synthetic but structurally valid vbmeta, so the script
# is verifiable with no device and no factory image.
# ---------------------------------------------------------------------------


def _synthetic_vbmeta(flags=0):
    """A minimal, self-consistent SHA256_RSA4096-shaped vbmeta.

    The signature is not a real RSA signature -- verifying that needs a key we
    do not have and is chapter 20's job. What IS real here is the hash
    invariant: stored_hash == sha256(header || aux), which is the property this
    script demonstrates.
    """
    aux = b"\xA5" * 512
    auth_size = 32 + 512          # sha256 digest + 4096-bit signature
    header = bytearray(HEADER_LEN)
    header[0:4] = MAGIC
    struct.pack_into(">II", header, 4, 1, 0)
    struct.pack_into(">QQ", header, 12, auth_size, len(aux))
    struct.pack_into(">I", header, 28, 2)                 # SHA256_RSA4096
    struct.pack_into(">11Q", header, 32,
                     0, 32,            # hash offset/size
                     32, 512,          # signature offset/size
                     0, 0,             # public key offset/size
                     0, 0,             # public key metadata offset/size
                     0, len(aux),      # descriptors offset/size
                     0)                # rollback index
    struct.pack_into(">II", header, 120, flags, 0)
    header[128:128 + 13] = b"avbtool 1.3.0"

    digest = hashlib.sha256(bytes(header) + aux).digest()
    auth = digest + (b"\x00" * 512)
    return bytes(header) + auth + aux


def cmd_selftest(_args):
    failures = []

    def check(name, cond, detail=""):
        if cond:
            print("  PASS  %s" % name)
        else:
            print("  FAIL  %s   %s" % (name, detail))
            failures.append(name)

    print("parsing")
    blob = _synthetic_vbmeta()
    v = Vbmeta(blob)
    check("magic accepted", True)
    check("algorithm is SHA256_RSA4096", v.algorithm == 2)
    check("flags start at 0", v.flags == 0)
    check("integrity hash matches", v.integrity_ok() is True)
    check("release string round-trips", v.release == "avbtool 1.3.0", v.release)

    print("flags field location")
    check("FLAGS_OFFSET is 120", FLAGS_OFFSET == 120)
    for bit, label in ((FLAG_HASHTREE_DISABLED, "--disable-verity"),
                       (FLAG_VERIFICATION_DISABLED, "--disable-verification")):
        out, _before, after = set_flags(blob, add=bit)
        changed = byte_diff(blob, out)
        check("%s changes exactly one byte, at offset 123" % label,
              changed == [123], str(changed))
        check("%s sets the expected bit" % label, after == bit,
              "0x%08x" % after)

    print("the invariant this script exists to demonstrate")
    out, _b, _a = set_flags(blob, add=FLAG_HASHTREE_DISABLED)
    v2 = Vbmeta(out)
    check("flag is readable after the edit",
          bool(v2.flags & FLAG_HASHTREE_DISABLED))
    check("integrity hash NO LONGER matches", v2.integrity_ok() is False)
    check("verdict names dm-verity", "dm-verity DISABLED" in v2.verdict())

    out2, _b, _a = set_flags(blob, add=FLAG_VERIFICATION_DISABLED)
    check("verification-disabled verdict is the broader one",
          "ALL AVB VERIFICATION DISABLED" in Vbmeta(out2).verdict())

    print("clearing round-trips")
    both, _b, _a = set_flags(blob, add=FLAG_HASHTREE_DISABLED |
                             FLAG_VERIFICATION_DISABLED)
    restored, _b2, after2 = set_flags(both, clear_all=True)
    check("clear returns flags to 0", after2 == 0)
    check("clearing restores the original bytes exactly", restored == blob)
    check("and the integrity hash matches again",
          Vbmeta(restored).integrity_ok() is True)

    print("bad input is rejected")
    for name, bad in (("empty file", b""),
                      ("wrong magic", b"XXXX" + blob[4:]),
                      ("truncated header", blob[:100])):
        try:
            Vbmeta(bad)
            print("  FAIL  %s   (accepted)" % name)
            failures.append(name)
        except VbmetaError:
            print("  PASS  %s" % name)

    print()
    if failures:
        print("%d FAILURE(S): %s" % (len(failures), ", ".join(failures)))
        return 2
    print("all self-tests passed")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Read and modify the AVB vbmeta disable flags "
                    "(chapter 61 -- Fastboot). Files only; never touches a device.")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("show", help="report the flags and the integrity invariant")
    p.add_argument("image")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("set", help="set a disable flag and show what it breaks")
    p.add_argument("image")
    p.add_argument("output")
    p.add_argument("--disable-verity", action="store_true")
    p.add_argument("--disable-verification", action="store_true")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("clear", help="clear all flags")
    p.add_argument("image")
    p.add_argument("output")
    p.set_defaults(func=cmd_clear)

    p = sub.add_parser("diff", help="byte-diff two vbmeta images")
    p.add_argument("original")
    p.add_argument("modified")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("selftest", help="run the built-in test suite")
    p.set_defaults(func=cmd_selftest)

    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 1
    try:
        return args.func(args)
    except VbmetaError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
