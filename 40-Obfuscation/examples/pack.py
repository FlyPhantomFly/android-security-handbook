#!/usr/bin/env python3
"""
pack.py
===========================================================================
WHAT IT DOES
    The build-side half of the minimal packer in PackerStub.java. It takes a
    plaintext classes.dex, validates that it really is one, encrypts it, and
    writes the container that PackerStub.decryptPayload() expects.

    It can also UNPACK — given the key, it reverses the process, which is the
    static unpacking route from lab 04 step 4 implemented for you so you can
    check your own answer.

WHY IT MATTERS
    Building a packer is what makes the constraint concrete. Run this, and
    then read the output of --verify: the tool will tell you that it has taken
    a valid DEX with N classes and produced a blob with none. Then read
    PackerStub.java and see the same blob turned back into that DEX inside the
    target process, because it has to be, because ART cannot execute anything
    else.

    That round trip is the whole argument of chapter 40 section 3.7:

        The packer must hand the runtime a complete, valid, PLAINTEXT DEX.
        Therefore be in the process at that moment and copy it out.
        Unpacking is not code-breaking. It is timing.

HOW TO RUN
    # host — pack
    python3 pack.py --in payload/classes.dex --out payload.dat
    python3 pack.py --in payload/classes.dex --out payload.dat --key 5AA53CC317712EE2

    # host — inspect what you produced
    python3 pack.py --verify payload.dat

    # host — unpack again (the lab-04 static route)
    python3 pack.py --unpack payload.dat --out recovered.dex --key 5AA53CC317712EE2
    python3 pack.py --verify recovered.dex

    # host — then confirm it is the real thing
    jadx -d out recovered.dex
    ls out/sources/

REQUIREMENTS
    Python 3.8+. No third-party packages.

CONTAINER FORMAT
    offset 0   4 bytes   magic "OBFP"
    offset 4   4 bytes   plaintext length, little-endian
    offset 8   N bytes   ciphertext (plaintext XOR repeating key)

    The magic exists so the stub fails loudly on a corrupt asset instead of
    producing a mysterious VerifyError. Real packers carry a header for the
    same reason, and it is frequently the first thing you find when you open
    the asset in a hex editor.

WHAT THIS IS NOT
    It is not a real packer. A production packer encrypts in native code with
    a key that is derived rather than stored, protects the payload at method
    granularity, ships anti-debug in .init_array, and mangles the manifest and
    resources. Those raise the cost of the FIRST analysis and change nothing
    about the constraint above.

AUTHORISED TESTING ONLY — teaching material for chapter 40.
===========================================================================
"""

import argparse
import struct
import sys

MAGIC = b"OBFP"

# The same eight bytes as PackerStub.KEY. Deliberately short and fixed: this
# is what a low-tier packer does, and recognising it is part of the exercise.
DEFAULT_KEY = bytes([0x5A, 0xA5, 0x3C, 0xC3, 0x17, 0x71, 0x2E, 0xE2])

DEX_MAGIC = b"dex\n"


# ---------------------------------------------------------------------------
# DEX validation — the same four checks the memory carver uses
#
# See ../scripts/frida-dexdump-lite.js and ../../12-DEX-Internals/README.md.
# Doing them here as well is deliberate: a packer that silently encrypts
# something that is not a DEX produces a target that fails for reasons nobody
# can diagnose.
# ---------------------------------------------------------------------------


def inspect_dex(data, label):
    """Return a dict describing a DEX, or raise ValueError with the reason."""
    if len(data) < 0x70:
        raise ValueError(f"{label}: shorter than a DEX header (0x70 bytes)")

    if data[:4] != DEX_MAGIC:
        raise ValueError(f"{label}: magic is {data[:4]!r}, expected {DEX_MAGIC!r}")

    version = data[4:7]
    if not version.isdigit() or data[7] != 0:
        raise ValueError(f"{label}: bad version field {data[4:8]!r}")

    file_size = struct.unpack_from("<I", data, 0x20)[0]
    header_size = struct.unpack_from("<I", data, 0x24)[0]
    endian_tag = struct.unpack_from("<I", data, 0x28)[0]

    if header_size != 0x70:
        raise ValueError(f"{label}: header_size is {header_size:#x}, expected 0x70")
    if endian_tag != 0x12345678:
        raise ValueError(f"{label}: endian_tag is {endian_tag:#x}, "
                         "expected 0x12345678")

    string_ids = struct.unpack_from("<I", data, 0x38)[0]
    method_ids = struct.unpack_from("<I", data, 0x58)[0]
    class_defs = struct.unpack_from("<I", data, 0x60)[0]

    return {
        "version": version.decode("ascii"),
        "file_size": file_size,
        "actual_size": len(data),
        "string_ids": string_ids,
        "method_ids": method_ids,
        "class_defs": class_defs,
    }


def print_dex_info(info, label):
    print(f"{label}:")
    print(f"    DEX version   {info['version']}")
    print(f"    file_size     {info['file_size']}  (actual {info['actual_size']})")
    if info["file_size"] != info["actual_size"]:
        print("      ^ MISMATCH — appended data, or a truncated carve.")
        print("        See ../../12-DEX-Internals/labs/lab-04-ctf-the-lying-dex.md")
    print(f"    string_ids    {info['string_ids']}")
    print(f"    method_ids    {info['method_ids']}")
    print(f"    class_defs    {info['class_defs']}", end="")
    if info["class_defs"] < 50:
        print("   <-- under ~50: this is a STUB, not an application")
    else:
        print()


# ---------------------------------------------------------------------------
# Pack / unpack
# ---------------------------------------------------------------------------


def xor(data, key):
    out = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)


def pack(dex_path, out_path, key, force):
    with open(dex_path, "rb") as fh:
        dex = fh.read()

    try:
        info = inspect_dex(dex, dex_path)
        print_dex_info(info, "input")
    except ValueError as e:
        if not force:
            print(f"error: {e}", file=sys.stderr)
            print("       pass --force to pack it anyway", file=sys.stderr)
            return 1
        print(f"warning: {e}", file=sys.stderr)
        info = None

    body = xor(dex, key)
    blob = MAGIC + struct.pack("<I", len(dex)) + body

    with open(out_path, "wb") as fh:
        fh.write(blob)

    print()
    print(f"packed {len(dex)} bytes -> {out_path} ({len(blob)} bytes)")
    print(f"key    {key.hex()}")
    print()
    print("Next:")
    print(f"    cp {out_path} app/src/main/assets/")
    print("    set <application android:name> to your PackerStub")
    print("    add <meta-data android:name=\"obflab.real.application\" ...>")
    print()
    print("Then check what you built the way an analyst would:")
    print(f"    python3 pack.py --verify {out_path}")
    return 0


def unpack(blob_path, out_path, key):
    with open(blob_path, "rb") as fh:
        blob = fh.read()

    if len(blob) < 8:
        print("error: file too short to be a container", file=sys.stderr)
        return 1
    if blob[:4] != MAGIC:
        print(f"error: magic is {blob[:4]!r}, expected {MAGIC!r}", file=sys.stderr)
        print("       this is not a container produced by pack.py", file=sys.stderr)
        return 1

    length = struct.unpack_from("<I", blob, 4)[0]
    if length <= 0 or length > len(blob) - 8:
        print(f"error: declared length {length} does not fit in "
              f"{len(blob) - 8} bytes of body", file=sys.stderr)
        return 1

    dex = xor(blob[8:8 + length], key)

    try:
        info = inspect_dex(dex, "decrypted")
        print_dex_info(info, "recovered")
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        print("       the key is wrong, or the container is from a different "
              "packer", file=sys.stderr)
        return 1

    with open(out_path, "wb") as fh:
        fh.write(dex)

    print()
    print(f"wrote {len(dex)} bytes -> {out_path}")
    print()
    print("Confirm it is the real application, not another stub:")
    print(f"    jadx -d out {out_path}")
    print("    ls out/sources/")
    print()
    print("Success criterion (section 6.1 phase 3): you can see classes whose")
    print("names correspond to the manifest's component names. Until that is")
    print("true, you have not unpacked.")
    return 0


def verify(path):
    with open(path, "rb") as fh:
        data = fh.read()

    print(f"file   {path}")
    print(f"size   {len(data)} bytes")

    # Entropy — the same measurement apk-obfuscation-triage.sh makes.
    import math
    if data:
        counts = [0] * 256
        for b in data[:4 * 1024 * 1024]:
            counts[b] += 1
        n = min(len(data), 4 * 1024 * 1024)
        h = -sum((c / n) * math.log2(c / n) for c in counts if c)
        print(f"entropy {h:.2f} bits/byte", end="")
        if h > 7.8:
            print("   <-- near-random: encrypted or already compressed")
        else:
            print()

    print()
    if data[:4] == MAGIC:
        length = struct.unpack_from("<I", data, 4)[0]
        print("This is a pack.py CONTAINER.")
        print(f"    magic          {MAGIC!r}")
        print(f"    declared length {length}")
        print(f"    body           {len(data) - 8} bytes")
        print()
        print("Unpack it with:")
        print(f"    python3 pack.py --unpack {path} --out recovered.dex "
              f"--key {DEFAULT_KEY.hex()}")
        return 0

    if data[:4] == DEX_MAGIC:
        try:
            info = inspect_dex(data, path)
            print_dex_info(info, "DEX")
            return 0
        except ValueError as e:
            print(f"claims to be a DEX but: {e}")
            return 1

    if data[:2] == b"PK":
        print("This is a ZIP/APK container.")
        return 0

    print("Unrecognised. First 16 bytes:")
    print("    " + " ".join(f"{b:02x}" for b in data[:16]))
    print()
    print("If you expected a DEX here, the decryption key is wrong. If you")
    print("expected a container, this asset belongs to a different packer —")
    print("look for its own magic and length field in a hex editor.")
    return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_key(text):
    t = text.strip()
    if len(t) % 2 != 0:
        raise ValueError("key must be an even number of hex characters")
    try:
        k = bytes.fromhex(t)
    except ValueError:
        raise ValueError("key must be hexadecimal, e.g. 5AA53CC317712EE2")
    if not k:
        raise ValueError("key must not be empty")
    return k


def main():
    ap = argparse.ArgumentParser(
        description="Minimal packer for chapter 40 labs 04 and 05.",
        epilog="The key is in the APK. There is nowhere else for it to be.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--in", dest="infile", help="plaintext classes.dex to pack")
    g.add_argument("--unpack", help="container to decrypt")
    g.add_argument("--verify", help="identify and describe a file")

    ap.add_argument("--out", help="output path")
    ap.add_argument("--key", help="hex key (default: the PackerStub.java key)")
    ap.add_argument("--force", action="store_true",
                    help="pack even if the input is not a valid DEX")
    args = ap.parse_args()

    if args.key:
        try:
            key = parse_key(args.key)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    else:
        key = DEFAULT_KEY

    if args.verify:
        return verify(args.verify)

    if not args.out:
        print("error: --out is required for --in and --unpack", file=sys.stderr)
        return 2

    if args.infile:
        return pack(args.infile, args.out, key, args.force)
    return unpack(args.unpack, args.out, key)


if __name__ == "__main__":
    sys.exit(main())
