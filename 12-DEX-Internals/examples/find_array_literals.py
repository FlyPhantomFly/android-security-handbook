#!/usr/bin/env python3
"""
find_array_literals.py — locate hardcoded byte arrays in a DEX file.

WHAT IT DOES
    Scans a DEX for `fill-array-data-payload` structures (../README.md 3.27)
    and prints their contents as hex, decimal and ASCII, flagging any whose
    length matches a common cryptographic key or IV size.

WHY IT MATTERS
    When a developer writes:

        byte[] key = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, ...};

    the compiler does NOT put those bytes in the string pool. It emits a
    `fill-array-data-payload`: a contiguous run of raw bytes in the data
    section, referenced by a `fill-array-data` instruction.

    Because it is not text, `strings` will not find it. Every "we searched for
    hardcoded keys and found none" report that only ran `strings` missed this.

    This is one of the highest-yield techniques for locating embedded key
    material. See ../README.md section 3.27 and ../../34-Cryptography/.

HOW IT WORKS
    The payload has a fixed, recognisable shape:

        ushort  ident         = 0x0300   (bytes: 00 03)
        ushort  element_width = 1, 2, 4 or 8
        uint    size          = element count
        ubyte[] data          = size * element_width bytes, padded to even

    The leading 0x00 is the `nop` opcode, deliberately chosen so a linear
    disassembler walking the instruction stream skips the payload harmlessly
    instead of misreading it as code.

    We scan the whole file for the 0x0300 identifier and validate the header
    that follows, which is fast and catches payloads regardless of which
    method references them.

HOW TO RUN
    python3 find_array_literals.py classes.dex
    python3 find_array_literals.py classes.dex --min-size 16
    python3 find_array_literals.py classes.dex --keys-only
    python3 find_array_literals.py classes.dex --width 1 --max-size 64

    # Across a whole APK
    unzip -o app.apk 'classes*.dex' -d /tmp/dex
    for f in /tmp/dex/classes*.dex; do
        echo "=== $f"; python3 find_array_literals.py "$f" --keys-only
    done

REQUIREMENTS
    Python 3.8+. Standard library only.

CAVEAT
    A byte array of length 16 is not necessarily an AES key. This tool finds
    CANDIDATES. Confirm by locating the `fill-array-data` instruction that
    references the payload and reading what the array is used for — or by
    hooking the crypto API at runtime and comparing.
    See ../../34-Cryptography/scripts/ for the runtime approach.
"""

import argparse
import struct
import sys

PAYLOAD_IDENT = 0x0300

# Lengths worth flagging, with what they commonly are.
INTERESTING_LENGTHS = {
    8:  "DES key / 64-bit block / IV fragment",
    12: "GCM nonce (96-bit) — the recommended size",
    16: "AES-128 key, or an AES/CBC IV (128-bit block)",
    20: "SHA-1 digest",
    24: "AES-192 key, or 3DES key",
    32: "AES-256 key, ChaCha20 key, or SHA-256 digest",
    48: "SHA-384 digest",
    64: "SHA-512 digest, or an HMAC block",
}


def find_payloads(data, width_filter=None, min_size=1, max_size=None):
    """Scan for fill-array-data-payload structures and validate each."""
    results = []
    pos = 0
    n = len(data)

    while pos < n - 8:
        idx = data.find(b"\x00\x03", pos)
        if idx == -1:
            break
        pos = idx + 1

        # The identifier must be 2-byte aligned within insns.
        if idx % 2 != 0:
            continue

        try:
            ident, width, count = struct.unpack_from("<HHI", data, idx)
        except struct.error:
            continue

        if ident != PAYLOAD_IDENT:
            continue
        if width not in (1, 2, 4, 8):
            continue
        if count == 0 or count > 4_000_000:
            continue

        byte_len = count * width
        end = idx + 8 + byte_len
        if end > n:
            continue

        if width_filter is not None and width != width_filter:
            continue
        if byte_len < min_size:
            continue
        if max_size is not None and byte_len > max_size:
            continue

        results.append({
            "offset": idx,
            "element_width": width,
            "count": count,
            "byte_length": byte_len,
            "data": data[idx + 8: end],
        })

    return results


def render_ascii(blob):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in blob)


def entropy_hint(blob):
    """Very rough: how many distinct byte values, as a fraction of length."""
    if not blob:
        return 0.0
    return len(set(blob)) / min(len(blob), 256)


def main():
    ap = argparse.ArgumentParser(
        description="Find hardcoded byte arrays (fill-array-data payloads) in a DEX")
    ap.add_argument("path")
    ap.add_argument("--width", type=int, choices=[1, 2, 4, 8],
                    help="only this element width (1 = byte arrays)")
    ap.add_argument("--min-size", type=int, default=4,
                    help="minimum total byte length (default 4)")
    ap.add_argument("--max-size", type=int, default=None,
                    help="maximum total byte length")
    ap.add_argument("--keys-only", action="store_true",
                    help="only payloads whose length matches a common key size")
    ap.add_argument("--full", action="store_true",
                    help="print the entire payload, not just the first 64 bytes")
    args = ap.parse_args()

    try:
        with open(args.path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if data[0:4] != b"dex\n":
        print(f"warning: {args.path} does not start with b'dex\\n' — "
              "scanning anyway", file=sys.stderr)

    payloads = find_payloads(data, args.width, args.min_size, args.max_size)

    if args.keys_only:
        payloads = [p for p in payloads if p["byte_length"] in INTERESTING_LENGTHS]

    print(f"\n=== {args.path} ===")
    print(f"Found {len(payloads)} fill-array-data payload(s)"
          + (" matching common key sizes" if args.keys_only else "") + "\n")

    if not payloads:
        print("  None matched. Try relaxing --min-size, or drop --keys-only.")
        print("  Note: an app with NO array literals at all is unusual — if you")
        print("  expected some, check you are scanning every classes*.dex.\n")
        return 0

    flagged = 0
    for p in payloads:
        blob = p["data"]
        length = p["byte_length"]
        note = INTERESTING_LENGTHS.get(length)

        marker = " <== " + note if note else ""
        if note:
            flagged += 1

        print(f"  offset 0x{p['offset']:08x}  "
              f"width={p['element_width']}  count={p['count']}  "
              f"bytes={length}{marker}")

        show = blob if args.full else blob[:64]
        # Hex, 16 bytes per line, with ASCII alongside.
        for i in range(0, len(show), 16):
            chunk = show[i:i + 16]
            hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(47)
            print(f"      {i:04x}  {hexpart}  |{render_ascii(chunk)}|")
        if not args.full and len(blob) > 64:
            print(f"      ... {len(blob) - 64} more bytes (use --full)")

        # A high-entropy short array is a stronger key candidate than a
        # low-entropy one, which is more likely a lookup table or a bitmap.
        e = entropy_hint(blob)
        if length in INTERESTING_LENGTHS and e > 0.6:
            print(f"      high byte diversity ({e:.2f}) — strong key candidate")
        elif length in INTERESTING_LENGTHS:
            print(f"      low byte diversity ({e:.2f}) — could be a lookup table")

        print()

    # --- guidance -------------------------------------------------------
    print("-" * 66)
    print(f"{flagged} payload(s) matched a common key or digest length.\n")
    print("NEXT STEPS")
    print("  1. Find which method references the payload:")
    print("       baksmali d classes.dex -o smali/")
    print("       grep -rn 'fill-array-data' smali/ | head")
    print("     The instruction's branch offset points at the payload.")
    print()
    print("  2. Read what the array is USED for. A 16-byte array is only a key")
    print("     if it reaches a SecretKeySpec or an IvParameterSpec.")
    print("       grep -rn 'SecretKeySpec\\|IvParameterSpec' smali/")
    print()
    print("  3. Confirm at runtime rather than guessing:")
    print("       frida -U -f <pkg> -l ../../34-Cryptography/scripts/jca-dump.js")
    print()
    print("  A length match is a CANDIDATE, not a finding. Confirm before")
    print("  reporting. See ../../52-StaticAnalysis/ on false positives.\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
