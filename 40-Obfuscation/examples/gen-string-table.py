#!/usr/bin/env python3
"""
gen-string-table.py
===========================================================================
WHAT IT DOES
    Generates the ciphertext tables and the matching Java decryptor class for
    each of the three string-encryption variants in chapter 40 section 3.2,
    so you can build a target for labs 01, 02 and 05.

      --variant xor       fixed single-byte XOR              (variant A)
      --variant aes       AES-128-CBC, key in the same DEX   (variant B)
      --variant perclass  per-class key + position-dependent (variant C)

WHY IT MATTERS
    You cannot properly assess a control you have never implemented. Building
    the encryption yourself makes three things concrete that are otherwise
    just assertions:

      1. The key has to be in the app. You will type it into the generated
         Java yourself, and there is nowhere else for it to go.
      2. The plaintext has to exist at runtime. You will write the decryptor
         that produces it.
      3. Changing the cipher changes nothing about the recovery cost, because
         the recovery hooks the result rather than the algorithm.

    Then run ../scripts/frida-string-decryptor.js against what you built and
    watch all three variants fall to the same script, unchanged.

HOW TO RUN
    # host — one string per line, blank lines and # comments ignored
    cat > strings.txt <<'EOF'
    https://api.obflab.example.com/v2
    /auth/login
    /payments/transfer
    sk_live_EXAMPLE_NOT_A_REAL_KEY_ch40
    AES/CBC/PKCS5Padding
    SHA-256
    EOF

    python3 gen-string-table.py --variant xor --strings strings.txt \
        --key 0x5A --class XorStrings --package com.obflab.demo.crypto \
        --out XorStrings.java

    python3 gen-string-table.py --variant aes --strings strings.txt \
        --class AesStrings --out AesStrings.java

    python3 gen-string-table.py --variant perclass --strings strings.txt \
        --key 0x4B --class S_PaymentService --out S_PaymentService.java

    # verify a round trip before you build an APK around it
    python3 gen-string-table.py --variant xor --strings strings.txt \
        --key 0x5A --self-test

REQUIREMENTS
    Python 3.8+ for the xor and perclass variants.
    The `cryptography` package for --variant aes (pip install cryptography).

WHAT THIS IS NOT
    It is not a bytecode transform. A real obfuscator rewrites compiled
    classes and replaces every string constant automatically; this generates
    the table and the decryptor and leaves you to substitute the call sites by
    hand. That manual substitution is deliberate — doing it once shows you
    exactly why a transform decrypts AT THE POINT OF USE rather than into a
    static field, and why that choice matters to an analyst.

AUTHORISED TESTING ONLY — teaching material for chapter 40.
===========================================================================
"""

import argparse
import base64
import os
import sys
import textwrap

# ---------------------------------------------------------------------------
# Encoders — one per variant
#
# Each returns a list of encoded units, one per input string, in whatever form
# the corresponding Java decryptor consumes.
# ---------------------------------------------------------------------------


def encode_xor(strings, key):
    """Variant A: every byte XORed with the same key."""
    out = []
    for s in strings:
        raw = s.encode("utf-8")
        out.append(bytes(b ^ key for b in raw))
    return out


def encode_perclass(strings, key):
    """
    Variant C: XOR with a per-class key, plus a position-dependent term.

    The `+ (i & 7)` here is the inverse of the `- (i & 7)` in the Java
    decryptor. It exists so that an analyst who reads the Smali, concludes
    "single-byte XOR", and tries it offline gets plausible-looking garbage
    rather than a clean failure — which costs more time than an obvious
    failure would, and is the point of the variant.
    """
    out = []
    for s in strings:
        raw = s.encode("utf-8")
        enc = bytearray(len(raw))
        for i, b in enumerate(raw):
            enc[i] = ((b + (i & 7)) & 0xFF) ^ key
        out.append(bytes(enc))
    return out


def encode_aes(strings, key, iv):
    """Variant B: AES-128-CBC with PKCS#5 padding, base64-encoded."""
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes)
    except ImportError:
        sys.exit("--variant aes needs the 'cryptography' package: "
                 "pip install cryptography")

    out = []
    for s in strings:
        raw = s.encode("utf-8")
        pad = 16 - (len(raw) % 16)
        padded = raw + bytes([pad]) * pad
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        out.append(enc.update(padded) + enc.finalize())
    return out


# ---------------------------------------------------------------------------
# Decoders — used only by --self-test, and written to mirror the Java exactly
# ---------------------------------------------------------------------------


def decode_xor(blobs, key):
    return ["".join(chr(b ^ key) for b in blob) for blob in blobs]


def decode_perclass(blobs, key):
    out = []
    for blob in blobs:
        chars = []
        for i, b in enumerate(blob):
            chars.append(chr(((b ^ key) - (i & 7)) & 0xFF))
        out.append("".join(chars))
    return out


def decode_aes(blobs, key, iv):
    from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes)
    out = []
    for blob in blobs:
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = dec.update(blob) + dec.finalize()
        out.append(padded[:-padded[-1]].decode("utf-8"))
    return out


# ---------------------------------------------------------------------------
# Java emission
# ---------------------------------------------------------------------------


def java_byte_array(blob, indent):
    """Render bytes as a Java byte[] initialiser, wrapped."""
    items = ", ".join(f"(byte) 0x{b:02X}" for b in blob)
    wrapped = textwrap.wrap(items, width=72)
    pad = " " * indent
    return ("\n" + pad).join(wrapped)


def emit_xor(package, cls, key, blobs, originals, show_map):
    rows = []
    for i, blob in enumerate(blobs):
        comment = f"        // {i}: {originals[i]!r}\n" if show_map else ""
        rows.append(comment + "        { " + java_byte_array(blob, 10) + " },")
    body = "\n".join(rows)

    return f"""/*
 * {cls}.java — GENERATED by gen-string-table.py (variant: xor)
 *
 * Chapter 40 section 3.2 variant A: fixed single-byte XOR.
 *
 * HOW THIS APPEARS TO AN ANALYST
 *   In Smali, `xor-int/lit8 vN, vN, 0x{key:02X}` inside a loop, in a method
 *   returning Ljava/lang/String;. That pattern has essentially no
 *   false-positive rate: ordinary code does not XOR a byte array element by
 *   element and construct a String from the result.
 *
 *   Recovery: twenty minutes statically, or one command dynamically.
 */
package {package};

public final class {cls} {{

    private static final byte KEY = (byte) 0x{key:02X};

    private static final byte[][] DATA = {{
{body}
    }};

    public static String get(int index) {{
        byte[] e = DATA[index];
        char[] out = new char[e.length];
        for (int i = 0; i < e.length; i++) {{
            out[i] = (char) (e[i] ^ KEY);
        }}
        return new String(out);
    }}

    private {cls}() {{ }}
}}
"""


def emit_perclass(package, cls, key, blobs, originals, show_map):
    rows = []
    for i, blob in enumerate(blobs):
        comment = f"        // {i}: {originals[i]!r}\n" if show_map else ""
        rows.append(comment + "        { " + java_byte_array(blob, 10) + " },")
    body = "\n".join(rows)

    return f"""/*
 * {cls}.java — GENERATED by gen-string-table.py (variant: perclass)
 *
 * Chapter 40 section 3.2 variant C: per-class key plus a position-dependent
 * term.
 *
 * Emit one of these per class, each with a DIFFERENT key, and ideally with a
 * slightly different mixing step. That combination defeats static
 * reimplementation completely — nobody ports four hundred algorithms by hand.
 *
 * It costs a dynamic recovery nothing at all, because every one of the four
 * hundred still ends by constructing a java.lang.String, and that is a single
 * choke point. See ../scripts/frida-string-decryptor.js.
 */
package {package};

final class {cls} {{

    private static final int K = 0x{key:02X};

    private static final byte[][] DATA = {{
{body}
    }};

    static String a(int index) {{
        byte[] e = DATA[index];
        char[] out = new char[e.length];
        for (int i = 0; i < e.length; i++) {{
            // & 0xFF matters: a Java byte is signed, and the position term
            // pushes some encoded bytes above 0x7F. Without the mask, sign
            // extension corrupts exactly those characters — a bug that is
            // easy to write and slow to find, because most of the string
            // still decodes correctly.
            out[i] = (char) ((((e[i] & 0xFF) ^ K) - (i & 7)) & 0xFF);
        }}
        return new String(out);
    }}

    private {cls}() {{ }}
}}
"""


def emit_aes(package, cls, key, iv, blobs, originals, show_map):
    rows = []
    for i, blob in enumerate(blobs):
        b64 = base64.b64encode(blob).decode("ascii")
        comment = f"        // {i}: {originals[i]!r}\n" if show_map else ""
        rows.append(comment + f'        "{b64}",')
    body = "\n".join(rows)

    return f"""/*
 * {cls}.java — GENERATED by gen-string-table.py (variant: aes)
 *
 * Chapter 40 section 3.2 variant B: AES-128-CBC, key in the same DEX.
 *
 * READ THE WARNING IN THE CHAPTER. This is NOT stronger than XOR in any
 * meaningful sense. The threat model is "an attacker holds the app"; if the
 * attacker holds the app, they hold the key, because the key must be in the
 * app for the app to work.
 *
 * AES buys exactly one thing over XOR: the strings cannot be recovered with a
 * twenty-line script that guesses a single byte. They are recovered by RUNNING
 * THE DECRYPTOR, which costs the same effort regardless of cipher.
 *
 * The 16-byte key and 16-byte IV literals below are also a recognisable shape
 * in their own right.
 */
package {package};

import android.util.Base64;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class {cls} {{

    private static final byte[] KEY = {{
        {java_byte_array(key, 8)}
    }};

    private static final byte[] IV = {{
        {java_byte_array(iv, 8)}
    }};

    private static final String[] DATA = {{
{body}
    }};

    public static String get(int index) {{
        try {{
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE,
                   new SecretKeySpec(KEY, "AES"),
                   new IvParameterSpec(IV));
            byte[] pt = c.doFinal(Base64.decode(DATA[index], Base64.NO_WRAP));
            return new String(pt, StandardCharsets.UTF_8);
        }} catch (Exception e) {{
            return null;
        }}
    }}

    private {cls}() {{ }}
}}
"""


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def load_strings(path):
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            s = line.rstrip("\n")
            if not s or s.lstrip().startswith("#"):
                continue
            out.append(s)
    if not out:
        sys.exit(f"no usable strings in {path}")
    return out


def parse_key(text):
    """Accept 0x5A, 90, or a 32-hex-character AES key."""
    t = text.strip()
    if len(t) == 32 and all(c in "0123456789abcdefABCDEF" for c in t):
        return bytes.fromhex(t)
    return int(t, 0)


def main():
    ap = argparse.ArgumentParser(
        description="Generate string-encryption tables and decryptors "
                    "for chapter 40 section 3.2.")
    ap.add_argument("--variant", required=True,
                    choices=["xor", "aes", "perclass"])
    ap.add_argument("--strings", required=True,
                    help="file with one plaintext string per line")
    ap.add_argument("--key",
                    help="xor/perclass: single byte (0x5A). "
                         "aes: 32 hex chars, or omit for a random key")
    ap.add_argument("--iv", help="aes: 32 hex chars, or omit for a random IV")
    ap.add_argument("--class", dest="cls", default="Strings",
                    help="generated class name (default: Strings)")
    ap.add_argument("--package", default="com.obflab.demo.crypto",
                    help="generated package (default: com.obflab.demo.crypto)")
    ap.add_argument("--out", help="output .java path (default: stdout)")
    ap.add_argument("--no-index-map", action="store_true",
                    help="omit the index->plaintext comments. USE THIS for a "
                         "target you intend to analyse: shipping the map "
                         "defeats the whole exercise")
    ap.add_argument("--self-test", action="store_true",
                    help="encode then decode and verify the round trip; "
                         "writes nothing")
    args = ap.parse_args()

    strings = load_strings(args.strings)

    # ---- encode -----------------------------------------------------------
    if args.variant in ("xor", "perclass"):
        key = parse_key(args.key) if args.key else 0x5A
        if not isinstance(key, int) or not 0 <= key <= 0xFF:
            sys.exit("--key for xor/perclass must be a single byte, e.g. 0x5A")
        blobs = (encode_xor(strings, key) if args.variant == "xor"
                 else encode_perclass(strings, key))
        decoded = (decode_xor(blobs, key) if args.variant == "xor"
                   else decode_perclass(blobs, key))
        aes_key = aes_iv = None
    else:
        aes_key = parse_key(args.key) if args.key else os.urandom(16)
        aes_iv = parse_key(args.iv) if args.iv else os.urandom(16)
        if not isinstance(aes_key, bytes) or len(aes_key) != 16:
            sys.exit("--key for aes must be 32 hex characters (16 bytes)")
        if not isinstance(aes_iv, bytes) or len(aes_iv) != 16:
            sys.exit("--iv for aes must be 32 hex characters (16 bytes)")
        blobs = encode_aes(strings, aes_key, aes_iv)
        decoded = decode_aes(blobs, aes_key, aes_iv)
        key = None

    # ---- verify -----------------------------------------------------------
    failures = [(i, a, b) for i, (a, b) in enumerate(zip(strings, decoded))
                if a != b]
    if failures:
        print("ROUND TRIP FAILED:", file=sys.stderr)
        for i, want, got in failures[:5]:
            print(f"  [{i}] want {want!r} got {got!r}", file=sys.stderr)
        return 1

    if args.self_test:
        print(f"round trip OK for {len(strings)} string(s), "
              f"variant={args.variant}")
        total = sum(len(b) for b in blobs)
        print(f"ciphertext total {total} bytes "
              f"(plaintext {sum(len(s.encode()) for s in strings)})")
        return 0

    # ---- emit -------------------------------------------------------------
    show_map = not args.no_index_map

    if args.variant == "xor":
        src = emit_xor(args.package, args.cls, key, blobs, strings, show_map)
    elif args.variant == "perclass":
        src = emit_perclass(args.package, args.cls, key, blobs, strings, show_map)
    else:
        src = emit_aes(args.package, args.cls, aes_key, aes_iv,
                       blobs, strings, show_map)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(src)
        print(f"wrote {args.out} ({len(strings)} strings, "
              f"variant={args.variant})", file=sys.stderr)
        if show_map:
            print("NOTE: the generated file contains an index->plaintext map "
                  "in comments.\n"
                  "      Pass --no-index-map for a build you intend to analyse.",
                  file=sys.stderr)
    else:
        print(src)

    # ---- the substitution the generator deliberately does not do ----------
    print("", file=sys.stderr)
    print("Now replace the constants at their POINT OF USE:", file=sys.stderr)
    print("", file=sys.stderr)
    for i, s in enumerate(strings[:6]):
        short = s if len(s) <= 40 else s[:37] + "..."
        print(f'    "{short}"  ->  {args.cls}.'
              f'{"a" if args.variant == "perclass" else "get"}({i})',
              file=sys.stderr)
    if len(strings) > 6:
        print(f"    ... and {len(strings) - 6} more", file=sys.stderr)
    print("", file=sys.stderr)
    print("Do NOT assign these to `static final String` fields. A real "
          "transform decrypts", file=sys.stderr)
    print("at the point of use, so the plaintext never sits in a field and "
          "the decryptor", file=sys.stderr)
    print("is called from hundreds of sites rather than one. That difference "
          "matters to", file=sys.stderr)
    print("an analyst, and building it wrong makes the lab too easy.",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
