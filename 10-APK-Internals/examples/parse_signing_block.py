#!/usr/bin/env python3
"""
parse_signing_block.py — walk the APK Signing Block, name every ID-value pair,
                         and dump the ones nobody can name.

WHAT IT DOES
    Implements the structures documented in ../README.md section 6.5:

        u64      sizeOfBlock                (excluding this field)
        repeat { u64 pairLength; u32 id; byte[] value }
        u64      sizeOfBlock                (must equal the first)
        char[16] "APK Sig Block 42"

    It locates the block the way the platform does - EOCD, central directory
    offset, then 16 bytes backwards for the magic - reports the block's start
    and end offsets, checks that the size prefix equals the size suffix, and
    walks every pair.

    Known IDs are named. UNKNOWN IDs are dumped: length, entropy, first bytes,
    and any recognisable magic inside them. That is the point of the tool.

WHY UNKNOWN PAIRS MATTER
    The v2/v3 digests cover the entry data, the central directory and the EOCD.
    They deliberately do NOT cover the signing block, because the signature
    lives inside it and cannot digest itself. Unknown IDs are ignored by design
    so that future schemes do not break old verifiers.

    Put those two facts together: an ID-value pair with an unrecognised ID is
    arbitrary attacker-chosen data riding inside an APK that verifies perfectly.
    It is not a signature bypass - the code that runs is still the code that was
    signed - but it is signature-safe storage, invisible to every tool that
    enumerates ZIP entries. Enumerate the pairs on every triage. Anything you
    cannot name deserves a look.

WHAT THIS WILL *NOT* TELL YOU
    - Whether any signature is VALID. Nothing here verifies a digest or checks a
      public key against a signature. The presence of a v2 pair means a v2
      structure exists, not that it verifies. `apksigner verify -v` is the
      authority and this tool is not a substitute for it.
    - Whether the certificate is trustworthy. --dump-certs gives you DER bytes.
      Whether `CN=Android Debug` matters, or whether a self-signed certificate
      is expected, is your judgement, not the tool's.
    - What an unknown blob IS. It reports length, entropy and any magic bytes it
      recognises. Identifying the payload is manual work.
    - Anything about v1 (JAR) signing beyond noting whether META-INF signature
      files exist. v1 lives in ZIP entries, not in this block.
    - Anything about v4. The v4 signature lives in a SEPARATE file next to the
      APK, `<name>.apk.idsig`, and is not in this block at all.

HOW TO RUN
    python3 parse_signing_block.py app.apk
    python3 parse_signing_block.py app.apk --verbose
    python3 parse_signing_block.py --dump-certs app.apk
    python3 parse_signing_block.py app.apk --dump-unknown ./blobs
    python3 parse_signing_block.py app.apk --json

    # Read a dumped certificate the way apksigner would have shown it
    python3 parse_signing_block.py --dump-certs app.apk
    openssl x509 -inform DER -in signer0_cert0.der -noout -text

    Run it from the chapter directory exactly as the chapter prints it:
        python3 examples/parse_signing_block.py app.apk
        python3 examples/parse_signing_block.py --dump-certs app.apk

    It needs no META-INF, no `apksigner`, no Java and no network. A v2/v3-only
    APK with no META-INF directory at all parses exactly the same way.

REQUIREMENTS
    Python 3.8 or newer. Standard library only. Works on Windows, macOS, Linux.

RELATED
    ../README.md section 6.5              the four signing schemes
    ../README.md section 18.4             signing-block smuggling
    ../labs/lab-01-dissecting-the-apk-byte-by-byte.md   step 2.4, by hand
    ./parse_apk_zip.py                    the container this block sits in

AUTHORISED TESTING ONLY.
"""

import argparse
import hashlib
import json
import math
import os
import struct
import sys

EOCD_SIG = b"PK\x05\x06"
CD_SIG = b"PK\x01\x02"
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"

EOCD_FIXED = 22
CDFH_FIXED = 46

V2_ID = 0x7109871A
V3_ID = 0xF05368C0
V31_ID = 0x1B93AD61

# README section 6.5 and labs/lab-01 step 2.5. IDs marked "observed" are not in
# any published specification; they are what turns up in APKs in the wild, and
# they are named here so that you can concentrate on the ones that do not.
BLOCK_IDS = {
    V2_ID: ("APK Signature Scheme v2", "spec"),
    V3_ID: ("APK Signature Scheme v3", "spec"),
    V31_ID: ("APK Signature Scheme v3.1", "spec"),
    0x42726577: ("verity padding block", "spec"),
    0x2B09189E: ("source stamp, v1 layout", "spec"),
    0x6DFF800D: ("source stamp, v2 layout", "spec"),
    0x504B4453: ("AGP dependency metadata", "observed"),
    0x2146444E: ("Google Play metadata, added at serving time", "observed"),
}

# Signature algorithm IDs - cheatsheet.md section 14.
SIG_ALGOS = {
    0x0101: "RSASSA-PSS, SHA-256",
    0x0102: "RSASSA-PSS, SHA-512",
    0x0103: "RSASSA-PKCS1-v1_5, SHA-256",
    0x0104: "RSASSA-PKCS1-v1_5, SHA-512",
    0x0201: "ECDSA, SHA-256",
    0x0202: "ECDSA, SHA-512",
    0x0301: "DSA, SHA-256",
    0x0421: "verity RSA, SHA-256",
    0x0423: "verity ECDSA, SHA-256",
    0x0425: "verity DSA, SHA-256",
}

# Magic bytes worth naming inside an unknown blob.
BLOB_MAGIC = [
    (b"dex\n", "a DEX file"),
    (b"PK\x03\x04", "a ZIP/APK/JAR"),
    (b"\x7fELF", "an ELF binary"),
    (b"\x1f\x8b", "gzip data"),
    (b"\x89PNG", "a PNG image"),
    (b"BZh", "bzip2 data"),
    (b"\xfd7zXZ", "xz data"),
    (b"{", "possibly JSON"),
    (b"<?xml", "text XML"),
    (b"\x03\x00\x08\x00", "Android binary XML (AXML)"),
    (b"\x30\x82", "a DER SEQUENCE - probably an X.509 certificate or key"),
]


class BlockError(Exception):
    """Raised when the signing block cannot be located or walked."""


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


def entropy(blob):
    """Shannon entropy in bits per byte. 8.0 means indistinguishable from
    random, which is what encrypted and compressed payloads look like."""
    if not blob:
        return 0.0
    counts = [0] * 256
    for b in blob:
        counts[b] += 1
    n = len(blob)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def identify(blob):
    for magic, what in BLOB_MAGIC:
        if blob.startswith(magic):
            return what
    printable = sum(1 for b in blob[:256] if 0x20 <= b < 0x7F or b in (9, 10, 13))
    if blob and printable / min(len(blob), 256) > 0.9:
        return "mostly printable text"
    return None


# ----------------------------------------------------------------------
# locating the block
# ----------------------------------------------------------------------

def find_eocd(data):
    n = len(data)
    if n < EOCD_FIXED:
        raise BlockError(f"file is {n} bytes; too small to be a ZIP")
    window = max(0, n - (EOCD_FIXED + 0xFFFF))
    best = -1
    pos = data.find(EOCD_SIG, window)
    while pos != -1:
        if pos + EOCD_FIXED <= n:
            comment_len = u16(data, pos + 20)
            if pos + EOCD_FIXED + comment_len == n:
                best = pos
        pos = data.find(EOCD_SIG, pos + 1)
    if best < 0:
        best = data.rfind(EOCD_SIG)
    if best < 0:
        raise BlockError("no EOCD signature (50 4B 05 06) - not a ZIP")
    return best


def v1_evidence(data, cd_offset, cd_size):
    """Walk the central directory just far enough to say whether v1 signature
    files exist. Purely informational: this tool does not need META-INF."""
    names = []
    off, end = cd_offset, min(cd_offset + cd_size, len(data))
    while off + CDFH_FIXED <= end and data[off:off + 4] == CD_SIG:
        n_len = u16(data, off + 28)
        m_len = u16(data, off + 30)
        k_len = u16(data, off + 32)
        name = data[off + CDFH_FIXED:off + CDFH_FIXED + n_len].decode(
            "utf-8", "replace")
        if name.upper().startswith("META-INF/"):
            names.append(name)
        off += CDFH_FIXED + n_len + m_len + k_len
    sig_files = [n for n in names
                 if n.upper().endswith((".SF", ".RSA", ".DSA", ".EC"))]
    return names, sig_files


class SigningBlock:

    def __init__(self, data, path="<memory>"):
        self.data = data
        self.path = path
        self.pairs = []
        self.warnings = []

        self.eocd_offset = find_eocd(data)
        self.cd_offset = u32(data, self.eocd_offset + 16)
        self.cd_size = u32(data, self.eocd_offset + 12)
        self.meta_inf, self.v1_files = v1_evidence(
            data, self.cd_offset, self.cd_size)

        if self.cd_offset < 32 or self.cd_offset > len(data):
            raise BlockError(
                f"central directory offset 0x{self.cd_offset:x} is not usable "
                f"in a {len(data)}-byte file")

        if data[self.cd_offset - 16:self.cd_offset] != APK_SIG_BLOCK_MAGIC:
            raise BlockError(
                "no 'APK Sig Block 42' magic in the 16 bytes before the central "
                f"directory (0x{self.cd_offset - 16:x}) - this APK carries no "
                "v2/v3 signature block. "
                + (f"It does have v1 material: {self.v1_files}."
                   if self.v1_files else "It has no v1 material either."))

        self.size_suffix = u64(data, self.cd_offset - 24)
        self.start = self.cd_offset - self.size_suffix - 8
        if self.start < 0 or self.start >= self.cd_offset:
            raise BlockError(
                f"size suffix {self.size_suffix} puts the block start at "
                f"{self.start}, which is impossible")
        self.size_prefix = u64(data, self.start)
        self.end = self.cd_offset
        self.total_bytes = self.end - self.start

        if self.size_prefix != self.size_suffix:
            self.warnings.append(
                f"size prefix ({self.size_prefix}) != size suffix "
                f"({self.size_suffix}); the two MUST be equal. A forward walk "
                "and a backward walk now disagree about the block's extent.")

        self._walk_pairs()

    def _walk_pairs(self):
        d = self.data
        p = self.start + 8
        pairs_end = self.cd_offset - 24     # where the trailing size field sits

        while p < pairs_end:
            if p + 12 > pairs_end:
                self.warnings.append(
                    f"{pairs_end - p} bytes left at 0x{p:x} - too few for "
                    "another pair header; the block is malformed or padded")
                break
            pair_len = u64(d, p)
            if pair_len < 4:
                self.warnings.append(
                    f"pair at 0x{p:x} declares length {pair_len} (minimum is 4, "
                    "the ID alone) - stopping the walk")
                break
            if p + 8 + pair_len > pairs_end + 8:
                self.warnings.append(
                    f"pair at 0x{p:x} declares length {pair_len}, which runs "
                    "past the end of the block - stopping the walk")
                break

            pair_id = u32(d, p + 8)
            value = d[p + 12:p + 8 + pair_len]
            name, source = BLOCK_IDS.get(pair_id, (None, None))
            self.pairs.append({
                "offset": p,
                "id": pair_id,
                "pair_length": pair_len,
                "value_length": len(value),
                "name": name,
                "source": source,
                "known": name is not None,
                "value": value,
            })
            p += 8 + pair_len

        ids = [x["id"] for x in self.pairs]
        if len(ids) != len(set(ids)):
            self.warnings.append(
                "the same block ID appears more than once. The verifier takes "
                "the first or the last depending on implementation; that is a "
                "divergence primitive.")

    # ------------------------------------------------------------------
    # certificate extraction
    # ------------------------------------------------------------------

    def signers(self):
        """Parse the v2/v3/v3.1 signer structures well enough to recover the
        X.509 certificates. Every length prefix is a little-endian uint32.

            value        = length-prefixed sequence of signers
            signer (v2)  = signed data || signatures || public key
            signer (v3)  = signed data || minSdk || maxSdk || signatures || key
            signed data  = digests || certificates || [minSdk, maxSdk] || attrs
            certificates = length-prefixed sequence of DER X.509 certificates
        """
        out = []
        for pair in self.pairs:
            if pair["id"] not in (V2_ID, V3_ID, V31_ID):
                continue
            scheme = BLOCK_IDS[pair["id"]][0]
            try:
                signers = list(read_lp_sequence(pair["value"]))
            except ValueError as exc:
                self.warnings.append(f"{scheme}: {exc}")
                continue

            for i, signer in enumerate(signers):
                try:
                    entry = parse_signer(signer, v3=(pair["id"] != V2_ID))
                except ValueError as exc:
                    self.warnings.append(f"{scheme} signer {i}: {exc}")
                    continue
                entry["scheme"] = scheme
                entry["scheme_id"] = pair["id"]
                entry["index"] = i
                out.append(entry)
        return out

    def summary(self, include_values=False):
        return {
            "path": self.path,
            "file_size": len(self.data),
            "eocd_offset": self.eocd_offset,
            "central_directory_offset": self.cd_offset,
            "block_start": self.start,
            "block_end": self.end,
            "block_total_bytes": self.total_bytes,
            "size_prefix": self.size_prefix,
            "size_suffix": self.size_suffix,
            "size_fields_agree": self.size_prefix == self.size_suffix,
            "v1_signature_files": self.v1_files,
            "pairs": [
                {k: (v.hex() if include_values and k == "value" else v)
                 for k, v in pair.items() if k != "value" or include_values}
                for pair in self.pairs
            ],
            "warnings": self.warnings,
        }


def read_lp_sequence(blob):
    """Yield each element of a length-prefixed sequence of length-prefixed
    elements. The outer length prefix has already been consumed by the caller
    when the sequence is itself a field."""
    off = 0
    n = len(blob)
    while off < n:
        if off + 4 > n:
            raise ValueError(f"truncated length prefix at offset {off}")
        length = struct.unpack_from("<I", blob, off)[0]
        off += 4
        if off + length > n:
            raise ValueError(
                f"element at {off} declares {length} bytes but only "
                f"{n - off} remain")
        yield blob[off:off + length]
        off += length


def read_lp_field(blob, off):
    """Read one length-prefixed field. Returns (bytes, new_offset)."""
    if off + 4 > len(blob):
        raise ValueError(f"truncated length prefix at {off}")
    length = struct.unpack_from("<I", blob, off)[0]
    off += 4
    if off + length > len(blob):
        raise ValueError(
            f"field at {off} declares {length} bytes but only "
            f"{len(blob) - off} remain")
    return blob[off:off + length], off + length


def parse_signer(signer, v3):
    off = 0
    signed_data, off = read_lp_field(signer, off)

    min_sdk = max_sdk = None
    if v3:
        if off + 8 > len(signer):
            raise ValueError("v3 signer is too short for minSdk/maxSdk")
        min_sdk, max_sdk = struct.unpack_from("<II", signer, off)
        off += 8

    signatures_blob, off = read_lp_field(signer, off)
    public_key, off = read_lp_field(signer, off)

    # signed data: digests, certificates, [minSdk, maxSdk for v3], attributes
    so = 0
    digests_blob, so = read_lp_field(signed_data, so)
    certs_blob, so = read_lp_field(signed_data, so)

    digests = []
    for element in read_lp_sequence(digests_blob):
        if len(element) < 8:
            continue
        algo = struct.unpack_from("<I", element, 0)[0]
        digest, _ = read_lp_field(element, 4)
        digests.append({
            "algorithm_id": algo,
            "algorithm": SIG_ALGOS.get(algo, "unknown"),
            "digest": digest.hex(),
        })

    signatures = []
    for element in read_lp_sequence(signatures_blob):
        if len(element) < 8:
            continue
        algo = struct.unpack_from("<I", element, 0)[0]
        sig, _ = read_lp_field(element, 4)
        signatures.append({
            "algorithm_id": algo,
            "algorithm": SIG_ALGOS.get(algo, "unknown"),
            "signature_bytes": len(sig),
        })

    certs = []
    for der in read_lp_sequence(certs_blob):
        certs.append({
            "der": der,
            "length": len(der),
            "sha256": hashlib.sha256(der).hexdigest(),
            "looks_like_der": der[:1] == b"\x30",
        })

    return {
        "min_sdk": min_sdk,
        "max_sdk": max_sdk,
        "public_key_bytes": len(public_key),
        "digests": digests,
        "signatures": signatures,
        "certificates": certs,
    }


# ----------------------------------------------------------------------
# reporting
# ----------------------------------------------------------------------

def print_report(sb, args):
    print(f"\n=== {sb.path} ({len(sb.data):,} bytes) ===\n")

    print("-- block --")
    print(f"  {'EOCD offset':<24} 0x{sb.eocd_offset:x}")
    print(f"  {'central directory':<24} 0x{sb.cd_offset:x}")
    print(f"  {'block start offset':<24} 0x{sb.start:x}  ({sb.start})")
    print(f"  {'block end offset':<24} 0x{sb.end:x}  ({sb.end})")
    print(f"  {'block total bytes':<24} {sb.total_bytes}  "
          f"(8 + sizeOfBlock)")
    print(f"  {'size prefix':<24} {sb.size_prefix}")
    print(f"  {'size suffix':<24} {sb.size_suffix}")
    agree = "AGREE" if sb.size_prefix == sb.size_suffix else "DISAGREE"
    print(f"  {'prefix == suffix':<24} {agree}")
    print(f"  {'ID-value pairs':<24} {len(sb.pairs)}")
    if sb.v1_files:
        print(f"  {'v1 material present':<24} {', '.join(sb.v1_files)}")
    else:
        print(f"  {'v1 material present':<24} none "
              f"(this APK has no JAR signature)")

    print("\n-- ID-value pairs --")
    unknown = []
    for pair in sb.pairs:
        if pair["known"]:
            tag = f"{pair['name']} [{pair['source']}]"
        else:
            tag = "*** UNKNOWN ID ***"
            unknown.append(pair)
        print(f"  0x{pair['id']:08x}  offset=0x{pair['offset']:<8x} "
              f"value={pair['value_length']:>8} bytes   {tag}")

    if unknown:
        print(f"\n-- unknown pairs ({len(unknown)}) --")
        print("  The signing block is not covered by any digest, so these bytes")
        print("  ride inside a validly-signed APK. Account for every one.")
        for pair in unknown:
            v = pair["value"]
            ent = entropy(v)
            guess = identify(v)
            print(f"\n  id 0x{pair['id']:08x} at 0x{pair['offset']:x} "
                  f"({len(v)} bytes)")
            print(f"    entropy   {ent:.2f} bits/byte"
                  + ("  (indistinguishable from random - encrypted or "
                     "compressed)" if ent > 7.5 else ""))
            if guess:
                print(f"    looks like {guess}")
            head = v[:48]
            print(f"    first {len(head)} bytes: {head.hex(' ')}")
            printable = "".join(
                chr(b) if 0x20 <= b < 0x7F else "." for b in head)
            print(f"    as text            : {printable}")
            if args.dump_unknown:
                os.makedirs(args.dump_unknown, exist_ok=True)
                out = os.path.join(
                    args.dump_unknown, f"block_{pair['id']:08x}.bin")
                with open(out, "wb") as fh:
                    fh.write(v)
                print(f"    written to {out}")
    else:
        print("\n  Every pair has a name. That is the expected outcome for an "
              "app built\n  and signed by normal tooling.")

    # --- signers ------------------------------------------------------
    signers = sb.signers()
    if signers:
        print(f"\n-- signers ({len(signers)}) --")
        for s in signers:
            print(f"\n  {s['scheme']} signer #{s['index']}")
            if s["min_sdk"] is not None:
                print(f"    applies to API {s['min_sdk']} .. {s['max_sdk']}")
            print(f"    public key         {s['public_key_bytes']} bytes")
            for d in s["digests"]:
                print(f"    digest             {d['algorithm']} "
                      f"(0x{d['algorithm_id']:04x})")
                if args.verbose:
                    print(f"                       {d['digest']}")
            for sig in s["signatures"]:
                print(f"    signature          {sig['algorithm']} "
                      f"(0x{sig['algorithm_id']:04x}), "
                      f"{sig['signature_bytes']} bytes")
            for j, c in enumerate(s["certificates"]):
                shape = "DER" if c["looks_like_der"] else "NOT DER - suspicious"
                print(f"    certificate {j}      {c['length']} bytes ({shape})")
                print(f"      SHA-256          {c['sha256']}")
                print("      (this is the same digest apksigner prints as "
                      "'certificate SHA-256 digest')")

    if args.dump_certs:
        written = dump_certs(sb, signers, args.out_dir)
        print(f"\n-- certificates written ({len(written)}) --")
        for path in written:
            print(f"  {path}")
        if written:
            print("\n  Read one with:")
            print(f"    openssl x509 -inform DER -in {written[0]} -noout -text")
            print(f"    openssl x509 -inform DER -in {written[0]} -noout "
                  "-subject -issuer -dates -fingerprint -sha256")
        else:
            print("  none - no v2/v3 signer structure was parseable")

    if sb.warnings:
        print(f"\n-- warnings ({len(sb.warnings)}) --")
        for w in sb.warnings:
            print(f"  ! {w}")

    print("\n-- reminder --")
    print("  Structure only. Nothing here was verified cryptographically.")
    print("  Confirm with: apksigner verify -v --print-certs <apk>")
    print()


def dump_certs(sb, signers, out_dir):
    written = []
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    for s in signers:
        for j, c in enumerate(s["certificates"]):
            name = f"signer{s['index']}_cert{j}.der"
            if s["scheme_id"] != V2_ID and any(
                    x["scheme_id"] == V2_ID for x in signers):
                # Keep v2 and v3 outputs distinguishable when both are present.
                name = f"signer{s['index']}_cert{j}_v3.der"
            path = os.path.join(out_dir, name) if out_dir else name
            with open(path, "wb") as fh:
                fh.write(c["der"])
            written.append(path)
    return written


def main():
    ap = argparse.ArgumentParser(
        description="Walk an APK Signing Block and name every ID-value pair")
    ap.add_argument("path", help="the .apk to read")
    ap.add_argument("--dump-certs", action="store_true",
                    help="write each signer's X.509 certificates as "
                         "signer<N>_cert<M>.der")
    ap.add_argument("--out-dir", default="",
                    help="directory for --dump-certs output "
                         "(default: current directory)")
    ap.add_argument("--dump-unknown", metavar="DIR",
                    help="write the value of every unknown ID to DIR")
    ap.add_argument("--verbose", action="store_true",
                    help="also print digest values")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    try:
        with open(args.path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        sb = SigningBlock(data, args.path)
    except BlockError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("\nIf you expected a v2/v3 signature, check the container first:",
              file=sys.stderr)
        print(f"  python3 parse_apk_zip.py {args.path}", file=sys.stderr)
        return 3

    if args.json:
        out = sb.summary(include_values=False)
        signers_json = []
        for s in sb.signers():
            entry = {k: v for k, v in s.items() if k != "certificates"}
            entry["certificates"] = [
                {kk: vv for kk, vv in c.items() if kk != "der"}
                for c in s["certificates"]]
            signers_json.append(entry)
        out["signers"] = signers_json
        print(json.dumps(out, indent=2, default=str))
        if args.dump_certs:
            dump_certs(sb, sb.signers(), args.out_dir)
        return 0

    print_report(sb, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
