#!/usr/bin/env python3
"""
apk-container-triage.py — run every ZIP-level attack-class check in
                          ../cheatsheet.md section 24 against one or more APKs
                          and print a pass/flag table with the next step for
                          each row.

WHAT IT DOES
    The cheatsheet gives you a table of container attack classes and a detection
    command for each. This runs all of them, in one pass over the file, and
    tells you what to do about each result.

      | Row                     | Checked by                                  |
      |-------------------------|---------------------------------------------|
      | Janus shape             | first four bytes vs 50 4B 03 04             |
      | Master Key class        | duplicate entry names in the central dir     |
      | LFH/CDFH divergence     | name, sizes, CRC and method compared         |
      | Unsigned trailing space | bytes after the EOCD; EOCD commentLength     |
      | Signing-block smuggling | ID-value pairs with no known ID              |
      | ZipSlip                 | entry names with '../' or a leading '/'      |
      | AXML parser confusion   | rawValue vs typedValue in the manifest       |

    Every row reports PASS, FLAG or N/A, and every FLAG carries the command you
    run next. Exit code is 0 when nothing is flagged, 1 when something is, so
    it drops into a pipeline.

HOW THIS DIFFERS FROM ../examples/parse_apk_zip.py
    The example is a teaching parser: it prints structure, and its output is
    something you read. This is the operational front end: it prints a verdict
    per attack class, and its output is something you act on. Use the example
    when you want to understand a file, this when you have forty of them and
    need to know which three to look at.

WHAT THIS WILL *NOT* TELL YOU
    - Whether the APK's signature verifies. Structure only. Run
      `apksigner verify -v --print-certs` alongside this, always.
    - Whether a FLAG is malicious. Repacking tools, obfuscators and old build
      chains produce odd containers by accident. Every FLAG is a lead.
    - Whether a PASS is safe. A structurally perfect container can hold a
      malicious DEX, a hardcoded key, and an exported provider. This checks the
      envelope, not the letter.
    - What the platform parsed from the manifest. The AXML row compares
      rawValue against typedValue inside the file. Only a device can tell you
      what PackageManager did with it: `adb shell dumpsys package <pkg>`.
    - Anything about splits. Run it against every APK `pm path` reports, not
      only base.apk.

HOW TO RUN
    python3 apk-container-triage.py app.apk
    python3 apk-container-triage.py *.apk
    python3 apk-container-triage.py app.apk --verbose
    python3 apk-container-triage.py app.apk --json
    python3 apk-container-triage.py app.apk --quiet    # one line per APK

    From the chapter directory:
        python3 scripts/apk-container-triage.py app.apk

REQUIREMENTS
    Python 3.8 or newer. Standard library only. Works on Windows, macOS, Linux.

RELATED
    ../cheatsheet.md section 24           the table this implements
    ../README.md section 18               each attack class in full
    ../examples/parse_apk_zip.py          the container parser
    ../examples/parse_signing_block.py    the signing block parser
    ../examples/parse_axml.py             the manifest parser

AUTHORISED TESTING ONLY.
"""

import argparse
import glob
import json
import os
import struct
import sys
import zlib

LFH_SIG = b"PK\x03\x04"
CD_SIG = b"PK\x01\x02"
EOCD_SIG = b"PK\x05\x06"
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"

KNOWN_BLOCK_IDS = {
    0x7109871A: "APK Signature Scheme v2",
    0xF05368C0: "APK Signature Scheme v3",
    0x1B93AD61: "APK Signature Scheme v3.1",
    0x42726577: "verity padding block",
    0x2B09189E: "source stamp, v1 layout",
    0x6DFF800D: "source stamp, v2 layout",
    0x504B4453: "AGP dependency metadata (observed)",
    0x2146444E: "Google Play metadata (observed)",
}

PASS, FLAG, NA = "PASS", "FLAG", "N/A"


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


class Row:
    def __init__(self, name, verdict, evidence, next_step):
        self.name = name
        self.verdict = verdict
        self.evidence = evidence
        self.next_step = next_step

    def as_dict(self):
        return {"check": self.name, "verdict": self.verdict,
                "evidence": self.evidence, "next_step": self.next_step}


# ----------------------------------------------------------------------
# the minimum container read the checks need
# ----------------------------------------------------------------------

class Container:
    """Just enough ZIP to answer the seven questions. For the full walk with
    every field printed, use ../examples/parse_apk_zip.py."""

    def __init__(self, data):
        self.data = data
        self.ok = False
        self.error = None
        self.entries = []
        self.eocd = None
        self.trailing = 0
        self.comment_len = 0
        self.block_pairs = []
        self.block_start = None
        self.block_consistent = None
        try:
            self._read()
            self.ok = True
        except Exception as exc:                     # noqa: BLE001
            self.error = str(exc)

    def _read(self):
        d = self.data
        n = len(d)
        window = max(0, n - (22 + 0xFFFF))
        eocd = -1
        pos = d.find(EOCD_SIG, window)
        while pos != -1:
            if pos + 22 <= n and pos + 22 + u16(d, pos + 20) == n:
                eocd = pos
            pos = d.find(EOCD_SIG, pos + 1)
        if eocd < 0:
            eocd = d.rfind(EOCD_SIG)
        if eocd < 0:
            raise ValueError("no EOCD signature - not a ZIP")

        self.eocd = eocd
        self.comment_len = u16(d, eocd + 20)
        self.trailing = n - (eocd + 22 + self.comment_len)
        total = u16(d, eocd + 10)
        cd_size = u32(d, eocd + 12)
        cd_off = u32(d, eocd + 16)
        self.declared_entries = total

        off, end = cd_off, min(cd_off + cd_size, n)
        while off + 46 <= end and d[off:off + 4] == CD_SIG:
            gpbf = u16(d, off + 8)
            n_len = u16(d, off + 28)
            m_len = u16(d, off + 30)
            k_len = u16(d, off + 32)
            name = d[off + 46:off + 46 + n_len].decode("utf-8", "replace")
            ent = {
                "name": name,
                "gpbf": gpbf,
                "method": u16(d, off + 10),
                "crc": u32(d, off + 16),
                "csize": u32(d, off + 20),
                "usize": u32(d, off + 24),
                "lfh": u32(d, off + 42),
                "divergences": [],
            }
            self.entries.append(ent)
            off += 46 + n_len + m_len + k_len

        for ent in self.entries:
            self._cross_check(ent)

        if cd_off >= 32 and d[cd_off - 16:cd_off] == APK_SIG_BLOCK_MAGIC:
            suffix = u64(d, cd_off - 24)
            start = cd_off - suffix - 8
            if 0 <= start < cd_off:
                self.block_start = start
                self.block_consistent = (u64(d, start) == suffix)
                p = start + 8
                limit = cd_off - 24
                while p + 12 <= limit:
                    pair_len = u64(d, p)
                    if pair_len < 4 or p + 8 + pair_len > limit + 8:
                        break
                    pair_id = u32(d, p + 8)
                    self.block_pairs.append(
                        {"id": pair_id, "length": pair_len - 4,
                         "offset": p,
                         "name": KNOWN_BLOCK_IDS.get(pair_id)})
                    p += 8 + pair_len

    def _cross_check(self, ent):
        d = self.data
        lo = ent["lfh"]
        if lo + 30 > len(d) or d[lo:lo + 4] != LFH_SIG:
            ent["divergences"].append(
                f"no local file header at 0x{lo:x}")
            return
        n_len = u16(d, lo + 26)
        m_len = u16(d, lo + 28)
        lname = d[lo + 30:lo + 30 + n_len].decode("utf-8", "replace")
        gpbf = u16(d, lo + 6)
        deferred = bool(gpbf & 0x0008)      # bit 3: sizes live in a descriptor

        if lname != ent["name"]:
            ent["divergences"].append(
                f"name central={ent['name']!r} local={lname!r}")
        if u16(d, lo + 8) != ent["method"]:
            ent["divergences"].append(
                f"method central={ent['method']} local={u16(d, lo + 8)}")
        if not deferred:
            if u32(d, lo + 18) != ent["csize"]:
                ent["divergences"].append(
                    f"csize central={ent['csize']} local={u32(d, lo + 18)}")
            if u32(d, lo + 22) != ent["usize"]:
                ent["divergences"].append(
                    f"usize central={ent['usize']} local={u32(d, lo + 22)}")
            if u32(d, lo + 14) != ent["crc"]:
                ent["divergences"].append(
                    f"crc central=0x{ent['crc']:08x} "
                    f"local=0x{u32(d, lo + 14):08x}")
        ent["local_name"] = lname
        ent["local_data_offset"] = lo + 30 + n_len + m_len

    def read_entry(self, name):
        for ent in self.entries:
            if ent["name"] != name or "local_data_offset" not in ent:
                continue
            blob = self.data[ent["local_data_offset"]:
                             ent["local_data_offset"] + ent["csize"]]
            if ent["method"] == 0:
                return blob
            if ent["method"] == 8:
                try:
                    return zlib.decompressobj(-15).decompress(blob)
                except zlib.error:
                    return None
            return None
        return None


# ----------------------------------------------------------------------
# the seven rows
# ----------------------------------------------------------------------

def row_janus(c):
    head = c.data[:4]
    if head == LFH_SIG:
        return Row("Janus shape (CVE-2017-13156)", PASS,
                   "file begins 50 4b 03 04", "")
    what = "unknown leading bytes"
    if c.data[:4] == b"dex\n":
        what = "'dex\\n' - a DEX file is prepended"
    return Row(
        "Janus shape (CVE-2017-13156)", FLAG,
        f"file begins {head.hex(' ')} ({what})",
        "apksigner verify -v <apk>   # v1-only + prepended data = Janus. "
        "Do not install it; preserve the sample.")


def row_master_key(c):
    if len(c.entries) != c.declared_entries:
        return Row(
            "Master Key class (CVE-2013-4787)", FLAG,
            f"the EOCD declares {c.declared_entries} entries but only "
            f"{len(c.entries)} central directory records could be walked",
            "python3 ../examples/parse_apk_zip.py <apk>   # a reader that "
            "trusts the count and one that walks until the records stop now "
            "see different archives. Check the first four bytes first: "
            "prepended data shifts every offset.")

    seen = {}
    for ent in c.entries:
        seen.setdefault(ent["name"], 0)
        seen[ent["name"]] += 1
    dupes = {k: v for k, v in seen.items() if v > 1}
    if not dupes:
        return Row("Master Key class (CVE-2013-4787)", PASS,
                   f"{len(c.entries)} entries, no duplicate names", "")
    listed = ", ".join(f"{k} x{v}" for k, v in sorted(dupes.items()))
    return Row(
        "Master Key class (CVE-2013-4787)", FLAG,
        f"duplicate entry names: {listed}",
        "python3 ../examples/parse_apk_zip.py <apk> --entries   # then extract "
        "BOTH copies by seeking to each local header offset and diff them. "
        "unzip and zipfile will only ever give you one.")


def row_lfh_cdfh(c):
    if not c.entries:
        return Row("LFH/CDFH divergence", NA,
                   "no central directory records were walked, so there is "
                   "nothing to compare",
                   "python3 ../examples/parse_apk_zip.py <apk>")
    bad = [e for e in c.entries if e["divergences"]]
    if not bad:
        return Row("LFH/CDFH divergence", PASS,
                   f"{len(c.entries)} entries agree in both headers", "")
    detail = "; ".join(
        f"{e['name']}: {', '.join(e['divergences'])}" for e in bad[:3])
    if len(bad) > 3:
        detail += f" (+{len(bad) - 3} more)"
    return Row(
        "LFH/CDFH divergence", FLAG, detail,
        "zipinfo -v <apk>   # prints both copies. The platform reads the "
        "central directory; find out which copy each of your tools believes.")


def row_trailing(c):
    problems = []
    if c.trailing > 0:
        problems.append(f"{c.trailing} bytes after the EOCD")
    elif c.trailing < 0:
        problems.append(
            f"the EOCD comment claims {-c.trailing} bytes past the end of file")
    if c.comment_len:
        problems.append(f"EOCD commentLength = {c.comment_len}")
    if not problems:
        return Row("Unsigned trailing space", PASS,
                   "EOCD ends exactly at end of file, comment length 0", "")
    end = c.eocd + 22 + c.comment_len
    return Row(
        "Unsigned trailing space", FLAG, "; ".join(problems),
        f"dd if=<apk> bs=1 skip={end} of=/tmp/tail.bin && file /tmp/tail.bin"
        "   # no signing scheme covers these bytes")


def row_signing_block(c):
    if c.block_start is None:
        return Row(
            "Signing-block smuggling", NA,
            "no APK Signing Block - this APK has no v2/v3 signature",
            "unzip -l <apk> | grep -E 'META-INF/.*\\.(SF|RSA|DSA|EC)$'   "
            "# v1-only? then the Janus and Master Key classes both apply.")
    unknown = [p for p in c.block_pairs if p["name"] is None]
    if c.block_consistent is False:
        return Row(
            "Signing-block smuggling", FLAG,
            "the block's size prefix and size suffix disagree",
            "python3 ../examples/parse_signing_block.py <apk>   # a forward "
            "walk and a backward walk now see different blocks.")
    if not unknown:
        named = ", ".join(
            f"0x{p['id']:08x}" for p in c.block_pairs)
        return Row("Signing-block smuggling", PASS,
                   f"{len(c.block_pairs)} pairs, all named ({named})", "")
    detail = ", ".join(
        f"0x{p['id']:08x} ({p['length']} bytes)" for p in unknown)
    return Row(
        "Signing-block smuggling", FLAG,
        f"{len(unknown)} unnamed ID-value pair(s): {detail}",
        "python3 ../examples/parse_signing_block.py <apk> --dump-unknown ./blobs"
        "   # not covered by any digest, so this is signature-safe storage.")


def row_zipslip(c):
    bad = []
    for ent in c.entries:
        name = ent["name"]
        if (name.startswith("/") or name.startswith("\\")
                or "../" in name or "..\\" in name
                or (len(name) > 1 and name[1] == ":")):
            bad.append(name)
    if not bad:
        return Row("ZipSlip entry names", PASS,
                   "no traversal sequences or absolute paths", "")
    return Row(
        "ZipSlip entry names", FLAG,
        f"{len(bad)} unsafe name(s): {bad[:3]}",
        "The installer refuses these, so they target whatever ELSE unpacks "
        "the file. Check your own sandbox and any app that extracts it. "
        "See ../README.md section 18.3.")


def row_axml(c, verbose=False):
    """A partial, file-only check for the rawValue/typedValue divergence and
    for a non-standard attributeSize. It cannot be conclusive; only a device
    can tell you what PackageManager parsed."""
    blob = c.read_entry("AndroidManifest.xml")
    if not blob:
        return Row("AXML parser confusion", NA,
                   "AndroidManifest.xml missing or undecompressible",
                   "python3 ../examples/parse_apk_zip.py <apk> --entries")
    if len(blob) < 8 or u16(blob, 0) != 0x0003:
        return Row("AXML parser confusion", NA,
                   f"manifest does not start with RES_XML_TYPE "
                   f"(got 0x{u16(blob, 0):04x})",
                   "python3 ../examples/parse_axml.py --extract <apk>")

    problems = []
    try:
        problems = scan_axml(blob)
    except Exception as exc:                          # noqa: BLE001
        return Row("AXML parser confusion", FLAG,
                   f"the manifest would not parse: {exc}",
                   "python3 ../examples/parse_axml.py --extract <apk>   "
                   "# a manifest that a careful parser refuses and the "
                   "platform accepts is exactly the interesting case.")

    if not problems:
        return Row("AXML parser confusion", PASS,
                   "no rawValue/typedValue divergence, attributeSize is 20 "
                   "throughout", "")
    return Row(
        "AXML parser confusion", FLAG, "; ".join(problems[:4]),
        "python3 ../examples/parse_axml.py --extract <apk>   then the "
        "three-way read: apktool d, aapt2 dump xmltree, and "
        "`adb shell dumpsys package <pkg>`. The device is the authority. "
        "See ../labs/lab-04-ctf-the-lying-manifest.md.")


def scan_axml(blob):
    """Minimal AXML pass: string pool, then every START_ELEMENT's attribute
    records. Deliberately narrow - the full parser is in ../examples/."""
    problems = []
    pool = []
    off = u16(blob, 2)                # root headerSize
    limit = min(u32(blob, 4), len(blob))

    while off + 8 <= limit:
        ctype, header_size, size = struct.unpack_from("<HHI", blob, off)
        if size == 0 or off + size > limit:
            break
        if ctype == 0x0001 and not pool:
            count = u32(blob, off + 8)
            flags = u32(blob, off + 16)
            strings_start = u32(blob, off + 20)
            utf8 = bool(flags & 0x100)
            offsets_at = off + header_size
            for i in range(count):
                if offsets_at + 4 * i + 4 > off + size:
                    break
                p = off + strings_start + u32(blob, offsets_at + 4 * i)
                if p >= len(blob):
                    pool.append(None)
                    continue
                try:
                    if utf8:
                        cn = blob[p]
                        p += 2 if cn & 0x80 else 1
                        bn = blob[p]
                        p += 2 if bn & 0x80 else 1
                        bn = bn & 0x7F
                        pool.append(blob[p:p + bn].decode("utf-8", "replace"))
                    else:
                        cn = u16(blob, p)
                        p += 2
                        if cn & 0x8000:
                            cn = ((cn & 0x7FFF) << 16) | u16(blob, p)
                            p += 2
                        pool.append(
                            blob[p:p + cn * 2].decode("utf-16-le", "replace"))
                except Exception:                     # noqa: BLE001
                    pool.append(None)
        elif ctype == 0x0102:                          # START_ELEMENT
            base = off + header_size
            attr_start = u16(blob, base + 8)
            attr_size = u16(blob, base + 10)
            attr_count = u16(blob, base + 12)
            ename = pool[u32(blob, base + 4)] if (
                u32(blob, base + 4) < len(pool)) else "?"
            if attr_size != 20:
                problems.append(
                    f"<{ename}> declares attributeSize {attr_size}, not 20")
            for i in range(attr_count):
                rec = base + attr_start + i * attr_size
                if rec + 20 > off + size:
                    problems.append(
                        f"<{ename}> attribute {i} runs past its chunk")
                    break
                name_idx = struct.unpack_from("<i", blob, rec + 4)[0]
                raw_idx = struct.unpack_from("<i", blob, rec + 8)[0]
                dtype = blob[rec + 15]
                data = u32(blob, rec + 16)
                if raw_idx < 0 or dtype == 0x03:
                    continue
                raw = pool[raw_idx] if raw_idx < len(pool) else None
                aname = pool[name_idx] if 0 <= name_idx < len(pool) else "?"
                if raw is None:
                    continue
                if dtype == 0x12:
                    typed = "true" if data else "false"
                elif dtype == 0x10:
                    typed = str(data)
                else:
                    continue
                if raw.strip().lower() != typed:
                    problems.append(
                        f"<{ename}> {aname}: rawValue={raw!r} but typedValue="
                        f"{typed}")
        off += size
    return problems


CHECKS = [
    ("janus", row_janus),
    ("master-key", row_master_key),
    ("lfh-cdfh", row_lfh_cdfh),
    ("trailing", row_trailing),
    ("signing-block", row_signing_block),
    ("zipslip", row_zipslip),
]


def triage(path):
    with open(path, "rb") as fh:
        data = fh.read()
    c = Container(data)
    if not c.ok:
        return c, [Row("container", FLAG, f"unreadable: {c.error}",
                       "python3 ../examples/parse_apk_zip.py <apk>   "
                       "# a container this tool cannot read but the platform "
                       "can install is itself the finding.")]
    rows = [fn(c) for _, fn in CHECKS]
    rows.append(row_axml(c))
    return c, rows


def main():
    ap = argparse.ArgumentParser(
        description="Run the chapter-10 container attack-class checks")
    ap.add_argument("paths", nargs="+", help="APK files (globs are expanded)")
    ap.add_argument("--verbose", action="store_true",
                    help="print evidence for PASS rows too")
    ap.add_argument("--quiet", action="store_true",
                    help="one summary line per APK")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    targets = []
    for pattern in args.paths:
        hits = glob.glob(pattern)
        targets.extend(hits if hits else [pattern])

    results = []
    worst = 0
    for path in targets:
        if not os.path.isfile(path):
            print(f"error: {path}: not a file", file=sys.stderr)
            worst = max(worst, 2)
            continue
        try:
            container, rows = triage(path)
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            worst = max(worst, 2)
            continue

        flags = [r for r in rows if r.verdict == FLAG]
        if flags:
            worst = max(worst, 1)
        results.append({"path": path,
                        "flags": len(flags),
                        "rows": [r.as_dict() for r in rows]})

        if args.json:
            continue
        if args.quiet:
            state = f"{len(flags)} FLAG" if flags else "clean"
            print(f"{state:<10} {path}")
            continue

        size = os.path.getsize(path)
        print(f"\n=== {path} ({size:,} bytes) ===\n")
        print(f"  {'check':<34} {'verdict':<8} evidence")
        print(f"  {'-' * 34} {'-' * 8} {'-' * 30}")
        for r in rows:
            print(f"  {r.name:<34} {r.verdict:<8} {r.evidence}")
        if flags:
            print("\n  -- next steps --")
            for r in flags:
                print(f"\n  {r.name}")
                print(f"    {r.next_step}")
        elif args.verbose:
            print("\n  Nothing flagged at the container layer.")
        print("\n  Reminder: this checks the envelope. Run "
              "`apksigner verify -v --print-certs` for the signature,")
        print("  and read the manifest on a device with `dumpsys package` for "
              "the platform's own view.")

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    print()
    return worst


if __name__ == "__main__":
    sys.exit(main())
