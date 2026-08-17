#!/usr/bin/env python3
"""
parse_apk_zip.py — walk an APK's ZIP container by hand and report every
                   structural anomaly the format permits.

WHAT IT DOES
    Implements the structures documented in ../README.md section 6.1, using only
    the Python standard library:

      - End Of Central Directory, found by scanning backwards       (README 6.1)
      - every Central Directory File Header                         (README 6.1)
      - every Local File Header, read at the offset the central
        directory points to                                         (README 6.1)
      - the APK Signing Block boundary, if one is present            (README 6.5)

    It then cross-checks the two copies of every entry's metadata and reports:

      | Check                        | Attack class it catches            |
      |------------------------------|------------------------------------|
      | first 4 bytes != 50 4B 03 04 | Janus, CVE-2017-13156  (README 18.1)|
      | duplicate entry names        | Master Key, CVE-2013-4787 (18.2)   |
      | LFH vs CDFH divergence       | parser disagreement generally       |
      | '../' or leading '/' in name | ZipSlip                (README 18.3)|
      | data after the EOCD          | unsigned trailing space             |
      | non-zero EOCD commentLength  | hidden data / EOCD confusion        |
      | gaps and overlaps in entry   | smuggled bytes between entries      |
      |   data coverage              |                                     |

WHY THIS DOES NOT USE `zipfile`
    Because `zipfile` is a good ZIP reader, and a good ZIP reader is exactly the
    wrong tool here. It reads the central directory, silently ignores whatever
    the local file headers say, quietly drops the earlier of two entries with
    the same name, and tolerates trailing data without telling you. Every one of
    those conveniences erases a signal you came here to find. The divergence is
    the finding; a library that resolves it for you has thrown the finding away.

    `--zipfile-crosscheck` runs `zipfile` deliberately, side by side, and prints
    what it saw versus what the raw walk saw. That comparison is the point of
    the option — it is a demonstration, not the parser.

WHAT THIS WILL *NOT* TELL YOU
    - Whether the APK's signature verifies. This tool reads structure, never
      cryptography. Use `apksigner verify -v`, and see parse_signing_block.py
      in this directory for what is inside the signing block.
    - What is *inside* any entry. A clean container can hold a malicious
      classes.dex. See ../../12-DEX-Internals/examples/dex_parser.py.
    - Which parser wins when the local and central headers disagree. It tells
      you THAT they disagree. Which reading the platform uses is a question you
      answer on a device with `dumpsys package`, not from a file on your disk.
    - Whether an anomaly is malicious. Zip tools in the wild emit odd archives
      by accident all the time. A finding here is a lead that needs a human.
    - Zip64. Zip64 records are detected and reported, but their 64-bit values
      are not resolved; an APK that needs them is either enormous or crafted,
      and both deserve manual reading rather than a silent best guess.

HOW TO RUN
    python3 parse_apk_zip.py app.apk
    python3 parse_apk_zip.py app.apk --entries            # every entry, not just findings
    python3 parse_apk_zip.py app.apk --entries --limit 0  # no truncation
    python3 parse_apk_zip.py app.apk | grep -i duplicate
    python3 parse_apk_zip.py app.apk --zipfile-crosscheck
    python3 parse_apk_zip.py app.apk --json
    python3 parse_apk_zip.py app.apk --strict             # exit 1 if anything is flagged

    Run it from the chapter directory exactly as the chapter prints it:
        python3 examples/parse_apk_zip.py app.apk

REQUIREMENTS
    Python 3.8 or newer. Standard library only. Works on Windows, macOS, Linux.

RELATED
    ../README.md section 6.1              the ZIP record layouts
    ../README.md section 18               the attack classes checked for
    ../labs/lab-01-dissecting-the-apk-byte-by-byte.md
                                          do this walk by hand first
    ./parse_signing_block.py              the block this tool only locates
    ../scripts/apk-container-triage.py    the same checks as a pass/fail triage

AUTHORISED TESTING ONLY.
"""

import argparse
import json
import struct
import sys

LFH_SIG = b"PK\x03\x04"          # 0x04034b50
DD_SIG = b"PK\x07\x08"           # 0x08074b50
CD_SIG = b"PK\x01\x02"           # 0x02014b50
EOCD_SIG = b"PK\x05\x06"         # 0x06054b50
Z64_EOCD_SIG = b"PK\x06\x06"     # 0x06064b50
Z64_LOC_SIG = b"PK\x06\x07"      # 0x06074b50

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
ZIP64_SENTINEL = 0xFFFFFFFF

EOCD_FIXED = 22
CDFH_FIXED = 46
LFH_FIXED = 30

METHODS = {
    0: "STORED",
    1: "SHRUNK",
    6: "IMPLODED",
    8: "DEFLATE",
    9: "DEFLATE64",
    12: "BZIP2",
    14: "LZMA",
    93: "ZSTD",
    95: "XZ",
    98: "PPMD",
}

# General purpose bit flag bits that change how the record must be read.
GPBF_ENCRYPTED = 0x0001
GPBF_DATA_DESCRIPTOR = 0x0008   # bit 3: CRC and sizes are zero in the LFH
GPBF_UTF8_NAME = 0x0800         # bit 11

# Magic bytes worth naming when they show up where PK\x03\x04 belongs.
HEAD_MAGIC = [
    (b"dex\n", "a DEX file is prepended - this is the Janus shape (CVE-2017-13156)"),
    (b"\x7fELF", "an ELF binary is prepended"),
    (b"\x1f\x8b", "gzip data is prepended"),
    (b"%PDF", "a PDF is prepended"),
    (b"PK\x05\x06", "the file begins with an EOCD - this archive is empty"),
]

ALERT, WARN, INFO = "ALERT", "WARN", "INFO"
LEVEL_ORDER = {ALERT: 0, WARN: 1, INFO: 2}


class ZipError(Exception):
    """Raised when the container cannot be walked at all."""


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


def decode_name(raw, gpbf):
    """Entry names are UTF-8 when bit 11 is set, CP437 historically, in
    practice always UTF-8 in an APK. Decode leniently and never raise: an
    undecodable name is itself information, not a reason to stop."""
    enc = "utf-8" if gpbf & GPBF_UTF8_NAME else "utf-8"
    return raw.decode(enc, "replace")


def method_name(m):
    return METHODS.get(m, f"UNKNOWN({m})")


class Finding:
    def __init__(self, level, code, message, next_step):
        self.level = level
        self.code = code
        self.message = message
        self.next_step = next_step

    def as_dict(self):
        return {
            "level": self.level,
            "code": self.code,
            "message": self.message,
            "next_step": self.next_step,
        }


class ApkZip:
    """A hand-rolled ZIP container reader that keeps every contradiction."""

    def __init__(self, data, path="<memory>"):
        self.data = data
        self.path = path
        self.findings = []
        self.entries = []
        self.eocd = {}
        self.eocd_offset = -1
        self.eocd_candidates = []
        self.signing_block = None
        self.zip64 = False

        self._check_head()
        self._find_eocd()
        self._read_eocd()
        self._walk_central_directory()
        self._cross_check_local_headers()
        self._check_duplicate_names()
        self._check_entry_names()
        self._find_signing_block()
        self._check_coverage()

    # ------------------------------------------------------------------
    # findings
    # ------------------------------------------------------------------

    def add(self, level, code, message, next_step):
        self.findings.append(Finding(level, code, message, next_step))

    def flagged(self):
        return [f for f in self.findings if f.level in (ALERT, WARN)]

    # ------------------------------------------------------------------
    # 1. the first four bytes
    # ------------------------------------------------------------------

    def _check_head(self):
        head = self.data[:4]
        if head == LFH_SIG:
            return
        explanation = "unrecognised leading bytes"
        for magic, why in HEAD_MAGIC:
            if self.data.startswith(magic):
                explanation = why
                break
        self.add(
            ALERT, "head-magic",
            f"file does not begin with 50 4B 03 04 - it begins with "
            f"{head.hex(' ')} ({explanation})",
            "Run `apksigner verify -v` and read the v1/v2 lines. Prepending is "
            "only survivable under v1-only signing; a v1-only APK with data "
            "before offset 0 is very likely Janus-crafted. Do not install it.",
        )

    # ------------------------------------------------------------------
    # 2. the EOCD, found by scanning backwards
    # ------------------------------------------------------------------

    def _find_eocd(self):
        d = self.data
        n = len(d)
        if n < EOCD_FIXED:
            raise ZipError(f"file is {n} bytes; the EOCD alone is {EOCD_FIXED}")

        # The comment field is 16-bit, so the EOCD can sit at most
        # 22 + 65535 = 65557 bytes from the end. Scan that whole window.
        window_start = max(0, n - (EOCD_FIXED + 0xFFFF))
        pos = d.find(EOCD_SIG, window_start)
        while pos != -1:
            if pos + EOCD_FIXED <= n:
                comment_len = u16(d, pos + 20)
                consistent = (pos + EOCD_FIXED + comment_len == n)
                self.eocd_candidates.append(
                    {"offset": pos, "comment_len": comment_len,
                     "consistent": consistent})
            pos = d.find(EOCD_SIG, pos + 1)

        if not self.eocd_candidates:
            raise ZipError(
                "no EOCD signature (50 4B 05 06) in the last 65557 bytes - "
                "this is not a ZIP, or its tail has been destroyed")

        consistent = [c for c in self.eocd_candidates if c["consistent"]]
        if consistent:
            chosen = consistent[-1]
        else:
            chosen = self.eocd_candidates[-1]
            self.add(
                ALERT, "eocd-inconsistent",
                "no EOCD candidate whose offset + 22 + commentLength equals the "
                "file size; using the last signature found at offset "
                f"0x{chosen['offset']:x}",
                "There is data after the EOCD, or the comment length is a lie. "
                "Compare with `unzip -l` and `zipinfo -v`: implementations "
                "differ on which EOCD they accept, and that difference is the "
                "attack.",
            )

        if len(self.eocd_candidates) > 1:
            offs = ", ".join(f"0x{c['offset']:x}" for c in self.eocd_candidates)
            self.add(
                WARN, "eocd-multiple",
                f"{len(self.eocd_candidates)} EOCD signatures in the tail "
                f"window (at {offs}) - chose 0x{chosen['offset']:x}",
                "The bytes 50 4B 05 06 do occur by chance inside compressed "
                "data, so this is not proof of anything on its own. It IS how "
                "two parsers are made to pick different EOCDs. Check whether "
                "each candidate is self-consistent.",
            )

        self.eocd_offset = chosen["offset"]

    def _read_eocd(self):
        d = self.data
        o = self.eocd_offset
        self.eocd = {
            "offset": o,
            "disk_number": u16(d, o + 4),
            "cd_start_disk": u16(d, o + 6),
            "entries_this_disk": u16(d, o + 8),
            "total_entries": u16(d, o + 10),
            "cd_size": u32(d, o + 12),
            "cd_offset": u32(d, o + 16),
            "comment_len": u16(d, o + 20),
        }
        e = self.eocd
        e["comment"] = d[o + EOCD_FIXED: o + EOCD_FIXED + e["comment_len"]]

        expected_end = o + EOCD_FIXED + e["comment_len"]
        trailing = len(d) - expected_end
        if trailing > 0:
            self.add(
                ALERT, "trailing-data",
                f"{trailing} bytes after the end of the EOCD record "
                f"(EOCD ends at 0x{expected_end:x}, file ends at 0x{len(d):x})",
                "No signing scheme covers bytes past the EOCD, so this is "
                "free storage inside a validly-signed APK. Carve it out with "
                f"`dd if={self.path} bs=1 skip={expected_end}` and run `file` "
                "on the result.",
            )
        elif trailing < 0:
            self.add(
                ALERT, "eocd-truncated",
                f"the EOCD declares a {e['comment_len']}-byte comment that runs "
                f"{-trailing} bytes past the end of the file",
                "The file is truncated or the comment length is forged. "
                "Different readers will disagree about where the archive ends.",
            )

        if e["comment_len"] != 0:
            self.add(
                WARN, "eocd-comment",
                f"EOCD commentLength is {e['comment_len']} (normal APKs use 0)",
                "Dump it and look: `python3 parse_apk_zip.py app.apk --json` "
                "prints the comment bytes. A comment is not covered by v1 and "
                "is a documented hiding place; it can also carry a decoy EOCD "
                "signature.",
            )

        if e["disk_number"] != 0 or e["cd_start_disk"] != 0:
            self.add(
                WARN, "eocd-multidisk",
                f"multi-disk fields are non-zero "
                f"(disk={e['disk_number']}, cdStartDisk={e['cd_start_disk']})",
                "A floppy-disk relic. Android will not produce this. Treat a "
                "non-zero value as deliberate.",
            )

        if e["entries_this_disk"] != e["total_entries"]:
            self.add(
                WARN, "eocd-entry-count",
                f"entriesThisDisk={e['entries_this_disk']} but "
                f"totalEntries={e['total_entries']}",
                "Two fields that must agree do not. Readers pick one or the "
                "other; find out which each of your tools uses.",
            )

        # Zip64 detection.
        z64 = (e["cd_size"] == ZIP64_SENTINEL or e["cd_offset"] == ZIP64_SENTINEL
               or e["total_entries"] == 0xFFFF)
        loc = o - 20
        has_locator = loc >= 0 and d[loc:loc + 4] == Z64_LOC_SIG
        if z64 or has_locator:
            self.zip64 = True
            self.add(
                WARN, "zip64",
                "Zip64 structures are present "
                f"(sentinel fields={z64}, EOCD64 locator={has_locator})",
                "This parser does not resolve 64-bit values. APKs essentially "
                "never need Zip64, so a hand-built one that does is worth "
                "reading by hand - some parsers honour Zip64 and some ignore "
                "it, which is a divergence primitive.",
            )

    # ------------------------------------------------------------------
    # 3. the central directory - the authoritative index
    # ------------------------------------------------------------------

    def _walk_central_directory(self):
        d = self.data
        e = self.eocd
        off = e["cd_offset"]
        end = e["cd_offset"] + e["cd_size"]

        if off >= len(d):
            raise ZipError(
                f"central directory offset 0x{off:x} is past the end of a "
                f"{len(d)}-byte file")
        if end > len(d):
            self.add(
                ALERT, "cd-overruns",
                f"the central directory (0x{off:x} + {e['cd_size']}) runs past "
                f"the end of the file",
                "Either the file is truncated or cdSize is forged. Walk the "
                "records manually and see where they actually stop.",
            )
            end = len(d)

        index = 0
        while off + CDFH_FIXED <= end:
            if d[off:off + 4] != CD_SIG:
                self.add(
                    ALERT, "cd-bad-signature",
                    f"expected a central directory header at 0x{off:x}, found "
                    f"{d[off:off + 4].hex(' ')}",
                    "The walk stops here. Compare against `zipinfo -v` to see "
                    "which record the two readers part company on.",
                )
                break

            gpbf = u16(d, off + 8)
            n_len = u16(d, off + 28)
            m_len = u16(d, off + 30)
            k_len = u16(d, off + 32)
            raw_name = d[off + CDFH_FIXED: off + CDFH_FIXED + n_len]

            entry = {
                "index": index,
                "cd_offset": off,
                "version_made_by": u16(d, off + 4),
                "version_needed": u16(d, off + 6),
                "gpbf": gpbf,
                "method": u16(d, off + 10),
                "mod_time": u16(d, off + 12),
                "mod_date": u16(d, off + 14),
                "crc32": u32(d, off + 16),
                "csize": u32(d, off + 20),
                "usize": u32(d, off + 24),
                "name_len": n_len,
                "extra_len": m_len,
                "comment_len": k_len,
                "disk_start": u16(d, off + 34),
                "internal_attrs": u16(d, off + 36),
                "external_attrs": u32(d, off + 38),
                "lfh_offset": u32(d, off + 42),
                "name": decode_name(raw_name, gpbf),
                "raw_name": raw_name,
                "lfh": None,
                "divergences": [],
            }
            self.entries.append(entry)

            off += CDFH_FIXED + n_len + m_len + k_len
            index += 1

        if len(self.entries) != e["total_entries"]:
            self.add(
                ALERT, "cd-count-mismatch",
                f"the EOCD declares {e['total_entries']} entries but "
                f"{len(self.entries)} central directory records were walked",
                "A reader that trusts the count and a reader that walks until "
                "the bytes run out will now see different archives. That is "
                "the whole Master Key idea in one field.",
            )

    # ------------------------------------------------------------------
    # 4. the local file headers - the copy nobody should trust
    # ------------------------------------------------------------------

    def _cross_check_local_headers(self):
        d = self.data
        for ent in self.entries:
            lo = ent["lfh_offset"]
            if lo + LFH_FIXED > len(d):
                ent["divergences"].append(
                    f"local header offset 0x{lo:x} is past the end of the file")
                self.add(
                    ALERT, "lfh-out-of-range",
                    f"{ent['name']}: central directory points at 0x{lo:x}, "
                    f"past the end of a {len(d)}-byte file",
                    "The entry cannot be read at all by a central-directory "
                    "reader. Search for its real local header with "
                    f"`grep -abo` on the name, and compare.",
                )
                continue

            if d[lo:lo + 4] != LFH_SIG:
                ent["divergences"].append(
                    f"no local file header signature at 0x{lo:x} "
                    f"(found {d[lo:lo + 4].hex(' ')})")
                self.add(
                    ALERT, "lfh-bad-signature",
                    f"{ent['name']}: no 50 4B 03 04 at the offset the central "
                    f"directory gives (0x{lo:x})",
                    "Either the offsets are shifted (something was prepended) "
                    "or the pointer is forged. Check the first four bytes of "
                    "the file first.",
                )
                continue

            n_len = u16(d, lo + 26)
            m_len = u16(d, lo + 28)
            raw_name = d[lo + LFH_FIXED: lo + LFH_FIXED + n_len]
            gpbf = u16(d, lo + 6)

            lfh = {
                "offset": lo,
                "version_needed": u16(d, lo + 4),
                "gpbf": gpbf,
                "method": u16(d, lo + 8),
                "crc32": u32(d, lo + 14),
                "csize": u32(d, lo + 18),
                "usize": u32(d, lo + 22),
                "name_len": n_len,
                "extra_len": m_len,
                "name": decode_name(raw_name, gpbf),
                "data_offset": lo + LFH_FIXED + n_len + m_len,
            }
            ent["lfh"] = lfh

            # Bit 3 legitimately zeroes crc/csize/usize in the LOCAL header and
            # defers them to a data descriptor after the data. That is normal
            # and must not be reported as a divergence.
            deferred = bool(lfh["gpbf"] & GPBF_DATA_DESCRIPTOR)

            if lfh["name"] != ent["name"]:
                ent["divergences"].append(
                    f"name: central={ent['name']!r} local={lfh['name']!r}")
            if lfh["method"] != ent["method"]:
                ent["divergences"].append(
                    f"method: central={method_name(ent['method'])} "
                    f"local={method_name(lfh['method'])}")
            if not deferred:
                if lfh["csize"] != ent["csize"]:
                    ent["divergences"].append(
                        f"compressed size: central={ent['csize']} "
                        f"local={lfh['csize']}")
                if lfh["usize"] != ent["usize"]:
                    ent["divergences"].append(
                        f"uncompressed size: central={ent['usize']} "
                        f"local={lfh['usize']}")
                if lfh["crc32"] != ent["crc32"]:
                    ent["divergences"].append(
                        f"crc32: central=0x{ent['crc32']:08x} "
                        f"local=0x{lfh['crc32']:08x}")

            if lfh["gpbf"] & GPBF_ENCRYPTED:
                ent["divergences"].append(
                    "the encrypted bit (bit 0) is set - Android cannot install "
                    "this entry")

            if ent["divergences"]:
                detail = "; ".join(ent["divergences"])
                self.add(
                    ALERT, "lfh-cdfh-divergence",
                    f"{ent['name']}: local and central headers disagree - {detail}",
                    "A divergence here is a finding, not a typo. Decide which "
                    "copy each of your tools believes: `zipinfo -v app.apk` "
                    "prints both. The platform reads the central directory; a "
                    "tool that reads the local header sees a different file.",
                )

    # ------------------------------------------------------------------
    # 5. duplicate names - the Master Key class
    # ------------------------------------------------------------------

    def _check_duplicate_names(self):
        seen = {}
        for ent in self.entries:
            seen.setdefault(ent["name"], []).append(ent)

        dupes = {name: lst for name, lst in seen.items() if len(lst) > 1}
        self.duplicates = dupes

        if not dupes:
            return

        for name, lst in sorted(dupes.items()):
            offsets = ", ".join(f"0x{x['lfh_offset']:x}" for x in lst)
            self.add(
                ALERT, "duplicate-name",
                f"duplicate entry name {name!r} appears {len(lst)} times "
                f"(local headers at {offsets})",
                "This is the Master Key shape (CVE-2013-4787): the verifier "
                "digests one copy and the loader may retrieve the other. "
                "Extract BOTH copies by seeking to each local header offset "
                "and compare them. `unzip` will silently give you only one.",
            )

    # ------------------------------------------------------------------
    # 6. entry names - ZipSlip and friends
    # ------------------------------------------------------------------

    def _check_entry_names(self):
        for ent in self.entries:
            name = ent["name"]
            problems = []
            if name.startswith("/") or name.startswith("\\"):
                problems.append("absolute path (leading separator)")
            if "../" in name or "..\\" in name or name.startswith(".."):
                problems.append("path traversal sequence")
            if len(name) > 1 and name[1] == ":":
                problems.append("Windows drive letter")
            if "\x00" in name:
                problems.append("embedded NUL byte")
            if "�" in name:      # U+FFFD, left behind by errors="replace"
                problems.append("name is not valid UTF-8")

            if problems:
                self.add(
                    ALERT, "entry-name",
                    f"unsafe entry name {name!r}: {', '.join(problems)}",
                    "The platform installer will refuse this, so it is aimed "
                    "at whatever ELSE unpacks the archive - an analysis "
                    "sandbox, a build pipeline, or an app that extracts it. "
                    "See README section 18.3 on ZipSlip.",
                )

    # ------------------------------------------------------------------
    # 7. the APK Signing Block boundary
    # ------------------------------------------------------------------

    def _find_signing_block(self):
        d = self.data
        cd_off = self.eocd["cd_offset"]
        if cd_off < 32 or cd_off > len(d):
            return
        if d[cd_off - 16:cd_off] != APK_SIG_BLOCK_MAGIC:
            self.add(
                INFO, "no-signing-block",
                "no 'APK Sig Block 42' magic immediately before the central "
                "directory - the APK carries no v2/v3 signature",
                "Check for v1: `unzip -l app.apk | grep -E 'META-INF/.*\\.(SF|RSA|DSA|EC)$'`. "
                "A v1-only APK is exposed to the Janus and Master Key classes.",
            )
            return

        size_suffix = u64(d, cd_off - 24)
        block_start = cd_off - size_suffix - 8
        if block_start < 0 or block_start >= cd_off:
            self.add(
                ALERT, "signing-block-size",
                f"the signing block's size suffix ({size_suffix}) puts its "
                f"start at {block_start}, which is impossible",
                "Read the last 32 bytes before the central directory by hand "
                "with `xxd`. See parse_signing_block.py.",
            )
            return

        size_prefix = u64(d, block_start)
        self.signing_block = {
            "start": block_start,
            "end": cd_off,
            "total_bytes": cd_off - block_start,
            "size_prefix": size_prefix,
            "size_suffix": size_suffix,
            "consistent": size_prefix == size_suffix,
        }
        if size_prefix != size_suffix:
            self.add(
                ALERT, "signing-block-mismatch",
                f"signing block size prefix ({size_prefix}) != suffix "
                f"({size_suffix})",
                "The two must be equal. A reader that walks forwards from the "
                "prefix and one that walks backwards from the suffix now see "
                "different blocks. Run parse_signing_block.py.",
            )

    # ------------------------------------------------------------------
    # 8. coverage - is every byte accounted for?
    # ------------------------------------------------------------------

    def _check_coverage(self):
        """Entry data should tile the region from offset 0 to the signing
        block (or the central directory). Gaps hold bytes no structure claims;
        overlaps mean two entries share data."""
        d = self.data
        regions = []
        for ent in self.entries:
            lfh = ent["lfh"]
            if not lfh:
                continue
            start = lfh["offset"]
            csize = ent["csize"]          # central directory is authoritative
            end = lfh["data_offset"] + csize
            # An optional data descriptor follows the data when bit 3 is set.
            if lfh["gpbf"] & GPBF_DATA_DESCRIPTOR:
                if d[end:end + 4] == DD_SIG:
                    end += 16
                else:
                    end += 12
            regions.append((start, min(end, len(d)), ent["name"]))

        if not regions:
            return
        regions.sort()

        boundary = (self.signing_block["start"] if self.signing_block
                    else self.eocd["cd_offset"])

        cursor = 0
        gaps, overlaps = [], []
        for start, end, name in regions:
            if start > cursor:
                gaps.append((cursor, start, start - cursor))
            elif start < cursor:
                overlaps.append((start, cursor, name))
            cursor = max(cursor, end)
        if cursor < boundary:
            gaps.append((cursor, boundary, boundary - cursor))

        self.coverage = {"gaps": gaps, "overlaps": overlaps, "end": cursor,
                         "boundary": boundary}

        for start, end, name in overlaps:
            self.add(
                ALERT, "entry-overlap",
                f"entry data overlaps at 0x{start:x}-0x{end:x} (around "
                f"{name!r})",
                "Two entries claim the same bytes. Legitimate packaging never "
                "does this. Extract both and compare.",
            )

        for start, end, length in gaps:
            level = WARN if length > 1024 else INFO
            self.add(
                level, "coverage-gap",
                f"{length} bytes at 0x{start:x}-0x{end:x} are not claimed by "
                f"any entry",
                "Small gaps are usually alignment artefacts left by a repack. "
                f"Look at them: `xxd -s {start} -l 64 {self.path}`. A large "
                "unclaimed region inside the entry-data area is somewhere to "
                "hide a payload.",
            )

    # ------------------------------------------------------------------
    # reporting
    # ------------------------------------------------------------------

    def summary(self):
        return {
            "path": self.path,
            "size": len(self.data),
            "head": self.data[:4].hex(),
            "eocd": {k: v for k, v in self.eocd.items() if k != "comment"},
            "eocd_comment_hex": self.eocd.get("comment", b"").hex(),
            "eocd_candidates": self.eocd_candidates,
            "entry_count": len(self.entries),
            "duplicate_names": sorted(self.duplicates),
            "signing_block": self.signing_block,
            "zip64": self.zip64,
            "findings": [f.as_dict() for f in self.findings],
        }


# ----------------------------------------------------------------------
# the deliberately-labelled zipfile comparison
# ----------------------------------------------------------------------

def zipfile_crosscheck(path, apk):
    """Run the standard library's ZIP reader alongside the raw walk and show
    what it hides. This is a DEMONSTRATION, not part of the parser."""
    import zipfile

    print("\n-- zipfile cross-check (the library view, for comparison only) --")
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            infos = zf.infolist()
    except Exception as exc:                     # noqa: BLE001 - report anything
        print(f"  zipfile refused the file entirely: {exc}")
        print("  The raw walk above still produced a reading. When a library "
              "refuses and a hand walk succeeds, the difference is the finding.")
        return

    raw_names = [e["name"] for e in apk.entries]
    print(f"  zipfile.namelist()      : {len(names)} names")
    print(f"  zipfile addressable     : {len(set(names))} distinct names")
    print(f"  raw central directory   : {len(raw_names)} records")

    dupes = sorted(apk.duplicates)
    if dupes:
        print(f"  !! duplicate names present: {dupes}")
        print("     namelist() lists both, but ZipFile keys its lookup map on "
              "the NAME, so getinfo()/open()/read() can only ever reach ONE of "
              "them. Every other copy is unreachable through the library.")
        for name in dupes:
            copies = [i.header_offset for i in infos if i.filename == name]
            try:
                reachable = zf_getinfo_offset(path, name)
            except Exception:                        # noqa: BLE001
                reachable = None
            offs = ", ".join(f"0x{c:x}" for c in copies)
            print(f"       {name!r}: local headers at {offs}")
            if reachable is not None:
                print(f"       zipfile.read({name!r}) resolves to the copy at "
                      f"0x{reachable:x} - the others are invisible to it")

    print("  Note what zipfile never told you: it read the central directory "
          "only, so every local-file-header divergence above is invisible to "
          "it, and it said nothing about trailing data or the signing block.")


def zf_getinfo_offset(path, name):
    """Which copy does ZipFile.getinfo() actually hand back?"""
    import zipfile
    with zipfile.ZipFile(path) as zf:
        return zf.getinfo(name).header_offset


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def print_report(apk, args):
    d = apk.data
    e = apk.eocd

    print(f"\n=== {apk.path} ({len(d):,} bytes) ===\n")

    print("-- container --")
    head_ok = "OK - local file header" if d[:4] == LFH_SIG else "SUSPICIOUS"
    print(f"  {'first 4 bytes':<24} {d[:4].hex(' ')}  ({head_ok})")
    print(f"  {'EOCD offset':<24} 0x{e['offset']:x}")
    print(f"  {'EOCD candidates':<24} {len(apk.eocd_candidates)} "
          f"({sum(1 for c in apk.eocd_candidates if c['consistent'])} self-consistent)")
    print(f"  {'total entries (EOCD)':<24} {e['total_entries']}")
    print(f"  {'records walked':<24} {len(apk.entries)}")
    print(f"  {'central directory':<24} 0x{e['cd_offset']:x} .. "
          f"0x{e['cd_offset'] + e['cd_size']:x} ({e['cd_size']} bytes)")
    print(f"  {'EOCD commentLength':<24} {e['comment_len']}")
    if e["comment_len"]:
        preview = e["comment"][:48]
        print(f"  {'EOCD comment':<24} {preview.hex(' ')}")

    if apk.signing_block:
        sb = apk.signing_block
        print(f"  {'signing block':<24} 0x{sb['start']:x} .. 0x{sb['end']:x} "
              f"({sb['total_bytes']} bytes)")
        print(f"  {'  size prefix/suffix':<24} {sb['size_prefix']} / "
              f"{sb['size_suffix']} "
              f"({'agree' if sb['consistent'] else 'DISAGREE'})")
    else:
        print(f"  {'signing block':<24} absent (v1-only or unsigned)")

    # The word 'duplicate' must appear on this line in both outcomes: the
    # chapter greps for it.
    if apk.duplicates:
        print(f"  {'duplicate names':<24} {len(apk.duplicates)} "
              f"-> {sorted(apk.duplicates)}")
    else:
        print(f"  {'duplicate names':<24} none")

    diverging = [x for x in apk.entries if x["divergences"]]
    print(f"  {'LFH/CDFH divergences':<24} "
          f"{len(diverging) if diverging else 'none'}")

    # --- entries ------------------------------------------------------
    if args.entries:
        limit = args.limit if args.limit else len(apk.entries)
        print(f"\n-- entries ({len(apk.entries)}) --")
        print(f"  {'#':>5} {'method':<10} {'csize':>10} {'usize':>10} "
              f"{'lfh':>10}  name")
        for ent in apk.entries[:limit]:
            lfh_hex = f"0x{ent['lfh_offset']:x}"
            print(f"  {ent['index']:>5} {method_name(ent['method']):<10} "
                  f"{ent['csize']:>10} {ent['usize']:>10} "
                  f"{lfh_hex:>10}  {ent['name']}")
            for div in ent["divergences"]:
                print(f"        !! {div}")
        if limit < len(apk.entries):
            print(f"  ... {len(apk.entries) - limit} more "
                  f"(use --limit 0 for all)")
    elif diverging:
        print(f"\n-- diverging entries ({len(diverging)}) --")
        for ent in diverging:
            print(f"  {ent['name']}  (local header 0x{ent['lfh_offset']:x})")
            for div in ent["divergences"]:
                print(f"        !! {div}")

    # --- findings -----------------------------------------------------
    print(f"\n-- findings ({len(apk.findings)}) --")
    if not apk.findings:
        print("  none - every structure is self-consistent.")
    else:
        ordered = sorted(apk.findings, key=lambda f: LEVEL_ORDER[f.level])
        for f in ordered:
            marker = {"ALERT": "!!", "WARN": " !", "INFO": "  "}[f.level]
            print(f"  {marker} [{f.level:<5}] {f.code}")
            print(f"       {f.message}")
            print(f"       next step: {f.next_step}")

    flagged = apk.flagged()
    print(f"\n-- verdict --")
    if not flagged:
        print("  Container is structurally clean. That is a statement about "
              "the ZIP layer only:")
        print("  it says nothing about the signature, the manifest, or the "
              "code inside.")
    else:
        alerts = sum(1 for f in flagged if f.level == ALERT)
        warns = len(flagged) - alerts
        print(f"  {alerts} alert(s), {warns} warning(s). Work the 'next step' "
              "lines above in order.")
    print()


def main():
    ap = argparse.ArgumentParser(
        description="Walk an APK's ZIP container by hand and report anomalies")
    ap.add_argument("path", help="the .apk (or any .zip) to read")
    ap.add_argument("--entries", action="store_true",
                    help="list every entry, not just the diverging ones")
    ap.add_argument("--limit", type=int, default=40,
                    help="entries to print with --entries; 0 means all")
    ap.add_argument("--zipfile-crosscheck", action="store_true",
                    help="also read the file with the stdlib zipfile module "
                         "and show what it hides")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if anything is flagged ALERT or WARN")
    args = ap.parse_args()

    try:
        with open(args.path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        apk = ApkZip(data, args.path)
    except ZipError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(apk.summary(), indent=2, default=str))
    else:
        print_report(apk, args)
        if args.zipfile_crosscheck:
            zipfile_crosscheck(args.path, apk)
            print()

    if args.strict and apk.flagged():
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
