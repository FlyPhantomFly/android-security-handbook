#!/usr/bin/env python3
"""
OatHeaderParser.py — parse an Android OAT file header without oatdump.

WHAT IT DOES
    Reads a `base.odex` (which, despite the name, is an OAT file — an ELF
    shared object; see ../README.md section 3.1) and prints:

      - ELF validation and the oatdata / oatexec / oatlastword symbols
      - every OatHeader field
      - the full key-value store, including `compiler-filter`
      - an interpretation of what that filter means for hooking

WHY IT EXISTS
    `oatdump` lives on the device inside the ART APEX and needs root. This
    script runs on your workstation against a pulled file, which is often more
    convenient, and — more importantly — writing a parser is how you actually
    learn the format. Compare its output against `oatdump --header-only`; they
    should agree.

HOW TO RUN
    # pull the file first
    adb shell 'su -c "cat /data/app/~~*/com.example.target-*/oat/arm64/base.odex"' > base.odex
    # or, more reliably:
    adb shell "su -c 'cp /data/app/.../oat/arm64/base.odex /data/local/tmp/'"
    adb shell "su -c 'chmod 644 /data/local/tmp/base.odex'"
    adb pull /data/local/tmp/base.odex

    python3 OatHeaderParser.py base.odex
    python3 OatHeaderParser.py base.odex --json

REQUIREMENTS
    Python 3.8+. No third-party modules.

CAVEAT
    The OatHeader layout changes between ART versions. This parser handles the
    common modern layout and will tell you when it encounters a version it does
    not recognise, rather than printing confident nonsense. Always cross-check
    anything load-bearing against `oatdump`.
"""

import argparse
import json
import struct
import sys

OAT_MAGIC = b"oat\n"
ELF_MAGIC = b"\x7fELF"

# Interpretation of each compiler filter for an analyst. See README section 3.9.
FILTER_MEANING = {
    "assume-verified": ("Nothing compiled, verification skipped.",
                        "All methods interpreted. Ideal for hooking."),
    "extract":         ("Nothing compiled, DEX merely unpacked.",
                        "All methods interpreted. Ideal for hooking."),
    "verify":          ("Verified but NOT compiled.",
                        "All methods interpreted. Ideal for hooking."),
    "quicken":         ("Quickened bytecode (removed in Android 11+).",
                        "Interpreted. NOTE: extracted DEX may need unquickening."),
    "space-profile":   ("Profile-selected methods, size-optimised.",
                        "Mixed. Hot methods compiled; hooks on them may miss."),
    "space":           ("Everything compiled, size-optimised.",
                        "Compiled. Inlining likely; hooks may silently miss."),
    "speed-profile":   ("Profile-selected methods compiled.",
                        "Mixed. The normal steady state. Consider forcing verify."),
    "speed":           ("EVERYTHING compiled with aggressive inlining.",
                        "Worst case for hooking. Force verify before instrumenting."),
    "everything-profile": ("Profile-selected plus normally-skipped methods.",
                           "Compiled. Debug/analysis filter."),
    "everything":      ("Absolutely everything compiled.",
                        "Compiled. Debug/analysis filter."),
}


class OatParseError(Exception):
    pass


def read_elf_symbols(data):
    """
    Minimal ELF64 symbol reader: locate oatdata, oatexec and oatlastword.

    We only need enough ELF parsing to find the .dynsym / .symtab sections and
    walk their entries. This is deliberately simple rather than general.
    """
    if data[:4] != ELF_MAGIC:
        raise OatParseError("not an ELF file — is this really an OAT?")

    ei_class = data[4]
    if ei_class != 2:
        raise OatParseError("only 64-bit ELF is supported by this parser")

    # ELF64 header
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, = struct.unpack_from("<H", data, 0x3A)
    e_shnum, = struct.unpack_from("<H", data, 0x3C)
    e_shstrndx, = struct.unpack_from("<H", data, 0x3E)

    if e_shoff == 0 or e_shnum == 0:
        raise OatParseError("ELF has no section headers")

    def section(i):
        off = e_shoff + i * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
         sh_size, sh_link, sh_info, sh_align,
         sh_entsize) = struct.unpack_from("<IIQQQQIIQQ", data, off)
        return dict(name=sh_name, type=sh_type, addr=sh_addr, offset=sh_offset,
                    size=sh_size, link=sh_link, entsize=sh_entsize)

    shstr = section(e_shstrndx)

    def sec_name(off):
        end = data.index(b"\0", shstr["offset"] + off)
        return data[shstr["offset"] + off:end].decode("utf-8", "replace")

    symbols = {}
    for i in range(e_shnum):
        s = section(i)
        # SHT_SYMTAB = 2, SHT_DYNSYM = 11
        if s["type"] not in (2, 11):
            continue
        strtab = section(s["link"])
        count = s["size"] // s["entsize"] if s["entsize"] else 0
        for n in range(count):
            off = s["offset"] + n * s["entsize"]
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", data, off)
            if st_name == 0:
                continue
            try:
                end = data.index(b"\0", strtab["offset"] + st_name)
                nm = data[strtab["offset"] + st_name:end].decode("utf-8", "replace")
            except ValueError:
                continue
            if nm in ("oatdata", "oatexec", "oatlastword", "oatbss"):
                symbols[nm] = dict(value=st_value, size=st_size, offset=None)

    # Map virtual addresses back to file offsets via program headers.
    e_phoff, = struct.unpack_from("<Q", data, 0x20)
    e_phentsize, = struct.unpack_from("<H", data, 0x36)
    e_phnum, = struct.unpack_from("<H", data, 0x38)

    def vaddr_to_off(vaddr):
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            (p_type, p_flags, p_offset, p_vaddr, p_paddr,
             p_filesz, p_memsz, p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
            if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:  # PT_LOAD
                return p_offset + (vaddr - p_vaddr)
        return None

    for nm, info in symbols.items():
        info["offset"] = vaddr_to_off(info["value"])

    return symbols


def parse_oat_header(data, oatdata_off):
    """
    Parse the OatHeader at the given file offset.

    Field order follows art/runtime/oat.h. Fields after the fixed prefix vary
    by version, so we parse conservatively and stop at the key-value store.
    """
    if data[oatdata_off:oatdata_off + 4] != OAT_MAGIC:
        raise OatParseError(
            "OAT magic not found at oatdata (got %r)"
            % data[oatdata_off:oatdata_off + 4])

    off = oatdata_off
    hdr = {}

    hdr["magic"] = data[off:off + 4].decode("ascii", "replace")
    off += 4

    version_raw = data[off:off + 4]
    hdr["version"] = version_raw.rstrip(b"\0").decode("ascii", "replace")
    off += 4

    def u32():
        nonlocal off
        v, = struct.unpack_from("<I", data, off)
        off += 4
        return v

    hdr["adler32_checksum"]                = u32()
    hdr["instruction_set"]                 = u32()
    hdr["instruction_set_features_bitmap"] = u32()
    hdr["dex_file_count"]                  = u32()
    hdr["oat_dex_files_offset"]            = u32()
    hdr["bcp_bss_info_offset"]             = u32()
    hdr["executable_offset"]               = u32()
    hdr["interpreter_to_interpreter_bridge_offset"]    = u32()
    hdr["interpreter_to_compiled_code_bridge_offset"]  = u32()
    hdr["jni_dlsym_lookup_trampoline_offset"]          = u32()
    hdr["jni_dlsym_lookup_critical_trampoline_offset"] = u32()
    hdr["quick_generic_jni_trampoline_offset"]         = u32()
    hdr["quick_imt_conflict_trampoline_offset"]        = u32()
    hdr["quick_resolution_trampoline_offset"]          = u32()
    hdr["quick_to_interpreter_bridge_offset"]          = u32()
    hdr["nterp_trampoline_offset"]                     = u32()
    hdr["image_patch_delta"]               = u32()
    hdr["image_file_location_oat_checksum"] = u32()
    hdr["key_value_store_size"]            = u32()

    hdr["_kv_offset"] = off
    return hdr


def parse_key_value_store(data, start, size):
    """The store is a run of NUL-terminated key/value string pairs."""
    kv = {}
    end = start + size
    off = start
    while off < end:
        try:
            k_end = data.index(b"\0", off, end)
        except ValueError:
            break
        key = data[off:k_end].decode("utf-8", "replace")
        off = k_end + 1
        if off >= end:
            kv[key] = ""
            break
        try:
            v_end = data.index(b"\0", off, end)
        except ValueError:
            v_end = end
        val = data[off:v_end].decode("utf-8", "replace")
        off = v_end + 1
        if key:
            kv[key] = val
    return kv


ISA_NAMES = {
    0: "none", 1: "arm", 2: "arm64", 3: "x86",
    4: "x86_64", 5: "mips", 6: "mips64", 7: "riscv64",
}


def main():
    ap = argparse.ArgumentParser(description="Parse an Android OAT file header")
    ap.add_argument("path", help="path to base.odex (an OAT/ELF file)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    try:
        with open(args.path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"error: cannot read {args.path}: {e}", file=sys.stderr)
        return 1

    result = {"path": args.path, "size": len(data)}

    # --- Step 1: is it even an ELF? -------------------------------------
    if data[:4] == b"dey\n":
        print("This is a genuine Dalvik-era ODEX (magic 'dey\\n'), not an OAT file.")
        print("You are looking at a device from Android 4.4 or earlier.")
        return 2
    if data[:4] != ELF_MAGIC:
        print(f"error: not an ELF file (magic = {data[:4]!r})", file=sys.stderr)
        print("       A modern base.odex must be an ELF. See README section 3.1.",
              file=sys.stderr)
        return 2

    try:
        symbols = read_elf_symbols(data)
    except OatParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    result["symbols"] = {
        k: {"vaddr": hex(v["value"]),
            "file_offset": hex(v["offset"]) if v["offset"] is not None else None,
            "size": v["size"]}
        for k, v in symbols.items()
    }

    if "oatdata" not in symbols or symbols["oatdata"]["offset"] is None:
        print("error: could not locate the oatdata symbol", file=sys.stderr)
        return 2

    # --- Step 2: the OAT header -----------------------------------------
    try:
        hdr = parse_oat_header(data, symbols["oatdata"]["offset"])
    except OatParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    kv = parse_key_value_store(data, hdr["_kv_offset"], hdr["key_value_store_size"])
    result["header"] = {k: v for k, v in hdr.items() if not k.startswith("_")}
    result["key_value_store"] = kv

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    # --- Human-readable output ------------------------------------------
    print(f"\n=== {args.path} ({len(data):,} bytes) ===")

    print("\n-- ELF symbols --")
    for nm in ("oatdata", "oatexec", "oatlastword", "oatbss"):
        if nm in symbols:
            s = symbols[nm]
            fo = hex(s["offset"]) if s["offset"] is not None else "?"
            print(f"  {nm:<14} vaddr={hex(s['value']):<12} file_offset={fo}")

    print("\n-- OatHeader --")
    isa = hdr["instruction_set"]
    print(f"  {'magic':<44} {hdr['magic']!r}")
    print(f"  {'version':<44} {hdr['version']}")
    print(f"  {'adler32_checksum':<44} 0x{hdr['adler32_checksum']:08x}")
    print(f"  {'instruction_set':<44} {isa} ({ISA_NAMES.get(isa, 'unknown')})")
    print(f"  {'dex_file_count':<44} {hdr['dex_file_count']}")
    print(f"  {'executable_offset':<44} 0x{hdr['executable_offset']:x}")
    print(f"  {'key_value_store_size':<44} {hdr['key_value_store_size']}")

    print("\n-- Trampoline offsets --")
    for k in sorted(hdr):
        if k.endswith("_offset") and "trampoline" in k or "bridge" in k:
            print(f"  {k:<44} 0x{hdr[k]:x}")

    print("\n-- Key-value store --")
    if not kv:
        print("  (empty)")
    for k, v in kv.items():
        shown = v if len(v) <= 100 else v[:97] + "..."
        print(f"  {k:<28} {shown}")

    # --- The analyst's bottom line --------------------------------------
    print("\n-- What this means for you --")
    filt = kv.get("compiler-filter")
    if filt is None:
        print("  No compiler-filter recorded. Unusual — cross-check with oatdump.")
    else:
        meaning, advice = FILTER_MEANING.get(
            filt, ("Unrecognised filter.", "Cross-check with oatdump."))
        print(f"  compiler-filter = {filt}")
        print(f"    {meaning}")
        print(f"    {advice}")
        if filt in ("speed", "speed-profile", "space", "space-profile",
                    "everything", "everything-profile"):
            print()
            print("    To make Java hooks reliable:")
            print("      adb shell cmd package compile -m verify -f <package>")
            print("      adb shell am force-stop <package>")

    if "dex2oat-cmdline" in kv:
        print(f"\n  Compiled with:\n    {kv['dex2oat-cmdline'][:300]}")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
