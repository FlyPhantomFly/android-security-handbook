# 10 — APK Internals · Cheat Sheet

Printable reference for chapter [10-APK-Internals](README.md). Tables and commands only.
Related: [09-Android-App-Internals](../09-Android-App-Internals/README.md) ·
[12-DEX-Internals](../12-DEX-Internals/README.md) · [15-Native-Code](../15-Native-Code/README.md) ·
[32-Manifest](../32-Manifest/README.md) · [34-Cryptography](../34-Cryptography/README.md) ·
[38-TamperDetection](../38-TamperDetection/README.md) · [56-JADX](../56-JADX/README.md)

Baseline: Android 13–16 (API 33–36). Historical rows are marked.

---

## 1. ZIP record signatures (all little-endian on disk)

| Signature (u32 LE) | ASCII bytes | Record | Where it appears |
|---|---|---|---|
| `0x04034B50` | `50 4B 03 04` | Local File Header (LFH) | Before every entry's data |
| `0x08074B50` | `50 4B 07 08` | Data Descriptor | After entry data when GPBF bit 3 set |
| `0x02014B50` | `50 4B 01 02` | Central Directory File Header (CDFH) | Central directory, near end |
| `0x06054B50` | `50 4B 05 06` | End Of Central Directory (EOCD) | Last 22+ bytes of file |
| `0x06064B50` | `50 4B 06 06` | Zip64 EOCD Record | Before Zip64 locator |
| `0x07064B50` | `50 4B 06 07` | Zip64 EOCD Locator | Between Zip64 EOCD and EOCD |
| `0x05054B50` | `50 4B 05 05` | Archive digital signature (PKWARE) | Rare; not used by Android |
| `0x08064B50` | `50 4B 06 08` | Archive extra data record | Rare; not used by Android |
| `0x30304B50` | `50 4B 30 30` | Multi-volume spanning marker | Not valid in APKs |

```bash
# host — dump the first 4 bytes; a valid APK starts with 50 4B 03 04
xxd -l 4 app.apk
head -c 4 app.apk | xxd -p          # expect 504b0304
```

```bash
# host — a Janus-style prepended DEX shows 64 65 78 0a ("dex\n") at offset 0 instead
head -c 8 app.apk | xxd -p          # 6465780a30333500 == "dex\n035\0"
```

---

## 2. Local File Header — field offsets (30 bytes fixed + variable)

| Off | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `signature` | `0x04034B50` |
| 4 | 2 | `versionNeeded` | 10 = stored, 20 = deflate, 45 = Zip64 |
| 6 | 2 | `generalPurposeBitFlag` | See §4 |
| 8 | 2 | `compressionMethod` | 0 = STORED, 8 = DEFLATE |
| 10 | 2 | `lastModTime` | MS-DOS time, 2-second resolution |
| 12 | 2 | `lastModDate` | MS-DOS date, epoch 1980 |
| 14 | 4 | `crc32` | 0 if GPBF bit 3 set |
| 18 | 4 | `compressedSize` | 0 if bit 3 set; `0xFFFFFFFF` if Zip64 |
| 22 | 4 | `uncompressedSize` | 0 if bit 3 set; `0xFFFFFFFF` if Zip64 |
| 26 | 2 | `fileNameLength` (n) | |
| 28 | 2 | `extraFieldLength` (m) | Alignment padding lives here |
| 30 | n | `fileName` | No NUL terminator, no length prefix |
| 30+n | m | `extraField` | ID/size TLVs |
| 30+n+m | — | file data | `compressedSize` bytes |

> The LFH is **not authoritative**. Android resolves entries through the central directory.
> Mismatches between LFH and CDFH are the raw material for signature-bypass bug classes.

---

## 3. Central Directory File Header — field offsets (46 bytes fixed + variable)

| Off | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `signature` | `0x02014B50` |
| 4 | 2 | `versionMadeBy` | High byte = host OS (3 = Unix) |
| 6 | 2 | `versionNeeded` | |
| 8 | 2 | `generalPurposeBitFlag` | Must be consistent with LFH in practice |
| 10 | 2 | `compressionMethod` | **Authoritative** for Android |
| 12 | 2 | `lastModTime` | |
| 14 | 2 | `lastModDate` | |
| 16 | 4 | `crc32` | |
| 20 | 4 | `compressedSize` | |
| 24 | 4 | `uncompressedSize` | |
| 28 | 2 | `fileNameLength` (n) | |
| 30 | 2 | `extraFieldLength` (m) | |
| 32 | 2 | `fileCommentLength` (k) | |
| 34 | 2 | `diskNumberStart` | 0 for APKs |
| 36 | 2 | `internalFileAttributes` | |
| 38 | 4 | `externalFileAttributes` | Unix mode in high 16 bits |
| 42 | 4 | `localHeaderOffset` | **Authoritative pointer to the LFH** |
| 46 | n | `fileName` | |
| 46+n | m | `extraField` | |
| 46+n+m | k | `fileComment` | |

---

## 4. General Purpose Bit Flag

| Bit | Mask | Meaning | APK relevance |
|---|---|---|---|
| 0 | `0x0001` | Encrypted | Never legitimately set in an APK |
| 1–2 | `0x0006` | Deflate quality hint | Cosmetic |
| 3 | `0x0008` | Data descriptor follows entry data | Sizes/CRC are 0 in LFH |
| 4 | `0x0010` | Enhanced deflating | Not used |
| 5 | `0x0020` | Compressed patched data | Not used |
| 6 | `0x0040` | Strong encryption | Not used |
| 11 | `0x0800` | UTF-8 filename (EFS) | Set by modern zip tools |
| 13 | `0x2000` | Local header fields masked | Not used |

---

## 5. End Of Central Directory (EOCD) — field offsets

| Off | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `signature` | `0x06054B50` |
| 4 | 2 | `diskNumber` | 0 |
| 6 | 2 | `cdStartDisk` | 0 |
| 8 | 2 | `cdRecordsThisDisk` | |
| 10 | 2 | `cdRecordsTotal` | `0xFFFF` ⇒ look at Zip64 |
| 12 | 4 | `cdSizeBytes` | `0xFFFFFFFF` ⇒ Zip64 |
| 16 | 4 | `cdOffset` | **The single number everything hangs off** |
| 20 | 2 | `commentLength` (c) | 0–65535 |
| 22 | c | `comment` | Free-form; hiding spot |

### Zip64 EOCD Record (`0x06064B50`)

| Off | Size | Field |
|---|---|---|
| 0 | 4 | signature |
| 4 | 8 | size of record minus 12 |
| 12 | 2 | version made by |
| 14 | 2 | version needed |
| 16 | 4 | disk number |
| 20 | 4 | CD start disk |
| 24 | 8 | entries on this disk |
| 32 | 8 | total entries |
| 40 | 8 | CD size |
| 48 | 8 | CD offset |
| 56 | … | extensible data sector |

### Zip64 EOCD Locator (`0x07064B50`) — 20 bytes

| Off | Size | Field |
|---|---|---|
| 0 | 4 | signature |
| 4 | 4 | disk with Zip64 EOCD |
| 8 | 8 | offset of Zip64 EOCD record |
| 16 | 4 | total disks |

```bash
# host — find the EOCD by scanning the tail
tail -c 1024 app.apk | xxd | grep -n "504b 0506"
python3 -c "d=open('app.apk','rb').read(); i=d.rfind(b'PK\x05\x06'); print(hex(i), d[i:i+22].hex())"
```

---

## 6. Compression methods seen in APKs

| ID | Name | Used for |
|---|---|---|
| 0 | STORED | `resources.arsc` (mandatory uncompressed, API 30+), `.so` when `extractNativeLibs=false`, already-compressed assets |
| 8 | DEFLATE | Everything else by default |
| 1,6,9,12,14,93,95 | Shrink/Implode/Deflate64/BZIP2/LZMA/Zstd/XZ | **Not** accepted for APK entries by the platform installer |

---

## 7. APK entry inventory

| Path | Format | Compulsory | Purpose |
|---|---|---|---|
| `AndroidManifest.xml` | AXML (binary XML) | Yes | Package name, components, permissions, SDK levels |
| `classes.dex` | DEX | Yes (unless all code in splits) | Primary bytecode |
| `classes2.dex` … `classesN.dex` | DEX | No | Multidex overflow; numbering starts at 2 |
| `resources.arsc` | ARSC resource table | Practically yes | Compiled resource ID → value table |
| `res/…` | Binary XML, PNG, WEBP, raw | No | Layouts, drawables, XML resources |
| `assets/…` | Arbitrary | No | Raw files reachable via `AssetManager` |
| `assets/dexopt/baseline.prof`, `baseline.profm` | Baseline profile | No | ART AOT hints |
| `lib/<abi>/lib*.so` | ELF | No | Native libraries; `<abi>` ∈ `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86` |
| `META-INF/MANIFEST.MF` | Text | v1 only | Per-entry digests |
| `META-INF/<NAME>.SF` | Text | v1 only | Signature file; digests of MANIFEST.MF sections |
| `META-INF/<NAME>.RSA` / `.DSA` / `.EC` | PKCS#7 / CMS DER | v1 only | Signature block with certificate chain |
| `META-INF/services/…` | Text | No | `ServiceLoader` registrations |
| `META-INF/com/android/build/gradle/app-metadata.properties` | Text | No | AGP build metadata |
| `META-INF/version-control-info.textproto` | Text proto | No | AGP VCS stamp (git SHA) — leaks build provenance |
| `kotlin/…`, `kotlin-tooling-metadata.json` | Kotlin metadata | No | Kotlin reflection/module info |
| `DebugProbesKt.bin` | Binary | No | `kotlinx-coroutines-debug` probe class body |
| `stamp-cert-sha256` | Raw 32 bytes | No | Source-stamp certificate digest |
| `<name>.apk.idsig` | **Sibling file, not inside the APK** | v4 only | fs-verity Merkle tree + signature |

```bash
# host — quick inventory
unzip -l app.apk
unzip -l app.apk | grep -E 'classes.*\.dex|resources\.arsc|\.so$|META-INF'
zipinfo -v app.apk | less                # per-entry field dump
zipinfo -1 app.apk | sort | uniq -d      # DUPLICATE ENTRY NAMES → Master Key class
```

---

## 8. AXML / resource chunk type constants (`ResourceTypes.h`)

| Value | Constant | Chunk |
|---|---|---|
| `0x0000` | `RES_NULL_TYPE` | Padding / absent |
| `0x0001` | `RES_STRING_POOL_TYPE` | String pool |
| `0x0002` | `RES_TABLE_TYPE` | `resources.arsc` root |
| `0x0003` | `RES_XML_TYPE` | Binary XML root |
| `0x0100` | `RES_XML_START_NAMESPACE_TYPE` | Namespace open (also `RES_XML_FIRST_CHUNK_TYPE`) |
| `0x0101` | `RES_XML_END_NAMESPACE_TYPE` | Namespace close |
| `0x0102` | `RES_XML_START_ELEMENT_TYPE` | Element open + attributes |
| `0x0103` | `RES_XML_END_ELEMENT_TYPE` | Element close |
| `0x0104` | `RES_XML_CDATA_TYPE` | Character data |
| `0x017F` | `RES_XML_LAST_CHUNK_TYPE` | Range terminator |
| `0x0180` | `RES_XML_RESOURCE_MAP_TYPE` | Attribute-index → resource-ID map |
| `0x0200` | `RES_TABLE_PACKAGE_TYPE` | Package chunk |
| `0x0201` | `RES_TABLE_TYPE_TYPE` | Type chunk (one config) |
| `0x0202` | `RES_TABLE_TYPE_SPEC_TYPE` | Type spec (config-change flags) |
| `0x0203` | `RES_TABLE_LIBRARY_TYPE` | Dynamic shared-library refs |
| `0x0204` | `RES_TABLE_OVERLAYABLE_TYPE` | Overlayable declaration |
| `0x0205` | `RES_TABLE_OVERLAYABLE_POLICY_TYPE` | Overlay policy |
| `0x0206` | `RES_TABLE_STAGED_ALIAS_TYPE` | Staged resource ID alias |

### Common chunk headers

| Struct | Bytes | Layout |
|---|---|---|
| `ResChunk_header` | 8 | `u16 type`, `u16 headerSize`, `u32 size` |
| `ResStringPool_header` | 28 | chunk hdr + `u32 stringCount`, `u32 styleCount`, `u32 flags`, `u32 stringsStart`, `u32 stylesStart` |
| `ResXMLTree_header` | 8 | plain chunk header, `size` = whole file |
| `ResXMLTree_node` | 16 | chunk hdr + `u32 lineNumber`, `u32 comment` (string ref) |
| `ResXMLTree_namespaceExt` | 8 | `u32 prefix`, `u32 uri` |
| `ResXMLTree_endElementExt` | 8 | `u32 ns`, `u32 name` |
| `ResXMLTree_attrExt` | 20 | `u32 ns`, `u32 name`, `u16 attributeStart`, `u16 attributeSize`, `u16 attributeCount`, `u16 idIndex`, `u16 classIndex`, `u16 styleIndex` |
| `ResXMLTree_attribute` | 20 | `u32 ns`, `u32 name`, `u32 rawValue`, `Res_value typedValue` |
| `Res_value` | 8 | `u16 size` (=8), `u8 res0` (=0), `u8 dataType`, `u32 data` |

### String pool flags

| Mask | Constant | Meaning |
|---|---|---|
| `0x00000001` | `SORTED_FLAG` | Strings sorted; binary search allowed |
| `0x00000100` | `UTF8_FLAG` | Strings are modified-UTF-8, else UTF-16LE |

| Encoding | Length prefix | Terminator |
|---|---|---|
| UTF-16LE | 1× `u16` (or 2× `u16` if high bit set, for >32767 units) | `u16` 0x0000 |
| UTF-8 | 1 byte UTF-16 length + 1 byte UTF-8 byte length (each may be 2 bytes if high bit set) | `u8` 0x00 |

---

## 9. `Res_value.dataType` constants

| Value | Constant | `data` interpretation |
|---|---|---|
| `0x00` | `TYPE_NULL` | 0 = undefined, 1 = empty |
| `0x01` | `TYPE_REFERENCE` | Resource ID `0xPPTTEEEE` |
| `0x02` | `TYPE_ATTRIBUTE` | Theme attribute ID |
| `0x03` | `TYPE_STRING` | Index into the string pool |
| `0x04` | `TYPE_FLOAT` | IEEE-754 single, bit-reinterpreted |
| `0x05` | `TYPE_DIMENSION` | Complex: unit in bits 0–3 (px/dip/sp/pt/in/mm) |
| `0x06` | `TYPE_FRACTION` | Complex: 0 = fraction, 1 = fraction-parent |
| `0x07` | `TYPE_DYNAMIC_REFERENCE` | Reference resolved at runtime (shared libs) |
| `0x08` | `TYPE_DYNAMIC_ATTRIBUTE` | Attribute resolved at runtime |
| `0x10` | `TYPE_INT_DEC` (`TYPE_FIRST_INT`) | Signed int, printed decimal |
| `0x11` | `TYPE_INT_HEX` | Signed int, printed hex |
| `0x12` | `TYPE_INT_BOOLEAN` | 0 = false, non-zero (`0xFFFFFFFF`) = true |
| `0x1C` | `TYPE_INT_COLOR_ARGB8` (`TYPE_FIRST_COLOR_INT`) | `#aarrggbb` |
| `0x1D` | `TYPE_INT_COLOR_RGB8` | `#rrggbb` |
| `0x1E` | `TYPE_INT_COLOR_ARGB4` | `#argb` |
| `0x1F` | `TYPE_INT_COLOR_RGB4` (`TYPE_LAST_INT`) | `#rgb` |

### Complex unit encoding (dimension / fraction)

| Bits | Field |
|---|---|
| 0–3 | `COMPLEX_UNIT` (px=0, dip=1, sp=2, pt=3, in=4, mm=5; fraction: 0=%, 1=%p) |
| 4–7 | `COMPLEX_RADIX` (0=23p0, 1=16p7, 2=8p15, 3=0p23) |
| 8–31 | `COMPLEX_MANTISSA` |

---

## 10. Resource ID bit layout

```
  31            24 23            16 15                             0
 +----------------+----------------+-------------------------------+
 |    package PP  |     type TT    |          entry EEEE           |
 +----------------+----------------+-------------------------------+
       8 bits           8 bits                 16 bits
```

| Package ID | Owner |
|---|---|
| `0x01` | `android` framework (`android.R`) |
| `0x02`–`0x7E` | Vendor/system packages, runtime resource overlays |
| `0x7F` | The application itself (`<pkg>.R`) — the common case |
| `0x00` | Dynamic / shared library placeholder, bound at runtime via `RES_TABLE_LIBRARY_TYPE` |
| `0x80`+ | Reserved; used by some feature-split toolchains (`aapt2 --allow-reserved-package-id`) |

| Expression | Resolves to |
|---|---|
| `@string/app_name` | Entry in type `string`, package `0x7f` |
| `@android:string/ok` | Package `0x01` |
| `?attr/colorPrimary` | `TYPE_ATTRIBUTE`, resolved through the current theme |
| `@0x7f0a0012` | Literal ID, no name lookup |

```bash
# host — name → ID and ID → value
aapt2 dump resources app.apk | grep -A3 'string/app_name'
aapt2 dump resources app.apk | head -50
```

---

## 11. `resources.arsc` chunk layout

| Chunk | Type | Header size | Key fields |
|---|---|---|---|
| `ResTable_header` | `0x0002` | 12 | `u32 packageCount`; followed by the global value string pool |
| `ResStringPool` | `0x0001` | 28 | Global value pool, then per-package type/key pools |
| `ResTable_package` | `0x0200` | 288 | `u32 id`, `char16 name[128]`, `u32 typeStrings`, `u32 lastPublicType`, `u32 keyStrings`, `u32 lastPublicKey`, `u32 typeIdOffset` |
| `ResTable_typeSpec` | `0x0202` | 16 | `u8 id`, `u8 res0`, `u16 res1`, `u32 entryCount` + entryCount × `u32` config-change flags |
| `ResTable_type` | `0x0201` | 20 + sizeof(config) | `u8 id`, `u8 flags`, `u16 reserved`, `u32 entryCount`, `u32 entriesStart`, `ResTable_config config` |
| `ResTable_lib` | `0x0203` | 12 | Dynamic package ID → package name map |
| `ResTable_overlayable` | `0x0204` | — | Overlayable resource declaration |

| `ResTable_type.flags` | Mask | Meaning |
|---|---|---|
| `FLAG_SPARSE` | `0x01` | Entry offsets are a sparse (key, offset) array |
| `FLAG_OFFSET16` | `0x02` | 16-bit entry offsets (Android 14+ size optimisation) |

| `ResTable_entry.flags` | Mask | Meaning |
|---|---|---|
| `FLAG_COMPLEX` | `0x0001` | Entry is a bag/map (`ResTable_map_entry`) |
| `FLAG_PUBLIC` | `0x0002` | Declared `<public>` |
| `FLAG_WEAK` | `0x0004` | May be overridden |
| `FLAG_COMPACT` | `0x0008` | Compact entry encoding (Android 14+) |

---

## 12. Native libraries

| Concern | Rule |
|---|---|
| Path | `lib/<abi>/lib<name>.so` |
| ABIs | `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86` |
| `android:extractNativeLibs="false"` | `.so` must be **STORED** and aligned; linker `mmap`s straight from the APK |
| `android:extractNativeLibs="true"` | Installer copies `.so` to `/data/app/~~*/<pkg>-*/lib/<arch>/` |
| Alignment (4 KB devices) | `.so` data must start on a 4096-byte boundary |
| Alignment (16 KB devices, Android 15+) | `.so` data on a 16384-byte boundary **and** ELF `LOAD` segments aligned to `2**14` |
| `useLegacyPackaging` (AGP) | `true` restores compression + extraction |

```bash
# host — which ABIs, and are they stored?
unzip -l app.apk | grep '\.so$'
unzip -v app.apk | awk '$0 ~ /\.so$/ {print $2, $8}'     # Method column: Stored / Defl:N
zipalign -c -P 16 -v 4 app.apk | grep -i ' \.so'
```

```bash
# host — is the ELF itself 16 KB-friendly?
llvm-readelf -l lib/arm64-v8a/libfoo.so | grep -A1 LOAD    # expect Align 0x4000
objdump -p libfoo.so | grep LOAD
```

---

## 13. Signature scheme comparison

| Scheme | Block ID | Lives where | Min API | Covers | Does **not** cover | Main weakness |
|---|---|---|---|---|---|---|
| v1 (JAR) | — | `META-INF/*.MF/.SF/.RSA` | 1 | Uncompressed **content** of listed entries | ZIP metadata, entry order, compression method, unlisted entries, `META-INF/*`, central directory, EOCD, extra fields, comment | Janus (CVE-2017-13156), Master Key class (CVE-2013-4787), arbitrary added files |
| v2 | `0x7109871a` | APK Signing Block | 24 (Android 7.0) | Whole-file: (1) entry data, (2) central directory, (3) EOCD with `cdOffset` patched | The signing block itself | Extra ID-value pairs are unauthenticated space |
| v3 | `0xf05368c0` | APK Signing Block | 28 (Android 9) | Same 3 chunks + `minSdk`/`maxSdk` + proof-of-rotation lineage | The signing block itself | Lineage trust decisions; downgrade to v2 on old OS |
| v3.1 | `0x1b93ad61` | APK Signing Block | 33 (Android 13) | Same as v3, but rotation only advertised to platforms ≥ a chosen SDK | Older platforms deliberately ignore it | Two effective identities across OS versions |
| v4 | — (side file) | `<name>.apk.idsig` | 30 (Android 11) | fs-verity Merkle root over the APK bytes | Nothing alone — **requires** a valid v2 or v3 | Detached file; useless without v2/v3 |

| Requirement | Rule |
|---|---|
| Apps targeting API ≥ 30 | Must be signed with **v2 or higher**; v1-only is rejected at install |
| `X-Android-APK-Signed: 2, 3` | Main attribute in `CERT.SF`; stops a v2/v3 → v1 downgrade on API ≥ 24 |
| v4 | Only meaningful for `adb install --incremental` / Play incremental delivery |

### v1 file trio

| File | Contents |
|---|---|
| `MANIFEST.MF` | `Manifest-Version`, `Created-By`, then per-entry sections: `Name: path` + `SHA-256-Digest: <base64>` over the **uncompressed** bytes |
| `<NAME>.SF` | `SHA-256-Digest-Manifest` (whole `MANIFEST.MF`), `SHA-256-Digest-Manifest-Main-Attributes`, `X-Android-APK-Signed`, then per-entry `SHA-256-Digest` over each MANIFEST.MF **section's raw bytes** |
| `<NAME>.RSA/.DSA/.EC` | PKCS#7 / CMS `SignedData` (RFC 5652) over `<NAME>.SF`, carrying the X.509 (RFC 5280) certificate chain |

### v2/v3 digest construction

```
chunk_digest = H( 0xA5 || u32le(chunk_len) || chunk_bytes )      # chunks of 1 MiB
top_digest   = H( 0x5A || u32le(chunk_count) || chunk_digest_0 || … )
```

Chunked over three regions, in order: entry contents `[0, signingBlockStart)`, the central
directory, and the EOCD **with its `cdOffset` field replaced by `signingBlockStart`**.

---

## 14. APK Signing Block layout

```
  ┌───────────────────────── entry data (…) ─────────────────────────┐
  │ u64  sizeOfBlock            (excludes this field itself)         │
  │ ┌── ID-value pair ──────────────────────────────────────────┐    │
  │ │ u64 pairLength   u32 id   byte[pairLength-4] value        │    │
  │ └───────────────────────────────────────────────────────────┘ ×N │
  │ u64  sizeOfBlock            (must equal the first)               │
  │ char magic[16] = "APK Sig Block 42"                              │
  └──────────────────────────────────────────────────────────────────┘
  ┌── Central Directory ──┐  ┌── EOCD (cdOffset points at sizeOfBlock) ──┐
```

| Block ID | Meaning | Confidence |
|---|---|---|
| `0x7109871a` | APK Signature Scheme v2 | Documented |
| `0xf05368c0` | APK Signature Scheme v3 | Documented |
| `0x1b93ad61` | APK Signature Scheme v3.1 | Documented |
| `0x42726577` | Verity padding block (aligns the block to 4096) | AOSP `apksig` |
| `0x2b09189e` | Source stamp, v1 layout | AOSP `apksig` |
| `0x6dff800d` | Source stamp, v2 layout | AOSP `apksig` |
| `0x504b4453` | Android Gradle Plugin dependency metadata ("SDKP") | Observed, undocumented |
| `0x2146444e` | Google Play "frosting" metadata, added at Play-serving time | Observed, undocumented |
| anything else | **Unknown — dump it and look** | — |

> **⚠️** Unknown ID-value pairs are *not* covered by any signature digest. They are a legitimate
> extension point and an equally legitimate place to smuggle a payload past a signature check.

### v2/v3 signer structure (all lengths are `u32` LE prefixes)

```
value = seq< signer >
signer(v2) = { signedData, seq<signature{u32 algId, bytes}>, publicKey(SPKI DER) }
signer(v3) = { signedData, u32 minSdk, u32 maxSdk, seq<signature>, publicKey }
signedData(v2) = { seq<digest{u32 algId, bytes}>, seq<certificate DER>, seq<attribute{u32 id, bytes}> }
signedData(v3) = { seq<digest>, seq<certificate DER>, u32 minSdk, u32 maxSdk, seq<attribute> }
```

| Sig algorithm ID | Algorithm |
|---|---|
| `0x0101` | RSASSA-PSS, SHA-256 |
| `0x0102` | RSASSA-PSS, SHA-512 |
| `0x0103` | RSASSA-PKCS1-v1_5, SHA-256 |
| `0x0104` | RSASSA-PKCS1-v1_5, SHA-512 |
| `0x0201` | ECDSA, SHA-256 |
| `0x0202` | ECDSA, SHA-512 |
| `0x0301` | DSA, SHA-256 |
| `0x0421` / `0x0423` / `0x0425` | Verity-tree digest variants (RSA / ECDSA / DSA, SHA-256) |

---

## 15. Signature scheme detection — one-liners

```bash
# host — the authoritative answer
apksigner verify -v --print-certs app.apk
```

```bash
# host — v1 present?
unzip -l app.apk | grep -E 'META-INF/.*\.(SF|RSA|DSA|EC)$'
```

```bash
# host — signing block present at all?
grep -abo 'APK Sig Block 42' app.apk
```

```bash
# host — which block IDs, without any Android tooling
python3 examples/parse_signing_block.py app.apk
```

```bash
# host — v4 side file?
ls -l app.apk.idsig
```

```bash
# host — X-Android-APK-Signed stripping-protection header
unzip -p app.apk META-INF/CERT.SF | head -20 | grep -i 'X-Android-APK-Signed'
```

```bash
# adb shell — what the platform actually recorded for an installed package
adb shell dumpsys package com.example | grep -E 'signatures|pkgFlags|versionCode|codePath'
adb shell pm dump com.example | grep -A5 'signing'
```

---

## 16. Certificate inspection

```bash
# host — DN, validity, key size, fingerprints
apksigner verify --print-certs -v app.apk
```

```bash
# host — pull the v1 PKCS#7 block and decode it
unzip -p app.apk META-INF/CERT.RSA > cert.p7
openssl pkcs7 -inform DER -in cert.p7 -print_certs -text | head -40
openssl pkcs7 -inform DER -in cert.p7 -print_certs -out chain.pem
openssl x509 -in chain.pem -noout -fingerprint -sha256 -subject -issuer -dates
```

```bash
# host — from the v2/v3 block instead (works even with no META-INF)
python3 examples/parse_signing_block.py --dump-certs app.apk
openssl x509 -inform DER -in signer0_cert0.der -noout -text
```

```bash
# host — keytool view of a keystore's certificate
keytool -list -v -keystore my.keystore -alias mykey -storepass android
```

| Fingerprint | Command suffix | Used by |
|---|---|---|
| SHA-256 | `-sha256` | Play App Signing, `hasSigningCertificate`, pinning |
| SHA-1 | `-sha1` | Legacy Google APIs, Firebase |
| MD5 | `-md5` | Legacy only; do not trust |

---

## 17. Full unpack → modify → rebuild → align → sign sequence

```bash
# host — 0. get the APK off the device
adb shell pm path com.example
adb pull /data/app/~~AbC==/com.example-XyZ==/base.apk ./base.apk
```

```bash
# host — 1. decode resources + smali
apktool d -f -o work base.apk
```

```bash
# host — 2. edit
$EDITOR work/AndroidManifest.xml
$EDITOR work/smali/com/example/RootCheck.smali
```

```bash
# host — 3. rebuild (apktool 2.9+ uses aapt2 by default)
apktool b work -o rebuilt.apk
```

```bash
# host — 4. align BEFORE signing (apksigner preserves alignment; zipalign after signing breaks v2)
zipalign -p -f -v 4 rebuilt.apk aligned.apk
# 16 KB page-size devices:
zipalign -p -f -P 16 -v 4 rebuilt.apk aligned.apk
```

```bash
# host — 5. one-time keystore
keytool -genkeypair -v \
  -keystore test.keystore -alias testkey \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -storepass android -keypass android \
  -dname "CN=Android Test, OU=Research, O=Lab, L=NA, ST=NA, C=NA"
```

```bash
# host — 6. sign
apksigner sign \
  --ks test.keystore --ks-key-alias testkey \
  --ks-pass pass:android --key-pass pass:android \
  --min-sdk-version 24 --max-sdk-version 36 \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --v4-signing-enabled false \
  --out final.apk aligned.apk
```

```bash
# host — 7. verify
apksigner verify -v --print-certs final.apk
zipalign -c -v 4 final.apk | tail -3
```

```bash
# host — 8. install (uninstall first if the signer changed)
adb uninstall com.example
adb install -r final.apk
```

```bash
# host — split/bundle apps must be installed together
adb install-multiple base.apk split_config.arm64_v8a.apk split_config.xxhdpi.apk
```

---

## 18. `apktool` reference

| Command | Effect |
|---|---|
| `apktool d app.apk` | Decode to `app/`; resources → XML, DEX → smali |
| `apktool d -f -o out app.apk` | Force overwrite into `out/` |
| `apktool d -s app.apk` | Keep `classes*.dex` raw, no smali |
| `apktool d -r app.apk` | Keep `resources.arsc` raw, no resource decoding |
| `apktool d --only-main-classes app.apk` | Only disassemble `classes*.dex` in the root |
| `apktool b out -o new.apk` | Rebuild |
| `apktool b out --use-aapt2` | Force aapt2 (default in 2.9+) |
| `apktool b out -c` | Copy the original `AndroidManifest.xml`/`META-INF` |
| `apktool if framework-res.apk` | Install a framework for decoding vendor resources |
| `apktool empty-framework-dir --force` | Clear the framework cache when decoding fails |
| `apktool -advance` | Show advanced flags |

| Artefact | Meaning |
|---|---|
| `apktool.yml` | Records `versionCode`, `versionName`, `minSdkVersion`, `doNotCompress` list, `sdkInfo` |
| `doNotCompress:` in `apktool.yml` | Entries rebuilt as STORED — must include `resources.arsc` and `.so` when `extractNativeLibs=false` |
| `unknown/` | Entries apktool did not recognise; copied back verbatim |
| `original/` | Original `AndroidManifest.xml` + `META-INF`, used by `-c` |

---

## 19. `aapt2` reference

| Command | Output |
|---|---|
| `aapt2 dump badging app.apk` | Package, versionCode/Name, SDK levels, permissions, features, launchable activity, native code ABIs |
| `aapt2 dump packagename app.apk` | Just the package name |
| `aapt2 dump permissions app.apk` | Declared and used permissions |
| `aapt2 dump xmltree app.apk --file AndroidManifest.xml` | Parsed AXML tree **using the platform parser** |
| `aapt2 dump xmltree app.apk --file res/xml/network_security_config.xml` | Any binary XML resource |
| `aapt2 dump xmlstrings app.apk --file AndroidManifest.xml` | Raw string pool of that AXML |
| `aapt2 dump resources app.apk` | Full `resources.arsc` dump: packages, types, configs, entries |
| `aapt2 dump strings app.apk` | Global value string pool |
| `aapt2 dump configurations app.apk` | Config qualifiers present |
| `aapt2 dump chunks app.apk --file resources.arsc` | Chunk-level dump (offsets, types, sizes) |
| `aapt2 dump apc file.flat` | Compiled resource container |

```bash
# host — legacy aapt equivalents (still on many systems)
aapt dump badging app.apk
aapt dump xmltree app.apk AndroidManifest.xml
```

---

## 20. `apksigner` reference

| Flag | Meaning |
|---|---|
| `sign` / `verify` / `rotate` / `lineage` | Subcommands |
| `--ks <file>` | Keystore (JKS/PKCS#12) |
| `--ks-key-alias <alias>` | Key alias inside the keystore |
| `--ks-pass pass:… \| file:… \| env:… \| stdin` | Keystore password source |
| `--key-pass pass:…` | Key password source |
| `--key <pk8> --cert <x509.pem>` | Sign from raw key + cert instead of a keystore |
| `--out <file>` | Output APK (in-place if omitted) |
| `--min-sdk-version N` / `--max-sdk-version N` | Which schemes are required/allowed |
| `--v1-signing-enabled true\|false` | JAR signing |
| `--v2-signing-enabled true\|false` | Scheme v2 |
| `--v3-signing-enabled true\|false` | Scheme v3 |
| `--v4-signing-enabled true\|false` | Scheme v4; writes `<out>.idsig` |
| `--v4-no-merkle-tree` | v4 signature without the embedded tree |
| `--verbose` / `-v` | Per-scheme verdicts |
| `--print-certs` | Certificate DN, fingerprints, key algorithm and size |
| `--print-certs-pem` | Emit the certificates as PEM |
| `--lineage <file>` | Supply a rotation lineage |
| `--rotation-min-sdk-version N` | v3.1: only advertise rotation to API ≥ N |
| `--append-to-lineage` | Extend an existing lineage |

```bash
# host — key rotation lineage
apksigner rotate --out lineage.bin \
  --old-signer --ks old.jks --ks-key-alias old --ks-pass pass:android \
  --new-signer --ks new.jks --ks-key-alias new --ks-pass pass:android
apksigner lineage --in lineage.bin --print-certs -v
```

---

## 21. `zipalign`, `jadx`, `baksmali`, `bundletool`

| Tool | Command | Purpose |
|---|---|---|
| zipalign | `zipalign -p -f -v 4 in.apk out.apk` | 4-byte align; `-p` page-align `.so` |
| zipalign | `zipalign -P 16 -f 4 in.apk out.apk` | 16 KB page alignment for Android 15+ |
| zipalign | `zipalign -c -v 4 app.apk` | Check only; exit 0 = aligned |
| jadx | `jadx -d out app.apk` | Decompile DEX to Java |
| jadx | `jadx --show-bad-code -d out app.apk` | Keep undecompilable methods as comments |
| jadx | `jadx -e -d out app.apk` | Also export Gradle project structure |
| jadx | `jadx --no-res -d out app.apk` | Skip resources (faster) |
| jadx | `jadx-gui app.apk` | Interactive |
| baksmali | `baksmali d classes.dex -o smali_out` | DEX → smali |
| smali | `smali a smali_out -o classes.dex` | smali → DEX |
| dexdump | `dexdump -f classes.dex` | Header + class summary |
| bundletool | `bundletool build-apks --bundle=app.aab --output=app.apks --mode=universal` | AAB → single fat APK |
| bundletool | `bundletool build-apks --bundle=app.aab --output=app.apks --ks=k.jks --ks-key-alias=a` | Signed split set |
| bundletool | `bundletool install-apks --apks=app.apks` | Install the right splits |
| bundletool | `bundletool extract-apks --apks=app.apks --output-dir=out --device-spec=spec.json` | Pull matching splits |
| bundletool | `bundletool get-device-spec --output=spec.json` | Capture the connected device's config |
| bundletool | `bundletool dump manifest --bundle app.aab` | Manifest from the bundle |
| bundletool | `bundletool validate --bundle app.aab` | Structural checks |

---

## 22. Splits and App Bundles

| Split kind | Typical name | Contents |
|---|---|---|
| Base | `base.apk` | Manifest, `classes*.dex`, `resources.arsc`, default resources |
| ABI config | `split_config.arm64_v8a.apk` | `lib/arm64-v8a/*.so` only |
| Density config | `split_config.xxhdpi.apk` | Density-qualified drawables |
| Language config | `split_config.en.apk` | Locale-qualified strings |
| Feature | `split_<featurename>.apk` | On-demand feature module code + resources |

| Rule | Detail |
|---|---|
| Signer | Every split **must** be signed by the same signer as the base |
| Manifest | Splits carry `android:isSplitRequired`, `split="…"`, and `<manifest split=>` |
| Install | `adb install-multiple` or `pm install-create` / `install-write` / `install-commit` |
| Missing split | `INSTALL_FAILED_MISSING_SPLIT` |

```bash
# adb shell — enumerate the installed split set
adb shell pm path com.example
adb shell dumpsys package com.example | grep -E 'splitNames|codePath|resourcePath'
```

```bash
# host — session-based install
adb shell pm install-create -r -t
adb shell pm install-write -S $(stat -c%s base.apk) <SESSION> base.apk < base.apk
adb shell pm install-commit <SESSION>
```

---

## 23. Failure messages and causes

### `adb install` / `pm install`

| Message | Cause | Fix |
|---|---|---|
| `INSTALL_PARSE_FAILED_NO_CERTIFICATES` | APK unsigned, or the ZIP was rewritten after signing | Re-run `apksigner sign` as the **last** step |
| `INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES` | Entries covered by different v1 signers | Delete `META-INF/*` from the working copy and re-sign cleanly |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | Same package name, different signer than the installed copy | `adb uninstall <pkg>` first, or change `package=` |
| `INSTALL_FAILED_INVALID_APK` | Malformed ZIP, bad central directory, or truncated file | Rebuild; check `unzip -t app.apk` |
| `INSTALL_PARSE_FAILED_MANIFEST_MALFORMED` | AXML the platform cannot parse | Rebuild the manifest via apktool/aapt2, not by hand |
| `INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION` | Usually a broken manifest or unreadable ZIP entry | Check `adb logcat -s PackageParser PackageManager` |
| `INSTALL_FAILED_VERSION_DOWNGRADE` | `versionCode` lower than installed | Bump `versionCode`, or `adb install -r -d` |
| `INSTALL_FAILED_TEST_ONLY` | `android:testOnly="true"` in the manifest | `adb install -t`, or strip the attribute |
| `INSTALL_FAILED_MISSING_SPLIT` | Base installed without its required splits | `adb install-multiple` with the full set |
| `INSTALL_FAILED_NO_MATCHING_ABIS` | No `lib/<abi>/` for the device | Add the right ABI split, or use a universal APK |
| `INSTALL_FAILED_DEPRECATED_SDK_VERSION` | `targetSdkVersion` below the platform minimum | Raise `targetSdkVersion` in the manifest |
| `INSTALL_FAILED_INVALID_INSTALL_LOCATION` | `installLocation` conflict | Remove `android:installLocation` |
| `Failure [-124: … Requires development platform …]` | `<uses-sdk>` references a preview codename | Set a numeric `targetSdkVersion` |

### `apksigner`

| Message | Cause |
|---|---|
| `DOES NOT VERIFY … JAR entry X not covered by signature` | A file was added after v1 signing |
| `ERROR: … ZIP central directory digest did not verify` | The ZIP was modified after v2/v3 signing |
| `ERROR: APK Signature Scheme v2 signature did not verify` | Entry bytes changed, or a signing-block pair was inserted incorrectly |
| `ERROR: Missing META-INF/MANIFEST.MF` | v1 required for the chosen `--min-sdk-version` but absent |
| `Keystore was tampered with, or password was incorrect` | Wrong `--ks-pass` |
| `No key with alias 'x' found in keystore` | Wrong `--ks-key-alias`; list with `keytool -list -keystore` |
| `Signer #1 … not JAR-signed but v2 present` | Only relevant below API 24 |
| `WARNING: META-INF/… not protected by signature` | v1-only signing plus stray META-INF files |
| `v4 signature requires a v2 or v3 signature` | `--v4-signing-enabled true` with both disabled |

### `apktool`

| Message | Cause |
|---|---|
| `brut.androlib.AndrolibException: Could not decode arsc file` | Non-standard/obfuscated `resources.arsc`; retry with `-r` |
| `Could not find framework resource` | Vendor framework needed: `apktool if framework-res.apk` |
| `invalid resource directory name` | Hand-edited `res/` folder with a bad config qualifier |
| `Unable to rebuild apk … aapt2 exited with code 1` | Malformed XML you edited; read the aapt2 error above it |
| `Multiple resources … w/ name` | Duplicate resource declarations after a merge |
| `Exception in thread "main" java.lang.OutOfMemoryError` | Large APK; raise heap in the wrapper script |

---

## 24. ZIP-level attack classes — detection commands

| Class | What it is | Detection |
|---|---|---|
| Janus (CVE-2017-13156) | DEX prepended to a v1-only APK; ZIP still parses from the tail, ART reads DEX magic at offset 0 | First 4 bytes ≠ `50 4B 03 04`; require v2+ |
| Master Key class (CVE-2013-4787) | Duplicate entry names; verifier and loader disagree on which copy wins | `zipinfo -1 app.apk \| sort \| uniq -d` |
| LFH/CDFH divergence | Name, size or method differ between the two headers | `examples/parse_apk_zip.py` cross-check |
| Unsigned trailing space | Data after the EOCD, or an oversized EOCD comment | `commentLength` > 0 in the EOCD |
| Signing-block smuggling | Payload in an unknown ID-value pair | `examples/parse_signing_block.py` |
| ZipSlip | `ZipEntry.getName()` contains `../` and app code extracts without normalising | `zipinfo -1 app.apk \| grep -E '(^/|\.\./)'` |
| AXML parser confusion | apktool/jadx/MobSF render a different manifest than `ResXMLParser` does | Diff `apktool d` vs `aapt2 dump xmltree` vs `dumpsys package` |

```bash
# host — the three-way manifest diff that catches parser confusion
apktool d -f -o /tmp/at app.apk && xmllint --format /tmp/at/AndroidManifest.xml > /tmp/a.xml
aapt2 dump xmltree app.apk --file AndroidManifest.xml > /tmp/b.txt
adb shell dumpsys package com.example > /tmp/c.txt
diff <(grep -oE 'android:[a-zA-Z]+' /tmp/a.xml | sort -u) \
     <(grep -oE 'android:[a-zA-Z]+' /tmp/b.txt | sort -u)
```

```java
// Android app code — the ZipSlip-safe extraction pattern
File out = new File(destDir, entry.getName()).getCanonicalFile();
if (!out.toPath().startsWith(destDir.getCanonicalFile().toPath())) {
    throw new SecurityException("Zip path traversal: " + entry.getName());
}
```

> Apps targeting API 34+ get `dalvik.system.ZipPathValidator` enforcement by default: entry names
> containing `..` or starting with `/` raise `ZipException` from `ZipFile`/`ZipInputStream`.

---

## 25. Runtime self-signature checks — API surface

| API | Since | Returns |
|---|---|---|
| `PackageManager.GET_SIGNATURES` (`0x40`) | 1, deprecated 28 | `PackageInfo.signatures[]` |
| `PackageManager.GET_SIGNING_CERTIFICATES` (`0x08000000`) | 28 | `PackageInfo.signingInfo` |
| `SigningInfo.getApkContentsSigners()` | 28 | Current signer(s) |
| `SigningInfo.getSigningCertificateHistory()` | 28 | Rotation lineage |
| `SigningInfo.hasMultipleSigners()` | 28 | Multi-signer APK |
| `PackageManager.hasSigningCertificate(pkg, bytes, type)` | 28 | Lineage-aware boolean check |
| `PackageManager.checkSignatures(a, b)` | 1 | See table below |
| `getPackageInfo(String, PackageInfoFlags)` | 33 | Flags wrapper form |

| `checkSignatures` result | Value |
|---|---|
| `SIGNATURE_MATCH` | `0` |
| `SIGNATURE_NEITHER_SIGNED` | `1` |
| `SIGNATURE_FIRST_NOT_SIGNED` | `-1` |
| `SIGNATURE_SECOND_NOT_SIGNED` | `-2` |
| `SIGNATURE_NO_MATCH` | `-3` |
| `SIGNATURE_UNKNOWN_PACKAGE` | `-4` |

| `hasSigningCertificate` cert type | Value |
|---|---|
| `CERT_INPUT_RAW_X509` | `0` |
| `CERT_INPUT_SHA256` | `1` |

```bash
# host — find the check in a decompiled app
grep -rn "GET_SIGNING_CERTIFICATES\|GET_SIGNATURES\|checkSignatures\|hasSigningCertificate" out/sources/
grep -rn "getPackageInfo" out/smali/ | grep -i sign
```

```bash
# host — Frida hooks for the same
frida -U -f com.example -l scripts/apk-signature-hooks.js
```

---

## 26. Quick recall

| Question | Answer |
|---|---|
| Signature at offset 0 of every APK | `50 4B 03 04` |
| EOCD signature | `50 4B 05 06` |
| Field at EOCD+16 | Central directory offset |
| Signing block magic | `APK Sig Block 42`, 16 bytes, immediately before the CD |
| v2 block ID | `0x7109871a` |
| v3 block ID | `0xf05368c0` |
| v3.1 block ID | `0x1b93ad61` |
| What v2 does **not** cover | The signing block itself |
| Resource ID layout | `0xPPTTEEEE` |
| App package ID | `0x7F` |
| UTF-8 string pool flag | `0x00000100` |
| Start-element chunk type | `0x0102` |
| Order of operations | align → sign (never sign → align) |
| Minimum scheme for `targetSdk ≥ 30` | v2 |
