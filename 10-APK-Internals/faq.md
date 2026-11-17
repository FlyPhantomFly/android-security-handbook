# 10 — APK Internals · FAQ

Real questions learners ask about APK internals, answered directly. Nothing here is too basic to
ask. If a term is unfamiliar the first time it appears, it is defined in the same paragraph.

Related chapters: [09-Android-App-Internals](../09-Android-App-Internals/README.md) ·
[12-DEX-Internals](../12-DEX-Internals/README.md) · [32-Manifest](../32-Manifest/README.md) ·
[34-Cryptography](../34-Cryptography/README.md) · [38-TamperDetection](../38-TamperDetection/README.md) ·
[40-Obfuscation](../40-Obfuscation/README.md) · [56-JADX](../56-JADX/README.md)

---

## 1. Is an APK really just a ZIP file? Can I rename it to `.zip`?

Yes, and yes. An APK (Android Package) is a ZIP archive with a fixed set of expected entries and a
signature attached. There is no proprietary header, no encryption, and no wrapper format. If you
copy `app.apk` to `app.zip` and double-click it, your operating system's archive manager will open
it and show you `AndroidManifest.xml`, `classes.dex`, `resources.arsc`, `res/`, `lib/` and
`META-INF/`.

The important caveat is what happens on the way back out. Renaming is free; *re-zipping* is not.
If you extract an APK, change a file, and compress the folder again with a normal ZIP tool, you
will produce a structurally valid ZIP that Android will refuse to install, because you have
destroyed the signature and probably also the required alignment and the required "stored, not
compressed" property of `resources.arsc` and any `lib/*.so`. See question 6.

```bash
# host — prove it to yourself without renaming anything
unzip -l app.apk | head -20
file app.apk        # "Android package (APK), with ... " or "Zip archive data"
```

> **Definition — ZIP central directory.** The index at the end of a ZIP file listing every
> entry and where its data begins. ZIP readers find it by reading the last 22+ bytes of the file
> (the End Of Central Directory record), not by reading from the start. This "read from the end"
> behaviour is the root cause of several Android signature bugs.

---

## 2. Why can't I just open `AndroidManifest.xml` in a text editor?

Because the manifest inside a built APK is not text. It is *AXML*, Android's compiled binary XML
format. During the build, `aapt2` takes your human-readable XML and converts it into a chunk-based
binary structure: a header, a string pool holding every distinct string in the document exactly
once, an optional resource-map chunk, and then a stream of records describing namespace
declarations, element starts, attributes and element ends. Element and attribute names are stored
as 32-bit indices into the string pool, and attribute values are stored as 8-byte `Res_value`
structures carrying a type tag and a 32-bit payload.

There are three reasons Android does it this way. Parsing binary chunks is far faster than parsing
text at every app launch and at every `PackageManager` query. The string pool deduplicates repeated
strings, shrinking the file. And storing values pre-typed (`TYPE_INT_BOOLEAN`, `TYPE_REFERENCE`,
`TYPE_STRING`) means the framework never has to interpret the string `"true"` at runtime.

If you open it in a text editor you will see a sprinkling of recognisable ASCII (`android`,
`activity`, package names) surrounded by binary noise, because the UTF-16 string pool puts a NUL
byte between every ASCII character. To read it properly, use a parser:

```bash
# host — the platform's own parser, closest to what the phone sees
aapt2 dump xmltree app.apk --file AndroidManifest.xml
```

```bash
# host — apktool reconstructs editable text XML
apktool d -f -o work app.apk && cat work/AndroidManifest.xml
```

```bash
# host — the parser in this chapter, which also reports structural anomalies
python3 examples/parse_axml.py --extract app.apk
```

To *edit* it, decode with apktool, edit the text, and rebuild — apktool re-encodes to AXML for you.
Hand-patching bytes is possible but you must fix every downstream offset and chunk size, which is
why nobody does it except when deliberately building parser-confusion test cases.

---

## 3. Why does apktool show me a different manifest than the phone acts on?

Usually it does not, and when it does, that is a finding rather than a bug in your workflow.

Three different parsers are involved. `apktool` uses its own Java AXML reader. `aapt2 dump xmltree`
uses AOSP's own `ResXMLTree` code compiled for the host. The device uses `ResXMLParser` inside
`libandroidfw`, driven by the package parsing code in `frameworks/base/core/java/android/content/pm/parsing/`.
These three implementations differ in how strictly they validate `headerSize`, chunk `size`,
string-pool counts, and trailing data. A crafted APK can therefore be built so that a reversing
tool renders a benign manifest while the platform reads a different one.

The general shape of the technique is always the same: exploit a field one parser trusts and
another ignores. Examples of the class include declaring a `headerSize` larger than the real header
so a lenient parser skips over a record that the strict parser reads, declaring string-pool counts
that disagree with the offset table, or appending an extra chunk after the root element's
`END_ELEMENT` that one implementation keeps parsing and another stops at.

The defensive answer is never to trust one tool. Do a three-way comparison:

```bash
# host — tool view
apktool d -f -o /tmp/at app.apk && cat /tmp/at/AndroidManifest.xml

# host — AOSP host-side parser view
aapt2 dump xmltree app.apk --file AndroidManifest.xml
```

```bash
# adb shell — what the platform actually recorded after installing
adb shell dumpsys package com.example | sed -n '1,80p'
adb shell pm dump com.example | grep -iE 'debuggable|flags|permission|exported'
```

If the three disagree on `android:debuggable`, an `exported` attribute, `networkSecurityConfig`, or
a permission, you have found parser confusion. Chapter [32-Manifest](../32-Manifest/README.md)
covers the attribute semantics; `examples/parse_axml.py` in this chapter prints an anomaly report
designed exactly for this check.

---

## 4. What is the difference between `apktool b` and just re-zipping the folder?

They solve different problems. `apktool d` does not merely extract the ZIP — it *decodes* it. The
binary manifest becomes text XML, `resources.arsc` becomes a `res/` tree of readable XML plus a
`res/values/public.xml` mapping resource IDs to names, and `classes*.dex` becomes Smali assembly.
`apktool b` reverses all of that: it recompiles the resource tree with `aapt2` back into a new
`resources.arsc` and binary manifest, assembles the Smali back into DEX, and packages the result
with the right compression settings recorded in `apktool.yml`.

Plain re-zipping does none of that. If you decoded with apktool and then zipped the folder, you
would be packaging text XML and Smali files, which the platform cannot read at all.

Even when you have only extracted (not decoded) an APK, plain re-zipping still causes problems.
Your ZIP tool will happily deflate `resources.arsc` and every `lib/*.so`, and it will place entry
data at arbitrary offsets. Android requires `resources.arsc` to be STORED and 4-byte aligned for
apps targeting API 30 and above, and requires `lib/*.so` to be STORED and page-aligned when
`android:extractNativeLibs="false"`. It also destroys the signature in every case.

| Approach | Manifest | Resources | Code | Compression control | Signature |
|---|---|---|---|---|---|
| `apktool d` / `apktool b` | Decoded and re-encoded | Decoded and recompiled | Smali round-trip | Driven by `apktool.yml` `doNotCompress` | Must re-sign |
| `unzip` / `zip -r` | Untouched binary | Untouched binary | Untouched DEX | Wrong by default | Must re-sign |
| `zip app.apk edited.file` (in-place update) | Untouched | Untouched | Untouched | Wrong for stored entries | Must re-sign |

If you only need to swap one raw file and want the rest bit-identical, updating in place and then
re-aligning and re-signing is the least invasive route:

```bash
# host — surgical replacement, then fix alignment and signature
cp app.apk patched.apk
zip -X -0 patched.apk assets/config.json          # -0 = store, -X = no extra fields
zipalign -p -f 4 patched.apk aligned.apk
apksigner sign --ks test.keystore --ks-key-alias testkey --ks-pass pass:android \
  --key-pass pass:android --out final.apk aligned.apk
```

---

## 5. Do I need `zipalign` if I use `apksigner`?

You need alignment, and the order matters. `zipalign` rewrites the ZIP so that each uncompressed
entry's data starts on a 4-byte boundary (and, with `-p`, so that `.so` files start on a page
boundary). This exists because Android memory-maps `resources.arsc` and, when
`extractNativeLibs="false"`, the native libraries directly out of the APK file. `mmap` can only map
at page-granular offsets and the resource code reads 32-bit values directly out of the mapping, so
misaligned data means either a copy or an unaligned access.

`apksigner` does not align, but it *preserves* existing alignment: it knows about alignment
requirements and will not shift entry data when it inserts the signing block. So the correct order
is always **align first, sign second**. If you run `zipalign` after `apksigner`, zipalign rewrites
entry offsets, which invalidates the v2/v3 whole-file digests and you get
`INSTALL_PARSE_FAILED_NO_CERTIFICATES` or an apksigner verification error.

```bash
# host — correct order
zipalign -p -f -v 4 rebuilt.apk aligned.apk
apksigner sign --ks test.keystore --ks-key-alias testkey --ks-pass pass:android \
  --key-pass pass:android --out final.apk aligned.apk
apksigner verify -v final.apk
```

```bash
# host — verify alignment without changing anything
zipalign -c -v 4 final.apk | tail -5
zipalign -c -P 16 -v 4 final.apk | grep -i '\.so'    # 16 KB page devices, Android 15+
```

For Android 15 and newer devices that use a 16 KB memory page size, add `-P 16`. That only fixes the
ZIP-level placement; the shared objects themselves must also be linked with 16 KB segment alignment,
which is a build-time NDK setting covered in [15-Native-Code](../15-Native-Code/README.md).

---

## 6. Why does my rebuilt APK not install?

Work through the error string `adb install` prints. Each one has a specific meaning.

| Error | What it actually means | Fix |
|---|---|---|
| `INSTALL_PARSE_FAILED_NO_CERTIFICATES` | The platform found no valid signature. Either you never signed, or you modified the ZIP after signing (very often by running `zipalign` last). | Re-run `apksigner sign` as the final step. |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | A package with the same `package` name is already installed, signed by a different certificate. Android will never let one signer replace another's app. | `adb uninstall com.example` first, or rename the package. |
| `INSTALL_FAILED_INVALID_APK` | The ZIP is structurally broken: truncated, bad central directory, or an entry the installer cannot read. | `unzip -t app.apk`; rebuild from scratch. |
| `INSTALL_PARSE_FAILED_MANIFEST_MALFORMED` | The binary manifest failed to parse. Usually a hand-edited AXML or an XML file apktool could not re-encode. | Rebuild via apktool; read the aapt2 error it printed. |
| `INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES` | Different entries are covered by different v1 signers, typically because old `META-INF/*.SF`/`*.RSA` files survived your rebuild. | Delete everything under `META-INF/` before re-signing. |
| `INSTALL_FAILED_VERSION_DOWNGRADE` | Your `versionCode` is lower than the installed one. | Bump it, or `adb install -r -d`. |
| `INSTALL_FAILED_TEST_ONLY` | `android:testOnly="true"` in the manifest. | `adb install -t`, or remove the attribute. |
| `INSTALL_FAILED_MISSING_SPLIT` | The app is a split/bundle app and you installed only `base.apk`. | `adb install-multiple base.apk split_*.apk`. |
| `INSTALL_FAILED_NO_MATCHING_ABIS` | No `lib/<abi>/` directory matches the device. | Install the correct ABI split or a universal APK. |
| `INSTALL_FAILED_DEPRECATED_SDK_VERSION` | `targetSdkVersion` is below the platform's minimum (Android 14+ enforce a floor). | Raise `targetSdkVersion` in the manifest. |

When the message is not specific enough, watch the log while installing:

```bash
# host — in one terminal
adb logcat -c && adb logcat -s PackageManager PackageParser installd ApkSignatureVerifier
# host — in another
adb install -r final.apk
```

---

## 7. Why did adding a file to the APK break the v2 signature but not the v1 one?

Because the two schemes cover different byte ranges, and that difference is the whole point of v2.

APK Signature Scheme v1 is inherited from Java's JAR signing. `META-INF/MANIFEST.MF` contains one
section per entry with a `SHA-256-Digest` of that entry's *uncompressed content*. The verifier
walks the manifest's list and checks each listed entry. An entry that is not listed is not
checked. So adding a brand-new file to a v1-signed APK does not break anything: no digest covers it.
That is exactly what made repackaging trivial before Android 7.0.

APK Signature Scheme v2 digests the file as a whole. It splits the APK into three regions — the
contents of the ZIP entries, the central directory, and the End Of Central Directory record with
its central-directory-offset field replaced by the offset of the signing block — chunks each region
into 1 MiB pieces, hashes every chunk, and hashes the concatenation of chunk digests. Adding a file
changes the entry-content region, adds a central directory record, and changes the central
directory size and offset. All three digests change, so verification fails immediately.

The single carve-out is the APK Signing Block itself, which cannot be inside its own digest. That
means additional ID-value pairs inside the signing block are unauthenticated. That is by design so
that Google Play, the Android Gradle Plugin, and source-stamp tooling can attach metadata without
re-signing — and it is also where an attacker can park data.

```bash
# host — see it happen
cp app.apk broken.apk
zip broken.apk /etc/hostname
apksigner verify -v broken.apk
# Verified using v1 scheme (JAR signing): true      <-- if the app had v1
# Verified using v2 scheme (APK Signature Scheme v2): false
```

> **Pentester's Note** If an app is v1-only in 2026, that is a finding on its own. It cannot be
> installed at all if it targets API 30+, and if it targets lower it is exposed to the whole
> repackaging class. Report it against MASVS-CODE.

---

## 8. What is the difference between v2 and v3 if both verify?

v2 and v3 protect the same bytes with the same chunked digest construction. v3 adds two things.

First, the signed data includes the SDK version range (`minSdk` and `maxSdk`) that this signer is
valid for. That lets one APK carry signer information scoped to platform versions.

Second, and far more importantly, v3 introduces **key rotation**. A v3 block can carry a
*proof-of-rotation* lineage: an ordered chain in which each certificate is signed by the previous
one, proving that the holder of the old key authorised the new key. The platform stores the lineage
and can accept the new signer for an app that was originally installed with the old one, while apps
that pinned the old certificate can still be told the app has the old identity, depending on the
capability flags recorded in the lineage.

Capabilities recorded per lineage step control what the *old* certificate is still trusted for:
sharing a UID, granting signature-level permissions, being an authenticator, and being accepted by
`hasSigningCertificate`. That granularity is why an app should call
`PackageManager.hasSigningCertificate()` rather than comparing raw signature bytes — the former is
lineage-aware, the latter breaks when a legitimate developer rotates their key.

v3.1 (block ID `0x1b93ad61`, Android 13 / API 33) exists because rotation broke on some older
platforms: it lets a developer advertise rotation only to platforms at or above a chosen SDK, while
older platforms continue to see the pre-rotation v3 block. In practice you can encounter an APK
whose *effective* signer identity differs depending on the Android version reading it.

```bash
# host — inspect the lineage
apksigner lineage --in lineage.bin --print-certs -v
apksigner verify -v --print-certs app.apk
```

---

## 9. What is v4 and why is there a separate `.idsig` file?

APK Signature Scheme v4 exists to make *incremental installation* possible. Normally the whole APK
must be present and hashed before the app can start. v4 instead computes an fs-verity style Merkle
tree over the APK — a tree of SHA-256 hashes over 4096-byte blocks, where each level hashes the
level below — and signs only the root of that tree. The signature and the tree live in a sibling
file named `<name>.apk.idsig`, not inside the APK.

With the tree available, the kernel can verify any individual 4 KB block on demand. That means the
system can start running an app while the rest of the APK is still streaming in, verifying blocks
as they arrive. That is how Play's instant-start delivery and `adb install --incremental` work.

v4 is never sufficient on its own. The v4 signature explicitly references the v2 or v3 signature, so
an APK must carry one of those as well. If you pass `--v4-signing-enabled true` with v2 and v3 both
disabled, `apksigner` refuses.

```bash
# host — produce a v4 signature
apksigner sign --ks test.keystore --ks-key-alias testkey --ks-pass pass:android \
  --key-pass pass:android --v2-signing-enabled true --v4-signing-enabled true \
  --out final.apk aligned.apk
ls -l final.apk final.apk.idsig
adb install --incremental final.apk
```

---

## 10. Where exactly does the APK Signing Block live, and how do I find it by hand?

It sits in the one place a ZIP reader never looks: between the last entry's data and the first
central directory record. A ZIP reader starts at the End Of Central Directory record, reads the
central directory offset from it, jumps there, and reads entry records. Anything in the gap before
the central directory is invisible to a normal ZIP parser, which is why the block can be inserted
without breaking ZIP compatibility.

The block is self-describing from both ends:

```
  u64  sizeOfBlock                    <- start; excludes this 8-byte field
  { u64 pairLength; u32 id; bytes value }   x N
  u64  sizeOfBlock                    <- must equal the first
  char magic[16] = "APK Sig Block 42"
```

The last 16 bytes before the central directory are the magic string, and the 8 bytes before that
repeat the block size, so you can walk backwards from the central directory offset with certainty.
By hand:

```bash
# host — 1. find the EOCD and read the central directory offset at EOCD+16
python3 - <<'EOF'
d = open('app.apk','rb').read()
e = d.rfind(b'PK\x05\x06')
import struct
cd_off = struct.unpack_from('<I', d, e+16)[0]
print('EOCD at', hex(e), 'CD at', hex(cd_off))
print('magic  ', d[cd_off-16:cd_off])
print('size   ', struct.unpack_from('<Q', d, cd_off-24)[0])
EOF
```

```bash
# host — 2. or just grep for the magic and confirm it is where you expect
grep -abo 'APK Sig Block 42' app.apk
```

`examples/parse_signing_block.py` in this chapter does the whole walk, names known block IDs, and
dumps unknown ones so you can look for hidden payloads.

---

## 11. What does Janus (CVE-2017-13156) actually do, in bytes?

Janus is the cleanest illustration of the gap between "what the signature covers" and "what the
runtime reads".

Take an APK signed **only** with v1. Prepend a valid DEX file to the front of it, producing
`newfile = dexbytes || originalapk`. Two independent consumers now look at those bytes.

The package manager needs to verify the signature. It parses the file as a ZIP, which means it
scans backwards from the end for the EOCD, reads the central directory offset, and walks the
entries. Because v1 only digests the *content* of the entries listed in `MANIFEST.MF`, and those
contents are unchanged, the v1 signature still verifies. The affected ZIP handling tolerated the
prefix by treating offsets relative to the discovered structures rather than rejecting the file
outright.

The runtime needs to load code. The DEX loading path looked at the beginning of the file, found the
DEX magic `64 65 78 0a 30 33 35 00` (`"dex\n035\0"`), and treated the file as a bare DEX — executing
the attacker's prepended classes instead of the ones inside the ZIP.

So one file, verified as the developer's, executes as the attacker's. The fix is structural: an
APK Signature Scheme v2 signature digests the entire byte range from offset 0, so any prepended
bytes change the digest and verification fails. Android 7.0 and later, when a v2 block is present,
use it in preference to v1, and apps targeting API 30 and above must have at least v2. Devices
running Android 5.0 through 8.0 received the patch in the December 2017 security bulletin.

The detection is trivial:

```bash
# host — a legitimate APK begins with the local file header signature
head -c 4 app.apk | xxd -p          # expect 504b0304, NOT 6465780a
apksigner verify -v app.apk | grep -E 'v1 scheme|v2 scheme'
```

---

## 12. What is the "Master Key" bug class (CVE-2013-4787)?

It is the class of bugs where **two different pieces of Android code disagree about which bytes an
entry name refers to**. The ZIP format does not forbid two entries with the same name. When an
archive contains two entries called `classes.dex`, the code that verifies the signature and the code
that loads the file must agree on which one is real. In the original 2013 issue they did not: the
Java-side verification consumed one instance while the native extraction/loading path used the other.
An attacker could therefore take a legitimately signed APK, append a second `classes.dex` containing
their own code, and have the platform verify the original while executing the replacement.

Two related variants were disclosed in the same period, both exploiting inconsistencies rather than
duplicate names as such: one abused a mismatch in how the file-name length field was interpreted
between the local file header and the central directory, and another abused an integer size/sign
handling difference so that a length value read as one width in one parser was read as another
width elsewhere. Describe these as the *class* — parser disagreement over ZIP metadata — rather
than trying to attribute each variant to a specific identifier.

Modern Android mitigates the class in several ways: `libziparchive` rejects duplicate entry names in
the central directory, whole-file v2/v3 signatures make any post-signing edit fatal, and the
verification and loading paths share the same ZIP implementation. It is still worth checking,
because third-party apps that parse APKs or other ZIP archives themselves reintroduce the class all
the time.

```bash
# host — duplicate entry names in any archive
zipinfo -1 app.apk | sort | uniq -d
python3 examples/parse_apk_zip.py app.apk | grep -i duplicate
```

---

## 13. What is ZipSlip and why does it appear in the APK chapter?

ZipSlip is path traversal through archive entry names. `java.util.zip.ZipEntry.getName()` returns
whatever string was in the archive, including `../../../../data/data/com.example/files/evil.so`.
Application code that does `new File(destDir, entry.getName())` and writes to it will happily write
outside `destDir` — into the app's own private directory, over a native library, over a shared
preferences file, or over a downloaded DEX that the app later loads.

It belongs in this chapter because the vulnerable pattern is nearly always *an app processing an
archive*, and archives are the thing this chapter is about. Apps that download OTA content packs,
expansion files, plugin bundles, or user-supplied ZIPs are the usual carriers.

The safe pattern canonicalises the destination and checks containment:

```java
// Android app code — safe extraction
File root = destDir.getCanonicalFile();
for (ZipEntry e; (e = zin.getNextEntry()) != null; ) {
    File out = new File(root, e.getName()).getCanonicalFile();
    if (!out.toPath().startsWith(root.toPath())) {
        throw new SecurityException("Zip path traversal blocked: " + e.getName());
    }
    if (e.isDirectory()) { out.mkdirs(); continue; }
    out.getParentFile().mkdirs();
    try (OutputStream os = new FileOutputStream(out)) { /* copy */ }
}
```

Since Android 14 (API 34), the platform helps: `dalvik.system.ZipPathValidator` is enforced by
default for apps targeting API 34 and above, and `ZipFile`/`ZipInputStream` throw `ZipException` for
entry names containing `..` or beginning with `/`. Apps can opt out with
`ZipPathValidator.clearCallback()`, so seeing that call in decompiled code is itself worth flagging.

```bash
# host — hunt for the vulnerable pattern in a decompiled app
grep -rn "getNextEntry\|ZipInputStream\|ZipFile" out/sources/ | head
grep -rn "getName()" out/sources/ | grep -i entry
grep -rn "ZipPathValidator" out/sources/
```

---

## 14. How do I tell which signature schemes an APK uses, without installing it?

`apksigner verify -v` is the authoritative answer because it uses the same `apksig` library the
build system and the platform's verifier logic are derived from.

```bash
# host
apksigner verify -v --print-certs app.apk
```

```
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1
Signer #1 certificate DN: CN=Example, O=Example Ltd, C=GB
Signer #1 certificate SHA-256 digest: 1f2e...
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
```

Add `--min-sdk-version` to ask a specific question: "would this install on API 24?" changes which
schemes are *required*, and therefore whether the APK verifies at all.

Without Android tooling, the presence of each scheme is visible structurally:

| Scheme | Structural evidence |
|---|---|
| v1 | `META-INF/*.SF` plus a matching `*.RSA`/`*.DSA`/`*.EC` |
| v2 | Signing block ID-value pair with ID `0x7109871a` |
| v3 | Signing block ID-value pair with ID `0xf05368c0` |
| v3.1 | Signing block ID-value pair with ID `0x1b93ad61` |
| v4 | A sibling file `<name>.apk.idsig` |

```bash
# host
unzip -l app.apk | grep -E 'META-INF/.*\.(SF|RSA|DSA|EC)$'
python3 examples/parse_signing_block.py app.apk
```

---

## 15. If I re-sign an APK, what breaks for the app itself?

Three categories of thing, and you should check all three before concluding your patch "did not
work".

**Runtime signature pinning.** Many apps read their own certificate at startup and compare it to a
hard-coded digest. After re-signing, the digest differs and the app exits, shows a tamper warning,
or silently disables features. Look for `getPackageInfo` with `GET_SIGNING_CERTIFICATES` (API 28+)
or the deprecated `GET_SIGNATURES`, for `SigningInfo.getApkContentsSigners()`, for
`PackageManager.hasSigningCertificate()`, and for the same logic implemented in a `.so` via JNI —
native checks are the ones people miss. `scripts/apk-signature-hooks.js` in this chapter observes
and, optionally, spoofs all of the Java-side paths;
[38-TamperDetection](../38-TamperDetection/README.md) covers the wider topic.

**Backend-side signature binding.** Play Integrity API, SafetyNet-era attestation, Firebase App
Check, and many custom APIs bind requests to the app's signing certificate digest registered
server-side. Re-signing changes the digest, so the server rejects the client no matter how clean
your local patch is.

**Platform features keyed to the signer.** Signature-level permissions shared with a companion app,
a shared `android:sharedUserId`, Google Maps/Firebase API keys restricted to a SHA-1 fingerprint,
and app links verified against a `assetlinks.json` containing your fingerprint all stop working.

Practically, this means a re-signed APK is a fine tool for *analysis* and a poor proxy for *the
real app's behaviour*. When signature checks get in the way, prefer instrumenting the original APK
with Frida over patching and re-signing — see [53-Frida](../53-Frida/README.md).

---

## 16. Why is `resources.arsc` stored uncompressed, and what happens if I compress it?

Because the framework memory-maps it. `resources.arsc` is a big lookup table that is consulted on
every `getString()`, every layout inflation, and every configuration change. Rather than read and
decompress it into heap memory in each process, Android `mmap`s the file region straight out of the
APK and reads 32-bit fields directly from the mapping — which requires the data to be present
verbatim on disk and aligned.

Since Android 11 (API 30) the installer enforces this: an APK whose `resources.arsc` is compressed,
or not 4-byte aligned, is rejected at install time for apps targeting API 30 and above. Before that
it merely wasted memory.

If you rebuild an APK and let your ZIP tool deflate `resources.arsc`, you get an install failure or
a resource-loading crash. apktool records the requirement in `apktool.yml`:

```yaml
doNotCompress:
- resources.arsc
- lib/arm64-v8a/libfoo.so
```

```bash
# host — check the compression method column
unzip -v app.apk | grep -E 'resources\.arsc|\.so$'
# "Stored" is correct for resources.arsc and for .so when extractNativeLibs=false
```

The same reasoning applies to `lib/*.so` under `android:extractNativeLibs="false"`: the dynamic
linker maps the shared object out of the APK, so it must be stored and page-aligned. See question 5
for the alignment flags, including 16 KB pages on Android 15.

---

## 17. What is the difference between an APK and an AAB, and can I install an AAB?

You cannot install an AAB. An Android App Bundle (`.aab`) is a *publishing* format, not an
*installation* format. It contains the compiled code and resources for every device configuration
together with metadata describing how to split them. The store (or `bundletool` locally) processes
the bundle and generates a set of APKs tailored to a specific device: a `base.apk` plus
configuration splits for the device's ABI, screen density and language, plus any on-demand feature
splits.

To work with an AAB as a tester, convert it first:

```bash
# host — one fat APK containing every configuration
bundletool build-apks --bundle=app.aab --output=app.apks --mode=universal \
  --ks=test.keystore --ks-key-alias=testkey --ks-pass=pass:android --key-pass=pass:android
unzip -o app.apks -d apks_out && ls apks_out
```

```bash
# host — or the exact split set the connected device would receive
bundletool build-apks --bundle=app.aab --output=app.apks \
  --ks=test.keystore --ks-key-alias=testkey --ks-pass=pass:android --key-pass=pass:android
bundletool install-apks --apks=app.apks
```

Note the consequence for signing: because the store generates the APKs, the store signs them.
That is Play App Signing — the developer holds an *upload* key, Google holds the *app signing* key,
and the certificate you extract from a Play-delivered APK is Google's, not the developer's. It also
means Play-delivered APKs frequently carry extra, undocumented ID-value pairs in the signing block
that were added at serving time.

---

## 18. How do I pull an APK off a device, including all its splits?

`pm path` lists every APK belonging to a package. Modern apps are almost always split, so pulling
only `base.apk` will give you an app that will not install (`INSTALL_FAILED_MISSING_SPLIT`) and
whose resources or native code may be missing entirely.

```bash
# adb shell — list every path
adb shell pm path com.example
# package:/data/app/~~AbC==/com.example-XyZ==/base.apk
# package:/data/app/~~AbC==/com.example-XyZ==/split_config.arm64_v8a.apk
# package:/data/app/~~AbC==/com.example-XyZ==/split_config.xxhdpi.apk
```

```bash
# host — pull them all in one go
for p in $(adb shell pm path com.example | tr -d '\r' | sed 's/^package://'); do
  adb pull "$p" .
done
ls *.apk
```

```bash
# host — reinstall the full set later
adb install-multiple base.apk split_config.arm64_v8a.apk split_config.xxhdpi.apk
```

If `adb pull` is denied, the app's directory permissions are the problem, not the file's: use
`adb shell "run-as com.example ..."` for debuggable apps, or copy via `cat` on a rooted device.
`scripts/apk-recon.sh` in this chapter takes the pulled APK and produces a full report.

---

## 19. What does `android:extractNativeLibs` change, and why do I care as a tester?

`android:extractNativeLibs="true"` (the historical default) tells the installer to decompress every
`lib/<abi>/*.so` out of the APK and write it to the app's native library directory under
`/data/app/`. The app then loads libraries from that directory. `android:extractNativeLibs="false"`
(the modern default when `minSdkVersion` is 23 or higher) keeps the libraries inside the APK,
stored uncompressed and page-aligned, and the dynamic linker maps them directly from the APK file.

Three consequences for testing:

First, **where you find the `.so` differs**. With extraction enabled there is a copy on disk you can
read, checksum, and replace on a rooted device. Without it, the only copy is inside the APK, and
replacing it means re-signing.

Second, **`/proc/self/maps` looks different**. With `extractNativeLibs="false"`, the mapping's
backing file is the APK itself with an offset, not a standalone `.so` path. Anti-tamper code and
your own analysis scripts both need to handle that. Chapter
[15-Native-Code](../15-Native-Code/README.md) goes into the loading path.

Third, **integrity checks change shape**. An app that hashes its own `.so` on disk cannot do so the
same way when the library only exists inside the APK; such apps typically hash the APK instead,
which interacts with everything in question 15.

```bash
# adb shell — where did the libraries end up?
adb shell ls -l /data/app/*/com.example*/lib/arm64/ 2>/dev/null
adb shell cat /proc/$(adb shell pidof com.example)/maps | grep -E '\.so|\.apk'
```

---

## 20. Can I trust MobSF / jadx / apktool output on a hostile APK?

Not blindly, and that is not a criticism of those tools — it is a structural property of the
problem. Every one of them reimplements Android's parsers in a different language with different
strictness. On a benign APK the outputs agree. On an APK built to exploit the differences, they
diverge, and the tool that matters is the one running on the phone.

Concretely, treat automated tool output as a *hypothesis* and confirm the security-relevant facts
against the platform:

| Claim | Confirm with |
|---|---|
| `android:debuggable` is false | `adb shell dumpsys package com.example \| grep -i flags` (look for `DEBUGGABLE`) |
| A component is not exported | `adb shell dumpsys package com.example \| grep -A3 'Activity Resolver'`, and try to start it |
| Cleartext traffic is blocked | Actually attempt cleartext through a proxy; read `res/xml/*` via `aapt2 dump xmltree` |
| A permission is not requested | `adb shell dumpsys package com.example \| grep -A20 'requested permissions'` |
| These are all the DEX files | `unzip -l app.apk \| grep '\.dex$'` and check for duplicates |
| The manifest is what apktool shows | Three-way diff from question 3 |

> **Warning** A "clean" MobSF report on an APK that also fails the three-way manifest diff is a
> strong signal, not a clean bill of health. Report the divergence itself as the finding.

---

## 21. Why does `jadx` show me classes that `apktool` does not, or vice versa?

They read different things. `jadx` decompiles DEX to Java-like source; `apktool` disassembles DEX to
Smali and decodes resources. Divergence usually has one of four causes.

`jadx` may fail to decompile a method and omit it unless you pass `--show-bad-code`, which keeps the
undecompilable body as a comment. Obfuscators deliberately produce control flow that defeats
decompilation, so an "empty" class in jadx is often a full class in Smali — always cross-check in
`apktool`'s Smali output before concluding a method is empty. See
[40-Obfuscation](../40-Obfuscation/README.md).

`apktool d --only-main-classes` skips DEX files that are not `classes*.dex` at the archive root.
Some apps ship additional DEX inside `assets/` and load it with a `DexClassLoader` at runtime;
neither tool will show that code until you extract and disassemble it yourself.

Multidex numbering starts at `classes.dex`, `classes2.dex`, `classes3.dex` — note there is no
`classes1.dex`. A tool invocation that globs `classes[0-9]*.dex` misses the first file.

Finally, code can be generated at runtime or downloaded, in which case neither static tool will ever
see it. Chapter [12-DEX-Internals](../12-DEX-Internals/README.md) covers finding dynamically loaded
DEX; [56-JADX](../56-JADX/README.md) covers jadx's flags in detail.

```bash
# host — enumerate every DEX, wherever it hides
unzip -l app.apk | grep -iE '\.dex$'
unzip -l app.apk | grep -iE 'assets/.*\.(jar|zip|dex|apk)$'
```

---

## 22. What is the `stamp-cert-sha256` file, and the "source stamp"?

A source stamp is an additional, optional signature that records *who built or published* the APK,
separately from who signed it. It exists because with Play App Signing the app-signing key is held
by Google, so the final APK's certificate no longer identifies the developer. The source stamp
lets the developer attach their own identity anyway.

Mechanically there are two parts: a file named `stamp-cert-sha256` at the root of the archive
containing the raw SHA-256 digest of the stamp certificate, and an ID-value pair in the APK Signing
Block containing the stamp signature. `apksigner verify -v` reports it on the
`Verified for SourceStamp:` line.

For a tester it is mostly a provenance signal: two APKs with the same source stamp came from the
same build identity even if they were signed by different app-signing keys. Its absence means
nothing — it is optional and most apps do not use it.

```bash
# host
unzip -l app.apk | grep stamp-cert-sha256
unzip -p app.apk stamp-cert-sha256 | xxd -p -c 32
apksigner verify -v app.apk | grep -i sourcestamp
```

---

## 23. My decompiled `res/values/public.xml` has thousands of entries. What is it for?

`public.xml` is apktool's reconstruction of the resource-ID assignment. Inside a built APK,
resources are referenced only by their numeric ID — `0x7f0a0012`, not `@id/login_button`. The names
live in the `resources.arsc` key string pool. When apktool decodes, it emits `public.xml` mapping
every name back to the exact numeric ID so that rebuilding produces the *same* IDs.

That matters because IDs leak across boundaries. Compiled DEX code contains raw integers like
`0x7f0a0012` in `findViewById` calls and `R.string.*` references. If a rebuild reassigned IDs, all
that code would reference the wrong resources and the app would behave bizarrely rather than fail
cleanly. Keeping `public.xml` intact is what makes an apktool round-trip safe.

For analysis, `public.xml` is also the fastest way to turn a mystery integer in decompiled code into
a name:

```bash
# host — what is 0x7f0a0012?
grep -i '0x7f0a0012' work/res/values/public.xml
aapt2 dump resources app.apk | grep -B2 -A6 '0x7f0a0012'
```

> **Mental Model** `resources.arsc` is a database. The package chunk is the schema, type chunks
> are tables partitioned by configuration (language, density, orientation), and a resource ID
> `0xPPTTEEEE` is a primary key made of package, type and entry. Resolving `@string/foo` is a name
> lookup followed by a "best matching row for the current configuration" query.

---

## 24. How do I know whether a finding is a false positive from the signature/integrity family?

Ask what the check is actually protecting and whether the attacker model makes it matter. Three
common false-positive shapes:

"App is signed with a debug certificate" is only a finding if the *production* build is. A test
build you re-signed yourself trivially reports `CN=Android Debug`. Check the certificate you pulled
from the store artefact, not from your working copy.

"App does not perform runtime signature verification" is a weak finding by itself. Self-verification
is a speed bump against repackaging, not a security boundary — an attacker who can modify the APK
can also modify the check. It belongs under MASVS-RESILIENCE (raising the cost of tampering), not
under a claim that the app is exploitable. State it that way.

"App is signed with SHA-1 / a 1024-bit key" needs qualification. The v1 scheme's digest algorithm
and the certificate's own signature algorithm are different things; `apksigner verify -v` will name
both. A certificate self-signed with SHA-1 is cosmetic if the APK also carries v2/v3 signatures with
SHA-256 digests, because the platform's trust decision is "same key as before", not "is this
certificate chain valid". Report weak *keys* (small RSA moduli) as real; report weak certificate
self-signature algorithms as informational.

```bash
# host — get the facts before writing the finding
apksigner verify -v --print-certs app.apk
unzip -p app.apk META-INF/CERT.RSA | openssl pkcs7 -inform DER -print_certs -text -noout | \
  grep -E 'Signature Algorithm|Public-Key|Not After'
```
