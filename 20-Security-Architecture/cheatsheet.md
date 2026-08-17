# 20 — Security Architecture · Cheat Sheet

## Boot states

| State | Bootloader | Signed by | `ro.boot.verifiedbootstate` | Warning |
|---|---|---|---|---|
| GREEN | locked | OEM key in fuses | `green` | none |
| YELLOW | locked | user-embedded custom key | `yellow` | key fingerprint, ~5 s |
| ORANGE | unlocked | nothing enforced | `orange` | "can't be checked" |
| RED | locked | verification FAILED | `red` | "device is corrupt", boot refused |
| *(none)* | **no bootloader at all** — emulator | nothing | **empty string** | none. `!"orange".equals(state)` is **true** here |

## Device posture properties

| Property | Values | Meaning |
|---|---|---|
| `ro.boot.verifiedbootstate` | green/yellow/orange/red **/ empty** | boot state (FORGEABLE by root; **empty on an emulator** — allow-list `green`, never deny-list `orange`) |
| `ro.boot.flash.locked` | 1 / 0 **/ empty** | bootloader lock (FORGEABLE; also empty on an emulator) |
| `ro.boot.veritymode` | enforcing / logging / eio | dm-verity error mode |
| `ro.boot.vbmeta.digest` | hex | digest of all vbmeta blobs |
| `ro.boot.vbmeta.device_state` | locked / unlocked | as reported by bootloader |
| `ro.build.version.security_patch` | YYYY-MM-DD | system patch level |
| `ro.vendor.build.security_patch` | YYYY-MM-DD | vendor patch level |
| `ro.build.fingerprint` | string | full build identity |
| `ro.build.type` | user / userdebug / eng | build flavour |
| `ro.build.tags` | release-keys / test-keys | signing keys used |
| `ro.debuggable` | 1 / 0 | global debuggability |
| `ro.secure` | 1 / 0 | adbd drops root when 1 |
| `ro.crypto.state` | encrypted / unencrypted / unsupported | encryption state |
| `ro.crypto.type` | file / block | FBE vs FDE |
| `ro.crypto.metadata.enabled` | true / false | metadata encryption |

## One-shot posture command

```bash
# adb shell
for p in ro.product.manufacturer ro.product.model ro.build.fingerprint \
  ro.build.type ro.build.tags ro.build.version.release ro.build.version.sdk \
  ro.build.version.security_patch ro.vendor.build.security_patch \
  ro.boot.verifiedbootstate ro.boot.flash.locked ro.boot.veritymode \
  ro.boot.vbmeta.digest ro.debuggable ro.secure ro.crypto.state ro.crypto.type; do
  echo "$p = $(getprop $p)"; done; echo "selinux = $(getenforce)"
```

## AVB descriptors

| Descriptor | Verifies | Applied to |
|---|---|---|
| `AvbHashDescriptor` | whole-partition hash at boot | boot, init_boot, dtbo, vendor_boot |
| `AvbHashtreeDescriptor` | Merkle root, lazy per-block | system, vendor, product, system_ext |
| `AvbChainPartitionDescriptor` | delegates to another key | vbmeta_system, vbmeta_vendor |
| `AvbKernelCmdlineDescriptor` | cmdline fragments | dm-verity table |
| `AvbPropertyDescriptor` | key/value metadata | fingerprint, patch level |

## dm-verity error modes

| Mode | On hash mismatch |
|---|---|
| `eio` | read returns `-EIO` |
| `restart` / `enforcing` | immediate reboot, persistent corruption flag |
| `logging` | logged, read SUCCEEDS — **no protection** |
| `panic` | kernel panic |
| `check_at_most_once` | caches verification per block — weakens re-read protection |

## Encryption classes

| Class | Path | Key available | Contents |
|---|---|---|---|
| DE (Device Encrypted) | `/data/user_de/<u>/<pkg>/` | at boot | Direct Boot aware components |
| CE (Credential Encrypted) | `/data/user/<u>/<pkg>/` | after first unlock | everything else |

BFU = Before First Unlock (CE keys absent). AFU = After First Unlock (CE keys in kernel memory).

## Play Integrity verdicts

| Field | Values |
|---|---|
| `deviceRecognitionVerdict` | `MEETS_BASIC_INTEGRITY`, `MEETS_DEVICE_INTEGRITY`, `MEETS_STRONG_INTEGRITY`, `MEETS_VIRTUAL_INTEGRITY`, *(empty)* |
| `appRecognitionVerdict` | `PLAY_RECOGNIZED`, `UNRECOGNIZED_VERSION`, `UNEVALUATED` |
| `appLicensingVerdict` | `LICENSED`, `UNLICENSED`, `UNEVALUATED` |
| `playProtectVerdict` | `NO_ISSUES`, `NO_DATA`, `POSSIBLE_RISK`, `MEDIUM_RISK`, `HIGH_RISK` |
| `appAccessRiskVerdict` | `KNOWN_INSTALLED`, `UNKNOWN_INSTALLED`, `UNKNOWN_CAPTURING`, `UNKNOWN_OVERLAYS` |

### Mandatory server-side checks

| # | Check | Failure impact |
|---|---|---|
| 1 | decode server-side (`decodeIntegrityToken`) | client-side branch is hookable |
| 2 | `requestPackageName` == your package | token from any other app accepted |
| 3 | nonce is server-issued, single-use, operation-bound | replay |
| 4 | `timestampMillis` within minutes | indefinite replay of a clean-device token |

## Device commands

```bash
# adb shell
getenforce; id -Z; ps -Z | head
dmesg | grep -iE 'verity|dm-|fscrypt|avb|selinux'
cat /proc/cmdline | tr ' ' '\n' | grep androidboot
ls /apex/; pm list packages --apex-only
mount | grep -E 'system|vendor|data'
ls -l /dev/block/mapper/
settings get global package_verifier_user_consent
```

```bash
# host — factory image inspection
avbtool info_image   --image vbmeta.img
avbtool info_image   --image boot.img
avbtool verify_image --image vbmeta.img --key pubkey.pem
magiskboot unpack boot.img
payload_dumper payload.bin
```

```bash
# host — userdebug/eng + unlocked only
adb root && adb disable-verity && adb reboot && adb wait-for-device && adb remount
```

## APK static checks

```bash
# host
aapt2 dump xmltree app.apk --file AndroidManifest.xml | \
  grep -E 'debuggable|allowBackup|usesCleartextTraffic|networkSecurityConfig|targetSdkVersion|sharedUserId'
jadx -d out app.apk
grep -rn -E 'IntegrityManager|requestIntegrityToken|SafetyNet|setAttestationChallenge' out/sources/
grep -rn -E 'ro\.(boot|build|debuggable|secure|crypto)' out/sources/
unzip -o app.apk -d x >/dev/null && strings -a x/lib/*/*.so | grep -aE '^ro\.|/su$|magisk|frida'
```

## Attack-surface priority (typical engagement)

| Rank | Area | Chapter |
|---|---|---|
| 1 | Server-side authz reached via the app | — |
| 2 | Local storage of bearer credentials | [33](../33-Storage/) |
| 3 | Exported components / IPC | [24](../24-IPC/)–[32](../32-Manifest/) |
| 4 | Client-side-only security decisions | [67](../67-BypassingProtections/) |
| 5 | TLS / pinning | [35](../35-SSL/), [36](../36-CertificatePinning/) |
| 6 | Hardcoded secrets, third-party SDKs | [40](../40-Obfuscation/), [17](../17-Libraries/) |
| 7 | Platform vulnerabilities | [70](../70-VulnerabilityResearch/) |

## Forgeable vs not

| Signal | Forgeable by root? |
|---|---|
| Any `getprop` value | YES (`resetprop`) |
| `Build.*` fields | YES |
| File existence / hashes under `/system` | YES (mount namespaces) |
| `getenforce` output | YES |
| Play Integrity verdict read on-device | YES |
| Play Integrity token verified server-side with nonce+package+freshness | NO (raises cost substantially) |
| Key attestation extension verified server-side to a Google root | NO (absent TEE compromise / leaked keybox) |
