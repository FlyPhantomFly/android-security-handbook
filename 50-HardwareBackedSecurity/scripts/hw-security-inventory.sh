#!/usr/bin/env bash
# hw-security-inventory.sh — read-only inventory of a device's hardware security posture.
#
# PURPOSE
#   Before you can say anything about an app's use of hardware-backed keys, you have to know what
#   hardware the device actually has. This script asks the device, and shows its working: which
#   KeyMint/Keymaster HAL is running, whether a StrongBox element is declared, which Gatekeeper
#   implementation is present, whether a lock-screen credential exists (and therefore whether
#   Gatekeeper holds a password handle at all), and what the bootloader claims about verified boot.
#
#   It deliberately prints the RAW evidence next to each conclusion, because most of the wrong
#   answers in this area come from trusting one indicator. In particular it prints
#   `ro.boot.verifiedbootstate` and then tells you not to believe it: that property lives in the
#   normal world, and on a rooted device it is routinely rewritten to `green`. The only
#   trustworthy version of the same fact is `rootOfTrust.verifiedBootState` inside a key
#   attestation, which is signed inside the TEE. Produce one with ./probe-security-levels.sh
#   --attest and read it with ./parse-attestation.py.
#
# USAGE
#   ./hw-security-inventory.sh                       # inventory the single attached device
#   ANDROID_SERIAL=<serial> ./hw-security-inventory.sh
#
# REQUIREMENTS
#   bash, adb, a device with USB debugging enabled. No root. Nothing is installed or modified.
#
# WHAT THIS WILL *NOT* TELL YOU
#   - It will NOT tell you the security level of any particular key. Feature flags and HAL names
#     are a capability ceiling, not a measurement. Two devices measured while writing chapter 50
#     both returned TRUSTED_ENVIRONMENT keys, and only one of them declared
#     `android.hardware.hardware_keystore` at all (that feature constant did not exist before API
#     31). Run ./probe-security-levels.sh for the answer that counts.
#   - It will NOT tell you whether the TEE is trustworthy. A running KeyMint HAL says a TEE exists,
#     not that it is unbroken or patched.
#   - It will NOT detect root. `ro.boot.verifiedbootstate` is not a root check and this script does
#     not pretend it is; see ../../37-RootDetection/README.md.
#   - Anything read through `adb shell` runs as uid 2000. Several services (IGateKeeperService
#     among them) are simply invisible from there, and "not found" means "not visible to the
#     shell", not "absent".
#
# SAFETY
#   Every command is a read. Nothing is pushed, installed, started, stopped or written.

set -u

sh_() { adb shell "$@" 2>/dev/null | tr -d '\r'; }
hdr() { printf '\n=== %s\n' "$1"; }
prop() { printf '  %-38s %s\n' "$1" "$(sh_ getprop "$1")"; }

if ! adb get-state >/dev/null 2>&1 && [ -z "${ANDROID_SERIAL:-}" ]; then
    ONLINE="$(adb devices | tr -d '\r' | awk '$2=="device"{print $1}')"
    if [ "$(printf '%s\n' "$ONLINE" | grep -c .)" = "1" ]; then
        ANDROID_SERIAL="$ONLINE"; export ANDROID_SERIAL
    else
        echo "need exactly one online device - set ANDROID_SERIAL" >&2; exit 1
    fi
fi

hdr "IDENTITY - record this with every claim you make"
prop ro.product.model
prop ro.product.device
prop ro.build.version.release
prop ro.build.version.sdk
prop ro.build.version.security_patch
prop ro.vendor.build.security_patch
prop ro.hardware
prop ro.board.platform
printf '  %-38s %s\n' "adb shell id" "$(sh_ id)"
printf '  %-38s %s\n' "getenforce" "$(sh_ getenforce)"

hdr "DECLARED FEATURES - the capability the framework advertises"
FEATS="$(sh_ 'pm list features')"
for f in android.hardware.strongbox_keystore android.hardware.hardware_keystore \
         android.software.device_id_attestation android.hardware.identity_credential \
         android.software.secure_lock_screen; do
    LINE="$(printf '%s\n' "$FEATS" | grep -F "feature:$f")"
    if [ -n "$LINE" ]; then
        printf '  %-46s PRESENT   %s\n' "$f" "$LINE"
    else
        printf '  %-46s absent\n' "$f"
    fi
done
cat <<'NOTE'
  note: android.hardware.hardware_keystore carries the Keymaster/KeyMint version as its value
        (41 = Keymaster 4.1, 100 = KeyMint 1.0, 200 = KeyMint 2.0, ...). The constant itself only
        exists from API 31, so its ABSENCE on an older device tells you nothing at all. An API 30
        device measured for chapter 50 declared neither feature and still put every key in the TEE.
NOTE

hdr "THE HAL THAT ACTUALLY BACKS THE KEYSTORE"
echo "  -- running services (ps):"
sh_ 'ps -A -o USER,PID,NAME' | grep -i -E 'keystore|keymaster|keymint|gatekeeper' | sed 's/^/    /'
echo "  -- declared HAL interfaces (lshal):"
sh_ 'lshal' | grep -i -E 'keymaster|keymint|gatekeeper' | sed 's/^/    /'
echo "  -- keystore-related binder services:"
sh_ 'service list' | grep -i -E 'keystore|gatekeeper|authorization' | sed 's/^/    /'
cat <<'NOTE'
  read it like this: a process named android.hardware.keymint@N-service.* means the modern AIDL
  KeyMint HAL. A process named android.hardware.keymaster@4.x-service.* means the LEGACY Keymaster
  HIDL HAL, which keystore2 drives through a compatibility shim
  (android.security.compat / IKeystoreCompatService). Android 12+ does NOT imply KeyMint: a device
  measured for chapter 50 runs Android 13 with keystore2 in front of Keymaster 4.1.
NOTE

hdr "GATEKEEPER - the source of the hardware auth token"
prop ro.hardware.gatekeeper
prop init.svc.gatekeeperd
echo "  -- lock-screen credential state (this decides whether an auth-bound key can exist):"
sh_ 'dumpsys lock_settings' | sed -n '1,25p' | sed 's/^/    /'
cat <<'NOTE'
  read it like this: `SID: 0` together with `CredentialType: None` means NO lock-screen credential
  is set. Gatekeeper therefore holds no password handle, the Secure User ID is 0, and KeyMint will
  refuse to create any key with setUserAuthenticationRequired(true). The failure you will see is
  an IllegalStateException, not a security exception, and it is easy to misread as a bug.
  A non-zero SID is Gatekeeper's identifier for the current credential; it changes when the
  credential changes, which is exactly why every auth-bound key dies on a PIN change.
NOTE

hdr "VERIFIED BOOT - as claimed by the NORMAL world (do not trust these)"
prop ro.boot.verifiedbootstate
prop ro.boot.veritymode
prop ro.boot.flash.locked
prop ro.secure
prop ro.debuggable
cat <<'NOTE'
  DO NOT TRUST THE FIVE VALUES ABOVE. They are ordinary system properties, set from the kernel
  command line, living in the normal world. Every mainstream rooting stack rewrites them. Measured
  for chapter 50: a rooted device reported ro.boot.verifiedbootstate=green while the TEE-signed
  attestation for a key generated seconds later on the same device reported
  verifiedBootState=Unverified, deviceLocked=false and an all-zero verifiedBootKey.

  The trustworthy version of this fact is in the attestation extension:
      ./probe-security-levels.sh --attest | sed -n '/BEGIN CHAIN/,/END CHAIN/p' > chain.pem
      python3 -B ./parse-attestation.py chain.pem
NOTE

hdr "KEYSTORE STORAGE (paths only - contents are not readable without root, and are opaque anyway)"
sh_ 'ls -ldZ /data/misc/keystore 2>/dev/null || echo "    (not listable as shell - expected)"' | sed 's/^/    /'
# The braces matter. `ls ... | head -6 || echo ...` puts the || after the whole
# PIPELINE, whose exit status is head's, and head exits 0 whether or not ls
# produced anything -- so on the ordinary non-root device, where ls DOES fail,
# the explanatory message never prints and the section is silently blank. The
# device shell is mksh and has no pipefail to rescue it. Grouping ls with its
# own fallback, and piping the group into head, makes the || test what it was
# meant to test.
sh_ '{ ls -l /data/system_de/0/spblob 2>/dev/null || echo "    (not listable as shell - expected)"; } | head -6' | sed 's/^/    /'
cat <<'NOTE'
  Even with root these are the wrong thing to read. A keystore blob is ciphertext under a key
  derived from a hardware-unique key that no software can read, so copying it off the device gains
  an attacker nothing. See ../../49-KeyStore/README.md section 2.3.
NOTE

hdr "NEXT STEP"
cat <<'NOTE'
  This was the capability ceiling. Now measure what a key actually gets:
      ./probe-security-levels.sh
  and, for a specific app rather than the device:
      ../labs/lab-01-measure-every-key-type.md
NOTE
