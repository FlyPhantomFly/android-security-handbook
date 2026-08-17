#!/usr/bin/env python3
# 47-Authentication/scripts/auth-surface-scan.py
#
# PURPOSE
#   Map the *authentication surface* of one or more Android APKs without decompiling
#   them. It answers the first question of any authentication review: "which
#   authentication mechanisms does this app actually contain, and where is the
#   authentication *decision* being made?"
#
#   It is deliberately a LEAD GENERATOR, not a vulnerability scanner. Chapters 33, 36
#   and 52 of this repository each measured the same lesson independently — a sweep
#   produces leads, not findings, and confidence ranking is not severity ranking. This
#   script prints a surface inventory and a small number of explicitly-labelled
#   SUSPECT rows, and it refuses to call anything a vulnerability.
#
#   Detection is done on the raw string pool of every classes*.dex plus the compiled
#   AndroidManifest.xml, so it works on release, minified and multi-DEX APKs, and it
#   does not need jadx, apktool, baksmali or a JVM.
#
# USAGE
#   python3 -B auth-surface-scan.py app.apk
#   python3 -B auth-surface-scan.py *.apk --json out.json
#   python3 -B auth-surface-scan.py app.apk --verbose      # show matched strings
#
#   Pull an APK off a device first:
#     adb shell pm path com.example.app
#     adb pull /data/app/~~xxx/com.example.app-1/base.apk
#
#   Split APKs: an app that ships its code in split APKs will show an almost empty
#   base.apk. Scan every split, or the scan lies. Chapter 38 hit exactly this.
#
# LIMITS, STATED HONESTLY
#   * A string match proves the *symbol* is present, not that the code path runs.
#     A library the app never calls still contributes its strings.
#   * R8 renames application classes but NOT platform/AndroidX API names, so the
#     framework markers survive minification and the app's own names do not. That
#     asymmetry is why the LOCAL-GATE heuristics are rated weak.
#   * No exit code is derived from findings. Exit 0 = scan ran; exit 1 = scan failed.
#
# TWO CORRECTIONS THIS SCRIPT MADE TO ITSELF, BOTH MEASURED
#
#   1. `FLAG_SECURE` CANNOT BE FOUND BY SCANNING FOR STRINGS. It is a compile-time
#      `public static final int` (0x2000), so javac inlines it and the identifier
#      never reaches the .class file, let alone the DEX. Verified by compiling an
#      Activity that provably sets it: the string is absent from both artefacts,
#      while `setFlags` survives and the constant appears only as bytecode
#      `const/16 v0, #int 8192 // #2000`. An earlier revision of this script
#      reported "3/17 apps use FLAG_SECURE"; all three were apps that mention the
#      name for some other reason. The marker is now a bytecode heuristic and is
#      labelled as requiring confirmation. Grepping an APK for FLAG_SECURE is a
#      widely-published check with a true-positive rate of zero.
#
#   2. `getPassword`/`setPassword` are NOT AccountManager markers on their own.
#      Measured across 17 real APKs: 15 contained the identifier but only 13
#      contained `Landroid/accounts/AccountManager;`, so at least 2 were pure false
#      positives (any credential DTO, any KeyStore load, any JDBC-shaped API has a
#      `getPassword`). The marker now REQUIRES the AccountManager type descriptor to
#      co-occur before it is reported as STRONG. This is the same discipline chapter
#      38 arrived at: if a detector agrees with you about every sample, suspect the
#      detector.
#
# AUTHORISED TESTING ONLY. Scan applications you own or have written permission to
# assess. This script reads files; it sends nothing anywhere.

import argparse
import json
import re
import struct
import sys
import zipfile
from collections import OrderedDict

# --------------------------------------------------------------------------------
# The surface catalogue.
#
# Each entry: (family, marker-regex, strength, one-line meaning, requires)
#
# strength STRONG  -- the symbol is specific to the mechanism and hard to hit by accident
# strength WEAK    -- the symbol is generic; treat a hit as "look here", nothing more
#
# `requires` names another regex that must ALSO be present in the same DEX before the
# hit is reported at its declared strength. A hit whose requirement is unmet is
# demoted to WEAK and annotated, rather than dropped -- dropping it would hide a
# genuine hit in an app that loads AccountManager reflectively.
#
# Chapter 38 measured why the STRONG/WEAK split is mandatory: a detector that agreed
# with the analyst about every sample was wrong about 5 of 18, because one generic
# marker (getPackageInfo) matched every SDK that reads its own versionName.
# --------------------------------------------------------------------------------

ACCOUNT_MANAGER_TYPE = rb"Landroid/accounts/AccountManager;"

CATALOGUE = [
    # ---- Platform account plumbing -------------------------------------------
    ("AccountManager", rb"Landroid/accounts/AccountManager;", "STRONG",
     "Uses the platform account database (/data/system_ce/<u>/accounts_ce.db)"),
    ("AccountManager", rb"addAccountExplicitly", "STRONG",
     "Writes an account row itself - it IS an authenticator, not just a consumer"),
    ("AccountManager", rb"setPassword|getPassword", "STRONG",
     "Touches the accounts.password column - a plaintext password column on disk",
     ACCOUNT_MANAGER_TYPE),
    ("AccountManager", rb"peekAuthToken|setAuthToken|invalidateAuthToken", "STRONG",
     "Caches bearer tokens in the plaintext authtokens table"),
    ("AccountManager", rb"Landroid/accounts/AbstractAccountAuthenticator;", "STRONG",
     "Implements an authenticator service - other apps can ask it for tokens"),

    # ---- Credential Manager / passkeys ---------------------------------------
    ("CredentialManager", rb"Landroidx/credentials/CredentialManager;", "STRONG",
     "androidx.credentials - the modern unified sign-in entry point"),
    ("CredentialManager", rb"CreatePublicKeyCredentialRequest|GetPublicKeyCredentialOption", "STRONG",
     "Passkey (WebAuthn) creation or assertion via Credential Manager"),
    ("CredentialManager", rb"Landroid/credentials/CredentialManager;", "STRONG",
     "Platform CredentialManager - requires API 34+ at runtime"),
    ("CredentialManager", rb"GetPasswordOption|CreatePasswordRequest", "STRONG",
     "Password saved to / read from the platform credential store"),
    ("CredentialManager", rb"GetSignInWithGoogleOption|GetGoogleIdOption", "STRONG",
     "Google federated sign-in through Credential Manager"),

    # ---- FIDO2 / WebAuthn (pre-Credential-Manager path) ----------------------
    ("FIDO2", rb"com/google/android/gms/fido", "STRONG",
     "GMS FIDO2 API - the pre-API-34 route to platform authenticators"),
    ("FIDO2", rb"PublicKeyCredentialCreationOptions|AuthenticatorAssertionResponse", "STRONG",
     "WebAuthn ceremony objects present"),
    ("FIDO2", rb"assetlinks\.json|\.well-known/assetlinks", "WEAK",
     "Digital Asset Links - the origin binding that makes a passkey app-specific"),

    # ---- OTP / SMS -----------------------------------------------------------
    ("OTP-SMS", rb"SmsRetriever|SMS_RETRIEVED_ACTION", "STRONG",
     "SMS Retriever API - reads ONE hash-matched SMS, needs no SMS permission"),
    ("OTP-SMS", rb"createAppSpecificSmsToken", "STRONG",
     "Platform per-app SMS token - the permissionless OTP path (API 26+)"),
    ("OTP-SMS", rb"android\.permission\.READ_SMS|android\.permission\.RECEIVE_SMS", "STRONG",
     "Reads the user's whole SMS inbox - almost never necessary for OTP"),
    ("OTP-SMS", rb"SmsUserConsent|startSmsUserConsent", "STRONG",
     "SMS User Consent API - user taps to release one message"),
    ("OTP-TOTP", rb"TOTP|totp|HmacSHA1.*otp|OtpProvider", "WEAK",
     "Time-based one-time password generation, possibly on-device"),

    # ---- Autofill ------------------------------------------------------------
    ("Autofill", rb"Landroid/view/autofill/AutofillManager;", "STRONG",
     "Interacts with the autofill framework directly"),
    ("Autofill", rb"Landroid/service/autofill/AutofillService;", "STRONG",
     "IS an autofill service - it can be offered other apps' credential fields"),
    ("Autofill", rb"setAutofillHints|autofillHints", "STRONG",
     "Declares field semantics so a password manager can fill correctly"),
    ("Autofill", rb"importantForAutofill", "WEAK",
     "Opts a view in or out of autofill - check it is not opting the password out"),

    # ---- Biometric / device credential step-up (depth belongs to ch.48) ------
    ("DeviceCredential", rb"Landroidx/biometric/BiometricPrompt;|Landroid/hardware/biometrics/BiometricPrompt;", "STRONG",
     "Local biometric or device-credential prompt - see 48-Biometrics"),
    ("DeviceCredential", rb"createConfirmDeviceCredentialIntent|isDeviceSecure", "STRONG",
     "Falls back to PIN/pattern/password - see 48-Biometrics"),
    ("DeviceCredential", rb"setUserAuthenticationRequired", "STRONG",
     "Binds a Keystore key to user authentication - see 49-KeyStore"),

    # ---- Session / token handling (formats belong to ch.46) ------------------
    ("Session", rb"Set-Cookie|CookieManager|CookieJar", "WEAK",
     "Cookie-based session - check Secure/HttpOnly and the WebView/OkHttp split"),
    ("Session", rb"Authorization|Bearer ", "WEAK",
     "Bearer credential on the wire - see 46-Tokens"),
    ("Session", rb"refresh_token|refreshToken", "STRONG",
     "Holds a refresh token - the longest-lived credential in the app"),
    ("Session", rb"/logout|signOut|revoke_token|/revoke", "WEAK",
     "A logout or revocation path exists - test whether it is server-side"),

    # ---- Screen protection ---------------------------------------------------
    # See the header: the STRING "FLAG_SECURE" is inlined away by javac and is NOT a
    # usable marker. What survives is the call site. This pair is the honest form:
    # `Window.setFlags` present at all, and the literal 0x2000 present as bytecode.
    # Neither is conclusive; together they are a place to point a disassembler.
    ("ScreenProtect", rb"Landroid/view/Window;", "WEAK",
     "Window API present - prerequisite for FLAG_SECURE, proves nothing alone"),
    ("ScreenProtect", rb"setFlags", "WEAK",
     "Window.setFlags call site may exist - the ONLY textual trace FLAG_SECURE leaves"),
    ("ScreenProtect", rb"FLAG_SECURE", "WEAK",
     "The literal name appears - NOT evidence of use; the constant is inlined, so "
     "this is a resource name, a log string or reflection"),

    # ---- Device binding ------------------------------------------------------
    ("DeviceBinding", rb"getAttestationChallenge|setAttestationChallenge", "STRONG",
     "Key attestation - real device binding, see 49-KeyStore / 50-HardwareBackedSecurity"),
    ("DeviceBinding", rb"SafetyNet|PlayIntegrity|IntegrityManager", "STRONG",
     "Remote attestation of the device/app - see 38-TamperDetection"),
    ("DeviceBinding", rb"ANDROID_ID|getAndroidId|Settings\$Secure", "WEAK",
     "May be using an OS identifier as a device id - resets on factory reset, spoofable"),

    # ---- The local-gate anti-pattern (WEAK by construction) ------------------
    ("LOCAL-GATE", rb"isLoggedIn|is_logged_in|loggedIn|IS_LOGGED_IN", "WEAK",
     "SUSPECT: a boolean that may be the authentication decision itself"),
    ("LOCAL-GATE", rb"isPremium|isPro|isSubscribed|hasPurchased", "WEAK",
     "SUSPECT: an entitlement boolean - check the server re-checks it"),
    ("LOCAL-GATE", rb"isAdmin|is_admin|userRole|user_role", "WEAK",
     "SUSPECT: a client-side role - check authorisation is server-side"),
    ("LOCAL-GATE", rb"savedPassword|saved_password|mPassword|cachedPassword", "WEAK",
     "SUSPECT: a field name suggesting a password is retained in the app"),
]

MANIFEST_MARKERS = [
    ("Manifest", rb"android\.permission\.GET_ACCOUNTS", "STRONG",
     "Legacy account-listing permission - a no-op for visibility on API 26+"),
    ("Manifest", rb"android\.permission\.AUTHENTICATE_ACCOUNTS", "STRONG",
     "Legacy - removed as a third-party permission; presence dates the code"),
    ("Manifest", rb"android\.permission\.USE_BIOMETRIC|USE_FINGERPRINT", "STRONG",
     "Local authentication prompt permission"),
    ("Manifest", rb"android\.permission\.READ_SMS|RECEIVE_SMS", "STRONG",
     "Full SMS access - a red flag on an app whose only SMS need is an OTP"),
    ("Manifest", rb"allowBackup", "WEAK",
     "Backup attribute present - read its value, it governs credential exfiltration"),
    ("Manifest", rb"android\.accounts\.AccountAuthenticator", "STRONG",
     "Declares an authenticator - it owns an account type on the device"),
    ("Manifest", rb"autoVerify", "WEAK",
     "App Links verification - relevant to passkey/OAuth redirect integrity"),
]


def dex_string_blob(apk_path):
    """Concatenate every classes*.dex plus the manifest into one searchable blob.

    We do not parse the DEX string table properly on purpose: a raw scan is
    faster, tolerant of DEX version drift, and cannot be defeated by a container
    format change. The cost is that we may match a string that lives in a
    non-string section, which is why every marker above is either a type
    descriptor or a distinctive identifier.
    """
    dex_blob = bytearray()
    manifest_blob = bytearray()
    dex_names = []
    try:
        with zipfile.ZipFile(apk_path) as z:
            for name in z.namelist():
                if re.fullmatch(r"classes\d*\.dex", name):
                    dex_names.append(name)
                    dex_blob += z.read(name)
                elif name == "AndroidManifest.xml":
                    manifest_blob += z.read(name)
    except (zipfile.BadZipFile, OSError) as exc:
        raise RuntimeError("cannot read %s: %s" % (apk_path, exc))
    return bytes(dex_blob), bytes(manifest_blob), dex_names


def utf16_and_utf8(blob):
    """AXML stores strings as UTF-16LE. Return a UTF-8-ish view of both encodings
    so one regex catalogue works against the manifest and the DEX alike."""
    try:
        folded = blob.decode("utf-16-le", "ignore").encode("utf-8", "ignore")
    except (UnicodeDecodeError, UnicodeEncodeError):
        folded = b""
    return blob + b"\x00" + folded


def flag_secure_bytecode_probe(dex):
    """Count `const/16 vX, #int 8192` instructions in the DEX.

    Opcode 0x13 is const/16; the encoding is `13 AA BBBB` where AA is the
    destination register and BBBB is a little-endian signed 16-bit literal. 8192
    is 0x2000, so the literal bytes are `00 20`. The full instruction is therefore
    `13 <reg> 00 20`.

    This is the only textual trace FLAG_SECURE leaves, and it is NOT specific:
    8192 is a popular buffer size. Treat a non-zero count as "disassemble around
    these", never as "the app sets FLAG_SECURE". A zero count is the more useful
    direction -- it is decent evidence the flag is never set from Java, though a
    native or reflective caller would still evade it.

    Verified against a purpose-built Activity that provably sets FLAG_SECURE:
    dexdump renders exactly `1300 0020  |0007: const/16 v0, #int 8192 // #2000`.
    """
    count = 0
    for m in re.finditer(rb"\x13.\x00\x20", dex, re.DOTALL):
        count += 1
    return count


def scan_one(apk_path, verbose=False):
    dex, manifest, dex_names = dex_string_blob(apk_path)
    manifest_view = utf16_and_utf8(manifest)

    families = OrderedDict()
    hits = []

    def record(family, strength, meaning, matched, where, note=None):
        families.setdefault(family, {"STRONG": 0, "WEAK": 0})
        families[family][strength] += 1
        hits.append({
            "family": family, "strength": strength, "meaning": meaning,
            "sample": matched, "where": where, "note": note,
        })

    for entry in CATALOGUE:
        family, pattern, strength, meaning = entry[0], entry[1], entry[2], entry[3]
        requires = entry[4] if len(entry) > 4 else None
        m = re.search(pattern, dex)
        if not m:
            continue
        note = None
        if requires is not None and not re.search(requires, dex):
            # The corroborating symbol is absent. Do not drop the hit -- demote it,
            # and say why. This is how the false positives in the header were caught.
            strength = "WEAK"
            note = ("demoted: required co-occurring symbol %r not present"
                    % requires.decode("latin-1"))
        record(family, strength, meaning, m.group(0).decode("latin-1")[:80], "dex", note)

    for family, pattern, strength, meaning in MANIFEST_MARKERS:
        m = re.search(pattern, manifest_view)
        if m:
            record(family, strength, meaning,
                   m.group(0).decode("latin-1")[:80], "manifest")

    const_8192 = flag_secure_bytecode_probe(dex)

    return {
        "apk": apk_path,
        "dex_files": dex_names,
        "dex_bytes": len(dex),
        "families": families,
        "hits": hits,
        "const_8192_sites": const_8192,
        "verdict": verdict_for(families, len(dex)),
    }


def verdict_for(families, dex_bytes):
    """A one-line orientation, not a severity. Deliberately conservative."""
    if dex_bytes < 200_000:
        return ("THIN APK - under 200 KB of DEX. If this is a real app its code is "
                "probably in split APKs; scan those too or this result is meaningless.")
    modern = any(f in families for f in ("CredentialManager", "FIDO2"))
    legacy = "AccountManager" in families
    otp = "OTP-SMS" in families
    gate = "LOCAL-GATE" in families
    bits = []
    if modern:
        bits.append("modern credential API present")
    if legacy:
        bits.append("platform AccountManager in use")
    if otp:
        bits.append("SMS OTP path present")
    if gate:
        bits.append("weak local-gate identifiers present (leads only)")
    if not bits:
        bits.append("no recognised authentication surface - it may authenticate "
                    "purely over HTTP with hand-rolled code, which this scan cannot see")
    return "; ".join(bits)


def print_report(result, verbose):
    print("=" * 78)
    print("APK      : %s" % result["apk"])
    print("DEX      : %d file(s), %s bytes" % (len(result["dex_files"]), f"{result['dex_bytes']:,}"))
    print("Verdict  : %s" % result["verdict"])
    print("-" * 78)
    if not result["families"]:
        print("  (no catalogue markers matched)")
    for family, counts in result["families"].items():
        print("  %-16s STRONG=%d  WEAK=%d" % (family, counts["STRONG"], counts["WEAK"]))
    print("  %-16s %d `const/16 vX, #int 8192` site(s) -- FLAG_SECURE candidates, "
          "NOT confirmations" % ("[bytecode]", result["const_8192_sites"]))
    if verbose:
        print("-" * 78)
        for h in result["hits"]:
            print("  [%-6s] %-16s %-8s %s" % (h["strength"], h["family"], h["where"], h["meaning"]))
            print("           matched: %r" % h["sample"])
            if h.get("note"):
                print("           NOTE   : %s" % h["note"])
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Inventory the authentication surface of Android APKs (leads, not findings).")
    ap.add_argument("apks", nargs="+", help="one or more .apk files")
    ap.add_argument("--json", metavar="FILE", help="write full results as JSON")
    ap.add_argument("--verbose", action="store_true", help="print every matched marker")
    args = ap.parse_args(argv)

    results = []
    for path in args.apks:
        try:
            r = scan_one(path, args.verbose)
        except RuntimeError as exc:
            print("SKIP %s (%s)" % (path, exc), file=sys.stderr)
            continue
        results.append(r)
        print_report(r, args.verbose)

    if not results:
        print("no APK could be read", file=sys.stderr)
        return 1

    # Cross-app roll-up. This is the number worth quoting in a report: how many of
    # the apps you looked at use each mechanism.
    print("=" * 78)
    print("ROLL-UP across %d APK(s)" % len(results))
    print("-" * 78)
    every_family = []
    for r in results:
        for f in r["families"]:
            if f not in every_family:
                every_family.append(f)
    for f in sorted(every_family):
        n = sum(1 for r in results if f in r["families"])
        print("  %-16s %2d/%d" % (f, n, len(results)))
    print()
    print("Remember: presence of a marker is not use of a mechanism, and use of a")
    print("mechanism is not correctness of a mechanism. Every row above is a place")
    print("to look, and nothing more.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print("\nwrote %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
