#!/usr/bin/env python3
"""
hardware_posture_policy.py — turn an attestation into a TIER, not a boolean.

WHAT THIS DEMONSTRATES
    The server-side decision that README section 9.5 argues for: given a parsed attestation,
    assign the device a trust TIER rather than accepting or rejecting it.

    The argument for tiers is operational, not aesthetic. A hard fail on "no hardware attestation"
    generates support tickets from users with legitimate but limited devices. Teams then relax the
    check to a warning, the warning is ignored, and the control is gone. A tier gives those users
    somewhere to live that is neither "blocked" nor "fully trusted", so the control survives
    contact with a real support queue.

    It also demonstrates, by construction, the two bugs that make most real verifiers useless:

      * reading fields from the SOFTWARE-enforced list (the merge bug), and
      * accepting a chain without checking where its root came from.

    Both are refused here, loudly, with the reason attached.

USAGE
    # produce a parsed attestation with the chapter's offline parser, then decide:
    python3 -B ../scripts/parse-attestation.py chain.pem --json > parsed.json
    python3 -B hardware_posture_policy.py parsed.json
    python3 -B hardware_posture_policy.py parsed.json --expect-package com.example.app \\
            --expect-signer 301aa3cb...  --min-patch 202401 \\
            --trusted-root-spki feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae

REQUIREMENTS
    Python 3.7+, standard library only. Input is the JSON produced by
    ../scripts/parse-attestation.py --json.

WHAT THIS WILL *NOT* DO
    - It is NOT a production verifier. It does no revocation checking, no certificate date
      validation against a trusted clock, and no rate limiting. For the production-shaped version
      see 49-KeyStore/examples/04-verify-attestation.py, which is the server-side policy verifier
      this chapter deliberately does not duplicate.
    - It will NOT tell you the app using the key is honest. No attestation can. See
      49-KeyStore/README.md section 1.3.
    - It will NOT invent a trusted root for you. If you do not pass --trusted-root-spki, it says
      so and caps the tier, rather than pretending the chain was anchored.
    - It does NOT consume the challenge. Challenge issuance, storage and single use are the
      caller's job and are the most commonly missing part of a real deployment.

SAFETY
    Pure function of its input. Reads one JSON file, writes to stdout, touches nothing else.
"""

import json
import sys

# Tiers, most trusted first. See README section 9.5 for the table these correspond to.
FULL, STANDARD, RESTRICTED, MINIMAL = "FULL", "STANDARD", "RESTRICTED", "MINIMAL"
ORDER = [FULL, STANDARD, RESTRICTED, MINIMAL]


class Decision:
    def __init__(self):
        self.tier = FULL
        self.reasons = []
        self.refusals = []

    def cap(self, tier, reason):
        """Lower the tier to at most `tier`, recording why. Tiers never go back up."""
        if ORDER.index(tier) > ORDER.index(self.tier):
            self.tier = tier
        self.reasons.append("%-10s %s" % ("[-> " + tier + "]", reason))

    def note(self, reason):
        self.reasons.append("%-10s %s" % ("[ok]", reason))

    def refuse(self, reason):
        """A structural problem: the input cannot support ANY decision."""
        self.refusals.append(reason)
        self.tier = MINIMAL


def decide(parsed, expect_package=None, expect_signer=None,
           min_patch=None, trusted_root_spki=None):
    d = Decision()
    att = parsed.get("attestation")

    # ---- 0. is there an attestation at all? -----------------------------------------------
    if not att:
        d.refuse("no attestation extension in the chain: a self-signed 'CN=Android Keystore Key' "
                 "certificate with no extension proves nothing about any hardware")
        return d

    # ---- 1. did the chain actually verify, and does it end anywhere we trust? --------------
    checks = parsed.get("checks", [])
    bad = [c for c in checks if c.get("signature_valid") is False]
    skipped = [c for c in checks if c.get("signature_valid") is None]
    if bad:
        d.refuse("a certificate signature FAILED: " + "; ".join(c["check"] for c in bad))
        return d
    if skipped:
        d.cap(RESTRICTED, "some signatures could not be checked (%s) - treat as unproven"
                          % "; ".join(c.get("note") or c["check"] for c in skipped))
    else:
        d.note("every certificate signature in the chain verified")

    certs = parsed.get("certificates", [])
    if not certs:
        d.refuse("no certificates in the parsed input")
        return d
    root = certs[-1]
    if trusted_root_spki is None:
        # THE bug this refuses to have. A chain that verifies internally and ends at an
        # attacker's own root verifies perfectly and proves nothing.
        d.cap(RESTRICTED,
              "no --trusted-root-spki given, so the chain is UNANCHORED. Its root is '%s' "
              "(spki-sha256 %s). Until you compare that against a root you obtained through a "
              "channel you trust, this chain proves only internal consistency"
              % (root["subject"], root["spki_sha256"]))
    elif root["spki_sha256"].lower() != trusted_root_spki.lower():
        d.refuse("chain root spki-sha256 %s does not match the trusted root %s - subject was '%s'"
                 % (root["spki_sha256"], trusted_root_spki, root["subject"]))
        return d
    else:
        d.note("chain is anchored to the expected root")

    # ---- 2. WHERE was the statement made? ---------------------------------------------------
    att_level = att.get("attestationSecurityLevel")
    key_level = att.get("keymasterSecurityLevel")

    if att_level == "Software":
        d.cap(MINIMAL,
              "attestationSecurityLevel is Software: the entire statement was produced by the "
              "Android framework, which an attacker with root owns. Nothing below is evidence")
        # Deliberately keep going, so the report shows WHY the software case is worthless.
    else:
        d.note("attestation was produced in %s" % att_level)

    if key_level == "Software":
        d.cap(MINIMAL, "the attested key itself lives in software")
    elif key_level == "StrongBox":
        d.note("the attested key lives in StrongBox")
    elif key_level == "TrustedEnvironment":
        d.note("the attested key lives in the TEE")
        # Not a downgrade. Most devices have no StrongBox and that is not the app's fault.

    hw = att.get("hardwareEnforced") or {}
    sw = att.get("softwareEnforced") or {}

    if not hw:
        d.cap(MINIMAL,
              "the hardwareEnforced list is EMPTY - every authorisation below was asserted by "
              "software. A verifier that merged the two lists would not notice this")

    # ---- 3. boot state, from the HARDWARE list only -----------------------------------------
    rot = hw.get("rootOfTrust")
    if rot is None:
        if "rootOfTrust" in sw:
            d.cap(MINIMAL,
                  "rootOfTrust is present ONLY in the softwareEnforced list. This is the "
                  "single most exploited verifier bug: reading it from there means reading a "
                  "value the attacker supplied")
        else:
            d.cap(RESTRICTED, "no rootOfTrust at all - boot integrity is unattested")
    else:
        state, locked = rot.get("verifiedBootState"), rot.get("deviceLocked")
        if state == "Verified" and locked:
            d.note("boot: verifiedBootState=Verified, deviceLocked=true")
        elif state == "SelfSigned":
            d.cap(RESTRICTED, "boot: SelfSigned - a custom key verified this boot "
                              "(custom ROM or a user-flashed image)")
        elif state in ("Unverified", "Failed") or not locked:
            d.cap(RESTRICTED,
                  "boot: verifiedBootState=%s deviceLocked=%s - the bootloader is unlocked or "
                  "the boot chain was not verified. Whatever ro.boot.verifiedbootstate says on "
                  "this device, THIS is the signed answer" % (state, locked))

    # ---- 4. key policy ----------------------------------------------------------------------
    origin = hw.get("origin")
    if origin is None and "origin" in sw:
        d.cap(RESTRICTED, "origin appears only in the softwareEnforced list, so 'GENERATED' is "
                          "the framework's word for it")
    elif origin and origin != "GENERATED":
        d.cap(RESTRICTED, "origin=%s - the key material existed outside the secure hardware at "
                          "some point, so device-binding claims about it are weaker" % origin)
    elif origin == "GENERATED":
        d.note("origin=GENERATED, hardware-enforced")

    if hw.get("noAuthRequired") or sw.get("noAuthRequired"):
        d.cap(STANDARD, "the key carries noAuthRequired: it can be used with no user "
                        "authentication at all. Acceptable for a device-identity key, NOT for a "
                        "key that authorises a transaction")
    else:
        timeout = hw.get("authTimeout")
        if timeout is None:
            d.note("key is auth-bound per-use (no authTimeout): the strongest available binding")
        else:
            d.cap(STANDARD,
                  "key is auth-bound with a %s-second window: for %s seconds after ANY unlock, "
                  "any code in the app's process can use this key with no prompt"
                  % (timeout, timeout))

    # ---- 5. patch level ---------------------------------------------------------------------
    patch = hw.get("osPatchLevel")
    if min_patch is not None:
        if patch is None:
            d.cap(RESTRICTED, "no hardware-enforced osPatchLevel to check against the minimum")
        elif int(patch) < int(min_patch):
            d.cap(RESTRICTED, "osPatchLevel %s is below the required minimum %s"
                              % (patch, min_patch))
        else:
            d.note("osPatchLevel %s meets the minimum %s" % (patch, min_patch))
    elif patch is not None:
        d.note("osPatchLevel %s (no minimum configured)" % patch)

    # ---- 6. which app is this? --------------------------------------------------------------
    # attestationApplicationId is supplied by the framework and lands in the software list on
    # every device. That is normal (KeyMint cannot know package names) and it is why this check
    # is a signal rather than a binding. See README section 4.3.
    appid = hw.get("attestationApplicationId") or sw.get("attestationApplicationId")
    if appid is None:
        d.cap(RESTRICTED, "no attestationApplicationId - nothing ties this key to a package")
    else:
        packages = [p.get("package") for p in appid.get("packages", [])]
        signers = [s.lower() for s in appid.get("signature_digests", [])]
        if expect_package is not None:
            if expect_package in packages:
                d.note("attestationApplicationId names our package (%s)" % expect_package)
            else:
                d.refuse("attestationApplicationId names %s, not %s - a different app generated "
                         "this key" % (packages, expect_package))
                return d
        if expect_signer is not None:
            if expect_signer.lower() in signers:
                d.note("signing certificate digest matches")
            else:
                d.refuse("signing digest %s not among %s - repackaged app"
                         % (expect_signer, signers))
                return d
        if expect_package is None and expect_signer is None:
            d.cap(STANDARD, "no expected package/signer configured, so 'which app holds this "
                            "key' was never checked. Packages seen: %s" % packages)

    # ---- 7. the challenge ------------------------------------------------------------------
    chal = att.get("attestationChallenge") or ""
    ascii_chal = att.get("attestationChallengeAscii") or ""
    if len(chal) < 32:
        d.cap(RESTRICTED, "attestation challenge is only %d hex chars - too short to be a "
                          "meaningful nonce" % len(chal))
    if ascii_chal and all(32 <= ord(c) < 127 for c in ascii_chal) and len(set(ascii_chal)) > 3:
        d.cap(RESTRICTED,
              "the challenge is printable ASCII (%r), which usually means a CONSTANT string "
              "rather than a server-issued random nonce. Verify by attesting twice and comparing"
              % ascii_chal)
    d.reasons.append("%-10s %s" % ("[note]", "challenge freshness and single use CANNOT be "
                                             "checked from the chain alone - that is the "
                                             "server's records, and it is the check most often "
                                             "missing entirely"))
    return d


def main(argv):
    path, expect_package, expect_signer, min_patch, root_spki = None, None, None, None, None
    i = 0
    while i < len(argv):
        if argv[i] == "--expect-package":
            expect_package = argv[i + 1]; i += 2
        elif argv[i] == "--expect-signer":
            expect_signer = argv[i + 1]; i += 2
        elif argv[i] == "--min-patch":
            min_patch = argv[i + 1]; i += 2
        elif argv[i] == "--trusted-root-spki":
            root_spki = argv[i + 1]; i += 2
        else:
            path = argv[i]; i += 1
    if path is None:
        print("usage: hardware_posture_policy.py parsed.json [--expect-package P] "
              "[--expect-signer HEX] [--min-patch YYYYMM] [--trusted-root-spki HEX]",
              file=sys.stderr)
        return 2

    with open(path, "r", encoding="utf-8") as fh:
        parsed = json.load(fh)

    d = decide(parsed, expect_package, expect_signer, min_patch, root_spki)

    print("=" * 78)
    print("DEVICE TRUST TIER: %s" % d.tier)
    print("=" * 78)
    for r in d.reasons:
        print("  " + r)
    if d.refusals:
        print()
        print("  REFUSED:")
        for r in d.refusals:
            print("    - " + r)
    print()
    print({
        FULL:       "  Full: high-value transactions and long sessions permitted.",
        STANDARD:   "  Standard: normal use. Step up authentication for anything unusual.",
        RESTRICTED: "  Restricted: read-only. Require step-up for every state change.",
        MINIMAL:    "  Minimal: treat this exactly like an unauthenticated browser session. "
                    "Claim NO device binding.",
    }[d.tier])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
