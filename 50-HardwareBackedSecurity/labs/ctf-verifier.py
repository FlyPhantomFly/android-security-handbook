#!/usr/bin/env python3
"""
ctf-verifier.py — the backend attestation verifier for lab-04-ctf-the-honest-phone.md.

THIS CODE IS DELIBERATELY BROKEN. DO NOT COPY IT INTO ANYTHING.

It is written the way real verifiers are written: by a competent engineer, from the documentation,
in an afternoon, with tests that pass. It accepts devices it must not accept. Your job in the CTF
is to find out which ones and why.

USAGE
    python3 -B ctf-verifier.py                       # verdicts for all five devices
    python3 -B ctf-verifier.py device-bravo          # one device, verbose
    python3 -B ctf-verifier.py --show-issued         # the nonces this server believes it issued

REQUIREMENTS
    Python 3.7+, standard library only. Reads ctf-attestations.json from the same directory.

COMPARE IT WITH
    ../examples/hardware_posture_policy.py, which is the same decision written correctly.
    Running both over the same input and diffing the verdicts is the fastest route to the flag.

WHAT THIS WILL *NOT* TELL YOU
    - It will not tell you it is wrong. That is the exercise. It reports every verdict with total
      confidence, which is exactly how this class of bug survives code review and reaches
      production.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "ctf-attestations.json")

# The server's record of the challenges it has issued. In a real deployment this would be a
# short-lived row in a database, created per request and DELETED on use.
ISSUED_CHALLENGES = {
    "9f2c41ab77d0e5613c8a04bf2e91d7635ac0182f4b6e9d3a7c15e8042b9f6d10": "issued 2026-08-12T09:14:02Z",
    "77c3a91e04b5d8267f0a3c94e15b82d6039f7ca41e8b620d5934ac71f0e28b45": "issued 2026-08-12T09:15:41Z",
    "b0e4f27a913c85d6042fae7b19c530846da2f1e93b7c05a8146ef2903dbc7154": "issued 2026-08-12T09:19:08Z",
    "41dc91b868325313fef961975c8823e22f338a2b3a2a93fffe0928e07c6fb144": "issued 2026-08-12T09:21:55Z",
}

# Our app, as the backend knows it.
OUR_PACKAGE = "com.bank.example"
OUR_SIGNER = "b1946ac92492d2347c6235b4d2611184a1e0b0bd06d8a1e8c1e0b0bd06d8a1e8"
MIN_OS_PATCH = 202401


def verify(name, doc, verbose=False):
    """Return (accepted: bool, reasons: list[str])."""
    reasons = []
    att = doc.get("attestation")

    if att is None:
        return False, ["no attestation extension in the chain"]

    # --- 1. the chain -------------------------------------------------------------------------
    # Every certificate must be signed by the next one up.
    for c in doc.get("checks", []):
        if c.get("signature_valid") is not True:
            return False, ["signature check failed: " + c["check"]]
    reasons.append("chain: all signatures verify")

    # The chain must terminate in a self-signed root.
    certs = doc.get("certificates", [])
    if not certs or not certs[-1].get("self_signed"):
        return False, ["chain does not terminate in a self-signed certificate"]
    reasons.append("chain: terminates in a self-signed root (%s)" % certs[-1]["subject"])

    # --- 2. flatten the authorisation lists ----------------------------------------------------
    # The attestation splits its authorisations across two lists. Merge them so the rest of this
    # function can just look fields up by name.
    fields = dict(att.get("softwareEnforced", {}))
    fields.update(att.get("hardwareEnforced", {}))
    reasons.append("authorisations: %d fields available" % len(fields))

    # --- 3. boot state -------------------------------------------------------------------------
    rot = fields.get("rootOfTrust")
    if rot is None:
        return False, reasons + ["no rootOfTrust: boot integrity is unattested"]
    if rot.get("verifiedBootState") != "Verified":
        return False, reasons + ["verifiedBootState is %s, not Verified"
                                 % rot.get("verifiedBootState")]
    if not rot.get("deviceLocked"):
        return False, reasons + ["bootloader is unlocked"]
    reasons.append("boot: Verified and locked")

    # --- 4. patch level -------------------------------------------------------------------------
    patch = fields.get("osPatchLevel")
    if patch is None:
        return False, reasons + ["no osPatchLevel"]
    if int(patch) < MIN_OS_PATCH:
        return False, reasons + ["osPatchLevel %s below minimum %s" % (patch, MIN_OS_PATCH)]
    reasons.append("patch: osPatchLevel %s meets minimum %s" % (patch, MIN_OS_PATCH))

    # --- 5. the key's own policy ---------------------------------------------------------------
    if fields.get("algorithm") != "EC" or int(fields.get("keySize", 0)) < 256:
        return False, reasons + ["key policy: expected EC >= 256"]
    reasons.append("key: %s-%s, purposes %s"
                   % (fields.get("algorithm"), fields.get("keySize"), fields.get("purpose")))

    # --- 6. the challenge ------------------------------------------------------------------------
    challenge = att.get("attestationChallenge", "")
    if not challenge:
        return False, reasons + ["no attestation challenge"]
    reasons.append("challenge: present (%d hex chars)" % len(challenge))

    # --- 7. accept -------------------------------------------------------------------------------
    reasons.append("ACCEPTED: binding device to account")
    return True, reasons


def main(argv):
    if "--show-issued" in argv:
        for c, when in ISSUED_CHALLENGES.items():
            print("%s  %s" % (c, when))
        return 0

    with open(DATA, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    data.pop("_README", None)

    wanted = [a for a in argv if not a.startswith("-")]
    names = wanted if wanted else sorted(data)

    for name in names:
        if name not in data:
            print("unknown device: %s" % name, file=sys.stderr)
            continue
        accepted, reasons = verify(name, data[name])
        print("=" * 72)
        print("%-16s %s" % (name, "ACCEPTED" if accepted else "REJECTED"))
        print("=" * 72)
        for r in reasons:
            print("   " + r)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
