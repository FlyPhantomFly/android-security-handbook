#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scope-checklist.py -- turn an app profile into a scoped MASVS control set, with a
                      written justification for every EXCLUSION.

WHAT IT DOES
    Scoping is the part of an engagement that decides whether the other nine days were
    well spent, and it is the part nobody practises. This script mechanises the
    bookkeeping half of it so that the judgement half is what you spend your attention
    on.

    You give it a profile: a set of assertions about the app and the engagement -- does
    the device owner belong in the threat model, does the app hold financial data, is
    there a rooted device available, is the backend in scope. It gives you back three
    tables:

        IN SCOPE   one row per control, with a priority and the assertion that put it there
        BLOCKED    controls you would test but cannot, with what would unblock them
        EXCLUDED   controls deliberately not tested, with a reason AND the future event
                   that puts each back in scope

    The EXCLUDED table is the reason this script exists. Inclusions are cheap to justify
    -- "it is in the standard" is nearly always enough. Exclusions are where a tester's
    judgement is actually visible, because each one asserts that a whole category of
    failure does not matter for this app. That assertion can be wrong, and the client is
    entitled to see it and disagree with it.

    It also distinguishes EXCLUDED from BLOCKED, which reports routinely conflate.
    EXCLUDED is a risk decision you made. BLOCKED is a limitation imposed on you. A
    client who reads a BLOCKED control as EXCLUDED believes you considered and dismissed
    something you simply could not reach.

WHAT THIS IS *NOT* -- the boundary with other chapters
    It does not rate severity and it does not produce a report. The severity rubric, the
    CVSS discussion, the finding template and the engagement checklist all belong to
    80-Appendix, and restaging them here would create two copies that drift apart.

    It does not tell you HOW to test any control. That belongs to the chapter that owns
    the mechanism -- 34-Cryptography for CRYPTO, 32-Manifest and 24-IPC for PLATFORM,
    and so on. Chapter 71 owns the standard and how to use it, not the techniques.

WHAT THIS WILL *NOT* TELL YOU
    - Whether your profile is true. Every field is an assertion the script cannot check.
      "uses_cryptography": false produces a confident exclusion of both CRYPTO controls,
      and if the app does in fact encrypt something, that exclusion is wrong and the
      script will never know. Verify each field against the artefact and the client
      before trusting the output.
    - Whether your threat model is right. The single most consequential field is
      threat_model.hostile_device_owner, and the script takes your word for it. Get it
      wrong in one direction and you recommend obfuscation to an internal tool; wrong in
      the other and you tell a bank its fraud problem is out of scope.
    - What you will find. A scope guarantees coverage, never insight. The day allocation
      it prints deliberately reserves unstructured time, because the findings that matter
      most are the ones no control would have led you to. See labs/lab-03-find-the-gap.md.
    - Whether the control identifiers below are current. The standard has been renumbered
      before. The built-in catalogue is a convenience with a stated provenance, not an
      authority -- resolve identifiers at https://mas.owasp.org/ and override the
      catalogue with --controls when the project moves.
    - Anything about the backend. MASVS is a mobile application standard. If the API is
      in scope, scope OWASP ASVS for it explicitly, as a named workstream with its own
      days.

HOW TO RUN
    # host -- the scope, as a text report
    python3 scope-checklist.py ../examples/profile-banking.json

    # host -- paste straight into an engagement document
    python3 scope-checklist.py ../examples/profile-internal-tool.json --markdown

    # host -- only the table that gets argued about
    python3 scope-checklist.py ../examples/profile-banking.json --exclusions-only

    # host -- the profile schema, with every field explained
    python3 scope-checklist.py --print-schema

    # host -- your own control catalogue, one "ID|CATEGORY|title" per line
    python3 scope-checklist.py profile.json --controls my-masvs-v3.txt

REQUIREMENTS
    Python 3.6+. Standard library only (json, argparse, textwrap), so it runs on a
    locked-down assessment laptop with no pip access.

    Output is pure ASCII on purpose: a Windows console defaults to a codepage that
    cannot encode box-drawing characters, and a UnicodeEncodeError halfway through a
    scoping document is worse than a plain table.

    The script writes nothing and imports nothing local. Run it as a script so it leaves
    no __pycache__ beside the repository source.

EXIT CODES
    0  ran to completion
    2  profile could not be read, parsed, or validated

AUTHORISED TESTING ONLY.
"""

import argparse
import json
import os
import sys
import textwrap

# ---------------------------------------------------------------------------
#  Control catalogue.
#
#  PROVENANCE, read this before trusting a row: these are the MASVS v2.x control
#  identifiers as published by the OWASP MAS project, with titles PARAPHRASED for
#  testers. The paraphrases are not quotations and must not be pasted into a report as
#  if they were the standard's own wording.
#
#  The identifiers have changed before -- v1 used MSTG-<CATEGORY>-<n> and included an
#  ARCH group that no longer exists -- and they may change again. Resolve them at
#  https://mas.owasp.org/ and use --controls to override this list when they do.
# ---------------------------------------------------------------------------

DEFAULT_CONTROLS = [
    ("MASVS-STORAGE-1",    "STORAGE",    "Sensitive data is stored securely"),
    ("MASVS-STORAGE-2",    "STORAGE",    "Sensitive data does not leak by unintended channels"),
    ("MASVS-CRYPTO-1",     "CRYPTO",     "Strong cryptography, used correctly"),
    ("MASVS-CRYPTO-2",     "CRYPTO",     "Sound key management"),
    ("MASVS-AUTH-1",       "AUTH",       "Authentication and authorization enforced server-side"),
    ("MASVS-AUTH-2",       "AUTH",       "Local authentication implemented properly"),
    ("MASVS-AUTH-3",       "AUTH",       "Additional authentication for sensitive operations"),
    ("MASVS-NETWORK-1",    "NETWORK",    "All network traffic secured to current practice"),
    ("MASVS-NETWORK-2",    "NETWORK",    "Identity pinning for developer-controlled endpoints"),
    ("MASVS-PLATFORM-1",   "PLATFORM",   "IPC mechanisms used securely"),
    ("MASVS-PLATFORM-2",   "PLATFORM",   "WebViews used securely"),
    ("MASVS-PLATFORM-3",   "PLATFORM",   "User interface used securely"),
    ("MASVS-CODE-1",       "CODE",       "An up-to-date platform version is required"),
    ("MASVS-CODE-2",       "CODE",       "A mechanism exists for enforcing app updates"),
    ("MASVS-CODE-3",       "CODE",       "No components with known vulnerabilities"),
    ("MASVS-CODE-4",       "CODE",       "Untrusted input validated and sanitised"),
    ("MASVS-RESILIENCE-1", "RESILIENCE", "Platform integrity is validated"),
    ("MASVS-RESILIENCE-2", "RESILIENCE", "Anti-tampering measures"),
    ("MASVS-RESILIENCE-3", "RESILIENCE", "Anti-static-analysis measures"),
    ("MASVS-RESILIENCE-4", "RESILIENCE", "Anti-dynamic-analysis measures"),
    ("MASVS-PRIVACY-1",    "PRIVACY",    "Access to sensitive data and resources minimised"),
    ("MASVS-PRIVACY-2",    "PRIVACY",    "Identification of the user prevented"),
    ("MASVS-PRIVACY-3",    "PRIVACY",    "Transparency about collection and use"),
    ("MASVS-PRIVACY-4",    "PRIVACY",    "User control over their own data"),
]

CATEGORY_ORDER = ["STORAGE", "CRYPTO", "AUTH", "NETWORK",
                  "PLATFORM", "CODE", "RESILIENCE", "PRIVACY"]

# Base effort weight per category, before profile adjustments.
BASE_WEIGHT = {
    "STORAGE": 1.0, "CRYPTO": 1.0, "AUTH": 1.5, "NETWORK": 1.0,
    "PLATFORM": 1.5, "CODE": 0.75, "RESILIENCE": 1.5, "PRIVACY": 1.0,
}

SCHEMA_TEXT = """\
PROFILE SCHEMA -- every field is an ASSERTION the script cannot verify.

{
  "app":               "com.example.app",       package name
  "name":              "Human readable name",
  "version":           "1.2.3 (10203)",         versionName (versionCode)
  "engagement_days":   10,                      number; drives the day allocation only
  "standard_version":  "MASVS v2.x, resolved <date>",

  "threat_model": {
    "hostile_device_owner":            true,    THE most consequential field in the file
    "hostile_device_owner_adversary":  "who, concretely -- required when the above is true",
    "sensitive_data":  ["financial","identity","credentials","health","location",
                        "employee_pii","children","none"],
    "distribution":         "public" | "managed" | "internal",
    "managed_devices":      false,              MDM-enrolled, organisation-owned
    "backend_in_scope":     true,               scope OWASP ASVS separately if so
    "backend_reachability": "public" | "internal" | "none"
  },

  "app_traits": {
    "has_accounts":             true,
    "has_local_auth":           true,           biometric or PIN unlock
    "has_sensitive_operations": true,           payments, transfers, credential change
    "uses_webview":             true,
    "uses_cryptography":        true,
    "stores_data_locally":      true,
    "has_backend":              true,
    "has_update_mechanism":     true,
    "third_party_sdks":         12,             count; 0 is an assertion, verify it
    "collects_personal_data":   true,
    "child_users":              false           forces every PRIVACY control into scope
  },

  "constraints": {
    "rooted_device_available":  true,           absence BLOCKS, it does not EXCLUDE
    "second_account_available": true,           needed for authorization testing
    "source_code_available":    false,
    "privacy_policy_available": true            needed to assess transparency
  }
}

Missing fields are treated as absent rather than false, and every one produces a
warning, because a scope built on defaults you never stated is a scope you cannot
defend."""


# ---------------------------------------------------------------------------
#  Profile access
# ---------------------------------------------------------------------------

class Profile(object):

    def __init__(self, data, path):
        self.data = data if isinstance(data, dict) else {}
        self.path = path
        self.warnings = []
        self.tm = self._section("threat_model")
        self.traits = self._section("app_traits")
        self.limits = self._section("constraints")

    def _section(self, name):
        v = self.data.get(name)
        if not isinstance(v, dict):
            self.warnings.append(
                'section "%s" is missing or not an object; every field in it will be '
                'treated as unstated' % name)
            return {}
        return v

    def flag(self, section, key, default=False):
        """A boolean assertion. An absent field is recorded, not silently defaulted."""
        src = getattr(self, section)
        if key not in src:
            self.warnings.append(
                '%s.%s is unstated; assuming %s. State it explicitly -- an unstated '
                'assertion is one you cannot defend in a scoping call.'
                % (section_name(section), key, str(default).lower()))
            return default
        val = src.get(key)
        if isinstance(val, str):
            self.warnings.append(
                '%s.%s is the string "%s"; JSON booleans are unquoted true/false. '
                'Treating it as %s.'
                % (section_name(section), key, val, val.strip().lower() == "true"))
            return val.strip().lower() == "true"
        return bool(val)

    def num(self, section, key, default=0):
        src = getattr(self, section)
        try:
            return int(src.get(key, default))
        except (TypeError, ValueError):
            self.warnings.append('%s.%s is not a number; using %d'
                                 % (section_name(section), key, default))
            return default

    def text(self, section, key, default=""):
        src = getattr(self, section)
        v = src.get(key, default)
        return v if isinstance(v, str) else default

    @property
    def sensitive(self):
        v = self.tm.get("sensitive_data")
        if isinstance(v, list):
            return [str(x).lower() for x in v]
        if isinstance(v, str):
            return [v.lower()]
        self.warnings.append(
            "threat_model.sensitive_data is unstated; depth cannot be reasoned about "
            "and every control is scoped at baseline")
        return []

    @property
    def high_sensitivity(self):
        return bool(set(self.sensitive) &
                    {"financial", "credentials", "health", "identity", "children"})


def section_name(attr):
    return {"tm": "threat_model", "traits": "app_traits", "limits": "constraints"}[attr]


# ---------------------------------------------------------------------------
#  Decisions
# ---------------------------------------------------------------------------

class Decision(object):
    __slots__ = ("cid", "category", "title", "state", "priority", "reason", "change")

    def __init__(self, cid, category, title, state, priority, reason, change):
        self.cid = cid
        self.category = category
        self.title = title
        self.state = state          # IN | BLOCKED | EXCLUDED
        self.priority = priority    # HIGH | MEDIUM | LOW | --
        self.reason = reason
        self.change = change        # what would move it out of this state


NO_HOSTILE_OWNER = (
    "the profile declares no hostile device owner{ctx}. The whole resilience category "
    "therefore defends against an adversary that does not exist for this app, at a cost "
    "in engineering effort, crash-reporting fidelity and support load. Resilience is "
    "orthogonal to the other categories, never a higher tier")

WOULD_CHANGE_RESILIENCE = (
    "the app becoming installable on devices the organisation does not control; "
    "the app gaining client-side value worth attacking (an embedded key, offline "
    "entitlement, licensing or pricing logic); or the client naming a fraud, "
    "cracking or automation adversary")


def decide(cid, category, title, p):
    """Return a Decision for one control, given a profile."""

    hostile = p.flag("tm", "hostile_device_owner", False)
    managed = p.flag("tm", "managed_devices", False)
    dist = p.text("tm", "distribution", "unstated")
    backend = p.flag("traits", "has_backend", True)
    accounts = p.flag("traits", "has_accounts", True)
    local_auth = p.flag("traits", "has_local_auth", False)
    sensitive_ops = p.flag("traits", "has_sensitive_operations", False)
    webview = p.flag("traits", "uses_webview", False)
    crypto = p.flag("traits", "uses_cryptography", True)
    stores = p.flag("traits", "stores_data_locally", True)
    personal = p.flag("traits", "collects_personal_data", True)
    children = p.flag("traits", "child_users", False)
    sdks = p.num("traits", "third_party_sdks", 0)
    rooted = p.flag("limits", "rooted_device_available", True)
    second_acct = p.flag("limits", "second_account_available", True)
    policy = p.flag("limits", "privacy_policy_available", True)

    hi = "HIGH" if p.high_sensitivity else "MEDIUM"

    # -- STORAGE -----------------------------------------------------------
    if cid == "MASVS-STORAGE-1":
        if not stores:
            return Decision(cid, category, title, "EXCLUDED", "--",
                            "the profile asserts the app stores nothing locally. This is "
                            "the single most frequently wrong assertion in a profile: "
                            "WebView caches, crash reporters, analytics SDKs and the "
                            "recents thumbnail all write without the developer deciding "
                            "to. Confirm with a data-directory diff before accepting it",
                            "any observed write to the private data directory, shared "
                            "storage, or an SDK cache")
        if not rooted:
            return Decision(cid, category, title, "BLOCKED", hi,
                            "the private data directory cannot be inspected without root "
                            "or a debuggable build, so the evidence this control requires "
                            "cannot be produced",
                            "a rooted device or emulator, or a client-provided debuggable "
                            "build of the same version")
        return Decision(cid, category, title, "IN", hi,
                        "the app stores data locally; a full inventory of what is written, "
                        "where, and in what form is required", "")

    if cid == "MASVS-STORAGE-2":
        return Decision(cid, category, title, "IN",
                        hi if personal else "MEDIUM",
                        "leakage channels -- system log, clipboard, backups, recents "
                        "thumbnail, crash reports -- exist for every app and need no root "
                        "to observe", "")

    # -- CRYPTO ------------------------------------------------------------
    if category == "CRYPTO":
        if not crypto:
            return Decision(cid, category, title, "EXCLUDED", "--",
                            "the profile asserts the app performs no cryptographic "
                            "operations of its own. Confirm this with a runtime JCA trace "
                            "rather than a grep before accepting it -- a bundled SDK "
                            "encrypting its own cache is still the app's finding",
                            "any Cipher, KeyGenerator, MessageDigest or SecureRandom use "
                            "observed at runtime, including inside a third-party SDK")
        return Decision(cid, category, title, "IN", hi,
                        "the app performs cryptographic operations; algorithm, mode, "
                        "parameters and key provenance must be captured at runtime, not "
                        "read from source", "")

    # -- AUTH --------------------------------------------------------------
    if cid == "MASVS-AUTH-1":
        if not accounts and not backend:
            return Decision(cid, category, title, "EXCLUDED", "--",
                            "the app has no accounts and no backend, so there is no "
                            "authorization decision for a server to enforce",
                            "the app gaining any user identity, entitlement or "
                            "server-side state")
        if not second_acct:
            return Decision(cid, category, title, "BLOCKED", "HIGH",
                            "authorization testing needs two accounts at different "
                            "privilege levels; only one is available. Testing with one "
                            "account finds authentication bugs and misses the entire IDOR "
                            "class, which is where the severe findings are",
                            "a second test account, ideally at a lower privilege level, "
                            "provisioned by the client")
        return Decision(cid, category, title, "IN", "HIGH",
                        "server-side enforcement must be proven by replaying every "
                        "endpoint unauthenticated and as a lower-privileged user", "")

    if cid == "MASVS-AUTH-2":
        if not local_auth:
            return Decision(cid, category, title, "EXCLUDED", "--",
                            "the app implements no local authentication surface -- no "
                            "biometric prompt, no app PIN, no device-credential gate",
                            "the app adding any biometric or PIN unlock, at which point "
                            "the question becomes whether it is bound to a CryptoObject "
                            "or is merely a boolean")
        return Decision(cid, category, title, "IN", hi,
                        "a local authentication gate exists; it must be shown to be "
                        "cryptographically bound rather than decorative", "")

    if cid == "MASVS-AUTH-3":
        if not sensitive_ops:
            return Decision(cid, category, title, "EXCLUDED", "--",
                            "the profile declares no operation sensitive enough to warrant "
                            "step-up authentication -- no money movement, no credential "
                            "change, no bulk data export",
                            "the app gaining a payment, transfer, credential-change or "
                            "data-export flow")
        return Decision(cid, category, title, "IN", "HIGH",
                        "sensitive operations exist; step-up authentication must be shown "
                        "to be enforced by the server, not merely prompted by the app", "")

    # -- NETWORK -----------------------------------------------------------
    if cid == "MASVS-NETWORK-1":
        if not backend:
            return Decision(cid, category, title, "EXCLUDED", "--",
                            "the app makes no network calls of its own. Verify with a "
                            "capture, including non-HTTP traffic and third-party SDK "
                            "egress, before accepting this",
                            "any observed egress, including from a bundled SDK")
        return Decision(cid, category, title, "IN", hi,
                        "all traffic must be captured and the app's handling of expired, "
                        "self-signed and wrong-hostname certificates recorded "
                        "individually", "")

    if cid == "MASVS-NETWORK-2":
        if not backend:
            return Decision(cid, category, title, "EXCLUDED", "--",
                            "there is no developer-controlled remote endpoint to pin to",
                            "the app gaining a backend under the client's control")
        if p.text("tm", "backend_reachability", "") == "internal" and managed:
            return Decision(cid, category, title, "EXCLUDED", "--",
                            "the backend is reachable only from the organisation's own "
                            "network, on devices the organisation owns, with certificates "
                            "the same organisation issues. Pinning would defend against an "
                            "interception capability that belongs to the client itself",
                            "the API becoming internet-reachable, the devices becoming "
                            "BYOD, or the certificates moving to a public CA")
        return Decision(cid, category, title, "IN",
                        "HIGH" if p.high_sensitivity else "MEDIUM",
                        "endpoints are developer-controlled and publicly reachable; pin "
                        "presence, mechanism, expiry and backup pin must each be "
                        "recorded", "")

    # -- PLATFORM ----------------------------------------------------------
    if cid == "MASVS-PLATFORM-1":
        return Decision(cid, category, title, "IN", "HIGH",
                        "every Android app has an IPC surface whether the developer "
                        "intended one or not, and a third-party SDK can inject components "
                        "the developer never wrote. Reproduce every conclusion from an "
                        "unprivileged probe app, never from adb shell", "")

    if cid == "MASVS-PLATFORM-2":
        if not webview:
            return Decision(cid, category, title, "EXCLUDED", "--",
                            "the profile asserts the app embeds no WebView. Confirm from "
                            "the shipped artefact rather than the source, since login, "
                            "consent, help and advertising SDKs all commonly bring one",
                            "any WebView, Custom Tab with a JavaScript bridge, or "
                            "embedded browser component found in the artefact")
        return Decision(cid, category, title, "IN", "HIGH",
                        "every WebView's settings, loadable origins and JavaScript "
                        "bridges must be enumerated from the shipped artefact", "")

    if cid == "MASVS-PLATFORM-3":
        return Decision(cid, category, title, "IN",
                        "HIGH" if (p.high_sensitivity or children) else "MEDIUM",
                        "screenshot, recents, clipboard, overlay and deep-link consent "
                        "surfaces exist for every app with a user interface", "")

    # -- CODE --------------------------------------------------------------
    if cid == "MASVS-CODE-1":
        return Decision(cid, category, title, "IN", "MEDIUM",
                        "minSdk, targetSdk and the legacy behaviours a low value "
                        "re-enables are nearly free to assess and change the meaning of "
                        "several other controls", "")

    if cid == "MASVS-CODE-2":
        if not p.flag("traits", "has_update_mechanism", False):
            return Decision(cid, category, title, "IN", "LOW",
                            "the profile declares no update-enforcement mechanism, which "
                            "is itself the assessment: the question is whether the server "
                            "will serve an arbitrarily old client indefinitely. Kept in "
                            "scope deliberately -- an absent control is a finding, not an "
                            "exclusion", "")
        return Decision(cid, category, title, "IN", "LOW",
                        "an update mechanism exists; the question is whether the server "
                        "enforces it or the client merely suggests it", "")

    if cid == "MASVS-CODE-3":
        pr = "HIGH" if sdks >= 8 else ("MEDIUM" if sdks > 0 else "LOW")
        note = ("the profile declares no third-party SDKs, which is rare and worth "
                "verifying: fingerprint the shipped artefact rather than trusting a "
                "build file" if sdks == 0 else
                "%d third-party components declared; a version-bearing inventory is "
                "required, and 'unknown version' is a legitimate recorded state" % sdks)
        return Decision(cid, category, title, "IN", pr, note, "")

    if cid == "MASVS-CODE-4":
        return Decision(cid, category, title, "IN", "MEDIUM",
                        "every entry point that accepts outside data -- intents, deep "
                        "links, provider arguments, WebView messages, push payloads, "
                        "imported files -- is in scope for this control", "")

    # -- RESILIENCE --------------------------------------------------------
    if category == "RESILIENCE":
        if not hostile:
            ctx = ""
            if managed:
                ctx = (" and the devices are organisation-owned and MDM-managed, so the "
                       "device owner is the employer rather than an adversary")
            elif dist in ("internal", "managed"):
                ctx = " and distribution is restricted rather than public"
            return Decision(cid, category, title, "EXCLUDED", "--",
                            NO_HOSTILE_OWNER.format(ctx=ctx),
                            WOULD_CHANGE_RESILIENCE)
        adversary = p.text("tm", "hostile_device_owner_adversary", "").strip()
        if not adversary:
            return Decision(cid, category, title, "IN", "MEDIUM",
                            "the profile declares a hostile device owner but names no "
                            "adversary. IN SCOPE PROVISIONALLY -- name the adversary or "
                            "reconsider the scoping, because a resilience recommendation "
                            "without a named adversary costs the client engineering "
                            "effort and buys nothing measurable", "")
        return Decision(cid, category, title, "IN", "HIGH",
                        "the device owner is in the threat model: %s. Inventory each "
                        "protection, measure the cost of defeating it, and record whether "
                        "anything server-side consumes its verdict" % adversary, "")

    # -- PRIVACY -----------------------------------------------------------
    if category == "PRIVACY":
        if children:
            return Decision(cid, category, title, "IN", "HIGH",
                            "the profile declares child users. Every privacy control is in "
                            "scope at elevated priority regardless of other assertions, "
                            "because the regulatory and reputational exposure does not "
                            "scale with the amount of data collected", "")
        if not personal:
            return Decision(cid, category, title, "EXCLUDED", "--",
                            "the profile asserts the app collects no personal data. This "
                            "is rarely true once third-party SDK egress is measured; "
                            "confirm from a traffic capture attributed by destination host",
                            "any egress carrying an identifier, a location, or "
                            "user-generated content, including from a bundled SDK")
        if cid == "MASVS-PRIVACY-3" and not policy:
            return Decision(cid, category, title, "BLOCKED", "MEDIUM",
                            "transparency is assessed by comparing observed egress against "
                            "the published policy, and no policy is available to compare "
                            "against",
                            "the client providing the privacy policy and the in-app "
                            "disclosures as they are actually shown to users")
        if cid == "MASVS-PRIVACY-4" and not accounts:
            return Decision(cid, category, title, "EXCLUDED", "--",
                            "there is no account or data-control surface for a user to "
                            "exercise control through",
                            "the app gaining accounts, an export function, or a deletion "
                            "flow")
        pr = "HIGH" if (sdks >= 5 or p.high_sensitivity) else "MEDIUM"
        sdk_note = (" across %d declared third-party SDKs" % sdks) if sdks else ""
        privacy_reason = {
            "MASVS-PRIVACY-1":
                "the app collects personal data%s; every permission and every collected "
                "field needs a justification checked against actual code use, not against "
                "the developer's intent" % sdk_note,
            "MASVS-PRIVACY-2":
                "the app collects personal data%s; identifiers must be inventoried and "
                "classified as resettable or permanent, and any join between an identifier "
                "and an account is a finding in itself" % sdk_note,
            "MASVS-PRIVACY-3":
                "the app collects personal data%s; observed egress must be compared "
                "against the published policy line by line, attributed by destination host"
                % sdk_note,
            "MASVS-PRIVACY-4":
                "the app collects personal data and has accounts; export, deletion and "
                "opt-out paths must be exercised end to end, including server-side effect",
        }.get(cid, "the app collects personal data%s" % sdk_note)
        return Decision(cid, category, title, "IN", pr, privacy_reason, "")

    # Unknown identifier from a --controls override.
    return Decision(cid, category, title, "IN", "MEDIUM",
                    "control from an overridden catalogue; no scoping rule is defined for "
                    "it, so it is included by default. Decide it by hand", "")


# ---------------------------------------------------------------------------
#  Day allocation
# ---------------------------------------------------------------------------

def allocate_days(decisions, p):
    """
    Suggest a day split across in-scope categories. Deliberately reserves
    unstructured time: a plan with every day allocated to the checklist has
    allocated zero days to the findings the checklist cannot describe.
    """
    try:
        days = int(p.data.get("engagement_days", 0))
    except (TypeError, ValueError):
        days = 0
    if days <= 0:
        return None, []

    live = {}
    for d in decisions:
        if d.state == "IN":
            live[d.category] = live.get(d.category, 0) + 1

    weights = {}
    sens = set(p.sensitive)
    for cat in CATEGORY_ORDER:
        if cat not in live:
            continue
        w = BASE_WEIGHT[cat]
        if cat == "AUTH" and sens & {"financial", "credentials", "identity"}:
            w *= 1.5
        if cat == "CRYPTO" and sens & {"financial", "credentials", "health"}:
            w *= 1.25
        if cat == "PRIVACY":
            if p.flag("traits", "child_users", False) or "health" in sens:
                w *= 2.0
            if p.num("traits", "third_party_sdks", 0) >= 5:
                w *= 1.5
        if cat == "PLATFORM" and p.flag("traits", "uses_webview", False):
            w *= 1.25
        if cat == "CODE" and p.num("traits", "third_party_sdks", 0) >= 8:
            w *= 1.5
        weights[cat] = w

    reserve = max(0.5, round(days * 0.15 * 2) / 2.0)
    reporting = 1.0 if days >= 5 else 0.5
    testable = max(0.5, days - reserve - reporting)

    # Largest-remainder allocation in half-day units, so the printed rows sum to
    # exactly the testable budget. Naive rounding over-allocates on short
    # engagements, which is precisely when the over-allocation matters.
    units = int(round(testable * 2))
    cats = [c for c in CATEGORY_ORDER if c in weights]
    total_w = sum(weights[c] for c in cats) or 1.0
    quota = {c: units * weights[c] / total_w for c in cats}
    alloc = {c: int(quota[c]) for c in cats}
    left = units - sum(alloc.values())
    for c in sorted(cats, key=lambda c: (quota[c] - int(quota[c]), weights[c]),
                    reverse=True):
        if left <= 0:
            break
        alloc[c] += 1
        left -= 1

    rows = [(c, alloc[c] / 2.0, live[c]) for c in cats]
    extra = [("UNSTRUCTURED -- the app's own functionality", reserve, 0),
             ("Verification, severity review and reporting", reporting, 0),
             ("TOTAL", float(days), 0)]
    return days, rows + extra


# ---------------------------------------------------------------------------
#  Rendering
# ---------------------------------------------------------------------------

def wrap(text, width, indent):
    text = " ".join(str(text).split())
    return textwrap.wrap(text, width=width, initial_indent=indent,
                         subsequent_indent=indent) or [indent]


def render_text(decisions, p, width, only_exclusions):
    out = []
    bar = "=" * width
    rule = "-" * width
    name = p.data.get("name") or p.data.get("app") or "<unnamed app>"

    out.append(bar)
    out.append("  SCOPE -- %s" % name)
    out.append(bar)
    out.append("  profile          : %s" % p.path)
    out.append("  package          : %s" % (p.data.get("app") or "<unstated>"))
    out.append("  version          : %s" % (p.data.get("version") or "<unstated>"))
    out.append("  standard version : %s" % (p.data.get("standard_version") or
                                            "<UNSTATED -- record it before delivery>"))
    counts = {}
    for d in decisions:
        counts[d.state] = counts.get(d.state, 0) + 1
    out.append("  decisions        : " + ", ".join(
        "%s %d" % (s, counts[s]) for s in ("IN", "BLOCKED", "EXCLUDED") if s in counts))
    out.append("")

    def table(title, state, extra_col):
        rows = [d for d in decisions if d.state == state]
        out.append(rule)
        out.append("  %s (%d)" % (title, len(rows)))
        out.append(rule)
        if not rows:
            out.append("  none")
            out.append("")
            return
        for d in rows:
            head = "  %-20s %-8s " % (d.cid, d.priority)
            out.append(head + d.title)
            for line in wrap(d.reason, width - 6, ""):
                out.append("      " + line)
            if extra_col and d.change:
                for i, line in enumerate(wrap(d.change, width - 24, "")):
                    out.append("      %s %s" % ("back in scope if:" if i == 0
                                                else "                 ", line))
            out.append("")

    if not only_exclusions:
        table("IN SCOPE", "IN", False)
        table("BLOCKED -- would test, cannot. A limitation, NOT a risk decision",
              "BLOCKED", True)
    table("EXCLUDED -- deliberately not tested. THIS is where your judgement is visible",
          "EXCLUDED", True)

    if not only_exclusions:
        days, rows = allocate_days(decisions, p)
        if days:
            out.append(rule)
            out.append("  SUGGESTED DAY ALLOCATION -- %d day(s)" % days)
            out.append(rule)
            for label, d, n in rows:
                if label == "TOTAL":
                    out.append("  " + "-" * (width - 4))
                suffix = "  (%d control(s) in scope)" % n if n else ""
                if n and d == 0.0:
                    suffix += "  <- no separate budget at this length; fold it in"
                out.append("  %-46s %5.1f%s" % (label, d, suffix))
            out.append("")
            out.append("  The unstructured row is not slack. It is the only time allocated")
            out.append("  to findings no control would have led you to, which is the part")
            out.append("  of the report that will differ from a competitor's.")
            out.append("")
            if any(n and d == 0.0 for _l, d, n in rows):
                out.append("  One or more in-scope categories received no separate budget.")
                out.append("  That is the plan telling you the engagement is shorter than")
                out.append("  the scope. Resolve it explicitly -- fold those categories into")
                out.append("  another workstream as declared triage, move them to EXCLUDED")
                out.append("  with a reason, or ask for more days. Do not leave it implicit;")
                out.append("  an unfunded category becomes a silent gap in the report.")
                out.append("")

    if p.warnings:
        out.append(rule)
        out.append("  WARNINGS (%d) -- unstated or suspicious profile fields" % len(p.warnings))
        out.append(rule)
        for w in p.warnings:
            for i, line in enumerate(wrap(w, width - 8, "")):
                out.append(("  - " if i == 0 else "    ") + line)
        out.append("")

    out.append(rule)
    out.append("  Nothing above is verified. Every decision is derived from assertions in")
    out.append("  the profile, which this script cannot check. A wrong profile produces a")
    out.append("  confidently wrong scope.")
    out.append("")
    out.append("  The generated exclusion reasons cite YOUR INPUT, not the client's")
    out.append("  situation. Rewrite each one in your own words before it reaches a client")
    out.append("  document, and record who agreed to it.")
    out.append("")
    out.append("  Severity, CVSS, the finding template and the engagement checklist belong")
    out.append("  to 80-Appendix. Backend coverage belongs to OWASP ASVS. Neither is here.")
    out.append(rule)
    return "\n".join(out)


def render_markdown(decisions, p, only_exclusions):
    out = []
    name = p.data.get("name") or p.data.get("app") or "unnamed app"
    out.append("# Scope -- %s" % name)
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append("| Profile | `%s` |" % p.path)
    out.append("| Package | `%s` |" % (p.data.get("app") or "unstated"))
    out.append("| Version | %s |" % (p.data.get("version") or "unstated"))
    out.append("| Standard version | %s |" % (p.data.get("standard_version") or
                                              "**UNSTATED -- record before delivery**"))
    out.append("")

    def table(title, state, show_change):
        rows = [d for d in decisions if d.state == state]
        out.append("## %s (%d)" % (title, len(rows)))
        out.append("")
        if not rows:
            out.append("None.")
            out.append("")
            return
        if show_change:
            out.append("| Control | Reason | Back in scope if |")
            out.append("|---|---|---|")
            for d in rows:
                out.append("| `%s` | %s | %s |" % (
                    d.cid, esc(d.reason), esc(d.change) or "--"))
        else:
            out.append("| Control | Priority | Reason |")
            out.append("|---|---|---|")
            for d in rows:
                out.append("| `%s` | %s | %s |" % (d.cid, d.priority, esc(d.reason)))
        out.append("")

    if not only_exclusions:
        table("In scope", "IN", False)
        table("Blocked -- a limitation, not a risk decision", "BLOCKED", True)
    table("Excluded -- deliberately not tested", "EXCLUDED", True)

    if not only_exclusions:
        days, rows = allocate_days(decisions, p)
        if days:
            out.append("## Suggested day allocation -- %d day(s)" % days)
            out.append("")
            out.append("| Workstream | Days |")
            out.append("|---|---|")
            for label, d, _n in rows:
                out.append("| %s | %.1f |" % (label, d))
            out.append("")

    if p.warnings:
        out.append("## Warnings")
        out.append("")
        for w in p.warnings:
            out.append("- %s" % esc(w))
        out.append("")

    out.append("---")
    out.append("")
    out.append("Every decision above is derived from assertions in the profile, which this "
               "script cannot verify. The generated exclusion reasons cite the input, not "
               "the client's situation -- rewrite each one in your own words and record who "
               "agreed to it before this reaches a client.")
    return "\n".join(out)


def esc(s):
    return " ".join(str(s).split()).replace("|", "\\|")


# ---------------------------------------------------------------------------
#  Catalogue loading
# ---------------------------------------------------------------------------

def load_controls(path):
    controls = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [x.strip() for x in line.split("|")]
            if len(parts) != 3:
                sys.stderr.write("[-] %s:%d: expected 'ID|CATEGORY|title'\n"
                                 % (path, lineno))
                return None
            controls.append((parts[0], parts[1].upper(), parts[2]))
    return controls


# ---------------------------------------------------------------------------
#  main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Turn an app profile into a scoped MASVS control set, with a written "
                    "justification for every exclusion.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Chapter 71 owns scoping, mapping and coverage. Severity, CVSS and report "
               "templates belong to 80-Appendix; testing technique belongs to the chapter "
               "that owns the mechanism.")
    ap.add_argument("profile", nargs="?", help="Path to a profile JSON. '-' for stdin.")
    ap.add_argument("--markdown", action="store_true", help="Emit Markdown.")
    ap.add_argument("--exclusions-only", action="store_true",
                    help="Only the exclusions table -- the one that gets argued about.")
    ap.add_argument("--controls", metavar="FILE",
                    help="Override the built-in catalogue. One 'ID|CATEGORY|title' per "
                         "line; '#' comments allowed.")
    ap.add_argument("--print-schema", action="store_true",
                    help="Print the profile schema and exit.")
    ap.add_argument("--width", type=int, default=92, help="Text output width.")
    args = ap.parse_args(argv)

    if args.print_schema:
        print(SCHEMA_TEXT)
        return 0

    if not args.profile:
        ap.print_help()
        sys.stderr.write("\n[-] no profile given. Try --print-schema.\n")
        return 2

    if args.profile == "-":
        raw, shown = sys.stdin.read(), "<stdin>"
    else:
        if not os.path.isfile(args.profile):
            sys.stderr.write("[-] no such file: %s\n" % args.profile)
            return 2
        with open(args.profile, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        shown = args.profile

    try:
        data = json.loads(raw)
    except ValueError as exc:
        sys.stderr.write("[-] profile is not valid JSON: %s\n" % exc)
        sys.stderr.write("    JSON has no comments and booleans are unquoted "
                         "true/false. See --print-schema.\n")
        return 2

    if not isinstance(data, dict):
        sys.stderr.write("[-] profile must be a JSON object\n")
        return 2

    controls = DEFAULT_CONTROLS
    if args.controls:
        controls = load_controls(args.controls)
        if controls is None:
            return 2
        if not controls:
            sys.stderr.write("[-] control catalogue is empty: %s\n" % args.controls)
            return 2

    p = Profile(data, shown)
    decisions = [decide(cid, cat, title, p) for cid, cat, title in controls]

    if args.markdown:
        print(render_markdown(decisions, p, args.exclusions_only))
    else:
        print(render_text(decisions, p, args.width, args.exclusions_only))
    return 0


if __name__ == "__main__":
    sys.exit(main())
