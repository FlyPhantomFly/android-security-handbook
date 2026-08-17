#!/usr/bin/env python3
"""
static-sweep.py — run chapter 52's grep catalogue over a decompiled tree and
                  emit RANKED LEADS, each with a confidence and a next step.

WHAT IT DOES
    Walks a decompiled application tree (jadx `sources/`, apktool `smali/`, a
    plain source checkout, or all three at once), applies the rule catalogue
    from README section 8, and prints a queue of leads sorted by how likely
    each one is to be worth the next ten minutes of your life.

    Three things make this different from `grep -r password .`, and they are
    the whole reason the script exists:

      1. IT AGGREGATES.  A hit is one line in one file. A LEAD is one distinct
         value or construct, with every site it appears at attached. On a real
         app the ratio is brutal: chapter 33's leak hunter turned 3,370 raw
         hits into 1,426 distinct values, and 132 of those were "high
         confidence" and every single one was wrong. Listing hits produces a
         report nobody reads. Listing leads produces a queue you can work.

      2. IT SCORES, AND SAYS WHY.  Every lead carries a confidence between
         0.05 and 0.95 and a printed list of the factors that produced it --
         which rule fired, whether the file is in the app's own package or in
         androidx, how many distinct files share the value. You can disagree
         with the number because you can see the arithmetic.

      3. IT NEVER RETURNS A VERDICT.  There is no severity column, no
         "VULNERABLE", no red text. Confidence answers "is this worth
         investigating", which is a property of the lead. Severity answers
         "how bad is this", which is a property of the finding, and no tool
         reading files on a disk can know it -- see README section 11.2.
         Every lead therefore ends in a NEXT STEP: a command to run, usually
         ./validate-lead.sh, that will either confirm the lead or kill it.

    It also prints a BLIND SPOTS section, which is the part people skip and
    should not. Static analysis cannot see runtime-registered receivers (69%
    of the broadcast surface on a real device -- chapter 29 measured it),
    RegisterNatives bindings, reflective dispatch, dynamically loaded DEX, or
    anything the server decides. When this script sees the fingerprints of
    those mechanisms it says so, because "the sweep was clean" and "the app is
    clean" are different statements and the gap between them is where reports
    go wrong.

WHAT THIS WILL *NOT* TELL YOU
    - Whether anything here is a vulnerability. Every line of output is a
      LEAD. A string in a DEX is not a finding; reachability decides, and
      reachability is what ./validate-lead.sh goes and gets.
    - Whether a lead is reachable. This script does no call-graph work at all.
      That is deliberate: reachability needs the whole tree in memory and a
      different tool. Run ./validate-lead.sh --reach for the approximate
      caller closure, and read its caveats before you quote it.
    - Anything about code that is not in the tree you pointed it at. If the
      app decrypts a DEX at runtime, the interesting code was never in the
      files this script read. Section BLIND SPOTS will usually notice; it
      cannot notice everything.
    - Anything about the manifest's semantics. Exported components, custom
      permissions, protection levels, deep links: chapter 32 owns those and
      ships manifest-audit.py. This script only reads the manifest to learn
      the app's own package name and its declared entry points, so that it
      can tell app code from library code and label its own blind spots.
    - Which library a class belongs to, or what version it is. Chapter 17
      owns that and ships lib-inventory.sh and lib-fingerprint.py.
    - What a deobfuscated name would have been. Chapter 40 owns that.
    - Anything at all about native code beyond noticing that it exists. The
      catalogue is text rules over text files; a .so is neither.

HOW TO RUN
    # host -- the normal case: point it at a jadx output directory
    python3 -B static-sweep.py ./out

    # a jadx tree and an apktool tree together (they see different things)
    python3 -B static-sweep.py ./jadx-out ./apktool-out

    # tell it which package is the app's own, if there is no manifest in the
    # tree. Without this everything scores as third-party and you will miss
    # the app's own code.
    python3 -B static-sweep.py ./out --app-package com.example.target

    # only leads worth looking at first
    python3 -B static-sweep.py ./out --min-confidence 0.5

    # only the app's own code -- the highest-yield first pass on a big app.
    # --files app skips library files before reading them (fast); --scope app
    # reads everything and then reports only leads with a site in app code.
    python3 -B static-sweep.py ./out --files app
    python3 -B static-sweep.py ./out --scope app

    # machine-readable, for the findings ledger in ../examples/
    python3 -B static-sweep.py ./out --csv leads.csv
    python3 -B static-sweep.py ./out --json leads.json

    # what did it decide NOT to show me, and why?
    python3 -B static-sweep.py ./out --show-suppressed

    # just the catalogue, so you can run the greps by hand
    python3 -B static-sweep.py --print-catalogue

    Use `python3 -B`. Without -B, Python may leave a __pycache__ directory
    next to this script, which is a build artefact this repository refuses to
    carry. Setting PYTHONDONTWRITEBYTECODE in the environment is not always
    enough -- a module loaded through importlib writes bytecode regardless --
    so pass -B on the command line.

REQUIREMENTS
    Python 3.8 or newer. Standard library only. Works on Windows, macOS and
    Linux -- the tree it reads was produced by jadx or apktool, which run
    everywhere, and nothing here shells out to grep.

    Measured runtime on the machine this was written on: about 1 minute over a
    3,655-file tree, about 6 minutes over a 20,091-file one. Roughly forty
    regular expressions are applied to every line of every file, and that is
    the cost. Use --files app on a large tree for the first pass.

RELATED
    ../README.md section 3            the pipeline this automates, stage by stage
    ../README.md section 8           the rule catalogue in prose, with the
                                      equivalent grep for every rule
    ../README.md section 11.2        why there is no severity column
    ./validate-lead.sh                stage 7: confirm or kill one lead
    ../examples/triage-worksheet.md   what a worked queue looks like
    ../examples/findings-ledger.csv   what a worked queue looks like when most
                                      of it was rejected, with the reasons
    ../labs/lab-02-false-positive-gauntlet.md
                                      the lab that runs this against a tree
                                      where most leads are wrong
    ../../32-Manifest/scripts/        manifest auditing -- not this script's job
    ../../17-Libraries/scripts/lib-inventory.sh
                                      dependency inventory -- also not this
                                      script's job
    ../../04-Java/scripts/dump-strings.py
                                      the DEX string table, when you have no
                                      decompiled tree at all

AUTHORISED TESTING ONLY. Only run this against applications you have written
permission to test.
"""

import argparse
import base64
import binascii
import csv
import json
import os
import re
import sys
from collections import defaultdict

VERSION = "1.0"

# ---------------------------------------------------------------------------
# Package classification
#
# The single most important input to the confidence score is "is this the
# app's own code, or is it a library?". A password-shaped string in
# androidx.appcompat is the framework; the same string in the app's own
# package is a lead. On a trivial 2,800-class test app the word "password"
# appeared 137 times and 136 of those were library code -- see README 3.4.
# ---------------------------------------------------------------------------

THIRD_PARTY_PREFIXES = (
    "android/", "androidx/", "com/android/", "com/google/android/material/",
    "com/google/android/gms/", "com/google/android/play/", "com/google/common/",
    "com/google/gson/", "com/google/protobuf/", "com/google/errorprone/",
    "kotlin/", "kotlinx/", "java/", "javax/", "sun/", "org/jetbrains/",
    "org/intellij/", "okhttp3/", "okio/", "retrofit2/", "io/reactivex/",
    "rx/", "org/apache/", "org/json/", "org/w3c/", "org/xml/", "org/xmlpull/",
    "com/squareup/", "com/bumptech/glide/", "coil/", "coil3/",
    "com/facebook/drawee/", "com/facebook/imagepipeline/", "com/facebook/soloader/",
    "com/fasterxml/", "org/bouncycastle/", "org/spongycastle/",
    "com/google/firebase/", "com/google/crypto/", "com/google/mlkit/",
    "io/grpc/", "io/sentry/", "com/bugsnag/", "dagger/", "javax/inject/",
    "butterknife/", "timber/", "org/slf4j/", "org/koin/", "io/ktor/",
)

# Generated code. Real, in the app's own package, and almost never interesting:
# R.java is thousands of resource identifiers, BuildConfig is three constants,
# *Binding is view binding boilerplate.
GENERATED_BASENAMES = ("R.java", "R.smali", "BuildConfig.java", "BuildConfig.smali")
GENERATED_PATTERNS = (
    re.compile(r"(^|/)R\$[A-Za-z0-9_]+\.(java|smali)$"),
    re.compile(r"(^|/)[A-Za-z0-9_]+Binding\.(java|smali)$"),
    re.compile(r"(^|/)[A-Za-z0-9_]+_(Factory|MembersInjector|Impl)\.(java|smali)$"),
)

SCOPE_APP = "app"
SCOPE_THIRD_PARTY = "third-party"
SCOPE_GENERATED = "generated"
SCOPE_RESOURCE = "resource"
SCOPE_UNKNOWN = "unknown"

SOURCE_EXTENSIONS = (".java", ".kt", ".smali", ".js", ".json", ".xml",
                     ".properties", ".txt", ".cfg", ".yml", ".yaml", ".gradle")

# Files that are large, generated, and produce nothing but noise.
SKIP_BASENAMES = ("public.xml", "ids.xml", "R.txt", "DebugProbesKt.bin")

MAX_FILE_BYTES = 4 * 1024 * 1024   # a 4 MB "source file" is generated data
MAX_LINE_CHARS = 4000              # one-line minified JS, mostly

# ---------------------------------------------------------------------------
# Known-noise values
#
# Strings that appear in essentially every APK and are never the finding. They
# are not deleted -- they are demoted and counted, and --show-suppressed
# prints them. A filter you cannot inspect is a filter that will one day eat
# your finding and never tell you.
# ---------------------------------------------------------------------------

NOISE_SUBSTRINGS = (
    "schemas.android.com", "www.w3.org", "xmlpull.org", "java.sun.com",
    "xml.org/sax", "apache.org/xml", "docs.oracle.com", "kotlinlang.org",
    "developer.android.com", "source.android.com", "goo.gl/",
    "github.com/square/", "github.com/JetBrains/", "github.com/google/",
    "www.apache.org/licenses", "creativecommons.org", "opensource.org/licenses",
    "127.0.0.1", "0.0.0.0", "255.255.255.255", "localhost",
    "android.intent.action", "android.permission.",
)

# Values whose SHAPE matches a credential rule but whose CONTENT is a
# well-known constant. Each entry is a compiled pattern plus the reason, and
# the reason is printed, because "suppressed" with no explanation is how a
# scanner earns distrust.
NOISE_VALUE_RULES = [
    (re.compile(r"^(true|false|null|none|default|unknown|test|example)$", re.I),
     "a literal placeholder word, not a value"),
    (re.compile(r"^[0-9a-f]{32}$", re.I),
     "32 hex characters is also an MD5 of something public; corroborate before "
     "calling it a key"),
    (re.compile(r"^(AAAA|////|MMMM|0000|1111){2,}"),
     "a padding or format-string constant"),
    (re.compile(r"^(android|androidx|kotlin|java|javax)[./]"),
     "a package or class name that happens to match a shape rule"),
]

# ---------------------------------------------------------------------------
# The rule catalogue
#
# Each rule is:
#   id          short stable identifier -- used in the ledger, so do not
#               renumber existing rules; append new ones
#   category    grouping for the report
#   precision   how much a bare match is worth before any modifier:
#                 format   0.75  an unambiguous format (PEM header, AKIA...)
#                 api      0.55  a specific API call with a specific argument
#                 shape    0.30  looks like a secret (base64, long hex)
#                 keyword  0.15  mentions a word associated with secrets
#               These are judgements, not measurements, and the README says so.
#   pattern     compiled regex, applied per line
#   value_group which capture group is the LEAD's identity (0 = whole match)
#   what        one line: what matched
#   next_step   what to do about it. Every rule has one. A rule with no next
#               step is a rule that should not be in the catalogue.
#   blind       True if a match means static analysis is about to lose sight
#               of something, rather than meaning there is a lead
# ---------------------------------------------------------------------------


class Rule(object):
    def __init__(self, rid, category, precision, pattern, what, next_step,
                 value_group=0, blind=False, grep=None, collapse=False,
                 validator=None):
        # validator: optional callable(value) -> True to keep, False to drop.
        # A regex says "this has the right shape". A validator says "and it is
        # not the thousand things that share that shape". Without one, the
        # base64 rule reports every camelCase identifier over 32 characters
        # long -- measured: 91 spurious leads on a 2,800-class test app.
        self.validator = validator
        self.id = rid
        self.category = category
        self.precision = precision
        self.pattern = pattern
        self.what = what
        self.next_step = next_step
        self.value_group = value_group
        self.blind = blind
        self.grep = grep or ""
        # collapse=True means "the identity of this lead is the CONSTRUCT, not
        # the matched text". Forty calls to Log.d are one lead with forty
        # sites, not forty leads. Value-shaped rules (a key, a URL, a base64
        # blob) collapse by value instead, because there the text IS the lead.
        self.collapse = collapse


PRECISION = {"format": 0.75, "api": 0.55, "shape": 0.30, "keyword": 0.15}


def _r(rid, category, precision, regex, what, next_step, value_group=0,
       blind=False, flags=0, grep=None, collapse=False, validator=None):
    return Rule(rid, category, PRECISION[precision], re.compile(regex, flags),
                what, next_step, value_group, blind, grep, collapse, validator)


# --- validators -------------------------------------------------------------

_RE_IDENTIFIER = re.compile(r"^[A-Za-z]+$")
_RE_CAMEL_PATH = re.compile(r"^[A-Za-z][A-Za-z0-9]*([./_][A-Za-z][A-Za-z0-9]*)+$")
_JAVA_PACKAGE_HEADS = ("kotlin.", "kotlinx.", "java.", "javax.", "android.",
                       "androidx.", "com.google.", "org.jetbrains.", "sun.",
                       "org.apache.", "com.android.")


def v_base64ish(value):
    """
    A base64 blob has character variety AND decodes. `actionModeCloseContent
    Description` is 33 characters of pure letters and is a resource name, not
    a secret; without this check it was reported as a credential lead.

    Rejecting a candidate here is cheap and reversible: run the rule's own
    grep by hand if you suspect the filter ate something.
    """
    if _RE_IDENTIFIER.match(value):
        return False
    # A JVM internal class descriptor -- kotlin/collections/CollectionsKt -- is
    # 32 legal base64 characters and decodes without error. It is not a secret.
    if re.match(r"^[A-Za-z0-9$_]+(/[A-Za-z0-9$_]+)+$", value):
        return False
    if not re.search(r"[0-9+/=]", value):
        return False
    if len(value) % 4 != 0 or len(value) < 20:
        return False
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(raw) < 12:
        return False
    printable = sum(1 for b in raw if 0x20 <= b < 0x7F or b in (9, 10, 13))
    if printable / float(len(raw)) >= 0.85:
        return True            # decodes to text: you have already won
    return len(raw) in (16, 24, 32, 48, 64) or len(raw) >= 32


COMMON_TLDS = frozenset("""
com net org io co uk de fr in us ai app dev cloud xyz me tv info biz eu jp cn
au ca nl es it ru br site online tech store link live gov edu mil sh to gg
""".split())


def v_hostname(value):
    """
    Reject Java package names. `kotlin.jvm.internal.Intrinsics`,
    `androidx.core.internal.view.menu` and `Debug.common.kt` all match a
    naive "contains internal./debug." hostname rule and none of them is a
    hostname -- measured: 75 spurious leads before this existed.

    Two tests, both cheap: the last label must be a plausible TLD, and no
    label may start with a capital.
    """
    lowered = value.lower()
    for head in _JAVA_PACKAGE_HEADS:
        if head in lowered:
            return False
    if re.search(r"(^|\.)[A-Z]", value):
        return False           # a capitalised label is a class name
    labels = lowered.rstrip(".").split(".")
    if len(labels) < 3:
        return False
    return labels[-1] in COMMON_TLDS


def v_hex_not_uuid(value):
    """A 40+ character hex run that is all one repeated nibble is padding."""
    return len(set(value.lower())) > 4


CATALOGUE = [

    # -- Credentials ------------------------------------------------------
    _r("CRED-01", "credential", "format",
       r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
       "PEM private key header in a shipped file",
       "Read the whole block. If it is a real key, the private half of a key "
       "pair is in the hands of everyone who downloaded the app. Establish "
       "what it signs or decrypts before writing severity.",
       grep=r"grep -rn -- '-----BEGIN' ."),

    _r("CRED-02", "credential", "format",
       r"\bAKIA[0-9A-Z]{16}\b",
       "AWS access key id format",
       "An AKIA id is only half a credential. Find the matching secret access "
       "key in the same class or resource; without it the id alone is a "
       "Low. ./validate-lead.sh --value <id> --near secret",
       grep=r"grep -rnE 'AKIA[0-9A-Z]{16}' ."),

    _r("CRED-03", "credential", "format",
       r"\bAIza[0-9A-Za-z_\-]{35}\b",
       "Google API key format",
       "Google API keys are DESIGNED to ship in clients. The finding is never "
       "'a key was found'; it is 'the key has no application restriction and "
       "an over-broad API scope'. Check restrictions with the client before "
       "reporting. This is the single most over-reported Android finding.",
       grep=r"grep -rnE 'AIza[0-9A-Za-z_-]{35}' ."),

    _r("CRED-04", "credential", "format",
       r"\b[sr]k_(live|test)_[0-9A-Za-z]{10,}\b",
       "Stripe key format",
       "sk_live_ is a secret key and must never be in a client: that is a "
       "finding on sight. pk_ and sk_test_ are not. Read the prefix before "
       "you read anything else.",
       grep=r"grep -rnE '[sr]k_(live|test)_' ."),

    _r("CRED-05", "credential", "format",
       r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*",
       "JWT-shaped token literal",
       "Base64url-decode the payload. Check `exp`, `iss` and scope. An expired "
       "test token is Informational; a long-lived service token is not. Also "
       "check whether it is a token at all -- signed JSON blobs used for "
       "integrity have the same shape and are usually correct behaviour.",
       grep=r"grep -rnE 'eyJ[A-Za-z0-9_-]+\\.' ."),

    _r("CRED-06", "credential", "format",
       r"\b(gh[pousr]_[0-9A-Za-z]{20,}|xox[abprs]-[0-9A-Za-z\-]{10,})\b",
       "GitHub or Slack token format",
       "Unambiguous vendor formats. Confirm the token is live only with "
       "written client permission -- using a credential you found is a "
       "different authorisation than reading one.",
       grep=r"grep -rnE 'gh[pousr]_|xox[abprs]-' ."),

    _r("CRED-07", "credential", "keyword",
       r"(?i)\b(api[_\-]?key|apikey|client[_\-]?secret|consumer[_\-]?secret|"
       r"access[_\-]?key|private[_\-]?key|x-api-key)\b",
       "names a key",
       "A NAME is not a VALUE. Open the site and answer one question: is the "
       "value next to the name, or is the name a lookup into something "
       "fetched at runtime? Most of these are the second. "
       "./validate-lead.sh --file <f> --line <n>",
       grep=r"grep -rnEi 'api[_-]?key|client[_-]?secret' ."),

    _r("CRED-08", "credential", "keyword",
       r"(?i)(password|passwd|passphrase|\bpwd\b)\s*=\s*[\"'][^\"']{3,}[\"']",
       "password-like name assigned a string literal",
       "Read the literal. Field names, log messages, JSON keys and resource "
       "identifiers all match a bare 'password' grep; an ASSIGNMENT to a "
       "literal is the narrower form and is worth opening.",
       grep=r"grep -rnEi 'password\\s*=\\s*\"' ."),

    _r("CRED-09", "credential", "shape",
       r"[\"']([A-Za-z0-9+/=]{20,})[\"']",
       "long base64-looking literal",
       "Decode it. If it decodes to readable text the obfuscation is already "
       "defeated and you know what it is. If it decodes to bytes, note the "
       "length -- 16 or 32 bytes next to a Cipher call is a key, and that is "
       "a different finding. Encoding is not encryption.",
       value_group=1, validator=v_base64ish,
       grep=r"grep -rnoE '\"[A-Za-z0-9+/]{32,}={0,2}\"' ."),

    _r("CRED-10", "credential", "shape",
       r"[\"']([0-9a-fA-F]{40,})[\"']",
       "long hex literal",
       "40 hex characters is a SHA-1, 64 is a SHA-256, and both are far more "
       "often a checksum, a certificate fingerprint or a resource digest than "
       "a key. Look at what is done with it before anything else.",
       value_group=1, validator=v_hex_not_uuid,
       grep=r"grep -rnoE '\"[0-9a-fA-F]{40,}\"' ."),

    # -- Endpoints --------------------------------------------------------
    _r("NET-01", "endpoint", "format",
       r"\bhttp://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}",
       "cleartext http:// URL",
       "Cleartext is only a finding if it is used. Check whether the host is "
       "reachable, whether cleartextTrafficPermitted allows it (chapter 44), "
       "and whether the string is a namespace URI rather than an endpoint -- "
       "http://schemas.android.com is in every APK ever built.",
       grep=r"grep -rnoE 'http://[^\"]+' ."),

    _r("NET-02", "endpoint", "shape",
       r"\bhttps://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}",
       "https:// URL",
       "Inventory, not a finding. Sort the hosts, group them by vendor, and "
       "look for the ones that are not the app's own backend and not a known "
       "SDK. Staging, admin and internal hostnames are the interesting rows.",
       grep=r"grep -rnoE 'https://[^\"]+' ."),

    _r("NET-03", "endpoint", "shape",
       r"[\"'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?[\"']",
       "hardcoded IP address literal",
       "10.0.2.2 is the emulator's view of the host machine and means debug "
       "configuration shipped to production. A private RFC1918 address means "
       "an internal service the app expects to reach. A public address means "
       "DNS was skipped, and certificate validation often was too.",
       value_group=1,
       grep=r"grep -rnoE '\"([0-9]{1,3}\\.){3}[0-9]{1,3}\"' ."),

    _r("NET-04", "endpoint", "keyword",
       r"(?i)\b(staging|preprod|pre-prod|uat|sandbox|\.dev\.|internal|"
       r"debug)\.[a-z0-9-]+\.[a-z]{2,}",
       "non-production hostname",
       "A staging host in a production build is a real finding when the host "
       "is reachable and weaker than production. Resolve it and say so; do "
       "not report a string.",
       validator=v_hostname,
       grep=r"grep -rnEi '(staging|uat|sandbox|internal)\\.[a-z0-9-]+\\.' ."),

    # -- Cryptography (chapter 34 owns the analysis; this only finds it) ---
    _r("CRY-01", "crypto", "api",
       r"getInstance\s*\(\s*[\"'][A-Za-z0-9]+/ECB/",
       "Cipher configured with ECB mode",
       "ECB leaks plaintext structure. Confirm what is encrypted with it: ECB "
       "over a 12-byte device id is Informational, ECB over a session token "
       "is not. Chapter 34 section 5 has the severity reasoning.",
       collapse=True, grep=r"grep -rn 'ECB' ."),

    _r("CRY-02", "crypto", "api",
       r"new\s+(IvParameterSpec|GCMParameterSpec)\s*\(\s*[\"']|"
       r"IvParameterSpec\s*\(\s*[a-zA-Z_]+\.getBytes",
       "IV constructed from a literal or a fixed string",
       "A fixed IV with CBC leaks equality of first blocks; with GCM it is "
       "catastrophic and breaks the key. Establish the mode before rating. "
       "Then check the IV really is fixed and not a field assigned elsewhere.",
       collapse=True, grep=r"grep -rn 'IvParameterSpec' ."),

    _r("CRY-03", "crypto", "api",
       r"SecureRandom\s*\([^)]+\)|\.setSeed\s*\(",
       "SecureRandom seeded explicitly",
       "Seeding SecureRandom with a constant makes it deterministic. Seeding "
       "with time is nearly as bad. Read the argument; a seed from another "
       "SecureRandom is fine and common.",
       collapse=True, grep=r"grep -rn 'setSeed' ."),

    _r("CRY-04", "crypto", "api",
       r"MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA-?1)[\"']",
       "MD5 or SHA-1 in use",
       "Both are fine for non-security uses -- cache keys, ETags, file "
       "dedupe -- and are still everywhere for exactly that reason. The "
       "finding requires showing it is used for integrity or authentication.",
       collapse=True, grep=r"grep -rnE 'getInstance\\(\"(MD5|SHA-?1)\"\\)' ."),

    _r("CRY-05", "crypto", "api",
       r"PBEKeySpec\s*\([^)]*,\s*(\d{1,4})\s*[,)]",
       "PBKDF2 iteration count below five digits",
       "Read the literal. Under 10,000 iterations is weak by any modern "
       "guidance and under 1,000 is a finding. Confirm the number is the "
       "iteration argument and not the key length.",
       collapse=True, grep=r"grep -rn 'PBEKeySpec' ."),

    # -- TLS trust (chapters 35, 36 and 44 own the analysis) --------------
    _r("TLS-01", "tls", "api",
       r"(implements|extends)\s+(X509TrustManager|X509ExtendedTrustManager)|"
       r"checkServerTrusted\s*\(",
       "custom TrustManager",
       "A custom TrustManager is not automatically wrong -- pinning is "
       "implemented this way. Read checkServerTrusted: an EMPTY body accepts "
       "every certificate. Chapter 36 measured 12 of 14 real apps presenting "
       "a pinning surface while only 4 actually pinned, so the presence of "
       "the class proves nothing in either direction.",
       collapse=True, grep=r"grep -rn 'checkServerTrusted' ."),

    _r("TLS-02", "tls", "api",
       r"ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier|"
       r"HostnameVerifier\s*\(\s*\)\s*\{",
       "custom or permissive HostnameVerifier",
       "Read the verify() body. `return true` accepts a certificate for any "
       "host and defeats TLS as thoroughly as accepting any certificate. "
       "Anything else needs reading before you judge it.",
       collapse=True, grep=r"grep -rn 'HostnameVerifier' ."),

    _r("TLS-03", "tls", "api",
       r"onReceivedSslError\s*\(",
       "WebView SSL error handler",
       "The finding is a call to handler.proceed() inside it. handler.cancel() "
       "is correct behaviour. Open the method -- this rule cannot tell them "
       "apart and will not pretend to. Chapter 43 owns WebView.",
       collapse=True, grep=r"grep -rn 'onReceivedSslError' ."),

    _r("TLS-04", "tls", "api",
       r"certificatePinner|CertificatePinner\.Builder|network_security_config|"
       r"pin-set",
       "pinning surface present",
       "Presence of a pinner is not pinning. Find the actual pin VALUES: a "
       "CertificatePinner.Builder with no .add() call pins nothing. This is "
       "exactly the 12-versus-4 gap chapter 36 measured.",
       collapse=True, grep=r"grep -rn 'CertificatePinner' ."),

    # -- Storage (chapter 33 owns the analysis) ---------------------------
    _r("STO-01", "storage", "api",
       r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|MODE_WORLD_WRITABLE",
       "world-accessible file mode constant",
       "These constants throw SecurityException from API 24 onward, so on a "
       "modern target this is dead code that reads as a critical finding. "
       "Check minSdk before you write anything.",
       collapse=True, grep=r"grep -rn 'MODE_WORLD' ."),

    _r("STO-02", "storage", "api",
       r"getExternalStorage(Directory|PublicDirectory)|"
       r"Environment\.getExternalStorage",
       "legacy external storage path",
       "External storage is world-visible to any app holding READ_EXTERNAL "
       "on old targets, and scoped on new ones. What matters is WHAT is "
       "written there. Follow the stream, not the path.",
       collapse=True, grep=r"grep -rn 'getExternalStorage' ."),

    _r("STO-03", "storage", "keyword",
       r"(?i)putString\s*\(\s*[\"'][^\"']*(token|password|secret|key|pin|"
       r"session|auth)[^\"']*[\"']",
       "sensitive-looking key written to SharedPreferences",
       "SharedPreferences is private storage; writing a token there is normal "
       "and correct for most apps. The finding requires something more: "
       "allowBackup=true (chapter 32), a rooted-device threat model the "
       "client accepts, or the value also leaving the device.",
       grep=r"grep -rnEi 'putString\\(\"[^\"]*(token|password)' ."),

    _r("STO-04", "storage", "api",
       r"\.setJavaScriptEnabled\s*\(\s*true\s*\)|addJavascriptInterface\s*\(",
       "WebView JavaScript bridge",
       "addJavascriptInterface exposes annotated Java methods to page script. "
       "The finding needs the loaded URL to be attacker-influenced. Find "
       "every loadUrl and loadData call in the same class first. Chapter 43.",
       collapse=True, grep=r"grep -rn 'addJavascriptInterface' ."),

    # -- Logging and debug ------------------------------------------------
    _r("DBG-01", "debug", "api",
       r"android:debuggable\s*=\s*[\"']true[\"']|"
       r"<application[^>]*debuggable",
       "debuggable flag in a manifest",
       "android:debuggable=\"true\" in a shipped build lets any user with adb "
       "attach a debugger to the process and read its memory. Confirm the "
       "manifest came from the SHIPPED artefact and not from a debug build "
       "you compiled yourself -- that mistake has been published more than "
       "once. Then check `dumpsys package <pkg> | grep flags` on the device.",
       grep=r"grep -rn 'debuggable' AndroidManifest.xml"),

    _r("DBG-02", "debug", "shape",
       r"Log\.(d|v|i)\s*\(\s*[^,]+,\s*[^\"')]+\s*[,)]",
       "log call whose message is a variable",
       "A logged variable might be a token. On API 26 and above ordinary apps "
       "cannot read another app's logcat, which caps severity hard -- but "
       "anyone with adb can, and so can anything with READ_LOGS. Confirm "
       "what the variable holds at runtime; this is a dynamic question.",
       collapse=True, grep=r"grep -rn 'Log\\.d(' ."),

    _r("DBG-03", "debug", "keyword",
       r"(?i)\b(TODO|FIXME|HACK|XXX)\b[: ].{0,80}",
       "developer note left in shipped code",
       "Never a finding on its own. Occasionally it names the thing you were "
       "about to spend two hours finding. Read them, quote none.",
       collapse=True, grep=r"grep -rnE 'TODO|FIXME' ."),

    _r("DBG-04", "debug", "keyword",
       r"printStackTrace\s*\(\s*\)",
       "stack trace printed",
       "Noise in almost every app. Worth a line in the report only when the "
       "trace reaches a user-visible surface or a remote crash reporter that "
       "the client has not accounted for.",
       collapse=True, grep=r"grep -rn 'printStackTrace' ."),

    # -- Blind spots: static analysis is about to stop working ------------
    _r("BLIND-01", "blindspot", "api",
       r"\bregisterReceiver\s*\(",
       "receiver registered at runtime",
       "Chapter 29 parsed a live device: 299 of 431 distinct broadcast actions "
       "registered by third-party processes had NO manifest-declared receiver "
       "anywhere -- 69% of the surface. Every APK-based tool, including this "
       "one, is blind to it. Enumerate the live table with "
       "`dumpsys activity broadcasts` while the app runs.",
       blind=True, collapse=True,
       grep=r"grep -rn 'registerReceiver' ."),

    _r("BLIND-02", "blindspot", "api",
       r"Class\.forName\s*\(|getDeclaredMethod\s*\(|getMethod\s*\(\s*[\"']|"
       r"\.invoke\s*\(",
       "reflective dispatch",
       "A reflective call has no static edge. Your call graph, your IDE's "
       "'find usages', and every reachability claim you make stop here. Hook "
       "Method.invoke at runtime and log the target, or read the string "
       "arguments if they are literals.",
       blind=True, collapse=True,
       grep=r"grep -rnE 'Class\\.forName|getDeclaredMethod' ."),

    _r("BLIND-03", "blindspot", "api",
       r"DexClassLoader|InMemoryDexClassLoader|PathClassLoader|"
       r"DelegateLastClassLoader",
       "runtime DEX loading",
       "Code that is not in this tree will execute. Nothing you conclude "
       "about the app's behaviour is complete until you have dumped what "
       "gets loaded. Chapter 40 section 3.7.3 is the procedure.",
       blind=True, collapse=True,
       grep=r"grep -rn 'DexClassLoader' ."),

    _r("BLIND-04", "blindspot", "api",
       r"System\.loadLibrary\s*\(|System\.load\s*\(|\bnative\s+[a-zA-Z<]",
       "native code boundary",
       "Java_-prefixed exports are visible in the .so symbol table; anything "
       "bound with RegisterNatives in JNI_OnLoad is not, and that is the "
       "common case for anything deliberately hidden. A native method with no "
       "matching Java_ symbol is not missing -- it is registered. Chapter 16.",
       blind=True, collapse=True,
       grep=r"grep -rn 'loadLibrary' ."),

    _r("BLIND-05", "blindspot", "api",
       r"(?i)(remoteconfig|firebaseremoteconfig|featureflag|feature_flag|"
       r"\.getBoolean\s*\(\s*[\"'](enable|disable|is)_)",
       "server-controlled behaviour",
       "A flag the server sets can enable or disable a security control after "
       "you finish testing. You cannot see the server's answer in these "
       "files. Ask the client for the flag inventory and test both values.",
       blind=True, collapse=True,
       grep=r"grep -rni 'remoteconfig' ."),

    _r("BLIND-06", "blindspot", "shape",
       r"\bassets/[A-Za-z0-9_./-]+\.(dex|jar|apk|zip|so|bin|dat|enc)\b",
       "executable-looking payload in assets",
       "An encrypted DEX in assets plus a small class count is the packer "
       "signature. Run chapter 17's lib-inventory.sh section 04 and chapter "
       "40's unpacking procedure before trusting anything else in this report.",
       blind=True, collapse=True,
       grep=r"unzip -l app.apk | grep -E 'assets/.*\\.(dex|so|bin)'"),
]

CATALOGUE_BY_ID = dict((r.id, r) for r in CATALOGUE)


# ---------------------------------------------------------------------------
# File walking and classification
# ---------------------------------------------------------------------------

def normalise(path):
    return path.replace("\\", "/")


def classify_path(rel_path, app_prefixes):
    """
    Decide whether a file is the app's own code, a library, generated, or a
    resource. Returns one of the SCOPE_* constants.
    """
    p = normalise(rel_path)
    base = p.rsplit("/", 1)[-1]

    # Strip the container directory jadx and apktool add, so that
    # sources/androidx/... and smali/androidx/... both classify the same.
    for container in ("sources/", "smali/", "smali_classes2/", "smali_classes3/",
                      "smali_classes4/", "src/main/java/", "src/"):
        idx = p.find(container)
        if idx != -1:
            p = p[idx + len(container):]
            break

    if base in SKIP_BASENAMES:
        return SCOPE_RESOURCE
    if base in GENERATED_BASENAMES:
        return SCOPE_GENERATED
    for pat in GENERATED_PATTERNS:
        if pat.search(p):
            return SCOPE_GENERATED

    # Resources, carefully. `/res/` must not be matched anywhere in the path:
    # androidx/core/content/res/ResourcesCompat.java is code, and an earlier
    # version of this function called it a resource, which quietly changed
    # every score in the report. Anchor to the tree roots jadx and apktool
    # actually produce.
    raw = normalise(rel_path)
    if (raw.startswith("res/") or raw.startswith("resources/res/")
            or "/resources/res/" in raw or raw.startswith("assets/")
            or "/assets/" in raw):
        return SCOPE_RESOURCE
    if base == "AndroidManifest.xml":
        return SCOPE_APP

    for prefix in app_prefixes:
        if p.startswith(prefix):
            return SCOPE_APP
    for prefix in THIRD_PARTY_PREFIXES:
        if p.startswith(prefix):
            return SCOPE_THIRD_PARTY
    return SCOPE_UNKNOWN


def find_manifest(roots):
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            if "AndroidManifest.xml" in files:
                return os.path.join(dirpath, "AndroidManifest.xml")
    return None


def read_text(path, limit=MAX_FILE_BYTES):
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > limit:
        return None
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        return None
    return raw.decode("utf-8", "replace")


def app_package_from_manifest(manifest_path):
    """
    Read package="..." out of a decoded manifest. jadx and apktool both write
    a real XML file; a binary AndroidManifest.xml will not match and we return
    None rather than guessing.
    """
    text = read_text(manifest_path, limit=2 * 1024 * 1024)
    if not text:
        return None
    match = re.search(r'package\s*=\s*"([A-Za-z0-9_.]+)"', text)
    return match.group(1) if match else None


def entry_points_from_manifest(manifest_path, app_package):
    """
    Every android:name on a component element. These are the classes the
    PLATFORM can start, which is the only entry-point set that does not
    depend on a call graph. validate-lead.sh needs the same list.
    """
    text = read_text(manifest_path, limit=2 * 1024 * 1024)
    if not text:
        return []
    names = set()
    for match in re.finditer(
            r"<(activity|activity-alias|service|receiver|provider|application)\b[^>]*?"
            r'android:name\s*=\s*"([^"]+)"', text, re.S):
        name = match.group(2)
        if name.startswith("."):
            name = (app_package or "") + name
        names.add(name)
    return sorted(names)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

SCOPE_MODIFIER = {
    SCOPE_APP: (+0.25, "in the app's own package"),
    SCOPE_UNKNOWN: (+0.05, "package not recognised as a known library"),
    SCOPE_THIRD_PARTY: (-0.30, "in a third-party or framework package"),
    SCOPE_GENERATED: (-0.35, "in generated code (R, BuildConfig, bindings)"),
    SCOPE_RESOURCE: (-0.10, "in resources rather than code"),
}


def is_noise_value(value):
    for noise in NOISE_SUBSTRINGS:
        if noise in value:
            return "matches the known-constant list (%s)" % noise
    for pattern, reason in NOISE_VALUE_RULES:
        if pattern.search(value):
            return reason
    return None


class Lead(object):
    """One distinct value or construct, plus every site it was seen at."""

    def __init__(self, rule, value):
        self.rule = rule
        self.value = value
        self.sites = []            # (rel_path, lineno, scope, line_text)
        self.total_sites = 0       # counts past the printed-site cap
        self.app_sites = 0
        self.all_files = set()     # counts past the printed-site cap
        self.seen_scopes = set()
        self.confidence = 0.0
        self.factors = []
        self.suppressed_reason = None

    @property
    def scopes(self):
        return self.seen_scopes or set(site[2] for site in self.sites)

    @property
    def files(self):
        return self.all_files or set(site[0] for site in self.sites)

    def best_scope(self):
        for scope in (SCOPE_APP, SCOPE_UNKNOWN, SCOPE_RESOURCE,
                      SCOPE_THIRD_PARTY, SCOPE_GENERATED):
            if scope in self.scopes:
                return scope
        return SCOPE_UNKNOWN

    def score(self, corroboration):
        """
        Confidence is a product of judgement, not of measurement, and the
        factor list exists so that you can overrule it with your eyes.
        """
        base = self.rule.precision
        factors = [("rule %s precision" % self.rule.id, base)]
        value = base

        scope = self.best_scope()
        delta, why = SCOPE_MODIFIER[scope]
        value += delta
        factors.append((why, delta))

        n_files = len(self.files)
        if self.rule.collapse:
            # A construct rule aggregates every call site, so file count says
            # nothing about whether the lead is real -- it only says the app
            # is large. What matters is whether any site is in app code.
            if self.app_sites:
                value += 0.10
                factors.append(("%d of %d site(s) in app code"
                                % (self.app_sites, self.total_sites), +0.10))
            else:
                value -= 0.15
                factors.append(("no site in app code -- this is library "
                                "behaviour until proven otherwise", -0.15))
        elif n_files > 8:
            value -= 0.25
            factors.append(("value appears in %d distinct files -- that is a "
                            "shared constant, not a secret" % n_files, -0.25))
        elif n_files == 1 and scope == SCOPE_APP:
            value += 0.10
            factors.append(("single site, in app code", +0.10))

        noise = is_noise_value(self.value)
        if noise:
            value -= 0.45
            factors.append(("known-noise: %s" % noise, -0.45))
            self.suppressed_reason = noise

        if corroboration:
            value += 0.10
            factors.append(("corroborated: %s" % corroboration, +0.10))

        self.confidence = max(0.05, min(0.95, value))
        self.factors = factors
        return self.confidence


def confidence_band(value):
    if value >= 0.65:
        return "HIGH"
    if value >= 0.40:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------

class SweepResult(object):
    def __init__(self):
        self.files_scanned = 0
        self.files_skipped = 0
        self.files_filtered = 0
        self.bytes_scanned = 0
        self.raw_hits = 0
        self.rejected_by_validator = 0
        self.leads = {}            # (rule_id, value) -> Lead
        self.blind = {}            # rule_id -> Lead-like aggregate
        self.scope_counts = defaultdict(int)
        self.app_package = None
        self.entry_points = []
        self.manifest_path = None


def sweep(roots, app_prefixes, result, follow_resources=True,
          app_files_only=False):
    for root in roots:
        root = os.path.abspath(root)
        base = root if os.path.isdir(root) else os.path.dirname(root)
        walk_targets = [root] if os.path.isdir(root) else []
        if not walk_targets:
            _sweep_file(root, os.path.basename(root), app_prefixes, result,
                        app_files_only)
            continue
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
            for name in files:
                ext = os.path.splitext(name)[1].lower()
                if ext not in SOURCE_EXTENSIONS and name != "AndroidManifest.xml":
                    continue
                if not follow_resources and "/res/" in normalise(dirpath):
                    continue
                full = os.path.join(dirpath, name)
                rel = normalise(os.path.relpath(full, base))
                _sweep_file(full, rel, app_prefixes, result, app_files_only)


def _sweep_file(full, rel, app_prefixes, result, app_files_only=False):
    scope = classify_path(rel, app_prefixes)
    if app_files_only and scope in (SCOPE_THIRD_PARTY, SCOPE_GENERATED):
        result.files_filtered += 1
        return
    text = read_text(full)
    if text is None:
        result.files_skipped += 1
        return
    result.files_scanned += 1
    result.bytes_scanned += len(text)
    result.scope_counts[scope] += 1

    lines = text.split("\n")
    for lineno, line in enumerate(lines, 1):
        if len(line) > MAX_LINE_CHARS:
            line = line[:MAX_LINE_CHARS]
        for rule in CATALOGUE:
            for match in rule.pattern.finditer(line):
                result.raw_hits += 1
                try:
                    value = match.group(rule.value_group)
                except (IndexError, re.error):
                    value = match.group(0)
                if value is None:
                    value = match.group(0)
                value = value.strip()
                if not value:
                    continue
                if rule.validator is not None and not rule.validator(value):
                    result.rejected_by_validator += 1
                    continue
                if len(value) > 160:
                    value = value[:157] + "..."
                # A construct rule's identity is the construct. Forty Log.d
                # calls are one lead with forty sites, not forty leads.
                identity = ("<%s>" % rule.what) if rule.collapse else value
                key = (rule.id, identity)
                store = result.blind if rule.blind else result.leads
                lead = store.get(key)
                if lead is None:
                    lead = Lead(rule, identity)
                    store[key] = lead
                lead.total_sites += 1
                lead.all_files.add(rel)
                lead.seen_scopes.add(scope)
                if scope == SCOPE_APP:
                    lead.app_sites += 1
                if len(lead.sites) < 60:
                    lead.sites.append((rel, lineno, scope, line.strip()[:200]))


# ---------------------------------------------------------------------------
# Corroboration
#
# One extra pass, and it is the cheapest useful thing in the script: a
# credential-shaped value sitting in a file that also mentions a URL or a
# Cipher is more interesting than the same value alone. This is a weak signal
# and it is weighted like one (+0.10).
# ---------------------------------------------------------------------------

CORROBORATORS = [
    (re.compile(r"(?i)\b(cipher|keyspec|secretkey|encrypt|decrypt|sign)\b"),
     "the same file uses cryptography"),
    (re.compile(r"(?i)\b(https?://|retrofit|okhttp|urlconnection|@POST|@GET)\b"),
     "the same file makes network calls"),
    (re.compile(r"(?i)\b(authorization|bearer|x-api-key|setRequestProperty|"
                r"addHeader)\b"),
     "the same file sets request headers"),
]


def corroborate(result, roots):
    """For every lead, look at the first site's file for supporting context."""
    cache = {}
    for lead in result.leads.values():
        if not lead.sites:
            continue
        rel = lead.sites[0][0]
        if rel not in cache:
            cache[rel] = _load_by_rel(roots, rel)
        text = cache[rel]
        found = None
        # XML corroborates nothing: every manifest contains the schemas.android
        # .com namespace URI, which made an earlier version of this function
        # report "the same file makes network calls" for every manifest lead.
        if rel.lower().endswith((".xml", ".properties", ".txt")):
            text = None
        if text:
            for pattern, reason in CORROBORATORS:
                if pattern.search(text):
                    found = reason
                    break
        lead.score(found)
    for lead in result.blind.values():
        lead.score(None)


def _load_by_rel(roots, rel):
    for root in roots:
        base = root if os.path.isdir(root) else os.path.dirname(root)
        candidate = os.path.join(base, rel.replace("/", os.sep))
        if os.path.isfile(candidate):
            return read_text(candidate)
    return None


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def rule_line(char="-", width=78):
    return char * width


def lead_id(index):
    return "L%03d" % index


def print_report(result, args, out=sys.stdout):
    write = out.write

    leads = sorted(result.leads.values(),
                   key=lambda l: (-l.confidence, l.rule.id, l.value))
    shown = [l for l in leads if l.confidence >= args.min_confidence
             and not (l.suppressed_reason and not args.show_suppressed)]
    suppressed = [l for l in leads if l.suppressed_reason]

    write("\n%s\n" % rule_line("="))
    write(" static-sweep %s -- LEADS, NOT FINDINGS\n" % VERSION)
    write("%s\n" % rule_line("="))
    write("  trees scanned      %s\n" % ", ".join(args.paths))
    if result.app_package:
        write("  app package        %s\n" % result.app_package)
    else:
        write("  app package        NOT DETERMINED -- pass --app-package. "
              "Without it\n                     every file scores as "
              "third-party and app code is buried.\n")
    write("  files scanned      %d   (%d unreadable or over the size cap)\n"
          % (result.files_scanned, result.files_skipped))
    if result.files_filtered:
        write("  files filtered out %d   (--files app: classified as "
              "third-party\n                     or generated and never "
              "opened)\n" % result.files_filtered)
    for scope in (SCOPE_APP, SCOPE_THIRD_PARTY, SCOPE_GENERATED,
                  SCOPE_RESOURCE, SCOPE_UNKNOWN):
        if result.scope_counts.get(scope):
            write("      %-14s %d\n" % (scope, result.scope_counts[scope]))
    write("  raw hits           %d\n" % result.raw_hits)
    write("  killed by a rule's own validator  %d   (right shape, wrong "
          "thing:\n                     identifiers that look like base64, "
          "package names that\n                     look like hostnames)\n"
          % result.rejected_by_validator)
    write("  distinct leads     %d\n" % len(leads))
    write("  shown here         %d   (min-confidence %.2f)\n"
          % (len(shown), args.min_confidence))
    write("  demoted as noise   %d   (--show-suppressed to see them)\n"
          % len(suppressed))
    write("  blind-spot notices %d\n" % len(result.blind))

    if result.raw_hits and len(leads):
        write("\n  Aggregation ratio: %d raw hits collapsed to %d leads (%.1fx).\n"
              % (result.raw_hits, len(leads), result.raw_hits / float(len(leads))))
        write("  That ratio is the entire argument for not pasting grep output\n"
              "  into a report.\n")

    # -- the queue --------------------------------------------------------
    write("\n%s\n" % rule_line("="))
    write(" THE QUEUE -- work it top down\n")
    write("%s\n" % rule_line("="))

    if not shown:
        write("\n  Nothing above the confidence floor.\n\n")
        write("  That is a RESULT, not a clean bill of health. Read the blind\n"
              "  spots below before you write the words 'no issues found'.\n")

    counter = 0
    for lead in shown:
        counter += 1
        band = confidence_band(lead.confidence)
        write("\n%s\n" % rule_line("-"))
        write("%s  [%s %.2f]  %s  (%s)\n"
              % (lead_id(counter), band, lead.confidence, lead.rule.id,
                 lead.rule.category))
        write("  what      %s\n" % lead.rule.what)
        write("  value     %s\n" % lead.value)
        write("  sites     %d occurrence(s) in %d file(s); %d in app code\n"
              % (lead.total_sites, len(lead.files), lead.app_sites))
        # App-code sites first: on a large app the interesting site is often
        # the fortieth in walk order.
        ordered = sorted(lead.sites, key=lambda s: 0 if s[2] == SCOPE_APP else 1)
        for rel, lineno, scope, text in ordered[:args.max_sites]:
            write("            %s:%d  [%s]\n" % (rel, lineno, scope))
            if args.verbose:
                write("              | %s\n" % text)
        if lead.total_sites > args.max_sites:
            write("            ... and %d more\n"
                  % (lead.total_sites - args.max_sites))
        write("  score     ")
        write("; ".join("%s (%+.2f)" % (why, delta)
                        for why, delta in lead.factors) + "\n")
        write("  NEXT STEP %s\n" % _wrap(lead.rule.next_step, 12))
        if lead.suppressed_reason:
            write("  demoted   %s\n" % lead.suppressed_reason)

    # -- blind spots ------------------------------------------------------
    write("\n%s\n" % rule_line("="))
    write(" BLIND SPOTS -- what this sweep could not see\n")
    write("%s\n" % rule_line("="))
    write("\n  These are not leads. They are places where the file on disk\n"
          "  stops describing the running program, so a clean result above\n"
          "  does not extend past this point.\n")

    if not result.blind:
        write("\n  None of the blind-spot fingerprints appeared. That is\n"
              "  mildly reassuring and nothing more: an app can register a\n"
              "  receiver, reflect, or load code through paths this catalogue\n"
              "  does not match, and server-side behaviour leaves no trace in\n"
              "  an APK at all.\n")

    by_rule = defaultdict(list)
    for lead in result.blind.values():
        by_rule[lead.rule.id].append(lead)
    for rid in sorted(by_rule):
        group = by_rule[rid]
        rule = CATALOGUE_BY_ID[rid]
        n_sites = sum(l.total_sites for l in group)
        n_files = len(set(f for l in group for f in l.files))
        app_files = sorted(set(s[0] for l in group for s in l.sites
                               if s[2] == SCOPE_APP))
        write("\n  %s  %s\n" % (rid, rule.what))
        write("    %d occurrence(s) across %d file(s)" % (n_sites, n_files))
        if app_files:
            write("; %d in app code\n" % len(app_files))
            for f in app_files[:5]:
                write("      %s\n" % f)
        else:
            write("; none in app code\n")
        write("    %s\n" % _wrap(rule.next_step, 4))

    # -- suppressed -------------------------------------------------------
    if args.show_suppressed and suppressed:
        write("\n%s\n" % rule_line("="))
        write(" DEMOTED AS NOISE -- shown so you can audit the filter\n")
        write("%s\n" % rule_line("="))
        for lead in suppressed:
            write("  %-9s %-50s %s\n"
                  % (lead.rule.id, lead.value[:50], lead.suppressed_reason))

    # -- footer -----------------------------------------------------------
    write("\n%s\n" % rule_line("="))
    write(" Everything above is a LEAD.\n")
    write("%s\n" % rule_line("="))
    write("""
  A lead becomes a finding when you can answer all four:

    1. Is the construct really there?      (read the code, not the grep)
    2. Is it reachable?                    (./validate-lead.sh --reach)
    3. Who can reach it?                   (another app? the network? only
                                            the app itself?)
    4. What does reaching it get them?     (that answer is the severity)

  Chapter 33's leak hunter returned 132 high-confidence hits against a real
  browser install and all 132 were false positives. Chapter 36 found 12 of
  14 apps presenting a pinning surface and only 4 actually pinning. Assume
  you are in those numbers until you have done the work above.

  This script has no severity column and will not be given one.
""")


def _wrap(text, indent, width=76):
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width - indent:
            lines.append(current)
            current = word
        else:
            current = (current + " " + word).strip()
    if current:
        lines.append(current)
    pad = " " * indent
    return ("\n" + pad).join(lines)


def write_csv(result, path, args):
    leads = sorted(result.leads.values(),
                   key=lambda l: (-l.confidence, l.rule.id, l.value))
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["lead_id", "rule_id", "category", "confidence",
                         "band", "value", "n_sites", "n_files", "first_site",
                         "scope", "next_step", "verdict", "reason"])
        for index, lead in enumerate(leads, 1):
            if lead.confidence < args.min_confidence:
                continue
            first = lead.sites[0] if lead.sites else ("", 0, "", "")
            writer.writerow([
                lead_id(index), lead.rule.id, lead.rule.category,
                "%.2f" % lead.confidence, confidence_band(lead.confidence),
                lead.value, len(lead.sites), len(lead.files),
                "%s:%s" % (first[0], first[1]), lead.best_scope(),
                " ".join(lead.rule.next_step.split()),
                "", ""])   # verdict and reason are for the HUMAN to fill in


def write_json(result, path, args):
    leads = sorted(result.leads.values(),
                   key=lambda l: (-l.confidence, l.rule.id, l.value))
    payload = {
        "tool": "static-sweep",
        "version": VERSION,
        "app_package": result.app_package,
        "files_scanned": result.files_scanned,
        "raw_hits": result.raw_hits,
        "distinct_leads": len(leads),
        "leads": [],
        "blind_spots": [],
        "disclaimer": "Every entry is a LEAD, not a finding. No severity is "
                      "expressed or implied.",
    }
    for index, lead in enumerate(leads, 1):
        if lead.confidence < args.min_confidence:
            continue
        payload["leads"].append({
            "lead_id": lead_id(index),
            "rule_id": lead.rule.id,
            "category": lead.rule.category,
            "confidence": round(lead.confidence, 2),
            "band": confidence_band(lead.confidence),
            "value": lead.value,
            "scope": lead.best_scope(),
            "sites": [{"file": s[0], "line": s[1], "scope": s[2]}
                      for s in lead.sites[:args.max_sites]],
            "factors": [{"why": w, "delta": round(d, 2)} for w, d in lead.factors],
            "next_step": " ".join(lead.rule.next_step.split()),
        })
    for lead in result.blind.values():
        payload["blind_spots"].append({
            "rule_id": lead.rule.id,
            "what": lead.rule.what,
            "value": lead.value,
            "n_sites": len(lead.sites),
            "files": sorted(lead.files)[:10],
        })
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def print_catalogue():
    print("\nstatic-sweep rule catalogue, version %s" % VERSION)
    print(rule_line("="))
    print("Every rule has an equivalent you can run by hand. Run them by hand")
    print("at least once: a tool you have never checked is a tool you cannot")
    print("defend in a report.\n")
    by_cat = defaultdict(list)
    for rule in CATALOGUE:
        by_cat[rule.category].append(rule)
    for category in sorted(by_cat):
        print("\n## %s" % category)
        for rule in by_cat[category]:
            marker = "  [BLIND SPOT]" if rule.blind else ""
            print("\n  %s  precision=%.2f%s" % (rule.id, rule.precision, marker))
            print("    what : %s" % rule.what)
            if rule.grep:
                print("    grep : %s" % rule.grep)
            print("    next : %s" % _wrap(rule.next_step, 11))
    print("")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass

    parser = argparse.ArgumentParser(
        prog="static-sweep.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Sweep a decompiled tree and rank the leads. Never returns "
                    "a verdict.",
        epilog="""
Confidence is not severity. Confidence answers "should I look at this next",
which a tool can estimate. Severity answers "how bad is this", which depends
on reachability, on who can reach it, and on what it protects -- none of
which is in the files on your disk. See ../README.md section 11.2.
""")
    parser.add_argument("paths", nargs="*",
                        help="one or more decompiled trees (jadx sources/, "
                             "apktool output, a source checkout)")
    parser.add_argument("--app-package", metavar="PKG",
                        help="the application's own package, e.g. "
                             "com.example.target. Read from AndroidManifest.xml "
                             "when the tree contains one.")
    parser.add_argument("--files", choices=["all", "app"], default="all",
                        help="'app' skips files that classify as third-party "
                             "or generated BEFORE reading them. On a 20,000-"
                             "file tree this turns a six-minute sweep into a "
                             "one-minute one, and is the right first pass.")
    parser.add_argument("--scope", choices=["all", "app"], default="all",
                        help="'app' reports only leads with at least one site "
                             "in the app's own package (default: all)")
    parser.add_argument("--min-confidence", type=float, default=0.0,
                        metavar="F", help="hide leads below this confidence "
                                          "(0.0-0.95, default 0.0)")
    parser.add_argument("--max-sites", type=int, default=6, metavar="N",
                        help="how many sites to print per lead (default 6)")
    parser.add_argument("--show-suppressed", action="store_true",
                        help="also print leads demoted by the noise list, and "
                             "the reason each was demoted")
    parser.add_argument("--no-resources", action="store_true",
                        help="skip res/ -- faster, and loses string resources, "
                             "which is where a surprising number of endpoints "
                             "and keys actually live")
    parser.add_argument("--verbose", action="store_true",
                        help="print the matching source line under each site")
    parser.add_argument("--csv", metavar="FILE",
                        help="write the queue as CSV with empty verdict and "
                             "reason columns for you to fill in")
    parser.add_argument("--json", metavar="FILE", help="write the queue as JSON")
    parser.add_argument("--print-catalogue", action="store_true",
                        help="print every rule and its hand-run equivalent, "
                             "then exit")

    args = parser.parse_args()

    if args.print_catalogue:
        print_catalogue()
        return 0

    if not args.paths:
        parser.error("give at least one decompiled tree, or --print-catalogue")

    for path in args.paths:
        if not os.path.exists(path):
            sys.stderr.write("error: no such path: %s\n" % path)
            return 2

    result = SweepResult()

    manifest = find_manifest(args.paths)
    result.manifest_path = manifest
    package = args.app_package
    if not package and manifest:
        package = app_package_from_manifest(manifest)
    result.app_package = package
    if manifest:
        result.entry_points = entry_points_from_manifest(manifest, package)

    app_prefixes = []
    if package:
        app_prefixes.append(package.replace(".", "/") + "/")
        # The top two components catch the common case where the code lives
        # under com/vendor/ while the applicationId carries a flavour suffix.
        parts = package.split(".")
        if len(parts) >= 2:
            app_prefixes.append("/".join(parts[:2]) + "/")

    sweep(args.paths, app_prefixes, result,
          follow_resources=not args.no_resources,
          app_files_only=(args.files == "app"))
    corroborate(result, args.paths)

    if args.scope == "app":
        result.leads = dict(
            (k, v) for k, v in result.leads.items() if SCOPE_APP in v.scopes)

    print_report(result, args)

    if args.csv:
        write_csv(result, args.csv, args)
        sys.stderr.write("csv written to %s\n" % args.csv)
    if args.json:
        write_json(result, args.json, args)
        sys.stderr.write("json written to %s\n" % args.json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
