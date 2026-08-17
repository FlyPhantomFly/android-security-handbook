#!/usr/bin/env python3
# 79-Glossary/scripts/glossary-coverage.py
#
# PURPOSE
#   Make this chapter's coverage claim TESTABLE instead of aspirational, in
#   both directions:
#
#     FORWARD   every term on the watchlist (scripts/lexicon.txt) has a
#               glossary entry.
#     REVERSE   every glossary entry is a word the repository actually uses.
#     PROPOSE   high-frequency technical terms that are in neither, so the
#               watchlist cannot silently rot as chapters are added.
#
# WHY THIS EXISTS
#   `79-Glossary/README.md:3` used to read "Every term used anywhere in this
#   repository". Nobody had measured it and it was false. A reader-experience
#   audit found eight words with no entry, ranked by the number of files using
#   them:
#
#       Activity 120 · SELinux 107 · logcat 95 · Gradle 86 · bytecode 75
#       syscall 62 · BroadcastReceiver 46 · daemon 45
#
#   `syscall` was used in the glossary's OWN introduction. Meanwhile `Deodex`
#   had an entry and appeared nowhere else in the repository. So the claim was
#   wrong in both directions at once, which is exactly why this script checks
#   both.
#
# WHY "EVERY TERM" IS NOT AN ACHIEVABLE TARGET
#   This was attempted before the present design was settled on, and the
#   attempt is worth recording so it is not repeated.
#
#   828 markdown files containing embedded shell, Java, Smali and XML yield
#   roughly 20,000 distinct identifiers. Purely mechanical extraction — the
#   obvious approach — produced ~1,300 "candidate terms" appearing in 40+
#   files, of which the overwhelming majority were English (`before`, `never`,
#   `check`) or shell fragments harvested from inline code spans (`grep`,
#   `read`, `for`). Three extractor designs were measured:
#
#     shape only (CamelCase/ALLCAPS/hyphenated)
#         misses every word the audit found. `logcat`, `bytecode`, `syscall`
#         and `daemon` are ordinary-looking lowercase words with no shape.
#     shape + lowercase prose with an English stop-list
#         1,933 undefined candidates at 40+ files, nearly all noise. Any
#         stop-list large enough to suppress English is also large enough to
#         swallow a technical word silently — the failure mode is invisible.
#     "words the repository marks up itself" (bold or inline code)
#         better, but `bytecode` is code-spanned in 0 files and bolded in 7,
#         `daemon` in 0 and 4. The signal is too weak at any useful threshold.
#
#   The honest conclusion: a term is technical because of what it MEANS, and no
#   amount of surface shape recovers that. So the target this script enforces
#   is bounded and stated, and README.md:3 now claims exactly it and no more:
#
#       every term on the watchlist is defined, and every definition is used
#
#   PROPOSE mode keeps that from being a way to hide. It nominates candidates
#   by shape at a threshold; each nomination is triaged into the watchlist (and
#   an entry is written for it) or into EXCLUSIONS with a written reason. It is
#   advisory and never changes the exit code, because shape recognition is
#   exactly the technique shown above to miss the terms that mattered.
#
# WAS THIS EXECUTED?
#   YES. Run against this repository on 2026-08-18, CPython 3.13.3, Windows 11,
#   Git Bash. Final state after the eight audit terms and seven more were
#   written:
#
#       markdown files scanned                    826
#       glossary entries (A-Z)                    156
#       glossary lookup keys                      427
#       watchlist terms                           131
#       FORWARD: watchlist terms undefined          0
#       REVERSE: entries used in 0 files            0
#         warn: entry names used in 0 files         3
#       proposals at 60+ files                      0
#
#   The first run found two things by itself, both real: `Service` -- an
#   Android component type -- had no entry, and 16 entries were reported as
#   used in zero files, every one of them a multi-word term that the matcher
#   could not see (see file_count). One was a missing definition, the other a
#   bug in this script; both are fixed.
#
#   The three remaining warnings are alternative names carried by an entry
#   whose other name does the work: `Deodex` (the entry is `Deodex / ODEX`,
#   and only `ODEX` is used), and the spelled-out expansions of AAPT2 and PIE.
#   `Deodex` appearing in zero files is exactly what the audit reported, now
#   reproduced by the tool rather than asserted.
#
#   Re-run before quoting any figure here; the counts move whenever a chapter
#   is edited.
#
# USAGE
#   python3 -B 79-Glossary/scripts/glossary-coverage.py            # report
#   python3 -B 79-Glossary/scripts/glossary-coverage.py --strict   # gate
#   python3 -B 79-Glossary/scripts/glossary-coverage.py --propose
#   python3 -B 79-Glossary/scripts/glossary-coverage.py --term SELinux
#
#   Exit codes: 0 clean, 1 forward or reverse failure under --strict,
#               2 setup problem (glossary or lexicon unreadable).

from __future__ import annotations

import argparse
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir))
GLOSSARY = os.path.join(REPO, "79-Glossary", "README.md")
LEXICON = os.path.join(HERE, "lexicon.txt")

DEFAULT_PROPOSE_MIN = 60

# Untracked maintainer build logs, by name. A build log is not prose: it quotes
# term names in bulk while narrating the build, so counting one would report
# every glossary term as "used" and the coverage figure would mean nothing. The
# names stay listed whether or not the files are present in a given checkout --
# a name that matches nothing costs nothing, and removing it would silently
# change what the coverage number is measured over.
SKIP_FILES = {"BUILD-STATUS.md"}
SKIP_DIR_NAMES = {".git", "node_modules"}

# Shape-based proposals only. Each entry needs a written reason: these are
# words that LOOK technical to the extractor and correctly have no entry.
EXCLUSIONS = {
    "readme": "filename, not vocabulary",
    "github": "hosting platform",
    "powershell": "host shell, not Android vocabulary",
    "windows": "host operating system",
    "macos": "host operating system",
    "ubuntu": "host operating system",
    "google": "vendor name",
    "pixel": "device model",
    "gitbash": "host shell",
    "http": "web fundamentals, assumed; TLS/pinning terms have entries",
    "https": "web fundamentals, assumed",
    "json": "interchange format, assumed knowledge",
    "yaml": "interchange format, assumed knowledge",
    "xml": "covered concretely as AXML and AndroidManifest.xml",
    "sql": "assumed knowledge; SQL injection is taught in chapter 27",
    "url": "web fundamentals, assumed",
    "uri": "web fundamentals, assumed; URI permission grant has an entry",
    "usb": "physical transport",
    "cpu": "hardware fundamentals, chapter 01 §3.1",
    "ram": "hardware fundamentals, chapter 01 §3.1",
    "ide": "development environment, not a term of art here",
    "gui": "user-interface abbreviation",
    "cli": "user-interface abbreviation",
    "api": "used generically for 'API level' and 'an API'; targetSdkVersion carries the meaning",
    "sdk": "toolchain, not a security concept",
    "ndk": "already in the acronym table",
    "app": "the subject of the book",
    "apps": "the subject of the book",
    "note": "callout label",
    "warning": "callout label",
    "definition": "callout label",
    "chapter": "repository structure",
    "chapters": "repository structure",
    "prerequisites": "chapter front-matter",
    "lab": "repository structure",
    "labs": "repository structure",
    "cheatsheet": "repository structure",
    "mindmap": "repository structure",
    "true": "ordinary English surviving the shape filter",
    "false": "ordinary English surviving the shape filter",
    "null": "programming primitive, assumed",
    "int": "programming primitive, assumed",
    "string": "programming primitive, assumed",
    "boolean": "programming primitive, assumed",
    "byte": "defined in chapter 01 §3.2 as a unit, not a term of art",
    "bytes": "see byte",
    "static": "generic modifier; 'static analysis' is chapter 52",
    "dynamic": "generic modifier; 'dynamic analysis' is chapter 51",
    "native": "generic modifier; JNI and Native Code have entries",
    "public": "Java modifier, assumed",
    "private": "Java modifier, assumed",
    "class": "Java fundamentals, chapter 04",
    "classes": "Java fundamentals, chapter 04",
    "method": "Java fundamentals, chapter 04",
    "object": "Java fundamentals, chapter 04",
    "library": "generic; specific libraries have entries",
    "framework": "generic; the Android framework is chapter 06",
    "process": "OS fundamentals, chapter 01 §3.12",
    "thread": "OS fundamentals, chapter 01 §3.14",
    "kernel": "OS fundamentals, chapter 01 §3.10",
    "stack": "OS fundamentals, chapter 01 §3.16",
    "heap": "OS fundamentals, chapter 01 §3.17",
    "socket": "OS fundamentals, chapter 02 §3.15",
    "emulator": "testing environment; emulator detection is chapter 39",
    "vendor": "partition name; listed in section 7",
    "verified": "Verified Boot has an entry under AVB",
    "success": "checklist vocabulary",
    "absent": "checklist vocabulary",
    "measured": "the repository's evidence label",

    # ALLCAPS emphasis. The acronym extractor cannot tell `NOT` used for
    # emphasis from `JNI`; nothing else can either, so they are listed.
    "the": "ALLCAPS emphasis in prose",
    "not": "ALLCAPS emphasis in prose",
    "this": "ALLCAPS emphasis in prose",
    "only": "ALLCAPS emphasis in prose",
    "first": "ALLCAPS emphasis in prose",
    "before": "ALLCAPS emphasis in prose",
    "high": "ALLCAPS severity label",
    "name": "ALLCAPS emphasis in prose",
    "auth": "ALLCAPS emphasis; OAuth and Authentication have their own coverage",
    "crypto": "ALLCAPS emphasis; the cryptography terms have entries",
    "nul": "ALLCAPS emphasis on the NUL byte; chapter 01 §3.5 covers encoding",

    # Directory names of this repository, harvested from cross-reference text.
    "rootdetection": "chapter directory name",
    "tamperdetection": "chapter directory name",
    "staticanalysis": "chapter directory name",
    "contentproviders": "chapter directory name (ContentProvider has an entry)",
    "bypassingprotections": "chapter directory name",
    "androidmanifest": "filename; covered in sections 5 and 6",
    "faq": "repository structure",
    "ctf": "difficulty label used by the labs",

    # Concrete values, flags and identifiers, not vocabulary.
    "m2101k6p": "device model of the reference phone",
    "miui": "vendor Android distribution",
    "oem": "industry abbreviation",
    "cve": "vulnerability identifier scheme",
    "rfc": "standards document scheme",
    "buildtools": "SDK component directory",
    "arm64v8a": "an ABI value; ABI has an entry",
    "dynsyms": "a readelf flag",
    "printcerts": "an apksigner flag",
    "conststring": "a Smali opcode; Smali has an entry",
    "invokevirtual": "a Smali opcode; Smali has an entry",
    "invokestatic": "a Smali opcode; Smali has an entry",
    "forcestop": "an adb subcommand",
    "intentfilter": "a manifest element; Intent has an entry",
    "mainactivity": "conventional class name in examples",
    "apks": "plural of APK",
    "apis": "plural of API",
    "sdks": "plural of SDK",
    "kib": "unit of measurement",
    "eacces": "an errno value",
    "utf": "text encoding, chapter 01 §3.5",
    "ascii": "text encoding, chapter 01 §3.5",
    "zip": "archive format; APK has an entry and is one",
    "javascript": "language name; WebView carries the security meaning",
    "jvm": "desktop Java VM, contrasted with ART throughout chapter 13",
    "sqlite": "the database engine; storage findings are chapter 33",
    "okhttp": "a specific third-party library, one of many",
    "frida-server": "a component of Frida, which has an entry",
    "jnienv": "a JNI structure; JNI has an entry",
    "jdwp": "the Java debug protocol; debuggable is covered under run-as",
    "jdk": "toolchain component, installed in 00 §3.6.1",
    "repl": "interactive-prompt abbreviation",
    "xor": "a bitwise operation, chapter 01 §3.2",
    "sha": "hash family; hashing is contrasted with encryption in section 5",
    "aes": "cipher name; the mode entries (ECB, GCM, AEAD) carry the meaning",
    "rsa": "cipher name; see AES",
    "tls": "the protocol chapter 35 owns; SSL/pinning/CA have entries",
    "ssl": "see TLS",
    "owasp": "the body behind MASVS/MASTG, which have an entry",
    "oauth": "the protocol chapter 45 owns; PKCE and DPoP have entries",
    "mobsf": "a tool with its own chapter (55); not a concept",
    "ida": "a tool with its own chapter (58); not a concept",
    "arm": "the architecture chapter 18 owns; AAPCS64 and MTE have entries",
    "securityexception": "the exception a denied permission throws; see Permissions",
    "registernatives": "a JNI function; JNI's entry names it",
    "activitythread": "a framework class; Activity and Zygote carry the meaning",
    "packagemanagerservice": "a system service; named in the pm/package-manager entries",
    "sharedpreferences_": "placeholder guard, unused",

    # Ordinary hyphenated English that the hyphen extractor cannot distinguish
    # from `dm-verity`.
    "thirdparty": "ordinary English compound",
    "serverside": "ordinary English compound",
    "clientside": "ordinary English compound",
    "attackercontrolled": "ordinary English compound",
    "highestvalue": "ordinary English compound",
    "oneline": "ordinary English compound",
    "loadbearing": "ordinary English compound",
    "handwritten": "ordinary English compound",
    "perapp": "ordinary English compound",
    "hardwarebacked": "ordinary English compound",
    "crosscheck": "ordinary English compound",
    "controlflow": "ordinary English compound",
    "nonzero": "ordinary English compound",
    "securityrelevant": "ordinary English compound",
    "realworld": "ordinary English compound",
    "falsepositive": "ordinary English compound",
    "antianalysis": "ordinary English compound",
    "llvmreadelf": "a tool invocation, not a term",
    "llvmobjdump": "a tool invocation, not a term",
    "dynamicanalysis": "chapter directory name",
    "activitymanagerservice": "a system service; Activity and Binder carry the meaning",
    "enoent": "an errno value",
    "urls": "plural of URL",
    "cas": "plural of CA, which has an entry",
    "uids": "plural of UID, which has an entry",
    "ids": "plural of ID",
    "q10": "a lab question number",
    "one": "ALLCAPS emphasis in prose",
    "armeabiv7a": "an ABI value; ABI has an entry",
    "metadata": "a manifest element name (`<meta-data>`)",
    "antidebug": "ordinary English compound; TracerPid and ptrace carry the meaning",
    "antitamper": "ordinary English compound; chapter 38 owns it",
    "antitampering": "ordinary English compound; chapter 38 owns it",
    "byteidentical": "ordinary English compound",
    "worldreadable": "ordinary English compound; permission bits are chapter 02 §3.7",
    "compiletime": "ordinary English compound",
    "crossreference": "ordinary English compound",
    "crossreferences": "ordinary English compound",
    "littleendian": "ordinary English compound; endianness is chapter 01 §3.4",
    "memorysafety": "ordinary English compound; chapter 19 owns it",
}


# --------------------------------------------------------------------------
# Markdown handling
# --------------------------------------------------------------------------
FENCE_RE = re.compile(r"^\s*(?:```|~~~)")
LINK_TARGET_RE = re.compile(r"\]\([^)\n]*\)")
URL_RE = re.compile(r"https?://\S+")
INLINE_CODE_RE = re.compile(r"`[^`\n]*`")

# A token as it appears on the page, case preserved. Hyphenated and dotted
# forms are kept whole so `dm-verity` and `dex2oat` survive tokenisation.
TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:[.-][A-Za-z0-9_]+)*")


def prose_of(text: str) -> str:
    """Everything outside fenced code blocks, with link targets removed."""
    kept = []
    in_fence = False
    for line in text.split("\n"):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            kept.append(line)
    body = "\n".join(kept)
    body = LINK_TARGET_RE.sub("] ", body)
    body = URL_RE.sub(" ", body)
    return body


def tokens_of(text: str) -> set[str]:
    """Every surface token in the file, case preserved, link targets removed."""
    body = LINK_TARGET_RE.sub("] ", text)
    body = URL_RE.sub(" ", body)
    out: set[str] = set()
    for tok in TOKEN_RE.findall(body):
        out.add(tok)
        # `dm-verity` should also answer to itself with the trailing
        # punctuation of a sentence already stripped by the regex; split
        # compounds so `boot.img` matches a lexicon entry of `boot.img`
        # and `AndroidManifest.xml` does not swallow `AndroidManifest`.
        for part in re.split(r"[.-]", tok):
            if len(part) > 2:
                out.add(part)
    return out


# --------------------------------------------------------------------------
# Glossary index
# --------------------------------------------------------------------------
BOLD_ENTRY_RE = re.compile(r"^\*\*([^*]+)\*\*\s+—\s")
TABLE_ROW_RE = re.compile(r"^\|\s*([^|]+?)\s*\|")
TABLE_HEADERS = {"a", "acronym", "path", "extension / name", "term", "noun",
                 "your machine", "if missing"}


def surface_forms(field: str) -> list[str]:
    """`Deodex / ODEX` -> both. `ABI (Application Binary Interface)` -> both."""
    out: list[str] = []
    parens = re.findall(r"\(([^)]+)\)", field)
    head = re.sub(r"\([^)]*\)", " ", field)
    for chunk in re.split(r"\s*(?:/| or | vs\.? | versus )\s*", head):
        chunk = chunk.strip().strip("`*. ")
        if chunk:
            out.append(chunk)
    for p in parens:
        p = p.strip().strip("`*. ")
        if p and not p.lower().startswith(("e.g", "see ", "not ", "the ")):
            out.append(p)
    return out


def key(term: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", term.lower())


def index_glossary(path: str):
    """-> (keys defined, [(display term, [surface forms])], entry count)."""
    with io.open(path, encoding="utf-8", newline="") as f:
        raw = f.read()

    defined: set[str] = set()
    entries: list[tuple[str, list[str]]] = []
    n_bold = 0

    for line in raw.split("\n"):
        m = BOLD_ENTRY_RE.match(line)
        if m:
            n_bold += 1
            forms = surface_forms(m.group(1))
            if forms:
                entries.append((m.group(1).strip(), forms))
            for t in forms:
                defined.add(key(t))
                for w in re.findall(r"[A-Za-z][A-Za-z0-9_.-]{2,}", t):
                    defined.add(key(w))
            continue
        m = TABLE_ROW_RE.match(line)
        if m:
            cell = m.group(1)
            if cell.startswith("-") or cell.strip().lower() in TABLE_HEADERS:
                continue
            cell = cell.replace("**", "").replace("`", " ")
            for t in surface_forms(cell):
                if 1 < len(t) < 60:
                    defined.add(key(t))
                    for w in re.findall(r"[A-Za-z][A-Za-z0-9_.-]{2,}", t):
                        defined.add(key(w))
    defined.discard("")
    return defined, entries, n_bold


# --------------------------------------------------------------------------
# Watchlist
# --------------------------------------------------------------------------
def load_lexicon(path: str) -> list[str]:
    terms: list[str] = []
    with io.open(path, encoding="utf-8", newline="") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                terms.append(line)
    return terms


# --------------------------------------------------------------------------
# Corpus
# --------------------------------------------------------------------------
def markdown_files(root: str) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for fn in filenames:
            if fn.endswith(".md") and fn not in SKIP_FILES:
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


def load_corpus(files: list[str]):
    """-> [(path, token set, prose, flattened text)]; glossary itself excluded.

    The flattened text is whitespace-collapsed so a multi-word term still
    matches when the source wrapped it across two lines -- which, in a
    repository that hard-wraps prose at 100 columns, is most of the time.
    """
    corpus = []
    for path in files:
        if os.path.abspath(path) == os.path.abspath(GLOSSARY):
            continue
        try:
            with io.open(path, encoding="utf-8", newline="") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError) as exc:
            sys.stderr.write("warn: skipping %s (%s)\n" % (path, exc))
            continue
        flat = re.sub(r"\s+", " ", LINK_TARGET_RE.sub("] ", text))
        corpus.append((path, tokens_of(text), prose_of(text), flat))
    return corpus


PHRASE_CACHE: dict[str, re.Pattern] = {}


def phrase_re(form: str) -> re.Pattern:
    """Word-bounded, case-insensitive, backtick- and emphasis-tolerant."""
    pat = PHRASE_CACHE.get(form)
    if pat is None:
        parts = [re.escape(w) for w in form.split()]
        body = r"[\s`*_]+".join(parts)
        pat = re.compile(r"(?<![A-Za-z0-9])" + body + r"(?![A-Za-z0-9])",
                         re.IGNORECASE)
        PHRASE_CACHE[form] = pat
    return pat


def file_count(corpus, forms: list[str]) -> int:
    """Files containing any surface form.

    SINGLE WORDS are matched case-sensitively against the token set. Case
    matters here: matching `SELinux` case-insensitively also counts `selinux`
    inside a path, and matching `ISA` case-insensitively counts every `is a`
    that lost its space in a heading slug. Both were observed while this
    script was being written. A leading capital is accepted as well, because a
    lowercase term legitimately starts a sentence.

    MULTI-WORD terms cannot be matched that way at all -- a token set has no
    notion of adjacency -- so they are matched as phrases against the
    flattened text. Getting this wrong is not theoretical: the first run of
    this script reported 16 entries as "used in 0 files", every one of them a
    multi-word term (`Deep link`, `Exported component`, `Intent redirection`),
    and every one of them false.
    """
    singles = set()
    phrases = []
    for f in forms:
        if " " in f.strip():
            phrases.append(f.strip())
        else:
            singles.add(f)
            if f[:1].islower():
                singles.add(f[0].upper() + f[1:])

    n = 0
    for _, toks, _, flat in corpus:
        if singles and (toks & singles):
            n += 1
            continue
        if any(phrase_re(p).search(flat) for p in phrases):
            n += 1
    return n


# --------------------------------------------------------------------------
# Proposal mode
# --------------------------------------------------------------------------
CAMEL_RE = re.compile(r"\b[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+\b")
ACRONYM_RE = re.compile(r"\b[A-Z][A-Z0-9]{1,5}(?:[a-z]{1,7})?\b")
HYPHEN_RE = re.compile(r"\b[a-z][a-z0-9]{2,14}-[a-z][a-z0-9]{2,14}\b")


def propose(corpus, defined, watch_keys, minimum):
    seen: set[str] = set()
    for _, _, prose, _ in corpus:
        nocode = INLINE_CODE_RE.sub(" ", prose)
        seen.update(CAMEL_RE.findall(nocode))
        seen.update(ACRONYM_RE.findall(nocode))
        seen.update(HYPHEN_RE.findall(nocode))

    excluded = {key(k) for k in EXCLUSIONS}
    rows = []
    for term in seen:
        if len(term) < 3:
            continue
        k = key(term)
        if k in defined or k in watch_keys or k in excluded:
            continue
        n = file_count(corpus, [term])
        if n >= minimum:
            rows.append((n, term))
    rows.sort(key=lambda r: (-r[0], r[1]))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Glossary coverage, both directions.")
    ap.add_argument("--root", default=REPO)
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 on any forward or reverse failure")
    ap.add_argument("--propose", action="store_true",
                    help="nominate high-frequency terms in neither list")
    ap.add_argument("--propose-min", type=int, default=DEFAULT_PROPOSE_MIN)
    ap.add_argument("--show", type=int, default=40)
    ap.add_argument("--term", help="report one term and exit")
    args = ap.parse_args()

    if not os.path.isfile(GLOSSARY):
        sys.stderr.write("error: cannot read %s\n" % GLOSSARY)
        return 2
    if not os.path.isfile(LEXICON):
        sys.stderr.write("error: cannot read %s\n" % LEXICON)
        return 2

    defined, entries, n_bold = index_glossary(GLOSSARY)
    watch = load_lexicon(LEXICON)
    watch_keys = {key(t) for t in watch}

    files = markdown_files(args.root)
    corpus = load_corpus(files)

    if args.term:
        t = args.term
        print("term        : %s" % t)
        print("files using : %d  (of %d, glossary excluded)" %
              (file_count(corpus, [t]), len(corpus)))
        print("in glossary : %s" % ("yes" if key(t) in defined else "NO"))
        print("on watchlist: %s" % ("yes" if key(t) in watch_keys else "no"))
        for ex_term, reason in EXCLUSIONS.items():
            if key(ex_term) == key(t):
                print("excluded    : %s" % reason)
                break
        return 0

    # FORWARD -----------------------------------------------------------
    missing = [t for t in watch if key(t) not in defined]
    used = [(t, file_count(corpus, [t])) for t in watch]

    # REVERSE -----------------------------------------------------------
    #
    # An entry counts as used if ANY of its names is used, because
    # `Deodex / ODEX` is one concept under two names. That is right, but it
    # hides something worth seeing: `Deodex` itself appears in zero files
    # while `ODEX` carries the entry. Unused names are reported separately,
    # as a warning rather than a failure -- a term nobody in the repository
    # uses is either historical (say so in the entry) or dead weight.
    dead = []
    unused_names = []
    for display, forms in entries:
        if file_count(corpus, forms) == 0:
            dead.append(display)
            continue
        if len(forms) > 1:
            for f in forms:
                if file_count(corpus, [f]) == 0:
                    unused_names.append((f, display))

    w = 40
    print("-" * (w + 12))
    print("%-*s %10d" % (w, "markdown files scanned", len(corpus)))
    print("%-*s %10d" % (w, "glossary entries (A-Z)", n_bold))
    print("%-*s %10d" % (w, "glossary lookup keys", len(defined)))
    print("%-*s %10d" % (w, "watchlist terms", len(watch)))
    print("%-*s %10d" % (w, "FORWARD: watchlist terms undefined", len(missing)))
    print("%-*s %10d" % (w, "REVERSE: entries used in 0 files", len(dead)))
    print("%-*s %10d" % (w, "  warn: entry names used in 0 files",
                         len(unused_names)))
    print("-" * (w + 12))

    if missing:
        print("\nFORWARD FAILURE — on the watchlist, no glossary entry:\n")
        for t in missing:
            print("  %5d files   %s" % (file_count(corpus, [t]), t))
        print("\nWrite the entry, or remove the term from lexicon.txt.")

    if dead:
        print("\nREVERSE FAILURE — defined but used nowhere else:\n")
        for t in dead:
            print("    %s" % t)
        print("\nEither the term is genuinely obsolete and the entry should say")
        print("so, or the repository stopped using a word it still teaches.")

    if unused_names:
        print("\nwarning — alternative names no file uses (not a failure):\n")
        for name, display in unused_names:
            print("    %-24s  (entry: %s)" % (name, display))

    if not missing and not dead:
        print("\nEvery watchlist term is defined, and every glossary entry is")
        print("used somewhere in the repository. Both directions hold.")

    print("\nwatchlist usage, most-used first:\n")
    for t, n in sorted(used, key=lambda r: (-r[1], r[0]))[: args.show]:
        print("  %5d files   %s" % (n, t))
    if len(used) > args.show:
        print("  ... and %d more (raise --show)" % (len(used) - args.show))

    if args.propose:
        rows = propose(corpus, defined, watch_keys, args.propose_min)
        print("\nproposals — shape-recognised, in %d+ files, in neither list:\n"
              % args.propose_min)
        if not rows:
            print("  (none)")
        for n, term in rows[: args.show]:
            print("  %5d files   %s" % (n, term))
        if len(rows) > args.show:
            print("  ... and %d more (raise --show)" % (len(rows) - args.show))
        print("\nProposals are a backlog, not a gate: they never change the exit")
        print("code. Triage each into lexicon.txt (writing the entry it then")
        print("requires) or into EXCLUSIONS with a reason. And note that shape")
        print("recognition cannot see lowercase prose jargon at all — an empty")
        print("list here does not mean the glossary is complete. Read the header.")

    if args.strict and (missing or dead):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
