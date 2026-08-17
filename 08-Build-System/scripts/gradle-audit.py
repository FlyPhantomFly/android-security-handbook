#!/usr/bin/env python3
"""
gradle-audit.py — static security audit of an Android Gradle project's build files.

PURPOSE
    Automates items 1-27 of the pentester's build-file checklist in
    ../README.md section 5.5. It reads (never executes) every Gradle build file,
    properties file, version catalog and wrapper descriptor in a project and
    reports the security-relevant configuration: repository trust, wrapper
    integrity, release hardening, embedded secrets, signing material and
    dependency hygiene.

    This script NEVER runs Gradle. A build.gradle file is arbitrary code and
    executing one is exactly what we are warning about. Everything here is
    text analysis.

USAGE
    python3 gradle-audit.py /path/to/android-project
    python3 gradle-audit.py /path/to/android-project --json report.json
    python3 gradle-audit.py /path/to/android-project --min-severity MEDIUM

EXIT CODES
    0  no findings at or above the minimum severity
    1  findings present
    2  usage / path error

REQUIREMENTS
    Python 3.8+. Standard library only. No network access.

AUTHOR NOTE
    Every finding is a *candidate*. Read ../README.md section 5.3 for the
    severity reasoning before putting anything from this tool into a report.
    In particular, this script cannot tell a genuine credential from a public
    identifier such as a Maps or Firebase Web API key.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, asdict, field
from typing import List, Optional

# --------------------------------------------------------------------------
# Severity model
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

COLOURS = {
    "CRITICAL": "\033[1;31m",
    "HIGH":     "\033[0;31m",
    "MEDIUM":   "\033[0;33m",
    "LOW":      "\033[0;36m",
    "INFO":     "\033[0;37m",
    "RESET":    "\033[0m",
}


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    path: str
    line: int = 0
    reference: str = ""          # section of ../README.md that explains it


@dataclass
class Report:
    project: str
    findings: List[Finding] = field(default_factory=list)
    facts: dict = field(default_factory=dict)

    def add(self, severity, title, detail, path, line=0, reference=""):
        self.findings.append(
            Finding(severity, title, detail, path, line, reference)
        )


# --------------------------------------------------------------------------
# File discovery
# --------------------------------------------------------------------------

SKIP_DIRS = {".git", "build", ".gradle", "node_modules", ".idea", "out", ".cxx"}


def walk_project(root: str):
    """Yield every file path in the project, skipping generated directories."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def lines_matching(text: str, pattern: re.Pattern):
    """Yield (line_number, line_text) for every line matching the pattern."""
    for i, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            yield i, line.strip()


def rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


# --------------------------------------------------------------------------
# Check 1 — repositories and dependency-confusion exposure
# --------------------------------------------------------------------------

RE_REPO_BLOCK = re.compile(r"repositories\s*\{", re.MULTILINE)
RE_MAVEN_URL = re.compile(r"""url\s*=?\s*\(?\s*uri\s*\(?\s*['"]([^'"]+)['"]""")
RE_MAVEN_URL_SIMPLE = re.compile(r"""maven\s*[({]\s*['"]?(https?://[^'"\s)]+)""")
RE_CONTENT_FILTER = re.compile(r"content\s*\{")
RE_REPO_MODE = re.compile(r"repositoriesMode\.set\s*\(\s*RepositoriesMode\.(\w+)")
RE_JITPACK = re.compile(r"jitpack\.io", re.IGNORECASE)


def check_repositories(root: str, report: Report):
    settings = [p for p in walk_project(root)
                if os.path.basename(p).startswith("settings.gradle")]
    roots = [p for p in walk_project(root)
             if os.path.basename(p).startswith("build.gradle")]

    all_repo_files = settings + roots
    found_content_filter = False
    found_repo_mode = None
    declared_repos = []

    for path in all_repo_files:
        text = read_text(path)
        if not RE_REPO_BLOCK.search(text):
            continue

        if RE_CONTENT_FILTER.search(text):
            found_content_filter = True

        m = RE_REPO_MODE.search(text)
        if m:
            found_repo_mode = m.group(1)

        for regex in (RE_MAVEN_URL, RE_MAVEN_URL_SIMPLE):
            for lineno, line in lines_matching(text, regex):
                url = (regex.search(line) or [None, ""])[1]
                declared_repos.append(url)
                if url.startswith("http://"):
                    report.add(
                        "HIGH",
                        "Repository declared over plaintext HTTP",
                        f"Artefacts fetched over HTTP can be substituted by a "
                        f"network attacker: {url}",
                        rel(root, path), lineno, "section 5.4",
                    )

        for lineno, line in lines_matching(text, RE_JITPACK):
            report.add(
                "MEDIUM",
                "JitPack repository declared",
                "JitPack builds libraries on demand from a git reference, so a "
                "dependency's content can change with no change to this project. "
                "Pin commit hashes and add dependency verification, or fork and "
                "republish internally.",
                rel(root, path), lineno, "section 5.4.6",
            )

    report.facts["repositories"] = sorted(set(r for r in declared_repos if r))
    report.facts["repositoriesMode"] = found_repo_mode

    if all_repo_files and not found_content_filter:
        report.add(
            "MEDIUM",
            "No repository content filtering",
            "No repository declares a content { includeGroupByRegex / "
            "excludeGroupByRegex } filter. Gradle will therefore ask public "
            "repositories about internal coordinates, which is the precondition "
            "for a dependency-confusion substitution.",
            rel(root, settings[0]) if settings else "(settings.gradle missing)",
            0, "section 5.4.1",
        )

    if found_repo_mode not in ("FAIL_ON_PROJECT_REPOS", "PREFER_SETTINGS"):
        report.add(
            "LOW",
            "repositoriesMode not restricted",
            "Without repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS), "
            "any module's build file may add its own repository, so the reviewed "
            "repository set in settings.gradle is not authoritative.",
            "settings.gradle(.kts)", 0, "section 5.4.1",
        )


# --------------------------------------------------------------------------
# Check 2 — the Gradle wrapper
# --------------------------------------------------------------------------

def check_wrapper(root: str, report: Report):
    props = os.path.join(root, "gradle", "wrapper", "gradle-wrapper.properties")
    jar = os.path.join(root, "gradle", "wrapper", "gradle-wrapper.jar")

    if not os.path.exists(props):
        report.facts["wrapper"] = None
        return

    text = read_text(props)
    dist_url = ""
    m = re.search(r"distributionUrl\s*=\s*(\S+)", text)
    if m:
        dist_url = m.group(1).replace("\\:", ":")

    has_sha = "distributionSha256Sum" in text
    report.facts["wrapper"] = {
        "distributionUrl": dist_url,
        "distributionSha256Sum": has_sha,
    }

    if dist_url and not dist_url.startswith("https://services.gradle.org/"):
        report.add(
            "HIGH",
            "Gradle distribution fetched from a non-official host",
            f"distributionUrl = {dist_url}. Anything other than "
            "services.gradle.org (or a controlled internal mirror whose "
            "provenance you have verified) means the Gradle distribution itself "
            "comes from an untrusted party.",
            rel(root, props), 0, "section 5.4.4",
        )

    if not has_sha:
        report.add(
            "MEDIUM",
            "Gradle wrapper has no distributionSha256Sum",
            "Without a pinned checksum the wrapper accepts whatever the "
            "distribution URL serves. Add distributionSha256Sum, or regenerate "
            "the wrapper with --gradle-distribution-sha256-sum.",
            rel(root, props), 0, "section 5.4.4",
        )

    if os.path.exists(jar):
        digest = hashlib.sha256(open(jar, "rb").read()).hexdigest()
        report.facts["wrapperJarSha256"] = digest
        report.add(
            "INFO",
            "Gradle wrapper JAR present — verify it by hand",
            f"SHA-256 = {digest}. Compare against the official checksum for the "
            "declared Gradle version at https://gradle.org/release-checksums/ . "
            "This is a committed binary that executes on the first ./gradlew.",
            rel(root, jar), 0, "section 5.4.4",
        )


# --------------------------------------------------------------------------
# Check 3 — code that runs before everything
# --------------------------------------------------------------------------

RE_DANGEROUS_BUILD_LOGIC = re.compile(
    r"\b(ProcessBuilder|Runtime\.getRuntime|exec\s*\(|URL\s*\(|HttpURLConnection"
    r"|HttpClient|Socket\s*\(|readText\s*\(|writeText\s*\(|System\.getenv"
    r"|dependencySubstitution|resolutionStrategy|eachDependency)\b"
)


def check_build_logic(root: str, report: Report):
    targets = []
    for name in ("buildSrc", "build-logic"):
        d = os.path.join(root, name)
        if os.path.isdir(d):
            targets.append(d)

    init_scripts = [p for p in walk_project(root)
                    if os.path.basename(p).endswith(".init.gradle")
                    or os.path.basename(p).endswith(".init.gradle.kts")]

    report.facts["buildLogicDirs"] = [rel(root, t) for t in targets]
    report.facts["initScripts"] = [rel(root, p) for p in init_scripts]

    if targets:
        report.add(
            "INFO",
            "Pre-execution build logic present — review it as production code",
            "buildSrc / build-logic is compiled and executed before any build "
            "script is evaluated, on every invocation including IDE import. "
            "Read every line: " + ", ".join(rel(root, t) for t in targets),
            ", ".join(rel(root, t) for t in targets), 0, "section 5.4.3",
        )

    for d in targets:
        for path in walk_project(d):
            if not path.endswith((".kt", ".kts", ".groovy", ".java", ".gradle")):
                continue
            text = read_text(path)
            for lineno, line in lines_matching(text, RE_DANGEROUS_BUILD_LOGIC):
                report.add(
                    "MEDIUM",
                    "Build logic performs I/O, process spawn or dependency rewriting",
                    "This construct in pre-execution build logic can read "
                    "credentials, contact the network, or silently substitute a "
                    "dependency for another. Every occurrence needs an "
                    "explanation: " + line[:160],
                    rel(root, path), lineno, "section 5.4.3",
                )

    for path in init_scripts:
        report.add(
            "MEDIUM",
            "Gradle init script present",
            "Init scripts run before the build and apply to every project. "
            "Review this file in full.",
            rel(root, path), 0, "section 5.4.3",
        )


# --------------------------------------------------------------------------
# Check 4 — release hardening
# --------------------------------------------------------------------------

RE_DEBUGGABLE = re.compile(r"\b(isDebuggable\s*=\s*true|debuggable\s+true)\b")
RE_MINIFY_FALSE = re.compile(r"\b(isMinifyEnabled\s*=\s*false|minifyEnabled\s+false)\b")
RE_MINIFY_TRUE = re.compile(r"\b(isMinifyEnabled\s*=\s*true|minifyEnabled\s+true)\b")
RE_SHRINK_RES = re.compile(r"\b(isShrinkResources|shrinkResources)\b")
RE_TESTONLY = re.compile(r"\b(isTestOnly\s*=\s*true|testOnly\s+true)\b")
RE_RELEASE_BLOCK = re.compile(
    r"(getByName\(\s*['\"]release['\"]\s*\)|release\s*\{|create\(\s*['\"]release['\"]\s*\))"
)
RE_V1_SIGNING = re.compile(r"enableV1Signing\s*=\s*true")
RE_LINT_OFF = re.compile(
    r"\b(abortOnError\s*[= ]\s*false|checkReleaseBuilds\s*[= ]\s*false)\b"
)


def extract_release_block(text: str) -> Optional[str]:
    """Return the text of the release build-type block, brace-balanced."""
    m = RE_RELEASE_BLOCK.search(text)
    if not m:
        return None
    start = text.find("{", m.start())
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:]


def check_release_hardening(root: str, report: Report):
    gradle_files = [p for p in walk_project(root)
                    if os.path.basename(p).startswith("build.gradle")]

    for path in gradle_files:
        text = read_text(path)
        block = extract_release_block(text)

        for lineno, line in lines_matching(text, RE_LINT_OFF):
            report.add(
                "LOW",
                "Lint failures do not fail the build",
                "Android Lint reports real security issues (exported components, "
                "trust-all TrustManagers, cleartext traffic). Disabling "
                "abortOnError or checkReleaseBuilds discards them silently.",
                rel(root, path), lineno, "section 5.2",
            )

        if block is None:
            continue

        if RE_DEBUGGABLE.search(block):
            report.add(
                "CRITICAL",
                "Release build type is debuggable",
                "android:debuggable=\"true\" lets any user run "
                "`adb shell run-as <pkg>` and read the entire private data "
                "directory with no root, and attach a JDWP debugger to the "
                "process.",
                rel(root, path), 0, "section 5.3.3",
            )

        if RE_MINIFY_FALSE.search(block):
            report.add(
                "LOW",
                "Release build does not run R8 (minifyEnabled false)",
                "No shrinking and no obfuscation. This is a MASVS-RESILIENCE "
                "hardening gap, not a vulnerability — report it as such.",
                rel(root, path), 0, "section 3.15",
            )

        if RE_TESTONLY.search(block):
            report.add(
                "MEDIUM",
                "Release build marked testOnly",
                "testOnly=\"true\" artefacts are rejected by Play and installable "
                "only with `adb install -t`. Usually indicates an IDE-produced "
                "artefact reached a release path.",
                rel(root, path), 0, "section 3.13",
            )

        if RE_V1_SIGNING.search(block) or RE_V1_SIGNING.search(text):
            report.add(
                "INFO",
                "v1 (JAR) signing explicitly enabled",
                "v1 signing does not cover the ZIP structure itself. It is only "
                "needed for minSdk < 24; verify the project's minSdk before "
                "reporting this either way.",
                rel(root, path), 0, "section 3.14",
            )

        if "signingConfig" not in block:
            report.add(
                "INFO",
                "Release build type declares no signingConfig",
                "The release artefact will be unsigned, or signed by whatever "
                "the CI does afterwards. Confirm where signing actually happens.",
                rel(root, path), 0, "section 3.14",
            )


# --------------------------------------------------------------------------
# Check 5 — signing material and credentials
# --------------------------------------------------------------------------

KEY_FILE_EXT = (".jks", ".keystore", ".p12", ".pfx", ".pk8", ".pem", ".key")

RE_CREDENTIAL_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(
        [A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|
        CREDENTIAL|ACCESS_KEY)[A-Z0-9_]*
    )
    \s*[=:]\s*
    (?!\s*$)                       # not empty
    (?!System\.getenv)             # not read from the environment
    (?!providers\.)                # not a Gradle provider
    (?!project\.findProperty)
    (?!["']\s*["'])                # not an empty string
    (\S+)
    """
)

RE_LITERAL_SECRET = re.compile(
    r"""(?x)
    (sk_live_[0-9a-zA-Z]{10,})
    | (AKIA[0-9A-Z]{16})
    | (ghp_[0-9A-Za-z]{36})
    | (xox[baprs]-[0-9A-Za-z-]{10,})
    | (-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----)
    | (eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})
    """
)

RE_GOOGLE_API_KEY = re.compile(r"AIza[0-9A-Za-z_\-]{35}")


def check_secrets(root: str, report: Report):
    keystores = []

    for path in walk_project(root):
        base = os.path.basename(path)
        low = base.lower()

        if low.endswith(KEY_FILE_EXT):
            keystores.append(rel(root, path))
            report.add(
                "CRITICAL" if low.endswith((".jks", ".keystore", ".p12", ".pk8"))
                else "HIGH",
                "Signing / key material present in the repository",
                "A keystore or private key in the working tree (and therefore, "
                "almost certainly, in git history) lets anyone holding the "
                "repository sign artefacts as the vendor.",
                rel(root, path), 0, "section 5.3.4",
            )
            continue

        if low == "google-services.json":
            report.add(
                "INFO",
                "google-services.json present",
                "Its values are compiled into resources.arsc. The Firebase Web "
                "API key it contains is a public identifier; the finding, if "
                "any, is an open Firebase database. Test the security rules.",
                rel(root, path), 0, "section 5.3.1",
            )
            continue

        if not (base.startswith("build.gradle")
                or base.startswith("settings.gradle")
                or low.endswith((".properties", ".toml", ".pro", ".cfg", ".yml",
                                 ".yaml", ".xml"))):
            continue

        text = read_text(path)

        for lineno, line in lines_matching(text, RE_CREDENTIAL_ASSIGNMENT):
            report.add(
                "HIGH",
                "Credential-looking assignment in a build input file",
                "This value is not read from the environment or a secret store: "
                + line[:160],
                rel(root, path), lineno, "section 5.3.4",
            )

        for lineno, line in lines_matching(text, RE_LITERAL_SECRET):
            report.add(
                "CRITICAL",
                "High-confidence secret literal",
                "A value matching a known credential format appears verbatim: "
                + line[:120],
                rel(root, path), lineno, "section 5.3.1",
            )

        for lineno, line in lines_matching(text, RE_GOOGLE_API_KEY):
            report.add(
                "INFO",
                "Google API key literal (AIza...)",
                "Maps/Firebase Web API keys are designed to ship and are NOT "
                "secrets. The reportable issue is an unrestricted key or open "
                "Firebase rules — verify before rating this. See section 5.3.1.",
                rel(root, path), lineno, "section 5.3.1",
            )

    report.facts["keyMaterialFiles"] = keystores

    gi = os.path.join(root, ".gitignore")
    if keystores and os.path.exists(gi):
        ignore = read_text(gi)
        if not any(tok in ignore for tok in ("*.jks", "*.keystore", "*.p12")):
            report.add(
                "MEDIUM",
                ".gitignore does not exclude keystore files",
                "Key material is present and .gitignore does not exclude the "
                "usual extensions, so it is very likely committed.",
                ".gitignore", 0, "section 5.3.4",
            )


# --------------------------------------------------------------------------
# Check 6 — embedded configuration injected into the artefact
# --------------------------------------------------------------------------

RE_BUILD_CONFIG_FIELD = re.compile(r"buildConfigField\s*\(")
RE_RES_VALUE = re.compile(r"resValue\s*\(")
RE_MANIFEST_PLACEHOLDER = re.compile(r"manifestPlaceholders")


def check_injected_config(root: str, report: Report):
    for path in walk_project(root):
        if not os.path.basename(path).startswith("build.gradle"):
            continue
        text = read_text(path)

        for regex, name, where in (
            (RE_BUILD_CONFIG_FIELD, "buildConfigField", "the DEX string pool"),
            (RE_RES_VALUE, "resValue", "resources.arsc"),
            (RE_MANIFEST_PLACEHOLDER, "manifestPlaceholders",
             "the merged AndroidManifest.xml"),
        ):
            for lineno, line in lines_matching(text, regex):
                sev = "INFO"
                # Heuristic: anything that looks like a credential name is worse.
                if re.search(r"(?i)key|secret|token|password|credential|auth",
                             line):
                    sev = "HIGH"
                report.add(
                    sev,
                    f"{name} injects a build-time value into the artefact",
                    f"The value ends up in {where} verbatim. Obfuscation does not "
                    f"alter string contents and javac inlines static final "
                    f"constants at every use site: " + line[:160],
                    rel(root, path), lineno, "section 5.3.1",
                )


# --------------------------------------------------------------------------
# Check 7 — dependency hygiene
# --------------------------------------------------------------------------

RE_COORD = re.compile(
    r"""['"]([a-zA-Z0-9_.\-]+):([a-zA-Z0-9_.\-]+):([^'"]+)['"]"""
)
RE_MUTABLE_VERSION = re.compile(
    r"""['"][^'"]+:[^'"]+:(?:[^'"]*\+|latest\.[a-z]+|[^'"]*-SNAPSHOT)['"]"""
)
RE_DEP_CONFIG = re.compile(
    r"^\s*(implementation|api|compileOnly|runtimeOnly|debugImplementation"
    r"|releaseImplementation|testImplementation|androidTestImplementation"
    r"|annotationProcessor|kapt|ksp)\s*[\s(]"
)
RE_DEBUG_ONLY_LIB = re.compile(
    r"(?i)(leakcanary|flipper|chucker|stetho|kotlinx-coroutines-debug|hyperion)"
)


def check_dependencies(root: str, report: Report):
    coords = set()
    for path in walk_project(root):
        base = os.path.basename(path)
        if not (base.startswith("build.gradle") or base.endswith(".versions.toml")):
            continue
        text = read_text(path)

        for g, a, v in RE_COORD.findall(text):
            if "." in g or "-" in a:
                coords.add(f"{g}:{a}:{v}")

        for lineno, line in lines_matching(text, RE_MUTABLE_VERSION):
            report.add(
                "MEDIUM",
                "Mutable dependency version",
                "A dynamic version (+, latest.release) or a -SNAPSHOT resolves "
                "differently over time, so the shipped code can change with no "
                "commit. Pin exact versions: " + line[:160],
                rel(root, path), lineno, "section 5.4.5",
            )

        for lineno, line in lines_matching(text, RE_DEBUG_ONLY_LIB):
            if RE_DEP_CONFIG.match(line) and not line.lstrip().startswith("debug"):
                report.add(
                    "HIGH",
                    "Debug-oriented library on a shipping configuration",
                    "This library is intended for debugImplementation only. On "
                    "`implementation` it is packaged into the release APK, "
                    "frequently with a listening socket or an interception hook: "
                    + line[:160],
                    rel(root, path), lineno, "section 5.3.3",
                )

    report.facts["declaredCoordinates"] = sorted(coords)
    report.facts["declaredCoordinateCount"] = len(coords)

    verification = os.path.join(root, "gradle", "verification-metadata.xml")
    if not os.path.exists(verification):
        report.add(
            "MEDIUM",
            "No dependency verification metadata",
            "gradle/verification-metadata.xml is absent, so no artefact is "
            "pinned by checksum or signature and any resolved dependency may be "
            "silently substituted. Generate it from a known-good state with "
            "`./gradlew --write-verification-metadata sha256,pgp help` and "
            "review the result in a pull request.",
            "gradle/verification-metadata.xml", 0, "section 5.4.2",
        )
    else:
        report.facts["dependencyVerification"] = True


# --------------------------------------------------------------------------
# Check 8 — R8 keep rules that defeat obfuscation
# --------------------------------------------------------------------------

RE_BROAD_KEEP = re.compile(
    r"^\s*-keep(?:class)?\s+class\s+\*\*\s*(\{\s*\*\s*;?\s*\}|$)"
)
RE_DISABLE = re.compile(r"^\s*-(dontobfuscate|dontshrink|dontoptimize)\b")


def check_keep_rules(root: str, report: Report):
    for path in walk_project(root):
        if not (path.endswith(".pro")
                or os.path.basename(path).startswith("proguard")):
            continue
        text = read_text(path)
        for lineno, line in lines_matching(text, RE_BROAD_KEEP):
            report.add(
                "MEDIUM",
                "Keep rule matches every class",
                "`-keep class ** { *; }` disables shrinking and obfuscation "
                "app-wide in a single line: " + line[:160],
                rel(root, path), lineno, "section 3.15",
            )
        for lineno, line in lines_matching(text, RE_DISABLE):
            report.add(
                "MEDIUM",
                "R8 feature explicitly disabled",
                line[:160],
                rel(root, path), lineno, "section 3.15",
            )

    report.add(
        "INFO",
        "Verify the MERGED R8 configuration, not just proguard-rules.pro",
        "Every AAR may ship consumer-rules.pro / proguard.txt that AGP merges "
        "silently. After a build, read "
        "app/build/outputs/mapping/release/configuration.txt — one dependency "
        "can disable obfuscation for the whole application.",
        "app/build/outputs/mapping/release/configuration.txt", 0, "section 4.5",
    )


# --------------------------------------------------------------------------
# Check 9 — native build hardening
# --------------------------------------------------------------------------

HARDENING_FLAGS = {
    "-fstack-protector-strong": "stack canaries",
    "_FORTIFY_SOURCE": "fortified string/memory functions",
    "-Wl,-z,relro": "RELRO",
    "-Wl,-z,now": "immediate binding (full RELRO)",
}


def check_native(root: str, report: Report):
    cmake = [p for p in walk_project(root)
             if os.path.basename(p) == "CMakeLists.txt"]
    if not cmake:
        report.facts["nativeBuild"] = False
        return

    report.facts["nativeBuild"] = True
    combined = "\n".join(read_text(p) for p in cmake)
    gradle_native = "\n".join(
        read_text(p) for p in walk_project(root)
        if os.path.basename(p).startswith("build.gradle")
    )
    haystack = combined + "\n" + gradle_native

    missing = [desc for flag, desc in HARDENING_FLAGS.items()
               if flag not in haystack]
    if missing:
        report.add(
            "LOW",
            "Native build does not explicitly enable some hardening flags",
            "Not found in CMakeLists.txt or the Gradle native configuration: "
            + ", ".join(missing) +
            ". Some are NDK defaults depending on toolchain version — verify "
            "against the shipped .so files with readelf rather than concluding "
            "from build files alone.",
            rel(root, cmake[0]), 0, "section 3.17",
        )


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def print_report(report: Report, min_severity: str, use_colour: bool):
    threshold = SEVERITY_ORDER[min_severity]
    shown = [f for f in report.findings
             if SEVERITY_ORDER[f.severity] >= threshold]
    shown.sort(key=lambda f: -SEVERITY_ORDER[f.severity])

    def c(sev, s):
        if not use_colour:
            return s
        return f"{COLOURS[sev]}{s}{COLOURS['RESET']}"

    print()
    print("=" * 78)
    print(f"  Gradle build audit — {report.project}")
    print("=" * 78)

    print("\n-- Facts ---------------------------------------------------------")
    for k, v in report.facts.items():
        if isinstance(v, list) and len(v) > 8:
            print(f"  {k}: {len(v)} entries (see --json output)")
        else:
            print(f"  {k}: {v}")

    print(f"\n-- Findings ({len(shown)} at {min_severity}+) --------------------")
    if not shown:
        print("  none")
    for f in shown:
        print()
        print(f"  [{c(f.severity, f.severity)}] {f.title}")
        print(f"      file : {f.path}" + (f":{f.line}" if f.line else ""))
        print(f"      ref  : ../README.md {f.reference}" if f.reference else "")
        for line in _wrap(f.detail, 68):
            print(f"      {line}")

    counts = {}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    print("\n-- Summary -------------------------------------------------------")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in counts:
            print(f"  {c(sev, sev):<20} {counts[sev]}")
    print()
    print("  Every finding is a CANDIDATE. Read ../README.md section 5.3 for the")
    print("  severity reasoning before any of this reaches a report. This tool")
    print("  cannot distinguish a real credential from a public identifier.")
    print()

    return len(shown)


def _wrap(text: str, width: int):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return out


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Static security audit of an Android Gradle project. "
                    "Never executes the build."
    )
    ap.add_argument("project", help="path to the Android project root")
    ap.add_argument("--json", metavar="FILE",
                    help="also write the full report as JSON")
    ap.add_argument("--min-severity", default="INFO",
                    choices=list(SEVERITY_ORDER.keys()),
                    help="minimum severity to print (default INFO)")
    ap.add_argument("--no-colour", action="store_true")
    args = ap.parse_args()

    root = os.path.abspath(args.project)
    if not os.path.isdir(root):
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    report = Report(project=root)

    check_repositories(root, report)
    check_wrapper(root, report)
    check_build_logic(root, report)
    check_release_hardening(root, report)
    check_secrets(root, report)
    check_injected_config(root, report)
    check_dependencies(root, report)
    check_keep_rules(root, report)
    check_native(root, report)

    use_colour = (not args.no_colour) and sys.stdout.isatty()
    shown = print_report(report, args.min_severity, use_colour)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "project": report.project,
                    "facts": report.facts,
                    "findings": [asdict(f) for f in report.findings],
                },
                fh, indent=2,
            )
        print(f"  JSON report written to {args.json}\n")

    return 1 if shown else 0


if __name__ == "__main__":
    sys.exit(main())
