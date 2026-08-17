#!/usr/bin/env python3
# scripts/proguard-rules-audit.py
#
# PURPOSE
#   Read a ProGuard/R8 rules file -- proguard-rules.pro, consumer-rules.pro, a
#   library's META-INF/proguard/*.pro, or the merged configuration.txt that R8
#   itself writes -- and answer three questions about every directive in it:
#
#     1. WHAT does this rule actually preserve?  Names only, or names and
#        bodies? Classes only, or members too? Does it also disable shrinking
#        and optimisation for what it matches?
#     2. HOW BROAD is it?  A rule that matches one class is a decision. A rule
#        that matches every class in the application is a surrender.
#     3. WHAT IS MISSING?  The directives whose ABSENCE is the finding --
#        no -printmapping, no -renamesourcefileattribute next to a
#        -keepattributes SourceFile, and so on.
#
#   The output is ranked, and every line explains itself. This is a reading
#   aid, not a linter that you silence.
#
# USAGE
#   # host -- audit one file
#   python3 -B scripts/proguard-rules-audit.py app/proguard-rules.pro
#
#   # host -- audit several, including everything a build actually fed to R8
#   python3 -B scripts/proguard-rules-audit.py \
#       app/proguard-rules.pro \
#       app/build/outputs/mapping/release/configuration.txt
#
#   # host -- audit every rules file shipped inside an AAR or a JAR
#   unzip -o lib.aar -d lib_ext >/dev/null
#   python3 -B scripts/proguard-rules-audit.py lib_ext/proguard.txt
#
#   # host -- machine-readable, for a pipeline
#   python3 -B scripts/proguard-rules-audit.py rules.pro --json
#
#   # host -- only the findings at or above a severity
#   python3 -B scripts/proguard-rules-audit.py rules.pro --min-severity HIGH
#
#   Exit status: 0 if nothing at or above --fail-on (default: never fail),
#   1 if something was found, 2 on a usage or parse error.
#
# REQUIREMENTS
#   Python 3.8+. No third-party packages, no network, no Android SDK.
#   Run with `python3 -B` so no __pycache__ directory is created next to the
#   script -- this repository treats build artefacts as a defect.
#
# WHAT THIS WILL *NOT* TELL YOU
#   * It will NOT tell you whether a rule is NECESSARY. Only the running app
#     can tell you that. A rule this script rates CRITICAL may be the only
#     thing standing between you and a ClassNotFoundException in production.
#     The finding is "this rule is broader than its justification", and you
#     supply the justification.
#   * It does NOT see your dependencies' rules. Every AAR may ship a
#     consumer-rules.pro that AGP merges into the build without it ever
#     appearing in your file. Audit
#     app/build/outputs/mapping/<variant>/configuration.txt to see the real,
#     merged set -- that file is R8's own record of everything it was given.
#   * It does NOT see AGP's generated rules either: the manifest-derived keeps
#     in build/intermediates/aapt_proguard_file/, the AndroidX defaults, or
#     the contents of proguard-android-optimize.txt. Again: configuration.txt.
#   * It does NOT know which classes your rules match. A pattern that looks
#     narrow can match half the app; a pattern that looks broad can match
#     nothing at all. Feed the built APK to scripts/what-survived.py to find
#     out what was really preserved.
#   * It does NOT verify semantics against a real ProGuard or R8. The two
#     engines disagree on several rules -- notably R8 full mode's treatment of
#     default constructors under -keep, and -assumenosideeffects, which R8
#     honours much more aggressively. Where this matters the note says so.
#   * "No findings" is NOT a pass. A rules file can be perfectly narrow and
#     still keep the one class that mattered.
#
# The severities are hardening severities. Absent or weak obfuscation is not a
# vulnerability; see the chapter README section 5.6 before you write any of
# this into a report.

import argparse
import json
import os
import re
import sys

# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def sev_at_least(sev, floor):
    return SEVERITY_ORDER[sev] >= SEVERITY_ORDER[floor]


# --------------------------------------------------------------------------- #
# The keep family, and what each member actually preserves.
#
# Three independent things can be preserved, and the confusion between them is
# the single biggest source of wrong rules:
#
#   PRESENCE   the entity is not removed by tree shaking
#   NAME       the entity is not renamed by the obfuscator
#   SHAPE      the entity is not altered by the optimiser (inlined, merged,
#              had its arguments removed, had its class merged into another)
#
# -keep      preserves all three, for the class AND for whatever members the
#            member specification names.
# -keepnames preserves NAME only, and only IF the entity survives shrinking.
#            It is exactly `-keep,allowshrinking`.
# --------------------------------------------------------------------------- #
KEEP_DIRECTIVES = {
    "keep": {
        "applies_to": "class + named members",
        "presence": True,
        "name": True,
        "meaning": "Class is not removed, not renamed. Members matched by the "
                   "member specification are also not removed and not renamed.",
    },
    "keepclassmembers": {
        "applies_to": "named members only",
        "presence": False,
        "name": True,
        "meaning": "Does NOT keep the class. If the class survives on its own "
                   "merits, the matched members are kept and unrenamed. If "
                   "nothing references the class, the class still goes.",
    },
    "keepclasseswithmembers": {
        "applies_to": "class + named members, conditionally",
        "presence": True,
        "name": True,
        "meaning": "Keeps the class AND the matched members, but ONLY for "
                   "classes that possess all the named members. A conditional "
                   "-keep with the condition on the class's own shape.",
    },
    "keepnames": {
        "applies_to": "class name only",
        "presence": False,
        "name": True,
        "meaning": "Shorthand for -keep,allowshrinking. The class may still be "
                   "removed if unused; if it survives, its name is unchanged.",
    },
    "keepclassmembernames": {
        "applies_to": "member names only",
        "presence": False,
        "name": True,
        "meaning": "Shorthand for -keepclassmembers,allowshrinking. Members "
                   "may be removed; survivors keep their names.",
    },
    "keepclasseswithmembernames": {
        "applies_to": "class + member names, conditionally",
        "presence": False,
        "name": True,
        "meaning": "Shorthand for -keepclasseswithmembers,allowshrinking. The "
                   "canonical use is the native-method rule: keep the NAME of "
                   "any class that has a native method, because the JNI symbol "
                   "is derived from it.",
    },
}

KEEP_MODIFIERS = {
    "allowshrinking": "the entity MAY still be removed if nothing uses it; only its name is protected",
    "allowobfuscation": "the entity MAY still be renamed; only its presence is protected",
    "allowoptimization": "the entity MAY still be inlined, merged or reshaped; presence and name are protected",
    "allowaccessmodification": "access modifiers on the entity may be widened (needed by -allowaccessmodification globally)",
    "includedescriptorclasses": "classes named in the kept members' signatures are kept and unrenamed too",
    "includecode": "the CODE of matched methods is preserved unchanged, not just the method",
}

# Global on/off directives, and what turning them on costs.
GLOBAL_DIRECTIVES = {
    "dontshrink": (
        "HIGH",
        "Tree shaking is OFF for the whole build. Every unused class, method and "
        "field ships -- including dead debug helpers, unreferenced test constants "
        "and abandoned code paths. This is the setting that leaves staging tokens "
        "in release APKs.",
    ),
    "dontobfuscate": (
        "MEDIUM",
        "Renaming is OFF for the whole build. Every original class, method and "
        "field name ships. Almost always added to make crash reports readable; "
        "the correct fix for that is -keepattributes SourceFile,LineNumberTable "
        "plus -renamesourcefileattribute, which keeps traces resolvable through "
        "mapping.txt without publishing the names.",
    ),
    "dontoptimize": (
        "LOW",
        "Optimisation is OFF. Not a security setting on its own -- R8's "
        "optimiser is a size and speed pass -- but its output is also the thing "
        "that makes decompiled code hard to read, so disabling it makes the app "
        "meaningfully easier to follow. Often inherited by using "
        "proguard-android.txt instead of proguard-android-optimize.txt.",
    ),
    "dontpreverify": (
        "INFO",
        "A no-op on Android. Preverification is a J2ME/Java-6 concept; DEX has "
        "no preverify step. Its presence is a reliable tell that the rules file "
        "was copied from a Java desktop project or from a very old tutorial.",
    ),
    "dontusemixedcaseclassnames": (
        "INFO",
        "Forces lower-case-only generated names. Historically needed for "
        "case-insensitive filesystems when unpacking JARs; harmless on Android, "
        "and another copy-from-2012 tell.",
    ),
    "dontnote": (
        "LOW",
        "Suppresses ProGuard/R8 notes. Notes are where 'your rule matched "
        "nothing' and 'this class is referenced reflectively' are reported. "
        "Silencing them globally hides the feedback that would let you narrow "
        "your rules.",
    ),
    "ignorewarnings": (
        "MEDIUM",
        "Turns every missing-class ERROR into a warning and continues. A missing "
        "class usually means a dependency is incomplete; at runtime it becomes "
        "NoClassDefFoundError on a code path nobody tested.",
    ),
    "verbose": ("INFO", "Diagnostic only."),
    "overloadaggressively": (
        "INFO",
        "Renames members so that different types share a name (a(String) and "
        "a(byte[])). Increases reader confusion slightly; known to break "
        "reflection and some serialisation libraries. R8 does not implement it.",
    ),
    "allowaccessmodification": (
        "INFO",
        "Lets the optimiser widen access modifiers so it can inline across "
        "class boundaries. Enabled by proguard-android-optimize.txt. Makes "
        "output harder to read, which is a side effect and not a control.",
    ),
    "repackageclasses": (
        "INFO",
        "Moves every renamed class into a single package. Genuinely raises "
        "reading cost: the package structure -- which often survives renaming "
        "and tells you the app's architecture -- is flattened away.",
    ),
    "flattenpackagehierarchy": (
        "INFO",
        "Weaker sibling of -repackageclasses; collapses the package hierarchy "
        "into one level rather than one package.",
    ),
    "renamesourcefileattribute": (
        "INFO",
        "Overwrites every SourceFile attribute with one constant string. This is "
        "the correct companion to -keepattributes SourceFile,LineNumberTable: "
        "line numbers stay resolvable through mapping.txt, original filenames do "
        "not ship.",
    ),
    "printmapping": (
        "INFO",
        "Writes mapping.txt. Under AGP this is set for you and the file lands in "
        "app/build/outputs/mapping/<variant>/. The file is a BUILD ARTEFACT: it "
        "must never be packaged into the APK and must never be committed.",
    ),
    "printseeds": ("INFO", "Writes seeds.txt: every entity matched by a -keep rule. The best single artefact for auditing your own rules."),
    "printusage": ("INFO", "Writes usage.txt: every entity tree shaking removed."),
    "printconfiguration": ("INFO", "Writes the fully merged configuration, including every library's consumer rules. Read this, not your own file."),
    "keepdirectories": ("INFO", "Preserves directory entries in output archives. Irrelevant to APKs."),
    "adaptclassstrings": (
        "LOW",
        "Rewrites string literals that look like class names when the class they "
        "name is renamed. Fixes some Class.forName cases automatically -- and "
        "silently corrupts any string that merely LOOKS like a class name.",
    ),
    "adaptresourcefilenames": ("INFO", "Renames resource FILES to match renamed classes."),
    "adaptresourcefilecontents": (
        "LOW",
        "Rewrites class names found inside resource file CONTENTS. Powerful and "
        "dangerous: it edits files it does not understand.",
    ),
    "assumenosideeffects": (
        "MEDIUM",
        "Tells the optimiser that calls to the named methods may be deleted. The "
        "usual target is android.util.Log. R8 applies this far more "
        "aggressively than ProGuard did, and it applies to the RETURN VALUE too "
        "-- a method assumed side-effect-free whose result is used can be "
        "replaced with a constant. Getting this wrong deletes code you needed.",
    ),
    "assumenoexternalsideeffects": ("LOW", "As above, restricted to effects outside the method's own object."),
    "assumevalues": ("MEDIUM", "Tells the optimiser a field or method always returns a given value or range. Wrong assumptions here delete live branches -- including security checks."),
    "whyareyoukeeping": ("INFO", "Diagnostic: prints the shortest reason chain that keeps a matched entity. The single most useful directive for narrowing a rules file."),
    "optimizations": ("INFO", "Selects which optimisation passes run. R8 ignores it."),
    "optimizationpasses": ("INFO", "Number of optimiser passes. R8 ignores it."),
    "injars": ("INFO", "Input specification. Never appears in an Android app's rules file; AGP supplies inputs itself."),
    "outjars": ("INFO", "Output specification. As above."),
    "libraryjars": ("INFO", "Library classpath. Under AGP this is android.jar and your dependencies, supplied automatically."),
    "target": ("INFO", "Java class-file version target. Irrelevant under AGP."),
    "forceprocessing": ("INFO", "Reprocess even if outputs look up to date."),
    "skipnonpubliclibraryclasses": ("INFO", "Legacy speed option. Breaks builds more often than it helps; ProGuard's own manual advises against it."),
    "dontskipnonpubliclibraryclasses": ("INFO", "The default since ProGuard 4.5. Another copy-from-an-old-template tell."),
    "dontskipnonpubliclibraryclassmembers": ("INFO", "As above."),
    "microedition": ("INFO", "J2ME target. Meaningless on Android."),
    "android": ("INFO", "Tells ProGuard it is targeting Android. R8 ignores it; it is always true under AGP."),
}

# Attributes, and why each one matters when kept.
ATTRIBUTES = {
    "Signature": "Generic type information. GSON's TypeToken, Retrofit's return types and Kotlin's reified generics all read it. Dropping it turns a List<User> into a raw List and deserialisation quietly returns LinkedTreeMap.",
    "SourceFile": "The original .java/.kt filename. Kept ALONE it publishes your source tree's filenames; kept together with -renamesourcefileattribute it is overwritten with a constant and is safe.",
    "LineNumberTable": "Maps bytecode offsets to source lines. Required for a resolvable stack trace. Safe to keep as long as SourceFile is renamed.",
    "LocalVariableTable": "Original local variable NAMES. Debug information. It should not be in a release build; if it is, decompiled output reads almost like source.",
    "LocalVariableTypeTable": "As above, with generic types.",
    "Exceptions": "The declared throws clause. Needed for correct reflection over methods and for some proxy generators.",
    "InnerClasses": "Needed for Class.getSimpleName() and for the inner/outer relationship to survive.",
    "EnclosingMethod": "Needed for anonymous and local classes to report their enclosing context.",
    "Deprecated": "Cosmetic.",
    "Synthetic": "Marks compiler-generated members.",
    "RuntimeVisibleAnnotations": "Class-level annotations readable at runtime. Retrofit's @GET, Room's @Entity, GSON's @SerializedName all live here.",
    "RuntimeVisibleParameterAnnotations": "Parameter annotations. Retrofit's @Path, @Query, @Body.",
    "RuntimeVisibleTypeAnnotations": "Type-use annotations.",
    "RuntimeInvisibleAnnotations": "Annotations not readable at runtime. Rarely needed.",
    "RuntimeInvisibleParameterAnnotations": "As above.",
    "RuntimeInvisibleTypeAnnotations": "As above.",
    "AnnotationDefault": "Default values of annotation members. Needed if you define your own annotations with defaults.",
    "MethodParameters": "Parameter NAMES. Debug-grade information; keeping it hands an analyst the developer's own vocabulary.",
    "EnclosingMethod,InnerClasses": "(compound form)",
}

# Package prefixes whose appearance in an app's own rules file usually means a
# copy-paste rather than a decision.
FRAMEWORK_PREFIXES = (
    "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.",
    "com.google.android.", "org.jetbrains.",
)


class Rule:
    """One parsed directive."""

    __slots__ = ("directive", "modifiers", "class_spec", "members", "line",
                 "raw", "source")

    def __init__(self, directive, modifiers, class_spec, members, line, raw, source):
        self.directive = directive
        self.modifiers = modifiers
        self.class_spec = class_spec
        self.members = members
        self.line = line
        self.raw = raw
        self.source = source


def strip_comments(text):
    """Remove # comments, preserving line structure so line numbers stay true."""
    out = []
    for ln in text.splitlines():
        h = ln.find("#")
        out.append(ln if h < 0 else ln[:h])
    return "\n".join(out)


DIRECTIVE_RE = re.compile(r"^\s*-([A-Za-z]+)([^\n{]*)", re.M)


def parse(text, source):
    """
    Parse a rules file into Rule objects.

    The grammar is line-oriented with one wrinkle: a class specification may be
    followed by a brace-delimited member specification that spans lines. The
    parser below walks the file once, finds each directive, and if a '{' follows
    the directive's own line before the next directive, consumes to the matching
    '}'.
    """
    clean = strip_comments(text)
    rules = []
    pos = 0
    lines_before = clean.count("\n", 0, 0)
    for m in DIRECTIVE_RE.finditer(clean):
        if m.start() < pos:
            continue
        directive = m.group(1)
        tail = m.group(2)
        end = m.end()
        members = None
        # Does a member block follow? Look ahead past whitespace only.
        look = end
        while look < len(clean) and clean[look] in " \t\r\n":
            look += 1
        if look < len(clean) and clean[look] == "{":
            depth = 0
            i = look
            while i < len(clean):
                if clean[i] == "{":
                    depth += 1
                elif clean[i] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            members = clean[look + 1:i]
            end = i + 1
        pos = end
        lineno = clean.count("\n", 0, m.start()) + 1
        raw = clean[m.start():end].strip()
        mods = []
        spec = tail.strip()
        if spec.startswith(","):
            head, _, rest = spec.partition(" ")
            mods = [x for x in head.split(",") if x]
            spec = rest.strip()
        rules.append(Rule(directive, mods, spec, members, lineno, raw, source))
    _ = lines_before
    return rules


# --------------------------------------------------------------------------- #
# Breadth analysis
# --------------------------------------------------------------------------- #
def class_pattern(spec):
    """
    Pull the class-name pattern out of a class specification, discarding
    annotations, access modifiers, the class/interface/enum keyword, and any
    extends/implements clause.
    """
    s = spec.strip()
    s = re.sub(r"^@\S+\s*", "", s)
    s = re.sub(r"^(?:!?(?:public|final|abstract|static|synthetic|private|protected)\s+)*", "", s)
    s = re.sub(r"^(class|interface|enum|@interface)\s+", "", s)
    s = re.split(r"\s+(?:extends|implements)\s+", s)[0]
    return s.strip()


def breadth(pattern):
    """
    Score how much of an application a class pattern can match.

    The three wildcards are NOT interchangeable and this is the distinction the
    whole audit turns on:

        *    matches any part of a name, but NOT the package separator '.'
        **   matches any part of a name INCLUDING '.', so it crosses packages
        ***  matches any TYPE, including arrays -- it is a type wildcard, used
             in member signatures, not a name wildcard

    A pattern of `com.app.*` therefore matches one package's classes; the same
    pattern with `**` matches that package and every package beneath it.
    """
    p = pattern.strip()
    if not p:
        return 100, "empty pattern -- matches every class"
    if p in ("*", "**", "***"):
        return 100, "matches EVERY class in the program, including all libraries"
    segs = [s for s in p.split(".") if s]
    concrete = [s for s in segs if "*" not in s and "?" not in s]
    if "**" in p:
        depth = len(concrete)
        if depth == 0:
            return 100, "matches every class"
        if depth == 1:
            return 90, "one concrete package segment before a '**' -- matches an entire top-level namespace"
        if depth == 2:
            return 75, "two concrete segments before a '**' -- typically a whole vendor namespace"
        return 55, "'**' crosses package boundaries: this matches the named package AND every package beneath it"
    if "*" in p:
        if p.endswith(".*"):
            return 40, "'*' does not cross '.', so this matches one package's classes but not its subpackages"
        return 30, "wildcard within a name"
    return 5, "a single named class"


def member_breadth(members):
    """How much of a class's surface a member specification covers."""
    if members is None:
        return 0, "no member specification -- the class itself is kept, its members are not"
    m = members.strip()
    if not m:
        return 0, "empty member block -- equivalent to no member specification"
    entries = [e.strip() for e in m.split(";") if e.strip()]
    if any(e == "*" for e in entries):
        return 100, "'*;' keeps EVERY field and EVERY method, reachable or not"
    if any(e in ("<methods>", "<fields>") for e in entries):
        return 70, "<methods>/<fields> keeps every method or every field of the matched classes"
    if any(e.startswith("@") for e in entries):
        return 60, "annotation-driven member keep -- breadth depends entirely on how widely the annotation is used"
    if any("*" in e for e in entries):
        return 45, "wildcarded member names"
    return 10, "explicitly named members"


def analyse_rule(r):
    """Return (severity, headline, explanation lines) for one keep-family rule."""
    info = KEEP_DIRECTIVES[r.directive]
    pat = class_pattern(r.class_spec)
    cb, cwhy = breadth(pat)
    mb, mwhy = member_breadth(r.members)

    notes = []
    notes.append("preserves: " + info["applies_to"])
    notes.append(info["meaning"])
    notes.append("class pattern '%s': %s" % (pat or "(none)", cwhy))
    notes.append("members: " + mwhy)

    for mod in r.modifiers:
        notes.append("modifier ,%s -- %s" % (mod, KEEP_MODIFIERS.get(mod, "unrecognised modifier")))

    # Framework namespaces in an app's own file.
    if any(pat.startswith(fp) for fp in FRAMEWORK_PREFIXES):
        notes.append(
            "targets a framework/library namespace. Under AGP these keeps are "
            "usually supplied already, by proguard-android.txt or by the "
            "library's own consumer rules. Check configuration.txt before "
            "keeping this line.")

    score = cb + (mb * 0.6)
    if r.directive in ("keepnames", "keepclassmembernames", "keepclasseswithmembernames"):
        # Name-only rules cannot defeat shrinking, so their ceiling is lower.
        score *= 0.55
        notes.append(
            "this is a NAME-only rule: it cannot prevent shrinking, so it "
            "cannot leave dead code in the APK. Its cost is readability only.")

    members_only = r.directive in ("keepclassmembers", "keepclassmembernames")
    if score >= 130:
        sev = "CRITICAL"
        head = ("over-broad member keep: applied to every class in the program"
                if members_only else
                "over-broad keep: this rule alone can defeat shrinking, renaming "
                "and optimisation for a whole namespace")
    elif score >= 95:
        sev = "HIGH"
        head = "very broad keep"
    elif score >= 60:
        sev = "MEDIUM"
        head = "broad keep -- narrow it if you can name what needs keeping"
    elif score >= 30:
        sev = "LOW"
        head = "moderately scoped keep"
    else:
        sev = "INFO"
        head = "narrowly scoped keep"

    # The specific shapes worth calling out by name.
    if "**" in pat and mb >= 100 and r.directive in ("keep", "keepclasseswithmembers"):
        sev = "CRITICAL"
        head = ("'-%s class %s { *; }' -- the canonical rules-file defect. '**' "
                "crosses package separators, so every class in that namespace "
                "and every namespace beneath it keeps its name, every one of "
                "its members, and every line of its dead code. Shrinking, "
                "renaming and optimisation are all disabled for the matched "
                "set." % (r.directive, pat))
    elif cb >= 90 and mb >= 100:
        sev = "CRITICAL"
        head = ("'-%s class %s { *; }' matches an entire namespace and keeps "
                "every member of every class in it." % (r.directive, pat))
    if pat in ("*", "**") and r.directive == "keep":
        sev = "CRITICAL"
        head = "keeps every class in the program. Minification is switched on and doing nothing."

    return sev, head, notes


# --------------------------------------------------------------------------- #
# Whole-file checks: the findings that come from what is NOT there
# --------------------------------------------------------------------------- #
def analyse_file(rules, findings):
    seen = {}
    for r in rules:
        seen.setdefault(r.directive, []).append(r)

    attrs = []
    for r in seen.get("keepattributes", []):
        attrs.extend([a.strip() for a in r.class_spec.replace(" ", ",").split(",") if a.strip()])

    default_source = rules[0].source if rules else "(no file)"

    def add(sev, code, msg, line=0, source=None):
        source = default_source if source is None else source
        findings.append({"severity": sev, "code": code, "message": msg,
                         "line": line, "source": source, "kind": "file"})

    # -keepattributes *
    for r in seen.get("keepattributes", []):
        if r.class_spec.strip() in ("*", "**"):
            add("HIGH", "ATTRS_ALL",
                "-keepattributes * retains EVERY attribute, including "
                "LocalVariableTable and LocalVariableTypeTable when they are "
                "present. Those carry the developer's own local variable names, "
                "and decompiled output with them reads very close to source. "
                "Name the attributes you need.",
                r.line, r.source)

    if "SourceFile" in attrs and "renamesourcefileattribute" not in seen:
        add("MEDIUM", "SOURCEFILE_UNRENAMED",
            "-keepattributes SourceFile is present but -renamesourcefileattribute "
            "is not. The original .java and .kt filenames therefore ship inside "
            "the DEX, one per class. jadx will use them to name classes "
            "(--use-source-name-as-class-name-alias), which recovers a large part "
            "of what renaming removed. Add: -renamesourcefileattribute SourceFile")

    if any(a in attrs for a in ("LocalVariableTable", "LocalVariableTypeTable")):
        add("HIGH", "ATTRS_LOCALS",
            "LocalVariableTable / LocalVariableTypeTable are kept. These are "
            "DEBUG attributes carrying original local variable names. They "
            "should not be in a release build at all.")

    for name in ("dontshrink", "dontobfuscate", "dontoptimize", "dontpreverify",
                 "dontusemixedcaseclassnames", "ignorewarnings", "dontnote",
                 "overloadaggressively", "adaptclassstrings",
                 "adaptresourcefilecontents", "assumenosideeffects",
                 "assumevalues", "skipnonpubliclibraryclasses",
                 "dontskipnonpubliclibraryclasses"):
        for r in seen.get(name, []):
            sev, msg = GLOBAL_DIRECTIVES.get(name, ("INFO", ""))
            add(sev, "GLOBAL_" + name.upper(), "-%s: %s" % (name, msg), r.line, r.source)

    # -dontwarn breadth
    for r in seen.get("dontwarn", []):
        spec = r.class_spec.strip()
        if spec in ("", "*", "**"):
            add("MEDIUM", "DONTWARN_ALL",
                "-dontwarn with no argument (or '**') silences EVERY "
                "missing-class warning in the build. Those warnings are how you "
                "learn that a dependency is incomplete; at runtime the same "
                "condition is a NoClassDefFoundError. Scope each -dontwarn to "
                "the package that actually warns, and leave a comment saying why.",
                r.line, r.source)

    if "printmapping" not in seen:
        add("INFO", "NO_PRINTMAPPING",
            "No -printmapping in this file. Under AGP that is normal -- the "
            "plugin sets it and mapping.txt lands in "
            "app/build/outputs/mapping/<variant>/. Outside AGP, a build with no "
            "-printmapping produces an app whose crash reports cannot be "
            "de-obfuscated at all.")

    if "printseeds" not in seen and "printconfiguration" not in seen:
        add("INFO", "NO_PRINTSEEDS",
            "Neither -printseeds nor -printconfiguration is set. seeds.txt lists "
            "every entity your keep rules matched and is the fastest way to see "
            "that a rule is broader than you meant. Add both while you are "
            "narrowing rules, then remove them.")

    # Rules that are duplicated verbatim.
    counts = {}
    for r in rules:
        counts.setdefault(re.sub(r"\s+", " ", r.raw), []).append(r)
    for raw, group in counts.items():
        if len(group) > 1 and raw.startswith("-keep"):
            add("LOW", "DUPLICATE",
                "the same rule appears %d times (lines %s). Duplicates are "
                "harmless to the build and are a reliable sign the file has "
                "been edited by accretion rather than by decision."
                % (len(group), ", ".join(str(g.line) for g in group)),
                group[0].line, group[0].source)

    return findings


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
COLOURS = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
           "LOW": "\033[36m", "INFO": "\033[90m"}
RESET = "\033[0m"


def colour(sev, use):
    return (COLOURS[sev] + sev + RESET) if use else sev


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit a ProGuard/R8 rules file: what each rule preserves, "
                    "how broad it is, and what is missing.")
    ap.add_argument("files", nargs="+", help="one or more .pro / .txt rules files")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("--min-severity", default="INFO",
                    choices=list(SEVERITY_ORDER), help="hide findings below this")
    ap.add_argument("--fail-on", default=None, choices=list(SEVERITY_ORDER),
                    help="exit 1 if any finding is at or above this severity")
    ap.add_argument("--no-colour", action="store_true")
    args = ap.parse_args(argv)

    use_colour = (not args.no_colour) and sys.stdout.isatty()

    all_rules = []
    for path in args.files:
        if not os.path.isfile(path):
            sys.stderr.write("error: no such file: %s\n" % path)
            return 2
        with open(path, "rb") as fh:
            raw = fh.read()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
            sys.stderr.write("warning: %s is not valid UTF-8; decoded as latin-1\n" % path)
        all_rules.extend(parse(text, path))

    findings = []
    unknown = []
    for r in all_rules:
        if r.directive in KEEP_DIRECTIVES:
            sev, head, notes = analyse_rule(r)
            findings.append({"severity": sev, "code": "KEEP_" + r.directive.upper(),
                             "message": head, "line": r.line, "source": r.source,
                             "kind": "rule", "rule": r.raw.split("\n")[0][:120],
                             "notes": notes})
        elif r.directive in GLOBAL_DIRECTIVES or r.directive in (
                "keepattributes", "keepparameternames", "dontwarn",
                "whyareyoukeeping", "assumenosideeffects"):
            pass  # handled in analyse_file, or purely informational
        else:
            unknown.append(r)

    analyse_file(all_rules, findings)

    for r in unknown:
        findings.append({"severity": "LOW", "code": "UNKNOWN_DIRECTIVE",
                         "message": "-%s is not a directive this auditor knows. "
                                    "Check the spelling: ProGuard and R8 both "
                                    "ERROR on an unknown directive, so if your "
                                    "build succeeds, one of us is out of date."
                                    % r.directive,
                         "line": r.line, "source": r.source, "kind": "rule",
                         "rule": r.raw.split("\n")[0][:120], "notes": []})

    findings = [f for f in findings if sev_at_least(f["severity"], args.min_severity)]
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["source"], f["line"]))

    if args.json:
        print(json.dumps({"files": args.files,
                          "rules_parsed": len(all_rules),
                          "findings": findings}, indent=2))
    else:
        print("=" * 78)
        print("ProGuard/R8 rules audit")
        for p in args.files:
            print("  file: %s" % p)
        print("  directives parsed: %d" % len(all_rules))
        print("=" * 78)
        if not findings:
            print("\nNo findings at or above %s." % args.min_severity)
            print("That is not a pass. Read the WHAT THIS WILL NOT TELL YOU header.")
        for f in findings:
            loc = "%s:%d" % (os.path.basename(f["source"]), f["line"]) if f["line"] else os.path.basename(f["source"])
            print("\n[%s] %s  (%s)" % (colour(f["severity"], use_colour), f["code"], loc))
            if f.get("rule"):
                print("    rule: %s" % f["rule"])
            for line in wrap(f["message"], 74, "    "):
                print(line)
            for n in f.get("notes", []):
                for line in wrap("- " + n, 72, "      "):
                    print(line)

        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        print("\n" + "-" * 78)
        print("summary: " + ", ".join("%s=%d" % (s, counts.get(s, 0))
                                      for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")))
        print("Severities are HARDENING severities. An over-broad keep is a")
        print("weakened control, not a vulnerability. Report it proportionately.")

    if args.fail_on:
        for f in findings:
            if sev_at_least(f["severity"], args.fail_on):
                return 1
    return 0


def wrap(text, width, indent):
    words = text.split()
    lines, cur = [], indent
    for w in words:
        if len(cur) + len(w) + 1 > width + len(indent) and cur.strip():
            lines.append(cur.rstrip())
            cur = indent + w + " "
        else:
            cur += w + " "
    if cur.strip():
        lines.append(cur.rstrip())
    return lines


if __name__ == "__main__":
    sys.exit(main())
