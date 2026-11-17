#!/usr/bin/env bash
# scripts/build-classic-module.sh
#
# PURPOSE
#   Compile a CLASSIC-API Xposed module, and the specimen Xposed detector, to
#   DEX -- with no network, no Gradle, no Android Studio, and no working Xposed
#   installation anywhere.
#
#   Three reasons this chapter needs it:
#
#     1. IT PROVES THE API IS ALIVE.  examples/ClassicXposedModule.java is
#        written entirely against the API rovo89 froze at version 82. If it
#        compiles and dexes cleanly, the chapter's claim that a 2015 module
#        still builds in 2026 is a measurement rather than an assertion.
#
#     2. IT IS THE GROUND TRUTH FOR THE SCANNER.
#        scripts/xposed-detection-scan.py was validated against 237 real APKs
#        that contain NO Xposed detection code -- a detector validated only on
#        clean samples has not been validated. examples/XposedDetector.java is
#        the positive control, and --ground-truth writes a file recording
#        exactly what the scanner found in it.
#
#     3. IT SHOWS WHAT compileOnly MEANS, MECHANICALLY.  The generated API stub
#        is compiled against and then EXCLUDED from the DEX, which is precisely
#        what Gradle's `compileOnly` does. The DEX therefore REFERENCES
#        de.robv.android.xposed types it does not DEFINE -- and that dangling
#        reference is what makes a module recognisable and what section 8 of
#        the README keys on.
#
# USAGE
#   ./build-classic-module.sh [options]
#
#     --src DIR          Directory of .java sources. Default: ../examples
#     --api-jar PATH     Use a real de.robv.android.xposed:api:82 jar instead
#                        of the generated stub.
#     --out DIR          Build directory. MUST be outside this repository.
#                        Default: ${TMPDIR:-/tmp}/ch64-build
#     --min-api N        d8 --min-api. Default 21 -- deliberately LOW, because
#                        this is a chapter about a framework whose last
#                        supported release was API 27.
#     --with-detector    Also compile examples/XposedDetector.java. It needs
#                        android.jar on the classpath; the script finds one.
#     --disassemble      Run baksmali over the DEX and print the listings the
#                        README quotes.
#     --ground-truth F   Write a machine-checkable record of what the scanner
#                        found, to F. Implies --with-detector.
#     --keep             Do not delete the build directory on exit.
#     -h, --help         This text.
#
# EXAMPLES
#   ./build-classic-module.sh
#   ./build-classic-module.sh --with-detector --disassemble --keep
#   ./build-classic-module.sh --ground-truth /tmp/ch64-ground-truth.txt
#
# REQUIREMENTS
#   javac and java (JDK 11+) on PATH.
#   d8 from the Android SDK build-tools. Found via $D8, $ANDROID_HOME,
#   $ANDROID_SDK_ROOT, or $LOCALAPPDATA/Android/Sdk on Windows.
#   android.jar from any installed platform, for --with-detector.
#   baksmali (apktool ships one under its Resources/) for --disassemble.
#
# WHERE IT BUILDS
#   Into $OUTDIR, default ${TMPDIR:-/tmp}/ch64-build -- OUTSIDE this
#   repository. `.class`, `.jar` and `.dex` are on the artefact blocklist and
#   this repository ships sources only. The script REFUSES to build inside the
#   repository even if you ask it to.
#
# EXECUTION STATUS
#   EXECUTED. Run to completion on the host described in README section 7.1
#   (Windows 11, Git Bash, JDK 24, build-tools 35.0.1) on 2026-08-16. Every
#   number quoted in README section 6 came out of this script.
#
# GIT BASH / MSYS NOTES -- two traps that cost real time elsewhere in this repo
#   1. javac, java and d8 are native Windows binaries and do not understand
#      /c/Users/... paths. Every path handed to them goes through winpath().
#      `cygpath -m` (mixed, forward slashes) is used rather than `-w`, because
#      inside a javac @argfile a backslash is an escape character and the -w
#      form silently mangles every path.
#   2. `set -o pipefail` is NOT used. It turns early-exit consumers -- head,
#      grep -q -- into spurious failures via SIGPIPE, which has cost two
#      workers in this repository an afternoon each. This script tests content,
#      not exit status.
#
# AUTHORISED TESTING ONLY -- though this is your own code, so go ahead.

set -u

SRC_DIR=""
API_JAR=""
OUT_DIR=""
MIN_API=21
DETECTOR=0
DISASM=0
GROUND_TRUTH=""
KEEP=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die()  { printf '\n[FATAL] %s\n' "$*" >&2; exit 2; }
info() { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }

usage() { sed -n '2,85p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --src)           SRC_DIR="${2:-}"; shift 2 ;;
        --api-jar)       API_JAR="${2:-}"; shift 2 ;;
        --out)           OUT_DIR="${2:-}"; shift 2 ;;
        --min-api)       MIN_API="${2:-}"; shift 2 ;;
        --with-detector) DETECTOR=1; shift ;;
        --disassemble)   DISASM=1; shift ;;
        --ground-truth)  GROUND_TRUTH="${2:-}"; DETECTOR=1; shift 2 ;;
        --keep)          KEEP=1; shift ;;
        -h|--help)       usage ;;
        *)               die "unknown option: $1  (try --help)" ;;
    esac
done

[ -n "$SRC_DIR" ] || SRC_DIR="$SCRIPT_DIR/../examples"
[ -d "$SRC_DIR" ] || die "source directory not found: $SRC_DIR"

if command -v cygpath >/dev/null 2>&1; then
    winpath() { cygpath -m "$1"; }
else
    winpath() { printf '%s' "$1"; }
fi

[ -n "$OUT_DIR" ] || OUT_DIR="${TMPDIR:-/tmp}/ch64-build"
mkdir -p "$OUT_DIR" || die "cannot create $OUT_DIR"

case "$(cd "$OUT_DIR" && pwd)" in
    *Android-Security-Handbook*)
        die "refusing to build inside the repository: $OUT_DIR
     .class/.jar/.dex are build artefacts and must never be committed.
     Pass --out with a path outside the repo, or omit --out entirely." ;;
esac

finish() { [ "$KEEP" = 0 ] && rm -rf "$OUT_DIR/classes" "$OUT_DIR/stub-src"; }
trap finish EXIT

STUB_SRC="$OUT_DIR/stub-src"
CLASSES="$OUT_DIR/classes"
DEXDIR="$OUT_DIR/dex"
SMALI="$OUT_DIR/smali"
rm -rf "$STUB_SRC" "$CLASSES" "$DEXDIR"
mkdir -p "$STUB_SRC" "$CLASSES" "$DEXDIR"

info "build directory: $OUT_DIR"

# ---------------------------------------------------------------------------
# Tool discovery. Newest build-tools first; `sort -Vr` not `sort -r`, because
# 35.0.1 must beat 9.0.0 and a lexical sort does not know that.
# ---------------------------------------------------------------------------
find_sdk() {
    [ -n "${ANDROID_HOME:-}" ]     && [ -d "$ANDROID_HOME" ]     && { printf '%s' "$ANDROID_HOME"; return 0; }
    [ -n "${ANDROID_SDK_ROOT:-}" ] && [ -d "$ANDROID_SDK_ROOT" ] && { printf '%s' "$ANDROID_SDK_ROOT"; return 0; }
    local c
    for c in "${LOCALAPPDATA:-}/Android/Sdk" "$HOME/Android/Sdk" \
             "$HOME/Library/Android/sdk" "/usr/lib/android-sdk"; do
        [ -d "$c" ] && { printf '%s' "$c"; return 0; }
    done
    return 1
}

SDK="$(find_sdk || true)"

find_d8_jar() {
    [ -n "${D8:-}" ] && [ -f "$D8" ] && { printf '%s' "$D8"; return 0; }
    [ -n "$SDK" ] && [ -d "$SDK/build-tools" ] || return 1
    local v
    for v in $(ls -1 "$SDK/build-tools" 2>/dev/null | sort -Vr); do
        [ -f "$SDK/build-tools/$v/lib/d8.jar" ] && {
            printf '%s' "$SDK/build-tools/$v/lib/d8.jar"; return 0; }
    done
    return 1
}

find_android_jar() {
    [ -n "${ANDROID_JAR:-}" ] && [ -f "$ANDROID_JAR" ] && { printf '%s' "$ANDROID_JAR"; return 0; }
    [ -n "$SDK" ] && [ -d "$SDK/platforms" ] || return 1
    local v
    for v in $(ls -1 "$SDK/platforms" 2>/dev/null | sort -Vr); do
        [ -f "$SDK/platforms/$v/android.jar" ] && {
            printf '%s' "$SDK/platforms/$v/android.jar"; return 0; }
    done
    return 1
}

command -v javac >/dev/null 2>&1 || die "javac not on PATH. Install a JDK 11 or newer."
ok "javac: $(javac -version 2>&1)"

D8_JAR="$(find_d8_jar || true)"
[ -n "$D8_JAR" ] || die "could not find d8.jar. Set \$D8 to its path, or \$ANDROID_HOME to your SDK."
ok "d8:    $D8_JAR"

# android.jar is required unconditionally, not only for --with-detector.
# The real LoadPackageParam.appInfo is an android.content.pm.ApplicationInfo,
# and a stub that types it as Object compiles for a module that never touches
# it and fails for one that reads appInfo.uid -- which is a difference between
# TWO CORRECT MODULES, so the stub must be faithful rather than convenient.
ANDROID_JAR_PATH="$(find_android_jar || true)"
[ -n "$ANDROID_JAR_PATH" ] || die "could not find android.jar. Set \$ANDROID_JAR, or \$ANDROID_HOME to your SDK."
ok "android.jar: $ANDROID_JAR_PATH"

# ---------------------------------------------------------------------------
# The API: a real jar, or a generated SOURCE-COMPATIBLE stub.
#
# The stub has no runtime behaviour whatsoever. Its only job is to let javac
# resolve the names so that the DEX carries the right type references. It is
# never packaged -- see the exclusion step below, and the warning printed at
# the end.
#
# The signatures below match the published Xposed API 82 surface. Where a
# method's exact throws clause differs it does not matter: nothing here is
# ever executed, and d8 records the reference, not the stub's body.
# ---------------------------------------------------------------------------
if [ -n "$API_JAR" ]; then
    [ -f "$API_JAR" ] || die "--api-jar given but not found: $API_JAR"
    ok "using real Xposed API jar: $API_JAR"
    API_CP="$(winpath "$API_JAR")"
else
    info "no --api-jar given; generating a source-compatible stub"
    P="$STUB_SRC/de/robv/android/xposed"
    mkdir -p "$P/callbacks"

    cat > "$P/XposedBridge.java" <<'EOF'
package de.robv.android.xposed;
import java.lang.reflect.Member;
import java.util.Set;
public final class XposedBridge {
    public static final int XPOSED_BRIDGE_VERSION = 82;
    private XposedBridge() { }
    public static void log(String text) { throw new UnsupportedOperationException("stub"); }
    public static void log(Throwable t) { throw new UnsupportedOperationException("stub"); }
    public static XC_MethodHook.Unhook hookMethod(Member m, XC_MethodHook cb) { throw new UnsupportedOperationException("stub"); }
    public static Set<XC_MethodHook.Unhook> hookAllMethods(Class<?> c, String n, XC_MethodHook cb) { throw new UnsupportedOperationException("stub"); }
    public static Set<XC_MethodHook.Unhook> hookAllConstructors(Class<?> c, XC_MethodHook cb) { throw new UnsupportedOperationException("stub"); }
    public static Object invokeOriginalMethod(Member m, Object thisObject, Object[] args) { throw new UnsupportedOperationException("stub"); }
}
EOF

    cat > "$P/XposedHelpers.java" <<'EOF'
package de.robv.android.xposed;
public final class XposedHelpers {
    private XposedHelpers() { }
    public static Class<?> findClass(String className, ClassLoader cl) { throw new UnsupportedOperationException("stub"); }
    public static Class<?> findClassIfExists(String className, ClassLoader cl) { throw new UnsupportedOperationException("stub"); }
    public static XC_MethodHook.Unhook findAndHookMethod(String className, ClassLoader cl, String methodName, Object... parameterTypesAndCallback) { throw new UnsupportedOperationException("stub"); }
    public static XC_MethodHook.Unhook findAndHookMethod(Class<?> clazz, String methodName, Object... parameterTypesAndCallback) { throw new UnsupportedOperationException("stub"); }
    public static XC_MethodHook.Unhook findAndHookConstructor(Class<?> clazz, Object... parameterTypesAndCallback) { throw new UnsupportedOperationException("stub"); }
    public static Object getObjectField(Object obj, String fieldName) { throw new UnsupportedOperationException("stub"); }
    public static void setObjectField(Object obj, String fieldName, Object value) { throw new UnsupportedOperationException("stub"); }
    public static Object getStaticObjectField(Class<?> clazz, String fieldName) { throw new UnsupportedOperationException("stub"); }
    public static void setStaticObjectField(Class<?> clazz, String fieldName, Object value) { throw new UnsupportedOperationException("stub"); }
    public static boolean getBooleanField(Object obj, String fieldName) { throw new UnsupportedOperationException("stub"); }
    public static int getIntField(Object obj, String fieldName) { throw new UnsupportedOperationException("stub"); }
    public static Object callMethod(Object obj, String methodName, Object... args) { throw new UnsupportedOperationException("stub"); }
    public static Object callStaticMethod(Class<?> clazz, String methodName, Object... args) { throw new UnsupportedOperationException("stub"); }
    public static Object getAdditionalInstanceField(Object obj, String key) { throw new UnsupportedOperationException("stub"); }
    public static Object setAdditionalInstanceField(Object obj, String key, Object value) { throw new UnsupportedOperationException("stub"); }
}
EOF

    cat > "$P/XC_MethodHook.java" <<'EOF'
package de.robv.android.xposed;
import java.lang.reflect.Member;
public abstract class XC_MethodHook extends XCallback {
    public XC_MethodHook() { super(PRIORITY_DEFAULT); }
    public XC_MethodHook(int priority) { super(priority); }
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable { }
    protected void afterHookedMethod(MethodHookParam param) throws Throwable { }
    public static final class MethodHookParam extends XCallback.Param {
        public Member method;
        public Object thisObject;
        public Object[] args;
        public Object getResult() { throw new UnsupportedOperationException("stub"); }
        public void setResult(Object result) { throw new UnsupportedOperationException("stub"); }
        public Throwable getThrowable() { throw new UnsupportedOperationException("stub"); }
        public boolean hasThrowable() { throw new UnsupportedOperationException("stub"); }
        public void setThrowable(Throwable throwable) { throw new UnsupportedOperationException("stub"); }
        public Object getResultOrThrowable() throws Throwable { throw new UnsupportedOperationException("stub"); }
    }
    public class Unhook implements IXUnhook<XC_MethodHook> {
        public Member getHookedMethod() { throw new UnsupportedOperationException("stub"); }
        public XC_MethodHook getCallback() { throw new UnsupportedOperationException("stub"); }
        public void unhook() { throw new UnsupportedOperationException("stub"); }
    }
}
EOF

    cat > "$P/XC_MethodReplacement.java" <<'EOF'
package de.robv.android.xposed;
public abstract class XC_MethodReplacement extends XC_MethodHook {
    public XC_MethodReplacement() { super(); }
    public XC_MethodReplacement(int priority) { super(priority); }
    @Override protected final void beforeHookedMethod(MethodHookParam param) throws Throwable { }
    @Override protected final void afterHookedMethod(MethodHookParam param) throws Throwable { }
    protected abstract Object replaceHookedMethod(MethodHookParam param) throws Throwable;
    public static final XC_MethodReplacement DO_NOTHING = new XC_MethodReplacement(PRIORITY_HIGHEST * 2) {
        @Override protected Object replaceHookedMethod(MethodHookParam param) { return null; }
    };
    public static XC_MethodReplacement returnConstant(final Object result) {
        return new XC_MethodReplacement() {
            @Override protected Object replaceHookedMethod(MethodHookParam param) { return result; }
        };
    }
}
EOF

    cat > "$P/XCallback.java" <<'EOF'
package de.robv.android.xposed;
public abstract class XCallback implements Comparable<XCallback> {
    public static final int PRIORITY_DEFAULT = 50;
    public static final int PRIORITY_LOWEST  = -10000;
    public static final int PRIORITY_HIGHEST = 10000;
    public final int priority;
    public XCallback(int priority) { this.priority = priority; }
    @Override public int compareTo(XCallback other) { return 0; }
    public static abstract class Param { }
}
EOF

    cat > "$P/IXUnhook.java" <<'EOF'
package de.robv.android.xposed;
public interface IXUnhook<T> { void unhook(); }
EOF

    cat > "$P/IXposedMod.java" <<'EOF'
package de.robv.android.xposed;
public interface IXposedMod { }
EOF

    cat > "$P/IXposedHookZygoteInit.java" <<'EOF'
package de.robv.android.xposed;
public interface IXposedHookZygoteInit extends IXposedMod {
    void initZygote(StartupParam startupParam) throws Throwable;
    final class StartupParam {
        public String modulePath;
        public boolean startsSystemServer;
    }
}
EOF

    cat > "$P/IXposedHookLoadPackage.java" <<'EOF'
package de.robv.android.xposed;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
public interface IXposedHookLoadPackage extends IXposedMod {
    void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable;
}
EOF

    cat > "$P/callbacks/XC_LoadPackage.java" <<'EOF'
package de.robv.android.xposed.callbacks;
import de.robv.android.xposed.XCallback;
public abstract class XC_LoadPackage extends XCallback {
    public XC_LoadPackage() { super(PRIORITY_DEFAULT); }
    public static final class LoadPackageParam extends XCallback.Param {
        public String packageName;
        public String processName;
        public ClassLoader classLoader;
        public android.content.pm.ApplicationInfo appInfo;
        public boolean isFirstApplication;
    }
}
EOF
    ok "generated API stub: 10 source files"
    API_CP=""
fi

# ---------------------------------------------------------------------------
# Compile.
# ---------------------------------------------------------------------------
SOURCES="$OUT_DIR/sources.txt"
: > "$SOURCES"

# A javac @argfile splits on WHITESPACE, so any path containing a space -- and
# this repository lives under a directory whose name has one -- must be QUOTED
# inside it. Without the quotes javac reports `invalid flag: C:/Users/.../Android`,
# naming half a path, which reads like a corrupt argfile rather than a quoting
# bug. Same rule applies to d8's argfile.
qpath() { printf '"%s"\n' "$(winpath "$1")"; }

if [ -z "$API_JAR" ]; then
    while IFS= read -r f; do qpath "$f"; done < <(find "$STUB_SRC" -name '*.java') >> "$SOURCES"
fi

MODULE_SRC="$SRC_DIR/ClassicXposedModule.java"
[ -f "$MODULE_SRC" ] || die "module source not found: $MODULE_SRC"
qpath "$MODULE_SRC" >> "$SOURCES"

if [ "$DETECTOR" = 1 ]; then
    DET_SRC="$SRC_DIR/XposedDetector.java"
    [ -f "$DET_SRC" ] || die "--with-detector but $DET_SRC not found"
    qpath "$DET_SRC" >> "$SOURCES"
fi

info "compiling $(wc -l < "$SOURCES" | tr -d ' ') source files"

CP="$(winpath "$ANDROID_JAR_PATH")"
[ -n "$API_CP" ] && CP="$API_CP:$CP"

JAVAC_ARGS=( -nowarn -d "$(winpath "$CLASSES")" )
[ -n "$CP" ] && JAVAC_ARGS+=( -cp "$CP" )
# --release 8 keeps the bytecode inside what d8 accepts without desugaring
# gymnastics, and is what a real module's build.gradle would target.
JAVAC_ARGS+=( --release 8 )

javac "${JAVAC_ARGS[@]}" "@$(winpath "$SOURCES")" 2>&1 | grep -vE '^Note:|bootstrap class path|deprecat' || true

CLASS_COUNT="$(find "$CLASSES" -name '*.class' | wc -l | tr -d ' ')"
[ "$CLASS_COUNT" -gt 0 ] || die "javac produced no class files -- see errors above"
ok "compiled: $CLASS_COUNT class files"

# ---------------------------------------------------------------------------
# EXCLUDE the API classes from the DEX. This is what compileOnly does.
#
# Package a copy of de.robv.android.xposed with your module and the module's
# code calls the MODULE's XposedBridge -- a different class from the one the
# framework loaded -- so every hook is installed into nothing. The module loads
# cleanly, logs nothing, and hooks nothing. It is the single most common
# first-module failure and it produces no error at any stage.
# ---------------------------------------------------------------------------
# MEASURED, and worth knowing before you copy this pattern: javac's @argfile
# and d8's @argfile DO NOT SHARE A GRAMMAR, even though both ship in the same
# toolchain. javac splits on whitespace and honours double quotes; d8 does not
# strip them, and hands the quote straight to java.nio, which fails with
#     InvalidPathException: Illegal char <"> at index 0
# naming a path that is plainly correct apart from the quotes you added to make
# javac work. So the two argfiles cannot be written the same way.
#
# Rather than maintain two grammars, the API classes are DELETED from the
# output tree and the remainder is packed into one jar. d8 then takes a single
# path, on the command line, quoted by the shell in the ordinary way -- and a
# jar is also what a real Gradle build hands d8.
EXCLUDED="$(find "$CLASSES/de/robv" -name '*.class' 2>/dev/null | wc -l | tr -d ' ')"
rm -rf "$CLASSES/de/robv"

DEX_COUNT="$(find "$CLASSES" -name '*.class' | wc -l | tr -d ' ')"
[ "$DEX_COUNT" -gt 0 ] || die "nothing left to dex after excluding the API classes"
info "dexing $DEX_COUNT class files ($EXCLUDED API classes excluded, as compileOnly would)"

MODULE_JAR="$OUT_DIR/module-classes.jar"
rm -f "$MODULE_JAR"
( cd "$CLASSES" && jar cf "$(winpath "$MODULE_JAR")" . ) \
    || die "jar failed -- is the JDK's jar tool on PATH?"

java -cp "$(winpath "$D8_JAR")" com.android.tools.r8.D8 \
     --min-api "$MIN_API" \
     --output "$(winpath "$DEXDIR")" \
     "$(winpath "$MODULE_JAR")" 2>&1 | grep -viE '^warning:|desugar' || true

[ -f "$DEXDIR/classes.dex" ] || die "d8 produced no classes.dex"
DEX_SIZE="$(wc -c < "$DEXDIR/classes.dex" | tr -d ' ')"
ok "classes.dex: $DEX_SIZE bytes"

# ---------------------------------------------------------------------------
# String extraction.
#
# DO NOT USE `strings` HERE. On this host the `strings` on PATH is a
# Sysinternals-style Windows build, which (a) cannot open an MSYS /c/... path
# and (b) emits CRLF, so every anchored grep silently matches nothing --
# a trap this repository has already lost time to once. python3 is a hard
# requirement of the repo's tooling and behaves identically everywhere.
# ---------------------------------------------------------------------------
dexstrings() {
    # $1 = file, $2 = python regex (bytes), prints unique matches, sorted
    python3 -B -c '
import re, sys
data = open(sys.argv[1], "rb").read()
seen = sorted({m.decode("ascii", "replace") for m in re.findall(sys.argv[2].encode(), data)})
for s in seen:
    print(s)
' "$(winpath "$1")" "$2"
}

# The reference list. This is the obfuscation-proof fingerprint: a module MUST
# name de.robv types by their real names, because the framework supplies those
# classes at runtime, so no renamer may touch them.
echo
echo "de.robv type references carried by the DEX (defined by NOTHING in it):"
REFS="$(dexstrings "$DEXDIR/classes.dex" 'Lde/robv/android/xposed/[A-Za-z0-9$/_]+;')"
printf '%s\n' "$REFS" | sed 's/^/    /'
REFCOUNT="$(printf '%s\n' "$REFS" | grep -c . || true)"
echo "    ($REFCOUNT distinct types)"

# The module's target list, in plaintext, because reflection is string-based.
echo
echo "Class-name-shaped string constants -- the module's target list:"
dexstrings "$DEXDIR/classes.dex" '[a-z][a-z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*){2,}' \
    | awk 'length($0) >= 10' | sed 's/^/    /'

echo
echo "Absolute paths named by the DEX -- the classic-Xposed artefact list:"
dexstrings "$DEXDIR/classes.dex" '/(?:system|data|proc)/[A-Za-z0-9._/-]+' | sed 's/^/    /'

# ---------------------------------------------------------------------------
# Ground truth for the scanner.
# ---------------------------------------------------------------------------
if [ -n "$GROUND_TRUTH" ]; then
    info "writing ground truth to $GROUND_TRUTH"
    {
        echo "# ch64 ground truth -- generated by scripts/build-classic-module.sh"
        echo "# host: $(uname -s) $(uname -m)"
        echo "# javac: $(javac -version 2>&1)"
        echo "# d8: $D8_JAR"
        echo "# min-api: $MIN_API"
        echo
        echo "dex_bytes=$DEX_SIZE"
        echo "class_files_compiled=$CLASS_COUNT"
        echo "class_files_dexed=$DEX_COUNT"
        echo "api_classes_excluded=$EXCLUDED"
        echo "distinct_de_robv_types=$REFCOUNT"
        echo
        echo "# de.robv type references"
        dexstrings "$DEXDIR/classes.dex" 'Lde/robv/android/xposed/[A-Za-z0-9$/_]+;'
        echo
        echo "# classic-Xposed artefact paths named by the detector"
        dexstrings "$DEXDIR/classes.dex" '/(?:system|data|proc)/[A-Za-z0-9._/-]+'
        echo
        echo "# framework package names named by the detector"
        dexstrings "$DEXDIR/classes.dex" '[a-z][a-z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*){2,}' \
            | grep -E 'xposed|lsposed|riru|weishu|va\.exposed'
    } > "$GROUND_TRUTH"
    ok "ground truth: $GROUND_TRUTH"
fi

# ---------------------------------------------------------------------------
# Disassembly.
# ---------------------------------------------------------------------------
if [ "$DISASM" = 1 ]; then
    BAKSMALI=""
    for c in "${BAKSMALI:-}" "$(command -v baksmali 2>/dev/null || true)"; do
        [ -n "$c" ] && [ -f "$c" ] && { BAKSMALI="$c"; break; }
    done
    if [ -z "$BAKSMALI" ]; then
        # apktool ships one under Resources/. This is where it lives on this
        # host; adjust if yours differs.
        for c in "$HOME"/.local/share/apktool/Resources/baksmali*.jar \
                 /c/ProgramData/chocolatey/lib/apktool/tools/Resources/baksmali*.jar \
                 "${APKTOOL_HOME:-}"/Resources/baksmali*.jar; do
            [ -f "$c" ] && { BAKSMALI="$c"; break; }
        done
    fi
    if [ -z "$BAKSMALI" ]; then
        warn "baksmali not found -- skipping disassembly."
        warn "NOTE: jadx 1.5.3 on this host produces NO OUTPUT for a bare classes.dex,"
        warn "      exits 0, and hangs on a .jar. That was measured by 63-LSPosed."
        warn "      Use baksmali; do not rediscover the jadx behaviour."
    else
        rm -rf "$SMALI"
        java -jar "$(winpath "$BAKSMALI")" d "$(winpath "$DEXDIR/classes.dex")" \
             -o "$(winpath "$SMALI")" && ok "smali: $SMALI"
        echo
        echo "smali files:"
        find "$SMALI" -name '*.smali' | sed "s|$SMALI/||" | sort | sed 's/^/    /'
    fi
fi

echo
if [ -z "$API_JAR" ]; then
    cat <<'EOF'
[!] The Xposed API used here was a GENERATED STUB, not the real
    de.robv.android.xposed:api:82 jar. That is fine for compiling, dexing and
    disassembling -- the DEX carries the correct type references either way,
    which is the whole point of compileOnly. It is NOT fine for running: the
    stub methods all throw. To actually run this module you need a device with
    a framework that supplies the real classes, which in 2026 means LSPosed.
    See 63-LSPosed.
EOF
fi
echo "done. Everything is under $OUT_DIR -- nothing was written into the repository."
