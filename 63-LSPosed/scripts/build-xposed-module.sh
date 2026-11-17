#!/usr/bin/env bash
# scripts/build-xposed-module.sh
#
# PURPOSE
#   Compile an LSPosed / Xposed module to DEX with no network, no Gradle and no
#   Android Studio, and optionally decompile the result so you can see exactly
#   what a module looks like to an analyst.
#
#   The chapter needs this for three separate reasons:
#
#     1. TEACHING.  A module is an ordinary APK whose DEX references one
#        package, de.robv.android.xposed.  Building one by hand is the fastest
#        way to internalise that there is nothing magic about it.
#     2. REVERSE ENGINEERING.  README §6.2 shows what XposedBridge looks like
#        in jadx output and in smali.  Those listings are produced BY THIS
#        SCRIPT, from the source in examples/, rather than copied from a
#        third-party module whose licence and provenance you cannot check.
#     3. OFFLINE.  The real API is published as de.robv.android.xposed:api:82.
#        If you have it, pass --api-jar and the script uses it.  If you do not,
#        the script synthesises a minimal SOURCE-COMPATIBLE stand-in so the
#        example still compiles.  The stand-in has no runtime behaviour and is
#        never packaged - see the warning printed at the end.
#
# USAGE
#   ./build-xposed-module.sh [options]
#
#   Options:
#     --src DIR         Directory of module .java sources.
#                       Default: ../examples
#     --api-jar PATH    Use a real Xposed API jar instead of the generated stub.
#     --out DIR         Build directory. MUST be outside this repository -
#                       .class, .jar and .dex files are on the artefact
#                       blocklist.  Default: a fresh mktemp -d.
#     --min-api N       d8 --min-api. Default 27 (Android 8.1, LSPosed's floor).
#     --decompile       Also run jadx and dexdump over the DEX and print the
#                       parts README §6 quotes.
#     --keep            Do not delete the build directory on exit.
#     -h, --help        This text.
#
# EXAMPLES
#   # Just build, using the generated stub API
#   ./build-xposed-module.sh
#
#   # Build against the real API and show what an analyst would see
#   ./build-xposed-module.sh --api-jar ~/.m2/.../api-82.jar --decompile --keep
#
# REQUIREMENTS
#   javac (JDK 11 or newer) and java, on PATH.
#   d8, from the Android SDK build-tools.  The script finds it in this order:
#     $D8, then $ANDROID_HOME/build-tools/*/lib/d8.jar, then
#     $ANDROID_SDK_ROOT/..., then $LOCALAPPDATA/Android/Sdk/... on Windows.
#   jadx and dexdump are optional and only needed for --decompile.
#
# NOTES
#   Runs under Git Bash on Windows as well as Linux/macOS.  On Windows the JDK
#   and d8 are native binaries and need Windows paths, so every path handed to
#   them goes through winpath() below.  Forgetting that conversion is the
#   single most common way this class of script fails on Windows, with an error
#   message that names a file which plainly exists.
#
set -uo pipefail

SRC_DIR=""
API_JAR=""
OUT_DIR=""
MIN_API=27
DECOMPILE=0
KEEP=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die()  { printf '\n[FATAL] %s\n' "$*" >&2; exit 1; }
info() { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }

usage() { sed -n '2,60p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --src)        SRC_DIR="${2:-}"; shift 2 ;;
        --api-jar)    API_JAR="${2:-}"; shift 2 ;;
        --out)        OUT_DIR="${2:-}"; shift 2 ;;
        --min-api)    MIN_API="${2:-}"; shift 2 ;;
        --decompile)  DECOMPILE=1; shift ;;
        --keep)       KEEP=1; shift ;;
        -h|--help)    usage ;;
        *)            die "unknown option: $1  (try --help)" ;;
    esac
done

[ -n "$SRC_DIR" ] || SRC_DIR="$SCRIPT_DIR/../examples"
[ -d "$SRC_DIR" ] || die "source directory not found: $SRC_DIR"

# ---------------------------------------------------------------------------
# Windows path conversion.  Native tools (javac, java, jadx) do not understand
# /c/Users/... .  cygpath exists in Git Bash and MSYS; elsewhere this is a
# no-op.
# ---------------------------------------------------------------------------
# cygpath -m gives "mixed" form, C:/Users/... with FORWARD slashes.  That is
# deliberate and not cosmetic: javac and d8 accept it, and inside a javac
# @argfile a backslash is an escape character, so the -w form silently
# mangles every path.
if command -v cygpath >/dev/null 2>&1; then
    winpath() { cygpath -m "$1"; }
else
    winpath() { printf '%s' "$1"; }
fi

# ---------------------------------------------------------------------------
# Build directory - deliberately OUTSIDE the repository.
# ---------------------------------------------------------------------------
CLEANUP=0
if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t ch63)"
    CLEANUP=1
fi
mkdir -p "$OUT_DIR" || die "cannot create $OUT_DIR"

case "$(cd "$OUT_DIR" && pwd)" in
    *Android-Security-Handbook*)
        die "refusing to build inside the repository: $OUT_DIR
     .class/.jar/.dex are build artefacts and must never be committed.
     Pass --out with a path outside the repo, or omit --out entirely." ;;
esac

finish() {
    if [ "$CLEANUP" = 1 ] && [ "$KEEP" = 0 ]; then rm -rf "$OUT_DIR"; fi
}
trap finish EXIT

STUB_SRC="$OUT_DIR/stub-src"
CLASSES="$OUT_DIR/classes"
DEXDIR="$OUT_DIR/dex"
mkdir -p "$STUB_SRC" "$CLASSES" "$DEXDIR"

info "build directory: $OUT_DIR"

# ---------------------------------------------------------------------------
# Locate d8.  Newer build-tools ship lib/d8.jar plus a .bat/.sh wrapper; the
# jar is the portable thing to invoke.
# ---------------------------------------------------------------------------
find_d8_jar() {
    [ -n "${D8:-}" ] && [ -f "$D8" ] && { printf '%s' "$D8"; return 0; }
    local roots=()
    [ -n "${ANDROID_HOME:-}" ]     && roots+=("$ANDROID_HOME")
    [ -n "${ANDROID_SDK_ROOT:-}" ] && roots+=("$ANDROID_SDK_ROOT")
    [ -n "${LOCALAPPDATA:-}" ]     && roots+=("$LOCALAPPDATA/Android/Sdk")
    roots+=("$HOME/Android/Sdk" "$HOME/Library/Android/sdk" "/usr/lib/android-sdk")
    local r j
    for r in "${roots[@]}"; do
        [ -d "$r/build-tools" ] || continue
        # newest build-tools first
        for j in $(ls -1 "$r/build-tools" 2>/dev/null | sort -Vr); do
            [ -f "$r/build-tools/$j/lib/d8.jar" ] && { printf '%s' "$r/build-tools/$j/lib/d8.jar"; return 0; }
        done
    done
    return 1
}

D8_JAR="$(find_d8_jar || true)"
[ -n "$D8_JAR" ] || die "could not find d8.jar. Set \$D8 to its path, or \$ANDROID_HOME to your SDK."
ok "d8: $D8_JAR"

# dexdump lives next to d8 in build-tools and is almost never on PATH.
BT_DIR="$(dirname "$(dirname "$D8_JAR")")"
if ! command -v dexdump >/dev/null 2>&1; then
    if [ -x "$BT_DIR/dexdump" ] || [ -f "$BT_DIR/dexdump.exe" ]; then
        PATH="$BT_DIR:$PATH"; export PATH
        info "added build-tools to PATH for dexdump: $BT_DIR"
    fi
fi

command -v javac >/dev/null 2>&1 || die "javac not on PATH"
JAVAC_VER="$(javac -version 2>&1)"
ok "javac: $JAVAC_VER"

# ---------------------------------------------------------------------------
# The API: real jar, or a generated source-compatible stub.
# ---------------------------------------------------------------------------
generate_stub_api() {
    local p="$STUB_SRC/de/robv/android/xposed"
    mkdir -p "$p/callbacks"

    cat > "$p/XposedBridge.java" <<'EOF'
package de.robv.android.xposed;

import java.lang.reflect.Member;
import java.util.HashSet;
import java.util.Set;

/**
 * COMPILE-TIME STUB ONLY - generated by scripts/build-xposed-module.sh.
 *
 * Source-compatible with de.robv.android.xposed:api:82 for the subset this
 * chapter's examples use.  It has NO runtime behaviour.  At runtime the real
 * class is supplied by LSPosed inside the target process; a module APK must
 * never package this file, which is why the real dependency is declared
 * compileOnly and never implementation.
 */
public final class XposedBridge {
    private XposedBridge() { }

    /** The module's output channel. Ends up in LSPosed's log, not logcat. */
    public static void log(String text) { }

    /** Log a Throwable with its stack trace. */
    public static void log(Throwable t) { }

    /** Hook one specific Member (Method or Constructor). */
    public static XC_MethodHook.Unhook hookMethod(Member hookMethod, XC_MethodHook callback) {
        return null;
    }

    /** Hook every method of the given name, whatever its parameters. */
    public static Set<XC_MethodHook.Unhook> hookAllMethods(
            Class<?> hookClass, String methodName, XC_MethodHook callback) {
        return new HashSet<XC_MethodHook.Unhook>();
    }

    /** Hook every declared constructor. */
    public static Set<XC_MethodHook.Unhook> hookAllConstructors(
            Class<?> hookClass, XC_MethodHook callback) {
        return new HashSet<XC_MethodHook.Unhook>();
    }

    /** Invoke the original implementation, bypassing all hooks. */
    public static Object invokeOriginalMethod(Member method, Object thisObject, Object[] args)
            throws Throwable {
        return null;
    }
}
EOF

    cat > "$p/XC_MethodHook.java" <<'EOF'
package de.robv.android.xposed;

import java.lang.reflect.Member;

/** COMPILE-TIME STUB ONLY - see XposedBridge.java. */
public abstract class XC_MethodHook extends de.robv.android.xposed.callbacks.XCallback {

    public XC_MethodHook() { super(PRIORITY_DEFAULT); }
    public XC_MethodHook(int priority) { super(priority); }

    protected void beforeHookedMethod(MethodHookParam param) throws Throwable { }
    protected void afterHookedMethod(MethodHookParam param) throws Throwable { }

    /** The mutable state of one hooked invocation. */
    public static final class MethodHookParam extends de.robv.android.xposed.callbacks.XCallback.Param {
        /** The Method or Constructor that was hooked. */
        public Member method;
        /** The receiver, or null for a static method. */
        public Object thisObject;
        /** The live argument array. Writing to it changes what the callee sees. */
        public Object[] args;

        private Object result;
        private Throwable throwable;

        public Object getResult() { return result; }
        /** In before: skips the original body. In after: changes what the caller sees. */
        public void setResult(Object result) { this.result = result; this.throwable = null; }
        public Throwable getThrowable() { return throwable; }
        public boolean hasThrowable() { return throwable != null; }
        public void setThrowable(Throwable throwable) { this.throwable = throwable; this.result = null; }
        public Object getResultOrThrowable() throws Throwable {
            if (throwable != null) throw throwable;
            return result;
        }
    }

    /** Handle returned by every hook installation; call unhook() to remove it. */
    public class Unhook implements IXposedHookLoadPackage.Unhooker {
        public Member getHookedMethod() { return null; }
        public XC_MethodHook getCallback() { return XC_MethodHook.this; }
        public void unhook() { }
    }
}
EOF

    cat > "$p/XC_MethodReplacement.java" <<'EOF'
package de.robv.android.xposed;

/** COMPILE-TIME STUB ONLY - see XposedBridge.java. */
public abstract class XC_MethodReplacement extends XC_MethodHook {
    public XC_MethodReplacement() { super(); }
    public XC_MethodReplacement(int priority) { super(priority); }

    /** Replaces the method body entirely. The original never runs. */
    protected abstract Object replaceHookedMethod(MethodHookParam param) throws Throwable;

    @Override
    protected final void beforeHookedMethod(MethodHookParam param) throws Throwable { }
    @Override
    protected final void afterHookedMethod(MethodHookParam param) throws Throwable { }

    /** A replacement that does nothing and returns the given constant. */
    public static XC_MethodReplacement returnConstant(final Object result) { return null; }

    public static final XC_MethodReplacement DO_NOTHING = null;
}
EOF

    cat > "$p/XposedHelpers.java" <<'EOF'
package de.robv.android.xposed;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * COMPILE-TIME STUB ONLY - see XposedBridge.java.
 *
 * The real class is ~2000 lines of reflection convenience wrappers with a
 * member cache.  Everything here can be done with plain java.lang.reflect;
 * XposedHelpers exists so that a module is readable.
 */
public final class XposedHelpers {
    private XposedHelpers() { }

    /** Resolve a class by name from a class loader, or throw ClassNotFoundError. */
    public static Class<?> findClass(String className, ClassLoader classLoader) { return null; }

    /** Resolve a class by name, or return null instead of throwing. */
    public static Class<?> findClassIfExists(String className, ClassLoader classLoader) { return null; }

    /**
     * The workhorse.  parameterTypesAndCallback is a varargs array whose last
     * element MUST be the XC_MethodHook and whose earlier elements are the
     * parameter types - as Class objects, or as fully-qualified type names.
     */
    public static XC_MethodHook.Unhook findAndHookMethod(
            Class<?> clazz, String methodName, Object... parameterTypesAndCallback) { return null; }

    public static XC_MethodHook.Unhook findAndHookMethod(
            String className, ClassLoader classLoader, String methodName,
            Object... parameterTypesAndCallback) { return null; }

    public static XC_MethodHook.Unhook findAndHookConstructor(
            Class<?> clazz, Object... parameterTypesAndCallback) { return null; }

    public static XC_MethodHook.Unhook findAndHookConstructor(
            String className, ClassLoader classLoader, Object... parameterTypesAndCallback) { return null; }

    public static Method findMethodExact(Class<?> clazz, String methodName, Object... parameterTypes) { return null; }
    public static Field  findField(Class<?> clazz, String fieldName) { return null; }

    public static Object  getObjectField (Object obj, String fieldName) { return null; }
    public static int     getIntField    (Object obj, String fieldName) { return 0; }
    public static long    getLongField   (Object obj, String fieldName) { return 0L; }
    public static boolean getBooleanField(Object obj, String fieldName) { return false; }

    public static void setObjectField (Object obj, String fieldName, Object value) { }
    public static void setIntField    (Object obj, String fieldName, int value) { }
    public static void setBooleanField(Object obj, String fieldName, boolean value) { }

    public static Object getStaticObjectField(Class<?> clazz, String fieldName) { return null; }
    public static void   setStaticObjectField(Class<?> clazz, String fieldName, Object value) { }

    public static Object callMethod(Object obj, String methodName, Object... args) { return null; }
    public static Object callStaticMethod(Class<?> clazz, String methodName, Object... args) { return null; }
    public static Object newInstance(Class<?> clazz, Object... args) { return null; }

    /** Per-object side table, for state a module wants to attach to someone else's object. */
    public static Object getAdditionalInstanceField(Object obj, String key) { return null; }
    public static Object setAdditionalInstanceField(Object obj, String key, Object value) { return null; }
}
EOF

    cat > "$p/IXposedHookLoadPackage.java" <<'EOF'
package de.robv.android.xposed;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

/** COMPILE-TIME STUB ONLY - see XposedBridge.java. */
public interface IXposedHookLoadPackage extends IXposedMod {
    /** Called once per PROCESS, inside the app, before the app's code runs. */
    void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable;

    interface Unhooker {
        void unhook();
    }
}
EOF

    cat > "$p/IXposedHookZygoteInit.java" <<'EOF'
package de.robv.android.xposed;

/** COMPILE-TIME STUB ONLY - see XposedBridge.java. */
public interface IXposedHookZygoteInit extends IXposedMod {
    /** Called once, in Zygote, before any application process exists. */
    void initZygote(StartupParam startupParam) throws Throwable;

    final class StartupParam {
        private StartupParam() { }
        /** Absolute path of this module's own APK. */
        public String modulePath;
        /** True in the Zygote that will fork system_server. */
        public boolean startsSystemServer;
    }
}
EOF

    cat > "$p/IXposedHookInitPackageResources.java" <<'EOF'
package de.robv.android.xposed;

import de.robv.android.xposed.callbacks.XC_InitPackageResources;

/** COMPILE-TIME STUB ONLY - see XposedBridge.java. */
public interface IXposedHookInitPackageResources extends IXposedMod {
    /** Called when a package's resources are first loaded - layouts, strings, drawables. */
    void handleInitPackageResources(XC_InitPackageResources.InitPackageResourcesParam resparam)
            throws Throwable;
}
EOF

    cat > "$p/IXposedMod.java" <<'EOF'
package de.robv.android.xposed;

/** COMPILE-TIME STUB ONLY - marker interface every module entry point extends. */
public interface IXposedMod { }
EOF

    cat > "$p/callbacks/XCallback.java" <<'EOF'
package de.robv.android.xposed.callbacks;

/** COMPILE-TIME STUB ONLY - see XposedBridge.java. */
public abstract class XCallback implements Comparable<XCallback> {
    public static final int PRIORITY_DEFAULT = 50;
    public static final int PRIORITY_LOWEST  = -10000;
    public static final int PRIORITY_HIGHEST =  10000;

    public final int priority;

    public XCallback(int priority) { this.priority = priority; }

    /** Higher priority runs its before-callback FIRST and its after-callback LAST. */
    public int compareTo(XCallback other) { return 0; }

    public static class Param {
        protected Param() { }
        public Object getObjectExtra(String key) { return null; }
        public void setObjectExtra(String key, Object value) { }
    }
}
EOF

    cat > "$p/callbacks/XC_LoadPackage.java" <<'EOF'
package de.robv.android.xposed.callbacks;

/** COMPILE-TIME STUB ONLY - see XposedBridge.java. */
public abstract class XC_LoadPackage extends XCallback {
    public XC_LoadPackage() { super(PRIORITY_DEFAULT); }
    public XC_LoadPackage(int priority) { super(priority); }

    public abstract void handleLoadPackage(LoadPackageParam lpparam) throws Throwable;

    /** Everything a module is told about the process it just landed in. */
    public static final class LoadPackageParam extends XCallback.Param {
        public LoadPackageParam() { }
        /** e.g. "com.pentest.ch63.vault" */
        public String packageName;
        /** e.g. "com.pentest.ch63.vault:worker" - NOT always == packageName */
        public String processName;
        /** The app's class loader. Its own classes resolve only through this. */
        public ClassLoader classLoader;
        /** android.content.pm.ApplicationInfo, typed as Object in this stub so
         *  that the example compiles without android.jar. */
        public Object appInfo;
        /** True for the first (main) application in the process. */
        public boolean isFirstApplication;
    }
}
EOF

    cat > "$p/callbacks/XC_InitPackageResources.java" <<'EOF'
package de.robv.android.xposed.callbacks;

/** COMPILE-TIME STUB ONLY - see XposedBridge.java. */
public abstract class XC_InitPackageResources extends XCallback {
    public XC_InitPackageResources() { super(PRIORITY_DEFAULT); }

    public abstract void handleInitPackageResources(InitPackageResourcesParam resparam) throws Throwable;

    public static final class InitPackageResourcesParam extends XCallback.Param {
        public InitPackageResourcesParam() { }
        public String packageName;
        /** android.content.res.XResources in the real API. */
        public Object res;
    }
}
EOF
}

CP=""
if [ -n "$API_JAR" ]; then
    [ -f "$API_JAR" ] || die "--api-jar not found: $API_JAR"
    CP="$(winpath "$API_JAR")"
    ok "using real Xposed API jar: $API_JAR"
    USING_STUB=0
else
    info "no --api-jar given; generating a source-compatible stub API"
    generate_stub_api
    USING_STUB=1
fi

# ---------------------------------------------------------------------------
# Compile.
# ---------------------------------------------------------------------------
SOURCES="$OUT_DIR/sources.txt"
: > "$SOURCES"
find "$SRC_DIR" -name '*.java' -print >> "$SOURCES"
[ "$USING_STUB" = 1 ] && find "$STUB_SRC" -name '*.java' -print >> "$SOURCES"

NSRC=$(wc -l < "$SOURCES" | tr -d ' ')
[ "$NSRC" -gt 0 ] || die "no .java sources found under $SRC_DIR"
info "compiling $NSRC source files"

# Convert every path in the list for the native javac, and QUOTE it - this
# repository's own tree lives under a directory with a space in its name, and
# an unquoted @argfile entry splits there into two nonexistent files.
WSOURCES="$OUT_DIR/sources.win.txt"
: > "$WSOURCES"
while IFS= read -r f; do printf '"%s"\n' "$(winpath "$f")" >> "$WSOURCES"; done < "$SOURCES"

JAVAC_ARGS=(-d "$(winpath "$CLASSES")" -encoding UTF-8 -nowarn)
# --release 8 keeps the class-file version inside d8's comfort zone.  JDK 21+
# warns that 8 is obsolete; JDK 24 may refuse it outright, so fall back to 11.
if javac --release 8 -version >/dev/null 2>&1; then
    JAVAC_ARGS+=(--release 8)
else
    JAVAC_ARGS+=(--release 11)
    warn "this JDK refuses --release 8; using 11. d8 handles both."
fi
[ -n "$CP" ] && JAVAC_ARGS+=(-classpath "$CP")

if ! javac "${JAVAC_ARGS[@]}" "@$(winpath "$WSOURCES")"; then
    die "compilation failed"
fi
NCLASS=$(find "$CLASSES" -name '*.class' | wc -l | tr -d ' ')
ok "compiled: $NCLASS class files"

# ---------------------------------------------------------------------------
# Dex.  Only the MODULE's classes - never the stub API, which at runtime is
# provided by LSPosed.  This mirrors compileOnly in a Gradle build, and getting
# it wrong is a real failure mode: a module that ships its own XposedBridge
# gets its hooks silently ignored, because the class the module calls is not
# the class LSPosed loaded.
# ---------------------------------------------------------------------------
MODCLASSES="$OUT_DIR/module-classes.txt"
: > "$MODCLASSES"
find "$CLASSES" -name '*.class' | grep -v '/de/robv/android/xposed/' > "$MODCLASSES" || true
NMOD=$(wc -l < "$MODCLASSES" | tr -d ' ')
[ "$NMOD" -gt 0 ] || die "no module classes to dex (everything was API stub?)"
info "dexing $NMOD module class files (API classes excluded, as compileOnly would)"

D8_ARGS=(--output "$(winpath "$DEXDIR")" --min-api "$MIN_API")
# d8 needs the API on its classpath to resolve references it is not dexing.
if [ -n "$CP" ]; then
    D8_ARGS+=(--classpath "$CP")
else
    D8_ARGS+=(--classpath "$(winpath "$CLASSES")")
fi

D8_FILES=()
while IFS= read -r f; do D8_FILES+=("$(winpath "$f")"); done < "$MODCLASSES"

if ! java -cp "$(winpath "$D8_JAR")" com.android.tools.r8.D8 "${D8_ARGS[@]}" "${D8_FILES[@]}"; then
    die "d8 failed"
fi

DEX="$DEXDIR/classes.dex"
[ -f "$DEX" ] || die "d8 produced no classes.dex"
DEXSZ=$(wc -c < "$DEX" | tr -d ' ')
ok "classes.dex: $DEXSZ bytes  ->  $DEX"

# ---------------------------------------------------------------------------
# What an analyst sees.
# ---------------------------------------------------------------------------
if [ "$DECOMPILE" = 1 ]; then
    printf '\n===================== WHAT AN ANALYST SEES =====================\n\n'

    if command -v dexdump >/dev/null 2>&1; then
        printf -- '--- 1. Every de.robv type this DEX references -------------------\n'
        dexdump -d "$(winpath "$DEX")" 2>/dev/null \
            | grep -oE 'Lde/robv/android/xposed/[A-Za-z0-9$/_]+;' \
            | sort -u
        printf '\n'
    else
        warn "dexdump not on PATH; skipping the type-reference listing"
    fi

    # baksmali gives the ground truth: real smali, no reconstruction step that
    # could disagree with the bytecode.  Chapter 56 measured decompiled Java
    # silently disagreeing with the DEX it came from; smali cannot, because it
    # IS the DEX.  jadx is deliberately not invoked here - it is the right tool
    # for reading someone else's module (README §6.2 shows its output) but it
    # is a network-checking GUI-adjacent tool and a build script should not
    # depend on one.
    BAKSMALI="${BAKSMALI:-}"
    if [ -z "$BAKSMALI" ]; then
        for c in "/c/Program Files (x86)/apktool/Resources/baksmali.jar" \
                 "$HOME/baksmali.jar" "/usr/local/lib/baksmali.jar"; do
            [ -f "$c" ] && { BAKSMALI="$c"; break; }
        done
    fi

    if [ -n "$BAKSMALI" ] && [ -f "$BAKSMALI" ]; then
        SMOUT="$OUT_DIR/smali"
        printf -- '--- 2. baksmali disassembly -------------------------------------\n'
        rm -rf "$SMOUT"
        if java -jar "$(winpath "$BAKSMALI")" d "$(winpath "$DEX")" \
                -o "$(winpath "$SMOUT")" >"$OUT_DIR/baksmali.log" 2>&1; then
            find "$SMOUT" -name '*.smali' | sort | while IFS= read -r s; do
                printf '  %6s lines  %s\n' "$(wc -l < "$s" | tr -d ' ')" "${s#$SMOUT/}"
            done
            printf '\n'
            printf -- '--- 3. every Xposed API call site, with its descriptor ----------\n'
            grep -rhoE 'invoke-[a-z]+ \{[^}]*\}, Lde/robv/[^ ]+' "$SMOUT" \
                | sed 's/^invoke-[a-z]* {[^}]*}, //' | sort | uniq -c | sort -rn
        else
            warn "baksmali failed; see $OUT_DIR/baksmali.log"
        fi
    else
        warn "baksmali.jar not found. Set \$BAKSMALI to its path to see the smali."
    fi
    printf '\n================================================================\n'
fi

printf '\n'
if [ "$USING_STUB" = 1 ]; then
    cat <<'EOF'
[!] The API used for this build was a GENERATED STUB, not the real
    de.robv.android.xposed:api:82.  That is enough to prove the module
    compiles and to produce the DEX an analyst would see, and it is NOT
    enough to run the module: the stub's methods have empty bodies.

    To actually run a module you need LSPosed on the device and the real
    API at compile time, declared compileOnly so it is not packaged.
EOF
fi
[ "$KEEP" = 1 ] && info "build kept at: $OUT_DIR"
ok "done"
