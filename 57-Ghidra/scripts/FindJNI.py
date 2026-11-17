# FindJNI.py — inventory the JNI surface and risk indicators of one native library.
#
# WHAT IT DOES
#   For a single Ghidra program (one .so), reports:
#     1. Statically registered JNI entry points   (Java_* exports)
#     2. JNI_OnLoad / JNI_OnUnload and .init_array constructors
#     3. Imported functions that indicate interesting behaviour, with their callers
#     4. Strings matching security-relevant patterns, with cross-reference counts
#     5. A one-line machine-readable summary suitable for a corpus CSV
#
#   It is deliberately read-only: it renames nothing and modifies no types, so it
#   is safe to run over an analyst's working project.
#
# WHY IT IS THE FIRST SCRIPT YOU RUN
#   The three questions that decide how you spend the next hour are: are there
#   Java_* exports (static registration, easy), is there a JNI_OnLoad (dynamic
#   registration, harder), and does the library import anything that suggests
#   anti-analysis or code loading. All three are answered in seconds.
#
#   See ../README.md sections 3.9 and 8.4.
#
# HOW TO RUN — GUI
#   Window -> Script Manager -> add this directory to the script paths -> run.
#
# HOW TO RUN — HEADLESS
#   $GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra-proj TriageProject \
#       -import lib/arm64-v8a/libnative.so \
#       -processor AARCH64:LE:64:v8A \
#       -scriptPath "$(pwd)/scripts" \
#       -postScript FindJNI.py \
#       -analysisTimeoutPerFile 900 \
#       -deleteProject
#
#   Add an argument to emit only the CSV line:
#       -postScript FindJNI.py csv
#
# LANGUAGE
#   Jython 2.7 (Ghidra's bundled Python). Avoid f-strings and Python 3 syntax.
#
# @category Android.JNI
# @author Android-Security-Handbook

import re

# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #

# Imports that change how you read a library. Grouped so the output explains
# WHY each one is interesting rather than just listing it.
INTERESTING_IMPORTS = {
    "anti-analysis": [
        "ptrace", "prctl", "syscall", "kill", "getppid", "fork", "vfork",
        "sigaction", "raise", "personality",
    ],
    "code loading": [
        "dlopen", "dlsym", "dladdr", "dlclose", "android_dlopen_ext",
        "mmap", "mprotect", "memfd_create", "dl_iterate_phdr",
    ],
    "process execution": [
        "system", "popen", "execve", "execl", "execlp", "execvp", "posix_spawn",
    ],
    "filesystem probing": [
        "fopen", "open", "openat", "access", "faccessat", "stat", "stat64",
        "lstat", "lstat64", "readlink", "opendir", "realpath",
    ],
    "device state": [
        "__system_property_get", "__system_property_find", "gethostname",
        "getuid", "geteuid", "getpid",
    ],
    "timing / anti-debug": [
        "gettimeofday", "clock_gettime", "times", "nanosleep",
    ],
    "crypto": [
        "HMAC_Init_ex", "HMAC_Update", "HMAC_Final",
        "EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "EVP_DigestInit_ex",
        "AES_set_encrypt_key", "RAND_bytes", "SSL_CTX_set_verify",
        "SSL_CTX_set_custom_verify", "SSL_read", "SSL_write",
    ],
    "networking": [
        "socket", "connect", "send", "recv", "getaddrinfo", "curl_easy_perform",
    ],
    "JNI runtime": [
        "JNI_GetCreatedJavaVMs", "__android_log_print", "__android_log_write",
    ],
}

# Strings that change your reading of a library. Each entry is (regex, why).
STRING_PATTERNS = [
    (r"^/system/|^/sbin/|^/vendor/|^/data/local/tmp", "filesystem path probe"),
    (r"(^|/)su$|busybox|magisk|supersu|superuser|kernelsu|ksud", "root indicator"),
    (r"frida|gum-js|gmain|linjector|27042|re\.frida", "anti-instrumentation"),
    (r"xposed|substrate|riru|zygisk|lsposed", "hooking-framework detection"),
    (r"TracerPid|/proc/self/(maps|status|task|cmdline)", "self-inspection"),
    (r"ro\.debuggable|ro\.secure|ro\.build\.tags|ro\.boot\.verifiedbootstate", "property probe"),
    (r"^https?://", "endpoint"),
    (r"-----BEGIN", "PEM key or certificate"),
    (r"\bAES\b|\bHMAC\b|SHA-?(1|256|512)|PBKDF2|RSA|ECDSA|ChaCha", "crypto algorithm name"),
    (r"^[A-Za-z0-9+/]{40,}={0,2}$", "long base64 blob"),
    (r"^[A-Fa-f0-9]{32,}$", "long hex blob"),
    (r"Java/|Ljava/|\(\[?[BCDFIJSZ]", "JNI signature fragment"),
    (r"^[a-z0-9_]+\.so$", "library name (possible dlopen target)"),
]

MAX_STRINGS_SHOWN = 120

# --------------------------------------------------------------------------- #
# output helpers
# --------------------------------------------------------------------------- #

_summary = {
    "program": "",
    "language": "",
    "sha256": "",
    "jni_static": 0,
    "jni_onload": "no",
    "init_array": 0,
    "imports_flagged": 0,
    "strings_flagged": 0,
    "functions": 0,
    "stripped": "unknown",
}


def banner(title):
    print("")
    print("=" * 78)
    print(title)
    print("=" * 78)


def line(fmt, *args):
    print(fmt % args if args else fmt)


# --------------------------------------------------------------------------- #
# 0. program facts
# --------------------------------------------------------------------------- #

prog = currentProgram  # noqa: F821 - provided by Ghidra
fm = prog.getFunctionManager()
st = prog.getSymbolTable()
listing = prog.getListing()

_summary["program"] = prog.getName()
_summary["language"] = str(prog.getLanguageID())
try:
    _summary["sha256"] = prog.getExecutableSHA256()
except Exception:
    _summary["sha256"] = "?"
_summary["functions"] = fm.getFunctionCount()

banner("Program")
line("  name       : %s", prog.getName())
line("  language   : %s", prog.getLanguageID())
line("  compiler   : %s", prog.getCompilerSpec().getCompilerSpecID())
line("  image base : %s", prog.getImageBase())
line("  sha256     : %s", _summary["sha256"])
line("  functions  : %d", _summary["functions"])
line("  memory     : %d block(s)", len(prog.getMemory().getBlocks()))

# A library with a .symtab was not stripped, which is itself a finding: it hands
# the analyst every internal function name for free.
has_symtab = False
for block in prog.getMemory().getBlocks():
    if block.getName() in (".symtab", ".strtab"):
        has_symtab = True
_summary["stripped"] = "no" if has_symtab else "yes"
line("  stripped   : %s", _summary["stripped"])
if not has_symtab:
    line("               (expected for a release build)")
else:
    line("               [!] NOT stripped - internal symbol names are present")

# --------------------------------------------------------------------------- #
# 1. statically registered JNI entry points
# --------------------------------------------------------------------------- #

banner("1. Statically registered JNI entry points (Java_*)")

java_funcs = []
f = getFirstFunction()  # noqa: F821
while f is not None:
    name = f.getName()
    if name.startswith("Java_"):
        java_funcs.append(f)
    f = getFunctionAfter(f)  # noqa: F821

_summary["jni_static"] = len(java_funcs)

if len(java_funcs) == 0:
    line("  (none found)")
    line("")
    line("  This means one of three things, in order of likelihood:")
    line("    a) Registration is DYNAMIC - look at JNI_OnLoad below.")
    line("    b) The library is a pure dependency with no Java-facing surface.")
    line("    c) You imported the wrong file, or the wrong ABI's copy.")
    line("  See ../README.md section 3.9.")
else:
    for fn in java_funcs:
        # Decode the mangled name back into something readable. The rules are
        # mechanical: '_' separates package components, '_1' encodes a literal
        # underscore, and '__' introduces an encoded argument signature.
        raw = fn.getName()
        body = raw[len("Java_"):]
        overload = None
        if "__" in body:
            body, overload = body.split("__", 1)
        readable = body.replace("_1", "\x00").replace("_", ".").replace("\x00", "_")
        line("  %s", raw)
        line("      -> %s%s", readable,
             ("   [overload sig: " + overload + "]") if overload else "")
        line("      @ %s   (%d bytes)", fn.getEntryPoint(), fn.getBody().getNumAddresses())

# --------------------------------------------------------------------------- #
# 2. JNI_OnLoad, JNI_OnUnload, and .init_array
# --------------------------------------------------------------------------- #

banner("2. Load-time entry points")

for nm in ("JNI_OnLoad", "JNI_OnUnload"):
    syms = getSymbols(nm, None)  # noqa: F821
    if len(syms) == 0:
        line("  %-14s : absent", nm)
        continue
    for s in syms:
        line("  %-14s : %s", nm, s.getAddress())
        if nm == "JNI_OnLoad":
            _summary["jni_onload"] = "yes"

if _summary["jni_onload"] == "yes" and _summary["jni_static"] == 0:
    line("")
    line("  [!] JNI_OnLoad present with NO Java_* exports.")
    line("      This is the signature of DYNAMIC registration. Next steps:")
    line("        1. Define JNIEnv (see ../README.md section 3.8).")
    line("        2. Find the call through offset 0x6b8 (64-bit) = RegisterNatives.")
    line("        3. Follow its third argument to the JNINativeMethod array.")
    line("        4. Or recover it at runtime with Frida - see")
    line("           ../../53-Frida/scripts/native-tracer.js")

# .init_array holds constructors that run at dlopen time, BEFORE JNI_OnLoad and
# before any Java code sees the library. Anti-analysis and unpacking logic is
# put here precisely because it is early. See ../README.md section 11.
init_count = 0
for block in prog.getMemory().getBlocks():
    if block.getName() not in (".init_array", ".preinit_array", ".ctors"):
        continue
    line("")
    line("  %s at %s (%d bytes)", block.getName(), block.getStart(), block.getSize())
    ptr_size = prog.getDefaultPointerSize()
    addr = block.getStart()
    end = block.getEnd()
    while addr.compareTo(end) < 0:
        try:
            target = getDataAt(addr)  # noqa: F821
            val = None
            if target is not None and target.isPointer():
                val = target.getValue()
            else:
                # Read the raw pointer if Ghidra has not typed it yet.
                mem = prog.getMemory()
                raw = mem.getLong(addr) if ptr_size == 8 else mem.getInt(addr)
                if raw != 0:
                    val = prog.getAddressFactory().getDefaultAddressSpace() \
                              .getAddress(raw)
            if val is not None and str(val) != "00000000":
                fn = getFunctionAt(val)  # noqa: F821
                nm = fn.getName() if fn is not None else "(no function defined)"
                line("      [%d] %s  ->  %s", init_count, val, nm)
                init_count += 1
        except Exception:
            pass
        addr = addr.add(ptr_size)

_summary["init_array"] = init_count
if init_count > 0:
    line("")
    line("  [!] %d constructor(s) run at dlopen time, BEFORE JNI_OnLoad.", init_count)
    line("      Read these first if you suspect unpacking or anti-debug.")

# --------------------------------------------------------------------------- #
# 3. interesting imports and their callers
# --------------------------------------------------------------------------- #

banner("3. Imported functions of interest")

# Build a lookup of every import name -> category.
wanted = {}
for category, names in INTERESTING_IMPORTS.items():
    for n in names:
        wanted[n] = category

flagged = {}
for s in st.getExternalSymbols():
    name = s.getName()
    base = name.split("@")[0]  # strip @plt / @@GLIBC style suffixes
    category = wanted.get(base)
    if category is None:
        continue

    callers = set()
    try:
        for r in getReferencesTo(s.getAddress()):  # noqa: F821
            fn = getFunctionContaining(r.getFromAddress())  # noqa: F821
            if fn is not None:
                callers.add("%s @ %s" % (fn.getName(), fn.getEntryPoint()))
    except Exception:
        pass

    flagged.setdefault(category, []).append((base, sorted(callers)))

_summary["imports_flagged"] = sum(len(v) for v in flagged.values())

if len(flagged) == 0:
    line("  (none of the tracked imports are present)")
else:
    for category in sorted(flagged.keys()):
        line("")
        line("  --- %s ---", category)
        for name, callers in sorted(flagged[category]):
            line("    %-30s %d caller(s)", name, len(callers))
            for c in callers[:12]:
                line("        %s", c)
            if len(callers) > 12:
                line("        ... %d more", len(callers) - 12)

# --------------------------------------------------------------------------- #
# 4. strings of interest
# --------------------------------------------------------------------------- #

banner("4. Strings of interest")

compiled = [(re.compile(p), why) for p, why in STRING_PATTERNS]
shown = 0
data_iter = listing.getDefinedData(True)

while data_iter.hasNext() and shown < MAX_STRINGS_SHOWN:
    d = data_iter.next()
    if not d.hasStringValue():
        continue
    try:
        value = str(d.getValue())
    except Exception:
        continue
    if len(value) < 4:
        continue

    for rx, why in compiled:
        if rx.search(value):
            nrefs = 0
            try:
                for _ in getReferencesTo(d.getAddress()):  # noqa: F821
                    nrefs += 1
            except Exception:
                pass
            display = value if len(value) <= 60 else value[:57] + "..."
            line("  %-62s @ %s  xref=%d", display, d.getAddress(), nrefs)
            line("      ^ %s", why)
            shown += 1
            break

_summary["strings_flagged"] = shown

if shown == 0:
    line("  (nothing matched)")
    line("")
    line("  A clean sweep is NOT evidence of absence: string encryption hides")
    line("  all of the above. See ../../40-Obfuscation/README.md.")
elif shown >= MAX_STRINGS_SHOWN:
    line("")
    line("  (output truncated at %d - narrow STRING_PATTERNS)", MAX_STRINGS_SHOWN)

# --------------------------------------------------------------------------- #
# 5. machine-readable summary
# --------------------------------------------------------------------------- #

banner("5. Summary")

line("  %-22s %s", "program", _summary["program"])
line("  %-22s %s", "language", _summary["language"])
line("  %-22s %s", "stripped", _summary["stripped"])
line("  %-22s %d", "functions", _summary["functions"])
line("  %-22s %d", "static JNI entries", _summary["jni_static"])
line("  %-22s %s", "JNI_OnLoad", _summary["jni_onload"])
line("  %-22s %d", "init_array entries", _summary["init_array"])
line("  %-22s %d", "flagged imports", _summary["imports_flagged"])
line("  %-22s %d", "flagged strings", _summary["strings_flagged"])

print("")
print("CSV,%s,%s,%s,%d,%d,%s,%d,%d,%d" % (
    _summary["program"],
    _summary["sha256"],
    _summary["stripped"],
    _summary["functions"],
    _summary["jni_static"],
    _summary["jni_onload"],
    _summary["init_array"],
    _summary["imports_flagged"],
    _summary["strings_flagged"],
))
print("# CSV columns: program,sha256,stripped,functions,jni_static,jni_onload,"
      "init_array,imports_flagged,strings_flagged")

# --------------------------------------------------------------------------- #
# 6. what to do next
# --------------------------------------------------------------------------- #

banner("6. Suggested next steps")

if _summary["jni_static"] > 0:
    line("  * Define JNIEnv, then set signatures on each Java_* function:")
    line("      jstring Java_x_y_z(JNIEnv *env, jobject thiz, jstring arg)")
    line("    ../README.md section 3.8")
if _summary["jni_onload"] == "yes":
    line("  * Read JNI_OnLoad and recover the RegisterNatives table:")
    line("      RecoverRegisterNatives.py, or ../labs/lab-02-dynamic-jni-recovery.md")
if _summary["init_array"] > 0:
    line("  * Read the .init_array constructors FIRST - they run before everything.")
if "code loading" in flagged:
    line("  * This library loads code at runtime. Dump memory after the load and")
    line("    analyse THAT, not the on-disk bytes. ../README.md section 7.4")
if "anti-analysis" in flagged:
    line("  * Anti-analysis imports present. Expect the process to resist")
    line("    attachment. ../../67-BypassingProtections/README.md")
if _summary["jni_static"] == 0 and _summary["jni_onload"] == "no":
    line("  * No Java-facing surface at all. Confirm this library is actually")
    line("    LOADED by the app before spending more time:")
    line("      adb shell cat /proc/$(pidof pkg)/maps | grep '\\.so'")

print("")
print("FindJNI.py complete.")
