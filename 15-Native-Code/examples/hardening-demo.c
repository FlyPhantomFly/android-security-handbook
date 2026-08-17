/*
 * hardening-demo.c -- one source file, six different ELF files.
 *
 * PURPOSE
 *     Every mitigation on the chapter 15 checklist is a BUILD-TIME decision.
 *     The way to internalise that is to compile this file several ways and
 *     watch the checklist output change while the source does not.
 *
 *     Nothing in here is a realistic library. It is deliberately small so the
 *     resulting .so has a handful of symbols and you can read the whole thing.
 *     The bugs are real bugs, and they are here so that the difference between
 *     "this mitigation is missing" and "this mitigation would have mattered"
 *     is something you can see rather than something you are told.
 *
 * HOW TO BUILD
 *     See examples/build-fixtures.sh, which does all of this for you. Or, by
 *     hand, with the NDK's cross compiler:
 *
 *       NDK=$ANDROID_HOME/ndk/<version>/toolchains/llvm/prebuilt/<host>/bin
 *       CC=$NDK/aarch64-linux-android21-clang
 *
 *       # 1. defaults -- what you get from the compiler driver alone
 *       $CC -shared -fPIC -O2 -o libdemo-default.so hardening-demo.c
 *
 *       # 2. hardened -- what a release build SHOULD look like
 *       $CC -shared -fPIC -O2 \
 *           -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
 *           -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack \
 *           -Wl,-z,max-page-size=16384 \
 *           -o libdemo-hard.so hardening-demo.c
 *
 *       # 3. deliberately weakened -- every mitigation off
 *       $CC -shared -fPIC -O1 \
 *           -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
 *           -Wl,-z,norelro -Wl,-z,lazy -Wl,-z,execstack \
 *           -o libdemo-weak.so hardening-demo.c
 *
 *       # 4. stripped copy of the hardened build
 *       cp libdemo-hard.so libdemo-hard-stripped.so
 *       $NDK/llvm-strip libdemo-hard-stripped.so
 *
 *     Then, for each one:
 *       python3 ../scripts/elf-harden-check.py libdemo-*.so
 *
 * NO BINARY IS SHIPPED WITH THIS CHAPTER, ON PURPOSE
 *     A compiled .so is a build artefact and this repository does not commit
 *     build artefacts -- and you should not run a binary you did not build.
 *     Everything the labs need, you produce yourself in three commands.
 *
 * BUILD STATUS, HONESTLY
 *     This file was compiled and the resulting libraries were checked while the
 *     chapter was written, with NDK r25c's aarch64-linux-android21-clang and
 *     armv7a-linux-androideabi21-clang, on a host that had no other C
 *     toolchain. The outputs quoted in README section 9 are that build's real
 *     output, not an illustration. If your NDK version differs, expect the
 *     symbol addresses to differ and the CHECKLIST STATES not to.
 *
 * WHAT THIS FILE WILL *NOT* SHOW YOU
 *     - A working exploit. There is no payload here and none is needed to see
 *       the mitigations differ.
 *     - Anything about JNI. There is deliberately no JNIEnv, no jstring and no
 *       Java_ prefix in this file, because the JNI bridge is chapter 16's
 *       subject and mixing it in here confuses which layer is being taught.
 *       examples/jni-surface.c is the one that has JNI entry points, and it
 *       has them only so that the export table has something to show.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------
 * A secret in .rodata. This is the single most common real finding in an
 * Android native library, and it needs no bug at all -- `strings` finds it.
 * The compiler puts it in a read-only section; read-only is not secret.
 * ------------------------------------------------------------------------ */
static const char *const API_KEY = "sk_live_0000_REPLACE_ME_0000";

/* ------------------------------------------------------------------------
 * 1. A stack overflow. `strcpy` copies until it finds a terminator, and it has
 *    no idea `buf` is 64 bytes. With -fstack-protector-strong the compiler
 *    puts a canary between `buf` and the saved return address, notices the
 *    corruption on the way out, and calls __stack_chk_fail. Without it, the
 *    return address is simply overwritten.
 *
 *    With _FORTIFY_SOURCE=2 the call becomes __strcpy_chk(dst, src, 64) and
 *    aborts at the point of overflow instead. Look for that symbol change in
 *    the two builds -- it is the clearest single demonstration of what the
 *    flag does.
 * ------------------------------------------------------------------------ */
int check_password(const char *supplied)
{
    char buf[64];
    strcpy(buf, supplied);              /* deliberate: no bound */
    return strcmp(buf, API_KEY) == 0;
}

/* ------------------------------------------------------------------------
 * 2. A heap overflow that FORTIFY cannot see. The destination size is not a
 *    compile-time constant, so there is nothing for __sprintf_chk to check.
 *    This is why "we enabled FORTIFY" is not an answer to "is this safe".
 * ------------------------------------------------------------------------ */
char *build_command(const char *user_input, size_t hint)
{
    char *p = (char *)malloc(hint);     /* caller-supplied size */
    if (!p) {
        return NULL;
    }
    sprintf(p, "fetch --id=%s --key=%s", user_input, API_KEY);
    return p;
}

/* ------------------------------------------------------------------------
 * 3. Command injection. Nothing to do with memory safety at all, and no
 *    mitigation on the checklist addresses it. It is here to make the point
 *    that the checklist is about EXPLOITABILITY OF MEMORY BUGS, and most real
 *    findings in native code are not memory bugs.
 * ------------------------------------------------------------------------ */
void run_helper(const char *arg)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "/system/bin/sh -c 'helper %s'", arg);
    system(cmd);                        /* arg is not quoted or validated */
}

/* ------------------------------------------------------------------------
 * 4. A function pointer in writable memory. Full RELRO does NOT protect this:
 *    RELRO covers relocated sections, and this pointer lives in .data because
 *    the program writes to it itself. An attacker with an arbitrary write does
 *    not need the GOT when a target like this exists.
 * ------------------------------------------------------------------------ */
typedef void (*log_fn)(const char *);
static void default_log(const char *m) { printf("[demo] %s\n", m); }
log_fn g_logger = default_log;          /* .data, writable for the process life */

void set_logger(log_fn f) { g_logger = f; }
void emit(const char *m) { if (g_logger) { g_logger(m); } }

/* ------------------------------------------------------------------------
 * 5. A constructor. This runs when the dynamic linker finishes relocating the
 *    library -- before JNI_OnLoad, before System.loadLibrary returns, before
 *    any Java code observes anything. Its address appears in .init_array.
 *
 *    On AArch64 the .init_array slot in the FILE is zero and the real address
 *    is carried in the R_AARCH64_RELATIVE relocation's addend. On ARM32, which
 *    uses REL rather than RELA, the address really is in the slot. If you read
 *    .init_array by hand, this difference will confuse you exactly once.
 * ------------------------------------------------------------------------ */
__attribute__((constructor))
static void on_load(void)
{
    /* A real one would check for a debugger, or decrypt the payload. */
    emit("constructor ran");
}

/* ------------------------------------------------------------------------
 * 6. Hidden visibility. This function is compiled into .text exactly like the
 *    others, but it does not appear in .dynsym, so Module.findExportByName
 *    cannot find it and `nm -D` will not list it. It is not gone; it is
 *    nameless. Find it by offset from an export, or by pattern.
 * ------------------------------------------------------------------------ */
__attribute__((visibility("hidden")))
int internal_checksum(const unsigned char *p, size_t n)
{
    int acc = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        acc = (acc * 31) + p[i];
    }
    return acc;
}

int public_checksum(const unsigned char *p, size_t n)
{
    return internal_checksum(p, n);
}
