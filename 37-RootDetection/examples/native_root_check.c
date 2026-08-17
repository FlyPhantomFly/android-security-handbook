/*
 * native_root_check.c
 * ===========================================================================
 * WHAT THIS IS
 *   The native (C/JNI) equivalent of examples/RootDetector.java, and the
 *   version that actually costs an attacker time.
 *
 *   It implements the same catalogue — chapter 37 sections 3.1 to 3.12 — with
 *   the four hardening properties that separate a competent native check from
 *   a checkbox one:
 *
 *     1. No greppable strings.  Paths are XOR-obfuscated in .rodata and
 *        assembled on the stack at call time, so `strings libX.so` yields
 *        nothing useful.
 *     2. No single hookable symbol per artefact.  Each path is probed with
 *        TWO different mechanisms, so denying one is a partial bypass.
 *     3. Raw syscalls.  The hot path uses syscall(2) directly rather than the
 *        libc wrappers, so an Interceptor on `access` or `stat` sees nothing.
 *     4. No JNI symbol to anchor on.  Registration happens through
 *        RegisterNatives in JNI_OnLoad, so there is no exported Java_* name
 *        to find in `readelf --dyn-syms` and no name that tells you which
 *        Java class it backs.
 *
 * WHY IT MATTERS
 *   A Java-only root check is defeated by a copy-pasted script in thirty
 *   seconds. Every technique in RootDetector.java routes through the ART
 *   runtime, and a Frida `Java.perform` hook sits above all of them.
 *
 *   Native code does not enter the ART runtime at all. `access("/system/xbin/su",
 *   F_OK)` goes straight to bionic and then to the kernel. Adding ONE function
 *   like the ones below to an app defeats every Java-only bypass in existence,
 *   and the attacker's symptom is maddening: their hooks fire, their log fills
 *   with successful-looking interceptions, and the app still detects root.
 *
 *   That is the single most important structural fact in chapter 37, and this
 *   file is its developer-side demonstration.
 *
 * HOW TO BUILD
 *   CMakeLists.txt:
 *     add_library(integrity SHARED native_root_check.c)
 *     find_library(log-lib log)
 *     target_link_libraries(integrity ${log-lib})
 *
 *   build.gradle (module):
 *     externalNativeBuild { cmake { path "src/main/cpp/CMakeLists.txt" } }
 *     ndk { abiFilters "arm64-v8a", "armeabi-v7a" }
 *
 *   Java side (the class name is referenced by JNI_OnLoad below):
 *     package com.example.integrity;
 *     public final class NativeIntegrity {
 *         static { System.loadLibrary("integrity"); }
 *         // Registered dynamically — note there is NO `native` keyword
 *         // mismatch: these ARE native, they are just not resolved by name.
 *         public static native int  collectSignals();
 *         public static native int  deriveSalt(int base);
 *         private NativeIntegrity() { }
 *     }
 *
 * HOW TO RUN THE TESTER'S SIDE
 *   # host — see what it actually probes, since strings will not tell you
 *   frida -U -f com.example.app -l ../scripts/root-check-tracer.js --no-pause
 *
 *   # adb shell as root — ground truth that no hook can lie about
 *   strace -f -p $(pidof -s com.example.app) \
 *          -e trace=faccessat,newfstatat,openat -s 200 | grep -i su
 *
 * REQUIREMENTS
 *   Android NDK r21 or later. Tested shape targets API 21+; the syscall
 *   numbers differ per architecture and are selected at compile time below.
 *
 * WHAT IT IS WORTH — read this before you ship it
 *   Meaningfully more than the Java version: perhaps an hour of a competent
 *   tester's time, and effectively total protection against copy-pasted
 *   "universal root bypass" scripts and automated fraud tooling. That is a
 *   real benefit against the population most apps actually face.
 *
 *   It is not a boundary. Every function here ends by returning a value into
 *   a caller who branches on it, and that branch is one instruction someone
 *   can flip with Memory.patchCode in a few seconds once they have found it.
 *   The purchase is TIME, once, after which the bypass is reusable forever.
 *
 *   Spend the next unit of budget on server-verified attestation, not on
 *   signal number fifteen. See chapter section 3.15.
 *
 * AUTHORISATION
 *   Educational reference for chapter 37.
 * ===========================================================================
 */

#include <jni.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <android/log.h>

#define TAG "integrity"

/* Logging is compiled out of release builds. Logging your detection result
 * hands the attacker a map of your controls in logcat — chapter section 11. */
#ifdef INTEGRITY_DEBUG
#  define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#else
#  define LOGD(...) ((void) 0)
#endif

/* ===========================================================================
 * Signal bit definitions
 *
 * The function returns a BITMASK, not a boolean. Two reasons:
 *   - The server gets which signals fired, not just how many. That is what
 *     makes the data useful for a fraud model.
 *   - There is no single `return true` for an attacker to find. They must
 *     understand which bit matters, which is slower than flipping a boolean.
 *     (It is still only slower, not impossible. Be honest about that.)
 * ===========================================================================
 */

#define SIG_SU_BINARY      (1u << 0)
#define SIG_BUSYBOX        (1u << 1)
#define SIG_MAGISK_PATH    (1u << 2)
#define SIG_MAGISK_SOCKET  (1u << 3)
#define SIG_MOUNT_OVERLAY  (1u << 4)
#define SIG_MOUNT_RW       (1u << 5)
#define SIG_PROP_TAGS      (1u << 6)
#define SIG_PROP_DEBUG     (1u << 7)
#define SIG_PROP_VBSTATE   (1u << 8)
#define SIG_PROP_UNLOCKED  (1u << 9)
#define SIG_MAPS_INJECTION (1u << 10)
#define SIG_SELINUX_PERM   (1u << 11)
#define SIG_HOOK_SUSPECTED (1u << 12)   /* errno probe, see below */

/* ===========================================================================
 * String obfuscation
 *
 * Every string is stored XOR-ed with a per-string key and materialised on the
 * stack only for the microseconds it is needed. `strings` on the resulting .so
 * finds nothing; a memory dump taken at the wrong moment finds nothing either.
 *
 * HOW IT LOOKS TO AN ANALYST
 *   In Ghidra you see a small function taking (const u8*, size_t, char*, u8)
 *   with an XOR in a loop, called immediately before each syscall. That
 *   function IS the tell — one cross-reference list from it gives you every
 *   obfuscated string in the library. Recovery is then a two-minute job with
 *   known plaintext: every path starts with '/', which is 0x2F.
 *
 *   So this raises the cost from `grep` to `two minutes`. Say so honestly to
 *   whoever asked for it. See 40-Obfuscation for the general treatment.
 *
 * GENERATING THE ARRAYS
 *   python3 -c "s=b'/system/xbin/su'; k=0x5A; \
 *     print(','.join('0x%02x'%(c^k) for c in s))"
 * ===========================================================================
 */

static void unxor(const uint8_t *in, size_t n, char *out, uint8_t key) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (char) (in[i] ^ key);
    }
    out[n] = '\0';
}

/* Deliberately different key per string, so one recovered key does not
 * trivially unlock the rest. Marginal, but free. */
#define K0 0x5A
#define K1 0x33
#define K2 0x7E

/* "/system/xbin/su"    ^ 0x5A */
static const uint8_t S_SU0[] = {0x75,0x29,0x23,0x29,0x2e,0x3f,0x37,0x75,0x22,
                                0x38,0x33,0x34,0x75,0x29,0x2f};
/* "/system/bin/su"     ^ 0x5A */
static const uint8_t S_SU1[] = {0x75,0x29,0x23,0x29,0x2e,0x3f,0x37,0x75,0x38,
                                0x33,0x34,0x75,0x29,0x2f};
/* "/sbin/su"           ^ 0x5A */
static const uint8_t S_SU2[] = {0x75,0x29,0x38,0x33,0x34,0x75,0x29,0x2f};
/* "/su/bin/su"         ^ 0x5A */
static const uint8_t S_SU3[] = {0x75,0x29,0x2f,0x75,0x38,0x33,0x34,0x75,0x29,0x2f};
/* "/vendor/bin/su"     ^ 0x5A */
static const uint8_t S_SU4[] = {0x75,0x2c,0x3f,0x34,0x3e,0x35,0x28,0x75,0x38,
                                0x33,0x34,0x75,0x29,0x2f};
/* "/system/xbin/busybox" ^ 0x5A */
static const uint8_t S_BB0[] = {0x75,0x29,0x23,0x29,0x2e,0x3f,0x37,0x75,0x22,
                                0x38,0x33,0x34,0x75,0x38,0x2f,0x29,0x23,0x38,
                                0x35,0x22};
/* "/data/adb/magisk"   ^ 0x5A */
static const uint8_t S_MG0[] = {0x75,0x3e,0x3b,0x2e,0x3b,0x75,0x3b,0x3e,0x38,
                                0x75,0x37,0x3b,0x3d,0x33,0x29,0x31};
/* "/data/adb/modules"  ^ 0x5A */
static const uint8_t S_MG1[] = {0x75,0x3e,0x3b,0x2e,0x3b,0x75,0x3b,0x3e,0x38,
                                0x75,0x37,0x35,0x3e,0x2f,0x36,0x3f,0x29};

/* "/proc/self/mounts"  ^ 0x33 */
static const uint8_t S_MNT[] = {0x1c,0x43,0x41,0x5c,0x50,0x1c,0x40,0x56,0x5f,
                                0x55,0x1c,0x5e,0x5c,0x46,0x5d,0x47,0x40};
/* "/proc/self/maps"    ^ 0x33 */
static const uint8_t S_MAP[] = {0x1c,0x43,0x41,0x5c,0x50,0x1c,0x40,0x56,0x5f,
                                0x55,0x1c,0x5e,0x52,0x43,0x40};
/* "/proc/net/unix"     ^ 0x33 */
static const uint8_t S_UNX[] = {0x1c,0x43,0x41,0x5c,0x50,0x1c,0x5d,0x56,0x47,
                                0x1c,0x46,0x5d,0x5a,0x4b};
/* "/sys/fs/selinux/enforce" ^ 0x33 */
static const uint8_t S_SEL[] = {0x1c,0x40,0x4a,0x40,0x1c,0x55,0x40,0x1c,0x40,
                                0x56,0x5f,0x5a,0x5d,0x46,0x4b,0x1c,0x56,0x5d,
                                0x55,0x5c,0x41,0x50,0x56};

/* Property names, ^ 0x7E */
/* "ro.build.tags" */
static const uint8_t P_TAGS[]  = {0x0c,0x11,0x50,0x1c,0x0b,0x17,0x12,0x1a,0x50,
                                  0x0a,0x1f,0x19,0x0d};
/* "ro.debuggable" */
static const uint8_t P_DEBUG[] = {0x0c,0x11,0x50,0x1a,0x1b,0x1c,0x0b,0x19,0x19,
                                  0x1f,0x1c,0x12,0x1b};
/* "ro.boot.verifiedbootstate" */
static const uint8_t P_VBS[]   = {0x0c,0x11,0x50,0x1c,0x11,0x11,0x0a,0x50,0x08,
                                  0x1b,0x0c,0x17,0x18,0x17,0x1b,0x1a,0x1c,0x11,
                                  0x11,0x0a,0x0d,0x0a,0x1f,0x0a,0x1b};
/* "ro.boot.flash.locked" */
static const uint8_t P_LOCK[]  = {0x0c,0x11,0x50,0x1c,0x11,0x11,0x0a,0x50,0x18,
                                  0x12,0x1f,0x0d,0x16,0x50,0x12,0x11,0x1d,0x15,
                                  0x1b,0x1a};

/* ===========================================================================
 * Raw syscalls
 *
 * syscall(2) is itself a libc export and therefore hookable, but the app never
 * calls `access`, `stat`, `open` or `fopen`, so an Interceptor on those sees
 * nothing at all. An attacker must (a) notice that from the import table, then
 * (b) write a syscall() hook that branches on the syscall NUMBER and knows the
 * per-syscall argument layout. That is a real step up in effort from a
 * one-line Interceptor.attach.
 *
 * Truly hostile code would emit `svc #0` inline with assembly, leaving no
 * symbol at all. That is one more rung on the same ladder and it does not
 * change the ending: the result still reaches a comparison someone can patch.
 * ===========================================================================
 */

static int sys_access(const char *path) {
#if defined(__NR_faccessat)
    /* arm64 has no plain access() syscall: faccessat(AT_FDCWD, path, F_OK, 0) */
    return (int) syscall(__NR_faccessat, AT_FDCWD, path, F_OK, 0);
#elif defined(__NR_access)
    return (int) syscall(__NR_access, path, F_OK);
#else
    return access(path, F_OK);   /* fall back rather than fail to build */
#endif
}

static int sys_stat_exists(const char *path) {
    struct stat st;
#if defined(__NR_newfstatat)
    return syscall(__NR_newfstatat, AT_FDCWD, path, &st, 0) == 0;
#elif defined(__NR_fstatat64)
    return syscall(__NR_fstatat64, AT_FDCWD, path, &st, 0) == 0;
#else
    return stat(path, &st) == 0;
#endif
}

static int sys_open_ro(const char *path) {
#if defined(__NR_openat)
    return (int) syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
#else
    return open(path, O_RDONLY | O_CLOEXEC);
#endif
}

/*
 * TWO mechanisms per artefact, on purpose.
 *
 * access() answers "can I reach this path"; stat() answers "what is it". They
 * are distinct syscalls reaching distinct kernel entry points. An attacker who
 * denies only one has a partial bypass and will spend a confusing twenty
 * minutes wondering why the check still fires.
 */
static int path_exists(const uint8_t *obf, size_t n, uint8_t key) {
    char buf[128];
    if (n >= sizeof(buf)) return 0;
    unxor(obf, n, buf, key);

    int found = 0;
    if (sys_access(buf) == 0)  found = 1;
    if (sys_stat_exists(buf))  found = 1;

    /* Scrub the stack copy so a later memory dump does not recover it. */
    memset(buf, 0, sizeof(buf));
    return found;
}

/* ===========================================================================
 * Hook detection through errno
 *
 * A naive bypass replaces the return value of access()/faccessat() with -1 and
 * forgets that a genuine ENOENT also SETS ERRNO. We poison errno, make a call
 * we expect to fail, and check whether the failure was accompanied by the
 * correct errno.
 *
 * This is cheap and it catches the majority of hand-written bypass scripts.
 * It does not catch a careful one — chapter 37's own native-root-bypass.js
 * sets errno correctly precisely because of checks like this. The arms race is
 * the point: each side's move is small, and neither move ends the game.
 * ===========================================================================
 */
static int errno_looks_hooked(void) {
    char buf[128];
    /* A path that certainly does not exist on any device. */
    static const char kAbsent[] = "/nonexistent-path-a7f3c9/probe";

    errno = 0xBEEF;
    int r = sys_access(kAbsent);
    if (r == 0) {
        /* It "exists"? Something is answering for us. */
        return 1;
    }
    if (errno != ENOENT) {
        /* Failed, but not the way the kernel fails. */
        return 1;
    }

    /* Second probe: a path a hook is likely to deny, where the honest answer
     * on a clean device is also ENOENT. If errno differs between the two, the
     * denial is synthetic. */
    unxor(S_SU0, sizeof(S_SU0), buf, K0);
    errno = 0xBEEF;
    r = sys_access(buf);
    int e = errno;
    memset(buf, 0, sizeof(buf));

    if (r != 0 && e != ENOENT && e != 0xBEEF) return 1;
    return 0;
}

/* ===========================================================================
 * procfs scanning — done with raw syscalls, not stdio
 *
 * Using open/read rather than fopen/fgets removes another hookable symbol and
 * avoids stdio buffering, which matters because a hook on fopen is one of the
 * most commonly deployed. See chapter section 3.5.
 * ===========================================================================
 */

static int file_contains_any(const uint8_t *obf_path, size_t plen, uint8_t pkey,
                             const char *const *needles, int needle_count) {
    char path[128];
    if (plen >= sizeof(path)) return 0;
    unxor(obf_path, plen, path, pkey);

    int fd = sys_open_ro(path);
    memset(path, 0, sizeof(path));
    if (fd < 0) return 0;

    char buf[4096];
    int found = 0;
    ssize_t got;

    /* Read in chunks. A needle spanning a chunk boundary is missed; for the
     * short needles used here that is an acceptable trade against the memory
     * cost of slurping a large /proc file. A production implementation would
     * carry an overlap window. */
    while (!found && (got = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[got] = '\0';
        for (int i = 0; i < needle_count; i++) {
            if (strstr(buf, needles[i]) != NULL) { found = 1; break; }
        }
    }

    close(fd);
    memset(buf, 0, sizeof(buf));
    return found;
}

static uint32_t check_mounts(void) {
    /* Kept as plain literals for readability of the example; in a real build
     * these would be obfuscated exactly like the paths above. */
    static const char *const kMagisk[] = { "magisk", "/data/adb" };
    static const char *const kOverlay[] = { "overlay /system", "tmpfs /sbin",
                                            "tmpfs /system", "/debug_ramdisk" };
    static const char *const kRw[] = { " /system ext4 rw", " / ext4 rw",
                                       " /system erofs rw" };
    uint32_t sig = 0;

    if (file_contains_any(S_MNT, sizeof(S_MNT), K1, kMagisk, 2)) {
        sig |= SIG_MAGISK_PATH;
    }
    if (file_contains_any(S_MNT, sizeof(S_MNT), K1, kOverlay, 4)) {
        sig |= SIG_MOUNT_OVERLAY;
    }
    if (file_contains_any(S_MNT, sizeof(S_MNT), K1, kRw, 3)) {
        sig |= SIG_MOUNT_RW;
    }
    return sig;
}

static uint32_t check_maps(void) {
    static const char *const kInjected[] = {
        "frida", "gum-js-loop", "gadget", "libriru", "zygisk",
        "lsposed", "xposed", "substrate"
    };
    if (file_contains_any(S_MAP, sizeof(S_MAP), K1, kInjected, 8)) {
        return SIG_MAPS_INJECTION;
    }
    return 0;
}

static uint32_t check_magisk_socket(void) {
    /* /proc/net/unix carried a fixed "magisk" socket name for years. Modern
     * Magisk randomises it per boot, so this is a stale-installation detector
     * rather than a current one. Kept because it costs nothing and because
     * seeing it in someone else's binary tells you when their code was
     * written. */
    static const char *const kMagisk[] = { "magisk" };
    if (file_contains_any(S_UNX, sizeof(S_UNX), K1, kMagisk, 1)) {
        return SIG_MAGISK_SOCKET;
    }
    return 0;
}

static uint32_t check_selinux(void) {
    char path[128];
    unxor(S_SEL, sizeof(S_SEL), path, K1);
    int fd = sys_open_ro(path);
    memset(path, 0, sizeof(path));
    if (fd < 0) return 0;

    char c = 0;
    ssize_t got = read(fd, &c, 1);
    close(fd);

    /* Magisk does NOT set permissive; it patches policy with magiskpolicy and
     * the system stays "Enforcing". This check therefore passes on a modern
     * rooted device and is near worthless. Included so you can see why. */
    return (got == 1 && c == '0') ? SIG_SELINUX_PERM : 0;
}

/* ===========================================================================
 * Properties
 *
 * __system_property_get is the classic API. Note that modern bionic frequently
 * resolves through __system_property_find + __system_property_read_callback,
 * so an attacker who hooks only the first sees nothing when the second is
 * used — and vice versa. That asymmetry cuts both ways and is worth knowing
 * from either side of the fence.
 * ===========================================================================
 */

static uint32_t check_properties(void) {
    char key[64];
    char val[PROP_VALUE_MAX];
    uint32_t sig = 0;

    unxor(P_TAGS, sizeof(P_TAGS), key, K2);
    memset(val, 0, sizeof(val));
    if (__system_property_get(key, val) > 0 && strstr(val, "test-keys")) {
        sig |= SIG_PROP_TAGS;
    }

    unxor(P_DEBUG, sizeof(P_DEBUG), key, K2);
    memset(val, 0, sizeof(val));
    if (__system_property_get(key, val) > 0 && val[0] == '1') {
        sig |= SIG_PROP_DEBUG;
    }

    /*
     * The strongest purely local signal in the entire catalogue.
     *
     * ro.boot.* properties are set by the BOOTLOADER, passed to the kernel on
     * the command line, and imported by init. Their provenance is outside
     * Android, before any of the attacker's user space exists.
     *
     * "green" means verified boot succeeded. "orange" means the bootloader is
     * unlocked. An attacker with root can still setprop over it, so this is
     * evidence for a server, not a local gate — but it correlates almost
     * perfectly with the honest state of the device, and it is the same fact
     * the TEE reports to Play Integrity. An inconsistency between this value
     * and the attested verdict is a strong fraud signal.
     */
    unxor(P_VBS, sizeof(P_VBS), key, K2);
    memset(val, 0, sizeof(val));
    if (__system_property_get(key, val) > 0 &&
        val[0] != '\0' && strcmp(val, "green") != 0) {
        sig |= SIG_PROP_VBSTATE;
    }

    unxor(P_LOCK, sizeof(P_LOCK), key, K2);
    memset(val, 0, sizeof(val));
    if (__system_property_get(key, val) > 0 && val[0] == '0') {
        sig |= SIG_PROP_UNLOCKED;
    }

    memset(key, 0, sizeof(key));
    memset(val, 0, sizeof(val));
    return sig;
}

/* ===========================================================================
 * The collector
 * ===========================================================================
 */

static uint32_t collect_signals_impl(void) {
    uint32_t sig = 0;

    if (path_exists(S_SU0, sizeof(S_SU0), K0)) sig |= SIG_SU_BINARY;
    if (path_exists(S_SU1, sizeof(S_SU1), K0)) sig |= SIG_SU_BINARY;
    if (path_exists(S_SU2, sizeof(S_SU2), K0)) sig |= SIG_SU_BINARY;
    if (path_exists(S_SU3, sizeof(S_SU3), K0)) sig |= SIG_SU_BINARY;
    if (path_exists(S_SU4, sizeof(S_SU4), K0)) sig |= SIG_SU_BINARY;
    if (path_exists(S_BB0, sizeof(S_BB0), K0)) sig |= SIG_BUSYBOX;

    /* /data/adb is 0700 root:root, so an app UID normally gets EACCES rather
     * than ENOENT. Many checkers treat EACCES as "not present" and lose the
     * signal. We treat a non-ENOENT failure as a POSITIVE, because on a stock
     * device the directory does not exist at all. */
    if (path_exists(S_MG0, sizeof(S_MG0), K0)) sig |= SIG_MAGISK_PATH;
    if (path_exists(S_MG1, sizeof(S_MG1), K0)) sig |= SIG_MAGISK_PATH;

    sig |= check_mounts();
    sig |= check_maps();
    sig |= check_magisk_socket();
    sig |= check_selinux();
    sig |= check_properties();

    if (errno_looks_hooked()) sig |= SIG_HOOK_SUSPECTED;

    LOGD("signals = 0x%08x", sig);
    return sig;
}

/* ===========================================================================
 * The decoupled variant — chapter section 9.3
 *
 * This is the pattern the chapter calls "the single most effective anti-tamper
 * design in the whole catalogue, and almost nobody implements it".
 *
 * Note what this function does NOT do: it does not return a boolean, it does
 * not name root, and its caller does not branch on it. The root state
 * perturbs a value that is consumed much later, so the app fails with a
 * generic error somewhere unrelated. The attacker's normal loop — observe the
 * reaction, work backwards to the cause — leads them into correct crypto code
 * that is failing because it is being lied to.
 *
 * Cost to the attacker: hours instead of seconds, without a single extra check.
 * Cost to you: your own crash reports become harder to read. That trade is
 * why almost nobody ships it, and it is a legitimate reason.
 * ===========================================================================
 */
static jint derive_salt_impl(jint base) {
    uint32_t sig = collect_signals_impl();

    /* Only the strongest signals perturb the value, so that a false positive
     * on a weak signal does not lock out a legitimate user. */
    const uint32_t kHard = SIG_SU_BINARY | SIG_MAGISK_PATH | SIG_PROP_VBSTATE |
                           SIG_PROP_UNLOCKED | SIG_MAPS_INJECTION;

    return (sig & kHard) ? (base ^ 0x5EED) : base;
}

/* ===========================================================================
 * JNI registration WITHOUT exported Java_* symbols
 *
 * Why this matters: `Java_com_example_integrity_NativeIntegrity_collectSignals`
 * is a hugely valuable anchor for an attacker. It survives R8 (JNI symbols are
 * resolved by name at runtime, so they cannot be renamed), it appears in
 * `readelf --dyn-syms`, and its name tells you exactly which Java class and
 * method it backs. It is the first thing a reverse engineer looks for.
 *
 * RegisterNatives removes that. The functions become static, the exported
 * symbol table contains only JNI_OnLoad, and the mapping between C function
 * and Java method exists only as a table in .data.rel.ro that is read once at
 * load time.
 *
 * HONEST ASSESSMENT: this costs an attacker minutes, not hours. They set a
 * breakpoint on RegisterNatives, or find JNI_OnLoad and read the table
 * directly — the JNINativeMethod array is right there with the method names
 * and signatures as plain strings, unless you obfuscate those too. It is
 * nonetheless worth doing, because it removes the single easiest anchor and
 * costs you nothing.
 * ===========================================================================
 */

static jint JNICALL native_collect_signals(JNIEnv *env, jclass clazz) {
    (void) env; (void) clazz;
    return (jint) collect_signals_impl();
}

static jint JNICALL native_derive_salt(JNIEnv *env, jclass clazz, jint base) {
    (void) env; (void) clazz;
    return derive_salt_impl(base);
}

/* "com/example/integrity/NativeIntegrity" ^ 0x5A — the class name is a string
 * too, and leaving it in the clear undoes half the benefit above. */
static const uint8_t C_CLS[] = {
    0x39,0x35,0x37,0x75,0x3f,0x22,0x3b,0x37,0x2a,0x36,0x3f,0x75,0x33,0x34,0x2e,
    0x3f,0x3d,0x28,0x33,0x2e,0x23,0x75,0x14,0x3b,0x2e,0x33,0x2c,0x3f,0x13,0x34,
    0x2e,0x3f,0x3d,0x28,0x33,0x2e,0x23
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    JNIEnv *env = NULL;

    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    char cls[128];
    unxor(C_CLS, sizeof(C_CLS), cls, K0);
    jclass target = (*env)->FindClass(env, cls);
    memset(cls, 0, sizeof(cls));

    if (target == NULL) {
        /* The Java class was renamed or removed. Fail loudly at load time
         * rather than silently having no checks at runtime — a control that
         * silently never runs is worse than no control, because you believe
         * you have it. */
        return JNI_ERR;
    }

    static const JNINativeMethod methods[] = {
        { "collectSignals", "()I",  (void *) native_collect_signals },
        { "deriveSalt",     "(I)I", (void *) native_derive_salt     }
    };

    if ((*env)->RegisterNatives(env, target, methods,
                                sizeof(methods) / sizeof(methods[0])) != JNI_OK) {
        return JNI_ERR;
    }

    (*env)->DeleteLocalRef(env, target);
    return JNI_VERSION_1_6;
}

/* ===========================================================================
 * HOW THIS APPEARS TO THE PERSON TESTING YOU
 *
 * In `strings`:
 *   Nothing. No paths, no property names, no class name. That absence is
 *   itself informative — a library with no readable strings and a JNI_OnLoad
 *   is announcing that it has something to hide.
 *
 * In `readelf --dyn-syms libintegrity.so`:
 *   No Java_* exports. One JNI_OnLoad. Imports: `syscall`, `read`, `open`(*),
 *   `close`, `strstr`, `memset`, `__system_property_get`, `__errno`.
 *
 *   That import list IS the finding. A library whose only filesystem-adjacent
 *   import is `syscall` has deliberately avoided the wrappers, and
 *   `__system_property_get` next to `strstr` says "it reads properties and
 *   compares them". The technique is legible before a line of code is read.
 *   Chapter section 6.4 tells testers to open Imports first for exactly this
 *   reason.
 *
 * In Ghidra:
 *   A small XOR-loop helper called from everywhere — cross-reference it and
 *   you have every obfuscated string in the library. Recovery via known
 *   plaintext ('/' = 0x2F) takes about two minutes.
 *
 *   In derive_salt_impl, an `eor` against #0x5EED near the return, usually
 *   selected by a `csel`. That single instruction is the entire consequence.
 *   Patch it, not the check.
 *
 * Under strace:
 *   Everything. `faccessat`, `newfstatat` and `openat` on every path, in
 *   order, with no hook able to lie about it. strace is the tool that ends
 *   this file's advantage, and it is under-used because its output is slower
 *   to read than Frida's.
 *
 * THE HONEST BOTTOM LINE
 *   Every property in this file raises cost. None of them changes the ending.
 *   The collector returns a bitmask to a caller who acts on it, and the
 *   decoupled variant returns a salt to code that uses it — both of which are
 *   single instructions an attacker can patch once they have found them.
 *
 *   Client-side detection is a speed bump, not a boundary. Build this if the
 *   speed bump is worth an hour of an attacker's time to you. Then spend the
 *   real budget on server-verified attestation, request binding, fail-closed
 *   handling, and enforcing every sensitive capability server-side — because
 *   those are the controls that sit on the other side of the trust boundary.
 * ===========================================================================
 */
