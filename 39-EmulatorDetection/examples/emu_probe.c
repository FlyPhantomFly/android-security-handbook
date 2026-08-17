/*
 * examples/emu_probe.c
 *
 * PURPOSE
 *   A native (C) emulator-signal probe for Android. It reads every signal an
 *   app's own native code can reach WITHOUT going through the Java framework --
 *   which matters because every Java-layer signal in this chapter can be
 *   neutralised with a one-line Frida hook, while these require the analyst to
 *   hook libc or patch the binary.
 *
 *   It prints one TSV row per signal:
 *
 *       <group>  <signal>  <value>  <verdict>
 *
 *   where <verdict> is EMU, REAL or UNKNOWN. It deliberately does NOT compute an
 *   overall "is emulator" boolean. Section 3 of the chapter README explains why:
 *   a single boolean is one hook away from being a lie, and the point of a probe
 *   is to hand you the evidence, not a conclusion.
 *
 * BUILD (host, with the Android NDK -- no Android Studio, no Gradle)
 *   NDK=$LOCALAPPDATA/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/windows-x86_64/bin
 *   "$NDK/aarch64-linux-android21-clang" -Wall -Wextra -O2 \
 *        -Wl,-z,max-page-size=16384 -o emu_probe.arm64  emu_probe.c
 *   "$NDK/x86_64-linux-android21-clang"  -Wall -Wextra -O2 \
 *        -Wl,-z,max-page-size=16384 -o emu_probe.x86_64 emu_probe.c
 *
 *   Both targets compile clean with -Wall -Wextra. Verified.
 *
 *   -Wl,-z,max-page-size=16384 IS NOT OPTIONAL and the failure it prevents is
 *   maximally confusing. NDK r25c defaults to 4 KiB ELF segment alignment.
 *   Android 15 emulator images tagged `page_size_16kb` -- the `sdk_gphone16k_*`
 *   family -- run a 16 KiB-page kernel, and the loader cannot map a 4 KiB-aligned
 *   binary there. Every such binary dies with SIGSEGV *before reaching main*.
 *   Measured while writing this chapter: a three-line `int main(void){return 42;}`
 *   built without the flag exits 139 on that AVD. Nothing in the error output
 *   points at page size, so you will blame your own code first. Chapter 70 hit
 *   the same wall independently; this is the flag that fixes it.
 *
 * RUN (host)
 *   adb push emu_probe.arm64 /data/local/tmp/emu_probe
 *   adb shell chmod 755 /data/local/tmp/emu_probe
 *   adb shell /data/local/tmp/emu_probe
 *
 *   If the device's vendor policy blocks execve on /data/local/tmp -- which the
 *   Redmi this chapter was written against does -- invoke the loader directly:
 *
 *   adb shell /system/bin/linker64 /data/local/tmp/emu_probe
 *
 * CLEAN UP
 *   adb shell rm -f /data/local/tmp/emu_probe
 *
 * A NOTE ON WHAT THIS PROVES
 *   Running this from `adb shell` measures what the SHELL uid (2000) can see.
 *   An app runs as an app uid in the SELinux domain `untrusted_app`, which can
 *   be strictly less. Where the two disagree the chapter says so explicitly;
 *   see README section 3.11. Prove reachability from an app, not from the shell.
 *
 * AUTHORISED TESTING ONLY. Run this on a device you own.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Output helpers                                                     */
/* ------------------------------------------------------------------ */

static void row(const char *group, const char *signal,
                const char *value, const char *verdict)
{
    printf("%-10s\t%-34s\t%-46s\t%s\n", group, signal,
           (value && *value) ? value : "(empty)", verdict);
}

/* Case-insensitive substring search. strcasestr is a GNU extension that is
 * present in bionic, but spelling it out keeps the file portable and makes the
 * matching rule explicit rather than implied. */
static int contains_ci(const char *hay, const char *needle)
{
    size_t nl, hl, i, j;
    if (!hay || !needle) return 0;
    nl = strlen(needle);
    hl = strlen(hay);
    if (nl == 0 || nl > hl) return 0;
    for (i = 0; i + nl <= hl; i++) {
        for (j = 0; j < nl; j++) {
            char a = hay[i + j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
        }
        if (j == nl) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Group 1: system properties, read through libc -- NOT through Java   */
/* ------------------------------------------------------------------ */

/*
 * __system_property_get() is the libc entry point that
 * android.os.SystemProperties.get() eventually reaches. Reading it here rather
 * than in Java means a Frida hook on the Java method does not see this call at
 * all -- the analyst has to hook the native symbol instead. That difference is
 * the entire reason a serious check is written in C.
 *
 * Under the hood it does not perform IPC. The property area is a read-only
 * shared mapping of /dev/__properties__, so this is a lock-free read of a trie
 * in the caller's own address space. There is no server to intercept.
 */
static void probe_prop(const char *name, const char *emu_if_equals,
                       const char *emu_if_contains)
{
    char buf[PROP_VALUE_MAX + 1];
    int n;
    const char *verdict = "UNKNOWN";

    memset(buf, 0, sizeof(buf));
    n = __system_property_get(name, buf);

    if (n <= 0) {
        /* An unset property is not evidence of a real device. The emulator sets
         * some of these only on some images, and a vendor may unset one. */
        verdict = "unset";
    } else if (emu_if_equals && strcmp(buf, emu_if_equals) == 0) {
        verdict = "EMU";
    } else if (emu_if_contains && contains_ci(buf, emu_if_contains)) {
        verdict = "EMU";
    } else {
        verdict = "REAL";
    }
    row("prop", name, buf, verdict);
}

/* Enumerate EVERY property and count the ones whose NAME betrays the emulator.
 *
 * This is worth more than any individual property check and almost nobody does
 * it. There is no public Java API to enumerate properties -- SystemProperties
 * only has get() -- but libc exports __system_property_foreach, so native code
 * can walk the whole trie. An app that spoofs `ro.kernel.qemu` one property at a
 * time still leaves `ro.boottime.qemu-props`, `init.svc.goldfish-logcat` and
 * friends sitting in the trie. See README section 3.4.
 */
struct prop_scan { int total; int emu_named; };

static void foreach_cb(const prop_info *pi, void *cookie)
{
    struct prop_scan *s = (struct prop_scan *)cookie;
    char name[PROP_NAME_MAX + 1];
    char value[PROP_VALUE_MAX + 1];

    memset(name, 0, sizeof(name));
    memset(value, 0, sizeof(value));
    __system_property_read(pi, name, value);

    s->total++;
    if (contains_ci(name, "qemu")     || contains_ci(name, "goldfish") ||
        contains_ci(name, "ranchu")   || contains_ci(name, "genymo")   ||
        contains_ci(name, "vbox")     || contains_ci(name, "nox")      ||
        contains_ci(name, "bluestack")) {
        s->emu_named++;
    }
}

static void probe_prop_trie(void)
{
    struct prop_scan s = { 0, 0 };
    char buf[64];

    if (__system_property_foreach(foreach_cb, &s) != 0) {
        row("proptrie", "__system_property_foreach", "failed", "UNKNOWN");
        return;
    }
    snprintf(buf, sizeof(buf), "%d", s.total);
    row("proptrie", "total properties", buf, "info");

    snprintf(buf, sizeof(buf), "%d", s.emu_named);
    row("proptrie", "properties with emulator NAMES", buf,
        s.emu_named > 0 ? "EMU" : "REAL");
}

/* ------------------------------------------------------------------ */
/* Group 2: device nodes and files                                     */
/* ------------------------------------------------------------------ */

/*
 * access(F_OK) and stat() are the two syscalls behind Java's File.exists().
 * They fail with two DIFFERENT errnos that most published checks conflate:
 *
 *   ENOENT  -- the path genuinely does not exist
 *   EACCES  -- it exists but you may not look at it (DAC or SELinux)
 *
 * Java's File.exists() returns plain `false` for both, which is why a check
 * written in Java cannot tell "no emulator here" from "I am not allowed to
 * know". This probe prints the errno so you can. README section 3.6.
 */
static void probe_path(const char *path, const char *meaning)
{
    struct stat st;
    const char *verdict;
    char detail[192];

    if (stat(path, &st) == 0) {
        snprintf(detail, sizeof(detail), "present mode=%o %s",
                 (unsigned)(st.st_mode & 07777), meaning);
        verdict = "EMU";
    } else if (errno == ENOENT) {
        snprintf(detail, sizeof(detail), "ENOENT (%s)", meaning);
        verdict = "REAL";
    } else {
        /* The interesting case: it may or may not be there. */
        snprintf(detail, sizeof(detail), "errno=%d %s (%s)",
                 errno, strerror(errno), meaning);
        verdict = "UNKNOWN";
    }
    row("path", path, detail, verdict);
}

/* ------------------------------------------------------------------ */
/* Group 3: files whose CONTENT carries the signal                     */
/* ------------------------------------------------------------------ */

static void probe_file_contains(const char *path, const char *needle,
                                const char *label)
{
    int fd;
    ssize_t got;
    char buf[65536];
    char detail[256];

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        snprintf(detail, sizeof(detail), "cannot open: errno=%d %s",
                 errno, strerror(errno));
        /* This is the single most important UNKNOWN in the whole probe.
         * /proc/tty/drivers and /proc/cmdline are both unreadable by an app on
         * a modern device, so any checklist that lists them is listing a check
         * that cannot run. */
        row("content", label, detail, "UNKNOWN");
        return;
    }
    memset(buf, 0, sizeof(buf));
    got = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (got <= 0) {
        row("content", label, "read returned nothing", "UNKNOWN");
        return;
    }
    buf[got] = '\0';

    if (contains_ci(buf, needle)) {
        snprintf(detail, sizeof(detail), "%zd bytes, contains \"%s\"", got, needle);
        row("content", label, detail, "EMU");
    } else {
        snprintf(detail, sizeof(detail), "%zd bytes, no \"%s\"", got, needle);
        row("content", label, detail, "REAL");
    }
}

/* /proc/cpuinfo is readable by apps, and on x86 it carries the `hypervisor`
 * CPUID feature bit -- which the guest cannot clear, because it is reported by
 * the CPU rather than written by Android. Distinguish carefully: an ARM
 * emulator image has no such bit, so this signal is architecture-specific.
 * A "no hypervisor flag" result on arm64 means nothing at all. */
static void probe_cpuinfo(void)
{
    probe_file_contains("/proc/cpuinfo", "hypervisor",
                        "/proc/cpuinfo hypervisor flag (x86 only)");
    probe_file_contains("/proc/cpuinfo", "Android virtual processor",
                        "/proc/cpuinfo model name");
    probe_file_contains("/proc/cpuinfo", "goldfish",
                        "/proc/cpuinfo goldfish");
}

/* ------------------------------------------------------------------ */
/* Group 4: ABI / native bridge                                        */
/* ------------------------------------------------------------------ */

/*
 * The most durable signal in this whole file, and the one that costs an
 * attacker the most to fake.
 *
 * If this binary was compiled for arm64 and is executing, and the property
 * ro.product.cpu.abi says x86_64, then an ARM-to-x86 binary translator
 * (libndk_translation.so, historically libhoudini.so) is between the code and
 * the CPU. That is not something you patch a property to hide: the translation
 * layer has to exist for the code to run at all.
 *
 * We detect our own build architecture at compile time and compare it to what
 * the platform claims.
 */
#if defined(__aarch64__)
#  define BUILD_ARCH "arm64-v8a"
#elif defined(__arm__)
#  define BUILD_ARCH "armeabi-v7a"
#elif defined(__x86_64__)
#  define BUILD_ARCH "x86_64"
#elif defined(__i386__)
#  define BUILD_ARCH "x86"
#else
#  define BUILD_ARCH "unknown"
#endif

static void probe_abi(void)
{
    char abi[PROP_VALUE_MAX + 1];
    char bridge[PROP_VALUE_MAX + 1];
    char detail[192];

    memset(abi, 0, sizeof(abi));
    memset(bridge, 0, sizeof(bridge));
    __system_property_get("ro.product.cpu.abi", abi);
    __system_property_get("ro.dalvik.vm.native.bridge", bridge);

    snprintf(detail, sizeof(detail), "compiled=%s platform=%s", BUILD_ARCH, abi);

    if (abi[0] == '\0') {
        row("abi", "build arch vs ro.product.cpu.abi", detail, "UNKNOWN");
    } else if (strcmp(BUILD_ARCH, abi) != 0) {
        /* We are an ARM binary on an x86 platform, or vice versa. Something is
         * translating. On a physical device that essentially never happens. */
        row("abi", "build arch vs ro.product.cpu.abi", detail, "EMU");
    } else {
        row("abi", "build arch vs ro.product.cpu.abi", detail, "REAL");
    }

    /* An explicitly configured native bridge is the emulator telling you it
     * expects to run foreign binaries. On the API 35 image measured for this
     * chapter this reads "libndk_translation.so"; the Redmi reads "0". */
    if (bridge[0] == '\0' || strcmp(bridge, "0") == 0) {
        row("abi", "ro.dalvik.vm.native.bridge", bridge, "REAL");
    } else {
        row("abi", "ro.dalvik.vm.native.bridge", bridge, "EMU");
    }
}

/* ------------------------------------------------------------------ */
/* Group 5: timing                                                     */
/* ------------------------------------------------------------------ */

/*
 * Timing checks are the weakest family in this chapter and the probe reports
 * them as INFO, never as a verdict. The reasoning is in README section 3.10:
 * a fast desktop host running a QEMU guest with KVM can beat a thermally
 * throttled midrange phone at almost any microbenchmark, so "slow means
 * emulated" is simply false, and a threshold tuned on your laptop will
 * misclassify real devices in the field.
 *
 * It is measured here so the chapter can print real numbers from both sides
 * rather than assert a folk rule.
 */
static void probe_timing(void)
{
    struct timespec t0, t1;
    volatile unsigned long long acc = 0;
    unsigned long i;
    double ns_per_iter;
    char detail[128];
    const unsigned long ITERS = 20000000UL;

    if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0) {
        row("timing", "clock_gettime", "unavailable", "UNKNOWN");
        return;
    }
    for (i = 0; i < ITERS; i++) {
        acc += i ^ (acc >> 3);
    }
    if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) {
        row("timing", "clock_gettime", "unavailable", "UNKNOWN");
        return;
    }

    ns_per_iter = ((double)(t1.tv_sec - t0.tv_sec) * 1e9 +
                   (double)(t1.tv_nsec - t0.tv_nsec)) / (double)ITERS;

    snprintf(detail, sizeof(detail), "%.3f ns/iter over %lu iters (acc=%llu)",
             ns_per_iter, ITERS, (unsigned long long)acc);
    /* INFO, deliberately. Never a verdict. */
    row("timing", "integer ALU loop", detail, "info");
}

/* ------------------------------------------------------------------ */

int main(void)
{
    printf("# emu_probe -- native emulator-signal probe (chapter 39)\n");
    printf("# built for: %s\n", BUILD_ARCH);
    printf("%-10s\t%-34s\t%-46s\t%s\n", "GROUP", "SIGNAL", "VALUE", "VERDICT");
    printf("# ------------------------------------------------------------\n");

    /* --- properties whose VALUE is the signal ---------------------- */
    probe_prop("ro.kernel.qemu",        "1",       NULL);
    probe_prop("ro.boot.qemu",          "1",       NULL);
    probe_prop("ro.boot.qemu.avd_name", NULL,      "");     /* any value = EMU */
    probe_prop("ro.hardware",           NULL,      "ranchu");
    probe_prop("ro.boot.hardware",      NULL,      "ranchu");
    probe_prop("ro.product.board",      NULL,      "goldfish");
    probe_prop("ro.hardware.gralloc",   NULL,      "ranchu");
    probe_prop("ro.hardware.vulkan",    NULL,      "ranchu");
    probe_prop("ro.soc.model",          NULL,      "ranchu");
    probe_prop("ro.hardware.egl",       NULL,      "emulation");
    probe_prop("ro.build.characteristics", NULL,   "emulator");
    probe_prop("ro.product.model",      NULL,      "sdk_gphone");
    probe_prop("ro.product.name",       NULL,      "sdk_gphone");
    probe_prop("ro.build.fingerprint",  NULL,      "generic");
    probe_prop("ro.build.tags",         "dev-keys", NULL);
    probe_prop("ro.build.type",         "userdebug", NULL);
    probe_prop("ro.serialno",           NULL,      "EMULATOR");
    probe_prop("init.svc.goldfish-logcat", NULL,   "running");

    /* --- the whole trie -------------------------------------------- */
    probe_prop_trie();

    /* --- device nodes ---------------------------------------------- */
    /* The classic check, and -- measured on API 35 -- a FALSE NEGATIVE. */
    probe_path("/dev/qemu_pipe",              "classic check, gone on modern AVDs");
    /* What actually exists there now: */
    probe_path("/dev/goldfish_pipe_dprctd",   "the renamed pipe, API 35");
    probe_path("/dev/goldfish_sync",          "goldfish sync driver");
    probe_path("/dev/goldfish_address_space", "goldfish address space driver");
    probe_path("/dev/socket/qemud",           "classic check, long gone");
    probe_path("/dev/hvc0",                   "virtio console");
    probe_path("/sys/module/goldfish_pipe",   "kernel module sysfs entry");
    probe_path("/sys/bus/platform/drivers/goldfish_pipe", "platform driver");
    probe_path("/system/lib/libc_malloc_debug_qemu.so", "classic check, long gone");
    probe_path("/system/bin/qemu-props",      "classic check, long gone");
    probe_path("/dev/socket/genyd",           "Genymotion daemon socket");
    probe_path("/dev/vboxguest",              "VirtualBox guest additions");

    /* --- content --------------------------------------------------- */
    probe_cpuinfo();
    probe_file_contains("/proc/tty/drivers", "goldfish",
                        "/proc/tty/drivers goldfish");
    probe_file_contains("/proc/cmdline", "androidboot.hardware=ranchu",
                        "/proc/cmdline ranchu");
    probe_file_contains("/proc/modules", "goldfish",
                        "/proc/modules goldfish");
    probe_file_contains("/proc/self/mounts", "goldfish",
                        "/proc/self/mounts goldfish");

    /* --- structural ------------------------------------------------ */
    probe_abi();
    probe_timing();

    printf("# ------------------------------------------------------------\n");
    printf("# No overall boolean is printed, on purpose. See README section 3.2.\n");
    return 0;
}
