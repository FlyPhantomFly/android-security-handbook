/*
 * examples/guarded-app/native_guard.c
 *
 * The native tier of the demonstration app.
 *
 * BUILD (out of tree - never write a .so into this repository):
 *   NDK=$ANDROID_HOME/ndk/25.2.9519653
 *   CC=$NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android21-clang
 *   $CC -shared -fPIC -O2 -Wall -Wextra -o /tmp/libch67guard.so native_guard.c -llog
 *   ../build.sh does exactly this and packages the result.
 *
 * WHY THIS FILE MATTERS MORE THAN Guard.java
 *   Not because native code is harder to read - Ghidra reads it fine - but
 *   because of WHEN it runs.
 *
 *     1. ctor_early()   runs from .init_array, DURING dlopen(), before
 *                       System.loadLibrary() has returned to Java.
 *     2. JNI_OnLoad()   runs immediately after, still inside
 *                       System.loadLibrary(), before any of the app's own
 *                       Java code sees the library.
 *
 *   Both are earlier than any Java-level hook you install by ATTACHING to a
 *   running process, and earlier than a Frida script that waits for
 *   Java.perform() unless you spawn the process suspended. That is the
 *   difference between "my hooks did nothing" and "my hooks ran first", and it
 *   is why ../../scripts/early-instrument.js is built the way it is.
 *
 * WHAT THIS FILE WILL NOT DO
 *   It does not use inline syscalls, it does not check its own text section
 *   for breakpoints, and it does not obfuscate its strings. All three are real
 *   techniques and all three appear in this chapter's prose; leaving them out
 *   of the demo keeps the labs tractable and keeps the file honest about being
 *   a teaching artefact rather than a hardened product.
 *
 * AUTHORISED USE ONLY. Build it, attack it, and leave other people's apps
 * alone.
 */

#include <jni.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>

#define TAG "CH67Guard"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)

/* ------------------------------------------------------------------------ */
/* State recorded at load time, reported to Java later.                       */
/*                                                                            */
/* The report is history, not a live check. An attacker who hooks             */
/* nativeReport() changes the STORY the app tells, not the DECISION the app   */
/* already took - a distinction the chapter calls attacking the wrong seam.   */
/* ------------------------------------------------------------------------ */

static char g_report[1024];
static int  g_report_len = 0;
static int  g_fired = 0;

static void note(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void note(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int space = (int) sizeof(g_report) - g_report_len - 2;
    if (space > 0) {
        int n = vsnprintf(g_report + g_report_len, (size_t) space, fmt, ap);
        if (n > 0) {
            g_report_len += (n < space) ? n : space;
            if (g_report_len < (int) sizeof(g_report) - 1) {
                g_report[g_report_len++] = '\n';
                g_report[g_report_len] = '\0';
            }
        }
    }
    va_end(ap);
}

/* ------------------------------------------------------------------------ */
/* Read 1: is anything listening on the default frida-server port?            */
/*                                                                            */
/* This is the same question Guard.checkFridaPort() asks in Java, asked from  */
/* below. A Java-only hook on java.net.Socket does nothing to it. That        */
/* asymmetry - same question, two tiers, one hook - is the single most common */
/* reason a bypass "works" and the app still refuses to run.                  */
/* ------------------------------------------------------------------------ */

static int frida_port_open(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t) port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int rc = connect(fd, (struct sockaddr *) &sa, sizeof(sa));
    close(fd);
    return rc == 0;
}

/* ------------------------------------------------------------------------ */
/* Read 2: /proc/self/maps, looking for an injected agent.                    */
/* ------------------------------------------------------------------------ */

static int maps_contain_agent(char *witness, size_t witness_len) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    static const char *needles[] = {
        "frida", "gum-js", "gadget", "linjector", "/data/local/tmp/", NULL
    };

    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; needles[i]; i++) {
            if (strstr(line, needles[i])) {
                snprintf(witness, witness_len, "%s", line);
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Read 3: TracerPid.                                                         */
/* ------------------------------------------------------------------------ */

static int tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;

    char line[256];
    int pid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            pid = atoi(line + 10);
            break;
        }
    }
    fclose(f);
    return pid;
}

/* ------------------------------------------------------------------------ */
/* Read 4: thread names.                                                      */
/* ------------------------------------------------------------------------ */

static int suspicious_thread(char *witness, size_t witness_len) {
    DIR *d = opendir("/proc/self/task");
    if (!d) return 0;

    struct dirent *e;
    int found = 0;
    while (!found && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;

        char path[128];
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", e->d_name);

        FILE *f = fopen(path, "r");
        if (!f) continue;

        char comm[64] = {0};
        if (fgets(comm, sizeof(comm), f)) {
            if (strstr(comm, "gum-js") || strstr(comm, "gmain")
                || strstr(comm, "frida") || strstr(comm, "gdbus")) {
                snprintf(witness, witness_len, "tid %s -> %s", e->d_name, comm);
                found = 1;
            }
        }
        fclose(f);
    }
    closedir(d);
    return found;
}

/* ------------------------------------------------------------------------ */
/* Stage 1: the .init_array constructor.                                      */
/*                                                                            */
/* This runs while dlopen() is still on the stack. Nothing of the app's Java  */
/* has executed since the library was requested, and if you attached to a     */
/* running process instead of spawning it, your hooks were installed long     */
/* before - which is exactly the case this DOES let you catch. What it        */
/* defeats is the reader who spawns and then installs hooks lazily.           */
/* ------------------------------------------------------------------------ */

__attribute__((constructor))
static void ctor_early(void) {
    char witness[512] = {0};

    LOGI("ctor: .init_array running (pid=%d)", getpid());
    note("ctor: ran at dlopen time, pid=%d", getpid());

    if (maps_contain_agent(witness, sizeof(witness))) {
        g_fired = 1;
        note("ctor: FIRED frida.maps seam=S2-read witness=%s", witness);
        LOGW("ctor: injected mapping seen: %s", witness);
    } else {
        note("ctor: frida.maps clean");
    }
}

/* ------------------------------------------------------------------------ */
/* Stage 2: JNI_OnLoad.                                                       */
/*                                                                            */
/* Still inside System.loadLibrary(). Responding here with abort() gives the  */
/* symptom this chapter is repeatedly sent readers for: the process dies      */
/* immediately, before any UI, with SIGABRT and a tombstone, and              */
/* `dumpsys activity exit-info` reports reason=5 CRASH_NATIVE.                */
/* ------------------------------------------------------------------------ */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    JNIEnv *env = NULL;
    char witness[512] = {0};

    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad: native tier starting");
    note("JNI_OnLoad: entered");

    int tp = tracer_pid();
    note("JNI_OnLoad: TracerPid=%d", tp);
    if (tp > 0) {
        g_fired = 1;
        note("JNI_OnLoad: FIRED debugger.tracerpid seam=S2-read value=%d", tp);
    }

    if (suspicious_thread(witness, sizeof(witness))) {
        g_fired = 1;
        note("JNI_OnLoad: FIRED frida.threadnames seam=S2-read witness=%s", witness);
    } else {
        note("JNI_OnLoad: frida.threadnames clean");
    }

    if (frida_port_open(27042)) {
        g_fired = 1;
        note("JNI_OnLoad: FIRED frida.port27042 seam=S1-input");
        LOGW("JNI_OnLoad: 127.0.0.1:27042 accepted a connection - aborting");

        /*
         * Respond in native code, immediately, with the most brutal option
         * available. This is what an attacker sees as "the app dies the
         * instant I touch it". It is also, from the defender's side, the
         * WORST response available: it is loud, it is a crash the user
         * reports, and it tells the attacker exactly which check to look at
         * first. Chapter 67 section 5.5 argues the case.
         */
        abort();
    } else {
        note("JNI_OnLoad: frida.port27042 clean");
    }

    note("JNI_OnLoad: complete, fired=%d", g_fired);
    return JNI_VERSION_1_6;
}

/* ------------------------------------------------------------------------ */
/* Reporting surface, called from Java long after the decisions were taken.   */
/* ------------------------------------------------------------------------ */

JNIEXPORT jstring JNICALL
Java_com_pentest_ch67_guarded_NativeGuard_nativeReport(JNIEnv *env, jclass clazz) {
    (void) clazz;
    if (g_report_len == 0) {
        return (*env)->NewStringUTF(env, "(native tier recorded nothing)");
    }
    return (*env)->NewStringUTF(env, g_report);
}

JNIEXPORT void JNICALL
Java_com_pentest_ch67_guarded_NativeGuard_nativeAbort(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    LOGW("nativeAbort: aborting on request from the Java tier");
    abort();
}
