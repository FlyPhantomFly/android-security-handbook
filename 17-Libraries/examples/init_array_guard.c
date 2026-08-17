/*
 * init_array_guard.c -- a native library whose anti-analysis check runs in
 *                       .init_array, before JNI_OnLoad and before any Java
 *                       code exists.
 *
 * WHAT IT IS
 *     The target for ../labs/lab-04-constructor-hook.md, and a minimal,
 *     honest reproduction of a pattern that is standard in commercial RASP
 *     and anti-fraud SDKs: the decision is made during dlopen(), and by the
 *     time anything you can normally hook exists, it has already been made.
 *
 *     Chapter 17 section 9.1 shows the ordering with two log lines. This file
 *     is the same ordering with a consequence attached.
 *
 * THE ORDERING, WHICH IS THE WHOLE POINT
 *
 *     System.loadLibrary("guarded")
 *       -> Runtime.nativeLoad          (framework)
 *       -> android_dlopen_ext          (libdl / linker)
 *          -> mmap the segments
 *          -> apply relocations
 *          -> run DT_INIT and .init_array   <-- early_guard() RUNS HERE
 *       -> dlsym("JNI_OnLoad") and call it  <-- and only now this
 *       -> the static initialiser returns
 *       -> Java code continues
 *
 *     Everything before the arrow marked "RUNS HERE" happens inside one call
 *     that has not returned yet. A Frida script that installs its hooks in
 *     the onLeave of android_dlopen_ext installs them after the decision.
 *     A Java.perform() hook installs them much later still. Both silently
 *     see nothing, report nothing, and let you believe there was nothing to
 *     see. That failure is the lesson.
 *
 * WHAT IT CHECKS, AND WHY THOSE
 *     Two checks, chosen because they are what real code does and because
 *     each one is defeated at a different layer:
 *
 *       1. TracerPid in /proc/self/status -- non-zero when a debugger or an
 *          injecting process is attached. Read through fopen/fgets, i.e.
 *          through libc, which is ALREADY LOADED when your process starts.
 *          That is the hook point: you cannot hook this library before it
 *          loads, but you can hook the libc it calls.
 *
 *       2. A scan of /proc/self/maps for the names instrumentation leaves
 *          mapped. Same layer, same defeat, and it also catches the case
 *          where the tool did not attach with ptrace.
 *
 *     Neither is strong. They are not meant to be. The point of the lab is
 *     the TIMING, not the strength -- a weak check you never saw run beats a
 *     strong one you neutralised.
 *
 * WHAT THIS IS NOT
 *     - Not a root detector. Chapter 37 owns that.
 *     - Not an obfuscation sample. Chapter 40 owns that. The strings here
 *       are plaintext on purpose, so that the lab is about when the code
 *       runs, not about what the code says.
 *     - Not a Frida bypass tutorial. Chapter 53 owns Frida itself.
 *     - Not shippable protection. Do not put this in a product and believe
 *       it is doing something.
 *
 * BUILD
 *     Drop into app/src/main/cpp/ of an ordinary NDK project.
 *
 *     # app/src/main/cpp/CMakeLists.txt
 *     cmake_minimum_required(VERSION 3.18.1)
 *     project(guarded)
 *     add_library(guarded SHARED init_array_guard.c)
 *     find_library(log-lib log)
 *     target_link_libraries(guarded ${log-lib})
 *
 *     # app/build.gradle  (module)
 *     android {
 *         externalNativeBuild { cmake { path "src/main/cpp/CMakeLists.txt" } }
 *         defaultConfig { ndk { abiFilters "arm64-v8a" } }
 *     }
 *
 *     Confirm the constructor is registered before you go any further:
 *         readelf -S libguarded.so | grep init_array
 *         readelf --dyn-syms libguarded.so | grep -E 'JNI_OnLoad|Java_'
 *     or, with no binutils installed:
 *         python3 ../scripts/lib-fingerprint.py libguarded.so
 *
 * JAVA SIDE
 *
 *     package com.liblab.guarded;
 *
 *     public class Guard {
 *         static { System.loadLibrary("guarded"); }
 *         public static native String secret();
 *         public static native boolean tripped();
 *     }
 *
 * AUTHORISED TESTING ONLY.
 */

#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#define TAG "libguarded"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)

/*
 * The verdict. It is written exactly once, during dlopen(), and read much
 * later. That gap is what makes the naive bypass fail and what makes the
 * "patch the variable afterwards" bypass work -- see the lab's solution
 * ladder, method 2.
 *
 * volatile so the compiler cannot fold the read in secret() into a constant
 * once it has proved to itself that nothing else writes the variable. That
 * would defeat the lab by accident.
 */
static volatile int g_analysis_detected = 0;
static volatile int g_guard_ran = 0;

/* Filled in by the constructor. The lab's flag is derived from it, so that
 * "I saw the constructor run" and "I have the value" are the same claim. */
static unsigned int g_seed = 0;

/* ------------------------------------------------------------------------ */
/* check 1 -- TracerPid                                                     */
/* ------------------------------------------------------------------------ */
/*
 * /proc/self/status has a TracerPid line. It is 0 when nobody is attached
 * and the attaching process's pid otherwise. Read through fopen/fgets on
 * purpose: those are libc exports, libc is mapped before this library is,
 * and a hook placed on them at process spawn is therefore already in place
 * when this function runs. That is the entire bypass, and it is a layering
 * argument rather than a trick.
 */
static int tracer_pid_nonzero(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        /* Failing open is a decision. Real anti-analysis code often treats
         * "I could not check" as "I am being tampered with"; this returns 0
         * so that the lab does not produce false positives on devices where
         * procfs is restricted. Note the choice, because you will meet the
         * other choice in the field. */
        return 0;
    }
    char line[256];
    int tracer = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer = (int) strtol(line + 10, NULL, 10);
            break;
        }
    }
    fclose(f);
    return tracer != 0;
}

/* ------------------------------------------------------------------------ */
/* check 2 -- suspicious mappings                                           */
/* ------------------------------------------------------------------------ */
/*
 * An injected agent has to be mapped into the process to run, and a mapping
 * has a name. Reading your own maps is the cheapest possible detector and
 * catches tools that never used ptrace at all.
 *
 * The needles are plaintext. In a real SDK they would be assembled at
 * runtime or decrypted -- that is chapter 40's subject, not this one's, and
 * putting them in the clear here keeps the lab about timing.
 */
static const char *const kNeedles[] = {
    "frida", "gum-js-loop", "gadget", "linjector", "re.frida.server", NULL
};

static int suspicious_mapping(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int hit = 0;
    while (!hit && fgets(line, sizeof(line), f)) {
        for (int i = 0; kNeedles[i] != NULL; i++) {
            if (strstr(line, kNeedles[i])) {
                LOGW("suspicious mapping: %s", line);
                hit = 1;
                break;
            }
        }
    }
    fclose(f);
    return hit;
}

/* ------------------------------------------------------------------------ */
/* the constructor                                                          */
/* ------------------------------------------------------------------------ */
/*
 * __attribute__((constructor)) puts a pointer to this function into the
 * .init_array section. The dynamic linker walks that array and calls every
 * entry, in order, as the last step of dlopen() -- before dlopen() returns,
 * and therefore before the caller can do anything at all.
 *
 * The optional priority argument (constructor(101)) controls ordering among
 * several constructors in the same library. Priorities below 101 are
 * reserved for the implementation. Multiple .init_array entries in one .so
 * are a good sign that something non-trivial is happening at load time --
 * lib-inventory.sh reports the count for exactly that reason.
 */
__attribute__((constructor(101)))
static void early_guard(void) {
    g_guard_ran = 1;

    int traced = tracer_pid_nonzero();
    int mapped = suspicious_mapping();
    g_analysis_detected = (traced || mapped);

    /* A value that only exists because this function ran. The lab's flag is
     * built from it, so a reader who patches the verdict but never reaches
     * the constructor cannot produce it. */
    g_seed = g_analysis_detected ? 0xDEADBEEFu : 0x5AA53CC3u;

    LOGI("constructor ran: traced=%d mapped=%d verdict=%d",
         traced, mapped, g_analysis_detected);
}

/* ------------------------------------------------------------------------ */
/* JNI                                                                      */
/* ------------------------------------------------------------------------ */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) vm; (void) reserved;
    /* Read the log ordering. This line ALWAYS appears after the constructor
     * line, on every device, on every Android version, because the linker
     * calls the constructors before the runtime can look this symbol up. */
    LOGI("JNI_OnLoad ran (guard already decided: %d)", g_analysis_detected);
    return JNI_VERSION_1_6;
}

JNIEXPORT jboolean JNICALL
Java_com_liblab_guarded_Guard_tripped(JNIEnv *env, jclass clazz) {
    (void) env; (void) clazz;
    return g_analysis_detected ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_liblab_guarded_Guard_secret(JNIEnv *env, jclass clazz) {
    (void) clazz;

    if (!g_guard_ran) {
        /* Cannot happen through a normal load. If you see this, you called
         * the function without letting the library initialise -- which is
         * itself a useful thing to know how to do. */
        return (*env)->NewStringUTF(env, "guard never ran");
    }

    if (g_analysis_detected) {
        /* Note what this does NOT do: it does not crash, exit, or complain.
         * It returns a plausible wrong answer. Silent degradation is what
         * good anti-analysis does, because a loud failure tells you exactly
         * where to look and a quiet one wastes your afternoon. */
        return (*env)->NewStringUTF(env, "the weather is fine");
    }

    /* The real answer, derived from the constructor's seed so that it is
     * inseparable from the constructor having run cleanly. */
    char out[64];
    snprintf(out, sizeof(out), "clean-load-token-%08x", g_seed);
    return (*env)->NewStringUTF(env, out);
}
