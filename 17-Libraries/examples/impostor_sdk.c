/*
 * impostor_sdk.c -- a native library that claims to be part of a well-known
 *                   open-source HTTP client, and is not.
 *
 * WHAT IT IS
 *     The challenge binary for ../labs/lab-05-ctf-library-that-lied.md.
 *
 *     It is built as libokhttp_native.so, it exports symbols shaped like
 *     okhttp3 JNI entry points, and it sits in an APK next to a set of Java
 *     classes under the okhttp3 package. Everything about its NAME says
 *     OkHttp. Nothing about its BEHAVIOUR does.
 *
 *     The single most important fact for the lab, and one you can check
 *     yourself in thirty seconds: OkHttp is a pure Java/Kotlin library. It
 *     ships no native code at all. A .so whose name claims otherwise is
 *     already lying before you have disassembled a single instruction.
 *
 *         # host -- download any real release and look
 *         curl -sO https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/4.9.3/okhttp-4.9.3.jar
 *         unzip -l okhttp-4.9.3.jar | grep -ci '\.so$'      # 0
 *
 *     README section 11 lists "trusting a package prefix" as a reverse
 *     engineer mistake, and this file is that mistake made concrete. A
 *     package name is a string the author chose. So is a .so filename. So is
 *     an exported symbol. None of them is evidence of provenance; all three
 *     are free to forge.
 *
 * WHAT IT ACTUALLY DOES
 *     During dlopen -- in .init_array, before JNI_OnLoad, before any Java
 *     code exists to observe it -- it:
 *
 *       1. reads /proc/self/cmdline to learn which application it is inside;
 *       2. derives a key from that package name;
 *       3. decrypts a blob carried in .rodata using that key;
 *       4. leaves the plaintext in a static buffer, and emits it on a
 *          channel a casual observer will read straight past.
 *
 *     Deriving the key from the host package is the part worth understanding.
 *     It means the blob cannot be decrypted by looking at the .so alone: you
 *     need a second fact, from the manifest, from a running process, or from
 *     a guess. Real malicious SDKs bind their payloads to their environment
 *     for exactly this reason -- an analyst who extracts one file and walks
 *     away with it gets nothing.
 *
 * WHAT IT IS NOT
 *     - Not malware. It has no network code, no persistence, no privilege
 *       escalation, and it exfiltrates nothing. It writes a string to logcat.
 *       Everything hostile about it is structural, so that the lab can teach
 *       identification without shipping anything harmful.
 *     - Not a comment on OkHttp, which is a well-regarded library and is
 *       here purely because it is one everybody can check against: its
 *       releases are on Maven Central and its class sets are verifiable.
 *       The lesson is about the impostor, never about the original.
 *     - Not obfuscated. Chapter 40 owns obfuscation. If this were obfuscated
 *       the lab would be about string recovery rather than identification.
 *
 * BUILD
 *     # app/src/main/cpp/CMakeLists.txt
 *     cmake_minimum_required(VERSION 3.18.1)
 *     project(okhttp_native)
 *     add_library(okhttp_native SHARED impostor_sdk.c)
 *     find_library(log-lib log)
 *     target_link_libraries(okhttp_native ${log-lib})
 *
 *     The host application package MUST be com.liblab.shop. The key is
 *     derived from it, so a different applicationId produces a blob that
 *     decrypts to nothing -- which is itself a fair thing to experience once.
 *
 * AUTHORISED TESTING ONLY.
 */

#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <android/log.h>

/* A log tag chosen to be boring. Analysts filter logcat by the tags they
 * expect to be interesting, and "OkHttp" is not one of them. */
#define TAG "OkHttp"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

/* ------------------------------------------------------------------------ */
/* the payload                                                              */
/* ------------------------------------------------------------------------ */
/*
 * 42 bytes in .rodata. To a strings(1) pass this is nothing: no printable
 * run long enough to notice, no recognisable structure, no entropy signature
 * worth remarking on at this size.
 *
 * It is the flag, XORed byte-wise with the host application's package name
 * repeated. That is the weakest cipher there is, and it is chosen for that:
 * the lab is about locating the key material and understanding when the
 * decryption happens, not about breaking anything.
 */
static const unsigned char kBlob[] = {
    0x2F, 0x26, 0x2F, 0x62, 0x2D, 0x2B, 0x19, 0x0D, 0x3E, 0x0C, 0x4F, 0x07,
    0x01, 0x19, 0x15, 0x3C, 0x03, 0x04, 0x4C, 0x33, 0x1D, 0x0A, 0x0D, 0x15,
    0x3D, 0x41, 0x18, 0x00, 0x1B, 0x04, 0x13, 0x30, 0x03, 0x4B, 0x1A, 0x0C,
    0x10, 0x33, 0x09, 0x03, 0x4A, 0x0E
};

static char g_plain[sizeof(kBlob) + 1];
static int  g_ready = 0;

/* ------------------------------------------------------------------------ */
/* environment binding                                                      */
/* ------------------------------------------------------------------------ */
/*
 * /proc/self/cmdline holds the process name, which for an ordinary Android
 * application is its package name. It is NUL-terminated, so a plain string
 * read gets it without any parsing.
 *
 * Reading it in a constructor is the interesting part. At this moment the
 * process has already been forked from Zygote and renamed, so the package
 * name is available -- but no application code has run, no Context exists,
 * and nothing at the Java layer can observe the read.
 */
static int host_package(char *out, size_t cap) {
    FILE *f = fopen("/proc/self/cmdline", "r");
    if (!f) return 0;
    size_t n = fread(out, 1, cap - 1, f);
    fclose(f);
    if (n == 0) return 0;
    out[n] = '\0';
    /* cmdline is a NUL-separated vector; the first element is what we want,
     * and the fread above already stopped us at the buffer size. A process
     * renamed by the runtime may carry a suffix such as ":remote" for a
     * secondary process -- that would change the key, which is a detail
     * worth knowing if the app declares android:process anywhere. */
    return (int) strlen(out);
}

static void decrypt_with(const char *key, int keylen) {
    if (keylen <= 0) return;
    for (size_t i = 0; i < sizeof(kBlob); i++) {
        g_plain[i] = (char) (kBlob[i] ^ (unsigned char) key[i % (size_t) keylen]);
    }
    g_plain[sizeof(kBlob)] = '\0';
    g_ready = 1;
}

/* ------------------------------------------------------------------------ */
/* the constructor                                                          */
/* ------------------------------------------------------------------------ */
/*
 * This is the whole library. Everything below it is decoration whose only
 * job is to look like the SDK it is pretending to be.
 *
 * Consider what an analyst who hooks only the JNI surface sees: a class
 * called okhttp3.internal.platform.Platform calling a native method called
 * nativeInit, which returns 1. Entirely unremarkable. The work happened
 * before the class was even resolved.
 */
__attribute__((constructor))
static void sdk_init(void) {
    char pkg[128];
    int n = host_package(pkg, sizeof(pkg));

    /* A line that reads like ordinary SDK chatter. Nobody greps for it. */
    LOGI("Platform initialised (%s)", n ? pkg : "unknown");

    if (n > 0) {
        decrypt_with(pkg, n);
        /* Emitted at DEBUG, tagged as the library it is impersonating, with
         * a label that looks like a build identifier. This is the channel:
         * unremarkable, already-present, and read by nobody. */
        LOGD("platform-build=%s", g_ready ? g_plain : "(none)");
    }
}

/* ------------------------------------------------------------------------ */
/* the disguise                                                             */
/* ------------------------------------------------------------------------ */
/*
 * Symbol names in the shape of okhttp3 JNI entry points. Note that these
 * would resolve for real: JNI binds by name, so a class
 * okhttp3.internal.platform.Platform declaring `static native int
 * nativeInit()` will find this function. Nothing about the mechanism cares
 * that the real OkHttp has no such method.
 *
 * README section 3.7 technique 3 makes the point in the other direction:
 * Java_* symbols survive R8 because JNI resolution is by name. That is
 * usually a gift to you. Here it is being used as camouflage, and the
 * defence is the same in both cases -- compare against the real artifact
 * rather than reading the names.
 */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) vm; (void) reserved;
    return JNI_VERSION_1_6;
}

JNIEXPORT jint JNICALL
Java_okhttp3_internal_platform_Platform_nativeInit(JNIEnv *env, jclass clazz) {
    (void) env; (void) clazz;
    return 1;
}

JNIEXPORT jstring JNICALL
Java_okhttp3_internal_platform_Platform_nativeVersion(JNIEnv *env, jclass clazz) {
    (void) clazz;
    /* A plausible-looking version string, present so that a version-banner
     * grep finds something and stops looking. Compare it against the class
     * set: that is the check this string is designed to survive, and the one
     * that catches it. */
    return (*env)->NewStringUTF(env, "okhttp/4.9.3");
}
