// examples/EnterpriseBridge.java
//
// Example 9.5a -- the Java half of a JNI layer someone senior owns.
//
// WHAT THIS SHOWS
//     What the boundary looks like when the bug classes in README section 5
//     have been designed out rather than reviewed out:
//
//       - the native handle is never a raw address the caller can see or
//         forge; it is an opaque index, and it is closed exactly once
//       - close() is atomic, so two threads racing cannot double-free
//       - every native method is private; the public API is the only way in,
//         and -- crucially -- the native side does NOT depend on that being
//         true (see enterprise_bridge.cpp, which re-validates everything)
//       - lengths are never passed alongside arrays; the native side derives
//         them, so there is no second source of truth to disagree
//       - the class is registered dynamically, so its name is free to be
//         obfuscated, and the keep rule below reflects that
//
// WHAT IT DOES NOT CLAIM
//     None of this makes the native code a security boundary. It is the same
//     process, the same UID, the same address space. This is engineering
//     discipline that removes memory-safety defects; it is not a defence
//     against an attacker who controls the device. See README section 5.1
//     and the Principal-level interview answer in section 10.
//
// PROGUARD / R8
//     Because registration is dynamic, this class CAN be renamed -- but then
//     the C++ side's FindClass string must be updated to match, which is
//     fragile. Most teams keep the class and let the method names be
//     obfuscated, which dynamic registration also permits since ART is given
//     the name explicitly:
//
//         -keep class com.example.bridge.EnterpriseBridge { *; }
//
//     Contrast with the static-registration keep rule, which is forced:
//         -keepclasseswithmembernames class * { native <methods>; }
//
// HOW TO BUILD
//     See examples/README.md.

package com.example.bridge;

import java.io.Closeable;
import java.util.concurrent.atomic.AtomicLong;

public final class EnterpriseBridge implements Closeable {

    static {
        System.loadLibrary("enterprise");
    }

    // ---------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------

    /**
     * An OPAQUE TOKEN, not an address. The C++ side keeps a table of live
     * sessions and hands out indices with a generation counter mixed in, so
     * a forged or stale value is rejected by an integer comparison rather
     * than being dereferenced. See README section 5.5 fix (c).
     *
     * AtomicLong, not long, so that getAndSet(0) makes close() exactly-once
     * even when two threads race. A plain field allows both threads to read
     * the same non-zero value and both call the native close.
     */
    private final AtomicLong token = new AtomicLong(0);

    private EnterpriseBridge(long t) {
        token.set(t);
    }

    /** Factory, so a half-constructed object can never escape. */
    public static EnterpriseBridge open(String configJson) {
        if (configJson == null) throw new IllegalArgumentException("config is null");
        long t = nativeOpen(configJson);
        if (t == 0) throw new IllegalStateException("native open failed");
        return new EnterpriseBridge(t);
    }

    @Override
    public void close() {
        long t = token.getAndSet(0);          // exactly once, even under a race
        if (t != 0) nativeClose(t);
    }

    private long tokenOrThrow() {
        long t = token.get();
        if (t == 0) throw new IllegalStateException("bridge is closed");
        return t;
    }

    // ---------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------

    /**
     * Note what is NOT in this signature: a length. The array carries its own
     * length, the native side reads it with GetArrayLength, and there is
     * therefore no second source of truth for the two sides to disagree
     * about. Every "trusted length" overflow in README section 5.2 starts
     * with an API that takes both.
     */
    public byte[] seal(byte[] payload) {
        if (payload == null) throw new IllegalArgumentException("payload is null");
        return nativeSeal(tokenOrThrow(), payload);
    }

    public byte[] unseal(byte[] sealed) {
        if (sealed == null) throw new IllegalArgumentException("sealed is null");
        return nativeUnseal(tokenOrThrow(), sealed);
    }

    /**
     * A callback delivered from a native worker thread. The C++ side attaches
     * that thread to the VM, calls this, and detaches -- see
     * enterprise_bridge.cpp's AttachedEnv helper and README section 3.19.
     *
     * This method must not throw across the boundary carelessly: if it does,
     * the native side is required to notice (ExceptionCheck) and decide.
     * enterprise_bridge.cpp logs and clears rather than propagating from a
     * worker thread, because there is no Java caller to propagate to.
     */
    public interface ResultListener {
        void onResult(int code, byte[] data);
    }

    public void sealAsync(byte[] payload, ResultListener listener) {
        if (payload == null || listener == null) {
            throw new IllegalArgumentException("payload and listener are required");
        }
        nativeSealAsync(tokenOrThrow(), payload, listener);
    }

    // ---------------------------------------------------------------
    // Native methods -- all private, all registered dynamically.
    //
    // The signatures, for reference and for hooking:
    //   nativeOpen       (Ljava/lang/String;)J
    //   nativeClose      (J)V
    //   nativeSeal       (J[B)[B
    //   nativeUnseal     (J[B)[B
    //   nativeSealAsync  (J[BLcom/example/bridge/EnterpriseBridge$ResultListener;)V
    //
    // Remember the argument layout for a hook on any of these. They are all
    // STATIC, so args[1] is a jclass:
    //   args[0] JNIEnv*   args[1] jclass   args[2] the first real parameter
    // ---------------------------------------------------------------

    private static native long   nativeOpen(String configJson);
    private static native void   nativeClose(long token);
    private static native byte[] nativeSeal(long token, byte[] payload);
    private static native byte[] nativeUnseal(long token, byte[] sealed);
    private static native void   nativeSealAsync(long token, byte[] payload,
                                                 ResultListener listener);
}
