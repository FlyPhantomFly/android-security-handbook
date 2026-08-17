// examples/UnsafeDemo.java
//
// Example 9.3c -- the Java side of unsafe_jni.c / fixed_jni.c.
//
// *** WARNING ***
//     This class is deliberately structured to be exploitable. It exists to
//     demonstrate one sentence:
//
//         A bounds check written in Java protects nothing once the value
//         crosses into C.
//
//     Build it only inside a throwaway test app on a device you control.
//
// WHAT THIS SHOWS
//     The wrapper/native pair that appears in real codebases everywhere: a
//     public method that validates, and a package-private native method that
//     does the work and assumes the validation happened. The validation is
//     real. It is also bypassable three different ways, and none of them
//     require modifying the app:
//
//       1. Reflection.       Method.setAccessible(true) and invoke.
//       2. Frida.            Java.use exposes package-private methods.
//       3. A second thread.  Mutate the array after the check, before the use.
//
// HOW TO BUILD
//     See examples/README.md. Link against libunsafe.so to reproduce the
//     defects, or against libfixed.so to verify the corrections. The symbol
//     names are identical, which is the point: the fix is entirely on the C
//     side, and no Java change is required.

package com.example.jnidemo;

import java.lang.reflect.Method;

public class UnsafeDemo {

    static {
        // Swap for "fixed" to run against the corrected implementation.
        System.loadLibrary("unsafe");
    }

    private static final int MAX = 256;

    // A raw native pointer, stored in a Java field. See README section 5.5.
    // NOTE: this is not final and not atomic. Two threads calling close()
    // concurrently both read the same non-zero value, so both call
    // nativeClose on it. fixed_jni.c makes the native side reject the second
    // call, but the correct Java fix is an AtomicLong with getAndSet(0).
    private long nativeHandle;

    // =================================================================
    // VULN 1 -- the wrapper validates; the native method does not.
    // =================================================================

    /** The API a reviewer reads. The check is real. */
    public byte[] decode(byte[] input) {
        if (input == null || input.length > MAX) {
            throw new IllegalArgumentException("input too large");
        }
        return nativeDecode(input, input.length);
    }

    /**
     * The method that actually runs. Package-private, which is NOT a
     * security boundary -- it is a compile-time visibility rule that
     * reflection ignores entirely.
     *
     * Signature: ([BI)[B
     * Symbol:    Java_com_example_jnidemo_UnsafeDemo_nativeDecode
     */
    native byte[] nativeDecode(byte[] input, int length);

    /** Bypass 1: reflection. No instrumentation framework required. */
    public static byte[] bypassByReflection(UnsafeDemo target, int size) throws Exception {
        Method m = UnsafeDemo.class.getDeclaredMethod(
                "nativeDecode", byte[].class, int.class);
        m.setAccessible(true);
        byte[] big = new byte[size];
        java.util.Arrays.fill(big, (byte) 0x41);
        // The wrapper's `input.length > MAX` check never executes.
        return (byte[]) m.invoke(target, big, size);
    }

    // =================================================================
    // VULN 2 -- UTF-16 units counted against a byte buffer.
    // Signature: (Ljava/lang/String;)V
    // =================================================================

    public static native void nativeLog(String msg);

    /** A string of 127 emoji: 127 UTF-16 units, but far more UTF-8 bytes. */
    public static String overflowString() {
        StringBuilder sb = new StringBuilder();
        // Each of these is one BMP character that encodes to 3 bytes in
        // modified UTF-8, so 127 of them is 381 bytes into a 128-byte buffer.
        for (int i = 0; i < 127; i++) {
            // U+20AC EURO SIGN: one UTF-16 unit, three modified-UTF-8 bytes.
            // Written as a numeric escape so this file stays pure ASCII.
            sb.append((char) 0x20AC);
        }
        return sb.toString();
    }

    // =================================================================
    // VULN 3 -- no exception check on the callback path.
    // Signature: (Lcom/example/jnidemo/UnsafeDemo$Listener;Ljava/lang/String;)V
    // =================================================================

    public interface Listener {
        void onData(String s);
    }

    public native void nativeDeliver(Listener listener, String payload);

    /** A listener that throws, which is all it takes to reach VULN 3. */
    public static final class ThrowingListener implements Listener {
        @Override public void onData(String s) {
            throw new IllegalStateException("boom");
        }
    }

    // =================================================================
    // VULN 4 -- a raw pointer in a long.
    // Signatures: ()J   (J[B)I   (J)V
    // =================================================================

    private static native long nativeOpen();
    private static native int  nativeRead(long handle, byte[] out);
    private static native void nativeClose(long handle);

    public void open()  { nativeHandle = nativeOpen(); }
    public int  read(byte[] out) { return nativeRead(nativeHandle, out); }
    public void close() { nativeClose(nativeHandle); nativeHandle = 0; }

    /**
     * Bypass 4: pass a pointer of your choosing. The native side casts it
     * straight to a struct pointer. A crash at the address you supplied is
     * proof of controlled dereference -- and the tombstone records it.
     */
    public static int forgeHandle(long address) throws Exception {
        Method m = UnsafeDemo.class.getDeclaredMethod(
                "nativeRead", long.class, byte[].class);
        m.setAccessible(true);
        return (Integer) m.invoke(null, address, new byte[16]);
    }

    // =================================================================
    // VULN 5 -- local reference exhaustion.
    // Signature: ([Ljava/lang/String;)I
    // =================================================================

    public native int nativeCount(String[] items);

    /** 600 elements is enough: the ART default cap is 512 per thread. */
    public static String[] overflowArray() {
        String[] a = new String[600];
        java.util.Arrays.fill(a, "x");
        return a;
    }

    // =================================================================
    // A note on the time-of-check/time-of-use window (README section 5.1).
    //
    // Even with the wrapper's check intact and never bypassed, this is
    // racy: decode() reads input.length, then the native code reads the
    // array AGAIN. Between the two, another thread holding a reference to
    // the same array can change its contents. Java's memory model does not
    // close that window, because the second read happens in C.
    //
    // The native-side fix in fixed_jni.c closes it for the LENGTH, because
    // it re-derives the length itself. It cannot close it for the CONTENTS.
    // Code that must see a stable snapshot has to copy first --
    // GetByteArrayRegion into native memory -- and then work only from the
    // copy.
    // =================================================================

    public static void main(String[] args) throws Exception {
        UnsafeDemo d = new UnsafeDemo();

        System.out.println("1. wrapper rejects oversize input:");
        try { d.decode(new byte[4096]); }
        catch (IllegalArgumentException e) { System.out.println("   " + e); }

        System.out.println("2. reflection bypasses the wrapper entirely:");
        bypassByReflection(d, 4096);          // expect: corruption or abort
    }
}
