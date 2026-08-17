// examples/HelloJni.java
//
// Example 9.1 -- the minimum correct JNI bridge, statically registered.
//
// WHAT THIS SHOWS
//     One native method, bound by symbol name. The C side is hello_jni.c.
//     Read the two together: this file declares the contract, that file
//     implements it, and the symbol name is the only thing joining them.
//
// THE SYMBOL THIS PRODUCES
//     Package  com.example.jnidemo
//     Class    HelloJni
//     Method   greeting
//     ->       Java_com_example_jnidemo_HelloJni_greeting
//
//     Verify it yourself without compiling anything:
//         python3 ../scripts/jni_mangle.py --mangle com.example.jnidemo.HelloJni.greeting
//
// HOW TO BUILD (host, requires a JDK and the Android NDK)
//     See examples/README.md. There is no compiler assumed on the machine
//     this repository was written on, so nothing here has been compiled --
//     the code is written to be read, and the build steps are given so you
//     can compile it yourself.
//
// WHAT TO NOTICE
//     1. The static initialiser runs when the class is first used, and
//        System.loadLibrary blocks until JNI_OnLoad (if any) has returned.
//     2. `native` methods have no body. In the DEX they carry ACC_NATIVE
//        (0x0100) and have no code_item.
//     3. The binding is LAZY: the symbol is looked up when greeting() is
//        first called, not when the library is loaded. Delete the symbol
//        from the .so and this class still loads fine -- it throws
//        UnsatisfiedLinkError only at the call.

package com.example.jnidemo;

public class HelloJni {

    static {
        // Maps "hellojni" -> "libhellojni.so" and searches this class's
        // ClassLoader's native library path. See README section 3.1.
        System.loadLibrary("hellojni");
    }

    /**
     * Signature: (Ljava/lang/String;)Ljava/lang/String;
     *
     * The C function receives THREE parameters, not one:
     *     JNIEnv *env      -- synthetic, always first
     *     jobject thiz     -- synthetic, the receiver (this is an instance method)
     *     jstring name     -- the declared parameter
     *
     * In a Frida hook that is args[0], args[1], args[2] respectively.
     */
    public native String greeting(String name);

    /**
     * A deliberately overloaded pair, so you can see the long-name mangling.
     * Because two native methods share the name "describe", the short symbol
     * Java_com_example_jnidemo_HelloJni_describe is ambiguous, so ART falls
     * back to the long form:
     *
     *     describe(int)     -> Java_com_example_jnidemo_HelloJni_describe__I
     *     describe(byte[])  -> Java_com_example_jnidemo_HelloJni_describe___3B
     *
     * Note the THREE underscores in the second one: the "__" overload marker
     * followed by "_3", the escape for '['.
     */
    public native String describe(int value);

    public native String describe(byte[] value);

    /**
     * A static native, to show that args[1] becomes a jclass rather than a
     * jobject. The offset of the real arguments does not change.
     *
     * Signature: ()I
     */
    public static native int version();

    public static void main(String[] args) {
        HelloJni h = new HelloJni();
        System.out.println(h.greeting("world"));
        System.out.println(h.describe(42));
        System.out.println(h.describe(new byte[] { 1, 2, 3 }));
        System.out.println("native version = " + version());
    }
}
