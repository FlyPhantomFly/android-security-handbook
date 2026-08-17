// examples/IVaultService.aidl
//
// WHAT THIS IS
//   The interface behind the matched pair VaultService-vulnerable.java and
//   VaultService-fixed.java. Both implement exactly this, so the only
//   difference between them is the security logic.
//
// WHY IT MATTERS THAT YOU READ THE ORDER
//   The AIDL compiler assigns transaction codes by POSITION, starting at
//   IBinder.FIRST_CALL_TRANSACTION, which is 1. Nothing else determines them:
//   not the method name, not the return type, not an annotation.
//
//       readSecret      -> code 1
//       writeSecret     -> code 2
//       deleteSecret    -> code 3
//       listSecrets     -> code 4
//       notifyChanged   -> code 5   (oneway)
//       registerWatcher -> code 6
//
//   Two consequences:
//
//   1. REORDERING THESE LINES IS A BREAKING ABI CHANGE. Every already-built
//      client keeps sending the old numbers. This is why AOSP interfaces only
//      ever APPEND methods, and why you should too.
//
//   2. An attacker who has this file -- or the decompiled Stub class, which
//      contains the same information as TRANSACTION_* constants -- can call
//      any of these methods by number with no generated code at all. See
//      RawBinderClient.java.
//
// HOW TO BUILD
//   Inside an Android Studio module, put this at
//     src/main/aidl/com/example/vault/IVaultService.aidl
//   and add to the module's build.gradle:
//     android { buildFeatures { aidl true } }
//   The generated Java lands in build/generated/aidl_source_output_dir/.
//
//   To generate it by hand with the SDK's own compiler:
//     $ANDROID_SDK/build-tools/<ver>/aidl \
//         -I. -o out/ com/example/vault/IVaultService.aidl
//
// WHAT THIS WILL *NOT* TELL YOU
//   - Anything about who is allowed to call these methods. AIDL generates
//     dispatch and serialisation. It generates NO security whatsoever. Every
//     check is code the service author has to write, which is the entire
//     subject of README section 3.12.
//   - Whether the service is exported. That is the manifest's job.

package com.example.vault;

import com.example.vault.IVaultWatcher;

interface IVaultService {

    /**
     * Code 1.
     * Parcel in : interface token, then String16 name.
     * Parcel out: int32 exception header, then String16 result.
     *
     * `name` is HOSTILE INPUT. In the vulnerable implementation it is passed
     * straight to new File(name), which makes it an absolute-path read
     * primitive with the service's privileges.
     */
    String readSecret(String name);

    /**
     * Code 2.
     * Parcel in : interface token, String16 name, String16 value.
     */
    void writeSecret(String name, String value);

    /**
     * Code 3.
     * Parcel out: int32 exception header, then int32 boolean.
     */
    boolean deleteSecret(String name);

    /**
     * Code 4.
     * Parcel out: int32 exception header, then an int32 count and that many
     * String16 values. Note that a null array is written as the single
     * int32 -1, which is NOT the same as an empty array (int32 0).
     */
    String[] listSecrets();

    /**
     * Code 5. ONEWAY.
     *
     * Three things change because of that keyword, and all three matter:
     *   - the caller does not block and gets no reply;
     *   - an exception thrown here NEVER reaches the caller;
     *   - on the receiving side Binder.getCallingPid() is 0, because the
     *     driver records no sending thread for a one-way transaction.
     *
     * The return type must be void. It cannot be anything else.
     */
    oneway void notifyChanged(String name);

    /**
     * Code 6.
     *
     * Passing an IBinder is passing a CAPABILITY. The kernel translates the
     * object reference so it is usable in the receiving process, and whoever
     * holds it can call it -- including a third party the receiver hands it
     * on to, who never satisfied any manifest permission.
     *
     * A service that keeps these must linkToDeath on each one, or the map is
     * an unauthenticated memory-exhaustion primitive: bind, register, die,
     * repeat.
     */
    void registerWatcher(IVaultWatcher watcher);
}
