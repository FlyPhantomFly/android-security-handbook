// examples/IVaultService.aidl
//
// The interface behind VaultService-vulnerable.java and VaultService-fixed.java.
// Both implement THIS EXACT interface: the vulnerability is entirely in the
// implementation, not in the contract. That is the point of shipping one .aidl
// and two services.
//
// BUILD (Windows host -- note the backslashes, this is not cosmetic):
//     aidl.exe --lang=java "-Isrc\" -ogen "src\com\example\notesvault\IVaultService.aidl"
//
// BUILD (Linux / macOS):
//     aidl --lang=java -Isrc -ogen src/com/example/notesvault/IVaultService.aidl
//
// On Windows the AIDL compiler shipped in build-tools 35.0.1 rejects
// forward-slash paths with
//     "directory src/ is not found in any of the import paths: - src\"
// even though the directory plainly exists. Backslashes work. This cost half an
// hour when the chapter's fixtures were built, so it is recorded here.
//
// In a Gradle project none of that applies -- put the file under
// src/main/aidl/com/example/notesvault/ and the plugin does it for you.
//
// ---------------------------------------------------------------------------
// METHOD ORDER IS THE WIRE FORMAT.
//
// The AIDL compiler assigns transaction codes in declaration order, starting at
// IBinder.FIRST_CALL_TRANSACTION (1):
//
//     getAuthToken()      -> code 1
//     setSyncEndpoint()   -> code 2
//     isUnlocked()        -> code 3
//
// APPENDING a method is safe. REORDERING or REMOVING one silently breaks every
// client that was not rebuilt: the client sends code 2 meaning setSyncEndpoint
// and the server dispatches whatever is now second. Nothing warns you, because
// there is no schema on the wire -- only an interface token, and it still
// matches. See 25-Binder section 3.8.
//
// It also means an attacker who knows the ORDER knows the codes, and the order
// is recoverable from the generated Stub in any decompiled APK (README 6.4) or,
// on a live device, guessable by starting at 1.
// ---------------------------------------------------------------------------

package com.example.notesvault;

interface IVaultService {

    /**
     * Returns the current session token.
     *
     * In VaultService-vulnerable.java this has NO caller check and returns the
     * real token to anyone who can bind. Transaction code 1.
     */
    String getAuthToken();

    /**
     * Sets the server the app synchronises with.
     *
     * A write primitive: an attacker who can call this points the victim's own
     * sync traffic at a server they control. Transaction code 2.
     */
    void setSyncEndpoint(String url);

    /**
     * Whether the vault is currently unlocked. Transaction code 3.
     */
    boolean isUnlocked();
}
