// examples/05-tink-envelope.kt
//
// WHAT THIS IS
//   Google Tink used the way it is meant to be used on Android: envelope
//   encryption, with the data keyset held in SharedPreferences but ENCRYPTED by a
//   non-exportable AndroidKeyStore master key, associated data binding every
//   record to its owner and field, and explicit key rotation.
//
//   This is the recommended high-level approach. If you are writing a "secure
//   replacement" paragraph and the app is not constrained to platform APIs only,
//   this is what you recommend.
//
// WHY IT MATTERS
//   Every finding in README section 5.2 is a MISUSE finding. AES is fine; the API
//   around it is a minefield with no guard rails. Cipher.getInstance("AES") is
//   legal and means ECB. GCMParameterSpec takes bits where everything else takes
//   bytes. Nothing in the JCA stops you supplying the same nonce twice, or
//   skipping the MAC, or comparing tags with Arrays.equals.
//
//   Tink's design goal is to make those mistakes unrepresentable rather than
//   merely discouraged:
//
//     - There is no mode parameter. You ask for an Aead; you get AES-GCM or
//       AES-EAX or ChaCha20-Poly1305. ECB is not offered. F-02 cannot occur.
//     - There is no nonce parameter. Tink generates it, prepends it, and parses
//       it back. F-03 and F-04 cannot occur.
//     - Every primitive is authenticated. There is no unauthenticated Aead.
//       F-12 cannot occur.
//     - Keys are objects with types, purposes and status, not byte arrays. You
//       cannot accidentally use a MAC key for encryption.
//     - Rotation is a first-class operation with a primary key and a set of
//       accepted keys, so old ciphertext keeps working during a migration.
//
//   > Mental Model
//   > The JCA hands you a box of scalpels with no handles and expects you to know
//   > which end to hold. Tink hands you three tools with handles, and does not
//   > sell the ones that mostly cut their owner.
//
//   > Pentester's Note
//   > Finding Tink in an app changes what you look for. Stop hunting for ECB and
//   > fixed IVs — they are structurally impossible. Look instead at: (1) is the
//   > keyset encrypted with a master key URI, or written in cleartext? (2) what
//   > is the associated data, and does it actually bind the record to its
//   > context? (3) does the app hold onto raw key material anywhere outside Tink?
//   > Point (1) is where real Tink findings live: withMasterKeyUri() is optional,
//   > and an app that omits it stores its keyset in plaintext SharedPreferences.
//
// HOW TO RUN
//   build.gradle.kts:
//       dependencies {
//           implementation("com.google.crypto.tink:tink-android:<current version>")
//       }
//
//   Then:
//       val vault = RecordVault(context, userId = "42")
//       val blob = vault.seal("email", "alice@example.com".toByteArray())
//       val back = vault.open("email", blob)
//
//   Confirm under instrumentation that no software key is ever visible:
//       # host
//       frida -U -f com.example.secure -l ../scripts/frida-jca-universal-hook.js
//   The keyset-wrapping operations show a key whose getEncoded() is null.
//
// REQUIREMENTS
//   API 23+ for the AndroidKeyStore-backed master key path (Tink falls back to a
//   cleartext keyset below that, which you must decide about explicitly rather
//   than inherit silently — see the note at the bottom).
//   Tink's Android artifact; check the current version rather than pinning one
//   from a document, because the API surface moved between 1.7 and 1.9.
//
// AUTHORISED USE. This file is safe to ship.

package com.example.secure

import android.content.Context
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.aead.PredefinedAeadParameters
import com.google.crypto.tink.integration.android.AndroidKeysetManager

class RecordVault(context: Context, userId: String) {

    private val aead: Aead

    init {
        AeadConfig.register()
        val manager = AndroidKeysetManager.Builder()
            // Keyset is persisted in SharedPreferences, but ENCRYPTED by a
            // non-exportable AndroidKeyStore key referenced by this URI.
            .withSharedPref(context, "record_keyset", "com.example.tink_prefs")
            .withKeyTemplate(PredefinedAeadParameters.AES256_GCM.toKeyTemplate())
            .withMasterKeyUri("android-keystore://record_master_key")
            .build()
        aead = manager.keysetHandle.getPrimitive(Aead::class.java)
        this.userId = userId
    }

    private val userId: String

    /**
     * Associated data binds the ciphertext to the record owner and type.
     * Moving a ciphertext between users or fields now fails authentication,
     * which closes a whole class of confused-deputy bugs that encryption alone does not.
     */
    fun seal(field: String, plaintext: ByteArray): ByteArray =
        aead.encrypt(plaintext, context(field))

    fun open(field: String, ciphertext: ByteArray): ByteArray =
        aead.decrypt(ciphertext, context(field))

    private fun context(field: String): ByteArray =
        "v1|user=$userId|field=$field".toByteArray(Charsets.UTF_8)
}

// ===========================================================================
//  What "envelope encryption" means, drawn out
// ===========================================================================
//
//  Two layers of key, each solving a problem the other cannot.
//
//      +--------------------------------------------------------------+
//      |  AndroidKeyStore / TEE                                        |
//      |    master key  "android-keystore://record_master_key"         |
//      |    - generated inside the keystore, never leaves it           |
//      |    - getEncoded() returns null                                |
//      +----------------------------+---------------------------------+
//                                   | wraps (encrypts)
//                                   v
//      +--------------------------------------------------------------+
//      |  SharedPreferences "com.example.tink_prefs"                   |
//      |    encrypted keyset "record_keyset"                           |
//      |    - contains the DATA keys (AES-256-GCM)                     |
//      |    - useless to anyone who cannot use the master key          |
//      +----------------------------+---------------------------------+
//                                   | data keys decrypt/encrypt
//                                   v
//      +--------------------------------------------------------------+
//      |  Your records                                                 |
//      |    nonce || ciphertext || tag, bound to user+field by AAD     |
//      +--------------------------------------------------------------+
//
//  Why not just use the keystore key directly for every record, as in
//  04-keystore-backed-vault.kt? Three reasons, and they are practical rather
//  than cryptographic:
//
//    1. SPEED. Every keystore operation is a Binder round trip into another
//       process and often into the TEE. Encrypting ten thousand small records
//       that way is slow enough to be visible in a UI. The data key lives in the
//       app process, so bulk work runs at full AES-NI / ARMv8-crypto speed, and
//       only the (rare) keyset unwrap touches the TEE.
//
//    2. ROTATION. Rotating a keystore key means re-encrypting every record under
//       the new key. Rotating a data key inside a Tink keyset means adding a new
//       primary and leaving the old key present for decryption — new writes use
//       the new key, old reads still work, and you migrate lazily.
//
//    3. PORTABILITY. The same keyset design works on a server, in a desktop
//       client, or against a cloud KMS, by changing only the master key URI.
//
//  The cost is honest and worth stating in a review: while the app is running,
//  the DATA key IS in the app's memory, so an attacker with code execution can
//  read it — unlike the pure-keystore design, where they can only borrow the key.
//  Envelope encryption trades a little of that protection for speed and
//  operability. For most apps that is the right trade; for a payment credential
//  it is not.

// ===========================================================================
//  Key rotation
// ===========================================================================

/**
 * Rotation with Tink is a keyset operation, not a data migration.
 *
 * A keyset holds several keys with statuses. Exactly one is PRIMARY (used for
 * encryption); the others remain ENABLED (accepted for decryption). Tink writes a
 * 5-byte key-id prefix into each ciphertext, so decryption picks the right key
 * automatically. That is what makes lazy migration possible.
 *
 * The sketch below uses the KeysetManager API. Check the exact symbols against
 * the Tink version you depend on — this is the one part of Tink whose API has
 * moved between releases, and a document that pins a signature will be wrong
 * before it is old.
 */
object RotationNotes {

    /*
     *  val manager = AndroidKeysetManager.Builder()
     *      .withSharedPref(context, "record_keyset", "com.example.tink_prefs")
     *      .withKeyTemplate(PredefinedAeadParameters.AES256_GCM.toKeyTemplate())
     *      .withMasterKeyUri("android-keystore://record_master_key")
     *      .build()
     *
     *  // Add a new key and make it primary. Existing keys stay enabled, so every
     *  // record already on disk still decrypts.
     *  manager.rotate(PredefinedAeadParameters.AES256_GCM.toKeyTemplate())
     *
     *  // Later, once you are confident nothing old remains:
     *  //   disable, then delete, the superseded key ids.
     */

    /**
     * When to rotate, in decreasing order of urgency:
     *
     *   - Immediately, if you have any reason to believe a key was exposed.
     *   - On a schedule, if a compliance regime requires it (many do; the
     *     cryptographic benefit is modest but the operational benefit is real —
     *     an organisation that has never rotated cannot rotate under pressure).
     *   - When the algorithm changes, e.g. moving from AES-GCM to AES-GCM-SIV.
     *   - When a user's security context changes materially: password change,
     *     device change, re-enrolment.
     *
     * When NOT to rotate: "every 90 days" applied to a key protecting local
     * cache, at the cost of re-encrypting a large database on a user's phone over
     * mobile data. Rotation is not free, and a policy that ignores that produces
     * battery complaints rather than security.
     */
    const val NOTE = "rotate on suspicion, on schedule, on algorithm change"
}

// ===========================================================================
//  The Tink findings that DO exist
// ===========================================================================
//
//  Tink removes the algorithmic findings. It does not remove judgement. These are
//  the four things to check in a Tink-using app, in the order you should check
//  them.
//
//  1. NO MASTER KEY URI  — the finding that matters.
//
//         AndroidKeysetManager.Builder()
//             .withSharedPref(context, "keyset", "prefs")
//             .withKeyTemplate(...)
//             .build()                       // <-- no withMasterKeyUri()
//
//     Without it the keyset is stored in CLEARTEXT in SharedPreferences. Pull
//     the file and read the base64:
//         # adb shell as root
//         cat /data/data/<pkg>/shared_prefs/prefs.xml
//     You get the raw AES key. Severity: High to Critical, exactly as F-01,
//     because it is F-01 wearing a library.
//
//  2. WEAK ASSOCIATED DATA. `aead.encrypt(pt, ByteArray(0))` compiles and runs.
//     Encryption alone does not stop an attacker moving a valid ciphertext from
//     one database row to another, because the key is the same for both. Ask what
//     the ciphertext is bound to. If the answer is "nothing", the app is exposed
//     to relocation attacks even though every primitive is correct.
//
//  3. RAW KEY MATERIAL LEAVING TINK. `CleartextKeysetHandle.write(...)` exists
//     for tests and for interoperability. In production code it is a finding:
//     someone exported the keyset, and wherever it went is now the weakest point.
//     grep for CleartextKeysetHandle.
//
//  4. THE APP DOING ITS OWN CRYPTO ANYWAY. It is common to find Tink used for one
//     feature and a hand-rolled Cipher.getInstance("AES") in another, written
//     before or after. Tink's presence is not evidence that the whole app is
//     clean; run the full sweep regardless.
//
//  > Warning
//  > Do not report "the app uses a third-party crypto library" as a finding. Tink
//  > is maintained by Google's crypto team and is the recommendation. Reporting
//  > its presence as risk is a fast way to be ignored on the findings that matter.

/*
 * ---------------------------------------------------------------------------
 * CHOOSING BETWEEN THE THREE CORRECT DESIGNS IN THIS CHAPTER
 *
 * | Use case                                  | File                            |
 * |-------------------------------------------|---------------------------------|
 * | Key arrives from elsewhere (server, KDF)  | 02-correct-aes-gcm.java         |
 * | Password-derived, offline-capable         | 03-pbkdf2-and-argon2.kt         |
 * | Small amounts of high-value local data    | 04-keystore-backed-vault.kt     |
 * | Large local datasets, rotation, many keys | 05-tink-envelope.kt (this file) |
 *
 * And the one-line version for a report: use Tink; if you cannot add a
 * dependency, use AES-GCM with a key generated in the AndroidKeyStore and a
 * provider-generated nonce.
 *
 * Related: ../../49-KeyStore/README.md, ../../50-HardwareBackedSecurity/README.md,
 *          ../../33-Storage/README.md, ../../71-OWASP-Mobile/README.md
 * ---------------------------------------------------------------------------
 */
