// examples/04-keystore-backed-vault.kt
//
// VERIFICATION
//   Compiles clean under kotlinc 1.9.24 against android-35. It did not before
//   this was checked: describeKey() read info.isRandomizedEncryptionRequired
//   from a KeyInfo, and that accessor is declared on KeyGenParameterSpec (the
//   request), not on KeyInfo (the fact). See the note in describeKey() -- the
//   distinction is the point of that method, so the bug was the exact error the
//   method exists to prevent. Not RUN: which security level a device actually
//   returns is what describeKey() is for on real hardware.
//
// WHAT THIS IS
//   The correct pattern for app-local encryption on Android: the key is GENERATED
//   INSIDE THE ANDROID KEYSTORE and never exists in the app's process. The app
//   holds a handle. Every encryption and decryption is a request to the keystore
//   daemon, which talks to the TEE (or a discrete secure element) over Binder.
//
//   Compare with 02-correct-aes-gcm.java, which is correct in every algorithmic
//   respect but keeps the key in the app's heap. This file removes that last
//   weakness, and in doing so changes what an attacker has to do.
//
// WHY IT MATTERS
//   Read the difference in attacker terms, because that is what determines
//   severity in your report.
//
//     Software key, however well handled:
//       An attacker with code execution in the app process — a Frida hook, a
//       malicious library, a heap dump, a memory-disclosure bug — reads the key
//       bytes and takes them away. From that moment they can decrypt every record
//       the app ever produced, on any machine, forever, offline.
//
//     AndroidKeyStore key:
//       The same attacker cannot read the key, because it is not there.
//       getEncoded() returns null. What they CAN do is ask the keystore to use
//       the key on their behalf, for as long as they have code execution on that
//       device. That is a real and serious attack — but it is an ORACLE, not an
//       EXFILTRATION. It stops when they lose access to the device, it cannot be
//       replayed offline, and with setUserAuthenticationRequired it additionally
//       requires the user to have unlocked recently.
//
//   > Mental Model
//   > A software key is a copy of the house key. A keystore key is a locksmith
//   > who lives in the wall: you can ask them to open the door while you are
//   > standing there, but you cannot take them with you.
//
//   This is the single most valuable design change in the chapter, and it is the
//   remediation you will write most often. The full treatment of the mechanism —
//   keystore2, KeyMint, the TEE boundary, attestation — is in
//   ../../49-KeyStore/README.md; this file is the application-level pattern.
//
// HOW TO RUN
//   Add to an Android module (minSdk 23 for AES in the keystore) and call:
//       val vault = KeystoreVault()
//       val sealed = vault.seal("secret".toByteArray(), aad = "user=42".toByteArray())
//       val plain  = vault.open(sealed, aad = "user=42".toByteArray())
//       Log.i("vault", vault.describeKey())
//
//   To prove the key is really unreachable, attack your own app:
//       # host
//       frida -U -f com.example.secure -l ../scripts/frida-jca-universal-hook.js
//   The Cipher.init hook will print
//       key=<android.security.keystore2.AndroidKeyStoreSecretKey  getEncoded()=null
//            — NON-EXPORTABLE, almost certainly AndroidKeyStore/TEE>
//   That null is the whole point of this file.
//
// REQUIREMENTS
//   API 23+ for symmetric keys in the AndroidKeyStore (API 18+ covers RSA only).
//   API 28+ for StrongBox, which is optional and gracefully skipped.
//   A lock screen must be set for setUserAuthenticationRequired(true) to be
//   satisfiable; handle the case where it is not, because users disable it.
//
// AUTHORISED USE. This file is safe to ship.

package com.example.secure

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class KeystoreVault(private val alias: String = "vault_key_v1") {

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key(): SecretKey {
        (keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            // The provider generates the IV. The app CANNOT supply one, which makes
            // nonce reuse structurally impossible for this key.
            .setRandomizedEncryptionRequired(true)
            // Key usable only within 30 s of a device-credential or biometric unlock.
            .setUserAuthenticationRequired(true)

        if (android.os.Build.VERSION.SDK_INT >= 30) {
            builder.setUserAuthenticationParameters(
                30,
                KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(30)
        }

        if (android.os.Build.VERSION.SDK_INT >= 28) {
            // StrongBox is a discrete secure element. Not present on every device —
            // catch StrongBoxUnavailableException and fall back to the TEE.
            builder.setIsStrongBoxBacked(true)
        }

        return try {
            generate(builder.build())
        } catch (e: android.security.keystore.StrongBoxUnavailableException) {
            builder.setIsStrongBoxBacked(false)
            generate(builder.build())
        }
    }

    private fun generate(spec: KeyGenParameterSpec): SecretKey =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            .apply { init(spec) }
            .generateKey()

    fun seal(plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        aad?.let(c::updateAAD)
        val ct = c.doFinal(plaintext)
        return ByteBuffer.allocate(12 + ct.size).put(c.iv).put(ct).array()
    }

    fun open(record: ByteArray, aad: ByteArray? = null): ByteArray {
        val bb = ByteBuffer.wrap(record)
        val nonce = ByteArray(12).also(bb::get)
        val ct = ByteArray(bb.remaining()).also(bb::get)
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, nonce))
        }
        aad?.let(c::updateAAD)
        return c.doFinal(ct)
    }

    /** Diagnostic: prove to yourself (and to a report) where the key really lives. */
    fun describeKey(): String {
        val k = key()
        val factory = javax.crypto.SecretKeyFactory.getInstance(k.algorithm, "AndroidKeyStore")
        val info = factory.getKeySpec(k, android.security.keystore.KeyInfo::class.java)
                as android.security.keystore.KeyInfo
        return buildString {
            append("alias=").append(info.keystoreAlias)
            append(" size=").append(info.keySize)
            append(" userAuthRequired=").append(info.isUserAuthenticationRequired)
            append(" blockModes=").append(info.blockModes.joinToString("|"))
            append(" paddings=").append(info.encryptionPaddings.joinToString("|"))
            // NOT randomizedEncryption. isRandomizedEncryptionRequired() lives on
            // KeyGenParameterSpec, which is what you ASKED FOR; KeyInfo, which is
            // what you GOT, has no such accessor and never has. That asymmetry is
            // the whole point of this method, so reaching for it here would have
            // been the exact mistake the method exists to prevent. Verified
            // against android-35: KeyInfo exposes isInsideSecureHardware,
            // isUserAuthenticationRequired, blockModes, encryptionPaddings,
            // origin, securityLevel -- and no randomized-encryption flag.
            //
            // You confirm the constraint by USE, not by query: with
            // setRandomizedEncryptionRequired(true) the key refuses an operation
            // that supplies its own IV, so Cipher.init(ENCRYPT_MODE, key,
            // GCMParameterSpec(...)) throws InvalidAlgorithmParameterException.
            // That throw is the evidence for a report.
            append(" securityLevel=")
            append(
                if (android.os.Build.VERSION.SDK_INT >= 31) info.securityLevel.toString()
                else @Suppress("DEPRECATION") info.isInsideSecureHardware.toString()
            )
        }
    }

    // ======================================================================= //
    //  Everything below is the operational reality that a tutorial omits and    //
    //  that a production app cannot.                                           //
    // ======================================================================= //

    /**
     * Delete the key. Every record encrypted under it becomes permanently
     * unreadable, which is exactly what you want on logout or on "erase my data".
     *
     * This is a genuinely useful property: destroying a 32-byte key in the TEE is
     * a faster and more complete erasure than overwriting a database, because the
     * ciphertext can stay on disk and in backups and remain meaningless.
     */
    fun destroy() {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    fun exists(): Boolean = keyStore.containsAlias(alias)

    /**
     * Rotate to a new key version, re-encrypting the supplied records.
     *
     * Note the alias carries a version suffix ("vault_key_v1"). That is not
     * decoration: a keystore key cannot be exported, so rotation ALWAYS means
     * "generate a new key, decrypt with the old one, encrypt with the new one,
     * then delete the old one". Design the alias scheme for that on day one, or
     * the first rotation becomes a migration project.
     */
    fun rotateTo(newAlias: String, records: List<Pair<ByteArray, ByteArray?>>)
            : Pair<KeystoreVault, List<ByteArray>> {
        val next = KeystoreVault(newAlias)
        val migrated = records.map { (record, aad) -> next.seal(open(record, aad), aad) }
        destroy()
        return next to migrated
    }
}

// ===========================================================================
//  The three failure modes you MUST handle
// ===========================================================================
//
//  A keystore key is not a variable. It is a resource owned by another process,
//  subject to the device's security state, and it can become unusable for reasons
//  that have nothing to do with your code. An app that does not handle these
//  three cases will crash in the field, and the crash will look like data
//  corruption.

/**
 * Wrapper showing correct handling. Copy the structure, not just the calls.
 */
class ResilientVault(private val alias: String = "vault_key_v1") {

    private var vault = KeystoreVault(alias)

    sealed class Result {
        data class Ok(val data: ByteArray) : Result()
        /** The user must authenticate, then you retry. Not an error — a state. */
        object NeedsAuthentication : Result()
        /**
         * FAILURE MODE 1 — KeyPermanentlyInvalidatedException.
         *
         * The key was bound to user authentication, and the biometric enrolment or
         * the lock screen changed. Android deliberately invalidates such keys: the
         * user who enrolled the fingerprint is not necessarily the user standing
         * there now, so keeping the key usable would break the guarantee.
         *
         * This is NOT a bug and NOT recoverable. The data encrypted under that key
         * is gone. The only correct responses are:
         *   - delete the key, generate a new one, and re-fetch the data from the
         *     server if you can, or
         *   - tell the user plainly that locally-stored data was cleared because
         *     the device's security settings changed.
         *
         * Apps that swallow this exception and retry in a loop are the reason
         * "encrypted local cache" features get removed.
         */
        object KeyInvalidated : Result()
        data class Failed(val cause: Throwable) : Result()
    }

    fun open(record: ByteArray, aad: ByteArray? = null): Result = try {
        Result.Ok(vault.open(record, aad))
    } catch (e: UserNotAuthenticatedException) {
        // FAILURE MODE 2 — the authentication validity window expired.
        // Prompt with BiometricPrompt, then call this again. See ../../48-Biometrics.
        Result.NeedsAuthentication
    } catch (e: KeyPermanentlyInvalidatedException) {
        Result.KeyInvalidated
    } catch (e: Exception) {
        // FAILURE MODE 3 — the record itself failed authentication
        // (AEADBadTagException), which means it was tampered with, truncated, or
        // encrypted under a different key. Never fall back to returning partial
        // plaintext: that turns a correct design into a decryption oracle.
        Result.Failed(e)
    }

    fun resetAfterInvalidation() {
        vault.destroy()
        vault = KeystoreVault(alias)
    }
}

/*
 * ---------------------------------------------------------------------------
 * DESIGN DECISIONS, AND WHY EACH ONE IS THERE
 *
 * setRandomizedEncryptionRequired(true)
 *     The keystore refuses to accept a caller-supplied IV for this key. Finding
 *     F-04 (nonce reuse) becomes impossible to write, not merely unlikely. When
 *     you can make a class of bug unrepresentable, do it — that beats any amount
 *     of code review. Note the consequence: on decryption you still pass the
 *     nonce back in a GCMParameterSpec, which is allowed; only supplying one on
 *     ENCRYPT is refused.
 *
 * setUserAuthenticationRequired(true) + a 30-second window
 *     Binds key USE to a recent unlock. An attacker with code execution but no
 *     unlocked screen cannot use the key at all. Choose the window deliberately:
 *     0 means "authenticate for every single operation" (correct for a payment
 *     confirmation, hostile for a note-taking app), 30 seconds is a reasonable
 *     default, 300 is generous. From API 30 use setUserAuthenticationParameters,
 *     which lets you say WHICH authenticators count.
 *
 * AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL
 *     Accepting device credential as well as biometrics is a deliberate usability
 *     choice: a user whose fingerprint sensor fails can still reach their data.
 *     If the threat model says otherwise, drop AUTH_DEVICE_CREDENTIAL — but know
 *     that you are also dropping the users who cannot use biometrics.
 *
 * setIsStrongBoxBacked(true) with a fallback
 *     StrongBox is a physically separate secure element with its own CPU and
 *     memory, resistant to attacks that reach the main SoC. It is not present on
 *     most devices, it is slower, and it has tight key-count limits. Request it,
 *     catch StrongBoxUnavailableException, fall back. Never make it mandatory
 *     unless you control the hardware.
 *
 * The alias carries a version suffix
 *     Keystore keys cannot be exported, so rotation is always
 *     generate-decrypt-reencrypt-delete. Version the alias on day one.
 *
 * WHAT THIS DESIGN DOES NOT DO
 *     It does not stop an attacker with code execution from asking the keystore
 *     to decrypt. Nothing does. Be precise about this in reports: the finding
 *     "the app can be made to decrypt its own data under Frida" is true of every
 *     correct design and is not a vulnerability in the crypto. What you should
 *     report instead is whether the app makes that easy — no root detection, no
 *     auth binding, a decrypt-everything method reachable from an exported
 *     component.
 * ---------------------------------------------------------------------------
 * VERSION MATRIX
 *
 * | API | What changes                                                        |
 * |-----|---------------------------------------------------------------------|
 * | 18  | AndroidKeyStore introduced; asymmetric keys only                     |
 * | 23  | Symmetric (AES/HMAC) keys, KeyGenParameterSpec, auth binding         |
 * | 24  | Key attestation for symmetric keys; fingerprint-bound keys mature    |
 * | 28  | StrongBox; setUnlockedDeviceRequired; importWrappedKey               |
 * | 30  | setUserAuthenticationParameters replaces the duration-only API       |
 * | 31  | keystore2 replaces keystore; KeyInfo.getSecurityLevel() added        |
 * | 33+ | Key rotation and attestation improvements; see ../../49-KeyStore     |
 *
 * Related: ../../49-KeyStore/README.md (the mechanism in depth),
 *          ../../50-HardwareBackedSecurity/README.md (TEE, StrongBox, attestation),
 *          ../../48-Biometrics/README.md (the authentication side),
 *          ../../33-Storage/README.md (where the sealed records go).
 * ---------------------------------------------------------------------------
 */
