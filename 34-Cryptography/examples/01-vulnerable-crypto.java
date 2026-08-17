// examples/01-vulnerable-crypto.java
//
// WHAT THIS IS
//   A catalogue of the crypto findings described in ../README.md section 5.2,
//   written the way real Android code writes them. EVERY LINE OF THIS CLASS IS A
//   FINDING. It exists so you can practise recognising them, so you can build a
//   target for labs/lab-01-break-the-vault.md, and so you can test your detection
//   tooling against a file whose answers you already know.
//
// WHY IT MATTERS
//   Nobody writes bad crypto because they want bad crypto. Every pattern below
//   has a reason a competent, busy engineer wrote it — a deadline, a storage
//   format that could not change, a tutorial from 2011 that still ranks first in
//   search results, or a genuine design tension with no obvious answer. If your
//   report explains only what is wrong and not why it was written, the developer
//   will fix the line and reintroduce the same mistake elsewhere next sprint.
//
//   So each method is annotated with three things:
//       WHY  — why a developer writes it
//       COST — what it actually costs, concretely
//       FIX  — where the correct version lives
//
// HOW TO USE IT
//   Compile it into a throwaway app to practise against:
//       # host
//       ./gradlew assembleRelease
//       adb install -r app/build/outputs/apk/release/app-release.apk
//
//   Then confirm each finding two ways:
//       # host — static
//       python3 ../scripts/detect-ecb.py unpacked/
//       semgrep --config ../scripts/semgrep-crypto.yml jadx-out/sources/
//       # host — dynamic
//       frida -U -f com.example.insecure -l ../scripts/frida-jca-universal-hook.js
//
// REQUIREMENTS
//   Android API 19+ to compile. Some methods deliberately behave differently on
//   API 24+ and 26+; those differences are called out inline, because "it worked
//   on my phone" is itself one of the findings.
//
// DO NOT SHIP ANY OF THIS.

package com.example.insecure;

import android.content.Context;
import android.provider.Settings;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class InsecureCrypto {

    // ---------------------------------------------------------------- F-01 ---
    // Hardcoded symmetric key.
    //
    // WHY  It works, it is deterministic, it can be unit tested, and the
    //      alternative — key management — is genuinely hard. Many developers also
    //      believe R8/ProGuard makes strings unreadable. It does not: R8 renames
    //      identifiers, it does not encrypt string constants.
    // COST The key is identical in every installation of the app, so the exposure
    //      is not per-device, it is GLOBAL. One APK download decrypts every user's
    //      stored data and every intercepted "encrypted" request body.
    //      Recover it in one command:  strings classes.dex | grep -i secret
    // FIX  See ../examples/04-keystore-backed-vault.kt.
    private static final String KEY = "MySuperSecretKey";       // exactly 16 bytes -> AES-128

    // ---------------------------------------------------------------- F-03 ---
    // Constant IV shared by every message.
    //
    // WHY  Storing the IV means changing the storage format, which means a
    //      migration. A fixed IV keeps the format simple and makes encryption
    //      deterministic — which some teams actively want, because they use the
    //      ciphertext as a database lookup key.
    // COST CBC becomes deterministic: identical plaintexts give identical
    //      ciphertexts. That permits equality detection across records and a
    //      dictionary attack wherever the plaintext space is small — encrypt all
    //      10,000 four-digit PINs and match.
    // FIX  The lookup-key requirement is real. The answer is a keyed hash
    //      (HMAC-SHA256) for the lookup column and properly randomised
    //      encryption for the value. Two columns, two primitives.
    private static final byte[] IV = new byte[16];              // all zeroes

    private InsecureCrypto() {}

    /**
     * F-02: no mode or padding given, so the JCA resolves this to
     * AES/ECB/PKCS5Padding.
     *
     * WHY  The two-character habit. The developer did not choose ECB; they chose
     *      nothing, and the platform default chose for them. This single line is
     *      the most common cryptographic defect in Android applications.
     * COST Two distinct attacks. (1) Pattern leakage: any structure in the
     *      plaintext at 16-byte granularity survives into the ciphertext, so for a
     *      fixed-format record you can tell which users share a value. (2) Block
     *      shuffling: with no chaining and no integrity you can cut and paste
     *      ciphertext blocks between records, turning a confidentiality issue into
     *      an authorisation bypass.
     * FIX  Cipher.getInstance("AES/GCM/NoPadding") — see 02-correct-aes-gcm.java.
     */
    public static String encryptEcb(String plaintext) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY.getBytes("UTF-8"), "AES"));
        return Base64.encodeToString(c.doFinal(plaintext.getBytes("UTF-8")), Base64.NO_WRAP);
    }

    /**
     * F-03 + F-12: fixed IV, CBC, and no authentication of the ciphertext.
     *
     * WHY  CBC "feels" safer than ECB and the developer knew enough to move off
     *      ECB but not enough to move off CBC. The IV is fixed for the
     *      storage-format reason above.
     * COST Deterministic encryption (F-03) plus malleability (F-12). Because
     *      nothing authenticates the ciphertext, an attacker who can modify stored
     *      bytes can flip bits in the first plaintext block at will by flipping the
     *      corresponding bits of the IV. And if the decryption path distinguishes
     *      a padding failure from any other failure — a different log line, a
     *      different toast, a crash instead of no crash — the whole plaintext is
     *      recoverable at roughly 128 requests per byte. That is
     *      labs/lab-04-ctf-padding-oracle.md.
     * FIX  AES-GCM, or encrypt-then-MAC if the format truly cannot change.
     */
    public static String encryptCbcFixedIv(String plaintext) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY.getBytes("UTF-8"), "AES"),
               new IvParameterSpec(IV));
        return Base64.encodeToString(c.doFinal(plaintext.getBytes("UTF-8")), Base64.NO_WRAP);
    }

    /**
     * F-06: a 256-bit key with at most about 48 bits of entropy.
     *
     * WHY  java.util.Random is the Random everybody imports first; SecureRandom
     *      requires knowing that the distinction exists.
     * COST java.util.Random is a 48-bit linear congruential generator. Two
     *      consecutive outputs are enough to recover its internal state and
     *      predict every future value. Seeding it from currentTimeMillis() makes
     *      it worse still: the attacker knows roughly when the key was created, so
     *      the search space collapses to a few million candidates — seconds of
     *      work. The key is 32 bytes long and provides nothing like 256 bits.
     * FIX  new SecureRandom().nextBytes(k), with no setSeed() call.
     */
    public static byte[] generateKeyBadly() {
        byte[] k = new byte[32];
        new Random(System.currentTimeMillis()).nextBytes(k);
        return k;
    }

    /**
     * F-05 + F-07: a hash is not a KDF, and MD5 is not a hash you should use.
     *
     * WHY  "I need 16 bytes from a password and MD5 gives me exactly 16 bytes."
     *      The length arithmetic is genuinely convenient, which is exactly why the
     *      pattern spread.
     * COST A hash is designed to be fast; a password KDF is designed to be slow.
     *      There is no salt, so identical passwords produce identical keys across
     *      every device and precomputation applies. There is no work factor, so a
     *      GPU tests billions of candidates per second. A six-character password
     *      falls in minutes.
     * FIX  PBKDF2WithHmacSHA256 with a 16-byte random salt and >= 600,000
     *      iterations, or Argon2id — see 03-pbkdf2-and-argon2.kt.
     */
    public static byte[] deriveKeyBadly(String password) throws Exception {
        return MessageDigest.getInstance("MD5").digest(password.getBytes("UTF-8"));
    }

    /**
     * F-07 length extension: H(secret || data) is forgeable without the secret.
     *
     * WHY  It looks exactly like a MAC. Hash the secret, hash the message, send
     *      the digest. It is the intuitive construction, and it is wrong.
     * COST SHA-256 is a Merkle-Damgard hash: its output IS its internal state.
     *      An attacker who has H(secret || data) and knows len(secret) can resume
     *      the hash from that state and compute H(secret || data || padding ||
     *      anything) — a valid tag for a message they chose, without ever
     *      learning the secret. If the appended text is "&role=admin", the
     *      authorisation decision is theirs.
     * FIX  Mac.getInstance("HmacSHA256"). HMAC exists precisely to fix this, by
     *      hashing twice with two derived keys (RFC 2104).
     */
    public static String signRequest(String body) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(KEY.getBytes("UTF-8"));
        md.update(body.getBytes("UTF-8"));
        return Base64.encodeToString(md.digest(), Base64.NO_WRAP);
    }

    /**
     * F-10: encoding is not encryption.
     *
     * WHY  The output looks scrambled. In a code review, in a screenshot, and in
     *      a data-flow diagram, Base64 and ciphertext are indistinguishable to
     *      anyone not looking closely — and the method is called "protect".
     * COST None of the data is protected. Anyone can decode it. The finding is
     *      not "Base64 is weak"; the finding is that data the app documents as
     *      encrypted is stored in cleartext.
     * FIX  Actually encrypt it, under a key from the AndroidKeyStore.
     */
    public static String protect(String secret) {
        return Base64.encodeToString(secret.getBytes(), Base64.NO_WRAP);
    }

    // ======================================================================= //
    //  Everything below is additional catalogue material referenced by         //
    //  README section 5.2 but not shown in the section 9.1 excerpt.            //
    // ======================================================================= //

    /**
     * F-11: XOR "encryption".
     *
     * WHY  It is the first cipher anyone learns, it is fast, it needs no library,
     *      and it produces output that looks random to the naked eye.
     * COST With a repeating key this is a Vigenere cipher, breakable by
     *      frequency analysis with no knowledge of the key at all. Where the
     *      plaintext is partly known — a JSON prefix, an XML header, a fixed field
     *      name — the key falls out by XORing the known plaintext against the
     *      ciphertext. There is no security property here of any kind.
     * SEVERITY NOTE  Be careful. If this is string obfuscation inside a packer,
     *      it is context, not a vulnerability — see ../../40-Obfuscation. If the
     *      app tells the user their data is encrypted, it is a finding.
     * FIX  AES-GCM. There is no correct way to do this with XOR unless you can
     *      deliver a truly random key as long as the message and never reuse it,
     *      at which point you did not need the cipher.
     */
    public static byte[] xorEncrypt(byte[] data) {
        byte[] key = {0x13, 0x37, 0x42, 0x69};
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return out;
    }

    /**
     * F-05: key derived from a device identifier.
     *
     * WHY  It sounds like exactly the right idea — the key is per-device, so a
     *      stolen database from one phone does not decrypt another. The reasoning
     *      is sound; the ingredient is not.
     * COST ANDROID_ID is an identifier, not a secret. It is readable by the
     *      platform, it lands in support logs and backups, and it is available to
     *      any code already running on the device — which is the attacker you are
     *      defending against. There is no work factor and no salt, so recovering
     *      the key is a single hash away.
     * FIX  AndroidKeyStore. Let the keystore daemon generate the key so that it
     *      never enters the app process at all, and bind it to user
     *      authentication if the data warrants it.
     */
    @SuppressWarnings("HardwareIds")
    public static SecretKey deviceBoundKeyBadly(Context ctx) throws Exception {
        String id = Settings.Secure.getString(ctx.getContentResolver(),
                                              Settings.Secure.ANDROID_ID);
        byte[] material = MessageDigest.getInstance("SHA-256")
                                       .digest(id.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(material, "AES");
    }

    /**
     * F-05: the SHA1PRNG "key derivation" that also silently corrupts data.
     *
     * WHY  It circulated as the canonical Android answer for turning a password
     *      into an AES key, and it appears in thousands of copies of the same
     *      Stack Overflow snippet.
     * COST Two separate problems. (1) It is not a KDF: no salt, no work factor,
     *      so the password is brute-forceable at hardware speed. (2) From Android
     *      7 (API 24), SecureRandom.setSeed() SUPPLEMENTS the internal seed rather
     *      than replacing it, so this code produces a different key on a newer
     *      device than on an older one. Apps usually discover this bug as a
     *      data-loss incident, not as a security review finding — every record
     *      encrypted before the OS upgrade becomes undecryptable.
     * FIX  PBKDF2WithHmacSHA256, or HKDF if the input already has real entropy.
     */
    public static SecretKey sha1prngKeyBadly(String password) throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(password.getBytes(StandardCharsets.UTF_8));
        byte[] key = new byte[32];
        sr.nextBytes(key);
        return new SecretKeySpec(key, "AES");
    }

    /**
     * F-04: GCM with a caller-supplied nonce that never changes.
     *
     * WHY  The developer moved to GCM — genuinely the right decision — and then
     *      wrote the nonce handling by hand because the API asks for a
     *      GCMParameterSpec on decryption and symmetry felt cleaner.
     * COST This is worse than the CBC fixed-IV case, not better. GCM is CTR mode
     *      underneath: reusing a (key, nonce) pair means the same keystream
     *      encrypts two messages, so their XOR is immediately recoverable. Worse,
     *      the repetition lets an attacker solve for the GHASH authentication
     *      subkey H, after which they can forge a valid authentication tag for
     *      ANY message under that key, permanently. Moving from CBC to GCM while
     *      keeping a fixed IV converts a confidentiality problem into a total
     *      break of both confidentiality and authenticity.
     * FIX  Never pass a GCMParameterSpec on encryption. Call init(ENCRYPT_MODE,
     *      key), then read cipher.getIV() and store it with the ciphertext.
     */
    private static final byte[] FIXED_NONCE = "123456789012".getBytes(StandardCharsets.UTF_8);

    public static byte[] encryptGcmReusedNonce(byte[] plaintext) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY.getBytes("UTF-8"), "AES"),
               new GCMParameterSpec(128, FIXED_NONCE));
        return c.doFinal(plaintext);
    }

    /**
     * F-12: GCM tag length given in bytes instead of bits.
     *
     * WHY  Every other length parameter in the JCA is in bytes. This one is in
     *      bits. The API is the trap, not the developer.
     * COST A 16-bit tag is forgeable in about 2^15 attempts. On a local app with
     *      no rate limiting that is a fraction of a second. The scheme still
     *      "works" in every test the developer runs, because valid tags always
     *      verify; only forgery becomes cheap, and nobody tests for that.
     * FIX  128. Always 128. NIST SP 800-38D permits 96 and above; there is no
     *      reason to use anything but the maximum.
     */
    public static byte[] encryptGcmShortTag(byte[] plaintext, byte[] nonce) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY.getBytes("UTF-8"), "AES"),
               new GCMParameterSpec(16, nonce));       // 16 BITS, not 16 bytes
        return c.doFinal(plaintext);
    }

    /**
     * F-15: non-constant-time comparison of an authentication tag.
     *
     * WHY  Arrays.equals is the obvious way to compare two byte arrays, and it is
     *      correct for every non-secret use.
     * COST Arrays.equals returns at the first differing byte, so the time it takes
     *      reveals how many leading bytes matched. An attacker who can time the
     *      call precisely recovers the tag one byte at a time — 256 attempts per
     *      byte instead of 2^128 for the whole tag.
     * HONEST SEVERITY  On-device timing is usually dominated by scheduler noise,
     *      GC pauses and JIT state, so exploiting this against a local Android app
     *      is rarely practical. Report it as Low, say why, and note that it
     *      becomes serious if the same code runs on the server. Overclaiming here
     *      is a classic way to lose a client's trust.
     * FIX  MessageDigest.isEqual(a, b), which is constant-time by contract.
     */
    public static boolean verifyTagBadly(byte[] message, byte[] receivedTag) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY.getBytes("UTF-8"), "HmacSHA256"));
        byte[] expected = mac.doFinal(message);
        return Arrays.equals(expected, receivedTag);       // early-exit comparison
    }

    /**
     * F-13: the key stored next to the ciphertext.
     *
     * WHY  The key has to live somewhere, and SharedPreferences is where
     *      everything else lives. Some teams reason that the app sandbox already
     *      protects it, which is true right up until the device is rooted, the
     *      data is backed up, or a path-traversal bug in a ContentProvider lets
     *      another app read the file.
     * COST The scheme degrades to obfuscation. An attacker who can read the
     *      ciphertext can, by construction, read the key beside it. Encryption at
     *      rest that stores its own key at rest protects against nothing but a
     *      casual glance.
     * FIX  Wrap the data key with an AndroidKeyStore key (envelope encryption), so
     *      that what is stored on disk is useless without the hardware-held
     *      wrapping key. See 05-tink-envelope.kt.
     */
    public static String storeKeyBesideData(Context ctx, String plaintext) throws Exception {
        byte[] dataKey = new byte[32];
        new SecureRandom().nextBytes(dataKey);            // the RNG here is fine
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dataKey, "AES"));
        byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        ctx.getSharedPreferences("vault", Context.MODE_PRIVATE).edit()
           .putString("data", Base64.encodeToString(ct, Base64.NO_WRAP))
           .putString("iv", Base64.encodeToString(c.getIV(), Base64.NO_WRAP))
           .putString("key", Base64.encodeToString(dataKey, Base64.NO_WRAP))   // <-- here
           .apply();
        return "stored";
    }

    /**
     * F-14: textbook RSA.
     *
     * WHY  "RSA/ECB/NoPadding" looks like it is doing less magic, and the "ECB"
     *      token confuses people into thinking they have chosen a mode. RSA has no
     *      mode; that token is a JCA naming artefact.
     * COST Textbook RSA is deterministic (equal plaintexts give equal
     *      ciphertexts), malleable (multiply two ciphertexts and you have
     *      encrypted the product), and recoverable by integer root extraction
     *      whenever the plaintext is small — which a symmetric key or a PIN
     *      always is. PKCS#1 v1.5 padding is better but is the Bleichenbacher /
     *      ROBOT oracle class.
     * FIX  RSA/ECB/OAEPWithSHA-256AndMGF1Padding, with an explicit
     *      OAEPParameterSpec — the default MGF1 digest is not the same across
     *      providers, which produces interoperability bugs that get "fixed" by
     *      downgrading to PKCS1.
     */
    public static byte[] wrapKeyBadly(java.security.PublicKey pub, byte[] aesKey)
            throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(aesKey);
    }

    /**
     * F-16: an update path with only a hash check.
     *
     * WHY  A SHA-256 comparison genuinely does detect corruption, which is what
     *      the developer set out to solve. Integrity against accident and
     *      integrity against an adversary are different problems that look alike.
     * COST A hash with no key proves nothing about origin. An attacker who can
     *      replace the payload simply replaces the expected hash too — it is
     *      served from the same place. The result is arbitrary code execution
     *      inside the app's sandbox, with all its permissions.
     * FIX  Verify a signature (SHA256withECDSA) using a public key pinned inside
     *      the app, and prefer not to load code dynamically at all.
     */
    public static boolean verifyUpdateBadly(byte[] payload, String expectedSha256)
            throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload);
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString().equals(expectedSha256);
    }
}

/*
 * ---------------------------------------------------------------------------
 * SELF-TEST
 *
 * Close the file and list the findings from memory. There are fourteen distinct
 * ones above. If you can name ten, you can run a crypto review; if you can name
 * all fourteen and give the honest severity of each, you can defend that review
 * in a room with the developers who wrote the code.
 *
 * Answers, in order of appearance:
 *   F-01 hardcoded key                    F-03 constant IV
 *   F-02 silent ECB                       F-03+F-12 fixed-IV CBC, unauthenticated
 *   F-06 java.util.Random                 F-05+F-07 MD5 as a KDF
 *   F-07 hash-based MAC (length extension) F-10 Base64 as encryption
 *   F-11 XOR "encryption"                 F-05 key from ANDROID_ID
 *   F-05 SHA1PRNG derivation              F-04 GCM nonce reuse
 *   F-12 GCM tag length in bytes          F-15 Arrays.equals on a MAC
 *   F-13 key stored beside ciphertext     F-14 textbook RSA
 *   F-16 hash-only update verification
 * ---------------------------------------------------------------------------
 */
