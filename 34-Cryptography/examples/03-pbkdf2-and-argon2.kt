// examples/03-pbkdf2-and-argon2.kt
//
// WHAT THIS IS
//   Password-based key derivation done properly, plus the distinction that
//   confuses more engineers than any other in this chapter: the difference
//   between a PASSWORD KDF (PBKDF2, scrypt, Argon2) and a KEY-BASED KDF (HKDF).
//   They are both called "KDF" and they solve opposite problems.
//
//   Three things live in this file:
//     1. PasswordVault  — PBKDF2-HMAC-SHA256 + AES-GCM, with a stored parameter
//                         record so the work factor can be raised later.
//     2. Argon2Notes    — what to use when you can add a dependency, and why.
//     3. Hkdf           — extract-then-expand for high-entropy inputs, with a
//                         from-scratch implementation so the two phases are
//                         visible rather than hidden behind a library call.
//
// WHY IT MATTERS
//   A password is not a key. A key has 128 or 256 bits of entropy drawn from a
//   uniform distribution. A password chosen by a human has, empirically, somewhere
//   between 20 and 40 bits, drawn from a distribution an attacker can enumerate in
//   order of likelihood. Using a password as a key — or hashing it once and using
//   that — hands the attacker a guessing game they win.
//
//   A password KDF's job is to make each guess EXPENSIVE, so that the attacker's
//   advantage in knowing the distribution is offset by cost. That is the whole
//   idea, and every parameter you choose is a statement about how expensive.
//
//   > Definition
//   > WORK FACTOR — the deliberate computational cost added to each derivation.
//   > For PBKDF2 it is the iteration count; for Argon2 it is time cost, memory
//   > cost and parallelism together. It is the only defence against offline
//   > guessing, because you cannot make the user choose a better password.
//
// HOW TO RUN
//   As part of an Android module, or on a desktop JVM:
//       # host
//       kotlinc 03-pbkdf2-and-argon2.kt -include-runtime -d vault.jar
//       java -jar vault.jar
//
//   To see the parameters an app under test actually uses, hook the constructor:
//       # host
//       frida -U -f com.example.target -l ../scripts/frida-jca-universal-hook.js
//   The PBEKeySpec hook prints the password, salt length, iteration count and key
//   size, and flags counts below the current recommendation.
//
// REQUIREMENTS
//   API 26+ for PBKDF2WithHmacSHA256 through the platform provider. On older API
//   levels the platform ships PBKDF2WithHmacSHA1 only; see the version matrix
//   below for what to do about that. Argon2 needs a third-party dependency.
//
// AUTHORISED USE. This file is safe to ship.

package com.example.secure

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

// ===========================================================================
//  1. PBKDF2 — the answer you can always reach for, because it is in the
//     platform and needs no dependency.
// ===========================================================================

object PasswordVault {

    private const val VERSION: Byte = 1
    private const val SALT_BYTES = 16
    private const val NONCE_BYTES = 12
    private const val TAG_BITS = 128
    private const val KEY_BITS = 256

    // Calibrate this on the slowest device you support: aim for ~100 ms.
    // Store it in the record so it can be increased for new data without breaking old data.
    //
    // 600,000 is the current OWASP figure for PBKDF2-HMAC-SHA256. It is not a
    // magic number — it is "as many as we can afford". Numbers you will meet in
    // real apps and what they mean:
    //
    //     1,000        the 2010 default, still copied from tutorials. Worthless.
    //     10,000       common in 2015-era code. A GPU does this at ~1M guesses/s.
    //     100,000      the previous recommendation. Adequate for low-value data.
    //     600,000      current recommendation for PBKDF2-HMAC-SHA256.
    //
    // PBKDF2's structural weakness is that it needs almost no memory, so a GPU or
    // an ASIC parallelises it enormously. Raising the iteration count buys linear
    // defence against an attacker whose hardware advantage is several orders of
    // magnitude. That is why Argon2 exists — see section 2.
    private const val DEFAULT_ITERATIONS = 600_000

    private val rng = SecureRandom()

    /**
     * Record layout:
     *   [0]      version
     *   [1..4]   iterations (big-endian int)
     *   [5..20]  salt (16)
     *   [21..32] nonce (12)
     *   [33..]   ciphertext ‖ tag
     */
    fun seal(password: CharArray, plaintext: ByteArray): ByteArray {
        val salt = ByteArray(SALT_BYTES).also(rng::nextBytes)
        val key = deriveKey(password, salt, DEFAULT_ITERATIONS)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, key)
        }
        val nonce = cipher.iv
        // Bind the header to the ciphertext so an attacker cannot downgrade the iteration count.
        val header = ByteBuffer.allocate(1 + 4 + SALT_BYTES)
            .put(VERSION).putInt(DEFAULT_ITERATIONS).put(salt).array()
        cipher.updateAAD(header)
        val ct = cipher.doFinal(plaintext)

        return ByteBuffer.allocate(header.size + NONCE_BYTES + ct.size)
            .put(header).put(nonce).put(ct).array()
    }

    fun open(password: CharArray, record: ByteArray): ByteArray {
        val bb = ByteBuffer.wrap(record)
        val version = bb.get()
        require(version == VERSION) { "unsupported record version $version" }
        val iterations = bb.int
        require(iterations in 10_000..10_000_000) { "implausible iteration count" }
        val salt = ByteArray(SALT_BYTES).also(bb::get)
        val nonce = ByteArray(NONCE_BYTES).also(bb::get)
        val ct = ByteArray(bb.remaining()).also(bb::get)

        val header = ByteBuffer.allocate(1 + 4 + SALT_BYTES)
            .put(version).putInt(iterations).put(salt).array()
        val key = deriveKey(password, salt, iterations)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, nonce))
            updateAAD(header)
        }
        return cipher.doFinal(ct)   // AEADBadTagException on wrong password or tampering
    }

    private fun deriveKey(password: CharArray, salt: ByteArray, iterations: Int): SecretKeySpec {
        val spec = PBEKeySpec(password, salt, iterations, KEY_BITS)
        try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
        } finally {
            spec.clearPassword()
        }
    }

    /**
     * Measure how long one derivation takes on THIS device, so you can choose an
     * iteration count instead of copying one.
     *
     * Run it on the slowest hardware you support, not on your development phone.
     * A flagship will happily do 600,000 iterations in 80 ms while a five-year-old
     * budget device takes 900 ms, and a 900 ms pause on unlock is a support ticket.
     */
    fun calibrate(targetMillis: Long = 100): Int {
        val probeIterations = 50_000
        val password = "calibration-probe".toCharArray()
        val salt = ByteArray(SALT_BYTES).also(rng::nextBytes)

        // Warm up so JIT compilation is not measured as work factor.
        deriveKey(password, salt, 5_000)

        val start = System.nanoTime()
        deriveKey(password, salt, probeIterations)
        val elapsedMillis = (System.nanoTime() - start) / 1_000_000.0

        val scaled = (probeIterations * (targetMillis / elapsedMillis)).toInt()
        // Never go below the published floor even on very slow hardware. If the
        // device cannot afford the floor, the right answer is to move the secret
        // into the AndroidKeyStore, not to weaken the KDF.
        return maxOf(scaled, 210_000)
    }
}

// ===========================================================================
//  2. Argon2 — what to use when you can add a dependency.
// ===========================================================================
//
//  Argon2 won the Password Hashing Competition in 2015 and is the current
//  recommendation wherever a dependency is acceptable. Its advantage over PBKDF2
//  is MEMORY HARDNESS: it is designed so that computing it requires a large,
//  randomly-accessed block of memory. Memory is the one resource a GPU or ASIC
//  cannot multiply cheaply, so the attacker's hardware advantage shrinks from
//  several orders of magnitude to a small constant.
//
//  Variants:
//    Argon2d   data-dependent memory access. Fastest, but the access pattern
//              depends on the password, so it is vulnerable to side channels.
//              Use only where no adversary can observe memory access — not on a
//              phone.
//    Argon2i   data-independent access. Side-channel resistant, weaker against
//              time-memory trade-off attacks.
//    Argon2id  a hybrid: one pass of Argon2i then Argon2d. THIS IS THE ONE.
//              It is the default recommendation in RFC 9106 and in the OWASP
//              Password Storage Cheat Sheet.
//
//  Parameters, and what each one actually controls:
//    m (memory cost)      KiB of memory. The main defensive lever. 19 MiB is the
//                         OWASP minimum; 46-64 MiB is comfortable on a phone.
//    t (time cost)        number of passes over that memory. 2-3 is typical.
//    p (parallelism)      lanes. 1 on mobile; more only if you will actually give
//                         it that many threads.
//
//  A starting point for a mobile app, from RFC 9106's second recommended option:
//      m = 19456 (19 MiB), t = 2, p = 1, 16-byte salt, 32-byte output
//  Then measure. Same rule as PBKDF2: calibrate, do not copy.
//
//  > Warning
//  > Memory cost is a real constraint on Android. Asking for 64 MiB inside an app
//  > whose heap limit is 192 MiB, on a device already under memory pressure, is a
//  > reliable way to get killed by the low-memory killer mid-derivation. Test on
//  > a low-end device with several apps open, not on an idle flagship.
//
//  Dependencies that work on Android (add exactly one):
//      implementation("org.bouncycastle:bcprov-jdk18on:<version>")   // Argon2BytesGenerator
//      implementation("com.lambdapioneer.argon2kt:argon2kt:<version>") // native libargon2
//
//  The Bouncy Castle route, sketched (kept as a comment so this file compiles
//  with no dependencies — copy it into a module that has BC):
//
//      import org.bouncycastle.crypto.generators.Argon2BytesGenerator
//      import org.bouncycastle.crypto.params.Argon2Parameters
//
//      fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int = 32): ByteArray {
//          val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
//              .withVersion(Argon2Parameters.ARGON2_VERSION_13)
//              .withIterations(2)          // t
//              .withMemoryAsKB(19456)      // m — 19 MiB
//              .withParallelism(1)         // p
//              .withSalt(salt)
//              .build()
//          val gen = Argon2BytesGenerator().apply { init(params) }
//          val out = ByteArray(outLen)
//          gen.generateBytes(password, out)
//          return out
//      }
//
//  As with PBKDF2, STORE THE PARAMETERS with the record, and authenticate them as
//  associated data. The standard encoded form does this for you:
//      $argon2id$v=19$m=19456,t=2,p=1$<b64 salt>$<b64 hash>
//  If you invent your own record format, keep the same four facts in it.
//
//  > Pentester's Note
//  > Finding Argon2id in an Android app is a strong positive signal — someone on
//  > that team read the current guidance. Check the parameters anyway. m=1024,
//  > t=1 is Argon2 in name only, and it appears when a developer hit an OOM on a
//  > test device and reduced the numbers until the crash stopped.

object Argon2Notes {
    const val RECOMMENDED_MEMORY_KIB = 19_456
    const val RECOMMENDED_ITERATIONS = 2
    const val RECOMMENDED_PARALLELISM = 1
    const val RECOMMENDED_SALT_BYTES = 16
    const val RECOMMENDED_OUTPUT_BYTES = 32
}

// ===========================================================================
//  3. HKDF — the OTHER kind of KDF, and why confusing the two is a finding.
// ===========================================================================
//
//  > Definition
//  > HKDF (RFC 5869) — HMAC-based Extract-and-Expand Key Derivation Function.
//  > It turns ONE high-entropy secret into SEVERAL independent keys. It has no
//  > work factor and it is fast, deliberately.
//
//  The distinction, stated once and precisely:
//
//    PBKDF2 / Argon2   input: a LOW-entropy secret a human chose.
//                      job:   make each guess expensive.
//                      speed: slow, on purpose.
//
//    HKDF              input: a HIGH-entropy secret (an ECDH shared secret, a
//                             random key, a token from a server).
//                      job:   produce several independent keys from it, so that
//                             compromise of one does not affect the others.
//                      speed: fast, on purpose. A work factor would be pointless
//                             because the input is already unguessable.
//
//  Getting this backwards produces two distinct findings:
//    - HKDF over a password: no work factor, so offline guessing is unimpeded.
//      Severity tracks the value of what the key protects.
//    - PBKDF2 over an ECDH shared secret: not insecure, just 600,000 times slower
//      than it needed to be. Report as Informational, and be precise about why.
//
//  HKDF has two phases, and the reason for each is worth knowing:
//
//    EXTRACT   PRK = HMAC(salt, input_key_material)
//              Concentrates whatever entropy the input has into a uniformly
//              random pseudorandom key. Necessary because inputs like a raw ECDH
//              shared secret are unguessable but NOT uniform — an X coordinate on
//              a curve has structure, and feeding structure directly into a
//              cipher key is how subtle biases become attacks.
//
//    EXPAND    OKM = HMAC(PRK, info || counter), concatenated to the length wanted
//              Produces as many independent bytes as you ask for. The `info`
//              parameter is a context label, and it is the important one: derive
//              your encryption key with info="enc" and your MAC key with
//              info="mac" and the two are cryptographically independent, so a
//              flaw that leaks one tells the attacker nothing about the other.
//
//  Android has no platform HKDF before API 33 (javax.crypto.KDF arrived late and
//  provider support varies), so it is implemented here from HMAC primitives. It
//  is about thirty lines, and seeing it written out makes the two phases concrete.

object Hkdf {

    private const val HASH = "HmacSHA256"
    private const val HASH_LEN = 32

    /** Phase 1. Salt may be null, in which case a block of zeros is used (RFC 5869 §2.2). */
    fun extract(salt: ByteArray?, inputKeyMaterial: ByteArray): ByteArray {
        val effectiveSalt = salt ?: ByteArray(HASH_LEN)
        val mac = Mac.getInstance(HASH)
        mac.init(SecretKeySpec(effectiveSalt, HASH))
        return mac.doFinal(inputKeyMaterial)
    }

    /**
     * Phase 2.
     *
     * @param info the context label. Use a DIFFERENT one for every derived key.
     *             Include a version string, so that rotating the scheme later does
     *             not require rotating the underlying secret.
     */
    fun expand(prk: ByteArray, info: ByteArray, outputLength: Int): ByteArray {
        require(outputLength <= 255 * HASH_LEN) { "output too long for HKDF-SHA256" }
        val mac = Mac.getInstance(HASH)
        mac.init(SecretKeySpec(prk, HASH))

        val output = ByteArray(outputLength)
        var previousBlock = ByteArray(0)
        var written = 0
        var counter = 1

        while (written < outputLength) {
            mac.reset()
            mac.update(previousBlock)
            mac.update(info)
            mac.update(counter.toByte())
            previousBlock = mac.doFinal()

            val take = minOf(HASH_LEN, outputLength - written)
            System.arraycopy(previousBlock, 0, output, written, take)
            written += take
            counter++
        }
        return output
    }

    /** Both phases, which is how you will normally call it. */
    fun derive(
        inputKeyMaterial: ByteArray,
        salt: ByteArray?,
        info: String,
        outputLength: Int = 32
    ): ByteArray = expand(extract(salt, inputKeyMaterial), info.toByteArray(Charsets.UTF_8),
                          outputLength)
}

// ===========================================================================
//  Version matrix — what the platform actually gives you
// ===========================================================================
//
//  | API | PBKDF2WithHmacSHA1 | PBKDF2WithHmacSHA256 | Notes                    |
//  |-----|--------------------|----------------------|--------------------------|
//  | 19  | yes                | no                   | SHA-1 variant only       |
//  | 24  | yes                | no                   |                          |
//  | 26  | yes                | yes                  | SHA-256 variant added    |
//  | 28+ | yes                | yes                  | ChaCha20-Poly1305 too    |
//
//  On minSdk below 26 you have three choices, in order of preference:
//    1. Raise minSdk. In most 2024+ projects this costs nothing real.
//    2. Bundle Bouncy Castle or Conscrypt and use its PBKDF2WithHmacSHA256.
//    3. Use PBKDF2WithHmacSHA1 with a higher iteration count (OWASP suggests
//       1,300,000 for the SHA-1 variant). PBKDF2-HMAC-SHA1 is not broken by the
//       SHA-1 collision — collisions do not affect HMAC — but the throughput
//       difference means it needs more iterations for the same defence.
//
//  > Under the Hood
//  > PBKDF2 is defined in RFC 8018 (PKCS #5 v2.1) as
//  >     DK = T_1 || T_2 || … where T_i = F(P, S, c, i)
//  >     F(P, S, c, i) = U_1 XOR U_2 XOR … XOR U_c
//  >     U_1 = PRF(P, S || INT(i)),  U_j = PRF(P, U_{j-1})
//  > Each U depends on the previous one, so the chain is inherently sequential —
//  > which is what makes the iteration count meaningful. But each T_i is
//  > independent of the others, so requesting an output longer than the hash
//  > length costs proportionally more work for the DEFENDER while an attacker
//  > testing a guess only needs T_1 to reject it. Practical consequence: never
//  > request more output than one hash length. Ask for 256 bits from
//  > PBKDF2-HMAC-SHA256, not 512.

// ===========================================================================
//  Demonstration
// ===========================================================================

fun main() {
    println("=== PBKDF2 + AES-GCM vault ===")
    val password = "correct horse battery staple".toCharArray()
    val record = PasswordVault.seal(password.copyOf(), "account balance: 42".toByteArray())
    println("record length: ${record.size} bytes")
    println("layout: 1 version + 4 iterations + 16 salt + 12 nonce + ct||tag")

    println("open with correct password: " +
            String(PasswordVault.open("correct horse battery staple".toCharArray(), record)))

    try {
        PasswordVault.open("wrong password".toCharArray(), record)
        println("FAIL: wrong password accepted")
    } catch (e: Exception) {
        println("wrong password: rejected (${e.javaClass.simpleName})")
    }

    // Downgrade attempt: edit the stored iteration count from 600000 to 1000.
    val downgraded = record.clone()
    ByteBuffer.wrap(downgraded).putInt(1, 1_000)
    try {
        PasswordVault.open("correct horse battery staple".toCharArray(), downgraded)
        println("FAIL: downgraded iteration count accepted")
    } catch (e: Exception) {
        println("downgrade attempt: rejected (${e.javaClass.simpleName}) " +
                "— because the header is authenticated as associated data")
    }

    println()
    println("=== calibration on this machine ===")
    println("iterations for ~100 ms: ${PasswordVault.calibrate(100)}")
    println("(run this on your SLOWEST supported device, not this one)")

    println()
    println("=== HKDF: one secret, several independent keys ===")
    val sharedSecret = ByteArray(32).also { SecureRandom().nextBytes(it) }
    val salt = ByteArray(32).also { SecureRandom().nextBytes(it) }

    val encKey = Hkdf.derive(sharedSecret, salt, "myapp:v1:record-encryption")
    val macKey = Hkdf.derive(sharedSecret, salt, "myapp:v1:record-authentication")

    println("enc key: ${encKey.toHexString()}")
    println("mac key: ${macKey.toHexString()}")
    println("Same input, same salt, different info — and the outputs are")
    println("independent. Compromising one tells an attacker nothing about the")
    println("other. That is what the info parameter is for.")
}

private fun ByteArray.toHexString(): String =
    joinToString("") { "%02x".format(it) }

/*
 * ---------------------------------------------------------------------------
 * REVIEW CHECKLIST — what to check in someone else's password-based crypto
 *
 *   1. Which KDF? A bare hash (MD5/SHA-256 of the password) is F-05, High.
 *   2. Is there a salt? Random and per-record, or constant? An empty or constant
 *      salt means the same password gives the same key on every device.
 *   3. How many iterations, and is the count STORED? A hardcoded constant means
 *      the work factor can never be raised without invalidating every record.
 *   4. Is the stored count AUTHENTICATED? If not, an attacker edits it down to
 *      1,000 before handing you the record back, and brute-forces cheaply.
 *   5. Is the password a String or a CharArray? A String is immutable and
 *      interned; it sits in the heap until GC and shows up in a heap dump.
 *      Look for clearPassword() in a finally block.
 *   6. Is the derived key cached anywhere it outlives the session?
 *   7. Does a wrong password produce a distinguishable error from a corrupt
 *      record? Under AES-GCM both raise AEADBadTagException, which is correct.
 *      Under CBC+manual padding they differ — that is a padding oracle.
 *
 * Related chapters: ../../49-KeyStore/README.md for moving the secret out of the
 * app process entirely, ../../47-Authentication/README.md for where passwords
 * come from, ../../33-Storage/README.md for where the records land.
 * ---------------------------------------------------------------------------
 */
