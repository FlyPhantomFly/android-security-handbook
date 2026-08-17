// CtfVaultGuardian.kt -- the challenge binary for labs/lab-04-ctf-the-leaked-key.md
//
// Build it with examples/build-ctf.sh, which runs R8 with rules-ctf.pro.
// Do NOT read this file if you intend to attempt the CTF: it is the answer key.
// The lab tells you when to come back and check your work against it.
//
// Three flag segments are hidden, each recoverable by a DIFFERENT chapter-42
// technique, and none recoverable by simply grepping the DEX for strings:
//
//   Segment 1 -- carried by a METHOD NAME that R8 inlines out of existence.
//                Recoverable only by retracing a stack trace through mapping.txt.
//   Segment 2 -- carried by a KOTLIN PROPERTY NAME. R8 renames the backing field,
//                and rewrites the class and function names in kotlin.Metadata,
//                but leaves the property name -- see README section 3.10.3.
//   Segment 3 -- carried by a CLASS NAME that a keep rule exempted from renaming,
//                as happens whenever a class is reached reflectively by name. It is
//                in the APK in plain text; the skill is knowing to look for it.

package com.pentest.ch42.ctf

import java.util.Collections

enum class GuardTier { BASIC, HARDENED, SEALED }

data class GuardRecord(
    val holderId: String,
    val tier: GuardTier,
    val issuedEpochDay: Long
)

/**
 * Segment 2 lives in the NAME of a property in this class, not in its value.
 * R8 renames the backing field to a single letter; kotlin.Metadata keeps the
 * Kotlin-level property name because a Kotlin property is not a JVM member.
 */
class SegmentCarrier {
    val segmentTwoIsM3T4D4T4: Int = 0x2A
    val decoyFieldName: String = "not-a-flag-segment"
    private val rotorOffset: Int = 7

    fun mix(seed: Int): Int = (seed * 31 + rotorOffset) and 0xFFFF
}

/**
 * Segment 3 is this class's own NAME, and it survives in the APK in plain text.
 *
 * Not because R8 failed, but because rules-ctf.pro keeps it WITHOUT
 * `allowobfuscation` -- the shape a developer writes when a class is looked up
 * reflectively BY NAME (`Class.forName`, a service loader, a `@SerializedName`
 * contract, a WorkManager Worker). R8 obeys: the class must keep its name, so
 * it does.
 *
 * The lesson is the one in README section 5.4: a keep rule without
 * `allowobfuscation` is an obfuscation exemption, and a handful of them are how
 * an app with `minifyEnabled true` ends up disclosing its most interesting class
 * names -- precisely the reflective, entry-point ones.
 */
class SegmentThreeIsK33PRUL3 {
    fun scale(x: Int): Int = x * 3 + 1
    fun describe(): String = "reflectively instantiated"
}

/** Reachable, and the home of the desugared lambda the lab asks you to classify. */
class HolderOrdering {
    fun orderHolders(records: List<GuardRecord>): List<GuardRecord> {
        val copy = ArrayList(records)
        // A lambda handed to a Java SAM: becomes $$ExternalSyntheticLambda.
        Collections.sort(copy) { a, b -> a.holderId.compareTo(b.holderId) }
        return copy
    }
}

class VaultGuardian(private val deviceBinding: String) {

    private val issued = mutableListOf<GuardRecord>()

    companion object {
        const val GUARD_FORMAT_VERSION: Int = 4
        private const val BINDING_PEPPER = "ch42-ctf-pepper"
    }

    /**
     * Segment 1 is this method's NAME. It is private and tiny, so R8 inlines it
     * into every caller and no method with this name exists in the APK. It
     * appears only as an inline frame inside mapping.txt.
     */
    private fun segmentOneIsR3TR4C3(input: String): Int {
        // The sentinel is what the player triggers to produce a stack trace that
        // passes through this method. Because R8 inlines it, the trace shows the
        // caller only -- the name is recoverable solely by retracing.
        if (input == "--verify") {
            throw IllegalStateException("guardian verification tripped")
        }
        var acc = 17
        for (c in input) {
            acc = acc * 31 + c.code
        }
        for (c in BINDING_PEPPER) {
            acc = acc * 31 + c.code
        }
        return acc
    }

    private fun tierWeight(tier: GuardTier): Int = when (tier) {
        GuardTier.BASIC -> 1
        GuardTier.HARDENED -> 20
        GuardTier.SEALED -> 300
    }

    fun issue(holderId: String, tier: GuardTier, issuedEpochDay: Long): GuardRecord {
        val record = GuardRecord(holderId, tier, issuedEpochDay)
        issued.add(record)
        return record
    }

    fun activationCode(record: GuardRecord): Int {
        val salt = segmentOneIsR3TR4C3(record.holderId)
        return (salt xor deviceBinding.hashCode()) + tierWeight(record.tier)
    }

    fun bindingFingerprint(): Int = segmentOneIsR3TR4C3(deviceBinding)

    fun bindingFor(input: String): Int = segmentOneIsR3TR4C3(input)

    fun issuedCount(): Int = issued.size
}

object CtfEntryPoint {
    @JvmStatic
    fun main(args: Array<String>) {
        val guardian = VaultGuardian("DEVICE-BINDING-0001")
        val record = guardian.issue("holder-alpha", GuardTier.HARDENED, 20250L)
        println("activation=" + guardian.activationCode(record))
        println("fingerprint=" + guardian.bindingFingerprint())
        println("issued=" + guardian.issuedCount())

        val ordering = HolderOrdering()
        println("ordered=" + ordering.orderHolders(listOf(record)).size)

        val carrier = SegmentCarrier()
        println("mixed=" + carrier.mix(carrier.segmentTwoIsM3T4D4T4))

        // Kept by name via a keep rule with no `allowobfuscation`, so its class
        // name survives renaming and ships in the DEX in plain text.
        println("scaled=" + SegmentThreeIsK33PRUL3().scale(carrier.segmentTwoIsM3T4D4T4))

        // The challenge entry point: passing --verify drives the sentinel inside
        // the (inlined) segment-1 method and produces the stack trace to retrace.
        if (args.isNotEmpty() && args[0] == "--verify") {
            println("binding=" + guardian.bindingFor(args[0]))
        }
    }
}
