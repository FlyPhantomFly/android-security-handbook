package com.pentest.ch42.vault

/**
 * Deliberately shaped to produce every artefact chapter 42 talks about:
 *  - a class that R8 will rename           -> mapping.txt class line
 *  - a private method R8 will rename       -> mapping.txt member line
 *  - an inlined method                     -> mapping.txt inline frame
 *  - a lambda passed to a Java SAM         -> $$ExternalSyntheticLambda
 *  - a private member touched from a nested class -> access$ / $$Nest$
 *  - a data class, enum and sealed class   -> kotlin.Metadata payloads
 */

enum class LicenceTier {
    FREE,
    PRO,
    ENTERPRISE
}

data class LicenceRecord(
    val subscriberId: String,
    val tier: LicenceTier,
    val expiryEpochDay: Long
)

sealed class VerificationOutcome {
    data class Granted(val record: LicenceRecord) : VerificationOutcome()
    data class Denied(val reason: String) : VerificationOutcome()
    object Indeterminate : VerificationOutcome()
}

class LicenceVault(private val hardwareId: String) {

    private val issuedRecords = mutableListOf<LicenceRecord>()

    companion object {
        const val VAULT_FORMAT_VERSION: Int = 3
        private const val PEPPER = "ch42-r8-pepper"

        @JvmStatic
        fun defaultVault(): LicenceVault = LicenceVault("unknown-hardware")
    }

    // Small and private: a prime candidate for R8 inlining, which is what
    // produces multi-frame retrace output.
    private fun mixSubscriberSalt(subscriberId: String): Int {
        var acc = 17
        for (c in subscriberId) {
            acc = acc * 31 + c.code
        }
        for (c in PEPPER) {
            acc = acc * 31 + c.code
        }
        return acc
    }

    private fun tierWeight(tier: LicenceTier): Int = when (tier) {
        LicenceTier.FREE -> 0
        LicenceTier.PRO -> 10
        LicenceTier.ENTERPRISE -> 100
    }

    fun issueLicence(subscriberId: String, tier: LicenceTier, expiryEpochDay: Long): LicenceRecord {
        val record = LicenceRecord(subscriberId, tier, expiryEpochDay)
        issuedRecords.add(record)
        return record
    }

    fun computeActivationCode(record: LicenceRecord): Int {
        val salt = mixSubscriberSalt(record.subscriberId)
        val weight = tierWeight(record.tier)
        return (salt xor hardwareId.hashCode()) + weight
    }

    fun verify(record: LicenceRecord, todayEpochDay: Long): VerificationOutcome {
        if (record.expiryEpochDay < todayEpochDay) {
            return VerificationOutcome.Denied("expired")
        }
        if (record.tier == LicenceTier.FREE && record.expiryEpochDay > todayEpochDay + 365) {
            return VerificationOutcome.Indeterminate
        }
        return VerificationOutcome.Granted(record)
    }

    // A lambda handed to a Java functional interface. On the DEX side this
    // becomes a $$ExternalSyntheticLambda class, because DEX has no invokedynamic.
    fun sortedBySubscriber(): List<LicenceRecord> {
        val copy = ArrayList(issuedRecords)
        java.util.Collections.sort(copy) { a, b -> a.subscriberId.compareTo(b.subscriberId) }
        return copy
    }

    fun activeTierNames(todayEpochDay: Long): List<String> {
        val runnableProbe = Runnable { auditTrail.add("scan:$todayEpochDay") }
        runnableProbe.run()
        return issuedRecords
            .filter { it.expiryEpochDay >= todayEpochDay }
            .map { it.tier.name }
    }

    private val auditTrail = mutableListOf<String>()

    fun auditSize(): Int = auditTrail.size

    // Nested class touching an outer private member: the classic access$ /
    // $$Nest$ bridge generator.
    inner class Diagnostics {
        fun hardwareFingerprint(): Int = mixSubscriberSalt(hardwareId)
        fun recordCount(): Int = issuedRecords.size
    }

    fun diagnostics(): Diagnostics = Diagnostics()
}

object VaultEntryPoint {
    @JvmStatic
    fun main(args: Array<String>) {
        val vault = LicenceVault("HW-0001")
        val record = vault.issueLicence("subscriber-alpha", LicenceTier.PRO, 20000L)
        println("code=" + vault.computeActivationCode(record))
        println("verify=" + vault.verify(record, 19000L))
        println("sorted=" + vault.sortedBySubscriber().size)
        println("tiers=" + vault.activeTierNames(19000L))
        println("fingerprint=" + vault.diagnostics().hardwareFingerprint())
        println("audit=" + vault.auditSize())
        // Force a stack trace through an inlined private method so the lab has
        // something real to retrace.
        if (args.isNotEmpty() && args[0] == "--crash") {
            vault.detonate()
        }
    }
}

fun LicenceVault.detonate(): Nothing =
    throw IllegalStateException("vault detonated")
