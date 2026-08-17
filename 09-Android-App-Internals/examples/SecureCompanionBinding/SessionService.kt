// examples/SecureCompanionBinding/SessionService.kt
package com.example.vault

import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Binder
import android.os.IBinder
import android.util.Log

/**
 * BUILDING — read this before you try.
 *   This file is illustrative source, not a buildable module, and it is the only
 *   file in this directory. It refers to two things that are deliberately not
 *   shipped here: `ISession`, which you would generate with the AIDL compiler
 *   from an ISession.aidl of your own, and `SessionStore`, which stands in for
 *   whatever actually holds your session token. Dropping it into a project means
 *   supplying both. Verified only as far as that allows: it is Kotlin 1.9.24
 *   clean apart from those two unresolved references, and nothing else.
 *
 *   The point of the file is the SHAPE of the three checks below, which is
 *   copy-pasteable into any Service. Chapter 25 ships a complete, compilable
 *   AIDL service if you want one to build: ../../25-Binder/examples/.
 *
 * Defence in depth, in three independent layers:
 *   1. A signature-level permission on the manifest declaration. The platform refuses the bind
 *      outright unless the caller is signed with our key. This is the primary control.
 *   2. A UID-derived, signature-verified check in code, for callers that somehow reach us
 *      anyway (a mis-declared component, a future refactor, a platform bug).
 *   3. Explicit handling of the sharedUserId case, where one UID maps to several packages.
 */
class SessionService : Service() {

    private val binder = object : ISession.Stub() {
        override fun getSessionToken(): String {
            enforceTrustedCaller()
            return SessionStore.token()
        }
    }

    override fun onBind(intent: Intent): IBinder? {
        enforceTrustedCaller()
        return binder
    }

    private fun enforceTrustedCaller() {
        val uid = Binder.getCallingUid()

        // Anything below FIRST_APPLICATION_UID is the system or a daemon. Decide deliberately
        // whether you trust that; here we do not, because this interface is for one companion.
        if (uid < 10000) throw SecurityException("caller uid $uid is not an application")

        val packages = packageManager.getPackagesForUid(uid)
            ?: throw SecurityException("no packages for uid $uid")

        // getPackagesForUid returns SEVERAL names when the caller uses sharedUserId.
        // Requiring EVERY member to be trusted is the conservative reading; requiring only
        // ONE would let a shared-UID group smuggle an untrusted member in.
        val allTrusted = packages.all { pkg ->
            pkg == EXPECTED_PACKAGE && packageManager.hasSigningCertificate(
                pkg, EXPECTED_CERT_SHA256, PackageManager.CERT_INPUT_SHA256
            )
        }
        if (!allTrusted) {
            Log.w(TAG, "rejected uid=$uid packages=${packages.joinToString()}")
            throw SecurityException("caller is not the trusted companion")
        }
    }

    companion object {
        private const val TAG = "SessionService"
        private const val EXPECTED_PACKAGE = "com.example.companion"

        // SHA-256 of the companion's signing certificate, pinned at build time.
        // Obtain with: apksigner verify --print-certs companion.apk
        private val EXPECTED_CERT_SHA256 = byteArrayOf(
            0x7f.toByte(), 0x3a.toByte(), /* … 32 bytes total … */ 0x1d.toByte()
        )
    }
}
