// examples/SecureSharing.kt
package com.example.realapp

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import java.io.File

object SecureSharing {

    /**
     * Share a single generated file with whatever app the user picks.
     *
     * Security properties, each deliberate:
     *  - The file is written inside the app sandbox (cacheDir/exports), never to shared storage.
     *  - FileProvider only serves paths declared in file_paths.xml, and it canonicalises,
     *    so ../ traversal cannot escape the declared subtree.
     *  - The grant is per-URI, read-only, and revoked when the receiving activity finishes.
     *  - The provider itself is exported="false"; access exists ONLY through the grant.
     */
    fun shareReport(ctx: Context, pdfBytes: ByteArray): Intent {
        val dir = File(ctx.cacheDir, "exports").apply { mkdirs() }
        val file = File(dir, "report-${System.currentTimeMillis()}.pdf")
        file.writeBytes(pdfBytes)

        val uri: Uri = FileProvider.getUriForFile(
            ctx, "${ctx.packageName}.fileprovider", file)

        return Intent(Intent.ACTION_SEND).apply {
            type = "application/pdf"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)   // read only, temporary
            // Deliberately NOT: FLAG_GRANT_WRITE_URI_PERMISSION
            // Deliberately NOT: FLAG_GRANT_PERSISTABLE_URI_PERMISSION
        }.let { Intent.createChooser(it, "Share report") }
    }

    /** Called on logout — the sandbox does not clean up after you. */
    fun purgeExports(ctx: Context) {
        File(ctx.cacheDir, "exports").listFiles()?.forEach { it.delete() }
    }
}
