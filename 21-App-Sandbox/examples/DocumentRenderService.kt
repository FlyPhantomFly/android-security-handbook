// examples/DocumentRenderService.kt
package com.example.enterprise.render

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.SharedMemory
import java.io.FileInputStream

class DocumentRenderService : Service() {

    private val binder = object : IDocumentRenderer.Stub() {

        /**
         * Contract, and why each clause exists:
         *  - input  : a READ-ONLY descriptor to exactly one document. We never open a path
         *             ourselves, so path traversal in this process is structurally impossible.
         *  - output : a SharedMemory region the host created and will seal read-only after
         *             we write, so we cannot mutate it behind the host's back later.
         *  - return : a small struct of primitives. No file paths, no URIs, no Parcelables
         *             with custom writeToParcel — nothing that could confuse the host's reader.
         */
        override fun render(
            input: ParcelFileDescriptor,
            output: SharedMemory,
            maxPages: Int
        ): RenderResult {
            require(maxPages in 1..512) { "implausible page count" }

            val bytes = FileInputStream(input.fileDescriptor).use { it.readBytes() }
            val buffer = output.mapReadWrite()
            return try {
                val pages = NativeParser.renderInto(bytes, buffer, maxPages)
                RenderResult(pages, buffer.position(), null)
            } catch (t: Throwable) {
                // Never propagate parser internals — an exception message is an
                // information channel out of the sandbox.
                RenderResult(0, 0, "render failed")
            } finally {
                SharedMemory.unmap(buffer)
            }
        }
    }

    override fun onBind(intent: Intent): IBinder = binder
}
