// examples/DocumentRenderClient.kt — the host side
package com.example.enterprise.render

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.SharedMemory
import android.system.OsConstants
import java.io.File
import java.util.concurrent.CompletableFuture

class DocumentRenderClient(private val ctx: Context) {

    fun render(doc: File, pages: Int): CompletableFuture<RenderResult> {
        val future = CompletableFuture<RenderResult>()

        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                val renderer = IDocumentRenderer.Stub.asInterface(service)

                // Read-only descriptor: the isolated process cannot modify the source.
                val pfd = ParcelFileDescriptor.open(doc, ParcelFileDescriptor.MODE_READ_ONLY)

                // A bounded output region. The isolated process cannot allocate our memory.
                val shm = SharedMemory.create("render-out", 8 * 1024 * 1024)

                try {
                    val result = renderer.render(pfd, shm, pages)
                    // Seal AFTER the render: from here the region is immutable for everyone.
                    shm.setProtect(OsConstants.PROT_READ)
                    future.complete(result)
                } catch (t: Throwable) {
                    future.completeExceptionally(t)
                } finally {
                    pfd.close()
                    ctx.unbindService(this)
                }
            }
            override fun onServiceDisconnected(name: ComponentName) {
                future.completeExceptionally(IllegalStateException("renderer died"))
            }
        }

        ctx.bindService(
            Intent(ctx, DocumentRenderService::class.java),
            conn,
            Context.BIND_AUTO_CREATE or Context.BIND_NOT_FOREGROUND
        )
        return future
    }
}
