// examples/RenderZygotePreload.kt
package com.example.enterprise.render

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo

/**
 * Runs once, in the app's own Zygote (which is itself isolated).
 * Everything loaded here is shared copy-on-write by every render process,
 * so N isolated renderers cost roughly the memory of one.
 */
class RenderZygotePreload : ZygotePreload {
    override fun doPreload(appInfo: ApplicationInfo) {
        System.loadLibrary("docparser")     // the risky native code, loaded once
        NativeParser.warmTables()           // any expensive read-only setup
    }
}
