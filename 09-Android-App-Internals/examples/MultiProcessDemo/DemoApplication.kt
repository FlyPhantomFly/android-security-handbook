// examples/MultiProcessDemo/DemoApplication.kt
package com.example.multiproc

import android.app.Application
import android.os.Process
import android.util.Log
import java.io.File

class DemoApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        // This line appears TWICE in logcat, with two different PIDs and two different
        // process names, but the SAME uid and the SAME dataDir.
        Log.i(TAG, "APPLICATION onCreate  process=${processName()} " +
                   "pid=${Process.myPid()} uid=${Process.myUid()}")
        Log.i(TAG, "  dataDir  = ${applicationInfo.dataDir}")
        Log.i(TAG, "  Counter.value at Application start = ${Counter.value}")
    }

    companion object {
        const val TAG = "MultiProc"

        /**
         * The process's own name. Application.getProcessName() exists from API 28; reading
         * /proc/self/cmdline works everywhere and needs no version check, which is why the
         * chapter's tooling prefers it.
         */
        fun processName(): String = try {
            File("/proc/self/cmdline").readText().trim { it <= ' ' }
        } catch (e: Exception) {
            "(unknown)"
        }
    }
}
