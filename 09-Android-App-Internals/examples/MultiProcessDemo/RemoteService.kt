// examples/MultiProcessDemo/RemoteService.kt
package com.example.multiproc

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.Process
import android.util.Log
import java.io.File

class RemoteService : Service() {

    override fun onCreate() {
        super.onCreate()
        Log.i(DemoApplication.TAG, "REMOTE   process=${DemoApplication.processName()} " +
              "pid=${Process.myPid()} uid=${Process.myUid()} Counter.value=${Counter.value}")

        // Memory is NOT shared: Counter.value is 0 here no matter how many times the
        // activity incremented it.
        // Storage IS shared: the file the activity just wrote is readable, because both
        // processes run as the same UID against the same data directory.
        val f = File(filesDir, "shared.txt")
        Log.i(DemoApplication.TAG, "  filesDir      = $filesDir")
        Log.i(DemoApplication.TAG, "  shared.txt    = " +
              if (f.exists()) f.readText().trim() else "(missing)")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_NOT_STICKY

    // Not a bound service: returning null keeps this demo about processes, not about IPC.
    override fun onBind(intent: Intent?): IBinder? = null
}
