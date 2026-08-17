// examples/MultiProcessDemo/MainActivity.kt
package com.example.multiproc

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Process
import android.util.Log
import android.widget.TextView

class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        Counter.value += 1
        Log.i(DemoApplication.TAG, "MAIN     process=${DemoApplication.processName()} " +
              "pid=${Process.myPid()} uid=${Process.myUid()} Counter.value=${Counter.value}")

        // Write a file, so the NEXT section can show that the filesystem IS shared even
        // though memory is not.
        openFileOutput("shared.txt", MODE_PRIVATE).use {
            it.write("written by ${DemoApplication.processName()}\n".toByteArray())
        }

        // Starting the service forks a second process, because of one manifest attribute.
        startService(Intent(this, RemoteService::class.java))

        setContentView(TextView(this).apply {
            setPadding(48, 48, 48, 48)
            typeface = android.graphics.Typeface.MONOSPACE
            text = "main pid=${Process.myPid()} uid=${Process.myUid()}\n" +
                   "Counter.value here = ${Counter.value}\n\n" +
                   "adb logcat -d -s MultiProc -v time"
        })
    }
}
