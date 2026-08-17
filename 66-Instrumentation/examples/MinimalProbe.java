// examples/MinimalProbe.java
//
// The smallest instrumentation that can exist and still tell you something true.
// Eleven lines of body. No androidx, no JUnit, no dependencies of any kind
// beyond the platform.
//
// It answers exactly one question -- "who am I, once the framework has put me
// inside the target?" -- and the four values it returns are the whole capability
// claim of chapter 66 in one screen:
//
//     uid            the TARGET's uid, not the test package's and not 2000
//     process        the TARGET's process name
//     testPackage    getContext()       -> the TEST package
//     targetPackage  getTargetContext() -> the TARGET package
//
// HOW TO BUILD AND RUN IT
//   This file is a drop-in replacement for the runner class in the chapter's
//   probe fixture. The fastest route is:
//
//     1. cp MinimalProbe.java vault-probe/
//     2. edit vault-probe/AndroidManifest.xml, change android:name to
//        com.pentest.ch66.probe.MinimalProbe
//     3. ./build-instrumentation-fixtures.sh --install
//     4. adb shell am instrument -w -r \
//            com.pentest.ch66.vault.test/com.pentest.ch66.probe.MinimalProbe
//
//   Expected output, measured on sdk_gphone16k_x86_64 (Android 15 / API 35):
//
//     INSTRUMENTATION_RESULT: process=com.pentest.ch66.vault
//     INSTRUMENTATION_RESULT: targetPackage=com.pentest.ch66.vault
//     INSTRUMENTATION_RESULT: testPackage=com.pentest.ch66.vault.test
//     INSTRUMENTATION_RESULT: uid=10210
//     INSTRUMENTATION_CODE: -1
//
//   INSTRUMENTATION_CODE: -1 is Activity.RESULT_OK. It means success.
//
// THREE THINGS THIS FILE IS DELIBERATELY SHOWING YOU
//   1. onCreate() must call start() or onStart() never runs and the process just
//      sits there until something kills it.
//   2. finish() reports the bundle AND kills the process. It is not a return.
//   3. There is no manifest permission anywhere in this. The binding is
//      <instrumentation android:targetPackage="..."> and nothing else.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.probe;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import android.os.Process;

public class MinimalProbe extends Instrumentation {

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        // Spawn the instrumentation thread. Control continues in onStart().
        start();
    }

    @Override
    public void onStart() {
        Bundle r = new Bundle();
        r.putString("uid", String.valueOf(Process.myUid()));
        r.putString("process", String.valueOf(getProcessName()));
        r.putString("testPackage", getContext().getPackageName());
        r.putString("targetPackage", getTargetContext().getPackageName());
        finish(Activity.RESULT_OK, r);
    }
}
