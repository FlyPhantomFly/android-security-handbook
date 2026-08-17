// examples/victim-app/MainActivity.java
// Package: com.pentest.ch30.victim
//
// Declared in AndroidManifest.xml with the MAIN/LAUNCHER filter, launchMode=standard (the default) and taskAffinity left at the default, which is the package name com.pentest.ch30.victim. This is the activity the user reaches by tapping the app icon, and it is the activity labs/lab-02 tries to hijack.
//
// It has no logic of its own. Everything it does comes from Base.java, so any
// behaviour you observe in `dumpsys activity activities` or in logcat is
// attributable to the manifest attribute above and to nothing else. That is the
// whole point: labs/lab-01-read-the-task-graph.md compares these side by side.

package com.pentest.ch30.victim;

public class MainActivity extends Base {
}
