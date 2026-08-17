// examples/victim-app/AlphaActivity.java
// Package: com.pentest.ch30.victim
//
// Declared with android:launchMode="standard". Every start builds a NEW instance, in the caller's task, even if an instance is already sitting at the top. Expect a fresh identityHashCode from every start.
//
// It has no logic of its own. Everything it does comes from Base.java, so any
// behaviour you observe in `dumpsys activity activities` or in logcat is
// attributable to the manifest attribute above and to nothing else. That is the
// whole point: labs/lab-01-read-the-task-graph.md compares these side by side.

package com.pentest.ch30.victim;

public class AlphaActivity extends Base {
}
