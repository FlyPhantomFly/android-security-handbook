// examples/victim-app/DeltaActivity.java
// Package: com.pentest.ch30.victim
//
// Declared with android:launchMode="singleInstance". The instance is alone in its own task and that task never accepts another activity -- anything it starts is routed elsewhere. This is the strictest mode and the one with the worst usability consequences.
//
// It has no logic of its own. Everything it does comes from Base.java, so any
// behaviour you observe in `dumpsys activity activities` or in logcat is
// attributable to the manifest attribute above and to nothing else. That is the
// whole point: labs/lab-01-read-the-task-graph.md compares these side by side.

package com.pentest.ch30.victim;

public class DeltaActivity extends Base {
}
