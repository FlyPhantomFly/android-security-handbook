// examples/victim-app/EpsilonActivity.java
// Package: com.pentest.ch30.victim
//
// Declared with android:launchMode="standard" but android:taskAffinity="com.pentest.ch30.other" -- a non-default affinity inside the app's own package. It is the control for the whole affinity argument: it belongs to this app and STILL lands in a different task, which proves that the task boundary follows the affinity string, not the package.
//
// It has no logic of its own. Everything it does comes from Base.java, so any
// behaviour you observe in `dumpsys activity activities` or in logcat is
// attributable to the manifest attribute above and to nothing else. That is the
// whole point: labs/lab-01-read-the-task-graph.md compares these side by side.

package com.pentest.ch30.victim;

public class EpsilonActivity extends Base {
}
