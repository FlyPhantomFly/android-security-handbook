// examples/victim-app/BetaActivity.java
// Package: com.pentest.ch30.victim
//
// Declared with android:launchMode="singleTop". If an instance is already at the TOP of the target task, the system reuses it and calls onNewIntent. If it is anywhere else in the stack -- even one activity down -- a second instance is built. Both facts are measured in lab-01.
//
// It has no logic of its own. Everything it does comes from Base.java, so any
// behaviour you observe in `dumpsys activity activities` or in logcat is
// attributable to the manifest attribute above and to nothing else. That is the
// whole point: labs/lab-01-read-the-task-graph.md compares these side by side.

package com.pentest.ch30.victim;

public class BetaActivity extends Base {
}
