// examples/victim-app/GammaActivity.java
// Package: com.pentest.ch30.victim
//
// Declared with android:launchMode="singleTask". At most one instance exists per task-affinity group, and starting it when it already exists REUSES the instance and destroys everything stacked above it. Note the part most write-ups get wrong: it does not necessarily create a new task.
//
// It has no logic of its own. Everything it does comes from Base.java, so any
// behaviour you observe in `dumpsys activity activities` or in logcat is
// attributable to the manifest attribute above and to nothing else. That is the
// whole point: labs/lab-01-read-the-task-graph.md compares these side by side.

package com.pentest.ch30.victim;

public class GammaActivity extends Base {
}
