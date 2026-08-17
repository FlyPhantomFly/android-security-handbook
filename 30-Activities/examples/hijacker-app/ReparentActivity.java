// examples/hijacker-app/ReparentActivity.java
// Package: com.pentest.ch30.attacker
//
// The allowTaskReparenting variant of the task attack.
//
// ---------------------------------------------------------------------------
// HOW IT DIFFERS FROM THE singleTask VARIANT
// ---------------------------------------------------------------------------
// The singleTask variant (HijackActivity) captures the task NAME up front: the
// attacker's activity runs once, creates a task carrying the victim's affinity,
// and waits for the victim to be drawn into it.
//
// Reparenting works the other way round. The attacker's activity is started
// INSIDE some task -- typically the victim's own, because the victim just
// started it via a deputy, a share sheet, or a browser hand-off -- and then
// android:allowTaskReparenting="true" asks the system to MOVE it into whichever
// task has a matching affinity when that task next comes to the foreground.
//
// The practical difference for an attacker is stealth. The singleTask variant
// leaves an extra task in Recents from the moment it is armed. Reparenting does
// not need a pre-created task at all, so there is nothing to see until the
// moment the swap happens.
//
// The practical difference for a defender is that the two are mitigated by
// different code paths, so they must be tested separately. Do not report
// "task hijacking is fixed" on the strength of one of them.
//
// ---------------------------------------------------------------------------
// WHAT TO LOOK FOR
// ---------------------------------------------------------------------------
// Reparenting is visible in `dumpsys activity activities` as an ActivityRecord
// whose package differs from the package of its task's root activity. Concretely,
// compare the `Hist #` lines of one Task block: if
//
//     Hist #0: ... com.pentest.ch30.victim/.MainActivity   t<N>
//     Hist #1: ... com.pentest.ch30.attacker/.ReparentActivity t<N>
//
// share a task id, two packages are stacked in one task and the user's back
// button now walks across a trust boundary.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch30.attacker;

public class ReparentActivity extends HijackActivity {
    // Behaviour is identical; only the manifest attributes differ. Keeping the
    // code identical is deliberate -- it guarantees that any difference the lab
    // measures comes from allowTaskReparenting and not from the activity itself.
}
