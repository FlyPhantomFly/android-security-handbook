// labs/ctf-vault/Gate.java
//
// DELIBERATELY VULNERABLE CTF FIXTURE -- chapter 66, lab 04.
//
// One boolean. The application never sets it to true; there is no code path in
// this APK that does. It is read exactly once, inside CtfApp.onCreate(), and the
// value it holds at that instant decides whether fragment 3 is decoded or
// replaced with a refusal.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.ctf;

public final class Gate {

    /**
     * Never written by this application. Read once, during CtfApp.onCreate().
     *
     * If you are reading this file as part of the challenge: the interesting
     * question is not "how do I set it" -- reflection sets it in three lines --
     * but "at what moment must it already be set". Get that wrong and the write
     * succeeds, the field reads back true, and fragment 3 is still a refusal.
     */
    static boolean sUnlocked = false;

    private Gate() {
    }

    static boolean isUnlocked() {
        return sUnlocked;
    }
}
