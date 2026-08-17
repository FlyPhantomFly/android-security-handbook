// examples/vault-target/LicenseGate.java
//
// A single boolean decision, held in a private static field. This is the
// smallest honest model of a licence check, a feature flag, or a "device is
// rooted" verdict: a value computed once and consulted afterwards.
//
// Chapter 66 uses it to make one point precisely. An instrumentation is IN the
// target process, so it can write this field by reflection and the target will
// read the new value -- no hooking, no trampoline, no ART internals. That is the
// difference between instrumentation and hooking: hooking changes what a method
// DOES (see 65-Hooking), instrumentation changes what the process CONTAINS.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.vault;

public final class LicenseGate {

    /** Private, static, and never written after startup -- by the app, at least. */
    private static boolean sPremium = false;

    private LicenseGate() {
    }

    public static boolean isPremium() {
        return sPremium;
    }

    /**
     * The only writer the app itself ships. It is deliberately package-private
     * and unused, so that any observed change to sPremium came from outside.
     */
    static void grant() {
        sPremium = true;
    }
}
