package com.pentest.ch56;

/*
 * examples/01-source-to-java/AccountVault.java
 *
 * Chapter 56 (JADX) — the "source" end of a source -> DEX -> decompiled-Java triple.
 * Build it with ./build.sh, which produces two DEX files (release and debug) and runs
 * jadx over both. Compare this file with decompiled-release.java and decompiled-debug.java.
 *
 * Nothing in here is clever. Every construct is something a real Android app uses every
 * day. The point of the file is what survives the trip through d8 and back out through
 * jadx, and what does not.
 *
 * No Android APIs are used, so it compiles against any JDK and needs no device.
 */

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AccountVault {

    public enum Tier {
        FREE, PLUS, ENTERPRISE
    }

    private static final String ENDPOINT = "https://api.example.invalid/v3/session";
    private static final int MAX_ATTEMPTS = 3;

    private final Map<String, List<String>> rolesByAccount = new HashMap<String, List<String>>();
    private final char[] masterKey;
    private int failedAttempts;

    public AccountVault(char[] masterKey) {
        this.masterKey = masterKey.clone();
        this.failedAttempts = 0;
    }

    /** Generic container plus an enhanced for loop over a generic collection. */
    public List<String> rolesFor(String accountId) {
        List<String> roles = rolesByAccount.get(accountId);
        if (roles == null) {
            return new ArrayList<String>();
        }
        List<String> visible = new ArrayList<String>();
        for (String role : roles) {
            if (!role.startsWith("_internal")) {
                visible.add(role);
            }
        }
        return visible;
    }

    /** switch over String: javac turns this into hashCode + equals + a second switch. */
    public Tier tierFromPlanName(String planName) {
        switch (planName) {
            case "free":
                return Tier.FREE;
            case "plus":
                return Tier.PLUS;
            case "enterprise":
                return Tier.ENTERPRISE;
            default:
                throw new IllegalArgumentException("unknown plan: " + planName);
        }
    }

    /** try-with-resources: javac synthesises a finally block and a suppressed-exception dance. */
    public String readHeader(byte[] payload) throws IOException {
        try (InputStream in = new ByteArrayInputStream(payload)) {
            StringBuilder sb = new StringBuilder();
            int b;
            while ((b = in.read()) != -1 && b != '\n') {
                sb.append((char) b);
            }
            return sb.toString();
        }
    }

    /** Ternary, string concatenation in a loop, and a compile-time constant. */
    public String describe(String accountId, Tier tier) {
        String label = (tier == Tier.ENTERPRISE) ? "priority" : "standard";
        String out = ENDPOINT + "?acct=" + accountId + "&lane=" + label;
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            out = out + "&r" + i;
        }
        return out;
    }

    /** A varargs method and an anonymous inner class. */
    public Runnable auditor(final String... tags) {
        return new Runnable() {
            @Override
            public void run() {
                for (String tag : tags) {
                    System.out.println("audit:" + tag);
                }
            }
        };
    }

    /** The security-relevant one. Constant-time-ish comparison over a char[]. */
    public boolean unlock(char[] candidate) {
        if (failedAttempts >= MAX_ATTEMPTS) {
            return false;
        }
        boolean equal = candidate.length == masterKey.length;
        int limit = Math.min(candidate.length, masterKey.length);
        for (int i = 0; i < limit; i++) {
            if (candidate[i] != masterKey[i]) {
                equal = false;
            }
        }
        if (!equal) {
            failedAttempts++;
        }
        return equal;
    }

    /** A static nested class with a private field the outer class reads. */
    static final class Session {
        private final String token;
        private final long issuedAtMillis;

        Session(String token, long issuedAtMillis) {
            this.token = token;
            this.issuedAtMillis = issuedAtMillis;
        }
    }

    public String tokenOf(Session session) {
        return session.token;
    }
}
