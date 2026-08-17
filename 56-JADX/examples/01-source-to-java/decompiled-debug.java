/*
 * examples/01-source-to-java/decompiled-debug.java
 *
 * CAPTURED OUTPUT -- do not edit. jadx 1.5.3, verbatim, for the DEBUG build of
 * AccountVault.java in this directory:
 *
 *   javac --release 8 -g  ->  d8 --debug --min-api 30  ->  jadx -q -d out
 *
 * Reproduce with ./build.sh. Only the "loaded from:" header comment that jadx emits above
 * the class (line 53 below) was shortened from an absolute path; nothing else was touched.
 * It is named without its slash-star delimiters here because writing them out would close
 * this comment.
 *
 * READ THIS ALONGSIDE decompiled-release.java. Two things happen here and they point in
 * opposite directions:
 *
 *   1. Almost every method comes back with the ORIGINAL local variable names --
 *      candidate, equal, limit, roles, visible, role, payload, tags, tag, accountId,
 *      label, out -- because d8 --debug wrote a debug_info_item into the DEX.
 *      unlock() is character-for-character the source apart from `this.` qualification.
 *      Declared types improve too: `InputStream in` instead of
 *      `ByteArrayInputStream byteArrayInputStream`, and `new ArrayList<>()` with a
 *      diamond instead of a raw `new ArrayList()`.
 *
 *   2. tierFromPlanName() -- which decompiles CLEANLY in the release build -- is REFUSED
 *      here. jadx emits "Can't fix incorrect switch cases order, some code will
 *      duplicate", "Removed duplicated region for block", and replaces the body with
 *      throw new UnsupportedOperationException("Method not decompiled: ...").
 *
 * Point 2 is the more interesting one, and it is the reason this file is in the chapter.
 * MORE INFORMATION MADE THE OUTPUT WORSE FOR ONE METHOD. The line-number table constrains
 * how jadx may reorder and duplicate blocks, and SwitchOverStringVisitor's reconstruction
 * of a string switch needs exactly that freedom. So "build with debug info and you get
 * better output" is true on average and false per-method, which is precisely the kind of
 * claim this chapter exists to stop you making.
 *
 * There is a bonus: the refusal's instruction dump below is the REAL two-stage string
 * switch that javac emits -- hashCode() into a lookup switch, then equals() confirmation,
 * then a second switch on a synthesised index. That is what the release build's tidy
 * `switch (str)` with its orphan `str.hashCode();` is a reconstruction OF.
 *
 * This file is not compiled by anything. It is evidence.
 *
 * It has, however, been PUT THROUGH javac once, as a check on that claim, and the
 * result is worth recording: under `javac 24` against `android-35` it produces
 * exactly TWO errors, both at the anonymous Runnable in section 8 of README.md --
 * "anonymous class implements interface; cannot have arguments" and the
 * `this.this$0 = this` assignment. Those two ARE the evidence; they are jadx
 * choosing accuracy over validity, exactly as the chapter says.
 *
 * Any OTHER diagnostic means this file has been damaged in transit, not that jadx
 * did something new. Until this sweep there were 32 of them, because the header
 * comment above used to name the "loaded from:" marker with its slash-star
 * delimiters intact and so closed itself at that line.
 */

package com.pentest.ch56;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* loaded from: dex-debug/classes.dex */
public class AccountVault {
    private static final String ENDPOINT = "https://api.example.invalid/v3/session";
    private static final int MAX_ATTEMPTS = 3;
    private final char[] masterKey;
    private final Map<String, List<String>> rolesByAccount = new HashMap();
    private int failedAttempts = 0;

    public enum Tier {
        FREE,
        PLUS,
        ENTERPRISE
    }

    public AccountVault(char[] masterKey) {
        this.masterKey = (char[]) masterKey.clone();
    }

    public List<String> rolesFor(String accountId) {
        List<String> roles = this.rolesByAccount.get(accountId);
        if (roles == null) {
            return new ArrayList();
        }
        List<String> visible = new ArrayList<>();
        for (String role : roles) {
            if (!role.startsWith("_internal")) {
                visible.add(role);
            }
        }
        return visible;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0026  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.pentest.ch56.AccountVault.Tier tierFromPlanName(java.lang.String r4) {
        /*
            r3 = this;
            int r0 = r4.hashCode()
            switch(r0) {
                case -802737311: goto L1c;
                case 3151468: goto L12;
                case 3444122: goto L8;
                default: goto L7;
            }
        L7:
            goto L26
        L8:
            java.lang.String r0 = "plus"
            boolean r0 = r4.equals(r0)
            if (r0 == 0) goto L7
            r0 = 1
            goto L27
        L12:
            java.lang.String r0 = "free"
            boolean r0 = r4.equals(r0)
            if (r0 == 0) goto L7
            r0 = 0
            goto L27
        L1c:
            java.lang.String r0 = "enterprise"
            boolean r0 = r4.equals(r0)
            if (r0 == 0) goto L7
            r0 = 2
            goto L27
        L26:
            r0 = -1
        L27:
            switch(r0) {
                case 0: goto L49;
                case 1: goto L46;
                case 2: goto L43;
                default: goto L2a;
            }
        L2a:
            java.lang.IllegalArgumentException r0 = new java.lang.IllegalArgumentException
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            java.lang.String r2 = "unknown plan: "
            java.lang.StringBuilder r1 = r1.append(r2)
            java.lang.StringBuilder r1 = r1.append(r4)
            java.lang.String r1 = r1.toString()
            r0.<init>(r1)
            throw r0
        L43:
            com.pentest.ch56.AccountVault$Tier r0 = com.pentest.ch56.AccountVault.Tier.ENTERPRISE
            return r0
        L46:
            com.pentest.ch56.AccountVault$Tier r0 = com.pentest.ch56.AccountVault.Tier.PLUS
            return r0
        L49:
            com.pentest.ch56.AccountVault$Tier r0 = com.pentest.ch56.AccountVault.Tier.FREE
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.pentest.ch56.AccountVault.tierFromPlanName(java.lang.String):com.pentest.ch56.AccountVault$Tier");
    }

    public String readHeader(byte[] payload) throws IOException {
        InputStream in = new ByteArrayInputStream(payload);
        try {
            StringBuilder sb = new StringBuilder();
            while (true) {
                int b = in.read();
                if (b == -1 || b == 10) {
                    break;
                }
                sb.append((char) b);
            }
            String string = sb.toString();
            in.close();
            return string;
        } catch (Throwable th) {
            try {
                in.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    public String describe(String accountId, Tier tier) {
        String label = tier == Tier.ENTERPRISE ? "priority" : "standard";
        String out = "https://api.example.invalid/v3/session?acct=" + accountId + "&lane=" + label;
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            out = out + "&r" + i;
        }
        return out;
    }

    public Runnable auditor(final String... tags) {
        return new Runnable(this) { // from class: com.pentest.ch56.AccountVault.1
            final /* synthetic */ AccountVault this$0;

            {
                this.this$0 = this;
            }

            @Override // java.lang.Runnable
            public void run() {
                for (String tag : tags) {
                    System.out.println("audit:" + tag);
                }
            }
        };
    }

    public boolean unlock(char[] candidate) {
        if (this.failedAttempts >= MAX_ATTEMPTS) {
            return false;
        }
        boolean equal = candidate.length == this.masterKey.length;
        int limit = Math.min(candidate.length, this.masterKey.length);
        for (int i = 0; i < limit; i++) {
            if (candidate[i] != this.masterKey[i]) {
                equal = false;
            }
        }
        if (!equal) {
            this.failedAttempts++;
        }
        return equal;
    }

    static final class Session {
        private final long issuedAtMillis;
        private final String token;

        Session(String token, long issuedAtMillis) {
            this.token = token;
            this.issuedAtMillis = issuedAtMillis;
        }
    }

    public String tokenOf(Session session) {
        return session.token;
    }
}
