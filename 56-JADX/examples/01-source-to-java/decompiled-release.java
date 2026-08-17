/*
 * examples/01-source-to-java/decompiled-release.java
 *
 * CAPTURED OUTPUT -- do not edit. This is jadx 1.5.3's output, verbatim, for the RELEASE
 * build of AccountVault.java in this directory:
 *
 *   javac --release 8 -g:none  ->  d8 --release --min-api 30  ->  jadx -q -d out
 *
 * Reproduce with ./build.sh. The only line that will differ on your machine is the
 * "loaded from:" header comment that jadx emits above the class (line 29 below), which has
 * been shortened here from an absolute path to a relative one purely so the file reads
 * cleanly. Nothing else was touched. That comment is named without its slash-star
 * delimiters here because writing them out would close this comment.
 *
 * Chapter 56 section 6.2 walks this file against AccountVault.java line by line.
 * Compare with decompiled-debug.java to see what debug information changes -- including
 * one method that decompiles here and REFUSES there.
 *
 * This file is not compiled by anything. It is evidence.
 *
 * It has, however, been PUT THROUGH javac once, as a check on that claim. Under
 * `javac 24` against `android-35` it produces exactly TWO errors, both at the
 * anonymous Runnable in section 8 of README.md. Those two ARE the evidence: jadx
 * choosing accuracy over validity. Any OTHER diagnostic means the file has been
 * damaged, not that jadx did something new -- until this sweep there were eight,
 * because the header above named the "loaded from:" marker with its slash-star
 * delimiters intact and so closed itself at that line.
 */

package com.pentest.ch56;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* loaded from: dex-release/classes.dex */
public class AccountVault {
    private static final String ENDPOINT = "https://api.example.invalid/v3/session";
    private static final int MAX_ATTEMPTS = 3;
    private final char[] masterKey;
    private final Map<String, List<String>> rolesByAccount = new HashMap();
    private int failedAttempts = 0;

    static final class Session {
        private final long issuedAtMillis;
        private final String token;

        Session(String str, long j) {
            this.token = str;
            this.issuedAtMillis = j;
        }
    }

    public enum Tier {
        FREE,
        PLUS,
        ENTERPRISE
    }

    public AccountVault(char[] cArr) {
        this.masterKey = (char[]) cArr.clone();
    }

    public Runnable auditor(final String... strArr) {
        return new Runnable(this) { // from class: com.pentest.ch56.AccountVault.1
            final /* synthetic */ AccountVault this$0;

            {
                this.this$0 = this;
            }

            @Override // java.lang.Runnable
            public void run() {
                for (String str : strArr) {
                    System.out.println("audit:" + str);
                }
            }
        };
    }

    public String describe(String str, Tier tier) {
        String str2 = "https://api.example.invalid/v3/session?acct=" + str + "&lane=" + (tier == Tier.ENTERPRISE ? "priority" : "standard");
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            str2 = str2 + "&r" + i;
        }
        return str2;
    }

    public String readHeader(byte[] bArr) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bArr);
        try {
            StringBuilder sb = new StringBuilder();
            while (true) {
                int i = byteArrayInputStream.read();
                if (i == -1 || i == 10) {
                    break;
                }
                sb.append((char) i);
            }
            String string = sb.toString();
            byteArrayInputStream.close();
            return string;
        } catch (Throwable th) {
            try {
                byteArrayInputStream.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    public List<String> rolesFor(String str) {
        List<String> list = this.rolesByAccount.get(str);
        if (list == null) {
            return new ArrayList();
        }
        ArrayList arrayList = new ArrayList();
        for (String str2 : list) {
            if (!str2.startsWith("_internal")) {
                arrayList.add(str2);
            }
        }
        return arrayList;
    }

    public Tier tierFromPlanName(String str) {
        str.hashCode();
        switch (str) {
            case "enterprise":
                return Tier.ENTERPRISE;
            case "free":
                return Tier.FREE;
            case "plus":
                return Tier.PLUS;
            default:
                throw new IllegalArgumentException("unknown plan: " + str);
        }
    }

    public String tokenOf(Session session) {
        return session.token;
    }

    public boolean unlock(char[] cArr) {
        if (this.failedAttempts >= MAX_ATTEMPTS) {
            return false;
        }
        int length = cArr.length;
        char[] cArr2 = this.masterKey;
        boolean z = length == cArr2.length;
        int iMin = Math.min(cArr.length, cArr2.length);
        for (int i = 0; i < iMin; i++) {
            if (cArr[i] != this.masterKey[i]) {
                z = false;
            }
        }
        if (!z) {
            this.failedAttempts++;
        }
        return z;
    }
}
