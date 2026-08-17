/*
 * AfterObfuscation.java
 * ===========================================================================
 * WHAT THIS IS
 *   The "after" half of the pair. This is what BeforeObfuscation.java looks
 *   like coming out of jadx once each technique in chapter 40 section 3 has
 *   been applied to it.
 *
 *   It is presented as one compilable file per stage so you can read them in
 *   sequence -- and that word "compilable" is now checked rather than claimed:
 *   this file compiles clean under `javac 24 -Xlint:all` against `android-35`.
 *   It did not always. Stage 1 and Stage 2 each declared login and post as
 *   `a(String,String)` in the same class, which is not legal Java or DEX and is
 *   not something R8 emits, because overload-based renaming requires DISTINCT
 *   parameter types -- exactly as README section 3.1 says. post is now `c`.
 *
 *   The content of each stage is real decompiler-shaped output:
 *   the naming, the byte-array literals, the `while(true){switch}` and the
 *   reflection chains are what you will actually see on a target.
 *
 *   Stage 1  identifier renaming (R8 default)
 *   Stage 2  plus string encryption
 *   Stage 3  plus control-flow flattening
 *   Stage 4  plus reflection at the API boundary
 *   Stage 5  plus native migration
 *
 * WHY IT MATTERS
 *   The gap between these two files IS the chapter. Reading the "after" and
 *   working out that it is the "before" is the entire skill, and doing it once
 *   deliberately — with the answer available — is worth more than reading any
 *   amount of description.
 *
 *   Pay particular attention to what does NOT change between stages. Stage 1
 *   destroys every name and leaves every string. Stage 2 destroys the strings
 *   and leaves the structure. Stage 3 destroys the structure and leaves the
 *   method boundaries. Stage 4 destroys the static cross-references and
 *   replaces them with strings — which stage 2 already taught you how to
 *   recover. Each layer removes one kind of information, and the methodology
 *   in section 6.1 is ordered to restore them in the cheapest sequence.
 *
 * HOW TO USE IT
 *   Read BeforeObfuscation.java first. Then read one stage at a time and, for
 *   each, ask: what could I still recover, and how? Write the answer down
 *   before reading the commentary at the end of the stage.
 *
 * REQUIREMENTS
 *   None to read. To reproduce: R8, the string-encryption generator in
 *   gen-string-table.py, and a text editor for the hand-flattening.
 *
 * AUTHORISED TESTING ONLY — teaching material for chapter 40.
 * ===========================================================================
 */

package com.obflab.demo;

/* ===========================================================================
 * STAGE 1 — IDENTIFIER RENAMING (R8 default)
 *
 * Class `PaymentService` became `a`. Methods `login`, `transfer`,
 * `classifyRisk` all became `a` with different signatures. Fields became `a`,
 * `b`, `c`. The package became `p001a.b` or similar under
 * `-repackageclasses`.
 *
 * NOTHING ELSE CHANGED. Read the strings.
 * ===========================================================================
 */

final class Stage1 {

    // Was: PaymentService
    // In jadx this appears as `public class a` in package `p001a.b`.
    static final class a {

        // Was: TAG, BASE_URL, LOGIN_PATH, TRANSFER_PATH, API_KEY, ...
        private static final String a = "PaymentService";
        private static final String b = "https://api.obflab.example.com/v2";
        private static final String c = "/auth/login";
        private static final String d = "/payments/transfer";
        private static final String e = "/accounts/balance";
        private static final String f = "sk_live_EXAMPLE_NOT_A_REAL_KEY_ch40";
        private static final String g = "payment_prefs";
        private static final String h = "auth_token";
        private static final String i = "AES/CBC/PKCS5Padding";
        private static final String j = "SHA-256";

        private final android.content.Context k;
        private final android.content.SharedPreferences l;

        a(android.content.Context context) {
            this.k = context.getApplicationContext();
            this.l = this.k.getSharedPreferences(g, 0);
        }

        // Was: login(String, String)
        public String a(String str, String str2) {
            try {
                org.json.JSONObject jSONObject = new org.json.JSONObject();
                jSONObject.put("username", str);
                jSONObject.put("password", str2);
                jSONObject.put("device_id", b());
                String a2 = c(b + c, jSONObject.toString());
                if (a2 == null) {
                    return null;
                }
                String optString = new org.json.JSONObject(a2).optString("access_token", null);
                if (optString != null) {
                    this.l.edit().putString(h, optString).apply();
                }
                return optString;
            } catch (Exception e2) {
                android.util.Log.w(a, "login failed", e2);
                return null;
            }
        }

        // Was: transfer(String, long)
        public boolean a(String str, long j2) {
            try {
                org.json.JSONObject jSONObject = new org.json.JSONObject();
                jSONObject.put("to", str);
                jSONObject.put("amount", j2);
                jSONObject.put("signature", b(str, j2));
                String a2 = c(b + d, jSONObject.toString());
                return a2 != null && new org.json.JSONObject(a2).optBoolean("ok", false);
            } catch (Exception e2) {
                android.util.Log.w(a, "transfer failed", e2);
                return false;
            }
        }

        private String b() { return null; }              // getOrCreateDeviceId
        private String b(String s, long l2) { return null; }  // signRequest
        private String c(String s, String b2) { return null; } // post

        // Note `c` is BOTH a static String field (above) and a method here.
        // Fields and methods occupy separate namespaces in the JVM and in DEX,
        // so R8 reuses the same short name for both. It is legal, it is normal
        // in real output, and it is one more thing to keep straight while you
        // read. What R8 will NOT do is emit two methods with the same name and
        // the same parameter types in one class, because that is not legal
        // anywhere: overload-based renaming needs distinct parameter types.
        // That is why post is `c(String,String)` and not another
        // `a(String,String)` beside login. See README section 3.1.
    }

    /* ------------------------------------------------------------------------
     * WHAT YOU CAN STILL RECOVER — everything.
     *
     * `a.a(String, String)` puts "username" and "password" into JSON and posts
     * it to `b + c`, where c is "/auth/login". That method is `login`, with
     * certainty, in under ten seconds.
     *
     * The credential is sitting in field `f` in plaintext.
     *
     * This is why the chapter says renaming alone buys HOURS, not days. It is
     * a nuisance, not an obstacle, and it is defeated by the survivors table:
     * framework calls (`JSONObject.put`, `SharedPreferences.edit`), the string
     * constants, and the structure are all untouched.
     *
     * The one genuine cost renaming imposes: you must now hold a mental map
     * from `a` to `login`, and that map is expensive to maintain across a
     * large app. Which is exactly why Phase 6 (semantic renaming) exists as a
     * discrete step — you write the map down in jadx and stop paying for it.
     * ---------------------------------------------------------------------- */
}

/* ===========================================================================
 * STAGE 2 — PLUS STRING ENCRYPTION
 *
 * The string pool now contains ciphertext. `strings classes.dex | grep https`
 * returns nothing. Every constant became a call to a decryptor.
 * ===========================================================================
 */

final class Stage2 {

    // The decryptor. In jadx this is a small class with a byte[][] and a tight
    // loop containing `^`. In Smali it is unmistakable: `xor-int/lit8` inside
    // a loop, in a method returning Ljava/lang/String;.
    static final class q {
        private static final byte[][] a = {
            // {0x22, 0x3a, 0x3a, 0x2a, 0x29, ...}  <- the ciphertext arrays
        };

        static String a(int i) {
            byte[] bArr = a[i];
            char[] cArr = new char[bArr.length];
            for (int j = 0; j < bArr.length; j++) {
                cArr[j] = (char) (bArr[j] ^ 0x5A);      // <-- THE GIVEAWAY
            }
            return new String(cArr);
        }
    }

    static final class a {

        private final android.content.Context k;
        private final android.content.SharedPreferences l;

        a(android.content.Context context) {
            this.k = context.getApplicationContext();
            this.l = this.k.getSharedPreferences(q.a(6), 0);
        }

        public String a(String str, String str2) {
            try {
                org.json.JSONObject jSONObject = new org.json.JSONObject();
                jSONObject.put(q.a(14), str);
                jSONObject.put(q.a(15), str2);
                jSONObject.put(q.a(16), b());
                String a2 = c(q.a(1) + q.a(2), jSONObject.toString());
                if (a2 == null) return null;
                String optString = new org.json.JSONObject(a2).optString(q.a(17), null);
                if (optString != null) {
                    this.l.edit().putString(q.a(7), optString).apply();
                }
                return optString;
            } catch (Exception e2) {
                android.util.Log.w(q.a(0), q.a(18), e2);
                return null;
            }
        }

        private String b() { return null; }
        private String c(String s, String b2) { return null; }   // post
    }

    /* ------------------------------------------------------------------------
     * WHAT CHANGED — the last readable semantics went.
     *
     * You can still see the SHAPE: something is put into a JSON object, posted
     * somewhere, and a field is extracted and stored in SharedPreferences. You
     * cannot see WHAT, and "what" is what you are being paid to find out.
     *
     * This is the step that genuinely costs an analyst time, and it is the
     * reason section 3.2 says string encryption is "the single most effective
     * thing a developer can do to make an app hard to read".
     *
     * WHAT YOU DO ABOUT IT — the universal counter, in one command:
     *
     *   frida -U -f com.obflab.demo -l ../scripts/frida-string-decryptor.js --pause
     *   sd.candidates()                        # q.a tops the list
     *   sd.exhaust("...q", "a", 0, 512)        # every string, including
     *                                          # ones no code path reaches
     *   sd.save()
     *   python3 ../scripts/annotate-smali-strings.py --smali out --json ... --write
     *
     * After the annotation pass this stage reads exactly like Stage 1 again:
     *
     *   invoke-static {v0}, Lq;->a(I)Ljava/lang/String;   # [str] "/auth/login"
     *
     * Half a day of protection, defeated by a script that does not know or
     * care what the cipher was — because it hooks the RESULT, not the
     * algorithm. See section 3.2's "THE UNIVERSAL COUNTER".
     * ---------------------------------------------------------------------- */
}

/* ===========================================================================
 * STAGE 3 — PLUS CONTROL-FLOW FLATTENING
 *
 * `classifyRisk` from BeforeObfuscation.java, flattened. Same program, same
 * result, no visible order.
 * ===========================================================================
 */

final class Stage3 {

    static final class a {

        // Was: classifyRisk(int, boolean, int)
        public String a(int i, boolean z, int i2) {
            String str = null;
            int i3 = 0;
            int state = 0x2C1A7F;                 // entry — note: not 0
            while (true) {
                switch (state) {
                    case 0x2C1A7F:
                        state = (i < 0) ? 0x71B93E : 0x0A4D62;
                        break;
                    case 0x71B93E:
                        return "invalid";
                    case 0x0A4D62:
                        state = (i < 30) ? 0x55E018 : 0x3F27CB;
                        break;
                    case 0x55E018:
                        str = "high";
                        state = 0x18AF04;
                        break;
                    case 0x3F27CB:
                        state = (i < 70) ? 0x62D5A1 : 0x7E0C39;
                        break;
                    case 0x62D5A1:
                        str = "medium";
                        state = 0x18AF04;
                        break;
                    case 0x7E0C39:
                        str = "low";
                        state = 0x18AF04;
                        break;
                    case 0x18AF04:
                        state = (z && !"low".equals(str)) ? 0x2390BD : 0x4CE651;
                        break;
                    case 0x2390BD:
                        str = "high";
                        state = 0x4CE651;
                        break;
                    case 0x4CE651:
                        i3 = 0;
                        state = 0x09F8D2;
                        break;
                    case 0x09F8D2:
                        state = (i3 < i2) ? 0x6BA415 : 0x37C08E;
                        break;
                    case 0x6BA415:
                        if ("low".equals(str))          { state = 0x5D1E93; }
                        else if ("medium".equals(str))  { state = 0x11720A; }
                        else                            { state = 0x48F6CC; }
                        break;
                    case 0x5D1E93:
                        str = "medium";
                        state = 0x48F6CC;
                        break;
                    case 0x11720A:
                        str = "high";
                        state = 0x48F6CC;
                        break;
                    case 0x48F6CC:
                        i3++;
                        state = 0x09F8D2;
                        break;
                    case 0x37C08E:
                        return str.toUpperCase();
                    default:
                        return null;
                }
            }
        }
    }

    /* ------------------------------------------------------------------------
     * WHAT CHANGED — the order.
     *
     * Every block from the original is still here, verbatim and readable:
     * `str = "high"`, the `i < 30` test, the loop increment. What is gone is
     * the RELATIONSHIP between them. Your eye cannot follow
     * 0x2C1A7F -> 0x0A4D62 -> 0x3F27CB -> 0x62D5A1 -> 0x18AF04 without writing
     * it down, and a real flattened method has forty cases.
     *
     * Note also that the strings SURVIVED flattening entirely. "high",
     * "medium", "low", "invalid" are all still constants. Flattening rearranges
     * intra-procedural control flow and touches nothing else — which is why
     * Phase 4 (strings) can and should come before Phase 5 (control flow).
     *
     * WHY THE DECOMPILER GIVES UP: it reconstructs if/while by finding
     * DOMINANCE in the control-flow graph. Here the dispatcher dominates
     * everything and nothing dominates anything else, because every block's
     * only successor is the dispatcher. There is no structure to find, so the
     * decompiler correctly emits the only one that exists.
     *
     * WHAT YOU DO ABOUT IT — three options, in ascending cost:
     *
     *   1. Build the state-transition table. Ten minutes, completely reliable
     *      at this size. Sort by reachability and the original falls out.
     *   2. Trace the dispatcher for one input; forty cases collapse to eight.
     *   3. DO NOT DEFLATTEN. Ask first: do you need to UNDERSTAND this method,
     *      or only to PREDICT it? A boundary hook answers "what does it return
     *      for these inputs" in five minutes and is completely unaffected by
     *      anything inside.
     *
     * Option 3 is right more often than the instinct to understand everything
     * suggests. See section 3.3.2's Pentester's Note.
     * ---------------------------------------------------------------------- */
}

/* ===========================================================================
 * STAGE 4 — PLUS REFLECTION AT THE API BOUNDARY
 *
 * The crypto from BeforeObfuscation.java, routed through reflection. There is
 * now no static reference to javax.crypto.Cipher anywhere in the DEX.
 * ===========================================================================
 */

final class Stage4 {

    static final class a {

        // Was: encryptLocal(byte[], byte[])
        public byte[] a(byte[] bArr, byte[] bArr2) throws Exception {
            Class<?> cls  = Class.forName(Stage2.q.a(20));   // "javax.crypto.Cipher"
            Class<?> cls2 = Class.forName(Stage2.q.a(21));   // "javax.crypto.spec.SecretKeySpec"
            Class<?> cls3 = Class.forName(Stage2.q.a(22));   // "javax.crypto.spec.IvParameterSpec"

            Object obj = cls.getMethod(Stage2.q.a(23), String.class)   // "getInstance"
                            .invoke(null, Stage2.q.a(8));               // "AES/CBC/PKCS5Padding"

            Object obj2 = cls2.getConstructor(byte[].class, String.class)
                              .newInstance(b(), Stage2.q.a(9));         // "AES"

            Object obj3 = cls3.getConstructor(byte[].class)
                              .newInstance((Object) bArr2);

            cls.getMethod(Stage2.q.a(24),                               // "init"
                          Integer.TYPE,
                          Class.forName(Stage2.q.a(25)),                // "java.security.Key"
                          Class.forName(Stage2.q.a(26)))                // "...AlgorithmParameterSpec"
               .invoke(obj, 1, obj2, obj3);

            return (byte[]) cls.getMethod(Stage2.q.a(27), byte[].class) // "doFinal"
                               .invoke(obj, bArr);
        }

        private byte[] b() { return new byte[16]; }        // deriveKey
    }

    /* ------------------------------------------------------------------------
     * WHAT CHANGED — the static cross-references.
     *
     * `grep -rn 'Cipher' out/sources/` now returns nothing. A call-graph tool
     * sees a chain of `Method.invoke` calls with no edge to the crypto API. An
     * analyst searching for "where does this app do encryption" comes up empty.
     *
     * WHAT DID NOT CHANGE — and this is the joke at the heart of the
     * technique: the reflection targets are STRINGS. "javax.crypto.Cipher",
     * "getInstance", "doFinal" are all string constants, and strings survive
     * renaming. So the moment you have completed Phase 4, this stage is not
     * merely defeated, it is MORE legible than a direct call would have been:
     * you can see the exact method names being resolved.
     *
     * Reflection is opaque to static analysis and completely transparent to
     * dynamic analysis (section 3.4). One hook makes it visible:
     *
     *   Java.perform(function () {
     *       var C = Java.use("java.lang.Class");
     *       C.forName.overload("java.lang.String").implementation = function (n) {
     *           console.log("[forName] " + n);
     *           return this.forName(n);
     *       };
     *   });
     *
     * The developer paid real complexity for a protection that costs you one
     * line. Price it accordingly when you advise them.
     * ---------------------------------------------------------------------- */
}

/* ===========================================================================
 * STAGE 5 — PLUS NATIVE MIGRATION
 *
 * `deriveKey` has moved into a .so. The Java side is now a declaration and a
 * call, with the logic somewhere in ARM64.
 * ===========================================================================
 */

final class Stage5 {

    static final class a {

        static { System.loadLibrary("core"); }

        // Registered with RegisterNatives in JNI_OnLoad, so there is no
        // Java_com_obflab_demo_a_b symbol in .dynsym for you to grep for.
        private static native byte[] b(String str, String str2);

        public byte[] a(byte[] bArr, byte[] bArr2) throws Exception {
            byte[] key = b(c(), Stage2.q.a(5));       // deriveKey, natively
            // ... reflection chain from Stage 4 ...
            return bArr;
        }

        private String c() { return null; }
    }

    /* ------------------------------------------------------------------------
     * WHAT CHANGED — the language, and your toolchain.
     *
     * You are now in Ghidra rather than jadx, which is slower and requires a
     * different skill. That is a real cost and it is the honest benefit of
     * native migration.
     *
     * WHAT DID NOT CHANGE — anything fundamental. Three plaintext choke points
     * remain, by construction:
     *
     *   1. THE JNI BOUNDARY. Every value crossing between Java and native is
     *      observable. `frida-trace -U -f pkg -i 'Java_*'` gives you the whole
     *      conversation, and even with RegisterNatives you can hook
     *      RegisterNatives itself or read the JNINativeMethod array out of
     *      JNI_OnLoad in Ghidra, where the names and signatures sit as plain
     *      strings.
     *
     *   2. libc. File access, networking and process control all go through
     *      interposable symbols.
     *
     *   3. THE CRYPTO LIBRARIES. libcrypto/libssl and the platform providers
     *      are hookable, and a key must be passed to them in the clear.
     *
     * And the shortcut that applies here as everywhere else: you rarely need
     * to understand the native function. You need the value it returns for the
     * inputs the app gives it, and a boundary hook produces that in seconds.
     *
     * ALWAYS trace the JNI boundary BEFORE opening Ghidra. The number of hours
     * lost to reversing a native function whose output a hook would have
     * printed immediately is difficult to overstate.
     * ---------------------------------------------------------------------- */
}

/*
 * ===========================================================================
 * THE COMPARISON, AS A TABLE
 *
 * | Stage | Removes | Leaves | Recovery |
 * |-------|---------|--------|----------|
 * | 1 renaming   | names          | strings, structure, framework calls | rename from strings; hours |
 * | 2 strings    | the semantics  | structure, framework calls          | hook the decryptor; half a day, then collapses to stage 1 |
 * | 3 flattening | intra-method order | strings, method boundaries      | transition table, or hook the boundary and do not bother |
 * | 4 reflection | static xrefs   | the target STRINGS                  | free once stage 2 is done; one hook on Class.forName |
 * | 5 native     | the language   | the JNI boundary, libc, crypto libs | frida-trace the boundary before touching Ghidra |
 *
 * READ THAT TABLE DOWNWARD. Each layer removes exactly one kind of
 * information, and none of them removes the one below it. That is why the
 * methodology in section 6.1 is ordered the way it is: restore the cheapest,
 * highest-yield category first (strings), and each subsequent layer becomes
 * smaller, because you now know which parts of it you actually need.
 *
 * READ IT ACROSS and you get the developer conversation: each row is real
 * engineering effort, real build complexity, real ongoing cost in crash
 * reports and profiling — bought against a recovery cost measured in hours.
 * That is a legitimate purchase against casual and automated attackers, and it
 * is not a boundary. Price it honestly and spend the next unit of budget on
 * something that is.
 * ===========================================================================
 */
