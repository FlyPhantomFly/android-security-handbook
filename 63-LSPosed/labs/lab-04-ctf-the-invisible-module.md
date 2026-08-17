# Lab 04 — CTF: The Invisible Module

> **Difficulty:** CTF
> **Time:** 3–5 hours
> **Needs LSPosed installed?** **Partially.** Bronze and Silver are reachable with static analysis
> and a host-only toolchain. Gold needs a rooted device with Zygisk and LSPosed. Platinum needs
> neither, which is the point of Platinum.
> **Prerequisites:** [Lab 02](lab-02-your-first-module.md) and [Lab 03](lab-03-scope-timing-and-failure.md).

---

## The scenario

You have been given a build of `com.pentest.ch63.strongvault`, an application that is authorised for
testing. It holds a secret behind a gate, and its authors have read the same detection blog posts
everybody else has — plus two things they worked out themselves.

The application defends itself **four ways**:

| # | Defence | What it catches |
|---|---|---|
| **D1** | Asks whether `de.robv.android.xposed.XposedBridge` is resolvable in this process | Any framework loaded into this process |
| **D2** | Throws and inspects its own stack for a dispatcher frame | Any hook on the method that does the throwing |
| **D3** | Walks its own class-loader chain and counts loaders backed by an APK that is not its own | Any foreign DEX loaded into this process |
| **D4** | Caches nothing, decides late, and reads its expected value only inside a method it also protects | A pre-filled static, and a hook on the obvious producer |

Each defence is individually well known and individually defeatable. **Exactly one approach walks
past all four at once**, and finding it is the Gold objective.

Then there is Platinum, which is the objective a report is written about.

---

## Scoring

| Grade | What you achieved | Why it is worth what it is worth |
|---|---|---|
| **Bronze** | You enumerated all four defences statically and can name the exact class, method and mechanism of each | You cannot beat a control you have not read |
| **Silver** | You defeated D1, D2 and D3 individually — each with its own hook — and can explain why each fix is fragile | The obvious answer, and it teaches why the obvious answer is expensive |
| **Gold** | You reached the flag with **one** intervention that none of the four defences observes | The insight the CTF is built around |
| **Platinum** | You reproduced the result on a device with **no module enabled and no instrumentation of any kind**, and wrote the finding as a sentence about the application | This is what goes in the report |

Platinum is the highest grade for the same reason [65-Hooking Lab 04](../../65-Hooking/labs/lab-04-ctf-the-honest-trampoline.md)
reserves Gold for the solution that learns the secret and then does not need the hook: **a finding
that only reproduces under instrumentation is weaker than one that does not.**

---

## Building the target

The CTF app is small enough to type. Create a project with package
`com.pentest.ch63.strongvault`, minimum SDK 27, and these files.

### `Sentinel.java` — the four defences

```java
package com.pentest.ch63.strongvault;

import android.util.Log;

public final class Sentinel {

    private static final String TAG = "Sentinel";

    // ---------------- D1: is the API resolvable in this process? -----------
    static boolean frameworkClassPresent(ClassLoader cl) {
        for (String c : new String[]{
                "de.robv.android.xposed.XposedBridge",
                "de.robv.android.xposed.XposedHelpers",
                "io.github.libxposed.api.XposedInterface"}) {
            try {
                Class.forName(c, false, cl);
                Log.w(TAG, "D1 hit: " + c);
                return true;
            } catch (ClassNotFoundException expected) {
                // clean
            }
        }
        return false;
    }

    // ---------------- D2: is a dispatcher on our own stack? ----------------
    static boolean dispatcherOnStack() {
        StackTraceElement[] st = new Throwable().getStackTrace();
        for (StackTraceElement e : st) {
            String c = e.getClassName();
            if (c.startsWith("de.robv.android.xposed")
                    || c.contains("lsposed") || c.contains("LSPHooker")
                    || c.contains("EdHooker")) {
                Log.w(TAG, "D2 hit: " + c + "." + e.getMethodName());
                return true;
            }
        }
        return false;
    }

    // ---------------- D3: foreign class loaders ----------------------------
    static boolean foreignLoader(ClassLoader cl, String ownApkPath) {
        int guard = 0;
        while (cl != null && guard++ < 32) {
            String s = String.valueOf(cl);
            if (s.contains(".apk") && ownApkPath != null && !s.contains(ownApkPath)) {
                Log.w(TAG, "D3 hit: " + s);
                return true;
            }
            cl = cl.getParent();
        }
        return false;
    }

    /** All three, in one call. Deliberately NOT cached. */
    static boolean instrumented(ClassLoader cl, String ownApk) {
        return frameworkClassPresent(cl) || dispatcherOnStack() || foreignLoader(cl, ownApk);
    }
}
```

### `StrongGate.java` — D4, and the flag

```java
package com.pentest.ch63.strongvault;

import android.util.Log;

public final class StrongGate {

    private static final String TAG = "StrongGate";

    private final ClassLoader mLoader;
    private final String mOwnApk;

    public StrongGate(ClassLoader loader, String ownApk) {
        this.mLoader = loader;
        this.mOwnApk = ownApk;
    }

    /**
     * D4.  Nothing is cached.  The posture check runs on EVERY call, and it runs
     * INSIDE the same method that does the comparison, so a hook on a separate
     * "isDeviceOk()" producer has nothing to attach to.
     */
    public String open(String token) {
        if (Sentinel.instrumented(mLoader, mOwnApk)) {
            Log.w(TAG, "refusing: instrumented");
            return null;
        }
        if (!constantTimeEquals(token, expected())) {
            Log.i(TAG, "refusing: token");
            return null;
        }
        return flag(token);
    }

    /** The expected token, assembled at call time from parts. */
    private String expected() {
        int[] a = {0x37, 0x3E, 0x2F, 0x28, 0x76, 0x32, 0x35, 0x76, 0x28, 0x32, 0x3F, 0x3E};
        StringBuilder sb = new StringBuilder(a.length);
        for (int v : a) {
            sb.append((char) (v ^ 0x5B));
        }
        return sb.toString();
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }

    /** The flag is DERIVED from the token, so a forced return value gives you
     *  a null, not a flag. */
    private String flag(String token) {
        int h = 0;
        for (int i = 0; i < token.length(); i++) h = h * 31 + token.charAt(i);
        return "CH63{" + Integer.toHexString(h) + "_" + token.replace('-', '_') + "}";
    }
}
```

### `MainActivity.java`

```java
package com.pentest.ch63.strongvault;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 96, 48, 48);

        final EditText box = new EditText(this);
        box.setHint("token");
        root.addView(box, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        final TextView out = new TextView(this);
        out.setText("locked");

        final StrongGate gate = new StrongGate(
                getClassLoader(), getApplicationInfo().sourceDir);

        Button go = new Button(this);
        go.setText("Open");
        go.setOnClickListener(v -> {
            String f = gate.open(box.getText().toString());
            out.setText(f == null ? "denied" : f);
            Log.i("StrongVault", "open -> " + f);
        });

        root.addView(go);
        root.addView(out);
        setContentView(root);
    }
}
```

Build, install, and confirm the baseline: any token gives `denied`, and the log shows which defence
fired.

---

## Bronze — enumerate the defences

Do this **statically**, before touching a device.

```bash
# host
jadx -d out app-debug.apk
grep -rn "Class.forName\|getStackTrace\|getParent\|sourceDir" out/sources/
```

**Task B.1.** Fill in this table from the decompiled source. Do not guess.

| Defence | Class | Method | Exactly what it observes | What defeats it |
|---|---|---|---|---|
| D1 | | | | |
| D2 | | | | |
| D3 | | | | |
| D4 | | | | |

**Task B.2.** Answer three questions that decide your whole approach:

1. Is the posture result **cached** anywhere? (Compare with the Lab 02 target.)
2. Is there a separate `isDeviceOk()` producer method to hook? If not, why does that matter?
3. Is the flag a **constant**, or is it **derived from the token**? What does that do to a
   `setResult`-based bypass?

**Task B.3.** Decode `expected()` by hand. Show your working.

```bash
python3 -B -c "
a=[0x37,0x3E,0x2F,0x28,0x76,0x32,0x35,0x76,0x28,0x32,0x3F,0x3E]
print(''.join(chr(v^0x5B) for v in a))"
```

**Bronze is complete** when your table is filled in and you can say, in one sentence each, why D1–D3
are individually weak and why D4 is the one that makes this CTF interesting.

---

## Silver — beat D1, D2 and D3 the obvious way

Write a module that defeats each defence with its own hook.

**D1** — make the lookup fail:

```java
XposedBridge.hookAllMethods(ClassLoader.class, "loadClass", new XC_MethodHook() {
    @Override protected void beforeHookedMethod(MethodHookParam p) {
        String n = String.valueOf(p.args[0]);
        if (n.startsWith("de.robv.android.xposed") || n.startsWith("io.github.libxposed")) {
            p.setThrowable(new ClassNotFoundException(n));
        }
    }
});
```

**Task S.1.** That hooks `loadClass`. D1 calls `Class.forName(c, false, cl)`. Does `Class.forName`
reach `loadClass`? Verify rather than assuming — hook both and log.

**Task S.2.** Your own module is *also* loaded through a `ClassLoader`. What happens if your filter
runs before your own module has finished loading? Order matters; say why.

**D2** — filter the stack:

```java
XposedHelpers.findAndHookMethod(Throwable.class, "getStackTrace", new XC_MethodHook() {
    @Override protected void afterHookedMethod(MethodHookParam p) {
        StackTraceElement[] in = (StackTraceElement[]) p.getResult();
        if (in == null) return;
        java.util.List<StackTraceElement> out = new java.util.ArrayList<>(in.length);
        for (StackTraceElement e : in) {
            String c = e.getClassName();
            if (c.startsWith("de.robv.android.xposed") || c.contains("lsposed")
                    || c.contains("LSPHooker")) continue;
            out.add(e);
        }
        p.setResult(out.toArray(new StackTraceElement[0]));
    }
});
```

**Task S.3.** This is a **process-wide** hook on a `java.lang` method that everything uses — every
crash reporter, every logging framework, every library's error path. Name two things it will break
and one way an application could notice it.

**D3** — lie about the loader chain:

```java
XposedHelpers.findAndHookMethod(ClassLoader.class, "getParent", new XC_MethodHook() {
    @Override protected void afterHookedMethod(MethodHookParam p) {
        Object parent = p.getResult();
        if (parent != null && String.valueOf(parent).contains("ch63.module")) {
            p.setResult(((ClassLoader) parent).getParent());   // skip ourselves
        }
    }
});
```

**Task S.4.** Install all three, force-stop, and try the app. Does it now say `denied` for the wrong
reason, or does it accept a token?

**Task S.5 — the honest accounting.** You have now installed **three process-wide hooks on
`java.lang` classes** to defeat three checks. Write down:

- How many methods in the process are affected.
- What happens if the application adds a fourth check tomorrow.
- What happens if any of the three hooks has a bug.

**Silver is complete** when the three hooks work *and* you have written that accounting. The
accounting is the deliverable; the hooks are the easy part.

> **🧠 Mental Model.** Silver is the arms race, and the arms race is
> [67-BypassingProtections](../../67-BypassingProtections/README.md)'s subject. It works, it is
> expensive, it is brittle, and it scales linearly with the defender's effort. Gold is what you reach
> for when you notice that.

---

## Gold — one intervention, four defences

Re-read D1, D2 and D3 and ask what they have in common.

<details>
<summary>Hint 1 — click only after twenty minutes</summary>

All three observe **the process**. `Class.forName` in this process. The stack of a `Throwable`
created in this process. The class loaders of this process.

What does that tell you about *where* the observation happens, and therefore what an intervention
somewhere else would look like to them?

</details>

<details>
<summary>Hint 2</summary>

D4's contribution is that there is no cached boolean to pre-fill and no separate producer method to
hook. `Sentinel.instrumented(...)` is called from inside `open()` on every call.

So: what does `open()` actually need in order to return the flag? Look at `flag(token)` again. Is the
flag a secret the *application* holds, or a value the application *computes*?

</details>

<details>
<summary>Hint 3 — the shape of the answer</summary>

Every defence answers the question *"is something instrumenting me?"* None of them answers *"is the
token correct?"* — because that is not a security question to them.

The token is decoded, on your host, from `expected()`. You already did it in Bronze.

</details>

**Task G.1.** Reach the flag.

**Task G.2.** Write down exactly which of D1–D4 observed your intervention. Then write down why.

**Task G.3.** The flag is derived from the token by `flag(String token)`. Explain why a
`setResult(Boolean.TRUE)`-style bypass on any method here gives you nothing, and why that design
choice by the CTF's authors is a fair model of a real application that derives a session key from a
credential rather than gating on a boolean.

---

## Platinum — the report

**Task P.1.** Reproduce the result on a device with:

- no LSPosed module enabled,
- no Frida,
- no debugger,
- nothing at all.

**Task P.2.** Write the finding. It should be a sentence about the *application*, not about your
toolkit. Compare these two:

> ~~"The application's Xposed detection can be bypassed with three hooks on `java.lang` classes."~~

> "The application's unlock token is a constant embedded in `StrongGate.expected()`, obfuscated with
> a single-byte XOR. It is recoverable by static analysis in under two minutes with no device access,
> no root and no instrumentation, and it is identical in every installation. The instrumentation
> detection in `Sentinel` is irrelevant to this: it answers a question about the runtime environment
> and the defect is in the artefact."

**Task P.3.** Rate it honestly, and justify the rating in one sentence.

<details>
<summary>Model answer for P.3</summary>

**Severity depends entirely on what the token gates, and the CTF does not tell you** — which is the
point of the exercise.

- If the token unlocks a local UI on the user's own device, it is **Low to Informational**: a user
  who extracts a secret from their own copy of an app has attacked themselves.
- If the same token is accepted by a server as proof of anything, it is **High or Critical**, because
  it is a shared secret embedded in every installation, recoverable offline, and its compromise is
  permanent and affects every user at once.

The right sentence in a report names that dependency explicitly rather than picking a number:
*"Severity is Low if the token is purely local and High if any server-side action trusts it; the
application's design does not make this distinguishable from the client, which is itself worth
raising."*

This is the same judgement [65-Hooking §5.4](../../65-Hooking/README.md) makes about a hard-coded
HMAC key: **rate the scalability, not the possibility.** A secret is gone forever for every user; a
capability is bounded to a device the attacker already owns.

</details>

**Task P.4.** Write the remediation as code. Not "obfuscate the token better".

<details>
<summary>Model answer for P.4</summary>

```java
// The client cannot hold a secret. So do not make it hold one.
public final class StrongGate {

    // 1. No embedded constant. The token is not compared on the client at all.
    // 2. The server issues the nonce, so a captured request cannot be replayed.
    // 3. The response is what the client needed, not a boolean it can flip:
    //    there is no "return true" that yields the protected value.
    public void open(String userToken, Callback cb) {
        String nonce = Api.getNonce();                    // server-issued
        Api.post("https://vault.example.invalid/open",
                 new OpenRequest(nonce, userToken,
                                 PlayIntegrity.token(nonce)),   // TEE-signed
                 cb);                                     // server returns the secret, or does not
    }
}
```

The structural change is point 3. In the vulnerable version the protected value exists on the client
and a check decides whether to reveal it. In the fixed version **the client never has the value
until the server sends it**, so there is no in-process decision to subvert — which is the only form
of client-side protection that survives an attacker with code execution in the process.

Note what the fix does **not** claim: it does not stop an attacker with a module from reading the
secret *after* the server sends it. Nothing can. What it changes is that the attack now requires a
live, authenticated, instrumented session per target rather than a static extraction that works for
everyone forever.

</details>

---

## Instructor notes

<details>
<summary>Spoilers — do not open until you have graded yourself</summary>

**Gold's intended solution: type the token in.**

D1, D2, D3 and D4 all answer *"is this process instrumented?"*. None of them answers *"is the person
typing the token supposed to know it?"*. The token is a constant, XOR-encoded in `expected()`, and it
is recovered by reading the decompiled source — which happens on your laptop, in a process the
application cannot observe at all.

`expected()` decodes to **`lets-in-side`**, and the flag it derives is
**`CH63{fc99adea_lets_in_side}`** — verified by evaluating the same `h * 31 + charAt(i)` accumulation
with 32-bit wraparound, which is `String.hashCode`'s algorithm applied to a token of 12 characters.

There is no module. There is no hook. All four defences run, all four return `false`, and
`constantTimeEquals` returns `true`.

**Why this is the right lesson and not a trick.** Every one of the four defences is a real,
correctly-implemented control that costs the defender real effort, and each one is *individually*
better than what most applications ship. They are all aimed at the runtime environment. The defect is
in the artefact, and no amount of runtime defence reaches it. That is the same asymmetry
[65-Hooking](../../65-Hooking/README.md)'s CTF encodes in its flag name
`got_slot_beats_text_checksum`: **a defence that guards one representation of the program is blind to
a change in another.**

**Why Silver exists.** Because the arms race is the natural first instinct, it *does* work, and
walking it far enough to write the accounting in Task S.5 is what makes the Gold insight land. A
student handed Gold directly learns a trick; a student who spends an hour on three fragile
`java.lang` hooks and then finds Gold learns a principle.

**Why the flag is derived from the token.** So that no `setResult` gives it up. A student who hooks
`open()` and forces a return gets to choose the return value, and the return value they can choose
is not the flag. This models a real application deriving a session key from a credential rather than
gating on a boolean, which is a materially better design and is worth pointing out as the one thing
the CTF app does *right*.

**Common wrong turns, and what to say:**

| Wrong turn | Response |
|---|---|
| "I hooked `Sentinel.instrumented` to return false" | Good — that is a legitimate Silver-grade path and it works. Now note that it is a hook, and ask what D2 would have seen if `open()` had thrown its own `Throwable` after calling it |
| "I hooked `expected()` and read the return value" | Also legitimate, and faster than decoding by hand. But now ask: did you need the device at all? |
| "I patched the APK" | Different chapter — [18-ARM §5](../../18-ARM/README.md) and [10-APK-Internals](../../10-APK-Internals/README.md). It works and it invalidates the signature, which is exactly the trade this chapter's §1.2 describes |
| "The defences are unrealistic" | They are the four best in-process checks in chapter §5.5's "what does work" list. They are more than most shipping applications have |

**Grade distribution to expect** with a class that has done Labs 01–03: nearly all reach Bronze,
most reach Silver, roughly half find Gold unaided within the time, and the ones who reach Platinum
are the ones who will write good reports.

</details>

---

## Success criteria

- [ ] **Bronze:** the four-row table is filled in from the decompiled source, not from this document.
- [ ] **Silver:** three hooks, working, plus the honest accounting of what they cost.
- [ ] **Gold:** the flag, and a written explanation of why none of the four defences saw you.
- [ ] **Platinum:** the same result on a clean device, a finding written about the application, an
      honest severity with its dependency named, and a remediation as code.
- [ ] You removed the module and the app, and verified the scope table no longer names it.

---

## Cleanup

```bash
# host
adb uninstall com.pentest.ch63.strongvault
adb uninstall com.pentest.ch63.module
adb shell 'su 0 ls /data/adb/modules'     # unchanged from before you started
```

Disable and remove the module in the manager, and confirm. **A module left enabled on somebody's
device is a finding against you**, and the scope table is where an incident responder will find it.

---

| | |
|---|---|
| **Chapter** | [63-LSPosed](../README.md) — §5.5 detection, §5.3 severity, §7.9 tool choice |
| **See also** | [65-Hooking Lab 04](../../65-Hooking/labs/lab-04-ctf-the-honest-trampoline.md) — the native CTF this one rhymes with · [67-BypassingProtections](../../67-BypassingProtections/README.md) — owns the arms race Silver walks into |
