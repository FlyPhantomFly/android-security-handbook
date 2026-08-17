# Lab 04 — CTF: the app that works fine, and then does not

**Difficulty:** CTF
**Time:** 2–4 hours
**Chapter:** [38 — Tamper Detection](../README.md) · §3.12, §3.14, §5.6, §6.6, §7.7

---

## The brief

You are handed an APK called `vault-challenge.apk`. It installs. It launches. It shows a screen that
says *"Opening…"*, waits about six seconds, and then prints forty-two bytes of garbage.

It does not crash. It does not show an error. It does not log a warning. There is no string anywhere
in the application containing the words *tamper*, *integrity*, *signature*, *root*, *debug* or
*blocked*. `logcat` shows nothing except the garbage itself.

**Recover the flag.** It has the form `CH38{...}`.

---

## Rules

- The only application you may attack is this one, which you build yourself from the sources in
  [`ctf-app/`](ctf-app/).
- **Do not read [`ctf-app/Guard.java`](ctf-app/Guard.java) until you are done.** It is the answer key
  in source form. Reading it first turns a genuine exercise into a five-minute skim, and the whole
  point of this lab is the *experience* of having nothing to go on.
- `build-ctf.sh --solution` builds a working version. That is a self-check, not a solution. Using it
  first is the same mistake with extra steps.
- Root is **not** required. There are at least three routes to the flag and one of them is entirely
  offline.

---

## Setup

```bash
# host
cd 38-TamperDetection/labs/ctf-app
OUTDIR=/tmp/ch38ctf ./build-ctf.sh --install

adb shell am start -n com.pentest.ch38.ctf/.VaultActivity
adb logcat -s CH38CTF:V
```

Measured on the reference device (i9000S, Android 13 / API 33, unrooted), after the six-second wait:

```
I CH38CTF : vault=,(?V??'?~??eC+? #?????Z"?q?b???
I CH38CTF : raw=042c1928e7a456d2bc27cf7eebf67f65432bcb200b238bb27f99fceabd5a229271c26284a812ae3f3f0c
```

Forty-two bytes. No message. Nothing else in the log.

> **⚠️ Note on the build.** `build-ctf.sh` generates two throwaway keys and signs the challenge APK
> with the *distributor* one. In a real engagement you would be handed a repackaged APK and would
> have neither key; here you generate both so that the challenge is verifiable. **Do not look at the
> keystores.** That is not the intended route and it teaches nothing.

---

## Progressive hints

Work as far as you can before opening each. The difficulty is deliberate and the frustration is part
of the lesson: this is what a decoupled, silent integrity design *feels like* from the attacking side,
and §3.14 argues it is the most effective cheap measure a defender has for exactly this reason.

<details>
<summary>Hint 1 — where do you even start?</summary>

You have exactly one artefact: forty-two bytes that should have been something and were not.

Ask the question that opens every problem of this shape: **is the output wrong, or is the input to
the output wrong?**

The app printed *something*. It did not fail to print. That means the code path completed
successfully and produced a value it was perfectly happy with. Whatever went wrong happened
**upstream**, and long enough ago that nothing near the printing knows about it.

Start with the static map:

```bash
# host
python3 -B ../../scripts/tamper-surface-map.py /tmp/ch38ctf/vault-challenge.apk
```

Then decompile and look for the code that produced those bytes:

```bash
# host
jadx -d /tmp/ch38ctf/j /tmp/ch38ctf/vault-challenge.apk
ls /tmp/ch38ctf/j/sources/com/pentest/ch38/ctf/
```
</details>

<details>
<summary>Hint 2 — you found a promising method and patching it did nothing</summary>

You almost certainly found something called `isDeviceCompromised`. It has an obvious name, an obvious
`FLAG_DEBUGGABLE` test, an obvious `/system/bin/su` check, and an obvious boolean return.

Now search for its callers.

```bash
# host
grep -rn "isDeviceCompromised" /tmp/ch38ctf/j/sources/
```

**It has none.** It is dead code, put there on purpose.

This is not a cheap trick played on you. It is the most common real-world experience in this area,
and [18-ARM](../../18-ARM/README.md) records the same lesson from a measurement: a check function was
patched to `return 1`, verified as returning 1, and the protected routine still refused — because the
compiler had inlined the real check and the patched copy was called by nobody.

**Before you patch anything, cross-reference it.** If nothing calls it, it is not the check.
</details>

<details>
<summary>Hint 3 — where is the real check, and when does it run?</summary>

Look at the manifest.

```bash
# host
aapt2 dump xmltree --file AndroidManifest.xml /tmp/ch38ctf/vault-challenge.apk | grep -A6 provider
```

There is a `ContentProvider` that is not exported, has no exported functionality, and returns `null`
from every method.

**Why would anyone ship a provider that provides nothing?**

Because `ContentProvider.onCreate()` is called by `ActivityThread` **before**
`Application.onCreate()`. It is the earliest Java-tier entry point an app can reach without writing
native code, and it is exactly how several analytics and anti-fraud SDKs bootstrap without asking the
host app to change a line. See §3.12 and [27-ContentProviders](../../27-ContentProviders/README.md).

By the time you see a screen, whatever that provider did is long finished.
</details>

<details>
<summary>Hint 4 — there is no boolean to flip</summary>

Read the class the provider calls. You will find four checks and a `sweep()` method — and then you
will look for the `if` that acts on them, and there is not one.

```java
static void sweep(Context ctx) {
    long s = 0L;
    if (certOk(ctx))   s ^= C_SIG;
    if (notDebug(ctx)) s ^= C_DBG;
    if (noTracer())    s ^= C_TRC;
    if (mapsOk())      s ^= C_MAP;
    STATE.set(s);
}
```

Each check contributes a 64-bit constant **when it passes** and contributes nothing when it fails.
The result is not compared to anything. It is used.

```java
static byte[] vaultKey() {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(SALT);
    long s = STATE.get();
    for (int i = 0; i < 8; i++) md.update((byte)((s >>> (8*i)) & 0xff));
    return md.digest();
}
```

**There is no branch to invert, because there is no branch.** A failed check produces a different
key, a different key produces different bytes, and nothing in the app ever notices. This is §5.6's
"do not produce a boolean" design, and you are on the receiving end of it.

Which means your problem has changed shape entirely. You no longer need to *defeat* a check. You
need to work out **which check failed**, and then either make it pass or reconstruct the value it
would have contributed.
</details>

<details>
<summary>Hint 5 — which check failed?</summary>

Four checks. Reason about each on the device you are running on:

| Check | Would it pass here? |
|---|---|
| `notDebug` | The manifest has no `android:debuggable`, so `FLAG_DEBUGGABLE` is clear → **passes** |
| `noTracer` | Nothing is ptracing you → **passes** |
| `mapsOk` | A real app process has thousands of mappings; the check wants more than 50 → **passes** |
| `certOk` | Compares the running certificate against `ExpectedCert.SHA256`… | |

Confirm rather than assume:

```bash
# host
apksigner verify -v --print-certs /tmp/ch38ctf/vault-challenge.apk | grep 'certificate SHA-256'
```

Then find the constant the app expects, in the decompiled source. **They do not match.**

You are running a build signed by somebody other than the party the app expects. That is exactly the
scenario §1.2 calls threat T‑A, and the app detected it perfectly — it simply never said so.

So the state word is `HEALTHY ^ C_SIG` instead of `HEALTHY`, and every byte downstream is wrong.
</details>

<details>
<summary>Hint 6 — three ways to finish, pick one</summary>

**Route A — offline, no device, no root.** You have everything you need: the four constants, the
salt, and the key derivation, all readable in jadx. Compute what the state word *should* be
(all four checks passing), derive the key, and XOR it against the ciphertext yourself. Twelve lines
of Python.

**Route B — make the check pass.** Sign the APK with a key whose certificate hashes to
`ExpectedCert.SHA256`. You cannot construct such a key… but `build-ctf.sh` generated one, and this is
the only place in the lab where looking at it is legitimate — it is the *reference* build, and it is
what `--solution` does. This route teaches the least.

**Route C — at runtime.** Patch `certOk` to return `true` and re-sign. Now think carefully about what
you just did, because there is a trap: re-signing changes the certificate *again*, but you patched
the only thing that looks at it, so it no longer matters. Alternatively, with root and Frida, hook
`Guard.certOk` to return `true` — but note the timing constraint: `sweep()` runs in
`ContentProvider.onCreate`, so you must be attached **before** that. Spawn with `-f`; attaching later
is far too late.

Route A is the one worth doing, because it is the one that proves you understood the design rather
than just poked at it.
</details>

---

## Route A, in full — the offline solve

This is the intended solution. It uses no device and no root.

### Step 1 — extract the ingredients

```bash
# host
jadx -d /tmp/ch38ctf/j /tmp/ch38ctf/vault-challenge.apk
grep -rn "0x9E3779B97F4A7C15\|C_SIG\|SALT\|VAULT" /tmp/ch38ctf/j/sources/com/pentest/ch38/ctf/
```

You need four things:

| | |
|---|---|
| The four per-check constants | in `Guard` |
| The salt bytes | `"ch38-vault-v1"` |
| The ciphertext | the 42-byte array in `VaultActivity` |
| The keystream construction | `SHA-256(key ‖ counter)`, concatenated |

### Step 2 — reconstruct the healthy state word

Every check contributes when it passes, so a healthy device produces the XOR of all four constants.

### Step 3 — derive and decrypt

```python
#!/usr/bin/env python3
# solve.py  --  run with: python3 -B solve.py
import hashlib

C = [0x9E3779B97F4A7C15,
     0xC2B2AE3D27D4EB4F,
     0x165667B19E3779F9,
     0x27D4EB2F165667C5]

healthy = 0
for c in C:
    healthy ^= c                      # every check passes

SALT = b"ch38-vault-v1"
key = hashlib.sha256(SALT + healthy.to_bytes(8, "little")).digest()

def keystream(key, n):
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(key + bytes([ctr])).digest()
        ctr += 1
    return out[:n]

ct = bytes.fromhex(
    "9a47e0221bd212fcbd7186b60b73cd5d2264ffea7f8da4fdf2acc8805e3f47f7"
    "ffb4cfd39e03bc966a3f")

print(bytes(a ^ b for a, b in zip(ct, keystream(key, len(ct)))).decode())
```

Two details that will cost you an hour if you get them wrong, and both are visible in the decompiled
code if you read carefully:

- The state word is fed in **little-endian** — `(s >>> (8*i)) & 0xff` for `i` in `0..7`.
- The salt goes in **first**, before the state bytes.

### Step 4 — check your answer

```bash
# host
OUTDIR=/tmp/ch38ctf ./build-ctf.sh --solution
adb uninstall com.pentest.ch38.ctf
adb install -r /tmp/ch38ctf/vault-solution.apk
adb logcat -c
adb shell am start -n com.pentest.ch38.ctf/.VaultActivity
sleep 9
adb logcat -d -s CH38CTF:V
```

Measured:

```
I CH38CTF : vault=CH38{s1gn4tur3_g4t3_w1th_n0_3rr0r_m3ss4g3}
I CH38CTF : raw=434833387b7331676e34747572335f673474335f773174685f6e305f33727230725f6d3373733467337d
```

<details>
<summary>The flag</summary>

```
CH38{s1gn4tur3_g4t3_w1th_n0_3rr0r_m3ss4g3}
```
</details>

---

## Post-mortem questions

Answer these **after** you have the flag. They are the reason the lab exists.

### Q1. You never had to defeat a check. Why not?

<details>
<summary>Answer</summary>

Because the design has no *decision* to defeat. The four checks are not gates; they are **inputs to a
key derivation**. There is no `if (tampered)` to invert and no boolean to return.

That converts the attacker's task from "find and flip one branch" — minutes — into "understand the
whole derivation and reconstruct a value" — considerably longer. It also means the classic bypass
reflexes (patch the branch, hook the method, delete the call site) all fail, because none of them
targets anything that exists.

The honest limit, which §5.6 states explicitly: this defeats **branch-flipping**, not
**input-spoofing**. An attacker who hooks `Signature.toByteArray` to return the original certificate
makes `certOk` genuinely pass, gets the healthy state word, and gets the right key. It is a real
improvement and it is not a solution.
</details>

### Q2. The dead `isDeviceCompromised` cost you time. Is that fair?

<details>
<summary>Answer</summary>

It is *representative*, which is a better standard than fair.

Real apps are full of dead code: features removed but not deleted, SDK code R8 did not shake out,
abandoned experiments. A method with a promising name and no callers is the normal case, not a trap
laid for you.

The habit the lab is trying to build is one line long: **cross-reference before you patch.** If
nothing calls it, it is not the check. [18-ARM](../../18-ARM/README.md)'s measured case — a patch that
provably works against a function that provably no longer matters — is the same lesson from the
native side, and it is described there as the most useful teaching artefact in that chapter.
</details>

### Q3. The consequence was six seconds after the detection, in a different class, in a different
lifecycle phase. Should a real app do this?

<details>
<summary>Answer</summary>

It is genuinely effective against an attacker and genuinely harmful to users, and any honest answer
has to hold both.

**For:** it destroys the feedback loop. An attacker who changes something and immediately sees the
app behave differently converges fast. An attacker who has to wait six seconds and then reason about
whether the output changed for the reason they think — converges slowly. §3.14 rates this as one of
the most effective cheap measures available.

**Against:** the same property that stops an attacker correlating cause and effect stops **you**
correlating them. When this misfires on an honest user — an OEM that reports a surprising flag, a
device where a `/proc` read fails — that user gets an unexplained failure minutes after the real
cause, and your support team gets a ticket nobody can reproduce. You will be debugging blind.

The practical resolution: ship the delayed consequence **and** ship telemetry that records the verdict
at the moment it is decided. Then production behaves opaquely to the attacker and transparently to
you. That is §5.8's R5, and it is the item people skip.
</details>

### Q4. This whole design still fails against a determined attacker. Where?

<details>
<summary>Answer</summary>

Several places, and it is worth being precise rather than gesturing:

1. **Input spoofing.** Hook `Signature.toByteArray` at spawn time, before the provider runs. Every
   check genuinely passes. The state word is correct. Q1's limit.
2. **Static reconstruction** — which is what you just did. The constants, the salt and the derivation
   are all in `classes.dex`. Obfuscation and string encryption raise the cost of reading them; they do
   not remove them.
3. **Lifting the key.** Hook `Guard.vaultKey()` on a healthy build and record the 32 bytes. Now you
   have the key forever, on any device, no checks required.
4. **The vault is local.** Everything needed to produce the flag ships in the APK. No amount of
   client-side cleverness changes that, because the secret is *there*.

Point 4 is the one that matters and it is the chapter's thesis. If the vault contents came from a
server, and the server released them only against a verified attestation bound to a server-issued
nonce, then none of routes A, B or C would work — not because the client got better, but because the
secret was never on the client.
</details>

### Q5. Write the finding.

Suppose this were a real application in a real engagement. Write the report entry, following §5.3.

<details>
<summary>A model answer</summary>

**Client-side integrity gate (Informational — methodology).**

*The application performs four client-side integrity checks in `ContentProvider.onCreate`, before
`Application.onCreate`. Rather than branching on the results, it folds them into a 64-bit state word
used as key material for local content decryption, so a failed check produces incorrect output with
no error path. This is a well-constructed client-side design: there is no single boolean and no
branch to invert, and the consequence is separated from the detection by six seconds and by several
classes.*

*It was nonetheless defeated in under two hours by reconstructing the derivation offline from
`classes.dex`, which contains the per-check constants, the salt and the key-derivation routine. No
device access and no root were required.*

*This is recorded as methodology rather than as a vulnerability. The finding it enables is that **the
protected content is present in the client**: any client-side protection of a locally stored secret
can be reduced to reading the secret. Recommend that content of this sensitivity be released by the
server against a verified device-integrity attestation bound to a server-issued nonce, rather than
gated locally.*

**What makes this a good entry:** it does not call the control "weak" (it is not — it is unusually
well built), it states the cost, it separates methodology from finding, and its recommendation
addresses the actual problem rather than proposing a fifth check.
</details>

---

## Extension challenges

### E1 — Close route A

Make the offline reconstruction meaningfully harder without changing the architecture. Ideas: derive
the constants from device state rather than compiling them in; encrypt the string constants; move
`vaultKey()` into a native library.

**Then measure how much you actually bought.** Time yourself solving your own version. If it is under
an hour, say so honestly — that number is more valuable than the hardening.

### E2 — Close route C

Make hooking `Guard.certOk` insufficient. The cleanest approach is to remove the boolean from that
layer too: have `certOk` return the *constant* rather than a boolean, computed from the certificate
bytes so that a hook returning a fixed value produces a wrong contribution.

**Question:** what does an attacker do next, and how long does it take them?

### E3 — Do it properly

Rewrite the vault so the contents come from a server, released against an attested request, following
[`../examples/ServerVerifiedIntegrity.java`](../examples/ServerVerifiedIntegrity.java). A toy HTTP
server in twenty lines of Python is enough.

Then attack your own design and find out which of the three anti-patterns you accidentally
implemented. Most people implement at least one on the first attempt — the client-generated nonce is
the usual one, because nothing in any SDK documentation shouts at you about it.

### E4 — Turn the tables

Write the Frida script that would have solved this in five minutes if you had had root, and make it
*report* rather than bypass — in the style of
[`../scripts/which-check-fired.js`](../scripts/which-check-fired.js). It should print which of the
four checks contributed, and the resulting state word, without changing any of them.

Then ask yourself why that script would have been more useful than a bypass, and you will have
internalised §7.1.

---

## Success criteria

- [ ] You recovered the flag.
- [ ] You can name which of the four checks failed, and prove it from `apksigner` output rather than
      by guessing.
- [ ] You can explain why there was no boolean to flip.
- [ ] You noticed the dead decoy and can say how you should have noticed it faster.
- [ ] You can explain why the check ran before `Application.onCreate`.
- [ ] You can argue both sides of the delayed-consequence design.
- [ ] You wrote a finding that separates methodology from vulnerability.
- [ ] You can name the four ways this design still fails, and which one is fundamental.

---

## Clean up

```bash
# host
adb uninstall com.pentest.ch38.ctf
rm -rf /tmp/ch38ctf
cd 38-TamperDetection && find . \( -name "*.apk" -o -name "*.ks" -o -name "*.dex" -o -name "*.class" -o -name "__pycache__" \) -print
```

Nothing should print from that last command. And note that `/tmp/ch38ctf` held **two private keys** —
worthless throwaway keys for a lab app, but the habit of deleting them is worth building.

---

## What to take away

1. **The hardest client-side design to attack is the one with no decision in it.** No boolean, no
   branch, verdicts folded into a derived value. It cost you hours instead of minutes.
2. **It still lost**, because the secret was on the client. That is not a flaw in the design; it is
   the ceiling on the whole category.
3. **Cross-reference before you patch.** The decoy cost you time and it was representative, not
   unfair.
4. **`ContentProvider.onCreate` runs before `Application.onCreate`.** Remember it; it is where early
   checks hide, and it is where you must already be attached.
5. **Delayed, silent consequences work — on you and on the developer's own support team.** Ship them
   with telemetry or do not ship them.
6. **The route that taught you the most needed no device and no root.** Reading and reconstructing
   beats hooking more often than the tooling-first instinct suggests.

---

## Where next

- [37-RootDetection](../../37-RootDetection/README.md) — the environment half, and its own CTF built on
  a decoupled check. Doing both back to back is worthwhile: the designs rhyme.
- Chapter 67, *Bypassing Protections* — the general methodology and the adversarial back-and-forth.
  **This chapter owns the controls; 67 owns defeating them.**
- [49-KeyStore](../../49-KeyStore/README.md) §3.7 — what a secret released by a server against a
  hardware-attested request actually looks like, which is extension E3 done properly.
