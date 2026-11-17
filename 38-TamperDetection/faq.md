# 38 — Tamper Detection · FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct; the reasoning
lives in [README.md](README.md).

---

### 1. Is tamper detection worth implementing at all?

Yes — with the scope stated precisely, because the honest answer is neither "yes obviously" nor "no,
client-side security is a myth".

**What it buys:**

- It removes essentially all of the attack *volume*: the person who found a modded APK on a forum, or
  who is following a four-step blog post, stops.
- It raises per-release cost for everyone else. Not by much — minutes to hours — but multiplied
  across every version, that is real money for anyone attacking at scale.
- It produces a **detection signal**, and this is the underrated one. A control that reports its
  verdict to your server keeps working *after it is bypassed*, because the bypassing population is
  itself the signal.

**What it does not buy:** security against anyone motivated. It cannot. The check runs on hardware
the attacker owns.

The failure mode is not implementing it. The failure mode is implementing it and then designing the
system as though it were true. Ship it, log it, and never let a security decision depend on it.

---

### 2. Why does my app die at launch under Frida?

Almost always one of four things, in order of frequency:

1. **A signature check** — but only if you are running a *repackaged* build. Frida in `-U -f` mode
   changes nothing on disk, so a signature check passes. If you built a **Frida Gadget** APK, you
   repackaged and re-signed, and D1 fires. That trade is real and unavoidable: gadget mode costs you
   a signature.
2. **An anti-instrumentation check** — the `/proc/self/maps` scan or the 27042 port probe found
   frida-server.
3. **`ptrace(PTRACE_TRACEME)` failing** — if the app calls it and something already traces the
   process, the call fails and the app treats that as detection.
4. **A check in a tier that ran before your script** — `.init_array` or `JNI_OnLoad`.

**How to find out in one run**, rather than guessing:

```bash
# host
frida -U -f com.target.app -l scripts/which-check-fired.js
```

If nothing prints and the app still dies, hook the consequence instead:

```javascript
Java.perform(function () {
    Java.use('java.lang.System').exit.implementation = function (c) {
        console.log(Java.use('android.util.Log').getStackTraceString(
            Java.use('java.lang.Exception').$new()));
    };
});
```

The stack trace names the class that wanted you dead. That is three lines and it usually ends the
investigation.

---

### 3. Can an app really tell that it was repackaged?

Yes, reliably, and here is the measured proof.

Two APKs were built for this chapter. They are **identical in every byte of code** — the repackaging
step strips the signature and re-signs, and changes nothing else. Both were installed and run on a
real device:

```
clean.apk    D1 self-signature = PASS | f4a76558… | expected f4a76558…
repacked.apk D1 self-signature = FAIL | e9ff1d0f… | expected f4a76558…
```

The mechanism is not magic. The v2/v3 signature covers every byte of the APK, so any modification
invalidates it, so the platform refuses to install it, so the attacker **must** re-sign with a key
they hold. The app then asks the platform which certificate it was installed with, and gets a
different answer.

The app is not detecting modification — it cannot. It is detecting that *somebody else signed it*.
That is a narrower claim and it happens to be exactly the right one.

The caveat: it detects the re-signing, not the tampering. An attacker who does not repackage — Frida
on a rooted device — leaves the signature perfectly intact.

---

### 4. What is `TracerPid`?

A line in `/proc/self/status`:

```
$ adb shell 'cat /proc/$$/status | grep TracerPid'
TracerPid:      0
```

It holds the process ID of whatever is `ptrace`-attached to this process, or `0` if nothing is. The
file does not exist on disk — the kernel generates it when you read it.

It proves exactly one thing: **somebody is ptracing you right now**. Not a second ago. Not that they
ever tried.

---

### 5. Does `TracerPid` detect the Android Studio debugger?

**No. This was measured for this chapter and it contradicts a lot of published material.**

A debuggable build was installed, `jdb` was attached over `adb forward … jdwp:<pid>`, and it
successfully enumerated the app's threads — a fully working debugger session. While that session was
live:

```
TracerPid:      0
```

JDWP is a protocol ART speaks over a socket. It is not a `ptrace` attach, so the kernel's tracer
field is untouched.

The check that *does* catch it is `android.os.Debug.isDebuggerConnected()`, which asks the runtime
rather than the kernel. **They are different questions, and an app that ships only one has a hole
shaped exactly like the other.**

What `TracerPid` *does* catch: `gdb`, `lldb`, `strace`, and `frida-server` when it injects by ptrace.

---

### 6. Is obfuscating the check enough?

No, and it is worth being precise about *why*, because obfuscation does help — just not with the
thing people hope.

R8 renames the app's own classes, methods and fields. It **cannot** rename:

- Platform API names: `getPackageInfo`, `SigningInfo`, `toByteArray`.
- The constant `0x8000000`.
- JNI function names like `Java_com_example_Foo_check`, because the runtime resolves them by name.

So an obfuscated app is still *findable* with one grep. What obfuscation raises is the cost of
**reading and understanding** the check once you have found it — and control-flow flattening or
string encryption raise that cost meaningfully.

But re-read §1.5 of the README: there are five attack points and only two of them care how the check
is written. An attacker who cannot read your check at all can still:

- Hook `Signature.toByteArray` — the input.
- Hook `System.exit` — the consequence.
- Delete the call site.

None of those requires understanding a single line of your obfuscated code. See
[40-Obfuscation](../40-Obfuscation/README.md) for what obfuscation actually delivers.

---

### 7. Should I report "the app has no anti-tampering" as a finding?

**Usually no.**

It is a hardening control, not a vulnerability. It matters only against a threat model that includes
an attacker with root or physical control of the device. If that threat model does not apply — a
note-taking app, an internal tool on managed devices, a timetable — then the absence is a reasonable
engineering decision, and reporting it wastes the client's remediation budget.

When the threat model *does* apply (banking, payments, DRM, gambling, an MDM agent asserting
compliance), report it as **Low**, worded as hardening:

> *"The application implements no anti-tampering or anti-instrumentation controls. Given its threat
> model, this permits an attacker to repackage or instrument the client at negligible cost without
> leaving any signal the operator could act on. Not exploitable on its own."*

And in both cases: the real findings are on the server. See question 9.

---

### 8. I bypassed the app's tamper detection. Is *that* a finding?

No. It is **methodology**.

"Tamper detection can be bypassed" is true of every application that has ever existed, and reporting
it as Medium is precisely why developers stop reading security reports. Record it as Informational,
document how you obtained the access that enabled your real findings, and — this is the part that
makes it useful — **record the cost in minutes**.

"Twenty minutes, one Frida hook on `Signature.toByteArray`" is actionable. "Tamper detection was
bypassed" is not.

It becomes a genuine finding only when the bypass cost is wildly out of line with the assurance the
product claims: a payments app that markets hardware-backed device binding and whose entire control
is one `boolean` in one `Activity`. Then the finding is *"the control does not deliver the assurance
the design assumes"*, and the severity comes from what depends on that assumption.

---

### 9. So where *are* the real findings?

On the server, almost always. Eight of them, and **seven need no client-side bypass at all**:

1. The attestation token replays (capture a request, replay it later from another device).
2. **The endpoint accepts a request with no token at all** — strip the field. This is the single
   fastest test in the whole chapter and it catches an astonishing number of integrations.
3. The verdict is parsed and evaluated on the client.
4. Fail-open on attestation error — block the attestation host and see what happens.
5. The server does not check `requestDetails.requestPackageName`.
6. The server does not check the app's certificate digest.
7. UI-only enforcement — call the API directly with a valid session while the UI hides the button.
8. The integrity signal is never recorded anywhere, so a defeated control has zero residual value.

Several of these need only a proxy. They are more severe, easier to prove, and cannot be argued away
with "the user would have to root their phone".

---

### 10. What is the difference between a signature check and certificate pinning?

They sound similar and are unrelated.

| | Self-signature check (this chapter) | Certificate pinning ([36](../36-CertificatePinning/README.md)) |
|---|---|---|
| Whose certificate | **The app's own signing certificate** | The **server's** TLS certificate |
| What it protects against | Repackaging | A malicious or compromised CA / an intercepting proxy |
| Where the baseline lives | In the app | In the app |
| Checked by | The app, at runtime | The TLS stack, per connection |
| Related how? | Only in that both compare a certificate against a pinned value, and both are defeated by hooking | |

They are, however, entangled in practice: after you repackage an app to disable pinning, its
signature check fires. That is the "patch both or neither" rule.

---

### 11. Why does the app work when I install it, but fail after I patch and re-install?

Because you re-signed it. Three separate things break, and people usually blame the wrong one:

1. **The self-signature check fires** — a different certificate.
2. **Signature-level permissions break** — permissions shared with the vendor's other apps no longer
   match. See [23-Permissions](../23-Permissions/README.md).
3. **Play Integrity's `appIntegrity` verdict changes** — the app is no longer recognised as the
   Play-distributed build.

And before any of that, you probably hit:

```
Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Existing package … signatures do not
match newer version; ignoring!]
```

which is the platform refusing to *update* an installed package with a differently-signed one. You
must uninstall first, which loses the app's data — and if the app derives anything from that data,
you have now changed two variables at once. Uninstall deliberately, not by reflex.

---

### 12. Where does the expected hash live, if not in the app?

This is the **bootstrap problem**, and it is more interesting than it looks: *you cannot compile the
digest of a file into that file*, because adding the constant changes the bytes the constant
describes.

For a **signature** check there is no problem — the signature is applied after everything else, so
the expected certificate hash can sit happily in `classes.dex`.

For a **DEX or APK** hash there are exactly three answers:

| Where | How | Weakness |
|---|---|---|
| A native library | `libcheck.so` holds the expected DEX digest | The `.so` is itself unprotected. Who checks the checker? |
| An asset injected after dexing | The build dexes, hashes, then writes `assets/integrity.bin` into the zip | Trivial to find and edit; a custom build step that breaks silently |
| The server | The app sends what it computed; the server compares | Needs connectivity — and the app can send any value it likes |

Notice that all three *move* the problem rather than solving it. Follow that thought to its end and
you arrive at remote attestation.

---

### 13. Does a DEX hash check add anything over a signature check?

On a modern (v2+) APK, against a repackager: **no.** Measured — a clean build and a repackaged one
had the *identical* `classes.dex` CRC (`5e504f9e`), and only the signature check noticed anything was
wrong.

It adds something in four situations:

- **v1-only APKs**, where the zip structure is not signed at all.
- **Dynamically loaded code** — a downloaded DEX, a plugin JAR. The APK signature never covered it,
  so hashing it is the *only* protection. This is the highest-value version of the check and almost
  nobody does it.
- **Assets that carry policy** — a config or rules file, where a distinct alarm is worth having.
- When you deliberately want a second, differently-shaped alarm. Just do not count it twice in a risk
  assessment.

---

### 14. What is the difference between `.init_array` and `JNI_OnLoad`?

**When they run**, and that is the entire difference — but it decides everything for an analyst.

- A function marked `__attribute__((constructor))` goes into the `.init_array` section. The dynamic
  linker calls everything in `.init_array` as part of `dlopen()`, **before `dlopen()` returns**.
- `JNI_OnLoad` is looked up with `dlsym` and called by ART **after** `dlopen()` returned.

So the constructor runs first, always, structurally. Verify it yourself: `examples/tamper_check.c`
logs `E0` from its constructor and `JNI_OnLoad entered` afterwards.

Why it matters: a Frida script that waits for `Java.perform` has already lost when a check lives in a
constructor. To see it you must hook `android_dlopen_ext` and act in `onEnter`.

[17-Libraries](../17-Libraries/README.md) owns the linker mechanism and ships an `.init_array` lab.
This chapter owns what a *security check* looks like when it lives there.

---

### 15. Is `ptrace(PTRACE_TRACEME)` a detection?

Not by itself. It is a **denial**.

A process may have at most one tracer. Calling `PTRACE_TRACEME` claims that slot, so any later
`PTRACE_ATTACH` from a debugger or from frida-server fails with `EPERM`. That stops an attach; it
does not tell you one was attempted.

Calling it **twice** turns it into a detection: the second call fails if — and only if — somebody else
already holds the slot. Which also means an app that calls it twice by accident detects itself.

And it is worth nothing if the attacker was there first. `frida -U -f com.target.app` spawns the
process under Frida, so the tracer slot is taken before your library is even mapped. Anti-debug that
assumes it runs first loses to one command-line flag.

---

### 16. My static analysis found nothing. Does the app have no tamper detection?

Probably yes — but check the five signals first, because "nothing found" has two very different
causes:

| Signal | Reading |
|---|---|
| Tiny `classes.dex` next to a large `.so` | Packed. The DEX is a loader |
| A DEX string table full of short, high-entropy blobs | String encryption |
| An `.so` with a large `.text` and almost no printable strings | Stack-built or encrypted strings |
| **The app behaves identically with and without Frida** | **There probably is no check. Consider believing it** |
| The app dies under Frida but the mapper is empty | Something is hidden — go to `strace` |

Most apps genuinely have no tamper detection. Measured on an 18-APK corpus: only 13 had even a
self-signature *surface*, and exactly **one** imported `ptrace`. An empty report from a well-built
tool is usually just true.

One more trap: **analyse the split APKs.** One large app in the corpus showed zero controls in
`base.apk` because its native code ships in splits.

---

### 17. Why does the mapper flag things it calls WEAK?

Because the first version of it lied, and the fix is worth understanding.

Run against an 18-APK corpus, the self-signature row matched **18 of 18 apps** — including a 0.3 MB
stub whose only hit was the string `getPackageInfo`, which every analytics SDK on earth calls to read
its own `versionName`.

A checker that flags everything flags nothing. So every row is now graded:

- **STRONG** — the pattern has essentially one reason to exist. `GET_SIGNING_CERTIFICATES` is not
  called by accident.
- **WEAK** — the pattern is an *ingredient*. Consistent with the control and with a dozen innocent
  uses.

Never put a WEAK row in a report. Use it to decide where to look next. This is the same discipline
chapters 33, 36 and 52 arrived at independently: **a sweep produces leads, not findings.**

---

### 18. The app checks its signature but only hides a button when it fails. How bad is that?

The signature check is not the problem. The problem is that the API still works.

If `/api/transfer` accepts the request regardless of what the UI shows, there is no control — there
is a UI preference. A repackaged client, or `curl` with a valid session cookie, transacts happily.

Report it as **High**, and confirm that you proved it *without bypassing anything*: a proxy and a
replayed request are enough. That is the strongest kind of finding, because it cannot be argued away
with "the user would have to root their phone".

---

### 19. Can I detect Frida if it uses a non-default port?

Not with a port scan, no. But the port is the weakest of the anti-Frida signals anyway. Others
survive:

- **`/proc/self/maps`** — the agent has to be mapped in somewhere, and by default it has a name.
- **Thread names** in `/proc/self/task/*/comm` — Frida's runtime creates recognisable ones.
- **Inline-hook detection** — read the first bytes of a function you expect to be untouched and look
  for a trampoline. This is the most technically interesting one and the most expensive to evade.
- **`/proc/self/mem` scanning** for Frida's magic strings, which survives renaming the file.

Each of these is more expensive to evade than the port check. None is impossible to evade. And the
whole set falls to an attacker who hooks the *reads* rather than hiding the *artefacts* — which is
why the honest ranking is by attacker minutes, not by cleverness.

---

### 20. Should the app exit when it detects tampering?

Almost certainly not, and this is the design question that matters more than any individual check.

`System.exit()` is the **worst** option available:

- It is the best possible hook anchor for an attacker. Three lines of Frida on `System.exit` printing
  a stack trace identifies your check in one run.
- It is the worst possible outcome for a false positive. An honest user on an unusual OEM gets an app
  that closes itself with no explanation.

Better, roughly in order:

1. **Report it to the server** and continue. The attacker learns nothing; you learn everything.
2. **Degrade silently** — the feature stops working, with no message tying it to integrity.
3. **Corrupt a derived value** — fold the verdict into key material so there is no branch to invert.
   `examples/LayeredTamperDetector.java` shows this.
4. **Let the server decide**, and have the server *enforce* rather than notify.

One warning: delayed and silent failures are attacker-hostile *and* user-hostile. The same property
that stops an attacker correlating cause and effect stops your support team doing it. Ship it with
telemetry, or you will be debugging blind.

---

### 21. What is the single fastest useful test?

**Strip the integrity token from the request and see whether the operation still succeeds.**

No Frida, no root, no decompiler. A proxy and one deleted field. It takes about a minute and it
catches a surprising proportion of real attestation integrations, because fail-open handling is
extremely common and is invisible from the client side.

Second fastest: hook `System.exit`, print the stack, and read the class name.

---

### 22. Do I need root to study any of this?

For the *controls*, no. Everything in this chapter's labs 01 and 02 — building the detector,
repackaging it, watching the check fire, compiling the native tier, proving the `.init_array`
ordering — was done on an **unrooted** Android 13 device.

For the *bypasses*, effectively yes. `frida-server` needs root. The alternative is a Frida Gadget
build, which means repackaging, which means re-signing, which trips exactly the check you were trying
to study. That trade is real and there is no third option that avoids both.

This chapter is explicit about which of its claims were measured and which were not: see README §7.9.
The controls were built, installed and observed; the Frida-based bypasses were written against
documented APIs and syntax-checked, but **not executed against a live instrumented process**.
