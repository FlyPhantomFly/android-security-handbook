# Example 01 — An annotated Objection session, line by line

Every line of tool output below was produced on a real device against
[`target-app/`](target-app/), an application built for this chapter. Nothing is invented. Where
a line is a transcription of the equivalent REPL command rather than a REPL capture, it says
so.

**Environment**

| | |
|---|---|
| Device | Redmi `M2101K6P` (`sweetin`), MIUI 12.5, **Android 11 / API 30**, arm64-v8a |
| Root | Magisk. `adb shell "su -c id"` returns `uid=0(root) … context=u:r:magisk:s0` |
| frida-server | 16.1.6, `/data/local/tmp/frida-server`, running as root |
| Host | objection **1.11.0**, frida **16.1.6**, frida-tools **12.3.0**, Python 3.13.3 |
| Target | `com.pentest.ch54.target`, installed via `su -c 'pm install'` |

> **How these were captured.** `objection ... explore` needs a console, and this host had
> none, so the session ran through Objection's own headless API mode (`objection ... api`,
> then HTTP calls to `/rpc/invoke/<export>`). That loads the *same* `agent.js` and calls the
> *same* RPC exports the REPL calls — the agent output is identical. Where a REPL prompt is
> shown, it is the command you would type to produce the output beneath it.

---

## 0. Before you connect — the baseline

The most important command in the session is the one that runs before Objection does.

```bash
# host
adb shell am force-stop com.pentest.ch54.target
adb logcat -c
adb shell am start -n com.pentest.ch54.target/.MainActivity
sleep 3
adb logcat -d -s CH54
```

```
I CH54: A su-known-path        rooted=false
I CH54: B magisk-unknown-path  rooted=false
I CH54: C exec-string threw: Cannot run program "/system/bin/su": error=2, No such file or directory
I CH54: C exec-su-String       rooted=false
I CH54: D which-su-String[]    rooted=false
I CH54: E build-tags           rooted=false (TAGS=release-keys)
I CH54: VERDICT score=0/5 rooted=false
I CH54: AuthGate.checkPin(0000) -> false
I CH54: startup pin probe accepted=false note=ch54-lab-not-a-real-secret
```

**Annotation.**

- `score=0/5` on a device that is definitely rooted. Magisk's DenyList has hidden every
  artefact from the app's view, so all five checks honestly report "not rooted". This belongs
  to [37 §3.14](../../37-RootDetection/README.md), but it has an immediate consequence here:
  **any root-bypass command run against this app will produce no observable change**, because
  there is nothing to suppress.
- Without this baseline you would run `android root disable`, see 0/5, and conclude the bypass
  worked. It did not. There was nothing to do. This is [51 §3.2](../../51-DynamicAnalysis/README.md)'s
  control run, and it is the difference between a measurement and an anecdote.
- `am force-stop` first is not tidiness. Objection attaches to a running process and spawns a
  stopped one, silently, and the two give different results — see the chapter README §2.4.

---

## 1. Connecting

```bash
# host
objection -S 84f7a024 -g com.pentest.ch54.target explore
```

```
A newer version of objection is available!
You have v1.11.0 and v1.12.5 is ready for download.

Upgrade with: pip3 install objection --upgrade
For more information, please see: https://github.com/sensepost/objection/wiki/Updating

Using USB device `M2101K6P`
Agent injected and responds ok!
```

**Annotation.**

- **The upgrade banner prints before anything else, on every single run.** Do not act on it
  mid-engagement. Objection, the `frida` Python package and `frida-server` must move together
  (README §3.11); upgrading one because a banner suggested it is the commonest way a working
  setup becomes a broken one.
- `Using USB device 'M2101K6P'` confirms *which* device. Two phones and an emulator were
  attached to this host at various points while the chapter was written, and they were swapped
  without warning. `-S <serial>` removes the ambiguity; without it, `frida.get_usb_device(5)`
  picks one for you.
- **`Agent injected and responds ok!` is a real assertion, not decoration.** Objection calls
  `rpc.exports.ping()` and requires a truthy answer before printing it. If you see it, the
  chain from your keyboard to the app's process works. If you do not, nothing you type next
  can possibly work.
- What it does **not** prove: that your versions are compatible. `ping()` exercises the socket,
  not the Java bridge. An agent built against a different Frida major will print this line and
  then fail on the first hooking command.

---

## 2. Orientation — `env` and `frida`

```
# objection REPL
env
```

```json
{"application_name": "com.pentest.ch54.target", "board": "sweetin",
 "brand": "Redmi", "device": "sweetin", "host": "c5-miui-ota-bd237.bj",
 "id": "RKQ1.200826.002", "model": "M2101K6P", "product": "sweetin",
 "user": "builder", "version": "11"}
```

```
# objection REPL
frida
```

```json
{"arch": "arm64", "debugger": false, "heap": 7644640,
 "platform": "linux", "runtime": "QJS", "version": "16.1.6"}
```

**Annotation.**

- `application_name` confirms you are inside the process you meant to be inside. On a device
  with several similarly-named packages this catches a real mistake.
- `arch: arm64` is the architecture of **the process**, which is the number that matters. A
  64-bit device can run 32-bit processes, and a 64-bit `frida-server` cannot inject into one.
- `version: 16.1.6` is the Frida in the *target process*. Compare it against your host
  `frida --version`. Here they match exactly, which is why this session worked.
- **`heap: 7644640`.** Seven and a half megabytes of JavaScript heap, inside an application
  whose own code is three classes. That is Objection's footprint, and it is the number to
  quote when someone asks why a hardened app tolerates a small Frida script and kills an
  Objection session.
- `runtime: QJS` — QuickJS, not V8. Small and fast to start, slower in tight loops, which is
  why `memory search` over a large process is not quick.
- `debugger: false` is worth noting: Frida is not a JDWP debugger, and an app checking
  `Debug.isDebuggerConnected()` will not see it. [38-TamperDetection](../../38-TamperDetection/README.md)
  measured the converse — attaching `jdb` leaves `TracerPid: 0`.

---

## 3. Reconnaissance — what is this app made of?

```
# objection REPL
android hooking list classes
```

```
loaded classes: 16087
```

**Annotation.** Sixteen thousand and eighty-seven classes, in an application with **three** of
its own. Everything else is framework and support library. This command on its own is close to
useless; its value is as the input to a filter.

```
# objection REPL
android hooking search classes com.pentest.ch54
```

```
com.pentest.ch54.target.MainActivity
com.pentest.ch54.target.MainActivity$AuthGate
com.pentest.ch54.target.SecurityGate
```

**Annotation.** Three classes, and one of them is called `SecurityGate`. On a real target this
is the moment reconnaissance pays for itself: you now have a name worth reading, obtained
without decompiling anything. Even under R8 the package prefix usually survives, so this
filter still works when every leaf name is a single letter (README §6.1).

Note the `$` in `MainActivity$AuthGate` — that is a nested class, and the `$` is part of the
name you must type. In a shell it needs quoting or escaping.

```
# objection REPL
android hooking list class_methods com.pentest.ch54.target.MainActivity$AuthGate
```

```json
["public boolean com.pentest.ch54.target.MainActivity$AuthGate.checkPin(int)",
 "public boolean com.pentest.ch54.target.MainActivity$AuthGate.checkPin(java.lang.String)"]
```

**Annotation.** This is the single most valuable output in the session, and it is worth being
precise about why. It gives you **exact overload signatures**. Those strings are what you paste
into `.overload("java.lang.String")` when you write a real Frida script an hour from now.
Objection is doing the tedious, error-prone part of the job that *precedes* writing your own
code — which is exactly where a canned tool should be used.

Two overloads. Remember that; it matters in section 5.

---

## 4. The four-second question — is the protection worth my afternoon?

```
# objection REPL
android root disable
```

```
(agent) Registering job 370560. Type: root-detection-disable
```

Then re-trigger the app's gate and read **the app's** log, not Objection's:

```bash
# host
adb shell am start -n com.pentest.ch54.target/.GateActivity
adb logcat -d -s CH54 | tail -8
```

```
I CH54: VERDICT score=0/5 rooted=false
```

**Annotation — and this is the most important annotation in the file.**

The verdict was 0/5 before the command and 0/5 after it. **You cannot tell from this whether
the bypass worked or whether there was nothing to bypass.** Objection reports success
identically in both cases. It printed a job identifier and nothing else, and a job identifier
is a statement about Objection, not about the app.

A tester who skipped section 0's baseline would look at this and write "root detection
bypassed". That claim would be false, and it would be false in a way nobody could catch from
the transcript.

What you have actually learned: nothing about this app's root detection. To learn something,
run it the other way round.

---

## 5. Mapping the envelope with `android root simulate`

```
# objection REPL
android root simulate
```

```
(agent) Registering job 370560. Type: root-detection-enable
(agent) [370560] File existence check for /system/xbin/su detected, marking as true.
(agent) [370560] Check for 'su' using command exec detected, allowing.
```

```bash
# host
adb shell am start -n com.pentest.ch54.target/.GateActivity
adb logcat -d -s CH54 | grep -A8 "GateActivity re-running"
```

```
I CH54: GateActivity re-running the gate
I CH54: A su-known-path        rooted=true
I CH54: B magisk-unknown-path  rooted=false
I CH54: C exec-string threw: Attempt to invoke virtual method
        'void java.lang.Process.destroy()' on a null object reference
I CH54: C exec-su-String       rooted=false
I CH54: D which-su-String[]    rooted=false
I CH54: E build-tags           rooted=false (TAGS=release-keys)
I CH54: VERDICT score=1/5 rooted=true
```

**Annotation, check by check.**

| | Result | Why |
|---|---|---|
| **A** `/system/xbin/su` via `File.exists()` | **flipped to true** | The path is one of the thirteen hard-coded strings. Covered, and it worked |
| **B** `/sbin/magisk` via `File.exists()` | unchanged | Not on the list. `indexOf(path) >= 0` is an exact string match, so the hook falls straight through |
| **C** `Runtime.exec("/system/bin/su")` | unchanged, **and it broke differently** | Hooked, announced "allowing", and returned something that is not a `Process`. This is a bug in the canned script |
| **D** `exec(new String[]{"which","su"})` | unchanged | Only `exec(String)` is hooked. Frida hooks are per-signature, exactly as Java dispatch is |
| **E** `Build.TAGS.contains("test-keys")` | unchanged | Hooked, and never fired. See below |

**On check C.** Look at the exception text: it changed from `Cannot run program
"/system/bin/su"` to `... on a null object reference`. The canned hook's "success" branch does
`return this.apply(this, arguments)`, and `this` is a Java instance wrapper, not a function.
The app receives `null` where it expected a `Process`. If your detector was grepping logcat
for "No such file", it just went quiet — for the wrong reason.

**On check E.** The hook is on `java.lang.String.contains`, the argument *is* exactly
`"test-keys"`, and the agent's message for that hook never appeared. An identical hand-written
hook, installed by [`../scripts/root-disable-equivalent.js`](../scripts/root-disable-equivalent.js)
under `frida -f`, **did** fire. The difference is ordering: here the app had already executed
that check once before the command was issued. Same hook, same method, same device, opposite
result — see the chapter README §3.5.2.

**One of five.** That is the measured coverage of a canned root command against an app built
specifically so that three of its five checks sit inside the canned envelope. Two of the three
"covered" checks did not actually flip. Report the shape of this, not the number.

---

## 6. Watching a method, and forcing its answer

```
# objection REPL
android hooking watch class_method com.pentest.ch54.target.MainActivity$AuthGate.checkPin --dump-args --dump-backtrace --dump-return
```

```
(agent) Attempting to watch class com.pentest.ch54.target.MainActivity$AuthGate and method checkPin.
(agent) Hooking com.pentest.ch54.target.MainActivity$AuthGate.checkPin(int)
(agent) Hooking com.pentest.ch54.target.MainActivity$AuthGate.checkPin(java.lang.String)
(agent) Registering job 902292. Type: watch-method for: ...AuthGate.checkPin
```

**Annotation.** No overload filter was given, so **both** overloads were hooked — and Objection
tells you which ones it took, which is more than most tools do. That is usually what you want
during reconnaissance and usually not what you want when measuring, because two hooks on a
delegating pair double-report every call.

`--dump-backtrace` is the flag to remember. Arguments tell you *what* was asked;
the backtrace tells you *who* asked. [27-ContentProviders](../../27-ContentProviders/references/README.md)
puts it exactly: the backtrace "is what tells you whether a `query` came from the app's own UI
or from a Binder thread serving an external caller". Reachability is the difference between a
finding and a curiosity.

```
# objection REPL
android hooking set return_value com.pentest.ch54.target.MainActivity$AuthGate.checkPin true
```

```bash
# host
adb shell am start -n com.pentest.ch54.target/.MainActivity
adb logcat -d -s CH54 | grep -i "checkPin\|pin probe" | tail -2
```

```
I CH54: AuthGate.checkPin(0000) -> false
I CH54: startup pin probe accepted=true
```

**Annotation.** Two log lines, one call, and they disagree — and that disagreement is the whole
mechanism made visible.

`checkPin` **ran**. It compared `"0000"` against the expected PIN, computed `false`, and logged
`false`. Then the hook handed `true` to the caller, which logged `accepted=true`.

Consequences people get wrong:

- **Side effects still happen.** A failed-attempt counter would have incremented. An analytics
  event would have fired. A lockout would have progressed.
- **Booleans only.** `androidHookingSetMethodReturn` supports boolean returns and nothing else.
  A `String` or an object means you are writing a script.
- **The pair is the evidence.** A report that quotes both lines — the app decided `false`, the
  caller acted on `true` — demonstrates that the authorisation decision is client-side and
  therefore attacker-controlled. A report that quotes only "I got in" is an anecdote.

---

## 7. What was hooked — and cleaning up

```
# objection REPL
jobs list
```

```json
[{"identifier": "902292", "implementations": [null, null],
  "type": "watch-method for: com.pentest.ch54.target.MainActivity$AuthGate.checkPin"},
 {"identifier": "156258", "implementations": [null, null],
  "type": "set-return for: com.pentest.ch54.target.MainActivity$AuthGate.checkPin"}]
```

**Annotation.** Two jobs, two implementations each — the `(int)` and `(String)` overloads
again. Note that a `watch` and a `set return_value` are both live on the same method
simultaneously; Objection allows this and warns about nothing. They compose in installation
order.

`jobs list` is your record of every mutation you have made to the process, which is exactly
what [51 §7.8](../../51-DynamicAnalysis/README.md)'s runbook asks you to keep. Copy it into
your notes before you exit.

```
# objection REPL
jobs kill 902292
jobs kill 156258
exit
```

```bash
# host -- and then actually restore the device
adb shell am force-stop com.pentest.ch54.target
adb uninstall com.pentest.ch54.target
```

**Annotation.** `jobs kill` unloads hooks. It does **not** undo side effects: a downloaded
file, a changed proxy, a cleared KeyStore, an incremented counter. Objection's own `atexit`
handler unloads the agent when you quit, which is why you sometimes see `Asking jobs to
stop...` on the way out — but the app's *state* is yours to restore.

---

## 8. What this session established, written honestly

The defensible write-up of everything above:

> The application performs five root-detection checks, all in the Java layer, located in
> `com.pentest.ch54.target.SecurityGate`. On the reference device none of them fires, because
> Magisk's DenyList hides the artefacts they probe. Stock instrumentation tooling
> (`objection android root simulate`, objection 1.11.0) was able to influence **one** of the
> five; the remaining four are outside the canned envelope — two probe paths absent from the
> tool's hard-coded list, one uses the `exec(String[])` overload the tool does not hook, and
> one is a hook that installed without firing.
>
> The `AuthGate.checkPin` authorisation decision is made entirely client-side and returns a
> boolean. Forcing that boolean to `true` with a single stock command caused the caller to
> proceed while the method itself still computed `false`. **Whether this is a finding depends
> entirely on whether the server re-validates**; the client-side observation alone is not one.
>
> No conclusion is drawn about certificate pinning: the application performs no network
> activity, and `android sslpinning disable` reported three successful hooks against it
> regardless, which is a property of the tool rather than of the application.

Every clause in that is supported by a line of output above. That is the standard.

---

## Related

- Chapter README [§3.5](../README.md) — the three root hooks, in full
- Chapter README [§7.3](../README.md) — the four failure modes
- [`02-when-objection-fails.md`](02-when-objection-fails.md) — the same task where the canned
  command loses and a hand-written script wins
- [`../labs/lab-02-objection-versus-a-script.md`](../labs/lab-02-objection-versus-a-script.md) —
  do this comparison yourself
