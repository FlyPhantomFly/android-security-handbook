# 54 — Objection FAQ

Real questions, including the ones people are embarrassed to ask. Answers are measured against
**objection 1.11.0** / frida **16.1.6** unless stated otherwise.

---

### 1. Objection or Frida — which one do I learn?

Frida. Objection *is* Frida — it is one large pre-written Frida agent plus a prompt. Every
Objection command is a function inside a file called `agent.js` sitting on your disk right now.

The practical order is the opposite of the learning order, though, and that confuses people.
**Learn Frida, use Objection first.** On a new target you reach for Objection because the
first ten minutes are reconnaissance and you do not yet know what script to write. You reach
for Frida the moment you do.

If you learn Objection *instead* of Frida you will be able to run commands and unable to
diagnose them, because every one of Objection's failure modes is a Frida fact wearing a
disguise.

---

### 2. Why does it say "Unable to connect to the frida server"?

Because Objection prints that one sentence for **three different exceptions**:

```python
# objection/console/cli.py
except (frida.ServerNotRunningError, frida.NotSupportedError, frida.ProtocolError) as e:
    click.secho('Unable to connect to the frida server: {error}'.format(error=str(e)), fg='red')
```

**The headline is nearly always wrong. Read the text after the colon.** Measured, on an
unrooted Android 13 device:

```
Unable to connect to the frida server: need Gadget to attach on jailed Android;
its default location is: C:\Users\...\INetCache\frida\gadget-android-arm64.so
```

The server was not the problem at all — the device is not rooted, so Frida wants a gadget, and
it even names the path it expects one at.

The four real causes, in the order to check them:

1. **No `frida-server` running.** `adb shell "su -c 'ps -A | grep frida'"`.
2. **Not rooted** — you need `objection patchapk` instead. This is the "jailed Android" case.
3. **Version mismatch** — the message will name major versions. See Q12.
4. **Wrong device** — `frida-ps -U` picks one when several are attached. Use `-S <serial>`.

Triage all four at once with `python3 -B scripts/objection-doctor.py`.

---

### 3. Do I need root?

You need **either** root **or** a modified copy of the app. There is no third option.

| Path | Root? | Cost |
|---|---|---|
| `frida-server` | **Yes** | none to the app |
| `objection patchapk` (frida-gadget) | No | **the app's signature changes** |
| A rooted emulator | Yes, trivially | not the real device |

That signature change is not cosmetic. It breaks self-signature checks
([38-TamperDetection](../38-TamperDetection/README.md)), Play Integrity, and any pinning
derived from the app's own certificate. And app bundles mean you must patch every split.

---

### 4. `android sslpinning disable` said it worked, but Burp still shows nothing. Why?

The most-asked question about this tool, and the answer is that **the command's success
message is not about your app.**

Measured: run it against an application with **no networking at all** — no INTERNET permission,
no HTTP client, no TLS — and it reports:

```
(agent) Custom TrustManager ready, overriding SSLContext.init()
(agent) Found com.android.org.conscrypt.TrustManagerImpl, overriding TrustManagerImpl.verifyChain()
(agent) Found com.android.org.conscrypt.TrustManagerImpl, overriding TrustManagerImpl.checkTrustedRecursive()
```

Those three lines appear for essentially every Android app, because `SSLContext` and
`TrustManagerImpl` are **platform** classes present in every process. They mean "the hook
installed", not "the app pins" and certainly not "the bypass worked".

Your traffic is missing for one of these reasons:

- The app pins somewhere the seven hooks do not reach: **native** TLS (Flutter, Cronet),
  `network_security_config` `<pin-set>`, a **WebView** (its own network stack — the command is
  *inert* there), Certificate Transparency, TrustKit, or a bundled `org.conscrypt`.
- Your proxy is not actually in the path, or the app ignores the system proxy.
- The connection was established before you hooked.
- The code path you exercised makes no TLS calls.

**How to tell the difference:** watch for the `Called ...` lines, which print when a hook
actually *fires*. Do not use `--quiet`, which suppresses exactly those. And read
[36-CertificatePinning §7.1](../36-CertificatePinning/README.md) — map the layers statically
before you hook, because a partial bypass looks identical to a failed one.

---

### 5. Why did `android root disable` not work?

Four possibilities, and they need different responses.

**(a) The check is outside its envelope — most likely.** The command installs **three** hooks:
`String.contains("test-keys")`, `Runtime.exec(String)` ending in `su`, and `File.exists()`
against **13 hard-coded paths**. It does not touch `/sbin/magisk`, `/data/adb/*`,
`exec(String[])`, `ProcessBuilder`, `PackageManager`, `/proc/mounts`, SELinux state, RootBeer's
native library, or **anything native at all**.

**(b) Your hook landed too late.** Objection attaches to a running app and spawns a stopped
one, silently. Run `adb shell am force-stop <pkg>` and reconnect. If it now works, that was it.

**(c) It "worked" and you cannot tell.** If the app was not complaining in the first place —
Magisk DenyList hides root artefacts very effectively — then the command changed nothing and
reported success anyway. **Always take a baseline first.**

**(d) It hooked the right thing and the hook did not fire.** Measured: `String.contains` was
hooked, the argument was exactly `"test-keys"`, and it never fired, because ART had already
inlined the call into a caller compiled before the hook existed. The identical hook installed
under `frida -f` fired immediately.

---

### 6. Why does `android root disable` "work" but the app still says I am rooted?

Because you are looking at Objection's output instead of the app's behaviour. The command
prints a job identifier whether it changed anything or not. Read the app's log, UI or traffic.

And if it genuinely did not change the app's mind: read `agent.js` and find out what those
three hooks actually are —
`python3 -B scripts/split-agent.py --out /tmp/am && grep -n '"/' /tmp/am/*android_root*.js`.
That is a five-minute job and it converts a mystery into a coverage table.

---

### 7. What version of what goes with what?

Three relationships must hold and only one gives a clear error.

| Relationship | Enforced by | Symptom |
|---|---|---|
| objection → frida (Python) | pip: `frida>=14.0.0` | install fails, or `ImportError` at start-up |
| frida → frida-server | **wire protocol; MAJOR must match** | `please ensure that major versions match` |
| `agent.js` → the server's JS API | **nothing** | connects fine, commands throw individually |

| objection | frida | frida-server | Outcome |
|---|---|---|---|
| **1.11.0** | **16.1.6** | **16.1.6** | **works — measured** |
| 1.11.0 | 16.x | 16.y | expected to work |
| 1.11.0 | 16.x | 17.x | fails at connect |
| 1.11.0 | 17.x | 17.x | connects, then every hooking command fails |
| 1.12.x | 17.x | 17.x | works |

**Rule:** `frida --version` on your host is the authority. Download the `frida-server` whose
version string equals it *exactly*, for the ABI of the target **process**. Pin all three in a
`requirements.txt`. Run `python3 -B scripts/objection-doctor.py` to check.

---

### 8. It says a newer objection is available. Should I upgrade?

Not mid-engagement. That banner prints on **every single run**, before anything else, and
acting on it is one of the commonest ways a working setup breaks: upgrading Objection can pull
a new `frida` Python package, which then no longer speaks to the `frida-server` deployed on
your device.

Upgrade deliberately, between engagements, and move all three versions together.

---

### 9. Objection connects and `env` works, but every hooking command throws. What is that?

The third relationship in Q7: your `agent.js` was built against a different Frida JavaScript
API than the `frida-server` you are talking to. The socket works — which is why `ping()`
succeeds and you see `Agent injected and responds ok!` — but the Java-bridge calls fail.

**`Agent injected and responds ok!` does not mean your versions are compatible.** It means the
wire works. Nothing checks the third relationship until a command exercises it.

---

### 10. Why does `android hooking list classes` show 16,000 classes for a tiny app?

Because it reads the **runtime's loaded-class table**, which contains every framework and
support-library class the process has touched. Measured: 16,087 classes in an app with three
of its own.

Always filter: `android hooking search classes <your.target.package>`.

The corollary matters more: **the list is what is *loaded*, not what *exists*.** A class the
app has not touched yet is not there. If you enumerate before driving the app and conclude a
class does not exist, you may just have looked too early. Cross-check against a static class
list from [56-JADX](../56-JADX/README.md).

---

### 11. Does Objection work on obfuscated apps?

Yes, and better than people expect. [42-R8](../42-R8/README.md) measured it: class listing and
heap search "work on an R8 build exactly as on any other, because they operate on the runtime's
own class table — obfuscation taxes reading, not running."

R8 renames `LoginValidator` to `c`, but the runtime must still load, register and dispatch it,
so `android hooking list class_methods a.b.c` returns real signatures. You lose names and keep
structure. Find classes by **behaviour**: `android hooking get current_activity`, then
`android hooking search classes <package>` (the package prefix usually survives), then
`android hooking watch class` and drive the UI.

Two caveats: `-repackageclasses` flattens everything and destroys the prefix filter; and
Kotlin **property** names survive R8 structurally, so method listings are often more readable
than you would guess.

---

### 12. What is `-g` and why does it default to "Gadget"?

`-g` is the process or package to connect to. It is short for "gadget" because the flag
predates Objection's use with `frida-server`, and its default is literally the string `Gadget`
— which is the process name a **gadget-patched app** presents to Frida.

So after `objection patchapk`, you connect with `objection -g Gadget explore`, **not** the
package name. That trips up nearly everyone once.

`-g` also accepts a PID: the value is run through `int()` first, and an integer is treated as a
PID rather than a name.

---

### 13. Does Objection spawn the app or attach to it?

**Both, depending on whether the app happened to be running, and it does not tell you which.**

```python
# objection/utils/agent.py
try:
    self.session = self.device.attach(gadget_name)   # running -> ATTACH
    self.resumed = True
except frida.ProcessNotFoundError:
    self.spawned_pid = self.device.spawn(gadget_name)  # not running -> SPAWN
```

There is no flag to force one. The consequence is that the same command produces different
results five minutes apart. On the attach path, `Application.onCreate`, `attachBaseContext` and
every static initialiser have already run, so hooks on startup code are useless.

**Always `adb shell am force-stop <pkg>` first.** One second, and it converts an ambiguous
default into a known one. [53-Frida §2.3](../53-Frida/README.md) makes the same argument for
Frida's `-f` and states it as "Default to `-f`. Always."

---

### 14. `android hooking set return_value` returned true but the app still refused. Why?

Two likely reasons.

**The method still ran.** `set return_value` replaces what the *caller* sees; it does not stop
the body executing. Measured, on one call:

```
I CH54: AuthGate.checkPin(0000) -> false     <- the method's own log
I CH54: startup pin probe accepted=true      <- what the caller received
```

Any side effect — a counter, an analytics event, a lockout — still happened.

**Or the decision is not where you think.** If the refusal comes from a *second* check, or from
the server, forcing one boolean changes nothing. Use `android hooking watch class` on the whole
class and drive the app to find out what else is consulted.

Also note: **booleans only.** There is no command for a `String` or object return; that is a
script.

---

### 15. Can I run Objection without a terminal — in CI, or with redirected input?

Not `explore`. The REPL is constructed **before** any command runs, and `prompt_toolkit` aborts
when stdin is not a console. This is not theoretical: it is exactly what happened while writing
this chapter on a Windows host, and it kills `objection ... explore -c cmds.txt` too, because
`Repl()` is built first.

Use **API mode** instead:

```bash
objection -g com.example.app api &
curl -s http://127.0.0.1:8888/rpc/invoke/envFrida
```

Three sharp edges: the endpoint is the **RPC export** name, not the command
(`android root simulate` is `androidRootDetectionEnable`); no-argument methods need **GET**
(a `POST` body of `{}` is rejected as invalid); and arguments are passed **by position** — the
JSON keys are ignored entirely.

API mode is also how you make a session reproducible, which a scrollback never is.

---

### 16. How much does Objection change the process? Will it get me detected?

Measured: `agent.js` is **1,045,437 bytes** with 125 modules, and it produces about **7.6 MB of
QuickJS heap** inside the target (`frida` → `heap: 7644640`). That is roughly an order of
magnitude more footprint than a targeted script, for a task that usually needs one hook.

Everything that detects **Frida** detects Objection, because Objection is Frida —
`/proc/self/maps`, the `gum-js-loop` and `pool-frida` thread names, port 27042. One check is
Objection-specific: the class `com.sensepost.test.TrustManager`, which is registered only if
you ran `android sslpinning disable`.

If an app tolerates a small script and dies under Objection, that is usually **not** targeted
anti-Objection logic — it is the size. The fix is the smaller tool.

(Amusingly, the pinning module *does* think about detection: it renames Frida's temp-DEX prefix
from `frida` to `onetwothree` so it does not show up in `/proc/self/maps`.)

---

### 17. Is a successful pinning bypass a finding I can report?

**No**, and reporting it as one is the fastest way to lose a reader.
[36-CertificatePinning §5.6](../36-CertificatePinning/README.md) is explicit that
*"Pinning can be bypassed with Frida on a rooted device"* is **rejected** on almost every
programme, because "the payout is for a control that fails without attacker privilege on the
device. A bypass that requires root is not that." And §1.5: "An app with no certificate pinning
does not, by that fact, have a vulnerability."

What you *can* write is a methodology note: the bypass took under a minute with an unmodified
public tool on default settings, it establishes the precondition for the traffic-based findings
that follow, and it shows the control offers no resistance beyond the stock case. No severity
rating.

The real escalation is server-side: if, after bypassing, the **server** accepts what it should
not, *that* is the finding.

---

### 18. Objection crashes the app the instant it injects. Is the app detecting it?

Maybe, but check the boring causes first:

1. **Version skew** — a mismatched agent can crash the process outright.
2. **Wrong ABI** — a 64-bit `frida-server` cannot inject a 32-bit process.
3. **Footprint** — 7.6 MB of heap can trip a memory heuristic that a 200 KB script does not.
4. **Actual anti-Frida code** — [37 §3.9](../37-RootDetection/README.md) and
   [53 §6.2](../53-Frida/README.md).

Test 3 and 4 apart by attaching a **minimal** Frida script that does nothing but print. If that
survives and Objection does not, it is size, not detection.

---

### 19. Is it safe to run `android keystore clear`?

**No.** It deletes every entry in the app's `AndroidKeyStore`, with no confirmation and no
undo. On a real device that can destroy database encryption keys, credentials and device-bound
tokens permanently. Do not type it to see what happens.

More generally, the destructive commands with no prompt are: `android keystore clear`,
`rm`, `memory write`, and `file upload` over an existing file.

---

### 20. When exactly should I stop using Objection?

The moment your question changes from **"is there anything here?"** to **"why did that
happen?"**.

Concretely, stop when: you need to explain a mechanism in a report · you need a hook Objection
does not have (anything native, any non-boolean return, any conditional or stateful logic) ·
you need a *specific* overload or classloader · you need the result to be reproducible · or the
app fights back and you need the smallest possible footprint.

This is not a failure of the tool. It is the tool working as designed and you having a
different question. And the handoff is cheap, because Objection just gave you the exact
overload signatures with `android hooking list class_methods` and a scaffold with
`android hooking generate simple`.

[20-Security-Architecture](../20-Security-Architecture/README.md) states the rule best:
use it to *save time*, never to *understand*.

---

### 21. How do I find out what my version of a command actually does?

Read your own `agent.js`. This is the single most valuable habit in the chapter, it takes five
minutes, and your version is probably not the one this chapter measured:

```bash
python3 -B scripts/split-agent.py --out /tmp/am
grep -n '"/'                    /tmp/am/*android_root*.js       # the hard-coded paths
grep -oE 'Java\.use\("[^"]+"\)' /tmp/am/*pinning*.js | sort -u  # classes the bypass knows
```

Everything in the chapter's §3.5 and §3.6 came out of exactly those two commands.

---

### 22. Objection is written in Python but the hooks are JavaScript. Why?

Because Frida's agent runs *inside* the target process, in an embedded JavaScript engine
(QuickJS on Android). Python cannot run there. So the split is: Python on your workstation for
the CLI, the REPL and formatting; JavaScript in the app for the actual instrumentation; JSON-RPC
over a socket between them.

Practically this means the Python files are almost empty. `commands/android/pinning.py` is 26
lines and `root.py` is 25 — they call one function and tabulate the answer. **If you go looking
for what a command does and you read the Python, you will learn nothing.** All the intelligence
is in `agent.js`. That is the commonest wrong turn in trying to understand this tool.
