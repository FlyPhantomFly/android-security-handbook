# 67 — Bypassing Protections — Cheat Sheet

Printable. Tables and commands only. Full reasoning in [README.md](README.md).
**Authorised targets only: apps you own or are contracted to test.**

---

## The five seams

| Seam | You change | Where you act | Blast radius |
|---|---|---|---|
| **S1 input** | The world the control reads | Outside the process, on the device | Every process on the device |
| **S2 read** | What the read returns | libc / libcore, inside the process | One process |
| **S3 verdict** | The computed decision | The aggregation function | One function |
| **S4 branch** | Which way the `if` goes | The consumer of the verdict | One decision |
| **S5 gated code** | Nothing — you call the payload | The protected function itself | One call |

Mapping to [20-Security-Architecture/labs/lab-03](../20-Security-Architecture/labs/lab-03-integrity-gate-bypass.md):
S1 = altitude A, S2 = B, S3 = C, S5 = D.

---

## Seam / altitude table — cost and detectability

| Technique | Seam | Setup (first time) | Per app after | App can detect | Survives update | Survives R8 rename |
|---|---|---|---|---|---|---|
| Magisk DenyList | S1 | 30–60 min (root) | ~1 min | Rarely | Yes | Yes |
| `resetprop <k> <v>` | S1 | Minutes | Seconds | No | Until reboot | Yes |
| frida-server on a non-default port | S1 | Seconds | Seconds | No | Yes | Yes |
| frida-server `--directory` rename | S1 | Seconds | Seconds | No | Yes | Yes |
| Rename / rebuild the agent | S1 | Hours | Seconds | Hard | Yes | Yes |
| libc interposition (`access`,`stat`,`openat`,`fopen`) | S2 | 0 (script exists) | 5–15 min | Counter-instrumentation only | Usually | Yes |
| `/proc` content substitution | S2 | 10 min | 5 min | Counter-instrumentation only | Usually | Yes |
| Java hooks (`File.exists`, `SystemProperties.get`) | S2 | 0 | 5 min | Yes — re-check natively | Usually | Yes |
| Hook the verdict function | S3 | 0 | 2 min | **Easily** | **No** | **No** |
| Patch the branch (Smali / ARM) | S4 | 15 min | 15–60 min | Signature check catches it | **No** | **No** |
| Call the gated code directly | S5 | 0 | 2 min | **Not at all** | Sometimes | No |
| Early instrumentation (beat `JNI_OnLoad`) | S2 + timing | 20 min | ~1 min | Hard | Yes | Yes |
| Static patch of the `.so` | RE | 30 min | Hours | Only via signature/checksum | No | N/A |
| Read it and reimplement | RE | Hours | Hours | Not at all | N/A | N/A |

**Rule:** the lowest altitude that achieves your objective in the time you have.

---

## Symptom → cause → first move

| Symptom | Most likely cause | First move |
|---|---|---|
| Dies instantly on **attach** | Load-time check (`.init_array`, `JNI_OnLoad`) | Spawn: `frida -U -f pkg --no-pause` |
| Dies instantly on **spawn** too | Packer, or `PTRACE_TRACEME` in a constructor | `scripts/early-instrument.js`; hook `ptrace` before load |
| Hooks fire, app still detects | A native tier you did not hook | libc interposition, not Java hooks |
| Hook installed, nothing changed | Wrong overload / class loader / a second copy of the check | `frida-trace` first; confirm the hook fired at all |
| Detects only in release builds | `FLAG_DEBUGGABLE` or a signature check | Do not repackage with `debuggable` set |
| Detects only sometimes | Timing check, or a race with a background thread | Turn off `console.log` in hooks; re-measure |
| Nothing dies, results are wrong | Silent degradation (`POISON`) | Diff instrumented output vs a clean baseline |
| Server rejects your forged request | The server re-verifies | Good — that is the control that holds. Say so in the report |

---

## `ApplicationExitInfo` decoder (API 30+)

`adb shell dumpsys activity exit-info <pkg>`

| `reason` | Label | `status` means | Protection-related? |
|---|---|---|---|
| 1 | EXIT_SELF | the exit code | Likely — `System.exit(n)` |
| 2 | SIGNALED | the **signal number** | Likely if 9 (SIGKILL to self) |
| 3 | LOW_MEMORY | — | No |
| 4 | CRASH | — | Read the Java stack; usually a bug |
| 5 | CRASH_NATIVE | the **signal number** (6 = SIGABRT) | Likely — `abort()` |
| 6 | ANR | — | No, unless a check blocks the main thread |
| 10 | USER_REQUESTED | — | No — usually your own `am force-stop` |
| 13 | OTHER | — | No — system housekeeping |

Signals: `4 SIGILL · 5 SIGTRAP · 6 SIGABRT · 7 SIGBUS · 9 SIGKILL · 11 SIGSEGV`

> Read `reason` **before** `status`. The field is an exit code for reason 1 and a signal for 2 and 5.

---

## Measured response signatures (i9000S, Android 13 / API 33)

| App's response | reason | status | Lifecycle reached | Other evidence |
|---|---|---|---|---|
| `abort()` in `JNI_OnLoad` | 5 | 6 | **none** | tombstone `libch67guard.so (JNI_OnLoad+908)` |
| `abort()` called from Java | 5 | 6 | create→start→resume | tombstone with Java frames below |
| `System.exit(42)` | 1 | 42 | full | status is the developer's literal |
| `Process.killProcess(myPid())` | 2 | 9 | full | no dialog, no stack |
| `throw` caught by the caller | *(none)* | — | full | process survives |
| Silent degradation | *(none)* | — | full | output wrong, nothing logged |
| Clean run | *(none)* | — | full | correct output |

---

## Anti-debug: mechanism → defeat

| Mechanism | Detects | Defeat at | Cost |
|---|---|---|---|
| `TracerPid` in `/proc/self/status` | live `ptrace` | S2 — substitute the file content | Low |
| `PTRACE_TRACEME` on self | any later attach | S2 — hook `ptrace`, **spawn only** | Low if early, impossible if late |
| Forked watchdog that ptraces the parent | any later attach | S2 — be present before the fork | Medium |
| `Debug.isDebuggerConnected()` | **JDWP** only | S3 — return false | Trivial |
| `Debug.waitingForDebugger()` | JDWP wait state | S3 | Trivial |
| `FLAG_DEBUGGABLE` | tampered/repackaged build | S1 — do not set it | Zero |
| `ro.debuggable` / `ro.secure` | device build type | S1 — `resetprop` | Low |
| Timing around a function | hook overhead | S2 — quiet hooks, `CModule`, hook the clock | Medium |
| `.text` self-checksum | your inline hook | — use `Stalker`, or patch statically | High |
| `BRK` / breakpoint scan | software breakpoints | avoid breakpoints; use hooks or emulation | Medium |

---

## Anti-Frida: mechanism → defeat

| Mechanism | Defeat at | How |
|---|---|---|
| TCP 27042 open | **S1** | `frida-server -l 127.0.0.1:1337` |
| D-Bus handshake on the port | S1 | non-default port; gadget in `script` mode (no listener) |
| `/proc/net/tcp` full scan | S2 | hook the read; or use a unix socket |
| `/proc/self/maps` contains `frida`/`gum`/`gadget` | S2 | hook `open`/`read` of `maps`; rename the agent |
| Thread names `gum-js-loop`, `gmain`, `pool-frida`, `gdbus` | S2 | hook `readdir`/`open` on `/proc/self/task` |
| `/data/local/tmp/re.frida.server` | **S1** | `frida-server --directory /data/local/tmp/.x` |
| `linjector-*` pipes | **S1** | same `--directory` change |
| `dlopen` sees `frida-agent.so` | S2 | hook `dlopen` first (timing) |
| Inline-hook checksum | — | `Stalker`, or stop hooking |
| `RegisterNatives` monitoring | — | custom Frida build; consider going static |
| Timing | S2 | `CModule`, no logging in hooks |

**Five of these eleven are configuration changes, not hooks.**

---

## Timing: what runs when

```
fork from zygote
  -> System.loadLibrary("x")
       -> android_dlopen_ext
            -> .init_array constructors      <-- check #1  (inside dlopen)
       -> dlsym("JNI_OnLoad") ; call it      <-- check #2  (after dlopen)
  -> Application.attachBaseContext
  -> Application.onCreate
  -> Activity.onCreate                       <-- most tutorials start here
```

| Invocation | Before `.init_array`? | Before `JNI_OnLoad`? | Before Java? |
|---|---|---|---|
| `frida -U -f pkg --no-pause` | Yes | Yes | Yes |
| `frida -U -F` / `-n` (attach) | No | No | No |
| frida-gadget embedded in the APK | Yes | Yes | Yes |
| LSPosed / Xposed module | Java only | Varies | Yes |

Beat `.init_array` by (a) hooking `__dl__ZN6soinfo17call_constructorsEv`, or
(b) hooking the libc functions the constructor will call — libc is already mapped.

---

## Commands

### Identify and record the device — do this first

```bash
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.release
adb shell getenforce
adb shell "mount | grep -E 'cacerts|magisk|APatch'"
```

### Triage

```bash
python3 -B scripts/bypass-triage.py -p <pkg> -a .MainActivity
python3 -B scripts/bypass-triage.py -p <pkg> --postmortem
python3 -B scripts/bypass-triage.py -p <pkg> --apk target.apk --postmortem
python3 -B scripts/bypass-triage.py -p <pkg> --json base.json
python3 -B scripts/bypass-triage.py -p <pkg> --baseline base.json
adb shell dumpsys activity exit-info <pkg> | head -20
```

### Timing

```bash
frida -U -f <pkg> -l scripts/early-instrument.js --no-pause
frida -U -f <pkg> -l scripts/early-instrument.js -l my-bypass.js --no-pause
frida-trace -U -f <pkg> -i 'JNI_OnLoad' -i 'dlopen*' -i 'android_dlopen_ext'
```

### Find the branch

```bash
frida -U -f <pkg> -l scripts/kill-path-tracer.js --no-pause
# then in the REPL:  kpt.status()   kpt.block()
```

### Seam 1

```bash
# device root
magisk --denylist add <pkg>
resetprop ro.build.tags release-keys
resetprop ro.debuggable 0

# host
adb shell "/data/local/tmp/frida-server -l 127.0.0.1:1337 --directory /data/local/tmp/.x &"
frida -H 127.0.0.1:1337 -f <pkg> -l agent.js --no-pause
```

### Make a control fire (no root) — for testing your own build

```bash
adb reverse tcp:27042 tcp:27042     # real device-side listener; port check fires
adb reverse --remove tcp:27042      # ALWAYS remove it
adb shell am set-debug-app -w <pkg> # JDWP path; clear with --persistent off
adb shell am clear-debug-app
```

### Static

```bash
apktool d -f -o work target.apk
grep -rnE 'TracerPid|/proc/self/(status|maps|task)|27042|frida|gum-js' work/smali*/ | head -40
grep -rnE 'System;->exit|Process;->killProcess|Runtime;->halt' work/smali*/ | head -20
for so in work/lib/*/*.so; do
  strings -a -n 5 "$so" | grep -Ei 'frida|gum|27042|TracerPid|ptrace|/proc/self'
  llvm-readelf --dynamic "$so" | grep -E 'INIT|INIT_ARRAY'
  llvm-readelf --dyn-syms "$so" | grep JNI_OnLoad
done
r2 -A libguard.so -qc 'axt sym.imp.abort'
```

---

## Frida one-liners by seam

```javascript
// S2 native — the default technique
Interceptor.attach(Module.findExportByName('libc.so', 'access'), {
    onEnter: function (a) { this.p = a[0].readUtf8String(); },
    onLeave: function (r) { if (/\/su$|magisk|frida/.test(this.p || '')) r.replace(ptr(-1)); }
});

// S2 Java
Java.use('java.io.File').exists.implementation = function () {
    return /\/su$|magisk/.test(this.getAbsolutePath()) ? false : this.exists();
};

// S2 property
Java.use('android.os.SystemProperties').get.overload('java.lang.String')
    .implementation = function (k) {
        return k === 'ro.build.tags' ? 'release-keys' : this.get(k);
    };

// S3 — call the original first, log what it really concluded, then change it
const G = Java.use('com.x.Guard');
G.evaluate.implementation = function (c) {
    const v = this.evaluate(c);
    console.log('[real] ' + v.score.value);
    v.trusted.value = true; return v;
};

// S4 — suppress the consumer
Java.use('com.x.Guard').enforce.implementation = function (v) { };

// S5 — no bypass, no hook
Java.use('com.x.Vault').openUnchecked();

// anti-debug — ptrace, install before any app library loads
Interceptor.replace(Module.findExportByName('libc.so', 'ptrace'),
    new NativeCallback(function (req) { return req.toInt32() === 0 ? 0 : -1; },
                       'long', ['int', 'int', 'pointer', 'pointer']));
```

---

## Stop-hooking checklist

Go static when **any** is true:

- [ ] The check issues inline syscalls (`svc #0`) — no symbol to attach to
- [ ] The function checksums its own `.text` — your hook is the modification
- [ ] Three rounds in and each round costs more than the last
- [ ] The app dies before the first hook can install, even when spawning
- [ ] You want an **algorithm**, not a **decision**
- [ ] Someone else must reproduce it later, without your Frida session

Then: patch the binary · emulate it (Unicorn / Ghidra) · reimplement it · **or go around and attack
the server.**

---

## Reporting

| Question | If the answer is… | Severity |
|---|---|---|
| What did the control protect? | a screen reachable anyway | INFO |
| | a hardcoded key | depends on what it unlocks |
| | a client-side authorisation | depends on the server |
| Does the server re-verify? | **yes** | resilience finding only — MEDIUM at most |
| | **no** | the real finding is the authorisation flaw |
| What could you do once inside? | nothing new | INFO |
| | forge a signed request the server accepted | HIGH |

Write the resilience weakness and the access it enabled as **two separate findings**.
A valid forged signature proves nothing unless an invalid one is also shown to be rejected.

---

## Clean up

```bash
./examples/build.sh --uninstall
adb reverse --remove-all
adb forward --remove-all
adb shell am clear-debug-app
# device root, if you used seam 1:
magisk --denylist rm <pkg>
# reboot to clear resetprop changes
```

Leave the device as you found it. Seam-1 changes persist and will silently do the work you credit to
your next hook.
