# 67 — Examples

Two applications, one difference. Build both, attack both, and the chapter's argument becomes a
measurement rather than an opinion.

**These are targets you build. They exist so that every technique in this chapter can be practised
without touching software you do not own.** See
[README §1.3](../README.md#13-scope-and-ethics-stated-once-and-precisely).

---

## What is here

| Path | What it is |
|---|---|
| [`build.sh`](build.sh) | Builds all three APKs with no Gradle, out of tree. Read its header before running it |
| [`guarded-app/`](guarded-app/) | Every decision taken on the device. Four tiers, seven signals, six responses |
| [`server-app/`](server-app/) | The same seven checks, with the decision moved to a server. The control group |

Nothing here ships a built artefact. `.apk`, `.dex`, `.class` and `.so` are on the repository's
blocklist, and `build.sh` writes everything into `$OUTDIR` (default: a temp directory) so that
nothing lands next to the sources.

---

## `guarded-app` — the over-protected target

```
guarded-app/
  AndroidManifest.xml    one attribute is patched at build time to make the debuggable variant
  MainActivity.java      the timeline: native tier, then Java tier, then the gate
  Guard.java             the pipeline written out longhand: reads, verdict, branch, response
  NativeGuard.java       the Java side of the native tier
  Vault.java             the gated code, with three doors into the same secret
  native_guard.c         .init_array constructor + JNI_OnLoad + the reporting surface
```

### The five seams, mapped to files

| Seam | Where it lives |
|---|---|
| **S1 — input** | The device. `Guard.SU_PATHS`, port 27042, the manifest's `debuggable` attribute |
| **S2 — read** | `Guard.check*()` (Java) and `native_guard.c`'s `stat`/`fopen`/`connect` calls |
| **S3 — verdict** | `Guard.evaluate()` → a `Verdict` with a score and a list of signals |
| **S4 — branch** | `Guard.enforce()` — one `if` |
| **S5 — gated code** | `Vault.open()` (checked) and `Vault.openUnchecked()` (not) |

### The seven signals

| id | Seam it reads at | Weight | Response policy | Fires honestly without root? |
|---|---|---|---|---|
| `debugger.jdwp` | S2 | 60 | `EXIT_SELF` (42) | Yes, with `am set-debug-app` + a jdb attach |
| `build.debuggable` | S1 | 55 | `NATIVE_ABORT` | **Yes** — build the debuggable variant |
| `debugger.tracerpid` | S2 | 60 | `THROW` | Only with a live ptrace |
| `frida.port27042` | S1 | 50 | `SIGKILL_SELF` | **Yes** — `adb reverse tcp:27042 tcp:27042` |
| `frida.threadnames` | S2 | 70 | `SIGKILL_SELF` | No — needs a live agent |
| `frida.maps` | S2 | 70 | `POISON` | No — needs a live agent |
| `root.su` | S1 | 40 | `EXIT_SELF` (42) | No — needs root |

Deny threshold: **50**. Any single signal except `root.su` is enough on its own.

### Why six different responses

A real app picks one. This app picks six because **the death signature is the only evidence a triager
has** when the process dies before it can be asked anything, and the six are genuinely
distinguishable in `dumpsys activity exit-info`. Measured on an i9000S, Android 13 / API 33:

| Response | `reason` | `status` | Lifecycle reached |
|---|---|---|---|
| `abort()` in `JNI_OnLoad` | 5 CRASH_NATIVE | 6 SIGABRT | **none** |
| `abort()` called from Java | 5 CRASH_NATIVE | 6 SIGABRT | full |
| `System.exit(42)` | 1 EXIT_SELF | 42 | full |
| `Process.killProcess(myPid())` | 2 SIGNALED | 9 SIGKILL | full |
| `throw`, caught by the caller | *(no record)* | — | full |
| `POISON` | *(no record)* | — | full |

[`../scripts/bypass-triage.py`](../scripts/bypass-triage.py) decodes all six.

### The lab harness, stated plainly

Two of the seven signals can be made to fire honestly on a stock unrooted phone; the other five
cannot. So the app accepts an explicitly labelled simulation:

```bash
# host — mark a signal as fired without changing what the read returned
adb shell am start -n com.pentest.ch67.guarded/.MainActivity \
    --ez auto_open true --es simulate frida.threadnames
```

This is the app lying to itself so that a reader without root can learn the death signatures. It is
**not** a bypass, it is not how any lab defeats any control, and the chapter states for every
measurement whether a real trigger or a simulation produced it. The full explanation is in the
javadoc on `Guard.evaluate(Context, String)`.

`--ez auto_open true` is a scripting affordance: it takes the same checked path the button takes, so
that labs can be reproduced from a shell script.

### The correct output

```
SECRET: CH67{cl13nt_s1d3_b00l3an_1s_n0t_a_l0ck}
```

Write it down before you start. You cannot recognise a poisoned session without it — the `POISON`
response returns `ch[CLNTSDBLANSNTALCK]` and reports no error.

---

## `server-app` — the control group

```
server-app/
  AndroidManifest.xml    same permissions as the guarded app, so only ONE thing differs
  MainActivity.java      runs the same checks; reports them; asks the server
  server.py             the reference decision server, written to be read
```

The client performs the same reads. It does not decide anything. It POSTs a self-report and the
response body either contains the secret or does not.

```bash
# host — terminal 1
python3 -B examples/server-app/server.py

# host — terminal 2
adb reverse tcp:8767 tcp:8767
OUTDIR=/tmp/ch67 ./examples/build.sh --install-server
adb shell am start -n com.pentest.ch67.server/.MainActivity

# host — when finished
adb reverse --remove tcp:8767
```

The app has two buttons: an honest report and a deliberately forged clean one. **Both get the
secret**, and that is the lesson — the self-report was never load-bearing. `server.py` logs the
forgery as telemetry and gates on a nonce it issued itself.

Read `handle_unlock()` in [`server.py`](server-app/server.py). Its three commented blocks are the
whole argument:

1. what a naive server does with the client's self-report, and why it is worthless;
2. what actually gates the response — a nonce the client cannot forge, hook or patch;
3. why the response carries the **capability** (the data) and not the **permission** (a boolean).

### What to try against it

Every technique in this chapter. Hook `collect()`, flip every boolean, patch the branch, call the
gated code directly, search the DEX for the flag. None of them produces the secret, because the
secret is not on the device.

Then move to the questions that *do* apply: is the nonce single-use, does the endpoint authenticate,
does it send a capability or a permission? `server.py`'s comments say which of those it defends and
which it explicitly does not.

---

## Building

```bash
# host
export ANDROID_HOME=~/Android/Sdk
OUTDIR=/tmp/ch67 ./build.sh                     # build all three, install nothing
OUTDIR=/tmp/ch67 ./build.sh --install           # + install the release guarded app
OUTDIR=/tmp/ch67 ./build.sh --install-debuggable
OUTDIR=/tmp/ch67 ./build.sh --install-server
OUTDIR=/tmp/ch67 ./build.sh --uninstall
```

**Requirements:** an Android SDK with build-tools (`aapt2`, `d8`, `zipalign`, `apksigner`) and one
platform `android.jar`; a JDK with `javac` and `keytool`; `python3`; `adb`. An NDK is **optional** —
without it the native tier is simply absent, and the app reports `native tier absent`, which is a
state the labs deliberately ask you to recognise.

Built and verified on: build-tools 35.0.1, `android-35`'s `android.jar`, JDK 24, NDK 25.2.9519653
(`aarch64-linux-android21-clang`, compiled clean with `-Wall -Wextra`).

**On Git Bash / MSYS**, the SDK tools are native Windows binaries and do not understand `/c/Users/…`
paths. `build.sh` runs every path through `cygpath -w`; without that, `aapt2` reports "failed to load
XML file" on a file that plainly exists.

**If `adb install` fails with `INSTALL_FAILED_USER_RESTRICTED`**, that is an OEM "Install via USB"
policy rather than a fault in the APK. `build.sh` detects that specific failure and falls back to a
root install.

---

## A measured bug worth keeping

The first build of `guarded-app` ran its socket probe on the main thread. StrictMode threw
`NetworkOnMainThreadException` and the app died during `onCreate` with `reason=4 CRASH` — **before
any control had decided anything**.

That failure is preserved as a comment in `Guard.checkFridaPort()` and used as a lab exercise,
because it is the single most useful negative result in the chapter: **an app can die for reasons
that have nothing to do with its protections, and a triage tool that assumes every early death is a
control is wrong.** Read the stack before you believe the exit reason.

---

## Cleaning up

```bash
# host
OUTDIR=/tmp/ch67 ./build.sh --uninstall
adb reverse --remove-all
adb shell am clear-debug-app
```

Both apps are deliberately weak. Do not leave them installed on a phone you use.
