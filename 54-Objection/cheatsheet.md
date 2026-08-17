# 54 — Objection cheat sheet

Dense reference. Measured against **objection 1.11.0**, frida **16.1.6**, frida-server
**16.1.6**, Redmi `M2101K6P`, Android 11 / API 30, arm64.

**Check your own version.** Command names, RPC exports and — above all — *what each canned
script hooks* change between releases:
`python3 -B scripts/split-agent.py --list --filter android`

---

## 1. CLI

| Command | Purpose |
|---|---|
| `objection -g <pkg> explore` | Inject and open the REPL |
| `objection -g <pkg> explore -q` | …without the banner |
| `objection -g <pkg> explore -s "<cmd>"` | Run a command before the prompt appears (repeatable) |
| `objection -g <pkg> explore -c cmds.txt` | Run a newline-separated resource file, then the prompt |
| `objection -g <pkg> explore -S startup.js` | Import and run a Frida script at start-up |
| `objection -g <pkg> explore -a` | Also start the HTTP API server |
| `objection -g <pkg> explore -P ./plugins` | Load plugins from a folder |
| `objection -g <pkg> run <command>` | Run one command and exit |
| `objection -g <pkg> api` | **Headless.** No REPL, HTTP bridge only |
| `objection device-type` | Device name / system / model / version |
| `objection version` | objection's own version |
| `objection patchapk -s app.apk` | Embed frida-gadget, for an unrooted device |
| `objection signapk out.apk` | zipalign + sign with objection's throwaway key |

### Global flags (before the subcommand)

| Flag | Meaning | Default |
|---|---|---|
| `-g, --gadget` | Process name, package name **or PID** to connect to | `Gadget` |
| `-S, --serial` | adb serial — **use it whenever more than one device is attached** | auto |
| `-N, --network` | Connect over TCP instead of USB | off |
| `-h, --host` / `-p, --port` | Frida host/port for `-N` | `127.0.0.1:27042` |
| `-ah` / `-ap` | API server host/port | `127.0.0.1:8888` |
| `-d, --debug` | Verbose, and **keeps the agent source map** so stack traces name real lines | off |

`-g` accepts a PID: the value is passed through `int()` first, and an integer becomes a PID
rather than a process name.

---

## 2. Session hygiene — the four commands that prevent most problems

```bash
python3 -B scripts/objection-doctor.py --serial <serial>   # 1. versions agree?
adb devices -l && adb shell getprop ro.product.model       # 2. WHICH device?
frida-ps -U | head                                         # 3. is the wire up?
adb shell am force-stop <pkg>                              # 4. force SPAWN, not attach
```

Step 4 is not optional. Objection **attaches** if the app is running and **spawns** if it is
not, silently, and the two produce different results.

---

## 3. Generic REPL commands

| Command | Notes |
|---|---|
| `env` | Package name, device, paths |
| `frida` | Agent runtime, arch, **heap size**, Frida version *in the process* |
| `ping` | Liveness. Use it before believing a silent result |
| `jobs list` / `jobs kill <id>` | Every hook you have installed. Your mutation record |
| `import /path/to.js` | Load a hand-written Frida script into the session |
| `evaluate <js>` | Run JavaScript inside the agent |
| `reconnect` | Re-attach to the device |
| `! <shell cmd>` | Run a command on **your host** |
| `commands history` / `save` / `clear` | Session command log |
| `plugin load <path>` | Load an objection plugin |
| `exit` | Unloads jobs and the agent |

Persistent history lives at `~/.objection/objection_history` — every command, every session,
every client. Treat it as engagement data.

---

## 4. `android hooking` — reconnaissance

| Command | Returns |
|---|---|
| `android hooking list classes` | Every **loaded** class. 16,087 in a 3-class app — always filter |
| `android hooking search classes <term>` | Filtered class names. Use your target's package prefix |
| `android hooking list class_methods <fqcn>` | **Exact overload signatures.** The most useful output |
| `android hooking search methods <term>` | Walks classes then methods — slow |
| `android hooking list class_loaders` | Registered ClassLoaders |
| `android hooking list activities` | Manifest-declared Activities |
| `android hooking list services` | Manifest-declared Services |
| `android hooking list receivers` | Manifest-declared receivers — **blind to runtime-registered ones** |
| `android hooking get current_activity` | Foreground Activity and fragment |
| `android hooking generate simple <fqcn>` | Prints Frida hook source — your exit scaffold |
| `android hooking generate class <fqcn>` | A generic hook manager |

**`list` means *loaded*, not *present*.** Drive the app to the screen you care about first.

## 5. `android hooking` — modification

| Command | Flags | Notes |
|---|---|---|
| `android hooking watch class <fqcn>` | `--dump-args --dump-backtrace --dump-return` | Hooks **every** method. Very noisy |
| `android hooking watch class_method <fqcn.m>` | same | **The single most useful command.** No overload filter hooks *all* overloads |
| `android hooking set return_value <fqcn.m> true` | — | **Boolean only.** The body still runs |

`--dump-backtrace` answers *who called this*, which is what reachability arguments need.

`set return_value` does not prevent execution: measured, the method logged `false` internally
while the caller received `true`. Side effects still happen.

---

## 6. `android root` — exactly three hooks

| Command | RPC export | Effect |
|---|---|---|
| `android root disable` | `androidRootDetectionDisable` | the three hooks answer "not rooted" |
| `android root simulate` | `androidRootDetection**Enable**` | the same three answer "rooted" |

### What the three hooks are

| # | Hooked method | Fires when | Under `disable` |
|---|---|---|---|
| 1 | `java.lang.String.contains(String)` | argument is exactly `"test-keys"` | returns `false` |
| 2 | `java.lang.Runtime.exec(String)` | command `endsWith("su")` | throws `IOException("objection anti-root")` |
| 3 | `java.io.File.exists()` | absolute path is **exactly** one of 13 strings | returns `false` |

### The thirteen paths — the complete list

```
/data/local/bin/su                        /system/bin/failsafe/su
/data/local/su                            /system/etc/init.d/99SuperSUDaemon
/data/local/xbin/su                       /system/sd/xbin/su
/dev/com.koushikdutta.superuser.daemon/   /system/xbin/busybox
/sbin/su                                  /system/xbin/daemonsu
/system/app/Superuser.apk                 /system/xbin/su
/system/bin/su
```

Matched with `indexOf(path) >= 0` — **exact string equality**, not a prefix or a pattern.

### What it does NOT cover

`/sbin/magisk` · `/data/adb/magisk` · `/data/adb/modules` · any other path ·
`Runtime.exec(String[])` · `ProcessBuilder` · `PackageManager` queries · `/proc/self/mounts` ·
`/proc/self/maps` · SELinux state · `Settings.Global` · writability tests · RootBeer's native
library · **anything native** · Play Integrity.

### Measured coverage

Against an app with five checks, three inside the envelope: **one of five** could be
influenced. Two "covered" checks did not flip — one because of a bug in the canned hook
(`this.apply(this, arguments)` returns a non-`Process`, so the app gets a
`NullPointerException`), one because the hook was installed after ART had already inlined the
call.

---

## 7. `android sslpinning disable` — exactly seven hooks

| # | Class | Method | Notes |
|---|---|---|---|
| 1 | `javax.net.ssl.SSLContext` | `init(KeyManager[], TrustManager[], SecureRandom)` | substitutes empty `com.sensepost.test.TrustManager` |
| 2 | `okhttp3.CertificatePinner` | `check(String, List)` | no-op |
| 3 | `okhttp3.CertificatePinner` | `check$okhttp(String, **u15**)` | **hard-codes an R8-obfuscated type name.** Usually fails to install |
| 4 | `appcelerator.https.PinningTrustManager` | `checkServerTrusted` | Titanium only |
| 5 | `com.android.org.conscrypt.TrustManagerImpl` | `verifyChain` | **platform** — installs on every app |
| 6 | `com.android.org.conscrypt.TrustManagerImpl` | `checkTrustedRecursive` | **platform** — installs on every app |
| 7 | `nl.xservices.plugins.SSLCertificateChecker` | `execute` | Cordova/PhoneGap only |

`--quiet` suppresses the per-invocation `Called ...` lines — **the only output that
distinguishes a hook that fired from a hook that merely loaded.** Never use it while
investigating.

### Reading the output

| Line | Means |
|---|---|
| `Custom TrustManager ready, overriding SSLContext.init()` | nothing about the app. Always prints |
| `Found com.android.org.conscrypt.TrustManagerImpl, overriding …` | the app is an Android app. Always prints |
| `Found okhttp3.CertificatePinner, overriding …` | **informative** — the app uses OkHttp |
| `Called OkHTTP 3.x CertificatePinner.check(), not throwing an exception.` | **the good one** — the code path actually ran |

**Measured:** all three "always prints" lines appeared against an app with **no network code
at all**. A hook that installs proves a class exists. Only a hook that *fires* proves anything
about the app.

### Not covered

Native/BoringSSL pinning (Flutter, Cronet) · `network_security_config` `<pin-set>` ·
`HostnameVerifier` · **WebView** (inert — see [43](../43-WebView/README.md)) · Certificate
Transparency (Appmattus) · TrustKit · Volley's socket factory · Xamarin · mTLS · an app
bundling its own `org.conscrypt`.

Escalate to [`53-Frida/scripts/ssl-pinning-bypass.js`](../53-Frida/scripts/ssl-pinning-bypass.js) — six layers.

---

## 8. Filesystem — as the app's UID, from inside the app

| Command | Notes |
|---|---|
| `pwd` / `ls` / `cd <dir>` | Starts in the app's private directory |
| `file cat <f>` | Print contents |
| `file download <f> [dest]` | Pull to your host |
| `file upload <local> <remote>` | Push |
| `rm <f>` | Delete |
| `file http start` / `status` / `stop` | On-device HTTP server over the CWD — best for whole directories |

You are neither `adb shell` nor `run-as`: you are the app, so you can read what the app can
read, without root.

Useful paths: `/data/data/<pkg>/shared_prefs/` · `/databases/` · `/files/` · `/cache/` ·
`/no_backup/` · `/data/user_de/0/<pkg>/`

---

## 9. Heap, KeyStore, memory, SQLite, intents, UI

| Command | Notes |
|---|---|
| `android heap search instances <fqcn>` | `Java.choose` — live objects, returns handles. Exact class only |
| `android heap print fields <handle>` | Instance fields |
| `android heap print methods <handle>` | `--without-arguments` for brevity |
| `android heap execute <handle> <method>` | `--return-string` |
| `android heap evaluate <handle> <js>` | Arbitrary JS on the handle |
| `android keystore list` | AndroidKeyStore aliases — **an alias is not key material** |
| `android keystore watch` | Report KeyStore usage |
| `android keystore clear` | **DESTRUCTIVE. No prompt. No undo.** |
| `memory list modules` | Loaded native modules (309 in a trivial app) |
| `memory list exports <module>` | `--json` |
| `memory search <pattern>` | `--string`, `--offsets-only` |
| `memory write <addr> <bytes>` | `--string`. Dangerous |
| `memory dump all <file>` | Whole address space. Large and slow |
| `memory dump from_base <addr> <len> <file>` | Targeted — feed to [Ghidra](../57-Ghidra/README.md) |
| `sqlite connect <file>` | Downloads a **copy**, opens litecli. `--sync` writes back |
| `android intent launch_activity <fqcn>` | Re-trigger a code path with hooks already in place |
| `android intent launch_service <fqcn>` | |
| `android shell_exec <cmd>` | Runs as the app's UID |
| `android deoptimize` | Force the interpreter — fixes some inlining failures |
| `android proxy set <host> <port>` | Per-app proxy |
| `android ui screenshot <f>` / `android ui FLAG_SECURE <bool>` | |
| `android clipboard monitor` | |

**`sqlite connect` misses the WAL.** [33-Storage](../33-Storage/README.md) measured deleted
secrets surviving in a `-wal` file. For a storage assessment, `file download` the `.db`, `-wal`
**and** `-shm`, and read the files.

---

## 10. Headless / API mode

```bash
objection -S <serial> -g <pkg> api          # then, from another shell:
curl -s     http://127.0.0.1:8888/rpc/invoke/envFrida                    # no args -> GET
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"c":"com.example.Auth"}' \
     http://127.0.0.1:8888/rpc/invoke/androidHookingGetClassMethods      # args   -> POST
```

| Rule | Why |
|---|---|
| Endpoint = **RPC export name**, not the command | `android root simulate` is `androidRootDetectionEnable` |
| `GET` for no-argument methods | a `POST` body of `{}` is rejected: *"POST request without a valid body received"* |
| JSON **keys are ignored** | the handler does `getattr(rpc, m)(*post_data.values())` — position only |

### Export names you will actually use

| Command | Export |
|---|---|
| `env` | `envAndroid` |
| `frida` | `envFrida` |
| `android root disable` / `simulate` | `androidRootDetectionDisable` / `androidRootDetectionEnable` |
| `android sslpinning disable` | `androidSslPinningDisable` |
| `android hooking list classes` | `androidHookingGetClasses` |
| `android hooking list class_methods` | `androidHookingGetClassMethods` |
| `android hooking watch class_method` | `androidHookingWatchMethod` (`fqClazz, filterOverload, dargs, dbt, dret`) |
| `android hooking set return_value` | `androidHookingSetMethodReturn` (`fqClazz, filterOverload, ret`) |
| `android heap search instances` | `androidHeapGetLiveClassInstances` |
| `memory list modules` | `memoryListModules` |
| `jobs list` | `jobsGet` |

---

## 11. No root — `patchapk`

| Flag | Meaning |
|---|---|
| `-s, --source` | the APK (required) |
| `-a, --architecture` | force the ABI instead of detecting it |
| `-V, --gadget-version` | pin the gadget version |
| `-d, --enable-debug` | set `android:debuggable="true"` |
| `-N, --network-security-config` | inject a config trusting user CAs |
| `-t, --target-class` | the class whose `<clinit>` gets the loader |
| `-c` / `-l` | gadget config file / script file (script mode) |
| `-D, --skip-resources` | skip apktool resource decoding — **requires `-n`**, excludes `-d` and `-N` |
| `-n, --ignore-nativelibs` | leave `extractNativeLibs` alone |
| `-k, --skip-cleanup` / `-p, --pause` | keep temp files / pause before rebuild |

```bash
objection patchapk -s app.apk
adb install -r app.objection.apk        # uninstall the original first: signature changed
objection -g Gadget explore             # NOT the package name
```

**Costs:** signature changes → self-signature checks fire ·
Play Integrity fails · signature-derived pinning breaks · splits must all be handled ·
most failures are **apktool** failures on a resource, not Frida failures.

---

## 12. Version skew — three relationships

| Relationship | Enforced by | Symptom |
|---|---|---|
| objection → frida (Python) | pip (`frida>=14.0.0`) | install refuses / `ImportError` at start-up |
| frida → frida-server | wire protocol, **MAJOR must match** | `unable to communicate with remote frida-server; please ensure that major versions match` |
| `agent.js` → server JS API | **nothing** | connects fine, then commands throw individually |

| objection | frida | frida-server | Outcome |
|---|---|---|---|
| 1.11.0 | 16.1.6 | 16.1.6 | **works — measured** |
| 1.11.0 | 16.x | 16.y | expected to work (same major) |
| 1.11.0 | 16.x | 17.x | fails at connect |
| 1.11.0 | 17.x | 17.x | connects, then fails per command |
| 1.12.x | 17.x | 17.x | works |
| any | 16.x | 16.x, wrong ABI | fails at inject |

**`Agent injected and responds ok!` does NOT mean your versions are compatible.**
Pin all three. Derive the server version from `frida --version`, never the reverse.
Ignore the upgrade banner mid-engagement.

---

## 13. The four failure modes

| # | Symptom | Test | Fix |
|---|---|---|---|
| 1 | No `Agent injected…` line | `frida-ps -U` | root/gadget, versions, ABI, SELinux |
| 2 | Command errors, or a `Found …` line missing | is the class in the APK? (jadx) | drive the app further, or the library is absent |
| 3 | Success reported, nothing happens | `am force-stop`, reconnect | force a spawn |
| 4 | Success reported, nothing happens, *after* a force-stop | read `agent.js` | **exit** — write the hook |

3 and 4 look identical from Objection's output. `force-stop` and reconnect separates them.

---

## 14. Reading your own agent

```bash
python3 -B scripts/split-agent.py --out /tmp/am           # split the bundle
python3 -B scripts/split-agent.py --list --filter android # just the map

grep -n '"/'                      /tmp/am/*android_root*.js     # the hard-coded paths
grep -oE 'Java\.use\("[^"]+"\)'   /tmp/am/*pinning*.js | sort -u # classes the bypass knows
grep -oE '^\s+android[A-Za-z]+:'  /tmp/am/*rpc_android*.js       # every callable export
```

---

## 15. Honest severity

| Observation | Finding? |
|---|---|
| `root disable` and the app stops complaining | **No.** The protection is Java-layer and conventional |
| `sslpinning disable` and traffic flows | **No.** Expected property of a control on an attacker-owned device |
| `set return_value true` and you get in | **Only if the server does not re-check** |
| `file download` retrieved a token | **Depends on reachability** |
| `keystore list` showed aliases | **No.** Aliases are not key material |
| The app crashed on injection | **No.** You broke it |

There is no arrow from OBSERVE to REPORT. Never paste Objection output into a findings table.

---

## 16. When to stop

Stop the moment you need to know **why**. Also: a hook Objection lacks · a non-boolean return ·
a specific overload or classloader · reproducibility · an app that fights back.

Then: `android hooking list class_methods` for the signatures →
`android hooking generate simple` for the scaffold → an editor →
[53-Frida](../53-Frida/README.md).
