# 76 — Cheat Sheets · The sheet of sheets

Printable. No prose. Every command was executed in the form shown, on
`sdk_gphone16k_x86_64` (Android 15 / API 35, `userdebug`, Magisk 30.7), unless tagged `unrun`.
See [README.md](README.md) for why each of these is here.

**Needs:** `any` = uid 2000 · `dbg` = target is `android:debuggable` · `root` · `sig` = signed with
the target's key · `host`
**Device:** `all` · `avd` · `avd≠` differs on an emulator · `phys` needs a real device · `unrun`

---

## Start of every session — four commands

```bash
# host
adb devices -l                                  # which device, and is there exactly one
adb shell getprop ro.build.version.sdk          # API level
adb shell "su 0 id"                             # root, AOSP/AVD form -> uid=0(root)
adb shell "sh -c 'echo A; echo B'"              # quoting works -> prints A then B
```

If line 3 prints `su: invalid uid/gid '-c'` you used the other form. If line 4 prints only `B`, your
quoting is being eaten and every compound command today will lie to you.

---

## The five shell rules

| Rule | Wrong | Right |
|---|---|---|
| Quote the whole device command | `adb shell sh -c '…'` <!-- lint:allow --> | `adb shell "sh -c '…'"` |
| `adb` in a loop eats stdin | `while read x; do adb shell …; done` | `… adb shell … < /dev/null; done` |
| `pipefail` + early-exit consumer | `set -o pipefail` … `\| head` / `\| grep -q` | `grep -c`, `case` glob, or no `pipefail` |
| Trust content, not status | `adb devices && …` | `adb devices \| sed -n '2,$p' \| grep -c 'device$'` |
| Quote device paths (Git Bash) | `adb shell ls /sdcard/` <!-- lint:allow --> | `adb shell 'ls /sdcard/'` |

Measured exits: `yes \| head -3` under `pipefail` → **141**. `seq 1 100000 \| grep -q 5` → **141**.
`grep -c` → **0**.

MSYS rewrote every Android top-level path tested (`/system /data /dev /sdcard /apex /storage /vendor
/product /odm /oem /mnt /cache`) and passed **`/proc`** through unchanged — which is why half a
sheet works unquoted and half does not.

---

## Device posture

| Command | Needs | Device |
|---|---|---|
| `adb devices -l` | `host` | `all` |
| `adb shell getprop ro.product.model` | `any` | `all` |
| `adb shell getprop ro.build.version.release` | `any` | `all` |
| `adb shell getprop ro.build.version.sdk` | `any` | `all` |
| `adb shell getprop ro.build.type` | `any` | `all` |
| `adb shell getprop ro.build.fingerprint` | `any` | `all` |
| `adb shell getenforce` | `any` | `all` |
| `adb shell getconf PAGE_SIZE` | `any` | `avd≠` — 16384 here; 4096 on most phones |
| `adb shell "mount \| grep cacerts"` | `any` | `all` — do this before any trust-store claim |
| `adb shell "dumpsys trust" \| grep -o "deviceLocked=[01]"` | `any` | `all` |

## Root

| Command | Needs | Device |
|---|---|---|
| `adb shell "su 0 id"` | `root` | `all` — AOSP `su`, every userdebug build, every AVD |
| `adb shell "su -c id"` | `root` | `phys` — Magisk `su` on a phone; **fails on AOSP `su`** <!-- lint:allow --> |
| `adb shell "su 0 /debug_ramdisk/magisk -v"` | `root` | `avd` — `30.7:MAGISK:R`. Bare `magisk` is not on root's `PATH` |
| `adb shell "grep -c magisk /proc/self/mountinfo"` | `any` | `all` — returned **3** from shell, root and app |
| `adb shell "su 0 ls /data/adb/modules"` | `root` | `all` |

---

## Vantage — the same probe, three heights

```bash
# host — from 76-CheatSheets/
bash scripts/vantage.sh --posture --pkg <debuggable-pkg>
bash scripts/vantage.sh --file /system/xbin/su --pkg <debuggable-pkg>
bash scripts/vantage.sh --cmd 'getprop | wc -l' --pkg <debuggable-pkg>
```

| Probe | shell (2000) | root | app uid |
|---|---|---|---|
| `ls -l /system/xbin/su` | readable | readable | **Permission denied** |
| `test -e /system/xbin/su` | EXISTS | EXISTS | **NOT-VISIBLE** |
| `getprop \| wc -l` | **678** | **1062** | **638** |
| `getprop \| grep -c ro.boottime` | **0** | **111** | **0** |
| `grep -c magisk /proc/self/mountinfo` | 3 | 3 | 3 |
| `getprop ro.kernel.qemu` | 1 | 1 | 1 |

Three identical columns = a signal that needs no privilege = a **better** check.
`run-as` needs `FLAG_DEBUGGABLE` **and** an application uid.

| `run-as` refusal | Means |
|---|---|
| `package not debuggable` | Not debuggable |
| `package not an application` | Debuggable **system** app — a different condition |

---

## Task: APK and one hour

```bash
# host
sha256sum app.apk
aapt2 dump badging app.apk | grep -E 'package|sdkVersion|targetSdkVersion|uses-permission'
aapt2 dump xmltree app.apk --file AndroidManifest.xml | grep -B4 exported
unzip -p app.apk res/xml/network_security_config.xml
unzip -l app.apk | grep -E 'classes.*dex|lib/'
adb install app.apk
adb shell "dumpsys package <pkg>" | grep -E 'flags=\[|targetSdk|versionName'
adb shell "run-as <pkg> ls -laR ."
jadx -d out app.apk          # LAST, not first
```

Order matters: steps 2–3 and 7 are ten minutes and hold most writeable findings; `jadx` is where the
hour disappears.

| Step | Needs | Device |
|---|---|---|
| `aapt2 dump …` | `host` | `all` |
| `adb install` | `any` | `avd≠` — OEM builds return `INSTALL_FAILED_USER_RESTRICTED`; root path works. `unrun` |
| `dumpsys package` | `any` | `all` |
| `run-as` | `dbg` | `all` |

---

## Task: unrooted device

| Want | Do | Needs |
|---|---|---|
| App private data | `adb shell "run-as <pkg> tar czf - ." > data.tgz` | `dbg` |
| Shell as the app | `adb shell run-as <pkg> sh` | `dbg` |
| Frida in-process | Repackage with the **Gadget** — no server | `host` |
| Hooks without repackaging | `am instrument`, test APK signed with the **target's** key | `sig` |
| Query a provider | `adb shell content query --uri content://<auth>/<path>` | `any` |
| Fire a component | `adb shell am start -S -n <pkg>/<cls>` | `any` |
| Host listener from device | `adb reverse tcp:8080 tcp:8080` | `any` |

`am instrument` gate: **the signing relationship, or root.** `android:debuggable` plays no part.
`android:testOnly` is defeated by `adb install -t`.

---

## Task: only an emulator

| Question | AVD answer | Why it misleads |
|---|---|---|
| Verified boot state | `ro.boot.verifiedbootstate` = **empty string** | `!"orange".equals(s)` → **true**; check passes |
| Hardware-backed key | every key `SOFTWARE`, `hardwareEnforced` empty | **the chain still verifies** |
| Anything fastboot | no bootloader, no `misc`/`boot`/`recovery` | `adb reboot bootloader` returns to Android in ~40 s |
| `su` form | `su 0 <cmd>` | `su -c` → `su: invalid uid/gid '-c'` |
| Page size | 16384 | naive NDK binary exits **139** — `-Wl,-z,max-page-size=16384` |
| `frida-server` | present, **does not link** | `CANNOT LINK EXECUTABLE … DT_HASH/DT_GNU_HASH` |

Emulator heuristics measured **dead or inverted** on a stock current AVD:

```bash
# host
adb shell getprop ro.build.fingerprint     # google/sdk_gphone16k_x86_64/... -- NOT "generic"
adb shell 'ls /dev/qemu_pipe'              # No such file or directory
adb shell 'ls /dev/goldfish_pipe_dprctd'   # present -- the node moved
adb shell getprop ro.kernel.qemu           # 1 -- still works, from all three vantages
```

---

## Task: the app detects my hook

| # | Step |
|---|---|
| 1 | Confirm hooks land **somewhere else** first — is it detection or is it your tooling? |
| 2 | `adb logcat -d \| grep -i <pkg>` — the app usually says |
| 3 | Enumerate checks statically before hooking |
| 4 | `frida-trace -U -i "open*" -f <pkg>` — find the seam: Java, JNI or syscall |
| 5 | Only now hook |

| A "working" bypass changes nothing because | Evidence |
|---|---|
| The compiler **inlined** the target — zero call sites | hook installs, verifies, no effect |
| The patched copy is called by nothing | patched fn provably returns 1; check still fails |
| `objection android root disable` = 3 hooks, 13 paths | coverage **1 of 5** |
| `sslpinning disable` hooks **platform** classes | reported 3 successes vs an app with **no network code** |

---

## Task: see the traffic

Stop at the first layer that explains the silence.

| Layer | Check |
|---|---|
| 0 | Is there traffic at all? A void run and a clean negative look identical |
| 1 | Proxy reachable from the device |
| 2 | Trust store — **and `mount \| grep cacerts` first** |
| 3 | `network_security_config`: `cleartextTrafficPermitted`, `trust-anchors`, `<pin-set>` |
| 4 | `TrustManager` / `HostnameVerifier` overrides in code |
| 5 | Library pinning — OkHttp, Conscrypt, **BoringSSL inside Flutter** |
| 6 | Not HTTP — raw socket, gRPC, MQTT, WebSocket |

---

## Task: prove this finding

| # | Question |
|---|---|
| 1 | Who is the attacker, concretely? |
| 2 | What do they start with? |
| 3 | Does it reproduce **from an app uid**, not `adb shell`? |
| 4 | Does the server compensate? |
| 5 | Business impact in one sentence? |

A sweep produces **leads**. Measured funnels: 16,836 → 168 → 2 · 7,346 → 9 → 2 · 132 hits → **132
false positives**. One HIGH band adjudicated by hand: **15 of 17 rejected**, best finding at MEDIUM.

---

## Task: nothing works

| # | Check | Command |
|---|---|---|
| 1 | Device attached, and which | `adb devices -l` |
| 2 | Frida on the right device | `frida-ls-devices` |
| 3 | Quoting survived | `adb shell "sh -c 'echo A; echo B'"` |
| 4 | `su` form | `adb shell "su 0 id"` |
| 5 | Process alive | `adb shell pidof -s <pkg>` |
| 6 | Probe racing the target | wait on an **exit** marker, not an entry one |
| 7 | Screen locked | `adb shell "dumpsys trust" \| grep -o "deviceLocked=[01]"` |
| 8 | Pipeline lying | drop `pipefail`, or `grep -c` |

---

## Package, APK, storage, logs

| Command | Needs | Device |
|---|---|---|
| `adb shell pm list packages -3` | `any` | `all` |
| `adb shell pm path <pkg>` | `any` | `all` — returns **every** split |
| `adb shell dumpsys package <pkg>` | `any` | `all` — the authority when tools disagree |
| `adb pull <path> base.apk` | `any` | `all` |
| `adb shell "run-as <pkg> ls -laR ."` | `dbg` | `all` |
| `adb shell "su 0 ls -di /data/data /data/user/0"` | `root` | `all` — same inode: **bind mount** |
| `adb shell "ls /data/user_de/0/<pkg>"` | `root` | `all` |
| `adb logcat -c` then `adb logcat -d -t 200` | `any` | `all` |
| `adb shell pidof -s <pkg>` | `any` | `all` |
| `adb shell am start -S -n <pkg>/<cls>` | `any` | `all` — **`-S` is not optional** |
| `adb shell content query --uri content://<auth>/<path>` | `any` | `all` |
| `adb shell service list` | `any` | `all` |
| `adb shell dumpsys activity broadcasts` | `any` | `all` — extras are stored **cleartext** |

---

## Corrections — the obvious command lies

| Obvious move | Actually | Instead |
|---|---|---|
| `adb shell su -c 'cmd'` <!-- lint:allow --> | `su: invalid uid/gid '-c'` — reads as *not rooted* | `adb shell "su 0 cmd"` |
| `su -c 'magisk -v'` <!-- lint:allow --> | `-v` eaten by **`su`**; prints *su's* version | `su 0 /debug_ramdisk/magisk -v` |
| `su 0 magisk -v` | `failed to exec magisk` — not on root's `PATH` | absolute path |
| `adb shell sh -c 'a; b'` <!-- lint:allow --> | prints nothing for `a`, then `b`, exit 0 | `adb shell "sh -c 'a; b'"` |
| `pipefail` + `\| head` / `\| grep -q` | **141** on success | `grep -c` |
| `adb` in a `while read` loop | one row of N, exit 0 | `< /dev/null` |
| `frida-ps -U` works ⇒ Frida works | it enumerates **over adb**, no server needed | prove with an actual attach |
| `new File("/system/xbin/su").exists()` | **false** from an app on a rooted device | `/proc/self/mountinfo` |
| `FINGERPRINT.startsWith("generic")` | **false** on a stock AVD | populations and structure |
| `/dev/qemu_pipe` | `ENOENT` — node moved | enumerate, do not assume |
| probe from `adb shell` | 678 vs app 638 vs root 1062 | run it as the app |
| `!"orange".equals(vbstate)` | property is **empty** → check passes | test for absent too |
| `readlink /data/user/0` | nothing — it is a **bind mount** | `ls -di`, compare inodes |
| `grep -rn FLAG_SECURE` in release code | nothing — folded to `0x2000` (= 8192) | search the constant, or hook `setFlags` |
| `grep -i xposed` | 1,141 hits, **all** "exposed", 0 genuine | never a token under ~8 chars |
| `executeShellCommand("a \| b")` <!-- lint:allow --> | **not a shell**, and runs as uid 2000 | `executeShellCommand("sh -c '…'")` |
| `am start` twice, different extras | `filterEquals` ignores extras | `am start -S` |
| `getCallingUid()` in `onBind` | returns the **service's own** uid | check in the transaction |
| "only debuggable apps instrument" | gate is the **signing relationship**, or root | compare signing certs |
| `TracerPid` detects the debugger | **JDWP does not set it** | it detects `ptrace` |
| `ls -l *.apk` shows shrinking | 3 APKs **byte-identical** (signing-block padding) | compare the DEX |
| jadx `errors, count: 61` | tree held **2,104** refused methods | count the tree |
| query the DB | deleted rows survive in the **`-wal`** | read the files |
| valid attestation chain | on an emulator every key is `SOFTWARE` | assert on contents |
| `ro.boot.verifiedbootstate` | said `green` while the TEE said `Unverified` | the hardware, not the property |
| `--disable-verity` is honoured | flips one byte **inside** the AVB-hashed region | it is a corruption |
| `fastboot devices` silent ⇒ broken | **silence is success**, exit 0 | test content |
| `adb reboot bootloader` on an AVD | returns to Android in ~40 s | no bootloader exists |
| `lpdump` | `Failed to read metadata.` as root | `dmctl table` |
| `objection android root disable` | 1 of 5 checks | find the check first |
| "sslpinning disable succeeded" | a hook installed, nothing more | not evidence the app pinned |
| `classes.dex` CRC detects repackaging | CRC identical after re-signing | check the signing certificate |
| `adb shell ls /sdcard/` on Git Bash <!-- lint:allow --> | MSYS rewrites it to `C:/Program Files/Git/sdcard/` | quote it, or `MSYS_NO_PATHCONV=1` |

---

## The repo's own defect, measured

```bash
# host — from 76-CheatSheets/
python3 -B scripts/lint-commands.py --self-test        # 38 cases, 0 failures
python3 -B scripts/lint-commands.py --only-sheets --path ../
python3 -B scripts/lint-commands.py --format md --summary-only --no-fail \
    --out references/lint-report.md
```

| `su -c` form in repo markdown | Count |
|---|---:|
| `adb … shell "su -c …` | 283 |
| `adb … shell su -c …` | 79 |
| `adb … shell 'su -c …` | 13 |
| `adb … shell \"su -c …` | 1 |
| **Total** | **376** across **146** files |
| Unexplained | **0** |

The repository's original sweep for this defect was a hand-written `Select-String` one-liner whose
pattern required `su` to follow `shell` with nothing between, so it saw only the 79 — about 25% of
the defect, and it reported the total as "~105–118 broken command lines". A detector's blind spot is
invisible in its output; close the arithmetic instead.

---

## Rebuild the generated parts

```bash
# host — from 76-CheatSheets/
python3 -B scripts/build-cheatsheet-index.py --by chapter
python3 -B scripts/build-cheatsheet-index.py --by task
python3 -B scripts/build-cheatsheet-index.py --by tool
python3 -B scripts/build-cheatsheet-index.py --stats
python3 -B scripts/build-cheatsheet-index.py --check          # exit 1 if a chapter lost its sheet
python3 -B scripts/build-cheatsheet-index.py --verify-links   # must print 0 broken
```

| Measured 2026-08-16 | |
|---|---:|
| Sheets | 78 |
| Lines across sheets | 29,189 |
| H2 sections | 1,198 |
| Fenced blocks | 747 |
| Links emitted | 1,628 |
| Broken | **0** |

---

## Where to go next

| Need | Go |
|---|---|
| The right chapter's sheet | [`references/cheatsheet-index.md`](references/cheatsheet-index.md) |
| A sheet for the task | [`references/cheatsheet-index-by-task.md`](references/cheatsheet-index-by-task.md) |
| A sheet for the tool | [`references/cheatsheet-index-by-tool.md`](references/cheatsheet-index-by-tool.md) |
| The full command surface | [`77-UsefulCommands`](../77-UsefulCommands/cheatsheet.md) |
| A word you do not know | [`79-Glossary`](../79-Glossary/README.md) |
| Version matrix, severity, templates | [`80-Appendix`](../80-Appendix/README.md) |
