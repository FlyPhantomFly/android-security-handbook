# 76 — Cheat Sheets · References

Annotated. The first section is generated and must not be hand-edited; everything below it is a
pointer to the source of a claim made in [`../README.md`](../README.md) or
[`../cheatsheet.md`](../cheatsheet.md).

---

## Generated in this directory — do not edit by hand

Each carries a `GENERATED FILE` header and is overwritten by the next run of the generator. If one is
wrong, fix [`../scripts/build-cheatsheet-index.py`](../scripts/build-cheatsheet-index.py) and re-run.
Patching output leaves the next run to recreate the defect — which is exactly how 1,495 broken links
survived in this repository once.

| File | What it is | Rebuild with |
|---|---|---|
| [`cheatsheet-index.md`](cheatsheet-index.md) | Every H2 section of every chapter's `cheatsheet.md`, by chapter, each one linked | `--by chapter` |
| [`cheatsheet-index-by-task.md`](cheatsheet-index-by-task.md) | The same sheets routed by what the reader is doing — the one hand-curated layer, held in the generator's `TASKS` table | `--by task` |
| [`cheatsheet-index-by-tool.md`](cheatsheet-index-by-tool.md) | A mechanical census of tool names inside fenced code blocks: which sheet documents which tool, and how often | `--by tool` |
| [`lint-report.md`](lint-report.md) | Dated snapshot of the command lint over the repository's markdown. **Summary only** — the per-finding table is deliberately omitted, because it would quote hundreds of broken command forms back into the repository | `lint-commands.py --format md --summary-only` |

```bash
# host — from 76-CheatSheets/
python3 -B scripts/build-cheatsheet-index.py --by chapter
python3 -B scripts/build-cheatsheet-index.py --by task
python3 -B scripts/build-cheatsheet-index.py --by tool
python3 -B scripts/build-cheatsheet-index.py --verify-links      # must print 0 broken
python3 -B scripts/lint-commands.py --self-test                  # must print 0 failures
python3 -B scripts/lint-commands.py --format md --summary-only \
    --no-fail --out references/lint-report.md
```

> **Relative-link depth.** A file in this directory is **two** levels below the repository root.
> A link to another chapter is `../../NN-Chapter/…`, never `../NN-Chapter/…`. Every emit site in the
> generator uses one module constant for this, and `--verify-links` resolves every emitted path
> against the filesystem rather than trusting it. It found 58 broken links on its first run.

---

## Scripts in this chapter

| Script | Purpose | Executed? |
|---|---|---|
| [`../scripts/build-cheatsheet-index.py`](../scripts/build-cheatsheet-index.py) | Builds the three routers; `--stats`, `--check`, `--verify-links` | **Yes** — 78 sheets parsed, 1,628 links emitted, 0 broken |
| [`../scripts/lint-commands.py`](../scripts/lint-commands.py) | Eight rules for measured-broken command forms; `--self-test`, `--only-sheets` | **Yes** — 38/38 self-test cases pass; 787 markdown files scanned |
| [`../scripts/vantage.sh`](../scripts/vantage.sh) | One probe from `shell`, `root` and an app uid on an attached device | **Yes** — on `sdk_gphone16k_x86_64`, API 35, with a debuggable package |

---

## Where each measured claim in this chapter comes from

Claims re-measured in this session, on the AVD recorded in [`../README.md`](../README.md) §2, are
marked **here**. The rest are cited from the chapter that measured them, with the device and method
recorded there.

### Measured here, 2026-08-16, on `sdk_gphone16k_x86_64` (API 35, `userdebug`, Magisk 30.7)

| Claim | Command that produced it |
|---|---|
| `su` takes `su 0 <cmd>`; `su -c` returns `su: invalid uid/gid '-c'` | `adb shell "su 0 id"` / the other form |
| Magisk 30.7, binary at `/debug_ramdisk/magisk`, not on root's `PATH` | `adb shell "su 0 /debug_ramdisk/magisk -v"` |
| Quoting trap: `echo A` swallowed | both forms of `adb shell … 'echo A; echo B'` |
| `pipefail` + `head` / `grep -q` exits 141 | `bash -c 'set -o pipefail; yes \| head -3 …'` |
| `adb` in a `while read` loop prints 1 of 3 rows | `printf 'a\nb\nc\n' \| while read …` |
| Property census 678 / 1062 / 638; `ro.boottime.*` 0 / 111 / 0 | `scripts/vantage.sh --cmd 'getprop \| wc -l'` |
| `/system/xbin/su` readable to `shell`, denied to an app | `scripts/vantage.sh --file /system/xbin/su` |
| `/proc/self/mountinfo` carries 3 `magisk` lines, from every vantage | `scripts/vantage.sh --cmd 'grep -c magisk …'` |
| `frida-ps -U` works with no `frida-server` running; attach fails | `frida-ps -U`, then `frida -U -n zygote64` |
| `frida-server` will not link on this image | `adb shell "su 0 /data/local/tmp/frida-server --version"` |
| Fingerprint does not start with `generic` | `adb shell getprop ro.build.fingerprint` |
| `/dev/qemu_pipe` absent, `/dev/goldfish_pipe_dprctd` present | `adb shell ls` on both |
| `ro.boot.verifiedbootstate` is the empty string | `adb shell getprop ro.boot.verifiedbootstate` |
| `/data/data` and `/data/user/0` share an inode | `adb shell "su 0 ls -di /data/data /data/user/0"` |
| Page size 16384 | `adb shell getconf PAGE_SIZE` |
| `FLAG_SECURE` is `8192`, so `javac` folds it | `javap -p -constants` on `android-35`'s `android.jar` |
| 376 `su -c` lines across 146 files, decomposition closes to 0 unexplained | `scripts/lint-commands.py --rule SU-DASH-C --format json` |

### Cited from the chapter that measured it

| Claim | Chapter |
|---|---|
| `adb shell` is not an app — `com.android.shell` requests 200 permissions | [`60-ADB`](../../60-ADB/README.md) |
| `am instrument` is gated by the signing relationship, not `debuggable` | [`66-Instrumentation`](../../66-Instrumentation/README.md) |
| `UiAutomation.executeShellCommand` is not a shell and runs as uid 2000 | [`66-Instrumentation`](../../66-Instrumentation/README.md) |
| A probe waiting on an entry marker races its target | [`66-Instrumentation`](../../66-Instrumentation/README.md) |
| Hidden-API enforcement must be measured by census, not lookup | [`66-Instrumentation`](../../66-Instrumentation/README.md) |
| `run-as` refuses in two distinct ways | [`09-Android-App-Internals`](../../09-Android-App-Internals/README.md) |
| `objection android root disable` covers 1 of 5 checks | [`54-Objection`](../../54-Objection/README.md) |
| `sslpinning disable` reported success against an app with no network code | [`54-Objection`](../../54-Objection/README.md) |
| A perfectly-installed hook against an inlined function changes nothing | [`65-Hooking`](../../65-Hooking/README.md) |
| A patch that works against a function nothing calls | [`18-ARM`](../../18-ARM/README.md) |
| `TracerPid` does not detect a JDWP debugger | [`38-TamperDetection`](../../38-TamperDetection/README.md) |
| `classes.dex` CRC unchanged after re-signing | [`38-TamperDetection`](../../38-TamperDetection/README.md) |
| jadx under-reports its own failures by 30× | [`56-JADX`](../../56-JADX/README.md) |
| Three APKs byte-identical in size; compare the DEX | [`41-ProGuard`](../../41-ProGuard/README.md) |
| Deleted rows survive in the SQLite `-wal` | [`33-Storage`](../../33-Storage/README.md) |
| 132 high-confidence hits, 132 false positives | [`33-Storage`](../../33-Storage/README.md) |
| 15 of 17 HIGH-band leads rejected by hand | [`52-StaticAnalysis`](../../52-StaticAnalysis/README.md) |
| `grep -i xposed` has a 100% false-positive rate over 237 APKs | [`64-Xposed`](../../64-Xposed/README.md) |
| Emulator heuristics dead or inverted | [`39-EmulatorDetection`](../../39-EmulatorDetection/README.md) |
| Every emulator key is `SOFTWARE` and the chain still verifies | [`50-HardwareBackedSecurity`](../../50-HardwareBackedSecurity/README.md) |
| `verifiedbootstate` said `green` while the TEE said `Unverified` | [`50-HardwareBackedSecurity`](../../50-HardwareBackedSecurity/README.md) |
| `--disable-verity` flips one byte inside the AVB-hashed region | [`61-Fastboot`](../../61-Fastboot/README.md) |
| `fastboot devices` silence is success; `lpdump` vs `dmctl table` | [`61-Fastboot`](../../61-Fastboot/README.md) |
| No bootloader on an emulator | [`61-Fastboot`](../../61-Fastboot/README.md) |
| `am start` compares intents with `filterEquals`, ignoring extras | [`31-Fragments`](../../31-Fragments/README.md) |
| `getCallingUid()` in `onBind` returns the service's own uid | [`28-Services`](../../28-Services/README.md) |
| `INSTALL_FAILED_USER_RESTRICTED` bypassable with root | [`30-Activities`](../../30-Activities/README.md) |
| A trust store modified by the rooting stack invalidates naive TLS tests | [`44-NetworkSecurityConfig`](../../44-NetworkSecurityConfig/README.md) |
| A void run and a clean negative produce identical reports | [`51-DynamicAnalysis`](../../51-DynamicAnalysis/README.md) |
| `dumpsys` records broadcast extras in cleartext | [`29-BroadcastReceivers`](../../29-BroadcastReceivers/README.md) |
| 16 KiB pages: a three-line C program exits 139 | [`39-EmulatorDetection`](../../39-EmulatorDetection/README.md) |

---

## Repository documents this chapter is built against

| Document | Why |
|---|---|
| [`../../STYLE-GUIDE.md`](../../STYLE-GUIDE.md) | §4a defines the reference-chapter contract this chapter follows instead of the 14-section template |
| [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) | §1.1 states the measure-do-not-recite rule that §6's corrections table applies |
| [`../../README.md`](../../README.md) | The repository index |

---

## Sibling reference chapters

| Chapter | Relationship |
|---|---|
| [`77-UsefulCommands`](../../77-UsefulCommands/README.md) | Enumerates the command surface. This chapter condenses it into tasks and corrects the forms that do not work |
| [`79-Glossary`](../../79-Glossary/README.md) | The vocabulary every row here assumes. A glossary *is* a cheat sheet, which is why it ships none |
| [`80-Appendix`](../../80-Appendix/README.md) | Version matrix, severity rubric, report templates, engagement checklist |
| [`73-Labs`](../../73-Labs/) | The complete lab index across the repository |
| [`78-Diagrams`](../../78-Diagrams/README.md) | Every diagram in one place — the same aggregation problem in a visual medium |
| [`75-InterviewQuestions`](../../75-InterviewQuestions/README.md) | Solved the same problem three hours earlier: generate the index mechanically, add the layer no chapter can hold. Its `scripts/build-interview-index.py` is the model this chapter's generator follows |

---

## External

- Android Debug Bridge — https://developer.android.com/tools/adb
- `aapt2` — https://developer.android.com/tools/aapt2
- Android behaviour changes, per release — https://developer.android.com/about/versions
- Frida for Android — https://frida.re/docs/android/
- OWASP MASVS — https://mas.owasp.org/MASVS/
- OWASP MASTG — https://mas.owasp.org/MASTG/
- Android Code Search — https://cs.android.com/
- POSIX `pipefail` and SIGPIPE semantics — https://pubs.opengroup.org/onlinepubs/9699919799/
