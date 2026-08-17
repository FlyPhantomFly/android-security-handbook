# 77 — Useful Commands · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure.

A command reference has an unusual failure mode: the commands are easy to find and easy to run, so
the temptation is to skip the documentation entirely. The cost shows up later, in a report. `adb
shell` runs as the `shell` user, not as an app — so a `content query` that succeeds from your
terminal proves nothing about whether a *third-party app* could do the same. Half the sources below
exist to keep you from making that class of mistake.

---

## Official command documentation

| Resource | Why |
|---|---|
| [ADB command reference](https://developer.android.com/tools/adb) | The authoritative flag list. Read the "Direct ADB commands" and "Wireless" sections properly once |
| [`dumpsys`](https://developer.android.com/tools/dumpsys) | **The single highest-value command in this chapter.** Documents the per-service arguments, which are otherwise undiscoverable |
| [`dumpsys package`](https://developer.android.com/tools/dumpsys#package) | What `PackageManager` actually parsed — the arbiter when a tool and the platform disagree about a manifest |
| [`am` (activity manager)](https://developer.android.com/tools/adb#am) | `start`, `startservice`, `broadcast` — how you reach an exported component by hand |
| [`pm` (package manager)](https://developer.android.com/tools/adb#pm) | `list packages`, `path`, `dump`, and `compile` |
| [`content`](https://developer.android.com/studio/command-line/adb#shellcommands) | Provider query/insert/update/delete/call from the shell |
| [`logcat`](https://developer.android.com/tools/logcat) | Filter expressions and buffer selection. `-b crash` and `-b events` are the two most people never use |
| [`bmgr`](https://developer.android.com/identity/data/testingbackup) | Driving backup/restore, which is how you test `allowBackup` |
| [`sqlite3`](https://www.sqlite.org/cli.html) | The shell binary is present on most builds; `.dump` and `.schema` are what you want |

---

## The commands that change behaviour

Grouped separately because these **modify device state**. Know what each one does before running it
on a device you did not personally provision.

| Command | Effect | Note |
|---|---|---|
| `pm compile -m verify -f <pkg>` | Forces re-compilation at the `verify` filter | The single most useful command for dynamic analysis — see [13-ART](../../13-ART/README.md) for why AOT-compiled methods resist hooking |
| `pm clear <pkg>` | Wipes app data | Destroys the evidence you may still need. Snapshot first |
| `pm disable-user` / `enable` | Disables a component | Recoverable, but changes the attack surface you are measuring |
| `settings put global ...` | Changes system settings | Several detection routines read these — see [39-EmulatorDetection](../../39-EmulatorDetection/README.md) |
| `svc wifi` / `svc data` | Toggles radios | Useful for testing offline paths and certificate-validation fallbacks |
| `setprop` | Sets a system property | Only unrestricted properties, and only from a root shell. Reads bypass SELinux; writes do not — see [06-Android-Architecture](../../06-Android-Architecture/README.md) |

> **Record every state change.** A finding that depends on a setting you changed and forgot is a
> finding you will retract. The session log in [`scripts/session.sh`](../scripts/session.sh) exists
> for this reason.

---

## AOSP source

Where these commands are actually implemented. Read on [cs.android.com](https://cs.android.com/).
Reach for these when a command's output is ambiguous and the documentation does not say.

| Path | Covers |
|---|---|
| `frameworks/base/services/core/java/com/android/server/pm/PackageManagerShellCommand.java` | Every `pm` subcommand, including undocumented ones |
| `frameworks/base/services/core/java/com/android/server/am/ActivityManagerShellCommand.java` | Every `am` subcommand and exactly how it builds the Intent |
| `frameworks/base/cmds/content/src/com/android/commands/content/Content.java` | How `content query` maps its flags onto a real `ContentResolver` call — including `--projection`, `--where` and `--sort` |
| `frameworks/base/core/java/android/os/ServiceManager.java` | What `service list` is enumerating |
| `frameworks/base/cmds/dumpsys/dumpsys.cpp` | Argument dispatch, and why some services ignore extra arguments |
| `system/core/adb/` | The ADB protocol itself — see [60-ADB](../../60-ADB/README.md) |

---

## The `shell` user problem

**Read at least one of these before writing a provider or component finding.** The `shell` user
(UID 2000) holds privileges no third-party app has, so reachability from `adb shell` is not
reachability from an app.

| Resource | Why |
|---|---|
| [Android permissions overview](https://developer.android.com/guide/topics/permissions/overview) | Protection levels, and which are granted to `shell` |
| [`platform.xml`](https://cs.android.com/android/platform/superproject/+/master:frameworks/base/data/etc/platform.xml) | The actual list of permissions mapped to the `shell` GID |
| [Package visibility (API 30+)](https://developer.android.com/training/package-visibility) | Why an app cannot even *see* the target that `adb shell pm list packages` lists freely |
| [`labs/lab-03-exported-sweep.md`](../labs/lab-03-exported-sweep.md) | The discipline itself: prove reachability from an unprivileged app before reporting |

---

## Tooling

| Tool | Use |
|---|---|
| [Frida](https://frida.re/docs/android/) | Runtime instrumentation — [53-Frida](../../53-Frida/README.md) |
| [Objection](https://github.com/sensepost/objection) | Wraps most of this chapter's runtime commands — [54-Objection](../../54-Objection/README.md) |
| [apktool](https://apktool.org/) | Decode resources and AXML |
| [jadx](https://github.com/skylot/jadx) | `jadx-gui` for reading, `jadx` for scripted extraction |
| [Magisk](https://topjohnwu.github.io/Magisk/) | Root, and the denylist — [62-Magisk](../../62-Magisk/README.md) |
| [scrcpy](https://github.com/Genymobile/scrcpy) | Screen mirroring over ADB; invaluable for recording a proof-of-concept |

### Chapter tooling

| File | Purpose |
|---|---|
| [`scripts/apk-triage.sh`](../scripts/apk-triage.sh) | First-pass APK triage — signing, SDK levels, exported surface, secrets |
| [`scripts/session.sh`](../scripts/session.sh) | Timestamped, logged shell session so every command you ran is recoverable |
| [`examples/recon-session-annotated.md`](../examples/recon-session-annotated.md) | A full first-60-minutes recon, annotated line by line |
| [`examples/dumpsys-package-annotated.md`](../examples/dumpsys-package-annotated.md) | Reading `dumpsys package` output properly |

---

## OWASP

| Resource | Relevance |
|---|---|
| [MASTG — Android Basic Security Testing](https://mas.owasp.org/MASTG/) | The tooling setup and roughly this command set, in checklist form |
| [MASVS](https://mas.owasp.org/MASVS/) | The control categories to cite alongside a finding |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [60-ADB](../../60-ADB/README.md) | The ADB protocol and transport in depth |
| [61-Fastboot](../../61-Fastboot/README.md) | Bootloader and partition commands |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | The methodology these commands serve |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Validating what a sweep turns up |
| [32-Manifest](../../32-Manifest/README.md) | `dumpsys package` as the authority on what was parsed |
| [27-ContentProviders](../../27-ContentProviders/README.md) | Runtime exploitation of what `content query` reaches |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | Why `shell` is not an app |
| [76-CheatSheets](../../76-CheatSheets/README.md) | The condensed printable versions |
