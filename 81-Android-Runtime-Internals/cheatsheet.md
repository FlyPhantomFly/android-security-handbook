# 81 — Android Runtime Internals · Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these works.

---

## The one command that matters

```bash
# host — reduce inlining when a Java hook installs but never fires
adb shell "cmd package compile -m verify -f com.example.target"
adb shell "am force-stop com.example.target"
```

Then relaunch and test the hook before changing anything else.

---

## The three seams

| Seam | Question | Owner |
|---|---|---|
| Process creation | Did foreign code reach the child before or after specialization? | Zygisk / loader |
| Code visibility | Can the target's classes see the foreign DEX? | Class loader |
| Method dispatch | Does the call go through the entrypoint at all? | LSPlant / ART |

---

## Process identity

| Observation | Zygote | `preAppSpecialize` | App (`post`) | `system_server` |
|---|---|---|---|---|
| UID | root | root | app UID | 1000 |
| SELinux | zygote | zygote | app domain | `system_server` |
| seccomp | zygote's | zygote's | app's filter | system's |
| Mount namespace | zygote's | zygote's | app's view | system's view |
| Can open protected files | yes | yes | no (usually) | some |

---

## `ArtMethod` fields that matter

| Field | Meaning | Hook relevance |
|---|---|---|
| `declaring_class_` | Class that declares the method | GC root; keeps the class alive |
| `access_flags_` | Java flags + ART-internal bits | `kAccCompileDontBother`, `kAccPreCompiled` |
| `dex_method_index_` | Index into DEX `method_ids` | Identifies the method in the DEX |
| `method_index_` | Vtable / direct / IMT index | Dispatch |
| `hotness_count_` | JIT invocation counter | JIT state |
| `data_` | JNI function, code item, resolver data | JNI hooks |
| `entry_point_from_quick_compiled_code_` | Quick invocation target | **The patch point** |

Never hard-code the offset. Derive it or pin the build.

---

## Entrypoint destinations

| Destination | Mapping clue | Meaning |
|---|---|---|
| AOT | `base.odex` / `boot.art` (`oatexec`) | Compiled by `dex2oat` |
| JIT | `[anon:jit-code]` | Compiled at run time |
| `nterp` | `libart.so` | Interpreted, native-stack interpreter |
| Resolution stub | `libart.so` | Reference not resolved yet |
| Class-init stub | `libart.so` | `<clinit>` has not run |
| JNI trampoline | `libart.so` | `native` method |
| Deopt bridge | `libart.so` | Instrumentation/deoptimization |

"Quick" is the calling convention, not "compiled".

---

## Dispatch and hook failures

| Symptom | Likely cause | First check |
|---|---|---|
| Hook returns, callback never runs | Caller inlined | `Deoptimize(caller)` or compile `verify` |
| Works cold, fails hot | JIT/OSR | Test after warming the method |
| Works in app, fails in `system_server` | Hidden API / domain | Caller domain, trusted DEX |
| Module log absent | Not loaded / not in scope | Loader log, daemon binder |
| `ClassNotFoundException` | Wrong loader / parent | Enumerate loaders |
| Crash after unhook | Thread still in trampoline | Unhook lifetime |

---

## Zygisk callbacks (API v5)

| Callback | When | Identity |
|---|---|---|
| `onLoad` | Module loaded into the child | Before specialization |
| `preAppSpecialize` | After fork, before UID drop | Root / zygote |
| `postAppSpecialize` | After UID, SELinux, seccomp, mounts | App |
| `preServerSpecialize` | Before `system_server` transition | Root / zygote |
| `postServerSpecialize` | After transition | `system` (1000) |

`connectCompanion()` for privileged work. `setOption()` for flags. `exemptFd()` for FDs.

---

## Layer map

| Layer | Examples | Responsibility |
|---|---|---|
| Root | Magisk, KernelSU, APatch | Privilege and mounts |
| Loader | Zygisk, ZygiskNext | Get module code into the child |
| Framework | Vector, LSPosed | Scope, DEX, module dispatch |
| Hook engine | LSPlant | `ArtMethod` surgery |
| Inline hook | Dobby, LSPlt | Architecture-specific trampolines |
| Module | your code | The actual decision |

---

## Commands

```bash
# host — process tree
adb shell "ps -A -o PID,PPID,USER,NAME" | grep -E "zygote|system_server|com.example"

# host — identity and namespace
adb shell "su 0 cat /proc/<pid>/status" | grep -E "Uid|Gid|TracerPid"
adb shell "su 0 cat /proc/<pid>/attr/current"
adb shell "su 0 readlink /proc/<pid>/ns/mnt"

# host — mappings and FDs
adb shell "su 0 cat /proc/<pid>/maps" | grep -E "rwxp|r-xp"
adb shell "su 0 cat /proc/<pid>/maps" | grep -E "memfd|deleted"
adb shell "su 0 ls -l /proc/<pid>/fd" | head -40

# host — compilation state
adb shell "cmd package compile -m verify -f com.example.target"
adb shell "cmd package compile -m speed -f com.example.target"
adb shell "pm art clear-app-profiles com.example.target"

# host — loader/runtime logs
adb logcat -v threadtime | grep -Ei "zygisk|lsplant|vector|lsposed|art|dex2oat"
```

---

## Detection evidence

| Observation | What it can show | What it cannot show |
|---|---|---|
| Executable anonymous mapping | Possible trampoline/JIT | Which tool put it there |
| `libzgn.so` in maps | ZygiskNext may be present | That it hooked this app |
| `memfd:` mapping | In-memory file | That the file is malicious |
| Non-zero `TracerPid` | A tracer is attached now | That it was attached earlier |
| Extra class loader | Foreign DEX | Who loaded it |
| Entrypoint outside known mappings | Possible hook | That the method was called |
| `--inline-max-code-units=0` in OAT | Vector wrapper | That Vector is installed now |

---

## Version matrix

| Android | API | Runtime note |
|---|---|---|
| 8.1 | 27 | Vector's stated floor |
| 9 | 28 | Hidden-API enforcement tightened |
| 10 | 29 | Scoped storage |
| 11 | 30 | Boot-image profiles |
| 12 | 31 | Boot-image filter `speed-profile` |
| 13 | 33 | Package Manager dexopt |
| 14 | 34 | ART Service dexopt |
| 15 | 35 | ART Mainline updates |
| 16 | 36 | Layout used in this chapter |
| 16 QPR2 | 36.1 | Minor API level |
| 17 | 37 | Verify module claims |

---

## Related chapters

[11](../11-Android-Runtime/README.md) · [13](../13-ART/README.md) · [16](../16-JNI/README.md) ·
[25](../25-Binder/README.md) · [62](../62-Magisk/README.md) · [63](../63-LSPosed/README.md) ·
[65](../65-Hooking/README.md)
