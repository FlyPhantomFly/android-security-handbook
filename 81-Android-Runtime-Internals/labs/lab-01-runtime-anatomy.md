# Lab 01 — Runtime Anatomy of an App

**Difficulty:** Beginner
**Time:** 45–75 minutes
**Prerequisites:** [Chapter 81 §2–3](../README.md#2-high-level-architecture), a rooted lab device or
emulator, `adb`

---

## Objective

Map the three processes that matter — zygote, `system_server` and an app — and prove with observations
that they differ in UID, SELinux context, mount namespace and executable mappings while sharing the
same preloaded runtime. This lab installs nothing and hooks nothing. It builds the baseline that every
later lab depends on.

## Why this matters

Most wrong conclusions about runtime injection start with a missing baseline. A tester sees an
executable mapping and calls it a hook; it was the JIT. They see a different mount view and call it
hiding; it was normal app storage isolation. They see `TracerPid` zero and conclude no tracer was ever
attached; the loader detached after injection. This lab makes the normal state familiar, so the
abnormal state stands out.

---

## Setup

You need:

- a rooted device or emulator you own, with `adb` authorised;
- one app to observe. Use a app you built, or a system app such as Settings;
- a root shell form that works on your device. On this repository's lab device the working form is
  `su 0 <cmd>`; `su -c` is broken. Check yours before relying on it.

```bash
# host — confirm the device and the root form
adb devices
adb shell "su 0 id"
```

If `su 0 id` prints `uid=0(root)`, you have the form used below. If not, substitute your device's
working form and record it.

---

## Steps

### 1. Find zygote and `system_server`

```bash
# host — process table, filtered
adb shell "ps -A -o PID,PPID,USER,NAME" | grep -E "zygote|system_server"
```

You should see at least one `zygote64` and one `system_server`. Record their PIDs. Note the parent of
`system_server`: it is zygote, not `init`.

### 2. Start the target app and get its PID

```bash
# host — launch Settings (or your own app)
adb shell "am start -a android.settings.SETTINGS"
adb shell "pidof com.android.settings"
```

If the app has multiple processes, `pidof` may print more than one PID. Pick the one whose
`/proc/<pid>/cmdline` matches the process you want.

### 3. Compare identity

```bash
# host — UID, GID and tracer state
for p in $(adb shell "pidof zygote64") $(adb shell "pidof system_server") <app-pid>; do
  echo "== $p"
  adb shell "su 0 grep -E '^(Uid|Gid|TracerPid):' /proc/$p/status"
  adb shell "su 0 cat /proc/$p/attr/current"
done
```

Expected shape:

| Process | UID | SELinux context (example) |
|---|---|---|
| `zygote64` | 0 | `u:r:zygote:s0` |
| `system_server` | 1000 | `u:r:system_server:s0` |
| Settings | app UID (e.g. 10123) | `u:r:untrusted_app:s0:c...` |

Your labels may differ by device and vendor. The point is that they are different, and that the app's
label includes categories that the system processes do not.

### 4. Compare mount namespaces

```bash
# host — namespace identity
for p in $(adb shell "pidof zygote64") $(adb shell "pidof system_server") <app-pid>; do
  printf "%s " "$p"
  adb shell "su 0 readlink /proc/$p/ns/mnt"
done
```

Two processes in the same mount namespace print the same inode. The app is normally in its own
namespace; zygote and `system_server` may share one. A different inode is not proof of hiding; it is
proof of a different mount view.

### 5. Compare executable mappings

```bash
# host — mappings that are executable
for p in $(adb shell "pidof zygote64") $(adb shell "pidof system_server") <app-pid>; do
  echo "== $p"
  adb shell "su 0 awk '\$2 ~ /x/ {print \$6}' /proc/$p/maps" | sort -u | head -20
done
```

Look for shared framework mappings (`boot.art`, `boot.oat`, `libart.so`) and app-specific mappings.
The app should have its own `base.apk` and native libraries; it may also have a JIT code cache.

### 6. Prove copy-on-write sharing

```bash
# host — count mappings backed by the boot image
adb shell "su 0 grep -c 'boot.art' /proc/<app-pid>/maps"
adb shell "su 0 grep -c 'boot.art' /proc/$(adb shell pidof zygote64)/maps"
```

Both processes should show boot-image mappings. They are the same physical pages until one writes.
This is why preloading is a memory optimization and why a hook installed before the fork is visible
in the child.

### 7. Compare a clean app with a hooked one (optional)

If you have a device with a hook framework installed, repeat step 5 for an app in scope and an app out
of scope. Record the differences. Do not conclude "hooked" from a single extra mapping; correlate with
the loader's log and the process's class loaders.

---

## Hints

- If `su 0` is not your form, try `su -c` only to discover that it fails, then use the form your
  device documents. Do not disable SELinux.
- If `ps` truncates names, use `ps -A -o PID,PPID,USER,NAME` or `ps -A -o PID,NAME`.
- If an app has no `attr/current` permission, you are not root in that shell. Re-check the root form.

---

## Success criteria

You can answer all of these with a command and an observed value:

1. Which process is the parent of `system_server`?
2. What is the app's UID, and how does it differ from zygote's?
3. What is the app's SELinux context, and how does it differ from `system_server`'s?
4. Do zygote and the app share a mount namespace? How do you know?
5. Which executable mappings are shared with zygote, and which are app-specific?
6. Why does a hook installed in zygote before the fork appear in the app without re-injection?

Write the answers down with the build fingerprint and API level. That record is the baseline for the
next lab.

---

## Cleanup

```bash
# host — stop the app you launched
adb shell "am force-stop com.android.settings"
```

Nothing was installed or modified. If you changed a device setting, restore it.
