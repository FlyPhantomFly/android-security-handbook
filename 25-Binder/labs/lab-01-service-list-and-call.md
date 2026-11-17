# Lab 01 — `service list` and `service call` against a real device

> **Difficulty:** beginner
> **Time:** 60–90 minutes
> **Needs:** an Android device or emulator with `adb`, **no root**. If you have neither, every
> step works against [`../examples/fixture-device-snapshot/`](../examples/fixture-device-snapshot/README.md).
> **Reading:** [README §3.1](../README.md#31-what-devbinder-actually-is), [§3.8](../README.md#38-transaction-codes), [§3.16](../README.md#316-servicemanager-and-handle-0)

---

## Objective

By the end of this lab you will be able to:

1. Enumerate every Binder service on a device and explain why that list is **not** all of them.
2. Join a service name to its interface, its owning process and its SELinux type — and say honestly
   which of those four you actually know and which you guessed.
3. Ask any Binder object what interface it claims to be, using a transaction code rather than a tool.
4. Identify the services with **no interface token check**, and explain why that is the most
   interesting column on the page.
5. Make a real transaction and read the reply, including the case where you are refused — which is
   more informative than success.

You will not exploit anything. This lab builds the map. Labs 02 to 05 use it.

---

## Why this lab exists

Every Binder assessment starts with the same question: *what is there?* Almost everyone answers it
by running `service list`, skimming 200 lines, and picking something that looks interesting. That is
not a methodology, and it misses the two things that actually matter.

**First**, `service list` gives you two columns out of four. It tells you a name and an interface. It
does not tell you which process owns the service — so you cannot tell an AOSP service from an OEM
one, and OEM services are where a disproportionate share of real findings live. It does not tell you
the SELinux type of the name, which decides whether your domain may look it up at all.

**Second**, the most valuable row on the page looks like an error. A service whose interface shows as
`[]` has no interface descriptor, which almost always means a hand-written `onTransact` with no
`enforceInterface` — no interface token required, every transaction code reachable with an arbitrary
parcel. People skip those rows because they look empty.

---

## Setup

```bash
# host — confirm a device
adb devices -l
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell id
```

Expected shape of the last one — note the uid and the SELinux context, because they matter in
Task 6:

```
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),... context=u:r:shell:s0
```

**No device?** Use the fixture. Every Task that says "on a device" has a `--fixture` variant.

```bash
# host
cd 25-Binder/scripts
python3 -B binder-service-map.py --fixture ../examples/fixture-device-snapshot | head
```

---

## Task 1 — Look at the device nodes

Before enumerating services, look at what they live on.

```bash
# adb shell
ls -lZ /dev/binder /dev/hwbinder /dev/vndbinder
```

Measured on the reference device (Xiaomi M2101K6P, Android 11 / API 30):

```
lrwxrwxrwx 1 root root u:object_r:binder_device:s0     20 /dev/binder     -> /dev/binderfs/binder
lrwxrwxrwx 1 root root u:object_r:hwbinder_device:s0   22 /dev/hwbinder   -> /dev/binderfs/hwbinder
lrwxrwxrwx 1 root root u:object_r:vndbinder_device:s0  23 /dev/vndbinder  -> /dev/binderfs/vndbinder
```

**Questions to answer before moving on.**

1. Why are these symlinks and not character devices? (Hint: `ls -ld /dev/binderfs`.)
2. There are three of them. What would break if there were only one?
3. Try `cat /dev/binderfs/binder_logs/stats`. What happens, and what does that tell you about
   forensic access?

Now check which you can actually open:

```bash
# adb shell
for n in /dev/binder /dev/hwbinder /dev/vndbinder; do
  printf '%-16s ' "$n"
  if : < "$n" 2>/dev/null; then echo "readable"; else echo "denied"; fi
done
```

On the reference device `vndbinder` was denied to uid 2000 and the other two were not.

> **Record it.** Write down which nodes you can open. If `vndbinder` opens for you, you are on an
> unusual build and should say so in any report.

---

## Task 2 — Enumerate, three ways

```bash
# adb shell
service list | head -20
service list | wc -l
```

The reference device reported **217 services**. Yours will differ; that is the point.

Now two other enumerations that are **not** the same list:

```bash
# adb shell
dumpsys -l | wc -l      # services that implement dump()   — 211 on the reference device
cmd -l | wc -l          # services reachable by `cmd`      — 217 on the reference device
```

**Question.** `service list` said 217 and `dumpsys -l` said 211. Explain the six-service difference
without guessing. (Hint: `dumpsys` is transaction `'_DMP'`. What must a service do to answer it?)

**Question.** Is `lshal` on your device? Run it. Those services are on `/dev/hwbinder` and none of
them appear in `service list`. How many are there?

> **The trap**
> "I ran `service list`, so I have enumerated the Binder surface" is wrong in three ways. It misses
> `hwbinder`, it misses `vndbinder`, and — most importantly for app assessment — it misses every
> service published by an ordinary app through `onBind()`, because those are never registered with
> `servicemanager` at all. Those are found through the manifest;
> see [24 — IPC](../../24-IPC/README.md).

---

## Task 3 — Build the real map

`service list` gives two columns. Get the other two.

```bash
# host
cd 25-Binder/scripts
python3 -B binder-service-map.py | head -30
python3 -B binder-service-map.py | tail -15
```

The summary from the reference device:

```
SUMMARY
  services registered              : 217
  processes seen                   : 802
  with an explicit SELinux label   : 217
  UNLABELLED (default type)        : 0
  NO-INTERFACE (raw onTransact)    : 35
  vndservice (apps cannot reach)   : 1
  owner attributed by a rule       : 15
  owner GUESSED (verify these)     : 155
  owner unknown                    : 47
```

**Read that last block carefully.** 155 of 217 owners are *guesses*, and the tool says so. Below
root there is no reliable way to map a service name to a pid. A tool that printed `system_server`
for all 155 without a caveat would look tidier and be worse.

Now freeze it, so you can work offline and diff against another build later:

```bash
# host
python3 -B binder-service-map.py --capture ./my-snapshot
python3 -B binder-service-map.py --fixture ./my-snapshot --json > my-snapshot.json
```

**Exercise.** Diff your device's snapshot against the shipped one:

```bash
# host
python3 -B binder-service-map.py --fixture ./my-snapshot --csv | cut -d, -f1 | sort > mine.txt
python3 -B binder-service-map.py --fixture ../examples/fixture-device-snapshot --csv \
    | cut -d, -f1 | sort > ref.txt
comm -23 mine.txt ref.txt | head -20      # services yours has that the reference does not
comm -13 mine.txt ref.txt | head -20      # and vice versa
```

Anything in the first list that is not an AOSP name is an OEM service, and that is your target list.

---

## Task 4 — Find the OEM services

On the reference device, filtering by which contexts file labelled each name isolated six:

```
MiuiBackup       miui.app.backup.IBackupManager      miui_backup_service    [system_ext]
MiuiInit         miui.os.IMiuiInit                   miui_init_service      [system_ext]
MiuiWifiService  android.net.wifi.IMiuiWifiManager   miui_wifi_service      [system_ext]
ProcessManager   miui.IProcessManager                miui_process_service   [system_ext]
SlaveWifiService android.net.wifi.ISlaveWifiManager  slave_wifi_service     [system_ext]
xiaomi.joyose    com.xiaomi.joyose.IJoyoseInterface  system_app_service     [system_ext]
```

Do the same for yours:

```bash
# host
python3 -B binder-service-map.py --csv \
  | grep -v ',plat,' | cut -d, -f1,2,3,4 | column -t -s,
```

**Why this is the first minute of an engagement.** Every one of those interface names tells you which
APK to decompile. `com.xiaomi.joyose.IJoyoseInterface` says: find the package `com.xiaomi.joyose`,
pull it, open it in JADX, look for the class implementing that interface. That is Lab 05's opening
move.

---

## Task 5 — Find the services with no interface token

This is the heart of the lab.

```bash
# host
python3 -B binder-service-map.py --no-interface
```

Reference device, abridged — 35 of 217:

```
DockObserver                              -   DockObserver_service        ? (unknown)  [NO-INTERFACE]
SchedBoostService                         -   sched_boost_service         ? (unknown)  [NO-INTERFACE]
android.hardware.light.ILights/default    -   hal_light_service           hal_light_default (hal)
android.hardware.power.IPower/default     -   hal_power_service           hal_power_default (hal)
app_binding                               -   app_binding_service         ? (unknown)  [NO-INTERFACE]
battery                                   -   battery_service             ? (unknown)  [NO-INTERFACE]
binder_calls_stats                        -   binder_calls_stats_service  ? (unknown)  [NO-INTERFACE]
cacheinfo                                 -   cacheinfo_service           ? (unknown)  [NO-INTERFACE]
```

Verify one by hand, so you believe the tool:

```bash
# adb shell — 1598968902 is 0x5f4e5446, the ASCII '_NTF'
service call battery 1598968902
service call activity 1598968902
```

The second returns a descriptor. The first does not.

**What this means.** An empty descriptor means the object did not answer `INTERFACE_TRANSACTION`
with a string, which almost always means it is a raw `BBinder`/`Binder` subclass with a hand-written
`onTransact` rather than an AIDL-generated `Stub`. Two consequences:

- No `enforceInterface`, so no interface token is required. Every transaction code is reachable with
  an arbitrary parcel.
- No generated argument parsing, so the parcel layout is whatever the author wrote — and a native
  service reading a length it did not validate is a memory-corruption primitive.

Most of these are perfectly ordinary native services that never had an AIDL interface. That is
normal, not a bug. It is still the set worth reading.

> **Do not sweep transaction codes against these on a device you need.** A malformed parcel to a
> native `onTransact` can crash the service, and crashing `system_server` reboots the phone. Lab 04
> and Lab 05 do this responsibly.

---

## Task 6 — Make a transaction and read the reply

Now use the tool for what it is for.

```bash
# adb shell — is it alive?
service check notification
# Service notification: found

# adb shell — what is it?
service call notification 1598968902
```

Now call a real method. Transaction 2 of `INotificationManager`:

```bash
# adb shell
service call notification 2
```

Measured reply on the reference device:

```
Result: Parcel(
  0x00000000: ffffffff 0000001c 00690044 00610073 '........D.i.s.a.'
  0x00000010: 006c006c 0077006f 00640065 00200063 'l.l.o.w.e.d. .c.'
  0x00000020: 00610063 0020006c 006f0066 00200072 'a.l.l. .f.o.r. .'
  0x00000030: 00690075 00200064 00300032 00300030 'u.i.d. .2.0.0.0.'
  ...
```

Decode it:

```bash
# host
adb shell service call notification 2 | python3 -B ../scripts/parcel-decode.py - --as reply
```

```
EXCEPTION HEADER
  [0x0000] int32      -1   <- SecurityException
  [0x0004] String16   'Disallowed call for uid 2000'   <- the exception message
  [0x0044] int32      996   <- stack-trace header size
  [0x0048] String16   493 chars of remote stack trace

  REMOTE STACK TRACE
    at com.android.server.notification.NotificationManagerService.checkCallerIsSystem(NotificationManagerService.java:8683)
    at com.android.server.notification.NotificationManagerService.access$4500(NotificationManagerService.java:310)
    at com.android.server.notification.NotificationManagerService$10.clearData(NotificationManagerService.java:3703)
    at android.app.INotificationManager$Stub.onTransact(INotificationManager.java:1132)
    at android.os.Binder.execTransactInternal(Binder.java:1162)
```

**Stop and appreciate what you just got from a call that was refused.**

| From the refusal | What it tells you |
|---|---|
| `uid 2000` | The service saw our real UID. We did not send it; the kernel did |
| `checkCallerIsSystem` | The exact guard method. Now you know what to defeat |
| `clearData` | **Transaction code 2 is `clearData`.** You have just recovered a name for a bare integer |
| `INotificationManager$Stub.onTransact` | Confirms it is an AIDL-generated stub, so a token is enforced |
| Line numbers | Which AOSP release this build's framework corresponds to |

A *successful* call would have told you none of that.

**Exercise.** Do this for five services of your choosing. For each, record: the descriptor, the
transaction code you tried, the exception code, and any class or method the trace named. That table
is the deliverable.

---

## Task 7 — The trap that invalidates most Binder findings

Everything you have done so far ran as **uid 2000, SELinux domain `shell`**. That is not an app.

```bash
# adb shell
id
# uid=2000(shell) ... context=u:r:shell:s0
```

The `shell` domain holds `service_manager:find` rules and platform permissions that **no ordinary app
has**. Plenty of services answer you happily here and are completely unreachable from an app.

**Demonstrate it to yourself.** Pick a service that answered you, then look at whether an app could
even find it:

```bash
# host
python3 -B binder-service-map.py --explain notification
```

```
REACHING IT IS TWO SEPARATE MAC DECISIONS (see 22-SELinux 3.15):
  stage 1, looking the name up:
      allow YOUR_DOMAIN notification_service:service_manager find;
      a denial here says   tclass=service_manager   and NAMES the service
  stage 2, sending the transaction:
      allow YOUR_DOMAIN system_server:binder call;
      a denial here says   tclass=binder   and names NO service at all
```

Your domain, as `shell`, has rules that `untrusted_app` does not. Confirming which is
[22 — SELinux](../../22-SELinux/README.md)'s job; the practical rule for this chapter is absolute:

> **Pentester's Note**
> **A finding that only reproduces from `adb shell` is not a finding.** Reproduce it from an
> unprivileged APK — uid 10xxx, domain `untrusted_app` — before you write a word.
> [`../examples/RawBinderClient.java`](../examples/RawBinderClient.java) is the code to drop into
> that APK. If it does not reproduce, you have characterised a property of `shell`, which is worth
> knowing and is not a vulnerability.

---

## Task 8 — Answer these without looking

1. `service list` reported N services. Name three categories of Binder object that are **not** in
   that list.
2. What is transaction code 1598968902, in ASCII, and why does every service answer it?
3. A service shows `[]` for its interface. Give two consequences.
4. You called a service and got exception code `-1`. What is it, and what does the reply contain
   after the message?
5. Why is `service call` able to talk to AIDL services without you supplying an interface token?
6. `dumpsys -l` returned fewer entries than `service list`. Why?
7. Your `binder-service-map.py` output says `framework?` in the HOW column for 155 services. What
   does the `?` mean and what would you have to do to remove it?
8. Name the two SELinux checks that happen before a transaction is delivered, and say which one
   names the service in its denial.

---

## Success criteria

- [ ] You can state your device's service count and explain why it is not the total Binder surface.
- [ ] You have a captured snapshot directory and have diffed it against the shipped fixture.
- [ ] You have a list of OEM-labelled services on your device, with the APK to decompile for each.
- [ ] You have a list of services with no interface descriptor, verified by hand for at least one.
- [ ] You have decoded at least one refusal, including its remote stack trace, and can name the
      guard method it revealed.
- [ ] You can explain, unprompted, why an `adb shell` result does not transfer to an app.

---

## Going further

- Run the enumerator against a second device, or the same device before and after an OTA. Services
  that appear, or that lose their SELinux label between builds, are the highest-value diffs there
  are.
- Take one OEM service, find its APK (`pm path <package>`), pull it, run `jadx`, and locate the class
  implementing its interface. Do not call anything yet — Lab 05 does that.
- Read [`../examples/fixture-device-snapshot/README.md`](../examples/fixture-device-snapshot/README.md)
  and note which two contexts files could **not** be read as uid 2000. Why those two?

---

## Next

[Lab 02 — Parcel anatomy](lab-02-parcel-anatomy.md) takes the parcels you have been printing and
decodes them byte by byte, then breaks the interface token on purpose to see what the control
actually does.
