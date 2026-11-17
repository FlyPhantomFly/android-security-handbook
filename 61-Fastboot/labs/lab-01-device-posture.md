# Lab 01 — Device posture from the outside

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Prerequisites:** [Chapter 61 §1](../README.md#1-introduction),
[§2.3](../README.md#23-the-lock-state-machine--the-most-important-diagram-in-this-chapter),
[§3.1](../README.md#31-how-a-device-enters-fastboot-mode-and-how-it-leaves),
[60-ADB](../../60-ADB/README.md)
**You need:** any Android device or emulator you can run `adb shell` on. Root is optional and the lab
says which steps need it.

> **This lab does not put anything into fastboot mode, and you must not either.**
> Every command here runs against a booted Android. Nothing reboots, flashes, erases or unlocks.
> That is not a limitation of the lab — it is the point. Almost everything worth knowing about a
> device's bootloader posture is readable from the running system, and reading it is free while
> rebooting into a bootloader is not.

---

## Objective

Determine, for a device in front of you, and with the evidence written down next to each answer:

1. Is the bootloader locked, and **how much is that answer worth**?
2. What did the bootloader actually tell the kernel, and where did every `ro.boot.*` property come
   from?
3. Is this an A/B device? Are its partitions dynamic? What is the real device-mapper stack?
4. Is dm-verity running, or merely described?
5. Which of your answers are **claims** and which are **evidence** — and can you say why, for each
   one?

By the end you will have a reproducible audit script and, more importantly, a habit: never state a
device fact without stating where it came from and how forgeable it is.

## Why this matters

Three reasons, in increasing order of importance.

**It is the first thing you do on any engagement involving a device.** You cannot reason about an
app's platform-integrity checks without knowing the platform's actual state, and you cannot know that
without asking.

**It is where testers quietly poison their own results.** This repository has watched it happen. A
device whose posture you have not established will teach you the opposite of the truth — chapter 35
found an interception CA promoted into the *system* store by a rooting module, which made every
"the app trusts user CAs" measurement wrong in a way that was internally consistent and completely
false. Posture first, always.

**The distinction between a claim and evidence is the whole professional skill here.** Anyone can run
`getprop`. What separates a report that stands up from one that does not is knowing that
`ro.boot.verifiedbootstate` is a value in shared memory that root rewrites in one command, while the
`deviceLocked` field in a key attestation is signed by a key the normal world never sees. Same
question, two answers, wildly different weight.

---

## Setup

```bash
# host
adb devices -l
adb get-state          # must print exactly: device
```

If it prints `unauthorized`, unlock the device screen and accept the RSA fingerprint dialog. If it
prints `offline`, the device is still booting. Nothing below works until this reads `device`.

Record which device you are on, because every version-gated claim below depends on it:

```bash
# host
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.fingerprint
```

Write those three lines into your notes now. This repository has recorded a device being **swapped
mid-session** without warning — a chapter watched one phone vanish from `adb devices` and be replaced
by a different model. If your notes do not say which device produced a number, the number is worthless
three weeks later.

Create an evidence directory:

```bash
# host
SERIAL=$(adb get-serialno)
EV="lab01-evidence/$SERIAL/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EV"
adb shell getprop > "$EV/all-props.txt"
wc -l "$EV/all-props.txt"
```

---

## Part 1 — The lock-state properties, and what they are worth

### Step 1.1 — Read them

```bash
# host
for p in ro.boot.verifiedbootstate ro.boot.flash.locked ro.boot.vbmeta.device_state \
         ro.boot.veritymode ro.boot.vbmeta.digest ro.boot.vbmeta.size \
         ro.boot.vbmeta.hash_alg ro.boot.avb_version \
         ro.oem_unlock_supported sys.oem_unlock_allowed \
         ro.secure ro.debuggable ro.build.type ro.bootloader; do
    printf '%-34s = %s\n' "$p" "$(adb shell getprop $p | tr -d '\r')"
done | tee "$EV/lock-state.txt"
```

### Step 1.2 — Interpret, carefully

| `verifiedbootstate` | `flash.locked` | What it reports |
|---|---|---|
| `green` | `1` | Locked, OEM-signed, verified |
| `yellow` | `1` | Locked with an **owner-supplied** key — a deliberately installed custom OS |
| `orange` | `0` | Unlocked |
| `red` | `1` | Verification failed |
| *(empty)* | *(empty)* | **Nothing reported a state at all.** Not a boot state — an absence |

**Q1.** Which row did you get? Now the question that matters: **can you distinguish "this device is
locked" from "this device is lying about being locked" using only what you have read so far?**

<details>
<summary>Answer</summary>

No, and you cannot with any number of additional properties either. Everything in
`/proc/<pid>/property_area` is writable by root, and `resetprop` sets any `ro.` property in one
command. If the device is rooted, every value in step 1.1 is whatever the attacker chose.

The circularity is the point: you are asking a possibly-compromised system whether it is compromised.
Chapter 50 measured the failure directly — a device reported `ro.boot.verifiedbootstate = green` from
`getprop` while a TEE-signed key attestation pulled seconds later said `verifiedBootState =
Unverified`, `deviceLocked = false`, `verifiedBootKey` all zeroes.

The property is useful to *you*, as an honest observer of your own test device. It is worthless to a
*defender* as an integrity signal.
</details>

### Step 1.3 — The empty case

If any of those properties came back empty, do not skip past it.

**Q2.** An app contains this check. What does it return on a device where the property is empty, and
is that the safe answer?

```java
return !"orange".equals(SystemProperties.get("ro.boot.verifiedbootstate"));
```

<details>
<summary>Answer</summary>

It returns **`true`** — "the device is fine" — because the empty string is not `"orange"`.

This was measured on an Android 15 / API 35 emulator, where the property is genuinely absent. So the
check passes on an emulator: arguably the least trustworthy platform it could possibly encounter, and
certainly not one where a claim about a bootloader means anything.

This is the general shape of the bug: **treating an absent answer as a good answer.** The correct
handling enumerates the accepted values and treats everything else — including empty — as unknown.
[`../examples/BootStateChecker.java`](../examples/BootStateChecker.java) Part A2 shows that form,
returning a tri-state rather than a boolean so that "unknown" cannot silently collapse into "fine".
</details>

---

## Part 2 — Where the properties came from

This is the part most people skip, and it is where the understanding is.

### Step 2.1 — The kernel command line

```bash
# host
adb shell 'cat /proc/cmdline' | tr ' ' '\n' | grep -i androidboot | tee "$EV/cmdline.txt"
```

You will very likely get `Permission denied`. That is normal on modern Android and is itself worth
recording. If you have root:

```bash
# host -- try BOTH su forms. See the note below.
adb shell "su -c 'cat /proc/cmdline'" 2>&1 | tr ' ' '\n' | grep -i androidboot
adb shell "su 0 cat /proc/cmdline"    2>&1 | tr ' ' '\n' | grep -i androidboot
```

> **`su` is not portable, and getting this wrong looks like "not rooted"**
> A Magisk-style `su` takes `su -c '<cmd>'`. **The Android emulator's `su` takes `su 0 <cmd>` and
> fails on `-c`** in a way that reads exactly like an unrooted device. A previous chapter in this
> repository nearly recorded a rooted emulator as unrooted for that reason. Always try both.

### Step 2.2 — bootconfig

Modern devices put the parameters in bootconfig rather than on the command line, because the command
line has a length cap:

```bash
# host, as root
adb shell "su 0 cat /proc/bootconfig" 2>&1 | grep -i androidboot | tee "$EV/bootconfig.txt"
```

### Step 2.3 — Join the two together

This is the exercise. For each `ro.boot.X` property in step 1.1, find the matching `androidboot.X`
key in step 2.1 or 2.2.

```bash
# host -- the join, done crudely and effectively
grep -oE 'ro\.boot\.[a-z_.]+' "$EV/lock-state.txt" | sed 's/^ro\.boot\./androidboot./' | sort -u \
  > "$EV/expected-keys.txt"
cat "$EV/expected-keys.txt"
# now check each one against bootconfig.txt / cmdline.txt
```

**Q3.** State the rule you have just discovered, in one sentence, connecting an empty property to
its cause.

<details>
<summary>Answer</summary>

**A `ro.boot.X` property is empty exactly when `androidboot.X` is absent from the kernel command line
and from bootconfig**, because `init` derives the former from the latter and has nothing else to work
with.

Measured on the API 35 emulator: `androidboot.vbmeta.size`, `.digest`, `.hash_alg` and
`androidboot.veritymode` are all present in `/proc/bootconfig` and their properties are all set;
`androidboot.verifiedbootstate`, `androidboot.flash.locked`, `androidboot.vbmeta.device_state` and
`androidboot.slot_suffix` are all absent and their properties are all empty. Cause and effect, on one
device, in one session.

The consequence for testing: **"the property is empty" and "the bootloader reported a bad state" are
different conditions**, and code that conflates them gets the wrong answer. See §5.3 of the chapter.
</details>

**Q4.** `ro.bootloader` on your device — what is it? Compare with a second device if you have one.

<details>
<summary>Answer</summary>

Very often `unknown`. Chapter 39 measured `Build.BOOTLOADER == "unknown"` on **both** an API 35
emulator and a retail Redmi M2101K6P, which is why the widely-copied "`BOOTLOADER == unknown` means
emulator" check is dead. Confirmed again here.

This is a good moment to internalise the repository's most repeated lesson: **a signal that fires the
same way on both classes does not distinguish them**, however many blog posts list it.
</details>

---

## Part 3 — Slots and partitions

### Step 3.1 — A/B

```bash
# host
adb shell getprop ro.boot.slot_suffix
adb shell getprop ro.build.ab_update
adb shell getprop ro.virtual_ab.enabled
adb shell "su 0 bootctl get-number-slots"  2>&1
adb shell "su 0 bootctl get-current-slot"  2>&1
```

**Q5.** Suppose `slot_suffix` is `_a`. If you were to run `fastboot flash boot boot.img` on this
device, which partition would receive the image, and what would happen to it if the device
subsequently switched slots?

<details>
<summary>Answer</summary>

It goes to **`boot_a`**, because a flash targets the *active* slot unless you pass `--slot`.

If the device then switches to slot B — because an OTA completed, or because slot A failed to boot
enough times and the bootloader fell back — the device boots `boot_b`, which was never patched. The
symptom is "it stopped being rooted after an update", and the cause is that it was never rooted on
that slot.

The fixes are `--slot all` when you want a change to survive a slot switch, and recording
`current-slot` before and after any flash. This is the most common A/B mistake and it costs people an
afternoon each time.
</details>

### Step 3.2 — Physical partitions

```bash
# host
adb shell "su 0 ls -l /dev/block/by-name/" 2>&1 | tee "$EV/by-name.txt"
```

Check for each of these and write down present/absent:

| Partition | If absent, what does that tell you? |
|---|---|
| `boot` / `boot_a` | The kernel does not come from flash. On an emulator, QEMU supplies it |
| `init_boot` | Pre-Android-13, or not a GKI launch device. Determines which image you would patch |
| `recovery` | On A/B devices the recovery ramdisk usually lives inside `boot` instead |
| `misc` | **No Bootloader Control Block** — `adb reboot bootloader` has no mailbox to write into |
| `super` | Not a dynamic-partition device |
| `vbmeta` | No AVB, or an unusual layout |
| `dtbo` | Device tree overlay partition |

**Q6.** If `misc` is absent, what happens when you run `adb reboot bootloader`?

<details>
<summary>Answer</summary>

Nothing useful. `adb reboot bootloader` works by having `init` write the string
`bootonce-bootloader` into the `command[]` field of the `bootloader_message` struct in the `misc`
partition, then rebooting; the bootloader reads `misc`, sees the request, clears it, and enters
fastboot mode. No `misc` means no mailbox.

Measured on the API 35 emulator, which has no `misc` **and** no bootloader: the command returned 0,
the device rebooted, and came straight back into Android in about 40 seconds. `fastboot devices`
never saw it at any point.

The struct is defined at
`bootable/recovery/bootloader_message/include/bootloader_message/bootloader_message.h`.
</details>

### Step 3.3 — Dynamic partitions and the real device-mapper stack

```bash
# host, root needed
adb shell "su 0 dmctl list devices" 2>&1 | grep -v '^com\.android\.' | tee "$EV/dm-devices.txt"

for d in system system-verity vendor product system_ext system_dlkm; do
    echo "--- $d ---"
    adb shell "su 0 dmctl table $d" 2>&1
done | tee "$EV/dm-tables.txt"

adb shell "su 0 lpdump" 2>&1 | tee "$EV/lpdump.txt"
adb shell "su 0 grep -E ' (/|/vendor|/product|/system_ext) ' /proc/mounts" | tee "$EV/mounts.txt"
```

A `linear` target reads `START-LENGTH: linear, MAJOR:MINOR OFFSET`, in **512-byte sectors**.

**Q7.** Take every `linear` target you got and divide its offset by 2048. What do you notice, and why
does it matter?

<details>
<summary>Answer</summary>

Every one should be a whole number: **every logical partition starts on a 1 MiB boundary.** That is
`liblp`'s default alignment.

Measured on the API 35 emulator, offsets ÷ 2048 gave 1, 895, 902, 1110 and 3156 — five whole numbers.
It also produces visible gaps: `system` ended at sector 1,831,488 while `system_dlkm` began at
1,832,960, wasting 1,472 sectors purely to reach the next boundary.

Why it matters: anyone reconstructing a `super` image by concatenating partition images without
reproducing the alignment produces something that flashes cleanly and does not boot. The failure has
no error message pointing at alignment.
</details>

**Q8.** Did `lpdump` and `dmctl table` agree? If one failed, which do you believe?

<details>
<summary>Answer</summary>

**Believe `dmctl`.** It reports the live kernel mappings — what is actually serving reads. `lpdump`
reports the LP metadata stored in `super`, which is a *description* of what should be mapped.

Measured on the API 35 emulator: `lpdump` returned `Failed to read metadata.` as root, with and
without an explicit `/dev/block/by-name/super` argument, while `dmctl table` produced a complete and
internally consistent extent map. The cause of the `lpdump` failure was not determined and is not
guessed at.

The general rule, which this repository applies everywhere: **when a description and the running
system disagree, the running system wins.**
</details>

---

## Part 4 — Is dm-verity actually running?

```bash
# host
adb shell getprop ro.boot.veritymode
adb shell "su 0 dmctl list devices" 2>&1 | grep -i verity
adb shell "su 0 dmctl table system-verity" 2>&1
```

A verity target's fields, in order:
`version data_dev hash_dev data_block_size hash_block_size num_data_blocks hash_start_block algorithm root_digest salt [opt_count opts...]`

**Q9.** In the verity table you obtained (or the one below, from the API 35 emulator), what are the
data device and the hash device, and what does it mean that they are the same?

```
system-verity 0-1800416: verity, 1 254:0 254:0 4096 4096 225052 225052 sha256 \
              d7b94a2a...  34f93a31...  10 restart_on_corruption ignore_zero_blocks \
              use_fec_from_device 254:0 fec_blocks 226826 fec_start 226826 fec_roots 2
```

<details>
<summary>Answer</summary>

Both are `254:0`, which is the `system` linear device-mapper device. **The Merkle hash tree is stored
inside the `system` partition itself, immediately after the data.** `num_data_blocks` and
`hash_start_block` are both 225,052 — the tree begins exactly where the data ends.

Note the layering: `dm-5` (verity) sits on top of `dm-0` (linear) which sits on `vda2` (`super`).
Four layers to serve one read. The bootloader can write `vda2` and cannot work out which part of it
is `system` without `liblp`, which is precisely why `fastbootd` exists.

Also note `restart_on_corruption`: on a verity failure this device **reboots** rather than returning
an error to the reader. That is why verity evidence lives in the previous boot's log rather than the
current one.
</details>

**Q10.** Count your verity devices against the partitions in your mount table. Do all read-only
partitions have one?

<details>
<summary>Answer</summary>

Often not, and it is worth knowing rather than assuming.

Measured on the API 35 emulator: only `system` had a verity device. `/vendor`, `/product` and
`/system_ext` mounted their plain linear targets directly — **even though the `vbmeta` on the same
device carries `AvbHashtreeDescriptor` entries for all four of them.**

**Descriptors present is not the same as verity enforced.** The cause on that device was not
determined; it may be an emulator-specific first-stage-init path, and the emulator is explicitly not
a reference for boot behaviour. Recorded as an observation, not a conclusion — which is the honest
handling when you can see an effect and not its cause.

Practical consequence: if you are asked "is this partition integrity-protected at runtime?", read
`dmctl`, not the image's descriptors.
</details>

---

## Part 5 — Turn it into a script

You have now run about twenty commands by hand. Do it once more with the chapter's script and compare:

```bash
# host, from the chapter root
./scripts/bootstate-audit.sh -o "$EV/audit.txt"
```

Read the script. It is not doing anything you have not just done manually — that is deliberate, and it
is why you did it manually first.

**Q11.** The script probes `su -c` and `su 0` and reports which worked. Why is that worth a whole
branch rather than picking one?

<details>
<summary>Answer</summary>

Because the wrong one fails in a way that is indistinguishable from an unrooted device, and a tester
who concludes "not rooted" skips every root-only measurement for the rest of the session.

This is a recorded near-miss in this repository: an agent working on chapter 68 nearly recorded a
rooted emulator as unrooted on exactly this basis. The emulator's `su` wants `su 0 <cmd>`; Magisk's
wants `su -c '<cmd>'`.

The generalisable lesson is about *negative* results. A negative result from a probe you have not
validated is not evidence of absence — it is evidence that the probe returned nothing, which is a
different and much weaker statement.
</details>

**Q12.** Extend the script. Add a section that reports, for every `ro.boot.*` property the device
exposes (`adb shell getprop | grep '\[ro.boot'`), whether a matching `androidboot.*` key exists in
bootconfig. Any property with no matching key is either OEM-injected after boot or set by something
other than the bootloader — and that is a genuinely interesting thing to find.

---

## Part 6 — Claims versus evidence

Fill this table in for your device. This is the deliverable.

| Question | Your answer | Source | Forgeable by root? | Weight |
|---|---|---|---|---|
| Is the bootloader locked? | | `ro.boot.flash.locked` | **Yes** | Claim |
| Is the bootloader locked? | | key attestation `deviceLocked` | **No** | Evidence |
| Is verity enforcing? | | `ro.boot.veritymode` | **Yes** | Claim |
| Is verity enforcing? | | `dmctl list devices` | Yes, but requires kernel-level control | Strong |
| Which slot is live? | | `ro.boot.slot_suffix` | Yes | Claim |
| Which slot is live? | | `bootctl get-current-slot` | Yes (HAL call from root) | Medium |
| Is `/system` inside super? | | `dmctl table system` | Yes, but see above | Strong |

**Q13.** Only one row in that table is genuinely non-forgeable. Which, and what makes it different in
kind rather than in degree?

<details>
<summary>Answer</summary>

**Key attestation's `deviceLocked`.** The difference is *where the value is computed*.

Every other row is a value produced by software running in the normal world, on a platform that root
controls. Rewriting it is a matter of finding the right thing to rewrite. The attestation field is
populated inside the TEE, from a value the bootloader hands the TEE over a channel the normal world
cannot address, and signed with a key that never leaves the secure world. Root is not in the TEE, so
root cannot change it — not "cannot easily", cannot.

That is a difference in kind. Everything else on the list is a lock you can pick; this one is a lock
in a different building.

The practical procedure is in [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md),
and the app-side and server-side code is in
[`../examples/BootStateChecker.java`](../examples/BootStateChecker.java) Parts B and C.

One honest caveat to carry with it: attestation reports the state **at boot**, and boot was
potentially months ago. A device compromised after boot attests exactly as a clean one does.
</details>

---

## Success criteria

You are done when you can:

- [ ] Produce every value in Part 1 and say, for each, whether it is a claim or evidence
- [ ] Explain why `ro.boot.verifiedbootstate` is empty on a device where it is empty, by pointing at
      `/proc/bootconfig` rather than by guessing
- [ ] State what `!"orange".equals(state)` returns on an emulator, and why that is a bug
- [ ] Draw your device's storage stack from physical partition up to mount point, with the real
      sector offsets
- [ ] Say whether dm-verity is running on each read-only partition, from `dmctl` and not from a
      property
- [ ] Explain the difference between a hashtree *descriptor* existing and verity *running*
- [ ] Run `bootstate-audit.sh` and explain every section of its output without re-reading the chapter
- [ ] State the one non-forgeable source of lock state, and why it is different in kind

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `adb: no devices/emulators found` | USB, or the device is in fastboot mode | `adb devices -l`; a fastboot-mode device is invisible to adb by design |
| `unauthorized` | RSA dialog not accepted | Unlock the screen and accept |
| `su: inaccessible or not found` | Not rooted, **or the wrong `su` form** | Try `su 0 <cmd>` as well as `su -c '<cmd>'` |
| `dmctl: not found` | Older Android | Use `dmsetup table` if present, or read `/proc/mounts` and `ls -l /dev/block/mapper/` |
| `Permission denied` on `/proc/cmdline` | Normal on API 33+ | Use root; record the denial, it is a finding of its own |
| `lpdump: Failed to read metadata` | Measured on API 35 | Use `dmctl table`; it is the ground truth anyway |
| Every property empty | Emulator, or a device with an unusual boot path | Read [`../examples/measured-avd-boot-state.md`](../examples/measured-avd-boot-state.md) §2 |

## Cleanup

Nothing to clean. This lab wrote nothing to the device.

Your `lab01-evidence/` directory is host-side. Keep it — a posture baseline you can diff against
later is worth more than the individual readings, and "what exactly was on that device when you found
that bug?" is a question you will be asked.

## Next

[Lab 02 — the sparse image format, by hand](lab-02-sparse-images.md), which needs no device at all.
