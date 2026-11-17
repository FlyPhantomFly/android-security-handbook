# 61 — Fastboot: FAQ

The questions people actually ask, including the ones that feel too basic to ask out loud. Those are
usually the best ones.

---

### 1. What is the difference between `adb` and `fastboot`? They look like the same thing.

They are two different protocols, spoken to two different pieces of software, over two different USB
interfaces.

`adb` talks to `adbd`, a daemon running inside a booted Android. It exists only when Android is
running, and it operates *inside* Android's security model — SELinux applies to it, it cannot write
the boot partition even as root.

`fastboot` talks to the **bootloader**, which runs before Linux exists. It is available when Android
is completely broken, and it operates *underneath* the security model.

They even use different USB interface descriptors: both are class `0xFF`, subclass `0x42`, but adb is
protocol `0x01` and fastboot is `0x03`. That is why a device is visible to one tool or the other and
never both at the same time.

### 2. I ran `fastboot devices` and got nothing. Is it broken?

Almost certainly not. **`fastboot devices` with no device in fastboot mode prints nothing and exits
0** — measured. Silence is success, which is genuinely confusing the first time.

Check in this order:

1. Is the device actually *in* fastboot mode? A device running Android is invisible to fastboot by
   design.
2. **Is the cable a data cable?** A charge-only cable enumerates power and nothing else, and produces
   exactly this symptom. This wastes an hour for somebody every week.
3. On Linux: do you have a udev rule, or are you root? Missing permissions usually show as
   `no permissions` but can show as nothing at all.
4. On Windows: is a driver bound to the bootloader interface?

### 3. Why does unlocking wipe all my data? That seems like punishment.

It is the opposite — it is what makes your data safe from someone who steals your phone.

Unlocking lets you replace the code that *checks your screen lock*. If the data survived unlocking,
then "unlock the bootloader, flash a boot image whose `init` accepts any PIN, read everything" would
be a complete one-command bypass of Android's entire data-at-rest model, available to anyone holding
your phone for fifteen minutes.

The wipe is performed by the **bootloader itself**, not by Android, precisely so it cannot be skipped
by controlling Android. On devices with file-based encryption the keys are destroyed too, which makes
the erase cryptographic rather than merely physical — a bit-for-bit image of the flash afterwards
yields nothing.

### 4. So can I unlock, dump `/data`, and relock to get someone's data?

No, and this is worth being clear about because it appears in forensics marketing.

The unlock wipes before it reports the new state. There is no window in which the bootloader is
unlocked and the old data is still present and readable. Relocking wipes as well, for the mirror-image
reason: data written under the weaker guarantee must not be carried into the stronger state where
attestation will vouch for the device.

If a device arrives locked, its user data is not reachable through fastboot at all. The paths that
exist go through exploiting the bootloader, exploiting the running system, or a vendor's own service
tooling — none of which is "just use fastboot".

### 5. Can I unlock the bootloader on a phone I found, or a phone with a locked screen?

No. This is the single best-designed part of the whole system.

`fastboot flashing unlock` checks a flag that **only a booted, screen-unlocked Android can set** — the
"OEM unlocking" toggle in Developer Options. The bootloader exposes it as
`fastboot flashing get_unlock_ability`, which returns `1` or `0`. Without that `1`, the unlock fails,
and there is no fastboot-side way to change it.

So a thief with your locked, powered-off phone is stuck: unlocking requires your screen-lock
credential first, and the screen lock is exactly what the unlock was going to help them defeat. That
circular dependency is deliberate and it is why physical theft of a modern Android device is largely a
dead end.

(Anyone offering to remove a carrier lock or a factory-reset-protection lock is outside what this
chapter covers, on purpose. Those are legal and ethical boundaries, not technical puzzles.)

### 6. What is `fastbootd` and why is my device rebooting in the middle of a flash?

`fastbootd` is a *second implementation* of the same protocol that runs inside Android's recovery
ramdisk instead of in the bootloader. Its source is public, at `system/core/fastboot/device/`.

It exists because of dynamic partitions. Since Android 10, `/system` is not a physical partition — it
is a *logical* one carved out of a container called `super`, described by metadata that needs a parser
called `liblp`. Making every OEM embed `liblp` in their closed-source bootloader would have produced
dozens of independent implementations of a brick-prone format. Moving that half of the protocol into a
program that already has a kernel and `liblp` was the better answer.

The reboot you are seeing is the host tool doing this for you: it queries `is-userspace` and
`is-logical:system`, works out that the bootloader cannot serve the request, and issues
`reboot-fastboot` on your behalf. Nothing is wrong. You typed one command and the tool is doing five
things.

### 7. What is the difference between `fastboot boot` and `fastboot flash boot`?

The most important distinction in the chapter.

`fastboot boot image.img` downloads the image into RAM and boots from it **once**. Nothing is written
to flash. Power-cycle and the device is exactly as it was.

`fastboot flash boot image.img` writes it permanently.

The arithmetic: a wrong image with `boot` costs you a power-cycle. A wrong image with `flash boot`
costs you a device that will not boot, recoverable only via fastboot mode plus the correct factory
image plus the hardware key combination you hopefully wrote down. **Same information gained,
enormously different downside.**

Caveat: several OEMs disable the `boot` command even on unlocked devices, because "boot arbitrary RAM
image" is exactly the primitive an attacker wants. You will see `FAILED (remote: 'unknown command')`.
On those devices there is no free test.

### 8. I flashed a patched boot image and I still do not have root. What went wrong?

Three usual causes, in order of likelihood:

1. **You patched the wrong partition.** Since Android 13, on GKI launch devices, the ramdisk lives in
   `init_boot`, not `boot`. Advice written in 2021 produces a device with no root in 2024. Check:
   `ls -l /dev/block/by-name/ | grep init_boot`.
2. **You flashed the wrong A/B slot.** Flashing targets the *active* slot; if the device subsequently
   switched slots, you are running the unpatched copy. Check `getprop ro.boot.slot_suffix` before and
   after, and use `--slot all` when you want the change to survive a switch.
3. **Wrong build.** A boot image from a different build produces a bootloop or a device that cannot
   mount `/data`. "Close enough" is not a thing here; the fingerprint must match character for
   character.

### 9. Everyone says to flash `vbmeta` with `--disable-verity`. What does that actually do?

It sets **one bit, in one byte**: bit 0 of the `flags` field, a big-endian `uint32` at offset 120 of
the 256-byte AVB header — so byte 123. That flag makes AVB ignore every hashtree descriptor, so
dm-verity is never set up.

Now the part that is usually left out. **That byte is inside the region AVB hashes.** Setting it
invalidates the image's own integrity hash and therefore the signature over it. This was measured
against a real `vbmeta`: stored hash `93dfae21…`, recomputed after the flip `3695fea8…`, no match.

So `--disable-verity` is **not a supported option that AVB honours**. It is a deliberate corruption
that only an unlocked bootloader will accept, because only an unlocked bootloader treats verification
failure as advisory. On a locked device the same image gives you boot state RED and a phone that will
not start.

Practical upshot: you usually do not need it. It is not what lets a patched boot image run — the
*unlocked state* is. `--disable-verity` is what lets you modify `/system`.

### 10. What is the difference between `--disable-verity` and `--disable-verification`?

`--disable-verification` (bit 1) is strictly larger. Bit 0 stops the dm-verity machinery but still
checks the boot image hash and still verifies chained vbmetas. Bit 1 skips the **entire** chain —
nothing is verified.

Reach for the smaller one, and usually for neither.

### 11. Can I disable verity and then relock the bootloader, so it looks stock?

No. That is a description of a brick, and it is the exact scenario in
[lab 04](labs/lab-04-ctf-bricked-vault.md).

A locked bootloader *enforces* verification. A `vbmeta` with a disable flag fails its own hash check;
a patched boot image fails its hash check. Locking gives you a bootloader that refuses both, so the
device shows "Your device is corrupt" and will not boot. And then you cannot unlock again, because
unlocking requires Android to set a flag and Android will not start.

The only safe relock order is: **flash the full stock factory image, boot it, confirm it works, then
lock.**

### 12. My phone shows "Your device is corrupt and will not boot". Is it dead?

It is in boot state RED — a locked bootloader that found something that does not verify. Usually
because someone relocked with modified images on the device.

If you can still reach fastboot mode (try the hardware key combination — normally Volume Down +
Power), and if `fastboot flashing get_unlock_ability` returns `1`, you can unlock and reflash. If it
returns `0`, you cannot, because setting it requires a booted Android and you do not have one.

At that point the honest answer is that no software you own will fix it. Some manufacturers provide a
low-level recovery path (Qualcomm EDL, Samsung download mode, MediaTek BROM) that takes a
vendor-signed loader and can rewrite storage below the bootloader's refusal. That path is
vendor-specific, may require an authorised service centre, and does not exist for every model. Any
tool advertising a universal fix should be treated with suspicion.

### 13. Is `ro.boot.verifiedbootstate` a reliable way to check if a device is unlocked?

No, and this is the most important "no" in the chapter.

`ro.boot.*` properties are written by `init` from `androidboot.*` keys on the kernel command line or
in bootconfig, into a shared-memory property area that **root can rewrite**. Magisk's `resetprop`
sets it to `green` in one command.

This was measured in this repository: a device reported `ro.boot.verifiedbootstate = green` from
`getprop` while a TEE-signed key attestation pulled seconds later said `verifiedBootState =
Unverified`, `deviceLocked = false`. The property lies; the hardware does not.

It is useful to *you* as an honest observer of your own test device. It is worthless to a *defender*
as an integrity signal, because it is attacker-controlled data on precisely the devices the check
exists to detect.

### 14. My app checks `!"orange".equals(state)`. That is safe, right?

**No — it is worse than the version it is trying to improve on.**

Measured on an Android 15 / API 35 emulator: `ro.boot.verifiedbootstate` is the **empty string**, not
`orange`. `/proc/bootconfig` on that device explains why — there is no `androidboot.verifiedbootstate`
key for `init` to derive it from.

The empty string is not `"orange"`, so the check returns `true`. **It passes on an emulator**, which
is arguably the least trustworthy platform it could encounter.

The general bug is treating an *absent* answer as a *good* answer. Enumerate the accepted values
explicitly and treat everything else — including empty — as unknown. See
[`examples/BootStateChecker.java`](examples/BootStateChecker.java) Part A2.

### 15. Then what *is* a reliable way?

Hardware key attestation, verified server-side.

Generate a key in the AndroidKeyStore with `setAttestationChallenge(serverNonce)`, export the
certificate chain, and send the **whole chain, unparsed** to your server. The server verifies it to a
pinned Google root, checks revocation, checks the challenge equals the nonce it issued, and reads
`deviceLocked` and `verifiedBootState` out of the attestation extension.

Those fields are populated inside the TEE from a value the bootloader hands it over a channel the
normal world cannot address, and signed with a key that never leaves the secure world. Root is not in
the TEE, so root cannot change them.

Two things that are usually missed: the nonce is not optional (without it a captured chain replays
forever), and **`securityLevel` must be checked, not just the signature** — on an emulator every key
reports `SOFTWARE`, `hardwareEnforced` is empty, and the chain still verifies perfectly.

Full code, and the eleven server-side checks, in
[`examples/BootStateChecker.java`](examples/BootStateChecker.java).

### 16. Does an unlocked bootloader break hardware key attestation?

No — and that is exactly the point of it.

Attestation keeps working and keeps telling the truth: `deviceLocked` becomes `false` and
`verifiedBootState` becomes `Unverified` in every certificate the TEE issues. Almost every other
control in this repository degrades or fails on an unlocked device; attestation and Play Integrity
keep working, because their root of trust is in the TEE rather than in software the unlock made
writable.

That asymmetry is the strongest argument in the repository for attestation over local checks, and it
is measured rather than argued.

### 17. Why can I not just read the boot partition with `fastboot` to check if it is modified?

Because fastboot is essentially write-only for bulk data. The protocol was designed to *put* images
onto a device, not to take them off. `fastboot fetch PARTITION OUT_FILE` exists in the host tool, but
most retail bootloaders do not implement it.

The practical route is: `adb shell` on a rooted device to `dd` the partition out, hash it, and compare
against the OEM factory image for that exact fingerprint. That is why "record the stock hashes before
you touch anything" is a habit worth building — it turns "is this modified?" from an opinion into
arithmetic.

### 18. Can I practise all of this on an emulator?

**No, and this was measured rather than assumed.** An Android emulator has no bootloader.

On an `sdk_gphone16k_x86_64` AVD (Android 15 / API 35): `adb reboot bootloader` returned 0, the device
rebooted, and came straight back into Android in about 40 seconds. `fastboot devices` never saw it at
any point. `adb reboot fastboot` behaved identically.

Three structural confirmations from the same device: there is no `misc` partition (so no Bootloader
Control Block for the reboot request to be written into), no `boot` or `recovery` partition (the
kernel comes from QEMU, not from flash), and `bootctl get-number-slots` returns `Failed to get bootctl
module.`

The emulator *is* still useful for the downstream material — the property surface, the dynamic
partition layout, dm-verity mappings, and a real `vbmeta` to parse. All four produced measurements
used in this chapter. But any sentence of the form "on an emulator, fastboot does X" is meaningless.

### 19. What is a sparse image, and is it compressed?

**It is not compressed**, and naming it correctly matters.

A sparse image is a *description* of a disk image as a sequence of chunks of four kinds: `RAW` (these
exact bytes), `FILL` (this 4-byte pattern, N times), `DONT_CARE` (I decline to describe this range),
and `CRC32`. There is no dictionary and no entropy coding — a sparse image of *random* data is
**larger** than the raw data, by the chunk headers.

The enormous ratios come entirely from filesystem images being mostly empty. A 4 MiB image of one data
block plus zeros sparses to 4,152 bytes — a ratio of about 1,010 to 1, measured — because 1,023 blocks
of output are described by sixteen bytes of input.

It exists so that a 3 GiB `super.img` can go through a 256 MiB download buffer, split into pieces each
of which positions its own data.

### 20. Does flashing a sparse image erase the whole partition?

**No, and this catches people.** A `DONT_CARE` chunk means "skip this range", not "write zeros here".
The device may leave whatever was there before.

For a factory image that is fine, because the filesystem metadata says those blocks are free. For
anyone reasoning about data remanence — a forensic examiner, or someone asking whether a secret
survived a reflash — it is a real fact. If you need the old bytes gone, `erase` first.

### 21. What are A/B slots, and why did my root disappear after an update?

An A/B device has two complete copies of every partition needed to boot. One is active and running;
an update is written to the inactive one; a reboot switches which is active. A failed update is then a
reboot rather than a brick.

Your root "disappeared" because the device switched slots and you are now running the copy that was
never patched. Check `getprop ro.boot.slot_suffix` — if it changed, that is your answer.

The fix is `--slot all` when you want a change to survive a switch, and recording `current-slot`
before and after any flash. Mental model: A/B is a double-buffer, and `set_active` is the buffer swap.

### 22. What is `super` and why can the bootloader not flash `/system` any more?

`super` is a single physical partition containing several *logical* partitions — `system`, `vendor`,
`product`, `system_ext` — as named extents described by metadata called LP. It exists so an update
that needs `/system` to grow can take space from `/product` without repartitioning.

The bootloader can write the physical `super` partition happily. What it cannot do is work out *which
part of it* is `system`, because that needs the `liblp` metadata parser. Hence `fastbootd`.

One detail worth knowing if you ever rebuild a `super` image: **every logical partition starts on a
1 MiB boundary.** Measured on a real device, the five partitions started at sectors 2,048 / 1,832,960
/ 1,847,296 / 2,273,280 / 6,463,488 — every one a whole multiple of 2,048 sectors, with padding
between them. Concatenate partition images without reproducing that and you get something that
flashes cleanly and does not boot.

### 23. `lpdump` fails on my device but the partitions plainly work. Which do I believe?

**Believe the kernel.** `dmctl table <name>` reports live device-mapper mappings — what is actually
serving reads. `lpdump` reports the metadata stored in `super`, which is a *description* of what
should be mapped.

Measured on an API 35 emulator: `lpdump` returned `Failed to read metadata.` as root, both with and
without an explicit `super` argument, while `dmctl table` produced a complete and internally
consistent extent map. The cause was not determined.

The general rule, which this repository applies everywhere: when a description and the running system
disagree, the running system wins.

### 24. Is `fastboot oem <something>` safe to run?

`fastboot oem` is a vendor extension namespace with **no specification and no shared test suite**,
frequently written by the team under the most schedule pressure, running in the most privileged
execution context on the device with no memory protection, no ASLR and no stack protector.

`fastboot oem help` on some devices enumerates the verbs, and reading that list is legitimate
reconnaissance. Running an arbitrary `oem` verb is invoking undocumented code that may erase
something, blow a fuse, or crash the bootloader. Historically this is where bootloader
vulnerabilities have clustered.

Know what a verb does before you type it. If you cannot find out, that is information too.

### 25. I found a memory-corruption bug in a bootloader. How serious is it?

**The first and only question that matters: is it reachable on a *locked* device?**

If yes, it is **Critical**. It defeats Verified Boot at its root and yields a persistent, potentially
undetectable compromise on every device shipping that bootloader — millions of units, many already
sold, with no recall.

If it requires an already-unlocked bootloader, it is usually **Low**. On an unlocked device the
attacker can flash whatever they like. An exploit that grants what the device already grants is
not a vulnerability; it is a complicated way to do something easy.

Two follow-ups that separate a senior analysis from a principal one: does exploitation leave a trace
(if not, it is also an undetectable-persistence primitive), and does the fix bump the anti-rollback
index (if not, the vulnerable bootloader can be reflashed, and the fix is a speed bump).

### 26. Is an unlockable bootloader a security flaw?

No, and arguing that it is confuses two threat models.

Unlocking requires the owner's authenticated consent and destroys the data it was protecting, so it
grants an attacker nothing they did not already have. A thief cannot use it; an owner using it is
exercising ownership.

What it *does* is change who the relying party is trusting. On a locked device, a bank's app trusts
the OEM. On an unlocked device, it trusts the owner. The app's correct response is not to pretend
otherwise but to *detect* it — which is what attestation is for, and why attestation reports the state
rather than blocking the boot.

The genuinely difficult question is the adjacent one: a device that *cannot* be unlocked by its owner
is one where the owner is not the ultimate authority over their own hardware. No security research, no
alternative operating systems, no independent repair, no recourse when the vendor ends support.

### 27. Why is the protocol so primitive? No checksums, no authentication?

Because it must be implementable in a few kilobytes of freestanding C, with no allocator, on every SoC
anyone ships — and because it is the recovery path of last resort, where complexity is a bricking
risk. Every proposal to add framing or compression adds parser surface to the most privileged code on
the device.

The real gap is the missing host authentication: an unlocked device left in fastboot mode and plugged
into an untrusted USB port is fully open to whatever is on the other end. A locked device is not,
because it refuses the write commands. Something worth remembering about the device in your
conference bag.

### 28. What is the difference between a soft brick and a hard brick?

A **soft brick** is a device that does not boot Android but still reaches fastboot mode. It is
recoverable with the correct factory image.

A **hard brick** is a device whose bootloader is gone or refuses to run, so there is no fastboot.
Recovery requires a vendor low-level path (EDL, download mode, BROM) and often an OEM-signed loader
you do not have.

**The transition between them is `fastboot flash bootloader`** — or `xbl`, `aboot`, `sbl1`, whatever
your SoC calls it. That is exactly why those partitions sit behind `unlock_critical` as a separate,
additional gate. The bootloader is protecting itself from you, on purpose.

The rule that follows: **never flash a partition whose name you cannot explain.**

### 29. Where do I start if I want to read the real code?

`system/core/fastboot/README.md` — the protocol specification. It is short. Read it properly once and
most of the confusion in this topic evaporates.

Then `system/core/fastboot/device/commands.cpp` and `variables.cpp`, which are `fastbootd` and are the
open-source reference for what a conformant implementation does.

Then `system/core/fastboot/fuzzy_fastboot/`, which is Google's conformance and malformed-input suite
for OEM bootloaders. Reading its test names is a reconnaissance exercise: every case it tests is a
case some bootloader failed. It needs a device in fastboot mode to *run*, but the source reads fine
without one, and it is the highest-yield hour available on this topic.

### 30. What is the one habit that will save me a device?

`fastboot boot` before `fastboot flash`, every time you are testing a boot image.

RAM is free. Flash is not. And write down your device's hardware key combination *now*, while the
device still works — it is not discoverable from a bricked phone, and not knowing it is the single
most common way people lose a device in this chapter.

---

## Still stuck?

- [README.md](README.md) — the chapter, with every claim sourced
- [cheatsheet.md](cheatsheet.md) — every command and constant, tables only
- [examples/measured-avd-boot-state.md](examples/measured-avd-boot-state.md) — the raw measurements,
  so you can check the chapter rather than trust it
- [labs/lab-01-device-posture.md](labs/lab-01-device-posture.md) — start here if you have a device
- [labs/lab-04-ctf-bricked-vault.md](labs/lab-04-ctf-bricked-vault.md) — the relock brick, as a
  puzzle you can solve on files
- [62-Magisk](../62-Magisk/README.md) — the rooting side, and the one lab in this repository that
  performs the destructive procedure
