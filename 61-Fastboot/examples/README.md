# Examples — chapter 61, Fastboot

Four files. **None of them touches a device**, and none of them can destroy anything.

| File | What it is | How to use it |
|---|---|---|
| [`measured-avd-boot-state.md`](measured-avd-boot-state.md) | **The evidence base for the whole chapter.** Every raw measurement, verbatim, with the command that produced it — plus an explicit list of what was deliberately not run | Read alongside §3.7, §3.8 and §7.6. Re-run the commands on your own device and compare |
| [`fastboot-wire-transcript.md`](fastboot-wire-transcript.md) | Seven annotated protocol sessions, byte by byte — reconnaissance, a locked refusal, sparse splitting, the `fastbootd` reroute, `--disable-verity`, `fastboot boot`, and the unlock | Read alongside §2.2 and §3.2. **Labelled at the top as reconstructed, not captured** |
| [`BootStateChecker.java`](BootStateChecker.java) | The vulnerable platform-integrity check that real apps ship, and its server-side replacement, in one file | Read alongside §5.3 and §9.4. Drop into an app module to build |
| `README.md` | This file | |

## What each one is for

### `measured-avd-boot-state.md` — read this one first

This is the file that makes the chapter checkable. Everything the chapter claims to have measured is
in here in raw form: the property dump, `/proc/bootconfig`, the `/dev/block/by-name/` listing, every
device-mapper table, the full `vbmeta` parse with descriptors, the recomputed AVB hash, and the
timed poll proving an emulator never appears in `fastboot devices`.

It also contains the section that matters most for trusting the rest: **§8, what was deliberately not
run and why.** No destructive fastboot command was executed and no physical device was rebooted into
a bootloader while writing this chapter, because the only physical devices available are a
daily-driver phone and a borrowed handset.

Three measurements in it are worth knowing even if you read nothing else:

1. **`ro.boot.verifiedbootstate` is the empty string on an API 35 emulator** — not `orange` — and
   `/proc/bootconfig` shows exactly why: there is no `androidboot.verifiedbootstate` key for `init`
   to derive it from. An app checking `!"orange".equals(state)` passes there.
2. **Every logical partition inside `super` starts on a 1 MiB boundary**, visible in the raw sector
   offsets. Rebuild `super` without reproducing that and it flashes and does not boot.
3. **`--disable-verity` changes one byte, at offset 123, and breaks the image's own AVB hash.**
   Recomputed both ways against a real `vbmeta`.

### `fastboot-wire-transcript.md`

The protocol at the byte level, in the order the bytes actually move. It exists because the
three-leg structure of every fastboot operation — query, download into a shared buffer, act on the
buffer — is much easier to see in a transcript than in prose.

**It is explicitly labelled as reconstructed.** The *shape* of every exchange comes from the
specification at `system/core/fastboot/README.md` and from strings extracted from the shipped host
binary; the device's reply *values* are representative rather than observed. That labelling is not a
formality: a fabricated transcript in a chapter about commands that destroy devices would be worse
than no transcript, because a reader might follow it.

The two sessions to read if you are short of time are **session 2** (what a locked bootloader
actually refuses, and the surprising fact that it accepts the download and refuses only the act) and
**session 7** (the unlock, and why the wipe is a security property rather than an inconvenience).

### `BootStateChecker.java`

Three parts in one file, so the difference between the wrong answer and the right one is a diff:

- **Part A** — the vulnerable check, with four defects labelled inline. The one people miss is not
  that the input is forgeable; it is that the `catch` block returns `true`, so an attacker who makes
  the check *throw* passes without touching a property at all.
- **Part A2** — how to read these properties honestly if you have a legitimate reason to. A tri-state
  return instead of a boolean, enumerated accepted values, and a method name containing the word
  `Reported` so no caller can mistake it for a verdict.
- **Part B and C** — the fix. The device produces *evidence* (a hardware key-attestation chain bound
  to a server-issued nonce) and a server reaches the *verdict*. Part C enumerates the eleven
  server-side checks in pseudocode, including the two that are usually missing: revocation, and
  `securityLevel != SOFTWARE`.

> **The note in that file worth repeating here.** Part B is strictly better than Part A and it still
> has real costs — a server, a network dependency, and rejection of some legitimate devices whose
> attestation is absent or broken. If a team chose Part A deliberately with those tradeoffs
> understood and something else compensating, the finding is **Informational**. If Part A is the only
> gate on a payment or credential flow, it is a control failure. Report the difference, not the
> pattern.

## Running the chapter's scripts against these files

```bash
# host, from the chapter root
python3 -B scripts/sparse-tool.py  selftest        # 15 checks, no input needed
python3 -B scripts/vbmeta-flags.py selftest        # 19 checks, no input needed

# with a real vbmeta of your own (see measured-avd-boot-state.md section 5 for how to pull one)
python3 -B scripts/vbmeta-flags.py show vbmeta.img
python3 -B scripts/vbmeta-flags.py set  vbmeta.img out.img --disable-verity
python3 -B scripts/vbmeta-flags.py diff vbmeta.img out.img

# against your own device -- read-only, no reboot
./scripts/bootstate-audit.sh

# against your host tooling -- no device at all
./scripts/fastboot-recon.sh --host-audit
```

## Related

- [`../labs/`](../labs/) — four labs, none of which asks you to unlock or flash anything
- [`../scripts/`](../scripts/) — the five tools these examples exercise
- [`../../20-Security-Architecture/scripts/parse-vbmeta.py`](../../20-Security-Architecture/scripts/parse-vbmeta.py)
  — the full vbmeta parser; this chapter's `vbmeta-flags.py` is deliberately narrower
- [`../../62-Magisk/labs/lab-01-root-a-device.md`](../../62-Magisk/labs/lab-01-root-a-device.md)
  — where the destructive procedure lives, and where it belongs
