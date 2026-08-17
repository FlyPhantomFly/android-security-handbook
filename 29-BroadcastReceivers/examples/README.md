# `29-BroadcastReceivers/examples/` — what is here and how the pieces fit

Every file in this directory is a **source file**, not a build artefact. Nothing here
is an APK, a `.dex` or a `.class`. [`build.sh`](build.sh) produces those locally, in
one command, from files you can read first.

---

## The files

| File | Package | What it is |
|---|---|---|
| [`ConfigSyncReceiver-vulnerable.java`](ConfigSyncReceiver-vulnerable.java) | `com.example.vault` | A receiver that trusts a forgeable custom action because a protected one sits beside it in the same filter. Six numbered bugs. |
| [`ConfigSyncReceiver-fixed.java`](ConfigSyncReceiver-fixed.java) | `com.example.vault` | The same feature with all six fixed. Two receivers instead of one, `RECEIVER_NOT_EXPORTED`, an allowlist instead of a URL extra. |
| [`VaultApplication.java`](VaultApplication.java) | `com.example.vault` | **The half no manifest audit can see.** Registers two more receivers at runtime — one unguarded, one a priority-999 ordered interceptor. |
| [`AndroidManifest-vulnerable.xml`](AndroidManifest-vulnerable.xml) | `com.example.vault` | The declaration the vulnerable receiver relies on, annotated with three separate mistakes. |
| [`AndroidManifest-fixed.xml`](AndroidManifest-fixed.xml) | `com.example.vault` | The remediated declaration. Diff it against the one above. |
| [`AttackerBroadcaster.java`](AttackerBroadcaster.java) | `com.attacker.bcast` | Five attacks, in an app that declares **no permissions at all**: forge implicit, forge explicit, harvest the ordered result, intercept, eavesdrop. |
| [`CtfVaultReceivers.java`](CtfVaultReceivers.java) | `com.example.vaultctf` | The target for [lab-04](../labs/lab-04-ctf-the-receiver-that-is-not-there.md). Five flags across five primitives. **Contains the answers — do not read it before attempting the CTF.** |
| [`build.sh`](build.sh) | — | `aapt2` + `javac` + `d8` + `apksigner`. No Gradle. `--fixed` and `--ctf` select the other variants. |

---

## Path convention

The path comments at the top of each file name the file **as it lives in this
repository**, flat, not as it would sit in an Android module. In a real project
`ConfigSyncReceiver-vulnerable.java` would be
`app/src/main/java/com/example/vault/ConfigSyncReceiver.java`, and the two manifests
would both be `app/src/main/AndroidManifest.xml` in different branches. The flat
layout is deliberate: it puts the vulnerable and fixed versions of the same class
side by side, which is the point of reading them.

`build.sh` handles the mapping.

---

## The order to read them in

1. **`AndroidManifest-vulnerable.xml`** — audit it as you normally would. Write down
   how many receivers this app has.
2. **`VaultApplication.java`** — you were wrong. There are four, and the two you
   missed are worse than the two you found.
3. **`ConfigSyncReceiver-vulnerable.java`** — why "BOOT_COMPLETED is protected"
   protects nothing.
4. **`AttackerBroadcaster.java`** — what that costs, from an app with no permissions.
5. **`ConfigSyncReceiver-fixed.java`** and **`AndroidManifest-fixed.xml`** — the
   remediation, as code.

---

## Proving the gap on a live device

The claim that a runtime-registered receiver is invisible to static analysis is
worth testing rather than believing. With the vulnerable app installed and running:

```bash
# host — what the manifest says
aapt2 dump xmltree --file AndroidManifest.xml build/vault-vulnerable.apk | grep -A3 receiver

# host — what the platform's static resolver knows
adb shell cmd package query-receivers --brief -a com.example.vault.ACTION_WIPE_CACHE

# host — what is actually listening
python3 ../scripts/receiver-surface.py --package com.example.vault

# host — the class names, which none of the above can give you
frida -U -f com.example.vault -l ../scripts/hook-broadcast.js
```

The second command returns `No receivers found`. The third lists the receiver. That
disagreement is the chapter.

The same comparison against a stock Android 11 device, with no lab app involved at
all, produced the numbers quoted in [the README](../README.md#7-dynamic-analysis):
**299 of 431** distinct actions registered by third-party-uid processes had *zero*
manifest-declared receivers anywhere on the device.

---

## Building, and the install restriction

```bash
# host
export ANDROID_HOME=~/Android/Sdk        # or wherever your SDK lives
./build.sh                               # vulnerable variant
./build.sh --fixed                       # remediated variant
adb install -r build/vault-vulnerable.apk
```

The physical device this chapter was measured on — a Redmi `M2101K6P`, MIUI 12.5,
Android 11 / API 30 — **refuses every `adb install` with
`INSTALL_FAILED_USER_RESTRICTED`.** That is an OEM policy, not a fault in the APK.
Use an emulator for anything that needs an installed app;
[`labs/lab-01`](../labs/lab-01-map-the-runtime-receiver-surface.md) and
[`labs/lab-03`](../labs/lab-03-ordered-broadcasts-and-interception.md) were written
so their measurement halves run on a restricted device with no app installed at all.

---

## Related

- [Chapter 29 README](../README.md) — the reasoning behind every annotation here
- [`../scripts/receiver-surface.py`](../scripts/receiver-surface.py) — enumerate the runtime surface
- [`../scripts/hook-broadcast.js`](../scripts/hook-broadcast.js) — recover class names and export state
- [`../scripts/protected-broadcast-map.sh`](../scripts/protected-broadcast-map.sh) — which actions can actually be forged
- [26-Intent](../../26-Intent/README.md) — the Intent itself, resolution, and redirection
- [32-Manifest](../../32-Manifest/README.md) — auditing the declaration
