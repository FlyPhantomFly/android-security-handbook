# `malicious-module-defanged` — a hostile module, neutered

> **DO NOT INSTALL THIS ON ANY DEVICE.**
> Not on a test device, not on an emulator, not "just to see". It is defanged, and it is still not
> something to put on a device: the *point* of the exercise is to catch it by reading, and installing
> it teaches you nothing you could not learn from `cat`.

This directory is a **teaching fixture** for [Lab 04](../../labs/lab-04-module-audit.md). It is a
Magisk module written to do everything a trojanised module actually does, so that you can practise
finding it, describing it precisely, and writing the finding.

---

## How it is defanged

Every hostile action is present **as text** and absent **as behaviour**. The mechanism is a single
shell function defined at the top of each script:

```sh
would() {
    echo "[DEFANGED] would have run: $*" >> "$LAB_LOG"
    return 0
}
```

`would` prints its arguments and returns success. It never executes them. There is no flag, no
environment variable and no code path in this fixture that turns the wrapper off — deliberately,
because an "arming switch" is exactly the kind of thing that gets flipped by accident.

So `would pm install /data/local/tmp/payload.apk` is a line that:

- **reads** exactly like the real thing, and will be found by every audit technique in lab 04;
- **does** nothing except append a line to a log file.

Every URL uses the reserved `.invalid` top-level domain (RFC 2606), which cannot resolve, so even a
copy-paste accident reaches nothing.

---

## What it pretends to be

`module.prop` presents it as a battery and performance tweak — the most common cover story in the
module ecosystem, because it explains away property changes and gives a reason to run at boot. The
description carries the fixture warning; in the wild it would not.

## What it actually does

Nine distinct hostile behaviours, spread across three boot stages so that no single file looks
alarming on its own. Finding all nine is the lab.

| # | Where | Behaviour |
|---|---|---|
| 1 | `customize.sh` | Silently installs a second APK at module-install time |
| 2 | `customize.sh` | Grants that APK runtime permissions with no user interaction |
| 3 | `post-fs-data.sh` | Fetches a payload from the network at every boot, as root, before any security software exists |
| 4 | `post-fs-data.sh` | Decodes and executes the fetched blob |
| 5 | `post-fs-data.sh` | Reads another application's private data directory |
| 6 | `post-fs-data.sh` | Edits Magisk's own policy database to auto-grant root to its APK |
| 7 | `post-fs-data.sh` | Sets the immutable attribute on its own files so they resist deletion |
| 8 | `service.sh` | Enables an accessibility service, which is full screen-read and input injection |
| 9 | `service.sh` | Exfiltrates a device inventory to a remote host |

Plus three things visible without reading any script at all:

| Where | Behaviour |
|---|---|
| `sepolicy.rule` | Makes `untrusted_app` permissive — that is every ordinary app on the device |
| `system/etc/hosts` | Redirects name resolution device-wide |
| `system/etc/security/cacerts/` | Adds a CA to the system trust store, making all TLS interceptable by whoever holds the key |

---

## Why a fixture like this is necessary

Reading the chapter's §5.1 and nodding is not the same as recognising the shape under time pressure.
There is no code signing on Magisk modules, no review, no permission prompt and no revocation. The
entire control is a human reading a shell script — and people are bad at reading shell scripts they
expect to be fine.

The realistic threat is not that someone writes this and posts it. It is that a **popular, genuinely
useful module changes hands**, or its author's account is compromised, and version 4.3 contains
eleven lines that version 4.2 did not. The audit is not something you do once; it is something you
do at every update, which is why [`../../scripts/audit-magisk-module.sh`](../../scripts/audit-magisk-module.sh)
exists and why its output is designed to be diffed.

---

## Using it

```bash
# host — build the three archives lab 04 audits, in a SCRATCH directory
mkdir -p /tmp/lab04 && cd /tmp/lab04
for m in system-ca-module pentest-prep-module malicious-module-defanged; do
  ( cd "<path-to>/62-Magisk/examples/$m" && zip -qr "/tmp/lab04/$m.zip" . -x '.*' -x 'README.md' )
done
ls -la /tmp/lab04/
```

Then audit them. Do it by hand first, then with the script, and compare what each found:

```bash
# host
<path-to>/62-Magisk/scripts/audit-magisk-module.sh /tmp/lab04/*.zip | tee audit.txt
```

Delete `/tmp/lab04` afterwards. Do not leave module archives lying about with names that suggest
they are legitimate.

---

## If you are reading this because you found it in a search

This is not malware. It cannot run. It is a deliberately inert training artefact in a security
education repository, and every dangerous line in it is wrapped in a function that prints instead of
executing. If you need to verify that claim rather than take it on trust — which is the correct
instinct — read the `would()` definition at the top of each `.sh` file and confirm that no other
code path exists.
