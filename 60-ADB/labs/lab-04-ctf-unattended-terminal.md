# Lab 04 — CTF: The unattended terminal

> **Five flags on one badly configured device.** Fingerprint it from bytes alone, get a shell
> without the `adb` client, find the install that was never finished, work out who is authorised to
> drive it, and then write the finding that a client would act on. The last flag is not a string.

**Difficulty:** Advanced
**Time:** 3–5 hours
**Prerequisites:** [Lab 01](lab-01-read-the-wire.md), [Lab 02](lab-02-speak-the-protocol.md),
[Lab 03](lab-03-posture-and-exposure.md)
**You will need:** an **emulator** — this scenario must not be built on a device you use.

---

## The brief

> Northgate Centre has forty-one self-service terminals. They take card payments, print receipts and
> run an Android application the operator's IT supplier maintains remotely. All forty-one were imaged
> from the same master.
>
> You have been given network access to the mall's guest wifi and a scope that reads: *"assess the
> terminal estate; do not disrupt trading."*
>
> A port scan of the guest network found one host answering on **TCP 5555**.
>
> Everything else, you find out yourself.

You are simulating that terminal with an emulator, because an emulator ships in exactly the
configuration these devices ship in: `ro.adb.secure=0`, `ro.debuggable=1`, and a listening ADB port.
**That is not a convenient fiction. It is the actual configuration that self-propagating ADB malware
colonised across set-top boxes, TVs and embedded boards from 2018 onward.**

---

## Setup

```bash
# host — boot a disposable emulator
"$ANDROID_HOME/emulator/emulator" -avd <name> -no-window -no-audio -no-snapshot -no-boot-anim &
adb wait-for-device && adb devices -l
```

```bash
# host — plant the scenario
cd 60-ADB/labs
./ctf-setup.sh -s emulator-5554
```

The setup script refuses to run against anything whose serial does not begin with `emulator-`, and
it says why in its own header. Read that header before you run it — it is a worked example of a
script that will not let you damage something.

**Tear down when you are done:**

```bash
# host
./ctf-setup.sh -s emulator-5554 --teardown
```

### The rules

1. **No `adb` client for flags 1 and 2.** You are simulating an unknown host on a network. Use
   [`../scripts/adb-mini-client.py`](../scripts/adb-mini-client.py) or, better, the client you wrote
   in Lab 02.
2. **Do not send `A_AUTH(RSAPUBLICKEY)`.** In the story this is somebody else's device. Pass
   `--no-offer-key` and mean it.
3. **Do not use any of `root:`, `tcpip:`, `usb:`, `remount:`, `reboot:` as part of enumeration.**
   `adb root` is permitted once you have *established* that the build allows it — that is Flag 3 —
   but it is an action you take deliberately and record, not something you do while poking around.
4. **Record every command you run.** Flag 5 is the report, and a report you cannot reproduce is not
   a report.

Flags are of the form `CH60{...}`.

---

## Flag 1 — Recon: identify the terminal without authenticating

> You have an IP and a port. You have no credential, no `adb` client, and no idea what the device
> is. Establish what it is, using nothing but the protocol.

**What to produce:** the value of `ro.product.device` that the device volunteers, submitted as
`CH60{banner_is_<value>}`.

### Working

<details>
<summary>Hint 1 — where does a device tell you what it is?</summary>

Before any stream is opened. Before any authentication. Look at what comes back from `A_CNXN`.

</details>

<details>
<summary>Hint 2 — the command</summary>

```bash
# host
python3 -B ../scripts/adb-mini-client.py --host 127.0.0.1 --port 5555 \
        --handshake-only --no-offer-key
```

</details>

<details>
<summary>Solution</summary>

```
  -> A_CNXN  version=0x01000001 maxdata=262144
  <- A_CNXN  version=0x01000001 maxdata=262144
     systemtype : device
     serial     : (empty)
     banner     : ro.product.name=sdk_gphone16k_x86_64;
                  ro.product.model=sdk_gphone16k_x86_64;
                  ro.product.device=emu64xa16k;
                  features=shell_v2,cmd,stat_v2,ls_v2,…
```

On the emulator used to write this lab, the answer is
**`CH60{banner_is_emu64xa16k}`** — yours will match your own image.

</details>

### The point of Flag 1

You have just fingerprinted a device on a network with **zero credentials, zero interaction, and no
log entry that any human will ever look at.** The banner leaks the product name, the model, the
device codename and a feature list that pins down the Android version.

Two things follow, and both belong in your report:

- **The device required no authentication.** `A_AUTH` never appeared. Compare with what would have
  happened on a device with `ro.adb.secure=1` — see the end of
  [`../examples/handshake-transcript.txt`](../examples/handshake-transcript.txt).
- **The feature list is a version fingerprint.** `delayed_ack`, `openscreen_mdns` and `app_info`
  place this build in the Android 14+ range; a device advertising only twelve features is much older.
  Record the whole list.

---

## Flag 2 — Access: get a shell, and read the operator's configuration

> The provisioning team left something on the device. Find it, still without the `adb` client.

**What to produce:** the flag string inside the operator configuration file.

### Working

<details>
<summary>Hint 1 — where would a fleet tool put files?</summary>

Somewhere the `shell` user can write, because the provisioning tool ran as `shell` over ADB. There
is essentially one such directory on an Android device.

</details>

<details>
<summary>Hint 2 — the enumeration</summary>

```bash
# host
python3 -B ../scripts/adb-mini-client.py --port 5555 --no-offer-key \
        --service "shell:ls -la /data/local/tmp"
```

</details>

<details>
<summary>Solution</summary>

```bash
# host
python3 -B ../scripts/adb-mini-client.py --port 5555 --no-offer-key \
        --service "shell:ls -la /data/local/tmp/kiosk"
python3 -B ../scripts/adb-mini-client.py --port 5555 --no-offer-key \
        --service "shell:cat /data/local/tmp/kiosk/operator.json"
```

```json
{
  "site": "Northgate Centre - Level 2 - Unit 14",
  "terminal_id": "NGC-L2-014",
  "support": {
    "note": "Debug access left enabled so support can reach units remotely.",
    "adb_over_network": true,
    "port": 5555
  },
  "operator_pin": "4417",
  "flag": "CH60{unauthenticated_shell_on_a_public_network}"
}
```

**`CH60{unauthenticated_shell_on_a_public_network}`**

</details>

### The point of Flag 2

Read `provisioning.log` in the same directory. It is the whole story:

```
2026-03-02 09:39:55  fleet-tool  install-create  (session opened)
2026-03-02 09:40:31  fleet-tool  install-write   8538 bytes streamed
2026-03-02 09:40:31  fleet-tool  ERROR: link lost before install-commit
2026-03-02 09:41:00  fleet-tool  giving up, marking terminal provisioned anyway
```

Three separate steps, named exactly as the protocol names them. That log is your bridge to Flag 3,
and it is written the way it is because **that is genuinely what `adb install` does** — see
[60-ADB §3.14](../README.md#314-adb-install-is-three-streams--the-transport-half).

Also note what you did *not* need: no exploit, no vulnerability, no CVE. You typed a service string
and the device gave you a shell.

---

## Flag 3 — The install that never finished

> The provisioning log says an install was written but never committed. Find what was left behind.

**What to produce:** the flag inside the staged package.

### Working

<details>
<summary>Hint 1 — where does a session live before it is committed?</summary>

`install-create` returns a session id and creates a staging directory. It is under `/data/app/` and
its name contains the session id. It is **not** visible to `pm list packages`, because nothing was
installed.

</details>

<details>
<summary>Hint 2 — you will not be able to read it as `shell`</summary>

The staging directory is owned by `system`. You need more privilege. Go back to Flag 1's banner and
work out what this build permits — then check the property that decides it.

</details>

<details>
<summary>Hint 3 — the decision you are about to make</summary>

```bash
# host — is elevation permitted on this build?
python3 -B ../scripts/adb-mini-client.py --port 5555 --no-offer-key \
        --service "shell:getprop ro.debuggable; getprop ro.secure; getprop ro.build.type"
```

`ro.debuggable=1` means the `root:` service will restart `adbd` as uid 0. **On a real engagement
this is a deliberate, disruptive action you get authorisation for and record with a timestamp** —
it restarts the daemon and drops every existing connection. Here, the emulator is disposable.

</details>

<details>
<summary>Solution</summary>

```bash
# host — elevate (recorded as a deliberate action)
adb -s emulator-5554 root
adb -s emulator-5554 wait-for-device

# host — find the orphaned session
adb -s emulator-5554 shell 'ls -ld /data/app/vmdl*.tmp'
# drwx------ ... /data/app/vmdl1323012087.tmp

adb -s emulator-5554 shell 'ls -l /data/app/vmdl1323012087.tmp'
# -rw-r--r-- 1 system system 8599 ... base

# host — take a copy and open it
adb -s emulator-5554 pull /data/app/vmdl1323012087.tmp/base staged.apk
unzip -l staged.apk
unzip -p staged.apk assets/flag.txt
```

**`CH60{staged_but_never_committed}`**

Return the daemon to normal afterwards:

```bash
# host
adb -s emulator-5554 unroot
```

</details>

### The point of Flag 3

You have recovered a complete, signed APK that **was never installed**, that `pm list packages` has
never heard of, and that no app inventory on that device will ever show. It sat there because a link
dropped between `install-write` and `install-commit`.

That is a real incident-response artefact. An orphaned `/data/app/vmdl*.tmp` on a device you are
examining means an install was started over some transport and abandoned — and the APK is right
there to hash and analyse.

It is also the clearest demonstration of why the three-stream model matters. If `adb install` were
one atomic operation, this state could not exist.

> **Bonus:** examine the staged APK's signing certificate with
> `apksigner verify -v --print-certs staged.apk`. Who signed it? On this scenario it is the Android
> debug keystore — which, on a payment terminal, would itself be a finding worth a paragraph.

---

## Flag 4 — Who is allowed to drive this device?

> Establish which hosts are authorised to connect, and what that tells you about the fleet.

**What to produce:** `CH60{keys_<count>_<one-word verdict>}`, where the verdict is the single word
that best describes what you found. Get the count right and the reasoning right; the exact word
matters less than the argument you make for it.

### Working

<details>
<summary>Hint 1 — where does Android record authorised hosts?</summary>

Two files, in one directory, under `/data/misc/`. One is the permanent list; the other records when
each key was last used and drives the automatic expiry.

</details>

<details>
<summary>Hint 2 — you will be denied, and that is data</summary>

Try to read them as `shell` first, and find out **which** access control refuses you. Then try with
root.

</details>

<details>
<summary>Solution</summary>

```bash
# host — as shell
python3 -B ../scripts/adb-mini-client.py --port 5555 --no-offer-key \
        --service "shell:ls -ld /data/misc/adb"
# ls: /data/misc/adb: Permission denied
```

Denied — and on a normal device this is SELinux, not file permissions:

```
avc: denied { search } for comm="ls" name="adb"
     scontext=u:r:shell:s0 tcontext=u:object_r:adb_keys_file:s0 tclass=dir
```

With root:

```bash
# host
adb -s emulator-5554 root && adb -s emulator-5554 wait-for-device
adb -s emulator-5554 shell 'ls -la /data/misc/adb/ 2>&1'
adb -s emulator-5554 shell 'wc -l /data/misc/adb/adb_keys 2>&1'
adb -s emulator-5554 shell 'cat /data/misc/adb/adb_temp_keys.xml 2>&1'
adb -s emulator-5554 unroot
```

On this scenario, **`adb_keys` is empty or absent and the count is zero.**

**`CH60{keys_0_irrelevant}`** — and the reasoning is the flag.

</details>

### The point of Flag 4

Zero authorised keys, and you still have a root shell.

That is the finding. On a device with `ro.adb.secure=1`, the authorised-key list is the access
control and counting it tells you how many hosts can connect. **On this device the list is
irrelevant, because authentication is switched off entirely.** A tester who checks only the key
count on a device like this concludes "no authorised hosts, no exposure" and is exactly wrong.

Two things to write down:

- **Order your checks correctly.** `ro.adb.secure` first. Only if it is `1` does the key store mean
  anything.
- **Never record key material.** Counts, file sizes, modes and `lastConnection` timestamps. A public
  key plus its comment identifies an authorised host, and the comment is unauthenticated text
  somebody chose.

If you want to see what a *real* key store looks like, run the same commands against a phone you
own and have authorised. You will find one entry, 714 bytes, whose base64 field is exactly 700
characters — the fixed width of a 2048-bit ADB public key.

---

## Flag 5 — The report

> There is no string for this one. Produce the finding.

**What to produce:** a written finding, of the shape this repository uses everywhere: vulnerable
configuration → why it exists → detection → impact → remediation as code → honest severity.

### The facts you have

| | |
|---|---|
| TCP 5555 | listening, reachable from the mall's guest wifi |
| `ro.adb.secure` | `0` — no authentication of any kind |
| `ro.debuggable` | `1` — `adb root` is honoured |
| `ro.secure` | `1` — but irrelevant given the line above |
| Authorised keys | zero, and it does not matter |
| Device role | unattended self-service payment terminal, bolted down, never rebooted |
| Fleet | 41 units, all imaged from the same master |
| Also present | an operator PIN in a world-readable file, and an orphaned staged APK |

### The rubric

A finding that would score full marks:

- [ ] **Names the device role in the first sentence.** A severity without a stated role is a guess.
- [ ] **States that no credential is required**, and distinguishes that from "a credential exists but
      is weak" — they have completely different remediations.
- [ ] **Notes that `ro.debuggable=1` escalates it** from a remote `shell` to a remote root shell, and
      says what `shell` alone would already have been (183 install permissions, `INSTALL_PACKAGES`,
      `WRITE_SECURE_SETTINGS`, `READ_LOGS`, non-revocable `CAMERA` and `RECORD_AUDIO`).
- [ ] **Generalises to the fleet.** One master image, 41 units. This is not a finding about one
      terminal.
- [ ] **Includes reproduction steps a client's engineer can follow** — and notes that they need no
      special tooling, which is the point.
- [ ] **Rates it CRITICAL, and defends the rating** on reachability, lack of authentication,
      persistence across reboot, device role and blast radius — not on the fact that ADB exists.
- [ ] **Gives remediation as configuration**, not as advice.
- [ ] **Separates the secondary findings**: the operator PIN in a world-readable file, and the
      orphaned staged APK signed with a debug key. Each gets its own rating.
- [ ] **Says what you did not test and why.** You did not test the payment application. You did not
      pivot to other units. Scope discipline is part of the deliverable.

### Model remediation

```
# device image — production posture, gated in CI rather than by convention
ro.secure=1
ro.debuggable=0
ro.adb.secure=1
# and NO persist.adb.tcp.port anywhere in the image
```

```bash
#!/usr/bin/env bash
# host — the release gate. Run against a device flashed with a candidate image.
# Any FAIL blocks the build.
set -euo pipefail
fail=0
check() {
  actual="$(adb shell getprop "$1" | tr -d '\r')"
  [ "$actual" = "$2" ] && echo "ok    $1 = $actual" \
    || { echo "FAIL  $1 = '$actual', expected '$2'"; fail=1; }
}
check ro.secure     1
check ro.debuggable 0
check ro.adb.secure 1
check ro.build.type user

for p in service.adb.tcp.port persist.adb.tcp.port; do
  v="$(adb shell getprop "$p" | tr -d '\r')"
  [ -z "$v" ] || [ "$v" = "-1" ] && echo "ok    $p unset" \
    || { echo "FAIL  $p = $v"; fail=1; }
done

adb shell 'ls /adb_keys' >/dev/null 2>&1 \
  && { echo "FAIL  a ramdisk /adb_keys exists -- a vendor key is baked in"; fail=1; } \
  || echo "ok    no ramdisk /adb_keys"

exit $fail
```

And the operational half, which the configuration alone does not solve: the supplier needs a way to
reach these units for support. Say so, and propose one — per-device short-lived credentials, or an
outbound-initiated management channel, rather than a listening debug port. **A remediation that
ignores why the misconfiguration existed will be reverted within a quarter.**

---

## Scoring

| Flag | Points | What it proves |
|---|---|---|
| 1 | 10 | You can fingerprint an ADB endpoint from the protocol alone |
| 2 | 15 | You can drive a device with no vendor client |
| 3 | 25 | You understand that `adb install` is three streams, and you can recover the evidence that proves it |
| 4 | 20 | You check the controls in the right order, and you know what the key store is and is not |
| 5 | 30 | You can turn a measurement into a finding somebody will act on |

**Bonus points**

| | Points | |
|---|---|---|
| Solve flags 1 and 2 with a client **you** wrote in Lab 02, not the one shipped here | +15 | |
| Produce a full `--verbose` wire transcript for flag 1 and annotate every message | +10 | |
| Identify the signing certificate on the staged APK and explain why it matters | +10 | |
| Write a detection rule (network or host) that would have caught this fleet | +15 | |

---

## Tear down

```bash
# host
./ctf-setup.sh -s emulator-5554 --teardown
adb -s emulator-5554 unroot
adb -s emulator-5554 emu kill      # or just close the emulator
```

Confirm the staging directory is gone and `/data/local/tmp/kiosk` no longer exists. Leaving a
scenario running is how a lab artefact ends up in somebody's real report.

---

## Debrief — what this scenario is really teaching

**Nothing here was an exploit.** Every step used documented behaviour, working exactly as designed.
The device was compromised by its configuration, and no patch would have changed anything.

**The severity came from context, not from technology.** The identical facts on your bench are a
methodology note. On a payment terminal on a public network they are critical. If you can only rate
findings by their technical shape, you will be wrong in both directions.

**The transport is dumb and that is deliberate.** `adbd` does not decide what you are allowed to do
— it opens a stream and lets the service, `system_server`, SELinux and the package manager make
those decisions. Once you internalise that, the question "why did this command fail" becomes
answerable: you ask which layer refused, and each layer refuses in a different, recognisable way.

**The most valuable artefact was the one nobody meant to leave.** The orphaned staging directory was
not a security control, a log or a feature. It was a side effect of an interrupted three-step
protocol, and it held a complete signed APK. Understanding the *mechanism* is what let you know to
look for it — no tool would have told you.

---

## Where to go next

- [77-UsefulCommands](../../77-UsefulCommands/README.md) — the command set that rides on everything
  you have just learned.
- [09-Android-App-Internals](../../09-Android-App-Internals/README.md) — what happens *after*
  `install-commit`.
- [22-SELinux](../../22-SELinux/README.md) — the AVC you met in Flag 4, in depth.
- [23-Permissions](../../23-Permissions/README.md) — where `shell`'s 183 grants come from.
- `61-Fastboot` — the other protocol that can talk to a device, with no Android userspace behind it.
