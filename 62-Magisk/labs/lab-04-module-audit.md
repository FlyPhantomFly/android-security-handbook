# Lab 04 — Module Supply-Chain Audit

**Difficulty:** Advanced
**Time:** 3–4 hours
**Prerequisites:** [Lab 02](lab-02-write-a-module.md) — you must have written a module before you can
read one critically; [Chapter 62 §3.5](../README.md#35-boot-stages-and-when-your-code-runs),
[§3.6](../README.md#36-module-structure), [§5.1](../README.md#51-how-attackers-abuse-root),
[§8.1](../README.md#81-analysing-a-magisk-module-before-installing-it),
[§5.5](../README.md#55-how-forensic-analysts-view-a-magisk-device)

---

## The situation

You maintain a fleet of test devices for a security practice. A colleague sends you three module
archives with the message: *"these are the ones I use, they're all fine."*

Your job is to decide, with evidence, whether each may be installed on a device that will later hold
an authorised client's test data — and to write the finding for the one that may not.

> **Do not install any of these on a device.** Everything in this lab is done on the host, from
> the archive. That constraint is not a safety rail added on top of the exercise; it *is* the
> exercise. The only moment at which you get to make this decision is before installation.

---

## Objective

Audit three Magisk module archives statically, enumerate **every** behaviour of the hostile one
precisely enough that a developer could reimplement it, identify the behaviours a static audit
cannot see at all, produce the post-installation forensic checklist for a device already carrying
it, and write the finding.

You are told in advance which archive is hostile. That is deliberate. "Which one is bad" is the easy
half and it is not what a real report needs; **complete and precise enumeration** is the hard half,
and a report that catches seven of nine behaviours is a report that leaves two behaviours running on
the client's device.

## Why this matters

Magisk modules have **no code signing, no review, no permission model, no sandbox and no
revocation.** Installing one grants its author a root shell that executes at every boot, at
`post-fs-data`, before zygote, before any application, before any security software, and before any
logging you control. The entire control is a human reading a shell script.

The realistic threat is not somebody writing a blatantly hostile module and posting it. It is:

- a genuinely useful, popular module **changing hands**, and version 4.3 containing eleven lines
  that version 4.2 did not;
- an author's account, build machine, or distribution channel being compromised;
- a module distributed through a forum thread or a Telegram channel where nobody can tell you what
  the bytes were yesterday.

This is a supply-chain problem with the review step removed, and the review step is you. Section 5.1
of the chapter states it in one sentence: *"Installing a Magisk module is equivalent to giving the
module's author a permanent root shell on your device that runs at every boot before the framework
starts."*

---

## Setup

### Build the three archives

Build into a **scratch directory outside this repository**. Module archives are build artefacts and
must never be committed.

```bash
# host
WORK=$(mktemp -d)
REPO=<path-to>/Android-Pentesting-Notes/62-Magisk
echo "working in $WORK"

for m in system-ca-module pentest-prep-module malicious-module-defanged; do
  ( cd "$REPO/examples/$m" && zip -qr "$WORK/$m.zip" . -x '.*' -x '__MACOSX/*' -x 'README.md' )
done
ls -la "$WORK"
```

The CA module needs a certificate in it or its overlay will be empty. Generate a throwaway one — do
**not** reuse your real proxy CA for a lab fixture:

```bash
# host — a self-signed CA that exists only for this exercise
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$WORK/lab-ca.key" -out "$WORK/lab-ca.pem" \
  -subj "/CN=LAB THROWAWAY CA DO NOT TRUST" >/dev/null 2>&1
HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$WORK/lab-ca.pem" | head -1)

mkdir -p "$WORK/ca/system/etc/security/cacerts"
cp "$REPO/examples/system-ca-module/module.prop"  "$WORK/ca/"
cp "$REPO/examples/system-ca-module/customize.sh" "$WORK/ca/"
cp "$WORK/lab-ca.pem" "$WORK/ca/system/etc/security/cacerts/${HASH}.0"
( cd "$WORK/ca" && zip -qr "$WORK/system-ca-module.zip" . -x '.*' )
```

### The rule for the next 90 minutes

**Do not open `examples/malicious-module-defanged/README.md`.** It contains the answer key. Read it
in Part 3, after you have produced your own enumeration, and score yourself honestly.

Do read the fixture's in-file banner comments if you like — they tell you it is defanged, which you
should confirm rather than assume, and they do not tell you what the nine behaviours are.

---

## Part 1 — Audit by hand, with no script (60 minutes, timed)

Do this first. The script in Part 2 will find things you missed, and you will remember them; if you
run the script first you will learn nothing about your own reading.

Work through this procedure on **each** archive. Keep a worksheet.

### Step 1 — Identity, before extraction

```bash
# host
cd "$WORK"
for z in *.zip; do
  echo "=== $z"
  ls -la "$z"
  sha256sum "$z"
done
```

**Q1.** Magisk modules are not signed. What, then, is the hash for? Under what circumstances does
recording it actually protect you, and under what circumstances is it theatre?

### Step 2 — Layout, before extraction

```bash
# host
unzip -l malicious-module-defanged.zip
```

Read the file list before you read any file. Three things are visible here alone:

- Is `module.prop` at the archive **root**? (If not, Magisk rejects it.)
- Are there path components containing `..`? (Zip-slip: extraction writing outside the target
  directory.)
- What is in `system/`? Every path under there will be bind-mounted onto the running device.

**Q2.** From the file listing alone, before extracting anything, name two behaviours of the hostile
module that you can already assert. State them as you would in a report — the observation, then the
consequence.

### Step 3 — Extract to somewhere disposable

```bash
# host
mkdir -p "$WORK/x" && cd "$WORK/x"
unzip -o ../malicious-module-defanged.zip -d evil/
find evil -type f | sort
```

### Step 4 — Enumerate what runs, and when

This is the core of the audit. For each archive, fill in this table:

| File | Boot stage | Blocking? | Present? |
|---|---|---|---|
| `customize.sh` | install time, in the installer | n/a | |
| `post-fs-data.sh` | after `/data`, **before zygote** | **yes** | |
| `service.sh` | `late_start` | no | |
| `boot-completed.sh` | after `sys.boot_completed=1` | no | |
| `uninstall.sh` | at removal | n/a | |
| `META-INF/com/google/android/update-binary` | install time | n/a | |

**Q3.** Why does a hostile module split its work across `post-fs-data.sh` and `service.sh` rather
than putting it all in one? Answer in terms of what exists at each stage — and then note what that
means for an auditor who reads only one file.

### Step 5 — Read every script, top to bottom

```bash
# host
for f in evil/customize.sh evil/post-fs-data.sh evil/service.sh; do
  echo "########## $f"
  cat -v "$f"
done
```

`cat -v` rather than `cat`, so that control characters and other invisible content are shown rather
than interpreted. A script that looks empty in `cat` and has content in `cat -v` is telling you
something.

For each line that does anything other than log, write down: **what it does**, **why the author's
stated purpose would need it**, and **what it costs the device owner if the stated purpose is a
lie.** The middle column is where the audit actually happens — most hostile lines are individually
plausible and collectively absurd.

### Step 6 — SELinux rules

```bash
# host
cat evil/sepolicy.rule
```

**Q4.** For each rule, state the **blast radius**: which processes are affected. Pay particular
attention to the difference between a rule naming the module's own domain and a rule naming
`untrusted_app`. Which one of those two is "this module needs a permission" and which is "every app
on your phone loses a boundary"?

### Step 7 — Properties

```bash
# host
cat evil/system.prop 2>/dev/null || echo "(none)"
```

**Q5.** The hostile module here sets no properties. Suppose it did, and suppose it set
`ro.debuggable=1`. Describe the consequence — not "the device looks debuggable", but what an
attacker with a foothold could then do that they could not before.

### Step 8 — The `system/` overlay

```bash
# host
find evil/system -type f | sed 's|^evil||'
cat evil/system/etc/hosts
```

**Q6.** Read the `hosts` file completely. Most of it is a real ad-block list. Three lines are not.
Identify them, state how you distinguished them from the rest mechanically (not by intuition), and
explain what those three lines plus the `cacerts` overlay achieve **together** that neither achieves
alone.

### Step 9 — Native code

```bash
# host
find evil -name '*.so' | sed 's|^evil||'
```

None here. But answer anyway:

**Q7.** If there *were* a `zygisk/arm64-v8a.so` in this archive, how would that change the audit —
in terms of what you could still determine statically, what you could not, and how much time the
audit would now need? Be specific about which chapter's techniques you would reach for.

### Step 10 — Everything else

```bash
# host
find evil -type f | sort
```

**Q8.** Anything that is not `module.prop`, not a documented script, not under `system/` and not
under `zygisk/` has no defined role in the module format. List what falls into that category here.
What does the presence of such a file tell you before you have opened it?

### Your worksheet

Before moving on, write down your complete enumeration in this form. Do not skip this — Part 2
depends on having a fixed record of what *you* found:

| # | Behaviour | File and line | Class | Impact if the stated purpose is a lie |
|---|---|---|---|---|
| 1 | | | persistence / privilege / exfiltration / evasion / other | |

---

## Part 2 — Now run the script, and diff against yourself

```bash
# host
"$REPO/scripts/audit-magisk-module.sh" "$WORK"/*.zip | tee "$WORK/audit.txt"
```

See [`../scripts/audit-magisk-module.sh`](../scripts/audit-magisk-module.sh). Read its header first:
it tells you what it deliberately does not do, and one of the skills here is knowing a tool's blind
spots before you trust its output.

Now produce two lists. Both matter, and the first matters more.

**List A — things you found that the script did not.**
Every entry here is a pattern worth adding to the script, or a judgement the script structurally
cannot make. Which is it, for each?

**List B — things the script found that you did not.**
Every entry here is a gap in your reading procedure. What would you change about Step 5 so that you
catch it next time?

**Q9.** Run the script against the two **benign** modules as well. What does a clean report look
like? Why is knowing that as important as knowing what a dirty one looks like?

**Q10.** The script prints a HIGH count and then says explicitly that the count is "not a verdict".
Argue for and against having it print a verdict. Then state which you would ship, and why.

> **Pentester's Note**
> Notice which of the hostile behaviours the script catches by **pattern** and which it catches by
> **structure**. `curl` in a boot script is a pattern match — trivially evaded by using a different
> downloader, or by writing the bytes with `dd`, or by having the payload arrive through a socket
> the module opens. `sepolicy.rule` containing `permissive untrusted_app` is structural — that rule
> means what it means regardless of how it is written. Structural checks age well; pattern checks
> are a treadmill. Weight your reading accordingly.

---

## Part 3 — Score yourself, and classify

Now read [`../examples/malicious-module-defanged/README.md`](../examples/malicious-module-defanged/README.md).
It lists nine scripted behaviours plus three that are visible without reading any script.

**Q11.** How many of the twelve did you find? For each one you missed, write a single sentence
saying what in your procedure would have had to change.

For each of the twelve, complete this:

| Behaviour | Class | Impact | **On-device detection signature** |
|---|---|---|---|

The last column is the one people skip and it is the most valuable. If you were handed a device and
asked "was this module ever installed here", what would you look for? Some behaviours leave
artefacts that outlive the module directory — that is the entire point of them.

**Q12.** Which of the twelve behaviours **survives removal of the module**? For each, say what the
device owner would have to do beyond `touch /data/adb/modules/devoptimizer/remove` to be
clean. This is the difference between "uninstalled" and "remediated", and clients ask about it.

---

## Part 4 — What a static audit cannot tell you

**Q13.** `post-fs-data.sh` fetches a payload from the network and executes it. You have read every
byte of the archive. What fraction of the code that will run on the device have you read?

**Q14.** List everything you would need to answer "what does this module actually do" for a
fetch-at-boot module. Include at least: what you would capture, from where, and what you would still
be unable to conclude afterwards.

**Q15.** A module you audit today passes cleanly. It auto-updates. Describe the control that makes
today's audit still meaningful next month, and be specific about who does what and when.

> **Mental Model**
> A static audit answers "what is in this archive". It does not answer "what will run on the
> device", and for any module that fetches, decodes, or branches on device state, those two questions
> have different answers. Say which one you answered. A report that claims the second while having
> performed the first is wrong in a way that is very hard for the reader to detect.

---

## Part 5 — Post-installation forensics

Different question, different role. You are handed a device that already has this module installed.
Establish what happened.

Work through this on a *clean* rooted device — you will find nothing, which is the point: you are
learning what "nothing" looks like so that you can recognise "something".

```bash
# adb shell as root — 1. what modules exist, and when did they arrive
ls -la /data/adb/modules/
for m in /data/adb/modules/*/; do
  echo "== $m"
  cat "$m/module.prop" 2>/dev/null
  ls -la --time-style=full-iso "$m" | head
done
```

```bash
# adb shell as root — 2. the su policy database: who was granted root, and when
magisk --sqlite "SELECT * FROM policies"
magisk --sqlite "SELECT * FROM settings"
ls -la /data/adb/magisk.db
```

```bash
# adb shell as root — 3. standalone boot scripts, which no module owns
ls -la /data/adb/service.d/ /data/adb/post-fs-data.d/
```

```bash
# adb shell as root — 4. immutable files, which resist deletion
lsattr -R /data/adb /data/local/tmp 2>/dev/null | grep -E '^....i' || echo "(none immutable)"
```

```bash
# adb shell as root — 5. the trust store and name resolution
ls -la /system/etc/security/cacerts/ | wc -l
ls -la /apex/com.android.conscrypt/cacerts/ 2>/dev/null | wc -l
cat /system/etc/hosts
```

```bash
# adb shell as root — 6. accessibility services, the highest-value grant on the device
settings get secure enabled_accessibility_services
settings get secure accessibility_enabled
```

```bash
# adb shell as root — 7. what ran, and when
cat /data/adb/magisk.log 2>/dev/null | tail -100
logcat -d -b all | grep -iE 'magisk|module' | tail -50
```

```bash
# adb shell as root — 8. staged payloads outside module directories
ls -la /data/local/tmp/
find /data/local/tmp -type f -newermt '-30 days' 2>/dev/null
```

**Q16.** For each of the eight checks above, say which of the twelve behaviours it would have caught,
and which behaviours are caught by **none** of them. Then add the checks that close those gaps.

**Q17.** Chapter [§5.5](../README.md#55-how-forensic-analysts-view-a-magisk-device) says to *"capture
`/data/adb` in its entirety and hash it before doing anything else."* Why before anything else?
Name two specific things that change if you reboot first.

---

## Part 6 — The update problem

The realistic attack is version 4.3 of a module you already audited at 4.2. Simulate it.

```bash
# host — construct the "previous, clean" version by removing the hostile lines
cp -r evil clean-v42
cd clean-v42
grep -v '^would ' post-fs-data.sh > tmp && mv tmp post-fs-data.sh
grep -v '^would ' service.sh      > tmp && mv tmp service.sh
grep -v '^would ' customize.sh    > tmp && mv tmp customize.sh
sed -i 's/^versionCode=43/versionCode=42/; s/^version=v4.3/version=v4.2/' module.prop
cd ..
```

```bash
# host — the diff a maintainer would actually run
diff -ru clean-v42 evil | head -100
```

**Q18.** How long did it take you to read that diff, compared with reading the whole module in
Part 1? What does that tell you about where to spend audit effort on a module you have audited
before?

**Q19.** An attacker who knows you diff will spread the change across a version series, or bury it
inside a large legitimate refactor. Design a control that survives that. (Hint: it is not a better
diff. Think about what you are willing to install at all, and about the boundary between "a device
that runs modules" and "a device that holds client data".)

---

## Part 7 — Write the finding

Now the deliverable. Write the finding as you would submit it.

### A bad finding, for contrast

> **Malicious Magisk module found.** The module `devoptimizer` is malware. It does lots of dangerous
> things including installing apps and stealing data. Severity: Critical. Recommendation: remove it.

Everything in that is defensible and none of it is useful. It does not say what was examined, does
not enumerate, gives no evidence, gives no remediation beyond removal — which, as Q12 established,
does not remediate — and it does not distinguish what was observed from what was inferred.

### The shape to write instead

| Section | Content |
|---|---|
| **Summary** | One sentence: what the artefact is, and what it does. |
| **What was examined** | The archive, its sha256, the date, and explicitly: *statically, without installation.* |
| **Findings** | The enumeration table. One row per behaviour, each with file and line. |
| **What was not examined** | The fetched payload; native code, if any; device-conditional branches not taken. State it plainly. |
| **Impact** | Concrete. Not "could compromise the device" but "grants an installed application root without a prompt, permanently, by writing a row into `/data/adb/magisk.db`". |
| **Evidence** | Command output, quoted, reproducible. |
| **Remediation** | Removal **and** the eight forensic checks, because removal alone leaves items 3, 6, 7b and 8 in place. |
| **Severity, with reasoning** | And say what the reasoning is sensitive to. |

**Q20.** Write it. Then delete every sentence that asserts something you did not observe, and check
that what remains still supports the severity you assigned. If it does not, change the severity, not
the sentences.

---

## Part 8 — The policy question

**Q21.** You now own the practice's rule for modules on test devices. Draft it. It should answer at
minimum:

- Which modules are permitted at all, and who decides?
- Are versions pinned, and where is the pin recorded? (The device record from
  [Lab 01 Step 10](lab-01-root-a-device.md#step-10--write-the-device-record) has a row for this.)
- What happens when a module updates?
- What is the rule for a device that will hold client data?
- What is the rule for a device that has ever had an unaudited module on it?

**Q22.** One of the honest answers to the last question is "reflash it". Argue for and against that
being the standing rule, in terms of cost and of what a client would think of each answer.

---

## Hints

<details>
<summary>Hint 1 — a systematic reading order for a shell script you did not write</summary>

Read it three times, for a different thing each time.

1. **Control flow only.** Ignore what the commands do. Where does it branch, loop, exit early,
   background a process, source another file? A hostile action inside a branch that only fires on
   one API level is easy to skim past on a content-first read.
2. **Data flow only.** What enters the script from outside — arguments, environment, files, the
   network? What leaves it? Anything that both enters from the network and reaches an execution
   position is a loader, whatever it is called.
3. **Content.** Now read what the commands do, with the first two passes as context.

Most people do pass 3 only, which is why a hostile line inside an `if [ "$API" -ge 33 ]` gets missed.
</details>

<details>
<summary>Hint 2 — distinguishing the three hosts lines mechanically</summary>

Do not read the list looking for suspicious names; you will pattern-match on familiarity and miss
whatever you have not heard of. Sort by the **target address** instead:

```bash
# host
grep -vE '^\s*#|^\s*$' evil/system/etc/hosts | awk '{print $1}' | sort | uniq -c | sort -rn
```

Everything pointing at `0.0.0.0` or `127.0.0.1` is a block. Everything else is a redirect, and a
redirect is a different act entirely. The technique generalises: when auditing a list, group by the
field that determines *behaviour*, not the field that carries *meaning*.
</details>

<details>
<summary>Hint 3 — you cannot find the payload because it is not there</summary>

That is the finding. Write it down and move on.

A module whose `post-fs-data.sh` fetches and executes is not a module you have audited; it is a
loader whose payload you have not seen. The correct output of the audit is *"the executed code is
not present in the archive and was not examined"*, not an attempt to guess what it does.

If you want to go further, you are now doing network analysis, not static audit: you would need the
URL to be live, a capture of what it returns, and the honest caveat that what it returns to *you*
may not be what it returns to a real device. Servers fingerprint their clients. That is not
paranoia; it is standard practice in commodity droppers.
</details>

<details>
<summary>Hint 4 — what survives module removal</summary>

Magisk deletes the module directory. It does not know about, and does not touch:

- files the module wrote anywhere else (`/data/local/tmp`, `/data/adb/service.d`);
- rows the module wrote into `/data/adb/magisk.db`;
- applications the module installed;
- runtime permissions the module granted;
- secure settings the module changed;
- immutable attributes the module set, which will make some of the above resist deletion until
  cleared with `chattr -i`.

Walk your enumeration table and mark each row "removed with the module" or "persists". The persisting
rows are your remediation section.
</details>

---

## Solutions and expected answers

<details>
<summary>Q2 — what the file listing alone establishes</summary>

Two, at minimum:

1. `system/etc/security/cacerts/` exists in the overlay. **Observation:** the module installs a file
   into the system CA trust store. **Consequence:** every TLS connection made by every application
   on the device becomes interceptable by whoever holds the corresponding private key, including
   applications unrelated to the module's stated purpose.
2. `system/etc/hosts` exists in the overlay. **Observation:** the module replaces the device's
   hosts file. **Consequence:** device-wide control of name resolution for every application.

Note the form: observation, then consequence, with no adjectives. That form survives review.
</details>

<details>
<summary>Q3 — why the work is split across stages</summary>

`post-fs-data` runs before zygote. There is no framework, so `am`, `pm`, `settings` and `cmd` do not
work, and there is generally no usable network stack yet. But it is *first*, and it is the only
stage that runs before anything that could observe it.

So a payload puts in `post-fs-data.sh` the things that must be first or must be invisible —
persistence, the database write, the immutable attributes — and in `service.sh` the things that need
the framework: the accessibility grant, the broadcast, the exfiltration.

The consequence for the auditor is direct: **reading one script gives you half the behaviour**, and
the half you get looks incomplete rather than incriminating. Always enumerate every stage before
drawing conclusions about any of them.
</details>

<details>
<summary>Q4 — blast radius</summary>

`permissive magisk` affects Magisk's own domain. It is over-broad and lazy, and its consequences are
bounded by what runs in that domain.

`permissive untrusted_app` affects **every ordinary application on the device**. It removes SELinux
enforcement for all of them simultaneously. Once anything on the device has root, SELinux is the
remaining boundary between apps, and this line removes it wholesale.

`allow untrusted_app su_exec file { ... execute ... }` combined with the `magisk.db` row written in
`post-fs-data.sh` means any application can obtain root without a prompt. Two lines in two different
files, individually explicable, jointly a total compromise. That is the pattern to internalise:
hostile modules are rarely one damning line.
</details>

<details>
<summary>Q6 — the hosts lines, and why they matter together</summary>

The three lines pointing at a routable address are redirects, not blocks. Alone, a redirect gets you
a TLS error in the app: the certificate presented by the attacker's host does not chain to a trusted
root, and the connection fails loudly.

Together with the `cacerts` overlay it does not fail at all. The injected CA is in the system trust
store, so a certificate the attacker mints for `api.example-bank.invalid` validates. The app
connects, TLS succeeds, and there is no warning anywhere — a transparent man-in-the-middle for those
specific names, device-wide, surviving reboots.

Neither half is remarkable on its own; many modules ship a hosts file, and a CA overlay is exactly
what a tester's own module does. The finding is the **combination**, which is why enumerate-then-
correlate beats flag-as-you-go.
</details>

<details>
<summary>Q13 — how much of the code you have read</summary>

Unknown, and unknowable from the archive — which is itself the answer to give. The archive contains
a loader. The loaded code is fetched at boot from a host you do not control, may differ per device,
per boot and per requester, and is not present in anything you examined.

The correct statement in a report is: *"The module fetches and executes code from
`cdn.optimizer-profiles.invalid` at every boot. That code was not present in the archive and was not
examined. No statement can be made about its behaviour."*

That sentence is more useful to a client than any amount of speculation, and it is also the strongest
possible argument for the recommendation, which is that this class of module cannot be approved at
all.
</details>

---

## Success criteria

- [ ] You built the three archives in a scratch directory outside the repository, and no `.zip`
      ended up in the repo
- [ ] You audited by hand, timed, **before** running the script
- [ ] You produced a written enumeration table before seeing the answer key
- [ ] You named at least two behaviours from the archive listing alone, without extracting
- [ ] You filled in the boot-stage table for all three archives
- [ ] You stated the blast radius of every SELinux rule, distinguishing the module's domain from
      `untrusted_app`
- [ ] You identified the three redirect lines in `hosts` **mechanically**, and explained what they
      achieve in combination with the CA overlay
- [ ] You produced List A and List B against the script's output
- [ ] You ran the script against the benign modules and know what clean looks like
- [ ] You can say which of the script's checks are structural and which are pattern-based
- [ ] You scored yourself against all twelve behaviours and wrote what you would change for each
      one missed
- [ ] You determined which behaviours survive module removal, and what remediation each needs
- [ ] You stated plainly that the fetched payload was not examined
- [ ] You ran all eight forensic checks on a clean device and know what "nothing" looks like
- [ ] You did the version diff and can say where audit effort belongs on a re-audit
- [ ] You wrote the finding in the prescribed shape and deleted every unobserved claim
- [ ] You drafted the practice's module policy, including the client-data rule
- [ ] You answered Q1–Q22 in writing
- [ ] Nothing from this lab was installed on any device

---

## Next

[Lab 05 — CTF: The invisible mount](lab-05-ctf-invisible-mount.md). You have spent this lab reading
modules as a defender. Lab 05 makes you write one as an attacker — specifically, one that survives a
mechanism designed to remove it, which is a question about mount namespaces rather than about shell
scripts.
