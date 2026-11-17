# Lab 04 — CTF: The Gauntlet

> **Five flags, five chapters, one target, and no Frida.** Every flag is recoverable by at least two
> independent routes and every one is a fact about a target you built yourself. There is no
> steganography, no guessing, and no hidden string. What there is, in four of the five, is a
> plausible wrong answer that arrives before the right one — because the thing this chapter is about
> is what happens between the stages, and a CTF that tests one stage at a time would test nothing
> this chapter teaches.

**Difficulty:** CTF — the chapter's capstone. Labs 01–03 are all in play.
**Time:** 3–6 hours. Flag 3 is most of it, and flag 3 is the point.
**Prerequisites:** [Lab 01](lab-01-the-capability-survey.md),
[Lab 02](lab-02-the-chain-no-chapter-can-host.md), [Lab 03](lab-03-write-a-lab-that-survives.md).
**Requires:** a device or emulator, a JDK and the SDK build-tools. Root is needed for **flag 4
only**. **No Frida, no proxy, no NDK, no third-party decompiler is required** — every flag was
solved on the setup [Lab 01](lab-01-the-capability-survey.md) measured, which has a `frida-server`
that does not link and no `apktool`, `ghidra` or `radare2`.
**Device used to verify this challenge:** AVD `sdk_gphone16k_x86_64` (`emulator-5554`), Android 15 /
API 35, x86_64, `userdebug`, rooted with Magisk 30.7, SELinux Enforcing, 16 KiB pages. Every flag
below was recovered on that device on 2026-08-16, and §9 records the two that came out differently
from how they were expected to.

---

## 1. The rules

1. **Every flag is a string of the form `CH73{...}`,** or a short answer you can state in one line.
   You will know when you have it.
2. **No answer key.** §8 has progressive hints and §9 has the verification method, which lets you
   check yourself without being told. That is deliberate: a CTF you can look up is a reading
   exercise.
3. **Record your route.** Use [`../examples/evidence-ledger.md`](../examples/evidence-ledger.md).
   For each flag, write the route you took **and** the second route that would also have worked.
   Finding the second route is worth more than finding the flag.
4. **State your vantage on every claim.** Three of the five flags have a different answer from a
   different vantage, and two of those differences are the flag.
5. **Scope.** Everything here runs against software you built, on a device you own. See
   [SECURITY.md](../../SECURITY.md) for authorised-testing scope.

> **Mental Model.** A normal CTF asks *can you find the thing?* This one mostly asks *can you tell
> when you have found the wrong thing?* Four of the five flags have a decoy answer that is
> self-consistent, arrives first, and survives casual checking. The scoring that matters is how many
> decoys you rejected before submitting.

---

## 2. Setup

```bash
# host — from the repository root
cd 73-Labs/examples
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
./build-chain-target.sh --install
```

You should end with:

```
package:com.pentest.ch73.chain
```

Start a log stream in a second terminal and **leave it running for the whole challenge**. Lab 02 §5.2
and §6.1 both turned on a log line that a command's own output contradicted; this challenge has more
of those.

```bash
# host — terminal 2
adb logcat -c
adb logcat -s ch73chain
```

> **Warning.** If you did Lab 02, you already know three of this target's four defects. That is
> fine and intended — **none of the five flags is one of those defects.** They are all one layer
> underneath, and knowing the defects is the starting position, not the answer.

Take a baseline before you begin, so you can tell your own changes apart from the target's
behaviour:

```bash
# host
python3 -B ../scripts/lab-env-probe.py --match --json > "$HOME/ch73-ctf-baseline.json"
adb shell "pm list packages -U com.pentest.ch73.chain"
```

---

## 3. Flag 1 — The one that is not where the string is

> **Chapters in play:** [10-APK-Internals](../../10-APK-Internals/README.md),
> [12-DEX-Internals](../../12-DEX-Internals/README.md),
> [34-Cryptography](../../34-Cryptography/README.md).

The vault's secret is `CH73{the-chain-is-the-lesson}`. You already know that if you did Lab 02, and
you can get it in one command if you did not.

**That is not flag 1.**

**Flag 1 is the answer to this question:** *the secret is stored wrapped, and the wrapping is
reversible. Name the exact property of the wrapping that makes it reversible from the APK alone —
and then name the property that would still make it reversible even if the key were removed from the
DEX entirely.*

Answer in one line each. There are two properties, and the second is the interesting one: it means
that the obvious remediation — *"move the key out of the binary"* — does not fix it.

```bash
# host — the wrapped value, from the exported provider
adb shell "content query --uri content://com.pentest.ch73.chain.notes"
```

> **Pentester's Note.** If your answer to the second half is "the key would still be recoverable
> somehow", you have not answered it. The property is a property of the *algorithm*, holds without
> any key material at all, and is the reason this construction is unusable no matter where the key
> lives. It has a name.

**The decoy.** The satisfying-looking answer is "the key is hardcoded in the DEX". That is true, it
is a real finding, and it is not flag 1 — because it is the finding whose remediation does not work.

---

## 4. Flag 2 — The command that lies

> **Chapters in play:** [26-Intent](../../26-Intent/README.md),
> [30-Activities](../../30-Activities/README.md), [60-ADB](../../60-ADB/README.md).

Run this, exactly, twice in a row:

```bash
# host
adb shell "am start -n com.pentest.ch73.chain/.VaultActivity --ez com.pentest.ch73.chain.UNLOCK true"
adb shell "am start -n com.pentest.ch73.chain/.VaultActivity --ez com.pentest.ch73.chain.UNLOCK true"
```

**Flag 2 is the answer to:** *why does the second invocation of an identical command produce a
different effect from the first, what exactly does `am` print in the second case, and what is the
minimal change to the command — not to the app, not `force-stop` — that makes it work every time?*

The last clause is the flag. `am force-stop` is the sledgehammer Lab 02 used; there is a flag you
can pass to `am start` that solves it properly, and finding it teaches you something about Android's
task model that the sledgehammer hides.

> **Warning.** Do not read the answer off the app's screen. Read it off `logcat`. The screen shows
> you a **state**; the log shows you an **event**, and the entire trap in this flag is that the state
> looks the same in both cases.

**The decoy.** "The second one failed." It did not fail. It returned successfully, having done
something other than what you wanted, which is a different and more dangerous thing.

---

## 5. Flag 3 — The finding that changes verdict with the chair

> **Chapters in play:** [23-Permissions](../../23-Permissions/README.md),
> [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md),
> [32-Manifest](../../32-Manifest/README.md),
> [21-App-Sandbox](../../21-App-Sandbox/README.md).

This is the long one, and it is the reason the challenge exists.

`AdminReceiver` is exported and does something destructive. Establish, **with evidence for each**,
whether it is reachable from each of these four vantages:

| Vantage | Reachable? | Your evidence |
|---|---|---|
| An unprivileged third-party app | | |
| The `shell` user (uid 2000, over `adb`) | | |
| Root | | |
| A package signed with the same certificate as the target | | |

**Flag 3 is the four-row table, filled in, plus one sentence** stating the single manifest attribute
value that decides all four rows, quoted as the **integer** the package manager actually compares —
not the word a decoder prints for you.

Three things make this harder than it sounds, and each has cost somebody real time:

1. **The command prints the same thing whether or not anything happened.** Establishing "reachable"
   requires evidence that is not the command's own output.
2. **The first vantage is the one you do not have.** `adb shell` is not an app. Getting a genuine
   app vantage means building a second package — which is the single most valuable hour in this
   whole lab, and [30-Activities](../../30-Activities/README.md) has a two-app build you can adapt.
   If you cannot, the honest entry is `NOT TESTED`, not a guess.
3. **The fourth vantage you can create.** You hold the signing key: `build-chain-target.sh` generated
   it into `$OUTDIR`. Sign a second package with the same key and the fourth row becomes measurable
   rather than theoretical.

```bash
# host — the key you already have
ls -l /tmp/ch73-chain-build/debug.keystore
```

> **Under the Hood.** Before you fill the "root" row, look carefully at what the log line tells
> you about *who called*. There is a second, smaller flag hiding in that line — see flag 5 — and the
> two are connected: the reason the receiver cannot identify its caller is the reason a developer's
> obvious defence against this would not work.

**The decoy.** "Exported plus destructive action equals High." That verdict is what a manifest-only
read produces, it is what a scanner emits, and three of the four rows above contradict it.

---

## 6. Flag 4 — The one that needs root, and does not need what you think

> **Chapters in play:** [33-Storage](../../33-Storage/README.md),
> [21-App-Sandbox](../../21-App-Sandbox/README.md), [62-Magisk](../../62-Magisk/README.md).

The vault seeds a `SharedPreferences` file on first run.

**Flag 4 is:** *the full path of that file on this device, its owning uid, its SELinux context, and
the exact contents of the value it stores* — obtained **from the device**, not inferred from the
source.

Then the part that is actually the flag: **state the one thing about that file which means the
wrapped value there is not the same evidence as the wrapped value you got from the provider in
flag 1.** They look identical. They are not equivalent as evidence, and the difference is a sentence
about who could have seen each one.

```bash
# host — this AVD's su takes `su 0 <cmd>`. Lab 01 §3.2 explains why yours may differ.
adb shell "su 0 id"
```

> **Warning — two traps in one command here.**
> First, the `su` form: get it wrong and the output reads exactly like "not rooted". Second, the app
> uid is **not stable across reinstalls** — Lab 02 §6.3 measured it moving from 10210 to 10213. If
> you record a uid, record which install it belonged to, or your evidence cannot be reproduced.

**The decoy.** Reading the file with `run-as`. It may well work, and it gives you the contents — but
`run-as` is a *fifth* vantage with its own preconditions, and using it while claiming a root result
is exactly the vantage error this chapter keeps warning about.

---

## 7. Flag 5 — The identity that is not an identity

> **Chapters in play:** [24-IPC](../../24-IPC/README.md), [25-Binder](../../25-Binder/README.md),
> [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md).

`AdminReceiver` logs `Binder.getCallingUid()`. When you reach it from root (flag 3), it logs a
specific number.

**Flag 5 is:** *what that number actually is, why it is not the broadcaster's uid, and — the part
that matters — the general rule for when `Binder.getCallingUid()` does and does not identify a
caller.*

State the rule in one sentence, then name **one** place in Android where the same call **does**
correctly identify the caller, and say what is different about it.

```bash
# host — the number to explain
adb shell "pm list packages -U com.pentest.ch73.chain"
```

> **Pentester's Note.** This is not a lab curiosity. "Check the caller's uid in `onReceive`" is a
> defence real applications ship, and it does not do what its author believes. When you have the
> rule, you can recognise the bug class in any codebase in about four seconds.

**The decoy.** Concluding the number is "the system's uid" or "1000". It is not, and the actual value
is more informative than either.

---

## 8. Hints

Open in order. Each is a nudge, not an answer.

<details>
<summary>Flag 1, hint 1 — where to look</summary>

You do not need the device. You need the wrapped string and thirty lines of any language. The
property you are being asked for is visible in the *shape* of the transformation, not in the key.
</details>

<details>
<summary>Flag 1, hint 2 — the second property</summary>

What happens if you exclusive-or two different wrapped values together? What cancels?
</details>

<details>
<summary>Flag 2, hint 1</summary>

Read the second line `am` printed. It contains the word "delivered" and it is telling you the truth.
</details>

<details>
<summary>Flag 2, hint 2</summary>

`am start` accepts intent flags with `-f`. The one you want makes the system tear down the existing
instance rather than reuse it. There are two plausible candidates; one of them re-runs `onCreate`
and one does not.
</details>

<details>
<summary>Flag 3, hint 1</summary>

`aapt2 dump xmltree` prints the integer. `protectionLevel` has four values you should know by sight.
</details>

<details>
<summary>Flag 3, hint 2</summary>

For the app vantage: you do not need a full app. You need a package that is *not* signed with the
target's key and that can send a broadcast. For the fourth row: you already have the key.
</details>

<details>
<summary>Flag 3, hint 3 — the evidence problem</summary>

Stop using `am`'s output as evidence entirely. The only trustworthy signal that the receiver ran is
the receiver saying so.
</details>

<details>
<summary>Flag 4, hint 1</summary>

`/data/data/<package>/shared_prefs/`. The file is named after the preferences name in the source.
`ls -lZ` gives you owner and context in one command.
</details>

<details>
<summary>Flag 4, hint 2 — the evidence question</summary>

One copy of that value sits behind the app sandbox and needs root to read. The other was handed to
anybody who asked, over an exported interface, with no permission. Same bytes; completely different
sentence in a report.
</details>

<details>
<summary>Flag 5, hint 1</summary>

Compare the logged number with the target package's own uid. Then ask what the calling *binder
transaction* is at the moment `onReceive` runs.
</details>

<details>
<summary>Flag 5, hint 2</summary>

The rule is about whether you are inside an incoming transaction at all. `ContentProvider.query()`
is the contrasting case — ask why.
</details>

---

## 9. Verifying yourself, without an answer key

Each flag has a check you can run that does not require being told the answer.

| Flag | Self-check |
|---|---|
| 1 | Apply your stated second property to two wrapped values you generate yourself. If it recovers information with no key, you have it |
| 2 | Your minimal command change must produce the unlock log line **on every run**, ten times in a row, with no `force-stop` between them |
| 3 | Every row of your table must cite evidence that is not `am`'s own output. A row citing `Broadcast completed: result=0` is not filled in |
| 4 | Your path, uid and context must come from a device command you can paste. If any of the three is inferred from the source, it is not the flag |
| 5 | Your rule must correctly predict the contrasting case in hint 2 **before** you check it |

### 9.1 Two things that came out differently from expected

Recorded because a challenge whose author claims everything went to plan is a challenge whose author
did not run it.

- **Flag 2's decoy is stronger than intended.** On the verified device the second `am start` printed
  `Warning: Activity not started, intent has been delivered to currently running top-most instance` —
  which *names the problem outright*. It was still missed on the first pass, because the line begins
  with `Warning:` in a wall of output that begins with `Starting:`. **A diagnostic you do not read is
  not a diagnostic.**
- **Flag 3's root row was expected to be unreachable and is reachable.** The prediction was that a
  `signature` permission blocks everybody without the key. Root got through. That is correct
  behaviour and it was not anticipated, and it is why the flag is a four-row table rather than a
  yes/no: the question "is this exploitable?" has no answer until you say by whom.

---

## 10. Success criteria

- [ ] Five flags, each with a **stated vantage** and evidence that is not a command's own success
      message.
- [ ] For at least three flags, a **second independent route** written down.
- [ ] For at least three flags, the **decoy you rejected**, and what made you reject it.
- [ ] Flag 3's table has four rows, and any row you could not measure says `NOT TESTED` rather than
      carrying a guess.
- [ ] You can state the `protectionLevel` integer from memory.
- [ ] You can state the `Binder.getCallingUid()` rule in one sentence and name the contrasting case.
- [ ] Your ledger lives outside the repository, and the target is uninstalled.

---

## 11. Cleanup

```bash
# host
cd 73-Labs/examples
./build-chain-target.sh --uninstall
rm -rf /tmp/ch73-chain-build /tmp/ch73-sdk23 /tmp/ch73-jadx
rm -f "$HOME/ch73-ctf-baseline.json"
adb logcat -c
```

```bash
# host — verify
adb shell "pm list packages | grep ch73"    # expect no output
git status --short                           # expect no output
```

If you built a second package for flag 3, uninstall that too — and if you pushed anything to
`/data/local/tmp`, remove **only what you put there**. Files that are not yours may be another
session's live workspace, and residue and a live workspace look identical from outside.

---

## 12. Where this goes next

| Next | Why |
|---|---|
| [`../references/learning-paths.md`](../references/learning-paths.md) | Five ordered routes through the other 323 labs |
| [72-RealWorldFindings](../../72-RealWorldFindings/README.md) | Flag 3's table, as a severity argument you have to defend |
| [74-CaseStudies](../../74-CaseStudies/README.md) | Six investigations where the decoy won for a while |
| [75-InterviewQuestions](../../75-InterviewQuestions/README.md) | Flags 3 and 5 are both live interview questions |
