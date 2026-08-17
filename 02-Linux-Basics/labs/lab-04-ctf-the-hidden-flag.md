# Lab 04 — CTF: The Hidden Flag

> Five flags. No instructions. Everything you need was in labs 01, 02 and 03, and nothing you need
> requires root, an exploit, or a tool you do not already have. What this lab tests is whether you can
> *chain* mechanisms — a permission bit, a `/proc` entry, a symlink, a mount — when nobody tells you
> which one is in front of you.

**Chapter:** [02 — Linux Basics](../README.md)
**Difficulty:** CTF — assumes all three preceding labs
**Estimated time:** 2 to 4 hours if you do not read the hints
**Prerequisite labs:** [01](lab-01-filesystem-and-permissions.md) ·
[02](lab-02-processes-proc-and-signals.md) · [03](lab-03-ipc-sockets-and-namespaces.md)

---

## Objective

Real targets do not come with section headings. On an engagement, nobody tells you "this is a
permission problem" or "this is a namespace problem"; you get a device, an app, a denial, and a
deadline. The skill this lab builds is the one that separates someone who has *read* about these
mechanisms from someone who can *recognise* them:

- Seeing "Permission denied" and knowing which of five layers produced it.
- Noticing that a directory you cannot list is still a directory you can enter.
- Remembering that a process's environment is readable, and that it is not separated by spaces.
- Remembering that a deleted file is not a destroyed file.
- Refusing to trust a path until you have canonicalised it.
- Recognising that what you are reading may not be what is actually there.

Each of the five flags is protected by exactly one of those. They are stacked, so each one tells you
what to attack next. Nothing is guessable, nothing needs brute force, and there are no rabbit holes
that are not signposted as decoys once you reach them.

> **🧠 Mental Model**
> A CTF stage is a single mechanism with the noise removed. A real target is the same mechanisms with
> noise added. Learn to recognise the mechanism here, where it is clean, so that you can spot it later
> when it is buried in ten thousand lines of decompiled code.

---

## Prerequisites

| Requirement | Why | Check |
|---|---|---|
| Linux, WSL 2, or a Linux VM | Stages 2, 3 and 5 need `/proc` and mounts | `ls /proc/self/ns/` |
| `sudo`, for stage 5 only | Creating and removing a bind mount | `sudo -v` |
| `base64` | The payloads are base64-encoded so you cannot read them with `strings` | `which base64` |
| Labs 01–03 completed | Every technique here came from one of them | — |

If you have no `sudo`, the setup script says so, skips stage 5's mount, and leaves that flag sitting
in the open. Stages 1 to 4 are unaffected. Do stage 5 later on a machine where you have privilege.

> **⚠️ Warning**
> The challenge is built entirely inside one directory that you own. It starts three
> `while :; do sleep 5; done` background shells and, if it can, one bind mount over a directory it
> created itself. It does not touch anything else on your system. `sh ctf-setup.sh clean` reverses
> all of it, and Part G below insists that you run it.

---

## Setup

```bash
# host / WSL — from the chapter's scripts directory
cd /path/to/Android-Pentesting-Notes/02-Linux-Basics/scripts
sh ctf-setup.sh build
```

```
==============================================================================
 building the Lab 04 challenge in /home/harsh/ctf-lab04
==============================================================================
  [ok]   stage 1 built (directory mode 0111, name leaked in logs/app.log)
  [ok]   stage 2 built (daemon pid 51204 carries LAB04_STAGE2_SECRET)
  [ok]   stage 3 built (daemon pid 51211 holds a deleted file on fd 3)
  [ok]   stage 4 built (vault/latest -> ../store/rev-3 -> rev-2)
  [ok]   stage 5 built (bind mount over store/rev-2/final, cwd daemon pid 51219)

==============================================================================
 ready
==============================================================================
  Read the brief:   cat /home/harsh/ctf-lab04/BRIEF.txt
```

Then read the brief and **stop reading this file** until you are stuck:

```bash
# host / WSL
cat ~/ctf-lab04/BRIEF.txt
cd ~/ctf-lab04
```

Confirm the daemons are alive whenever you come back to it:

```bash
# host / WSL
sh /path/to/scripts/ctf-setup.sh status
```

### On Android

Everything except stage 5 works on a device. Push the script and build there instead:

```bash
# host
adb push ctf-setup.sh /data/local/tmp/
adb shell "LAB04_DIR=/data/local/tmp/ctf-lab04 sh /data/local/tmp/ctf-setup.sh build"
```

```bash
# adb shell
cat /data/local/tmp/ctf-lab04/BRIEF.txt
cd /data/local/tmp/ctf-lab04
```

Two device-specific notes. Toybox's `readlink -f` exists but `realpath` may not; and `base64 -d` is
`base64 -d` on Toybox as well, so the commands transfer. If `tr` refuses the NUL escape, fall back to
`xxd` or pull the file to your host with `adb exec-out`.

---

## The Rules

1. **Everything is inside the challenge directory.** Nothing outside it is part of the puzzle. If you
   find yourself reading `/etc/shadow`, you have gone off the map.
2. **No root is required** for stages 1 to 4. Stage 5 needs privilege only to *create* the mount,
   which the setup script already did; solving it does not require you to break anything.
3. **You never need to destroy anything** to make progress. One stage invites you to change your own
   view of the filesystem; that is not the same as changing the machine.
4. **Every flag looks like** `FLAG{lowercase_words_with_underscores}`.
5. **Each flag tells you what the next stage is.** If you have a flag and no idea what to do next,
   reread the text next to it.
6. **Take the hints one at a time.** They are in collapsed blocks below, ordered from a nudge to a
   full command. Opening the second before trying the first wastes the lab.

---

## The Challenge

### Stage 1 — Something you can enter but cannot read

The challenge directory contains a subdirectory. You cannot list it. You can prove that you cannot
list it, and the error you get will be the same error you would get if it did not exist at all — which
is the point.

Something else in the challenge directory knows a filename that lives inside it.

**Find the flag inside that directory.**

<details>
<summary>Hint 1.1 — I get "Permission denied" and I am the owner. How?</summary>

Look at the mode of the directory itself, not its contents: `ls -ld stage1`. Then reread the table in
[Lab 01 Part C1](lab-01-filesystem-and-permissions.md) about what `r` and `x` mean on a *directory*.
They are not the same permission and you have only one of them.
</details>

<details>
<summary>Hint 1.2 — If I cannot list it, how am I supposed to know what is in it?</summary>

You are not supposed to work it out. You are supposed to find where it leaked. Developers write
paths into logs. There is a `logs/` directory and it is world-readable.
</details>

<details>
<summary>Hint 1.3 — Give me the commands</summary>

```bash
ls -ld ~/ctf-lab04/stage1          # --x------ : traverse, do not list
ls ~/ctf-lab04/stage1              # Permission denied, as designed
grep -i stage1 ~/ctf-lab04/logs/app.log
cat ~/ctf-lab04/stage1/<the-name-from-the-log>
```
</details>

---

### Stage 2 — Something a process is carrying

A process belonging to you is running right now. Its command line contains a marker. It has never
written its secret to disk and it never will — the secret exists only in the process's environment
block, which was captured when it was executed.

**Read it.**

<details>
<summary>Hint 2.1 — How do I find a process by part of its command line?</summary>

`ps -ef` lists everything with the full command. Pipe it through `grep`. On Android use `ps -A -o
PID,NAME` or `ps -ef` depending on the build, and remember that `pgrep -f` matches the whole command
line rather than just the name.
</details>

<details>
<summary>Hint 2.2 — I found the PID. Where is the environment?</summary>

`/proc/<pid>/environ`. See [Lab 02 Part C](lab-02-processes-proc-and-signals.md). It is readable
because the process is yours.
</details>

<details>
<summary>Hint 2.3 — `cat` prints one long unreadable run of text</summary>

That is the whole lesson of this stage. The entries are separated by NUL bytes, and your terminal
draws a NUL as nothing. Translate the separator into a newline before you read it.
</details>

<details>
<summary>Hint 2.4 — Give me the commands</summary>

```bash
ps -ef | grep lab04-stage2 | grep -v grep
PID=<the pid>
tr '\0' '\n' < /proc/$PID/environ | grep LAB04
```
</details>

---

### Stage 3 — Something that has already been deleted

Another process is running. It opened a file, and then the file was removed from the filesystem. `ls`
will not find it. `find` will not find it. Its name no longer exists anywhere.

The data is still there.

**Recover it.**

<details>
<summary>Hint 3.1 — If the file is deleted, how can the data still exist?</summary>

Deleting a file removes a *name*. The inode survives until its link count reaches zero **and** no
process still has it open. Reread [Lab 01 Part E2](lab-01-filesystem-and-permissions.md) and
[Lab 02 Part D2](lab-02-processes-proc-and-signals.md).
</details>

<details>
<summary>Hint 3.2 — Where do I look for a file with no name?</summary>

At the descriptor table of the process that still holds it: `ls -l /proc/<pid>/fd`. A descriptor
pointing at a removed file is displayed with a distinctive suffix.
</details>

<details>
<summary>Hint 3.3 — Give me the commands</summary>

```bash
ps -ef | grep lab04-stage3 | grep -v grep
PID=<the pid>
ls -l /proc/$PID/fd            # look for "(deleted)"
cat /proc/$PID/fd/3
```
</details>

---

### Stage 4 — Something that is not where it says it is

There is a `vault/` directory. It contains an obvious-looking `flag.txt` that you cannot read, and a
`latest` entry that points somewhere.

One of those two is a decoy. Both are worth opening.

**Follow the path properly and read the flag at the end of it.**

<details>
<summary>Hint 4.1 — `vault/flag.txt` has mode 0000. Am I meant to break it?</summary>

No. You own it, so you can simply change the mode — which is itself the lesson. A mode protects a
file from *other* UIDs, not from its owner. Read it once you have; it will tell you what it is.
</details>

<details>
<summary>Hint 4.2 — `latest` points somewhere that points somewhere else</summary>

Yes. `ls -l` shows you one link. It does not follow the chain. There is a command that resolves every
symlink in a path all the way to the real thing, and it is the shell equivalent of Java's
`getCanonicalPath()` — the method you should always use instead of `getAbsolutePath()`.
</details>

<details>
<summary>Hint 4.3 — I found a `.b64` file and it is gibberish</summary>

It is base64. Decode it.
</details>

<details>
<summary>Hint 4.4 — Give me the commands</summary>

```bash
cd ~/ctf-lab04
chmod u+r vault/flag.txt && cat vault/flag.txt      # the decoy explains itself
ls -l vault/latest
readlink vault/latest                               # one hop
readlink -f vault/latest                            # all the hops
REAL=$(readlink -f vault/latest)
ls -la "$REAL"
base64 -d "$REAL/flag.b64"
```
</details>

---

### Stage 5 — Something that is not what it appears to be

The path from stage 4 leads to a directory, and that directory contains a file called `final.b64`.
Decode it and you will not get a flag.

Nothing has been deleted. Nothing is being faked. The kernel is answering your questions truthfully.

**Get the real contents.**

<details>
<summary>Hint 5.1 — The file exists, decodes cleanly, and is not a flag. What?</summary>

You are reading a real file. It is just not the file that lives at that path on disk. Something is
between you and it. There is a table of everything that is between you and the disk, and it is one
`cat` away.
</details>

<details>
<summary>Hint 5.2 — I looked at /proc/mounts and there is a bind mount over the directory</summary>

Correct. Now recall the key sentence from [Lab 03 Part E](lab-03-ipc-sockets-and-namespaces.md): a
mount hides a **path**, not an **inode**. Two consequences follow, and each gives you a way in. One
involves changing your own view of the filesystem without changing anyone else's. The other involves
a process that already had a reference to the real directory before the mount existed.
</details>

<details>
<summary>Hint 5.3 — The clean route: change only your own view</summary>

`sudo unshare --mount /bin/sh` gives you a shell in a fresh mount namespace with a private copy of
the mount table. Anything you unmount in there is unmounted for you and for nobody else. That is
precisely the mechanism the Magisk DenyList uses, run in reverse.
</details>

<details>
<summary>Hint 5.4 — The quieter route: a process that got there first</summary>

The setup started a daemon whose current working directory *is* the hidden directory, established
before the mount was created. `/proc/<pid>/cwd` follows that reference rather than re-resolving the
path, so it reaches the real directory even while the mount covers the path.
</details>

<details>
<summary>Hint 5.5 — Give me the commands</summary>

```bash
# see the mount
grep final /proc/mounts

# route A -- change only your own view
sudo unshare --mount /bin/sh
  umount ~/ctf-lab04/store/rev-2/final
  base64 -d ~/ctf-lab04/store/rev-2/final/final.b64
  exit

# route B -- through a process that already had a reference
ps -ef | grep lab04-stage5 | grep -v grep
PID=<the pid>
ls -l /proc/$PID/cwd
base64 -d /proc/$PID/cwd/final.b64
```
</details>

---

## Solution

Do not read this section until you have all five flags or have genuinely given up. `sh ctf-setup.sh
answers` prints the same information from the command line.

### Stage 1 — `FLAG{x_traverses__r_lists}`

```bash
$ ls -ld ~/ctf-lab04/stage1
d--x--x--x 2 harsh harsh 4096 Aug  5 15:00 /home/harsh/ctf-lab04/stage1

$ ls ~/ctf-lab04/stage1
ls: cannot open directory '/home/harsh/ctf-lab04/stage1': Permission denied

$ grep -i stage1 ~/ctf-lab04/logs/app.log
W/AppCache( 1201): could not open /home/harsh/ctf-lab04/stage1/k3y_2f9a.txt (ENOENT), regenerating

$ cat ~/ctf-lab04/stage1/k3y_2f9a.txt
FLAG{x_traverses__r_lists}
```

**The mechanism.** Mode `0111` gives execute but not read. Execute on a directory permits *traversal*
— resolving a name you already have through it. Read permits *enumeration* — obtaining the list of
names. You had traversal and not enumeration, so a name you knew worked and discovery did not.

**Where you meet this for real.** `/data/data` on every Android device is `drwxrwx--x`. Any process
can `stat` or `cd` into a package directory whose name it knows; no process can list `/data/data` to
learn which apps are installed. The list of installed applications is itself sensitive — it reveals
banking apps, dating apps, VPNs, medical apps — so Android removes the `r` and keeps the `x`.

**And the flaw you just exploited.** The protection is only as good as the secrecy of the names, and
names leak. They leak into logs, into stack traces, into `strings` output, into crash reports, into
`ContentProvider` URIs, and into error messages. An anti-enumeration control undone by a log line is
one of the most common real findings in mobile testing.

### Stage 2 — `FLAG{environ_is_nul_separated}`

```bash
$ ps -ef | grep lab04-stage2 | grep -v grep
harsh    51204 51190  0 15:00 pts/1  00:00:00 sh /home/harsh/ctf-lab04/.runtime/lab04-stage2.sh

$ cat /proc/51204/environ
SHELL=/bin/bashLAB04_STAGE2_SECRET=FLAG{environ_is_nul_separated} -- stage 3: ...PWD=/home/harsh...

$ tr '\0' '\n' < /proc/51204/environ | grep LAB04
LAB04_STAGE2_SECRET=FLAG{environ_is_nul_separated} -- stage 3: a process with lab04-stage3 in its command line is holding a deleted file open. Look at its file descriptors.
```

**The mechanism.** The kernel stores the environment as a run of NUL-terminated strings. `cat` writes
the bytes faithfully and the terminal renders NUL as nothing, so the entries appear fused. `tr '\0'
'\n'` replaces the separator with one the terminal does render.

**Where you meet this for real.** `/proc/<pid>/environ` is one of the first things to read on an app
process you have access to. Debug builds routinely carry API keys, backend hostnames, feature flags
and test credentials in environment variables, and developers rarely think of the environment as
"storage". The same NUL problem applies to `/proc/<pid>/cmdline`, and it is why `grep` sometimes
answers `Binary file matches` instead of showing you the line — use `grep -a`, or translate first.

### Stage 3 — `FLAG{unlinked_but_still_open}`

```bash
$ ps -ef | grep lab04-stage3 | grep -v grep
harsh    51211 51190  0 15:00 pts/1  00:00:00 sh /home/harsh/ctf-lab04/.runtime/lab04-stage3.sh

$ ls -l /proc/51211/fd
lrwx------ 1 harsh harsh 64 Aug  5 15:02 0 -> /dev/pts/1
lrwx------ 1 harsh harsh 64 Aug  5 15:02 1 -> /dev/pts/1
lrwx------ 1 harsh harsh 64 Aug  5 15:02 2 -> /dev/pts/1
lr-x------ 1 harsh harsh 64 Aug  5 15:02 3 -> '/home/harsh/ctf-lab04/.runtime/.s3seed (deleted)'

$ cat /proc/51211/fd/3
FLAG{unlinked_but_still_open}
...
```

**The mechanism.** `rm` removes a directory entry and decrements the inode's link count. The inode's
data is freed only when the link count reaches zero **and** the kernel's open-file count for it also
reaches zero. A process holding the descriptor keeps the second count above zero, so the data
survives with no name anywhere in the filesystem. `/proc/<pid>/fd/3` is a reference to the open file
description, not a path lookup, so it still reaches it.

**Where you meet this for real.** Applications write a temporary file, unlink it "for security", and
carry on using the descriptor. Decrypted content, session state, downloaded payloads and screenshots
all turn up this way. During a live analysis, `ls -l /proc/<pid>/fd | grep deleted` costs one command
and occasionally hands you the entire finding. It is also why "we delete the file immediately" is not
a remediation.

### Stage 4 — `FLAG{canonicalise_before_you_trust}`

```bash
$ chmod u+r ~/ctf-lab04/vault/flag.txt && head -3 ~/ctf-lab04/vault/flag.txt
Not the flag.

$ ls -l ~/ctf-lab04/vault/latest
lrwxrwxrwx 1 harsh harsh 15 Aug  5 15:00 latest -> ../store/rev-3

$ ls -l ~/ctf-lab04/store/rev-3
lrwxrwxrwx 1 harsh harsh 5 Aug  5 15:00 rev-3 -> rev-2

$ readlink -f ~/ctf-lab04/vault/latest
/home/harsh/ctf-lab04/store/rev-2

$ base64 -d /home/harsh/ctf-lab04/store/rev-2/flag.b64
FLAG{canonicalise_before_you_trust} -- final stage: read final/final.b64 from here...
```

**The mechanism.** A symbolic link stores a path as text and is resolved afresh at every `open()`.
`ls -l` shows one hop. `readlink` shows one hop. `readlink -f` resolves every hop, plus `.` and `..`,
until it reaches something that is not a link — which is exactly what `getCanonicalPath()` does in
Java and what `realpath()` does in C.

**Where you meet this for real.** Three named bug classes come out of this single fact:

- **TOCTOU.** A program checks a path, then opens it. Between the two, the path becomes a symlink to
  something else. The check was true when it ran and false when it mattered.
- **Path traversal / ZipSlip.** An archive entry named `../../../../data/data/com.victim/files/x.so`
  extracted without validation writes outside the intended directory. The APK is a ZIP, so this is a
  live Android concern.
- **Provider path escape.** A `ContentProvider` that serves files by name and validates with
  `getAbsolutePath()` rather than `getCanonicalPath()` can be pointed at anything the app can read.

The remediation is identical in all three: resolve the path completely, *then* verify that the result
still starts with the directory you intended, and only then open it.

### Stage 5 — `FLAG{a_mount_hides_a_path_not_an_inode}`

```bash
$ base64 -d ~/ctf-lab04/store/rev-2/final/final.b64
Not the flag. Something is mounted over this directory...

$ grep final /proc/mounts
/dev/sdc /home/harsh/ctf-lab04/store/rev-2/final ext4 rw,relatime,discard,errors=remount-ro 0 0
```

**Route A — change only your own view.**

```bash
$ sudo unshare --mount /bin/sh
# grep -c final /proc/mounts
1
# umount /home/harsh/ctf-lab04/store/rev-2/final
# grep -c final /proc/mounts
0
# base64 -d /home/harsh/ctf-lab04/store/rev-2/final/final.b64
FLAG{a_mount_hides_a_path_not_an_inode}
# exit
```

And, back in the original shell, the mount is still there:

```bash
$ grep -c final /proc/mounts
1
```

**Route B — through a process that already had a reference.**

```bash
$ ps -ef | grep lab04-stage5 | grep -v grep
harsh    51219 51190  0 15:00 pts/1  00:00:00 sh /home/harsh/ctf-lab04/.runtime/lab04-stage5.sh

$ ls -l /proc/51219/cwd
lrwxrwxrwx 1 harsh harsh 0 Aug  5 15:10 /proc/51219/cwd -> /home/harsh/ctf-lab04/store/rev-2/final

$ base64 -d /proc/51219/cwd/final.b64
FLAG{a_mount_hides_a_path_not_an_inode}
```

**The mechanism.** A bind mount attaches an existing directory at a second point in the tree. Path
resolution through that point now lands on the new directory. The inodes that were there before are
untouched — nothing was deleted, moved or modified. Two consequences:

1. **A mount is per-namespace.** Unmounting inside a private mount namespace changes what *you* see
   and nothing else. That is route A, and it is the polite one: it does not alter the machine for any
   other process.
2. **A mount hides a path, not an inode.** A process whose current directory, open descriptor, or
   root already refers to the underlying directory keeps that reference. `/proc/<pid>/cwd` follows the
   reference rather than re-resolving the path. That is route B.

Route C — `sudo umount` in the original namespace — also works and is the one most people reach for.
It is worth naming explicitly as the *wrong instinct on an engagement*: it changes global state on a
machine you do not own, it is visible to every other process, and it may break the thing you were
trying to observe. Prefer the change that is scoped to you.

**Where you meet this for real.** This is systemless root, exactly:

1. Magisk never writes to `/system`. It builds an alternative view with bind mounts, leaving the real
   partition and its `dm-verity` hashes intact.
2. For an app on the DenyList it calls `unshare(CLONE_NEWNS)` in the forked child.
3. Inside that namespace only, it unmounts its own modifications.
4. The app then reads `/proc/self/mounts` and sees a clean table, `stat()`s `/system/xbin/su` and
   genuinely gets `ENOENT`, and lists `/system/bin` and genuinely finds nothing added.

Nothing is hooked and no API returns a fabricated value. The kernel tells the truth about a different
namespace. That is why file-existence root detection cannot win, and why the industry moved to
hardware-backed attestation evaluated server-side. See [62 — Magisk](../../62-Magisk/README.md) and
[37 — Root Detection](../../37-RootDetection/README.md).

It is also, in a quieter way, how Android does shared storage: `/storage/self/primary` is a
per-process bind mount, so two apps reading `/sdcard` are reading through different views.

---

## Tear down

```bash
# host / WSL
sh /path/to/scripts/ctf-setup.sh clean
```

```
==============================================================================
 tearing down /home/harsh/ctf-lab04
==============================================================================
  [ok]   stopped pid 51204
  [ok]   stopped pid 51211
  [ok]   stopped pid 51219
  [ok]   unmounted /home/harsh/ctf-lab04/store/rev-2/final
  [ok]   removed /home/harsh/ctf-lab04
```

```bash
# adb shell — the device version
LAB04_DIR=/data/local/tmp/ctf-lab04 sh /data/local/tmp/ctf-setup.sh clean
rm -f /data/local/tmp/ctf-setup.sh
```

Verify nothing was left behind:

```bash
# host / WSL
ls -d ~/ctf-lab04 2>&1
mount | grep ctf-lab04
ps -ef | grep lab04 | grep -v grep
```

All three should produce nothing. **Leaving tooling, mounts or background processes behind on a
client device at the end of an engagement is a genuine professional failure**, and the habit is
cheapest to build here.

---

## Success Criteria

| # | Criterion | Proof |
|---|---|---|
| 1 | You recovered all five flags | Five `FLAG{...}` strings |
| 2 | You solved stage 1 without being told the filename | Your command history |
| 3 | You can state the difference between `r` and `x` on a directory, and name an Android path that relies on it | One sentence |
| 4 | You explained why `cat /proc/<pid>/environ` looked fused together | One sentence |
| 5 | You recovered data from a file with no name anywhere in the filesystem | The `(deleted)` line and the content |
| 6 | You canonicalised a two-hop symlink chain and named the Java method that does the same thing | `readlink -f` output |
| 7 | You named the three bug classes that come out of "a symlink is resolved at every open" | Three names |
| 8 | You identified the bind mount from `/proc/mounts` unaided | The mount line |
| 9 | You solved stage 5 with route A or B, not by unmounting globally | Transcript |
| 10 | You can explain why route C is the wrong instinct on an engagement | One sentence |
| 11 | You can explain, in your own words, why an app cannot detect namespace-based root hiding by reading files | One paragraph |
| 12 | You tore the whole thing down and verified nothing remains | Three empty outputs |

---

## Going Further

1. **Solve stage 5 a third way.** A file descriptor already open on the hidden directory works as
   well as a cwd does. Open one with `exec 9< dir` *before* creating a mount over it, then read
   through `/proc/self/fd/9/`. Prove to yourself that the descriptor route and the cwd route are the
   same fact.

2. **Break your own stage 1.** Rebuild the challenge, then instead of reading the log, find the
   filename by other means: `strings` on the log, a shell history, an `inotify` watch, or the
   directory's inode via `debugfs` if you are on ext4 and feeling brave. Then think about which of
   those an app's private directory would actually leak through.

3. **Write the detector.** Write a shell script that, given a PID, reports whether that process is in
   a different mount namespace from PID 1, and lists the mounts that differ. That is thirty lines and
   it is a genuinely useful triage tool. Note what privilege it needs — and why an ordinary app
   cannot run it against itself usefully.

4. **Rebuild it on Android and do it as UID 2000.** Everything except the mount works from an
   ordinary `adb shell`. Note which stages become harder because you cannot read another UID's
   `/proc` entries, and what that tells you about why `run-as` and `adb root` matter.

5. **Add a sixth stage yourself.** Pick a mechanism from the chapter that is not represented — a FIFO
   with the wrong permissions, a setgid directory, a socket with no peer-credential check, a file
   whose contents are only reachable through a hard link in a directory you cannot list — and extend
   `ctf-setup.sh`. Designing a stage forces you to understand a mechanism far better than solving one
   does.

6. **Do the same five stages against a real app.** Pick an app you are authorised to test, and answer
   each question against it: can I enumerate its private directory or only traverse it; what is in its
   environment; does it hold any deleted files open; does it follow symlinks without canonicalising;
   and is its mount table the same as the shell's? That sequence is a genuine triage checklist and you
   now know how to run all five steps.

---

## Why this matters for Android security

**Chaining is the whole job.** Every stage here was solvable with one command from an earlier lab.
What made it a challenge was not the difficulty of any step, it was having to *decide which step*
with nobody telling you. That is exactly what an engagement feels like: you have a denial, a file, a
process and a deadline, and the skill is recognising which of a dozen mechanisms you are looking at.

**Each stage is a real finding class.** A leaked path in a log defeating an anti-enumeration control.
A secret in an environment variable on a debug build. A "securely deleted" temporary file still open
on a descriptor. A path validated with `getAbsolutePath()` instead of `getCanonicalPath()`. A
filesystem view that is not what the app believes it is. Those five appear in real mobile
assessments constantly, and you have now produced each one with your own hands.

**Stage 5 is the argument for attestation.** Once you have watched two shells read the same path and
get different, equally truthful answers, every on-device root check reads as a delaying tactic rather
than a control. That single realisation reframes chapters
[37 — Root Detection](../../37-RootDetection/README.md) and [62 — Magisk](../../62-Magisk/README.md),
and it is why serious apps put the decision on a server backed by hardware key attestation.

**Cleaning up is part of the work.** You started three processes and a mount, and you removed all of
them and verified it. On a client's device that habit is the difference between a professional
engagement and an incident report.

**Next:** [03 — Programming Fundamentals](../../03-Programming-Fundamentals/README.md), which steps
back from the operating system to ask what a *program* actually is — the last piece of groundwork
before you start reading Android's own code. Everything you have used in this chapter will be
waiting: [21 — App Sandbox](../../21-App-Sandbox/README.md) turns the permission bits into an
enforced sandbox, and [24 — IPC](../../24-IPC/README.md) turns the sockets into an attack surface.
