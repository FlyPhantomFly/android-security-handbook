# Worked Example — Permission Arithmetic Drill

Thirty problems, with the reasoning written out rather than just the answer. The goal is not to get
them right; it is to stop having to think.

**Chapter:** [02 — Linux Basics](../README.md) ·
**Lab:** [01 — Filesystem and permissions](../labs/lab-01-filesystem-and-permissions.md) ·
**Checker:** [`../scripts/explain-mode.sh`](../scripts/explain-mode.sh)

> **How to use this.** Cover the answer with your hand or a piece of paper. Write your answer down —
> physically, on paper, not in your head. Then uncover. If you were wrong, read the reasoning before
> moving on; if you were right but slow, do that section again tomorrow. Fifteen minutes a day for
> four days beats two hours once.

---

## The rules, in nine lines

```
 r = 4      w = 2      x = 1        (add them up, per class)

 rwx = 7    rw- = 6    r-x = 5    r-- = 4
 -wx = 3    -w- = 2    --x = 1    --- = 0

 Fourth digit:   4000 setuid    2000 setgid    1000 sticky
 Displayed as:   s in owner x   s in group x   t in other x
 (capital S or T if the underlying x bit was off — usually a mistake)

 The type character at the front (- d l c b s p) is NOT part of the number.
```

And the rule that decides *which* class applies:

> The kernel picks **one** class and stops. If your effective UID is the owner, the owner bits are
> used and the group and other bits are never consulted — even when they are more permissive.

---

## Section A — Symbolic to octal (10 problems)

### A1. `-rw-r--r--`

<details><summary>Answer</summary>

**644**

Ignore the leading `-` (type: regular file). Then `rw-` = 4+2 = **6**, `r--` = **4**, `r--` = **4**.

This is the most common mode on any system. On Android it is the mode of `base.apk`, which is
correct: an APK is not a secret, and this is why static analysis of any installed app is always
possible.
</details>

### A2. `-rwxr-xr-x`

<details><summary>Answer</summary>

**755**

`rwx` = 7, `r-x` = 4+1 = 5, `r-x` = 5. The mode of essentially every binary in `/system/bin` and
`/usr/bin`, and of most directories.
</details>

### A3. `drwx------`

<details><summary>Answer</summary>

**700**

`rwx` = 7, `---` = 0, `---` = 0. The `d` is the type, not part of the number.

**This is the Android app sandbox.** `/data/data/com.example.app` is `drwx------` owned by the app's
own UID. No other UID may enter it, list it, or read anything in it. That is the entire mechanism —
not a framework feature, not an API, just a directory mode.
</details>

### A4. `-rw-------`

<details><summary>Answer</summary>

**600**

The mode produced by `Context.openFileOutput(name, MODE_PRIVATE)` on Android. Anything wider than
this inside an app's private storage deserves a look.
</details>

### A5. `drwxrwx--x`

<details><summary>Answer</summary>

**771**

`rwx` = 7, `rwx` = 7, `--x` = **1**.

Look hard at that last digit. "Other" gets **execute but not read**. On a directory, execute means
*traverse* and read means *list*. So anyone can enter a subdirectory whose name they already know,
and nobody can obtain the list of names.

This is `/data` and `/data/data` on Android (they are `drwxrwx--x`), and it is a deliberate
anti-enumeration control: knowing which apps are installed is itself sensitive.
</details>

### A6. `-r--r-----`

<details><summary>Answer</summary>

**440**

`r--` = 4, `r--` = 4, `---` = 0. Read-only for the owner and the group, nothing for anyone else. A
reasonable mode for a config file that a service must read but nothing must change.
</details>

### A7. `drwxr-x---`

<details><summary>Answer</summary>

**750**

`rwx` = 7, `r-x` = 5, `---` = 0. A directory the owner controls, the group may use, and nobody else
can even traverse.
</details>

### A8. `-rwsr-xr-x`

<details><summary>Answer</summary>

**4755**

The `s` in the owner's execute slot is the **setuid** bit, worth `4000`. The underlying `x` is still
on (lower-case `s` tells you that; an upper-case `S` would mean it was off). Then `rwx` = 7, `r-x` =
5, `r-x` = 5.

`/usr/bin/passwd` and Android's `/system/bin/run-as` both look like this. When you run such a binary,
your process's effective UID becomes the file owner's — usually root. That is why setuid binaries are
the classic local privilege escalation target, and why finding an unexpected one is a finding.
</details>

### A9. `drwxrwxrwt`

<details><summary>Answer</summary>

**1777**

The `t` in the other execute slot is the **sticky** bit, worth `1000`. Then `rwx` three times = 777.

`/tmp` on desktop Linux. World-writable, so anyone may create files; sticky, so only an entry's owner
may delete or rename it. Without the sticky bit, write permission on the directory would let anyone
delete anyone's files — because deleting a file modifies the *directory*, not the file.
</details>

### A10. `-rwSr--r--`

<details><summary>Answer</summary>

**4644**

A capital `S`. Setuid is set (`4000`), but the owner's execute bit is **off**, so the file cannot be
executed at all and the setuid bit does nothing.

This is almost always a mistake — someone ran `chmod u+s` on a data file, or `chmod 4644` when they
meant `4755`. Report it as a hygiene issue: it is not exploitable, and it tells you the person
setting modes was not paying attention, which suggests looking harder at everything else they set.
</details>

---

## Section B — Octal to symbolic (10 problems)

Assume a regular file unless the mode is one you would only see on a directory.

### B1. `600`

<details><summary>Answer</summary>

`-rw-------`

6 = `rw-`, 0 = `---`, 0 = `---`.
</details>

### B2. `755`

<details><summary>Answer</summary>

`-rwxr-xr-x`
</details>

### B3. `640`

<details><summary>Answer</summary>

`-rw-r-----`

The sensible middle ground: the owner writes, a specific group reads, the world gets nothing. Reach
for this before `644` whenever the content is not meant to be public.
</details>

### B4. `751`

<details><summary>Answer</summary>

`-rwxr-x--x`

Note the `--x` for other. On a directory this means "you may pass through if you know the name, but
you may not look around" — the same pattern as A5.
</details>

### B5. `711`

<details><summary>Answer</summary>

`-rwx--x--x`

A directory at `711` is the strongest form of the traverse-but-do-not-enumerate pattern: the owner
does everything, and everyone else can only resolve names they already know.
</details>

### B6. `2775`

<details><summary>Answer</summary>

`-rwxrwsr-x`

The leading `2` is **setgid**. On a *directory* this is the interesting one: files created inside
inherit the directory's group rather than the creating process's primary group. It is how shared
project directories are built on multi-user systems.
</details>

### B7. `1730`

<details><summary>Answer</summary>

`-rwx-wx--T`

Two things to notice. `3` = `-wx` (write and execute, no read). And the other class is `0` = `---`,
so when the sticky bit forces a letter into the other-execute slot it appears as a **capital** `T`,
because the underlying `x` was off.

Modes like this are rare and usually indicate confusion. Verify with `stat` before writing anything
about them.
</details>

### B8. `466`

<details><summary>Answer</summary>

`-r--rw-rw-`

And now the important question: **can the owner write this file?**

**No.** The owner's effective UID matches the file's owner, so the kernel uses the owner class — `r--`
— and stops. It never looks at group or other. The owner has strictly *less* access than a complete
stranger.

This is the single most counter-intuitive fact about UNIX permissions, and the reason to state the
rule as "the kernel picks one class and stops" rather than "the kernel checks the permissions".
</details>

### B9. `000`

<details><summary>Answer</summary>

`----------`

Nobody can read, write or execute it — including the owner.

But the owner can still `chmod` it back, because `chmod` is governed by *ownership*, not by the mode.
And root ignores the mode entirely. So mode `000` protects a file from other unprivileged UIDs and
from nothing else. That is exactly the property Android's sandbox depends on, viewed from the other
side.
</details>

### B10. `775`

<details><summary>Answer</summary>

`-rwxrwxr-x`

Group-writable. Fine on a shared development directory, and a finding inside an Android app's private
storage, because the "group" for an app UID is that app's own group and anything wider is an
unnecessary widening.
</details>

---

## Section C — Judgement calls (10 problems)

These have no single numeric answer. Write a sentence, not a number.

### C1. An Android app's SQLite database at `/data/data/com.bank.app/databases/session.db` has mode `0660`. Is that a finding?

<details><summary>Answer</summary>

**Probably not, but check the group.**

`0660` is `-rw-rw----`: the owner and the group may read and write, the world gets nothing. For an
app file, the owner is the app's UID and the group is normally the app's own GID, so this is
effectively owner-only.

The question to ask is *which* group. If `ls -l` shows a group like `u0_a231` (the app's own), it is
fine. If it shows a shared group such as `sdcard_rw`, `media_rw` or `everybody`, then "group" means
something much wider and it is a finding. Always read the owner and group columns, never the mode
alone.
</details>

### C2. You find a file at mode `0777` on `/sdcard`. How serious is it?

<details><summary>Answer</summary>

**Less than the number suggests, but it is still shared storage.**

Two mount flags change the picture. `/storage/emulated` is mounted `noexec`, so the `x` bits are
inert — nothing there can be executed whatever its mode. It is also mounted `nosuid`, so a setuid bit
there would be ignored too.

More importantly, classic permission bits on shared storage are largely synthesised by the FUSE layer
rather than being the real access control; access is governed by Scoped Storage and by the media
permissions. The correct framing is not "this file is 0777" but "**this file is in shared storage,
therefore treat it as public**". Report the data that is exposed, not the mode.

```bash
# adb shell — check before you write it up
grep ' /storage/emulated ' /proc/mounts
```
</details>

### C3. `find /system -perm -4000 -type f` returns nothing on a device. Is the device unrooted?

<details><summary>Answer</summary>

**No, and this is the most important trap in the whole chapter.**

An empty list means there is no setuid binary *at that path in your view of the filesystem*. Modern
systemless root does not put a setuid `su` on disk at all. It builds an alternative filesystem view
with bind mounts and, for apps on its DenyList, gives them a private mount namespace with those
mounts removed.

So a negative result tells you one of three things and you cannot distinguish them from the shell
alone: the device is unrooted; the device is rooted systemlessly; or your process is in a namespace
where the modifications have been removed.

```bash
# adb shell — better evidence, none of it conclusive either
which su; ls -l /system/xbin/su /sbin/su 2>/dev/null
getprop ro.build.tags        # release-keys vs test-keys
getprop ro.boot.verifiedbootstate
grep -c magisk /proc/mounts
readlink /proc/self/ns/mnt; readlink /proc/1/ns/mnt   # same namespace as init?
```

See [Lab 04](../labs/lab-04-ctf-the-hidden-flag.md) and
[37 — Root Detection](../../37-RootDetection/README.md).
</details>

### C4. An app's cache directory is `drwxrwx--x` owned by `u0_a231:u0_a231_cache`. Why two different names?

<details><summary>Answer</summary>

Android gives some app directories a **separate cache GID** so that the platform can manage cache
storage — for example, deleting cached data under storage pressure — without holding the app's own
GID. The owner remains the app's UID.

The `--x` for other is the same anti-enumeration pattern as A5: another process can traverse to a
cache file whose exact name it knows and cannot list the directory to discover names.

The lesson for the drill: **the mode is only a third of the answer.** Owner, group and mode have to
be read together, and a name like `u0_a231_cache` is telling you something specific.
</details>

### C5. A developer says "I fixed the permission error with `chmod 777`." What do you write in the report?

<details><summary>Answer</summary>

Something like:

> The application resolves a file-access error by calling `chmod(path, 0777)` on
> `<path>`, making the file readable and writable by every UID on the device — that is, by every
> installed application. Zygote's default umask would otherwise have produced `0600`.
>
> **Impact** depends on the file's role: a config file becomes attacker-controllable, a credential
> store becomes attacker-readable, and an executable becomes an attacker-supplied code path inside
> this application's UID.
>
> **Root cause** is that `0777` was applied as a remedy for an error whose actual cause was
> elsewhere. On Android, "permission denied" has five possible sources: the file mode; a missing `x`
> on a parent directory; an SELinux denial; a `ro`/`noexec`/`nosuid` mount; or a seccomp filter.
> Widening the mode only ever addresses the first.
>
> **Remediation:** remove the `chmod` call, diagnose the original failure (`ls -ld` on every path
> component, then `dmesg | grep avc`), and create the file through `openFileOutput(name,
> MODE_PRIVATE)`. If data genuinely needs to be shared, share it through a permission-guarded
> `ContentProvider` or a bound service, both of which can identify the caller.
</details>

### C6. Why does `ls -l` show `lrwxrwxrwx` for every symbolic link?

<details><summary>Answer</summary>

Because a symlink's own permission bits are **not used for anything** on Linux, so they are always
displayed as fully open. Access is decided by the permissions of the *target*, resolved fresh at every
`open()`.

The security consequence is that you can never look at a symlink's mode and conclude anything. You
must resolve it:

```bash
readlink    /sdcard      # one hop
readlink -f /sdcard      # all hops, canonical
ls -l "$(readlink -f /sdcard)"
```

`readlink -f` is the shell equivalent of Java's `getCanonicalPath()`, and using `getAbsolutePath()`
instead is the root cause of a whole family of path-traversal bugs.
</details>

### C7. A directory is mode `0700` and the file inside it is mode `0666`. Who can read the file?

<details><summary>Answer</summary>

**Only the directory's owner (and root).**

To open `dir/file`, the kernel needs execute permission on `dir`. At `0700` only the owner has it, so
no other UID can traverse into the directory at all — and therefore no other UID can reach the file,
however permissive the file's own mode is.

This is why permission review must walk the whole path, not just look at the leaf. It also means
`0666` here is not exploitable *today* and is still worth reporting as defence-in-depth: the day
somebody loosens the directory to `0755`, the file becomes world-writable with no other change.
</details>

### C8. You can `cat /data/data/com.example.app/files/x.txt` but `ls /data/data/com.example.app/files/` says permission denied. Explain.

<details><summary>Answer</summary>

The directory has `x` and not `r` for your class — mode `--x` somewhere in the chain. Execute permits
traversal (resolving a name you already have), read permits enumeration (obtaining the list of names).
You have the first and not the second.

Practically, it means you can reach any file whose exact name you know and you cannot discover names.
Which turns the whole problem into "where do names leak" — logs, stack traces, `strings` output,
crash reports, `ContentProvider` URIs, and backup manifests. That is exactly stage 1 of
[Lab 04](../labs/lab-04-ctf-the-hidden-flag.md).
</details>

### C9. Your umask is `0077`. You run `touch a && mkdir b`. What modes do you get, and why not `0666` and `0777`?

<details><summary>Answer</summary>

`a` gets **0600** and `b` gets **0700**.

The C library requests `0666` for a new file and `0777` for a new directory. The kernel then applies
`requested & ~umask`. With a umask of `0077`, every bit for group and other is removed, leaving
`0600` and `0700`.

A umask can only ever take bits away. It is inherited across `fork()` and `execve()`, which is why
Zygote setting a restrictive umask before an app's code runs also protects any native helper the app
spawns — unless the app deliberately overrides it, which is C5.

```bash
# host / WSL — check your arithmetic
sh ../scripts/explain-mode.sh --umask 077 666
```
</details>

### C10. What is the difference between `find . -perm 644`, `find . -perm -644` and `find . -perm /644`?

<details><summary>Answer</summary>

| Form | Meaning | Matches |
|---|---|---|
| `-perm 644` | **Exactly** this mode, all twelve bits | Files whose mode is precisely `0644`, nothing else |
| `-perm -644` | **At least** these bits (all of them set) | `0644`, `0666`, `0755`, `0777`, ... |
| `-perm /644` | **Any** of these bits set | Almost everything |

The leading minus is what makes `find / -perm -4000 -type f` work. Without it, `-perm 4000` means
"mode is exactly `4000`" — a file with no read, write or execute bits at all but with setuid set —
which matches essentially nothing, and you will silently conclude the device has no setuid binaries.

**Getting this wrong produces a false negative in a security check, which is the worst kind of
mistake.** Read `man 1 find` on the `-perm` section once, properly.
</details>

---

## Speed test

Once the sections above are comfortable, do these ten in under ninety seconds, out loud, without
writing anything:

```
644   755   700   600   771   1777   4755   640   711   2775
```

<details><summary>Answers, in order</summary>

`-rw-r--r--`, `-rwxr-xr-x`, `-rwx------`, `-rw-------`, `-rwxrwx--x`, `-rwxrwxrwt`, `-rwsr-xr-x`,
`-rw-r-----`, `-rwx--x--x`, `-rwxrwsr-x`
</details>

And these ten, the other way:

```
-rw-r--r--   drwx------   -rwsr-xr-x   drwxrwxrwt   -r--------
drwxrwx--x   -rw-rw----   -rwxr-x---   ----------   -rwxrwxrwx
```

<details><summary>Answers, in order</summary>

644, 700, 4755, 1777, 400, 771, 660, 750, 000, 777
</details>

---

## Checking yourself

```bash
# host / WSL or adb shell — the chapter's checker
sh ../scripts/explain-mode.sh 4755
sh ../scripts/explain-mode.sh drwxrwx--x
sh ../scripts/explain-mode.sh --umask 022 666
sh ../scripts/explain-mode.sh --table
sh ../scripts/explain-mode.sh --drill

# and against the kernel itself, which is the real authority
stat -c '%a %A %U %G %n' /etc/passwd /tmp /usr/bin/passwd
```

```bash
# adb shell — the same, on a device
sh /data/local/tmp/explain-mode.sh /data/local/tmp
ls -ld /data /data/data /data/local/tmp
```

---

## Where this goes next

| Next | Why |
|---|---|
| [Lab 01](../labs/lab-01-filesystem-and-permissions.md) | Every mode here, observed on a real device |
| [Lab 04](../labs/lab-04-ctf-the-hidden-flag.md) | Stage 1 is C8, under time pressure |
| [Annotated `ls -l` and `/proc`](annotated-ls-l-and-proc.md) | The other eight fields of the line |
| [21 — App Sandbox](../../21-App-Sandbox/README.md) | `drwx------` turned into an enforced security boundary |
| [Chapter FAQ](../faq.md) | "Should I just chmod 777", answered at length |
