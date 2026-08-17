# Lab 04 — CTF: The Quiet Corruption

> **Objective:** you are handed a crash, a maps capture and a description of an app. Work out what
> the defect is, whether it is reachable, what an attacker could actually do with it, and write the
> severity paragraph you would defend in a client meeting. Six flags.

**Difficulty:** advanced
**Time:** 2–4 hours
**Prerequisites:** Labs [01](lab-01-reading-proc-maps.md), [02](lab-02-allocator-behaviour.md) and
[03](lab-03-detection-hwasan-mte.md). All of chapter 19 §3 and §5.

---

## The scenario

**Nimbus Notes** is a note-taking app with an end-to-end-encrypted sync feature. The crypto and the
sync protocol are implemented in a bundled native library, `libnimbus.so`, because the vendor
"wanted the key material out of Java". The app is in production with roughly 400,000 installs.

Your client is the vendor. Their crash dashboard shows a cluster of native crashes with no obvious
pattern: different functions, different threads, no reproducer. Support has been closing them as
"device-specific". Someone finally asked whether they might be the same bug.

You have been given:

- a symbolicated tombstone excerpt (Artefact A),
- a `/proc/<pid>/maps` capture from a device that crashed (Artefact B — use
  [`../examples/fixture-app-maps.txt`](../examples/fixture-app-maps.txt)),
- the relevant source of `libnimbus.so` (Artefact C),
- a HWASan report from a test build (Artefact D).

You do **not** have a device with the app installed. Everything is offline analysis, which is the
common case when a vendor sends you a crash dump.

**Rules of engagement.** The deliverable is an assessment, not an exploit. No flag requires you to
write shellcode, and a submission that includes a weaponised chain scores zero — the point of the
exercise is to show that you can reason about reachability without needing one.

---

## Artefact A — the tombstone

```
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000000000000041
Cause: null pointer dereference

    x0  0000000000000041  x1  b400007320104a80  x2  0000000000000020  x3  0000000000000000
    x8  4141414141414141  x9  b400007320104aa0

backtrace:
      #00 pc 000000000000c1f4  /data/app/~~kQ3n1==/com.nimbus.notes-Xb9==/lib/arm64/libnimbus.so (nimbus_sync_flush+68)
      #01 pc 000000000000a930  /data/app/~~kQ3n1==/com.nimbus.notes-Xb9==/lib/arm64/libnimbus.so (nimbus_session_close+112)
      #02 pc 0000000000009118  /data/app/~~kQ3n1==/com.nimbus.notes-Xb9==/lib/arm64/libnimbus.so (Java_com_nimbus_notes_Native_closeSession+40)
      #03 pc 00000000002f1a40  /apex/com.android.art/lib64/libart.so (art_quick_generic_jni_trampoline+144)
```

Other crashes in the same cluster show `fault addr 0x0000000000000000`, `fault addr
0x4141414141414141`, and one `Scudo ERROR: invalid chunk state when deallocating address
0x2000073201049c0`.

---

## Artefact C — the source

```c
/* nimbus_session.c -- abridged */

typedef struct {
    uint8_t  key[32];
    uint8_t *outbuf;          /* owned */
    size_t   outlen;
    void   (*on_flush)(void *ctx, const uint8_t *data, size_t len);
    void    *ctx;
} nimbus_session;

/* Called from the sync thread whenever the server sends a frame. */
int nimbus_sync_recv(nimbus_session *s, const uint8_t *frame, size_t frame_len)
{
    uint32_t declared = read_be32(frame);          /* attacker-controlled */
    if (declared > MAX_FRAME) {
        return -1;
    }
    if (s->outbuf == NULL) {
        s->outbuf = malloc(declared);
        s->outlen = declared;
    }
    memcpy(s->outbuf, frame + 4, declared);        /* [1] */
    return 0;
}

/* Called from the UI thread when the user closes the note. */
void nimbus_session_close(nimbus_session *s)
{
    free(s->outbuf);                               /* [2] */
    memset(s->key, 0, sizeof(s->key));
    free(s);                                       /* [3] */
}

/* Called from the sync thread on teardown. */
void nimbus_sync_flush(nimbus_session *s)
{
    if (s->on_flush != NULL) {
        s->on_flush(s->ctx, s->outbuf, s->outlen); /* [4] */
    }
}
```

---

## Artefact D — the HWASan report from a test build

```
==8821==ERROR: HWAddressSanitizer: tag-mismatch on address 0x0071320104a80 at pc 0x0072a1c0c1f4
READ of size 8 at 0x0071320104a80 tags: 3f/9c (ptr/mem) in thread T4

[0x0071320104a80,0x0071320104ac0) is a small unallocated heap chunk; size: 64 offset: 0

Cause: use-after-free
0x0071320104a80 is located 0 bytes inside of 64-byte region [0x0071320104a80,0x0071320104ac0)
freed by thread T1 here:
    #0 ... (libclang_rt.hwasan-aarch64-android.so+0x208dc)
    #1 nimbus_session_close+112
    #2 Java_com_nimbus_notes_Native_closeSession+40

previously allocated here:
    #0 ... (libclang_rt.hwasan-aarch64-android.so+0x20f88)
    #1 nimbus_session_open+64
```

---

## Flag 1 — Name the bug

**Submit:** the CWE class, the exact line numbers involved, and the two-sentence explanation you
would put at the top of the finding.

<details><summary>Hint</summary>

Look at which *threads* the HWASan report names. `freed by thread T1`, and the faulting read is
`in thread T4`.

</details>

<details><summary>Answer</summary>

**CWE-416, use-after-free**, with **CWE-362, a race condition** as its cause.

`nimbus_session_close` frees the session at `[3]` from the UI thread. `nimbus_sync_flush` reads
`s->on_flush` at `[4]` from the sync thread. Nothing serialises the two, so a user closing a note
while a sync frame is in flight causes the sync thread to read and then *call through* a function
pointer inside a freed structure.

The two-sentence version for the report: "Closing a note frees the native session object while the
sync thread may still be using it; the sync thread then reads a function pointer out of the freed
memory and calls it. Because the freed block is immediately reusable, the value it calls is whatever
the next allocation put there."

Note what makes this a *good* finding rather than a merely correct one: the trigger is an ordinary
user action, not a malformed input.

</details>

---

## Flag 2 — Explain the register state

**Submit:** why `x8` contains `0x4141414141414141` in one crash and `x0` contains `0x41` in another,
and what that tells you about attacker control.

<details><summary>Answer</summary>

`0x41` is `'A'`. `0x4141414141414141` is eight of them. Those are not addresses that occurred by
accident — they are data, being used as a pointer.

The sequence is: the session is freed at `[3]`, another allocation of the same size class reclaims
the block (Lab 02 measured that reuse is immediate on Android), and that allocation is filled with
content. In these crashes the content happened to be `'A'` bytes. `nimbus_sync_flush` then reads
`s->on_flush` — which is now those bytes — and calls it.

**What it tells you about control:** whoever wrote the `'A'`s into the reclaimed block controls the
value that gets called. That is a strong indicator of a *controlled* call target, which is the
difference between a crash and a control-flow hijack primitive.

**What it does not tell you:** whether an *attacker* wrote them. A UAF whose reclaiming allocation
is always some internal buffer the attacker cannot influence is far weaker. That is Flag 3.

The variety in the cluster — `0x0`, `0x41`, `0x4141414141414141` — is itself diagnostic. Crashes at
*different* addresses with the *same* stack are the signature of a use-after-free, because the value
depends on whatever reclaimed the memory. A null-pointer dereference crashes at `0x0` every time.

</details>

---

## Flag 3 — The reachability argument

**Submit:** the chain of conditions an attacker must satisfy, in order, and which of them you can
confirm from the artefacts alone.

<details><summary>Answer</summary>

1. **Trigger the free.** The user closes a note. An attacker cannot do this directly; they need the
   user to. *Confirmed from the source.* This is the weakest link and it must be stated.
2. **Have a sync frame in flight at that moment.** A malicious or compromised sync server can keep
   frames arriving continuously, which makes the window very wide rather than very narrow.
   *Inferred, not confirmed* — depends on whether the server is trusted and whether TLS pinning
   holds. Check that separately.
3. **Reclaim the freed 64-byte block with attacker-controlled content.** `nimbus_sync_recv` calls
   `malloc(declared)` with an attacker-supplied length and then `memcpy`s attacker-supplied bytes
   into it. If the attacker chooses `declared` so the allocation lands in the same size class, they
   groom the hole with their own bytes. *Confirmed from the source, and this is the crux.*
4. **Have the freed pointer read.** `nimbus_sync_flush` runs on teardown. *Confirmed from the
   backtrace.*
5. **Survive the call.** Calling an arbitrary address on AArch64 with PAC, BTI, NX and full RELRO in
   the way is a separate and much harder problem.

**What you can confirm from the artefacts:** 1, 3 and 4. **What you cannot:** 2 and 5.

The honest severity statement writes itself: an attacker who controls the sync server can place
chosen bytes into a freed object whose function pointer is subsequently called. It requires a user
action to trigger and a hostile or compromised server. It is a control-flow hijack primitive, not a
demonstrated exploit.

</details>

---

## Flag 4 — The second bug

There is a separate defect in `nimbus_sync_recv` that has nothing to do with threads.

**Submit:** what it is, why the `declared > MAX_FRAME` check does not prevent it, and the one-line
fix.

<details><summary>Hint</summary>

Read the `if (s->outbuf == NULL)` carefully. What happens on the *second* call?

</details>

<details><summary>Answer</summary>

**A heap buffer overflow, CWE-122.** The buffer is allocated once, on the first frame, at whatever
size that first frame declared. Every subsequent frame `memcpy`s `declared` bytes into it —
`declared` from *that* frame, not the one that sized the buffer.

The `MAX_FRAME` check does not help because it bounds `declared` against a constant, not against
`s->outlen`. Frame 1 declares 64 and allocates 64. Frame 2 declares 4000, passes the `MAX_FRAME`
check, and copies 4000 bytes into a 64-byte buffer.

There is a third defect hiding in the same function: `malloc(declared)` is not checked for `NULL`,
so a large-but-legal `declared` on a memory-pressured device gives a `NULL` `outbuf` and the
`memcpy` writes to address 0 onwards.

**The fix**, and note it is a *class* fix rather than an instance fix:

```c
if (s->outbuf == NULL) {
    s->outbuf = malloc(declared);
    if (s->outbuf == NULL) {
        return -1;
    }
    s->outlen = declared;
}
if (declared > s->outlen) {          /* <- against the CAPACITY, not a constant */
    return -1;
}
memcpy(s->outbuf, frame + 4, declared);
```

`heap-bugs-fixed.c`'s `buf_t` shows the structural version of the same idea: keep the capacity next
to the pointer so no caller can forget it. Note also that the check must be `declared > s->outlen`
and not `s->len + declared > s->outlen` — the additive form can overflow `size_t` and wrap.

</details>

---

## Flag 5 — Read the maps

Open [`../examples/fixture-app-maps.txt`](../examples/fixture-app-maps.txt) as Artefact B and run:

```bash
python3 ../scripts/maps-analyse.py ../examples/fixture-app-maps.txt
```

**Submit:** (a) which allocator and which checkers this process was running, (b) whether the
`libnimbus.so`-equivalent library is where you would expect, (c) one region in the capture that
would change your exploitability assessment, and why.

<details><summary>Answer</summary>

**(a)** Scudo (`[anon:scudo:primary]`, `[anon:scudo:secondary]`) **and** GWP-ASan
(`[anon:GWP-ASan guard]`, `[anon:GWP-ASan alive slot]`). No HWASan — no `SizeClassAllocator`
regions. So the crashing device had sampled guard-page checking enabled but no full instrumentation,
which is consistent with a production Android 14+ build.

That matters: GWP-ASan being present explains why *some* crashes in the cluster are clean guard-page
faults while most are the messy variable-address ones. It also means the vendor already has a
partial detector switched on and has been ignoring what it reports.

**(b)** Yes. `/data/app/~~kQ3n1==/com.example.target-Xb9==/lib/arm64/libnative-lib.so` is mapped with
the normal four-segment pattern, `r--p r-xp r--p rw-p`, from the app's install directory. Nothing
unusual. The analyser flags it `DATA-EXEC`, correctly, and the flag is not a finding — that is where
every app's native libraries live.

**(c)** Several candidates, and the reasoning matters more than the choice:

- `/data/data/com.example.target/files/libdyn-payload.so` — an executable library loaded from
  *runtime-writable* storage, not from the install directory. If the app can write there and then
  load it, an attacker who can influence that file has code execution without needing the UAF at
  all, and the UAF stops being the most interesting thing in the report.
- `[anon:dalvik-jit-code-cache]` at `rwxp` — writable and executable. An attacker with an arbitrary
  write does not need to defeat NX; there is already RWX memory at a *predictable* location, because
  it is inherited from the Zygote. This makes step 5 of Flag 3 materially easier and should be said
  out loud.
- The unnamed `rwxp` region at `007360000000` — 16 KiB of executable memory that nothing in bionic
  or ART named. Unexplained, and worth explaining before finishing the assessment.
- `/memfd:jit-cache (deleted)` — executable code with no file on disk. If it is not ART's, static
  analysis of the APK will never show it.

</details>

---

## Flag 6 — The severity paragraph

**Submit:** the paragraph you would put in the report, and defend it against both of these
objections:

> *Developer:* "This needs a malicious server and a user closing a note at exactly the right moment.
> That is not realistic."

> *Security lead:* "It is a function-pointer overwrite with attacker-controlled data. That is
> critical, full stop."

<details><summary>A model answer</summary>

**The paragraph:**

> `libnimbus.so` frees the native session object on the UI thread while the sync thread may still be
> dereferencing it (`nimbus_session_close` → `nimbus_sync_flush`, confirmed by HWASan with both
> stacks). Because Android's allocator reuses freed blocks immediately, and because
> `nimbus_sync_recv` allocates and fills a buffer with server-supplied length and content, an actor
> controlling the sync connection can place chosen bytes into the freed object before its `on_flush`
> function pointer is read and called. We confirmed the free, the reuse and the call from source and
> from the sanitiser report; we did **not** demonstrate control-flow hijack, and doing so would have
> to defeat PAC, BTI and full RELRO, which we did not attempt. A separate heap overflow in
> `nimbus_sync_recv` (frame 2 onward is copied against frame 1's allocation size) gives the same
> actor a second, simpler corruption primitive. We rate this **High**: the corruption is
> attacker-influenced and reaches a function pointer, but exploitation requires a hostile or
> compromised sync server and a concurrent user action, and we have not shown the final step.

**Against the developer:** the user action is *closing a note*, which every user does dozens of times
a day, and the timing window is as wide as the attacker wants it because they control the frame
rate. "Exactly the right moment" implies microseconds; it is not. Separately, the heap overflow in
Flag 4 needs no race at all — it is reachable with two frames and no user involvement — so even if
you accept the race argument entirely, the finding does not go away.

**Against the security lead:** "attacker-controlled function pointer" is the primitive, not the
outcome. We have not shown that the call can be turned into execution on a modern arm64 device with
PAC and BTI, and we did not try. Rating it Critical without that step means the rating rests on an
assumption, and the first competent developer to notice will discount everything else in the report.
High is defensible, and if we are given a week to demonstrate the final step and we succeed, we
raise it — with evidence.

Note what both defences have in common: neither argues from authority, and both point at something
checkable.

</details>

---

## Scoring

| Flag | What it tests | Points |
|---|---|---|
| 1 | Recognising a bug class from a sanitiser report | 10 |
| 2 | Reading register state as evidence about control | 15 |
| 3 | Building an ordered reachability chain, and marking what is unconfirmed | 25 |
| 4 | Finding the bug nobody pointed you at | 20 |
| 5 | Turning a maps capture into an exploitability input | 15 |
| 6 | Writing a severity you can defend from both directions | 15 |
| | **Total** | **100** |

**80+** — you can run this engagement.
**60–79** — solid; re-read §5.6 on reachability and §5.7 on severity.
**Below 60** — work through Labs 01–03 again with the fixtures actually running, not just read.

---

## Instructor notes

<details><summary>Open only after attempting the flags</summary>

**What this CTF deliberately does not include.** There is no exploit, no ROP chain, no gadget hunt.
Every flag can be scored by someone who has never written an exploit. That is intentional and it
mirrors the real deliverable: on an authorised engagement, the client needs "this is reachable and
here is the chain", not a working weapon. An assessor who can only demonstrate severity by achieving
code execution will systematically under-report the bugs they could not finish.

**The most common wrong answer to Flag 3** is to stop at "attacker controls a function pointer,
therefore critical". The chain has five links and two of them are unconfirmed. Marking the
unconfirmed links is the skill.

**The most common miss is Flag 4.** Given a race-condition UAF, most people stop looking. The
overflow is in the function the report already points at, is simpler, needs no race, and would be
the thing an attacker actually used.

**The artefacts are constructed.** `libnimbus.so` and Nimbus Notes do not exist; the tombstone and
HWASan report are written to be structurally faithful to real ones — the field order, the two
stacks, the `tags: X/Y (ptr/mem)` line, the `Cause:` classification — but they are not captures. The
maps fixture says the same about itself in its own header. Do not cite an address from any of them
as evidence of anything about a real product.

**Where the real-world equivalent of this bug shows up.** The pattern — an object freed on one
thread while another dereferences it, with a function pointer or vtable inside — is one of the most
common serious defect shapes in shipped native code, and is a recurring theme in Android's monthly
security bulletins. Rather than cite an identifier from memory and risk getting it wrong, read a few
months of the bulletin's "Media framework" and "System" sections and count how many entries are
use-after-free. The proportion is the point.

</details>

---

## Where to go next

| If you want to | Go to |
|---|---|
| Re-check any measurement this CTF assumed | [Lab 02](lab-02-allocator-behaviour.md) |
| Learn to read the sanitiser output properly | [Lab 03](lab-03-detection-hwasan-mte.md) |
| Look at the build-time mitigations that make step 5 hard | [15-Native-Code](../../15-Native-Code/README.md) §5 |
| Decompile the library the tombstone names | [57-Ghidra](../../57-Ghidra/README.md) |
| Work out which third-party library shipped the bug | [17-Libraries](../../17-Libraries/README.md) |
| Map the finding to a standard | [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) |
