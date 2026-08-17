# Lab 03 — Defining `JNIEnv` and Re-reading the Output

**Difficulty:** Intermediate
**Time:** 60–90 minutes
**Prerequisites:** [Lab 01](lab-01-first-contact-so.md),
[Chapter 57 §3.4](../README.md#34-type-propagation--the-part-you-will-spend-your-time-on) and
[§3.8](../README.md#38-the-jnienv-problem-and-how-to-solve-it)

> **Provenance.** Ghidra **is** installed on the machine this chapter was written on (12.1.2 PUBLIC,
> Java 24.0.2) and was run headless against the chapter's own target, so the tool behaviour this lab
> relies on is **✅ Measured**. Any decompiler listing quoted below as an *expected result* is
> **📘 Illustrative** — it shows the shape to look for, not a capture from a specific binary, and
> your addresses and variable names will differ. Build the real target with
> [`../examples/build.sh`](../examples/build.sh) and check your findings against its source. See
> [the chapter's provenance statement](../README.md#-read-this-before-you-read-anything-else-what-is-measured-here-and-what-is-not).

---

## Objective

Take one moderately complex JNI function and **measure** what type information buys you. You will:

1. Record the decompilation with no type information at all.
2. Add the function signature, and record it again.
3. Add `JNIEnv`, and record it again.
4. Recover and define a custom struct the code uses, and record it again.
5. Compare the four, and quantify the difference.

This lab has an unusual shape: the goal is not to solve a puzzle but to build an intuition you will
rely on for years. People who find Ghidra impenetrable are almost always looking at stage 1 output and
concluding the tool is bad.

---

## Why measure rather than just assert

"Define `JNIEnv` first" is advice that sounds like ritual until you have watched the same forty lines
of code go from meaningless to obvious. Writing down the before and after — actually copying the text
into a file — makes the mechanism concrete: *nothing about the binary changed; only what Ghidra knew
about `param_1` did*.

That framing generalises. Every subsequent frustration with decompiler output becomes a question with
an answer: "what does Ghidra not know yet, and can I tell it?"

---

## The target library

### `session.cpp`

```cpp
// Build for arm64-v8a. Deliberately uses a custom struct and several JNI calls,
// so that both kinds of typing (JNIEnv and a user struct) have visible effect.
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <android/log.h>

#define TAG "LAB03"

// The struct you will recover in stage 4. The compiler turns every field
// access into an offset from a base pointer; without the struct definition,
// Ghidra shows you the offsets.
typedef struct {
    unsigned int magic;        // +0x00
    unsigned int flags;        // +0x04
    unsigned long long issued; // +0x08
    unsigned long long expiry; // +0x10
    char           user[32];   // +0x18
    unsigned char  key[32];    // +0x38
    unsigned int   checksum;   // +0x58
} Session;                     // sizeof == 0x60

#define SESSION_MAGIC 0x5E5510EF
#define FLAG_ADMIN    0x0001
#define FLAG_EXPIRED  0x0002
#define FLAG_REVOKED  0x0004

static unsigned int checksum_of(const Session *s) {
    unsigned int acc = 0x811C9DC5u;
    const unsigned char *p = (const unsigned char *) s;
    // Everything except the checksum field itself.
    for (size_t i = 0; i < offsetof(Session, checksum); i++) {
        acc = (acc ^ p[i]) * 0x01000193u;
    }
    return acc;
}

static Session *g_session = nullptr;

extern "C" JNIEXPORT jboolean JNICALL
Java_com_ghidralab_session_Native_openSession(JNIEnv *env, jobject thiz,
                                              jstring username, jbyteArray key) {
    const char *u = env->GetStringUTFChars(username, nullptr);
    if (u == nullptr) return JNI_FALSE;

    jsize klen = env->GetArrayLength(key);
    if (klen != 32) {
        env->ReleaseStringUTFChars(username, u);
        __android_log_print(ANDROID_LOG_WARN, TAG, "bad key length %d", klen);
        return JNI_FALSE;
    }

    Session *s = (Session *) calloc(1, sizeof(Session));
    s->magic = SESSION_MAGIC;
    s->flags = 0;
    s->issued = (unsigned long long) time(nullptr);
    s->expiry = s->issued + 3600;
    strncpy(s->user, u, sizeof(s->user) - 1);

    jbyte *kb = env->GetByteArrayElements(key, nullptr);
    memcpy(s->key, kb, 32);
    env->ReleaseByteArrayElements(key, kb, JNI_ABORT);
    env->ReleaseStringUTFChars(username, u);

    if (strcmp(s->user, "root") == 0) {
        s->flags |= FLAG_ADMIN;
    }

    s->checksum = checksum_of(s);

    free(g_session);
    g_session = s;
    return JNI_TRUE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_ghidralab_session_Native_isAdmin(JNIEnv *env, jobject thiz) {
    if (g_session == nullptr) return JNI_FALSE;
    if (g_session->magic != SESSION_MAGIC) return JNI_FALSE;
    if (g_session->checksum != checksum_of(g_session)) return JNI_FALSE;
    if ((g_session->flags & (FLAG_EXPIRED | FLAG_REVOKED)) != 0) return JNI_FALSE;
    if ((unsigned long long) time(nullptr) > g_session->expiry) return JNI_FALSE;
    return (g_session->flags & FLAG_ADMIN) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_ghidralab_session_Native_describe(JNIEnv *env, jobject thiz) {
    char buf[128];
    if (g_session == nullptr) {
        return env->NewStringUTF("no session");
    }
    snprintf(buf, sizeof(buf), "user=%s flags=0x%04x expires=%llu",
             g_session->user, g_session->flags,
             (unsigned long long) g_session->expiry);
    return env->NewStringUTF(buf);
}
```

### `CMakeLists.txt`

```cmake
cmake_minimum_required(VERSION 3.22)
project(session)
add_library(session SHARED session.cpp)
find_library(log-lib log)
target_link_libraries(session ${log-lib})
set_target_properties(session PROPERTIES LINK_FLAGS "-Wl,--strip-all")
```

### The Java side

```java
package com.ghidralab.session;

public class Native {
    static { System.loadLibrary("session"); }
    public native boolean openSession(String username, byte[] key);
    public native boolean isAdmin();
    public native String describe();
}
```

```bash
# host
./gradlew assembleRelease
unzip -o -d raw app/build/outputs/apk/release/app-release.apk 'lib/*'
```

---

## Steps

Create a notes file. You will paste four versions of the same function into it.

```bash
# host
mkdir -p lab03-notes
touch lab03-notes/openSession-stages.c
```

### Stage 0 — Import, and do nothing else

Import `libsession.so` (`AARCH64:LE:64:v8A`), let analysis complete, and **do not** import
`jni_all.gdt` yet. Navigate to `Java_com_ghidralab_session_Native_openSession`.

Copy the entire decompilation into `lab03-notes/openSession-stages.c` under a heading
`/* ===== STAGE 0: nothing defined ===== */`.

It should look roughly like this:

```c
undefined8 Java_com_ghidralab_session_Native_openSession
                    (long param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4)
{
  int iVar1;
  long lVar2;
  undefined8 uVar3;
  undefined8 *puVar4;

  lVar2 = (**(code **)(*(long *)param_1 + 0x548))(param_1, param_3, 0);
  if (lVar2 == 0) {
    uVar3 = 0;
  }
  else {
    iVar1 = (**(code **)(*(long *)param_1 + 0x558))(param_1, param_4);
    if (iVar1 == 0x20) {
      puVar4 = (undefined8 *)calloc(1, 0x60);
      *(undefined4 *)puVar4 = 0x5e5510ef;
      ...
```

**Answer these questions from Stage 0 output alone**, and write your answers down:

| Question | Your answer |
|---|---|
| How many parameters does this function take? | |
| What does `0x548` do? | |
| What does `0x558` do? | |
| What is allocated, and how big is it? | |
| What is `0x5e5510ef`? | |
| What does the function return on failure? | |

You should find questions 2, 3 and 5 essentially unanswerable without either memorising the JNI offset
table or guessing.

### Stage 1 — Add the function signature only

Press `F` on the function name and enter:

```c
jboolean Java_com_ghidralab_session_Native_openSession(void *env, void *thiz, void *username, void *key)
```

Note: deliberately **not** `JNIEnv *` yet. This stage isolates what the *signature alone* buys you.

Copy the new decompilation under `/* ===== STAGE 1: signature, no JNIEnv ===== */`.

What changed? Parameter names and count are right, and the return type is now a `jboolean` rather than
`undefined8`. The JNI calls are still offset arithmetic.

**Record the diff in one sentence.**

### Stage 2 — Define `JNIEnv`

1. Data Type Manager → down-arrow → *Open File Archive…* → `jni_all.gdt`.
2. Press `F` again and set the real signature:

```c
jboolean Java_com_ghidralab_session_Native_openSession(JNIEnv *env, jobject thiz, jstring username, jbyteArray key)
```

Copy the new decompilation under `/* ===== STAGE 2: JNIEnv defined ===== */`.

It should now read approximately:

```c
jboolean Java_com_ghidralab_session_Native_openSession
                   (JNIEnv *env, jobject thiz, jstring username, jbyteArray key)
{
  char *pcVar1;
  jsize jVar2;
  void *pvVar3;
  jbyte *pjVar4;

  pcVar1 = (*env)->GetStringUTFChars(env, username, (jboolean *)0x0);
  if (pcVar1 == (char *)0x0) {
    return 0;
  }
  jVar2 = (*env)->GetArrayLength(env, key);
  if (jVar2 != 0x20) {
    (*env)->ReleaseStringUTFChars(env, username, pcVar1);
    __android_log_print(5, "LAB03", "bad key length %d", jVar2);
    return 0;
  }
  pvVar3 = calloc(1, 0x60);
  ...
```

**Now go back and answer the Stage 0 questions again.** All six should be trivial. Record how long
each took at each stage — even roughly. That ratio is the point of the lab.

### Stage 3 — Recover the `Session` struct

Ghidra now shows you a 0x60-byte allocation whose fields are written at offsets. You are going to give
those offsets names.

1. In the decompilation, find the `calloc(1, 0x60)` result and note every offset written to it:
   `+0x00`, `+0x04`, `+0x08`, `+0x10`, `+0x18`, `+0x38`, `+0x58`. Write the list down with the *size*
   of each write (`undefined4` = 4 bytes, `undefined8` = 8, a `strncpy`/`memcpy` gives you an array
   length).

2. Data Type Manager → right-click your program's category → *New → Structure*. Name it `Session`,
   set the size to `0x60`, and fill in:

| Offset | Type | Name | How you knew |
|---|---|---|---|
| `0x00` | `uint` | `magic` | 4-byte write of `0x5e5510ef` |
| `0x04` | `uint` | `flags` | 4-byte write of 0, later OR'd |
| `0x08` | `ulonglong` | `issued` | 8-byte write of `time()`'s result |
| `0x10` | `ulonglong` | `expiry` | 8-byte write of `issued + 0xe10` |
| `0x18` | `char[32]` | `user` | `strncpy` destination, length `0x1f` |
| `0x38` | `byte[32]` | `key` | `memcpy` destination, length `0x20` |
| `0x58` | `uint` | `checksum` | 4-byte write of the hash function's result |

3. Retype the local variable holding the `calloc` result: click it, `Ctrl+L`, `Session *`.

Copy the new decompilation under `/* ===== STAGE 3: Session struct defined ===== */`.

It should now read:

```c
  pSVar3 = (Session *)calloc(1, 0x60);
  pSVar3->magic = 0x5e5510ef;
  pSVar3->flags = 0;
  tVar5 = time((time_t *)0x0);
  pSVar3->issued = tVar5;
  pSVar3->expiry = tVar5 + 0xe10;
  strncpy(pSVar3->user, pcVar1, 0x1f);
```

4. Also retype the global. Go to the address the result is stored to (the `g_session` global), press
   `T`, and set it to `Session *`. Now `isAdmin` becomes readable too — **without you touching it**.

Open `Java_com_ghidralab_session_Native_isAdmin` and read it. This is the compounding effect: work you
did in one function paid off in another.

### Stage 4 — Name the constants

Ghidra shows `0xe10` and `0x5e5510ef` and `0x811c9dc5`. Give them meaning.

1. `0xe10` is 3600 — one hour. Right-click → *Convert → Unsigned Decimal*.
2. Create an enum for the flags: Data Type Manager → *New → Enum*, name it `SessionFlags`, add
   `FLAG_ADMIN = 1`, `FLAG_EXPIRED = 2`, `FLAG_REVOKED = 4`. Then retype the `flags` field to it.
3. `0x811c9dc5` and `0x01000193` are the FNV-1a 32-bit offset basis and prime. Recognising standard
   constants is a skill worth building — rename the hash function to `fnv1a`.

Copy the final decompilation under `/* ===== STAGE 4: constants named ===== */`.

### Stage 5 — Measure

Write a short summary at the top of your notes file answering:

1. How many lines of the Stage 0 output could you explain without guessing? How many at Stage 3?
2. How long did each stage take? (The whole sequence is typically under twenty minutes.)
3. Which single stage produced the largest improvement per minute spent?
4. Which function did you never edit but which became readable anyway, and why?

Then answer the security question the code actually poses:

5. `isAdmin` checks a magic value, a checksum, two flags and an expiry. **Is any of that a security
   control?** Write one paragraph. (Consider: where does `g_session` live, who can write to it, and
   what does the checksum protect against?)

---

## Hints

<details>
<summary>Hint — the field offsets do not line up</summary>

Remember alignment. An `unsigned long long` at offset `0x08` requires 8-byte alignment, which is why
`flags` (a 4-byte field at `0x04`) is followed by padding in some layouts and not others. If your
struct total is not exactly `0x60`, one of your sizes is wrong — the `calloc` size is the ground
truth.
</details>

<details>
<summary>Hint — Ctrl+L will not accept `Session *`</summary>

The struct must exist first, and it must be in a category Ghidra can see from this program. Create it
under the program's own category (the one named after your binary) rather than in a read-only archive.
</details>

<details>
<summary>Hint — Stage 2 still shows offsets</summary>

Setting the signature is not enough on its own if `JNIEnv` is not a known type — Ghidra will accept
`JNIEnv *` as a name but resolve it to nothing. Confirm `JNIEnv` appears in the Data Type Manager
after importing the archive. If it does not, the archive did not open; check the down-arrow menu
again.
</details>

<details>
<summary>Hint — how do I find the g_session global?</summary>

In the decompilation of `openSession`, the `calloc` result is eventually stored to something Ghidra
calls `DAT_...` or `PTR_...`. Double-click it to go to its address. It will be in `.bss` or `.data`.
</details>

---

## Success criteria

- [ ] Your notes file contains four complete, labelled versions of the same function.
- [ ] You answered the six Stage 0 questions twice — once from Stage 0 output, once from Stage 3 —
      and recorded the difference.
- [ ] You can state, in one sentence, what changed in the binary between stages. (Nothing.)
- [ ] Your `Session` struct has all seven fields at the right offsets and totals `0x60`.
- [ ] You retyped the global and observed `isAdmin` become readable without editing it.
- [ ] You created a `SessionFlags` enum and applied it.
- [ ] You recognised the FNV-1a constants and renamed the hash function.
- [ ] You answered the security question and can defend your answer.

---

## Going further

1. Repeat Stage 0 to Stage 2 on `describe`. Notice that `snprintf` with a format string gives you the
   field types for free — a reminder that leftover logging and formatting is a gift to the analyst.
2. Export your `Session` struct to a `.gdt` archive so you could apply it to a different build of the
   same library.
3. Rebuild the library **without** `--strip-all` and repeat Stage 0. How much of the work was the
   stripping responsible for?
4. Confirm the `Session` layout at runtime: hook `openSession` with Frida, read the returned pointer
   from the global, and `hexdump` `0x60` bytes. Compare against your struct field by field.

---

## Cleanup

Keep the project and the notes file. Both are reference material — the notes because you will want to
show someone the before/after, and the project because the `Session` struct is reusable.
