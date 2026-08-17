# Lab 04 — Reading code you did not write

**Difficulty:** The important one.
**Time:** 90 minutes for the timed run, plus 1–2 hours of debrief.
**Prerequisites:** Labs [01](lab-01-first-program-all-the-way-down.md),
[02](lab-02-hashmap-and-dex-strings.md), [03](lab-03-debugging-challenge.md);
[Chapter 03 §8.1](../README.md#81-the-single-most-important-pentester-skill-reading-code-you-did-not-write)

---

## Why this lab is the one that matters

Every engagement you will ever run starts in exactly one situation: **a pile of code nobody wrote for
you, and a question.** No documentation, no author to ask, no tests that explain intent, and a clock.

Labs 01 to 03 taught you what code *is*. This one teaches you what to *do* when you are handed some.
It is the single most transferable skill in this repository, and it is the one that separates people
who make progress on an unfamiliar target from people who open thirty tabs and produce nothing.

> **🧠 Mental Model — you are building a map, not reading a book.** A book is read once, forwards,
> and its value is the experience of reading it. A map is built incrementally, from landmarks
> outwards, and its value is that you can *return* to it. Every note you take and every symbol you
> rename is a landmark. Four hours of linear reading produces exhaustion; forty minutes of mapping
> produces an answer and an artefact that makes tomorrow faster.

---

## The challenge

You are given an unfamiliar codebase and **five specific questions**. You have ninety minutes.

You will not read most of the code. That is correct, and learning to be comfortable with it is half
the lab.

### Getting a codebase

Use whichever is available to you, in this order of preference.

**Option A — a real Android app you have never seen.** Best, because it is the real thing.

```bash
# host
adb shell pm list packages -3
adb shell pm path com.some.app
adb pull /data/app/~~xxx/com.some.app-yyy/base.apk ./target.apk
jadx -d out/ target.apk
apktool d target.apk -o work/
```

**Option B — an open-source Android app you have not read.** Pick something from
[F-Droid](https://f-droid.org/) with 200–2 000 files. Do **not** read the README, the wiki, or the
architecture docs until the ninety minutes are over. That prohibition is the lab.

**Option C — a small server codebase.** Any language. The methodology is language-independent, which
is itself worth proving to yourself.

**Option D — swap with a partner.** Each of you picks a codebase for the other and writes five
questions. This is the best version if you have someone to do it with, because the questions are
adversarial rather than self-selected.

### The five questions

If you are working alone, use these. They are deliberately generic so they apply to almost any
codebase, and deliberately *specific* in shape — each one names a single thing and asks for concrete
facts about it.

1. **What are all the ways execution can enter this application from outside?** List every one, with
   file and line.
2. **Where does it store persistent data, and what exactly is in there?** Name every store and every
   field.
3. **Pick the most sensitive value it handles** (a token, a key, a password, a session identifier).
   Where is it created, stored, read, and destroyed? Fill all four rows.
4. **Does it use cryptography, and if so, is any of it hand-rolled?** Name every algorithm, mode and
   key source.
5. **What is the single riskiest line of code in this repository, and why?** One line. Defend it.

Write them down before you start. **Do not add more questions mid-run** — scope creep is the failure
mode this lab exists to train out of you.

---

## The method

Five moves, in order. Time-box each. The times are guidelines and the *order* is not negotiable.

### Move 1 — Find the entry points (15 minutes)

Code is only interesting if something can reach it. Start where the outside world touches the app.

```bash
# host — Android
grep -n 'exported="true"' work/AndroidManifest.xml
grep -n '<activity\|<service\|<receiver\|<provider' work/AndroidManifest.xml
grep -n 'android:scheme\|<data ' work/AndroidManifest.xml
grep -rn 'Java_.*_.*(' out/sources/ 2>/dev/null | head        # JNI entry points
```

```bash
# host — any codebase
grep -rn 'def main\|int main\|fun main\|public static void main' .
grep -rn '@app.route\|@GetMapping\|@PostMapping\|router\.\(get\|post\)' .
grep -rn 'onReceive\|onStartCommand\|onCreate\|onHandleIntent' .
```

**Record:** a list. Nothing else yet. Resist the urge to open any of them.

**Checkpoint Q1.** How many entry points are there? Which one would you attack first, and why?

### Move 2 — Find the data (15 minutes)

The question is nearly always about a piece of data, and data has a small number of homes.

```bash
# host
grep -rn 'getSharedPreferences\|EncryptedSharedPreferences\|openFileOutput' out/sources/ \
  | grep -v -E '/(androidx|kotlin|kotlinx|okhttp3|okio|retrofit2|com/google|com/squareup)/'
grep -rn 'SQLiteDatabase\|Room\|@Entity\|CREATE TABLE' out/sources/
grep -rn 'Cipher\.getInstance\|KeyGenerator\|SecretKeySpec\|MessageDigest' out/sources/
grep -rn 'OkHttpClient\|Retrofit\|HttpURLConnection\|https://' out/sources/ | head -30
```

**Record:** every store, every base URL, every crypto call site. Three lists.

**Checkpoint Q2.** How many distinct persistent stores? How many network endpoints?

### Move 3 — Follow the state (30 minutes — the bulk of the time)

Pick the value from question 3 and fill in four rows. This is where findings come from.

| Event | Location (file:line) | Notes |
|---|---|---|
| Created | | Where does the value come from? |
| Stored | | Which store, which key, encrypted? |
| Read | | Every reader |
| Destroyed | | **An empty row here is usually the finding** |

Work **outwards from the store**, not inwards from the entry point. Find where it is written, then
find every caller of that write, then find every reader. Your IDE's or JADX's "find usages" is the
right tool; grepping for the field name is the fallback.

**Checkpoint Q3.** Is any row empty? Which one? Write the candidate finding as a single sentence.

### Move 4 — Ignore the noise, deliberately (5 minutes)

You should already be doing this. Make it explicit, once, so it becomes a habit.

```bash
# host — reduce the codebase to the part that is actually the app
grep -rln 'class ' out/sources/ \
  | grep -v -E '/(androidx|kotlin|kotlinx|okhttp3|okio|retrofit2|com/google|com/squareup|io/reactivex)/' \
  | grep -v -E '(R\$|BuildConfig|Databinding|_Impl|\$\$Lambda)' \
  > app_owned.txt
wc -l app_owned.txt
```

**Checkpoint Q4.** How many classes did you start with? How many remain? What is the ratio?

**Never skip**, regardless: anything named `*Security*`, `*Crypto*`, `*Auth*`, `*Token*`, `*Key*`,
`*Session*`; anything with `native` methods; anything parsing bytes; custom `TrustManager` or
`HostnameVerifier`; `WebView` configuration; reflection; anything calling `Runtime.exec`,
`DexClassLoader` or `System.load`.

### Move 5 — Name what you learn (continuous, plus 10 minutes at the end)

Your understanding must live outside your head, because you will lose it overnight. Keep this file
open from minute one and write to it continuously.

```markdown
## Entry points
- com.target.app.ui.DeepLinkActivity — exported, handles target://open?url=
- com.target.app.sync.SyncService — exported, no permission
- Java_com_target_app_crypto_Native_decrypt — in libtarget.so

## Data
- SharedPreferences "app_prefs": auth_token, refresh_token, device_id, pin_hash
- SQLite "app.db": users(id, email, token_blob), events
- API base: https://api.target.example/v3/

## State: auth_token
- created  : LoginActivity.onLoginSuccess -> TokenStore.save()
- stored   : SharedPreferences, plaintext (!!)   -> FINDING candidate
- read     : ApiClient.buildAuthHeader, SyncService.onHandleWork
- destroyed: never — logout clears only the in-memory field  -> FINDING candidate

## Questions / open threads
- What does Native.decrypt do with the key? Hook it.
- Is DeepLinkActivity's url parameter passed to a WebView? Follow it.
```

**And rename as you go.** JADX and Ghidra both persist renames in a project file.
`FUN_00012a40` becomes `parse_record_array`; `a.a.a.b` becomes `TokenStore`. This is not cosmetic:
each rename permanently reduces the cost of every later read, and the renames compound. After an hour
the code reads like code.

---

## The timed run

Set a timer for **90 minutes**. Answer the five questions. Stop when the timer stops, finished or
not.

```
00:00 – 00:15   Move 1 — entry points
00:15 – 00:30   Move 2 — the data
00:30 – 01:00   Move 3 — follow the state
01:00 – 01:05   Move 4 — prune
01:05 – 01:15   Move 5 — consolidate notes, finish renames
01:15 – 01:30   Write the five answers
```

Do not exceed the time. Running over is the same failure as not starting: the point is to learn what
ninety minutes buys, so that you can budget the next engagement honestly.

---

## Verify your answers dynamically

A reading is a hypothesis. Confirm at least three of your five answers by observation — this is the
step that turns "I think" into "I proved", and it is the difference between a report that survives
review and one that does not.

```bash
# host — is that method actually reached?
frida -U -f com.target.app -l - <<'EOF'
Java.perform(function () {
  var K = Java.use("com.target.app.data.TokenStore");
  K.save.implementation = function (t) {
    console.log("[+] TokenStore.save reached with " + t);
    return this.save(t);
  };
});
EOF
```

```bash
# adb shell as root — is the store really plaintext?
grep -r 'token' /data/data/com.target.app/shared_prefs/
ls -la /data/data/com.target.app/databases/
```

```bash
# host — does logout actually destroy it?
adb shell "su -c 'cat /data/data/com.target.app/shared_prefs/app_prefs.xml'" > /tmp/before.xml
# ... log out in the UI ...
adb shell "su -c 'cat /data/data/com.target.app/shared_prefs/app_prefs.xml'" > /tmp/after.xml
diff /tmp/before.xml /tmp/after.xml
```

**Q5.** Did any dynamic result **contradict** your reading? Those are the most valuable moments in
the lab — write down what you assumed and why the assumption was wrong.

---

## Failure modes — check yourself against these

Be honest. Most people hit at least three on their first run.

| Failure | Symptom | What to do instead |
|---|---|---|
| Reading linearly | 45 minutes in, still in utility classes | Start from entry points and sinks |
| Chasing every call | Twenty tabs, no conclusions | Time-box each thread; write the question down and move on |
| Refusing to skip | You read `okhttp3` source | App-owned packages only, first pass |
| Writing nothing down | Rediscovering the same fact twice | Keep the notes file open the whole time |
| Trusting decompiler output literally | "This code makes no sense" | Check the Smali or the raw bytes |
| Believing names | `SecureRandomUtil` wraps `java.util.Random` | Read the body of anything whose name makes a claim |
| Stopping at the first finding | One easy finding, five missed | Finish the map, then rank |
| Adding questions mid-run | 90 minutes gone, nothing answered | Write the new question in "open threads" and carry on |
| Not renaming | Still reading `a.b.c` at minute 80 | Rename the moment you understand something |

---

## Success criteria

- [ ] All five questions answered, with **file and line** for every claim
- [ ] A notes file exists with all four sections filled in
- [ ] At least fifteen symbols renamed in your tool
- [ ] The state table for question 3 has all four rows attempted, and any empty row is called out
- [ ] At least three answers verified dynamically, not just by reading
- [ ] You finished within ninety minutes, or you recorded honestly where the time went
- [ ] You can name which of the failure modes above you hit
- [ ] You can state what you deliberately did **not** read, and why that was the right call

---

## Debrief

1. What fraction of the codebase did you read? Estimate it. Was it more or less than you expected?
2. Which of the five moves produced the most information per minute? Which produced the least?
3. Where did you lose the most time? What would you time-box differently next run?
4. Name one thing you believed after reading that turned out to be false when you observed it. What
   led you to believe it?
5. You found (or did not find) a finding. Would you have found it faster with a different first move?
6. Someone hands you the same codebase tomorrow with a *different* question. How much of today's work
   is reusable? What does that tell you about the value of the notes file?
7. Explain to a developer, in three sentences, how you understood their code in ninety minutes
   without asking them anything.
8. If you had ninety more minutes, name the three specific things you would do — not "read more".

---

## Run it again

This lab is worth repeating four or five times on different codebases, and it improves fast.

| Run | Change |
|---|---|
| 2 | A different language — Go, Rust, or a React Native bundle. Prove the method is language-independent |
| 3 | An obfuscated APK. Notice which anchors survive and how much slower renaming makes you |
| 4 | 45 minutes instead of 90. Discover which moves you can compress and which you cannot |
| 5 | A partner writes the questions. Discover how much of your speed came from choosing your own |

Track your time-to-first-finding across runs. It should fall sharply between run 1 and run 3, and
then plateau — that plateau is your actual current skill, and it is what you should budget with.

---

## Note for instructors

The pedagogical goal is **not** the findings. It is the experience of being handed something
overwhelming and discovering that a method makes it tractable.

Run it as a group with everyone on the same codebase and the same five questions, then compare
answers. The variance between participants will be enormous — and the participants who did best will
almost always be the ones who wrote things down and renamed symbols, not the ones who read fastest.
Make that comparison explicit; it is the lesson.

Do not release the codebase's documentation until the debrief. Participants will ask for it, and the
asking is the moment to point out that on a real engagement there is nobody to ask.
