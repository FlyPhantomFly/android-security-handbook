# Lab 04 — CTF: The Padding Oracle

**Difficulty:** Advanced / CTF
**Time:** 3–5 hours
**Prerequisites:** [Lab 01](lab-01-break-the-vault.md), [Lab 02](lab-02-hook-everything.md),
[Chapter 34 §3.3.2–3.3.3](../README.md#333-the-padding-oracle-attack--explained-in-full),
Python 3, a device or emulator with `adb`

---

## The challenge

An app stores a sealed record. You have the ciphertext. You do **not** have the key, you cannot find
it in the APK, and it is not in the AndroidKeyStore either — the app fetches it from a server at first
launch and holds it only in memory.

The app also exposes a small service that will accept a ciphertext and tell you whether it decrypted.
It is careful: it never returns the plaintext, and it never returns the key.

**Recover the flag from the ciphertext, without the key.**

You are allowed roughly 2,048 oracle queries per 16-byte block. You will need about 128 per byte on
average. There is no brute force to be done and no cryptography to be broken — AES is untouched
throughout. What you are attacking is an **error message**.

---

## Rules

- No reading the key out of memory with Frida. That works, and it teaches you nothing about why this
  class of bug exists.
- No reading the flag off the screen or out of logcat.
- You must be able to state, in terms of the CBC decryption identity, why each oracle response tells
  you what it tells you.
- Your exploit must be your own code. You may check it against a reference afterwards.

---

## Why this matters

The padding oracle is the canonical demonstration that **a cipher can be perfectly implemented and the
system built from it can still be completely broken**. AES is not attacked. The key is not recovered.
Every primitive behaves exactly as specified. And the plaintext falls out anyway, because the system
told the attacker one bit — "was the padding well-formed?" — a few thousand times.

Once you have done this by hand, three things become permanent:

1. You will never again treat "it uses AES-256" as a statement about security.
2. You will start looking at **error handling** as an attack surface, in every protocol you touch.
3. You will understand, at a level no explanation conveys, why AEAD modes exist and why
   encrypt-then-MAC is not a stylistic preference.

> **🧠 Mental Model**
> An oracle is any mechanism that answers a question about a secret. It does not have to be a function
> that returns data. A different exception type is an oracle. A different HTTP status code is an
> oracle. A response that arrives 40 ms later is an oracle. **If the system's behaviour differs based
> on the value of a secret, the secret is leaking; the only question is how fast.**

---

## Building the challenge

Build it yourself. Implementing the vulnerability is half the education, and you need a target whose
plaintext you know so you can verify your exploit rather than guess at it.

### Part 1 — the vulnerable app

A minimal app with one deliberately careless decrypt path, reachable over a localhost socket. The
socket makes the oracle easy to drive from your host with `adb forward`; the same bug appears in the
wild behind an exported `Service`, a `ContentProvider`, a JavaScript bridge, or a network endpoint.

**`app/src/main/AndroidManifest.xml`** — needs INTERNET for the localhost listener:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.ctf.oracle">
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="PaddingOracle" android:allowBackup="false">
        <activity android:name=".OracleActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**`OracleActivity.java`**

```java
package com.ctf.oracle;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class OracleActivity extends Activity {

    private static final String TAG = "ORACLE";
    private static final int PORT = 9000;

    // In the real scenario this arrives from a server at first launch and is
    // never written to disk. For the lab we generate it once per process, which
    // gives the same property: you cannot find it statically, and you are not
    // allowed to read it out of memory.
    private static final byte[] KEY = new byte[16];
    private static final byte[] IV  = new byte[16];

    // The secret. Anything of a length that is not a multiple of 16 is better,
    // because it exercises the padding logic properly.
    private static final String FLAG =
            "CRYPTO{cbc_p4dding_0racle_l34ks_wh0le_pl41ntext}";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        setContentView(tv);

        new SecureRandom().nextBytes(KEY);
        new SecureRandom().nextBytes(IV);

        try {
            String sealed = Base64.encodeToString(encrypt(FLAG.getBytes("UTF-8")),
                                                  Base64.NO_WRAP);
            String ivB64 = Base64.encodeToString(IV, Base64.NO_WRAP);
            tv.setText("iv:  " + ivB64 + "\n\nct:  " + sealed);
            Log.i(TAG, "iv=" + ivB64);
            Log.i(TAG, "ct=" + sealed);
        } catch (Exception e) {
            Log.e(TAG, "seal failed", e);
        }

        new Thread(new Runnable() { @Override public void run() { serve(); } }).start();
    }

    static byte[] encrypt(byte[] plaintext) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV));
        return c.doFinal(plaintext);
    }

    /**
     * THE BUG.
     *
     * The method distinguishes a padding failure from every other failure, and
     * reports the difference to the caller. That is the entire vulnerability.
     * Note that it never returns plaintext and never returns the key — and it
     * does not need to.
     */
    static String decryptAndReport(byte[] iv, byte[] ciphertext) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"),
                   new IvParameterSpec(iv));
            byte[] plain = c.doFinal(ciphertext);

            // A second, application-level check. Realistic: apps almost always
            // validate something about the decrypted content.
            if (plain.length == 0 || plain[0] < 0x20) {
                return "ERR_CONTENT";          // decrypted, but content rejected
            }
            return "OK";
        } catch (BadPaddingException e) {
            return "ERR_PADDING";              // <-- the oracle
        } catch (Exception e) {
            return "ERR_OTHER";
        }
    }

    void serve() {
        try {
            ServerSocket ss = new ServerSocket(PORT, 8,
                    java.net.InetAddress.getByName("127.0.0.1"));
            Log.i(TAG, "listening on 127.0.0.1:" + PORT);
            while (true) {
                Socket s = ss.accept();
                try {
                    BufferedReader in = new BufferedReader(
                            new InputStreamReader(s.getInputStream()));
                    String line = in.readLine();          // "<ivB64> <ctB64>"
                    String reply = "ERR_INPUT";
                    if (line != null) {
                        String[] parts = line.trim().split("\\s+");
                        if (parts.length == 2) {
                            reply = decryptAndReport(Base64.decode(parts[0], Base64.DEFAULT),
                                                     Base64.decode(parts[1], Base64.DEFAULT));
                        }
                    }
                    OutputStream out = s.getOutputStream();
                    out.write((reply + "\n").getBytes("UTF-8"));
                    out.flush();
                } catch (Exception e) {
                    Log.e(TAG, "request failed", e);
                } finally {
                    try { s.close(); } catch (Exception ignored) {}
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "serve failed", e);
        }
    }
}
```

### Part 2 — install and expose the oracle

```bash
# host
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
adb shell am start -n com.ctf.oracle/.OracleActivity

# read the challenge material off the screen or out of logcat
adb logcat -d -s ORACLE

# bring the localhost listener to your machine
adb forward tcp:9000 tcp:9000
```

Confirm the oracle answers:

```bash
# host
printf '%s %s\n' "<ivB64>" "<ctB64>" | nc 127.0.0.1 9000
# -> OK
printf '%s %s\n' "<ivB64>" "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | nc 127.0.0.1 9000
# -> ERR_PADDING   (almost certainly)
```

> **⚠️ Warning**
> A localhost listener in an Android app is itself a finding, and a serious one — it is reachable by
> **any** app on the device with the INTERNET permission, with no permission check and no caller
> identity. That is the subject of [24-IPC](../../24-IPC/README.md) and its
> [localhost service lab](../../24-IPC/labs/lab-04-localhost-service.md). Here it is a convenience;
> in a real report it would be two findings, not one.

### Part 3 — variants worth building afterwards

Once the basic attack works, rebuild the target with each of these. Each teaches something the first
version does not.

**Variant A — no error message at all.** Delete the `ERR_PADDING` return; make every failure return
`ERR`. Now the only difference is **timing**, because the content check runs only when unpadding
succeeded. Measure it. This is why "we return a generic error" is not a fix.

**Variant B — an exported component instead of a socket.** Move `decryptAndReport` behind an exported
`BroadcastReceiver` that sets a result code, or a `ContentProvider` that returns a different cursor.
Drive it with `am broadcast` or `content query`. This is the realistic Android shape.

**Variant C — the fixed version.** Replace the whole scheme with AES-GCM
([`examples/02-correct-aes-gcm.java`](../examples/02-correct-aes-gcm.java)) and rerun your exploit.
It should fail at the first byte, and you should be able to say precisely why.

**Variant D — encrypt-then-MAC.** Keep CBC, add an HMAC-SHA256 over `iv ‖ ciphertext`, verified with
`MessageDigest.isEqual` **before** the cipher is touched. Rerun the exploit. Then move the MAC check to
*after* decryption and rerun again — the difference between those two orderings is the whole lesson of
[§3.8.2](../README.md#382-encrypt-then-mac-versus-mac-then-encrypt).

---

## Your first attempt (which will not work)

```bash
# host
jadx -d out challenge.apk
grep -rn "CRYPTO{" out/ || echo "flag not in the APK"
strings challenge.apk | grep -i crypto || echo "not in strings"
python3 ../scripts/detect-ecb.py out/sources/
```

**Q1.** The flag is a string constant in the source. Why can you not simply grep for it in the
installed app, and what would you have to do to make that approach work? (Consider what
[13-ART](../../13-ART/README.md) says about where installed bytecode lives.)

**Q2.** You find the key is never written to disk and never placed in the AndroidKeyStore. What are the
two ways you could get it anyway, and why does this lab forbid both?

---

## Investigation

Work these out before writing any exploit code.

### Characterise the oracle

```bash
# host
ORACLE() { printf '%s %s\n' "$1" "$2" | nc -q1 127.0.0.1 9000; }

ORACLE "$IV" "$CT"                                    # baseline
ORACLE "$IV" "$(echo -n 'A'|base64)"                  # too short
ORACLE "AAAAAAAAAAAAAAAAAAAAAAAAAAAA==" "$CT"         # wrong IV, right ciphertext
```

**Q3.** How many **distinct** responses can you produce? List them and state what each one tells you.

**Q4.** Send the original ciphertext with a **wrong IV**. What happens, and why is the answer
"only the first block is corrupted"? Write the CBC decryption identity and use it to explain.

**Q5.** Which response is the one you can build an attack from? Precisely what proposition does it
assert?

### Understand the identity you are exploiting

CBC decryption computes, for block *i*:

```
P_i = D_K(C_i) XOR C_{i-1}          with C_0 = IV
```

Write `I_i = D_K(C_i)` — the **intermediate value**.

**Q6.** `I_i` depends on which inputs, and crucially, on which inputs does it *not* depend? This one
fact is the entire attack; state it before continuing.

**Q7.** If you replace `C_{i-1}` with a value `C'` of your choosing and submit `C' ‖ C_i`, what does the
receiver compute? How much control do you have over that value?

**Q8.** You submit `C' ‖ C_i` and the oracle says the padding was valid. What is the most likely value
of the last plaintext byte, and what does that let you compute? Which *other* padding values could also
have produced a "valid" answer, and how would you rule them out?

### Estimate the cost

**Q9.** How many oracle queries, worst case and average, to recover one byte? One 16-byte block? The
whole 48-byte flag? At what query rate does the attack become impractical, and what would a defender
have to do to reach that rate?

---

## Writing the exploit

Write it yourself first. A reference implementation is in the solutions, but reading it before you
have struggled with the padding-collision case wastes the most instructive part of the lab.

Skeleton to work from:

```python
#!/usr/bin/env python3
# host — exploit.py
import base64, socket, sys

HOST, PORT = "127.0.0.1", 9000
BLOCK = 16

def oracle(iv: bytes, ct: bytes) -> bool:
    """Return True if the receiver reports that padding was VALID."""
    s = socket.create_connection((HOST, PORT), timeout=5)
    try:
        msg = base64.b64encode(iv) + b" " + base64.b64encode(ct) + b"\n"
        s.sendall(msg)
        reply = s.recv(64).decode().strip()
    finally:
        s.close()
    # ERR_PADDING  -> padding was malformed
    # anything else -> padding unpadded cleanly (content may still be rejected)
    return reply != "ERR_PADDING"

def recover_block(target: bytes, previous: bytes) -> bytes:
    """
    Recover P = D_K(target) XOR previous, one byte at a time from the right.
    You do not need the key and you never learn it.
    """
    raise NotImplementedError("this is your job")

if __name__ == "__main__":
    iv = base64.b64decode(sys.argv[1])
    ct = base64.b64decode(sys.argv[2])
    blocks = [iv] + [ct[i:i+BLOCK] for i in range(0, len(ct), BLOCK)]
    out = b""
    for i in range(1, len(blocks)):
        out += recover_block(blocks[i], blocks[i-1])
        print(f"[{i}/{len(blocks)-1}] {out!r}")
    print("\nFLAG:", out.decode(errors="replace"))
```

---

## Solutions

Do not read until you have made a genuine attempt at `recover_block`.

<details>
<summary>Solution A — the byte-at-a-time recovery</summary>

```python
def recover_block(target: bytes, previous: bytes) -> bytes:
    intermediate = bytearray(BLOCK)      # I = D_K(target). Unknown at the start.
    forged = bytearray(BLOCK)            # the block we control, in place of `previous`

    for pad in range(1, BLOCK + 1):
        idx = BLOCK - pad                # byte we are attacking, right to left

        # Force every already-known byte to equal the target padding value.
        for j in range(idx + 1, BLOCK):
            forged[j] = intermediate[j] ^ pad

        found = False
        for guess in range(256):
            forged[idx] = guess
            if not oracle(bytes(forged), bytes(forged) + target):
                continue

            # ---- the collision case, and why it must be handled ----
            # On the FIRST byte (pad == 1) a "valid" answer usually means the
            # final plaintext byte became 0x01. But it could instead have become
            # 0x02 while the byte before it happened to already be 0x02 — a valid
            # two-byte padding. Perturb the neighbouring byte: if the padding is
            # genuinely 0x01 the answer is unchanged, because that byte is not
            # part of the padding. If it flips to invalid, we hit a longer pad.
            if pad == 1 and idx > 0:
                saved = forged[idx - 1]
                forged[idx - 1] ^= 0xFF
                still_valid = oracle(bytes(forged), bytes(forged) + target)
                forged[idx - 1] = saved
                if not still_valid:
                    continue

            intermediate[idx] = guess ^ pad
            found = True
            break

        if not found:
            raise RuntimeError(f"no valid padding byte at index {idx}; "
                               f"oracle may be unreliable or rate-limited")

    # P = I XOR previous.  We never learned the key.
    return bytes(a ^ b for a, b in zip(intermediate, previous))
```

Note the oracle call passes `forged` as the IV *and* as the preceding block. That is deliberate: it
makes the two-block message `forged ‖ target` decrypt as a complete record whose final block is
`target`, which is exactly the configuration the padding check inspects. If your target's API takes the
IV separately, feed `forged` there and send only `target` as the ciphertext.

**Why it works, in one paragraph.** `I = D_K(target)` depends only on the key and on `target`. It does
not depend on the preceding block at all — the preceding block is XORed in *after* the block cipher
runs. So by substituting a block of our choosing we control the final plaintext by an arbitrary XOR
mask, without disturbing `I`. Driving the last plaintext byte to `0x01` makes the padding valid, and
the oracle tells us when we have. At that moment `I[15] = guess XOR 0x01`, and the real plaintext byte
is `I[15] XOR previous[15]`. Repeat with `0x02 0x02`, then `0x03 0x03 0x03`, and the whole block falls.

</details>

<details>
<summary>Solution B — the same attack against an exported component (Variant B)</summary>

Nothing about the cryptography changes; only the transport does.

```python
import subprocess, base64

def oracle(iv: bytes, ct: bytes) -> bool:
    out = subprocess.run(
        ["adb", "shell", "am", "broadcast",
         "-a", "com.ctf.oracle.DECRYPT",
         "-n", "com.ctf.oracle/.DecryptReceiver",
         "--es", "iv", base64.b64encode(iv).decode(),
         "--es", "ct", base64.b64encode(ct).decode()],
        capture_output=True, text=True)
    # setResultCode(1) for padding failure, 0 otherwise
    return "result=1" not in out.stdout
```

This is roughly a hundred times slower per query because of the `adb` round trip, so a full 48-byte
recovery moves from seconds to tens of minutes. Two lessons: batch your queries where the API allows
it, and note that **an attacker who is a malicious app on the same device does not pay this cost** —
they call the receiver directly through Binder at microsecond latency. Do not let your own tooling's
slowness mislead you about exploitability. See [24-IPC](../../24-IPC/README.md).

</details>

<details>
<summary>Solution C — the timing oracle (Variant A)</summary>

With all error messages made identical, the signal moves into the response time: when unpadding fails,
the application-level content check never runs.

```python
import time, statistics

def timed(iv, ct, n=15):
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        query(iv, ct)                      # ignore the response entirely
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)      # median, not mean: outliers are GC pauses
```

Take a baseline from a known-bad padding, and treat anything above the baseline plus a few median
absolute deviations as "padding valid". Practical notes that matter more than the code:

- Use the **median**, never the mean. A single GC pause or a JIT compilation event dwarfs the signal.
- Increase `n` until the two distributions separate. On a local socket the difference is often tens of
  microseconds; over `adb` it is invisible and you should give up on timing entirely.
- Warm the app up first, or the first hundred queries measure JIT compilation rather than your target.
- Pin the CPU governor if you can. Frequency scaling is the single largest source of noise.

The point of the variant: a generic error message is **not** a fix. It raises the number of queries and
the engineering effort, and it does not remove the oracle. The fix is to make the failure paths
computationally identical, which in practice means not having two failure paths — which means AEAD.

</details>

<details>
<summary>Solution D — why the exploit dies against Variants C and D</summary>

**Against AES-GCM (Variant C).** There is no padding, so there is nothing to be malformed. Every
modification you make to the ciphertext — including the very first guess — changes the GHASH
computation, so the authentication tag fails to verify and `doFinal` throws `AEADBadTagException`. The
oracle now returns exactly one answer for every one of your 256 guesses, so it conveys zero bits. More
fundamentally: the tag is checked **before** any plaintext is produced, so there is no intermediate
state whose validity could differ.

**Against encrypt-then-MAC (Variant D, correct ordering).** The HMAC over `iv ‖ ciphertext` fails for
every forged block, and because the MAC is verified before the cipher is invoked at all, the padding
logic never executes. The oracle answers "MAC failed" 256 times out of 256.

**Against MAC-then-encrypt (Variant D, wrong ordering).** The attack works again. The receiver must
decrypt in order to reach the MAC, so it must unpad first, so the padding check runs on
attacker-controlled data — and any distinguishable outcome from that check is the oracle, whatever
happens afterwards. This is precisely the ordering that produced Lucky 13 in TLS, and it is why the
ordering is not a matter of taste.

</details>

---

## Debrief questions

Answer these in writing. They are the actual point of the lab.

1. State the CBC decryption identity, and use it to explain in three sentences why controlling the
   preceding block gives you arbitrary control over the plaintext without knowing the key.
2. Explain the padding-collision case (`pad == 1`). What goes wrong if you skip the neighbour-flip
   check, how often does it happen, and how would you notice?
3. You recovered the plaintext without recovering the key. What does that tell you about the phrase
   "the data is protected by AES-256" as a security claim?
4. Rank these four mitigations by effectiveness and say what each actually costs: (a) a generic error
   message, (b) rate limiting the decrypt endpoint, (c) encrypt-then-MAC, (d) AES-GCM.
5. You find this bug in a client's app, but the decrypt path is behind an exported component that
   requires a signature-level permission. What is your severity, and what would change it?
6. Name three places in an Android app, other than a CBC padding check, where a decryption oracle
   commonly appears. For each, say what the distinguishable outcome is.
7. The `ERR_CONTENT` branch in the target is realistic — apps do validate decrypted content. Explain
   how that second check *helps* the attacker in the timing variant, and what a developer should do
   about it.
8. You are reviewing an app that uses `AES/CBC/PKCS5Padding` with a properly random per-record IV and
   an HMAC verified after decryption. Is it vulnerable? Argue precisely.

---

## Success criteria

- [ ] You built the target yourself and confirmed the oracle responds differently to the two cases
- [ ] You characterised every distinct oracle response before writing any exploit code
- [ ] You wrote `recover_block` yourself
- [ ] You handled the `pad == 1` padding-collision case, and can explain why it exists
- [ ] You recovered the complete flag
- [ ] You can state the query cost per byte, per block and for the whole message
- [ ] You rebuilt the target as Variant A and demonstrated a **timing** oracle with a generic error
- [ ] You rebuilt it as Variant C (GCM) and can explain precisely why your exploit fails at byte one
- [ ] You rebuilt it as Variant D both ways and can explain why the MAC ordering decides the outcome
- [ ] You answered all eight debrief questions in writing
- [ ] You can explain the whole attack to a developer in under five minutes, without a whiteboard

---

## Note for instructors

The pedagogical goal is **not** the flag. It is the moment when a participant realises they are
recovering plaintext while every cryptographic primitive in the system is behaving exactly as
specified. Until that lands, "use AEAD" is advice; afterwards it is obvious.

If running this as a group session:

- Hand out the socket variant first. The `adb`-driven variant is more realistic but the latency makes
  the feedback loop too slow for a first attempt, and people give up during debugging.
- Expect most participants to get the last byte of the last block and then stall. The two stalling
  points are the padding collision and forgetting that the *known* bytes must be re-forged to the new
  padding value on every round. Let them stall for a while — the second one in particular is where the
  identity becomes real rather than memorised.
- Ask anyone who finishes early to build Variant A and measure the timing signal. It converts "generic
  errors are a mitigation" from a plausible belief into a measured falsehood, and that conversion is
  worth more than the original exercise.
- Close by having someone run the exploit against Variant C while the room watches it fail. Ending on
  the fix, demonstrated, is what makes the lesson defensive rather than merely clever.
