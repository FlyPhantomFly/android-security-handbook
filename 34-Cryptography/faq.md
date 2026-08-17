# 34 — Cryptography · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. I keep hearing "encoding, hashing, encryption". What is the actual difference?**

Three different jobs that produce similarly scrambled-looking output, which is why they get confused.

| | Reversible? | Needs a key? | What it is for |
|---|---|---|---|
| **Encoding** (Base64, hex, URL) | Yes, by anyone | No | Transport compatibility |
| **Hashing** (SHA-256) | No | No | Fingerprinting, integrity |
| **Encryption** (AES) | Yes, with the key | Yes | Confidentiality |

Base64 provides no security whatsoever. It exists so that arbitrary bytes can travel through channels
that only accept text. If you see a "protected" field that Base64-decodes to readable text, the data is
stored in cleartext and the finding writes itself.

---

**2. Everyone says "never roll your own crypto". Does that mean I should not implement AES?**

It means something more specific and more useful than the slogan. Nobody expects you to implement AES;
that is not the mistake people actually make.

The real content of the rule is: **do not design a scheme**. Do not invent a way to combine encryption
with integrity. Do not invent a key derivation. Do not invent a nonce management approach. Do not
invent a padding scheme. Those are the decisions that break real systems, and they are the decisions
developers make casually because they do not look like cryptography — they look like ordinary
engineering.

Use `AES/GCM/NoPadding` with a provider-generated nonce, or use Tink. Both of those are decisions
someone else has already made correctly.

---

**3. Why is `Cipher.getInstance("AES")` a security bug? It looks fine.**

Because the JCA permits a one-token transformation string and fills in provider defaults for the parts
you left out. The default mode for a block cipher is **ECB**, and the default padding is PKCS5. So
`"AES"` silently means `"AES/ECB/PKCS5Padding"`.

The developer did not choose ECB. They chose nothing, and the API chose for them. This is the single
most common cryptographic defect in Android applications, and it is one grep away:

```bash
# host
grep -rEn 'getInstance\("(AES|DES|DESede|Blowfish)"\)' sources/
```

Always write all three tokens.

---

**4. Why exactly is ECB bad? The data still comes out encrypted.**

Two concrete attacks, not one aesthetic objection.

**Pattern leakage.** ECB encrypts each 16-byte block independently with no chaining, so identical
plaintext blocks always produce identical ciphertext blocks. Any structure in the plaintext at 16-byte
granularity survives into the ciphertext. The classic demonstration is the ECB-encrypted image of a
penguin, where you can still see the penguin.

**Block splicing.** With no chaining and no integrity, ciphertext blocks can be cut and pasted between
records and the result still decrypts. If a record is laid out as `userid | balance | flags`, an
attacker can splice their own `userid` block onto someone else's data. That turns a confidentiality
problem into an authorisation bypass, which is usually the more serious finding.

And it is provable from the data alone: split a stored ciphertext into 16-byte blocks and look for
repeats. See `scripts/detect-ecb.py`.

---

**5. If the IV is not secret, why does it matter what it is?**

The IV's job is not secrecy. It is **uniqueness**, and for CBC also **unpredictability**.

With a fixed IV, CBC becomes deterministic: the same plaintext under the same key always produces the
same ciphertext. That gives an attacker two things. They can tell which records contain the same value
without decrypting anything. And where the plaintext space is small — a PIN, a boolean, an enumerated
status — they can encrypt every candidate themselves and match, recovering the plaintext with no
cryptanalysis at all.

For CBC there is a further requirement: the IV must be *unpredictable*, not merely unique. An attacker
who can predict the next IV and influence the plaintext can mount a chosen-plaintext attack (this is
what BEAST did to TLS 1.0).

Store the IV with the ciphertext. It is not a secret and it never was.

---

**6. What is the difference between an IV, a nonce and a salt? They all look like random bytes.**

They are all public random-ish values stored alongside the data, which is exactly why people conflate
them. The differences are in the requirement each one carries.

| | IV | Nonce | Salt |
|---|---|---|---|
| Secret? | No | No | No |
| Must be unique | per message | **per key, forever** | per record |
| Must be unpredictable | **yes** (CBC) | no | no |
| Typical size | 16 bytes | 12 bytes | 16 bytes |
| Cost of reuse | determinism, dictionary attack | **total break** | precomputation applies |

The row that matters is the last one. Reusing an IV in CBC is bad. Reusing a nonce in GCM is
catastrophic, and the two are not comparable in severity.

---

**7. Why is GCM nonce reuse "catastrophic" rather than just "bad"?**

Two separate consequences, and the second is the one people miss.

GCM is CTR mode underneath: it generates a keystream from the nonce and XORs it with the plaintext. Two
messages under the same (key, nonce) share a keystream, so `C1 XOR C2 = P1 XOR P2`. The keystream
cancels and the XOR of the two plaintexts is recoverable by anyone. If any part of either plaintext is
guessable — a JSON prefix, a field name, an HTTP header — the corresponding part of the other falls out
immediately.

That is the confidentiality half. The authenticity half is worse. GCM's authentication tag is a
polynomial evaluated over GF(2^128) whose only secret is the subkey `H = E_K(0^128)`. Two ciphertexts
under the same nonce give an attacker equations in `H`, and `H` becomes solvable. Once they have `H`
they can forge a **valid authentication tag for any message they like** under that key, permanently.

So it is not a weakening. It is a complete break of both properties GCM was chosen to provide. This is
the "forbidden attack" (Joux).

---

**8. How do I avoid nonce reuse, then?**

Do not generate the nonce. On encryption, call `init(ENCRYPT_MODE, key)` with **no** parameter spec and
let the provider generate it, then read it back with `cipher.getIV()` and store it with the ciphertext.

```java
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, key);        // provider generates a fresh 12-byte nonce
byte[] iv = c.getIV();
byte[] ct = c.doFinal(plaintext);
// store iv ‖ ct
```

A nonce you generate is a nonce you can accidentally reuse — after a restore from backup, after a
counter resets on reinstall, or because a test fixture hardcoded one and reached production. If you use
an AndroidKeyStore key with `setRandomizedEncryptionRequired(true)`, the keystore will *refuse* a
caller-supplied IV, which makes the bug unrepresentable rather than merely unlikely.

---

**9. Is MD5 always a finding?**

No, and reporting it as one when it is not is a fast way to have the rest of your report discounted.

MD5 is collision-broken: an attacker can construct two different inputs with the same digest. That is
fatal when the digest is used for **integrity, signatures, certificates, password hashing or key
derivation**, because the whole security argument rests on distinct inputs producing distinct outputs.

It is not a problem when MD5 is used as a **cache key, an ETag, a de-duplication hash or a bucket
selector**, because there the only requirement is that different inputs usually differ, and an attacker
gains nothing by producing a collision.

Follow the digest to its consumer before deciding. The same applies to SHA-1, with the additional note
that HMAC-SHA1 is not broken by the collision — collisions do not affect HMAC's security argument —
even though bare SHA-1 is.

---

**10. Why can I not just hash the password and use that as the key?**

Because a hash is designed to be *fast* and a password KDF is designed to be *slow*, and that
difference is the entire defence.

A hash gives you no salt, so identical passwords produce identical keys on every device and
precomputed tables apply. It gives you no work factor, so an attacker with a GPU tests billions of
candidates per second. A human-chosen password has perhaps 20 to 40 bits of entropy drawn from a
distribution an attacker can enumerate in likelihood order, so a fast function hands them the key.

Use `PBKDF2WithHmacSHA256` with a 16-byte random salt and at least 600,000 iterations, or Argon2id. And
store the parameters in the record — see question 12.

---

**11. PBKDF2, bcrypt, scrypt, Argon2 — which one, and why are there four?**

They are four generations of the same idea, each adding a resource the attacker cannot cheaply
multiply.

| | Adds | Weakness |
|---|---|---|
| **PBKDF2** (2000) | Iteration count (CPU time) | Needs almost no memory, so GPUs and ASICs parallelise it massively |
| **bcrypt** (1999) | Iteration count + a small fixed memory footprint | 4 KiB is small enough for modern GPUs; 72-byte password limit |
| **scrypt** (2009) | Tunable memory cost | Parameter interactions are easy to get wrong |
| **Argon2id** (2015) | Memory, time and parallelism, tuned independently | Needs a dependency; memory cost is a real constraint on mobile |

Use **Argon2id** if you can add a dependency. Use **PBKDF2-HMAC-SHA256** if you cannot, because it is in
the platform from API 26. Do not use bcrypt on Android; it has no platform support and no advantage
over the other two here.

---

**12. Why should the iteration count be stored in the record rather than being a constant?**

Two reasons, one operational and one security.

Operationally: if the count is a constant in the code and you raise it — which you should, every few
years, as hardware improves — every existing record becomes undecryptable, because they were derived
with the old count. Storing it lets old records keep working while new records use the new value.

Security: because you stored it, an attacker who can modify the record can edit it *downwards* to
1,000 and hand it back to you, making their own brute force cheap. So the stored parameters must be
**authenticated**. Pass the header containing version, iteration count and salt as associated data to
the AEAD. Then editing it makes decryption fail. See `examples/03-pbkdf2-and-argon2.kt`.

---

**13. What is HKDF, and why is it not a password KDF?**

HKDF (RFC 5869) turns **one high-entropy secret** into **several independent keys**. Its input is
already unguessable — an ECDH shared secret, a random key, a token from a server — so there is no
guessing attack to slow down, and it is deliberately fast.

It has two phases. *Extract* concentrates whatever entropy the input has into a uniformly random
pseudorandom key, which matters because things like a raw ECDH shared secret are unguessable but not
uniform. *Expand* produces as many independent bytes as you ask for, keyed by a context label called
`info` — derive with `info="enc"` and `info="mac"` and the two outputs are cryptographically
independent.

Getting it backwards produces two different findings. HKDF over a password is a real weakness: no work
factor, so offline guessing proceeds unimpeded. PBKDF2 over an ECDH shared secret is not insecure at
all, just 600,000 times slower than necessary — report it as Informational and say why.

---

**14. The app uses `SecureRandom.getInstance("SHA1PRNG")` and `setSeed()`. What is wrong with that?**

Two things, and the second one is why teams usually discover it.

It is not a key derivation function. Seeding a PRNG with a secret and reading bytes out gives you no
salt and no work factor, so the input is brute-forceable exactly as in question 10.

And from Android 7 (API 24), `SecureRandom.setSeed()` **supplements** the internal seed rather than
replacing it. Code written this way produces a different key on a newer device than on an older one, so
every record encrypted before an OS upgrade becomes undecryptable. Apps normally meet this bug as a
data-loss incident rather than as a security review finding.

---

**15. My Frida hook on `Cipher.doFinal` installs cleanly but never fires. Why?**

In order of likelihood:

1. **The method was inlined** by the optimizing compiler, so there is no call site to intercept. Fix:
   ```bash
   # host
   adb shell cmd package compile -m verify -f com.example.target
   adb shell am force-stop com.example.target
   ```
   See [13-ART](../13-ART/README.md).
2. **You attached instead of spawning.** A great deal of crypto happens in `Application.onCreate`,
   before you arrive. Use `-f`, not `-n`.
3. **You hooked one overload.** `Cipher.init` has several signatures and `doFinal` has several more.
   Iterate `.overloads`.
4. **Wrong ClassLoader.** If the class came from a dynamically loaded DEX, `Java.use` will not find it
   in the default loader. Enumerate loaders.
5. **The app does not use the JCA.** Flutter and several commercial SDKs call BoringSSL directly. Hook
   `libcrypto.so`.

---

**16. `key.getEncoded()` returns `null`. Is the hook broken?**

No — that null is the most informative single value in the output. It means the key material is not in
the app's address space at all. The `SecretKey` object is a handle to a key held by the keystore
daemon, whose plaintext exists only inside the TEE or a StrongBox secure element. When the app calls
`doFinal`, it is not computing AES in-process; it is sending the data over Binder to `keystore2`, which
asks KeyMint in the secure world to do the work.

Stop trying to extract the key; you cannot, and that is the design working. Change the question to *how
the app uses it*:

- Is the key bound to user authentication? Read `KeyInfo.isUserAuthenticationRequired()`.
- Can you invoke the app's own decrypt path yourself, with `Java.choose` to find a live instance?
- Is there a plaintext copy of the data elsewhere?

---

**17. If a rooted attacker can always make the app decrypt its own data, what is the point of the KeyStore?**

The point is the difference between an **oracle** and an **exfiltration**.

With a software key, an attacker who gets code execution once reads the bytes, takes them away, and
decrypts everything the app ever produced — offline, forever, on any machine, including data captured
from other devices if the key is shared.

With a keystore key they can only ask the keystore to operate, on that device, for as long as they have
access. Nothing is portable, nothing is replayable offline, and with `setUserAuthenticationRequired`
they additionally need the user to have unlocked recently.

So in a report, "the app can be made to decrypt its own data under Frida" is true of every correct
design and is not a finding about the cryptography. What *is* a finding is whether the app makes that
easy: no authentication binding, a decrypt-everything method reachable from an exported component, no
instrumentation detection at all.

---

**18. Is it a finding that an app has a hardcoded key if that key only encrypts a preference cache?**

It depends, and this is exactly the question that separates a useful report from a noisy one. Work the
three questions from §5.1:

1. **What is protected, and does it matter?** UI preferences: no. Session tokens: yes.
2. **Who is the attacker, and can they reach it?** A hardcoded key is in every installation, so anyone
   who downloads the APK has it. That is a *global* compromise, not a per-device one — which is why
   this finding is usually more severe than people expect.
3. **What does exploitation actually produce?** Decrypt something and show it. "The key is hardcoded"
   is an observation; "here is the session-token database" is a finding.

A hardcoded key protecting a preference cache is genuinely Low or Informational — but say *why*,
because it demonstrates you did the analysis rather than skipped it. Reporting it as Critical costs you
credibility on the findings that actually are.

---

**19. The app XORs its strings with a constant. Is that a crypto finding?**

Usually not. Ask what claim is being made.

If it is **string obfuscation inside a packer or an anti-analysis layer**, it is context, not a
vulnerability — obfuscation is not supposed to be cryptography and reporting it as broken encryption
misunderstands its purpose. Note it, describe it, move on. See
[40-Obfuscation](../40-Obfuscation/README.md).

If the app **tells the user their data is encrypted** and this is the mechanism, it is a finding, and a
serious one, because there is no security property here at all. A repeating-key XOR is a Vigenère
cipher, breakable by frequency analysis with no knowledge of the key; and where any plaintext is known,
the key falls out by XORing the known plaintext against the ciphertext.

---

**20. How do I tell whether a stored blob is encrypted, compressed, or just binary?**

Measure the entropy, then look at the structure.

```bash
# host
python3 scripts/detect-ecb.py --entropy ./data/data/com.example.target
```

| Entropy (bits/byte) | Usually |
|---|---|
| > 7.5 | Ciphertext, or compressed data (they are indistinguishable by entropy alone) |
| 4 – 6 | Structured binary: SQLite, protobuf, a serialised object |
| < 4 with high printable ratio | Text |

To separate ciphertext from compressed data, check magic bytes (`PK\x03\x04`, `\x1f\x8b`) and look at
lengths: a multiple of 16 suggests a block mode with padding, and `12 + n + 16` suggests
`nonce ‖ ciphertext ‖ GCM tag`, which is a good sign.

---

**21. Is `Arrays.equals` on a MAC really a vulnerability, or is that theoretical?**

Mostly theoretical *on-device*, and you should say so.

The mechanism is real: `Arrays.equals` returns at the first differing byte, so the time it takes leaks
how many leading bytes the attacker got right, reducing forgery from 2^128 to 256 attempts per byte.

The exploitability on an Android device is usually poor, because scheduler noise, GC pauses and JIT
state dwarf a difference of a few nanoseconds. So report it as Low, explain the mechanism, and note
that it becomes serious if the same code runs server-side or is reachable over a channel the attacker
can time precisely.

The fix is free — `MessageDigest.isEqual` is constant-time — so there is no reason not to fix it.
Honest severity plus a free fix is an easy sell.

---

**22. What should I actually recommend when I write the remediation section?**

In descending order of preference:

1. **Tink** with `AndroidKeysetManager` and a master key URI. It makes ECB, nonce reuse and missing
   integrity structurally impossible.
2. **AES-GCM with an AndroidKeyStore key**, `setRandomizedEncryptionRequired(true)`, and the nonce read
   back from `getIV()`.
3. **AES-GCM with a KDF-derived key**, if the data must be recoverable from a password on another
   device.

Write it as code, not as advice. "Use the KeyStore" is a sentence a developer cannot act on;
`examples/04-keystore-backed-vault.kt` is.

---

**23. The app uses Tink. Is there anything left to look for?**

Yes, four things, in this order.

1. **No `withMasterKeyUri()`.** Without it the keyset is stored in **cleartext** SharedPreferences.
   Pull the file and read the base64 — you have the raw key. This is F-01 wearing a library, and it is
   the most common real Tink finding.
2. **Empty or weak associated data.** `aead.encrypt(pt, ByteArray(0))` compiles and runs. Encryption
   alone does not stop an attacker moving a valid ciphertext from one row or user to another, since the
   key is the same for both.
3. **`CleartextKeysetHandle`** anywhere in production code — someone exported the keyset.
4. **Hand-rolled crypto elsewhere in the same app.** Tink in one feature and
   `Cipher.getInstance("AES")` in another is extremely common. Run the full sweep regardless.

Do not report "the app uses a third-party crypto library" as a finding. Tink is the recommendation.

---

**24. I found what looks like a 32-byte key in the app's data directory. How do I confirm it?**

Try it. That is the whole method, and it is more convincing than any amount of inference.

Take an adjacent ciphertext, try the candidate as an AES key in ECB, then CBC with the first 16 bytes
as IV, then CBC with a zero IV, then GCM with the first 12 bytes as nonce. If any of those produce
readable plaintext, you have both the key and the format, and the finding is complete.

If none do, do not report it. A high-entropy 32-byte value could be a session token, a device
identifier, a salt or a hash. `detect-ecb.py` flags such values as *candidates* precisely because it
cannot tell.

---

**25. Do I need to understand the mathematics of AES to do this job?**

No, and it is a common trap to spend a month on Galois fields instead of a day on the findings
catalogue.

What you need to understand deeply is: what each mode guarantees and what it does not; what an IV, a
nonce and a salt each require; why authenticated encryption exists; how a padding oracle works, at the
level of the CBC decryption identity; and where each of these appears in the JCA. All of that is
mechanism, not mathematics.

The mathematics becomes relevant in exactly two places in practice: understanding *why* GCM nonce reuse
recovers the subkey `H`, and understanding *why* a repeated ECDSA nonce reveals the private key. Both
are worth doing once, and both are in the chapter.

---

**26. What is the single highest-value thing I can do on a new target in five minutes?**

Two commands.

```bash
# host — static, 30 seconds
grep -rEn 'getInstance\("[A-Za-z0-9/]+"\)' jadx-out/sources/ | sort | uniq -c | sort -rn

# host — dynamic, 4 minutes of exercising the app
frida -U -f com.example.target -l scripts/frida-jca-universal-hook.js \
      -P '{"filterPackage":"com.example"}'
```

The first tells you every algorithm choice the app makes. The second gives you every key it holds in
software, every IV, and a nonce-reuse check, with call sites. Between them you will have identified the
top two findings on most targets before you have finished your coffee.
