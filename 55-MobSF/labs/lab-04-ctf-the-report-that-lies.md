# Lab 04 — CTF: the report that lies

**Level:** CTF
**Time:** 3–5 hours
**Prerequisites:** Labs [01](lab-01-first-scan-and-inventory.md),
[02](lab-02-survival-rate.md) and [03](lab-03-obfuscation-blindness.md).
**MobSF required:** **No.** Flags 1–3 are solvable from the shipped report fixture alone. Flag 4
needs the artefact the report describes.

---

## 0. The premise

You have been handed a scanner report and asked to review it.

**Every flag in this CTF is behind a line of that report that is wrong.** Not wrong because the tool
is broken — every rule fired correctly — but wrong in the sense that matters: the line does not mean
what a reader will think it means.

Four flags, four different ways of being wrong:

| Flag | The lie | Solvable from |
|---|---|---|
| **1** | A row rated `info` that is a Medium | the report alone |
| **2** | A **negative** claim, in the reassuring band, that is false | the report alone |
| **3** | A `high` row whose value is not what the section calls it | the report alone |
| **4** | A finding that is in **no section at all** | the report **plus the artefact** |

**Flags are graded, but the write-ups are graded harder.** A flag with no defensible report entry
scores zero. That is the point of the exercise: recovering a value is a puzzle, and writing the
sentence that makes it matter is the job.

Flag format: `flag{...}`. Self-check hashes are given with each flag so you can verify without
spoiling the others.

---

## 1. Materials

```bash
# host
cd 55-MobSF/labs
REPORT=../examples/synthetic-mobsf-report.json
python3 -B -c "import json;d=json.load(open('$REPORT'));print(d['_fixture']['WHAT_IS_REAL'][:300])"
```

**Read the `_fixture` block first.** It is the provenance statement, and reading provenance before
citing anything is a habit this whole chapter is trying to install. It tells you that every *value*
in the report is a real measurement of a real APK and that the report's *structure* is a
reconstruction, because MobSF was not run
([README §1.6](../README.md#16-installation-reality--mobsf-was-not-run-here)).

**For flag 4** you also need the artefact:
`CMPen-Android-App-v1.2.apk`, SHA-256
`137186672dd93517bd6c85637c04c7f7cf912458e3ea9c887072dbbf00c39638` — a public, deliberately
vulnerable Android training application. Verify the hash before you start; a CTF against the wrong
binary is a long afternoon.

```bash
# host
sha256sum CMPen-Android-App-v1.2.apk
jadx -d out CMPen-Android-App-v1.2.apk
```

Useful throughout:

```bash
python3 -B ../scripts/mobsf-validate.py --report $REPORT --apk CMPen-Android-App-v1.2.apk --tree ./out
```

The validator will hand you flags 1 and 2 almost directly. **Solve them by hand first**, then run it
to check — the tool is there to confirm your reasoning, not to replace it.

---

## 2. Flag 1 — the row rated `info` that is a Medium

> **Check:** `sha256` of your answer starts with `7d8588de`

### The line

```bash
# host
python3 -B -c "
import json; d=json.load(open('$REPORT')); ma=d['manifest_analysis']['manifest_anal']
for it in ma:
    if it.get('severity')=='info': print(it['severity'],'|',it['title'][:140])"
```

One of those rows contains a clause that is the tool telling you, explicitly, that it has **not done
a check**. In a 39-item report nobody reads that clause.

### What to do

Find the clause. Do the check the tool declined to do. The evidence is in the same manifest, a few
elements away.

```bash
# host — the platform's own parser
aapt2 dump xmltree --file AndroidManifest.xml CMPen-Android-App-v1.2.apk | grep -B3 -A3 'E: permission'
```

If you have no `aapt2` and no APK, the report itself names the permission; you need one more fact
about it, and there is exactly one place that fact can live.

### The flag

Construct it from **the last token of the permission's name** and **the human-readable name of its
protection level**, joined by an underscore:

```
flag{<LAST_TOKEN>_<level>}
```

Levels, for reference — the low nibble of the integer decides who may hold the permission:

| Value | Level | Who can hold it |
|---|---|---|
| `0` | `normal` | **Any application that asks, at install time, with no prompt** |
| `1` | `dangerous` | Any application, after a runtime user prompt |
| `2` | `signature` | Only apps signed with the same key |
| `3` | `signatureOrSystem` | Same key, or a system app |

### The write-up (graded)

One paragraph. It must contain:

- The component, the authority, and the permission name.
- The measured `protectionLevel`, quoted from the parser output.
- **Why the scanner's `info` rating is wrong**, in a sentence a developer will accept.
- The severity you assign, and the reason.
- The fix, as an attribute.

<details>
<summary>Hint 1.1</summary>

Search the manifest analysis for a title containing the words *"should be checked"*. Scanners are
often honest in their own text and dishonest in their severity field. Read the text.

</details>

<details>
<summary>Hint 1.2</summary>

`protectionLevel` is printed by `aapt2` as an integer, usually in hex: `0x00000000`. The **low
nibble** is the base level; the high bits are flags (`privileged`, `instant`, `appop` and so on).
Only the base level decides who may hold the permission on an ordinary device.

</details>

<details>
<summary>Hint 1.3</summary>

`0x00000000` → the low nibble is `0` → `normal`. The permission is declared **in the same manifest**
the scanner just parsed, four elements above the provider it rated `info`.

</details>

---

## 3. Flag 2 — the negative claim that is false

> **Check:** `sha256` of your answer starts with `526d7306`

### The line

```bash
# host
python3 -B -c "
import json; d=json.load(open('$REPORT'))
for band in ('high','warning','info','secure'):
    for it in d['appsec'].get(band) or []:
        print('%-8s %s' % (band, it['title']))"
```

One of those is a **negative** claim about a security control. It is false.

Negative claims are the most dangerous output a scanner produces, because a reader has no reason to
check a reassurance. Lab 03 is the general case; this is the instance.

### What to do

Do not look for the *type name* the scanner looked for — that is exactly the mistake being
demonstrated. Look for the **value**, which survives R8 because R8 renames symbols and not string
literals.

```bash
# host
mkdir -p /tmp/dexes && unzip -o -j CMPen-Android-App-v1.2.apk 'classes*.dex' -d /tmp/dexes
# now: what does a CONFIGURED pin value look like, exactly?
```

> **`grep sha256/` alone is not the answer.** That substring is OkHttp's own parser constant and
> it hits on essentially every application that uses OkHttp. The distinguishing feature is what
> follows it: a base64-encoded SHA-256 digest is **43 characters plus one `=`**. Build the regex from
> that fact. [36-CertificatePinning §8.2](../../36-CertificatePinning/README.md#82-doing-it-by-hand)
> has the exact form if you get stuck.

### The flag

`flag{` + the **first eight characters of the base64 pin value, excluding the `sha256/` prefix** +
`}`.

So if the value were `sha256/AAAAbbbb...=`, the flag would be `flag{AAAAbbbb}`.

### The write-up (graded)

The correction paragraph a client receives. It must contain:

- The claim, quoted.
- The pin value and the host it is configured for.
- **The mechanism of the failure** — not "the scanner was wrong" but *why* it was wrong.
- The corroborating evidence that the mechanism is the cause.
- A sentence on why a false negative matters more than a false positive.
- And — do not skip this — the sentence that **a configured pin is still not proof of enforcement**.

<details>
<summary>Hint 2.1</summary>

The report fixture for the **same application one version earlier** ships next door:
[`synthetic-mobsf-report-v1.0.json`](../examples/synthetic-mobsf-report-v1.0.json). Look at its
`appsec.secure` band and compare. Two builds of one app, opposite verdicts, one variable.

</details>

<details>
<summary>Hint 2.2</summary>

The report's own `secrets` array already contains the value you are looking for. The scanner
extracted it, listed it as a *secret*, and then told you the app has no pinning. Both statements are
in the same JSON file.

(That overlap is also flag 3's territory: the same value is misclassified twice, in two different
directions, by two different sections.)

</details>

<details>
<summary>Hint 2.3</summary>

```bash
grep -a -o -h -E 'sha256/[A-Za-z0-9+/]{43}=' /tmp/dexes/*.dex | sort -u
```

Then find where it is used:

```bash
grep -rn '+xpjwBQ7' out/sources/ | head
```

</details>

---

## 4. Flag 3 — the `high` row whose value is not what it says

> **Check:** `sha256` of your answer starts with `1219c5e3`

### The line

The report's `secrets` array has seven entries under a `high`-severity code finding titled
*"Files may contain hardcoded sensitive information like usernames, passwords, keys etc."*

```bash
# host
python3 -B -c "
import json; [print(s) for s in json.load(open('$REPORT'))['secrets']]"
```

**Six of the seven are not secrets in any sense a report should use the word.** Classify all seven
before you touch any of them:

| Shape | It actually is |
|---|---|
| `sha256/` + 43 base64 chars | An SPKI **pin** — a *public* key hash |
| 32 / 40 / 64 hex chars | A **digest** |
| base64 → readable text | Obfuscation, defeated |
| base64 → high-entropy bytes | **Ciphertext** |

```bash
# host — the classifier, on every entry at once
python3 -B ../scripts/mobsf-validate.py --report $REPORT --apk CMPen-Android-App-v1.2.apk \
    --only warning 2>/dev/null | grep -A3 'classified as'
```

### What to do

Two of the seven decode to **binary that is not ciphertext** — it is plaintext under a trivial
transformation. Find them, and work out the transformation.

The method, and it is the general method for this class of value:

1. base64-decode.
2. Look at the bytes. Are they uniformly random-looking, or do they have structure?
3. If they have structure, try the cheapest transformations first, in this order: single-byte XOR,
   rotation, a repeating short key.
4. For single-byte XOR there are only 256 possibilities. **Try all of them and look for printable
   ASCII.**

```bash
# host — the whole attack, in one command
python3 -B -c "
import base64,sys
v = sys.argv[1]
d = base64.b64decode(v)
for k in range(256):
    out = bytes(b ^ k for b in d)
    if all(32 <= c < 127 for c in out):
        print('key=0x%02x  %s' % (k, out.decode()))
" 'PDY7PSEwagtvDRUvPjJoEjwREg0SERNsYzwLNjQTMyMrEwkROyc='
```

### The flag

The decoded string. It is already in `flag{...}` form.

**Take the one whose value is exposed through the WebView bridge**, not the one assembled onto the
heap at startup. Both decode; only one of them is reachable from outside the application, and the
CTF wants the reachable one. (If you decode the wrong one, its check hash starts with `dd3cc9d3` —
so you will know.)

### The write-up (graded)

Rewrite the scanner's single `high` "hardcoded sensitive information" row as **five separate
entries**, one per cited file, each with its own verdict. The report cites:

```
org/android/cmpen/AdminLoginActivity.java : 12,13,14
org/android/cmpen/FlagProvider.java       : 12
org/android/cmpen/DeepLinkActivity.java   : 14
org/android/cmpen/MemorySecret.java       : 7
org/android/cmpen/WebAppInterface.java    : 10
```

At least one must be `REJECTED`, at least one must be a `FINDING`, and at least one must be `MERGED`
into another finding. Give a reason for each.

**This split is the highest-value single act in the CTF.** One rule, five files, five different
answers — and reporting it as one `high` is how a scanner-derived report gets its reputation.

<details>
<summary>Hint 3.1</summary>

Two of the seven values begin with the same four base64 characters. Values that share a prefix after
base64 encoding share a prefix *before* it too — which means they start with the same plaintext bytes
under the same transformation. That is a strong signal that a fixed transformation is in play, and it
is visible without decoding anything.

</details>

<details>
<summary>Hint 3.2</summary>

The plaintext starts with `flag{`. You know five bytes of plaintext and you have the corresponding
ciphertext bytes. XOR them. If the result is the same byte five times, you have the key — this is a
known-plaintext attack in one line, and it is why single-byte XOR is not encryption.

</details>

<details>
<summary>Hint 3.3</summary>

The key is `0x5A`. Note the shape of the helper that does it: base64-decode, then XOR every byte with
a constant, then interpret as UTF-8. The value returned by the WebView bridge goes through exactly
that path.

</details>

---

## 5. Flag 4 — the finding that is in no section

> **Check:** `sha256` of your answer starts with `0b828c39`
> **This flag requires the artefact.**

### The premise

Flags 1–3 were report lines that were wrong. This one is a finding the report **does not contain at
all** — and the only route to it is reading the files that *other* findings cited.

That is the shape of the two best findings in this chapter's own worked example (README §9.3), and it
is why the "findings that did not originate from the scan" number is worth tracking.

### What to do

**Step 1 — follow the browsable-activity row.** The report has an `info` row naming a browsable
activity with a scheme, a host and a path. Open that Activity's source. It compares two URI query
parameters against string literals and grants access when they match. **Those literals are not in any
report section**, because no rule fires on a comparison against a constant.

```bash
# host
python3 -B -c "
import json; print(json.dumps(json.load(open('$REPORT'))['browsable_activities'], indent=2))"
sed -n '1,35p' out/sources/org/android/cmpen/DeepLinkActivity.java
```

**Step 2 — follow the ECB row.** The report has a `high` code finding for ECB mode citing one line of
one file. Open that file and read the **whole** function, not the cited line.

```bash
# host
sed -n '15,35p' out/sources/B/g.java
```

You will find that the ECB is the *second*-worst thing in the function. Above it is a key derivation
that **no scanner rule covers**: a single unsalted hash round over a caller-supplied string,
truncated, used directly as a symmetric key, with no IV because the mode has none.

**Step 3 — join them.** The Activity holds a ciphertext field. The helper holds the derivation. The
deep link holds the key material. Nothing in the report connects the three, because the analysers are
one-pass and independent
([README §5.4](../README.md#54-the-join-mobsf-does-not-make)).

**Step 4 — recover the plaintext.**

```bash
# host — reimplement the app's own derivation. Read B/g.java and match it exactly:
#   digest = SHA-256(secret); key = first 16 bytes; AES/ECB/PKCS5Padding; decrypt(base64(ct))
python3 -B - <<'PY'
import base64, hashlib
from Crypto.Cipher import AES          # pip install pycryptodome
SECRET = '<the token literal from DeepLinkActivity>'
CT     = '<the ciphertext field from DeepLinkActivity>'
key = hashlib.sha256(SECRET.encode()).digest()[:16]
pt  = AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(CT))
print(pt)
PY
```

If `pycryptodome` is unavailable, `openssl` will do it:

```bash
# host
KEY=$(python3 -B -c "import hashlib;print(hashlib.sha256(b'<secret>').hexdigest()[:32])")
echo '<ciphertext-b64>' | base64 -d | openssl enc -d -aes-128-ecb -K "$KEY" -nopad | xxd | head
```

### The flag

The decrypted plaintext, in `flag{...}` form. Ignore the padding bytes.

### The write-up (graded, and this one is the whole exercise)

Two entries.

**Entry A — the deep link.** A Medium. It must name: the scheme/host/path, the two parameters, the
fact that the comparison is against literals present in the shipped artefact, who can send the
Intent (**anyone with a web page**), and what they get.

**Entry B — the key derivation.** This is the finding no rule produced. It must name:

- The exact derivation, quoted from the source.
- **Three separate defects**, not one: no salt, no iteration count (a single hash round is not a KDF),
  and ECB with no IV. Any one of the three is enough for an attacker who can guess the input.
- Why it is worse than the ECB row the scanner *did* report.
- The fix, as code — a real KDF with a salt and a work factor, plus an authenticated cipher mode.

And a sentence explaining **why neither entry is in the scan**: entry A because no rule fires on a
comparison against a constant, entry B because there is no rule for "hash used as a KDF" and the
constructs it is built from (`MessageDigest`, `Arrays.copyOf`, `SecretKeySpec`) are individually
unremarkable.

<details>
<summary>Hint 4.1</summary>

The report's `android_api` section cites **two** lines of `B/g.java` under `api_crypto`, while the
ECB *finding* cites only one of them. The line that appears in the API inventory but in no finding is
where flag 4 begins. That asymmetry is visible in the JSON without opening the APK.

</details>

<details>
<summary>Hint 4.2</summary>

`DeepLinkActivity` has a private field holding a base64 blob, and an `onCreate` that compares
`data.getQueryParameter("ref")` and `data.getQueryParameter("token")` against two literals. One of
those two literals is the key material passed to the decryption helper.

</details>

<details>
<summary>Hint 4.3</summary>

The helper's signature is `a(String b64ct, String secret)`. Match its body exactly:

```java
MessageDigest.getInstance("SHA-256").digest(secret.getBytes(UTF_8))   // no salt, one round
Arrays.copyOf(digest, 16)                                            // truncate to AES-128
Cipher.getInstance("AES/ECB/PKCS5Padding")                           // no IV
cipher.init(DECRYPT_MODE, new SecretKeySpec(key16, "AES"))
cipher.doFinal(Base64.decode(b64ct, 0))
```

</details>

---

## 6. Scoring

| Item | Points |
|---|---|
| Flag 1 | 10 |
| Flag 2 | 15 |
| Flag 3 | 15 |
| Flag 4 | 25 |
| Write-up for flag 1 | 5 |
| Write-up for flag 2 (the correction paragraph) | 10 |
| Write-up for flag 3 (the five-way split) | 10 |
| Write-ups for flag 4 (both entries) | 20 |
| **Bonus:** a fifth item, from anywhere in the report, that you can show is wrong — with evidence | 10 |
| **Penalty:** any report line quoted in your write-up that you did not verify | −10 each |

**Total 110.** The write-ups are worth 45 of it, and the penalty exists. A CTF that
rewards only flag recovery teaches flag recovery.

---

## 7. Debrief — what each flag was really testing

| Flag | The surface lesson | The real lesson |
|---|---|---|
| 1 | Resolve `protectionLevel` | **Severity errors point both ways.** A tool that only over-reports is easy to correct for; one that also under-reports is not, and you cannot apply a blanket discount |
| 2 | Grep for the pin value | **Negative claims are unaudited.** Nobody checks a reassurance, and a name-based rule fails silently under R8 |
| 3 | Classify before naming | **One rule, five files, five answers.** "Hardcoded secrets: 7" is not a finding, it is seven questions |
| 4 | Read the whole file | **The best findings are not in the report.** They come from the files the report pointed at, and from joining sections nothing joins |

The four together are the chapter in one exercise:

> **A sweep produces leads, not findings — and confidence ranking is not severity ranking.**

---

## 8. Answer key

Do not open this until you have written the write-ups. The flags are the cheap part.

<details>
<summary>Full answer key</summary>

**Flag 1** — `flag{ACCESS_FLAG_normal}`
`org.android.cmpen.FlagProvider` is exported with
`android:readPermission="org.android.cmpen.permission.ACCESS_FLAG"`. That permission is declared in
the same manifest with `android:protectionLevel=0x00000000` = `normal`, granted at install time to
any application that asks. The scanner rated it `info` because a permission was present. It is a
Medium: the provider's `query()` returns a base64-encoded token.
SHA-256 `7d8588dedab12b7e33c8df252be863ac2552b83f99748ce53cd682d724b02a4c`.

**Flag 2** — `flag{+xpjwBQ7}`
The pin is `sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ=`, configured for
`ninja.secops.group` on a process-wide `OkHttpClient` built in the static initialiser of `b/h.java`.
The scanner's rule matches the type name `okhttp3.CertificatePinner`; R8 renamed it to `m.e`, so the
rule found nothing and the scorecard says the app does not pin. Version 1.0 of the same application,
unobfuscated, is detected correctly by the identical rule.
SHA-256 `526d7306ad0eaa6616b2ac78b1093067504c590a04f5eed56517c40c3b0515ab`.

**Flag 3** — `flag{j0Q5WOudh2HfKHWHKI69fQlnIiyqISKa}`
`PDY7PSEwagtvDRUvPjJoEjwREg0SERNsYzwLNjQTMyMrEwkROyc=`, base64-decoded then XORed byte-wise with
`0x5A`. It is the value returned by `WebAppInterface.getAuthToken()`, exposed to page JavaScript as
`AndroidBridge`.
SHA-256 `1219c5e3668ac5b1923164d42a957225b952479d2b97e619b880fe22c9fd9117`.

The decoy — `PDY7PSE0HBUgFBIvDTMCKR8OLCBoChsJYxkiHzFsaDQ2MQ4bAyc=`, the same transformation — is
`flag{nFOzNHuWiXsETvz2PAS9CxEk62nlkTAY}`, assembled onto the heap by `MemorySecret.assemble()` at
startup. Real, and not reachable from outside the process; SHA-256
`dd3cc9d3d26f0d0d767c6b743c7b5600d7e02544a67e44af5ced3d651196429b`.

**Flag 4** — `flag{ucYiU0U7hFGOp8jTDKhSl0X6mNzjzDHd}`
`DeepLinkActivity` handles `ctfapp://open/admin` and grants access when
`?ref=debug&token=admin_access_2026`. It holds the ciphertext
`cLwIQMxPtGi+cXUqqugxhZJiS0Dci/ZMF2UWCNj3kb+ONcEdRw18esrwwgyMcaoe`, decrypted by `B.g.a(ct, secret)`
with `secret` = the token. The derivation is
`AES-128-ECB(key = SHA-256("admin_access_2026")[0:16])` — unsalted, single-round, truncated, no IV.
SHA-256 `0b828c394fba3e29f14f8f6a7196af201ce11447680a2b9239a30a7bad0356ba`.

```python
import base64, hashlib
from Crypto.Cipher import AES
key = hashlib.sha256(b'admin_access_2026').digest()[:16]
print(AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(
    'cLwIQMxPtGi+cXUqqugxhZJiS0Dci/ZMF2UWCNj3kb+ONcEdRw18esrwwgyMcaoe')))
```

**Bonus candidates**, any of which earns the ten points with evidence:

- The `certificate_analysis` row *"Missing v1 signature scheme"* — a **direction error**. Absent v1
  on a `minSdk` 24 app is a compatibility note; *present* v1 without v2 is the Janus-relevant case.
- The code row *"App creates a temporary file"* — a **category error**. `CmpenApp.java:17` writes
  `databases/secrets.db`, a permanent file in the private data directory. The construct is real, the
  category is wrong, and the interesting fact (that the file is reachable through the unprotected
  provider) is not what the rule says.
- The manifest row *"App can be installed on a vulnerable Android version [minSdk=24]"* — fires on
  an integer, names no weakness.
- The `exported_activity` row for `MainActivity` — it is the **launcher**, exported because it must
  be.
- The eleven `appsec` scorecard entries, which restate the manifest, code and certificate sections
  and inflate a 27-item report to 39.

</details>

---

## 9. If you are running this for a team

- **Give them the report and nothing else for the first hour.** Flags 1–3 are all solvable from it,
  and the constraint forces them to read a report properly rather than jumping to the binary.
- **Release the APK at the one-hour mark** for flag 4.
- **Grade the write-ups first, in front of the group, before revealing the flags.** The order matters:
  it establishes that the sentence is the deliverable and the flag is the receipt.
- **Ask each person for one bonus item** and collect them. On a real report the bonus list is always
  longer than anyone expects, and seeing five people find five *different* wrong lines in one
  document is more persuasive than any amount of this chapter's prose.
