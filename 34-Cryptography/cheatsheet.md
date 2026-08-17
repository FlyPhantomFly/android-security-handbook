# 34 — Cryptography · Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these works.

---

## The four commands that matter

```bash
# host — the single highest-yield grep in an Android crypto review
grep -rEn 'getInstance\("(AES|DES|DESede|Blowfish|RC2)"\)' sources/

# host — every software symmetric key the app uses, at runtime
frida -U -f <pkg> -l scripts/frida-jca-universal-hook.js

# host — ECB proved from the data, no code required
python3 scripts/detect-ecb.py ./data/data/<pkg>

# host — is the app using hardware-backed keys at all?
grep -rn "AndroidKeyStore" sources/
```

---

## Decision table — what to use

| Need | Answer |
|---|---|
| Symmetric encryption | `AES/GCM/NoPadding`, 256-bit key, 12-byte provider nonce, 128-bit tag |
| Alternative AEAD | `ChaCha20/Poly1305/NoPadding` (API 28+) |
| Hash | `SHA-256` |
| Keyed integrity | `HmacSHA256`, compared with `MessageDigest.isEqual` |
| Password → key | `PBKDF2WithHmacSHA256`, ≥600,000 iterations, 16-byte random salt, count stored |
| Password → key (better) | Argon2id, m=19456 KiB, t=2, p=1 |
| Secret → keys | HKDF extract-then-expand, distinct `info` per output |
| Asymmetric encryption | `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` + explicit `OAEPParameterSpec` |
| Signature | `SHA256withECDSA` (P-256) or `SHA256withRSA/PSS` |
| Key agreement | ECDH P-256 or X25519, then HKDF |
| Randomness | `new SecureRandom()`, never `setSeed` |
| Key storage | `AndroidKeyStore` + `KeyGenParameterSpec` + `setRandomizedEncryptionRequired(true)` |
| Easiest correct answer | Tink `Aead` + `AndroidKeysetManager` + `withMasterKeyUri` |

---

## Modes

| Mode | Auth | IV/nonce | Padding | Parallel | Use |
|---|---|---|---|---|---|
| ECB | No | none | yes | yes | **Never** |
| CBC | No | 16B, unpredictable | yes | dec only | Legacy + MAC only |
| CTR | No | nonce+counter | no | yes | Legacy + MAC only |
| **GCM** | **Yes** | **12B, unique** | no | yes | **Default** |
| CCM | Yes | 7–13B | no | no | Constrained devices |
| ChaCha20-Poly1305 | Yes | 12B | no | yes | No AES hardware; API 28+ |
| GCM-SIV | Yes | 12B | no | yes | Nonce-misuse resistance |

### Failure mode per mode

| Mode | Reuse IV/nonce | No integrity |
|---|---|---|
| ECB | n/a — deterministic always | block splice |
| CBC | deterministic, dictionary attack | padding oracle, bit-flip in next block |
| CTR | `P1 ⊕ P2` leaks | full bit-flip malleability |
| GCM | `P1 ⊕ P2` **and** subkey H → universal forgery | n/a |

---

## The transformation-string trap

```java
Cipher.getInstance("AES")                 // == AES/ECB/PKCS5Padding
Cipher.getInstance("RSA")                 // == RSA/ECB/PKCS1Padding
Cipher.getInstance("AES/GCM/NoPadding")   // correct
```

| Token count | Meaning |
|---|---|
| 1 (`"AES"`) | provider defaults fill mode + padding → **ECB** |
| 3 (`"AES/GCM/NoPadding"`) | explicit; the only form to write |

`RSA/ECB/...` — "ECB" is a JCA naming artefact. RSA has no mode.

---

## IV vs nonce vs salt

| | IV | Nonce | Salt |
|---|---|---|---|
| Secret? | No | No | No |
| Must be unique | per message | **per (key, message)** | per record |
| Must be unpredictable | **yes** (CBC) | no | no |
| Typical size | 16B | 12B | 16B |
| Reuse cost | determinism | **total break** | precomputation |
| Stored with data | yes | yes | yes |

---

## Findings catalogue — quick reference

| ID | Finding | Severity | Fastest detection |
|---|---|---|---|
| F-01 | Hardcoded symmetric key | High–Critical | Hook `SecretKeySpec.$init` |
| F-02 | ECB mode | Medium–High | grep `getInstance("AES")` |
| F-03 | Static / zero IV | Medium–High | Compare IVs across two encryptions |
| F-04 | GCM nonce reuse | High–Critical | Record `(key, iv)` pairs |
| F-05 | Key from constant or device ID | High | grep `ANDROID_ID`, `SHA1PRNG`, `setSeed` |
| F-06 | `java.util.Random` for secrets | High | grep `new Random()` near crypto |
| F-07 | MD5/SHA-1 for integrity or auth | Info–Critical | Hook `MessageDigest.getInstance` |
| F-08 | Custom crypto | Varies | byte maths, no `javax.crypto` import |
| F-09 | Secrets in resources / BuildConfig | Varies | `aapt2 dump strings` |
| F-10 | Base64 as "encryption" | High | Decode stored preferences |
| F-11 | XOR "encryption" | Info–High | Constant array + `^` loop |
| F-12 | No integrity on ciphertext | Medium–High | Flip a bit, app still accepts |
| F-13 | Key stored beside ciphertext | Medium–High | 16/32B Base64 blobs in prefs |
| F-14 | Bad key transport / textbook RSA | Medium–High | grep `RSA/ECB/NoPadding` |
| F-15 | Non-constant-time comparison | Low–High | grep `Arrays.equals` after `doFinal` |
| F-16 | Unsigned code/update path | Critical | `DexClassLoader` + hash-only check |

---

## Static sweep, in order

```bash
# host
apktool d target.apk -o unpacked/ && jadx -d jadx-out/ target.apk

# 1. transformations
grep -rEn 'getInstance\("[A-Za-z0-9/]+"\)' jadx-out/sources/ | sort | uniq -c | sort -rn
# 2. silent ECB
grep -rEn 'getInstance\("(AES|DES|DESede|Blowfish)"\)' jadx-out/sources/
# 3. explicit weak
grep -rn 'ECB\|DES\|RC4\|MD5\|SHA-1\|SHA1' jadx-out/sources/
# 4. key material
grep -rn "SecretKeySpec" jadx-out/sources/
grep -rn "Ljavax/crypto/spec/SecretKeySpec;-><init>" unpacked/smali*/
# 5. randomness
grep -rn "new Random(\|SHA1PRNG\|setSeed\|Math.random" jadx-out/sources/
# 6. IV / nonce
grep -rn "IvParameterSpec\|GCMParameterSpec" jadx-out/sources/
# 7. integrity
grep -rn "MessageDigest\|Mac.getInstance\|Arrays.equals" jadx-out/sources/
# 8. resources
grep -riE "key|secret|password|token" unpacked/res/values/strings.xml
aapt2 dump strings target.apk | grep -iE "key|secret|token"
# 9. DEX string pool
strings unpacked/classes.dex | grep -E '^[A-Za-z0-9+/]{16,}={0,2}$'
# 10. embedded key files
find unpacked/assets unpacked/res/raw -type f 2>/dev/null | head
# 11. native
for so in unpacked/lib/*/*.so; do strings "$so" | grep -iE "aes|rsa|hmac|key"; done
# 12. keystore usage
grep -rn "AndroidKeyStore\|KeyGenParameterSpec\|KeyProperties" jadx-out/sources/
# 13. modern libraries
grep -rln "tink\|bouncycastle\|sqlcipher\|androidx.security" jadx-out/sources/

# automated
python3 scripts/detect-ecb.py unpacked/
semgrep --config scripts/semgrep-crypto.yml jadx-out/sources/
```

---

## Dynamic

```bash
# host
frida -U -f <pkg> -l scripts/frida-jca-universal-hook.js
frida -U -f <pkg> -l scripts/frida-jca-universal-hook.js \
      -P '{"filterPackage":"com.example","maxDump":512,"showStacks":true}'
```

```
jca.report()     summary, keys, nonce reuse, findings
jca.keys()       distinct key material + call sites
jca.filter(pkg)  restrict to one package
jca.reset()
```

### Objection

```bash
objection -g <pkg> explore
android hooking watch class javax.crypto.Cipher
android hooking watch class_method javax.crypto.Cipher.doFinal --dump-args --dump-return
android hooking watch class_method javax.crypto.spec.SecretKeySpec.$init --dump-args
android heap search instances javax.crypto.spec.SecretKeySpec
android keystore list
android keystore watch
```

### Hook fails to fire

```bash
# host
adb shell cmd package compile -m verify -f <pkg>     # defeat inlining
adb shell am force-stop <pkg>
```

---

## Data analysis

```bash
# adb shell (root)
su -c 'tar czf /sdcard/appdata.tgz /data/data/<pkg>'
```
```bash
# host
adb pull /sdcard/appdata.tgz && tar xzf appdata.tgz
python3 scripts/detect-ecb.py ./data/data/<pkg>
python3 scripts/detect-ecb.py --entropy ./data/data/<pkg>
```

| Observation | Conclusion |
|---|---|
| Two records share first 16 bytes | Same IV, or no IV |
| Two records share first 12 bytes, GCM | **Nonce reuse** |
| 16-byte block repeats within one record | ECB |
| Length always multiple of 16 | Block mode + padding |
| Length is `12 + n + 16` | `nonce ‖ ct ‖ tag` — good sign |
| Base64 decodes to readable text | Not encrypted (F-10) |
| 32-byte high-entropy blob beside data | Possibly the key (F-13) |
| Entropy < 6.0 in a "protected" file | Not encrypted, or partly plaintext |

---

## Key sizes and lifetimes

| Primitive | Minimum | Recommended |
|---|---|---|
| AES | 128 | 256 |
| RSA | 2048 | 3072+ |
| ECDSA / ECDH | P-256 | P-256 / P-384 |
| HMAC key | = hash output | 32 bytes |
| PBKDF2 salt | 8 bytes (RFC 8018) | 16 bytes |
| GCM tag | 96 bits | **128 bits** |
| GCM nonce | 12 bytes | 12 bytes |

---

## AndroidKeyStore

```java
KeyGenParameterSpec.Builder(alias, PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
    .setBlockModes(BLOCK_MODE_GCM)
    .setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
    .setKeySize(256)
    .setRandomizedEncryptionRequired(true)     // app cannot supply an IV → F-04 impossible
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(30, AUTH_DEVICE_CREDENTIAL | AUTH_BIOMETRIC_STRONG)  // API 30+
    .setIsStrongBoxBacked(true)                // API 28+, catch StrongBoxUnavailableException
    .build()
```

| Signal | Meaning |
|---|---|
| `key.getEncoded() == null` | Non-exportable. Hardware or keystore-held |
| `KeyInfo.isInsideSecureHardware()` | ≤ API 30 hardware check |
| `KeyInfo.getSecurityLevel()` | API 31+ (`SOFTWARE` / `TRUSTED_ENVIRONMENT` / `STRONGBOX`) |
| `KeyPermanentlyInvalidatedException` | Biometric/lock-screen changed. Data is gone |
| `UserNotAuthenticatedException` | Auth window expired. Prompt and retry |

| API | Change |
|---|---|
| 18 | AndroidKeyStore, asymmetric only |
| 23 | Symmetric keys, `KeyGenParameterSpec`, auth binding |
| 28 | StrongBox, `setUnlockedDeviceRequired`, `importWrappedKey` |
| 30 | `setUserAuthenticationParameters` |
| 31 | keystore2; `KeyInfo.getSecurityLevel()` |

---

## Providers

| Provider | Contains |
|---|---|
| `AndroidKeyStore` | Hardware-backed keys; `getEncoded()` returns null |
| `AndroidOpenSSL` / `Conscrypt` | Default; BoringSSL-backed AES, RSA, EC, TLS |
| `BC` (Bouncy Castle) | Legacy, progressively removed from the platform |
| `AndroidNSSP` | Network Security Provider (Play Services updatable) |

```java
for (Provider p : Security.getProviders()) Log.i("P", p.getName() + " " + p.getVersion());
```

---

## Frida one-liners

```javascript
// keys
Java.use('javax.crypto.spec.SecretKeySpec').$init.overload('[B','java.lang.String')
  .implementation = function (k, a) { console.log(a + ' ' + k); return this.$init(k, a); };

// transformations
Java.use('javax.crypto.Cipher').getInstance.overload('java.lang.String')
  .implementation = function (t) { console.log(t); return this.getInstance(t); };

// GCM nonce reuse
var seen={}; Java.use('javax.crypto.spec.GCMParameterSpec').$init.overload('int','[B')
  .implementation=function(l,iv){var h=''+iv;if(seen[h])console.error('REUSE '+h);
  seen[h]=1;return this.$init(l,iv);};

// PBKDF2 parameters
Java.use('javax.crypto.spec.PBEKeySpec').$init.overload('[C','[B','int','int')
  .implementation=function(p,s,i,l){console.log('iter='+i+' saltLen='+s.length);
  return this.$init(p,s,i,l);};

// is the key exportable?
Java.use('javax.crypto.Cipher').init.overload('int','java.security.Key')
  .implementation=function(o,k){console.log(k.$className+' enc='+k.getEncoded());
  return this.init(o,k);};
```

### Native (BoringSSL)

```javascript
['EVP_EncryptInit_ex','EVP_DecryptInit_ex','EVP_CipherInit_ex',
 'EVP_AEAD_CTX_seal','EVP_AEAD_CTX_open','AES_set_encrypt_key'].forEach(function(n){
  var a=Module.findExportByName('libcrypto.so',n);
  if(a) Interceptor.attach(a,{onEnter:function(x){console.log(n);}});
});
```

---

## Smali patterns

```
const-string v0, "AES/CBC/PKCS5Padding"
invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

new-instance v1, Ljavax/crypto/spec/SecretKeySpec;
invoke-direct {v1, v2, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

fill-array-data v2, :array_0
:array_0
.array-data 1
    0x4dt 0x79t 0x53t 0x75t ...      # 16/24/32 entries → candidate key
.end array-data
```

```bash
# host
grep -rn "Ljavax/crypto" unpacked/smali*/ | cut -d: -f3 | sort | uniq -c | sort -rn
grep -rn "fill-array-data" unpacked/smali*/ -A20 | grep -c "0x"
```

---

## MASVS mapping

| Control | Findings |
|---|---|
| MASVS-CRYPTO-1 | F-02, F-03, F-04, F-07, F-08, F-11, F-12, F-14 |
| MASVS-CRYPTO-2 | F-01, F-05, F-09, F-13 |
| MASVS-STORAGE-1 | F-01, F-10, F-13 |
| MASVS-STORAGE-2 | F-09 |
| MASVS-AUTH-2 | F-06, F-15 |
| MASVS-CODE-4 | F-16 |

---

## Named attacks (safe to cite)

| Name | What |
|---|---|
| Bleichenbacher / ROBOT | RSA PKCS#1 v1.5 padding oracle |
| Vaudenay padding oracle | CBC byte-at-a-time plaintext recovery |
| BEAST | Predictable CBC IVs in TLS 1.0 |
| Lucky 13 | Timing side channel, MAC-then-encrypt |
| POODLE | SSL 3.0 padding oracle |
| Sweet32 | Birthday attack on 64-bit blocks (3DES, Blowfish) |
| SHAttered | First public SHA-1 collision (2017) |
| Forbidden attack (Joux) | GCM nonce reuse → subkey H → universal forgery |
| Sony PS3 ECDSA | Constant `k` revealed the signing key |
| Debian OpenSSL PRNG | Entropy removed; 32,768 possible keys |

---

## Standards

| Doc | Covers |
|---|---|
| RFC 2104 | HMAC |
| RFC 5869 | HKDF |
| RFC 8018 | PKCS #5 v2.1 — PBKDF2 |
| RFC 8017 | PKCS #1 v2.2 — RSA, OAEP, PSS |
| RFC 8439 | ChaCha20-Poly1305 |
| RFC 8452 | AES-GCM-SIV |
| RFC 6979 | Deterministic ECDSA |
| RFC 9106 | Argon2 |
| NIST SP 800-38A | Block cipher modes |
| NIST SP 800-38D | GCM and GMAC |
| NIST SP 800-57 | Key management |
| NIST SP 800-131A | Algorithm transitions |
| FIPS 197 | AES |
| FIPS 186-5 | Digital signatures |

---

## Rules

1. You will never break AES. Look for the hand under the saw.
2. `getInstance("AES")` means ECB. Always.
3. GCM tag length is in **bits**. 128.
4. Never supply a nonce on encryption. Read `getIV()`.
5. `(key, nonce)` is the reuse unit, not `nonce`.
6. `getEncoded() == null` → stop extracting, start using.
7. A hash is not a KDF. A KDF is not a password hash.
8. Store the KDF parameters in the record, and authenticate them.
9. Encrypt-then-MAC, verified before decryption, constant-time.
10. Prove ECB from the ciphertext, not the code.
11. Search for the plaintext copy before fighting the ciphertext.
12. "Hardcoded key" is an observation. Decrypted data is a finding.
