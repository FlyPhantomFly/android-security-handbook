# CTF target — "the pin that moved"

Build instructions and **instructor notes** for
[Lab 04](../lab-04-ctf-the-pin-that-moved.md).

> **Spoilers below §3.** If you are solving the challenge, read §1 and §2 only.

| File | Role |
|---|---|
| [`challenge_server.py`](challenge_server.py) | TLS server, key rotation, and the flag oracle. Standard library only |
| [`PinGate.kt`](PinGate.kt) | The app's Java half: an OkHttp pin and a decoy |
| [`pin_gate.c`](pin_gate.c) | The app's native half: an obfuscated pin that reports what it accepted |

Nothing here ships a binary, a key, or a certificate. `challenge_server.py --setup` generates a CA
and three key pairs into `ctf-state/`, which must never be committed.

---

## 1. Run the server

```bash
# host
cd 36-CertificatePinning/labs/ctf-pin-that-moved
python3 -B challenge_server.py --setup
python3 -B challenge_server.py --pins
python3 -B challenge_server.py --serve --port 8443
```

`--setup` prints three pin values. Example output from a real run (yours will differ — the keys are
generated fresh):

```
pins for lab.local   (active key: original)

  original  sha256/atzZLy6iBj0u+xEvuxRI2sK5nzqNStQcpjxhAh+bvcM=
  rotated   sha256/1A/ZZHmAAzcGJSqdUXq2QyycPjy5ok8LbpOoajXOV1M=
  decoy     sha256/VoFXeEoq29UMj19vSKbr8n7bGlLlxaQBH+g3dUcKWN0=
```

Endpoints:

| Path | Behaviour |
|---|---|
| `/ping` | Always answers. Confirms reachability, so infrastructure problems do not masquerade as challenge difficulty |
| `/flag` | Returns a **decoy** flag to anybody who completes a handshake |
| `/claim` | The oracle. Requires an `X-Accepted-Pin` header naming the currently-served key |

---

## 2. Build the app

### 2.1 Fill in the pins

In [`PinGate.kt`](PinGate.kt):

```kotlin
const val PIN_ORIGINAL = "sha256/atzZLy6iBj0u+xEvuxRI2sK5nzqNStQcpjxhAh+bvcM="
const val PIN_DECOY    = "sha256/VoFXeEoq29UMj19vSKbr8n7bGlLlxaQBH+g3dUcKWN0="
```

In [`pin_gate.c`](pin_gate.c), the **rotated** pin, XOR-obfuscated. Generate the table:

```bash
# host
python3 -B - <<'EOF'
pin = "1A/ZZHmAAzcGJSqdUXq2QyycPjy5ok8LbpOoajXOV1M="   # your rotated pin, no prefix
print(", ".join("0x%02x" % (ord(c) ^ 0x5A) for c in pin))
EOF
```

Paste the 44 bytes into `PIN_ROTATED_XOR[]`.

### 2.2 Compile

```bash
# host — build OUTSIDE this repository
NDK=$HOME/Android/Sdk/ndk/25.2.9519653
TOOL=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin        # or windows-x86_64
OUT=/tmp/ch36-ctf/arm64-v8a
mkdir -p "$OUT"

"$TOOL/aarch64-linux-android24-clang" \
    -fPIC -shared -O2 -Wall -Wextra \
    -DOPENSSL_IS_BORINGSSL \
    -I"$BSSL/include" \
    -o "$OUT/libpingate.so" \
    pin_gate.c "$BSSL/build/libssl.a" "$BSSL/build/libcrypto.a" -llog
```

Strip it, so the challenge is the challenge:

```bash
# host
"$TOOL/llvm-strip" --strip-all "$OUT/libpingate.so"
"$TOOL/llvm-readelf" --dyn-syms "$OUT/libpingate.so"     # only the JNI entry should remain
```

### 2.3 Assemble and install

Any Android module with `com.squareup.okhttp3:okhttp:4.12.0` and `jniLibs` pointing at
`/tmp/ch36-ctf`. On the MIUI reference device:

```bash
# host
adb push app-debug.apk /data/local/tmp/ctf.apk
adb shell "su -c 'pm install -r /data/local/tmp/ctf.apk'"
```

Make `lab.local` resolve to your host, or set `CTF_HOST` to the host's IP and reissue the
certificates with a matching CN.

---

## 3. Instructor notes — the design

**Everything below is a spoiler.**

### 3.1 The trap

The obvious move is `ssl-pinning-bypass.js`. It works: the Java pin falls immediately and `/flag`
returns

```
CTF{you_disabled_everything_which_proves_nothing}
```

which is flag-shaped, arrives fast, and is wrong. A solver who stops here has demonstrated exactly
the habit the chapter argues against — treating "traffic appeared" as "the assessment is done".

### 3.2 Why "disable everything" cannot win

`/claim` requires `X-Accepted-Pin` to name the key the server is **currently serving**, and the app
fills that header in from the certificate its native gate *accepted*. Three failure modes, each with
its own response:

| What the solver did | Header contains | Server says |
|---|---|---|
| Replaced the verify callback with `return 0` | empty | `400 no X-Accepted-Pin header` |
| Found the decoy pin in the DEX and forged the header | the decoy pin | `403 that pin belongs to a key this server has never served` |
| Made the gate accept the original key while the server serves it | the original pin | `403 correct, but this is the key you were already pinned to` |
| Made the gate accept the **rotated** key while the server serves it | the rotated pin | the flag |

The last row is the only one that requires understanding rather than suppression.

### 3.3 The two intended solutions

**Path A — recover the obfuscated pin, then rotate the server.**
The native pin is XORed with `0x5A`. `strings` finds nothing; the deobfuscation routine is a
44-iteration loop feeding a `strcmp`, which is unmistakable in Ghidra. Recover the value, notice it
matches none of the pins in the DEX, run `challenge_server.py --rotate`, and the gate accepts
legitimately with no hooking at all. **This is the elegant solve and the one to reward.** The
solver's tool was comprehension.

Alternatively, dump it from memory at comparison time — a Frida `Interceptor.attach` on the `strcmp`
call site reads the deobfuscated buffer.

**Path B — make the gate accept the rotated key while the server serves it.**
Rotate first, then defeat the *comparison* rather than the callback: patch the XOR table in the
`.so` to encode the rotated key's pin, or hook the comparison to return equal. The header is
populated from the presented certificate either way, so it names the rotated key and the oracle
passes.

### 3.4 The dead ends, and what each teaches

| Dead end | Lesson |
|---|---|
| `Interceptor.replace` on `gate_verify` returning 0 | The handshake succeeds and `g_accepted_pin` stays empty. **A successful bypass is not a successful attack.** |
| Forging the header from the DEX decoy | The loudest artefact in the APK is the one placed there for you. |
| Setting `http_proxy` and expecting the native path in Burp | Native `connect(2)` never consults it. See Lab 02 §7.5. |
| Hooking every Java layer and nothing else | The Java path was never the gate. |
| `--rotate` without touching the app at all | Correct instinct, incomplete: the gate is pinned to the rotated key, so this **is** most of Path A. It only fails if the solver has not confirmed which key the gate wants. |

### 3.5 The flags

| Path | Value |
|---|---|
| `/flag` (decoy) | `CTF{you_disabled_everything_which_proves_nothing}` |
| `/claim` (real) | `CTF{pins_move_and_so_must_your_assumptions}` |

Both are plain ASCII with no control characters, deliberately — the flag in
`13-ART/labs/lab-04` is code points `0x00`–`0x06` and is written as escapes for exactly that reason.

### 3.6 Grading

| Level | Criterion |
|---|---|
| Pass | Real flag by any means, plus a written statement of why the decoy proves nothing |
| Good | Path A or B, with the layer that gated each request correctly identified |
| Excellent | Path A with **no runtime instrumentation at all** — comprehension plus a server-side rotation |
| Distinction | Also explains why the oracle's design defeats a universal bypass, and proposes a way it could be defeated anyway |

The distinction answer exists: an attacker who fully controls the client can compute the correct
header themselves once they know which key is being served, since it is a hash of a public key they
can fetch. **The oracle raises the cost; it does not make the challenge unwinnable by force.** A
solver who spots that has understood the chapter's central claim — that a check running inside a
process the attacker owns is a speed bump, and its value is measured in attacker hours, not in
impossibility.

---

## 4. Cleanup

```bash
# host
python3 -B challenge_server.py --clean            # removes ctf-state/ and its keys
rm -rf /tmp/ch36-ctf
adb shell "su -c 'pm uninstall com.pentest.ch36.ctf'"
adb shell rm -f /data/local/tmp/ctf.apk
adb shell settings put global http_proxy :0
```

Verify nothing leaked into the repository:

```bash
# host — from the repo root
find . \( -name 'ctf-state' -o -name '*.pem' -o -name '*.key' -o -name '*.so' \)   # expect nothing
grep -rn "^-----BEGIN" . 2>/dev/null                                              # expect nothing
```

The `grep` is anchored to the start of a line deliberately: an unanchored search for
`BEGIN CERTIFICATE` matches the scripts and prose that name it as a *pattern*, so it reports hits on
a clean repository, and a check that cries wolf is one nobody reads.
