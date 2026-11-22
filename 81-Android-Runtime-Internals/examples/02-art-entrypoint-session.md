# Example 02 — An Entrypoint Inspection Session

This is a transcript of a real-shaped session using
[`../scripts/art-entrypoints.js`](../scripts/art-entrypoints.js). Addresses and module paths are
illustrative; the states and the reasoning are the point.

---

## Cold method

```text
$ frida -U -p 12345 -l 81-Android-Runtime-Internals/scripts/art-entrypoints.js
art-entrypoints loaded. Pointer size: 8 bytes.
Try: art.inspect("com.example.Target", "check")

[Android Emulator 5554::PID 12345]-> art.inspect("com.artlab.runtime.Target", "check")

com.artlab.runtime.Target.check #0
  ArtMethod: 0x7b42d1c800
  offset:    0x20
  entry:     0x7b8f2a41c0
  module:    libart.so
  mapping:   /apex/com.android.art/lib64/libart.so [r-xp]
  state:     interpreter/stub
  candidates:
    0x10 -> 0x7b8f2a41c0  interpreter/stub  /apex/com.android.art/lib64/libart.so
    0x20 -> 0x7b8f2a41c0  interpreter/stub  /apex/com.android.art/lib64/libart.so
```

Two candidates point at the same address. The script chose the last one. On this build the
interpreter entry and the quick entry happen to coincide; on another build they do not. The
`candidates` list is printed so you can see the ambiguity instead of trusting the choice.

---

## After the method becomes hot

```text
[Android Emulator 5554::PID 12345]-> art.inspect("com.artlab.runtime.Target", "check")

com.artlab.runtime.Target.check #0
  ArtMethod: 0x7b42d1c800
  offset:    0x20
  entry:     0x7b9c004120
  module:    (none)
  mapping:   [anon:jit-code] [rwxp]
  state:     JIT
```

The `ArtMethod` address is the same; the entrypoint moved into the JIT code cache. That is the
state change the chapter describes. If you had installed a hook before this transition, the JIT may
have replaced your entrypoint; a correct hook engine prevents that or re-applies the hook.

---

## With an injected hook

```text
[Android Emulator 5554::PID 12345]-> art.inspect("com.artlab.vault.Vault", "check")

com.artlab.vault.Vault.check #0
  ArtMethod: 0x7b42d1e400
  offset:    0x20
  entry:     0x7b9d3f0a80
  module:    (none)
  mapping:   [anon:FridaAgent] [rwxp]
  state:     injected/unknown
```

The entrypoint is outside `libart.so`, the boot image and the JIT cache. That is evidence that the
dispatch layer was changed. It does not, by itself, prove which tool did it; the mapping name and the
process's libraries supply the attribution.

---

## What to record

| Field | Why |
|---|---|
| Build fingerprint | ART layout and compiler defaults vary by build |
| SDK / API level | The version matrix is keyed on it |
| ABI | Pointer size and register conventions |
| ART module version | Mainline updates change the runtime |
| `ArtMethod` address | The same method across states |
| Offset and candidates | Shows whether the derivation was ambiguous |
| Entry address and mapping | The state classification |
| Loader version | A hook can change without the app changing |

Write these down before you draw a conclusion. The transcript is reproducible only with the same
build and the same loader.
