# Lab 04 — CTF: The Invisible Hook

**Difficulty:** Advanced
**Time:** 2–4 hours
**Prerequisites:** [Lab 02](lab-02-artmethod-entrypoints.md), [Lab 03](lab-03-zygisk-module-anatomy.md),
[Chapter 81 §3.6–3.7](../README.md#36-entrypoints-what-quick-actually-means), Frida, `jadx`, `d8`

---

## The challenge

A small target program asks whether a candidate string is the password. The check is implemented in
Java and looks ordinary. On this device, it returns `false` for every input — including the correct
one. There is no anti-Frida check, no `TracerPid` check, and no native protector.

The check is being hooked. Your job is to find **which layer** the hook lives in, prove it with
runtime evidence, and recover the flag without disabling SELinux or patching the target's DEX.

The flag format is `ARTLAB{<candidate>}`.

---

## Rules

- Do not read `labs/ctf/hook.js` until you have written down your first hypothesis. The file is the
  answer key for the hook, not the challenge.
- Do not modify the target's DEX or the hook script to make the check pass.
- Do not disable SELinux or run the target as root.
- You may decompile the DEX. The original logic is still there; the hook changed the runtime, not the
  file.
- Record the evidence for each claim: command, output, and the layer it belongs to.

---

## Setup

### 1. Build the target

Save this as `Vault.java`:

```java
package com.artlab.vault;

public final class Vault {
    private static int hash(String s) {
        int acc = 0x5A17;
        for (int i = 0; i < s.length(); i++) {
            acc = (acc * 31) ^ (s.charAt(i) * 0x9E37);
        }
        return acc;
    }

    private static int expected() {
        return hash("zygote");
    }

    public static boolean check(String candidate) {
        return hash(candidate) == expected();
    }

    public static String reveal(String candidate) {
        return hash(candidate) == expected()
            ? "ARTLAB{" + candidate + "}"
            : "denied";
    }

    public static void main(String[] args) throws Exception {
        System.out.println("check(wrong)=" + check("wrong"));
        System.out.println("check(zygote)=" + check("zygote"));
        Thread.sleep(600_000);
    }
}
```

```bash
# host — build a DEX and push it
javac -source 8 -target 8 -d out Vault.java
d8 --output out out/com/artlab/vault/Vault.class
adb push out/classes.dex /data/local/tmp/vault.dex
```

### 2. Start the target

```bash
# host — run it as shell
adb shell "CLASSPATH=/data/local/tmp/vault.dex app_process /system/bin com.artlab.vault.Vault" &
adb shell "pidof app_process"
```

Record the PID. The output should show `check(zygote)=true` before the hook is attached. If it shows
`false`, the target is already hooked or the build is wrong.

### 3. Attach the hook

```bash
# host — attach the provided hook to the running target
frida -U -p <pid> -l 81-Android-Runtime-Internals/labs/ctf/hook.js
```

The hook logs each call and forces `check` to return `false`. The target's `check(zygote)` line was
already printed before the hook; the hook affects subsequent calls.

### 4. Confirm the symptom

```bash
# host — call check again from Frida
frida -U -p <pid> -e 'Java.perform(function(){ var V = Java.use("com.artlab.vault.Vault"); console.log(V.check("zygote")); });'
```

It prints `false`. The input is correct by construction; the runtime is lying.

---

## Steps

### 1. Rule out the obvious

- Is the app debuggable? Yes, it is `app_process` run as shell.
- Is there a `TracerPid`? Frida attaches through its own agent; check, but do not expect a simple
  ptrace relationship.
- Is the DEX modified? Compare the pushed DEX with the built one (`sha256sum`). It should match.
- Is the check inlined? The method is small and could be inlined, but the symptom is the opposite of
  the usual one: the check runs and returns the wrong value, so something is intercepting it.

### 2. Inspect the entrypoint

Use the classifier from Lab 02:

```bash
# host — from the repository root
frida -U -p <pid> -l 81-Android-Runtime-Internals/scripts/art-entrypoints.js
```

```text
art.inspect("com.artlab.vault.Vault", "check")
```

Record the `ArtMethod`, the entrypoint address, and the mapping. A normal interpreted or JIT method
points into `libart.so`, the JIT cache or the boot image. A hooked method points somewhere else.

### 3. Find the owner of the address

```bash
# host — map the entrypoint address to a file or an anonymous region
adb shell "su 0 cat /proc/<pid>/maps" | grep -iE "frida|gum|linjector|anon"
```

Frida's agent and its trampolines live in mappings that are not part of the target's DEX. The exact
names vary by Frida version and injection method. The evidence is the combination: the entrypoint is
outside the target's code, and the process has a Frida agent.

### 4. Read the original logic

The hook changed the runtime, not the DEX. Decompile it:

```bash
# host — pull the DEX and decompile it
adb pull /data/local/tmp/vault.dex .
jadx -d vault-out vault.dex
grep -rn "class Vault" vault-out/sources
```

Read `hash` and `expected`. The candidate is the string whose hash equals `expected()`. You can also
compute it directly from the decompiled code.

### 5. Call the unhooked path

`reveal` is not hooked. Call it with the candidate:

```bash
# host — call the original reveal path
frida -U -p <pid> -e 'Java.perform(function(){ var V = Java.use("com.artlab.vault.Vault"); console.log(V.reveal("zygote")); });'
```

It prints `ARTLAB{zygote}`. If it prints `denied`, you have the wrong candidate, or `reveal` is also
hooked (it is not, in the provided script).

### 6. Prove the layer

Write a short table:

| Observation | Value | Layer |
|---|---|---|
| `check` return value | `false` for the correct input | Behaviour |
| `ArtMethod` entrypoint | outside the DEX/JIT/boot image | Dispatch |
| Owning mapping | Frida agent/trampoline | Injection |
| DEX hash | matches the build | File integrity |
| `reveal` return value | `ARTLAB{zygote}` | Original logic intact |

The hook is at the **dispatch** layer: the method's entrypoint was replaced by a Frida Java hook. The
DEX is untouched, the class is the same, and the original logic is still callable through a path the
hook did not cover.

---

## Hints

- The target prints `check(zygote)=true` before the hook attaches. That is your control.
- Frida's Java hook is not LSPlant. The chapter's LSPlant section explains the general mechanism, but
  the artifact you find in `maps` will be Frida's, not Vector's.
- If `art.inspect` reports an unknown mapping, print the maps and find the address. Do not assume the
  hook is in `libart.so`.
- The candidate is a word used throughout this chapter. If you compute the hash yourself, you do not
  need to guess.
- `reveal` recomputes the hash instead of calling `check`. That is deliberate: it gives you a path
  that the hook did not cover, and it demonstrates that the original logic is still present.

---

## Success criteria

You can show:

1. The target's `check` returning `true` before the hook and `false` after it.
2. The `ArtMethod` entrypoint address and the mapping that owns it.
3. Evidence that the DEX is unchanged.
4. The recovered candidate and the flag `ARTLAB{<candidate>}`.
5. A layer table that distinguishes behaviour, dispatch, injection and file integrity.
6. An explanation of why "the check is hooked" is a more precise claim than "the app is tampered".

---

## Cleanup

```bash
# host
adb shell "su 0 pkill -f frida-server"
adb shell "rm /data/local/tmp/vault.dex"
adb shell "rm -rf vault-out"
```

If you used a disposable emulator, revert the snapshot.
