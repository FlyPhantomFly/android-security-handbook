# 39 — Emulator Detection: Mind Map

A single map of the whole chapter. Every leaf that carries a number was measured on a
**Redmi M2101K6P** (Android 11 / API 30, arm64) and a **Pixel_6_Pro_API_35** AVD
(Android 15 / API 35, x86_64).

```mermaid
mindmap
  root((39<br/>Emulator<br/>Detection))
    (1. What it is)
      Emulator = QEMU fork
        goldfish - original virtual hardware
        ranchu - virtio successor, current
        hybrid: HARDWARE=ranchu but goldfish nodes remain
      Virtualisation not emulation
        x86 guest runs on the host CPU via KVM/HVF
        this is WHY the emulator is faster
      Not the same question as root
        root asks about PRIVILEGE
        emulator asks about HARDWARE
        rooted real phone is the awkward third corner
      Why apps care
        SCALE - one attacker, a fleet
        fraud farms, bots, GPS spoofing
        malware detecting YOUR sandbox
    (2. Signal families)
      Properties
        ro.kernel.qemu = 1
        ro.hardware = ranchu
        ro.boot.* from bootconfig not cmdline
        ro.build.characteristics = emulator
        read via trie in shared memory
        NO IPC - so no server to intercept
        boottime_prop invisible to apps
      Build fields
        latched at class-init
        getter hook is TOO LATE
        FINGERPRINT generic is DEAD
        SUPPORTED_ABIS is HARD
      Filesystem
        qemu_pipe DEAD
        goldfish_pipe_dprctd is the real node
        goldfish_sync, goldfish_address_space
        exists loses errno
        ENOENT vs EACCES are different answers
      Sensors
        41 real vs 18 emulated
        0/41 vs 18/18 AOSP-vendored
        a POPULATION not a value
        faking = inventing a bill of materials
      Structural
        ABI mismatch x86 + ARM
        native bridge libndk_translation
        CPUID hypervisor bit
        guest cannot clear it
      Attestation
        the only off-device root of trust
        emulator = SOFTWARE, empty hardwareEnforced
        chain still verifies - check the LEVEL
    (3. Nine DEAD checks)
      /dev/qemu_pipe
      /dev/socket/qemud
      /system/bin/qemu-props
      libc_malloc_debug_qemu.so
      FINGERPRINT contains generic
      MODEL contains Emulator
      operator name Android
      IMEI and line-1 number
      proc tty/drivers, cmdline, modules
    (4. Four inverted checks)
      any qemu-named property
        2 on the REAL Redmi, 0 on the AVD
      emulators are slower
        AVD 2.398 vs phone 3.516 ns/iter
        1.47x FASTER
      fewer features means emulator
        AVD 96, phone 88
      BOOTLOADER unknown
        true on BOTH
    (5. Grading)
      HARD costly, survives a Java hook
      SOFT one hook or one resetprop
      DEAD measured never to fire
      NOISY fires on real devices
      INFO context only
      a flat checklist implies all are equal
    (6. The shell is not an app)
      properties root ~1062 shell ~678 app ~638
      phone shell 863 vs app 816
      proc/modules readable by shell, EACCES for app
      boottime_prop blocked by SELinux type
      prove reachability from an APP
    (7. Attacking)
      run on a stock AVD FIRST
      read the logs
      TRACE before hooking
      spawn -f never attach -p
      lowest altitude that works
      exercise the SENSITIVE flow
      short-circuit hides later checks
      inlining defeats a perfect hook
      test the SERVER
    (8. Defending)
      evidence not a boolean
      keep provenance - WHICH signals
      weighted score, threshold
      never let NOISY alone cross it
      server decides, client reports
      attestation + server nonce
      CI positive test vs a real AVD
      report-only mode first
    (9. Severity)
      depends on what the SERVER does
      DEAD check IS a finding
      false positive IS a finding
      bypass alone is NOT a finding
      no detection + trusted client flag = HIGH
    (10. Tooling)
      examples/emu_probe.c - native, errno-aware
      examples/EmulatorSignals.java - app-uid view
      scripts/emu-signal-map.py - static, graded
      scripts/emu-trace.js - which signal FIRES
      scripts/emu-bypass.js - selective, one family
      scripts/harden-avd.sh - environment side
      scripts/build-probe-app.sh - no Gradle
    (11. Traps)
      16 KiB page SIGSEGV before main
        needs -Wl,-z,max-page-size=16384
      Build fields latched
      MSYS path mangling on adb push
      a string is not a check
      analytics SDKs read ro.hardware too
      re-signing trips chapter 38
```

---

## How to read this map

The map is organised as an argument, not a list, and it is worth following in order.

**Branches 1–2** are the mechanism: what an emulator is, and where each observable signal physically
comes from. Note the two facts that shape everything downstream — properties are read from a
read-only shared mapping with *no server in the path*, so hooking the reader is the only interception
point; and `Build` fields are latched at class-initialisation, so the obvious hook is too late.

**Branches 3–4** are the chapter's most useful contribution, and they exist because the material was
measured rather than copied. Nine of the most-published checks do not fire on a current emulator, and
four widely-repeated rules are not merely weak but *backwards* — they classify the real phone as an
emulator and the emulator as a phone.

**Branch 5** is the vocabulary that makes the rest usable. A flat checklist silently implies every
entry is worth the same. Grading is what turns forty signals into a ranked set you can reason about.

**Branch 6** is the methodology trap that catches almost everyone: `adb shell` is uid 2000 in a
different SELinux domain and can see strictly more than an app. Every "an app can read X" claim in
this chapter was produced by running an actual app.

**Branches 7–9** are the two perspectives the grading serves — attacking and defending — and then the
question that decides what any of it is worth: what does the server do when the check is absent?

**Branches 10–11** are the instruments and the ways they bite.

---

## The one-sentence version

Emulator detection is the accumulation of cheap, individually forgeable observations into a judgement
that is expensive to forge as a **set** — and the discipline's published checklists have rotted badly
enough that measuring them is the first thing you should do, not the last.

---

## Related chapters

```mermaid
flowchart TB
    C39["39-EmulatorDetection<br/>the signals"]

    C37["37-RootDetection<br/>the sibling control"]
    C38["38-TamperDetection<br/>owns the controls"]
    C67["67-BypassingProtections<br/>owns the method"]
    C50["50-HardwareBackedSecurity<br/>attestation"]
    C22["22-SELinux<br/>why boottime_prop hides"]
    C62["62-Magisk<br/>resetprop"]
    C69["69-MalwareAnalysis<br/>adversary reversed"]
    C53["53-Frida"]
    C65["65-Hooking<br/>inlining"]
    C18["18-ARM<br/>the patch that did nothing"]
    C60["60-ADB<br/>shell is not an app"]

    C37 -->|"same trust boundary,<br/>disjoint signals"| C39
    C38 -->|"threat T-C,<br/>environment half"| C39
    C39 -->|"signals feed<br/>the method"| C67
    C39 -->|"the only signal<br/>that holds"| C50
    C22 -->|"property contexts"| C39
    C62 -->|"ro. is not<br/>a boundary"| C39
    C39 -->|"same signals,<br/>defender detects"| C69
    C53 --> C39
    C65 -->|"a hook can<br/>change nothing"| C39
    C18 -->|"inlined check<br/>survives a patch"| C39
    C60 -->|"prove it<br/>from an app"| C39

    style C39 fill:#f9d0d0
```

The diagram shows the chapter's two hard boundaries, which are worth stating plainly because they are
easy to trip over.

**37 and 39 are siblings, not duplicates.** They share a trust boundary — the user is the adversary —
and almost no signals. Root detection reads `su`, Magisk artefacts and mount state; emulator
detection reads virtual hardware. The only overlap is the NOISY "this is not a retail image" family
(`test-keys`, `userdebug`), which belongs to neither.

**39 owns the signals; 67 owns the method.** This chapter bypasses signals only to prove they are
load-bearing. The escalation ladder, the altitude vocabulary and the question of what to do when an
app fights back all live in 67.

The arrows *into* 39 are the chapters that explain why a signal behaves as it does: 22 for the SELinux
property contexts that hide `boottime_prop` from apps, 62 for why `ro.` immutability is not a
security boundary, 60 for the shell-versus-app distinction, and 18 and 65 for the two independent
measurements of why a perfectly installed hook can change nothing at all.
