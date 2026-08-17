# 59 — radare2 mind map

A single map of the whole chapter. Use it to check recall: cover a branch and try to reconstruct it.

```mermaid
mindmap
  root((radare2))
    1 Why it exists
      Corpus scale problem
        480 libraries one question
        clicking is not a strategy
      No display
        SSH into a jump host
        binary cannot leave the network
      On the device
        packer drops a library
        payload exists only in memory
      Framework not application
        libraries first shell on top
        explains the command language
    2 The grammar
      Root verbs
        a analyse
        i info
        p print
        s seek
        w write
        f flag
        e eval
        S sections
        V visual
      Narrowing letters
        l list
        f function
        x xrefs
        z strings
        E exports
      Suffixes
        j JSON the scripting suffix
        q quiet
        star replayable commands
        question help for this subtree
      Operators
        at sign temporal seek
        double at iterate
        tilde internal grep
        pipe to shell
      The key insight
        question mark on any prefix
        derive never memorise
    3 Cost model
      Parse is cheap
        bounded by symtab size
        rabin2 never decodes code
        imports exports strings sections
      Analysis is expensive
        bounded by text size
        aa aaa aaaa ladder
        af for one function only
      Measured
        10 of 11 stripped
        libc kept 2667 symbols
        libsqlite 414k insns 364 names
        libhwui 6.3MB code 1080 names
        floor 210k to 281k insns per sec
      Decision rule
        no xrefs needed run nothing
        one function seek then af
        whole binary xrefs then aaa
    4 Commands that matter
      axt xrefs to
        complete list via PLT stub
        blind without analysis
        blind to indirect calls
        a lower bound never an inventory
      iz strings
      ii imports capabilities
      iE exports attack surface
      iS init array runs at load
      pdf disassemble function
      VV graph shape recognition
        tree is normal
        wheel is flattening
    5 Android specifics
      JNI offsets are names
        0x30 FindClass
        0x6b8 RegisterNatives
        spec fixes the order
      Static registration
        Java underscore exports
        can be a single tail call
      Dynamic registration
        only JNI_OnLoad exported
        table in data rel ro
        signatures start with paren
        implementing function unnamed
      DEX support real limits
        Dalvik bytecode not Java
        no multi dex xrefs
        use JADX instead
      Runs on the phone
        Termux or push a static build
        16 KiB pages need the link flag
        execve may be blocked
    6 Scripting
      r2pipe spawns r2
        cmd returns text
        cmdj returns JSON
        no FFI no bindings
      Corpus triage
        structural only
        dedup by sha256
        diff against baseline
      Fail loudly
        empty report equals false negative
        exit non zero
    7 Patching
      r2 -w edits in place
        no undo no backup
        copy first
      io.cache is the undo
        wci commits
      wa wx wao
      vaddr is not file offset
        per section delta
      Patch the decision
        not the check
        read the caller first
    8 Measured findings
      O2 folded the XOR away
        plaintext shipped
        O0 hid it
        volatile key held
      Patch changed nothing
        upstream guard short circuits
        18-ARM found inlining
        same symptom two mechanisms
      Stock AVD ships su
        setuid root at system xbin
      Correct key alone insufficient
    9 Ecosystem
      rizin fork
        same grammar
        rz-bin rz-diff rzpipe
      Cutter is rizin GUI
      r2ghidra gives pdg
        pdc is not a decompiler
      r2frida live memory
        defeats packing
        dxc calls functions
    10 Limits
      No native decompiler
      Weak C plus plus recovery
      Command set moves
      Learning curve is front loaded
      Static xrefs are a lower bound
```

---

## How the pieces connect

The map above is a hierarchy, but the chapter's actual logic is a chain. If you can narrate this
chain unaided, you understand the chapter:

```mermaid
flowchart TD
    A["A stripped .so:<br/>414,397 instructions, 364 names"] --> B["Nothing records where<br/>functions begin"]
    B --> C["Analysis must INVENT<br/>the structure"]
    C --> D["That cost is bounded by<br/>.text size, not file size"]
    D --> E{"Does my question need<br/>the call graph?"}
    E -->|No| F["rabin2 / i-commands<br/>Seconds across hundreds of files"]
    E -->|Yes| G["aaa, once, then save<br/>a project"]
    F --> H["Most triage questions<br/>end here"]
    G --> I["axt: the highest-value<br/>security command"]
    I --> J["...but it is a LOWER BOUND<br/>indirect calls are invisible"]
    J --> K["Confirm at runtime:<br/>Frida or r2frida"]

    style F fill:#d0f9d0
    style H fill:#d0f9d0
    style J fill:#f9d0d0
```

Read that from the top. The stripped binary forces invention; invention costs time proportional to
code size; therefore the first question is always *"do I need this at all?"*, and the honest answer
is usually no. When the answer is yes, `axt` is what you bought — and even then its output is a
floor, not a census, which is why the chain ends at runtime rather than at a conclusion.

---

## The two failure modes, side by side

These are the chapter's measured findings and the two most expensive mistakes in the topic.

```mermaid
flowchart LR
    subgraph One["Obfuscation the compiler deleted"]
        A1["Source XORs a string<br/>with a constant key"] --> A2["Both operands are<br/>compile-time constants"]
        A2 --> A3["clang -O2 folds<br/>the whole loop"]
        A3 --> A4["Plaintext in .rodata<br/>strings finds it"]
        A5["-O0 build of<br/>identical source"] --> A6["Loop survives<br/>string hidden"]
        A4 --> A7["Fix: volatile key<br/>breaks the fold chain"]
    end
    subgraph Two["The patch that did nothing"]
        B1["Patch lt_verify_license<br/>to return 1"] --> B2["Bytes verified correct"]
        B2 --> B3["Behaviour unchanged"]
        B3 --> B4["Caller runs a root probe<br/>FIRST and returns early"]
        B4 --> B5["The patched function<br/>is never reached"]
        B5 --> B6["Diagnosis: axt, then<br/>read the caller"]
    end
    style A4 fill:#f9d0d0
    style B3 fill:#f9d0d0
    style A7 fill:#d0f9d0
    style B6 fill:#d0f9d0
```

The left branch inverts an assumption everybody holds: **higher optimisation made the secret more
visible**, because the optimiser is entitled to evaluate a constant expression and does not know it
was load-bearing.

The right branch is the same symptom this repository already recorded from a different cause. In
[18-ARM](../18-ARM/README.md) §5.4 the check had been *inlined*, so the standalone copy was dead
code. Here it is *short-circuited* by an earlier guard. Two mechanisms, one symptom, one diagnosis:
**read the caller before you patch the callee.**

---

## Quick revision prompts

Cover the answers and work down the list.

| Prompt |
|---|
| Name the seven root verbs and say what `?` does after any prefix. |
| Why is `rabin2 -i` fast on a 13 MB library when `aaa` is not? |
| What does `sym.imp.access` actually name, and why does that make `axt` on it useful? |
| Name `axt`'s two blind spots. |
| What is at `JNIEnv` offset `0x6b8`, and how would you know without a reference? |
| A library exports only `JNI_OnLoad`. Give the static route and the dynamic route to its natives. |
| Why did `/system/xbin/su` appear in the `-O2` build and not the `-O0` build? |
| Which one-word change fixed it, and why does that word work? |
| You patched a check to return 1 and nothing changed. Name two mechanisms. |
| Convert vaddr `0x4854` to a file offset given `.text` at vaddr `0x4794`, offset `0x794`. |
| Which command stages writes, and which commits them? |
| Write a command that disassembles every function whose name contains `lt_`. |
| Name three things radare2 does that Ghidra and IDA cannot. |
| What shape does a control-flow-flattened function make in `VV`? |
| Why must a corpus scanner exit non-zero when its tools are missing? |
