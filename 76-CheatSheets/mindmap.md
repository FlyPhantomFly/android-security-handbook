# 76 — Cheat Sheets · Mind map

One map of the whole chapter. The three branches on the left are what this chapter *contains*; the
three on the right are what it *guards against*.

```mermaid
mindmap
  root((76 · Cheat Sheets))
    Why this chapter is not a concatenation
      78 sheets
      29,189 lines
      1,198 H2 sections
      747 fenced blocks
      A copy has no link to its source
      Stale on the first chapter edit
      Unnavigable at that size
      So ship a ROUTER, not a COPY
    The generated router
      build-cheatsheet-index.py
        --by chapter
        --by task
        --by tool
        --stats
        --check
        --verify-links
      Parses H2, fences, tables
      Copies nothing
      1,628 links emitted
      0 broken after verification
      Two levels down means ../../
      Quoting text with links IS a link operation
    Task sheets
      I have an APK and one hour
        hash then manifest then traffic then code
        jadx is where the hour disappears
      I am on an unrooted device
        run-as needs DEBUGGABLE and an app uid
        Gadget instead of server
        am instrument gated by SIGNATURE
      I have only an emulator
        no bootloader at all
        every key SOFTWARE, chain still verifies
        verifiedbootstate is the EMPTY STRING
        16 KiB pages, exit 139
      The app detects my hook
        find the check before bypassing
        inlined target, zero call sites
        objection root disable covers 1 of 5
      I need to see the traffic
        stop at the first layer that explains silence
        check mount grep cacerts FIRST
      I need to prove this finding
        who, with what, from an app uid
        server compensation
        business impact in one sentence
      Nothing works
        debug the tool before the app
        liveness check before silence means anything
    Every row carries its preconditions
      Needs
        any
        dbg
        root
        sig
        host
      Device
        all
        avd
        avd differs
        phys
        unrun
      A row without them assumes one silently
    Vantage, the repeated finding
      shell 678 properties
      app 638 properties
      root 1,062 properties
      ro.boottime 0 · 0 · 111
      File.exists collapses absent, forbidden, invisible
      Same answer everywhere is a BETTER signal
      vantage.sh runs all three
    The corrections
      su -c fails or eats its own flags
      su 0 magisk needs the absolute path
      frida-ps -U proves adb, not Frida
      FLAG_SECURE folds to 0x2000
      grep -i xposed is 100% false positive
      am start needs -S
      getCallingUid in onBind is your own uid
      TracerPid misses JDWP
      a valid chain proves the chain
      fastboot silence is success
      MSYS rewrites device paths on Git Bash
    The linter
      lint-commands.py
      8 rules, all measured
      --self-test 38 cases, 0 failures
      lint:allow, per line or per fence
      Reports, never edits
      376 su -c lines across 146 files
      Published detector saw 79 of them
    Misuse to avoid
      Sheet instead of chapter
      Copying an unrun command
      Index generated at the wrong depth
      Reading the router as a summary
      Assuming the sheet's device
      Hearing "bypass succeeded" as "protection defeated"
```

## How the parts fit together

```mermaid
flowchart TB
    subgraph Sources["The 76 chapter sheets — the source of truth"]
        S1["10-APK-Internals/cheatsheet.md"]
        S2["33-Storage/cheatsheet.md"]
        S3["… 74 more"]
    end

    subgraph Gen["76-CheatSheets — generated, never transcribed"]
        G["build-cheatsheet-index.py"]
        R1["references/cheatsheet-index.md"]
        R2["…-by-task.md"]
        R3["…-by-tool.md"]
        V["--verify-links: resolve every emitted path"]
    end

    subgraph Written["76-CheatSheets — written here, owned here"]
        T["Task sheets — cross-chapter, chapter-shaped sheets cannot hold these"]
        C["Corrections — where the obvious command lies"]
        L["lint-commands.py — the repo's own broken forms"]
    end

    S1 --> G
    S2 --> G
    S3 --> G
    G --> R1
    G --> R2
    G --> R3
    R1 --> V
    R2 --> V
    R3 --> V
    S1 -. "read, not copied" .-> T
    C --> L
    L -. "reports, never edits" .-> Sources

    style G fill:#d0e8f9
    style V fill:#d9f2d0
    style L fill:#f9d0d0
```

The arrow that matters is the dotted one from the sheets to the task sheets: **read, not copied.**
Everything generated flows one way, from the chapters into `references/`, and can be rebuilt from
nothing. Everything written here is content no chapter owns. Nothing in this chapter is a duplicate
of anything in a chapter, which is why nothing here can go stale independently of its source.

The red box is the linter. It points back at the sources because that is where the defects are — and
it points with a dotted arrow because it **reports and never edits**. Two agents writing to one file
is how a repository loses content.

## The decision the chapter is built on

```mermaid
flowchart LR
    Q{"You want a command"}
    Q -->|"you know the chapter"| A["that chapter's cheatsheet.md"]
    Q -->|"you know the tool"| B["references/…-by-tool.md"]
    Q -->|"you know the task"| C["section 4, or …-by-task.md"]
    Q -->|"a tool just printed something"| D["section 6 — corrections"]
    Q -->|"you do not understand it yet"| E["the CHAPTER, not a sheet"]

    style E fill:#f9d0d0
```

The red terminal is the one people take by mistake. A cheat sheet read by someone who has not
understood the underlying mechanism is a list of magic words, and the output it produces cannot be
interpreted — which is how a `Job: … sslpinning disable` line ends up in a report as evidence that
an app pins.
