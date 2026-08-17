# 73 — Labs · Mind map

One map of the whole chapter. Prose in [README.md](README.md), commands in
[cheatsheet.md](cheatsheet.md).

```mermaid
mindmap
  root((73 Labs<br/>the aggregator))
    Why it exists
      327 labs across 79 chapters
      No chapter can see the others
      Concatenation adds length not facts
      Six things only an aggregator can do
        generated index
        learning paths
        the environment honestly
        how to build a lab
        what to do when it fails
        cross-chapter labs
    FIND
      Index is generated never written
        parsed from every NN/labs/*.md
        four header formats because the corpus uses four
        6 labs declare no difficulty
          reported as unstated not guessed
        rebuild command in the file banner
      Groupings
        by chapter reading order
        by difficulty band
        by requirement with evidence line
        learning paths
      Requirement derivation
        a tag is a command or a prerequisites line
        NOT a mention
        header denial wins outright
        optional phrasing skipped
        prose only for physical
        chapter tool inherited
      Link depth
        labs and references are TWO levels down
        ../../NN-Chapter/README.md
        verify by resolving not by eye
        one-level form once cost 1495 broken links
    ROUTE
      Five paths each with a rule
        two weeks no Android
        interview ready
        emulator only
          8 physical labs are unanswerable not hard
        native RE
          do not start at Ghidra
        no device at all
          58 labs never touch adb
      Chapter order is curated
      Lab lists are generated
        a path cannot name a deleted lab
    RUN
      Probe both ends
        host tool must EXECUTE not merely be found
        device identity before any claim
      The su form
        AVD takes su 0 cmd
        Magisk takes su -c cmd
        unquoted adb-shell su-dash-c is broken everywhere
        wrong form reads as not rooted
      Frida spans two machines
        host 16.1.6 fine
        server CANNOT LINK
        frida-ps still enumerates
        blocks 128 of 327 here
      Measured on the AVD
        API 35 x86_64 userdebug
        SELinux Enforcing
        16 KiB pages
        Magisk 30.7 Zygisk off
        no bootloader partitions
      140 of 327 runnable on the AVD
        re-measured 173 of 327 after the probe was fixed
        probe had missed apktool and Ghidra off PATH
        four downloads take it to 288
        emulator accounts for 8 blocks only
    BUILD
      Sources never binaries
      Out of tree under OUTDIR
      aapt2 link javac d8 zipalign apksigner
      Key generated per build never committed
      Write order is not reading order
        success criteria first
        measured outputs second
        steps derived backwards
      Validate mechanically
        why header vs derived
        verify-links
        lint-commands target 0 ERROR
        control bytes and BOM at byte level
      You cannot proofread your own environment
    FAIL
      Most common reader experience
      Ranked causes
        vantage
        device or version
        su form
        tool version
        a command that succeeded and did nothing
        the lab is wrong
      Outputs that prove nothing
        Broadcast completed result=0
        Starting Intent
        host tool version
        ["which() finding a file"]
      Verdicts
        HYPOTHESIS never final
        CONFIRMED with a vantage
        REFUTED only if it could have worked
        NOT TESTED beats silence
        DIVERGED cause not established
      Change nothing until you know why
    VANTAGE
      app 10xxx the only real attacker model
      shell 2000 neither app nor root
      root 0
      the app itself
      Same command opposite outcome identical output
      Name it in every claim
    LABS
      01 capability survey
        your machine against the corpus
      02 the chain
        static to dynamic to report
        one finding dies two change severity
      03 write a lab that survives
        validate with the generator
      04 CTF the gauntlet
        five flags five chapters
        every flag has a decoy that arrives first
        no Frida required
```

---

## How to read this map

**The five verbs are the chapter.** FIND, ROUTE, RUN, BUILD, FAIL — everything else hangs off one of
them, and each corresponds to a question a reader actually arrives with.

**The branches that repeat are the ones that matter.** *Vantage* appears under RUN, FAIL and as its
own branch, because it is the most repeated methodology error in this repository. *Evidence* appears
under FIND (the index's evidence lines), BUILD (measured outputs) and FAIL (what proves nothing) for
the same reason: the chapter is largely about the difference between a claim and its support.

**The counts are timestamped, not constant.** 327 labs, 140 runnable, 128 blocked on Frida — all
measured on 2026-08-16 on one machine. Re-run `--stats` and `--match`; a generated number is a
measurement, and comparing your shape against this one is more useful than matching digits.
