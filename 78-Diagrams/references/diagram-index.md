<!-- GENERATED FILE. Do not edit by hand.
     Rebuild with:  python3 -B scripts/diagram-census.py
     Source: every fenced ```mermaid block in every .md file in this repository,
     plus every standalone .mmd source file. -->

# Diagram index — by chapter

Built mechanically by [`scripts/diagram-census.py`](../scripts/diagram-census.py).

This index deliberately does **not** reproduce the diagrams. A diagram copied out of
its chapter loses the prose that STYLE-GUIDE.md requires to sit beside it, and goes
stale the moment the original is edited. What you get here is the location, the shape,
and the size — enough to decide whether to open it.

Columns: **Type** is the Mermaid diagram family. **Nodes** is a crude count of distinct
node, participant or class identifiers — a size signal, not an analysis. **Boundaries**
counts `subgraph` blocks, which is how this repository draws a trust boundary. **Atk**
marks a diagram that colours attacker-controlled input `#f9d0d0`, the convention in
STYLE-GUIDE.md section 6.


**824 diagrams across 188 files in 83 chapters.**


## (root) (2)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | Learning path | flowchart | 14 | 0 |  | [README.md:46](../../README.md#learning-path) |
| 2 | 6. Diagram conventions | flowchart | 5 | 2 | yes | [STYLE-GUIDE.md:227](../../STYLE-GUIDE.md#6-diagram-conventions) |

## 00-Introduction (11)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The map of the whole field | flowchart | 29 | 6 |  | [README.md:197](../../00-Introduction/README.md#21-the-map-of-the-whole-field) |
| 2 | 2.2 Where the attacker sits relative to the app | flowchart | 22 | 8 | yes | [README.md:250](../../00-Introduction/README.md#22-where-the-attacker-sits-relative-to-the-app) |
| 3 | 2.3 What a typical engagement looks like as a sequence | sequence | 5 | 0 |  | [README.md:336](../../00-Introduction/README.md#23-what-a-typical-engagement-looks-like-as-a-sequence) |
| 4 | 2.4 The learning state machine | state | 0 | 0 |  | [README.md:372](../../00-Introduction/README.md#24-the-learning-state-machine) |
| 5 | 3.2 The career ladder | flowchart | 10 | 0 |  | [README.md:439](../../00-Introduction/README.md#32-the-career-ladder) |
| 6 | Magisk: the systemless approach | flowchart | 6 | 0 |  | [README.md:1413](../../00-Introduction/README.md#magisk-the-systemless-approach) |
| 7 | Decision flow | flowchart | 11 | 0 | yes | [README.md:1683](../../00-Introduction/README.md#decision-flow) |
| 8 | 5.5 How to actually study this repository | flowchart | 9 | 0 |  | [README.md:2280](../../00-Introduction/README.md#55-how-to-actually-study-this-repository) |
| 9 | 8.1 The order of operations | flowchart | 10 | 0 |  | [README.md:2617](../../00-Introduction/README.md#81-the-order-of-operations) |
| 10 | 13.2 Chapter mind map | mindmap | 1 | 0 |  | [README.md:3237](../../00-Introduction/README.md#132-chapter-mind-map) |
| 11 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:7](../../00-Introduction/mindmap.md) |

## 01-Computer-Science-Basics (25)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The stack from transistor to app | flowchart | 24 | 5 | yes | [README.md:196](../../01-Computer-Science-Basics/README.md#21-the-stack-from-transistor-to-app) |
| 2 | 2.2 What one function call actually costs | block layout | 12 | 0 |  | [README.md:307](../../01-Computer-Science-Basics/README.md#22-what-one-function-call-actually-costs) |
| 3 | 2.3 A process's address space | block layout | 13 | 0 |  | [README.md:345](../../01-Computer-Science-Basics/README.md#23-a-processs-address-space) |
| 4 | 2.4 The lifetime of one instruction | sequence | 8 | 0 |  | [README.md:393](../../01-Computer-Science-Basics/README.md#24-the-lifetime-of-one-instruction) |
| 5 | 2.5 Trust boundaries | flowchart | 14 | 5 | yes | [README.md:444](../../01-Computer-Science-Basics/README.md#25-trust-boundaries) |
| 6 | 3.6 What a CPU does: fetch, decode, execute | state | 0 | 0 |  | [README.md:935](../../01-Computer-Science-Basics/README.md#36-what-a-cpu-does-fetch-decode-execute) |
| 7 | 3.11 Kernel space, user space, privilege rings and exception levels | flowchart | 10 | 2 | yes | [README.md:1298](../../01-Computer-Science-Basics/README.md#311-kernel-space-user-space-privilege-rings-and-exception-levels) |
| 8 | 3.12 Processes: address space, PID, and the process control block | flowchart | 11 | 1 |  | [README.md:1412](../../01-Computer-Science-Basics/README.md#312-processes-address-space-pid-and-the-process-control-block) |
| 9 | 3.12 Processes: address space, PID, and the process control block | state | 6 | 0 |  | [README.md:1437](../../01-Computer-Science-Basics/README.md#312-processes-address-space-pid-and-the-process-control-block) |
| 10 | 3.13 `fork`, `exec`, and why Zygote exists | sequence | 4 | 0 |  | [README.md:1501](../../01-Computer-Science-Basics/README.md#313-fork-exec-and-why-zygote-exists) |
| 11 | 3.13.1 Zygote: `fork` without `exec` | sequence | 4 | 0 |  | [README.md:1590](../../01-Computer-Science-Basics/README.md#3131-zygote-fork-without-exec) |
| 12 | 3.16 The stack, in full | block layout | 15 | 0 |  | [README.md:1830](../../01-Computer-Science-Basics/README.md#316-the-stack-in-full) |
| 13 | 3.17 The heap, in full | flowchart | 15 | 0 | yes | [README.md:1992](../../01-Computer-Science-Basics/README.md#317-the-heap-in-full) |
| 14 | 3.18.1 Pages and page tables | flowchart | 8 | 0 | yes | [README.md:2183](../../01-Computer-Science-Basics/README.md#3181-pages-and-page-tables) |
| 15 | 3.19 System calls | sequence | 4 | 0 |  | [README.md:2410](../../01-Computer-Science-Basics/README.md#319-system-calls) |
| 16 | 3.23 ELF: the container for all native code | block layout | 15 | 0 |  | [README.md:2795](../../01-Computer-Science-Basics/README.md#323-elf-the-container-for-all-native-code) |
| 17 | 3.24 The compilation pipeline | flowchart | 8 | 0 | yes | [README.md:2890](../../01-Computer-Science-Basics/README.md#324-the-compilation-pipeline) |
| 18 | 3.25 Static versus dynamic linking | sequence | 5 | 0 |  | [README.md:2999](../../01-Computer-Science-Basics/README.md#325-static-versus-dynamic-linking) |
| 19 | 4.2 Trace one: `open()` in Java reaches the kernel | sequence | 6 | 0 |  | [README.md:3153](../../01-Computer-Science-Basics/README.md#42-trace-one-open-in-java-reaches-the-kernel) |
| 20 | 4.3 Trace two: an app process is born | sequence | 6 | 0 |  | [README.md:3193](../../01-Computer-Science-Basics/README.md#43-trace-two-an-app-process-is-born) |
| 21 | 7. Dynamic Analysis | flowchart | 12 | 0 |  | [README.md:3691](../../01-Computer-Science-Basics/README.md#7-dynamic-analysis) |
| 22 | 13.2 Chapter mind map | mindmap | 1 | 0 |  | [README.md:4806](../../01-Computer-Science-Basics/README.md#132-chapter-mind-map) |
| 23 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:13](../../01-Computer-Science-Basics/mindmap.md) |
| 24 | Part C — Reading `/proc/<pid>/maps` | block layout | 13 | 0 |  | [labs/lab-02-processes-memory-maps.md:355](../../01-Computer-Science-Basics/labs/lab-02-processes-memory-maps.md#part-c--reading-procpidmaps) |
| 25 | Part B — Read the prologue and epilogue | block layout | 10 | 0 |  | [labs/lab-03-stack-frames-and-overflow.md:299](../../01-Computer-Science-Basics/labs/lab-03-stack-frames-and-overflow.md#part-b--read-the-prologue-and-epilogue) |

## 02-Linux-Basics (18)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The layers between your keystroke and the hardware | flowchart | 21 | 3 | yes | [README.md:145](../../02-Linux-Basics/README.md#21-the-layers-between-your-keystroke-and-the-hardware) |
| 2 | 2.2 Process creation: what actually happens when you type `ls` | sequence | 5 | 0 |  | [README.md:190](../../02-Linux-Basics/README.md#22-process-creation-what-actually-happens-when-you-type-ls) |
| 3 | 2.3 The Android filesystem at a glance | flowchart | 22 | 0 | yes | [README.md:228](../../02-Linux-Basics/README.md#23-the-android-filesystem-at-a-glance) |
| 4 | 2.4 Trust boundaries expressed as UIDs | flowchart | 23 | 6 | yes | [README.md:265](../../02-Linux-Basics/README.md#24-trust-boundaries-expressed-as-uids) |
| 5 | The problem the inode solves | flowchart | 10 | 2 |  | [README.md:528](../../02-Linux-Basics/README.md#the-problem-the-inode-solves) |
| 6 | How an app gets its UID: the install flow | sequence | 5 | 0 |  | [README.md:730](../../02-Linux-Basics/README.md#how-an-app-gets-its-uid-the-install-flow) |
| 7 | The complete access decision on Android | flowchart | 13 | 0 | yes | [README.md:983](../../02-Linux-Basics/README.md#the-complete-access-decision-on-android) |
| 8 | `fork()`, `execve()`, `wait()`, `exit()` — the process lifecycle | state | 7 | 0 |  | [README.md:1051](../../02-Linux-Basics/README.md#fork-execve-wait-exit--the-process-lifecycle) |
| 9 | Android's twist: Zygote instead of fork+exec | sequence | 5 | 0 |  | [README.md:1075](../../02-Linux-Basics/README.md#androids-twist-zygote-instead-of-forkexec) |
| 10 | Signals and debugging — the part that matters for Android RE | sequence | 3 | 0 |  | [README.md:1374](../../02-Linux-Basics/README.md#signals-and-debugging--the-part-that-matters-for-android-re) |
| 11 | Pipes | flowchart | 6 | 0 |  | [README.md:1500](../../02-Linux-Basics/README.md#pipes) |
| 12 | How Android replaces most of this with Binder | flowchart | 19 | 3 | yes | [README.md:1606](../../02-Linux-Basics/README.md#how-android-replaces-most-of-this-with-binder) |
| 13 | The dynamic linker, and why `LD_PRELOAD` is a hooking primitive | flowchart | 12 | 0 | yes | [README.md:2013](../../02-Linux-Basics/README.md#the-dynamic-linker-and-why-ld_preload-is-a-hooking-primitive) |
| 14 | How Magisk uses all of this | flowchart | 17 | 3 | yes | [README.md:2263](../../02-Linux-Basics/README.md#how-magisk-uses-all-of-this) |
| 15 | 4.4 Tracing one complete path: `File.exists()` down to the kernel | sequence | 6 | 0 |  | [README.md:2439](../../02-Linux-Basics/README.md#44-tracing-one-complete-path-fileexists-down-to-the-kernel) |
| 16 | 13.2 Chapter mind map | mindmap | 2 | 0 |  | [README.md:3440](../../02-Linux-Basics/README.md#132-chapter-mind-map) |
| 17 | _(no heading above it)_ | mindmap | 4 | 0 |  | [mindmap.md:5](../../02-Linux-Basics/mindmap.md) |
| 18 | The permission decision, as a flowchart | flowchart | 16 | 0 | yes | [labs/lab-01-filesystem-and-permissions.md:1269](../../02-Linux-Basics/labs/lab-01-filesystem-and-permissions.md#the-permission-decision-as-a-flowchart) |

## 03-Programming-Fundamentals (31)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The abstraction ladder | flowchart | 6 | 0 |  | [README.md:194](../../03-Programming-Fundamentals/README.md#21-the-abstraction-ladder) |
| 2 | 2.2 The four translation strategies | flowchart | 14 | 5 |  | [README.md:234](../../03-Programming-Fundamentals/README.md#22-the-four-translation-strategies) |
| 3 | 2.4 Anatomy of the pipeline that turns C into a running Android library | flowchart | 16 | 0 |  | [README.md:406](../../03-Programming-Fundamentals/README.md#24-anatomy-of-the-pipeline-that-turns-c-into-a-running-android-library) |
| 4 | 2.5 The Android version of the same pipeline | flowchart | 12 | 2 |  | [README.md:460](../../03-Programming-Fundamentals/README.md#25-the-android-version-of-the-same-pipeline) |
| 5 | 2.6 Where each concept in this chapter lands in the Android stack | mindmap | 4 | 0 |  | [README.md:497](../../03-Programming-Fundamentals/README.md#26-where-each-concept-in-this-chapter-lands-in-the-android-stack) |
| 6 | 3.1 Variables and memory — what a variable actually is | block layout | 13 | 0 |  | [README.md:584](../../03-Programming-Fundamentals/README.md#31-variables-and-memory--what-a-variable-actually-is) |
| 7 | 3.4.2 The worked example — an allocation size overflow | flowchart | 8 | 0 | yes | [README.md:852](../../03-Programming-Fundamentals/README.md#342-the-worked-example--an-allocation-size-overflow) |
| 8 | 3.6.2 What the CPU actually has | flowchart | 5 | 0 |  | [README.md:1156](../../03-Programming-Fundamentals/README.md#362-what-the-cpu-actually-has) |
| 9 | 3.8.3 The call stack, drawn | flowchart | 10 | 1 | yes | [README.md:1486](../../03-Programming-Fundamentals/README.md#383-the-call-stack-drawn) |
| 10 | 3.9.2 The linked list — flexible, scattered, pointer-chasing | flowchart | 5 | 0 |  | [README.md:1680](../../03-Programming-Fundamentals/README.md#392-the-linked-list--flexible-scattered-pointer-chasing) |
| 11 | 3.9.3 The stack — last in, first out | flowchart | 5 | 1 |  | [README.md:1737](../../03-Programming-Fundamentals/README.md#393-the-stack--last-in-first-out) |
| 12 | 3.9.4 The queue — first in, first out | flowchart | 5 | 0 |  | [README.md:1782](../../03-Programming-Fundamentals/README.md#394-the-queue--first-in-first-out) |
| 13 | 3.10.2 The idea | flowchart | 9 | 0 |  | [README.md:1855](../../03-Programming-Fundamentals/README.md#3102-the-idea) |
| 14 | 3.10.4 Collision resolution — the two real strategies | flowchart | 5 | 0 | yes | [README.md:1911](../../03-Programming-Fundamentals/README.md#3104-collision-resolution--the-two-real-strategies) |
| 15 | 3.10.7 Why this matters for DEX internals | flowchart | 10 | 2 |  | [README.md:2045](../../03-Programming-Fundamentals/README.md#3107-why-this-matters-for-dex-internals) |
| 16 | 3.11.1 Trees | flowchart | 7 | 0 |  | [README.md:2086](../../03-Programming-Fundamentals/README.md#3111-trees) |
| 17 | 3.11.2 Graphs | flowchart | 7 | 0 |  | [README.md:2131](../../03-Programming-Fundamentals/README.md#3112-graphs) |
| 18 | 3.14.1 The problem | flowchart | 7 | 0 | yes | [README.md:2434](../../03-Programming-Fundamentals/README.md#3141-the-problem) |
| 19 | 3.14.3 Garbage collection | flowchart | 10 | 2 | yes | [README.md:2483](../../03-Programming-Fundamentals/README.md#3143-garbage-collection) |
| 20 | 3.17.3 Exceptions | flowchart | 11 | 0 | yes | [README.md:2793](../../03-Programming-Fundamentals/README.md#3173-exceptions) |
| 21 | 3.18.1 Pure interpretation | sequence | 3 | 0 |  | [README.md:2898](../../03-Programming-Fundamentals/README.md#3181-pure-interpretation) |
| 22 | 3.18.2 Ahead-of-time compilation to native code | flowchart | 4 | 0 |  | [README.md:2923](../../03-Programming-Fundamentals/README.md#3182-ahead-of-time-compilation-to-native-code) |
| 23 | 3.18.4 JIT — compiling at run time | state | 0 | 0 |  | [README.md:2982](../../03-Programming-Fundamentals/README.md#3184-jit--compiling-at-run-time) |
| 24 | 3.18.5 Android's actual pipeline, end to end | flowchart | 16 | 2 |  | [README.md:3013](../../03-Programming-Fundamentals/README.md#3185-androids-actual-pipeline-end-to-end) |
| 25 | 3.19.2 The mental model: a DAG of snapshots | flowchart | 9 | 0 |  | [README.md:3121](../../03-Programming-Fundamentals/README.md#3192-the-mental-model-a-dag-of-snapshots) |
| 26 | 3.19.3 The three areas | flowchart | 4 | 0 |  | [README.md:3164](../../03-Programming-Fundamentals/README.md#3193-the-three-areas) |
| 27 | 4.3 The intern table — `art/runtime/intern_table.cc` and `intern_table.h` | sequence | 4 | 0 |  | [README.md:3315](../../03-Programming-Fundamentals/README.md#43-the-intern-table--artruntimeintern_tablecc-and-intern_tableh) |
| 28 | 8.1 The single most important pentester skill: reading code you did not write | flowchart | 8 | 0 | yes | [README.md:4079](../../03-Programming-Fundamentals/README.md#81-the-single-most-important-pentester-skill-reading-code-you-did-not-write) |
| 29 | 8.1.3 Move 3 — follow the state | flowchart | 7 | 0 | yes | [README.md:4160](../../03-Programming-Fundamentals/README.md#813-move-3--follow-the-state) |
| 30 | Mind map | mindmap | 1 | 0 |  | [README.md:5555](../../03-Programming-Fundamentals/README.md#mind-map) |
| 31 | _(no heading above it)_ | mindmap | 2 | 0 |  | [mindmap.md:5](../../03-Programming-Fundamentals/mindmap.md) |

## 04-Java (11)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 From source text to a running method | flowchart | 10 | 2 |  | [README.md:219](../../04-Java/README.md#21-from-source-text-to-a-running-method) |
| 2 | 2.2 What lives inside a class file | class | 4 | 0 |  | [README.md:265](../../04-Java/README.md#22-what-lives-inside-a-class-file) |
| 3 | 2.3 The runtime picture: where a Java object actually lives | block layout | 8 | 0 |  | [README.md:315](../../04-Java/README.md#23-the-runtime-picture-where-a-java-object-actually-lives) |
| 4 | 2.4 The lifecycle of a single method call | sequence | 4 | 0 |  | [README.md:351](../../04-Java/README.md#24-the-lifecycle-of-a-single-method-call) |
| 5 | 3.8 The collections framework | class | 3 | 0 |  | [README.md:777](../../04-Java/README.md#38-the-collections-framework) |
| 6 | `HashMap` internals — buckets, hashing, and collisions | flowchart | 12 | 0 |  | [README.md:844](../../04-Java/README.md#hashmap-internals--buckets-hashing-and-collisions) |
| 7 | 3.10 Exceptions | flowchart | 12 | 0 |  | [README.md:922](../../04-Java/README.md#310-exceptions) |
| 8 | Why attackers love reflection | sequence | 4 | 0 | yes | [README.md:1053](../../04-Java/README.md#why-attackers-love-reflection) |
| 9 | 4.3 What `setAccessible(true)` actually does | sequence | 5 | 0 |  | [README.md:1513](../../04-Java/README.md#43-what-setaccessibletrue-actually-does) |
| 10 | 13.2 The chapter as a map | mindmap | 1 | 0 |  | [README.md:2864](../../04-Java/README.md#132-the-chapter-as-a-map) |
| 11 | _(no heading above it)_ | mindmap | 0 | 0 |  | [mindmap.md:8](../../04-Java/mindmap.md) |

## 05-Kotlin (7)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The compilation pipeline, and where Kotlin inserts itself | flowchart | 12 | 1 |  | [README.md:190](../../05-Kotlin/README.md#21-the-compilation-pipeline-and-where-kotlin-inserts-itself) |
| 2 | 2.2 What the compiler adds to a class | class | 6 | 0 |  | [README.md:235](../../05-Kotlin/README.md#22-what-the-compiler-adds-to-a-class) |
| 3 | 2.3 Where Kotlin's guarantees live at runtime | flowchart | 15 | 3 | yes | [README.md:276](../../05-Kotlin/README.md#23-where-kotlins-guarantees-live-at-runtime) |
| 4 | 2.4 The lifecycle of a suspend function call | sequence | 4 | 0 |  | [README.md:316](../../05-Kotlin/README.md#24-the-lifecycle-of-a-suspend-function-call) |
| 5 | 4.4 Tracing one call end to end | sequence | 6 | 0 |  | [README.md:1324](../../05-Kotlin/README.md#44-tracing-one-call-end-to-end) |
| 6 | Mind map | mindmap | 1 | 0 |  | [README.md:2572](../../05-Kotlin/README.md#mind-map) |
| 7 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:14](../../05-Kotlin/mindmap.md) |

## 06-Android-Architecture (13)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The complete stack | flowchart | 42 | 8 | yes | [README.md:169](../../06-Android-Architecture/README.md#21-the-complete-stack) |
| 2 | 2.2 Trust boundaries | flowchart | 22 | 6 | yes | [README.md:278](../../06-Android-Architecture/README.md#22-trust-boundaries) |
| 3 | 2.3 The process view — what is actually running | flowchart | 24 | 6 |  | [README.md:343](../../06-Android-Architecture/README.md#23-the-process-view--what-is-actually-running) |
| 4 | 3.2.3 Project Treble and the system/vendor split | flowchart | 10 | 3 | yes | [README.md:620](../../06-Android-Architecture/README.md#323-project-treble-and-the-systemvendor-split) |
| 5 | 3.5 The Java API framework — what "the framework" actually is | flowchart | 13 | 3 | yes | [README.md:827](../../06-Android-Architecture/README.md#35-the-java-api-framework--what-the-framework-actually-is) |
| 6 | 3.7.1 The full sequence | sequence | 17 | 0 |  | [README.md:984](../../06-Android-Architecture/README.md#371-the-full-sequence) |
| 7 | 3.7.14 What a "soft reboot" actually is | flowchart | 10 | 0 |  | [README.md:1458](../../06-Android-Architecture/README.md#3714-what-a-soft-reboot-actually-is) |
| 8 | 3.8.2 `fork()` without `exec()` — what that actually means | sequence | 5 | 0 |  | [README.md:1540](../../06-Android-Architecture/README.md#382-fork-without-exec--what-that-actually-means) |
| 9 | 3.9.2 Why Zygote breaks that assumption | flowchart | 8 | 1 | yes | [README.md:1646](../../06-Android-Architecture/README.md#392-why-zygote-breaks-that-assumption) |
| 10 | 3.10.1 What it is and why it exists | flowchart | 14 | 4 |  | [README.md:1736](../../06-Android-Architecture/README.md#3101-what-it-is-and-why-it-exists) |
| 11 | 5.1 The layered trust model, stated precisely | flowchart | 8 | 0 | yes | [README.md:2287](../../06-Android-Architecture/README.md#51-the-layered-trust-model-stated-precisely) |
| 12 | Mind map | mindmap | 1 | 0 |  | [README.md:3013](../../06-Android-Architecture/README.md#mind-map) |
| 13 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:12](../../06-Android-Architecture/mindmap.md) |

## 07-AOSP (15)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 1.5 What is **not** in AOSP, and why it dominates security testing | flowchart | 24 | 4 | yes | [README.md:143](../../07-AOSP/README.md#15-what-is-not-in-aosp-and-why-it-dominates-security-testing) |
| 2 | 2.1 AOSP as a set of layers, mapped to directories | flowchart | 31 | 6 | yes | [README.md:237](../../07-AOSP/README.md#21-aosp-as-a-set-of-layers-mapped-to-directories) |
| 3 | 2.2 How the ~1000 repositories become one tree | flowchart | 19 | 3 |  | [README.md:300](../../07-AOSP/README.md#22-how-the-1000-repositories-become-one-tree) |
| 4 | 2.3 The trust boundaries visible in the source tree | flowchart | 25 | 5 | yes | [README.md:354](../../07-AOSP/README.md#23-the-trust-boundaries-visible-in-the-source-tree) |
| 5 | 2.4 Where a released device diverges from AOSP | flowchart | 8 | 0 | yes | [README.md:419](../../07-AOSP/README.md#24-where-a-released-device-diverges-from-aosp) |
| 6 | The procedure | flowchart | 18 | 0 |  | [README.md:631](../../07-AOSP/README.md#the-procedure) |
| 7 | 3.6 AIDL, and why every trace goes through it | sequence | 5 | 0 |  | [README.md:827](../../07-AOSP/README.md#36-aidl-and-why-every-trace-goes-through-it) |
| 8 | How enforcement works | flowchart | 11 | 0 | yes | [README.md:939](../../07-AOSP/README.md#how-enforcement-works) |
| 9 | 4.1 Trace A — `Context.startActivity()`, from your code to the kernel and back | sequence | 12 | 0 |  | [README.md:1274](../../07-AOSP/README.md#41-trace-a--contextstartactivity-from-your-code-to-the-kernel-and-back) |
| 10 | 4.2 Trace B — `SharedPreferences.edit().putString().apply()` to bytes on disk | flowchart | 35 | 0 |  | [README.md:1592](../../07-AOSP/README.md#42-trace-b--sharedpreferenceseditputstringapply-to-bytes-on-disk) |
| 11 | 4.3 Trace C — a permission check, from `checkSelfPermission` to the enforcement point | flowchart | 20 | 4 | yes | [README.md:1789](../../07-AOSP/README.md#43-trace-c--a-permission-check-from-checkselfpermission-to-the-enforcement-point) |
| 12 | Step 5 — where enforcement **actually** happens | flowchart | 11 | 0 | yes | [README.md:1944](../../07-AOSP/README.md#step-5--where-enforcement-actually-happens) |
| 13 | 5.3.4 Patch gapping — the bulletin as a vulnerability feed | flowchart | 8 | 0 | yes | [README.md:2385](../../07-AOSP/README.md#534-patch-gapping--the-bulletin-as-a-vulnerability-feed) |
| 14 | Mind map | mindmap | 1 | 0 |  | [README.md:3521](../../07-AOSP/README.md#mind-map) |
| 15 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:5](../../07-AOSP/mindmap.md) |

## 08-Build-System (17)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The two systems side by side | flowchart | 15 | 2 | yes | [README.md:180](../../08-Build-System/README.md#21-the-two-systems-side-by-side) |
| 2 | 2.2 The platform build graph | flowchart | 14 | 4 |  | [README.md:224](../../08-Build-System/README.md#22-the-platform-build-graph) |
| 3 | 2.3 The app build pipeline — the big diagram | flowchart | 46 | 7 | yes | [README.md:276](../../08-Build-System/README.md#23-the-app-build-pipeline--the-big-diagram) |
| 4 | 2.4 The trust boundaries of a build | flowchart | 15 | 3 | yes | [README.md:416](../../08-Build-System/README.md#24-the-trust-boundaries-of-a-build) |
| 5 | 2.5 Where each artefact ends up | block layout | 16 | 0 |  | [README.md:465](../../08-Build-System/README.md#25-where-each-artefact-ends-up) |
| 6 | 3.4 How SELinux policy is built | flowchart | 18 | 3 |  | [README.md:752](../../08-Build-System/README.md#34-how-selinux-policy-is-built) |
| 7 | 3.7 Gradle: the three phases | sequence | 6 | 0 |  | [README.md:873](../../08-Build-System/README.md#37-gradle-the-three-phases) |
| 8 | 3.9 Build variants: types, flavours, and source sets | flowchart | 18 | 4 |  | [README.md:1064](../../08-Build-System/README.md#39-build-variants-types-flavours-and-source-sets) |
| 9 | The priority order | flowchart | 6 | 0 | yes | [README.md:1146](../../08-Build-System/README.md#the-priority-order) |
| 10 | Play App Signing | sequence | 3 | 0 |  | [README.md:1508](../../08-Build-System/README.md#play-app-signing) |
| 11 | 3.15 Shrinking, obfuscation, and resource shrinking | flowchart | 16 | 1 |  | [README.md:1543](../../08-Build-System/README.md#315-shrinking-obfuscation-and-resource-shrinking) |
| 12 | 3.16 Resources: `aapt2` compile and link | flowchart | 13 | 0 |  | [README.md:1596](../../08-Build-System/README.md#316-resources-aapt2-compile-and-link) |
| 13 | 3.19 AAB, `bundletool`, splits and dynamic feature modules | flowchart | 8 | 0 |  | [README.md:1746](../../08-Build-System/README.md#319-aab-bundletool-splits-and-dynamic-feature-modules) |
| 14 | 4.4 Trace 2 — from `certificate: "platform"` to a signed APK on the image | sequence | 7 | 0 |  | [README.md:2048](../../08-Build-System/README.md#44-trace-2--from-certificate-platform-to-a-signed-apk-on-the-image) |
| 15 | 5.4 Supply-chain risk, in depth | flowchart | 18 | 3 | yes | [README.md:2689](../../08-Build-System/README.md#54-supply-chain-risk-in-depth) |
| 16 | Mind map | mindmap | 1 | 0 |  | [README.md:4724](../../08-Build-System/README.md#mind-map) |
| 17 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:5](../../08-Build-System/mindmap.md) |

## 09-Android-App-Internals (9)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The three axes: identity, storage, execution | flowchart | 17 | 3 | yes | [README.md:183](../../09-Android-App-Internals/README.md#21-the-three-axes-identity-storage-execution) |
| 2 | 2.2 Who does what: the component map | flowchart | 25 | 4 | yes | [README.md:251](../../09-Android-App-Internals/README.md#22-who-does-what-the-component-map) |
| 3 | 2.3 The lifetime of an app, end to end | state | 6 | 0 |  | [README.md:321](../../09-Android-App-Internals/README.md#23-the-lifetime-of-an-app-end-to-end) |
| 4 | 3.7 The install flow, end to end | sequence | 9 | 0 |  | [README.md:814](../../09-Android-App-Internals/README.md#37-the-install-flow-end-to-end) |
| 5 | 3.13 Zygote: how a process comes into existence | sequence | 5 | 0 |  | [README.md:1239](../../09-Android-App-Internals/README.md#313-zygote-how-a-process-comes-into-existence) |
| 6 | 3.14 `ActivityThread.main()` and the bootstrap order | sequence | 8 | 0 |  | [README.md:1323](../../09-Android-App-Internals/README.md#314-activitythreadmain-and-the-bootstrap-order) |
| 7 | 3.15 The main thread: Looper, MessageQueue, Handler | flowchart | 16 | 2 |  | [README.md:1400](../../09-Android-App-Internals/README.md#315-the-main-thread-looper-messagequeue-handler) |
| 8 | 13.2 The chapter as one picture | mindmap | 1 | 0 |  | [README.md:4062](../../09-Android-App-Internals/README.md#132-the-chapter-as-one-picture) |
| 9 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:11](../../09-Android-App-Internals/mindmap.md) |

## 10-APK-Internals (9)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.2 Parsing order — why it runs backwards | flowchart | 13 | 0 | yes | [README.md:302](../../10-APK-Internals/README.md#22-parsing-order--why-it-runs-backwards) |
| 2 | 2.3 The full picture | flowchart | 26 | 3 | yes | [README.md:334](../../10-APK-Internals/README.md#23-the-full-picture) |
| 3 | 3.4 resources.arsc | flowchart | 13 | 0 |  | [README.md:621](../../10-APK-Internals/README.md#34-resourcesarsc) |
| 4 | 3.5 Signing — the heart of the chapter | flowchart | 21 | 4 | yes | [README.md:682](../../10-APK-Internals/README.md#35-signing--the-heart-of-the-chapter) |
| 5 | Janus — CVE-2017-13156 | sequence | 4 | 0 |  | [README.md:1133](../../10-APK-Internals/README.md#janus--cve-2017-13156) |
| 6 | Scenario A — repackaging a banking app for a third-party store | sequence | 4 | 0 |  | [README.md:1310](../../10-APK-Internals/README.md#scenario-a--repackaging-a-banking-app-for-a-third-party-store) |
| 7 | The honest hierarchy | flowchart | 8 | 0 | yes | [README.md:1370](../../10-APK-Internals/README.md#the-honest-hierarchy) |
| 8 | Mind map | mindmap | 1 | 0 |  | [README.md:2271](../../10-APK-Internals/README.md#mind-map) |
| 9 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:9](../../10-APK-Internals/mindmap.md) |

## 11-Android-Runtime (17)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 1.5 Register machines versus stack machines, from first principles | flowchart | 9 | 2 |  | [README.md:345](../../11-Android-Runtime/README.md#15-register-machines-versus-stack-machines-from-first-principles) |
| 2 | 2.1 Where the runtime sits in the Android stack | flowchart | 19 | 4 | yes | [README.md:486](../../11-Android-Runtime/README.md#21-where-the-runtime-sits-in-the-android-stack) |
| 3 | 2.2 The complete lifecycle of code, source to silicon | flowchart | 15 | 0 | yes | [README.md:552](../../11-Android-Runtime/README.md#22-the-complete-lifecycle-of-code-source-to-silicon) |
| 4 | 2.3 The per-app process model | flowchart | 10 | 3 | yes | [README.md:660](../../11-Android-Runtime/README.md#23-the-per-app-process-model) |
| 5 | 2.4 Zygote: preload once, fork many | sequence | 5 | 0 |  | [README.md:723](../../11-Android-Runtime/README.md#24-zygote-preload-once-fork-many) |
| 6 | 2.5 Copy-on-write and what it costs you as an attacker | block layout | 8 | 0 |  | [README.md:798](../../11-Android-Runtime/README.md#25-copy-on-write-and-what-it-costs-you-as-an-attacker) |
| 7 | 2.6 The trust boundary map | flowchart | 12 | 3 | yes | [README.md:858](../../11-Android-Runtime/README.md#26-the-trust-boundary-map) |
| 8 | Mode 1 — Interpretation | flowchart | 9 | 0 |  | [README.md:922](../../11-Android-Runtime/README.md#mode-1--interpretation) |
| 9 | The comparison, side by side | flowchart | 11 | 0 |  | [README.md:1014](../../11-Android-Runtime/README.md#the-comparison-side-by-side) |
| 10 | 3.2 Profile-guided compilation and Cloud Profiles | sequence | 6 | 0 |  | [README.md:1065](../../11-Android-Runtime/README.md#32-profile-guided-compilation-and-cloud-profiles) |
| 11 | 3.7 The ClassLoader hierarchy on Android | class | 10 | 0 |  | [README.md:1297](../../11-Android-Runtime/README.md#37-the-classloader-hierarchy-on-android) |
| 12 | 3.8 Parent delegation and what it protects | sequence | 6 | 0 |  | [README.md:1400](../../11-Android-Runtime/README.md#38-parent-delegation-and-what-it-protects) |
| 13 | 3.10 Dynamic class loading as an attack technique | flowchart | 17 | 0 | yes | [README.md:1543](../../11-Android-Runtime/README.md#310-dynamic-class-loading-as-an-attack-technique) |
| 14 | 3.14 JIT hardening, W^X, and CFI | block layout | 6 | 0 |  | [README.md:1821](../../11-Android-Runtime/README.md#314-jit-hardening-wx-and-cfi) |
| 15 | 3.15 Deoptimization and why hooking frameworks depend on it | sequence | 4 | 0 |  | [README.md:1890](../../11-Android-Runtime/README.md#315-deoptimization-and-why-hooking-frameworks-depend-on-it) |
| 16 | Mind map | mindmap | 1 | 0 |  | [README.md:2722](../../11-Android-Runtime/README.md#mind-map) |
| 17 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:13](../../11-Android-Runtime/mindmap.md) |

## 12-DEX-Internals (12)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The whole file at a glance | block layout | 22 | 0 |  | [README.md:251](../../12-DEX-Internals/README.md#21-the-whole-file-at-a-glance) |
| 2 | 2.2 The index-and-data split | flowchart | 16 | 2 |  | [README.md:338](../../12-DEX-Internals/README.md#22-the-index-and-data-split) |
| 3 | 2.3 From `.java` to `classes.dex` | flowchart | 9 | 0 |  | [README.md:396](../../12-DEX-Internals/README.md#23-from-java-to-classesdex) |
| 4 | 2.4 Where DEX sits inside an APK | block layout | 10 | 0 |  | [README.md:435](../../12-DEX-Internals/README.md#24-where-dex-sits-inside-an-apk) |
| 5 | 3.2 `header_item` field by field | block layout | 23 | 0 | yes | [README.md:568](../../12-DEX-Internals/README.md#32-header_item-field-by-field) |
| 6 | 3.8 `string_id_item` and `string_data_item` | flowchart | 7 | 0 |  | [README.md:1174](../../12-DEX-Internals/README.md#38-string_id_item-and-string_data_item) |
| 7 | 3.13 `class_def_item` | flowchart | 13 | 0 |  | [README.md:1356](../../12-DEX-Internals/README.md#313-class_def_item) |
| 8 | The signed size convention | flowchart | 10 | 0 | yes | [README.md:1833](../../12-DEX-Internals/README.md#the-signed-size-convention) |
| 9 | 4.1 Trace — how the runtime opens a DEX file | sequence | 5 | 0 |  | [README.md:2686](../../12-DEX-Internals/README.md#41-trace--how-the-runtime-opens-a-dex-file) |
| 10 | 5.1 Why the format is a security topic at all | flowchart | 5 | 0 | yes | [README.md:2755](../../12-DEX-Internals/README.md#51-why-the-format-is-a-security-topic-at-all) |
| 11 | Mind map | mindmap | 1 | 0 |  | [README.md:3340](../../12-DEX-Internals/README.md#mind-map) |
| 12 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:13](../../12-DEX-Internals/mindmap.md) |

## 13-ART (11)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 Where ART sits in the system | flowchart | 14 | 4 | yes | [README.md:193](../../13-ART/README.md#21-where-art-sits-in-the-system) |
| 2 | 2.2 The compilation and execution pipeline | flowchart | 12 | 0 | yes | [README.md:242](../../13-ART/README.md#22-the-compilation-and-execution-pipeline) |
| 3 | 2.4 The three execution modes, compared | state | 0 | 0 |  | [README.md:320](../../13-ART/README.md#24-the-three-execution-modes-compared) |
| 4 | 2.5 Trust boundaries around ART | flowchart | 6 | 3 | yes | [README.md:348](../../13-ART/README.md#25-trust-boundaries-around-art) |
| 5 | 2.6 The object graph inside libart | class | 7 | 0 |  | [README.md:386](../../13-ART/README.md#26-the-object-graph-inside-libart) |
| 6 | 3.8 dex2oat: when it runs and what it does | sequence | 4 | 0 |  | [README.md:773](../../13-ART/README.md#38-dex2oat-when-it-runs-and-what-it-does) |
| 7 | 3.16 Entry points and the trampolines they point at | flowchart | 10 | 0 | yes | [README.md:1086](../../13-ART/README.md#316-entry-points-and-the-trampolines-they-point-at) |
| 8 | 3.17 Method entrypoint patching: the mechanism behind ALL Java hooking | sequence | 4 | 0 |  | [README.md:1119](../../13-ART/README.md#317-method-entrypoint-patching-the-mechanism-behind-all-java-hooking) |
| 9 | odrefresh and odsign | flowchart | 9 | 0 |  | [README.md:1450](../../13-ART/README.md#odrefresh-and-odsign) |
| 10 | Mind map | mindmap | 1 | 0 |  | [README.md:2417](../../13-ART/README.md#mind-map) |
| 11 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:10](../../13-ART/mindmap.md) |

## 14-Dalvik (7)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The Dalvik pipeline, end to end | flowchart | 14 | 2 | yes | [README.md:306](../../14-Dalvik/README.md#21-the-dalvik-pipeline-end-to-end) |
| 2 | 2.2 Stack machine versus register machine | flowchart | 9 | 2 |  | [README.md:353](../../14-Dalvik/README.md#22-stack-machine-versus-register-machine) |
| 3 | 2.5 The trace JIT | sequence | 4 | 0 |  | [README.md:545](../../14-Dalvik/README.md#25-the-trace-jit) |
| 4 | 2.6 Where Smali sits in the modern toolchain | flowchart | 14 | 2 | yes | [README.md:623](../../14-Dalvik/README.md#26-where-smali-sits-in-the-modern-toolchain) |
| 5 | 2.7 Trust boundaries when you rewrite Smali | flowchart | 11 | 4 | yes | [README.md:665](../../14-Dalvik/README.md#27-trust-boundaries-when-you-rewrite-smali) |
| 6 | Mind map | mindmap | 1 | 0 |  | [README.md:3990](../../14-Dalvik/README.md#mind-map) |
| 7 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../14-Dalvik/mindmap.md) |

## 15-Native-Code (7)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 From APK entry to mapped page | flowchart | 19 | 3 | yes | [README.md:213](../../15-Native-Code/README.md#21-from-apk-entry-to-mapped-page) |
| 2 | 2.2 The two tables, and who reads which | block layout | 12 | 0 |  | [README.md:276](../../15-Native-Code/README.md#22-the-two-tables-and-who-reads-which) |
| 3 | 2.3 What `System.loadLibrary` sets in motion | sequence | 6 | 0 |  | [README.md:311](../../15-Native-Code/README.md#23-what-systemloadlibrary-sets-in-motion) |
| 4 | 2.4 Trust boundaries at the native layer | flowchart | 15 | 3 | yes | [README.md:358](../../15-Native-Code/README.md#24-trust-boundaries-at-the-native-layer) |
| 5 | 3.8 PLT and GOT: the indirection that makes hooking possible | flowchart | 7 | 3 | yes | [README.md:979](../../15-Native-Code/README.md#38-plt-and-got-the-indirection-that-makes-hooking-possible) |
| 6 | 13.2 Chapter mind map | mindmap | 1 | 0 |  | [README.md:3311](../../15-Native-Code/README.md#132-chapter-mind-map) |
| 7 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../15-Native-Code/mindmap.md) |

## 16-JNI (9)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The bridge, drawn | flowchart | 12 | 3 | yes | [README.md:289](../../16-JNI/README.md#21-the-bridge-drawn) |
| 2 | 2.2 The life of a native call, end to end | sequence | 6 | 0 |  | [README.md:344](../../16-JNI/README.md#22-the-life-of-a-native-call-end-to-end) |
| 3 | 2.3 The `JNIEnv` double indirection | flowchart | 9 | 0 |  | [README.md:405](../../16-JNI/README.md#23-the-jnienv-double-indirection) |
| 4 | 2.4 Trust boundaries at the bridge | flowchart | 15 | 3 | yes | [README.md:440](../../16-JNI/README.md#24-trust-boundaries-at-the-bridge) |
| 5 | 2.5 The reference tables, drawn | class | 5 | 0 |  | [README.md:488](../../16-JNI/README.md#25-the-reference-tables-drawn) |
| 6 | 3.22 The managed-to-native transition inside ART | sequence | 6 | 0 |  | [README.md:2052](../../16-JNI/README.md#322-the-managed-to-native-transition-inside-art) |
| 7 | 6.6 The decision tree | flowchart | 11 | 0 |  | [README.md:3059](../../16-JNI/README.md#66-the-decision-tree) |
| 8 | Mind map | mindmap | 1 | 0 |  | [README.md:3913](../../16-JNI/README.md#mind-map) |
| 9 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../16-JNI/mindmap.md) |

## 17-Libraries (7)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | The library stack, from app code to kernel | flowchart | 26 | 5 | yes | [README.md:173](../../17-Libraries/README.md#the-library-stack-from-app-code-to-kernel) |
| 2 | How a library gets into a process | sequence | 5 | 0 |  | [README.md:253](../../17-Libraries/README.md#how-a-library-gets-into-a-process) |
| 3 | The three rings, as a decision tree | flowchart | 8 | 0 | yes | [README.md:367](../../17-Libraries/README.md#the-three-rings-as-a-decision-tree) |
| 4 | 8.1 The methodology — "enumerate every library in this APK and rate each" | flowchart | 20 | 0 | yes | [README.md:1786](../../17-Libraries/README.md#81-the-methodology--enumerate-every-library-in-this-apk-and-rate-each) |
| 5 | Mind map | mindmap | 4 | 0 |  | [README.md:2995](../../17-Libraries/README.md#mind-map) |
| 6 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:5](../../17-Libraries/mindmap.md) |
| 7 | The one-page decision flow | flowchart | 15 | 0 | yes | [mindmap.md:287](../../17-Libraries/mindmap.md#the-one-page-decision-flow) |

## 18-ARM (6)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 What is actually on the chip | flowchart | 24 | 5 |  | [README.md:174](../../18-ARM/README.md#21-what-is-actually-on-the-chip) |
| 2 | 2.2 The execution states, and why a phone has three | state | 4 | 0 |  | [README.md:239](../../18-ARM/README.md#22-the-execution-states-and-why-a-phone-has-three) |
| 3 | 2.3 From C to silicon | flowchart | 11 | 2 |  | [README.md:285](../../18-ARM/README.md#23-from-c-to-silicon) |
| 4 | 6.1 The path from Java down to the instruction | sequence | 5 | 0 |  | [README.md:2541](../../18-ARM/README.md#61-the-path-from-java-down-to-the-instruction) |
| 5 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:3592](../../18-ARM/README.md#132-mind-map) |
| 6 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:5](../../18-ARM/mindmap.md) |

## 19-Memory (6)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.2 What happens when you call `malloc(32)` | flowchart | 13 | 1 | yes | [README.md:216](../../19-Memory/README.md#22-what-happens-when-you-call-malloc32) |
| 2 | 2.3 The Zygote's consequence for address-space layout | sequence | 4 | 0 |  | [README.md:255](../../19-Memory/README.md#23-the-zygotes-consequence-for-address-space-layout) |
| 3 | 2.4 The detection landscape | flowchart | 16 | 3 |  | [README.md:308](../../19-Memory/README.md#24-the-detection-landscape) |
| 4 | 3.13.1 The shared idea: tagged memory | flowchart | 11 | 2 | yes | [README.md:1089](../../19-Memory/README.md#3131-the-shared-idea-tagged-memory) |
| 5 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:2968](../../19-Memory/README.md#132-mind-map) |
| 6 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../19-Memory/mindmap.md) |

## 20-Security-Architecture (12)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 Defence in depth, drawn once | flowchart | 30 | 6 | yes | [README.md:103](../../20-Security-Architecture/README.md#21-defence-in-depth-drawn-once) |
| 2 | 2.2 Trust boundaries, named explicitly | flowchart | 20 | 6 | yes | [README.md:171](../../20-Security-Architecture/README.md#22-trust-boundaries-named-explicitly) |
| 3 | 2.3 The boot-time sequence | sequence | 7 | 0 |  | [README.md:215](../../20-Security-Architecture/README.md#23-the-boot-time-sequence) |
| 4 | 2.4 Where each control lives in the stack | block layout | 22 | 0 |  | [README.md:250](../../20-Security-Architecture/README.md#24-where-each-control-lives-in-the-stack) |
| 5 | The mechanism: a Merkle tree | flowchart | 15 | 0 | yes | [README.md:382](../../20-Security-Architecture/README.md#the-mechanism-a-merkle-tree) |
| 6 | Why dm-verity forced Magisk to be "systemless" | flowchart | 7 | 3 | yes | [README.md:458](../../20-Security-Architecture/README.md#why-dm-verity-forced-magisk-to-be-systemless) |
| 7 | From FDE to FBE | state | 2 | 0 |  | [README.md:542](../../20-Security-Architecture/README.md#from-fde-to-fbe) |
| 8 | How the key is actually derived | sequence | 7 | 0 |  | [README.md:568](../../20-Security-Architecture/README.md#how-the-key-is-actually-derived) |
| 9 | Where the trust actually sits — the only paragraph that matters | sequence | 4 | 0 | yes | [README.md:693](../../20-Security-Architecture/README.md#where-the-trust-actually-sits--the-only-paragraph-that-matters) |
| 10 | 3.9 Synthesis — what is actually attackable in a typical engagement | flowchart | 12 | 0 | yes | [README.md:800](../../20-Security-Architecture/README.md#39-synthesis--what-is-actually-attackable-in-a-typical-engagement) |
| 11 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:2080](../../20-Security-Architecture/README.md#132-mind-map) |
| 12 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:3](../../20-Security-Architecture/mindmap.md) |

## 21-App-Sandbox (14)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The sandbox as nested enforcement layers | flowchart | 23 | 5 | yes | [README.md:114](../../21-App-Sandbox/README.md#21-the-sandbox-as-nested-enforcement-layers) |
| 2 | 2.2 The trust boundaries, named | flowchart | 15 | 5 | yes | [README.md:171](../../21-App-Sandbox/README.md#22-the-trust-boundaries-named) |
| 3 | 2.3 UID assignment at install time | sequence | 6 | 0 |  | [README.md:217](../../21-App-Sandbox/README.md#23-uid-assignment-at-install-time) |
| 4 | 2.4 Process creation — where the sandbox is actually installed | sequence | 5 | 0 |  | [README.md:253](../../21-App-Sandbox/README.md#24-process-creation--where-the-sandbox-is-actually-installed) |
| 5 | 2.5 The filesystem, drawn | block layout | 12 | 0 |  | [README.md:293](../../21-App-Sandbox/README.md#25-the-filesystem-drawn) |
| 6 | 3.4 SELinux as the second layer — the short version | flowchart | 8 | 2 | yes | [README.md:547](../../21-App-Sandbox/README.md#34-selinux-as-the-second-layer--the-short-version) |
| 7 | What `isolatedProcess` gives you | flowchart | 7 | 2 | yes | [README.md:709](../../21-App-Sandbox/README.md#what-isolatedprocess-gives-you) |
| 8 | What the SDK Runtime does | flowchart | 9 | 2 | yes | [README.md:786](../../21-App-Sandbox/README.md#what-the-sdk-runtime-does) |
| 9 | What scoped storage changes | flowchart | 6 | 0 | yes | [README.md:958](../../21-App-Sandbox/README.md#what-scoped-storage-changes) |
| 10 | How it works, step by step | sequence | 4 | 0 |  | [README.md:1040](../../21-App-Sandbox/README.md#how-it-works-step-by-step) |
| 11 | 3.14 What the sandbox does NOT protect against | flowchart | 14 | 0 | yes | [README.md:1094](../../21-App-Sandbox/README.md#314-what-the-sandbox-does-not-protect-against) |
| 12 | 3.15 Sandbox escape — the six classes | flowchart | 13 | 0 | yes | [README.md:1325](../../21-App-Sandbox/README.md#315-sandbox-escape--the-six-classes) |
| 13 | 13.2 Mindmap | mindmap | 1 | 0 |  | [README.md:3515](../../21-App-Sandbox/README.md#132-mindmap) |
| 14 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:15](../../21-App-Sandbox/mindmap.md) |

## 22-SELinux (9)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 Where SELinux sits in a system call | flowchart | 21 | 3 | yes | [README.md:127](../../22-SELinux/README.md#21-where-selinux-sits-in-a-system-call) |
| 2 | 2.2 The three layers of enforcement, drawn | flowchart | 13 | 3 | yes | [README.md:184](../../22-SELinux/README.md#22-the-three-layers-of-enforcement-drawn) |
| 3 | 2.3 Boot: how the policy gets loaded, and why the order matters | sequence | 6 | 0 |  | [README.md:217](../../22-SELinux/README.md#23-boot-how-the-policy-gets-loaded-and-why-the-order-matters) |
| 4 | 2.4 The trust boundaries SELinux draws | flowchart | 19 | 5 | yes | [README.md:264](../../22-SELinux/README.md#24-the-trust-boundaries-selinux-draws) |
| 5 | The full sequence, with the syscalls named | sequence | 6 | 0 |  | [README.md:584](../../22-SELinux/README.md#the-full-sequence-with-the-syscalls-named) |
| 6 | Diagram: the two apps | flowchart | 14 | 2 | yes | [README.md:908](../../22-SELinux/README.md#diagram-the-two-apps) |
| 7 | 3.15 Binder and `service_manager`: a two-stage MAC decision | sequence | 4 | 0 |  | [README.md:1607](../../22-SELinux/README.md#315-binder-and-service_manager-a-two-stage-mac-decision) |
| 8 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:3479](../../22-SELinux/README.md#132-mind-map) |
| 9 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:5](../../22-SELinux/mindmap.md) |

## 23-Permissions (10)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The life of one permission, end to end | flowchart | 15 | 3 | yes | [README.md:207](../../23-Permissions/README.md#21-the-life-of-one-permission-end-to-end) |
| 2 | 2.2 The three lists, and why conflating them produces wrong findings | flowchart | 9 | 4 | yes | [README.md:261](../../23-Permissions/README.md#22-the-three-lists-and-why-conflating-them-produces-wrong-findings) |
| 3 | 2.3 The two enforcement points | sequence | 5 | 0 |  | [README.md:305](../../23-Permissions/README.md#23-the-two-enforcement-points) |
| 4 | 2.4 The trust boundary drawn properly | flowchart | 10 | 4 | yes | [README.md:348](../../23-Permissions/README.md#24-the-trust-boundary-drawn-properly) |
| 5 | The flow | sequence | 5 | 0 |  | [README.md:1322](../../23-Permissions/README.md#the-flow) |
| 6 | Where the framework check physically lives | flowchart | 11 | 0 | yes | [README.md:1510](../../23-Permissions/README.md#where-the-framework-check-physically-lives) |
| 7 | The idea | flowchart | 8 | 3 | yes | [README.md:1560](../../23-Permissions/README.md#the-idea) |
| 8 | 4.3 From `<permission>` in XML to a decision at install | sequence | 6 | 0 |  | [README.md:2026](../../23-Permissions/README.md#43-from-permission-in-xml-to-a-decision-at-install) |
| 9 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:3565](../../23-Permissions/README.md#132-mind-map) |
| 10 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:8](../../23-Permissions/mindmap.md) |

## 24-IPC (10)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The whole IPC landscape in one picture | flowchart | 20 | 4 | yes | [README.md:184](../../24-IPC/README.md#21-the-whole-ipc-landscape-in-one-picture) |
| 2 | 2.2 The two shapes of IPC: mediated and direct | flowchart | 9 | 2 | yes | [README.md:267](../../24-IPC/README.md#22-the-two-shapes-of-ipc-mediated-and-direct) |
| 3 | 2.3 A concrete request, end to end | sequence | 5 | 0 |  | [README.md:304](../../24-IPC/README.md#23-a-concrete-request-end-to-end) |
| 4 | 2.4 Trust boundaries drawn explicitly | flowchart | 13 | 3 | yes | [README.md:339](../../24-IPC/README.md#24-trust-boundaries-drawn-explicitly) |
| 5 | 3.3 Binder — the substrate everything else sits on | flowchart | 11 | 3 | yes | [README.md:468](../../24-IPC/README.md#33-binder--the-substrate-everything-else-sits-on) |
| 6 | 3.4 Intents — the framework's message envelope | flowchart | 9 | 0 | yes | [README.md:515](../../24-IPC/README.md#34-intents--the-frameworks-message-envelope) |
| 7 | 3.20.1 The Android worked example | sequence | 4 | 0 |  | [README.md:1804](../../24-IPC/README.md#3201-the-android-worked-example) |
| 8 | 3.22 A full methodology for enumerating an app's IPC surface | flowchart | 8 | 0 |  | [README.md:2089](../../24-IPC/README.md#322-a-full-methodology-for-enumerating-an-apps-ipc-surface) |
| 9 | Mind map | mindmap | 1 | 0 |  | [README.md:4090](../../24-IPC/README.md#mind-map) |
| 10 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:3](../../24-IPC/mindmap.md) |

## 25-Binder (8)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The whole stack in one picture | flowchart | 22 | 3 | yes | [README.md:169](../../25-Binder/README.md#21-the-whole-stack-in-one-picture) |
| 2 | 2.2 One transaction, as a sequence | sequence | 5 | 0 |  | [README.md:231](../../25-Binder/README.md#22-one-transaction-as-a-sequence) |
| 3 | 2.3 The trust boundaries, drawn explicitly | flowchart | 16 | 3 | yes | [README.md:277](../../25-Binder/README.md#23-the-trust-boundaries-drawn-explicitly) |
| 4 | 2.4 Four device nodes, four separate worlds | flowchart | 12 | 3 | yes | [README.md:329](../../25-Binder/README.md#24-four-device-nodes-four-separate-worlds) |
| 5 | 3.12.2 Why the thread pool makes it dangerous | sequence | 3 | 0 |  | [README.md:1336](../../25-Binder/README.md#3122-why-the-thread-pool-makes-it-dangerous) |
| 6 | 5.1 The one-sentence threat model | flowchart | 16 | 0 | yes | [README.md:2008](../../25-Binder/README.md#51-the-one-sentence-threat-model) |
| 7 | 13.2 Mind map | mindmap | 2 | 0 |  | [README.md:3579](../../25-Binder/README.md#132-mind-map) |
| 8 | _(no heading above it)_ | mindmap | 3 | 0 |  | [mindmap.md:6](../../25-Binder/mindmap.md) |

## 26-Intent (15)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 What an Intent actually is, as a shape | class | 3 | 0 |  | [README.md:152](../../26-Intent/README.md#21-what-an-intent-actually-is-as-a-shape) |
| 2 | 2.2 The delivery path, end to end | sequence | 7 | 0 |  | [README.md:197](../../26-Intent/README.md#22-the-delivery-path-end-to-end) |
| 3 | 2.3 The trust boundary | flowchart | 12 | 4 | yes | [README.md:252](../../26-Intent/README.md#23-the-trust-boundary) |
| 4 | 2.4 Where resolution happens | flowchart | 13 | 0 | yes | [README.md:304](../../26-Intent/README.md#24-where-resolution-happens) |
| 5 | 3.4 The resolution algorithm — the part readers get wrong | flowchart | 13 | 0 | yes | [README.md:462](../../26-Intent/README.md#34-the-resolution-algorithm--the-part-readers-get-wrong) |
| 6 | Test 3 — data | flowchart | 8 | 0 |  | [README.md:536](../../26-Intent/README.md#test-3--data) |
| 7 | How verification works | sequence | 4 | 0 |  | [README.md:1110](../../26-Intent/README.md#how-verification-works) |
| 8 | 4.3 From `startActivity` to the resolver | flowchart | 33 | 0 | yes | [README.md:1395](../../26-Intent/README.md#43-from-startactivity-to-the-resolver) |
| 9 | 5.1 The taxonomy | mindmap | 1 | 0 |  | [README.md:1575](../../26-Intent/README.md#51-the-taxonomy) |
| 10 | The exploit | sequence | 4 | 0 |  | [README.md:1690](../../26-Intent/README.md#the-exploit) |
| 11 | 13.2 Mind map | mindmap | 3 | 0 |  | [README.md:3158](../../26-Intent/README.md#132-mind-map) |
| 12 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../26-Intent/mindmap.md) |
| 13 | The two apps, at a glance | flowchart | 10 | 2 | yes | [examples/README.md:80](../../26-Intent/examples/README.md#the-two-apps-at-a-glance) |
| 14 | Background: why this is a privilege escalation and not a routing bug | sequence | 4 | 0 |  | [labs/lab-01-intent-redirection.md:60](../../26-Intent/labs/lab-01-intent-redirection.md#background-why-this-is-a-privilege-escalation-and-not-a-routing-bug) |
| 15 | Background: request versus state | sequence | 4 | 0 |  | [labs/lab-03-applink-verification.md:45](../../26-Intent/labs/lab-03-applink-verification.md#background-request-versus-state) |

## 27-ContentProviders (9)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | The call path from a client app to a provider | flowchart | 19 | 4 | yes | [README.md:137](../../27-ContentProviders/README.md#the-call-path-from-a-client-app-to-a-provider) |
| 2 | Anatomy of a content URI | flowchart | 10 | 0 | yes | [README.md:208](../../27-ContentProviders/README.md#anatomy-of-a-content-uri) |
| 3 | Where providers sit among the four component types | flowchart | 8 | 1 |  | [README.md:231](../../27-ContentProviders/README.md#where-providers-sit-among-the-four-component-types) |
| 4 | 3.6 URI permissions: the temporary grant system | sequence | 3 | 0 |  | [README.md:522](../../27-ContentProviders/README.md#36-uri-permissions-the-temporary-grant-system) |
| 5 | 3.11 Provider lifecycle and process behaviour | state | 4 | 0 |  | [README.md:816](../../27-ContentProviders/README.md#311-provider-lifecycle-and-process-behaviour) |
| 6 | The exploit | flowchart | 7 | 0 | yes | [README.md:1812](../../27-ContentProviders/README.md#the-exploit) |
| 7 | 7.7 A complete testing workflow | flowchart | 15 | 0 | yes | [README.md:2734](../../27-ContentProviders/README.md#77-a-complete-testing-workflow) |
| 8 | Mind map | mindmap | 2 | 0 |  | [README.md:3755](../../27-ContentProviders/README.md#mind-map) |
| 9 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:3](../../27-ContentProviders/mindmap.md) |

## 28-Services (8)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 1.4 The three shapes, in one paragraph each | flowchart | 9 | 1 |  | [README.md:137](../../28-Services/README.md#14-the-three-shapes-in-one-paragraph-each) |
| 2 | 2.1 Who is involved | flowchart | 18 | 4 | yes | [README.md:195](../../28-Services/README.md#21-who-is-involved) |
| 3 | 2.2 One `bindService` call, end to end | sequence | 5 | 0 |  | [README.md:252](../../28-Services/README.md#22-one-bindservice-call-end-to-end) |
| 4 | 2.3 The lifecycle, as a state machine | state | 9 | 0 |  | [README.md:298](../../28-Services/README.md#23-the-lifecycle-as-a-state-machine) |
| 5 | 2.4 The trust boundaries, named | flowchart | 12 | 5 | yes | [README.md:330](../../28-Services/README.md#24-the-trust-boundaries-named) |
| 6 | 2.5 Where the three IBinder shapes sit | flowchart | 9 | 1 | yes | [README.md:371](../../28-Services/README.md#25-where-the-three-ibinder-shapes-sit) |
| 7 | Mind map | mindmap | 2 | 0 |  | [README.md:3637](../../28-Services/README.md#mind-map) |
| 8 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:7](../../28-Services/mindmap.md) |

## 29-BroadcastReceivers (9)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The whole path, in one picture | flowchart | 26 | 4 | yes | [README.md:202](../../29-BroadcastReceivers/README.md#21-the-whole-path-in-one-picture) |
| 2 | 2.2 The two registration paths — the visibility gap | flowchart | 15 | 2 | yes | [README.md:280](../../29-BroadcastReceivers/README.md#22-the-two-registration-paths--the-visibility-gap) |
| 3 | 2.3 The trust boundary, drawn explicitly | flowchart | 16 | 3 | yes | [README.md:349](../../29-BroadcastReceivers/README.md#23-the-trust-boundary-drawn-explicitly) |
| 4 | 2.4 What actually happens on the wire, in order | sequence | 7 | 0 |  | [README.md:412](../../29-BroadcastReceivers/README.md#24-what-actually-happens-on-the-wire-in-order) |
| 5 | 2.5 The life of one broadcast, as a state machine | state | 6 | 0 |  | [README.md:466](../../29-BroadcastReceivers/README.md#25-the-life-of-one-broadcast-as-a-state-machine) |
| 6 | 3.8 The two permission checks, and their asymmetry | flowchart | 8 | 0 | yes | [README.md:1031](../../29-BroadcastReceivers/README.md#38-the-two-permission-checks-and-their-asymmetry) |
| 7 | 5.1 The taxonomy | mindmap | 1 | 0 |  | [README.md:1524](../../29-BroadcastReceivers/README.md#51-the-taxonomy) |
| 8 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:3121](../../29-BroadcastReceivers/README.md#132-mind-map) |
| 9 | _(no heading above it)_ | mindmap | 3 | 0 |  | [mindmap.md:6](../../29-BroadcastReceivers/mindmap.md) |

## 30-Activities (10)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The four nouns, and how they nest | flowchart | 10 | 4 | yes | [README.md:159](../../30-Activities/README.md#21-the-four-nouns-and-how-they-nest) |
| 2 | 2.2 What actually happens when you call `startActivity` | sequence | 6 | 0 |  | [README.md:210](../../30-Activities/README.md#22-what-actually-happens-when-you-call-startactivity) |
| 3 | 2.3 The trust boundary | flowchart | 12 | 3 | yes | [README.md:252](../../30-Activities/README.md#23-the-trust-boundary) |
| 4 | 2.4 Where the two signature attacks sit | flowchart | 11 | 0 | yes | [README.md:300](../../30-Activities/README.md#24-where-the-two-signature-attacks-sit) |
| 5 | 3.1 The lifecycle, and which parts an attacker controls | state | 8 | 0 |  | [README.md:333](../../30-Activities/README.md#31-the-lifecycle-and-which-parts-an-attacker-controls) |
| 6 | 3.9 Tapjacking — a different subsystem entirely | sequence | 4 | 0 |  | [README.md:864](../../30-Activities/README.md#39-tapjacking--a-different-subsystem-entirely) |
| 7 | 3.10 The result channel | sequence | 2 | 0 |  | [README.md:952](../../30-Activities/README.md#310-the-result-channel) |
| 8 | The intended mechanism | sequence | 5 | 0 |  | [README.md:1356](../../30-Activities/README.md#the-intended-mechanism) |
| 9 | The chapter as one map | mindmap | 1 | 0 |  | [README.md:3304](../../30-Activities/README.md#the-chapter-as-one-map) |
| 10 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../30-Activities/mindmap.md) |

## 31-Fragments (8)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 Where a Fragment actually sits | flowchart | 14 | 2 | yes | [README.md:170](../../31-Fragments/README.md#21-where-a-fragment-actually-sits) |
| 2 | 2.2 Two Fragment implementations, and why an app has both | class | 4 | 0 |  | [README.md:226](../../31-Fragments/README.md#22-two-fragment-implementations-and-why-an-app-has-both) |
| 3 | 2.3 The trust boundary | flowchart | 14 | 3 | yes | [README.md:276](../../31-Fragments/README.md#23-the-trust-boundary) |
| 4 | 2.4 The injection, end to end | sequence | 5 | 0 |  | [README.md:326](../../31-Fragments/README.md#24-the-injection-end-to-end) |
| 5 | 3.1 The Fragment lifecycle, and the four ways it differs from an Activity's | state | 10 | 0 |  | [README.md:373](../../31-Fragments/README.md#31-the-fragment-lifecycle-and-the-four-ways-it-differs-from-an-activitys) |
| 6 | 5.1 The taxonomy | flowchart | 12 | 0 | yes | [README.md:1153](../../31-Fragments/README.md#51-the-taxonomy) |
| 7 | The chapter as one map | mindmap | 4 | 0 |  | [README.md:2664](../../31-Fragments/README.md#the-chapter-as-one-map) |
| 8 | _(no heading above it)_ | mindmap | 16 | 0 |  | [mindmap.md:7](../../31-Fragments/mindmap.md) |

## 32-Manifest (12)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | Where the manifest sits in the APK | flowchart | 9 | 1 | yes | [README.md:139](../../32-Manifest/README.md#where-the-manifest-sits-in-the-apk) |
| 2 | The lifecycle of a manifest, from source to enforcement | flowchart | 16 | 2 | yes | [README.md:169](../../32-Manifest/README.md#the-lifecycle-of-a-manifest-from-source-to-enforcement) |
| 3 | The trust boundary the manifest defines | flowchart | 11 | 4 | yes | [README.md:222](../../32-Manifest/README.md#the-trust-boundary-the-manifest-defines) |
| 4 | The two parsers you must reconcile | flowchart | 9 | 2 | yes | [README.md:263](../../32-Manifest/README.md#the-two-parsers-you-must-reconcile) |
| 5 | Reading the backup attributes together | flowchart | 10 | 0 | yes | [README.md:643](../../32-Manifest/README.md#reading-the-backup-attributes-together) |
| 6 | Task hijacking, precisely | sequence | 4 | 0 |  | [README.md:737](../../32-Manifest/README.md#task-hijacking-precisely) |
| 7 | The provider audit flow | flowchart | 18 | 0 | yes | [README.md:1008](../../32-Manifest/README.md#the-provider-audit-flow) |
| 8 | 3.17 Manifest merging — how components you never wrote appear in your APK | flowchart | 8 | 0 | yes | [README.md:1394](../../32-Manifest/README.md#317-manifest-merging--how-components-you-never-wrote-appear-in-your-apk) |
| 9 | 4.2 From bytes to `PackageInfo` | sequence | 6 | 0 |  | [README.md:1529](../../32-Manifest/README.md#42-from-bytes-to-packageinfo) |
| 10 | 4.4 The runtime check: `exported` and `permission` for an Activity | flowchart | 13 | 0 | yes | [README.md:1628](../../32-Manifest/README.md#44-the-runtime-check-exported-and-permission-for-an-activity) |
| 11 | Mind map | mindmap | 1 | 0 |  | [README.md:3194](../../32-Manifest/README.md#mind-map) |
| 12 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:11](../../32-Manifest/mindmap.md) |

## 33-Storage (5)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.2 The two trust boundaries | flowchart | 14 | 3 | yes | [README.md:232](../../33-Storage/README.md#22-the-two-trust-boundaries) |
| 2 | 2.3 What the same file looks like from three vantage points | sequence | 5 | 0 |  | [README.md:290](../../33-Storage/README.md#23-what-the-same-file-looks-like-from-three-vantage-points) |
| 3 | 2.4 The lifecycle of a byte | state | 3 | 0 |  | [README.md:343](../../33-Storage/README.md#24-the-lifecycle-of-a-byte) |
| 4 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:2520](../../33-Storage/README.md#132-mind-map) |
| 5 | _(no heading above it)_ | mindmap | 2 | 0 |  | [mindmap.md:7](../../33-Storage/mindmap.md) |

## 34-Cryptography (18)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The map of cryptography | flowchart | 17 | 0 |  | [README.md:192](../../34-Cryptography/README.md#21-the-map-of-cryptography) |
| 2 | 2.2 Where crypto lives in the Android stack | flowchart | 19 | 4 | yes | [README.md:241](../../34-Cryptography/README.md#22-where-crypto-lives-in-the-android-stack) |
| 3 | 2.3 The JCA call flow, end to end | sequence | 7 | 0 |  | [README.md:300](../../34-Cryptography/README.md#23-the-jca-call-flow-end-to-end) |
| 4 | 2.4 The shape of a *correct* encryption operation | flowchart | 12 | 2 | yes | [README.md:355](../../34-Cryptography/README.md#24-the-shape-of-a-correct-encryption-operation) |
| 5 | 3.3.1 ECB — Electronic Codebook | flowchart | 9 | 0 | yes | [README.md:505](../../34-Cryptography/README.md#331-ecb--electronic-codebook) |
| 6 | 3.3.2 CBC — Cipher Block Chaining | flowchart | 13 | 0 |  | [README.md:549](../../34-Cryptography/README.md#332-cbc--cipher-block-chaining) |
| 7 | 3.3.3 The padding oracle attack — explained in full | sequence | 2 | 0 |  | [README.md:630](../../34-Cryptography/README.md#333-the-padding-oracle-attack--explained-in-full) |
| 8 | 3.3.4 CTR — Counter mode | flowchart | 15 | 0 |  | [README.md:676](../../34-Cryptography/README.md#334-ctr--counter-mode) |
| 9 | 3.3.5 GCM — Galois/Counter Mode, and the catastrophe of nonce reuse | flowchart | 22 | 2 | yes | [README.md:710](../../34-Cryptography/README.md#335-gcm--galoiscounter-mode-and-the-catastrophe-of-nonce-reuse) |
| 10 | 3.6.1 The problem it solves | flowchart | 5 | 1 | yes | [README.md:959](../../34-Cryptography/README.md#361-the-problem-it-solves) |
| 11 | 3.6.3 Diffie–Hellman and ECDH — the colour-mixing analogy | sequence | 3 | 0 |  | [README.md:1045](../../34-Cryptography/README.md#363-diffiehellman-and-ecdh--the-colour-mixing-analogy) |
| 12 | 3.7.1 Length extension, and why HMAC exists | flowchart | 8 | 0 | yes | [README.md:1209](../../34-Cryptography/README.md#371-length-extension-and-why-hmac-exists) |
| 13 | 3.8.2 Encrypt-then-MAC versus MAC-then-encrypt | flowchart | 17 | 2 | yes | [README.md:1264](../../34-Cryptography/README.md#382-encrypt-then-mac-versus-mac-then-encrypt) |
| 14 | 3.8.3 Key derivation functions | flowchart | 11 | 0 |  | [README.md:1344](../../34-Cryptography/README.md#383-key-derivation-functions) |
| 15 | 3.10 Digital signatures and PKI in one page | flowchart | 7 | 0 |  | [README.md:1462](../../34-Cryptography/README.md#310-digital-signatures-and-pki-in-one-page) |
| 16 | 3.11.1 The provider model | class | 11 | 0 |  | [README.md:1500](../../34-Cryptography/README.md#3111-the-provider-model) |
| 17 | Mind map | mindmap | 1 | 0 |  | [README.md:3977](../../34-Cryptography/README.md#mind-map) |
| 18 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:10](../../34-Cryptography/mindmap.md) |

## 35-SSL (12)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 Where TLS sits | flowchart | 14 | 3 | yes | [README.md:185](../../35-SSL/README.md#21-where-tls-sits) |
| 2 | 2.2 The handshake, as a conversation | sequence | 2 | 0 |  | [README.md:239](../../35-SSL/README.md#22-the-handshake-as-a-conversation) |
| 3 | 2.3 The two questions, drawn separately | flowchart | 7 | 2 | yes | [README.md:284](../../35-SSL/README.md#23-the-two-questions-drawn-separately) |
| 4 | 2.5 The trust decision, as a state machine | state | 0 | 0 |  | [README.md:372](../../35-SSL/README.md#25-the-trust-decision-as-a-state-machine) |
| 5 | 3.2.3 What an intercepting proxy actually does | sequence | 3 | 0 |  | [README.md:534](../../35-SSL/README.md#323-what-an-intercepting-proxy-actually-does) |
| 6 | 13.2 The chapter as a map | mindmap | 1 | 0 |  | [README.md:2620](../../35-SSL/README.md#132-the-chapter-as-a-map) |
| 7 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:14](../../35-SSL/mindmap.md) |
| 8 | The shape of the exercise | flowchart | 10 | 0 | yes | [labs/lab-01-end-to-end-interception.md:79](../../35-SSL/labs/lab-01-end-to-end-interception.md#the-shape-of-the-exercise) |
| 9 | Stage 5 — Route 2: promote the CA to the system store | flowchart | 6 | 2 | yes | [labs/lab-01-end-to-end-interception.md:366](../../35-SSL/labs/lab-01-end-to-end-interception.md#stage-5--route-2-promote-the-ca-to-the-system-store) |
| 10 | Why one bad certificate is not enough | flowchart | 9 | 0 | yes | [labs/lab-02-deliberate-bad-certificate.md:39](../../35-SSL/labs/lab-02-deliberate-bad-certificate.md#why-one-bad-certificate-is-not-enough) |
| 11 | Part 0 — The six checks, named precisely | flowchart | 14 | 0 | yes | [labs/lab-03-dissecting-validation.md:83](../../35-SSL/labs/lab-03-dissecting-validation.md#part-0--the-six-checks-named-precisely) |
| 12 | The field: what stands between you and the flag | flowchart | 8 | 2 | yes | [labs/lab-04-ctf-the-trusted-impostor.md:316](../../35-SSL/labs/lab-04-ctf-the-trusted-impostor.md#the-field-what-stands-between-you-and-the-flag) |

## 36-CertificatePinning (9)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The layers | flowchart | 15 | 5 | yes | [README.md:204](../../36-CertificatePinning/README.md#21-the-layers) |
| 2 | 2.2 Order of operations for one connection | sequence | 7 | 0 |  | [README.md:266](../../36-CertificatePinning/README.md#22-order-of-operations-for-one-connection) |
| 3 | 2.3 Where the code physically lives | flowchart | 11 | 2 | yes | [README.md:308](../../36-CertificatePinning/README.md#23-where-the-code-physically-lives) |
| 4 | 2.4 The decision tree you are actually walking | state | 0 | 0 |  | [README.md:349](../../36-CertificatePinning/README.md#24-the-decision-tree-you-are-actually-walking) |
| 5 | 7.1 The workflow, in the order that works | flowchart | 11 | 0 | yes | [README.md:1772](../../36-CertificatePinning/README.md#71-the-workflow-in-the-order-that-works) |
| 6 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:3110](../../36-CertificatePinning/README.md#132-mind-map) |
| 7 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../36-CertificatePinning/mindmap.md) |
| 8 | 1. The failure this lab is designed to give you | flowchart | 9 | 0 | yes | [labs/lab-02-defeat-a-two-layer-pin.md:28](../../36-CertificatePinning/labs/lab-02-defeat-a-two-layer-pin.md#1-the-failure-this-lab-is-designed-to-give-you) |
| 9 | 4.1 The topology | flowchart | 10 | 2 | yes | [labs/lab-04-ctf-the-pin-that-moved.md:102](../../36-CertificatePinning/labs/lab-04-ctf-the-pin-that-moved.md#41-the-topology) |

## 37-RootDetection (12)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 What is on the device after rooting | flowchart | 18 | 4 | yes | [README.md:175](../../37-RootDetection/README.md#21-what-is-on-the-device-after-rooting) |
| 2 | 2.2 The detection surface map | flowchart | 16 | 3 | yes | [README.md:234](../../37-RootDetection/README.md#22-the-detection-surface-map) |
| 3 | 2.3 Where a check runs, and why that decides your approach | flowchart | 11 | 0 | yes | [README.md:275](../../37-RootDetection/README.md#23-where-a-check-runs-and-why-that-decides-your-approach) |
| 4 | 2.4 The trust boundary, drawn honestly | flowchart | 9 | 2 | yes | [README.md:302](../../37-RootDetection/README.md#24-the-trust-boundary-drawn-honestly) |
| 5 | How it works | flowchart | 12 | 0 | yes | [README.md:1636](../../37-RootDetection/README.md#how-it-works) |
| 6 | The arms race, drawn | sequence | 4 | 0 |  | [README.md:1854](../../37-RootDetection/README.md#the-arms-race-drawn) |
| 7 | 4.1 `File.exists()` → `faccessat` syscall | sequence | 7 | 0 |  | [README.md:2042](../../37-RootDetection/README.md#41-fileexists--faccessat-syscall) |
| 8 | 4.3 `PackageManager.getPackageInfo` across Binder | sequence | 5 | 0 |  | [README.md:2145](../../37-RootDetection/README.md#43-packagemanagergetpackageinfo-across-binder) |
| 9 | 7.1 The methodology, before any tool | flowchart | 13 | 0 | yes | [README.md:2460](../../37-RootDetection/README.md#71-the-methodology-before-any-tool) |
| 10 | 9.4 Real application — a banking app's layered posture | flowchart | 9 | 0 | yes | [README.md:2872](../../37-RootDetection/README.md#94-real-application--a-banking-apps-layered-posture) |
| 11 | Mind map | mindmap | 1 | 0 |  | [README.md:3221](../../37-RootDetection/README.md#mind-map) |
| 12 | _(no heading above it)_ | mindmap | 2 | 0 |  | [mindmap.md:15](../../37-RootDetection/mindmap.md) |

## 38-TamperDetection (8)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The life of a tampered app | flowchart | 17 | 2 | yes | [README.md:265](../../38-TamperDetection/README.md#21-the-life-of-a-tampered-app) |
| 2 | 2.2 The five tiers — when each check runs | flowchart | 14 | 0 |  | [README.md:312](../../38-TamperDetection/README.md#22-the-five-tiers--when-each-check-runs) |
| 3 | 2.3 Where a self-signature check gets its answer | sequence | 5 | 0 |  | [README.md:362](../../38-TamperDetection/README.md#23-where-a-self-signature-check-gets-its-answer) |
| 4 | 2.4 The detection surface, drawn honestly | flowchart | 16 | 3 | yes | [README.md:403](../../38-TamperDetection/README.md#24-the-detection-surface-drawn-honestly) |
| 5 | 2.5 A decision tree for the first ten minutes | flowchart | 15 | 0 | yes | [README.md:449](../../38-TamperDetection/README.md#25-a-decision-tree-for-the-first-ten-minutes) |
| 6 | Mind map | mindmap | 1 | 0 |  | [README.md:2669](../../38-TamperDetection/README.md#mind-map) |
| 7 | _(no heading above it)_ | mindmap | 2 | 0 |  | [mindmap.md:6](../../38-TamperDetection/mindmap.md) |
| 8 | Cross-chapter map | flowchart | 16 | 0 |  | [mindmap.md:222](../../38-TamperDetection/mindmap.md#cross-chapter-map) |

## 39-EmulatorDetection (7)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 Where the signals come from | flowchart | 16 | 5 | yes | [README.md:201](../../39-EmulatorDetection/README.md#21-where-the-signals-come-from) |
| 2 | 2.2 The detection surface, by cost to defeat | flowchart | 15 | 4 | yes | [README.md:269](../../39-EmulatorDetection/README.md#22-the-detection-surface-by-cost-to-defeat) |
| 3 | 2.3 The trust boundary, drawn honestly | flowchart | 11 | 4 | yes | [README.md:324](../../39-EmulatorDetection/README.md#23-the-trust-boundary-drawn-honestly) |
| 4 | 5.8 The correct architecture | sequence | 4 | 0 |  | [README.md:1636](../../39-EmulatorDetection/README.md#58-the-correct-architecture) |
| 5 | Mind map | mindmap | 1 | 0 |  | [README.md:2751](../../39-EmulatorDetection/README.md#mind-map) |
| 6 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:7](../../39-EmulatorDetection/mindmap.md) |
| 7 | Related chapters | flowchart | 12 | 0 | yes | [mindmap.md:176](../../39-EmulatorDetection/mindmap.md#related-chapters) |

## 40-Obfuscation (13)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | Where obfuscation happens in the build | flowchart | 23 | 5 | yes | [README.md:160](../../40-Obfuscation/README.md#where-obfuscation-happens-in-the-build) |
| 2 | The attacker's decision tree | flowchart | 12 | 0 | yes | [README.md:238](../../40-Obfuscation/README.md#the-attackers-decision-tree) |
| 3 | The runtime picture: what a packed app does at process start | sequence | 6 | 0 |  | [README.md:267](../../40-Obfuscation/README.md#the-runtime-picture-what-a-packed-app-does-at-process-start) |
| 4 | Layer map: what protects what | block layout | 9 | 0 |  | [README.md:307](../../40-Obfuscation/README.md#layer-map-what-protects-what) |
| 5 | 3.3.2 Control-flow flattening — the important one | flowchart | 10 | 1 |  | [README.md:801](../../40-Obfuscation/README.md#332-control-flow-flattening--the-important-one) |
| 6 | 3.3.2 Control-flow flattening — the important one | flowchart | 11 | 1 | yes | [README.md:817](../../40-Obfuscation/README.md#332-control-flow-flattening--the-important-one) |
| 7 | 3.7.3 The general unpacking methodology | flowchart | 12 | 0 | yes | [README.md:1204](../../40-Obfuscation/README.md#373-the-general-unpacking-methodology) |
| 8 | 3.7.4 Commercial protector families, descriptively | flowchart | 7 | 0 |  | [README.md:1337](../../40-Obfuscation/README.md#374-commercial-protector-families-descriptively) |
| 9 | 4.3 The framework side — how a packer's stub gets control | sequence | 5 | 0 |  | [README.md:1638](../../40-Obfuscation/README.md#43-the-framework-side--how-a-packers-stub-gets-control) |
| 10 | 6.1 THE DEOBFUSCATION METHODOLOGY | flowchart | 12 | 0 | yes | [README.md:1802](../../40-Obfuscation/README.md#61-the-deobfuscation-methodology) |
| 11 | Phase 2 — Decide static or dynamic | flowchart | 7 | 0 | yes | [README.md:1856](../../40-Obfuscation/README.md#phase-2--decide-static-or-dynamic) |
| 12 | Mind map | mindmap | 1 | 0 |  | [README.md:2870](../../40-Obfuscation/README.md#mind-map) |
| 13 | _(no heading above it)_ | mindmap | 2 | 0 |  | [mindmap.md:20](../../40-Obfuscation/mindmap.md) |

## 41-ProGuard (9)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 Where the rules file enters the build | flowchart | 19 | 3 | yes | [README.md:214](../../41-ProGuard/README.md#21-where-the-rules-file-enters-the-build) |
| 2 | 2.2 ProGuard's four phases, and R8's one | state | 0 | 0 |  | [README.md:273](../../41-ProGuard/README.md#22-proguards-four-phases-and-r8s-one) |
| 3 | 2.3 The reachability model — what "keep" actually means | flowchart | 15 | 1 | yes | [README.md:325](../../41-ProGuard/README.md#23-the-reachability-model--what-keep-actually-means) |
| 4 | 2.4 Trust boundaries, and where the interesting artefacts land | flowchart | 11 | 4 | yes | [README.md:401](../../41-ProGuard/README.md#24-trust-boundaries-and-where-the-interesting-artefacts-land) |
| 5 | 2.5 Where a rules file physically lives | flowchart | 13 | 3 |  | [README.md:450](../../41-ProGuard/README.md#25-where-a-rules-file-physically-lives) |
| 6 | Mind map | mindmap | 5 | 0 |  | [README.md:3156](../../41-ProGuard/README.md#mind-map) |
| 7 | _(no heading above it)_ | mindmap | 5 | 0 |  | [mindmap.md:8](../../41-ProGuard/mindmap.md) |
| 8 | The same material as a decision path | flowchart | 22 | 0 | yes | [mindmap.md:154](../../41-ProGuard/mindmap.md#the-same-material-as-a-decision-path) |
| 9 | The rules-writing loop | state | 0 | 0 |  | [mindmap.md:203](../../41-ProGuard/mindmap.md#the-rules-writing-loop) |

## 42-R8 (6)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 Where R8 sits in the build | flowchart | 17 | 4 | yes | [README.md:139](../../42-R8/README.md#21-where-r8-sits-in-the-build) |
| 2 | 2.2 The four phases inside R8 | sequence | 6 | 0 |  | [README.md:183](../../42-R8/README.md#22-the-four-phases-inside-r8) |
| 3 | 2.3 What comes out, and who is allowed to see it | flowchart | 10 | 3 | yes | [README.md:220](../../42-R8/README.md#23-what-comes-out-and-who-is-allowed-to-see-it) |
| 4 | 2.4 The compatibility-mode split | state | 1 | 0 |  | [README.md:252](../../42-R8/README.md#24-the-compatibility-mode-split) |
| 5 | Mind map | mindmap | 1 | 0 |  | [README.md:2363](../../42-R8/README.md#mind-map) |
| 6 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:5](../../42-R8/mindmap.md) |

## 43-WebView (7)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 Where everything actually runs | flowchart | 15 | 4 | yes | [README.md:217](../../43-WebView/README.md#21-where-everything-actually-runs) |
| 2 | 2.2 A page load, from `loadUrl` to pixels | sequence | 7 | 0 |  | [README.md:280](../../43-WebView/README.md#22-a-page-load-from-loadurl-to-pixels) |
| 3 | 2.3 The class stack, from the API you type to the code that runs | flowchart | 15 | 2 |  | [README.md:335](../../43-WebView/README.md#23-the-class-stack-from-the-api-you-type-to-the-code-that-runs) |
| 4 | 2.4 The certificate-error path, drawn on its own | flowchart | 15 | 0 | yes | [README.md:393](../../43-WebView/README.md#24-the-certificate-error-path-drawn-on-its-own) |
| 5 | 2.5 The two network stacks in one app | flowchart | 11 | 3 | yes | [README.md:439](../../43-WebView/README.md#25-the-two-network-stacks-in-one-app) |
| 6 | 13.2 The chapter as a map | mindmap | 1 | 0 |  | [README.md:3268](../../43-WebView/README.md#132-the-chapter-as-a-map) |
| 7 | _(no heading above it)_ | mindmap | 2 | 0 |  | [mindmap.md:6](../../43-WebView/mindmap.md) |

## 44-NetworkSecurityConfig (6)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 From a manifest attribute to a TLS decision | flowchart | 23 | 4 |  | [README.md:221](../../44-NetworkSecurityConfig/README.md#21-from-a-manifest-attribute-to-a-tls-decision) |
| 2 | 2.2 Answering one question: "may I connect to this host, and whom do I trust for it?" | sequence | 6 | 0 |  | [README.md:288](../../44-NetworkSecurityConfig/README.md#22-answering-one-question-may-i-connect-to-this-host-and-whom-do-i-trust-for-it) |
| 3 | 2.3 Which configuration applies to which host | flowchart | 11 | 0 | yes | [README.md:328](../../44-NetworkSecurityConfig/README.md#23-which-configuration-applies-to-which-host) |
| 4 | 2.4 The object graph, at runtime | class | 11 | 0 |  | [README.md:369](../../44-NetworkSecurityConfig/README.md#24-the-object-graph-at-runtime) |
| 5 | 13.2 The chapter as a map | mindmap | 1 | 0 |  | [README.md:3073](../../44-NetworkSecurityConfig/README.md#132-the-chapter-as-a-map) |
| 6 | _(no heading above it)_ | mindmap | 2 | 0 |  | [mindmap.md:5](../../44-NetworkSecurityConfig/mindmap.md) |

## 45-OAuth (23)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | The four roles | flowchart | 4 | 0 | yes | [README.md:111](../../45-OAuth/README.md#the-four-roles) |
| 2 | 2.1 The complete Android OAuth topology | flowchart | 13 | 5 | yes | [README.md:192](../../45-OAuth/README.md#21-the-complete-android-oauth-topology) |
| 3 | 2.2 The trust boundaries, drawn explicitly | flowchart | 16 | 3 | yes | [README.md:250](../../45-OAuth/README.md#22-the-trust-boundaries-drawn-explicitly) |
| 4 | 2.3 Where the pieces live on the device | block layout | 10 | 0 |  | [README.md:291](../../45-OAuth/README.md#23-where-the-pieces-live-on-the-device) |
| 5 | 2.4 Grant-type decision tree | flowchart | 9 | 0 | yes | [README.md:324](../../45-OAuth/README.md#24-grant-type-decision-tree) |
| 6 | 3.2 Grant type 1 — Authorisation Code (without PKCE) | sequence | 5 | 0 |  | [README.md:393](../../45-OAuth/README.md#32-grant-type-1--authorisation-code-without-pkce) |
| 7 | 3.3 Grant type 2 — Authorisation Code with PKCE (the correct choice) | sequence | 4 | 0 |  | [README.md:440](../../45-OAuth/README.md#33-grant-type-2--authorisation-code-with-pkce-the-correct-choice) |
| 8 | 3.4 Grant type 3 — Implicit (dead, and why) | sequence | 4 | 0 |  | [README.md:554](../../45-OAuth/README.md#34-grant-type-3--implicit-dead-and-why) |
| 9 | 3.5 Grant type 4 — Resource Owner Password Credentials (ROPC) (dead, and why apps still ship it) | sequence | 3 | 0 |  | [README.md:602](../../45-OAuth/README.md#35-grant-type-4--resource-owner-password-credentials-ropc-dead-and-why-apps-still-ship-it) |
| 10 | 3.6 Grant type 5 — Client Credentials | sequence | 2 | 0 |  | [README.md:661](../../45-OAuth/README.md#36-grant-type-5--client-credentials) |
| 11 | 3.7 Grant type 6 — Device Authorization Grant (RFC 8628) | sequence | 4 | 0 |  | [README.md:702](../../45-OAuth/README.md#37-grant-type-6--device-authorization-grant-rfc-8628) |
| 12 | 3.8 Grant type 7 — Refresh Token | sequence | 3 | 0 |  | [README.md:756](../../45-OAuth/README.md#38-grant-type-7--refresh-token) |
| 13 | 3.9 Custom Tabs versus WebView | flowchart | 8 | 2 | yes | [README.md:834](../../45-OAuth/README.md#39-custom-tabs-versus-webview) |
| 14 | 3.10.1 Custom URI schemes — and scheme hijacking | sequence | 5 | 0 | yes | [README.md:960](../../45-OAuth/README.md#3101-custom-uri-schemes--and-scheme-hijacking) |
| 15 | 3.11 The `state` parameter, and CSRF | sequence | 3 | 0 | yes | [README.md:1098](../../45-OAuth/README.md#311-the-state-parameter-and-csrf) |
| 16 | `id_token` versus `access_token` — the distinction that breaks systems | flowchart | 15 | 0 | yes | [README.md:1193](../../45-OAuth/README.md#id_token-versus-access_token--the-distinction-that-breaks-systems) |
| 17 | 3.13 Pushed Authorization Requests and other hardening | sequence | 3 | 0 |  | [README.md:1293](../../45-OAuth/README.md#313-pushed-authorization-requests-and-other-hardening) |
| 18 | 4.1 The redirect's journey through the platform | sequence | 6 | 0 |  | [README.md:1414](../../45-OAuth/README.md#41-the-redirects-journey-through-the-platform) |
| 19 | Attack 5 — Mix-up attacks | sequence | 4 | 0 | yes | [README.md:1694](../../45-OAuth/README.md#attack-5--mix-up-attacks) |
| 20 | Attack 6 — "Sign in with X" backend token confusion | sequence | 5 | 0 |  | [README.md:1726](../../45-OAuth/README.md#attack-6--sign-in-with-x-backend-token-confusion) |
| 21 | 5.5 How pentesters test it — the methodology in one place | flowchart | 9 | 0 |  | [README.md:1825](../../45-OAuth/README.md#55-how-pentesters-test-it--the-methodology-in-one-place) |
| 22 | Mind map | mindmap | 1 | 0 |  | [README.md:3449](../../45-OAuth/README.md#mind-map) |
| 23 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../45-OAuth/mindmap.md) |

## 46-Tokens (10)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The life of a token, end to end | flowchart | 12 | 4 | yes | [README.md:267](../../46-Tokens/README.md#21-the-life-of-a-token-end-to-end) |
| 2 | 2.2 The trust boundaries | flowchart | 16 | 3 | yes | [README.md:332](../../46-Tokens/README.md#22-the-trust-boundaries) |
| 3 | 2.3 The two token shapes, side by side | flowchart | 10 | 2 |  | [README.md:381](../../46-Tokens/README.md#23-the-two-token-shapes-side-by-side) |
| 4 | 2.4 Where a token can be on an Android device | block layout | 11 | 0 |  | [README.md:435](../../46-Tokens/README.md#24-where-a-token-can-be-on-an-android-device) |
| 5 | 3.3 Opaque tokens, and why the distinction changes everything | flowchart | 10 | 0 | yes | [README.md:650](../../46-Tokens/README.md#33-opaque-tokens-and-why-the-distinction-changes-everything) |
| 6 | 3.9 Refresh tokens: rotation and reuse detection | sequence | 3 | 0 |  | [README.md:942](../../46-Tokens/README.md#39-refresh-tokens-rotation-and-reuse-detection) |
| 7 | DPoP (RFC 9449) | sequence | 4 | 0 |  | [README.md:1095](../../46-Tokens/README.md#dpop-rfc-9449) |
| 8 | 7.1 The method, in order | flowchart | 10 | 0 |  | [README.md:2349](../../46-Tokens/README.md#71-the-method-in-order) |
| 9 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:3464](../../46-Tokens/README.md#132-mind-map) |
| 10 | _(no heading above it)_ | mindmap | 3 | 0 |  | [mindmap.md:8](../../46-Tokens/mindmap.md) |

## 47-Authentication (11)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The whole picture, and where trust stops | flowchart | 20 | 5 | yes | [README.md:252](../../47-Authentication/README.md#21-the-whole-picture-and-where-trust-stops) |
| 2 | 2.2 The login sequence, with the transport on every arrow | sequence | 6 | 0 |  | [README.md:322](../../47-Authentication/README.md#22-the-login-sequence-with-the-transport-on-every-arrow) |
| 3 | 2.3 The session lifecycle as a state machine | state | 3 | 0 |  | [README.md:385](../../47-Authentication/README.md#23-the-session-lifecycle-as-a-state-machine) |
| 4 | 2.4 Where the credential physically lives | block layout | 7 | 0 | yes | [README.md:447](../../47-Authentication/README.md#24-where-the-credential-physically-lives) |
| 5 | 3.3 Password handling — where a password comes from, before it reaches a KDF | flowchart | 9 | 0 | yes | [README.md:554](../../47-Authentication/README.md#33-password-handling--where-a-password-comes-from-before-it-reaches-a-kdf) |
| 6 | 3.5 The autofill framework — a third party is offered your password field | sequence | 4 | 0 |  | [README.md:764](../../47-Authentication/README.md#35-the-autofill-framework--a-third-party-is-offered-your-password-field) |
| 7 | 3.6 Credential Manager and passkeys | sequence | 5 | 0 |  | [README.md:861](../../47-Authentication/README.md#36-credential-manager-and-passkeys) |
| 8 | 4.1 The account stack | sequence | 5 | 0 |  | [README.md:1296](../../47-Authentication/README.md#41-the-account-stack) |
| 9 | 7.1 The order of operations, and why traffic comes first | flowchart | 6 | 0 | yes | [README.md:2563](../../47-Authentication/README.md#71-the-order-of-operations-and-why-traffic-comes-first) |
| 10 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:3510](../../47-Authentication/README.md#132-mind-map) |
| 11 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:5](../../47-Authentication/mindmap.md) |

## 48-Biometrics (10)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The whole system, once | flowchart | 18 | 4 | yes | [README.md:190](../../48-Biometrics/README.md#21-the-whole-system-once) |
| 2 | 2.2 The successful path, in order | sequence | 7 | 0 |  | [README.md:262](../../48-Biometrics/README.md#22-the-successful-path-in-order) |
| 3 | 2.3 Where each authenticator class can and cannot reach | flowchart | 12 | 3 | yes | [README.md:326](../../48-Biometrics/README.md#23-where-each-authenticator-class-can-and-cannot-reach) |
| 4 | 2.4 Trust boundaries, drawn honestly | block layout | 6 | 0 | yes | [README.md:379](../../48-Biometrics/README.md#24-trust-boundaries-drawn-honestly) |
| 5 | 3.8 What actually reaches the TEE — enrolment, matching, and the token | flowchart | 10 | 2 | yes | [README.md:848](../../48-Biometrics/README.md#38-what-actually-reaches-the-tee--enrolment-matching-and-the-token) |
| 6 | 7.1 The three-pass method | flowchart | 12 | 0 | yes | [README.md:1788](../../48-Biometrics/README.md#71-the-three-pass-method) |
| 7 | 9.4 Real application — a password manager | flowchart | 6 | 0 |  | [README.md:2390](../../48-Biometrics/README.md#94-real-application--a-password-manager) |
| 8 | 13.2 Mind map | mindmap | 3 | 0 |  | [README.md:2799](../../48-Biometrics/README.md#132-mind-map) |
| 9 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../48-Biometrics/mindmap.md) |
| 10 | 0. The shape of the work | flowchart | 7 | 0 |  | [labs/lab-03-audit-a-real-app.md:32](../../48-Biometrics/labs/lab-03-audit-a-real-app.md#0-the-shape-of-the-work) |

## 49-KeyStore (8)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The full stack, from your `Cipher` call to the silicon | flowchart | 23 | 5 | yes | [README.md:115](../../49-KeyStore/README.md#21-the-full-stack-from-your-cipher-call-to-the-silicon) |
| 2 | 2.2 The lifecycle of one key, as a sequence | sequence | 5 | 0 |  | [README.md:181](../../49-KeyStore/README.md#22-the-lifecycle-of-one-key-as-a-sequence) |
| 3 | 2.4 Trust boundaries, drawn explicitly | flowchart | 11 | 3 | yes | [README.md:270](../../49-KeyStore/README.md#24-trust-boundaries-drawn-explicitly) |
| 4 | 3.7.3 The chain | flowchart | 5 | 0 |  | [README.md:536](../../49-KeyStore/README.md#373-the-chain) |
| 5 | 3.7.5 How a server verifies, step by step | flowchart | 20 | 0 | yes | [README.md:627](../../49-KeyStore/README.md#375-how-a-server-verifies-step-by-step) |
| 6 | 7.1 The methodology, as a process | flowchart | 9 | 0 |  | [README.md:1300](../../49-KeyStore/README.md#71-the-methodology-as-a-process) |
| 7 | 13.2 Mindmap | mindmap | 1 | 0 |  | [README.md:1739](../../49-KeyStore/README.md#132-mindmap) |
| 8 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:15](../../49-KeyStore/mindmap.md) |

## 50-HardwareBackedSecurity (7)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The trust hierarchy, drawn once | flowchart | 18 | 3 | yes | [README.md:141](../../50-HardwareBackedSecurity/README.md#21-the-trust-hierarchy-drawn-once) |
| 2 | 2.4 From PIN to permitted operation: the whole chain in one sequence | sequence | 6 | 0 |  | [README.md:271](../../50-HardwareBackedSecurity/README.md#24-from-pin-to-permitted-operation-the-whole-chain-in-one-sequence) |
| 3 | 2.5 Where the boundaries are, and what crossing each one buys an attacker | flowchart | 12 | 4 | yes | [README.md:329](../../50-HardwareBackedSecurity/README.md#25-where-the-boundaries-are-and-what-crossing-each-one-buys-an-attacker) |
| 4 | 3.2 ARM TrustZone mechanics | state | 0 | 0 |  | [README.md:414](../../50-HardwareBackedSecurity/README.md#32-arm-trustzone-mechanics) |
| 5 | 3.7.2 How KeyMint checks it | flowchart | 14 | 0 | yes | [README.md:706](../../50-HardwareBackedSecurity/README.md#372-how-keymint-checks-it) |
| 6 | 13.2 The chapter as a map | mindmap | 1 | 0 |  | [README.md:2168](../../50-HardwareBackedSecurity/README.md#132-the-chapter-as-a-map) |
| 7 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../50-HardwareBackedSecurity/mindmap.md) |

## 51-DynamicAnalysis (9)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The pipeline | flowchart | 20 | 2 | yes | [README.md:212](../../51-DynamicAnalysis/README.md#21-the-pipeline) |
| 2 | 2.2 The nine observation channels, and what each can and cannot see | flowchart | 12 | 0 |  | [README.md:275](../../51-DynamicAnalysis/README.md#22-the-nine-observation-channels-and-what-each-can-and-cannot-see) |
| 3 | 2.3 The life of an observation | state | 0 | 0 |  | [README.md:342](../../51-DynamicAnalysis/README.md#23-the-life-of-an-observation) |
| 4 | 2.4 The other half of the loop | sequence | 3 | 0 |  | [README.md:394](../../51-DynamicAnalysis/README.md#24-the-other-half-of-the-loop) |
| 5 | 2.5 The trust boundary you are standing on | flowchart | 11 | 3 | yes | [README.md:445](../../51-DynamicAnalysis/README.md#25-the-trust-boundary-you-are-standing-on) |
| 6 | 3.5.1 The four altitudes | flowchart | 10 | 0 | yes | [README.md:1029](../../51-DynamicAnalysis/README.md#351-the-four-altitudes) |
| 7 | 7.4 Instrumenting: the decision, not the mechanism | flowchart | 11 | 0 | yes | [README.md:2787](../../51-DynamicAnalysis/README.md#74-instrumenting-the-decision-not-the-mechanism) |
| 8 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:3772](../../51-DynamicAnalysis/README.md#132-mind-map) |
| 9 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:8](../../51-DynamicAnalysis/mindmap.md) |

## 52-StaticAnalysis (7)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The pipeline | flowchart | 22 | 3 | yes | [README.md:157](../../52-StaticAnalysis/README.md#21-the-pipeline) |
| 2 | 2.2 What each view can and cannot see | flowchart | 16 | 0 | yes | [README.md:216](../../52-StaticAnalysis/README.md#22-what-each-view-can-and-cannot-see) |
| 3 | 2.3 The life of a lead | state | 0 | 0 |  | [README.md:258](../../52-StaticAnalysis/README.md#23-the-life-of-a-lead) |
| 4 | 2.4 The trust boundary you are standing on | flowchart | 8 | 2 | yes | [README.md:297](../../52-StaticAnalysis/README.md#24-the-trust-boundary-you-are-standing-on) |
| 5 | 7.5 Which tool answers this question? | flowchart | 12 | 0 | yes | [README.md:1895](../../52-StaticAnalysis/README.md#75-which-tool-answers-this-question) |
| 6 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:2964](../../52-StaticAnalysis/README.md#132-mind-map) |
| 7 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:7](../../52-StaticAnalysis/mindmap.md) |

## 53-Frida (16)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The whole system, one picture | flowchart | 25 | 6 | yes | [README.md:204](../../53-Frida/README.md#21-the-whole-system-one-picture) |
| 2 | 2.2 The injection sequence, step by step | sequence | 6 | 0 |  | [README.md:282](../../53-Frida/README.md#22-the-injection-sequence-step-by-step) |
| 3 | 2.3 Spawn versus attach | flowchart | 16 | 2 | yes | [README.md:340](../../53-Frida/README.md#23-spawn-versus-attach) |
| 4 | 2.4 The message channel | sequence | 6 | 0 |  | [README.md:395](../../53-Frida/README.md#24-the-message-channel) |
| 5 | 2.5 The no-root path: frida-gadget | flowchart | 14 | 2 | yes | [README.md:432](../../53-Frida/README.md#25-the-no-root-path-frida-gadget) |
| 6 | 3.3 What lives inside the agent | block layout | 9 | 0 |  | [README.md:662](../../53-Frida/README.md#33-what-lives-inside-the-agent) |
| 7 | 3.6.1 `Interceptor` — attach versus replace | flowchart | 18 | 2 |  | [README.md:858](../../53-Frida/README.md#361-interceptor--attach-versus-replace) |
| 8 | 3.7 `Stalker` — instruction-level tracing | flowchart | 13 | 2 | yes | [README.md:1386](../../53-Frida/README.md#37-stalker--instruction-level-tracing) |
| 9 | 3.9.2 How a Java hook is installed, at the ART level | flowchart | 11 | 0 |  | [README.md:1603](../../53-Frida/README.md#392-how-a-java-hook-is-installed-at-the-art-level) |
| 10 | 7.2 The engagement workflow | flowchart | 10 | 0 |  | [README.md:3181](../../53-Frida/README.md#72-the-engagement-workflow) |
| 11 | 7.4 The four failure modes, exhaustively | flowchart | 12 | 0 | yes | [README.md:3524](../../53-Frida/README.md#74-the-four-failure-modes-exhaustively) |
| 12 | 7.4.2 Failure 2 — `ClassNotFoundException` and the ClassLoader problem | flowchart | 5 | 0 | yes | [README.md:3683](../../53-Frida/README.md#742-failure-2--classnotfoundexception-and-the-classloader-problem) |
| 13 | 7.4.4 Failure 4 — attaching instead of spawning | sequence | 5 | 0 |  | [README.md:3970](../../53-Frida/README.md#744-failure-4--attaching-instead-of-spawning) |
| 14 | 7.10 The no-root path: `frida-gadget` | flowchart | 11 | 0 | yes | [README.md:4685](../../53-Frida/README.md#710-the-no-root-path-frida-gadget) |
| 15 | Mind map | mindmap | 1 | 0 |  | [README.md:6077](../../53-Frida/README.md#mind-map) |
| 16 | _(no heading above it)_ | mindmap | 2 | 0 |  | [mindmap.md:12](../../53-Frida/mindmap.md) |

## 54-Objection (8)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The whole system in one picture | flowchart | 11 | 3 | yes | [README.md:180](../../54-Objection/README.md#21-the-whole-system-in-one-picture) |
| 2 | 2.2 What happens when you type the command | sequence | 6 | 0 |  | [README.md:237](../../54-Objection/README.md#22-what-happens-when-you-type-the-command) |
| 3 | 2.3 One agent, not one script per command | flowchart | 9 | 1 |  | [README.md:289](../../54-Objection/README.md#23-one-agent-not-one-script-per-command) |
| 4 | 3.11 Version skew — the commonest real-world blocker | flowchart | 5 | 0 | yes | [README.md:1194](../../54-Objection/README.md#311-version-skew--the-commonest-real-world-blocker) |
| 5 | 4.1 One command, end to end | flowchart | 16 | 0 | yes | [README.md:1254](../../54-Objection/README.md#41-one-command-end-to-end) |
| 6 | 7.3 The four failure modes, and how to tell them apart | flowchart | 10 | 0 | yes | [README.md:1800](../../54-Objection/README.md#73-the-four-failure-modes-and-how-to-tell-them-apart) |
| 7 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:2545](../../54-Objection/README.md#132-mind-map) |
| 8 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../54-Objection/mindmap.md) |

## 55-MobSF (8)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 What happens when you upload an APK | flowchart | 19 | 3 | yes | [README.md:339](../../55-MobSF/README.md#21-what-happens-when-you-upload-an-apk) |
| 2 | 2.2 Where MobSF sits inside 52's pipeline | flowchart | 12 | 2 | yes | [README.md:402](../../55-MobSF/README.md#22-where-mobsf-sits-inside-52s-pipeline) |
| 3 | 2.3 The report, as a data structure | class | 8 | 0 |  | [README.md:447](../../55-MobSF/README.md#23-the-report-as-a-data-structure) |
| 4 | 2.4 The REST API, as a conversation | sequence | 3 | 0 |  | [README.md:518](../../55-MobSF/README.md#24-the-rest-api-as-a-conversation) |
| 5 | 2.5 Static and dynamic, as two different machines | flowchart | 12 | 2 |  | [README.md:565](../../55-MobSF/README.md#25-static-and-dynamic-as-two-different-machines) |
| 6 | 2.6 The trust boundary you are standing on | flowchart | 13 | 3 | yes | [README.md:597](../../55-MobSF/README.md#26-the-trust-boundary-you-are-standing-on) |
| 7 | 13.2 The chapter as a mind map | mindmap | 1 | 0 |  | [README.md:3646](../../55-MobSF/README.md#132-the-chapter-as-a-mind-map) |
| 8 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:3](../../55-MobSF/mindmap.md) |

## 56-JADX (9)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 1.4 The three ways jadx fails | flowchart | 7 | 0 | yes | [README.md:255](../../56-JADX/README.md#14-the-three-ways-jadx-fails) |
| 2 | 2.1 Where jadx sits between the build and you | flowchart | 11 | 3 | yes | [README.md:324](../../56-JADX/README.md#21-where-jadx-sits-between-the-build-and-you) |
| 3 | 2.2 The information-loss ladder | block layout | 13 | 0 |  | [README.md:373](../../56-JADX/README.md#22-the-information-loss-ladder) |
| 4 | 2.3 The jadx internal pipeline | flowchart | 16 | 0 | yes | [README.md:405](../../56-JADX/README.md#23-the-jadx-internal-pipeline) |
| 5 | 2.4 GUI or CLI: a decision, not a preference | flowchart | 4 | 0 |  | [README.md:444](../../56-JADX/README.md#24-gui-or-cli-a-decision-not-a-preference) |
| 6 | 2.5 Trust boundary: jadx runs attacker-supplied input | flowchart | 9 | 3 | yes | [README.md:474](../../56-JADX/README.md#25-trust-boundary-jadx-runs-attacker-supplied-input) |
| 7 | 7.1 The read-hook-verify loop | sequence | 4 | 0 |  | [README.md:2805](../../56-JADX/README.md#71-the-read-hook-verify-loop) |
| 8 | Mind map | mindmap | 1 | 0 |  | [README.md:4123](../../56-JADX/README.md#mind-map) |
| 9 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:8](../../56-JADX/mindmap.md) |

## 57-Ghidra (9)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | The decompilation pipeline | flowchart | 13 | 0 |  | [README.md:207](../../57-Ghidra/README.md#the-decompilation-pipeline) |
| 2 | Ghidra's process architecture | flowchart | 8 | 2 |  | [README.md:247](../../57-Ghidra/README.md#ghidras-process-architecture) |
| 3 | Where Ghidra sits in the Android RE workflow | flowchart | 9 | 0 | yes | [README.md:291](../../57-Ghidra/README.md#where-ghidra-sits-in-the-android-re-workflow) |
| 4 | 3.8 The JNIEnv problem, and how to solve it | flowchart | 8 | 0 |  | [README.md:712](../../57-Ghidra/README.md#38-the-jnienv-problem-and-how-to-solve-it) |
| 5 | 3.9 Finding JNI entry points | flowchart | 9 | 0 | yes | [README.md:815](../../57-Ghidra/README.md#39-finding-jni-entry-points) |
| 6 | 3.15 The Ghidra debugger against an Android target | sequence | 5 | 0 |  | [README.md:1245](../../57-Ghidra/README.md#315-the-ghidra-debugger-against-an-android-target) |
| 7 | 7.1 The address arithmetic that connects the two worlds | flowchart | 4 | 0 |  | [README.md:1889](../../57-Ghidra/README.md#71-the-address-arithmetic-that-connects-the-two-worlds) |
| 8 | Mind map | mindmap | 1 | 0 |  | [README.md:3418](../../57-Ghidra/README.md#mind-map) |
| 9 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:18](../../57-Ghidra/mindmap.md) |

## 58-IDA (8)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The pipeline | flowchart | 11 | 0 |  | [README.md:243](../../58-IDA/README.md#21-the-pipeline) |
| 2 | 2.2 The database, and what is actually in it | flowchart | 8 | 1 | yes | [README.md:284](../../58-IDA/README.md#22-the-database-and-what-is-actually-in-it) |
| 3 | 2.3 Where IDA sits in an Android workflow | flowchart | 12 | 0 | yes | [README.md:336](../../58-IDA/README.md#23-where-ida-sits-in-an-android-workflow) |
| 4 | 3.4 Hex-Rays: microcode, and why it is not P-Code | flowchart | 13 | 0 |  | [README.md:548](../../58-IDA/README.md#34-hex-rays-microcode-and-why-it-is-not-p-code) |
| 5 | 3.7 FLIRT — measured, not described | flowchart | 9 | 0 | yes | [README.md:839](../../58-IDA/README.md#37-flirt--measured-not-described) |
| 6 | 3.9 The debugger and `android_server` | sequence | 5 | 0 |  | [README.md:937](../../58-IDA/README.md#39-the-debugger-and-android_server) |
| 7 | Mind map | mindmap | 1 | 0 |  | [README.md:2402](../../58-IDA/README.md#mind-map) |
| 8 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:5](../../58-IDA/mindmap.md) |

## 59-radare2 (11)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | The library stack | flowchart | 17 | 3 |  | [README.md:185](../../59-radare2/README.md#the-library-stack) |
| 2 | The separation that matters: parse versus analyse | flowchart | 5 | 0 |  | [README.md:256](../../59-radare2/README.md#the-separation-that-matters-parse-versus-analyse) |
| 3 | Where radare2 sits in the Android workflow | flowchart | 10 | 0 | yes | [README.md:359](../../59-radare2/README.md#where-radare2-sits-in-the-android-workflow) |
| 4 | 3.2 The command language, taught as a grammar | flowchart | 10 | 2 |  | [README.md:466](../../59-radare2/README.md#32-the-command-language-taught-as-a-grammar) |
| 5 | 3.6 Analysis levels — `aaa` and what it actually costs | flowchart | 8 | 0 |  | [README.md:882](../../59-radare2/README.md#36-analysis-levels--aaa-and-what-it-actually-costs) |
| 6 | 3.14 radare2 versus rizin versus Cutter | flowchart | 6 | 0 |  | [README.md:1327](../../59-radare2/README.md#314-radare2-versus-rizin-versus-cutter) |
| 7 | 7.1 The address arithmetic that connects static to dynamic | flowchart | 7 | 0 |  | [README.md:2001](../../59-radare2/README.md#71-the-address-arithmetic-that-connects-static-to-dynamic) |
| 8 | Mind map | mindmap | 1 | 0 |  | [README.md:2926](../../59-radare2/README.md#mind-map) |
| 9 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:5](../../59-radare2/mindmap.md) |
| 10 | How the pieces connect | flowchart | 11 | 0 | yes | [mindmap.md:166](../../59-radare2/mindmap.md#how-the-pieces-connect) |
| 11 | The two failure modes, side by side | flowchart | 15 | 2 | yes | [mindmap.md:195](../../59-radare2/mindmap.md#the-two-failure-modes-side-by-side) |

## 60-ADB (6)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 Three programs, not one | flowchart | 15 | 3 | yes | [README.md:133](../../60-ADB/README.md#21-three-programs-not-one) |
| 2 | 2.2 The handshake, message by message | sequence | 2 | 0 |  | [README.md:195](../../60-ADB/README.md#22-the-handshake-message-by-message) |
| 3 | 2.4 Where the trust boundaries actually are | flowchart | 11 | 3 | yes | [README.md:284](../../60-ADB/README.md#24-where-the-trust-boundaries-actually-are) |
| 4 | 3.14 `adb install` is three streams — the transport half | sequence | 3 | 0 |  | [README.md:1222](../../60-ADB/README.md#314-adb-install-is-three-streams--the-transport-half) |
| 5 | Mind map | mindmap | 3 | 0 |  | [README.md:2974](../../60-ADB/README.md#mind-map) |
| 6 | _(no heading above it)_ | mindmap | 3 | 0 |  | [mindmap.md:6](../../60-ADB/mindmap.md) |

## 61-Fastboot (12)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 Where fastboot sits relative to everything else | flowchart | 15 | 5 | yes | [README.md:199](../../61-Fastboot/README.md#21-where-fastboot-sits-relative-to-everything-else) |
| 2 | 2.2 The three-legged transaction that every fastboot operation is built from | sequence | 2 | 0 |  | [README.md:262](../../61-Fastboot/README.md#22-the-three-legged-transaction-that-every-fastboot-operation-is-built-from) |
| 3 | 2.3 The lock-state machine — the most important diagram in this chapter | state | 3 | 0 |  | [README.md:313](../../61-Fastboot/README.md#23-the-lock-state-machine--the-most-important-diagram-in-this-chapter) |
| 4 | 2.4 Two implementations of one protocol | flowchart | 12 | 2 |  | [README.md:381](../../61-Fastboot/README.md#24-two-implementations-of-one-protocol) |
| 5 | 3.2 The wire protocol: five prefixes and nothing else | state | 2 | 0 |  | [README.md:527](../../61-Fastboot/README.md#32-the-wire-protocol-five-prefixes-and-nothing-else) |
| 6 | 3.6 `fastbootd` — userspace fastboot, and why it had to exist | sequence | 4 | 0 |  | [README.md:765](../../61-Fastboot/README.md#36-fastbootd--userspace-fastboot-and-why-it-had-to-exist) |
| 7 | 3.7 Dynamic partitions and the `super` partition | flowchart | 4 | 0 |  | [README.md:889](../../61-Fastboot/README.md#37-dynamic-partitions-and-the-super-partition) |
| 8 | 3.9 The factory-reset guarantee | sequence | 3 | 0 |  | [README.md:1034](../../61-Fastboot/README.md#39-the-factory-reset-guarantee) |
| 9 | 4.2 Tracing one complete path: `fastboot flash system system.img` | sequence | 7 | 0 |  | [README.md:1300](../../61-Fastboot/README.md#42-tracing-one-complete-path-fastboot-flash-system-systemimg) |
| 10 | 9.5 Enterprise — a fleet device-posture pipeline | flowchart | 11 | 3 | yes | [README.md:2602](../../61-Fastboot/README.md#95-enterprise--a-fleet-device-posture-pipeline) |
| 11 | 13.2 The chapter as a map | mindmap | 1 | 0 |  | [README.md:2975](../../61-Fastboot/README.md#132-the-chapter-as-a-map) |
| 12 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../61-Fastboot/mindmap.md) |

## 62-Magisk (6)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 Where Magisk sits in the boot chain | flowchart | 21 | 5 | yes | [README.md:160](../../62-Magisk/README.md#21-where-magisk-sits-in-the-boot-chain) |
| 2 | 2.2 The overlay illusion | flowchart | 13 | 4 | yes | [README.md:223](../../62-Magisk/README.md#22-the-overlay-illusion) |
| 3 | 2.3 The `su` request flow | sequence | 5 | 0 |  | [README.md:267](../../62-Magisk/README.md#23-the-su-request-flow) |
| 4 | 2.4 Zygisk — injection into every app | flowchart | 16 | 3 | yes | [README.md:312](../../62-Magisk/README.md#24-zygisk--injection-into-every-app) |
| 5 | Mind map | mindmap | 1 | 0 |  | [README.md:2144](../../62-Magisk/README.md#mind-map) |
| 6 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:3](../../62-Magisk/mindmap.md) |

## 63-LSPosed (13)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The injection chain, end to end | flowchart | 20 | 4 | yes | [README.md:261](../../63-LSPosed/README.md#21-the-injection-chain-end-to-end) |
| 2 | 2.2 One app launch, as a sequence | sequence | 7 | 0 |  | [README.md:322](../../63-LSPosed/README.md#22-one-app-launch-as-a-sequence) |
| 3 | 2.3 Four processes, four privilege levels | flowchart | 10 | 4 | yes | [README.md:365](../../63-LSPosed/README.md#23-four-processes-four-privilege-levels) |
| 4 | 2.5 Classic Xposed and LSPosed, side by side | flowchart | 10 | 2 | yes | [README.md:433](../../63-LSPosed/README.md#25-classic-xposed-and-lsposed-side-by-side) |
| 5 | 3.5 Getting a module's DEX into a foreign process — and the class-loader problem | flowchart | 4 | 0 | yes | [README.md:618](../../63-LSPosed/README.md#35-getting-a-modules-dex-into-a-foreign-process--and-the-class-loader-problem) |
| 6 | 3.7 `XC_MethodHook` — the lifecycle, precisely | state | 4 | 0 |  | [README.md:748](../../63-LSPosed/README.md#37-xc_methodhook--the-lifecycle-precisely) |
| 7 | 3.10 The backup method — the trampoline of the managed world | flowchart | 7 | 2 | yes | [README.md:885](../../63-LSPosed/README.md#310-the-backup-method--the-trampoline-of-the-managed-world) |
| 8 | 3.13 Timing: the three entry points and what exists at each | flowchart | 12 | 0 |  | [README.md:998](../../63-LSPosed/README.md#313-timing-the-three-entry-points-and-what-exists-at-each) |
| 9 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:2896](../../63-LSPosed/README.md#132-mind-map) |
| 10 | The chapter | mindmap | 1 | 0 |  | [mindmap.md:11](../../63-LSPosed/mindmap.md#the-chapter) |
| 11 | Decision: which instrument? | flowchart | 15 | 0 |  | [mindmap.md:165](../../63-LSPosed/mindmap.md#decision-which-instrument) |
| 12 | Diagnostic: the hook did not fire | flowchart | 18 | 0 | yes | [mindmap.md:196](../../63-LSPosed/mindmap.md#diagnostic-the-hook-did-not-fire) |
| 13 | The four privilege levels, at a glance | flowchart | 5 | 0 | yes | [mindmap.md:229](../../63-LSPosed/mindmap.md#the-four-privilege-levels-at-a-glance) |

## 64-Xposed (6)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The boot chain classic Xposed inserted itself into | flowchart | 20 | 3 | yes | [README.md:316](../../64-Xposed/README.md#21-the-boot-chain-classic-xposed-inserted-itself-into) |
| 2 | 2.2 One app launch, as a sequence | sequence | 6 | 0 |  | [README.md:374](../../64-Xposed/README.md#22-one-app-launch-as-a-sequence) |
| 3 | 2.3 What a classic install physically wrote to disk | block layout | 11 | 0 | yes | [README.md:418](../../64-Xposed/README.md#23-what-a-classic-install-physically-wrote-to-disk) |
| 4 | 2.5 The four things Xposed needed, and when each became impossible | flowchart | 10 | 2 | yes | [README.md:493](../../64-Xposed/README.md#25-the-four-things-xposed-needed-and-when-each-became-impossible) |
| 5 | 13.2 Mind map | mindmap | 2 | 0 |  | [README.md:3030](../../64-Xposed/README.md#132-mind-map) |
| 6 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:13](../../64-Xposed/mindmap.md) |

## 65-Hooking (7)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The five places a call can be intercepted | flowchart | 20 | 2 | yes | [README.md:169](../../65-Hooking/README.md#21-the-five-places-a-call-can-be-intercepted) |
| 2 | 2.2 What each hook physically overwrites | flowchart | 11 | 2 |  | [README.md:213](../../65-Hooking/README.md#22-what-each-hook-physically-overwrites) |
| 3 | 2.3 The anatomy of an inline hook | sequence | 4 | 0 |  | [README.md:244](../../65-Hooking/README.md#23-the-anatomy-of-an-inline-hook) |
| 4 | 2.5 Blast radius: the property that should drive your choice | flowchart | 6 | 0 | yes | [README.md:320](../../65-Hooking/README.md#25-blast-radius-the-property-that-should-drive-your-choice) |
| 5 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:2451](../../65-Hooking/README.md#132-mind-map) |
| 6 | _(no heading above it)_ | mindmap | 2 | 0 |  | [mindmap.md:6](../../65-Hooking/mindmap.md) |
| 7 | The one-diagram version | flowchart | 13 | 0 | yes | [mindmap.md:163](../../65-Hooking/mindmap.md#the-one-diagram-version) |

## 66-Instrumentation (5)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The command path | flowchart | 17 | 4 | yes | [README.md:184](../../66-Instrumentation/README.md#21-the-command-path) |
| 2 | 2.2 The Binder sequence, with the ordering that matters | sequence | 7 | 0 |  | [README.md:236](../../66-Instrumentation/README.md#22-the-binder-sequence-with-the-ordering-that-matters) |
| 3 | 2.4 The lifecycle as a state machine | state | 4 | 0 |  | [README.md:332](../../66-Instrumentation/README.md#24-the-lifecycle-as-a-state-machine) |
| 4 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:2420](../../66-Instrumentation/README.md#132-mind-map) |
| 5 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../66-Instrumentation/mindmap.md) |

## 67-BypassingProtections (7)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The five seams | flowchart | 20 | 2 | yes | [README.md:185](../../67-BypassingProtections/README.md#21-the-five-seams) |
| 2 | 2.2 The same picture as a sequence, with the timing that matters | sequence | 6 | 0 |  | [README.md:236](../../67-BypassingProtections/README.md#22-the-same-picture-as-a-sequence-with-the-timing-that-matters) |
| 3 | 2.4 The escalation ladder, drawn | state | 3 | 0 |  | [README.md:304](../../67-BypassingProtections/README.md#24-the-escalation-ladder-drawn) |
| 4 | 2.5 Where the responses live | flowchart | 11 | 0 | yes | [README.md:345](../../67-BypassingProtections/README.md#25-where-the-responses-live) |
| 5 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:2824](../../67-BypassingProtections/README.md#132-mind-map) |
| 6 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../67-BypassingProtections/mindmap.md) |
| 7 | The same thing as a decision tree | flowchart | 26 | 0 | yes | [mindmap.md:215](../../67-BypassingProtections/mindmap.md#the-same-thing-as-a-decision-tree) |

## 68-ReverseEngineering (11)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The investigation loop | flowchart | 10 | 0 |  | [README.md:348](../../68-ReverseEngineering/README.md#21-the-investigation-loop) |
| 2 | 2.2 The triage funnel, across both halves | flowchart | 12 | 3 | yes | [README.md:399](../../68-ReverseEngineering/README.md#22-the-triage-funnel-across-both-halves) |
| 3 | 2.3 The evidence ladder | flowchart | 6 | 0 | yes | [README.md:449](../../68-ReverseEngineering/README.md#23-the-evidence-ladder) |
| 4 | 2.4 Where the tools sit on the loop | flowchart | 13 | 2 |  | [README.md:499](../../68-ReverseEngineering/README.md#24-where-the-tools-sit-on-the-loop) |
| 5 | 2.5 The state of a question | state | 0 | 0 |  | [README.md:550](../../68-ReverseEngineering/README.md#25-the-state-of-a-question) |
| 6 | 3.3 Stage 2 — triage in twenty minutes | flowchart | 5 | 0 | yes | [README.md:715](../../68-ReverseEngineering/README.md#33-stage-2--triage-in-twenty-minutes) |
| 7 | 3.5 Stage 4 — hypothesis, prediction, experiment, verdict | sequence | 3 | 0 |  | [README.md:806](../../68-ReverseEngineering/README.md#35-stage-4--hypothesis-prediction-experiment-verdict) |
| 8 | 3.8 Crossing the managed/native boundary as one question | flowchart | 8 | 0 |  | [README.md:1005](../../68-ReverseEngineering/README.md#38-crossing-the-managednative-boundary-as-one-question) |
| 9 | 4.5 Tracing one question from Java to the kernel | sequence | 5 | 0 |  | [README.md:1560](../../68-ReverseEngineering/README.md#45-tracing-one-question-from-java-to-the-kernel) |
| 10 | 13.2 The chapter as one picture | mindmap | 1 | 0 |  | [README.md:2884](../../68-ReverseEngineering/README.md#132-the-chapter-as-one-picture) |
| 11 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:12](../../68-ReverseEngineering/mindmap.md) |

## 69-MalwareAnalysis (10)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The triage pipeline | flowchart | 22 | 5 | yes | [README.md:313](../../69-MalwareAnalysis/README.md#21-the-triage-pipeline) |
| 2 | 2.2 The capability stack — what an installed app can actually reach | block layout | 16 | 0 | yes | [README.md:384](../../69-MalwareAnalysis/README.md#22-the-capability-stack--what-an-installed-app-can-actually-reach) |
| 3 | 2.3 The lifecycle of a mobile malware campaign | sequence | 5 | 0 |  | [README.md:448](../../69-MalwareAnalysis/README.md#23-the-lifecycle-of-a-mobile-malware-campaign) |
| 4 | 2.4 The analysis environment — what "isolation" means concretely | flowchart | 10 | 3 | yes | [README.md:502](../../69-MalwareAnalysis/README.md#24-the-analysis-environment--what-isolation-means-concretely) |
| 5 | 2.5 The trust boundary you are standing on | flowchart | 9 | 2 | yes | [README.md:548](../../69-MalwareAnalysis/README.md#25-the-trust-boundary-you-are-standing-on) |
| 6 | 3.8 Persistence hook 3 — services, watchdogs and the platform's counter-moves | state | 0 | 0 |  | [README.md:987](../../69-MalwareAnalysis/README.md#38-persistence-hook-3--services-watchdogs-and-the-platforms-counter-moves) |
| 7 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:3030](../../69-MalwareAnalysis/README.md#132-mind-map) |
| 8 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:10](../../69-MalwareAnalysis/mindmap.md) |
| 9 | How the chapters connect | flowchart | 17 | 3 | yes | [mindmap.md:211](../../69-MalwareAnalysis/mindmap.md#how-the-chapters-connect) |
| 10 | The one-page decision tree | flowchart | 12 | 0 | yes | [mindmap.md:264](../../69-MalwareAnalysis/mindmap.md#the-one-page-decision-tree) |

## 70-VulnerabilityResearch (9)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 1.3 A crash is not a bug, and a bug is not a vulnerability | flowchart | 6 | 0 | yes | [README.md:145](../../70-VulnerabilityResearch/README.md#13-a-crash-is-not-a-bug-and-a-bug-is-not-a-vulnerability) |
| 2 | 2.1 The pipeline | flowchart | 8 | 0 |  | [README.md:303](../../70-VulnerabilityResearch/README.md#21-the-pipeline) |
| 3 | 2.2 The Android attack surface, drawn by who can reach what | flowchart | 13 | 5 | yes | [README.md:341](../../70-VulnerabilityResearch/README.md#22-the-android-attack-surface-drawn-by-who-can-reach-what) |
| 4 | 2.3 The funnel, with real numbers | flowchart | 8 | 0 |  | [README.md:410](../../70-VulnerabilityResearch/README.md#23-the-funnel-with-real-numbers) |
| 5 | 2.4 Where a crash comes from and where it goes | sequence | 5 | 0 |  | [README.md:440](../../70-VulnerabilityResearch/README.md#24-where-a-crash-comes-from-and-where-it-goes) |
| 6 | 4.4 Tracing one path from untrusted input to a parser | sequence | 5 | 0 | yes | [README.md:1359](../../70-VulnerabilityResearch/README.md#44-tracing-one-path-from-untrusted-input-to-a-parser) |
| 7 | The chapter as a map | mindmap | 1 | 0 |  | [README.md:3128](../../70-VulnerabilityResearch/README.md#the-chapter-as-a-map) |
| 8 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:5](../../70-VulnerabilityResearch/mindmap.md) |
| 9 | The same thing as a decision flow | flowchart | 20 | 0 | yes | [mindmap.md:187](../../70-VulnerabilityResearch/mindmap.md#the-same-thing-as-a-decision-flow) |

## 71-OWASP-Mobile (7)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | How the three documents relate | flowchart | 20 | 4 |  | [README.md:105](../../71-OWASP-Mobile/README.md#how-the-three-documents-relate) |
| 2 | The verification levels | flowchart | 6 | 3 | yes | [README.md:160](../../71-OWASP-Mobile/README.md#the-verification-levels) |
| 3 | Where each control area maps in this repository | flowchart | 28 | 0 |  | [README.md:192](../../71-OWASP-Mobile/README.md#where-each-control-area-maps-in-this-repository) |
| 4 | Scoping an engagement against the standard | flowchart | 10 | 0 |  | [README.md:389](../../71-OWASP-Mobile/README.md#scoping-an-engagement-against-the-standard) |
| 5 | Mind map | mindmap | 1 | 0 |  | [README.md:830](../../71-OWASP-Mobile/README.md#mind-map) |
| 6 | The whole standard, in one tree | mindmap | 1 | 0 |  | [mindmap.md:15](../../71-OWASP-Mobile/mindmap.md#the-whole-standard-in-one-tree) |
| 7 | Step 4 — The composition hunt, specifically | flowchart | 5 | 2 | yes | [labs/lab-03-find-the-gap.md:203](../../71-OWASP-Mobile/labs/lab-03-find-the-gap.md#step-4--the-composition-hunt-specifically) |

## 72-RealWorldFindings (5)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The adjudication pipeline | flowchart | 10 | 2 | yes | [README.md:184](../../72-RealWorldFindings/README.md#21-the-adjudication-pipeline) |
| 2 | 2.2 Where each finding class comes from | flowchart | 14 | 2 | yes | [README.md:232](../../72-RealWorldFindings/README.md#22-where-each-finding-class-comes-from) |
| 3 | 2.3 The severity funnel, drawn to scale | block layout | 6 | 0 |  | [README.md:279](../../72-RealWorldFindings/README.md#23-the-severity-funnel-drawn-to-scale) |
| 4 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:1871](../../72-RealWorldFindings/README.md#132-mind-map) |
| 5 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:7](../../72-RealWorldFindings/mindmap.md) |

## 73-Labs (6)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The corpus as a system | flowchart | 15 | 3 | yes | [README.md:164](../../73-Labs/README.md#21-the-corpus-as-a-system) |
| 2 | 2.2 How the index is produced | sequence | 4 | 0 |  | [README.md:208](../../73-Labs/README.md#22-how-the-index-is-produced) |
| 3 | 2.3 The lab environment, as a stack | block layout | 12 | 0 |  | [README.md:245](../../73-Labs/README.md#23-the-lab-environment-as-a-stack) |
| 4 | 2.4 The lifecycle of one lab attempt | state | 0 | 0 |  | [README.md:263](../../73-Labs/README.md#24-the-lifecycle-of-one-lab-attempt) |
| 5 | 13.2 Mind map | mindmap | 1 | 0 |  | [README.md:1373](../../73-Labs/README.md#132-mind-map) |
| 6 | _(no heading above it)_ | mindmap | 2 | 0 |  | [mindmap.md:6](../../73-Labs/mindmap.md) |

## 74-CaseStudies (6)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The five phases every investigation actually has | flowchart | 9 | 0 | yes | [README.md:173](../../74-CaseStudies/README.md#21-the-five-phases-every-investigation-actually-has) |
| 2 | 2.2 What each case is really about — the same shape six times | flowchart | 16 | 2 | yes | [README.md:205](../../74-CaseStudies/README.md#22-what-each-case-is-really-about--the-same-shape-six-times) |
| 3 | 2.3 Where the evidence for one case comes from | sequence | 5 | 0 |  | [README.md:253](../../74-CaseStudies/README.md#23-where-the-evidence-for-one-case-comes-from) |
| 4 | 13.2 Mind map | mindmap | 3 | 0 |  | [README.md:2067](../../74-CaseStudies/README.md#132-mind-map) |
| 5 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../74-CaseStudies/mindmap.md) |
| 6 | The chapter as a decision procedure | flowchart | 12 | 0 | yes | [mindmap.md:158](../../74-CaseStudies/mindmap.md#the-chapter-as-a-decision-procedure) |

## 75-InterviewQuestions (5)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 2.1 The pipeline as a system | flowchart | 13 | 4 | yes | [README.md:283](../../75-InterviewQuestions/README.md#21-the-pipeline-as-a-system) |
| 2 | 2.2 One round, end to end | sequence | 4 | 0 |  | [README.md:342](../../75-InterviewQuestions/README.md#22-one-round-end-to-end) |
| 3 | 2.3 The state machine of a single answer | state | 0 | 0 |  | [README.md:396](../../75-InterviewQuestions/README.md#23-the-state-machine-of-a-single-answer) |
| 4 | Mind map | mindmap | 1 | 0 |  | [README.md:2689](../../75-InterviewQuestions/README.md#mind-map) |
| 5 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:8](../../75-InterviewQuestions/mindmap.md) |

## 76-CheatSheets (4)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | Mind map | mindmap | 1 | 0 |  | [README.md:890](../../76-CheatSheets/README.md#mind-map) |
| 2 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:6](../../76-CheatSheets/mindmap.md) |
| 3 | How the parts fit together | flowchart | 14 | 3 | yes | [mindmap.md:112](../../76-CheatSheets/mindmap.md#how-the-parts-fit-together) |
| 4 | The decision the chapter is built on | flowchart | 6 | 0 | yes | [mindmap.md:163](../../76-CheatSheets/mindmap.md#the-decision-the-chapter-is-built-on) |

## 77-UsefulCommands (4)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | Where your commands actually land | flowchart | 28 | 6 | yes | [README.md:89](../../77-UsefulCommands/README.md#where-your-commands-actually-land) |
| 2 | The privilege ladder | flowchart | 6 | 0 |  | [README.md:166](../../77-UsefulCommands/README.md#the-privilege-ladder) |
| 3 | Mind map | mindmap | 1 | 0 |  | [README.md:1296](../../77-UsefulCommands/README.md#mind-map) |
| 4 | _(no heading above it)_ | mindmap | 1 | 0 |  | [mindmap.md:3](../../77-UsefulCommands/mindmap.md) |

## 78-Diagrams (37)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 4.1 The Android security stack, end to end | flowchart | 17 | 5 | yes | [README.md:347](../../78-Diagrams/README.md#41-the-android-security-stack-end-to-end) |
| 2 | 4.2 The boot chain, hardware root of trust to app code | sequence | 6 | 0 |  | [README.md:411](../../78-Diagrams/README.md#42-the-boot-chain-hardware-root-of-trust-to-app-code) |
| 3 | 4.3 Where every chapter sits in the platform | flowchart | 22 | 11 |  | [README.md:457](../../78-Diagrams/README.md#43-where-every-chapter-sits-in-the-platform) |
| 4 | 4.4 The complete trust-boundary map | flowchart | 16 | 4 | yes | [README.md:518](../../78-Diagrams/README.md#44-the-complete-trust-boundary-map) |
| 5 | 4.5 One Binder call, across every boundary | sequence | 5 | 0 |  | [README.md:580](../../78-Diagrams/README.md#45-one-binder-call-across-every-boundary) |
| 6 | 4.6 The engagement, static through dynamic to reporting | state | 0 | 0 |  | [README.md:619](../../78-Diagrams/README.md#46-the-engagement-static-through-dynamic-to-reporting) |
| 7 | 4.7 The device-state machine an engagement moves through | state | 0 | 0 |  | [README.md:662](../../78-Diagrams/README.md#47-the-device-state-machine-an-engagement-moves-through) |
| 8 | 5.2 Flowchart arrows and node shapes | flowchart | 6 | 0 |  | [README.md:720](../../78-Diagrams/README.md#52-flowchart-arrows-and-node-shapes) |
| 9 | 5.3 Sequence arrows — the four you must tell apart | sequence | 2 | 0 |  | [README.md:747](../../78-Diagrams/README.md#53-sequence-arrows--the-four-you-must-tell-apart) |
| 10 | 5.4 State and class notation | state | 0 | 0 |  | [README.md:778](../../78-Diagrams/README.md#54-state-and-class-notation) |
| 11 | 5.4 State and class notation | class | 2 | 0 |  | [README.md:794](../../78-Diagrams/README.md#54-state-and-class-notation) |
| 12 | 6.1 Show the boundary, do not imply it | flowchart | 6 | 2 | yes | [README.md:860](../../78-Diagrams/README.md#61-show-the-boundary-do-not-imply-it) |
| 13 | 6.4 Draw the actual flow, not the intended one | flowchart | 8 | 0 | yes | [README.md:932](../../78-Diagrams/README.md#64-draw-the-actual-flow-not-the-intended-one) |
| 14 | Mind map | mindmap | 1 | 1 |  | [README.md:1178](../../78-Diagrams/README.md#mind-map) |
| 15 | _(no heading above it)_ | mindmap | 1 | 1 |  | [mindmap.md:5](../../78-Diagrams/mindmap.md) |
| 16 | Version A — the diagram most people draw | flowchart | 5 | 0 |  | [examples/01-one-system-three-diagrams.md:30](../../78-Diagrams/examples/01-one-system-three-diagrams.md#version-a--the-diagram-most-people-draw) |
| 17 | Version B — the same system with the boundaries drawn | flowchart | 10 | 3 | yes | [examples/01-one-system-three-diagrams.md:106](../../78-Diagrams/examples/01-one-system-three-diagrams.md#version-b--the-same-system-with-the-boundaries-drawn) |
| 18 | Version C — the same system as a sequence | sequence | 6 | 0 |  | [examples/01-one-system-three-diagrams.md:194](../../78-Diagrams/examples/01-one-system-three-diagrams.md#version-c--the-same-system-as-a-sequence) |
| 19 | 1 — A semicolon in message or label text | sequence | 2 | 0 |  | [examples/02-broken-diagrams-and-their-fixes.md:48](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#1--a-semicolon-in-message-or-label-text) |
| 20 | 1 — A semicolon in message or label text | sequence | 2 | 0 |  | [examples/02-broken-diagrams-and-their-fixes.md:57](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#1--a-semicolon-in-message-or-label-text) |
| 21 | 2 — Unquoted parentheses or brackets in mindmap text | mindmap | 3 | 0 |  | [examples/02-broken-diagrams-and-their-fixes.md:93](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#2--unquoted-parentheses-or-brackets-in-mindmap-text) |
| 22 | 2 — Unquoted parentheses or brackets in mindmap text | mindmap | 1 | 0 |  | [examples/02-broken-diagrams-and-their-fixes.md:102](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#2--unquoted-parentheses-or-brackets-in-mindmap-text) |
| 23 | 3 — A backslash-escaped quote inside a quoted label | flowchart | 3 | 0 |  | [examples/02-broken-diagrams-and-their-fixes.md:129](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#3--a-backslash-escaped-quote-inside-a-quoted-label) |
| 24 | 3 — A backslash-escaped quote inside a quoted label | flowchart | 2 | 0 |  | [examples/02-broken-diagrams-and-their-fixes.md:136](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#3--a-backslash-escaped-quote-inside-a-quoted-label) |
| 25 | 4 — `style` inside a `sequenceDiagram` | sequence | 2 | 0 |  | [examples/02-broken-diagrams-and-their-fixes.md:166](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#4--style-inside-a-sequencediagram) |
| 26 | 4 — `style` inside a `sequenceDiagram` | sequence | 2 | 0 |  | [examples/02-broken-diagrams-and-their-fixes.md:178](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#4--style-inside-a-sequencediagram) |
| 27 | 5 — A participant id that collides with a keyword | sequence | 2 | 0 |  | [examples/02-broken-diagrams-and-their-fixes.md:221](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#5--a-participant-id-that-collides-with-a-keyword) |
| 28 | 6 — Unquoted parentheses in flowchart node text | flowchart | 3 | 0 |  | [examples/02-broken-diagrams-and-their-fixes.md:255](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#6--unquoted-parentheses-in-flowchart-node-text) |
| 29 | 7 — A mindmap leaf whose text starts with a diagram-type keyword | mindmap | 1 | 0 |  | [examples/02-broken-diagrams-and-their-fixes.md:284](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#7--a-mindmap-leaf-whose-text-starts-with-a-diagram-type-keyword) |
| 30 | 7 — A mindmap leaf whose text starts with a diagram-type keyword | mindmap | 3 | 0 |  | [examples/02-broken-diagrams-and-their-fixes.md:294](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#7--a-mindmap-leaf-whose-text-starts-with-a-diagram-type-keyword) |
| 31 | Part 5 — Draw it | flowchart | 15 | 4 | yes | [labs/lab-01-boundaries-from-evidence.md:287](../../78-Diagrams/labs/lab-01-boundaries-from-evidence.md#part-5--draw-it) |
| 32 | Part 5 — Redraw the diagram with the omission in it | flowchart | 10 | 0 | yes | [labs/lab-02-what-the-diagram-omits.md:282](../../78-Diagrams/labs/lab-02-what-the-diagram-omits.md#part-5--redraw-the-diagram-with-the-omission-in-it) |
| 33 | Part 1 — Draw the intended flow, before measuring | sequence | 4 | 0 |  | [labs/lab-03-intended-versus-actual.md:80](../../78-Diagrams/labs/lab-03-intended-versus-actual.md#part-1--draw-the-intended-flow-before-measuring) |
| 34 | Part 3 — Draw the actual flow | sequence | 5 | 0 |  | [labs/lab-03-intended-versus-actual.md:275](../../78-Diagrams/labs/lab-03-intended-versus-actual.md#part-3--draw-the-actual-flow) |
| 35 | Part 3 — Draw the actual flow | flowchart | 11 | 3 | yes | [labs/lab-03-intended-versus-actual.md:294](../../78-Diagrams/labs/lab-03-intended-versus-actual.md#part-3--draw-the-actual-flow) |
| 36 | The topology you were given | flowchart | 5 | 0 |  | [labs/lab-04-ctf-the-cartographers-error.md:178](../../78-Diagrams/labs/lab-04-ctf-the-cartographers-error.md#the-topology-you-were-given) |
| 37 | Stage 5 — Redraw it | flowchart | 12 | 2 | yes | [labs/lab-04-ctf-the-cartographers-error.md:403](../../78-Diagrams/labs/lab-04-ctf-the-cartographers-error.md#stage-5--redraw-it) |

## 79-Glossary (1)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | Mind map | mindmap | 1 | 0 |  | [README.md:1027](../../79-Glossary/README.md#mind-map) |

## 80-Appendix (1)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | Mind map | mindmap | 1 | 0 |  | [README.md:630](../../80-Appendix/README.md#mind-map) |

## 81-Android-Runtime-Internals (6)

| # | Depicts | Type | Nodes | Boundaries | Atk | Location |
|---:|---|---|---:|---:|:---:|---|
| 1 | 01-boot-to-app.mmd | flowchart | 19 | 4 | yes | [diagrams/01-boot-to-app.mmd:1](../../81-Android-Runtime-Internals/diagrams/01-boot-to-app.mmd) |
| 2 | 02-art-dispatch.mmd | flowchart | 12 | 3 | yes | [diagrams/02-art-dispatch.mmd:1](../../81-Android-Runtime-Internals/diagrams/02-art-dispatch.mmd) |
| 3 | 03-injection-stack.mmd | flowchart | 15 | 5 | yes | [diagrams/03-injection-stack.mmd:1](../../81-Android-Runtime-Internals/diagrams/03-injection-stack.mmd) |
| 4 | 04-hooked-call-sequence.mmd | sequence | 7 | 0 |  | [diagrams/04-hooked-call-sequence.mmd:1](../../81-Android-Runtime-Internals/diagrams/04-hooked-call-sequence.mmd) |
| 5 | 05-chapter-mindmap.mmd | mindmap | 1 | 0 |  | [diagrams/05-chapter-mindmap.mmd:1](../../81-Android-Runtime-Internals/diagrams/05-chapter-mindmap.mmd) |
| 6 | 06-standalone-mindmap.mmd | mindmap | 1 | 0 |  | [diagrams/06-standalone-mindmap.mmd:1](../../81-Android-Runtime-Internals/diagrams/06-standalone-mindmap.mmd) |

