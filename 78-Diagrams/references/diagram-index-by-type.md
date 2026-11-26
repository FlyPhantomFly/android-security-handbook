<!-- GENERATED FILE. Do not edit by hand.
     Rebuild with:  python3 -B scripts/diagram-census.py
     Source: every fenced ```mermaid block in every .md file in this repository,
     plus every standalone .mmd source file. -->

# Diagram index — by diagram type

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


**824 diagrams in 6 Mermaid families.** Use this view when you want a worked example of a particular diagram type to copy the shape of.


| Type | Count | Share |
|---|---:|---:|
| flowchart | 422 | 51.2% |
| mindmap | 169 | 20.5% |
| sequence | 157 | 19.1% |
| state | 36 | 4.4% |
| block layout | 28 | 3.4% |
| class | 12 | 1.5% |

## flowchart (422)

| Chapter | Depicts | Nodes | Atk | Location |
|---|---|---:|:---:|---|
| (root) | Learning path | 14 |  | [README.md:46](../../README.md#learning-path) |
| (root) | 6. Diagram conventions | 5 | yes | [STYLE-GUIDE.md:227](../../STYLE-GUIDE.md#6-diagram-conventions) |
| 00-Introduction | 2.1 The map of the whole field | 29 |  | [README.md:197](../../00-Introduction/README.md#21-the-map-of-the-whole-field) |
| 00-Introduction | 2.2 Where the attacker sits relative to the app | 22 | yes | [README.md:250](../../00-Introduction/README.md#22-where-the-attacker-sits-relative-to-the-app) |
| 00-Introduction | 3.2 The career ladder | 10 |  | [README.md:439](../../00-Introduction/README.md#32-the-career-ladder) |
| 00-Introduction | Magisk: the systemless approach | 6 |  | [README.md:1413](../../00-Introduction/README.md#magisk-the-systemless-approach) |
| 00-Introduction | Decision flow | 11 | yes | [README.md:1683](../../00-Introduction/README.md#decision-flow) |
| 00-Introduction | 5.5 How to actually study this repository | 9 |  | [README.md:2280](../../00-Introduction/README.md#55-how-to-actually-study-this-repository) |
| 00-Introduction | 8.1 The order of operations | 10 |  | [README.md:2617](../../00-Introduction/README.md#81-the-order-of-operations) |
| 01-Computer-Science-Basics | 2.1 The stack from transistor to app | 24 | yes | [README.md:196](../../01-Computer-Science-Basics/README.md#21-the-stack-from-transistor-to-app) |
| 01-Computer-Science-Basics | 2.5 Trust boundaries | 14 | yes | [README.md:444](../../01-Computer-Science-Basics/README.md#25-trust-boundaries) |
| 01-Computer-Science-Basics | 3.11 Kernel space, user space, privilege rings and exception levels | 10 | yes | [README.md:1298](../../01-Computer-Science-Basics/README.md#311-kernel-space-user-space-privilege-rings-and-exception-levels) |
| 01-Computer-Science-Basics | 3.12 Processes: address space, PID, and the process control block | 11 |  | [README.md:1412](../../01-Computer-Science-Basics/README.md#312-processes-address-space-pid-and-the-process-control-block) |
| 01-Computer-Science-Basics | 3.17 The heap, in full | 15 | yes | [README.md:1992](../../01-Computer-Science-Basics/README.md#317-the-heap-in-full) |
| 01-Computer-Science-Basics | 3.18.1 Pages and page tables | 8 | yes | [README.md:2183](../../01-Computer-Science-Basics/README.md#3181-pages-and-page-tables) |
| 01-Computer-Science-Basics | 3.24 The compilation pipeline | 8 | yes | [README.md:2890](../../01-Computer-Science-Basics/README.md#324-the-compilation-pipeline) |
| 01-Computer-Science-Basics | 7. Dynamic Analysis | 12 |  | [README.md:3691](../../01-Computer-Science-Basics/README.md#7-dynamic-analysis) |
| 02-Linux-Basics | 2.1 The layers between your keystroke and the hardware | 21 | yes | [README.md:145](../../02-Linux-Basics/README.md#21-the-layers-between-your-keystroke-and-the-hardware) |
| 02-Linux-Basics | 2.3 The Android filesystem at a glance | 22 | yes | [README.md:228](../../02-Linux-Basics/README.md#23-the-android-filesystem-at-a-glance) |
| 02-Linux-Basics | 2.4 Trust boundaries expressed as UIDs | 23 | yes | [README.md:265](../../02-Linux-Basics/README.md#24-trust-boundaries-expressed-as-uids) |
| 02-Linux-Basics | The problem the inode solves | 10 |  | [README.md:528](../../02-Linux-Basics/README.md#the-problem-the-inode-solves) |
| 02-Linux-Basics | The complete access decision on Android | 13 | yes | [README.md:983](../../02-Linux-Basics/README.md#the-complete-access-decision-on-android) |
| 02-Linux-Basics | Pipes | 6 |  | [README.md:1500](../../02-Linux-Basics/README.md#pipes) |
| 02-Linux-Basics | How Android replaces most of this with Binder | 19 | yes | [README.md:1606](../../02-Linux-Basics/README.md#how-android-replaces-most-of-this-with-binder) |
| 02-Linux-Basics | The dynamic linker, and why `LD_PRELOAD` is a hooking primitive | 12 | yes | [README.md:2013](../../02-Linux-Basics/README.md#the-dynamic-linker-and-why-ld_preload-is-a-hooking-primitive) |
| 02-Linux-Basics | How Magisk uses all of this | 17 | yes | [README.md:2263](../../02-Linux-Basics/README.md#how-magisk-uses-all-of-this) |
| 02-Linux-Basics | The permission decision, as a flowchart | 16 | yes | [labs/lab-01-filesystem-and-permissions.md:1269](../../02-Linux-Basics/labs/lab-01-filesystem-and-permissions.md#the-permission-decision-as-a-flowchart) |
| 03-Programming-Fundamentals | 2.1 The abstraction ladder | 6 |  | [README.md:194](../../03-Programming-Fundamentals/README.md#21-the-abstraction-ladder) |
| 03-Programming-Fundamentals | 2.2 The four translation strategies | 14 |  | [README.md:234](../../03-Programming-Fundamentals/README.md#22-the-four-translation-strategies) |
| 03-Programming-Fundamentals | 2.4 Anatomy of the pipeline that turns C into a running Android library | 16 |  | [README.md:406](../../03-Programming-Fundamentals/README.md#24-anatomy-of-the-pipeline-that-turns-c-into-a-running-android-library) |
| 03-Programming-Fundamentals | 2.5 The Android version of the same pipeline | 12 |  | [README.md:460](../../03-Programming-Fundamentals/README.md#25-the-android-version-of-the-same-pipeline) |
| 03-Programming-Fundamentals | 3.4.2 The worked example — an allocation size overflow | 8 | yes | [README.md:852](../../03-Programming-Fundamentals/README.md#342-the-worked-example--an-allocation-size-overflow) |
| 03-Programming-Fundamentals | 3.6.2 What the CPU actually has | 5 |  | [README.md:1156](../../03-Programming-Fundamentals/README.md#362-what-the-cpu-actually-has) |
| 03-Programming-Fundamentals | 3.8.3 The call stack, drawn | 10 | yes | [README.md:1486](../../03-Programming-Fundamentals/README.md#383-the-call-stack-drawn) |
| 03-Programming-Fundamentals | 3.9.2 The linked list — flexible, scattered, pointer-chasing | 5 |  | [README.md:1680](../../03-Programming-Fundamentals/README.md#392-the-linked-list--flexible-scattered-pointer-chasing) |
| 03-Programming-Fundamentals | 3.9.3 The stack — last in, first out | 5 |  | [README.md:1737](../../03-Programming-Fundamentals/README.md#393-the-stack--last-in-first-out) |
| 03-Programming-Fundamentals | 3.9.4 The queue — first in, first out | 5 |  | [README.md:1782](../../03-Programming-Fundamentals/README.md#394-the-queue--first-in-first-out) |
| 03-Programming-Fundamentals | 3.10.2 The idea | 9 |  | [README.md:1855](../../03-Programming-Fundamentals/README.md#3102-the-idea) |
| 03-Programming-Fundamentals | 3.10.4 Collision resolution — the two real strategies | 5 | yes | [README.md:1911](../../03-Programming-Fundamentals/README.md#3104-collision-resolution--the-two-real-strategies) |
| 03-Programming-Fundamentals | 3.10.7 Why this matters for DEX internals | 10 |  | [README.md:2045](../../03-Programming-Fundamentals/README.md#3107-why-this-matters-for-dex-internals) |
| 03-Programming-Fundamentals | 3.11.1 Trees | 7 |  | [README.md:2086](../../03-Programming-Fundamentals/README.md#3111-trees) |
| 03-Programming-Fundamentals | 3.11.2 Graphs | 7 |  | [README.md:2131](../../03-Programming-Fundamentals/README.md#3112-graphs) |
| 03-Programming-Fundamentals | 3.14.1 The problem | 7 | yes | [README.md:2434](../../03-Programming-Fundamentals/README.md#3141-the-problem) |
| 03-Programming-Fundamentals | 3.14.3 Garbage collection | 10 | yes | [README.md:2483](../../03-Programming-Fundamentals/README.md#3143-garbage-collection) |
| 03-Programming-Fundamentals | 3.17.3 Exceptions | 11 | yes | [README.md:2793](../../03-Programming-Fundamentals/README.md#3173-exceptions) |
| 03-Programming-Fundamentals | 3.18.2 Ahead-of-time compilation to native code | 4 |  | [README.md:2923](../../03-Programming-Fundamentals/README.md#3182-ahead-of-time-compilation-to-native-code) |
| 03-Programming-Fundamentals | 3.18.5 Android's actual pipeline, end to end | 16 |  | [README.md:3013](../../03-Programming-Fundamentals/README.md#3185-androids-actual-pipeline-end-to-end) |
| 03-Programming-Fundamentals | 3.19.2 The mental model: a DAG of snapshots | 9 |  | [README.md:3121](../../03-Programming-Fundamentals/README.md#3192-the-mental-model-a-dag-of-snapshots) |
| 03-Programming-Fundamentals | 3.19.3 The three areas | 4 |  | [README.md:3164](../../03-Programming-Fundamentals/README.md#3193-the-three-areas) |
| 03-Programming-Fundamentals | 8.1 The single most important pentester skill: reading code you did not write | 8 | yes | [README.md:4079](../../03-Programming-Fundamentals/README.md#81-the-single-most-important-pentester-skill-reading-code-you-did-not-write) |
| 03-Programming-Fundamentals | 8.1.3 Move 3 — follow the state | 7 | yes | [README.md:4160](../../03-Programming-Fundamentals/README.md#813-move-3--follow-the-state) |
| 04-Java | 2.1 From source text to a running method | 10 |  | [README.md:219](../../04-Java/README.md#21-from-source-text-to-a-running-method) |
| 04-Java | `HashMap` internals — buckets, hashing, and collisions | 12 |  | [README.md:844](../../04-Java/README.md#hashmap-internals--buckets-hashing-and-collisions) |
| 04-Java | 3.10 Exceptions | 12 |  | [README.md:922](../../04-Java/README.md#310-exceptions) |
| 05-Kotlin | 2.1 The compilation pipeline, and where Kotlin inserts itself | 12 |  | [README.md:190](../../05-Kotlin/README.md#21-the-compilation-pipeline-and-where-kotlin-inserts-itself) |
| 05-Kotlin | 2.3 Where Kotlin's guarantees live at runtime | 15 | yes | [README.md:276](../../05-Kotlin/README.md#23-where-kotlins-guarantees-live-at-runtime) |
| 06-Android-Architecture | 2.1 The complete stack | 42 | yes | [README.md:169](../../06-Android-Architecture/README.md#21-the-complete-stack) |
| 06-Android-Architecture | 2.2 Trust boundaries | 22 | yes | [README.md:278](../../06-Android-Architecture/README.md#22-trust-boundaries) |
| 06-Android-Architecture | 2.3 The process view — what is actually running | 24 |  | [README.md:343](../../06-Android-Architecture/README.md#23-the-process-view--what-is-actually-running) |
| 06-Android-Architecture | 3.2.3 Project Treble and the system/vendor split | 10 | yes | [README.md:620](../../06-Android-Architecture/README.md#323-project-treble-and-the-systemvendor-split) |
| 06-Android-Architecture | 3.5 The Java API framework — what "the framework" actually is | 13 | yes | [README.md:827](../../06-Android-Architecture/README.md#35-the-java-api-framework--what-the-framework-actually-is) |
| 06-Android-Architecture | 3.7.14 What a "soft reboot" actually is | 10 |  | [README.md:1458](../../06-Android-Architecture/README.md#3714-what-a-soft-reboot-actually-is) |
| 06-Android-Architecture | 3.9.2 Why Zygote breaks that assumption | 8 | yes | [README.md:1646](../../06-Android-Architecture/README.md#392-why-zygote-breaks-that-assumption) |
| 06-Android-Architecture | 3.10.1 What it is and why it exists | 14 |  | [README.md:1736](../../06-Android-Architecture/README.md#3101-what-it-is-and-why-it-exists) |
| 06-Android-Architecture | 5.1 The layered trust model, stated precisely | 8 | yes | [README.md:2287](../../06-Android-Architecture/README.md#51-the-layered-trust-model-stated-precisely) |
| 07-AOSP | 1.5 What is **not** in AOSP, and why it dominates security testing | 24 | yes | [README.md:143](../../07-AOSP/README.md#15-what-is-not-in-aosp-and-why-it-dominates-security-testing) |
| 07-AOSP | 2.1 AOSP as a set of layers, mapped to directories | 31 | yes | [README.md:237](../../07-AOSP/README.md#21-aosp-as-a-set-of-layers-mapped-to-directories) |
| 07-AOSP | 2.2 How the ~1000 repositories become one tree | 19 |  | [README.md:300](../../07-AOSP/README.md#22-how-the-1000-repositories-become-one-tree) |
| 07-AOSP | 2.3 The trust boundaries visible in the source tree | 25 | yes | [README.md:354](../../07-AOSP/README.md#23-the-trust-boundaries-visible-in-the-source-tree) |
| 07-AOSP | 2.4 Where a released device diverges from AOSP | 8 | yes | [README.md:419](../../07-AOSP/README.md#24-where-a-released-device-diverges-from-aosp) |
| 07-AOSP | The procedure | 18 |  | [README.md:631](../../07-AOSP/README.md#the-procedure) |
| 07-AOSP | How enforcement works | 11 | yes | [README.md:939](../../07-AOSP/README.md#how-enforcement-works) |
| 07-AOSP | 4.2 Trace B — `SharedPreferences.edit().putString().apply()` to bytes on disk | 35 |  | [README.md:1592](../../07-AOSP/README.md#42-trace-b--sharedpreferenceseditputstringapply-to-bytes-on-disk) |
| 07-AOSP | 4.3 Trace C — a permission check, from `checkSelfPermission` to the enforcement point | 20 | yes | [README.md:1789](../../07-AOSP/README.md#43-trace-c--a-permission-check-from-checkselfpermission-to-the-enforcement-point) |
| 07-AOSP | Step 5 — where enforcement **actually** happens | 11 | yes | [README.md:1944](../../07-AOSP/README.md#step-5--where-enforcement-actually-happens) |
| 07-AOSP | 5.3.4 Patch gapping — the bulletin as a vulnerability feed | 8 | yes | [README.md:2385](../../07-AOSP/README.md#534-patch-gapping--the-bulletin-as-a-vulnerability-feed) |
| 08-Build-System | 2.1 The two systems side by side | 15 | yes | [README.md:180](../../08-Build-System/README.md#21-the-two-systems-side-by-side) |
| 08-Build-System | 2.2 The platform build graph | 14 |  | [README.md:224](../../08-Build-System/README.md#22-the-platform-build-graph) |
| 08-Build-System | 2.3 The app build pipeline — the big diagram | 46 | yes | [README.md:276](../../08-Build-System/README.md#23-the-app-build-pipeline--the-big-diagram) |
| 08-Build-System | 2.4 The trust boundaries of a build | 15 | yes | [README.md:416](../../08-Build-System/README.md#24-the-trust-boundaries-of-a-build) |
| 08-Build-System | 3.4 How SELinux policy is built | 18 |  | [README.md:752](../../08-Build-System/README.md#34-how-selinux-policy-is-built) |
| 08-Build-System | 3.9 Build variants: types, flavours, and source sets | 18 |  | [README.md:1064](../../08-Build-System/README.md#39-build-variants-types-flavours-and-source-sets) |
| 08-Build-System | The priority order | 6 | yes | [README.md:1146](../../08-Build-System/README.md#the-priority-order) |
| 08-Build-System | 3.15 Shrinking, obfuscation, and resource shrinking | 16 |  | [README.md:1543](../../08-Build-System/README.md#315-shrinking-obfuscation-and-resource-shrinking) |
| 08-Build-System | 3.16 Resources: `aapt2` compile and link | 13 |  | [README.md:1596](../../08-Build-System/README.md#316-resources-aapt2-compile-and-link) |
| 08-Build-System | 3.19 AAB, `bundletool`, splits and dynamic feature modules | 8 |  | [README.md:1746](../../08-Build-System/README.md#319-aab-bundletool-splits-and-dynamic-feature-modules) |
| 08-Build-System | 5.4 Supply-chain risk, in depth | 18 | yes | [README.md:2689](../../08-Build-System/README.md#54-supply-chain-risk-in-depth) |
| 09-Android-App-Internals | 2.1 The three axes: identity, storage, execution | 17 | yes | [README.md:183](../../09-Android-App-Internals/README.md#21-the-three-axes-identity-storage-execution) |
| 09-Android-App-Internals | 2.2 Who does what: the component map | 25 | yes | [README.md:251](../../09-Android-App-Internals/README.md#22-who-does-what-the-component-map) |
| 09-Android-App-Internals | 3.15 The main thread: Looper, MessageQueue, Handler | 16 |  | [README.md:1400](../../09-Android-App-Internals/README.md#315-the-main-thread-looper-messagequeue-handler) |
| 10-APK-Internals | 2.2 Parsing order — why it runs backwards | 13 | yes | [README.md:302](../../10-APK-Internals/README.md#22-parsing-order--why-it-runs-backwards) |
| 10-APK-Internals | 2.3 The full picture | 26 | yes | [README.md:334](../../10-APK-Internals/README.md#23-the-full-picture) |
| 10-APK-Internals | 3.4 resources.arsc | 13 |  | [README.md:621](../../10-APK-Internals/README.md#34-resourcesarsc) |
| 10-APK-Internals | 3.5 Signing — the heart of the chapter | 21 | yes | [README.md:682](../../10-APK-Internals/README.md#35-signing--the-heart-of-the-chapter) |
| 10-APK-Internals | The honest hierarchy | 8 | yes | [README.md:1370](../../10-APK-Internals/README.md#the-honest-hierarchy) |
| 11-Android-Runtime | 1.5 Register machines versus stack machines, from first principles | 9 |  | [README.md:345](../../11-Android-Runtime/README.md#15-register-machines-versus-stack-machines-from-first-principles) |
| 11-Android-Runtime | 2.1 Where the runtime sits in the Android stack | 19 | yes | [README.md:486](../../11-Android-Runtime/README.md#21-where-the-runtime-sits-in-the-android-stack) |
| 11-Android-Runtime | 2.2 The complete lifecycle of code, source to silicon | 15 | yes | [README.md:552](../../11-Android-Runtime/README.md#22-the-complete-lifecycle-of-code-source-to-silicon) |
| 11-Android-Runtime | 2.3 The per-app process model | 10 | yes | [README.md:660](../../11-Android-Runtime/README.md#23-the-per-app-process-model) |
| 11-Android-Runtime | 2.6 The trust boundary map | 12 | yes | [README.md:858](../../11-Android-Runtime/README.md#26-the-trust-boundary-map) |
| 11-Android-Runtime | Mode 1 — Interpretation | 9 |  | [README.md:922](../../11-Android-Runtime/README.md#mode-1--interpretation) |
| 11-Android-Runtime | The comparison, side by side | 11 |  | [README.md:1014](../../11-Android-Runtime/README.md#the-comparison-side-by-side) |
| 11-Android-Runtime | 3.10 Dynamic class loading as an attack technique | 17 | yes | [README.md:1543](../../11-Android-Runtime/README.md#310-dynamic-class-loading-as-an-attack-technique) |
| 12-DEX-Internals | 2.2 The index-and-data split | 16 |  | [README.md:338](../../12-DEX-Internals/README.md#22-the-index-and-data-split) |
| 12-DEX-Internals | 2.3 From `.java` to `classes.dex` | 9 |  | [README.md:396](../../12-DEX-Internals/README.md#23-from-java-to-classesdex) |
| 12-DEX-Internals | 3.8 `string_id_item` and `string_data_item` | 7 |  | [README.md:1174](../../12-DEX-Internals/README.md#38-string_id_item-and-string_data_item) |
| 12-DEX-Internals | 3.13 `class_def_item` | 13 |  | [README.md:1356](../../12-DEX-Internals/README.md#313-class_def_item) |
| 12-DEX-Internals | The signed size convention | 10 | yes | [README.md:1833](../../12-DEX-Internals/README.md#the-signed-size-convention) |
| 12-DEX-Internals | 5.1 Why the format is a security topic at all | 5 | yes | [README.md:2755](../../12-DEX-Internals/README.md#51-why-the-format-is-a-security-topic-at-all) |
| 13-ART | 2.1 Where ART sits in the system | 14 | yes | [README.md:193](../../13-ART/README.md#21-where-art-sits-in-the-system) |
| 13-ART | 2.2 The compilation and execution pipeline | 12 | yes | [README.md:242](../../13-ART/README.md#22-the-compilation-and-execution-pipeline) |
| 13-ART | 2.5 Trust boundaries around ART | 6 | yes | [README.md:348](../../13-ART/README.md#25-trust-boundaries-around-art) |
| 13-ART | 3.16 Entry points and the trampolines they point at | 10 | yes | [README.md:1086](../../13-ART/README.md#316-entry-points-and-the-trampolines-they-point-at) |
| 13-ART | odrefresh and odsign | 9 |  | [README.md:1450](../../13-ART/README.md#odrefresh-and-odsign) |
| 14-Dalvik | 2.1 The Dalvik pipeline, end to end | 14 | yes | [README.md:306](../../14-Dalvik/README.md#21-the-dalvik-pipeline-end-to-end) |
| 14-Dalvik | 2.2 Stack machine versus register machine | 9 |  | [README.md:353](../../14-Dalvik/README.md#22-stack-machine-versus-register-machine) |
| 14-Dalvik | 2.6 Where Smali sits in the modern toolchain | 14 | yes | [README.md:623](../../14-Dalvik/README.md#26-where-smali-sits-in-the-modern-toolchain) |
| 14-Dalvik | 2.7 Trust boundaries when you rewrite Smali | 11 | yes | [README.md:665](../../14-Dalvik/README.md#27-trust-boundaries-when-you-rewrite-smali) |
| 15-Native-Code | 2.1 From APK entry to mapped page | 19 | yes | [README.md:213](../../15-Native-Code/README.md#21-from-apk-entry-to-mapped-page) |
| 15-Native-Code | 2.4 Trust boundaries at the native layer | 15 | yes | [README.md:358](../../15-Native-Code/README.md#24-trust-boundaries-at-the-native-layer) |
| 15-Native-Code | 3.8 PLT and GOT: the indirection that makes hooking possible | 7 | yes | [README.md:979](../../15-Native-Code/README.md#38-plt-and-got-the-indirection-that-makes-hooking-possible) |
| 16-JNI | 2.1 The bridge, drawn | 12 | yes | [README.md:289](../../16-JNI/README.md#21-the-bridge-drawn) |
| 16-JNI | 2.3 The `JNIEnv` double indirection | 9 |  | [README.md:405](../../16-JNI/README.md#23-the-jnienv-double-indirection) |
| 16-JNI | 2.4 Trust boundaries at the bridge | 15 | yes | [README.md:440](../../16-JNI/README.md#24-trust-boundaries-at-the-bridge) |
| 16-JNI | 6.6 The decision tree | 11 |  | [README.md:3059](../../16-JNI/README.md#66-the-decision-tree) |
| 17-Libraries | The library stack, from app code to kernel | 26 | yes | [README.md:173](../../17-Libraries/README.md#the-library-stack-from-app-code-to-kernel) |
| 17-Libraries | The three rings, as a decision tree | 8 | yes | [README.md:367](../../17-Libraries/README.md#the-three-rings-as-a-decision-tree) |
| 17-Libraries | 8.1 The methodology — "enumerate every library in this APK and rate each" | 20 | yes | [README.md:1786](../../17-Libraries/README.md#81-the-methodology--enumerate-every-library-in-this-apk-and-rate-each) |
| 17-Libraries | The one-page decision flow | 15 | yes | [mindmap.md:287](../../17-Libraries/mindmap.md#the-one-page-decision-flow) |
| 18-ARM | 2.1 What is actually on the chip | 24 |  | [README.md:174](../../18-ARM/README.md#21-what-is-actually-on-the-chip) |
| 18-ARM | 2.3 From C to silicon | 11 |  | [README.md:285](../../18-ARM/README.md#23-from-c-to-silicon) |
| 19-Memory | 2.2 What happens when you call `malloc(32)` | 13 | yes | [README.md:216](../../19-Memory/README.md#22-what-happens-when-you-call-malloc32) |
| 19-Memory | 2.4 The detection landscape | 16 |  | [README.md:308](../../19-Memory/README.md#24-the-detection-landscape) |
| 19-Memory | 3.13.1 The shared idea: tagged memory | 11 | yes | [README.md:1089](../../19-Memory/README.md#3131-the-shared-idea-tagged-memory) |
| 20-Security-Architecture | 2.1 Defence in depth, drawn once | 30 | yes | [README.md:103](../../20-Security-Architecture/README.md#21-defence-in-depth-drawn-once) |
| 20-Security-Architecture | 2.2 Trust boundaries, named explicitly | 20 | yes | [README.md:171](../../20-Security-Architecture/README.md#22-trust-boundaries-named-explicitly) |
| 20-Security-Architecture | The mechanism: a Merkle tree | 15 | yes | [README.md:382](../../20-Security-Architecture/README.md#the-mechanism-a-merkle-tree) |
| 20-Security-Architecture | Why dm-verity forced Magisk to be "systemless" | 7 | yes | [README.md:458](../../20-Security-Architecture/README.md#why-dm-verity-forced-magisk-to-be-systemless) |
| 20-Security-Architecture | 3.9 Synthesis — what is actually attackable in a typical engagement | 12 | yes | [README.md:800](../../20-Security-Architecture/README.md#39-synthesis--what-is-actually-attackable-in-a-typical-engagement) |
| 21-App-Sandbox | 2.1 The sandbox as nested enforcement layers | 23 | yes | [README.md:114](../../21-App-Sandbox/README.md#21-the-sandbox-as-nested-enforcement-layers) |
| 21-App-Sandbox | 2.2 The trust boundaries, named | 15 | yes | [README.md:171](../../21-App-Sandbox/README.md#22-the-trust-boundaries-named) |
| 21-App-Sandbox | 3.4 SELinux as the second layer — the short version | 8 | yes | [README.md:547](../../21-App-Sandbox/README.md#34-selinux-as-the-second-layer--the-short-version) |
| 21-App-Sandbox | What `isolatedProcess` gives you | 7 | yes | [README.md:709](../../21-App-Sandbox/README.md#what-isolatedprocess-gives-you) |
| 21-App-Sandbox | What the SDK Runtime does | 9 | yes | [README.md:786](../../21-App-Sandbox/README.md#what-the-sdk-runtime-does) |
| 21-App-Sandbox | What scoped storage changes | 6 | yes | [README.md:958](../../21-App-Sandbox/README.md#what-scoped-storage-changes) |
| 21-App-Sandbox | 3.14 What the sandbox does NOT protect against | 14 | yes | [README.md:1094](../../21-App-Sandbox/README.md#314-what-the-sandbox-does-not-protect-against) |
| 21-App-Sandbox | 3.15 Sandbox escape — the six classes | 13 | yes | [README.md:1325](../../21-App-Sandbox/README.md#315-sandbox-escape--the-six-classes) |
| 22-SELinux | 2.1 Where SELinux sits in a system call | 21 | yes | [README.md:127](../../22-SELinux/README.md#21-where-selinux-sits-in-a-system-call) |
| 22-SELinux | 2.2 The three layers of enforcement, drawn | 13 | yes | [README.md:184](../../22-SELinux/README.md#22-the-three-layers-of-enforcement-drawn) |
| 22-SELinux | 2.4 The trust boundaries SELinux draws | 19 | yes | [README.md:264](../../22-SELinux/README.md#24-the-trust-boundaries-selinux-draws) |
| 22-SELinux | Diagram: the two apps | 14 | yes | [README.md:908](../../22-SELinux/README.md#diagram-the-two-apps) |
| 23-Permissions | 2.1 The life of one permission, end to end | 15 | yes | [README.md:207](../../23-Permissions/README.md#21-the-life-of-one-permission-end-to-end) |
| 23-Permissions | 2.2 The three lists, and why conflating them produces wrong findings | 9 | yes | [README.md:261](../../23-Permissions/README.md#22-the-three-lists-and-why-conflating-them-produces-wrong-findings) |
| 23-Permissions | 2.4 The trust boundary drawn properly | 10 | yes | [README.md:348](../../23-Permissions/README.md#24-the-trust-boundary-drawn-properly) |
| 23-Permissions | Where the framework check physically lives | 11 | yes | [README.md:1510](../../23-Permissions/README.md#where-the-framework-check-physically-lives) |
| 23-Permissions | The idea | 8 | yes | [README.md:1560](../../23-Permissions/README.md#the-idea) |
| 24-IPC | 2.1 The whole IPC landscape in one picture | 20 | yes | [README.md:184](../../24-IPC/README.md#21-the-whole-ipc-landscape-in-one-picture) |
| 24-IPC | 2.2 The two shapes of IPC: mediated and direct | 9 | yes | [README.md:267](../../24-IPC/README.md#22-the-two-shapes-of-ipc-mediated-and-direct) |
| 24-IPC | 2.4 Trust boundaries drawn explicitly | 13 | yes | [README.md:339](../../24-IPC/README.md#24-trust-boundaries-drawn-explicitly) |
| 24-IPC | 3.3 Binder — the substrate everything else sits on | 11 | yes | [README.md:468](../../24-IPC/README.md#33-binder--the-substrate-everything-else-sits-on) |
| 24-IPC | 3.4 Intents — the framework's message envelope | 9 | yes | [README.md:515](../../24-IPC/README.md#34-intents--the-frameworks-message-envelope) |
| 24-IPC | 3.22 A full methodology for enumerating an app's IPC surface | 8 |  | [README.md:2089](../../24-IPC/README.md#322-a-full-methodology-for-enumerating-an-apps-ipc-surface) |
| 25-Binder | 2.1 The whole stack in one picture | 22 | yes | [README.md:169](../../25-Binder/README.md#21-the-whole-stack-in-one-picture) |
| 25-Binder | 2.3 The trust boundaries, drawn explicitly | 16 | yes | [README.md:277](../../25-Binder/README.md#23-the-trust-boundaries-drawn-explicitly) |
| 25-Binder | 2.4 Four device nodes, four separate worlds | 12 | yes | [README.md:329](../../25-Binder/README.md#24-four-device-nodes-four-separate-worlds) |
| 25-Binder | 5.1 The one-sentence threat model | 16 | yes | [README.md:2008](../../25-Binder/README.md#51-the-one-sentence-threat-model) |
| 26-Intent | 2.3 The trust boundary | 12 | yes | [README.md:252](../../26-Intent/README.md#23-the-trust-boundary) |
| 26-Intent | 2.4 Where resolution happens | 13 | yes | [README.md:304](../../26-Intent/README.md#24-where-resolution-happens) |
| 26-Intent | 3.4 The resolution algorithm — the part readers get wrong | 13 | yes | [README.md:462](../../26-Intent/README.md#34-the-resolution-algorithm--the-part-readers-get-wrong) |
| 26-Intent | Test 3 — data | 8 |  | [README.md:536](../../26-Intent/README.md#test-3--data) |
| 26-Intent | 4.3 From `startActivity` to the resolver | 33 | yes | [README.md:1395](../../26-Intent/README.md#43-from-startactivity-to-the-resolver) |
| 26-Intent | The two apps, at a glance | 10 | yes | [examples/README.md:80](../../26-Intent/examples/README.md#the-two-apps-at-a-glance) |
| 27-ContentProviders | The call path from a client app to a provider | 19 | yes | [README.md:137](../../27-ContentProviders/README.md#the-call-path-from-a-client-app-to-a-provider) |
| 27-ContentProviders | Anatomy of a content URI | 10 | yes | [README.md:208](../../27-ContentProviders/README.md#anatomy-of-a-content-uri) |
| 27-ContentProviders | Where providers sit among the four component types | 8 |  | [README.md:231](../../27-ContentProviders/README.md#where-providers-sit-among-the-four-component-types) |
| 27-ContentProviders | The exploit | 7 | yes | [README.md:1812](../../27-ContentProviders/README.md#the-exploit) |
| 27-ContentProviders | 7.7 A complete testing workflow | 15 | yes | [README.md:2734](../../27-ContentProviders/README.md#77-a-complete-testing-workflow) |
| 28-Services | 1.4 The three shapes, in one paragraph each | 9 |  | [README.md:137](../../28-Services/README.md#14-the-three-shapes-in-one-paragraph-each) |
| 28-Services | 2.1 Who is involved | 18 | yes | [README.md:195](../../28-Services/README.md#21-who-is-involved) |
| 28-Services | 2.4 The trust boundaries, named | 12 | yes | [README.md:330](../../28-Services/README.md#24-the-trust-boundaries-named) |
| 28-Services | 2.5 Where the three IBinder shapes sit | 9 | yes | [README.md:371](../../28-Services/README.md#25-where-the-three-ibinder-shapes-sit) |
| 29-BroadcastReceivers | 2.1 The whole path, in one picture | 26 | yes | [README.md:202](../../29-BroadcastReceivers/README.md#21-the-whole-path-in-one-picture) |
| 29-BroadcastReceivers | 2.2 The two registration paths — the visibility gap | 15 | yes | [README.md:280](../../29-BroadcastReceivers/README.md#22-the-two-registration-paths--the-visibility-gap) |
| 29-BroadcastReceivers | 2.3 The trust boundary, drawn explicitly | 16 | yes | [README.md:349](../../29-BroadcastReceivers/README.md#23-the-trust-boundary-drawn-explicitly) |
| 29-BroadcastReceivers | 3.8 The two permission checks, and their asymmetry | 8 | yes | [README.md:1031](../../29-BroadcastReceivers/README.md#38-the-two-permission-checks-and-their-asymmetry) |
| 30-Activities | 2.1 The four nouns, and how they nest | 10 | yes | [README.md:159](../../30-Activities/README.md#21-the-four-nouns-and-how-they-nest) |
| 30-Activities | 2.3 The trust boundary | 12 | yes | [README.md:252](../../30-Activities/README.md#23-the-trust-boundary) |
| 30-Activities | 2.4 Where the two signature attacks sit | 11 | yes | [README.md:300](../../30-Activities/README.md#24-where-the-two-signature-attacks-sit) |
| 31-Fragments | 2.1 Where a Fragment actually sits | 14 | yes | [README.md:170](../../31-Fragments/README.md#21-where-a-fragment-actually-sits) |
| 31-Fragments | 2.3 The trust boundary | 14 | yes | [README.md:276](../../31-Fragments/README.md#23-the-trust-boundary) |
| 31-Fragments | 5.1 The taxonomy | 12 | yes | [README.md:1153](../../31-Fragments/README.md#51-the-taxonomy) |
| 32-Manifest | Where the manifest sits in the APK | 9 | yes | [README.md:139](../../32-Manifest/README.md#where-the-manifest-sits-in-the-apk) |
| 32-Manifest | The lifecycle of a manifest, from source to enforcement | 16 | yes | [README.md:169](../../32-Manifest/README.md#the-lifecycle-of-a-manifest-from-source-to-enforcement) |
| 32-Manifest | The trust boundary the manifest defines | 11 | yes | [README.md:222](../../32-Manifest/README.md#the-trust-boundary-the-manifest-defines) |
| 32-Manifest | The two parsers you must reconcile | 9 | yes | [README.md:263](../../32-Manifest/README.md#the-two-parsers-you-must-reconcile) |
| 32-Manifest | Reading the backup attributes together | 10 | yes | [README.md:643](../../32-Manifest/README.md#reading-the-backup-attributes-together) |
| 32-Manifest | The provider audit flow | 18 | yes | [README.md:1008](../../32-Manifest/README.md#the-provider-audit-flow) |
| 32-Manifest | 3.17 Manifest merging — how components you never wrote appear in your APK | 8 | yes | [README.md:1394](../../32-Manifest/README.md#317-manifest-merging--how-components-you-never-wrote-appear-in-your-apk) |
| 32-Manifest | 4.4 The runtime check: `exported` and `permission` for an Activity | 13 | yes | [README.md:1628](../../32-Manifest/README.md#44-the-runtime-check-exported-and-permission-for-an-activity) |
| 33-Storage | 2.2 The two trust boundaries | 14 | yes | [README.md:232](../../33-Storage/README.md#22-the-two-trust-boundaries) |
| 34-Cryptography | 2.1 The map of cryptography | 17 |  | [README.md:192](../../34-Cryptography/README.md#21-the-map-of-cryptography) |
| 34-Cryptography | 2.2 Where crypto lives in the Android stack | 19 | yes | [README.md:241](../../34-Cryptography/README.md#22-where-crypto-lives-in-the-android-stack) |
| 34-Cryptography | 2.4 The shape of a *correct* encryption operation | 12 | yes | [README.md:355](../../34-Cryptography/README.md#24-the-shape-of-a-correct-encryption-operation) |
| 34-Cryptography | 3.3.1 ECB — Electronic Codebook | 9 | yes | [README.md:505](../../34-Cryptography/README.md#331-ecb--electronic-codebook) |
| 34-Cryptography | 3.3.2 CBC — Cipher Block Chaining | 13 |  | [README.md:549](../../34-Cryptography/README.md#332-cbc--cipher-block-chaining) |
| 34-Cryptography | 3.3.4 CTR — Counter mode | 15 |  | [README.md:676](../../34-Cryptography/README.md#334-ctr--counter-mode) |
| 34-Cryptography | 3.3.5 GCM — Galois/Counter Mode, and the catastrophe of nonce reuse | 22 | yes | [README.md:710](../../34-Cryptography/README.md#335-gcm--galoiscounter-mode-and-the-catastrophe-of-nonce-reuse) |
| 34-Cryptography | 3.6.1 The problem it solves | 5 | yes | [README.md:959](../../34-Cryptography/README.md#361-the-problem-it-solves) |
| 34-Cryptography | 3.7.1 Length extension, and why HMAC exists | 8 | yes | [README.md:1209](../../34-Cryptography/README.md#371-length-extension-and-why-hmac-exists) |
| 34-Cryptography | 3.8.2 Encrypt-then-MAC versus MAC-then-encrypt | 17 | yes | [README.md:1264](../../34-Cryptography/README.md#382-encrypt-then-mac-versus-mac-then-encrypt) |
| 34-Cryptography | 3.8.3 Key derivation functions | 11 |  | [README.md:1344](../../34-Cryptography/README.md#383-key-derivation-functions) |
| 34-Cryptography | 3.10 Digital signatures and PKI in one page | 7 |  | [README.md:1462](../../34-Cryptography/README.md#310-digital-signatures-and-pki-in-one-page) |
| 35-SSL | 2.1 Where TLS sits | 14 | yes | [README.md:185](../../35-SSL/README.md#21-where-tls-sits) |
| 35-SSL | 2.3 The two questions, drawn separately | 7 | yes | [README.md:284](../../35-SSL/README.md#23-the-two-questions-drawn-separately) |
| 35-SSL | The shape of the exercise | 10 | yes | [labs/lab-01-end-to-end-interception.md:79](../../35-SSL/labs/lab-01-end-to-end-interception.md#the-shape-of-the-exercise) |
| 35-SSL | Stage 5 — Route 2: promote the CA to the system store | 6 | yes | [labs/lab-01-end-to-end-interception.md:366](../../35-SSL/labs/lab-01-end-to-end-interception.md#stage-5--route-2-promote-the-ca-to-the-system-store) |
| 35-SSL | Why one bad certificate is not enough | 9 | yes | [labs/lab-02-deliberate-bad-certificate.md:39](../../35-SSL/labs/lab-02-deliberate-bad-certificate.md#why-one-bad-certificate-is-not-enough) |
| 35-SSL | Part 0 — The six checks, named precisely | 14 | yes | [labs/lab-03-dissecting-validation.md:83](../../35-SSL/labs/lab-03-dissecting-validation.md#part-0--the-six-checks-named-precisely) |
| 35-SSL | The field: what stands between you and the flag | 8 | yes | [labs/lab-04-ctf-the-trusted-impostor.md:316](../../35-SSL/labs/lab-04-ctf-the-trusted-impostor.md#the-field-what-stands-between-you-and-the-flag) |
| 36-CertificatePinning | 2.1 The layers | 15 | yes | [README.md:204](../../36-CertificatePinning/README.md#21-the-layers) |
| 36-CertificatePinning | 2.3 Where the code physically lives | 11 | yes | [README.md:308](../../36-CertificatePinning/README.md#23-where-the-code-physically-lives) |
| 36-CertificatePinning | 7.1 The workflow, in the order that works | 11 | yes | [README.md:1772](../../36-CertificatePinning/README.md#71-the-workflow-in-the-order-that-works) |
| 36-CertificatePinning | 1. The failure this lab is designed to give you | 9 | yes | [labs/lab-02-defeat-a-two-layer-pin.md:28](../../36-CertificatePinning/labs/lab-02-defeat-a-two-layer-pin.md#1-the-failure-this-lab-is-designed-to-give-you) |
| 36-CertificatePinning | 4.1 The topology | 10 | yes | [labs/lab-04-ctf-the-pin-that-moved.md:102](../../36-CertificatePinning/labs/lab-04-ctf-the-pin-that-moved.md#41-the-topology) |
| 37-RootDetection | 2.1 What is on the device after rooting | 18 | yes | [README.md:175](../../37-RootDetection/README.md#21-what-is-on-the-device-after-rooting) |
| 37-RootDetection | 2.2 The detection surface map | 16 | yes | [README.md:234](../../37-RootDetection/README.md#22-the-detection-surface-map) |
| 37-RootDetection | 2.3 Where a check runs, and why that decides your approach | 11 | yes | [README.md:275](../../37-RootDetection/README.md#23-where-a-check-runs-and-why-that-decides-your-approach) |
| 37-RootDetection | 2.4 The trust boundary, drawn honestly | 9 | yes | [README.md:302](../../37-RootDetection/README.md#24-the-trust-boundary-drawn-honestly) |
| 37-RootDetection | How it works | 12 | yes | [README.md:1636](../../37-RootDetection/README.md#how-it-works) |
| 37-RootDetection | 7.1 The methodology, before any tool | 13 | yes | [README.md:2460](../../37-RootDetection/README.md#71-the-methodology-before-any-tool) |
| 37-RootDetection | 9.4 Real application — a banking app's layered posture | 9 | yes | [README.md:2872](../../37-RootDetection/README.md#94-real-application--a-banking-apps-layered-posture) |
| 38-TamperDetection | 2.1 The life of a tampered app | 17 | yes | [README.md:265](../../38-TamperDetection/README.md#21-the-life-of-a-tampered-app) |
| 38-TamperDetection | 2.2 The five tiers — when each check runs | 14 |  | [README.md:312](../../38-TamperDetection/README.md#22-the-five-tiers--when-each-check-runs) |
| 38-TamperDetection | 2.4 The detection surface, drawn honestly | 16 | yes | [README.md:403](../../38-TamperDetection/README.md#24-the-detection-surface-drawn-honestly) |
| 38-TamperDetection | 2.5 A decision tree for the first ten minutes | 15 | yes | [README.md:449](../../38-TamperDetection/README.md#25-a-decision-tree-for-the-first-ten-minutes) |
| 38-TamperDetection | Cross-chapter map | 16 |  | [mindmap.md:222](../../38-TamperDetection/mindmap.md#cross-chapter-map) |
| 39-EmulatorDetection | 2.1 Where the signals come from | 16 | yes | [README.md:201](../../39-EmulatorDetection/README.md#21-where-the-signals-come-from) |
| 39-EmulatorDetection | 2.2 The detection surface, by cost to defeat | 15 | yes | [README.md:269](../../39-EmulatorDetection/README.md#22-the-detection-surface-by-cost-to-defeat) |
| 39-EmulatorDetection | 2.3 The trust boundary, drawn honestly | 11 | yes | [README.md:324](../../39-EmulatorDetection/README.md#23-the-trust-boundary-drawn-honestly) |
| 39-EmulatorDetection | Related chapters | 12 | yes | [mindmap.md:176](../../39-EmulatorDetection/mindmap.md#related-chapters) |
| 40-Obfuscation | Where obfuscation happens in the build | 23 | yes | [README.md:160](../../40-Obfuscation/README.md#where-obfuscation-happens-in-the-build) |
| 40-Obfuscation | The attacker's decision tree | 12 | yes | [README.md:238](../../40-Obfuscation/README.md#the-attackers-decision-tree) |
| 40-Obfuscation | 3.3.2 Control-flow flattening — the important one | 10 |  | [README.md:801](../../40-Obfuscation/README.md#332-control-flow-flattening--the-important-one) |
| 40-Obfuscation | 3.3.2 Control-flow flattening — the important one | 11 | yes | [README.md:817](../../40-Obfuscation/README.md#332-control-flow-flattening--the-important-one) |
| 40-Obfuscation | 3.7.3 The general unpacking methodology | 12 | yes | [README.md:1204](../../40-Obfuscation/README.md#373-the-general-unpacking-methodology) |
| 40-Obfuscation | 3.7.4 Commercial protector families, descriptively | 7 |  | [README.md:1337](../../40-Obfuscation/README.md#374-commercial-protector-families-descriptively) |
| 40-Obfuscation | 6.1 THE DEOBFUSCATION METHODOLOGY | 12 | yes | [README.md:1802](../../40-Obfuscation/README.md#61-the-deobfuscation-methodology) |
| 40-Obfuscation | Phase 2 — Decide static or dynamic | 7 | yes | [README.md:1856](../../40-Obfuscation/README.md#phase-2--decide-static-or-dynamic) |
| 41-ProGuard | 2.1 Where the rules file enters the build | 19 | yes | [README.md:214](../../41-ProGuard/README.md#21-where-the-rules-file-enters-the-build) |
| 41-ProGuard | 2.3 The reachability model — what "keep" actually means | 15 | yes | [README.md:325](../../41-ProGuard/README.md#23-the-reachability-model--what-keep-actually-means) |
| 41-ProGuard | 2.4 Trust boundaries, and where the interesting artefacts land | 11 | yes | [README.md:401](../../41-ProGuard/README.md#24-trust-boundaries-and-where-the-interesting-artefacts-land) |
| 41-ProGuard | 2.5 Where a rules file physically lives | 13 |  | [README.md:450](../../41-ProGuard/README.md#25-where-a-rules-file-physically-lives) |
| 41-ProGuard | The same material as a decision path | 22 | yes | [mindmap.md:154](../../41-ProGuard/mindmap.md#the-same-material-as-a-decision-path) |
| 42-R8 | 2.1 Where R8 sits in the build | 17 | yes | [README.md:139](../../42-R8/README.md#21-where-r8-sits-in-the-build) |
| 42-R8 | 2.3 What comes out, and who is allowed to see it | 10 | yes | [README.md:220](../../42-R8/README.md#23-what-comes-out-and-who-is-allowed-to-see-it) |
| 43-WebView | 2.1 Where everything actually runs | 15 | yes | [README.md:217](../../43-WebView/README.md#21-where-everything-actually-runs) |
| 43-WebView | 2.3 The class stack, from the API you type to the code that runs | 15 |  | [README.md:335](../../43-WebView/README.md#23-the-class-stack-from-the-api-you-type-to-the-code-that-runs) |
| 43-WebView | 2.4 The certificate-error path, drawn on its own | 15 | yes | [README.md:393](../../43-WebView/README.md#24-the-certificate-error-path-drawn-on-its-own) |
| 43-WebView | 2.5 The two network stacks in one app | 11 | yes | [README.md:439](../../43-WebView/README.md#25-the-two-network-stacks-in-one-app) |
| 44-NetworkSecurityConfig | 2.1 From a manifest attribute to a TLS decision | 23 |  | [README.md:221](../../44-NetworkSecurityConfig/README.md#21-from-a-manifest-attribute-to-a-tls-decision) |
| 44-NetworkSecurityConfig | 2.3 Which configuration applies to which host | 11 | yes | [README.md:328](../../44-NetworkSecurityConfig/README.md#23-which-configuration-applies-to-which-host) |
| 45-OAuth | The four roles | 4 | yes | [README.md:111](../../45-OAuth/README.md#the-four-roles) |
| 45-OAuth | 2.1 The complete Android OAuth topology | 13 | yes | [README.md:192](../../45-OAuth/README.md#21-the-complete-android-oauth-topology) |
| 45-OAuth | 2.2 The trust boundaries, drawn explicitly | 16 | yes | [README.md:250](../../45-OAuth/README.md#22-the-trust-boundaries-drawn-explicitly) |
| 45-OAuth | 2.4 Grant-type decision tree | 9 | yes | [README.md:324](../../45-OAuth/README.md#24-grant-type-decision-tree) |
| 45-OAuth | 3.9 Custom Tabs versus WebView | 8 | yes | [README.md:834](../../45-OAuth/README.md#39-custom-tabs-versus-webview) |
| 45-OAuth | `id_token` versus `access_token` — the distinction that breaks systems | 15 | yes | [README.md:1193](../../45-OAuth/README.md#id_token-versus-access_token--the-distinction-that-breaks-systems) |
| 45-OAuth | 5.5 How pentesters test it — the methodology in one place | 9 |  | [README.md:1825](../../45-OAuth/README.md#55-how-pentesters-test-it--the-methodology-in-one-place) |
| 46-Tokens | 2.1 The life of a token, end to end | 12 | yes | [README.md:267](../../46-Tokens/README.md#21-the-life-of-a-token-end-to-end) |
| 46-Tokens | 2.2 The trust boundaries | 16 | yes | [README.md:332](../../46-Tokens/README.md#22-the-trust-boundaries) |
| 46-Tokens | 2.3 The two token shapes, side by side | 10 |  | [README.md:381](../../46-Tokens/README.md#23-the-two-token-shapes-side-by-side) |
| 46-Tokens | 3.3 Opaque tokens, and why the distinction changes everything | 10 | yes | [README.md:650](../../46-Tokens/README.md#33-opaque-tokens-and-why-the-distinction-changes-everything) |
| 46-Tokens | 7.1 The method, in order | 10 |  | [README.md:2349](../../46-Tokens/README.md#71-the-method-in-order) |
| 47-Authentication | 2.1 The whole picture, and where trust stops | 20 | yes | [README.md:252](../../47-Authentication/README.md#21-the-whole-picture-and-where-trust-stops) |
| 47-Authentication | 3.3 Password handling — where a password comes from, before it reaches a KDF | 9 | yes | [README.md:554](../../47-Authentication/README.md#33-password-handling--where-a-password-comes-from-before-it-reaches-a-kdf) |
| 47-Authentication | 7.1 The order of operations, and why traffic comes first | 6 | yes | [README.md:2563](../../47-Authentication/README.md#71-the-order-of-operations-and-why-traffic-comes-first) |
| 48-Biometrics | 2.1 The whole system, once | 18 | yes | [README.md:190](../../48-Biometrics/README.md#21-the-whole-system-once) |
| 48-Biometrics | 2.3 Where each authenticator class can and cannot reach | 12 | yes | [README.md:326](../../48-Biometrics/README.md#23-where-each-authenticator-class-can-and-cannot-reach) |
| 48-Biometrics | 3.8 What actually reaches the TEE — enrolment, matching, and the token | 10 | yes | [README.md:848](../../48-Biometrics/README.md#38-what-actually-reaches-the-tee--enrolment-matching-and-the-token) |
| 48-Biometrics | 7.1 The three-pass method | 12 | yes | [README.md:1788](../../48-Biometrics/README.md#71-the-three-pass-method) |
| 48-Biometrics | 9.4 Real application — a password manager | 6 |  | [README.md:2390](../../48-Biometrics/README.md#94-real-application--a-password-manager) |
| 48-Biometrics | 0. The shape of the work | 7 |  | [labs/lab-03-audit-a-real-app.md:32](../../48-Biometrics/labs/lab-03-audit-a-real-app.md#0-the-shape-of-the-work) |
| 49-KeyStore | 2.1 The full stack, from your `Cipher` call to the silicon | 23 | yes | [README.md:115](../../49-KeyStore/README.md#21-the-full-stack-from-your-cipher-call-to-the-silicon) |
| 49-KeyStore | 2.4 Trust boundaries, drawn explicitly | 11 | yes | [README.md:270](../../49-KeyStore/README.md#24-trust-boundaries-drawn-explicitly) |
| 49-KeyStore | 3.7.3 The chain | 5 |  | [README.md:536](../../49-KeyStore/README.md#373-the-chain) |
| 49-KeyStore | 3.7.5 How a server verifies, step by step | 20 | yes | [README.md:627](../../49-KeyStore/README.md#375-how-a-server-verifies-step-by-step) |
| 49-KeyStore | 7.1 The methodology, as a process | 9 |  | [README.md:1300](../../49-KeyStore/README.md#71-the-methodology-as-a-process) |
| 50-HardwareBackedSecurity | 2.1 The trust hierarchy, drawn once | 18 | yes | [README.md:141](../../50-HardwareBackedSecurity/README.md#21-the-trust-hierarchy-drawn-once) |
| 50-HardwareBackedSecurity | 2.5 Where the boundaries are, and what crossing each one buys an attacker | 12 | yes | [README.md:329](../../50-HardwareBackedSecurity/README.md#25-where-the-boundaries-are-and-what-crossing-each-one-buys-an-attacker) |
| 50-HardwareBackedSecurity | 3.7.2 How KeyMint checks it | 14 | yes | [README.md:706](../../50-HardwareBackedSecurity/README.md#372-how-keymint-checks-it) |
| 51-DynamicAnalysis | 2.1 The pipeline | 20 | yes | [README.md:212](../../51-DynamicAnalysis/README.md#21-the-pipeline) |
| 51-DynamicAnalysis | 2.2 The nine observation channels, and what each can and cannot see | 12 |  | [README.md:275](../../51-DynamicAnalysis/README.md#22-the-nine-observation-channels-and-what-each-can-and-cannot-see) |
| 51-DynamicAnalysis | 2.5 The trust boundary you are standing on | 11 | yes | [README.md:445](../../51-DynamicAnalysis/README.md#25-the-trust-boundary-you-are-standing-on) |
| 51-DynamicAnalysis | 3.5.1 The four altitudes | 10 | yes | [README.md:1029](../../51-DynamicAnalysis/README.md#351-the-four-altitudes) |
| 51-DynamicAnalysis | 7.4 Instrumenting: the decision, not the mechanism | 11 | yes | [README.md:2787](../../51-DynamicAnalysis/README.md#74-instrumenting-the-decision-not-the-mechanism) |
| 52-StaticAnalysis | 2.1 The pipeline | 22 | yes | [README.md:157](../../52-StaticAnalysis/README.md#21-the-pipeline) |
| 52-StaticAnalysis | 2.2 What each view can and cannot see | 16 | yes | [README.md:216](../../52-StaticAnalysis/README.md#22-what-each-view-can-and-cannot-see) |
| 52-StaticAnalysis | 2.4 The trust boundary you are standing on | 8 | yes | [README.md:297](../../52-StaticAnalysis/README.md#24-the-trust-boundary-you-are-standing-on) |
| 52-StaticAnalysis | 7.5 Which tool answers this question? | 12 | yes | [README.md:1895](../../52-StaticAnalysis/README.md#75-which-tool-answers-this-question) |
| 53-Frida | 2.1 The whole system, one picture | 25 | yes | [README.md:204](../../53-Frida/README.md#21-the-whole-system-one-picture) |
| 53-Frida | 2.3 Spawn versus attach | 16 | yes | [README.md:340](../../53-Frida/README.md#23-spawn-versus-attach) |
| 53-Frida | 2.5 The no-root path: frida-gadget | 14 | yes | [README.md:432](../../53-Frida/README.md#25-the-no-root-path-frida-gadget) |
| 53-Frida | 3.6.1 `Interceptor` — attach versus replace | 18 |  | [README.md:858](../../53-Frida/README.md#361-interceptor--attach-versus-replace) |
| 53-Frida | 3.7 `Stalker` — instruction-level tracing | 13 | yes | [README.md:1386](../../53-Frida/README.md#37-stalker--instruction-level-tracing) |
| 53-Frida | 3.9.2 How a Java hook is installed, at the ART level | 11 |  | [README.md:1603](../../53-Frida/README.md#392-how-a-java-hook-is-installed-at-the-art-level) |
| 53-Frida | 7.2 The engagement workflow | 10 |  | [README.md:3181](../../53-Frida/README.md#72-the-engagement-workflow) |
| 53-Frida | 7.4 The four failure modes, exhaustively | 12 | yes | [README.md:3524](../../53-Frida/README.md#74-the-four-failure-modes-exhaustively) |
| 53-Frida | 7.4.2 Failure 2 — `ClassNotFoundException` and the ClassLoader problem | 5 | yes | [README.md:3683](../../53-Frida/README.md#742-failure-2--classnotfoundexception-and-the-classloader-problem) |
| 53-Frida | 7.10 The no-root path: `frida-gadget` | 11 | yes | [README.md:4685](../../53-Frida/README.md#710-the-no-root-path-frida-gadget) |
| 54-Objection | 2.1 The whole system in one picture | 11 | yes | [README.md:180](../../54-Objection/README.md#21-the-whole-system-in-one-picture) |
| 54-Objection | 2.3 One agent, not one script per command | 9 |  | [README.md:289](../../54-Objection/README.md#23-one-agent-not-one-script-per-command) |
| 54-Objection | 3.11 Version skew — the commonest real-world blocker | 5 | yes | [README.md:1194](../../54-Objection/README.md#311-version-skew--the-commonest-real-world-blocker) |
| 54-Objection | 4.1 One command, end to end | 16 | yes | [README.md:1254](../../54-Objection/README.md#41-one-command-end-to-end) |
| 54-Objection | 7.3 The four failure modes, and how to tell them apart | 10 | yes | [README.md:1800](../../54-Objection/README.md#73-the-four-failure-modes-and-how-to-tell-them-apart) |
| 55-MobSF | 2.1 What happens when you upload an APK | 19 | yes | [README.md:339](../../55-MobSF/README.md#21-what-happens-when-you-upload-an-apk) |
| 55-MobSF | 2.2 Where MobSF sits inside 52's pipeline | 12 | yes | [README.md:402](../../55-MobSF/README.md#22-where-mobsf-sits-inside-52s-pipeline) |
| 55-MobSF | 2.5 Static and dynamic, as two different machines | 12 |  | [README.md:565](../../55-MobSF/README.md#25-static-and-dynamic-as-two-different-machines) |
| 55-MobSF | 2.6 The trust boundary you are standing on | 13 | yes | [README.md:597](../../55-MobSF/README.md#26-the-trust-boundary-you-are-standing-on) |
| 56-JADX | 1.4 The three ways jadx fails | 7 | yes | [README.md:255](../../56-JADX/README.md#14-the-three-ways-jadx-fails) |
| 56-JADX | 2.1 Where jadx sits between the build and you | 11 | yes | [README.md:324](../../56-JADX/README.md#21-where-jadx-sits-between-the-build-and-you) |
| 56-JADX | 2.3 The jadx internal pipeline | 16 | yes | [README.md:405](../../56-JADX/README.md#23-the-jadx-internal-pipeline) |
| 56-JADX | 2.4 GUI or CLI: a decision, not a preference | 4 |  | [README.md:444](../../56-JADX/README.md#24-gui-or-cli-a-decision-not-a-preference) |
| 56-JADX | 2.5 Trust boundary: jadx runs attacker-supplied input | 9 | yes | [README.md:474](../../56-JADX/README.md#25-trust-boundary-jadx-runs-attacker-supplied-input) |
| 57-Ghidra | The decompilation pipeline | 13 |  | [README.md:207](../../57-Ghidra/README.md#the-decompilation-pipeline) |
| 57-Ghidra | Ghidra's process architecture | 8 |  | [README.md:247](../../57-Ghidra/README.md#ghidras-process-architecture) |
| 57-Ghidra | Where Ghidra sits in the Android RE workflow | 9 | yes | [README.md:291](../../57-Ghidra/README.md#where-ghidra-sits-in-the-android-re-workflow) |
| 57-Ghidra | 3.8 The JNIEnv problem, and how to solve it | 8 |  | [README.md:712](../../57-Ghidra/README.md#38-the-jnienv-problem-and-how-to-solve-it) |
| 57-Ghidra | 3.9 Finding JNI entry points | 9 | yes | [README.md:815](../../57-Ghidra/README.md#39-finding-jni-entry-points) |
| 57-Ghidra | 7.1 The address arithmetic that connects the two worlds | 4 |  | [README.md:1889](../../57-Ghidra/README.md#71-the-address-arithmetic-that-connects-the-two-worlds) |
| 58-IDA | 2.1 The pipeline | 11 |  | [README.md:243](../../58-IDA/README.md#21-the-pipeline) |
| 58-IDA | 2.2 The database, and what is actually in it | 8 | yes | [README.md:284](../../58-IDA/README.md#22-the-database-and-what-is-actually-in-it) |
| 58-IDA | 2.3 Where IDA sits in an Android workflow | 12 | yes | [README.md:336](../../58-IDA/README.md#23-where-ida-sits-in-an-android-workflow) |
| 58-IDA | 3.4 Hex-Rays: microcode, and why it is not P-Code | 13 |  | [README.md:548](../../58-IDA/README.md#34-hex-rays-microcode-and-why-it-is-not-p-code) |
| 58-IDA | 3.7 FLIRT — measured, not described | 9 | yes | [README.md:839](../../58-IDA/README.md#37-flirt--measured-not-described) |
| 59-radare2 | The library stack | 17 |  | [README.md:185](../../59-radare2/README.md#the-library-stack) |
| 59-radare2 | The separation that matters: parse versus analyse | 5 |  | [README.md:256](../../59-radare2/README.md#the-separation-that-matters-parse-versus-analyse) |
| 59-radare2 | Where radare2 sits in the Android workflow | 10 | yes | [README.md:359](../../59-radare2/README.md#where-radare2-sits-in-the-android-workflow) |
| 59-radare2 | 3.2 The command language, taught as a grammar | 10 |  | [README.md:466](../../59-radare2/README.md#32-the-command-language-taught-as-a-grammar) |
| 59-radare2 | 3.6 Analysis levels — `aaa` and what it actually costs | 8 |  | [README.md:882](../../59-radare2/README.md#36-analysis-levels--aaa-and-what-it-actually-costs) |
| 59-radare2 | 3.14 radare2 versus rizin versus Cutter | 6 |  | [README.md:1327](../../59-radare2/README.md#314-radare2-versus-rizin-versus-cutter) |
| 59-radare2 | 7.1 The address arithmetic that connects static to dynamic | 7 |  | [README.md:2001](../../59-radare2/README.md#71-the-address-arithmetic-that-connects-static-to-dynamic) |
| 59-radare2 | How the pieces connect | 11 | yes | [mindmap.md:166](../../59-radare2/mindmap.md#how-the-pieces-connect) |
| 59-radare2 | The two failure modes, side by side | 15 | yes | [mindmap.md:195](../../59-radare2/mindmap.md#the-two-failure-modes-side-by-side) |
| 60-ADB | 2.1 Three programs, not one | 15 | yes | [README.md:133](../../60-ADB/README.md#21-three-programs-not-one) |
| 60-ADB | 2.4 Where the trust boundaries actually are | 11 | yes | [README.md:284](../../60-ADB/README.md#24-where-the-trust-boundaries-actually-are) |
| 61-Fastboot | 2.1 Where fastboot sits relative to everything else | 15 | yes | [README.md:199](../../61-Fastboot/README.md#21-where-fastboot-sits-relative-to-everything-else) |
| 61-Fastboot | 2.4 Two implementations of one protocol | 12 |  | [README.md:381](../../61-Fastboot/README.md#24-two-implementations-of-one-protocol) |
| 61-Fastboot | 3.7 Dynamic partitions and the `super` partition | 4 |  | [README.md:889](../../61-Fastboot/README.md#37-dynamic-partitions-and-the-super-partition) |
| 61-Fastboot | 9.5 Enterprise — a fleet device-posture pipeline | 11 | yes | [README.md:2602](../../61-Fastboot/README.md#95-enterprise--a-fleet-device-posture-pipeline) |
| 62-Magisk | 2.1 Where Magisk sits in the boot chain | 21 | yes | [README.md:160](../../62-Magisk/README.md#21-where-magisk-sits-in-the-boot-chain) |
| 62-Magisk | 2.2 The overlay illusion | 13 | yes | [README.md:223](../../62-Magisk/README.md#22-the-overlay-illusion) |
| 62-Magisk | 2.4 Zygisk — injection into every app | 16 | yes | [README.md:312](../../62-Magisk/README.md#24-zygisk--injection-into-every-app) |
| 63-LSPosed | 2.1 The injection chain, end to end | 20 | yes | [README.md:261](../../63-LSPosed/README.md#21-the-injection-chain-end-to-end) |
| 63-LSPosed | 2.3 Four processes, four privilege levels | 10 | yes | [README.md:365](../../63-LSPosed/README.md#23-four-processes-four-privilege-levels) |
| 63-LSPosed | 2.5 Classic Xposed and LSPosed, side by side | 10 | yes | [README.md:433](../../63-LSPosed/README.md#25-classic-xposed-and-lsposed-side-by-side) |
| 63-LSPosed | 3.5 Getting a module's DEX into a foreign process — and the class-loader problem | 4 | yes | [README.md:618](../../63-LSPosed/README.md#35-getting-a-modules-dex-into-a-foreign-process--and-the-class-loader-problem) |
| 63-LSPosed | 3.10 The backup method — the trampoline of the managed world | 7 | yes | [README.md:885](../../63-LSPosed/README.md#310-the-backup-method--the-trampoline-of-the-managed-world) |
| 63-LSPosed | 3.13 Timing: the three entry points and what exists at each | 12 |  | [README.md:998](../../63-LSPosed/README.md#313-timing-the-three-entry-points-and-what-exists-at-each) |
| 63-LSPosed | Decision: which instrument? | 15 |  | [mindmap.md:165](../../63-LSPosed/mindmap.md#decision-which-instrument) |
| 63-LSPosed | Diagnostic: the hook did not fire | 18 | yes | [mindmap.md:196](../../63-LSPosed/mindmap.md#diagnostic-the-hook-did-not-fire) |
| 63-LSPosed | The four privilege levels, at a glance | 5 | yes | [mindmap.md:229](../../63-LSPosed/mindmap.md#the-four-privilege-levels-at-a-glance) |
| 64-Xposed | 2.1 The boot chain classic Xposed inserted itself into | 20 | yes | [README.md:316](../../64-Xposed/README.md#21-the-boot-chain-classic-xposed-inserted-itself-into) |
| 64-Xposed | 2.5 The four things Xposed needed, and when each became impossible | 10 | yes | [README.md:493](../../64-Xposed/README.md#25-the-four-things-xposed-needed-and-when-each-became-impossible) |
| 65-Hooking | 2.1 The five places a call can be intercepted | 20 | yes | [README.md:169](../../65-Hooking/README.md#21-the-five-places-a-call-can-be-intercepted) |
| 65-Hooking | 2.2 What each hook physically overwrites | 11 |  | [README.md:213](../../65-Hooking/README.md#22-what-each-hook-physically-overwrites) |
| 65-Hooking | 2.5 Blast radius: the property that should drive your choice | 6 | yes | [README.md:320](../../65-Hooking/README.md#25-blast-radius-the-property-that-should-drive-your-choice) |
| 65-Hooking | The one-diagram version | 13 | yes | [mindmap.md:163](../../65-Hooking/mindmap.md#the-one-diagram-version) |
| 66-Instrumentation | 2.1 The command path | 17 | yes | [README.md:184](../../66-Instrumentation/README.md#21-the-command-path) |
| 67-BypassingProtections | 2.1 The five seams | 20 | yes | [README.md:185](../../67-BypassingProtections/README.md#21-the-five-seams) |
| 67-BypassingProtections | 2.5 Where the responses live | 11 | yes | [README.md:345](../../67-BypassingProtections/README.md#25-where-the-responses-live) |
| 67-BypassingProtections | The same thing as a decision tree | 26 | yes | [mindmap.md:215](../../67-BypassingProtections/mindmap.md#the-same-thing-as-a-decision-tree) |
| 68-ReverseEngineering | 2.1 The investigation loop | 10 |  | [README.md:348](../../68-ReverseEngineering/README.md#21-the-investigation-loop) |
| 68-ReverseEngineering | 2.2 The triage funnel, across both halves | 12 | yes | [README.md:399](../../68-ReverseEngineering/README.md#22-the-triage-funnel-across-both-halves) |
| 68-ReverseEngineering | 2.3 The evidence ladder | 6 | yes | [README.md:449](../../68-ReverseEngineering/README.md#23-the-evidence-ladder) |
| 68-ReverseEngineering | 2.4 Where the tools sit on the loop | 13 |  | [README.md:499](../../68-ReverseEngineering/README.md#24-where-the-tools-sit-on-the-loop) |
| 68-ReverseEngineering | 3.3 Stage 2 — triage in twenty minutes | 5 | yes | [README.md:715](../../68-ReverseEngineering/README.md#33-stage-2--triage-in-twenty-minutes) |
| 68-ReverseEngineering | 3.8 Crossing the managed/native boundary as one question | 8 |  | [README.md:1005](../../68-ReverseEngineering/README.md#38-crossing-the-managednative-boundary-as-one-question) |
| 69-MalwareAnalysis | 2.1 The triage pipeline | 22 | yes | [README.md:313](../../69-MalwareAnalysis/README.md#21-the-triage-pipeline) |
| 69-MalwareAnalysis | 2.4 The analysis environment — what "isolation" means concretely | 10 | yes | [README.md:502](../../69-MalwareAnalysis/README.md#24-the-analysis-environment--what-isolation-means-concretely) |
| 69-MalwareAnalysis | 2.5 The trust boundary you are standing on | 9 | yes | [README.md:548](../../69-MalwareAnalysis/README.md#25-the-trust-boundary-you-are-standing-on) |
| 69-MalwareAnalysis | How the chapters connect | 17 | yes | [mindmap.md:211](../../69-MalwareAnalysis/mindmap.md#how-the-chapters-connect) |
| 69-MalwareAnalysis | The one-page decision tree | 12 | yes | [mindmap.md:264](../../69-MalwareAnalysis/mindmap.md#the-one-page-decision-tree) |
| 70-VulnerabilityResearch | 1.3 A crash is not a bug, and a bug is not a vulnerability | 6 | yes | [README.md:145](../../70-VulnerabilityResearch/README.md#13-a-crash-is-not-a-bug-and-a-bug-is-not-a-vulnerability) |
| 70-VulnerabilityResearch | 2.1 The pipeline | 8 |  | [README.md:303](../../70-VulnerabilityResearch/README.md#21-the-pipeline) |
| 70-VulnerabilityResearch | 2.2 The Android attack surface, drawn by who can reach what | 13 | yes | [README.md:341](../../70-VulnerabilityResearch/README.md#22-the-android-attack-surface-drawn-by-who-can-reach-what) |
| 70-VulnerabilityResearch | 2.3 The funnel, with real numbers | 8 |  | [README.md:410](../../70-VulnerabilityResearch/README.md#23-the-funnel-with-real-numbers) |
| 70-VulnerabilityResearch | The same thing as a decision flow | 20 | yes | [mindmap.md:187](../../70-VulnerabilityResearch/mindmap.md#the-same-thing-as-a-decision-flow) |
| 71-OWASP-Mobile | How the three documents relate | 20 |  | [README.md:105](../../71-OWASP-Mobile/README.md#how-the-three-documents-relate) |
| 71-OWASP-Mobile | The verification levels | 6 | yes | [README.md:160](../../71-OWASP-Mobile/README.md#the-verification-levels) |
| 71-OWASP-Mobile | Where each control area maps in this repository | 28 |  | [README.md:192](../../71-OWASP-Mobile/README.md#where-each-control-area-maps-in-this-repository) |
| 71-OWASP-Mobile | Scoping an engagement against the standard | 10 |  | [README.md:389](../../71-OWASP-Mobile/README.md#scoping-an-engagement-against-the-standard) |
| 71-OWASP-Mobile | Step 4 — The composition hunt, specifically | 5 | yes | [labs/lab-03-find-the-gap.md:203](../../71-OWASP-Mobile/labs/lab-03-find-the-gap.md#step-4--the-composition-hunt-specifically) |
| 72-RealWorldFindings | 2.1 The adjudication pipeline | 10 | yes | [README.md:184](../../72-RealWorldFindings/README.md#21-the-adjudication-pipeline) |
| 72-RealWorldFindings | 2.2 Where each finding class comes from | 14 | yes | [README.md:232](../../72-RealWorldFindings/README.md#22-where-each-finding-class-comes-from) |
| 73-Labs | 2.1 The corpus as a system | 15 | yes | [README.md:164](../../73-Labs/README.md#21-the-corpus-as-a-system) |
| 74-CaseStudies | 2.1 The five phases every investigation actually has | 9 | yes | [README.md:173](../../74-CaseStudies/README.md#21-the-five-phases-every-investigation-actually-has) |
| 74-CaseStudies | 2.2 What each case is really about — the same shape six times | 16 | yes | [README.md:205](../../74-CaseStudies/README.md#22-what-each-case-is-really-about--the-same-shape-six-times) |
| 74-CaseStudies | The chapter as a decision procedure | 12 | yes | [mindmap.md:158](../../74-CaseStudies/mindmap.md#the-chapter-as-a-decision-procedure) |
| 75-InterviewQuestions | 2.1 The pipeline as a system | 13 | yes | [README.md:283](../../75-InterviewQuestions/README.md#21-the-pipeline-as-a-system) |
| 76-CheatSheets | How the parts fit together | 14 | yes | [mindmap.md:112](../../76-CheatSheets/mindmap.md#how-the-parts-fit-together) |
| 76-CheatSheets | The decision the chapter is built on | 6 | yes | [mindmap.md:163](../../76-CheatSheets/mindmap.md#the-decision-the-chapter-is-built-on) |
| 77-UsefulCommands | Where your commands actually land | 28 | yes | [README.md:89](../../77-UsefulCommands/README.md#where-your-commands-actually-land) |
| 77-UsefulCommands | The privilege ladder | 6 |  | [README.md:166](../../77-UsefulCommands/README.md#the-privilege-ladder) |
| 78-Diagrams | 4.1 The Android security stack, end to end | 17 | yes | [README.md:347](../../78-Diagrams/README.md#41-the-android-security-stack-end-to-end) |
| 78-Diagrams | 4.3 Where every chapter sits in the platform | 22 |  | [README.md:457](../../78-Diagrams/README.md#43-where-every-chapter-sits-in-the-platform) |
| 78-Diagrams | 4.4 The complete trust-boundary map | 16 | yes | [README.md:518](../../78-Diagrams/README.md#44-the-complete-trust-boundary-map) |
| 78-Diagrams | 5.2 Flowchart arrows and node shapes | 6 |  | [README.md:720](../../78-Diagrams/README.md#52-flowchart-arrows-and-node-shapes) |
| 78-Diagrams | 6.1 Show the boundary, do not imply it | 6 | yes | [README.md:860](../../78-Diagrams/README.md#61-show-the-boundary-do-not-imply-it) |
| 78-Diagrams | 6.4 Draw the actual flow, not the intended one | 8 | yes | [README.md:932](../../78-Diagrams/README.md#64-draw-the-actual-flow-not-the-intended-one) |
| 78-Diagrams | Version A — the diagram most people draw | 5 |  | [examples/01-one-system-three-diagrams.md:30](../../78-Diagrams/examples/01-one-system-three-diagrams.md#version-a--the-diagram-most-people-draw) |
| 78-Diagrams | Version B — the same system with the boundaries drawn | 10 | yes | [examples/01-one-system-three-diagrams.md:106](../../78-Diagrams/examples/01-one-system-three-diagrams.md#version-b--the-same-system-with-the-boundaries-drawn) |
| 78-Diagrams | 3 — A backslash-escaped quote inside a quoted label | 3 |  | [examples/02-broken-diagrams-and-their-fixes.md:129](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#3--a-backslash-escaped-quote-inside-a-quoted-label) |
| 78-Diagrams | 3 — A backslash-escaped quote inside a quoted label | 2 |  | [examples/02-broken-diagrams-and-their-fixes.md:136](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#3--a-backslash-escaped-quote-inside-a-quoted-label) |
| 78-Diagrams | 6 — Unquoted parentheses in flowchart node text | 3 |  | [examples/02-broken-diagrams-and-their-fixes.md:255](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#6--unquoted-parentheses-in-flowchart-node-text) |
| 78-Diagrams | Part 5 — Draw it | 15 | yes | [labs/lab-01-boundaries-from-evidence.md:287](../../78-Diagrams/labs/lab-01-boundaries-from-evidence.md#part-5--draw-it) |
| 78-Diagrams | Part 5 — Redraw the diagram with the omission in it | 10 | yes | [labs/lab-02-what-the-diagram-omits.md:282](../../78-Diagrams/labs/lab-02-what-the-diagram-omits.md#part-5--redraw-the-diagram-with-the-omission-in-it) |
| 78-Diagrams | Part 3 — Draw the actual flow | 11 | yes | [labs/lab-03-intended-versus-actual.md:294](../../78-Diagrams/labs/lab-03-intended-versus-actual.md#part-3--draw-the-actual-flow) |
| 78-Diagrams | The topology you were given | 5 |  | [labs/lab-04-ctf-the-cartographers-error.md:178](../../78-Diagrams/labs/lab-04-ctf-the-cartographers-error.md#the-topology-you-were-given) |
| 78-Diagrams | Stage 5 — Redraw it | 12 | yes | [labs/lab-04-ctf-the-cartographers-error.md:403](../../78-Diagrams/labs/lab-04-ctf-the-cartographers-error.md#stage-5--redraw-it) |
| 81-Android-Runtime-Internals | 01-boot-to-app.mmd | 19 | yes | [diagrams/01-boot-to-app.mmd:1](../../81-Android-Runtime-Internals/diagrams/01-boot-to-app.mmd) |
| 81-Android-Runtime-Internals | 02-art-dispatch.mmd | 12 | yes | [diagrams/02-art-dispatch.mmd:1](../../81-Android-Runtime-Internals/diagrams/02-art-dispatch.mmd) |
| 81-Android-Runtime-Internals | 03-injection-stack.mmd | 15 | yes | [diagrams/03-injection-stack.mmd:1](../../81-Android-Runtime-Internals/diagrams/03-injection-stack.mmd) |

## mindmap (169)

| Chapter | Depicts | Nodes | Atk | Location |
|---|---|---:|:---:|---|
| 00-Introduction | 13.2 Chapter mind map | 1 |  | [README.md:3237](../../00-Introduction/README.md#132-chapter-mind-map) |
| 00-Introduction | _(no heading above it)_ | 1 |  | [mindmap.md:7](../../00-Introduction/mindmap.md) |
| 01-Computer-Science-Basics | 13.2 Chapter mind map | 1 |  | [README.md:4806](../../01-Computer-Science-Basics/README.md#132-chapter-mind-map) |
| 01-Computer-Science-Basics | _(no heading above it)_ | 1 |  | [mindmap.md:13](../../01-Computer-Science-Basics/mindmap.md) |
| 02-Linux-Basics | 13.2 Chapter mind map | 2 |  | [README.md:3440](../../02-Linux-Basics/README.md#132-chapter-mind-map) |
| 02-Linux-Basics | _(no heading above it)_ | 4 |  | [mindmap.md:5](../../02-Linux-Basics/mindmap.md) |
| 03-Programming-Fundamentals | 2.6 Where each concept in this chapter lands in the Android stack | 4 |  | [README.md:497](../../03-Programming-Fundamentals/README.md#26-where-each-concept-in-this-chapter-lands-in-the-android-stack) |
| 03-Programming-Fundamentals | Mind map | 1 |  | [README.md:5555](../../03-Programming-Fundamentals/README.md#mind-map) |
| 03-Programming-Fundamentals | _(no heading above it)_ | 2 |  | [mindmap.md:5](../../03-Programming-Fundamentals/mindmap.md) |
| 04-Java | 13.2 The chapter as a map | 1 |  | [README.md:2864](../../04-Java/README.md#132-the-chapter-as-a-map) |
| 04-Java | _(no heading above it)_ | 0 |  | [mindmap.md:8](../../04-Java/mindmap.md) |
| 05-Kotlin | Mind map | 1 |  | [README.md:2572](../../05-Kotlin/README.md#mind-map) |
| 05-Kotlin | _(no heading above it)_ | 1 |  | [mindmap.md:14](../../05-Kotlin/mindmap.md) |
| 06-Android-Architecture | Mind map | 1 |  | [README.md:3013](../../06-Android-Architecture/README.md#mind-map) |
| 06-Android-Architecture | _(no heading above it)_ | 1 |  | [mindmap.md:12](../../06-Android-Architecture/mindmap.md) |
| 07-AOSP | Mind map | 1 |  | [README.md:3521](../../07-AOSP/README.md#mind-map) |
| 07-AOSP | _(no heading above it)_ | 1 |  | [mindmap.md:5](../../07-AOSP/mindmap.md) |
| 08-Build-System | Mind map | 1 |  | [README.md:4724](../../08-Build-System/README.md#mind-map) |
| 08-Build-System | _(no heading above it)_ | 1 |  | [mindmap.md:5](../../08-Build-System/mindmap.md) |
| 09-Android-App-Internals | 13.2 The chapter as one picture | 1 |  | [README.md:4062](../../09-Android-App-Internals/README.md#132-the-chapter-as-one-picture) |
| 09-Android-App-Internals | _(no heading above it)_ | 1 |  | [mindmap.md:11](../../09-Android-App-Internals/mindmap.md) |
| 10-APK-Internals | Mind map | 1 |  | [README.md:2271](../../10-APK-Internals/README.md#mind-map) |
| 10-APK-Internals | _(no heading above it)_ | 1 |  | [mindmap.md:9](../../10-APK-Internals/mindmap.md) |
| 11-Android-Runtime | Mind map | 1 |  | [README.md:2722](../../11-Android-Runtime/README.md#mind-map) |
| 11-Android-Runtime | _(no heading above it)_ | 1 |  | [mindmap.md:13](../../11-Android-Runtime/mindmap.md) |
| 12-DEX-Internals | Mind map | 1 |  | [README.md:3340](../../12-DEX-Internals/README.md#mind-map) |
| 12-DEX-Internals | _(no heading above it)_ | 1 |  | [mindmap.md:13](../../12-DEX-Internals/mindmap.md) |
| 13-ART | Mind map | 1 |  | [README.md:2417](../../13-ART/README.md#mind-map) |
| 13-ART | _(no heading above it)_ | 1 |  | [mindmap.md:10](../../13-ART/mindmap.md) |
| 14-Dalvik | Mind map | 1 |  | [README.md:3990](../../14-Dalvik/README.md#mind-map) |
| 14-Dalvik | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../14-Dalvik/mindmap.md) |
| 15-Native-Code | 13.2 Chapter mind map | 1 |  | [README.md:3311](../../15-Native-Code/README.md#132-chapter-mind-map) |
| 15-Native-Code | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../15-Native-Code/mindmap.md) |
| 16-JNI | Mind map | 1 |  | [README.md:3913](../../16-JNI/README.md#mind-map) |
| 16-JNI | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../16-JNI/mindmap.md) |
| 17-Libraries | Mind map | 4 |  | [README.md:2995](../../17-Libraries/README.md#mind-map) |
| 17-Libraries | _(no heading above it)_ | 1 |  | [mindmap.md:5](../../17-Libraries/mindmap.md) |
| 18-ARM | 13.2 Mind map | 1 |  | [README.md:3592](../../18-ARM/README.md#132-mind-map) |
| 18-ARM | _(no heading above it)_ | 1 |  | [mindmap.md:5](../../18-ARM/mindmap.md) |
| 19-Memory | 13.2 Mind map | 1 |  | [README.md:2968](../../19-Memory/README.md#132-mind-map) |
| 19-Memory | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../19-Memory/mindmap.md) |
| 20-Security-Architecture | 13.2 Mind map | 1 |  | [README.md:2080](../../20-Security-Architecture/README.md#132-mind-map) |
| 20-Security-Architecture | _(no heading above it)_ | 1 |  | [mindmap.md:3](../../20-Security-Architecture/mindmap.md) |
| 21-App-Sandbox | 13.2 Mindmap | 1 |  | [README.md:3515](../../21-App-Sandbox/README.md#132-mindmap) |
| 21-App-Sandbox | _(no heading above it)_ | 1 |  | [mindmap.md:15](../../21-App-Sandbox/mindmap.md) |
| 22-SELinux | 13.2 Mind map | 1 |  | [README.md:3479](../../22-SELinux/README.md#132-mind-map) |
| 22-SELinux | _(no heading above it)_ | 1 |  | [mindmap.md:5](../../22-SELinux/mindmap.md) |
| 23-Permissions | 13.2 Mind map | 1 |  | [README.md:3565](../../23-Permissions/README.md#132-mind-map) |
| 23-Permissions | _(no heading above it)_ | 1 |  | [mindmap.md:8](../../23-Permissions/mindmap.md) |
| 24-IPC | Mind map | 1 |  | [README.md:4090](../../24-IPC/README.md#mind-map) |
| 24-IPC | _(no heading above it)_ | 1 |  | [mindmap.md:3](../../24-IPC/mindmap.md) |
| 25-Binder | 13.2 Mind map | 2 |  | [README.md:3579](../../25-Binder/README.md#132-mind-map) |
| 25-Binder | _(no heading above it)_ | 3 |  | [mindmap.md:6](../../25-Binder/mindmap.md) |
| 26-Intent | 5.1 The taxonomy | 1 |  | [README.md:1575](../../26-Intent/README.md#51-the-taxonomy) |
| 26-Intent | 13.2 Mind map | 3 |  | [README.md:3158](../../26-Intent/README.md#132-mind-map) |
| 26-Intent | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../26-Intent/mindmap.md) |
| 27-ContentProviders | Mind map | 2 |  | [README.md:3755](../../27-ContentProviders/README.md#mind-map) |
| 27-ContentProviders | _(no heading above it)_ | 1 |  | [mindmap.md:3](../../27-ContentProviders/mindmap.md) |
| 28-Services | Mind map | 2 |  | [README.md:3637](../../28-Services/README.md#mind-map) |
| 28-Services | _(no heading above it)_ | 1 |  | [mindmap.md:7](../../28-Services/mindmap.md) |
| 29-BroadcastReceivers | 5.1 The taxonomy | 1 |  | [README.md:1524](../../29-BroadcastReceivers/README.md#51-the-taxonomy) |
| 29-BroadcastReceivers | 13.2 Mind map | 1 |  | [README.md:3121](../../29-BroadcastReceivers/README.md#132-mind-map) |
| 29-BroadcastReceivers | _(no heading above it)_ | 3 |  | [mindmap.md:6](../../29-BroadcastReceivers/mindmap.md) |
| 30-Activities | The chapter as one map | 1 |  | [README.md:3304](../../30-Activities/README.md#the-chapter-as-one-map) |
| 30-Activities | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../30-Activities/mindmap.md) |
| 31-Fragments | The chapter as one map | 4 |  | [README.md:2664](../../31-Fragments/README.md#the-chapter-as-one-map) |
| 31-Fragments | _(no heading above it)_ | 16 |  | [mindmap.md:7](../../31-Fragments/mindmap.md) |
| 32-Manifest | Mind map | 1 |  | [README.md:3194](../../32-Manifest/README.md#mind-map) |
| 32-Manifest | _(no heading above it)_ | 1 |  | [mindmap.md:11](../../32-Manifest/mindmap.md) |
| 33-Storage | 13.2 Mind map | 1 |  | [README.md:2520](../../33-Storage/README.md#132-mind-map) |
| 33-Storage | _(no heading above it)_ | 2 |  | [mindmap.md:7](../../33-Storage/mindmap.md) |
| 34-Cryptography | Mind map | 1 |  | [README.md:3977](../../34-Cryptography/README.md#mind-map) |
| 34-Cryptography | _(no heading above it)_ | 1 |  | [mindmap.md:10](../../34-Cryptography/mindmap.md) |
| 35-SSL | 13.2 The chapter as a map | 1 |  | [README.md:2620](../../35-SSL/README.md#132-the-chapter-as-a-map) |
| 35-SSL | _(no heading above it)_ | 1 |  | [mindmap.md:14](../../35-SSL/mindmap.md) |
| 36-CertificatePinning | 13.2 Mind map | 1 |  | [README.md:3110](../../36-CertificatePinning/README.md#132-mind-map) |
| 36-CertificatePinning | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../36-CertificatePinning/mindmap.md) |
| 37-RootDetection | Mind map | 1 |  | [README.md:3221](../../37-RootDetection/README.md#mind-map) |
| 37-RootDetection | _(no heading above it)_ | 2 |  | [mindmap.md:15](../../37-RootDetection/mindmap.md) |
| 38-TamperDetection | Mind map | 1 |  | [README.md:2669](../../38-TamperDetection/README.md#mind-map) |
| 38-TamperDetection | _(no heading above it)_ | 2 |  | [mindmap.md:6](../../38-TamperDetection/mindmap.md) |
| 39-EmulatorDetection | Mind map | 1 |  | [README.md:2751](../../39-EmulatorDetection/README.md#mind-map) |
| 39-EmulatorDetection | _(no heading above it)_ | 1 |  | [mindmap.md:7](../../39-EmulatorDetection/mindmap.md) |
| 40-Obfuscation | Mind map | 1 |  | [README.md:2870](../../40-Obfuscation/README.md#mind-map) |
| 40-Obfuscation | _(no heading above it)_ | 2 |  | [mindmap.md:20](../../40-Obfuscation/mindmap.md) |
| 41-ProGuard | Mind map | 5 |  | [README.md:3156](../../41-ProGuard/README.md#mind-map) |
| 41-ProGuard | _(no heading above it)_ | 5 |  | [mindmap.md:8](../../41-ProGuard/mindmap.md) |
| 42-R8 | Mind map | 1 |  | [README.md:2363](../../42-R8/README.md#mind-map) |
| 42-R8 | _(no heading above it)_ | 1 |  | [mindmap.md:5](../../42-R8/mindmap.md) |
| 43-WebView | 13.2 The chapter as a map | 1 |  | [README.md:3268](../../43-WebView/README.md#132-the-chapter-as-a-map) |
| 43-WebView | _(no heading above it)_ | 2 |  | [mindmap.md:6](../../43-WebView/mindmap.md) |
| 44-NetworkSecurityConfig | 13.2 The chapter as a map | 1 |  | [README.md:3073](../../44-NetworkSecurityConfig/README.md#132-the-chapter-as-a-map) |
| 44-NetworkSecurityConfig | _(no heading above it)_ | 2 |  | [mindmap.md:5](../../44-NetworkSecurityConfig/mindmap.md) |
| 45-OAuth | Mind map | 1 |  | [README.md:3449](../../45-OAuth/README.md#mind-map) |
| 45-OAuth | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../45-OAuth/mindmap.md) |
| 46-Tokens | 13.2 Mind map | 1 |  | [README.md:3464](../../46-Tokens/README.md#132-mind-map) |
| 46-Tokens | _(no heading above it)_ | 3 |  | [mindmap.md:8](../../46-Tokens/mindmap.md) |
| 47-Authentication | 13.2 Mind map | 1 |  | [README.md:3510](../../47-Authentication/README.md#132-mind-map) |
| 47-Authentication | _(no heading above it)_ | 1 |  | [mindmap.md:5](../../47-Authentication/mindmap.md) |
| 48-Biometrics | 13.2 Mind map | 3 |  | [README.md:2799](../../48-Biometrics/README.md#132-mind-map) |
| 48-Biometrics | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../48-Biometrics/mindmap.md) |
| 49-KeyStore | 13.2 Mindmap | 1 |  | [README.md:1739](../../49-KeyStore/README.md#132-mindmap) |
| 49-KeyStore | _(no heading above it)_ | 1 |  | [mindmap.md:15](../../49-KeyStore/mindmap.md) |
| 50-HardwareBackedSecurity | 13.2 The chapter as a map | 1 |  | [README.md:2168](../../50-HardwareBackedSecurity/README.md#132-the-chapter-as-a-map) |
| 50-HardwareBackedSecurity | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../50-HardwareBackedSecurity/mindmap.md) |
| 51-DynamicAnalysis | 13.2 Mind map | 1 |  | [README.md:3772](../../51-DynamicAnalysis/README.md#132-mind-map) |
| 51-DynamicAnalysis | _(no heading above it)_ | 1 |  | [mindmap.md:8](../../51-DynamicAnalysis/mindmap.md) |
| 52-StaticAnalysis | 13.2 Mind map | 1 |  | [README.md:2964](../../52-StaticAnalysis/README.md#132-mind-map) |
| 52-StaticAnalysis | _(no heading above it)_ | 1 |  | [mindmap.md:7](../../52-StaticAnalysis/mindmap.md) |
| 53-Frida | Mind map | 1 |  | [README.md:6077](../../53-Frida/README.md#mind-map) |
| 53-Frida | _(no heading above it)_ | 2 |  | [mindmap.md:12](../../53-Frida/mindmap.md) |
| 54-Objection | 13.2 Mind map | 1 |  | [README.md:2545](../../54-Objection/README.md#132-mind-map) |
| 54-Objection | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../54-Objection/mindmap.md) |
| 55-MobSF | 13.2 The chapter as a mind map | 1 |  | [README.md:3646](../../55-MobSF/README.md#132-the-chapter-as-a-mind-map) |
| 55-MobSF | _(no heading above it)_ | 1 |  | [mindmap.md:3](../../55-MobSF/mindmap.md) |
| 56-JADX | Mind map | 1 |  | [README.md:4123](../../56-JADX/README.md#mind-map) |
| 56-JADX | _(no heading above it)_ | 1 |  | [mindmap.md:8](../../56-JADX/mindmap.md) |
| 57-Ghidra | Mind map | 1 |  | [README.md:3418](../../57-Ghidra/README.md#mind-map) |
| 57-Ghidra | _(no heading above it)_ | 1 |  | [mindmap.md:18](../../57-Ghidra/mindmap.md) |
| 58-IDA | Mind map | 1 |  | [README.md:2402](../../58-IDA/README.md#mind-map) |
| 58-IDA | _(no heading above it)_ | 1 |  | [mindmap.md:5](../../58-IDA/mindmap.md) |
| 59-radare2 | Mind map | 1 |  | [README.md:2926](../../59-radare2/README.md#mind-map) |
| 59-radare2 | _(no heading above it)_ | 1 |  | [mindmap.md:5](../../59-radare2/mindmap.md) |
| 60-ADB | Mind map | 3 |  | [README.md:2974](../../60-ADB/README.md#mind-map) |
| 60-ADB | _(no heading above it)_ | 3 |  | [mindmap.md:6](../../60-ADB/mindmap.md) |
| 61-Fastboot | 13.2 The chapter as a map | 1 |  | [README.md:2975](../../61-Fastboot/README.md#132-the-chapter-as-a-map) |
| 61-Fastboot | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../61-Fastboot/mindmap.md) |
| 62-Magisk | Mind map | 1 |  | [README.md:2144](../../62-Magisk/README.md#mind-map) |
| 62-Magisk | _(no heading above it)_ | 1 |  | [mindmap.md:3](../../62-Magisk/mindmap.md) |
| 63-LSPosed | 13.2 Mind map | 1 |  | [README.md:2896](../../63-LSPosed/README.md#132-mind-map) |
| 63-LSPosed | The chapter | 1 |  | [mindmap.md:11](../../63-LSPosed/mindmap.md#the-chapter) |
| 64-Xposed | 13.2 Mind map | 2 |  | [README.md:3030](../../64-Xposed/README.md#132-mind-map) |
| 64-Xposed | _(no heading above it)_ | 1 |  | [mindmap.md:13](../../64-Xposed/mindmap.md) |
| 65-Hooking | 13.2 Mind map | 1 |  | [README.md:2451](../../65-Hooking/README.md#132-mind-map) |
| 65-Hooking | _(no heading above it)_ | 2 |  | [mindmap.md:6](../../65-Hooking/mindmap.md) |
| 66-Instrumentation | 13.2 Mind map | 1 |  | [README.md:2420](../../66-Instrumentation/README.md#132-mind-map) |
| 66-Instrumentation | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../66-Instrumentation/mindmap.md) |
| 67-BypassingProtections | 13.2 Mind map | 1 |  | [README.md:2824](../../67-BypassingProtections/README.md#132-mind-map) |
| 67-BypassingProtections | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../67-BypassingProtections/mindmap.md) |
| 68-ReverseEngineering | 13.2 The chapter as one picture | 1 |  | [README.md:2884](../../68-ReverseEngineering/README.md#132-the-chapter-as-one-picture) |
| 68-ReverseEngineering | _(no heading above it)_ | 1 |  | [mindmap.md:12](../../68-ReverseEngineering/mindmap.md) |
| 69-MalwareAnalysis | 13.2 Mind map | 1 |  | [README.md:3030](../../69-MalwareAnalysis/README.md#132-mind-map) |
| 69-MalwareAnalysis | _(no heading above it)_ | 1 |  | [mindmap.md:10](../../69-MalwareAnalysis/mindmap.md) |
| 70-VulnerabilityResearch | The chapter as a map | 1 |  | [README.md:3128](../../70-VulnerabilityResearch/README.md#the-chapter-as-a-map) |
| 70-VulnerabilityResearch | _(no heading above it)_ | 1 |  | [mindmap.md:5](../../70-VulnerabilityResearch/mindmap.md) |
| 71-OWASP-Mobile | Mind map | 1 |  | [README.md:830](../../71-OWASP-Mobile/README.md#mind-map) |
| 71-OWASP-Mobile | The whole standard, in one tree | 1 |  | [mindmap.md:15](../../71-OWASP-Mobile/mindmap.md#the-whole-standard-in-one-tree) |
| 72-RealWorldFindings | 13.2 Mind map | 1 |  | [README.md:1871](../../72-RealWorldFindings/README.md#132-mind-map) |
| 72-RealWorldFindings | _(no heading above it)_ | 1 |  | [mindmap.md:7](../../72-RealWorldFindings/mindmap.md) |
| 73-Labs | 13.2 Mind map | 1 |  | [README.md:1373](../../73-Labs/README.md#132-mind-map) |
| 73-Labs | _(no heading above it)_ | 2 |  | [mindmap.md:6](../../73-Labs/mindmap.md) |
| 74-CaseStudies | 13.2 Mind map | 3 |  | [README.md:2067](../../74-CaseStudies/README.md#132-mind-map) |
| 74-CaseStudies | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../74-CaseStudies/mindmap.md) |
| 75-InterviewQuestions | Mind map | 1 |  | [README.md:2689](../../75-InterviewQuestions/README.md#mind-map) |
| 75-InterviewQuestions | _(no heading above it)_ | 1 |  | [mindmap.md:8](../../75-InterviewQuestions/mindmap.md) |
| 76-CheatSheets | Mind map | 1 |  | [README.md:890](../../76-CheatSheets/README.md#mind-map) |
| 76-CheatSheets | _(no heading above it)_ | 1 |  | [mindmap.md:6](../../76-CheatSheets/mindmap.md) |
| 77-UsefulCommands | Mind map | 1 |  | [README.md:1296](../../77-UsefulCommands/README.md#mind-map) |
| 77-UsefulCommands | _(no heading above it)_ | 1 |  | [mindmap.md:3](../../77-UsefulCommands/mindmap.md) |
| 78-Diagrams | Mind map | 1 |  | [README.md:1178](../../78-Diagrams/README.md#mind-map) |
| 78-Diagrams | _(no heading above it)_ | 1 |  | [mindmap.md:5](../../78-Diagrams/mindmap.md) |
| 78-Diagrams | 2 — Unquoted parentheses or brackets in mindmap text | 3 |  | [examples/02-broken-diagrams-and-their-fixes.md:93](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#2--unquoted-parentheses-or-brackets-in-mindmap-text) |
| 78-Diagrams | 2 — Unquoted parentheses or brackets in mindmap text | 1 |  | [examples/02-broken-diagrams-and-their-fixes.md:102](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#2--unquoted-parentheses-or-brackets-in-mindmap-text) |
| 78-Diagrams | 7 — A mindmap leaf whose text starts with a diagram-type keyword | 1 |  | [examples/02-broken-diagrams-and-their-fixes.md:284](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#7--a-mindmap-leaf-whose-text-starts-with-a-diagram-type-keyword) |
| 78-Diagrams | 7 — A mindmap leaf whose text starts with a diagram-type keyword | 3 |  | [examples/02-broken-diagrams-and-their-fixes.md:294](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#7--a-mindmap-leaf-whose-text-starts-with-a-diagram-type-keyword) |
| 79-Glossary | Mind map | 1 |  | [README.md:1027](../../79-Glossary/README.md#mind-map) |
| 80-Appendix | Mind map | 1 |  | [README.md:630](../../80-Appendix/README.md#mind-map) |
| 81-Android-Runtime-Internals | 05-chapter-mindmap.mmd | 1 |  | [diagrams/05-chapter-mindmap.mmd:1](../../81-Android-Runtime-Internals/diagrams/05-chapter-mindmap.mmd) |
| 81-Android-Runtime-Internals | 06-standalone-mindmap.mmd | 1 |  | [diagrams/06-standalone-mindmap.mmd:1](../../81-Android-Runtime-Internals/diagrams/06-standalone-mindmap.mmd) |

## sequence (157)

| Chapter | Depicts | Nodes | Atk | Location |
|---|---|---:|:---:|---|
| 00-Introduction | 2.3 What a typical engagement looks like as a sequence | 5 |  | [README.md:336](../../00-Introduction/README.md#23-what-a-typical-engagement-looks-like-as-a-sequence) |
| 01-Computer-Science-Basics | 2.4 The lifetime of one instruction | 8 |  | [README.md:393](../../01-Computer-Science-Basics/README.md#24-the-lifetime-of-one-instruction) |
| 01-Computer-Science-Basics | 3.13 `fork`, `exec`, and why Zygote exists | 4 |  | [README.md:1501](../../01-Computer-Science-Basics/README.md#313-fork-exec-and-why-zygote-exists) |
| 01-Computer-Science-Basics | 3.13.1 Zygote: `fork` without `exec` | 4 |  | [README.md:1590](../../01-Computer-Science-Basics/README.md#3131-zygote-fork-without-exec) |
| 01-Computer-Science-Basics | 3.19 System calls | 4 |  | [README.md:2410](../../01-Computer-Science-Basics/README.md#319-system-calls) |
| 01-Computer-Science-Basics | 3.25 Static versus dynamic linking | 5 |  | [README.md:2999](../../01-Computer-Science-Basics/README.md#325-static-versus-dynamic-linking) |
| 01-Computer-Science-Basics | 4.2 Trace one: `open()` in Java reaches the kernel | 6 |  | [README.md:3153](../../01-Computer-Science-Basics/README.md#42-trace-one-open-in-java-reaches-the-kernel) |
| 01-Computer-Science-Basics | 4.3 Trace two: an app process is born | 6 |  | [README.md:3193](../../01-Computer-Science-Basics/README.md#43-trace-two-an-app-process-is-born) |
| 02-Linux-Basics | 2.2 Process creation: what actually happens when you type `ls` | 5 |  | [README.md:190](../../02-Linux-Basics/README.md#22-process-creation-what-actually-happens-when-you-type-ls) |
| 02-Linux-Basics | How an app gets its UID: the install flow | 5 |  | [README.md:730](../../02-Linux-Basics/README.md#how-an-app-gets-its-uid-the-install-flow) |
| 02-Linux-Basics | Android's twist: Zygote instead of fork+exec | 5 |  | [README.md:1075](../../02-Linux-Basics/README.md#androids-twist-zygote-instead-of-forkexec) |
| 02-Linux-Basics | Signals and debugging — the part that matters for Android RE | 3 |  | [README.md:1374](../../02-Linux-Basics/README.md#signals-and-debugging--the-part-that-matters-for-android-re) |
| 02-Linux-Basics | 4.4 Tracing one complete path: `File.exists()` down to the kernel | 6 |  | [README.md:2439](../../02-Linux-Basics/README.md#44-tracing-one-complete-path-fileexists-down-to-the-kernel) |
| 03-Programming-Fundamentals | 3.18.1 Pure interpretation | 3 |  | [README.md:2898](../../03-Programming-Fundamentals/README.md#3181-pure-interpretation) |
| 03-Programming-Fundamentals | 4.3 The intern table — `art/runtime/intern_table.cc` and `intern_table.h` | 4 |  | [README.md:3315](../../03-Programming-Fundamentals/README.md#43-the-intern-table--artruntimeintern_tablecc-and-intern_tableh) |
| 04-Java | 2.4 The lifecycle of a single method call | 4 |  | [README.md:351](../../04-Java/README.md#24-the-lifecycle-of-a-single-method-call) |
| 04-Java | Why attackers love reflection | 4 | yes | [README.md:1053](../../04-Java/README.md#why-attackers-love-reflection) |
| 04-Java | 4.3 What `setAccessible(true)` actually does | 5 |  | [README.md:1513](../../04-Java/README.md#43-what-setaccessibletrue-actually-does) |
| 05-Kotlin | 2.4 The lifecycle of a suspend function call | 4 |  | [README.md:316](../../05-Kotlin/README.md#24-the-lifecycle-of-a-suspend-function-call) |
| 05-Kotlin | 4.4 Tracing one call end to end | 6 |  | [README.md:1324](../../05-Kotlin/README.md#44-tracing-one-call-end-to-end) |
| 06-Android-Architecture | 3.7.1 The full sequence | 17 |  | [README.md:984](../../06-Android-Architecture/README.md#371-the-full-sequence) |
| 06-Android-Architecture | 3.8.2 `fork()` without `exec()` — what that actually means | 5 |  | [README.md:1540](../../06-Android-Architecture/README.md#382-fork-without-exec--what-that-actually-means) |
| 07-AOSP | 3.6 AIDL, and why every trace goes through it | 5 |  | [README.md:827](../../07-AOSP/README.md#36-aidl-and-why-every-trace-goes-through-it) |
| 07-AOSP | 4.1 Trace A — `Context.startActivity()`, from your code to the kernel and back | 12 |  | [README.md:1274](../../07-AOSP/README.md#41-trace-a--contextstartactivity-from-your-code-to-the-kernel-and-back) |
| 08-Build-System | 3.7 Gradle: the three phases | 6 |  | [README.md:873](../../08-Build-System/README.md#37-gradle-the-three-phases) |
| 08-Build-System | Play App Signing | 3 |  | [README.md:1508](../../08-Build-System/README.md#play-app-signing) |
| 08-Build-System | 4.4 Trace 2 — from `certificate: "platform"` to a signed APK on the image | 7 |  | [README.md:2048](../../08-Build-System/README.md#44-trace-2--from-certificate-platform-to-a-signed-apk-on-the-image) |
| 09-Android-App-Internals | 3.7 The install flow, end to end | 9 |  | [README.md:814](../../09-Android-App-Internals/README.md#37-the-install-flow-end-to-end) |
| 09-Android-App-Internals | 3.13 Zygote: how a process comes into existence | 5 |  | [README.md:1239](../../09-Android-App-Internals/README.md#313-zygote-how-a-process-comes-into-existence) |
| 09-Android-App-Internals | 3.14 `ActivityThread.main()` and the bootstrap order | 8 |  | [README.md:1323](../../09-Android-App-Internals/README.md#314-activitythreadmain-and-the-bootstrap-order) |
| 10-APK-Internals | Janus — CVE-2017-13156 | 4 |  | [README.md:1133](../../10-APK-Internals/README.md#janus--cve-2017-13156) |
| 10-APK-Internals | Scenario A — repackaging a banking app for a third-party store | 4 |  | [README.md:1310](../../10-APK-Internals/README.md#scenario-a--repackaging-a-banking-app-for-a-third-party-store) |
| 11-Android-Runtime | 2.4 Zygote: preload once, fork many | 5 |  | [README.md:723](../../11-Android-Runtime/README.md#24-zygote-preload-once-fork-many) |
| 11-Android-Runtime | 3.2 Profile-guided compilation and Cloud Profiles | 6 |  | [README.md:1065](../../11-Android-Runtime/README.md#32-profile-guided-compilation-and-cloud-profiles) |
| 11-Android-Runtime | 3.8 Parent delegation and what it protects | 6 |  | [README.md:1400](../../11-Android-Runtime/README.md#38-parent-delegation-and-what-it-protects) |
| 11-Android-Runtime | 3.15 Deoptimization and why hooking frameworks depend on it | 4 |  | [README.md:1890](../../11-Android-Runtime/README.md#315-deoptimization-and-why-hooking-frameworks-depend-on-it) |
| 12-DEX-Internals | 4.1 Trace — how the runtime opens a DEX file | 5 |  | [README.md:2686](../../12-DEX-Internals/README.md#41-trace--how-the-runtime-opens-a-dex-file) |
| 13-ART | 3.8 dex2oat: when it runs and what it does | 4 |  | [README.md:773](../../13-ART/README.md#38-dex2oat-when-it-runs-and-what-it-does) |
| 13-ART | 3.17 Method entrypoint patching: the mechanism behind ALL Java hooking | 4 |  | [README.md:1119](../../13-ART/README.md#317-method-entrypoint-patching-the-mechanism-behind-all-java-hooking) |
| 14-Dalvik | 2.5 The trace JIT | 4 |  | [README.md:545](../../14-Dalvik/README.md#25-the-trace-jit) |
| 15-Native-Code | 2.3 What `System.loadLibrary` sets in motion | 6 |  | [README.md:311](../../15-Native-Code/README.md#23-what-systemloadlibrary-sets-in-motion) |
| 16-JNI | 2.2 The life of a native call, end to end | 6 |  | [README.md:344](../../16-JNI/README.md#22-the-life-of-a-native-call-end-to-end) |
| 16-JNI | 3.22 The managed-to-native transition inside ART | 6 |  | [README.md:2052](../../16-JNI/README.md#322-the-managed-to-native-transition-inside-art) |
| 17-Libraries | How a library gets into a process | 5 |  | [README.md:253](../../17-Libraries/README.md#how-a-library-gets-into-a-process) |
| 18-ARM | 6.1 The path from Java down to the instruction | 5 |  | [README.md:2541](../../18-ARM/README.md#61-the-path-from-java-down-to-the-instruction) |
| 19-Memory | 2.3 The Zygote's consequence for address-space layout | 4 |  | [README.md:255](../../19-Memory/README.md#23-the-zygotes-consequence-for-address-space-layout) |
| 20-Security-Architecture | 2.3 The boot-time sequence | 7 |  | [README.md:215](../../20-Security-Architecture/README.md#23-the-boot-time-sequence) |
| 20-Security-Architecture | How the key is actually derived | 7 |  | [README.md:568](../../20-Security-Architecture/README.md#how-the-key-is-actually-derived) |
| 20-Security-Architecture | Where the trust actually sits — the only paragraph that matters | 4 | yes | [README.md:693](../../20-Security-Architecture/README.md#where-the-trust-actually-sits--the-only-paragraph-that-matters) |
| 21-App-Sandbox | 2.3 UID assignment at install time | 6 |  | [README.md:217](../../21-App-Sandbox/README.md#23-uid-assignment-at-install-time) |
| 21-App-Sandbox | 2.4 Process creation — where the sandbox is actually installed | 5 |  | [README.md:253](../../21-App-Sandbox/README.md#24-process-creation--where-the-sandbox-is-actually-installed) |
| 21-App-Sandbox | How it works, step by step | 4 |  | [README.md:1040](../../21-App-Sandbox/README.md#how-it-works-step-by-step) |
| 22-SELinux | 2.3 Boot: how the policy gets loaded, and why the order matters | 6 |  | [README.md:217](../../22-SELinux/README.md#23-boot-how-the-policy-gets-loaded-and-why-the-order-matters) |
| 22-SELinux | The full sequence, with the syscalls named | 6 |  | [README.md:584](../../22-SELinux/README.md#the-full-sequence-with-the-syscalls-named) |
| 22-SELinux | 3.15 Binder and `service_manager`: a two-stage MAC decision | 4 |  | [README.md:1607](../../22-SELinux/README.md#315-binder-and-service_manager-a-two-stage-mac-decision) |
| 23-Permissions | 2.3 The two enforcement points | 5 |  | [README.md:305](../../23-Permissions/README.md#23-the-two-enforcement-points) |
| 23-Permissions | The flow | 5 |  | [README.md:1322](../../23-Permissions/README.md#the-flow) |
| 23-Permissions | 4.3 From `<permission>` in XML to a decision at install | 6 |  | [README.md:2026](../../23-Permissions/README.md#43-from-permission-in-xml-to-a-decision-at-install) |
| 24-IPC | 2.3 A concrete request, end to end | 5 |  | [README.md:304](../../24-IPC/README.md#23-a-concrete-request-end-to-end) |
| 24-IPC | 3.20.1 The Android worked example | 4 |  | [README.md:1804](../../24-IPC/README.md#3201-the-android-worked-example) |
| 25-Binder | 2.2 One transaction, as a sequence | 5 |  | [README.md:231](../../25-Binder/README.md#22-one-transaction-as-a-sequence) |
| 25-Binder | 3.12.2 Why the thread pool makes it dangerous | 3 |  | [README.md:1336](../../25-Binder/README.md#3122-why-the-thread-pool-makes-it-dangerous) |
| 26-Intent | 2.2 The delivery path, end to end | 7 |  | [README.md:197](../../26-Intent/README.md#22-the-delivery-path-end-to-end) |
| 26-Intent | How verification works | 4 |  | [README.md:1110](../../26-Intent/README.md#how-verification-works) |
| 26-Intent | The exploit | 4 |  | [README.md:1690](../../26-Intent/README.md#the-exploit) |
| 26-Intent | Background: why this is a privilege escalation and not a routing bug | 4 |  | [labs/lab-01-intent-redirection.md:60](../../26-Intent/labs/lab-01-intent-redirection.md#background-why-this-is-a-privilege-escalation-and-not-a-routing-bug) |
| 26-Intent | Background: request versus state | 4 |  | [labs/lab-03-applink-verification.md:45](../../26-Intent/labs/lab-03-applink-verification.md#background-request-versus-state) |
| 27-ContentProviders | 3.6 URI permissions: the temporary grant system | 3 |  | [README.md:522](../../27-ContentProviders/README.md#36-uri-permissions-the-temporary-grant-system) |
| 28-Services | 2.2 One `bindService` call, end to end | 5 |  | [README.md:252](../../28-Services/README.md#22-one-bindservice-call-end-to-end) |
| 29-BroadcastReceivers | 2.4 What actually happens on the wire, in order | 7 |  | [README.md:412](../../29-BroadcastReceivers/README.md#24-what-actually-happens-on-the-wire-in-order) |
| 30-Activities | 2.2 What actually happens when you call `startActivity` | 6 |  | [README.md:210](../../30-Activities/README.md#22-what-actually-happens-when-you-call-startactivity) |
| 30-Activities | 3.9 Tapjacking — a different subsystem entirely | 4 |  | [README.md:864](../../30-Activities/README.md#39-tapjacking--a-different-subsystem-entirely) |
| 30-Activities | 3.10 The result channel | 2 |  | [README.md:952](../../30-Activities/README.md#310-the-result-channel) |
| 30-Activities | The intended mechanism | 5 |  | [README.md:1356](../../30-Activities/README.md#the-intended-mechanism) |
| 31-Fragments | 2.4 The injection, end to end | 5 |  | [README.md:326](../../31-Fragments/README.md#24-the-injection-end-to-end) |
| 32-Manifest | Task hijacking, precisely | 4 |  | [README.md:737](../../32-Manifest/README.md#task-hijacking-precisely) |
| 32-Manifest | 4.2 From bytes to `PackageInfo` | 6 |  | [README.md:1529](../../32-Manifest/README.md#42-from-bytes-to-packageinfo) |
| 33-Storage | 2.3 What the same file looks like from three vantage points | 5 |  | [README.md:290](../../33-Storage/README.md#23-what-the-same-file-looks-like-from-three-vantage-points) |
| 34-Cryptography | 2.3 The JCA call flow, end to end | 7 |  | [README.md:300](../../34-Cryptography/README.md#23-the-jca-call-flow-end-to-end) |
| 34-Cryptography | 3.3.3 The padding oracle attack — explained in full | 2 |  | [README.md:630](../../34-Cryptography/README.md#333-the-padding-oracle-attack--explained-in-full) |
| 34-Cryptography | 3.6.3 Diffie–Hellman and ECDH — the colour-mixing analogy | 3 |  | [README.md:1045](../../34-Cryptography/README.md#363-diffiehellman-and-ecdh--the-colour-mixing-analogy) |
| 35-SSL | 2.2 The handshake, as a conversation | 2 |  | [README.md:239](../../35-SSL/README.md#22-the-handshake-as-a-conversation) |
| 35-SSL | 3.2.3 What an intercepting proxy actually does | 3 |  | [README.md:534](../../35-SSL/README.md#323-what-an-intercepting-proxy-actually-does) |
| 36-CertificatePinning | 2.2 Order of operations for one connection | 7 |  | [README.md:266](../../36-CertificatePinning/README.md#22-order-of-operations-for-one-connection) |
| 37-RootDetection | The arms race, drawn | 4 |  | [README.md:1854](../../37-RootDetection/README.md#the-arms-race-drawn) |
| 37-RootDetection | 4.1 `File.exists()` → `faccessat` syscall | 7 |  | [README.md:2042](../../37-RootDetection/README.md#41-fileexists--faccessat-syscall) |
| 37-RootDetection | 4.3 `PackageManager.getPackageInfo` across Binder | 5 |  | [README.md:2145](../../37-RootDetection/README.md#43-packagemanagergetpackageinfo-across-binder) |
| 38-TamperDetection | 2.3 Where a self-signature check gets its answer | 5 |  | [README.md:362](../../38-TamperDetection/README.md#23-where-a-self-signature-check-gets-its-answer) |
| 39-EmulatorDetection | 5.8 The correct architecture | 4 |  | [README.md:1636](../../39-EmulatorDetection/README.md#58-the-correct-architecture) |
| 40-Obfuscation | The runtime picture: what a packed app does at process start | 6 |  | [README.md:267](../../40-Obfuscation/README.md#the-runtime-picture-what-a-packed-app-does-at-process-start) |
| 40-Obfuscation | 4.3 The framework side — how a packer's stub gets control | 5 |  | [README.md:1638](../../40-Obfuscation/README.md#43-the-framework-side--how-a-packers-stub-gets-control) |
| 42-R8 | 2.2 The four phases inside R8 | 6 |  | [README.md:183](../../42-R8/README.md#22-the-four-phases-inside-r8) |
| 43-WebView | 2.2 A page load, from `loadUrl` to pixels | 7 |  | [README.md:280](../../43-WebView/README.md#22-a-page-load-from-loadurl-to-pixels) |
| 44-NetworkSecurityConfig | 2.2 Answering one question: "may I connect to this host, and whom do I trust for it?" | 6 |  | [README.md:288](../../44-NetworkSecurityConfig/README.md#22-answering-one-question-may-i-connect-to-this-host-and-whom-do-i-trust-for-it) |
| 45-OAuth | 3.2 Grant type 1 — Authorisation Code (without PKCE) | 5 |  | [README.md:393](../../45-OAuth/README.md#32-grant-type-1--authorisation-code-without-pkce) |
| 45-OAuth | 3.3 Grant type 2 — Authorisation Code with PKCE (the correct choice) | 4 |  | [README.md:440](../../45-OAuth/README.md#33-grant-type-2--authorisation-code-with-pkce-the-correct-choice) |
| 45-OAuth | 3.4 Grant type 3 — Implicit (dead, and why) | 4 |  | [README.md:554](../../45-OAuth/README.md#34-grant-type-3--implicit-dead-and-why) |
| 45-OAuth | 3.5 Grant type 4 — Resource Owner Password Credentials (ROPC) (dead, and why apps still ship it) | 3 |  | [README.md:602](../../45-OAuth/README.md#35-grant-type-4--resource-owner-password-credentials-ropc-dead-and-why-apps-still-ship-it) |
| 45-OAuth | 3.6 Grant type 5 — Client Credentials | 2 |  | [README.md:661](../../45-OAuth/README.md#36-grant-type-5--client-credentials) |
| 45-OAuth | 3.7 Grant type 6 — Device Authorization Grant (RFC 8628) | 4 |  | [README.md:702](../../45-OAuth/README.md#37-grant-type-6--device-authorization-grant-rfc-8628) |
| 45-OAuth | 3.8 Grant type 7 — Refresh Token | 3 |  | [README.md:756](../../45-OAuth/README.md#38-grant-type-7--refresh-token) |
| 45-OAuth | 3.10.1 Custom URI schemes — and scheme hijacking | 5 | yes | [README.md:960](../../45-OAuth/README.md#3101-custom-uri-schemes--and-scheme-hijacking) |
| 45-OAuth | 3.11 The `state` parameter, and CSRF | 3 | yes | [README.md:1098](../../45-OAuth/README.md#311-the-state-parameter-and-csrf) |
| 45-OAuth | 3.13 Pushed Authorization Requests and other hardening | 3 |  | [README.md:1293](../../45-OAuth/README.md#313-pushed-authorization-requests-and-other-hardening) |
| 45-OAuth | 4.1 The redirect's journey through the platform | 6 |  | [README.md:1414](../../45-OAuth/README.md#41-the-redirects-journey-through-the-platform) |
| 45-OAuth | Attack 5 — Mix-up attacks | 4 | yes | [README.md:1694](../../45-OAuth/README.md#attack-5--mix-up-attacks) |
| 45-OAuth | Attack 6 — "Sign in with X" backend token confusion | 5 |  | [README.md:1726](../../45-OAuth/README.md#attack-6--sign-in-with-x-backend-token-confusion) |
| 46-Tokens | 3.9 Refresh tokens: rotation and reuse detection | 3 |  | [README.md:942](../../46-Tokens/README.md#39-refresh-tokens-rotation-and-reuse-detection) |
| 46-Tokens | DPoP (RFC 9449) | 4 |  | [README.md:1095](../../46-Tokens/README.md#dpop-rfc-9449) |
| 47-Authentication | 2.2 The login sequence, with the transport on every arrow | 6 |  | [README.md:322](../../47-Authentication/README.md#22-the-login-sequence-with-the-transport-on-every-arrow) |
| 47-Authentication | 3.5 The autofill framework — a third party is offered your password field | 4 |  | [README.md:764](../../47-Authentication/README.md#35-the-autofill-framework--a-third-party-is-offered-your-password-field) |
| 47-Authentication | 3.6 Credential Manager and passkeys | 5 |  | [README.md:861](../../47-Authentication/README.md#36-credential-manager-and-passkeys) |
| 47-Authentication | 4.1 The account stack | 5 |  | [README.md:1296](../../47-Authentication/README.md#41-the-account-stack) |
| 48-Biometrics | 2.2 The successful path, in order | 7 |  | [README.md:262](../../48-Biometrics/README.md#22-the-successful-path-in-order) |
| 49-KeyStore | 2.2 The lifecycle of one key, as a sequence | 5 |  | [README.md:181](../../49-KeyStore/README.md#22-the-lifecycle-of-one-key-as-a-sequence) |
| 50-HardwareBackedSecurity | 2.4 From PIN to permitted operation: the whole chain in one sequence | 6 |  | [README.md:271](../../50-HardwareBackedSecurity/README.md#24-from-pin-to-permitted-operation-the-whole-chain-in-one-sequence) |
| 51-DynamicAnalysis | 2.4 The other half of the loop | 3 |  | [README.md:394](../../51-DynamicAnalysis/README.md#24-the-other-half-of-the-loop) |
| 53-Frida | 2.2 The injection sequence, step by step | 6 |  | [README.md:282](../../53-Frida/README.md#22-the-injection-sequence-step-by-step) |
| 53-Frida | 2.4 The message channel | 6 |  | [README.md:395](../../53-Frida/README.md#24-the-message-channel) |
| 53-Frida | 7.4.4 Failure 4 — attaching instead of spawning | 5 |  | [README.md:3970](../../53-Frida/README.md#744-failure-4--attaching-instead-of-spawning) |
| 54-Objection | 2.2 What happens when you type the command | 6 |  | [README.md:237](../../54-Objection/README.md#22-what-happens-when-you-type-the-command) |
| 55-MobSF | 2.4 The REST API, as a conversation | 3 |  | [README.md:518](../../55-MobSF/README.md#24-the-rest-api-as-a-conversation) |
| 56-JADX | 7.1 The read-hook-verify loop | 4 |  | [README.md:2805](../../56-JADX/README.md#71-the-read-hook-verify-loop) |
| 57-Ghidra | 3.15 The Ghidra debugger against an Android target | 5 |  | [README.md:1245](../../57-Ghidra/README.md#315-the-ghidra-debugger-against-an-android-target) |
| 58-IDA | 3.9 The debugger and `android_server` | 5 |  | [README.md:937](../../58-IDA/README.md#39-the-debugger-and-android_server) |
| 60-ADB | 2.2 The handshake, message by message | 2 |  | [README.md:195](../../60-ADB/README.md#22-the-handshake-message-by-message) |
| 60-ADB | 3.14 `adb install` is three streams — the transport half | 3 |  | [README.md:1222](../../60-ADB/README.md#314-adb-install-is-three-streams--the-transport-half) |
| 61-Fastboot | 2.2 The three-legged transaction that every fastboot operation is built from | 2 |  | [README.md:262](../../61-Fastboot/README.md#22-the-three-legged-transaction-that-every-fastboot-operation-is-built-from) |
| 61-Fastboot | 3.6 `fastbootd` — userspace fastboot, and why it had to exist | 4 |  | [README.md:765](../../61-Fastboot/README.md#36-fastbootd--userspace-fastboot-and-why-it-had-to-exist) |
| 61-Fastboot | 3.9 The factory-reset guarantee | 3 |  | [README.md:1034](../../61-Fastboot/README.md#39-the-factory-reset-guarantee) |
| 61-Fastboot | 4.2 Tracing one complete path: `fastboot flash system system.img` | 7 |  | [README.md:1300](../../61-Fastboot/README.md#42-tracing-one-complete-path-fastboot-flash-system-systemimg) |
| 62-Magisk | 2.3 The `su` request flow | 5 |  | [README.md:267](../../62-Magisk/README.md#23-the-su-request-flow) |
| 63-LSPosed | 2.2 One app launch, as a sequence | 7 |  | [README.md:322](../../63-LSPosed/README.md#22-one-app-launch-as-a-sequence) |
| 64-Xposed | 2.2 One app launch, as a sequence | 6 |  | [README.md:374](../../64-Xposed/README.md#22-one-app-launch-as-a-sequence) |
| 65-Hooking | 2.3 The anatomy of an inline hook | 4 |  | [README.md:244](../../65-Hooking/README.md#23-the-anatomy-of-an-inline-hook) |
| 66-Instrumentation | 2.2 The Binder sequence, with the ordering that matters | 7 |  | [README.md:236](../../66-Instrumentation/README.md#22-the-binder-sequence-with-the-ordering-that-matters) |
| 67-BypassingProtections | 2.2 The same picture as a sequence, with the timing that matters | 6 |  | [README.md:236](../../67-BypassingProtections/README.md#22-the-same-picture-as-a-sequence-with-the-timing-that-matters) |
| 68-ReverseEngineering | 3.5 Stage 4 — hypothesis, prediction, experiment, verdict | 3 |  | [README.md:806](../../68-ReverseEngineering/README.md#35-stage-4--hypothesis-prediction-experiment-verdict) |
| 68-ReverseEngineering | 4.5 Tracing one question from Java to the kernel | 5 |  | [README.md:1560](../../68-ReverseEngineering/README.md#45-tracing-one-question-from-java-to-the-kernel) |
| 69-MalwareAnalysis | 2.3 The lifecycle of a mobile malware campaign | 5 |  | [README.md:448](../../69-MalwareAnalysis/README.md#23-the-lifecycle-of-a-mobile-malware-campaign) |
| 70-VulnerabilityResearch | 2.4 Where a crash comes from and where it goes | 5 |  | [README.md:440](../../70-VulnerabilityResearch/README.md#24-where-a-crash-comes-from-and-where-it-goes) |
| 70-VulnerabilityResearch | 4.4 Tracing one path from untrusted input to a parser | 5 | yes | [README.md:1359](../../70-VulnerabilityResearch/README.md#44-tracing-one-path-from-untrusted-input-to-a-parser) |
| 73-Labs | 2.2 How the index is produced | 4 |  | [README.md:208](../../73-Labs/README.md#22-how-the-index-is-produced) |
| 74-CaseStudies | 2.3 Where the evidence for one case comes from | 5 |  | [README.md:253](../../74-CaseStudies/README.md#23-where-the-evidence-for-one-case-comes-from) |
| 75-InterviewQuestions | 2.2 One round, end to end | 4 |  | [README.md:342](../../75-InterviewQuestions/README.md#22-one-round-end-to-end) |
| 78-Diagrams | 4.2 The boot chain, hardware root of trust to app code | 6 |  | [README.md:411](../../78-Diagrams/README.md#42-the-boot-chain-hardware-root-of-trust-to-app-code) |
| 78-Diagrams | 4.5 One Binder call, across every boundary | 5 |  | [README.md:580](../../78-Diagrams/README.md#45-one-binder-call-across-every-boundary) |
| 78-Diagrams | 5.3 Sequence arrows — the four you must tell apart | 2 |  | [README.md:747](../../78-Diagrams/README.md#53-sequence-arrows--the-four-you-must-tell-apart) |
| 78-Diagrams | Version C — the same system as a sequence | 6 |  | [examples/01-one-system-three-diagrams.md:194](../../78-Diagrams/examples/01-one-system-three-diagrams.md#version-c--the-same-system-as-a-sequence) |
| 78-Diagrams | 1 — A semicolon in message or label text | 2 |  | [examples/02-broken-diagrams-and-their-fixes.md:48](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#1--a-semicolon-in-message-or-label-text) |
| 78-Diagrams | 1 — A semicolon in message or label text | 2 |  | [examples/02-broken-diagrams-and-their-fixes.md:57](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#1--a-semicolon-in-message-or-label-text) |
| 78-Diagrams | 4 — `style` inside a `sequenceDiagram` | 2 |  | [examples/02-broken-diagrams-and-their-fixes.md:166](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#4--style-inside-a-sequencediagram) |
| 78-Diagrams | 4 — `style` inside a `sequenceDiagram` | 2 |  | [examples/02-broken-diagrams-and-their-fixes.md:178](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#4--style-inside-a-sequencediagram) |
| 78-Diagrams | 5 — A participant id that collides with a keyword | 2 |  | [examples/02-broken-diagrams-and-their-fixes.md:221](../../78-Diagrams/examples/02-broken-diagrams-and-their-fixes.md#5--a-participant-id-that-collides-with-a-keyword) |
| 78-Diagrams | Part 1 — Draw the intended flow, before measuring | 4 |  | [labs/lab-03-intended-versus-actual.md:80](../../78-Diagrams/labs/lab-03-intended-versus-actual.md#part-1--draw-the-intended-flow-before-measuring) |
| 78-Diagrams | Part 3 — Draw the actual flow | 5 |  | [labs/lab-03-intended-versus-actual.md:275](../../78-Diagrams/labs/lab-03-intended-versus-actual.md#part-3--draw-the-actual-flow) |
| 81-Android-Runtime-Internals | 04-hooked-call-sequence.mmd | 7 |  | [diagrams/04-hooked-call-sequence.mmd:1](../../81-Android-Runtime-Internals/diagrams/04-hooked-call-sequence.mmd) |

## state (36)

| Chapter | Depicts | Nodes | Atk | Location |
|---|---|---:|:---:|---|
| 00-Introduction | 2.4 The learning state machine | 0 |  | [README.md:372](../../00-Introduction/README.md#24-the-learning-state-machine) |
| 01-Computer-Science-Basics | 3.6 What a CPU does: fetch, decode, execute | 0 |  | [README.md:935](../../01-Computer-Science-Basics/README.md#36-what-a-cpu-does-fetch-decode-execute) |
| 01-Computer-Science-Basics | 3.12 Processes: address space, PID, and the process control block | 6 |  | [README.md:1437](../../01-Computer-Science-Basics/README.md#312-processes-address-space-pid-and-the-process-control-block) |
| 02-Linux-Basics | `fork()`, `execve()`, `wait()`, `exit()` — the process lifecycle | 7 |  | [README.md:1051](../../02-Linux-Basics/README.md#fork-execve-wait-exit--the-process-lifecycle) |
| 03-Programming-Fundamentals | 3.18.4 JIT — compiling at run time | 0 |  | [README.md:2982](../../03-Programming-Fundamentals/README.md#3184-jit--compiling-at-run-time) |
| 09-Android-App-Internals | 2.3 The lifetime of an app, end to end | 6 |  | [README.md:321](../../09-Android-App-Internals/README.md#23-the-lifetime-of-an-app-end-to-end) |
| 13-ART | 2.4 The three execution modes, compared | 0 |  | [README.md:320](../../13-ART/README.md#24-the-three-execution-modes-compared) |
| 18-ARM | 2.2 The execution states, and why a phone has three | 4 |  | [README.md:239](../../18-ARM/README.md#22-the-execution-states-and-why-a-phone-has-three) |
| 20-Security-Architecture | From FDE to FBE | 2 |  | [README.md:542](../../20-Security-Architecture/README.md#from-fde-to-fbe) |
| 27-ContentProviders | 3.11 Provider lifecycle and process behaviour | 4 |  | [README.md:816](../../27-ContentProviders/README.md#311-provider-lifecycle-and-process-behaviour) |
| 28-Services | 2.3 The lifecycle, as a state machine | 9 |  | [README.md:298](../../28-Services/README.md#23-the-lifecycle-as-a-state-machine) |
| 29-BroadcastReceivers | 2.5 The life of one broadcast, as a state machine | 6 |  | [README.md:466](../../29-BroadcastReceivers/README.md#25-the-life-of-one-broadcast-as-a-state-machine) |
| 30-Activities | 3.1 The lifecycle, and which parts an attacker controls | 8 |  | [README.md:333](../../30-Activities/README.md#31-the-lifecycle-and-which-parts-an-attacker-controls) |
| 31-Fragments | 3.1 The Fragment lifecycle, and the four ways it differs from an Activity's | 10 |  | [README.md:373](../../31-Fragments/README.md#31-the-fragment-lifecycle-and-the-four-ways-it-differs-from-an-activitys) |
| 33-Storage | 2.4 The lifecycle of a byte | 3 |  | [README.md:343](../../33-Storage/README.md#24-the-lifecycle-of-a-byte) |
| 35-SSL | 2.5 The trust decision, as a state machine | 0 |  | [README.md:372](../../35-SSL/README.md#25-the-trust-decision-as-a-state-machine) |
| 36-CertificatePinning | 2.4 The decision tree you are actually walking | 0 |  | [README.md:349](../../36-CertificatePinning/README.md#24-the-decision-tree-you-are-actually-walking) |
| 41-ProGuard | 2.2 ProGuard's four phases, and R8's one | 0 |  | [README.md:273](../../41-ProGuard/README.md#22-proguards-four-phases-and-r8s-one) |
| 41-ProGuard | The rules-writing loop | 0 |  | [mindmap.md:203](../../41-ProGuard/mindmap.md#the-rules-writing-loop) |
| 42-R8 | 2.4 The compatibility-mode split | 1 |  | [README.md:252](../../42-R8/README.md#24-the-compatibility-mode-split) |
| 47-Authentication | 2.3 The session lifecycle as a state machine | 3 |  | [README.md:385](../../47-Authentication/README.md#23-the-session-lifecycle-as-a-state-machine) |
| 50-HardwareBackedSecurity | 3.2 ARM TrustZone mechanics | 0 |  | [README.md:414](../../50-HardwareBackedSecurity/README.md#32-arm-trustzone-mechanics) |
| 51-DynamicAnalysis | 2.3 The life of an observation | 0 |  | [README.md:342](../../51-DynamicAnalysis/README.md#23-the-life-of-an-observation) |
| 52-StaticAnalysis | 2.3 The life of a lead | 0 |  | [README.md:258](../../52-StaticAnalysis/README.md#23-the-life-of-a-lead) |
| 61-Fastboot | 2.3 The lock-state machine — the most important diagram in this chapter | 3 |  | [README.md:313](../../61-Fastboot/README.md#23-the-lock-state-machine--the-most-important-diagram-in-this-chapter) |
| 61-Fastboot | 3.2 The wire protocol: five prefixes and nothing else | 2 |  | [README.md:527](../../61-Fastboot/README.md#32-the-wire-protocol-five-prefixes-and-nothing-else) |
| 63-LSPosed | 3.7 `XC_MethodHook` — the lifecycle, precisely | 4 |  | [README.md:748](../../63-LSPosed/README.md#37-xc_methodhook--the-lifecycle-precisely) |
| 66-Instrumentation | 2.4 The lifecycle as a state machine | 4 |  | [README.md:332](../../66-Instrumentation/README.md#24-the-lifecycle-as-a-state-machine) |
| 67-BypassingProtections | 2.4 The escalation ladder, drawn | 3 |  | [README.md:304](../../67-BypassingProtections/README.md#24-the-escalation-ladder-drawn) |
| 68-ReverseEngineering | 2.5 The state of a question | 0 |  | [README.md:550](../../68-ReverseEngineering/README.md#25-the-state-of-a-question) |
| 69-MalwareAnalysis | 3.8 Persistence hook 3 — services, watchdogs and the platform's counter-moves | 0 |  | [README.md:987](../../69-MalwareAnalysis/README.md#38-persistence-hook-3--services-watchdogs-and-the-platforms-counter-moves) |
| 73-Labs | 2.4 The lifecycle of one lab attempt | 0 |  | [README.md:263](../../73-Labs/README.md#24-the-lifecycle-of-one-lab-attempt) |
| 75-InterviewQuestions | 2.3 The state machine of a single answer | 0 |  | [README.md:396](../../75-InterviewQuestions/README.md#23-the-state-machine-of-a-single-answer) |
| 78-Diagrams | 4.6 The engagement, static through dynamic to reporting | 0 |  | [README.md:619](../../78-Diagrams/README.md#46-the-engagement-static-through-dynamic-to-reporting) |
| 78-Diagrams | 4.7 The device-state machine an engagement moves through | 0 |  | [README.md:662](../../78-Diagrams/README.md#47-the-device-state-machine-an-engagement-moves-through) |
| 78-Diagrams | 5.4 State and class notation | 0 |  | [README.md:778](../../78-Diagrams/README.md#54-state-and-class-notation) |

## block layout (28)

| Chapter | Depicts | Nodes | Atk | Location |
|---|---|---:|:---:|---|
| 01-Computer-Science-Basics | 2.2 What one function call actually costs | 12 |  | [README.md:307](../../01-Computer-Science-Basics/README.md#22-what-one-function-call-actually-costs) |
| 01-Computer-Science-Basics | 2.3 A process's address space | 13 |  | [README.md:345](../../01-Computer-Science-Basics/README.md#23-a-processs-address-space) |
| 01-Computer-Science-Basics | 3.16 The stack, in full | 15 |  | [README.md:1830](../../01-Computer-Science-Basics/README.md#316-the-stack-in-full) |
| 01-Computer-Science-Basics | 3.23 ELF: the container for all native code | 15 |  | [README.md:2795](../../01-Computer-Science-Basics/README.md#323-elf-the-container-for-all-native-code) |
| 01-Computer-Science-Basics | Part C — Reading `/proc/<pid>/maps` | 13 |  | [labs/lab-02-processes-memory-maps.md:355](../../01-Computer-Science-Basics/labs/lab-02-processes-memory-maps.md#part-c--reading-procpidmaps) |
| 01-Computer-Science-Basics | Part B — Read the prologue and epilogue | 10 |  | [labs/lab-03-stack-frames-and-overflow.md:299](../../01-Computer-Science-Basics/labs/lab-03-stack-frames-and-overflow.md#part-b--read-the-prologue-and-epilogue) |
| 03-Programming-Fundamentals | 3.1 Variables and memory — what a variable actually is | 13 |  | [README.md:584](../../03-Programming-Fundamentals/README.md#31-variables-and-memory--what-a-variable-actually-is) |
| 04-Java | 2.3 The runtime picture: where a Java object actually lives | 8 |  | [README.md:315](../../04-Java/README.md#23-the-runtime-picture-where-a-java-object-actually-lives) |
| 08-Build-System | 2.5 Where each artefact ends up | 16 |  | [README.md:465](../../08-Build-System/README.md#25-where-each-artefact-ends-up) |
| 11-Android-Runtime | 2.5 Copy-on-write and what it costs you as an attacker | 8 |  | [README.md:798](../../11-Android-Runtime/README.md#25-copy-on-write-and-what-it-costs-you-as-an-attacker) |
| 11-Android-Runtime | 3.14 JIT hardening, W^X, and CFI | 6 |  | [README.md:1821](../../11-Android-Runtime/README.md#314-jit-hardening-wx-and-cfi) |
| 12-DEX-Internals | 2.1 The whole file at a glance | 22 |  | [README.md:251](../../12-DEX-Internals/README.md#21-the-whole-file-at-a-glance) |
| 12-DEX-Internals | 2.4 Where DEX sits inside an APK | 10 |  | [README.md:435](../../12-DEX-Internals/README.md#24-where-dex-sits-inside-an-apk) |
| 12-DEX-Internals | 3.2 `header_item` field by field | 23 | yes | [README.md:568](../../12-DEX-Internals/README.md#32-header_item-field-by-field) |
| 15-Native-Code | 2.2 The two tables, and who reads which | 12 |  | [README.md:276](../../15-Native-Code/README.md#22-the-two-tables-and-who-reads-which) |
| 20-Security-Architecture | 2.4 Where each control lives in the stack | 22 |  | [README.md:250](../../20-Security-Architecture/README.md#24-where-each-control-lives-in-the-stack) |
| 21-App-Sandbox | 2.5 The filesystem, drawn | 12 |  | [README.md:293](../../21-App-Sandbox/README.md#25-the-filesystem-drawn) |
| 40-Obfuscation | Layer map: what protects what | 9 |  | [README.md:307](../../40-Obfuscation/README.md#layer-map-what-protects-what) |
| 45-OAuth | 2.3 Where the pieces live on the device | 10 |  | [README.md:291](../../45-OAuth/README.md#23-where-the-pieces-live-on-the-device) |
| 46-Tokens | 2.4 Where a token can be on an Android device | 11 |  | [README.md:435](../../46-Tokens/README.md#24-where-a-token-can-be-on-an-android-device) |
| 47-Authentication | 2.4 Where the credential physically lives | 7 | yes | [README.md:447](../../47-Authentication/README.md#24-where-the-credential-physically-lives) |
| 48-Biometrics | 2.4 Trust boundaries, drawn honestly | 6 | yes | [README.md:379](../../48-Biometrics/README.md#24-trust-boundaries-drawn-honestly) |
| 53-Frida | 3.3 What lives inside the agent | 9 |  | [README.md:662](../../53-Frida/README.md#33-what-lives-inside-the-agent) |
| 56-JADX | 2.2 The information-loss ladder | 13 |  | [README.md:373](../../56-JADX/README.md#22-the-information-loss-ladder) |
| 64-Xposed | 2.3 What a classic install physically wrote to disk | 11 | yes | [README.md:418](../../64-Xposed/README.md#23-what-a-classic-install-physically-wrote-to-disk) |
| 69-MalwareAnalysis | 2.2 The capability stack — what an installed app can actually reach | 16 | yes | [README.md:384](../../69-MalwareAnalysis/README.md#22-the-capability-stack--what-an-installed-app-can-actually-reach) |
| 72-RealWorldFindings | 2.3 The severity funnel, drawn to scale | 6 |  | [README.md:279](../../72-RealWorldFindings/README.md#23-the-severity-funnel-drawn-to-scale) |
| 73-Labs | 2.3 The lab environment, as a stack | 12 |  | [README.md:245](../../73-Labs/README.md#23-the-lab-environment-as-a-stack) |

## class (12)

| Chapter | Depicts | Nodes | Atk | Location |
|---|---|---:|:---:|---|
| 04-Java | 2.2 What lives inside a class file | 4 |  | [README.md:265](../../04-Java/README.md#22-what-lives-inside-a-class-file) |
| 04-Java | 3.8 The collections framework | 3 |  | [README.md:777](../../04-Java/README.md#38-the-collections-framework) |
| 05-Kotlin | 2.2 What the compiler adds to a class | 6 |  | [README.md:235](../../05-Kotlin/README.md#22-what-the-compiler-adds-to-a-class) |
| 11-Android-Runtime | 3.7 The ClassLoader hierarchy on Android | 10 |  | [README.md:1297](../../11-Android-Runtime/README.md#37-the-classloader-hierarchy-on-android) |
| 13-ART | 2.6 The object graph inside libart | 7 |  | [README.md:386](../../13-ART/README.md#26-the-object-graph-inside-libart) |
| 16-JNI | 2.5 The reference tables, drawn | 5 |  | [README.md:488](../../16-JNI/README.md#25-the-reference-tables-drawn) |
| 26-Intent | 2.1 What an Intent actually is, as a shape | 3 |  | [README.md:152](../../26-Intent/README.md#21-what-an-intent-actually-is-as-a-shape) |
| 31-Fragments | 2.2 Two Fragment implementations, and why an app has both | 4 |  | [README.md:226](../../31-Fragments/README.md#22-two-fragment-implementations-and-why-an-app-has-both) |
| 34-Cryptography | 3.11.1 The provider model | 11 |  | [README.md:1500](../../34-Cryptography/README.md#3111-the-provider-model) |
| 44-NetworkSecurityConfig | 2.4 The object graph, at runtime | 11 |  | [README.md:369](../../44-NetworkSecurityConfig/README.md#24-the-object-graph-at-runtime) |
| 55-MobSF | 2.3 The report, as a data structure | 8 |  | [README.md:447](../../55-MobSF/README.md#23-the-report-as-a-data-structure) |
| 78-Diagrams | 5.4 State and class notation | 2 |  | [README.md:794](../../78-Diagrams/README.md#54-state-and-class-notation) |

