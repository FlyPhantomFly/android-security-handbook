# 22 — SELinux: Annotated References

Every entry says **what it is good for** and **when to reach for it**, because the volume of SELinux material is large and most of it is written for Red Hat rather than for Android.

Sources are grouped by how you would actually use them: read the model once, read the Android specifics carefully, and then live in the AOSP tree and on the device.

---

## 1. Start here — the two things to read first

| Source | Why first |
|---|---|
| **AOSP — Security-Enhanced Linux in Android** — `https://source.android.com/docs/security/features/selinux` | The canonical Android overview. Short, accurate, and it establishes the vocabulary the rest of the ecosystem uses. Read the "Concepts" and "Implementing" pages before anything else. |
| **The SELinux Notebook**, Richard Haines | The standard free reference for the SELinux *model* — types, attributes, constraints, MLS, the policy languages, and CIL. Android-agnostic, which is exactly why it is useful: it explains the machinery this chapter applies. The MLS chapter is the best explanation of `dom` and constraints anywhere, and the CIL chapter is the only readable explanation of the syntax you find on a device. |

If you read only one non-Android source, read the Notebook's chapters on **Type Enforcement**, **Constraints** and **MLS**. Those three cover almost everything [README §3.3](../README.md#33-the-access-decision-what-the-kernel-actually-computes) and [§3.7](../README.md#37-mcs-the-category-encoding-and-what-it-actually-enforces) build on.

---

## 2. AOSP source — the policy itself

These paths are stable across releases. Line numbers are not, and are deliberately not cited anywhere in this chapter.

| Path | What it gives you | Reach for it when |
|---|---|---|
| `system/sepolicy/` | the entire platform policy tree | always; this is the root |
| `system/sepolicy/public/` | types and attributes vendor policy may reference | you need to know what a vendor is *allowed* to name |
| `system/sepolicy/private/` | platform-internal types and rules | you are reading a rule and want its `.te` original |
| `system/sepolicy/private/seapp_contexts` | **where an app's domain is decided** | any question of the form "why is this app in that domain" — [§3.6](../README.md#36-seapp_contexts-where-the-domain-is-actually-decided) |
| `system/sepolicy/private/access_vectors` | **the definitive list of object classes and every permission** | you need to know what `execmod` or `dyntransition` or `manage_blob` actually means. Read this, not a blog post. |
| `system/sepolicy/private/security_classes` | the class list | you meet a `tclass=` you do not recognise |
| `system/sepolicy/private/mls` and `private/mls_macros` | **the MLS constraint definitions** | you want the source of the `mlsconstrain` lines that enforce MCS |
| `system/sepolicy/private/file_contexts` | the filesystem label map | a file has an unexpected label |
| `system/sepolicy/private/property_contexts` | property labels | a `property_service:set` denial |
| `system/sepolicy/private/service_contexts` | Binder service-name labels | a `service_manager:find` denial |
| `system/sepolicy/private/keystore2_key_contexts` | Keystore 2.0 namespace labels | anything `keystore2_key` — [§3.13](../README.md#313-the-keystore_key-and-keystore2_key-classes) |
| `system/sepolicy/private/mac_permissions.xml` | signing certificate to `seinfo` mapping | you need to know why an app did or did not match `seinfo=platform` |
| `system/sepolicy/prebuilts/api/<ver>/` | frozen public API per release | you are working on Treble compatibility |
| `system/sepolicy/tools/` | build-time checkers, including the permissive-domain check | you want to know what AOSP enforces at build time |
| `system/sepolicy/vendor/` | rules for `/vendor` domains that ship in AOSP | you are comparing an OEM's vendor policy against the AOSP baseline |

---

## 3. AOSP source — the implementation

| Path | What it gives you |
|---|---|
| **`external/selinux/libselinux/src/android/android_platform.c`** | **The single most important file for this chapter.** `seapp_context_lookup`, `seapp_context_cmp` (the specificity sort), `selinux_android_setcontext`, and the MCS arithmetic verified in [§3.7](../README.md#37-mcs-the-category-encoding-and-what-it-actually-enforces). |
| `external/selinux/libselinux/src/` | `getcon`, `setcon`, `security_compute_av`, `selinux_check_access` — the userspace API |
| `external/selinux/libsepol/` | policy manipulation; the basis of `sepolicy-analyze` |
| `external/selinux/secilc/` | the CIL compiler `init` runs on device when the precompiled hash does not match |
| `external/selinux/checkpolicy/` | the classic `.te` compiler |
| `system/core/init/selinux.cpp` | how `init` loads or compiles policy at boot, and the precompiled-hash comparison — [§4.2](../README.md#42-from-te-source-to-plat_sepolicycil-on-the-device) |
| `system/core/init/property_service.cpp` | where `property_service:set` is checked, and why property denials come wrapped in an `init` record |
| `frameworks/base/core/java/android/os/SELinux.java` | the entire `@hide` Java surface — six methods, no policy access |
| `frameworks/base/core/jni/android_os_SELinux.cpp` | its JNI implementation |
| `frameworks/base/services/core/java/com/android/server/pm/SELinuxMMAC.java` | parses `mac_permissions.xml`, assigns each package its `seinfo` at scan time — this is why `seinfo=platform` cannot be forged |
| `frameworks/native/cmds/servicemanager/Access.cpp` | where `service_manager:find` and `:add` are checked, and where the caller's context is obtained from the kernel rather than claimed |
| `frameworks/native/cmds/installd/` | `installd` — labels app data directories, passes descriptors to `dex2oat` |
| `bionic/libc/` | where the syscalls that get checked originate |

---

## 4. Kernel source

| Path | What it gives you |
|---|---|
| `security/selinux/hooks.c` | every LSM hook SELinux implements — the map from "operation" to "permission checked" |
| `security/selinux/avc.c` | the Access Vector Cache, and `avc_audit()` — **where the `avc: denied` text is actually formatted** |
| `security/selinux/ss/services.c` | `security_compute_av`, constraint evaluation, the security server |
| `security/selinux/selinuxfs.c` | `/sys/fs/selinux` — `enforce`, `policy`, `class/`, `avc/` |
| **`security/lsm_audit.c`** | `dump_common_audit_data` — the `switch` that decides which fields appear in a record. **Read this if you are writing a parser**: it is why `path=`, `name=`, `capability=` and "nothing at all" are all valid, depending on class. |
| `Documentation/admin-guide/LSM/SELinux.rst` | upstream kernel documentation |

---

## 5. Official Android documentation

| Page | What it covers | Note |
|---|---|---|
| `https://source.android.com/docs/security/features/selinux` | the overview and concept pages | the starting point |
| `https://source.android.com/docs/security/features/selinux/concepts` | types, domains, contexts, the model | short and accurate |
| `https://source.android.com/docs/security/features/selinux/implement` | build integration, Treble policy splitting | read before touching a build |
| `https://source.android.com/docs/security/features/selinux/device-policy` | the **vendor-facing** guide | worth reading *because* it is what OEM engineers read — it tells you what habits to expect in vendor policy |
| `https://source.android.com/docs/security/features/selinux/validate` | how Google expects vendors to test policy, including CTS requirements | the source of "permissive domains fail CTS" |
| `https://source.android.com/docs/security/features/selinux/customize` | adding domains and rules | |
| `https://source.android.com/docs/security/features/selinux/vendor-init` | why `vendor_init` is a separate domain | a good worked example of splitting a domain to tighten it |
| `https://source.android.com/docs/compatibility/cdd` §9.7 | the normative requirement that devices ship SELinux enforcing | cite this when a vendor argues about permissive |
| `https://source.android.com/docs/security/bulletin` | **Android Security Bulletins** | the authoritative source for CVE identifiers. Search by component, not by "SELinux". |

---

## 6. Tooling

| Tool | Where | What it does | Caveat |
|---|---|---|---|
| `sepolicy-analyze` | AOSP, `m sepolicy-analyze` | `permissive`, `dups`, `attribute`, `neverallow` against a binary policy | needs the binary policy |
| `sesearch` | `setools`, `https://github.com/SELinuxProject/setools` | search rules: `--allow`, `--neverallow`, `--dontaudit` | **`--dontaudit` is the one that answers "what is being silenced"** |
| `seinfo` | `setools` | enumerate types, attributes, classes, users | |
| `sediff` | `setools` | diff two binary policies | the right tool for [§8.6](../README.md#86-diffing-policies-between-builds) if you can get two binary policies |
| `audit2allow` | `policycoreutils` | denials to rules | **a suggestion engine, not an oracle.** Its own man page says so. Never paste its output. |
| `audit2why` | `policycoreutils` | denials to *reasons*, with the policy | **the tool worth having**: with `-p policy.bin` it distinguishes a missing `allow` from a constraint violation, which the audit record itself cannot express |
| `secilc` | AOSP `external/selinux/secilc` | compile CIL to binary policy | lets you build a binary policy from the device's own CIL without root |
| `checkpolicy` | AOSP | compile `.te` to binary | |
| `magiskpolicy` | Magisk | patch the **loaded** policy at runtime | the practical demonstration that `neverallow` is build-time only — [62 — Magisk](../../62-Magisk/README.md) |
| `restorecon` / `chcon` | on device, needs root | relabel files | `chcon` is for experiments; `restorecon` applies `file_contexts` and is what you actually want |

---

## 7. Books, papers and talks

| Source | What it is good for |
|---|---|
| **The SELinux Notebook**, Richard Haines | see §1. The single best free reference for the model. |
| **`SELinux by Example`**, Frank Mayer, Karl MacMillan, David Caplan | the standard book. Pre-Android, so all the examples are Red Hat, but the chapters on Type Enforcement, constraints and MLS are the model itself and transfer directly. |
| **Flask architecture papers** (Spencer, Smalley, Loscocco et al.) | the design rationale for separating policy from enforcement mechanism, which is what makes the AVC possible. Read once, for the *why*. |
| **NSA papers on Type Enforcement** | the original argument for labelling programs rather than users |
| **"SEAndroid" (USENIX Security)**, Smalley and Craig | the academic presentation of the Android port. The primary source on why MCS was chosen for app isolation rather than per-app types. |
| **Stephen Smalley's Linux Security Summit talks** | search "Android SELinux Smalley". The primary source on design decisions, including the zygote `dyntransition` approach. |
| **Project Zero's Android kernel posts** | the clearest public writing on defeating the MAC layer from the kernel side — which is the honest answer to "how is SELinux actually bypassed" |

> **On conference talks:** rather than cite URLs that rot, the search terms above are given deliberately. For SELinux *bypass* talks specifically, read them for the **technique class** rather than the specific bug — the bugs are long fixed and the classes are not.

---

## 8. On CVE identifiers — a deliberate omission

**This chapter cites no specific CVE numbers, and that is a decision rather than an oversight.**

SELinux-related Android vulnerabilities are essentially never filed against SELinux. They are filed against the *component* that was compromised, and SELinux appears only in the severity assessment — as the thing that did, or did not, contain the bug. Quoting an identifier and attributing it to SELinux would misrepresent the record.

The **classes** are stable and checkable, and are what you should look for:

| Class | Covered in |
|---|---|
| Over-permissive vendor domain (`dac_override`, `sys_admin`, `mlstrustedsubject`) | [§5.3](../README.md#53-vulnerability-class--an-over-permissive-vendor-domain) |
| Permissive domain on a production build | [§5.4](../README.md#54-vulnerability-class--a-permissive-domain-on-a-production-build) |
| Default-label over-grant (`default_android_service`, `default_prop`, `unlabeled`) | [§5.5](../README.md#55-vulnerability-class--the-default-label-trap-in-the-dangerous-direction) |
| Abstract socket reachable by any app | [§5.6](../README.md#56-vulnerability-class--an-abstract-socket-reachable-by-any-app) |
| Vendor `seapp_contexts` matching on `name=` alone | [§3.6](../README.md#36-seapp_contexts-where-the-domain-is-actually-decided) |
| Relying on SELinux for something it does not do | [§5.7](../README.md#57-vulnerability-class--relying-on-selinux-for-something-it-does-not-do) |
| Kernel defeat of the MAC layer | [§5.1](../README.md#51-how-attackers-abuse-selinux) |

When you need an identifier, go to the Android Security Bulletins, find the component, and read the assessment.

---

## 9. OWASP

| Source | Relevance |
|---|---|
| **MASVS** — `https://mas.owasp.org/MASVS/` | MASVS-STORAGE-1/2, MASVS-PLATFORM-1, MASVS-CODE-4, MASVS-CRYPTO-2 and MASVS-RESILIENCE-1 all rest on SELinux behaviour without naming it. Mapped in [§5.12](../README.md#512-owasp-masvs--mastg-mapping). |
| **MASTG** — `https://mas.owasp.org/MASTG/` | SELinux appears as an environmental precondition rather than as a test case. Worth knowing before you go looking for a test that does not exist. |

---

## 10. This chapter's own measured artefacts

Everything below was produced during the writing of this chapter. Where a file says "measured", it came off a physical arm64 device running Android 13 / API 33, stock `user` build, SELinux Enforcing, **not rooted**.

| File | What it is | How it was verified |
|---|---|---|
| [`../examples/avc-denials-measured.log`](../examples/avc-denials-measured.log) | a denial corpus with per-record provenance, including three denials whose exact causing command is recorded | captured with `adb logcat -d -b all`; the synthetic section is separately marked |
| [`../examples/seapp_contexts-measured.txt`](../examples/seapp_contexts-measured.txt) | the device's complete `plat_seapp_contexts` and `vendor_seapp_contexts`, annotated between the rules so the rules stay byte-identical | `adb shell cat`, verbatim |
| [`../examples/policy-rules-measured.cil`](../examples/policy-rules-measured.cil) | ~40 policy rules with commentary, covering the zygote transition, the MLS constraints, the code-execution permissions, `dex2oat`, `keystore2_key`, sockets and Binder | grepped out of the device's own 1,981,460-byte `plat_sepolicy.cil` |
| [`../examples/SelinuxProbe.java`](../examples/SelinuxProbe.java) | an in-app probe: context, decoded MCS checked against the arithmetic, global state, own labels, an access probe, and a live `file:execute_no_trans` test | **compiled clean** against `android.jar` from SDK 35 with `javac -source 8 -target 8` |
| [`../scripts/avc-decode.py`](../scripts/avc-decode.py) | decodes `avc` records into who/what/class/permission plus the candidate rule, in `.te` and CIL | **run against 5,993 real records** from the device, collapsing them to 33 distinct rules |
| [`../scripts/selinux-posture.sh`](../scripts/selinux-posture.sh) | device posture: enforcing state, policy files, running domains, permissive detection, denial summary, and one package's context and MCS arithmetic | **run end to end** against the device |
| [`../scripts/selinux-probe.js`](../scripts/selinux-probe.js) | Frida in-process probe, including an `execmem` test and refusal tracing with Java stack traces | syntax-verified; requires a rooted device to run, and the header says so |
| [`../cheatsheet.md`](../cheatsheet.md) | dense tables: context format, domains, classes, the `avc` field decoder, the command set, the finding-shaped greps | — |
| [`../mindmap.md`](../mindmap.md) | one large Mermaid mind map covering the whole chapter | — |
| [`../faq.md`](../faq.md) | 23 questions, including the "dumb" ones | — |
| [`../labs/`](../labs/) | five labs; the last is a CTF | — |

---

## 11. Related chapters

| Chapter | What it owns | What this chapter owns instead |
|---|---|---|
| [21 — App Sandbox](../../21-App-Sandbox/README.md) | the UID sandbox, DAC, seccomp-bpf, capability dropping, `isolatedProcess` from the sandbox side | **the MAC layer.** The two enforce independently and *both* must permit an operation. A DAC bug leaves MAC standing and vice versa; the same `EACCES` comes from either. |
| [06 — Android Architecture](../../06-Android-Architecture/README.md) | boot, the layered architecture, where the zygote comes from | how `init` loads policy during that boot, and how the zygote's children get their domains |
| [20 — Security Architecture](../../20-Security-Architecture/README.md) | Verified Boot, attestation, the adversary model | why the MAC layer's integrity *depends* on the verified boot chain — a modified boot image ships a modified policy |
| [24 — IPC](../../24-IPC/README.md) | the IPC surface: what channels exist, what travels over them, how they are attacked | whether MAC permits **reaching** the channel — decisive for abstract-namespace sockets, which have no filesystem permissions at all |
| [23 — Permissions](../../23-Permissions/README.md) | the runtime permission model, enforced in `system_server` in Java | the MAC gate *in front of* it: `service_manager:find` and `binder:call` must pass before any permission check runs |
| [25 — Binder](../../25-Binder/README.md) | Binder itself: the driver, transactions, parcels | the two-stage `service_manager:find` plus `binder:call` decision |
| [49 — KeyStore](../../49-KeyStore/README.md) | Keystore: key generation, attestation, hardware backing, KeyMint | the `keystore_key` and `keystore2_key` object classes, the namespace labels, and which domains hold `use_dev_id` and `gen_unique_id` |
| [40 — Obfuscation](../../40-Obfuscation/README.md) | packers, string encryption, dynamic code loading | the code-execution permissions — `execmem`, `execute`, `execute_no_trans`, `execmod` — and the honest causal story behind `InMemoryDexClassLoader` |
| [62 — Magisk](../../62-Magisk/README.md) | rooting, `magiskpolicy`, boot image patching | why a patched policy is bound by no `neverallow`, and why measurements on a rooted device may not transfer |
| [37 — Root Detection](../../37-RootDetection/README.md) | detection and evasion techniques | SELinux state and the process context as two of the signals apps read |
| [15 — Native Code](../../15-Native-Code/README.md) | ELF hardening, TEXTRELs, RELRO, PIE | what `file:execmod` is actually about, and why the NDK banned text relocations |
| [19 — Memory](../../19-Memory/README.md) | allocators, memory layout, ASLR | `process:execmem` as the MAC expression of W^X, and why apps are exempted |
| [11 — Android Runtime](../../11-Android-Runtime/README.md) | ART, the JIT, `dex2oat` from the runtime side | `dex2oat`'s domain as a trust property, and why the JIT needs `execmem` |
| [07 — AOSP](../../07-AOSP/README.md) | navigating the AOSP tree, `repo`, build targets | which files in that tree hold the policy, and how they compile to `plat_sepolicy.cil` |
| [02 — Linux Basics](../../02-Linux-Basics/README.md) | Unix permissions, processes, syscalls, `/proc` | the LSM layer that sits on top of all of it |
| [09 — Android App Internals](../../09-Android-App-Internals/README.md) | app process lifecycle, `packages.list`, UIDs | decoding the MCS categories those UIDs produce |
