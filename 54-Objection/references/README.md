# 54 — Objection references

Annotated. Every link says what it is *for*, and where it stops.

---

## The tool itself

| Link | What it gives you | Where it stops |
|---|---|---|
| [sensepost/objection](https://github.com/sensepost/objection) | The tool. Issues and releases are the fastest way to learn whether a behaviour you are seeing is a known bug | The README documents the command *surface*, not what each canned script hooks |
| [The agent source](https://github.com/sensepost/objection/tree/master/agents/frida) | **The most important link on this page.** The TypeScript that compiles to the `agent.js` on your disk | It is `master`. Your installed version is probably older — read yours |
| [`agents/frida/src/android/root.ts`](https://github.com/sensepost/objection/blob/master/agents/frida/src/android/root.ts) | The three hooks and the thirteen hard-coded paths behind `android root disable`. Everything in chapter §3.5 came from here | Java layer only, by construction |
| [`agents/frida/src/android/pinning.ts`](https://github.com/sensepost/objection/blob/master/agents/frida/src/android/pinning.ts) | The seven pinning hooks behind `android sslpinning disable`, with the authors' own comments citing the research each one came from | No native, no WebView, no `network_security_config` |
| [The wiki](https://github.com/sensepost/objection/wiki) | Installation, the `patchapk` / gadget workflow, plugin authoring | Thin on failure diagnosis, which is most of what you need |
| [Updating](https://github.com/sensepost/objection/wiki/Updating) | The page the start-up banner points at | Says nothing about keeping frida and frida-server in step, which is the actual risk |

> **Your own installed copy is the authority.**
> `python -c "import objection, os; print(os.path.dirname(objection.__file__))"`
> Then [`../scripts/split-agent.py`](../scripts/split-agent.py). Anything on this page — including
> this chapter — is a claim about *a* version. Your `agent.js` is a fact about *yours*.

---

## Frida — the runtime underneath

| Link | What it gives you | Where it stops |
|---|---|---|
| [frida.re/docs](https://frida.re/docs/home/) | The JavaScript API every Objection command ultimately calls | Assumes you are writing the agent, which is the thing Objection is hiding |
| [frida.re/docs/gadget](https://frida.re/docs/gadget/) | The gadget config-file format `objection patchapk` writes for you | Does not cover apktool's failure modes, which is where `patchapk` actually breaks |
| [frida-java-bridge](https://github.com/frida/frida-java-bridge) | How `Java.use`, `.overload()` and `.implementation` reach an `ArtMethod`. Read this when a hook installs and does not fire | Fast-moving; behaviour differs across Frida majors |
| [Frida releases](https://github.com/frida/frida/releases) | Where `frida-server` and `frida-gadget` binaries come from | **Match the version to your host `frida --version` exactly.** Nothing on the page warns you |

---

## AOSP — what the hooks actually sit on

File paths, not line numbers: the files are stable, the line numbers are not.

| Path | Why it matters here |
|---|---|
| `libcore/ojluni/src/main/java/java/io/File.java` | `exists()` — hook 3 of `root disable`. Delegates to `UnixFileSystem` → JNI → `stat64`, which is why a native check bypasses it entirely |
| `libcore/ojluni/src/main/java/java/lang/Runtime.java` | The `exec` overload chain. `exec(String)` → `exec(String[],…)` → `ProcessBuilder.start()`. Objection hooks only the top |
| `libcore/ojluni/src/main/java/java/lang/String.java` | `contains()` — hook 1. A core-library method ART may intrinsify, which is why the hook can install and never fire |
| `external/conscrypt/` | `TrustManagerImpl.verifyChain` and `checkTrustedRecursive` — hooks 5 and 6, the two that install on every app |
| `libcore/ojluni/src/main/java/javax/net/ssl/SSLContext.java` | `init()` — hook 1 of the pinning set |

---

## OWASP

| Link | Use |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | The controls Objection helps you evaluate. **MASVS-RESILIENCE is the one most often mis-reported from tool output** — the control is about raising cost, not about being uninstrumentable |
| [MASTG](https://mas.owasp.org/MASTG/) | Test procedures, several of which name Objection directly |

---

## The research behind the canned pinning hooks

Objection's own source comments cite these. They are the archaeology of *why* each hook exists,
and they explain why a canned bypass ages: every entry was added because an earlier one stopped
working.

| Source | What it produced |
|---|---|
| NCC Group, "Bypassing Android's Network Security Configuration" (2017) | The `TrustManagerImpl.verifyChain` hook |
| SensePost, "Tip-toeing past Android 7's Network Security Configuration" (2018) | The follow-up the agent links from the same function |
| Mediaservice.net, "Universal Android SSL Pinning Bypass 2" (2018) | The `checkTrustedRecursive` hook |
| [oleavr's registerClass gist](https://gist.github.com/oleavr/3ca67a173ff7d207c6b8c3b0ca65a9d8) | The empty-`TrustManager` pattern behind hook 1 |

---

## This chapter's own artefacts

| File | What it is for |
|---|---|
| [`../scripts/objection-doctor.py`](../scripts/objection-doctor.py) | Reports and adjudicates the objection / frida / frida-server triple plus the device ABI. Run it **before** a session, not after it fails |
| [`../scripts/split-agent.py`](../scripts/split-agent.py) | Splits `agent.js` into its 125 modules and recovers their source paths. The tool behind every claim in §3.5 and §3.6 |
| [`../scripts/root-disable-equivalent.js`](../scripts/root-disable-equivalent.js) | The same three hooks `android root disable` installs, plus the reporting it lacks. The chapter's thesis as runnable code |
| [`../examples/target-app/`](../examples/target-app/) | Five root checks, three inside Objection's envelope and two outside it. The measuring instrument |
| [`../examples/build.sh`](../examples/build.sh) | Builds and installs the target with `aapt2` → `javac` → `d8` → `zipalign` → `apksigner`. No Gradle, no network, out of tree |
| [`../examples/01-annotated-session.md`](../examples/01-annotated-session.md) | A full session, annotated line by line |
| [`../examples/02-when-objection-fails.md`](../examples/02-when-objection-fails.md) | One task, both tools, and the scoreboard |

---

## Environment this chapter was measured on

Recorded because every version-gated claim above depends on it, and because the devices
attached to this host were **swapped without warning** during the writing.

| | |
|---|---|
| objection | 1.11.0 (1.12.5 available; the banner says so on every run) |
| frida (host Python package) | 16.1.6 |
| frida-tools | 12.3.0 |
| frida-server | 16.1.6 — exact match |
| Python | 3.13.3, Windows host |
| Primary device | Redmi **`M2101K6P`** (`sweetin`), MIUI 12.5, **Android 11 / API 30**, arm64-v8a, Magisk-rooted, SELinux Enforcing |
| Secondary device | **`i9000S`**, Android 13 / API 33, **not rooted, no frida-server** — used only for the "jailed Android" failure in §7.1 |
| Target application | `com.pentest.ch54.target`, built by `examples/build.sh`, installed via `su -c 'pm install'` after `INSTALL_FAILED_USER_RESTRICTED` |

**Not measured, and labelled as such in the chapter:** `objection patchapk`; the interactive
REPL (sessions ran through API mode — same agent, same RPC exports); the frida 17.x rows of the
compatibility table; and every destructive command. See chapter §7.6 for the complete list.

---

## Related chapters

| Chapter | Why you go there from here |
|---|---|
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | The method Objection serves. It sits at Stage 3, Instrument, and nowhere else |
| [53-Frida](../../53-Frida/README.md) | The runtime this wraps. Every Objection failure is ultimately diagnosed here |
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | Owns pinning, its layers, and the severity framing for a bypass |
| [37-RootDetection](../../37-RootDetection/README.md) | Owns root detection and the taxonomy the three hooks map onto |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | The general bypass method when the canned envelope is not enough |
| [20-Security-Architecture](../../20-Security-Architecture/README.md) | Where "save time, never understand" is written down |
| [56-JADX](../../56-JADX/README.md) | The static counterpart; Objection's enumerator is its runtime cross-check |
| [42-R8](../../42-R8/README.md) | Why Objection's enumeration survives obfuscation |
| [43-WebView](../../43-WebView/README.md) | Where the pinning command is inert |
| [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) | Declarative pinning, which Objection does not touch |
| [49-KeyStore](../../49-KeyStore/README.md) | What the keystore commands mean, and why an alias is not key material |
| [33-Storage](../../33-Storage/README.md) | Why `sqlite connect` is the wrong tool for a storage assessment |
| [38-TamperDetection](../../38-TamperDetection/README.md) | What `patchapk`'s changed signature sets off |
| [57-Ghidra](../../57-Ghidra/README.md) | Where `memory dump` output goes next |
| [60-ADB](../../60-ADB/README.md) | Getting to the device in the first place |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The command inventory Objection wraps |

55-MobSF drives Frida for its own dynamic analysis and reaches many of the same conclusions
through a web interface rather than a REPL. It is named here as a topic because its chapter is
being written separately.
