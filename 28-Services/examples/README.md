# 28 — Services — Examples

Every file here was compiled. The two that were also **installed and run on a
physical device** are marked; the rest are annotated source that a reader can
drop into a project.

**Device for every measurement in this directory:** Redmi `M2101K6P` (`sweetin`),
MIUI 12.5, **Android 11 / API 30**, arm64, kernel 4.14.180.

---

## The files

| File | What it is | Run on device? |
|---|---|---|
| [`IVaultService.aidl`](IVaultService.aidl) | The AIDL interface behind the vulnerable/fixed pair. Three methods, three transaction codes | **yes** |
| [`VaultService-vulnerable.java`](VaultService-vulnerable.java) | Exported AIDL service with four annotated defects, including a caller check in `onBind` that is measurably inert | **yes** |
| [`VaultService-fixed.java`](VaultService-fixed.java) | The same interface, correct. Each fix annotated against a README section | compiles |
| [`MessengerCommandService.java`](MessengerCommandService.java) | The second pair: a `Messenger` command dispatcher, the attacker that beats a naive fix by supplying `msg.replyTo`, and the version that survives it | compiles |
| [`attacker-app/ProbeActivity.java`](attacker-app/ProbeActivity.java) | The whole attacker. Binds, reads the descriptor, probes codes, writes the correct interface token and calls | **yes** |
| [`attacker-app/AndroidManifest.xml`](attacker-app/AndroidManifest.xml) | Four lines. The `QUERY_ALL_PACKAGES` one is load-bearing and the comment says why | **yes** |
| [`attacker-app/build.sh`](attacker-app/build.sh) | Gradle-free build: `javac` → `d8` → `aapt2` → zip → `apksigner`. Handles the flat repo layout and the project layout | **yes** |
| [`measured-bind-probe.txt`](measured-bind-probe.txt) | Verbatim attacker output against four targets, plus the package-visibility controlled experiment. Assessed third-party package names are [pseudonymised](../../72-RealWorldFindings/references/README.md); every measurement is real | — |
| [`measured-frida-trace.txt`](measured-frida-trace.txt) | Verbatim `trace-service-lifecycle.js` output, with the `onBind` / `execTransact` uid pair that is the chapter's thesis | — |
| [`measured-service-recon.txt`](measured-service-recon.txt) | `service-recon.py` across the whole device: 839 services, 325 open, and the 16 that are guarded by a permission that does not guard | — |

---

## Repo layout versus project layout

The repository stores these **flat**. An Android project would store them in a
package-shaped tree. The mapping:

| Repo path | Android project path |
|---|---|
| `examples/IVaultService.aidl` | `src/main/aidl/com/example/notesvault/IVaultService.aidl` |
| `examples/VaultService-vulnerable.java` | `src/main/java/com/example/notesvault/VaultService.java` |
| `examples/VaultService-fixed.java` | `src/main/java/com/example/notesvault/VaultService.java` (the other build) |
| `examples/MessengerCommandService.java` | three files under `src/main/java/com/example/cmd/` |
| `examples/attacker-app/ProbeActivity.java` | `src/main/java/com/pentest/ch28probe/ProbeActivity.java` |

Each file's header comment repeats its own project path on the first line, which
is why a path checker may report a file that does not exist on disk. That is a
false positive, not a missing file: the comment gives the path the file would
occupy *inside an Android project*, while this repository stores its examples
flat. The flat files are the ones to read — they are annotated far beyond what a
project copy would be.

`build.sh` handles both layouts. If `ProbeActivity.java` sits next to it, it
stages a package-shaped tree under `out/src` first, because `javac` requires the
directory layout to match the `package` declaration.

---

## Building

```bash
# host, from examples/attacker-app/
sh build.sh                 # -> out/probe.apk
sh build.sh install         # + adb install
sh build.sh install root    # + install via su, for devices that refuse adb install
```

Nothing is committed from `out/`. **Never commit an APK, a DEX, a JAR or a
keystore** — the repository's verification script treats every one of those as a
build artefact and fails the chapter.

### Three build failures that cost real time here

| Symptom | Cause | Fix |
|---|---|---|
| `d8`: `NullPointerException: Cannot invoke "String.length()" because "<parameter1>" is null` | build-tools **34.0.0**'s `d8` on an anonymous inner class in a class file from JDK 24 with `-source 8 -target 8` | Use build-tools **35.0.1** or newer. The identical input compiled cleanly |
| `aidl`: `directory src/ is not found in any of the import paths: - src\` | The Windows `aidl.exe` rejects forward-slash paths | Pass backslashes: `aidl.exe --lang=java "-Isrc\" -ogen "src\com\example\notesvault\IVaultService.aidl"` |
| `aapt2 link`: `AndroidManifest.xml:10: error: not well-formed (invalid token)` | A **double hyphen inside an XML comment**, which is illegal XML. `aapt2` does not say so | Remove it. This bit the attacker manifest, whose comments are now written to avoid the sequence |

### Installing on a device that refuses `adb install`

```text
adb: failed to install probe.apk:
     Failure [INSTALL_FAILED_USER_RESTRICTED: Install canceled by user]
```

A MIUI restriction, not an Android behaviour and not a defect in the APK. Two
things were established rather than assumed:

- It gates **new packages only**. Installing an *update* over an already-present
  package succeeded.
- `adb shell "su -c 'pm install -r -t /data/local/tmp/probe.apk'"` succeeds on a
  rooted device, which is how every measurement here was obtained. Note the
  **outer** quotes: without them only `pm` reaches `su -c`.

**Root was used only to install.** Both test apps then ran as ordinary
unprivileged apps at uid 10310 and uid 10313, with no root, no ADB in the attack
path, and no permissions beyond `QUERY_ALL_PACKAGES`. That distinction matters
when quoting these results.

---

## The one result to take away

From `measured-bind-probe.txt`, two lines from opposite sides of a UID boundary,
one millisecond apart, on the same connection:

```text
CH28VAULT: onBind ... callingUid=10310        <- the service's OWN uid
CH28VAULT: getAuthToken() called by uid=10313 <- the real attacker
```

The service's `onBind` check compared 10310 with 10310 and passed. Its AIDL
method had no check at all and handed over the session token. Everything else in
this directory exists to make that pair of lines reproducible.

---

## Related

- [`../scripts/service-recon.py`](../scripts/service-recon.py) — find the targets
- [`../scripts/trace-service-lifecycle.js`](../scripts/trace-service-lifecycle.js) — watch both sides
- [`../labs/lab-02-bind-from-an-unprivileged-app.md`](../labs/lab-02-bind-from-an-unprivileged-app.md) — the guided version of the run above
- [`../README.md`](../README.md) §5.2 — the attack, written out
