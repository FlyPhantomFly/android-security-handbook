# Chapter 31 examples — the vulnerability tag table

`victim-app/` is deliberately vulnerable and `attacker-app/` exists to attack it. Install them on a
device you own and uninstall them when you are done — see [SECURITY.md](../../SECURITY.md) for the
handling rules:

```bash
cd examples && ./build.sh --install
# ... labs ...
cd examples && ./build.sh --uninstall
```

`attacker-app/` requests **zero permissions** and hard-codes `com.pentest.ch31.victim` as its only
target. It cannot be pointed at anything else without editing and rebuilding it, which is deliberate.

---

## The tags

Every vulnerability in this chapter has a `[Vn]` tag and every fix an `[Hn]` tag, and both appear in
the README, in the labs, and as the first comment block of the file itself. This is the convention
[43-WebView](../../43-WebView/README.md) established, and it exists so that "the vulnerable one" and
"the fixed one" are never ambiguous in a lab step.

| Tag | File | What it is | README |
|---|---|---|---|
| **[V1]** | [victim-app/SettingsActivity.java](victim-app/SettingsActivity.java) | `PreferenceActivity` whose `isValidFragment` returns `true`. The classic. | §5.2, §9.2 |
| **[H1]** | [victim-app/SettingsHardenedActivity.java](victim-app/SettingsHardenedActivity.java) | The same class with an exact-name allowlist. Refuses — and crashes the host, which is the point. | §5.2, §5.4, §9.2 |
| **[V2]** | [victim-app/FragmentHostActivity.java](victim-app/FragmentHostActivity.java) | A hand-written reflective host with no `PreferenceActivity` anywhere. Reachable by an extra **and** by a deep link. Two loader modes, for §4.5's ordering measurement. | §5.2, §9.1, §9.3 |
| **[H2]** | [victim-app/FragmentHostHardened.java](victim-app/FragmentHostHardened.java) | A closed key-to-factory map. No reflection left to abuse. | §5.2, §9.1 |
| **[V3]** | [victim-app/LegacySettingsActivity.java](victim-app/LegacySettingsActivity.java) | A `PreferenceActivity` subclass with **no** `isValidFragment` override. Behaviour depends entirely on `targetSdkVersion`; build it both ways. | §3.9 |
| **[H3]** | [04-hardening-a-settings-screen.kt](04-hardening-a-settings-screen.kt) | The migration a real app performs: off `PreferenceActivity`, closed route enum, destination-side session check. | §9.4 |
| **[H4]** | [05-enterprise-fragment-router.kt](05-enterprise-fragment-router.kt) | A sealed route table with per-route `allowExternal` and `requiresSession`, and observable refusals. | §9.5 |

## Supporting files

| File | Role |
|---|---|
| [victim-app/AndroidManifest.xml](victim-app/AndroidManifest.xml) | Six Activities, five exported, one not. The one that is not exported is the intended route. |
| [victim-app/Vault.java](victim-app/Vault.java) | The "secret" in the app's private files. The sandbox protects it perfectly; every attack here makes the victim read it. |
| [victim-app/AdminFragment.java](victim-app/AdminFragment.java) | **The prize.** Checks nothing, because Fragments normally do not have to. |
| [victim-app/PublicFragment.java](victim-app/PublicFragment.java) | **The control.** If you can load this one but not `AdminFragment`, the gate works. |
| [victim-app/VaultFragment.java](victim-app/VaultFragment.java) | **Stage two of the CTF.** A `DialogFragment` that **no code path in the app constructs**, which reads `getArguments()` and makes a decision from what it finds. |
| [victim-app/NotAFragment.java](victim-app/NotAFragment.java) | Not a Fragment. Logs from its static initialiser and its constructor, so you can see which of them ran. |
| [victim-app/LoginActivity.java](victim-app/LoginActivity.java) | The intended route: not exported, real PIN check, and completely irrelevant to the attack. |
| [victim-app/MainActivity.java](victim-app/MainActivity.java) | Launcher. Seeds the vault. Holds nothing. |
| [attacker-app/InjectActivity.java](attacker-app/InjectActivity.java) | Ten named attacks, driven by `--es attack <name>`. |
| [build.sh](build.sh) | No-Gradle build. `TARGET_SDK=17 MIN_SDK=14 ./build.sh` builds the legacy arm of §3.9's experiment. |

## The attacks

```bash
# host -- the SHELL starts the ATTACKER; the ATTACKER makes the call that matters.
# -S forces a stop first: `am start` compares Intents with filterEquals(), which
# ignores extras, so without it your second run is delivered to the first one.
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack <name>
adb logcat -s CH31 CH31ATK
```

| `<name>` | What it does | Expected |
|---|---|---|
| `probe` | Lists the victim's Activities as an ordinary app sees them | 5 exported, 1 internal |
| `control` | Loads `PublicFragment` through `[V2]` | `PUBLIC-FRAGMENT-REACHED` |
| `pref-inject` | `[V1]` with `:android:show_fragment` | `ADMIN-FRAGMENT-REACHED` + the secret |
| `pref-hardened` | The same Intent at `[H1]` | `IllegalArgumentException`, host crashes |
| `pref-legacy` | The same Intent at `[V3]` | `RuntimeException` at `targetSdk` 35; injection at `targetSdk` 17 |
| `host-inject` | `[V2]` with a class name in an extra | `ADMIN-FRAGMENT-REACHED` |
| `host-hardened` | `[H2]` with a class name as the key | `refused screen=...` |
| `host-deeplink` | `[V2]` through `ch31victim://screen/open?f=...` | `ADMIN-FRAGMENT-REACHED` |
| `args` | `[V1]` plus an attacker-built arguments `Bundle` | `ADMIN-FRAGMENT-ARGS keys=[accountId, note, skipAuth]` |
| `type-platform` | `[V2]` pointed at `NotAFragment`, platform loader | refused; **no** `NOTAFRAGMENT` lines |
| `type-erasure` | The same, AndroidX ordering | `NOTAFRAGMENT-CLINIT`, `NOTAFRAGMENT-CTOR`, then `ClassCastException` |
| `ctf` | Injects `VaultFragment` with an unlock value **you** supply: add `--es unlock <value>` | `VAULT-FRAGMENT-UNLOCKED` with flag 2, or `accepted=false` |

## Building

No Gradle, no Android Studio, no network. `build.sh` uses `aapt2 link` → `javac --release 8` → `d8` →
`zipalign` → `apksigner`, out of tree, so no `.apk`, `.dex` or `.class` ever lands in this
repository.

```bash
# host
ANDROID_HOME=/path/to/sdk ./build.sh --install
OUTDIR=/tmp/ch31 ./build.sh --install          # choose where artefacts go
TARGET_SDK=17 MIN_SDK=14 ./build.sh            # the legacy arm of the section 3.9 experiment
./build.sh --uninstall
```

Two build notes that cost time elsewhere in this repository and are handled here: on Git Bash the SDK
tools are native Windows binaries and need `cygpath -w` on every path, and **XML comments must not
contain a double hyphen** or `aapt2` rejects the file.

## What was actually run

Everything above was built and executed on **2026-08-16** against the AVD
`sdk_gphone16k_x86_64` (Android 15 / API 35, x86_64, `userdebug`, rooted with Magisk 30.7), with
build-tools 35.0.1, `android-35`'s `android.jar` and JDK 24.0.2. Victim uid 10219/10223 across
reinstalls, attacker uid 10220. The measured output of every attack is quoted in README §3, §4, §5
and §7, and §7.7 lists what was **not** measured.
