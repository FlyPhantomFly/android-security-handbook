# 31 — Fragments: cheat sheet

Dense reference. No prose. Everything marked **[m]** was measured on
`sdk_gphone16k_x86_64` (Android 15 / API 35) on 2026-08-16; see
[README §7.7](README.md) for what was not.

---

## The one-line facts

| | |
|---|---|
| A Fragment is | a portion of a screen with its own lifecycle |
| A Fragment is **not** | a component: no manifest entry, no `exported`, no permission, no `ActivityRecord`, no task |
| Access check on Fragment creation | **none** — there is nothing to check |
| Vulnerability condition | somebody outside the app chooses **which** Fragment is created |
| Platform extra | `:android:show_fragment` |
| Args extra | `:android:show_fragment_args` |
| The gate | `PreferenceActivity.isValidFragment(String)` |
| Gate default `targetSdk < 19` | `return true` **[m]** |
| Gate default `targetSdk >= 19` | `throw RuntimeException` **[m]** |
| Install floor, API 35 | `targetSdk` **24** **[m]** |
| Install floor, API 34 | `targetSdk` 23 |
| Refusal from a correct gate | `IllegalArgumentException` → **host crashes** **[m]** |

---

## The reflective path, API 35 **[m]**

```
PreferenceActivity.onCreate
  getIntent().getStringExtra(":android:show_fragment")        -> name
  getIntent().getBundleExtra(":android:show_fragment_args")   -> args
  if (name != null) switchToHeader(name, args)
    switchToHeaderInner(name, args)
      isValidFragment(name)                    <-- THE ONLY GATE
      Fragment.instantiate(this, name, args)
      getFragmentManager().beginTransaction()
          .replace(0x01020458, fragment)
          .commitAllowingStateLoss()
```

## `isValidFragment`, API 35, exact **[m]**

```
0004: iget v0, v0, ApplicationInfo.targetSdkVersion:I
0006: const/16 v1, #int 19
0008: if-ge v0, v1, 000c
000a: const/4 v0, #int 1
000b: return v0                      <-- targetSdk < 19
000c: new-instance v0, RuntimeException
003c: throw v0                       <-- targetSdk >= 19
```

## The three gate states

| State | Condition | Result | Reachable on API 35? |
|---|---|---|---|
| A | no override, `targetSdk < 19` | any Fragment loads | only via `pm install --bypass-low-target-sdk-block` (shell) **[m]** |
| B | no override, `targetSdk >= 19` | host crashes | **yes** **[m]** |
| C | override present | whatever it says | **yes** — where every real app lives |

---

## Loader constraints (both libraries)

1. app's `ClassLoader` can load it
2. assignable to `Fragment`
3. **public, no-argument constructor**

No package check. No signature check. No allowlist.

## Type-check ordering **[m]**

| Loader | Order | Consequence |
|---|---|---|
| `android.app.Fragment.instantiate` | `isAssignableFrom` @0x19 → `newInstance` @0x52 | non-Fragment refused, **constructor does not run** |
| `androidx...FragmentFactory.instantiate` | `newInstance` @18 → `checkcast` @21 | **constructor and `<clinit>` run first**, then raw `ClassCastException` |
| `loadFragmentClass` | **no `checkcast` at all** | generic cast erased; its `catch (ClassCastException)` is dead code |

---

## Lifecycle: Fragment vs Activity

| | Activity | Fragment |
|---|---|---|
| Callbacks | `onCreate` `onStart` `onResume` `onPause` `onStop` `onDestroy` | `onAttach` `onCreate` `onCreateView` `onViewCreated` `onStart` `onResume` `onPause` `onStop` `onDestroyView` `onDestroy` `onDetach` |
| Destroyed by the system alone | yes | **no** — only by its `FragmentManager` |
| Second attacker Intent | `onNewIntent` (beware stale `getIntent()`) | **none** |
| Outlives its own view | no | **yes** (back stack → `onDestroyView`, object lives) |
| Caller identity available | partial (`getCallingActivity()` if started for result) | **never** |
| Owner chapter | [30](../30-Activities/README.md) | this one |

## Back stacks

| | Task back stack | Fragment back stack |
|---|---|---|
| Owner | `system_server` | app process, per `FragmentManager` |
| Holds | `ActivityRecord`s | **transactions**, not Fragments |
| Survives process death | yes (Recents) | only via saved state |
| In `dumpsys activity activities` | yes | **no** (use `dumpsys activity <pkg>`) |

---

## Grep / find

```bash
# Smali anchors that SURVIVE R8 (framework names cannot be renamed)
grep -rl "Landroid/preference/PreferenceActivity;" out/
grep -rn "\.method.*isValidFragment"               out/
grep -rn "Landroid/app/Fragment;->instantiate"     out/
grep -rn ':android:show_fragment'                  out/

# the vulnerable gate, in bytes
#   12 11   const/4 v1, #int 1
#   0f 01   return v1

# structural scan (per-method source+sink co-occurrence)
python3 -B scripts/fragment-injection-scan.py app.apk --verbose
python3 -B scripts/fragment-injection-scan.py corpus/ --recursive --quiet
```

R8 renames `androidx...FragmentFactory` and `instantiate`. The AndroidX path is **not findable by
name** in a minified app.

---

## Device commands

```bash
# who am I on
adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk

# is the screen locked (app-originated starts can be silently refused)
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"

# live fragment state -- the finding
adb shell "dumpsys activity <pkg>" | grep -A8 "Active Fragments"
adb shell "dumpsys activity top"   | sed -n '/Added Fragments/,/^$/p'

# what absorbed my am start
adb shell "dumpsys window" | grep mCurrentFocus

# platform questions about THIS build
./scripts/preference-gate-probe.sh

# read the gate out of the device
adb pull /system/framework/framework.jar
python3 -B -c "import zipfile;z=zipfile.ZipFile('framework.jar');[open(n,'wb').write(z.read(n)) for n in z.namelist() if n.endswith('.dex')]"
dexdump -d classes3.dex | grep -A35 "name          : 'isValidFragment'"
```

## Driving the labs

```bash
cd examples && ./build.sh --install
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack <name>
adb logcat -s CH31 CH31ATK
cd examples && ./build.sh --uninstall
```

`-S` is mandatory: `am start` compares Intents with `filterEquals()`, **which ignores extras**, so
without it the second run is delivered to the first instance. **[m]**

| attack | expect |
|---|---|
| `probe` | 5 exported, 1 internal |
| `control` | `PUBLIC-FRAGMENT-REACHED` |
| `pref-inject` | `ADMIN-FRAGMENT-REACHED` + secret |
| `pref-hardened` | `IllegalArgumentException`, host crashes |
| `pref-legacy` | `RuntimeException` @ tsdk 35; injection @ tsdk 17 |
| `host-inject` | `ADMIN-FRAGMENT-REACHED` |
| `host-hardened` | `refused screen=...` |
| `host-deeplink` | `ADMIN-FRAGMENT-REACHED`, no attacker install needed |
| `args` | `ADMIN-FRAGMENT-ARGS keys=[accountId, note, skipAuth]` |
| `type-platform` | refused, **no** `NOTAFRAGMENT` lines |
| `type-erasure` | `NOTAFRAGMENT-CLINIT`, `NOTAFRAGMENT-CTOR`, then CCE |
| `ctf --es unlock <v>` | `VAULT-FRAGMENT-UNLOCKED` or `accepted=false` |

---

## Frida (`scripts/fragment-trace.js` — reviewed, **unrun**; see README §7.4)

```javascript
Java.use('android.preference.PreferenceActivity').isValidFragment.implementation = function (n) {
    var r; try { r = this.isValidFragment(n); }
    catch (e) { console.log('THREW for ' + n); throw e; }      // base impl throws at tsdk >= 19
    console.log(n + ' -> ' + r); return r;
};
Java.use('android.app.Fragment').instantiate
    .overload('android.content.Context','java.lang.String','android.os.Bundle')
    .implementation = function (c, n, a) { console.log('instantiate ' + n); return this.instantiate(c,n,a); };
```

Hook the **base** class, not the app's subclass — it catches subclasses you have not found.

---

## Allowlists that do NOT work

| Form | Admits |
|---|---|
| `startsWith("com.app.")` | every Fragment in the app — where the interesting ones are |
| `endsWith("SettingsFragment")` | `AdminSettingsFragment`, `DebugSettingsFragment`, library classes |
| `instanceof` after `instantiate` | too late — the constructor already ran |
| denylist (`!contains("Admin")`) | anything renamed, anything new, `...AdminPanelFragment$Inner` |

**Working form:** a lookup of the input in a set the attacker cannot extend. **Better form:** accept a
key, not a type name.

## Fixes, ranked

| | Reflection left | Fails open | R8 can prove reachability | Refusal |
|---|---|---|---|---|
| exact-name allowlist | yes | if edited wrong | no | **crash** |
| closed key map | **no** | no | yes | `finish()` |
| destination session check | n/a | no | n/a | remove + finish |

---

## Severity

| Scenario | Rating |
|---|---|
| Exported host + reachable sensitive Fragment | **High** |
| Same, reachable from a browsable deep link | **High** — no install precondition at all |
| Injection + attacker-controlled args driving an auth flag | **High** |
| Prefix/suffix allowlist | Medium–High (enumerate the reachable set) |
| No override, `targetSdk >= 19`, exported | Low–Medium (crash on demand) |
| Reflective loader behind `exported="false"` | **Informational** |
| Exported host, all reachable Fragments harmless | Low |

**Caps:** the attacker gets **display**, not exfiltration; only public no-arg-constructor Fragments
are reachable; server-side checks and user-auth-bound keys still hold.
**Raises:** browsable deep link; attacker-controlled arguments.

---

## Corpus sweep, 241 APKs on a stock Android 15 image **[m]**

```
tier 1 (input -> loader, one method)   1   (this chapter's own victim app)
tier 2 (PreferenceActivity gate)       6
tier 3 (structural only)              38   NOT findings
no signal                            196
classes*.dex 254 = 234 STORED + 20 DEFLATED
```

| `isValidFragment` shape | count | exported | verdict |
|---|---:|---:|---|
| real comparison | 32 | n/a | 32/32 correct, all one settings app |
| no override | 11 | **5** | crash primitive |
| `return true` | 5 | **0** | shape alive, **not reachable** |
| **total** | **48** | | arithmetic closes |

---

## MASVS

| ID | Why |
|---|---|
| MASVS-PLATFORM-1 | exported Activity with an unbounded type-name parameter |
| MASVS-PLATFORM-3 | `DialogFragment` phishing, `FLAG_SECURE`, Recents |
| MASVS-AUTH-1 | injection as authentication bypass |
| MASVS-CODE-4 | the arguments `Bundle` |

## Traps

| Trap | Symptom | Fix |
|---|---|---|
| `filterEquals` ignores extras | 2nd `am start` prints nothing | `am start -S` |
| Permission review dialog | `am start` "succeeds", nothing happens | `dumpsys window \| grep mCurrentFocus` |
| Keyguard | app-originated starts silently refused | `dumpsys trust` |
| `adb shell` is not an app | you proved the shell can do it | use a probe app |
| `adb shell su -c '…'` | only the first word runs | `adb shell "su -c 'cmd'"`, or `su 0 cmd` on the AVD | <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- trap table: the first cell IS the wrong form, the third is the fix -->
| `jadx 1.5.3` on a bare `classes.dex` | no output, exit 0 | `baksmali` from apktool's jar |
| `Bundle.keySet()` logged directly | `MapCollections$KeySet@1325cbe1` | `new ArrayList<>(b.keySet())` |
| `base.apk` only | zero findings in a split app | pull every `pm path` entry |
