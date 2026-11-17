# 31 — Fragments: FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct; the README
sections named have the long version.

---

### 1. What is a Fragment, in one sentence, without jargon?

A piece of a screen that behaves like a screen: it has its own setup and teardown, its own state, and
it can be swapped in and out of a real screen without the app restarting anything.

---

### 2. Why not just use more Activities?

Because an Activity is a heavy, system-owned thing. Starting one is IPC through `system_server`
([30 §2.2](../30-Activities/README.md)), it gets a place in a task, and it cannot share the screen
with another Activity. If you want a list on the left and a detail pane on the right, you cannot do
it with two Activities. Fragments were invented for exactly that, on tablets, in 2011.

---

### 3. Is a Fragment a "component" like an Activity or a Service?

**No, and this is the single most important thing in the chapter.** The four Android components are
Activity, Service, BroadcastReceiver and ContentProvider. They are declared in the manifest, they can
be `exported`, they can require a permission, and `system_server` tracks them.

A Fragment is none of that. It is an ordinary Java object. There is no `<fragment>` element, no
`android:exported`, and nothing in `system_server` knows it exists.

---

### 4. So if a Fragment can't be exported, how can it be attacked?

It cannot be attacked. It can be **chosen**.

The attack is on the *Activity* that hosts it. If that Activity is exported and it decides which
Fragment to show based on a string that came from outside the app, then an attacker who can send that
string chooses the screen. The Fragment is the payload, not the vulnerability. [README §5.2](README.md).

---

### 5. What is `:android:show_fragment` and why does it have colons in it?

It is an Intent extra key that `android.preference.PreferenceActivity` reads. The leading colon is
just a naming convention the framework uses for its own internal extras to avoid colliding with app
keys — it is a perfectly ordinary string.

When you send it to a `PreferenceActivity` subclass, the platform will try to instantiate the class
you named and put it on the screen. [README §3.9](README.md) has the measured path.

---

### 6. Wasn't fragment injection fixed in 2013?

Half of it was, and the honest answer has three parts:

1. **The reflective path was never removed.** It is unchanged on API 35, measured out of the device's
   own `framework.jar`.
2. **The default gate was fixed**, in the sense that an app targeting API 19 or later now crashes
   instead of loading anything. That branch is not exploitable — it is a crash.
3. **The fix delegated the decision to the app**, and an app that answers "yes" to everything is
   exactly as vulnerable as it was in 2013. That was measured working on API 35 with `targetSdk` 35,
   from a zero-permission app.

So: fixed as a *platform default*, not fixed as a *bug class*.

---

### 7. My app targets API 35. Am I safe?

Only from the automatic case. Your `targetSdk` decides what the **base** `isValidFragment` does, and
at 35 it throws — so if you never override it, you get a crash rather than an injection. If you *do*
override it (and you must, or the screen is unusable), your override is the entire control.

And none of that applies at all if you are not using `PreferenceActivity`, which you probably are
not. The modern form of this bug is a hand-written router. [README §5.2](README.md), example `[V2]`.

---

### 8. Can I just check the caller's package name in the host Activity?

No, and this is worth understanding rather than memorising.

An Intent carries **no caller identity** ([26 §3.8](../26-Intent/README.md)). Binder stamps the
caller's uid onto the transaction, and that stamp is unforgeable
([25-Binder](../25-Binder/README.md)) — but that transaction ends inside `system_server`. The launch
that reaches your Activity is a *second* transaction, from `system_server`, so by the time `onCreate`
runs there is nothing to read. `getCallingActivity()` answers only when the caller used
`startActivityForResult`, and an attacker will not.

Check the *input*, not the caller.

---

### 9. Is an allowlist in `isValidFragment` enough?

It stops the injection. It does not stop the crash.

When your override returns `false`, `PreferenceActivity.switchToHeaderInner` throws
`IllegalArgumentException` out of `onCreate`, uncaught, and your app dies. Any installed app can do
that on demand. Measured — [README §5.4](README.md).

The complete fix is to stop extending `PreferenceActivity`. `androidx.preference` has no equivalent
Activity, which is not an accident.

---

### 10. What is wrong with `fragmentName.startsWith("com.myapp.")`?

It admits every Fragment in your app, and every Fragment in your app is exactly what the attacker
wants. It excludes framework Fragments, which were never the target.

The general rule: every allowlist that is a **predicate over the attacker's string** eventually
admits something. A working control is a **lookup in a set the attacker cannot extend**. Better
still, accept a key ("about", "general") and choose the class yourself, so there is no name to
filter. [README §5.3](README.md).

---

### 11. Does the type cast protect me? It has to be a `Fragment` to be loaded.

It depends which library, and the answer surprises people.

- **Platform** (`android.app.Fragment.instantiate`): yes, effectively. It calls
  `Fragment.class.isAssignableFrom(clazz)` *before* `newInstance()`, so a non-Fragment class is
  refused without its constructor running. Measured.
- **AndroidX** (`FragmentFactory`): no. `loadFragmentClass` does a generic cast that **erasure
  deletes** — `javap -c` shows no `checkcast` at all — so the only type check happens *after*
  `Constructor.newInstance`. The class's static initialiser and constructor run first.

So on AndroidX, naming a non-Fragment class is not "blocked". It is "blocked after it ran".
[README §4.5](README.md).

---

### 12. What could an attacker actually *do* with an arbitrary constructor?

Look for classes whose static initialiser or no-argument constructor has a side effect: a crash
reporter that starts uploading, a cache that clears itself, a feature-flag holder that reloads from
disk, a debug helper that opens a socket, an SDK that registers a receiver.

That search is called gadget hunting, and it is the same skill as gadget hunting for Java
deserialisation — except the classpath is the app rather than a library set. Most apps have nothing
useful. Some have exactly one thing.

---

### 13. If injection works, has the attacker stolen the data?

**Usually not, and this is the most common over-claim in this bug class.**

The injected Fragment is the *victim's* code, running in the *victim's* process. It reads the
victim's data and puts it on the victim's screen. The attacker made that happen; the attacker did not
receive anything.

Getting it back needs a second step: an argument that makes the Fragment write somewhere readable, a
result the host returns via `setResult`, an accessibility service, a screen capture, or a human
looking at the phone. Find that step or say in your report that you did not.
[README §5.7](README.md).

---

### 14. Why does my second `am start` print nothing?

Because Android compared your two Intents with `Intent.filterEquals()`, **which does not look at
extras**, decided they were the same Intent, and delivered the second one to the already-running
instance instead of starting a new one:

```
Warning: Activity not started, intent has been delivered to currently running top-most instance.
```

Use `am start -S`, or `am force-stop` between runs. Every command in this chapter does.

---

### 15. My `am start` says it worked but nothing happened. What?

Three usual suspects, in order:

1. A **permission review dialog** is on screen (common right after installing an app with a low
   `targetSdk`). `adb shell "dumpsys window" | grep mCurrentFocus` will name
   `ReviewPermissionsActivity`.
2. The **keyguard** is up, and some builds silently refuse app-originated Activity starts.
   `adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"`.
3. You are reading a stale log because of question 14.

A silent run and a clean negative look identical. Always have a liveness check.

---

### 16. Can I just test this with `adb shell am start` against the victim?

You can, and the result will not support a finding.

`adb shell` runs as uid 2000, which holds privileges no application has — including the ability to
start **non-exported** Activities. If your test succeeds from the shell, you have proved the shell can
do it. Use a probe app with zero permissions; `examples/attacker-app/` is one, and you can still
trigger it from the shell because the shell starts the *attacker* and the *attacker* starts the
victim.

---

### 17. Where do I put `FLAG_SECURE` for one sensitive Fragment?

You cannot. `FLAG_SECURE` is a **window** flag and a Fragment has no window — it has a `View` inside
the host's window. `getActivity().getWindow().addFlags(FLAG_SECURE)` covers the whole Activity,
including every other Fragment in it.

The exception is `DialogFragment`, which *does* have its own window, so
`getDialog().getWindow().addFlags(FLAG_SECURE)` protects the dialog independently.

Toggling the flag in `onResume`/`onPause` races the Recents snapshot and is not reliable.

---

### 18. What is the difference between `onDestroyView` and `onDestroy`?

`onDestroyView` destroys the view hierarchy and keeps the Fragment object — this is what happens when
a Fragment goes onto the back stack. `onDestroy` destroys the object.

The practical consequence: anything held in a field survives `onDestroyView`, and anything held in a
`View` does not. This is why `getViewLifecycleOwner()` exists, and why observing data with the
*Fragment's* lifecycle instead of the *view's* leaks an observer per back-stack visit.

---

### 19. Is `setRetainInstance(true)` a security problem?

Not directly. It is deprecated because a retained Fragment holds a reference to an `Activity` that is
being destroyed and recreated, so dead `Activity` objects stay in the heap. That is a memory problem
that becomes a security problem only when a heap dump is the artefact somebody is reading.

Use a `ViewModel`. But note the scoping: an **Activity-scoped** `ViewModel` is shared by every
Fragment in that Activity — **including one that was injected**. That is documented behaviour, not a
bug, and developers are frequently surprised by it. [README §3.4](README.md).

---

### 20. Can another app send my Fragment a `setFragmentResult`?

No. The Fragment result API is in-process, keyed by a string, routed through the `FragmentManager`.
There is no IPC and no `exported` concept. If you find `setFragmentResult` in a decompiled app, it is
not an entry point.

**But** an injected Fragment is in the same process and the same `FragmentManager`, so it can
subscribe to any key it knows — and the keys are plain strings sitting in the DEX.

---

### 21. Why does the manifest not list Fragments? Is that a design flaw?

It is not a flaw; it is what "not a component" means. The manifest describes the **boundary** of the
app: the things another process may address. A Fragment is internal, so there is nothing to declare.

The problem is second-order: as apps moved to one Activity and many Fragments, the number of
things in the manifest fell while the number of screens did not. Every manifest-driven tool now
reports a smaller attack surface than exists. [README §6.5](README.md).

---

### 22. Do I need to worry about this if my app uses Jetpack Compose?

Different shape, same question. Compose apps still usually have one Activity, and they still usually
route by a **string** — a Navigation route rather than a class name. A route string is a *bounded*
parameter if the route table is closed and an *unbounded* one if the app resolves it dynamically.

The specific reflective-instantiation primitive of this chapter does not apply, because Compose
destinations are not instantiated by class name. The general question — *does external input choose
which screen appears, and is the destination itself gated?* — applies exactly as written.

---

### 23. Is there a CVE I can cite?

Not from this chapter. The `PreferenceActivity` issue has real published history from 2013 and
identifiers exist for specific vendor instances, but a wrong identifier in a report is worse than no
identifier at all.

Cite the **class** ("fragment injection through a reflective Fragment loader") and verify any specific
ID against the [Android Security Bulletins](https://source.android.com/docs/security/bulletin) before
you use it.

---

### 24. My scanner says "app uses PreferenceActivity — vulnerable to fragment injection". Is it right?

Almost certainly not, and here is the checklist that resolves it in five minutes:

1. **Is the host exported?** Measured over 241 APKs on a stock Android 15 image: five `return true`
   gates existed and **not one** of their hosts was exported.
2. **Does the gate read its parameter?** 32 of 48 gates in that corpus performed a real comparison.
3. **What is in the reachable set?** If every Fragment the app has is a read-only about-screen, the
   primitive is real and the impact is not.

If you cannot answer all three, you have a lead, not a finding. [README §8.4](README.md).

---

### 25. I found `isValidFragment` in a minified app and the class names are gibberish. Now what?

Three things survive R8 and are your anchors: the **superclass** `Landroid/preference/PreferenceActivity;`,
the **method name** `isValidFragment` (it is an override, so renaming it would break dispatch), and
the **string** `:android:show_fragment`.

Then read the method body and ask whether it touches its parameter register. A gate that only builds
a `StringBuilder` and calls `Log` has decided nothing, no matter what the class is called.
[README §6.2](README.md).

---

### 26. Why does this chapter keep saying "measured"?

Because this repository has recorded about thirty cases where a widely-repeated claim turned out to
be wrong on a real device, and because the specific question "is fragment injection still
exploitable?" is one where every published answer disagrees with every other.

Everything labelled `measured` here was taken on a named device on a named date, and
[README §7.7](README.md) lists what was *not* measured — including that `frida-server` does not link
on that image, so `scripts/fragment-trace.js` ships reviewed and unrun. An unrun script honestly
marked is more useful than one implied to work.
