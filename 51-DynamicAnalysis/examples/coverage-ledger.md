# Coverage ledger — what was and was not exercised

The companion to [`session-transcript-annotated.md`](session-transcript-annotated.md). That file
records **what was observed**; this one records **what was driven**, which is the half that bounds
every sentence in a report.

**Target.** Anonymised commercial field-management application, version 1.9, `com.vendor.fieldmgr`.
**Device.** Physical `i9000S`, Android 13 / API 33, arm64, Enforcing, not rooted, no `frida-server`.
**Sessions.** Three, totalling about 2 minutes 5 seconds of window, on 2026-08-12.
**Instrumentation altitude.** 0 and 2 only — `dumpsys`, logcat and `run-as`. No proxy, no hooks, no
modification.

---

## 0. How to use this ledger

A coverage ledger has four jobs, and a percentage does only the first of them.

| Field | What goes in it |
|---|---|
| **Inventory** | Every component the *artefact* declares, with its kind. Not the device's list — §2 shows why |
| **Reached** | Yes or no, and **the evidence line that settled it**, never a bare tick |
| **Bucket** | If not reached: why not, from the four-way classification in §4 |
| **Consequence** | The sentence in the report that this row forbids or permits |

The last column is what makes a ledger worth keeping. A row that says "not reached" and stops is a
statistic. A row that says "not reached, therefore no statement in §5 of the report applies to
`AcRunOnStartUp`" is a control on the report.

---

## 1. The sessions

| # | Window | Exercise | Verdict |
|---|---|---|---|
| control | 45 s | Nothing. App idle | Calibration. `lo +4,017 B`, `dummy0 +5,877 B`, every other channel silent |
| warm | 43 s | `am start` against the already-running app | **VOID.** `am start -W` reported `Activity: com.android.permissioncontroller/…GrantPermissionsActivity` — a pending permission dialog absorbed the launch. **Excluded from all coverage arithmetic** |
| cold | 38 s | `am force-stop`, then `am start -W`, 35 s foreground | Valid. Channel 03 shows pid 30140 appearing, which is what proves the exercise happened |

**A void session is excluded, not counted as zero.** Counting it would understate coverage; ignoring
the distinction would let a run that did not happen look like a run that found nothing. Both errors
are worse than deleting the row and saying so.

---

## 2. The denominator — and why there are two

```bash
# host — source A: the shipped artefact, via the platform's own parser
aapt2 dump xmltree --file AndroidManifest.xml base.apk | awk '...'

# host — source B: the device's resolver tables
adb shell "dumpsys package $PKG" | grep -oE "$PKG/[A-Za-z0-9_.\$]+" | sort -u
```

| Source | Components | Missing |
|---|---|---|
| **A — static artefact** | **4** | — |
| B — device resolver tables | 3 | `MachineAccessActivty` |

`MachineAccessActivty` carries no `<intent-filter>`. `dumpsys package`'s resolver tables exist to
answer *"which component would win this Intent"*, so a component that cannot win one is not indexed.
It is entirely real and is started by explicit Intent from inside the app.

**Source A is the denominator used throughout this ledger.** Source B is recorded only to quantify the
error.

---

## 3. The ledger

| # | Component | Kind | Reached | Evidence, verbatim | Bucket |
|---|---|---|---|---|---|
| 1 | `com.vendor.fieldmgr.MainActivity` | activity | **yes** | `ActivityTaskManager: START u0 {flg=0x10000000 cmp=com.vendor.fieldmgr/.MainActivity} from uid 2000` | — |
| 2 | `androidx.core.content.FileProvider` | provider | **yes** | `ContentProviderRecord{… com.vendor.fieldmgr/androidx.core.content.FileProvider}` from `dumpsys activity providers` | — |
| 3 | `com.vendor.fieldmgr.MachineAccessActivty` | activity | **no** | — | **C — not reachable from the UI path driven** |
| 4 | `com.vendor.fieldmgr.AcRunOnStartUp` | receiver | **no** | — | **D — needs a broadcast this session did not send** |

**2 of 4 — 50%.**

Against the device denominator the same two components would read **2 of 3 — 67%**.

### Read the evidence column, not the tick

Row 1 says *"the platform was **asked** to start this Activity"*. It does **not** say the Activity
ran to completion, and in the warm session that exact evidence line coexisted with the app's UI never
appearing at all. `coverage-reporter.py` prints the proof text next to every "yes" for this reason.

The stronger evidence would have been a `Displayed com.vendor.fieldmgr/.MainActivity` line. **There is
none in the capture**, which is recorded here as a weaker-than-ideal reach rather than papered over.

### Row 1 carries a second caveat

`from uid 2000`. The Activity was started **by the shell**, not by the app and not by another app. So
row 1 supports *"this Activity was exercised"* and does **not** support *"this Activity is reachable
by a third-party application"*. Those are different claims and only the first is in evidence.

---

## 4. The four-way classification of what was not reached

| Bucket | Meaning | Rows | What to do about it |
|---|---|---|---|
| **A** | Reachable, I simply did not | none | Free coverage. Drive it |
| **B** | Reachable, but needs state I did not have | none | Get the state, or record why not |
| **C** | Not reachable from the UI path driven | 3 | Start it explicitly — **only against an app you own** |
| **D** | Not reachable by a user at all | 4 | Trigger it deliberately: `am broadcast`. Same caveat |

Rows 3 and 4 both sit in the "would require an action this engagement's scope did not permit"
category: the target is a **third-party application on a daily-driver device** and the discipline for
this pass was **observation only**. Starting `MachineAccessActivty` or broadcasting to
`AcRunOnStartUp` would have been mutations of somebody else's application.

**That is a legitimate reason for a coverage gap and it is stated rather than hidden.** A gap with a
recorded reason is methodology; a gap with no reason is an omission.

---

## 5. What each unreached row forbids the report from saying

This is the column that makes the ledger a control rather than a statistic.

| Row | Forbidden sentence | Permitted sentence |
|---|---|---|
| 3 `MachineAccessActivty` | "The application does not expose machine-access functionality without authentication" | "`MachineAccessActivty` was not exercised. Its behaviour, its input handling and its authorisation checks were not examined" |
| 4 `AcRunOnStartUp` | "The application has no unguarded broadcast receiver" | "`AcRunOnStartUp` was not exercised. Whether it validates its Intent, and whether it is reachable by an unprivileged sender, was not established" |
| 1 (reached, weakly) | "`MainActivity` was fully exercised" | "`MainActivity` was started; the platform recorded the start request. No `Displayed` event was captured, and branch coverage within it was not measured" |
| 1 (uid caveat) | "`MainActivity` is reachable by another application" | "`MainActivity` was started from `adb shell` (uid 2000). Reachability from an unprivileged application was not established" |

---

## 6. Beyond components — the grains this ledger does not cover

| Grain | Measured? | If not, the sentence it forbids |
|---|---|---|
| Screen | partly — one screen requested, never confirmed drawn | "All screens were reviewed" |
| **Component** | **yes — 2 of 4** | — |
| Method | no | "The credential-handling code was reviewed at runtime" |
| Instruction / branch | no | Anything about which branch of a conditional executed |

Method and instruction coverage need `Stalker`
([53-Frida](../../53-Frida/README.md) §7.9, at 100–1000× slowdown) or a coverage-instrumented build.
Neither was available: no root, no `frida-server`, and no permission to rebuild.

---

## 7. Channels, and what a closed one costs

A closed channel is a **gap**, not a negative. This table is the difference between the two.

| Channel | Captured | If not, the sentence it forbids |
|---|---|---|
| 01 identity | yes | — |
| 02 grants | yes | — |
| 03 process | yes | — |
| 04 private storage | **yes**, via `run-as` (debuggable + app uid) | — |
| 05 external storage | yes | — |
| 06 runtime receivers | yes, as a **snapshot pair** | "No receiver was registered" — one registered and dropped inside the window is in neither snapshot |
| 07 services | yes | — |
| 08 network **counters** | yes | — |
| 08 network **content** | **no** — no proxy was used | "The application transmits no sensitive data"; "the application does not pin" |
| Heap | **no** — no dump taken | "No credential persists in memory after logout" |
| Method coverage | **no** | Anything about branches |
| Another app's data | **no** — no root | "This application cannot read other applications' data" |

---

## 8. The statement this ledger produces

Paste-ready, with every number traceable to a row above:

```
COVERAGE OF THE DYNAMIC PASS

This assessment exercised com.vendor.fieldmgr version 1.9 on an i9000S,
Android 13 / API 33, arm64, SELinux Enforcing, not rooted, no frida-server,
security patch level 2021-11-05. The system CA store was verified unmodified
(mount | grep cacerts returned nothing). Instrumentation was at altitude 0-2:
dumpsys, logcat and run-as. No proxy, no hooks, no modification of the target.

Three sessions were recorded, totalling approximately 2 minutes 5 seconds of
observation window. One of the three was void -- the launch was absorbed by a
pending runtime-permission dialog, confirmed by `am start -W` reporting
Activity: com.android.permissioncontroller/.permission.ui.GrantPermissionsActivity
-- and is excluded from the arithmetic below rather than counted as a null result.

Of 4 components enumerated from the shipped artefact, 2 (50%) were reached.
The same evidence measured against the device's own resolver tables would read
2 of 3 (67%); that denominator omits components without an intent-filter and is
an upper bound. The static figure is quoted.

Components NOT exercised, and to which no statement in this report -- positive
or negative -- applies:

  - com.vendor.fieldmgr.MachineAccessActivty (activity)
      not reachable from the UI path driven; starting it explicitly would have
      been a mutation of a third-party application outside the scope of this pass
  - com.vendor.fieldmgr.AcRunOnStartUp (receiver)
      requires a broadcast that was not sent, for the same reason

Component coverage is not code coverage. Branch coverage within reached
components was not measured, and no method-level instrumentation was used.

Channels not captured: network content (no proxy), process heap (no dump), and
any other application's data (no root). No statement in this report addresses
what the application transmits, what persists in its memory, or its access to
other applications.

Runtime observation additionally cannot establish completeness, dependency
versions, or server-side behaviour. Those were addressed by the static pass.
```

---

## 9. What this ledger cost, and what it bought

**Cost.** About four minutes: one `aapt2` invocation, two `coverage-reporter.py` runs, and the time to
write the bucket and consequence columns by hand.

**Bought.**

1. **The 50% figure instead of the 67% one.** A number that survives review.
2. **Two named components** a client can ask to have tested, instead of a percentage they cannot act
   on.
3. **The uid-2000 caveat on row 1**, which would otherwise have become an unsupported reachability
   claim.
4. **The void-session exclusion**, written down, so that the session count in the report is honest.
5. **A forbidden-sentence table**, which is the cheapest possible defence against the single most
   common failure in dynamic reporting: writing a negative your coverage does not support.

> **A ledger is not documentation of the work. It is a constraint on the report.** Fill it in before
> you write the findings, and it will stop you writing at least one sentence you could not defend.
