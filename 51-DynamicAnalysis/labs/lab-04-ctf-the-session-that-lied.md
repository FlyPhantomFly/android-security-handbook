# Lab 04 — CTF: the session that lied

> **Objective.** You have inherited a complete, professional-looking evidence set from a dynamic pass
> that somebody else ran. Recover the flag, and write the report they should have written.
> **Points are awarded for the flag and deducted for every claim you make that the evidence does not
> support.**

**Difficulty:** advanced. The commands are trivial; the discipline is the challenge.
**Time:** two to three hours.
**Prerequisites:** [Lab 01](lab-01-first-runtime-pass.md) and
[Lab 03](lab-03-coverage-and-blind-spots.md). **No device is needed** — the evidence set is built by
the script in §1.

---

## 0. The premise

A junior tester has assessed `com.acme.fieldnotes` and produced an evidence directory in the exact
shape `session-recorder.sh` and `coverage-reporter.py` produce. Their draft report says:

> *"The application stores an authentication token in cleartext in shared preferences and leaks it to
> the system log. The application is otherwise clean: no other channel showed any change during a
> thorough 5-minute session covering all major screens. **HIGH.**"*

**Every sentence of that paragraph is wrong**, and the evidence to prove it wrong is already in the
directory they handed you. Four fragments of the flag are hidden in four different mistakes.

The flag has the form `CH51{f1_f2_f3_f4}` and each fragment is a lowercase word or short phrase you
will read directly out of the evidence once you look in the right place.

> **⚠️ The scoring is asymmetric on purpose.** Finding the flag is worth 40 points. Writing a correct
> report is worth 60. Every unsupported claim costs 10. It is entirely possible to find the flag and
> score negative.

---

## 1. Build the evidence set

Everything below is invented. No real application, device or person is involved, and the values are
constructed to make specific mistakes possible.

```bash
# host — run once, in a scratch directory OUTSIDE this repository
cat > build-ctf.sh <<'BUILDEOF'
#!/usr/bin/env bash
# build-ctf.sh -- construct the lab 04 evidence set. Everything here is fictional.
set -eu
R=ctf-evidence
rm -rf "$R"; mkdir -p "$R"/{control/before,control/after,s01/before,s01/after}

# ---------------------------------------------------------------- device
cat > "$R"/control/before/device.txt <<'EOF'
# device identity, recorded 2026-03-04T09:11:02Z
serial            EMULATOR-CTF-0001
model             Pixel 5a
manufacturer      Google
release           13
sdk               33
security_patch    2023-08-05
fingerprint       google/barbet/barbet:13/TQ3A.230805.001/10316531:user/release-keys
abi               arm64-v8a
ro.debuggable     0
selinux           Enforcing
device_locked     deviceLocked=0
shell_uid         2000
recorder_version  1.0
EOF
cp "$R"/control/before/device.txt "$R"/control/after/device.txt
cp "$R"/control/before/device.txt "$R"/s01/before/device.txt
cp "$R"/control/before/device.txt "$R"/s01/after/device.txt

printf 'com.acme.fieldnotes' > "$R"/control/package.txt
printf 'com.acme.fieldnotes' > "$R"/s01/package.txt
printf 'run-as' > "$R"/control/mode.txt
printf 'run-as' > "$R"/s01/mode.txt
printf '300 seconds\n' > "$R"/control/window.txt
printf '300 seconds\n' > "$R"/s01/window.txt

# ---------------------------------------------------------------- 01 identity
for D in control/before control/after s01/before s01/after; do
cat > "$R"/$D/01-identity.txt <<'EOF'
codePath=/data/app/~~kQ9v2==/com.acme.fieldnotes-Hh31Za==
flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
installerPackageName=null
privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION ]
userId=10214
versionCode=118 minSdk=24 targetSdk=33
versionName=3.4.1
EOF
done

# ---------------------------------------------------------------- 02 grants
for D in control/before control/after s01/before; do
cat > "$R"/$D/02-grants.txt <<'EOF'
android.permission.ACCESS_COARSE_LOCATION: granted=false
android.permission.ACCESS_FINE_LOCATION: granted=false
android.permission.CAMERA: granted=false
android.permission.POST_NOTIFICATIONS: granted=true
android.permission.READ_MEDIA_IMAGES: granted=false
EOF
done
cat > "$R"/s01/after/02-grants.txt <<'EOF'
android.permission.ACCESS_COARSE_LOCATION: granted=false
android.permission.ACCESS_FINE_LOCATION: granted=false
android.permission.CAMERA: granted=true
android.permission.POST_NOTIFICATIONS: granted=true
android.permission.READ_MEDIA_IMAGES: granted=false
EOF

# ---------------------------------------------------------------- 03 process
cat > "$R"/control/before/03-process.txt <<'EOF'
ProcessRecord{4471:com.acme.fieldnotes/u0a214}
curProcState=13
pid 4471
EOF
cp "$R"/control/before/03-process.txt "$R"/control/after/03-process.txt
cat > "$R"/s01/before/03-process.txt <<'EOF'
ProcessRecord{4471:com.acme.fieldnotes/u0a214}
curProcState=13
pid 4471
EOF
cat > "$R"/s01/after/03-process.txt <<'EOF'
ProcessRecord{4471:com.acme.fieldnotes/u0a214}
curProcState=13
pid 4471
EOF

# ---------------------------------------------------------------- 04 private fs
cat > "$R"/control/before/04-privatefs.txt <<'EOF'
cache/http/journal	4096	6bd7e0a5c1f4429ab0b3e0c5b2c9a771
files/telemetry.q	1180	af31c0d92e7b48119c6ad4e6c3f10b52
shared_prefs/com.acme.fieldnotes_preferences.xml	512	1c9f4e7a2b5d40c98e6f3a1b7d2c8e05
shared_prefs/session.xml	288	7f2a91c4e3b64d0fa1c58d9e2b3f4a60
EOF
cat > "$R"/control/after/04-privatefs.txt <<'EOF'
cache/http/journal	4096	6bd7e0a5c1f4429ab0b3e0c5b2c9a771
files/telemetry.q	1412	b7429ea1d05c4f6398d2c1a4e6b0f375
shared_prefs/com.acme.fieldnotes_preferences.xml	512	1c9f4e7a2b5d40c98e6f3a1b7d2c8e05
shared_prefs/session.xml	288	7f2a91c4e3b64d0fa1c58d9e2b3f4a60
EOF
cat > "$R"/s01/before/04-privatefs.txt <<'EOF'
cache/http/journal	4096	6bd7e0a5c1f4429ab0b3e0c5b2c9a771
files/telemetry.q	1412	b7429ea1d05c4f6398d2c1a4e6b0f375
shared_prefs/com.acme.fieldnotes_preferences.xml	512	1c9f4e7a2b5d40c98e6f3a1b7d2c8e05
shared_prefs/session.xml	288	7f2a91c4e3b64d0fa1c58d9e2b3f4a60
EOF
cat > "$R"/s01/after/04-privatefs.txt <<'EOF'
cache/http/journal	4096	6bd7e0a5c1f4429ab0b3e0c5b2c9a771
files/telemetry.q	1655	5c08b3f7a2e14d9b86c0d5a1f3e7b924
shared_prefs/com.acme.fieldnotes_preferences.xml	512	1c9f4e7a2b5d40c98e6f3a1b7d2c8e05
shared_prefs/session.xml	288	7f2a91c4e3b64d0fa1c58d9e2b3f4a60
EOF

# ---------------------------------------------------------------- 05 external fs
for D in control/before control/after s01/before; do : > "$R"/$D/05-externalfs.txt; done
cat > "$R"/s01/after/05-externalfs.txt <<'EOF'
20480,1772614901,/sdcard/Android/data/com.acme.fieldnotes/files/export/notes-2026-03-04.csv
EOF

# ---------------------------------------------------------------- 06 receivers
for D in control/before control/after s01/before; do
cat > "$R"/$D/06-receivers.txt <<'EOF'
Action: "android.intent.action.SCREEN_OFF"
Action: "android.intent.action.SCREEN_ON"
Action: "android.net.conn.CONNECTIVITY_CHANGE"
EOF
done
cat > "$R"/s01/after/06-receivers.txt <<'EOF'
Action: "android.intent.action.SCREEN_OFF"
Action: "android.intent.action.SCREEN_ON"
Action: "android.net.conn.CONNECTIVITY_CHANGE"
Action: "com.acme.fieldnotes.ADMIN_WIPE"
Action: "com.acme.fieldnotes.SYNC_NOW"
EOF

# ---------------------------------------------------------------- 07 services
for D in control/before control/after s01/before s01/after; do : > "$R"/$D/07-services.txt; done

# ---------------------------------------------------------------- 08 network
cat > "$R"/control/before/08-network.txt <<'EOF'
iface lo 88214 88214
iface wlan0 40218811 3312907
EOF
cat > "$R"/control/after/08-network.txt <<'EOF'
iface lo 92511 92511
iface wlan0 40244193 3319884
EOF
cat > "$R"/s01/before/08-network.txt <<'EOF'
iface lo 92511 92511
iface wlan0 40244193 3319884
EOF
cat > "$R"/s01/after/08-network.txt <<'EOF'
iface lo 96702 96702
iface wlan0 40270055 3326610
EOF

# ---------------------------------------------------------------- 09 logcat
: > "$R"/control/09-logcat.txt
cat > "$R"/s01/09-logcat.txt <<'EOF'
03-04 09:22:14.001  1188  1244 I ActivityManager: Force stopping com.acme.fieldnotes appid=10214 user=0: from pid 22019
03-04 09:22:14.006  1188  1244 I ActivityManager: Killing 4471:com.acme.fieldnotes/u0a214 (adj 900): stop com.acme.fieldnotes due to from pid 22019
03-04 09:22:17.220  1188  1244 I ActivityTaskManager: START u0 {flg=0x10000000 cmp=com.acme.fieldnotes/.ui.MainActivity} from uid 2000
03-04 09:22:17.318  1188  1301 I ActivityTaskManager: START u0 {cmp=com.android.permissioncontroller/.permission.ui.GrantPermissionsActivity} from uid 10214
03-04 09:22:17.905  1188  1301 I ActivityTaskManager: Displayed com.android.permissioncontroller/.permission.ui.GrantPermissionsActivity: +512ms
03-04 09:22:41.774  1188  1244 I ActivityManager: Start proc 22140:com.acme.fieldnotes:sync/u0a214 for service {com.acme.fieldnotes/.sync.SyncService}
03-04 09:22:42.010 22140 22140 D FieldNotesSync: begin sync cycle, queue=3
03-04 09:22:42.660 22140 22171 D FieldNotesSync: POST https://api.acme.example/v2/notes  hdr=Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.ZmFrZS1kZW1v.SIGNATURE_REDACTED
03-04 09:22:43.118 22140 22171 D FieldNotesSync: 200 OK, 3 accepted
03-04 09:22:43.140 22140 22140 D FieldNotesSync: queue drained
03-04 09:23:02.551  1188  1244 I ActivityTaskManager: START u0 {cmp=com.acme.fieldnotes/.ui.ExportActivity} from uid 2000
03-04 09:23:02.998  1188  1301 I ActivityTaskManager: Displayed com.acme.fieldnotes/.ui.ExportActivity: +391ms
03-04 09:23:11.402 22140 22140 I FieldNotesExport: wrote /sdcard/Android/data/com.acme.fieldnotes/files/export/notes-2026-03-04.csv (20480 bytes, 41 rows)
03-04 09:24:55.010  1188  1244 W ActivityManager: Unable to start service Intent { act=com.acme.fieldnotes.ADMIN_WIPE } U=0: not found
03-04 09:26:59.882  1188  1244 I ActivityManager: Killing 22140:com.acme.fieldnotes:sync/u0a214 (adj 985): empty for 1801s
EOF

cat > "$R"/s01/exercise.log <<'EOF'
Starting: Intent { cmp=com.acme.fieldnotes/.ui.MainActivity }
Status: ok
LaunchState: COLD (1)
Activity: com.android.permissioncontroller/.permission.ui.GrantPermissionsActivity
TotalTime: 604
WaitTime: 655
Complete
EOF

# ---------------------------------------------------------------- the manifest inventory
cat > "$R"/entrypoints.txt <<'EOF'
# entry points, from aapt2 dump xmltree on base.apk (SHA-256 4b1c...e07a)
com.acme.fieldnotes.ui.MainActivity kind=activity
com.acme.fieldnotes.ui.ExportActivity kind=activity
com.acme.fieldnotes.ui.SettingsActivity kind=activity
com.acme.fieldnotes.ui.AdminActivity kind=activity
com.acme.fieldnotes.sync.SyncService kind=service
com.acme.fieldnotes.sync.BootReceiver kind=receiver
com.acme.fieldnotes.data.NotesProvider kind=provider
EOF

# ---------------------------------------------------------------- the junior's draft
cat > "$R"/draft-report.md <<'EOF'
# com.acme.fieldnotes 3.4.1 -- dynamic assessment (DRAFT)

## F-01 Authentication token stored in cleartext (HIGH)
The application stores an authentication token in cleartext in shared preferences.

## F-02 Authentication token leaked to the system log (HIGH)
`adb logcat` shows the bearer token in plain text.

## Conclusion
The application is otherwise clean. A thorough 5-minute session covering all major
screens showed no other change on any channel. Coverage: 100%.
EOF

echo "built: $R"
BUILDEOF
bash build-ctf.sh
```

> **Everything in `ctf-evidence/` is invented.** The token is a fabricated JWT-shaped string with a
> redacted signature, the hosts are `.example` reserved names, and no real product is depicted.

---

## 2. Reconstruct the reports

The evidence directories are in the recorder's own format, so the recorder can re-render them:

```bash
# host
bash ../scripts/session-recorder.sh --report-only --out ./ctf-evidence/control
bash ../scripts/session-recorder.sh --report-only --out ./ctf-evidence/s01

cat ctf-evidence/control/DELTA.md
cat ctf-evidence/s01/DELTA.md
```

And the coverage report, both ways:

```bash
# host — with the static denominator, and with no device
python3 -B ../scripts/coverage-reporter.py -p com.acme.fieldnotes --no-device \
        --components ctf-evidence/entrypoints.txt \
        --logcat ctf-evidence/s01/09-logcat.txt
```

---

## 3. The task

Produce two files.

### 3.1 `flag.txt`

One line: `CH51{f1_f2_f3_f4}`.

Each fragment is a lowercase token you read **directly out of the evidence**. You will know you have
the right one because it will be the obvious short name for the mistake you just caught.

### 3.2 `report.md`

The report the junior should have written. It must contain:

- A findings section, with the four validation questions answered for **every** finding.
- A **rejections** section: every claim in `draft-report.md` that the evidence does not support,
  with the specific file and line that refutes it.
- A coverage statement with the real number, the denominator's source, and the unreached components
  named.
- A limits section.

---

## 4. Rules of engagement

1. **Every claim cites evidence.** File and line, in the evidence directory. A claim with no citation
   costs 10 points whether or not it is true.
2. **You may not add evidence.** There is no device. If the evidence cannot answer a question, the
   answer is "not established", and saying so scores points.
3. **The draft report is not evidence.** It is a hypothesis, and it is mostly wrong.
4. **Severity is question four.** A finding with no asset named is not a finding.
5. **"The app is clean" is worth −10 in any phrasing.**

---

## 5. Where the fragments are — the questions, not the answers

Each fragment corresponds to one of the four correlation disciplines from
[README §3.7](../README.md#37-stage-6--correlate). The lab tells you which discipline; finding the
fragment is your job.

| Fragment | The discipline | The question to ask |
|---|---|---|
| **f1** | Subtract the **control run** | One of the two files that changed in `s01` also changed in `control`. Which, and what does that make it? |
| **f2** | Subtract **your own tooling** | Two log lines record an action performed by uid 2000. What was uid 2000, and which of the junior's claims does that invalidate? |
| **f3** | **Did the exercise happen?** | `exercise.log` names the Activity that ended up in front. Is it the app's? What does that make the junior's "thorough session covering all major screens"? |
| **f4** | The **denominator** | The junior wrote "Coverage: 100%". Compute it against `entrypoints.txt`. What is the real figure, and which components were never reached? |

> **Hint — the fragments are words, not numbers.** Each one is the single most natural word for the
> category the observation belongs in. If you find yourself constructing an acronym, you have
> over-thought it.

---

## 6. Hints

<details>
<summary>Hint 1 — I cannot see any difference between the control and s01 filesystem lists.</summary>

Diff them properly. The recorder's report does this for you, but by hand:

```bash
diff ctf-evidence/control/before/04-privatefs.txt ctf-evidence/control/after/04-privatefs.txt
diff ctf-evidence/s01/before/04-privatefs.txt    ctf-evidence/s01/after/04-privatefs.txt
```

One file moves in **both**. A file that changes while you do nothing is not evidence about what you
did. What is the one-word name for that category?
</details>

<details>
<summary>Hint 2 — the token in logcat looks like a real finding to me.</summary>

It may well be one. But read the *whole* line, and then ask two questions the junior did not:

- Which process emitted it? Compare the pid on that line against `03-process.txt`.
- Is that process even in the coverage inventory under the name the junior assumed?

And separately: which lines in that log were caused by **the tester's own commands**? Look for
`from pid 22019` and `from uid 2000`. Neither of those is the application.
</details>

<details>
<summary>Hint 3 — the `Activity:` line in exercise.log.</summary>

`am start -W` reports the Activity that actually ended up in front when the launch settled. Compare
what it names against what the junior claimed they exercised. Then look at
`s01/09-logcat.txt` at `09:22:17` and see which package's Activity was `Displayed`.

Now ask: for how much of the 300-second window was the app's own UI in front? And what does that do
to "covering all major screens"?

The fragment is the word for a session whose exercise did not happen.
</details>

<details>
<summary>Hint 4 — coverage.</summary>

```bash
python3 -B ../scripts/coverage-reporter.py -p com.acme.fieldnotes --no-device \
        --components ctf-evidence/entrypoints.txt --logcat ctf-evidence/s01/09-logcat.txt
```

Seven components in the inventory. Count how many the log gives evidence for. The junior said 100%.

Then read the section headed "Reached, but not in the inventory", if there is one, and ask what a
component named in the evidence but absent from the inventory tells you about the *denominator*.
</details>

<details>
<summary>Hint 5 — I think there is a real finding here and I am not sure which.</summary>

There are two, and neither is the one the junior reported as F-01.

Look at what changed in channel 02 and channel 05, and at what appeared in channel 06 that was not
there before. Then, for each, ask question 4: what does reaching it get an attacker, and who is the
attacker?

One of them is a genuine High. One of them is Informational and it is worth saying so explicitly,
because saying "this is not a finding" with a reason is worth points in this lab.
</details>

---

## 7. Answer key

**Do not read this until `flag.txt` and `report.md` are both complete.**

<details>
<summary>Open the answer key</summary>

### The flag

```
CH51{background_shell_void_denominator}
```

### f1 — `background`

`files/telemetry.q` grew in **both** runs:

| Run | before | after |
|---|---|---|
| control | 1180 bytes, `af31c0d9…` | 1412 bytes, `b7429ea1…` |
| s01 | 1412 bytes, `b7429ea1…` | 1655 bytes, `5c08b3f7…` |

A file that grows by roughly the same amount while you do nothing is a periodic writer. It is
**background** and it must be subtracted before anything is attributed. The junior did not take the
control run into account at all.

Note also what did **not** change: `shared_prefs/session.xml` is **byte-identical, same digest
`7f2a91c4…`, in all four snapshots**. The junior's F-01 claims the app "stores an authentication
token in cleartext in shared preferences" — the evidence set contains no evidence for that at all.
The file existed before the session, was never written during it, and its contents were never read.
**F-01 is unsupported.**

### f2 — `shell`

Three log lines are the tester's own commands, not the application:

```
09:22:14.001  Force stopping com.acme.fieldnotes ... from pid 22019
09:22:17.220  START ... cmp=com.acme.fieldnotes/.ui.MainActivity from uid 2000
09:23:02.551  START ... cmp=com.acme.fieldnotes/.ui.ExportActivity from uid 2000
```

`uid 2000` is the **shell**. Both Activity starts were performed by `adb`, so neither demonstrates
reachability by an application, and `ExportActivity` — which produced the external-storage write —
was reached only because the tester started it explicitly.

The fragment word is **`shell`**, and the discipline is subtraction 3: your own tooling is not the
app's behaviour.

### f3 — `void`

```
Activity: com.android.permissioncontroller/.permission.ui.GrantPermissionsActivity
```

and, in the log:

```
09:22:17.318 START u0 {cmp=com.android.permissioncontroller/...GrantPermissionsActivity} from uid 10214
09:22:17.905 Displayed com.android.permissioncontroller/...GrantPermissionsActivity: +512ms
```

The launch produced a **permission dialog**, not the app's UI. `MainActivity` never appears in a
`Displayed` line. The only Activity of the app that was displayed is `ExportActivity`, at 09:23:02,
and that was started from the shell.

So the junior's "thorough 5-minute session covering all major screens" is **void** — the exercise
they describe did not happen. This is the same failure the chapter measured on a real device
([README §3.6.4](../README.md#364-how-this-stage-fails-measured)).

### f4 — `denominator`

Seven components in `entrypoints.txt`. Evidence exists for three:

| Component | Reached | Evidence |
|---|---|---|
| `ui.MainActivity` | yes (asked) | `START … cmp=…/.ui.MainActivity` — asked for, never `Displayed` |
| `ui.ExportActivity` | yes | `Displayed com.acme.fieldnotes/.ui.ExportActivity` |
| `sync.SyncService` | yes | `Start proc … for service {com.acme.fieldnotes/.sync.SyncService}` |
| `ui.SettingsActivity` | **no** | — |
| `ui.AdminActivity` | **no** | — |
| `sync.BootReceiver` | **no** | — |
| `data.NotesProvider` | **no** | — |

**3 of 7 — 43%.** The junior wrote 100%.

And the deeper point the fragment names: they had no **denominator** at all. `entrypoints.txt` was
sitting in the same directory.

### The two real findings

**R-01 — Bearer token written to the system log (High).**

```
09:22:42.660 22140 22171 D FieldNotesSync: POST https://api.acme.example/v2/notes
    hdr=Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.ZmFrZS1kZW1v.SIGNATURE_REDACTED
```

| Question | Answer |
|---|---|
| Real? | Yes — one log line, emitted by the app's own `:sync` process (pid 22140) |
| Reachable? | It occurred during a sync cycle the tester did not trigger, i.e. on an ordinary path |
| Who? | Anyone with ADB access to the unlocked device; and any app holding `READ_LOGS` on builds that grant it |
| So what? | A live bearer token for `api.acme.example` — an account-level credential |

**Severity High**, precondition *ADB access to an unlocked device*. Note it is **not** the finding the
junior reported: their F-02 said "in shared preferences and in the log"; only the log half is
supported.

**R-02 — Two runtime receivers registered with no manifest declaration (Informational, pending
demonstration).**

```
Action: "com.acme.fieldnotes.ADMIN_WIPE"
Action: "com.acme.fieldnotes.SYNC_NOW"
```

Both appeared during the window and neither is in `entrypoints.txt`. `ADMIN_WIPE` is an alarming
name. But:

- The evidence does not record whether either filter carries a sender permission.
- The one attempt in the log is `Unable to start service Intent { act=com.acme.fieldnotes.ADMIN_WIPE }
  U=0: not found` — which is an unrelated *service* start failing, not a broadcast being received.
- **No state change was demonstrated.**

**An unguarded runtime receiver is a precondition, not a finding.** Correct verdict:
Informational, with a stated next step — send the broadcast from an unprivileged app and show
observable state changing. Reporting this as High on the strength of the word `ADMIN_WIPE` costs
points.

### The other things worth catching

| Observation | Correct verdict |
|---|---|
| `flags=[ DEBUGGABLE … ]` in **all four** identity snapshots | A real finding the junior never mentioned. It was in the baseline, so it produced no *delta* — and a delta report is not the only place findings live |
| `CAMERA: granted=false → granted=true` in channel 02 | The permission dialog at 09:22:17 was granted. This is the tester's own action, and it also explains the void exercise |
| `notes-2026-03-04.csv`, 20,480 bytes, on external storage | Real, and outside the sandbox — but it was produced by an `ExportActivity` **the tester started from the shell**. Report it as user-initiated export to a world-adjacent location, Low, not as covert exfiltration |
| `wlan0` moved ~25 KB in s01 and ~25 KB in control | Within background. Attributing network volume here is unsupported |
| `security_patch 2023-08-05` on an Android 13 build | Worth a line in the device section |
| `03-process.txt` shows the same pid 4471 before and after | The app was **not** cold-started despite the force-stop in the log — another sign the session did not go as described |

</details>

---

## 8. Scoring

<details>
<summary>Open the scoring rubric</summary>

| Item | Points |
|---|---|
| Correct flag | +40 |
| R-01 reported, with all four questions answered and the precondition named | +15 |
| R-02 reported as **Informational** with a stated next step | +10 |
| `DEBUGGABLE` caught, with the observation that it is invisible in a delta | +10 |
| Coverage stated as 3 of 7 (43%) with the four unreached components **named** | +10 |
| Draft F-01 explicitly rejected, citing the identical `session.xml` digest | +5 |
| Draft's "100% coverage" explicitly rejected, citing `entrypoints.txt` | +5 |
| `telemetry.q` identified as background, citing the control run | +5 |
| The two shell-initiated Activity starts identified as such | +5 |
| A limits section naming at least three things the evidence cannot establish | +5 |
| | |
| **Each claim with no citation** | −10 |
| **Reporting R-02 as High or Critical** | −10 |
| **Reporting the CSV export as exfiltration** | −10 |
| **Any sentence of the form "the app is clean" / "no other issues"** | −10 |
| **Claiming reachability from the shell-initiated starts** | −10 |
| **Repeating the junior's F-01 as written** | −15 |

| Score | Verdict |
|---|---|
| 90+ | You would be trusted with an engagement report |
| 70–89 | Solid. Re-read the rejections you missed |
| 50–69 | You found the flag and over-claimed. This is the median and it is the failure the lab tests |
| < 50 | Re-read [README §3.7](../README.md#37-stage-6--correlate) and run it again |

</details>

---

## 9. Debrief

Answer these in writing before you move on. They are the lab.

1. The junior's F-01 was **entirely unsupported** and yet it was the first thing they wrote. What
   about the evidence set made it feel supported?
2. `session.xml` has the same digest in all four snapshots. If the recorder had captured only
   **size**, would you have been able to say that? What does that tell you about the cost of the
   second `find` pass?
3. `DEBUGGABLE` was present in the *baseline*, so it produced no delta at all. **What class of finding
   does a delta-based method systematically miss**, and what do you do about it?
4. Both Activity starts came from uid 2000. Write the one sentence you would put in a report about
   `ExportActivity`'s reachability.
5. The exercise was void and every channel still produced *something*. Why is a void run more
   dangerous than an empty one?
6. Coverage was 43% against a denominator that was sitting in the same directory. What would it have
   been against the device's resolver tables, and which figure would the junior have quoted?

---

## 10. Where to go next

- Re-run [Lab 01](lab-01-first-runtime-pass.md) against a real app and consciously look for each of
  the four mistakes in your own output. They are much harder to see in your own work.
- Take your Lab 03 limits section and score it against §8's rubric. Would it survive?
- Read [52-StaticAnalysis lab 04](../../52-StaticAnalysis/labs/lab-04-ctf-honest-report.md), which
  tests the same failure — over-claiming — from the static side. The two labs are deliberately the
  same shape, because the failure is the same failure.
