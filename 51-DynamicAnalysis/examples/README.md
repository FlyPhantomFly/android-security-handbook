# 51 — Dynamic Analysis · Examples

Two files, meant to be read together and in this order.

| File | What it is |
|---|---|
| [`session-transcript-annotated.md`](session-transcript-annotated.md) | A real dynamic pass, command by command, with a **Proves** line under every observation — and, where it applies, a line saying what it does *not* prove |
| [`coverage-ledger.md`](coverage-ledger.md) | What was and was not exercised in that same pass, with the arithmetic that produced 50% rather than 67%, and a table of the sentences each gap **forbids** the report from containing |

Read the transcript first for the observations, then the ledger for the bounds on them. Neither is
complete without the other, which is the chapter's whole argument in miniature: a dynamic finding is
an observation plus its coverage.

---

## Why the coverage half is a deliverable

52-StaticAnalysis argues that a static report's rejected leads are part of the deliverable, because a
report showing only what survived looks like luck. The dynamic equivalent is coverage, and the
argument is the same shape.

| Run | Components in inventory | Reached | Coverage | Observations | Attributed | Discarded as background |
|---|---|---|---|---|---|---|
| control (45 s, idle) | 4 | 0 | — | 2 | 0 | 2 |
| warm launch (43 s) | 4 | — | **void** | 1 | 0 | 1 |
| cold start (38 s) | 4 | 2 | **50%** | 3 | 1 | 2 |

Three sessions, six observations, **one finding**. A report that printed the six observations would
look busier and be worth less. A report that printed the finding and omitted the 50% would be
unfalsifiable.

---

## Anonymisation, stated plainly

- The target is a **commercial third-party application already installed on the test device**, which
  is somebody's daily driver. Its package is written throughout as `com.vendor.fieldmgr`, its
  preference **values** are redacted, and its APK SHA-256 is omitted.
- The second third-party package on the device appears once, as `com.vendor.fieldapp`, only to
  demonstrate the second of `run-as`'s two refusals.
- The OEM system package names (`com.ubx.*`, `com.udroid.*`) are **not** anonymised: they are vendor
  firmware components, not anyone's private data, and the finding is about the device build.
- **Every flag, uid, SELinux context, pid, count, byte figure, timing and percentage is the real
  measured value.** Nothing was rounded to make a point, and the one place a measurement disagreed
  with the neat story — the warm launch that turned out to be void — is kept and made into the most
  important section of the transcript.
- **No instrumentation, modification, repackaging or bypass was performed against the target.** The
  entire pass is observation, which is exactly the altitude discipline the chapter argues for, and it
  still produced a validated finding.

---

## Reproducing the run

You cannot reproduce it against this target — it is one device's installed application. You can
reproduce the *method* against any application on your own device in about fifty minutes:

```bash
# host
export PKG=<your target>

# stage 1 -- posture, and it gates everything after it
adb shell "getprop ro.product.model; getprop ro.build.version.sdk; getprop ro.build.version.security_patch"
adb shell "getenforce; which su"; adb shell "mount | grep cacerts"

# stage 1b -- the platform's record, and whether you can get inside
adb shell "dumpsys package $PKG" | grep -E 'flags=|granted=|versionName|userId='
adb jdwp
adb shell "run-as $PKG id"

# stage 1c -- the denominator, from the artefact
adb pull $(adb shell pm path $PKG | head -1 | cut -d: -f2 | tr -d '\r') base.apk
aapt2 dump xmltree --file AndroidManifest.xml base.apk > mf.txt
awk '/E: (activity|activity-alias|service|receiver|provider) /{k=$2; next}
     /E: /{ if ($2 !~ /^(intent-filter|meta-data|action|category|data)$/) k=""; next }
     k != "" && /android:name\(0x01010003\)=/ {
        match($0,/="[^"]+"/); print substr($0,RSTART+2,RLENGTH-3)" kind="k; k="" }' \
    mf.txt | sort -u > entrypoints.txt

# stage 2 -- calibrate
bash ../scripts/session-recorder.sh -p "$PKG" -o ./ev/control --wait 45

# stages 4-5 -- exercise. [MUTATES] force-stop; the app restarts.
bash ../scripts/session-recorder.sh -p "$PKG" -o ./ev/s01 \
  --exec "adb shell am force-stop $PKG; sleep 3;
          adb shell am start -W -n $PKG/<LAUNCH>; sleep 35"

# stage 0 -- both denominators, so you can see the gap for yourself
python3 -B ../scripts/coverage-reporter.py -p "$PKG" -c entrypoints.txt --logcat ./ev/s01/09-logcat.txt
python3 -B ../scripts/coverage-reporter.py -p "$PKG"                    --logcat ./ev/s01/09-logcat.txt
```

The two coverage figures at the end will differ. That difference is the most transferable thing in
either file.

---

## Using the ledger as a template

Copy [`coverage-ledger.md`](coverage-ledger.md) and replace the content of its four tables. The
columns are deliberately split between what a tool fills in and what only you can:

| Column | Filled by |
|---|---|
| Component, Kind | `aapt2 dump xmltree`, or 52's stage 4 entry-point list |
| Reached | `coverage-reporter.py` |
| Evidence, verbatim | `coverage-reporter.py` prints the proof text — **paste it, do not summarise it** |
| Bucket (A/B/C/D) | **You.** Why was it not reached, and could it have been? |
| Consequence | **You.** The sentence in the report this row forbids |
| Session verdict (valid / void) | **You.** Read `am start -W`'s `Activity:` line before anything else |

The **Consequence** column is the one people leave out and it is the one that earns the file's
existence. Fill it in *before* you write the findings section, and it will stop you writing at least
one sentence you could not defend.

---

## The two mistakes these files exist to prevent

1. **Publishing a void session as a clean result.** The warm launch produced silence on all nine
   channels and had not happened. The only evidence was one line of `am start -W` output that a
   `>/dev/null` had thrown away.
2. **Quoting the denominator the device offers you.** 67% and 50% describe the same session. The
   device will hand you the first one every time, and it will always be the flattering one, because
   its resolver tables index only components that carry an intent-filter.
