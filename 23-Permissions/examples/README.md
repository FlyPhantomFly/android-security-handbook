# 23 — Permissions · Examples

Everything here is **source**. Nothing in this directory is a built artefact, and nothing should
be — an APK in a git repository is a liability, and every example ships with the one command that
builds it.

## What is here

| Path | What it is |
|---|---|
| [squat-pair/](squat-pair/) | Four manifests that reproduce permission squatting end to end, plus a build script. This is the chapter's signature demonstration |
| [SignatureGuardedService.java](SignatureGuardedService.java) | A `signature`-protected component done **correctly** — the manifest permission plus the in-code caller check the manifest cannot express |
| [signature-guarded-AndroidManifest.xml](signature-guarded-AndroidManifest.xml) | The manifest that goes with it, annotated attribute by attribute |
| [probe-app/](probe-app/) | The unprivileged probe. `adb shell` is UID 2000 and proves nothing; this is what proves reachability |
| [weak-permissions-AndroidManifest.xml](weak-permissions-AndroidManifest.xml) | An audit target: a manifest with every custom-permission defect this chapter describes, one per element |

## The rule these examples exist to demonstrate

A permission is only as strong as the guarantee that **your** app defines it, at a level an
attacker cannot reach. `squat-pair/` breaks that guarantee three different ways.
`SignatureGuardedService.java` is what you recommend instead.

## Building

Every buildable example needs the Android SDK build tools and a JDK. Nothing needs Gradle, Android
Studio, or an internet connection.

```bash
# host — set this once; the scripts read it
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"        # or %LOCALAPPDATA%\Android\Sdk on Windows
```

The apps in `squat-pair/` deliberately contain **no code at all** (`android:hasCode="false"`).
A permission declaration needs no DEX, and stripping the example to a manifest plus one string
resource makes the mechanism impossible to miss. `probe-app/` does contain code, because a probe
has to actually call something.

## Where the measurements came from

Every `adb` output quoted in this chapter's README and labs was produced by building exactly these
manifests, with the script in `squat-pair/`, and installing them on a physical device running
**Android 13 / API 33, arm64**. Where a claim was not measured, the text says so.

## The exact command lines

XML forbids a double hyphen inside a comment, so the manifests here cannot print a command that
uses a `--flag`. They point at this section instead.

```bash
# host — the three tools, three questions, same file. Run all three and compare.
python3 ../scripts/permission-audit.py --manifest weak-permissions-AndroidManifest.xml
python3 ../../21-App-Sandbox/scripts/manifest-exposure.py weak-permissions-AndroidManifest.xml
python3 ../../32-Manifest/scripts/manifest-audit.py weak-permissions-AndroidManifest.xml

# host — the same auditor against the correct version. Every row should be ENFORCEABLE.
python3 ../scripts/permission-audit.py --manifest signature-guarded-AndroidManifest.xml

# host — the squatting case. UNOWNED without a device capture, SQUATTED with one.
python3 ../scripts/permission-audit.py --manifest squat-pair/victim-suite-AndroidManifest.xml
adb shell pm list permissions -f -g > perms.txt
python3 ../scripts/permission-audit.py \
        --manifest squat-pair/victim-suite-AndroidManifest.xml --pm-list perms.txt
```

## A note on `<queries>`

Every probe manifest here carries a `<queries>` block naming its target. From `targetSdkVersion`
30 onwards an app cannot see a package it has not declared an interest in, and a probe that
silently sees nothing looks exactly like a probe that proved the target unreachable. This is the
single most common reason a home-made test app returns a wrong negative. See README.md §3.11.

## Related

- [../scripts/grant-state.py](../scripts/grant-state.py) — read the grant state these examples produce
- [../scripts/permission-audit.py](../scripts/permission-audit.py) — audit the manifests here
- [../labs/lab-02-squatting.md](../labs/lab-02-squatting.md) — the lab that walks `squat-pair/`
- [../../21-App-Sandbox/examples/](../../21-App-Sandbox/examples/) — the attacker app used for the sandbox chapter's reachability work
