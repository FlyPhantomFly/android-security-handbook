# Lab 02 — Manifest Audit From a Live Device

**Difficulty:** Intermediate
**Time:** 60–90 minutes
**Prerequisites:** [Lab 01](lab-01-device-recon.md), [32-Manifest](../../32-Manifest/README.md)

---

## Objective

Reconstruct an application's complete component and permission surface using only `dumpsys package`,
with no access to the APK. Then obtain the APK and diff your reconstruction against the real manifest
to find out what you missed.

## Why this matters

Three situations make this skill essential rather than academic.

You are testing an app on a device you cannot pull binaries from, because the client's policy forbids
removing the APK from the premises. You are testing a system or pre-installed app whose APK lives on
a read-only partition you cannot reach. Or you are triaging quickly and want the answer in thirty
seconds rather than after a five-minute decode.

There is also a subtler reason. `dumpsys package` shows you what `PackageManagerService` **actually
parsed** — not what `apktool` thinks the manifest says. When an APK uses binary-XML parser confusion
to make tools disagree with the platform, `dumpsys` is the authority.

---

## Setup

Pick any third-party application on your test device. A banking app, a social app, or a deliberately
vulnerable app such as InsecureBankv2, DIVA, or the OWASP MASTG test apps all work well. For this lab
we will refer to it as `$PKG`.

```bash
# host
export PKG=com.example.target        # replace
adb shell pm list packages -3 | grep -i <something>
```

---

## Steps

### Step 1 — Capture the record

```bash
# host
adb shell dumpsys package "$PKG" > pkg.txt
wc -l pkg.txt
```

Open `pkg.txt` and read it once end to end before doing anything else. It is long, but every section
maps to something you already know from [32-Manifest](../../32-Manifest/README.md).

### Step 2 — Identity and flags

Find and record:

| Field in `dumpsys` output | What it tells you |
|---|---|
| `userId=` | The app's UID. Note it — you need it to correlate with `ps`, `logcat`, and network stats |
| `pkg=Package{...}` | Package name |
| `codePath=` / `resourcePath=` | Where the APK lives |
| `dataDir=` | The private data directory |
| `versionCode=` / `versionName=` | Version |
| `targetSdk=` | **Critical** — decides default export, cleartext, PendingIntent mutability, and more |
| `minSdk=` | Oldest supported platform |
| `flags=[ ... ]` | Look for `DEBUGGABLE`, `ALLOW_BACKUP`, `TEST_ONLY`, `HAS_CODE`, `LARGE_HEAP` |
| `privateFlags=[ ... ]` | Look for `PRIVATE_FLAG_...` entries such as cleartext-traffic state |
| `signatures=` / `signing details` | The certificate digest |
| `installerPackageName=` | Where it came from — sideloaded or Play |
| `firstInstallTime=` / `lastUpdateTime=` | Timeline |

```bash
# host — extract the essentials
grep -E "userId=|codePath=|dataDir=|versionName=|versionCode=|targetSdk=|minSdk=|flags=|privateFlags=|installerPackageName=" pkg.txt
```

**Question:** the `flags` list contains `DEBUGGABLE`. What can you now do that you could not before,
and what is the severity of that as a finding? Write two sentences.

### Step 3 — Permissions

```bash
# host
sed -n '/requested permissions:/,/install permissions:/p' pkg.txt
sed -n '/install permissions:/,/runtime permissions:/p' pkg.txt
sed -n '/runtime permissions:/,$p' pkg.txt | head -40
```

Build a table with three columns: permission, protection level, and *what an attacker gains if they
compromise this app*. Look up any permission you do not recognise with:

```bash
# host
adb shell pm list permissions -f | grep -A3 "permission:android.permission.XXX"
```

**Question:** does the app request `QUERY_ALL_PACKAGES`, `SYSTEM_ALERT_WINDOW`,
`REQUEST_INSTALL_PACKAGES`, `MANAGE_EXTERNAL_STORAGE`, or bind an accessibility service? Each of
those is a significant capability and deserves a justification from the developer.

### Step 4 — Components

This is the heart of the lab. `dumpsys package` prints resolver tables listing every component with
its intent filters.

```bash
# host
sed -n '/Activity Resolver Table:/,/Receiver Resolver Table:/p'  pkg.txt > activities.txt
sed -n '/Receiver Resolver Table:/,/Service Resolver Table:/p'   pkg.txt > receivers.txt
sed -n '/Service Resolver Table:/,/Provider Resolver Table:/p'   pkg.txt > services.txt
sed -n '/Provider Resolver Table:/,/Key Set Manager:/p'          pkg.txt > providers.txt
wc -l activities.txt receivers.txt services.txt providers.txt
```

For each component, record: fully-qualified name, whether it is exported, any `permission` guarding
it, and its intent filters (action, category, data scheme/host/path).

> The resolver tables only list components that have intent filters. Components exported
> without a filter appear elsewhere in the output. Search for `exported=true` across the whole file
> as well:
> ```bash
> grep -n "exported=true" pkg.txt
> ```

**Question:** for each exported component with no `permission` attribute, write the single `adb`
command that would invoke it. You will use these in [Lab 03](lab-03-exported-sweep.md).

### Step 5 — Providers in detail

```bash
# host
grep -E "authority=|readPermission=|writePermission=|grantUriPermissions=" pkg.txt
```

Any provider with `exported=true` and no read permission is an immediate lead. Any provider with
`grantUriPermissions=true` is a lead for a URI-grant theft chain — see
[27-ContentProviders](../../27-ContentProviders/README.md).

### Step 6 — Signature

```bash
# host
sed -n '/signatures=/,+5p' pkg.txt
grep -A10 "signing details" pkg.txt
```

Record the certificate digest. You will compare it against `apksigner verify --print-certs` in the
next step, and against any hardcoded value you later find in the app's own tamper-detection code.

### Step 7 — Now get the APK and diff

```bash
# host
adb shell pm path "$PKG"
adb pull <path> target.apk
apktool d target.apk -o target/
aapt2 dump xmltree target.apk --file AndroidManifest.xml > manifest-parsed.txt
apksigner verify -v --print-certs target.apk
```

Compare your reconstruction against the real manifest. Specifically check:

- Did you find every exported component? Components can be exported implicitly (an `intent-filter`
  with no explicit `exported` attribute on `targetSdk` below 31) — did your `dumpsys` reading catch
  those?
- Did you find every permission, including `maxSdkVersion`-limited ones?
- Do `apktool`'s manifest and `aapt2 dump xmltree` agree with each other, and with `dumpsys`? If they
  do not, you have found something far more interesting than the lab intended — see
  [10-APK-Internals](../../10-APK-Internals/README.md) on AXML parser confusion.

### Step 8 — Write it up

Produce a one-page audit in the format you would give a client: component inventory table, permission
justification table, and a prioritised list of leads to test dynamically.

---

## Hints

<details>
<summary>Hint 1 — the resolver tables are indented oddly</summary>

Component entries appear as lines like `1a2b3c4 com.example/.MainActivity filter 5d6e7f8`. The class
name is the second field. Extract them with:
```bash
grep -oE '[a-z0-9]+ [A-Za-z0-9_.]+/[A-Za-z0-9_.$]+' activities.txt | awk '{print $2}' | sort -u
```
</details>

<details>
<summary>Hint 2 — exported status is not always on the same line</summary>

In the resolver tables, `exported` may not be printed at all — the presence of the component in the
resolver table with a matching filter is what makes it reachable. Cross-check against the
`Packages:` section further down, and against the decoded manifest in step 7.
</details>

<details>
<summary>Hint 3 — output differs across Android versions</summary>

The exact section headings in `dumpsys package` change between releases. If a `sed` range does not
match, print the section headings first:
```bash
grep -nE "^[A-Z][A-Za-z ]+:$" pkg.txt
```
</details>

---

## Solution

<details>
<summary>Reference extraction script</summary>

```bash
#!/usr/bin/env bash
# live-manifest.sh — reconstruct a component/permission surface from dumpsys
set -uo pipefail
PKG="${1:?usage: $0 <package>}"
T=$(mktemp)
adb shell dumpsys package "$PKG" > "$T"

echo "=== IDENTITY ==="
grep -E "^\s+(userId|codePath|dataDir|versionName|versionCode|targetSdk|minSdk)=" "$T" | sed 's/^\s*/  /'

echo
echo "=== FLAGS ==="
grep -E "^\s+(flags|privateFlags)=" "$T" | sed 's/^\s*/  /'
for f in DEBUGGABLE ALLOW_BACKUP TEST_ONLY EXTERNAL_STORAGE; do
    grep -q "$f" "$T" && echo "  !! $f present"
done

echo
echo "=== SIGNATURE ==="
grep -A4 -E "signatures=|signing details" "$T" | head -12 | sed 's/^\s*/  /'

echo
echo "=== REQUESTED PERMISSIONS ==="
sed -n '/requested permissions:/,/^\s*[a-z]* permissions:/p' "$T" \
  | grep -oE "[a-zA-Z0-9_.]+\.permission\.[A-Z_]+|android\.permission\.[A-Z_]+" | sort -u | sed 's/^/  /'

echo
echo "=== COMPONENTS WITH FILTERS ==="
for section in "Activity" "Receiver" "Service" "Provider"; do
    echo "  --- $section ---"
    sed -n "/${section} Resolver Table:/,/Resolver Table:/p" "$T" \
      | grep -oE "$PKG/[A-Za-z0-9_.\$]+" | sort -u | sed 's/^/    /'
done

echo
echo "=== EXPLICITLY EXPORTED ==="
grep -B2 "exported=true" "$T" | grep -oE "$PKG/[A-Za-z0-9_.\$]+" | sort -u | sed 's/^/  /'

echo
echo "=== PROVIDERS ==="
grep -E "authority=|readPermission=|writePermission=|grantUriPermissions=" "$T" | sed 's/^\s*/  /'

rm -f "$T"
```
</details>

---

## Success criteria

- [ ] You produced a complete component inventory without ever opening the APK
- [ ] Your inventory matches the decoded manifest, or you can explain every difference
- [ ] You recorded the certificate digest from both `dumpsys` and `apksigner` and they agree
- [ ] You can state the app's `targetSdk` and name three security defaults it determines
- [ ] For every exported component you wrote the `adb` command to invoke it
- [ ] You can explain why `dumpsys` is more authoritative than `apktool` when the two disagree
