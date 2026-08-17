# `system-ca-module` — a systemless system CA

A minimal, complete `system/` overlay module. It exists to put one file into the Android system
trust store without writing a byte to the `/system` partition.

Used by [Lab 02](../../labs/lab-02-write-a-module.md) Part 2 and measured by
[Lab 03](../../labs/lab-03-denylist-investigation.md).

---

## Layout

```
system-ca-module/
├── module.prop
├── customize.sh
├── README.md                                   <- this file, not part of the module
└── system/
    └── etc/
        └── security/
            └── cacerts/
                └── .gitkeep                    <- placeholder; replaced by YOUR certificate
```

Everything under `system/` is mirrored onto `/` by bind mounts at `post-fs-data`. A file at
`system/etc/security/cacerts/9a5ba580.0` inside the module appears at
`/system/etc/security/cacerts/9a5ba580.0` on the running device, and the physical partition is
untouched. Chapter [§3.6](../../README.md#36-module-structure) explains the tmpfs directory clone
that makes the *other* certificates in that directory survive.

`README.md` and `.gitkeep` are repository artefacts. `customize.sh` deletes them at install time so
they never reach a device.

---

## Producing the certificate

The filename is not decoration. Android's trust store is looked up by the **old-style subject hash**
of the certificate with a `.0` suffix, and a correctly-formatted PEM under any other name is
silently ignored — no error, no log line, nothing.

```bash
# host — export the CA from your proxy first.
#   Burp:      Proxy > Settings > Import/Export CA certificate > DER
#   mitmproxy: ~/.mitmproxy/mitmproxy-ca-cert.pem is already PEM
openssl x509 -inform DER -in cacert.der -out proxy-ca.pem -outform PEM

# the lookup name
HASH=$(openssl x509 -inform PEM -subject_hash_old -in proxy-ca.pem | head -1)
echo "trust store filename: ${HASH}.0"

cp proxy-ca.pem "system/etc/security/cacerts/${HASH}.0"
```

```bash
# host — sanity checks worth doing before you spend a reboot on it
openssl x509 -in "system/etc/security/cacerts/${HASH}.0" -noout -subject -issuer -dates
openssl x509 -in "system/etc/security/cacerts/${HASH}.0" -noout -text \
  | grep -A1 'X509v3 Basic Constraints'      # expect CA:TRUE
```

> **`-subject_hash_old`, not `-subject_hash`.** OpenSSL 1.0.0 changed the hashing algorithm used for
> trust-store lookups. Android's store was built against the older one and never migrated. Using the
> modern flag produces a filename Android will never look for, and the failure is completely silent.

---

## Build and install

```bash
# host
cd system-ca-module
zip -r /tmp/systemca.zip . -x '.*' -x '__MACOSX/*' -x 'README.md'
cd ..
unzip -l /tmp/systemca.zip          # module.prop must be at the ROOT of the archive

adb push /tmp/systemca.zip /sdcard/Download/
# Magisk app > Modules > Install from storage > systemca.zip > Reboot
```

Or without the app:

```bash
# adb shell as root
magisk --install-module /sdcard/Download/systemca.zip
reboot
```

---

## Verify it, at the level that matters

```bash
# adb shell — level 1: the file is visible
ls /system/etc/security/cacerts/ | wc -l          # original count + 1
```

```bash
# adb shell as root — level 2: it is a MOUNT, not a copy
grep -i cacerts /proc/self/mountinfo
grep -ic magisk /proc/self/mountinfo
```

Level 3 is an application actually trusting it, which needs a proxy and a target app; level 4 is
checking what a *specific* app sees, which is [`../../scripts/ns-diff.sh`](../../scripts/ns-diff.sh)
and lab 03.

---

## Known limits, stated up front

| Limit | Detail |
|---|---|
| **Android 14+** | The trust store moved into the Conscrypt APEX (`/apex/com.android.conscrypt/cacerts`). A `system/etc/security/cacerts` overlay is not what the runtime reads. `customize.sh` warns about this at install time; it does not work around it |
| **DenyList** | Adding an app to DenyList unmounts every Magisk mount in that app's namespace, including this one. The certificate disappears for exactly the app you wanted to intercept. This is measured in lab 03 and is not fixable by reinstalling |
| **Pinning** | An app that pins a certificate or ships its own trust store ignores the system store entirely. That is a different problem with a different answer |
| **Not a hiding measure** | This module makes root *more* detectable, not less: it adds mounts, and mount-table inspection is a standard root check |

---

## Cleanup

Leaving an interception CA in a device's system trust store is a real risk to that device. Remove it
when you are done:

```bash
# adb shell as root
touch /data/adb/modules/systemca/remove
reboot
# after the reboot:
ls /data/adb/modules/                              # systemca is gone
ls /system/etc/security/cacerts/ | wc -l           # back to the original count
```
