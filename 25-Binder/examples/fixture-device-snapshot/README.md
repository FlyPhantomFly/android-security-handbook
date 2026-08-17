# fixture-device-snapshot — a real device's Binder state, frozen

Everything in this directory was captured from a **physical device** with
`scripts/binder-service-map.py --capture`. Nothing is synthetic or illustrative. It exists
so that every lab in this chapter can be completed with no device attached, and so that the
numbers quoted in `README.md` can be checked rather than believed.

> **One edit was made before committing, and it is not to any measurement.** Three
> processes in `ps.txt` are third-party commercial applications that were installed on the
> device; their package names are written `com.vendor.<category>`, per
> [72-RealWorldFindings §4](../../../72-RealWorldFindings/references/README.md). Every PID,
> UID, SELinux label, service name and count is the real captured value, and platform and
> OEM system packages keep their real names — those are the operating system this snapshot
> exists to show.

| | |
|---|---|
| Device | Xiaomi M2101K6P (codename `sweetin`) |
| Android | 11 |
| API level | 30 |
| ABI | `arm64-v8a` |
| Kernel | `4.14.180-perf` |
| Security patch | 2021-12-01 |
| Capturing identity | `adb shell`, uid 2000, SELinux context `u:r:shell:s0` |
| Root | **no** — every file here is world-readable to the `shell` domain |

> **⚠️ Warning**
> This is **not** a stock AOSP build. It is MIUI, and it registers services that AOSP does
> not (`MiuiBackup`, `MiuiInit`, `ProcessManager`, `xiaomi.joyose`, `SlaveWifiService`).
> That is the point — a real device is not the emulator, and OEM services are where a
> disproportionate share of real Binder findings live. Do not quote counts from this
> snapshot as "Android 11 has N services"; quote them as "this device had N".

## The files

| File | Device command | What it is |
|---|---|---|
| `service_list.txt` | `service list` | Every name registered with `servicemanager`, with the interface descriptor each object reports. 217 services. |
| `ps.txt` | `ps -A -o PID,USER,LABEL,NAME` | The process table with SELinux domains. 802 processes. |
| `plat_service_contexts.txt` | `cat /system/etc/selinux/plat_service_contexts` | AOSP's mapping from service **name** to SELinux **type**. This is the target of the `service_manager:find` check. |
| `system_ext_service_contexts.txt` | `cat /system_ext/etc/selinux/system_ext_service_contexts` | The same, for `/system_ext`. This is where the MIUI service labels live. |
| `product_service_contexts.txt` | `cat /product/etc/selinux/product_service_contexts` | The same, for `/product`. |
| `vnd_service_contexts.txt` | `cat /vendor/etc/selinux/vndservice_contexts` | Names registered on **`/dev/vndbinder`**, a separate namespace that apps cannot open at all. |
| `getprop.txt` | four `getprop` reads | Build identity, so the snapshot cannot be mistaken for another device's. |

`plat_hwservice_contexts` and `vendor_service_contexts` are **absent on purpose**: both were
`Permission denied` to uid 2000 on this device. An honest fixture reproduces what you can
actually read, not what you wish you could.

## Using it

```bash
# host — no device needed
cd ../../scripts
python3 -B binder-service-map.py --fixture ../examples/fixture-device-snapshot
python3 -B binder-service-map.py --fixture ../examples/fixture-device-snapshot --explain notification
python3 -B binder-service-map.py --fixture ../examples/fixture-device-snapshot --no-interface
```

## Make your own

```bash
# host, with your own device attached
python3 -B binder-service-map.py --capture ./my-snapshot
python3 -B binder-service-map.py --fixture ./my-snapshot
```

Diffing two snapshots — stock against an OEM build, or one ROM version against the next — is
the fastest way to find services that were added without being labelled. See
[`../../labs/lab-01-service-list-and-call.md`](../../labs/lab-01-service-list-and-call.md).
