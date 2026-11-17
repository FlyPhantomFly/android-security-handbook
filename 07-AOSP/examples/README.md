# 07 — AOSP: Examples

Runnable material for [README.md §9](../README.md#9-examples).

| File | Section | What it demonstrates |
|---|---|---|
| [`01-trace-worksheet.md`](01-trace-worksheet.md) | §4, §9.1–9.2 | A blank worksheet for tracing any API to its enforcement point, plus a fully worked example |
| [`02-HiddenApiProbe.kt`](02-HiddenApiProbe.kt) | §3.8 | Reach a hidden API by reflection, observe the blocklist denying it, and see the policy setting change the outcome |
| [`03-binder-service-probe/BinderProbe.kt`](03-binder-service-probe/BinderProbe.kt) | §5.3.1, §9.4 | Enumerate and call a Binder service by raw `Parcel` transaction from a zero-permission app |
| [`03-binder-service-probe/AndroidManifest.xml`](03-binder-service-probe/AndroidManifest.xml) | §5.3.1 | The manifest that proves the app holds no permissions at all |
| [`04-binder-trace.patch`](04-binder-trace.patch) | §3.10, §9.3 | A reviewed AOSP patch adding system-wide Binder tracing |
| [`05-research-env/setup.sh`](05-research-env/setup.sh) | §9.5 | Reproducible AOSP research environment: pinned sync, patch series, build, boot |

---

## Running order

1. **`01-trace-worksheet.md`** first, with nothing but a browser. It costs no setup and it is the skill
   the rest of the chapter is built on.
2. **`02-HiddenApiProbe.kt`** next, on any device you have adb access to. It demonstrates the one
   platform setting that most changes what your tooling can do.
3. **`03-binder-service-probe/`** when you have a device with a vendor service to probe. Read
   [`../scripts/binder-service-enum.sh`](../scripts/binder-service-enum.sh) output first to know what to
   aim at.
4. **`04-binder-trace.patch`** and **`05-research-env/setup.sh`** when you are ready to build. Budget a
   day; see [Lab 02](../labs/lab-02-build-and-boot-aosp.md).

---

> **** `03-binder-service-probe/` calls services on a device. Only run it against a device you are
> authorised to test. Calling an unknown vendor service with an arbitrary transaction code can crash
> `system_server` and reboot the device — which is itself a (denial-of-service) finding, but make sure
> that is a result you intended and are permitted to produce.

> **** `04-binder-trace.patch` produces a **research instrument**, not evidence. Every finding
> demonstrated on a patched image must be reproduced on an unmodified one before it goes in a report,
> and the report must say which image each piece of evidence came from.
