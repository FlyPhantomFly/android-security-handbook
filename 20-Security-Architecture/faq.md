# 20 — Security Architecture · FAQ

Real questions, including the ones people are embarrassed to ask.

---

### 1. Is Android secure?

The question has no answer as asked. Security is always relative to an adversary. Android is very strong against a malicious co-installed application, strong against a network attacker, strong against a physical attacker holding a powered-off device with a good credential, and *deliberately provides no defence at all* against the device's own owner acting on hardware they control. Ask which of the six adversaries in §1.4 you mean, and the question becomes answerable.

---

### 2. If I root my phone, have I "broken" Android's security?

You have withdrawn one specific guarantee: that only software approved by the manufacturer runs. Everything else still works. SELinux still enforces, the sandbox still separates apps, encryption still encrypts. What changes is that *you* now have a privileged position from which those controls can be adjusted, and that the device can no longer produce a hardware attestation saying it is locked. That last point is why banking apps object, and it is a reasonable objection: they cannot distinguish your rooted phone from a fraudster's.

---

### 3. Why does unlocking the bootloader wipe my data? It feels like punishment.

It is not punishment; it is the only thing that makes device encryption meaningful. If unlocking preserved data, the attack would be: steal a locked phone, unlock the bootloader, flash an image that dumps `/data`, read everything. The wipe is enforced by the bootloader itself, before any of your software runs, precisely so that no software can be tricked into skipping it.

---

### 4. What is the difference between Verified Boot and dm-verity? People use them interchangeably.

Verified Boot is the whole scheme: a chain of signature checks from silicon upward. dm-verity is one *component* of it — the kernel mechanism that protects large read-only partitions after the kernel is running, by checking each block against a Merkle tree whose root hash was signed as part of Verified Boot. Verified Boot verifies the small pieces eagerly and delegates the large pieces to dm-verity to be verified lazily.

---

### 5. Why doesn't Android just hash the whole system partition at boot and be done?

Because it is several gigabytes. Hashing it would add tens of seconds to every boot, and users will not accept that. It would also only prove the partition was intact *at that instant* — it would not stop a modification made afterwards through direct block-device writes. Lazy per-block verification is both faster and stronger.

---

### 6. How does Magisk get root without breaking dm-verity? This seems like magic.

It is not magic; it is a category distinction. dm-verity protects the *bytes in the partition*. Magisk never changes those bytes. It patches the boot image so that its own code runs as the first process, then uses Linux mount namespaces and bind mounts to make different files *appear* at paths like `/system/bin/su` for processes it chooses. The real `system` partition is byte-identical, so every hash still matches. The modification lives entirely in what each process is allowed to see.

---

### 7. So can an app detect Magisk by hashing files in `/system`?

Unreliably. The hash it computes depends on which mount namespace the app's process is in. Magisk's DenyList exists precisely to enter a target process's namespace and unmount the overlays before the app's code starts, so the app sees a pristine `/system`. Detection that works today typically looks for side effects — leftover mounts in `/proc/self/mountinfo`, unusual processes, the Zygisk injection — and those change with every Magisk release. Treat all of it as a delay, not a barrier.

---

### 8. What is the difference between DE and CE storage, in practice?

Device Encrypted storage is readable as soon as the device boots, before anyone types a PIN. Credential Encrypted storage is readable only after the user has unlocked at least once since boot. Your alarm clock must work at 6 a.m. after a 3 a.m. reboot, so it uses DE. Your messages must not be readable by someone who steals the phone and reboots it, so they use CE. An app opts into DE explicitly with `directBootAware` and `createDeviceProtectedStorageContext()`; everything else is CE by default.

---

### 9. What do BFU and AFU mean and why does every forensics person say them?

Before First Unlock and After First Unlock. In BFU the credential-encrypted keys do not exist anywhere in memory, so recovering user data requires defeating the credential through hardware that rate-limits attempts. In AFU those keys are resident in kernel memory, so any kernel-level compromise yields plaintext. The difference between the two states is often the difference between "nothing recoverable" and "everything recoverable", which is why examiners keep seized phones powered and why rebooting a phone before it is seized is meaningful.

---

### 10. If the phone is encrypted, why do I still need to worry about what an app stores locally?

Because encryption protects the device *at rest*, against someone who has the hardware and not the credential. It does nothing at runtime, when the device is unlocked and the data is decrypted for the app that owns it. It does nothing on a rooted device. And it does nothing against another process that the app has voluntarily given access to. Encryption answers "what if someone steals the phone", not "what if the app is careless".

---

### 11. Is Play Integrity just SafetyNet with a new name?

No. SafetyNet Attestation returned two booleans and has been retired. Play Integrity returns a structured set of verdicts covering the device, the app binary's Play provenance, the account's licensing, Play Protect's opinion, and the presence of screen-capture or overlay-capable apps. It is also more tightly integrated with hardware attestation, which is what makes `MEETS_STRONG_INTEGRITY` meaningful. The architectural lesson is unchanged: the token must be verified on your server.

---

### 12. Can Play Integrity be bypassed?

"Bypassed" is the wrong frame. On devices where a TEE keybox has leaked, attestation-spoofing modules have produced `MEETS_DEVICE_INTEGRITY` on modified devices; Google revokes known-abused keyboxes, so this is an ongoing contest. More commonly, what gets bypassed is not Play Integrity but the *app's use of it*: the app checks the verdict locally and a single Frida hook inverts the branch, or the backend never checks the nonce so a token is replayed. Those are implementation failures, and they are where you will find your findings.

---

### 13. The app I am testing checks `ro.debuggable` and `ro.build.tags`. Is that a finding?

Yes, and the way you phrase it matters. The finding is not "the app has root detection". The finding is that a security decision is made on the basis of normal-world system properties which any privileged process on the device can rewrite, so the control provides no assurance while creating the impression of assurance. The remediation is to move the decision server-side and anchor it in hardware key attestation. Demonstrate the bypass, then write the remediation as code.

---

### 14. Why is `targetSdkVersion` a security setting? I thought it was for compatibility.

Android gates hardening on it to avoid breaking old apps. Scoped storage, package visibility filtering, `PendingIntent` mutability requirements, background-start restrictions, and even which `untrusted_app_<n>` SELinux domain your process is assigned all depend on it. An app targeting API 28 running on Android 15 is genuinely subject to weaker platform enforcement than one targeting API 35 on the same device. A stale `targetSdkVersion` is therefore a legitimate finding on its own.

---

### 15. The device says patch level 2023-05-01 but the vendor says it is up to date. Who is lying?

Probably neither. `ro.build.version.security_patch` covers the system and framework; `ro.vendor.build.security_patch` covers vendor components and frequently lags. On top of that, Mainline/APEX modules update through Google Play independently of both, so the media stack, TLS stack, and permission controller may be current even when the build's patch string is old. Check all three: the system property, the vendor property, and `ls /apex/` with module versions.

---

### 16. What actually is a TEE? Is it a separate chip?

Usually not a separate chip. On ARM, TrustZone splits the *same* CPU into a "normal world" and a "secure world" by adding a hardware signal that propagates through the memory and bus fabric, so certain memory regions and peripherals are physically inaccessible to the normal world regardless of privilege level — the normal-world kernel cannot read secure memory even in kernel mode. A small trusted OS runs in the secure world. StrongBox *is* a separate chip, with its own CPU, RAM and storage, which is why it resists physical attacks better.

---

### 17. If everything on the device can be faked by root, why bother with any client-side control?

Three reasons. It raises attacker cost, which prices out casual and automated abuse — most fraud is opportunistic, not skilled. It generates telemetry: an app that reports "integrity signal X failed" gives your fraud team a feature to score on, even if any individual signal is forgeable. And it forces the attacker into a smaller, noisier set of behaviours that your server-side detection can spot. What you must never do is treat any of it as a *barrier*, or as a substitute for server-side enforcement.

---

### 18. Where do I actually start on a real engagement, given all of this?

Run the posture script from the cheat sheet and record the answers; that is your environment baseline and often produces a finding by itself on a corporate fleet. Then pull the APK and read the manifest. Then run the Frida integrity observer script for thirty seconds to learn what the app checks. Then proxy the traffic and look at what leaves the device and what the server accepts. Almost everything of value in a two-week engagement comes from those four steps and the depth you add to the last two — not from attacking the platform.

---

### 19. Do I need an unlocked bootloader and root to test an app?

Not for everything, but for anything worth calling a thorough test, yes. Without root you cannot read the app's private data directory, cannot inspect the databases and preferences, cannot attach Frida without repackaging the APK, and cannot see what the app writes. The alternative — repackaging the APK with a Frida gadget — works but changes the app's signature, which breaks signature-based checks and Play licensing checks, and therefore changes the behaviour you are trying to observe. Use a dedicated, unlocked research device.

---

### 20. Everyone says "don't fabricate CVE numbers". How seriously should I take that?

Extremely. A report is a professional document that the client may forward to their vendor, their auditor, or their regulator. One invented identifier that somebody looks up and finds is unrelated destroys the credibility of every other finding in the document, including the correct ones. If you know the vulnerability class but not the identifier, describe the class — that is both honest and more useful, because the class tells the developer what to look for across their whole codebase.
