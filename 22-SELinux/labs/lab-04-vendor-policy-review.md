# Lab 04 — Reviewing a Vendor Policy

**Difficulty:** Advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-reading-contexts.md), [Lab 02](lab-02-denial-to-rule.md), [Lab 03](lab-03-mcs-and-app-isolation.md), [Chapter 22 §5](../README.md#5-security-perspective), [§8](../README.md#8-static-analysis). **No root required.**

---

## Objective

Take a real device's vendor SELinux policy — the roughly one third of the total that **nobody outside the OEM has ever reviewed** — and systematically look for the seven finding shapes this chapter describes. Then write up whatever you find in a form a vendor engineer will act on rather than dismiss.

## Why this matters

On the reference device, measured:

| Policy fragment | Bytes |
|---|---|
| `/system/etc/selinux/plat_sepolicy.cil` | 1,981,460 |
| `/vendor/etc/selinux/vendor_sepolicy.cil` | 1,072,684 |
| `/system_ext/etc/selinux/system_ext_sepolicy.cil` | 328,536 |
| `/vendor/etc/selinux/plat_pub_versioned.cil` | 930,005 |

The platform half is written by Google, reviewed publicly, and covered by a large body of `neverallow` assertions and CTS tests. The **vendor** half is written by an OEM's platform team, usually under schedule pressure, usually without an SELinux specialist, and is reviewed by nobody outside the company. It is a million bytes of security policy with no external review, and it is where local privilege escalation on OEM builds lives.

Before Android 8 and Treble, a device had one policy. After it, a device has two, and only one of them has been looked at. That single structural fact is why this lab exists.

> **⚠️ Scope and legality**
> Analyse a device you own or are explicitly authorised to test. Reading policy files off a device is passive and harmless, but the *findings* you produce may be sensitive. If you find something serious on a shipped device, follow the vendor's disclosure process; [§5.13](../README.md#513-bug-bounty-patterns) discusses what triage teams accept.

---

## Setup

### Step 0 — Pull everything

```bash
# host
mkdir -p vendor-review && cd vendor-review

# platform, for comparison
adb pull /system/etc/selinux/plat_sepolicy.cil
adb pull /system/etc/selinux/plat_seapp_contexts
adb pull /system/etc/selinux/plat_service_contexts
adb pull /system/etc/selinux/plat_property_contexts
adb pull /system/etc/selinux/plat_file_contexts
adb pull /system/etc/selinux/plat_keystore2_key_contexts

# system_ext, if present
adb pull /system_ext/etc/selinux/system_ext_sepolicy.cil
adb pull /system_ext/etc/selinux/system_ext_seapp_contexts
adb pull /system_ext/etc/selinux/system_ext_service_contexts

# THE ONES THAT MATTER
adb pull /vendor/etc/selinux/vendor_sepolicy.cil
adb pull /vendor/etc/selinux/vendor_seapp_contexts
adb pull /vendor/etc/selinux/vendor_service_contexts
adb pull /vendor/etc/selinux/vendor_property_contexts
adb pull /vendor/etc/selinux/vendor_file_contexts
adb pull /vendor/etc/selinux/plat_pub_versioned.cil

# odm and product, if the device has them
adb pull /odm/etc/selinux/odm_sepolicy.cil
adb pull /product/etc/selinux/product_sepolicy.cil

ls -la
```

> **⚠️ Some pulls will fail silently.** On the reference device, `vendor_service_contexts`, `plat_hwservice_contexts` and `plat_mac_permissions.xml` were unreadable from a shell — they showed as `-?????????` in `ls -l`, which is the `getattr` denial pattern from Lab 02. If `adb pull` produces nothing, check for the denial rather than assuming the file is absent:
> ```bash
> adb logcat -d -b all | grep -a 'avc:' | grep -a getattr | tail
> ```

### Step 1 — Establish the ratio

```bash
# host
wc -c *.cil
```

**Question 1.** What fraction of your device's policy is vendor-written? Record the number. It is the first line of your write-up, because it establishes how much of the device's security policy has had no external review.

### Step 2 — Enumerate the vendor's own domains

```bash
# host — every type declared in vendor policy
grep -oE '^\(type [a-z_0-9]+' vendor_sepolicy.cil | awk '{print $2}' | sort -u > vendor_types.txt
wc -l vendor_types.txt

# which of them are running right now?
adb shell 'ps -A -Z' | awk 'NR>1 {split($1,a,":"); print a[3]}' | sort -u > running_domains.txt
comm -12 vendor_types.txt running_domains.txt
```

**Question 2.** How many vendor domains exist, and how many are actually running? A domain that exists but never runs is not zero-risk — it may be started on demand — but a running one is where to start.

---

## Part 1 — The seven finding shapes

Run each grep. For every hit, work out what the rule actually grants before deciding whether it matters.

### Shape 1 — `mlstrustedsubject` on a vendor domain

```bash
# host
grep -n 'typeattributeset mlstrustedsubject' vendor_sepolicy.cil
grep -n 'typeattributeset mlstrustedsubject' plat_sepolicy.cil
grep -n 'typeattributeset mlstrustedobject' vendor_sepolicy.cil plat_sepolicy.cil
```

**Why it matters.** As Lab 03 established, every MLS constraint in the policy ends with `(eq t1 mlstrustedsubject)`. A domain carrying that attribute is exempt from **all** of them, so the MCS categories that separate one app's private data from another's stop protecting anything from it.

**Question 3.** List every domain in the `mlstrustedsubject` set. Cross off the AOSP ones (`init`, `zygote`, `system_server`, `installd`, `vold`, and a handful of others — check `plat_sepolicy.cil` for the platform list). What is left is the vendor's addition. For each one, write one sentence justifying it, or flag it.

**The finding, if you find one:**

> "The vendor domain `<name>` carries the `mlstrustedsubject` attribute, exempting it from every MLS constraint in the loaded policy. The MCS categories that separate applications' private data therefore provide no protection against this domain. This is not itself an exploitable condition; its significance is that it converts any memory-safety or injection bug in `<name>` from a single-component compromise into disclosure of every application's private data on the device."

### Shape 2 — Dangerous capabilities

```bash
# host
grep -nE '\(allow [a-z_0-9]+ self \(capability \(' vendor_sepolicy.cil

# the ones that matter most
grep -nE '\(allow [a-z_0-9]+ self \(capability \(.*(dac_override|dac_read_search)' vendor_sepolicy.cil
grep -nE '\(allow [a-z_0-9]+ self \(capability \(.*sys_admin' vendor_sepolicy.cil
grep -nE '\(allow [a-z_0-9]+ self \(capability \(.*sys_module' vendor_sepolicy.cil
grep -nE '\(allow [a-z_0-9]+ self \(capability \(.*(setuid|setgid)' vendor_sepolicy.cil
grep -nE '\(allow [a-z_0-9]+ self \(capability2? \(' vendor_sepolicy.cil
```

| Capability | What it grants |
|---|---|
| `dac_override` | **ignore every file permission bit on the device** |
| `dac_read_search` | ignore read and search bits |
| `sys_admin` | mount, and a long list of other privileged operations — the "everything else" capability |
| `sys_module` | load a kernel module. Total compromise. |
| `sys_ptrace` | ptrace any process |
| `setuid` / `setgid` | become another user |
| `net_raw` | raw and packet sockets |
| `sys_rawio` | raw I/O port and `/dev/mem` access |

**Question 4.** For each hit, ask three questions: (a) is this domain reachable by anything less privileged? (b) does it parse untrusted input? (c) is the capability actually necessary, or was it a workaround for a labelling or ownership mistake?

`dac_override` in particular is almost always a workaround. The correct fix for "my daemon cannot read a file it should be able to read" is to fix the file's ownership or its label — not to give the daemon the ability to ignore ownership device-wide.

### Shape 3 — App domains reaching things they should not

```bash
# host — every rule whose SOURCE is an app domain
grep -nE '\(allow (appdomain|untrusted_app|untrusted_app_all|untrusted_app_2[579]) ' vendor_sepolicy.cil

# and the reverse: vendor domains reaching app data
grep -nE '\(allow [a-z_0-9]+ (app_data_file|privapp_data_file) ' vendor_sepolicy.cil
```

**Why it matters.** Any rule granting an app domain access to a vendor object is an expansion of the untrusted attack surface. AOSP's `untrusted_app` rule set is carefully minimal; every vendor addition widens it, and the widening is invisible unless you go looking.

**Question 5.** For every rule whose source is `appdomain` or `untrusted_app*`, name the target type and say what a malicious app could do with it. Sort them by how much you would mind.

**Question 6.** For rules where a vendor domain reaches `app_data_file` or `privapp_data_file` directly, compare with how `dex2oat` does it ([§3.12](../README.md#312-dex2oat-in-its-own-domain-a-real-trust-property-not-a-slogan)) — `read`/`write` on a *passed descriptor*, with `open` forbidden by a `neverallow`. Does the vendor rule grant `open`? If so, that domain can go looking rather than only acting on what it was given.

### Shape 4 — Abstract sockets with no DAC

```bash
# adb shell — what abstract sockets exist right now?
adb shell 'cat /proc/net/unix' | grep '@'
```

```bash
# host — who may reach them?
grep -nE 'unix_stream_socket \(.*connectto' vendor_sepolicy.cil
grep -nE 'unix_dgram_socket \(.*sendto'     vendor_sepolicy.cil
```

**Why it matters.** An abstract-namespace socket has **no filesystem entry at all**: no inode, no owner, no permission bits. DAC does not apply in any form. `connectto` is the only control that exists.

For comparison, the complete measured list of listeners an ordinary app may reach on the reference device's *platform* policy:

```lisp
(allow appdomain tombstoned (unix_stream_socket (connectto)))
(allow appdomain logd (unix_stream_socket (connectto)))
(allow appdomain adbd (unix_stream_socket (connectto)))
(allow untrusted_app_all traced (unix_stream_socket (connectto)))
(allow untrusted_app_all heapprofd (unix_stream_socket (connectto)))
(allow untrusted_app_all traced_perf (unix_stream_socket (connectto)))
(allow untrusted_app_all runas_app (unix_stream_socket (connectto)))
```

Seven. That is the whole list, and its shortness is the design.

**Question 7.** Does your device's vendor policy add any `connectto` rule whose source is `appdomain`, `untrusted_app` or `untrusted_app_all`? If so, identify the target daemon, work out what it does, and write the finding.

**The finding shape:**

> "Policy grants `<app domain>` the `unix_stream_socket:connectto` permission on the vendor daemon `<name>`. `<name>` binds an abstract-namespace socket (`@<name>` in `/proc/net/unix`), which carries no filesystem entry and therefore no Unix permission bits — SELinux is the only access control on it. Any third-party application on the device can therefore open a connection to `<name>` with no permission request and no user interaction, and the daemon's own input handling is the entire security boundary between untrusted application code and `<what the daemon can do>`."

### Shape 5 — Default-label over-grants

```bash
# host
grep -nE 'allow .* default_android_service ' vendor_sepolicy.cil
grep -nE 'allow .* (default_prop|vendor_default_prop) '  vendor_sepolicy.cil
grep -nE 'allow .* unlabeled ' vendor_sepolicy.cil
grep -nE 'allow .* (device|system_file|vendor_file) ' vendor_sepolicy.cil | grep -v neverallow
```

**Why it matters.** A *default* type is the fallback for any object the relevant contexts file did not name. Granting access to a default type grants access to **every** object that fell through — including objects added later by a different team who forgot to label theirs. It is a rule that becomes more permissive over time without anyone editing it.

`unlabeled` deserves particular attention: it means "the system could not determine a label at all", which is sometimes a set an attacker can influence by creating files in unexpected places.

The measured denial from the reference device shows the *benign* direction of this trap:

```
avc: denied { find } for pid=2396 uid=10028 name=USDKPlus
  scontext=u:r:priv_app:s0:c512,c768
  tcontext=u:object_r:default_android_service:s0
  tclass=service_manager permissive=0
```

A vendor registered a Binder service and forgot to add it to `service_contexts`. It landed on `default_android_service`, no `find` rule exists, and the vendor's own privileged app cannot reach it — so it retries in a loop. The dangerous "fix" is a rule granting `find` on the default type.

**Question 8.** Enumerate what actually falls to the default types on your device:

```bash
# adb shell — every registered Binder service
dumpsys -l | tail -n +2 | tr -d ' ' | sort > /sdcard/services.txt
```

```bash
# host
adb pull /sdcard/services.txt
# names present in service_contexts
grep -oE '^[a-zA-Z0-9._-]+' plat_service_contexts vendor_service_contexts 2>/dev/null \
  | sed 's/.*://' | sort -u > labelled.txt
comm -23 services.txt labelled.txt
```

Anything in the output has fallen to `default_android_service`. Is any of it interesting?

### Shape 6 — Vendor `seapp_contexts` that a third-party app can claim

```bash
# host — the single highest-yield line in this lab
grep 'name=' vendor_seapp_contexts | grep -v 'seinfo=' | grep -v 'isPrivApp='
```

**Why it matters.** `seinfo=` is derived from the APK's **signing certificate**, via `mac_permissions.xml`, and is assigned by `PackageManagerService` at scan time. A third-party app cannot forge it. `isPrivApp=` requires installation in a `priv-app/` directory in the system image. But `name=` is just a package name, and an app chooses its own.

A vendor line of the form:

```
user=_app name=com.vendor.helper domain=vendor_helper_app type=vendor_app_data_file levelFrom=user
```

with no `seinfo=` and no `isPrivApp=` means **any app that installs itself under that package name lands in `vendor_helper_app`** — with whatever permissions that domain has.

The measured reference device's vendor file, for comparison, gets this right — all four lines require `seinfo=platform`:

```
user=_app seinfo=platform name=com.trustonic.tuiservice domain=mobicore_app type=app_data_file levelFrom=user
user=_app seinfo=platform name=com.mediatek.emcamera domain=emcamera_app type=app_data_file levelFrom=user
user=_app seinfo=platform name=com.mediatek.sensorhub.ui domain=sensorhub_app type=app_data_file levelFrom=user
user=_app seinfo=platform name=com.android.simulate.printer.server domain=simulate_app type=simulate_app_data_file levelFrom=user
```

**Question 9.** If your device *does* have such a line, work out (a) whether the named package is actually installed (if it is, you cannot claim the name), and (b) what the target domain is permitted to do. Then write the finding.

**Question 10.** Even where the lines are correct, look at the *domains* they create. `mobicore_app`, `emcamera_app`, `sensorhub_app`, `simulate_app` — none of these exists in AOSP, so none has been reviewed. What can each of them do?

```bash
# host
for d in mobicore_app emcamera_app sensorhub_app simulate_app; do
  echo "=== $d ==="
  grep -cE "^\(allow $d " vendor_sepolicy.cil
done
```

### Shape 7 — Keystore, and the two permissions that matter

```bash
# host
grep -nE 'keystore2_key \(' vendor_sepolicy.cil
grep -nE 'keystore2_key \(.*(manage_blob|use_dev_id|gen_unique_id)' \
    vendor_sepolicy.cil plat_sepolicy.cil
grep -nE 'keystore_key \('  vendor_sepolicy.cil
```

Measured on the reference device's platform policy, exactly one domain holds each of the three:

```lisp
(allow vold vold_key (keystore2_key (convert_storage_key_to_ephemeral delete
  get_info manage_blob rebind req_forced_op update use)))
(allow system_server keystore (keystore2_key (delete get_info grant rebind
  update use use_dev_id)))
(allow gmscore_app keystore (keystore2_key (gen_unique_id)))
```

| Permission | What it grants | Who has it on stock AOSP |
|---|---|---|
| `manage_blob` | supply or retrieve **raw KeyMint blobs** — key *material*, not key *use* | `vold` only |
| `use_dev_id` | include IMEI, MEID and serial number in an attestation | `system_server` only |
| `gen_unique_id` | request the attestation unique ID | `gmscore_app` only |

**Question 11.** Does your vendor policy grant any of the three to a domain outside that set? A vendor grant of `manage_blob` is a strong finding, because it is one of the very few permissions in the class that touches key material.

---

## Part 2 — What is *missing* from the vendor policy

Everything above looks for rules that are too broad. This part looks for the absence of the things a considered policy contains.

### Step 3 — Count the assertions

```bash
# host
echo "platform allow:      $(grep -c '^(allow ' plat_sepolicy.cil)"
echo "platform neverallow: $(grep -c '^(neverallow ' plat_sepolicy.cil)"
echo "vendor allow:        $(grep -c '^(allow ' vendor_sepolicy.cil)"
echo "vendor neverallow:   $(grep -c '^(neverallow ' vendor_sepolicy.cil)"
```

**Question 12.** What is the ratio of `allow` to `neverallow` in each? This is the single best proxy for whether the policy was *designed* or *accumulated*.

A vendor policy with tens of thousands of `allow` rules and no `neverallow` assertions of its own tells you that the team ran `audit2allow` until the denials stopped and never wrote down what the design was supposed to be. That is not a finding you can report on its own, but it is a strong prior for everything else in this lab.

**Question 13.** Note the caveat, though: `neverallow` is **compile-time only** ([§3.16](../README.md#316-neverallow-dontaudit-auditallow-and-the-rules-that-are-not-rules)). A high count means the vendor thought about design; it does **not** mean the shipped device enforces anything extra. State that distinction in your write-up so a reader does not draw the wrong conclusion.

### Step 4 — Permissive domains

```bash
# host — the only reliable check from a stock shell
adb logcat -d -b all | grep -a 'permissive=1'
```

If you have the binary policy:

```bash
# host, with AOSP host tools
sepolicy-analyze policy.bin permissive
```

To build a binary policy from the CIL you pulled, without root:

```bash
# host, needs secilc from an AOSP checkout
secilc -m -M true -c 31 -o policy.bin -f /dev/null \
    plat_sepolicy.cil system_ext_sepolicy.cil vendor_sepolicy.cil
sepolicy-analyze policy.bin permissive
```

**Question 14.** Are there any? On the reference device the `permissive=1` grep returned nothing, which is correct for a stock `user` build. A hit here is a report-ready finding: it fails CTS and it fails Play Integrity, so it usually gets fixed.

### Step 5 — Who may end the game

```bash
# host
grep -nE '\(allow [a-z_0-9]+ kernel \(security \(' vendor_sepolicy.cil plat_sepolicy.cil
grep -nE 'security \(.*(setenforce|load_policy|setbool)' vendor_sepolicy.cil plat_sepolicy.cil
```

**Question 15.** `security:setenforce` and `security:load_policy` are the two permissions that end the MAC layer entirely. On a stock device essentially nothing outside `init` has them. Does your vendor policy grant either to anything? If so, that is the highest-severity finding available in this lab.

---

## Part 3 — Correlate with what is actually running

Static policy review tells you what is *permitted*. Pair it with what is *happening*.

### Step 6 — Denials from vendor domains

```bash
# host
adb logcat -d -b all | python3 ../scripts/avc-decode.py - --group --rules-only > all_rules.txt
cat all_rules.txt
```

Filter to vendor domains:

```bash
# host
while read -r d; do
  grep -H "allow $d " all_rules.txt
done < vendor_types.txt
```

**Question 16.** Every denial from a vendor domain tells you something the vendor's own code is *trying* to do. Some of it is benign probing; some of it reveals design intent that did not make it into policy. Which of your device's vendor-domain denials would you investigate further, and why?

### Step 7 — What the vendor daemons actually touch

```bash
# adb shell — for each running vendor domain, what is the process?
ps -A -Z | grep -E 'mtk_|qti_|exynos_|<your OEM prefix>'
```

**Question 17.** Pick the vendor domain with the broadest rule set (highest `grep -c` from Question 10). Read its rules end to end. Write a one-paragraph description of what a full compromise of that process would give an attacker, in terms of concrete capabilities rather than rule names.

---

## Part 4 — Write it up

### The structure that gets acted on

For each finding:

| Section | Content |
|---|---|
| **Title** | The rule, not the consequence. "Vendor domain `foo` carries `mlstrustedsubject`" beats "SELinux misconfiguration". |
| **Evidence** | The exact rule, quoted verbatim, with the file and line number from *your* pull. Never paraphrase a rule. |
| **What it grants** | In concrete terms: "read access to every application's private data", not "elevated privileges". |
| **What it does NOT do** | Say this explicitly. Most of these findings are **impact amplifiers**, not vulnerabilities. Saying so first is what makes the rest credible. |
| **Reachability** | Can anything less privileged reach this domain? If not, severity drops sharply. |
| **Remediation, as policy** | Write the replacement rules. A finding with a diff attached gets fixed; one without gets triaged into next quarter. |
| **Severity** | With the reasoning shown. |

### The paragraph that saves an argument

Somewhere in the report, include the denial-severity paragraph from [§5.9](../README.md#59-honest-severity-an-avc-denial-is-not-a-finding), adapted to your numbers:

> "The device logged **N** SELinux audit records during the assessment. All **N** resolve to **M** distinct denial shapes, of which **K** are platform components being refused operations they probe for optionally and handle gracefully. Denial records are evidence that the mandatory access control layer is operating; a device producing none would be more concerning, not less. The findings below are drawn from *policy review*, not from the denial log."

That last sentence is the important one. It tells the reader that you know the difference, which is what makes them believe the rest.

**Question 18.** Produce a findings table for your device:

| # | Shape | Domain / rule | What it grants | Reachable by | Severity | Remediation |
|---|---|---|---|---|---|---|

Include at least one row that you have marked **"not a finding"** with the reasoning — for example, a broad-looking rule on a domain that nothing less privileged can reach. Being able to *rule things out* credibly is as valuable as finding them.

---

## Part 5 — The hard version (optional)

If you want to do this properly, compare the vendor policy against clean AOSP.

```bash
# host — requires an AOSP checkout of the same release, built
# 1. build the AOSP policy for the same API level
# 2. sort both, because CIL statement order is not meaningful
sort vendor_sepolicy.cil > vendor.sorted
sort aosp_vendor_sepolicy.cil > aosp.sorted
diff aosp.sorted vendor.sorted | grep '^>' | grep '(allow ' > vendor_added.txt
wc -l vendor_added.txt
```

**Question 19.** How many rules did the vendor add relative to the AOSP baseline for the same release? That number, and a categorisation of those rules, is the difference between "the vendor policy looks broad" and "the vendor added 412 rules, of which these 6 grant an app domain access to a privileged daemon."

This is real work — obtaining and building a matching AOSP tree is not trivial — and it is what separates a policy review from a policy grep.

---

## Hints

<details>
<summary>Everything I grep returns hundreds of lines</summary>

That is normal and it is why the greps are ordered. Work them in the order given: Shape 1 (`mlstrustedsubject`) usually returns fewer than ten lines and is the highest-value. Shape 6 (`seapp_contexts` with `name=` and no `seinfo=`) usually returns zero or one.

Do not start with Shape 3, which returns the most and means the least without context.
</details>

<details>
<summary>My device has no vendor_sepolicy.cil</summary>

Three possibilities:

1. It is a pre-Treble device (Android 7 or earlier), where there is one monolithic policy. Everything is in the platform file.
2. It is a Google Pixel or an AOSP build, where vendor policy is small or absent.
3. The file is unreadable from your shell. Check for a `getattr` denial.

An emulator has essentially no vendor policy, which makes it a poor target for this lab. Use a physical OEM device.
</details>

<details>
<summary>How do I know which mlstrustedsubject entries are AOSP?</summary>

Compare against the platform file:

```bash
grep -A2 'typeattributeset mlstrustedsubject' plat_sepolicy.cil
grep -A2 'typeattributeset mlstrustedsubject' vendor_sepolicy.cil
```

The platform set is the baseline. Anything in the vendor set that is not in the platform set is the vendor's addition. Note that the attribute *set* may be declared once and added to in both files, so check both.
</details>

<details>
<summary>I found something. How serious is it?</summary>

Ask, in order:

1. **Is the domain reachable?** A domain nothing less privileged can talk to is much less interesting, regardless of what it can do.
2. **Does it parse untrusted input?** A parser is a plausible bug site; a state machine driven only by `init` is not.
3. **Does the rule remove a control, or grant a capability?** `mlstrustedsubject` removes a control — it is an amplifier. `sys_module` grants a capability — it is closer to a direct issue.
4. **Would exploitation require a second bug?** Almost always yes, and saying so is what makes the finding credible.

Most findings in this lab are Medium on their own and High-to-Critical when chained. Say so, and show the chain.
</details>

---

## Success criteria

You can, without notes:

1. State what fraction of a device's policy is vendor-written and why that matters structurally.
2. Run the seven finding-shape greps from memory, in the right order.
3. Explain, for each shape, what the rule grants in concrete terms.
4. Distinguish an impact amplifier from a vulnerability, and say why the distinction makes a report credible rather than weaker.
5. Explain why `neverallow` count is a good proxy for design quality but *not* a runtime protection.
6. Enumerate what has fallen to a default type on a real device.
7. Write a finding with evidence, reachability, remediation-as-policy, and reasoned severity.
8. Rule something out credibly.

## Deliverable

A written review of one device's vendor policy, containing:

- the size ratio and what it implies;
- the seven grep results, with hits explained and misses noted;
- a findings table with at least one entry marked "not a finding", with reasoning;
- the denial-severity paragraph, adapted to your device's actual numbers;
- remediation written as policy, not as prose, for at least one finding.

Four to eight pages. If it is longer than that, you are including the greps rather than their conclusions.

---

## Next

[Lab 05 — CTF: The Quiet Domain](lab-05-ctf-the-quiet-domain.md). Everything from Labs 01–04, applied to a constructed policy with a flag in it.
