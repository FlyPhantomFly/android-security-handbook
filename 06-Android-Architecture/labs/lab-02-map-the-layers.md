# Lab 02 — Map Every Process to Its Layer

**Difficulty:** Intermediate
**Time:** 90–120 minutes
**Prerequisites:** [Lab 01](lab-01-trace-the-boot.md), [Chapter 06 §2, §5](../README.md),
a rooted device or emulator

---

## Objective

Take a running device and account for **every** process: which architectural layer it belongs to, what
privilege it holds, and whether that privilege is justified. Then find the anomalies.

## Why this matters

A `ps` listing is data. A privilege map is an assessment.

On an OEM device the productive findings are almost never in AOSP — they are vendor daemons running
with more privilege than they need, exposing IPC endpoints outside the framework's permission model.
This lab is the systematic way to find them, and it is the same procedure whether you have thirty
minutes or three days.

---

## Setup

```bash
# host
adb shell getprop ro.product.manufacturer
adb shell getprop ro.product.model
adb shell getenforce
adb shell 'command -v su >/dev/null && echo "root available" || echo "no root"'
```

Root substantially improves coverage (capabilities, sockets, `/proc` access for other UIDs). Without
it you can still complete most of the lab.

---

## Steps

### Step 1 — The raw census

```bash
# adb shell
ps -A -o USER,PID,PPID,NAME | head -50
ps -A | wc -l
```

**Q1.** How many processes are running? Roughly what proportion are apps?

### Step 2 — Group by UID class

```bash
# adb shell
ps -A -o USER | tail -n +2 | sed -E 's/^(u[0-9]+_a)[0-9]+$/\1NNN/; s/^(u[0-9]+_i)[0-9]+$/\1NNN/' \
  | sort | uniq -c | sort -rn
```

Fill in the layer for each UID class using the table in §6.2 of the chapter:

| UID class | Count | Layer | Notes |
|---|---|---|---|
| `root` | | | |
| `system` | | | |
| `shell` | | | |
| `u0_aNNN` | | | |
| `u0_iNNN` | | | |
| others | | | |

**Q2.** Which UID class has the most processes? Is that what you expected?

**Q3.** `shell` appears in the list. Which layer is it, and why is it emphatically **not** an app?
(This distinction decides whether a finding is real — see [77](../../77-UsefulCommands/README.md).)

### Step 3 — Group by SELinux domain

```bash
# adb shell
ps -A -Z | tail -n +2 | awk '{print $1}' | sed 's/^u:r://; s/:s0.*//' \
  | sort | uniq -c | sort -rn | head -30
```

**Q4.** How many distinct domains are there? Which has the most processes?

**Q5.** Find the app domains (`untrusted_app*`). Are there several variants
(`untrusted_app_27`, `untrusted_app_29`, `untrusted_app_30`…)? What determines which an app gets?
See [22-SELinux](../../22-SELinux/README.md).

### Step 4 — Examine one app's privilege in full

```bash
# adb shell
PID=$(pidof -s com.android.settings)   # or any app
cat /proc/$PID/status | grep -E '^(Name|Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|Seccomp|NoNewPrivs):'
cat /proc/$PID/attr/current
```

Record the values:

| Field | Value | Expected |
|---|---|---|
| `Uid` | | 10000+ |
| `Gid` | | matches |
| `Groups` | | 3003 if it has INTERNET |
| `CapEff` | | `0000000000000000` |
| `Seccomp` | | `2` |
| `NoNewPrivs` | | `1` |
| SELinux context | | `u:r:untrusted_app_XX:s0:cNNN,cNNN` |

**Q6.** Is `CapEff` all zeros? What would a non-zero value mean?

**Q7.** What is `Seccomp: 2`, and which function installed that filter? (See §4.3 of the chapter.)

**Q8.** The SELinux context ends with two MCS categories such as `c512,c768`. What do they provide
that the domain alone does not?

### Step 5 — Compare an app against system_server

```bash
# adb shell
SPID=$(pidof -s system_server)
cat /proc/$SPID/status | grep -E '^(Uid|Gid|Groups|CapEff|Seccomp|NoNewPrivs):'
cat /proc/$SPID/attr/current
```

**Q9.** Compare the two side by side. How many supplementary groups does `system_server` have? Is its
`CapEff` empty? Is seccomp active?

**Q10.** Why is `system_server` such a high-value target, and what is the characteristic vulnerability
class against it?

### Step 6 — Audit the root processes

```bash
# adb shell
ps -A -o USER,PID,NAME | awk '$1=="root" {print $3}' | sort
```

Now filter out the ones you expect on any AOSP device:

```bash
# adb shell
ps -A -o USER,NAME | awk '$1=="root" {print $2}' | sort -u \
  | grep -vE '^(init|ueventd|logd|lmkd|vold|servicemanager|hwservicemanager|vndservicemanager|healthd|installd|netd|zygote|zygote64|apexd|keystore2?|traced.*|\[.*\]|k[a-z]+/?[0-9]*|migration.*|rcu_.*|ksoftirqd.*|kworker.*|watchdogd|kswapd.*)$'
```

**Q11.** What remains? These are the vendor's additions — the productive part of the assessment.

For each one:

```bash
# adb shell — find its init entry and read its privilege budget
grep -rA12 "^service .*<name>" /vendor/etc/init/ /system/etc/init/ /odm/etc/init/ 2>/dev/null
```

**Q12.** For each vendor daemon, record: `user` (absent = root), `group`, `capabilities`, `seclabel`,
and any `socket` declarations with their mode. Which have more privilege than their name suggests they
need?

### Step 7 — Find world-accessible IPC endpoints

This is where the findings usually are.

```bash
# adb shell as root
ls -l /dev/socket/
ls -l /dev/socket/ | awk '$1 ~ /rw.rw.rw|srw.rw.rw/'
```

**Q13.** Any sockets with mode `0666`? Who owns them, and which daemon created them?

```bash
# adb shell as root — abstract-namespace sockets have NO filesystem permissions at all
cat /proc/net/unix | awk '$NF ~ /^@/ {print $NF}' | sort -u
```

**Q14.** How many abstract sockets are there? Why is the abstract namespace a distinct concern from
filesystem sockets? See [24-IPC](../../24-IPC/README.md).

```bash
# adb shell — localhost TCP listeners: reachable by any app holding INTERNET
netstat -tlnp 2>/dev/null | grep -E '127\.0\.0\.1|::1'
```

**Q15.** Any localhost listeners? Which process owns each, and what does it do?

### Step 8 — Verify with the script

```bash
# host
../scripts/layer-census.sh --detail
../scripts/layer-census.sh --anomalies
../scripts/layer-census.sh --pkg com.android.settings
```

**Q16.** Does the script agree with your manual analysis? Did it flag anything you missed, or miss
anything you found?

### Step 9 — Write the assessment

Produce a one-page privilege map:

1. A table of layers with process counts
2. The list of non-AOSP root processes, with each one's privilege budget
3. Any world-accessible sockets or localhost listeners
4. Anything anomalous about app-process privilege
5. For each concern: what an attacker gains, and what you would need to prove it

**Q17.** Which of your observations are **findings**, and which are merely **notes**? Justify the
distinction for at least two of them.

---

## Hints

<details>
<summary>Hint 1 — pidof returns nothing</summary>

The app may not be running. Launch it first:
```bash
adb shell monkey -p com.android.settings -c android.intent.category.LAUNCHER 1
```
Or list what is running: `adb shell ps -A | grep -i settings`
</details>

<details>
<summary>Hint 2 — cannot read /proc/&lt;pid&gt;/status for another UID</summary>

Most fields are readable, but some need root:
```bash
adb shell "su -c 'cat /proc/$PID/status'"
```
Without root you can still fully inspect processes you own, and `ps -Z` still works for all.
</details>

<details>
<summary>Hint 3 — the vendor filter leaves too much / too little</summary>

The filter in Step 6 is a starting point, not gospel — vendors name things unpredictably. A more
reliable approach is to work from the init files rather than from `ps`:

```bash
adb shell "ls /vendor/etc/init/ /odm/etc/init/ 2>/dev/null"
```

Anything defined there is by definition a vendor addition.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q3.** `shell` is UID 2000 — the identity `adbd` and your `adb shell` run as. It is **not** an app.
It holds developer privileges an app does not have, which is why a finding demonstrated only from
`adb shell` is not yet a finding: you must reproduce it from an ordinary app UID. This is the single
most common false positive in mobile reports.

**Q5.** The `untrusted_app_NN` variants correspond to `targetSdkVersion` ranges. Older-targeting apps
land in more permissive domains for compatibility, which is one more reason a low `targetSdk` is worth
reporting — it changes the app's SELinux domain, not just its framework defaults.

**Q6.** All zeros is correct and expected: `SpecializeCommon()` calls `capset()` to drop every
capability before app code runs. A non-zero `CapEff` on an app process is highly anomalous and worth
investigating immediately — it means the process was not created through the normal Zygote path.

**Q7.** `Seccomp: 2` means a BPF filter is installed. `SetUpSeccompFilter()` inside
`SpecializeCommon()` installs it, using the allow-lists in `bionic/libc/seccomp/`. It removes the
large portion of the kernel syscall surface that apps never legitimately need, shrinking what a
sandbox escape has to work with.

**Q8.** The MCS categories give **per-app isolation within a shared domain**. Every untrusted app
shares the `untrusted_app` domain, so type enforcement alone would not separate them; the two
per-app categories do. It is how two apps in the same domain still cannot read each other's data.

**Q9–Q10.** `system_server` has many supplementary groups and substantial capabilities — it must, to
do its job. It is high-value precisely because it is privileged **and** reachable over Binder by every
app on the device by design. The characteristic vulnerability is the **confused deputy**: performing a
privileged action on an app's behalf without checking that the app was entitled to request it. Note
this is a bug in the service, not in Binder — Binder delivers an unspoofable caller UID; the service
simply has to check it.

**Q13–Q15.** A `0666` socket is reachable by every app on the device, entirely outside the framework
permission model — no permission check, no Binder UID verification. Abstract-namespace sockets are
worse in one respect: they have **no filesystem permissions at all**, so there is not even a mode bit
to get wrong. Localhost TCP listeners are reachable by any app holding `INTERNET`, which is almost
every app. All three are real, recurring findings on OEM devices.

**Q17.** The distinction that matters: an observation about the **device as shipped** with a
demonstrable attacker benefit is a finding. An observation about **your own rooted test device**, or
about a privilege that is justified and correctly constrained, is a note. Stating which is which — and
why — is what makes a report credible.

</details>

---

## Success criteria

- [ ] You produced a complete census grouped by both UID class and SELinux domain
- [ ] You can state why `shell` is not an app, and what that means for reporting
- [ ] You inspected one app's full privilege and confirmed empty capabilities, seccomp and `NoNewPrivs`
- [ ] You explained what the MCS categories add over the domain alone
- [ ] You compared an app against `system_server` and can articulate the confused-deputy risk
- [ ] You isolated the non-AOSP root processes and read at least three init entries
- [ ] You enumerated world-accessible sockets, abstract sockets and localhost listeners
- [ ] Your manual analysis agrees with `layer-census.sh`
- [ ] You produced a one-page privilege map separating findings from notes, with justification
