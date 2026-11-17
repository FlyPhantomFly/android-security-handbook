# Lab 05 — CTF: The Quiet Domain

**Difficulty:** CTF
**Time:** 2–4 hours
**Prerequisites:** [Lab 01](lab-01-reading-contexts.md), [Lab 02](lab-02-denial-to-rule.md), [Lab 03](lab-03-mcs-and-app-isolation.md), [Lab 04](lab-04-vendor-policy-review.md). **No device required.** Everything you need is in [`ctf-quiet-domain/`](ctf-quiet-domain/).

---

## The brief

You are handed the SELinux artefacts from a mid-range handset — the **Aurora Mobile AM-7**, Android 13, API 33 — as part of a pre-release security review. The vendor's platform team says the policy is clean: "we ran it for a week, there are barely any denials, and none of them are ours."

They are right that there are barely any denials. That is the problem.

Your job is to find a path by which **an application any user could install from a store, with no permissions requested and no user interaction, ends up reading another application's private database.**

There is a flag. It is assembled from four values you will have derived by the time you have the whole chain, so if you have the chain you have the flag.

---

## Artefacts

```
labs/ctf-quiet-domain/
├── vendor_sepolicy.cil       the vendor policy fragment
├── vendor_seapp_contexts     which apps land in which vendor domains
└── avc.log                   one uptime's audit records
```

> **These artefacts are SYNTHETIC.** They are constructed for this exercise in the exact formats a real device uses, but the domains, daemons and rules are invented. Every file says so in its header. Do not quote anything from them as evidence of real platform behaviour — the measured, real material is in [`../examples/`](../examples/).
>
> The rules are, however, **realistic**. Every mistake in this policy is one that has been made on shipping devices, and the shapes are the seven from [Lab 04](lab-04-vendor-policy-review.md).

Tools you already have:

```bash
# host
cd 22-SELinux
python3 scripts/avc-decode.py labs/ctf-quiet-domain/avc.log --group
python3 scripts/avc-decode.py labs/ctf-quiet-domain/avc.log --rules-only
```

---

## Rules of engagement

1. **No device is required and none will help.** The answer is entirely in the three files.
2. **Everything you need is derivable.** There is no guessing step, no wordlist, and no brute force.
3. **Read `vendor_sepolicy.cil` in full at least once** before grepping. It is deliberately short enough — about 130 rules — that this is possible, and the structure matters.
4. The four tokens are **exact strings from the artefacts**, lowercase where the artefact is lowercase.
5. Check your answer against the hash in [Scoring](#scoring). Do not read the solution first; the hash lets you self-verify without spoiling anything.

---

## Warm-up — establish the baseline

Before hunting, calibrate. Two of the four vendor daemons in this policy are written *correctly*. Find them and read their rules, so that you know what "good" looks like on this device before you judge anything else.

```bash
# host
cd labs/ctf-quiet-domain
grep -c '^(allow ' vendor_sepolicy.cil
grep -c '^(neverallow ' vendor_sepolicy.cil
grep -oE '^\(type [a-z_0-9]+' vendor_sepolicy.cil | awk '{print $2}' | sort
```

**W1.** Which two domains carry `neverallow` assertions of their own? What does the presence of those assertions tell you about how those domains were developed, compared with the ones that have none?

**W2.** Read the rules for `vnd_sensord`. It reaches `sysfs`, its own data files, and `servicemanager`. It has **no** capabilities and **no** access to app data, and it explicitly forbids itself both. Write, in one sentence, what a full compromise of `vnd_sensord` would give an attacker.

**W3.** Now run the denial log through the decoder:

```bash
# host
python3 ../../scripts/avc-decode.py avc.log --group --rules-only
```

Twenty distinct rules from twenty-four records. Compare that against the reference measurement in [§5.9](../README.md#59-honest-severity-an-avc-denial-is-not-a-finding): a real Android 13 device produced 6,101 records collapsing to 33 rules. **This device produces almost no denials.** State two possible explanations, one benign and one not.

---

## Stage 1 — Who can get in?

The chain starts with an attacker-controlled process. An ordinary app is `untrusted_app`, and `untrusted_app`'s rules are AOSP's and are tight. So the first question is whether an ordinary app can end up somewhere *else*.

```bash
# host
cat vendor_seapp_contexts
```

Recall from [§3.6](../README.md#36-seapp_contexts-where-the-domain-is-actually-decided) which input keys an app can and cannot control:

| Key | Attacker-controllable? |
|---|---|
| `seinfo=` | **No** — derived from the APK's signing certificate via `mac_permissions.xml` |
| `isPrivApp=` | **No** — requires installation in a `priv-app/` directory in the system image |
| `isEphemeralApp=` | No |
| `minTargetSdkVersion=` | Yes, but it only selects among the `untrusted_app*` variants |
| `name=` | **Yes** — an app author chooses their own package name |

**S1.1.** Run the check from Lab 04, Shape 6:

```bash
grep 'name=' vendor_seapp_contexts | grep -v 'seinfo=' | grep -v 'isPrivApp='
```

**S1.2.** What domain does that line assign? Write it down — **this is token 1.**

**S1.3.** Describe the attack in two sentences: what does the attacker build, and what happens when the user installs it? Note the one precondition that has to hold for it to work at all.

**S1.4.** Read the rules for the domain you just found. Compare its permission set against what an ordinary `untrusted_app` gets on AOSP (see [`../examples/policy-rules-measured.cil`](../examples/policy-rules-measured.cil)). Which of its rules are *additional*? There are four that matter.

---

## Stage 2 — What can it reach?

The domain from Stage 1 is still an app domain — a member of `appdomain`. It has no capabilities, no `mlstrustedsubject`, and no direct access to any other app's data. Check that for yourself before continuing; the chain does not work by giving the attacker's domain the prize directly.

So it has to **reach something**.

```bash
# host
grep -nE 'unix_stream_socket' vendor_sepolicy.cil
```

**S2.1.** Which rule lets the Stage 1 domain connect to a daemon? Note where in the file it sits, and consider why.

**S2.2.** The target of a `connectto` rule is a **process domain**, not an object type. Explain, in terms of [§3.14](../README.md#314-sockets-where-mac-is-the-only-control-there-is), why that matters — and specifically why there is **no `sock_file` rule anywhere** for this socket.

**S2.3.** Now find the socket's name. It is in the audit log, hex-encoded:

```bash
# host
python3 ../../scripts/avc-decode.py avc.log --tclass unix_stream_socket
```

The decoder prints it. **The name, without the leading `@`, is token 2.**

**S2.4.** Explain what the `@` means and why the raw field was hex-encoded rather than quoted. (Two separate reasons — one about the byte at the start, one about how the audit subsystem encodes field values.)

**S2.5.** That audit record shows an `untrusted_app` being **refused** the connection — `permissive=0`. So why is it evidence *for* the chain rather than against it?

---

## Stage 3 — What does the daemon have?

You have reached a vendor daemon. Now read everything it can do.

```bash
# host
grep -nE '^\(allow vnd_diagd ' vendor_sepolicy.cil
grep -n 'mlstrustedsubject' vendor_sepolicy.cil
```

**S3.1.** List the daemon's capabilities. For each, say in one sentence what it lets the daemon ignore.

**S3.2.** The daemon is a member of one attribute that appears in **every** MLS constraint in the platform policy. Name it — **this is token 3** — and state precisely what its presence removes.

Go back to [Lab 03, Step 7](lab-03-mcs-and-app-isolation.md#step-7--read-the-constraints-out-of-the-real-policy) and re-read the measured constraints if you need to. Every one of them ends with the same clause.

**S3.3.** Compare the daemon's app-data rules against `vnd_otad`'s, and against the `dex2oat` rules in [`../examples/policy-rules-measured.cil`](../examples/policy-rules-measured.cil):

| Domain | `app_data_file:file` permissions | Has `open`? | Has `dir search`? |
|---|---|---|---|
| `dex2oat` (real, measured) | `read write getattr lock map` | **no — `neverallow`** | no |
| `vnd_otad` (this policy) | | | |
| `vnd_diagd` (this policy) | | | |

**S3.4.** Explain, in terms of the distinction in [§3.12](../README.md#312-dex2oat-in-its-own-domain-a-real-trust-property-not-a-slogan), why the presence of `open` and `dir search` is the difference between "can act on descriptors it was given" and "can go looking".

**S3.5.** Now state the complete chain in four sentences: attacker installs X → lands in domain Y → connects to Z over W → Z can do V. Each step must name the specific rule that permits it.

---

## Stage 4 — Who is the victim?

The chain lets the attacker reach a daemon that can read any app's data. The audit log tells you which app was actually read.

```bash
# host
python3 ../../scripts/avc-decode.py avc.log --group | grep -B20 'permissive=1'
```

or look directly:

```bash
grep 'permissive=1' avc.log
```

**S4.1.** Three records carry `permissive=1`. What does that field mean about whether those operations succeeded? Which domain produced them, and what does the `typepermissive` statement naming it mean for a shipping build?

**S4.2.** The victim's data files carry the context `u:object_r:app_data_file:s0:c188,c256,c512,c768`. Decode the categories:

- Which Android user?
- What is the appId?
- What is the full UID?

**The appId is token 4.**

**S4.3.** These three records are *not part of the chain you found in Stages 1–3* — they come from a different domain entirely. Explain what they are evidence of, and why finding them is a **second, independent finding** rather than a step in the first.

**S4.4.** Which of the two findings is more severe? Argue both sides in three sentences, then commit to an answer.

---

## Stage 5 — Assemble and report

**The flag:**

```
FLAG{<token1>-<token2>-<token3>-<token4>}
```

where:

| Token | What it is | From which stage |
|---|---|---|
| 1 | the domain an ordinary app can claim by package name alone | S1.2 |
| 2 | the abstract socket's name, without the leading `@` | S2.3 |
| 3 | the attribute that exempts the daemon from every MLS constraint | S3.2 |
| 4 | the appId encoded by the victim's MCS categories, as a decimal number | S4.2 |

---

## Scoring

Verify without spoiling:

```bash
# host — replace with your answer
printf 'FLAG{...}' | sha256sum
```

The correct flag hashes to:

```
573f042b85c9da8e92c3e37b00847ab55473b063dc2992a55b28fcb4aac21ed9
```

If your hash does not match, the most common mistakes are:

- including the `@` in token 2 (it is a rendering of a NUL byte, not part of the name);
- using the type name of the socket rather than the socket's *name*;
- using the full UID rather than the appId for token 4;
- capitalising a token — every token is exactly as it appears in the artefact.

### Full marks

The flag is worth about half. The rest is the write-up.

| | Points | Requirement |
|---|---|---|
| Flag | 40 | correct hash |
| Chain | 20 | all four links named, **each with the exact rule quoted verbatim** from the artefact |
| Second finding | 15 | the permissive domain identified separately, with the `permissive=1` evidence and an explanation of what it means |
| Severity | 10 | each finding rated with reasoning, including at least one honest "this is an impact amplifier, not a vulnerability" |
| Remediation | 10 | written **as policy**, not as prose — replacement rules and `seapp_contexts` lines |
| Ruling out | 5 | at least one thing in the artefacts that *looks* like a finding and is not, with the reasoning |

---

## The things that are meant to catch you

Read this section only after you have your flag, or if you are properly stuck.

<details>
<summary>Decoy 1 — the OTA daemon</summary>

`vnd_otad` has `dac_override`, `sys_admin`, `mlstrustedsubject`, and read access to every app's data. It looks like the worst domain in the file, and in isolation it is very broad.

But: **can anything less privileged reach it?** Read its rules. It is reachable from `update_engine` and from `servicemanager`, and its `seapp_contexts` line requires `seinfo=platform` **and** `isPrivApp=true`. There is no path from an attacker-installed app.

That does not make its rules *good* — an OTA daemon with `sys_admin` and app-data read is worth a paragraph in the report — but it is not the chain, and saying so is part of the exercise. **Reachability is the first question, not the last.**

There is also a genuine, separate observation about `vnd_otad` in the audit log. Find it.
</details>

<details>
<summary>Decoy 2 — the sensor daemon's denial</summary>

```
avc: denied { search } for comm="vnd_sensord" name="com.aurora.diag"
  scontext=u:r:vnd_sensord:s0
  tcontext=u:object_r:diag_app_data_file:s0:c512,c768 tclass=dir permissive=0
```

A vendor daemon being refused access to an app's data directory. It looks like an attempted lateral move.

It is the **containment working**. `vnd_sensord` has an explicit `neverallow` against app data, it has no `mlstrustedsubject`, and it is at bare `s0` so it does not dominate `{c512, c768}`. This denial is exactly what a correctly-confined domain looks like when its code touches something it should not.

Reporting it as a finding would be the mistake [§5.9](../README.md#59-honest-severity-an-avc-denial-is-not-a-finding) is about.
</details>

<details>
<summary>Decoy 3 — untrusted_app can find a vendor service</summary>

```lisp
(allow untrusted_app vnd_diag_service (service_manager (find)))
```

Any app can look up the vendor's diagnostics Binder service. That is a widening of the untrusted attack surface and deserves a mention.

But `service_manager:find` only gets you a *handle*. You then need `binder:call` on the **server's domain** ([§3.15](../README.md#315-binder-and-service_manager-a-two-stage-mac-decision)) — and `untrusted_app` does not have it. Check: the `binder:call` rule for `vnd_diagd` names `diag_app`, not `untrusted_app`.

So this rule alone is a dead end. It becomes interesting only *after* Stage 1, at which point the attacker is `diag_app` and has both. Worth noting as part of the chain's blast radius, not as the chain.
</details>

<details>
<summary>Decoy 4 — the daemon can talk to the security server</summary>

```lisp
(allow vnd_diagd kernel (security (compute_av check_context)))
```

`security` is the class containing `setenforce` and `load_policy`, so any rule on it draws the eye.

`compute_av` and `check_context` are *query* permissions: they let a process ask the security server what a decision would be, and whether a context string is valid. They grant no ability to change anything. Plenty of legitimate userspace uses them.

`setenforce` and `load_policy` are the ones that matter, and neither is granted here. There **is** a `setenforce` record in the audit log, though — read it carefully and note what its `permissive` field says.
</details>

---

## Hints, in escalating order

<details>
<summary>Hint 1 — where to start</summary>

Start at `vendor_seapp_contexts`, not at the policy. The policy tells you what each domain can do; `seapp_contexts` tells you which domains an attacker can *get into*. A domain with terrifying permissions that nothing can reach is not a chain.
</details>

<details>
<summary>Hint 2 — the socket</summary>

There is no `sock_file` rule anywhere in the policy for the diagnostics socket, and that absence is a clue rather than an omission. Re-read [§3.14](../README.md#314-sockets-where-mac-is-the-only-control-there-is): a socket with a filesystem path has a `sock_file` node to label; an abstract-namespace socket has nothing at all.

The name is in the audit log as a hex-encoded `path=` field. `avc-decode.py` decodes it, or you can do it by hand: pairs of hex digits, ASCII.
</details>

<details>
<summary>Hint 3 — the attribute</summary>

```bash
grep -n 'typeattributeset' vendor_sepolicy.cil
```

One of those lines has two members and is the reason the whole chain works. Compare it against the MLS constraints in [`../examples/policy-rules-measured.cil`](../examples/policy-rules-measured.cil) — every constraint ends with the same clause, naming the same attribute.
</details>

<details>
<summary>Hint 4 — the appId</summary>

The victim's context is `u:object_r:app_data_file:s0:c188,c256,c512,c768`.

```
first  category c188 = appid & 0xff        -> 188
second category c256 = 256 + (appid >> 8)  -> (appid >> 8) = 0
appid = (0 << 8) | 188 = 188
```

Token 4 is the appId, not the UID. The UID would be 10188.
</details>

<details>
<summary>Hint 5 — the second finding</summary>

```bash
grep 'permissive=1' avc.log
grep -n 'typepermissive' vendor_sepolicy.cil
```

Three records, one domain, and a one-line `typepermissive` statement you may have skipped. Read [§3.9](../README.md#39-enforcing-permissive-and-why-setenforce-0-is-a-bigger-deal-than-it-looks) on what `permissive=1` means about whether the operation succeeded.
</details>

---

## Full solution

<details>
<summary>Open only after you have your own answer</summary>

### The chain

**Link 1 — `vendor_seapp_contexts`, line 5 of the rules:**

```
user=_app name=com.aurora.diag domain=diag_app type=diag_app_data_file levelFrom=user
```

No `seinfo=`. No `isPrivApp=`. The only input key is `name=`, which the app author chooses. **Any app published under the package name `com.aurora.diag` lands in `diag_app`.**

The precondition: the real `com.aurora.diag` must not already be installed, since two apps cannot share a package name. On a device where the vendor's own diagnostics app is preinstalled, the attack requires either a device where it is absent, a sideload path, or getting there first — which on a store is a race the attacker can sometimes win for an app the vendor has not published yet.

Note also `levelFrom=user`: `diag_app` processes get only `s0:c512,c768`, so they are not even separated from each other by MCS.

**Link 2 — `vendor_sepolicy.cil`, the last rule in the `vnd_diagd` block:**

```lisp
(allow diag_app vnd_diagd (unix_stream_socket (connectto)))
```

`diag_app` may connect to `vnd_diagd`. The target is the daemon's **process domain**, because the socket is abstract-namespace and has no filesystem object to label. There is no `sock_file` rule anywhere, and there cannot be — there is no node. **SELinux is the only access control on this socket**, and it has just permitted the attacker.

The socket's name comes from the audit log:

```
avc: denied { connectto } for comm="reader" path=00766E645F6469616700
  scontext=u:r:untrusted_app:s0:c201,c256,c512,c768
  tcontext=u:r:vnd_diagd:s0 tclass=unix_stream_socket permissive=0
```

`00 76 6e 64 5f 64 69 61 67 00` = NUL, `vnd_diag`, NUL. Rendered `@vnd_diag`. The record shows an *ordinary* `untrusted_app` being refused — which is exactly the point: **the refusal proves the rule is domain-specific**, and Stage 1 is how the attacker stops being `untrusted_app`.

**Link 3 — the attribute:**

```lisp
(typeattributeset mlstrustedsubject (vnd_diagd vnd_otad ))
```

`vnd_diagd` is `mlstrustedsubject`. Every MLS constraint in the platform policy ends with `(eq t1 mlstrustedsubject)`, so `vnd_diagd` is exempt from all of them. **The MCS categories that separate one app's data from another's do not apply to it.**

**Link 4 — what it can then do:**

```lisp
(allow vnd_diagd self (capability (dac_override dac_read_search sys_ptrace)))
(allow vnd_diagd app_data_file (dir (search getattr read open)))
(allow vnd_diagd app_data_file (file (open read getattr map)))
(allow vnd_diagd privapp_data_file (dir (search getattr read open)))
(allow vnd_diagd privapp_data_file (file (open read getattr map)))
```

- `dac_override` and `dac_read_search`: DAC does not stop it.
- `mlstrustedsubject`: MCS does not stop it.
- `dir search` **and** `open` on `app_data_file`: it can **enumerate and open by path**, not merely act on descriptors it was handed. Compare `dex2oat`, which has `read`/`write` but a `neverallow` on `open`.

Both isolation layers are gone simultaneously. The daemon can read any app's private database, and the attacker can ask it to.

### The flag

| Token | Value | Where |
|---|---|---|
| 1 | `diag_app` | `vendor_seapp_contexts` |
| 2 | `vnd_diag` | decoded from `path=00766E645F6469616700` |
| 3 | `mlstrustedsubject` | `(typeattributeset mlstrustedsubject (vnd_diagd vnd_otad ))` |
| 4 | `188` | `c188` → `188 & 0xff`, `c256` → `(188 >> 8) = 0` |

```
FLAG{diag_app-vnd_diag-mlstrustedsubject-188}
```

### The second, independent finding

```lisp
(typepermissive vnd_factory_app)
```

```
avc: denied { open }   ... scontext=u:r:vnd_factory_app:s0:c512,c768
  tcontext=u:object_r:app_data_file:s0:c188,c256,c512,c768 tclass=file permissive=1
avc: denied { read }   ... permissive=1
avc: denied { search } ... tclass=dir permissive=1
```

`vnd_factory_app` is a **permissive domain on a shipping build**. All three operations **succeeded**. A factory-test app read `com.aurora.wallet`'s key database, and policy would have refused all three.

This is a separate finding from the chain, and in some ways a worse one: it needs no exploitation at all. It also fails CTS and Play Integrity, so it has commercial consequences the vendor will care about.

Its `seapp_contexts` line requires `seinfo=platform`, so an attacker cannot claim it. Its severity comes from the fact that the factory-test app itself is running unconfined on a user device.

### The `vnd_otad` observation

```
avc: denied { setenforce } for comm="vnd_otad" scontext=u:r:vnd_otad:s0
  tcontext=u:object_r:kernel:s0 tclass=security permissive=0
```

The OTA daemon **tried to turn SELinux off**. It was refused — policy does not grant it `security:setenforce`, and this is the mechanism working. But the *attempt* is worth a paragraph: it means the vendor's OTA code contains a `setenforce 0` path, presumably left over from bring-up. If a future policy change ever grants it, the device loses the MAC layer during every update.

This is the shape from [§5.9](../README.md#59-honest-severity-an-avc-denial-is-not-a-finding)'s second case: *a denial naming a security-critical operation is worth investigating regardless of the outcome, because something is trying it.*

### Remediation, as policy

**Fix 1 — the `seapp_contexts` line.** Require a signature:

```
user=_app seinfo=platform name=com.aurora.diag domain=diag_app type=diag_app_data_file levelFrom=all
```

`seinfo=platform` closes the chain at its first link. `levelFrom=all` additionally restores per-app MCS separation between `diag_app` instances.

**Fix 2 — remove `mlstrustedsubject` from `vnd_diagd`:**

```lisp
(typeattributeset mlstrustedsubject (vnd_otad ))
```

A diagnostics daemon does not need to be exempt from MLS. If it genuinely must collect data from many apps, the data should be *pushed* to a shared, dedicated type rather than *pulled* out of each app's directory.

**Fix 3 — replace direct app-data access with fd passing.** Model on `dex2oat`:

```lisp
(allow vnd_diagd vnd_diag_shared_file (dir (search)))
(allow vnd_diagd vnd_diag_shared_file (file (open read getattr)))
(neverallow vnd_diagd app_data_file (file (open)))
(neverallow vnd_diagd app_data_file (dir (search)))
(neverallow vnd_diagd privapp_data_file (file (open)))
```

plus a `file_contexts` entry:

```
/data/vendor/diag/shared(/.*)?   u:object_r:vnd_diag_shared_file:s0
```

**Fix 4 — drop the capabilities:**

```lisp
(neverallow vnd_diagd self (capability (dac_override dac_read_search sys_ptrace)))
```

`dac_override` was almost certainly a workaround for a file-ownership mistake. Fix the ownership.

**Fix 5 — narrow the socket rule, or replace the socket:**

```lisp
;; minimum
(neverallow { appdomain -diag_app } vnd_diagd (unix_stream_socket (connectto)))

;; better: expose a labelled Binder service instead of an abstract socket,
;; so that servicemanager's find check applies and the interface is
;; enumerable and reviewable.
```

**Fix 6 — remove the permissive domain:**

```lisp
;; delete entirely
;; (typepermissive vnd_factory_app)
```

and remove `com.aurora.factorytest` from the shipping build.

**Fix 7 — remove the `setenforce` call** from the OTA daemon's source.

### Severity

| Finding | Severity | Reasoning |
|---|---|---|
| The chain (Stages 1–4) | **High** | No exploitation of a memory-safety bug is required — the whole path is *permitted by policy*. It needs the attacker to win the package name, which is a real precondition and is why this is not Critical. |
| Permissive `vnd_factory_app` | **High** | No preconditions at all beyond the app being present. The evidence is in the log: three operations that succeeded. Fails CTS and Play Integrity. |
| `vnd_otad` breadth | **Medium** | `sys_admin`, `dac_override`, `mlstrustedsubject` and app-data read — but nothing less privileged can reach it. An **impact amplifier**: it converts any OTA-daemon bug into total data disclosure. |
| `untrusted_app` → `vnd_diag_service:find` | **Low** | Widens the untrusted surface, but `binder:call` is not granted, so it is a dead end on its own. |
| `vnd_otad` attempting `setenforce` | **Informational** | Refused. Worth reporting because it shows a `setenforce 0` path exists in vendor code. |

### What to rule out

- **`vnd_sensord`'s denial on `diag_app_data_file`** — the containment working. Not a finding.
- **`vnd_diagd kernel:security { compute_av check_context }`** — query permissions only. Not a finding.
- **The GMS, `system_suspend`, `vold` and `dexoptanalyzer` denials** — ordinary platform noise, exactly the shapes measured on a real device in [`../examples/avc-denials-measured.log`](../examples/avc-denials-measured.log). Not findings.
- **The `system_server` ioctl denial** — `0x6686` is `FS_IOC_ENABLE_VERITY` on a read-only partition. Benign, and it is there to test whether you write the `allowxperm` rule alongside the `allow`.

</details>

---

## Success criteria

You have completed this CTF when you can:

1. Produce the correct flag hash.
2. State the four-link chain with the exact rule quoted for each link.
3. Explain why the abstract socket has no `sock_file` rule, and why that absence is the point.
4. Explain what `mlstrustedsubject` removes, naming the constraint clause.
5. Identify the permissive domain as a **separate** finding and explain what `permissive=1` means about the three operations.
6. Rule out at least three things that look like findings and are not, with reasoning for each.
7. Write remediation as policy rather than as prose.
8. Assign severity to each finding with an explicit reachability argument.

---

## Where this came from

Every mistake in this policy is one that has been made on shipping devices:

| Artefact mistake | Real-world shape | Chapter section |
|---|---|---|
| `seapp_contexts` matching on `name=` alone | vendor lines with no signature requirement | [§3.6](../README.md#36-seapp_contexts-where-the-domain-is-actually-decided) |
| `connectto` from an app domain to a daemon over an abstract socket | the single most productive class on OEM builds | [§5.6](../README.md#56-vulnerability-class--an-abstract-socket-reachable-by-any-app) |
| A vendor domain added to `mlstrustedsubject` | usually added to make an MCS denial stop | [§5.3](../README.md#53-vulnerability-class--an-over-permissive-vendor-domain) |
| `dac_override` as a workaround for a labelling mistake | the commonest `audit2allow` artefact | [§5.2](../README.md#52-how-developers-misuse-it) |
| A permissive domain surviving into a `user` build | bring-up pressure | [§5.4](../README.md#54-vulnerability-class--a-permissive-domain-on-a-production-build) |
| `open` and `dir search` where fd-passing was the right design | the `dex2oat` contrast | [§3.12](../README.md#312-dex2oat-in-its-own-domain-a-real-trust-property-not-a-slogan) |
| A `setenforce` call left in vendor code | leftover bring-up scaffolding | [§3.9](../README.md#39-enforcing-permissive-and-why-setenforce-0-is-a-bigger-deal-than-it-looks) |

**The title is the lesson.** `vnd_diagd` generates no denials at all, because it has been granted everything it needs. A domain that is quiet in the audit log is not a domain that is well-behaved — it is a domain nobody has had to look at. The noisy domains in this policy (`vnd_sensord`, `vnd_audiofx`) are the correctly-written ones, and their denials are the containment working.

That inversion — **noise is health, silence is unexamined** — is the single most useful instinct this chapter can leave you with.
