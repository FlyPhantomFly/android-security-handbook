# Example 01 — one question, five tiers

Every chapter in this repository covers **one topic at all five tiers**. This file does
the opposite: it takes **one question at a time and escalates it through all five tiers**,
so you can see what actually changes.

What changes is not the amount of detail. A Principal-tier answer is often *shorter* than
a Senior one. What changes is **what the answer is about**:

| Tier | The answer is about… |
|---|---|
| Beginner | the mechanism |
| Intermediate | the mechanism's failure modes |
| Senior | the evidence, and what it is evidence *for* |
| Staff Engineer | the system the mechanism sits in, and the trade |
| Principal Engineer | whether the question was the right question |

Three questions follow. Read the five answers to each one in order and watch where the
centre of gravity moves.

---

## Question A — "How does an application detect that the device is rooted?"

### A / Beginner

Root means UID 0, the Linux superuser, for which the kernel skips its normal permission
checks. Android ships no supported way to get it, so a rooted device has had something
added to it — usually by unlocking the bootloader and flashing a patched boot image that
starts a daemon which can hand UID 0 to chosen processes.

An app detects it by looking for the traces. The common checks are: does a `su` binary
exist at one of the well-known paths; is a root-manager package installed, which
`PackageManager` can answer; does `Build.TAGS` contain `test-keys`, which suggests a
non-retail build; is any partition mounted read-write that should be read-only; and does
running `su` actually succeed.

*What this tier is being graded on: can you say what root is without saying "it gives you
admin", and can you name checks without reciting a library.*

### A / Intermediate

The same list, plus the reasons each item fails.

`File.exists("/system/bin/su")` is the one everybody writes and it is weak in two separate
ways. It is trivially defeated — Magisk has for years hidden its own paths from selected
processes — and, more interestingly, it can be **structurally unable to answer**. On a
rooted Android 15 emulator, `/system/xbin/su` exists and is setuid root, and `adb shell`
can see it; but `/system/xbin` is mode `0750 root:shell`, so an app uid cannot traverse the
directory and gets `EACCES`. `File.exists()` maps both "absent" and "forbidden" to the same
`false`. So on the only category of device where the check could matter, it returns the
answer that means "clean".

The package check is trivially defeated by renaming a package. The `test-keys` check fires
on every custom ROM whether or not it is rooted, and on every `userdebug` build, so it
generates false positives on developer devices. Running `su` is the strongest of the five
because it tests the capability rather than an artefact — but it is also the loudest,
because it typically triggers the root manager's permission prompt.

*What this tier is being graded on: do you know why the standard checks fail, or only
that they do.*

### A / Senior

I would reframe before answering, because "how does an app detect root" is three
questions wearing one coat.

The first is **what to check**, and I would separate artefact checks from capability
checks. An artefact check asks "is there a file/package/property that a rooted device
tends to have"; it is a race against an attacker who can rename and hide, and it is a race
the app loses on its own timescale because the app ships quarterly and the hiding module
ships weekly. A capability check asks "can something on this device do a thing only root
can do" — for example, is a path writable that should not be, or does a mount table entry
name a rooting substrate. On the device I looked at, `/proc/self/mountinfo` carried three
lines whose mount source was literally `magisk`, and it was readable from every vantage I
tried, including an app uid, with no permission at all. That is a far better signal than
any path probe, and it needs nothing.

The second is **from where**, and this is the part most people skip. A probe verified from
`adb shell` has not been verified. The shell is a different SELinux domain with different
privileges. I want to be careful with the numbers, because I had them wrong until recently:
on this emulator an app sees about 638 properties, the shell about 678, and **root about
1,062**. The figure I used to quote had the *root* number labelled as the shell number, which
made the shell look far less representative than it is. The corrected version changes the
conclusion — a shell test is a reasonable proxy for app reachability and a terrible proxy for
root, so the mistake that costs you is not "I tested from the shell", it is "I tested from
root and called it shell". The one family where the gap is total is `ro.boottime.*`: 111
properties to root, **zero** to the shell and zero to an app, and that is precisely the family
that looks like an ideal emulator signal from a privileged prompt. So I run every candidate
check as the app, via `run-as`, a purpose-built probe APK, or Frida in-process — or I label
the result as a shell measurement and say so.

The third is **what the app does with the answer**, and it dominates the other two. If
fifty checks collapse into one boolean returned by one method, the attacker hooks that one
method and the fiftieth check bought nothing. If instead the app accumulates a score with
provenance — which signals fired, not just how many — and ships that to a server which
makes the decision, the attacker now has to defeat the checks rather than the verdict, and
the decision is made somewhere they cannot reach.

*What this tier is being graded on: whether you treat a detection result as evidence with
a provenance, or as a fact.*

### A / Staff Engineer

At this tier I would not answer the question as posed, I would ask what the detection is
*for*, because the four plausible answers lead to four different systems.

If it is for fraud — bot farms, emulator farms, promo abuse — then root is a weak proxy
and the right architecture is server-side risk scoring fed by many weak signals, of which
root is one, weighted low. If it is for regulatory or contractual compliance, then the
requirement is usually "we made a reasonable effort", the honest design is cheap and
documented, and spending engineering budget on an arms race is a misallocation. If it is
for DRM or content licensing, the licensor has usually specified the mechanism already and
the engineering question is integration, not design. And if it is to protect the user's
own credentials on their own device, then root detection is close to the wrong control
entirely: the right control is that the credential is not usable outside the device, which
is a Keystore and key-attestation question, not a detection question.

The trade I would put in front of a director is this. Client-side root detection buys
**time**, measured in days to weeks against a competent, motivated attacker and in months
against an indifferent one. It costs engineering time, permanently, because it decays; it
costs support load, because it fires on legitimate users with unusual devices; and it
costs credibility with the security team when it is presented as a control rather than as
friction. Its correct budget is small and its correct owner is the fraud team, not the app
team.

The one place I would spend real money is the part that is not client-side: hardware key
attestation evaluated on the server, because that verdict is produced by something the
attacker does not run. And I would insist on the caveat that goes with it, because I have
seen it get skipped: a valid, correctly-verifying attestation chain proves the chain. On
an emulator, every key is `SOFTWARE`, the hardware-enforced list is empty, and the chain
still verifies perfectly. If the server does not read the security level and the root of
trust out of the *hardware-enforced* list, it has bought a signature and no assurance.

*What this tier is being graded on: whether you can decline to build something, and defend
the decline commercially.*

### A / Principal Engineer

The question contains an assumption worth surfacing: that the device is the thing whose
integrity we want to establish. For most of the systems where this question gets asked,
that is false. What the business actually wants to know is whether a *transaction* is
legitimate, and device integrity is one weak input to that.

The structural argument is short. Any check that executes inside a process the adversary
controls can, in the limit, return whatever the adversary wants. That is not a statement
about how good the check is; it is a statement about where the check runs. So the entire
family of client-side integrity controls has an asymptote, and everything we build there
is a delay, correctly priced as a delay. The interesting engineering is therefore in two
places: producing evidence that an adversary cannot forge because it is signed by
something they do not control, and building a decision system that degrades gracefully
when that evidence is absent — because it will be absent, for the privacy-conscious user
on a de-Googled phone as much as for the attacker.

The failure mode I would warn a leadership team about is not technical. It is that
detection systems accumulate. Every incident adds a check, no check is ever removed
because removal is unattributable and addition is, and after three years there is a
subsystem nobody understands that fires on 0.4% of legitimate users. I would want an
explicit retirement policy for signals — each one carries a measured true-positive and
false-positive rate or it comes out — and I would want the metric to be *fraud loss and
support cost*, not *devices detected*, because "devices detected" is a number that goes up
when your detection is wrong.

I would also be honest that I am arguing against a genuine counter-position. Teams that
have shipped serious client-side hardening report real, sustained reductions in automated
abuse, and dismissing that as "security theatre" is intellectually lazy. My claim is
narrower: it is friction with a price, it should be budgeted as friction, and the person
who owns it should be the person who owns the fraud loss.

*What this tier is being graded on: whether you can hold a position, state the strongest
version of the opposing one, and still decide.*

---

## Question B — "Where should an Android app store a session token?"

### B / Beginner

In the app's private storage, which on disk is `/data/data/<package>` and which the kernel
protects because each app runs as its own Linux UID. In practice that means
`SharedPreferences` or a private file or a private database. Not on external storage, not
in the app's own APK, and not in a log line.

### B / Intermediate

Private storage is correct, and the follow-up is what "protected" is protecting against.
It protects against another installed app, because of the UID boundary. It does not
protect against someone with root, against a backup that the user or the platform copies
off the device, or against a debuggable build, where `run-as` gives a shell inside the
app's own uid.

So the practical answer is: private storage, plus `android:allowBackup="false"` if the
token should not be copied off, plus a short server-side lifetime so that a stolen token
stops being valuable quickly. Encrypting the token with a Keystore key is a common
recommendation and it is a real but limited improvement — the key is in the Keystore, so it
cannot be copied off the device, but any code running as the app's uid can *use* it, and on
a rooted device that includes the attacker.

One thing that catches people: deleting a row is not deleting the data. A logout that
deleted two rows from a SQLite database left all four secrets readable in a 61 KB
write-ahead log while SQL reported them gone. Any review that queries the database rather
than reading its files will miss that.

### B / Senior

I would answer with a question of my own: what is the token *for*, and what does
possession of it authorise? Because "where to store it" is downstream of "how bad is it
when someone has it", and that is a server-side property.

Given that, my answer has three parts. Store it in private storage — that is table stakes
and the alternatives are worse, not better. Bind it, so that possession alone is
insufficient: a refresh token bound to a device-held key, where the client must sign a
proof of possession, converts a stolen file into a stolen file that does not work
elsewhere. And bound the blast radius in time, because the difference between a 30-day and
a 15-minute access token is the difference between an incident and a log line.

On severity, and this is where I part company with a lot of report templates: "session
token found in SharedPreferences" is not, on its own, a finding. That is how essentially
every Android application works, and on a stock locked device it is the intended
mechanism. I write it up when something makes it reachable — a debuggable build, backup
enabled, a world-readable path, a token with no expiry, an exported component that leaks
it — and I say which. A report full of "sensitive data in SharedPreferences" findings
trains the client to skim my reports, which costs me the finding that mattered.

I would also want to say what I have *not* established. Whether the app's Keystore key is
genuinely hardware-backed is a claim I would verify with a key attestation rather than
assume from the API used, because I have seen `ro.boot.verifiedbootstate` read `green` on
a device whose own TEE-signed attestation reported `Unverified` in the same session. The
property is attacker-controllable data; the attestation is not.

### B / Staff Engineer

I would push the decision up a layer, because "where do we store the token" is a question
that only arises because we decided the client holds a long-lived bearer credential, and
that decision is the one that matters.

The design I would advocate: short-lived access tokens, a refresh token bound to a
non-exportable device key, proof-of-possession on refresh, and server-side revocation that
actually works — meaning a revocation list that is consulted, not merely maintained. The
storage question then becomes almost uninteresting, which is the mark of a good design:
the sensitive thing is the private key, the private key never leaves the Keystore, and the
worst case for the token file is that the attacker gets fifteen minutes of what the user
already had on a device the attacker already controls.

The organisational half matters as much. I would want one place in the codebase that
issues, stores, refreshes and clears credentials, because the failures I actually see are
not cryptographic — they are a second code path added in a hurry that writes the token
somewhere else, a crash reporter that captures it in a breadcrumb, or a WebView that
inherits it into a cookie jar with a different lifetime. And I would want a test that
fails the build if the token appears in a log, a backup, or a crash payload, because a
convention that is not enforced by a machine decays at exactly the rate the team grows.

### B / Principal Engineer

The framing I would want the organisation to adopt is that a bearer token is a *design
debt*, not a storage problem. A bearer credential is, by construction, something that
works for whoever holds it. Every control we then build — encryption at rest, root
detection, obfuscation, integrity checks — is an attempt to make a thing that works for
anyone work for only one person, on hardware we do not control. That attempt has an
asymptote and the asymptote is not zero risk.

The alternative is to make possession insufficient, which is a protocol decision, not an
app decision. Once the credential is bound to a key that cannot leave the device, the
threat model simplifies enormously and — this is the part worth arguing to a board —
several expensive client-side programmes become optional rather than load-bearing.

What I would not do is pretend the migration is cheap. Binding credentials to device keys
breaks device migration, it breaks users who wipe phones, it interacts badly with multi
device usage, and it puts a hardware dependency on the critical login path for a
population of devices whose Keystore quality varies more than the marketing suggests. On
some devices the "hardware-backed" key is software. So the honest recommendation is
staged: bind refresh, not access; fall back to unbound refresh with a shorter lifetime and
a higher risk score rather than locking the user out; and instrument the fallback rate,
because if it is 30% the design is not what you think it is.

---

## Question C — "You have an APK and thirty minutes. Go."

### C / Beginner

Get the file properly first: `adb shell pm path <package>` rather than pulling `base.apk`,
because modern apps ship as split APKs and the base one may not contain what I want. Hash
it and write the hash and version down.

Then unpack it. `apktool d` for the decoded manifest and resources; jadx for readable Java.
Read the manifest: what components are exported, what permissions are requested, is
`debuggable` set, is `allowBackup` on, is there a network security config. Then install it
and use it as a user for a few minutes, with `logcat` running, because half of what a beginner
misses is visible in the log.

### C / Intermediate

The same, in a fixed order, with the traps I know about.

Acquisition: `pm path`, all splits. A large app can show zero interesting code in
`base.apk` because everything lives in a feature split, and that reads as a clean app.

Triage before decompilation: ZIP listing, signature scheme and signer, target SDK, native
libraries and their ABIs. Target SDK matters because so much platform behaviour is gated on
it.

Then decompile — and check whether the decompilation *worked*. jadx will print a small
error count and be badly wrong about it: on one real 17.5 MB app the console said
`finished with errors, count: 61` while the output tree contained 2,104 refused methods
across 1,424 files. If I do not count the tree, I will conclude that a grep found nothing
when in fact a grep could not have found it.

Then a first-pass sweep for the obvious: cleartext traffic settings, exported components
with no permission, `WebView` with JavaScript enabled plus a JavaScript interface, hardcoded
URLs and environment names. Every one of these is a lead, not a finding.

### C / Senior

The first thing I do is refuse the brief as stated, politely. "See what you can find" has
no termination condition, so thirty minutes will produce a list of leads and no finding.
I would spend the first two minutes converting it into one bounded, falsifiable question:
"can an unprivileged app on the same device read this app's session token", or "does this
app's certificate pinning stop an interception proxy". Then thirty minutes is enough to
answer one of those properly, and an answered question beats a list.

After that, my order is acquisition, triage, then a *reachability-first* pass rather than a
grep-first pass, because I have learned what a grep-first pass costs. On a 17 MB commercial
app a keyword sweep produced 16,836 raw hits, which the funnel reduced to 168 leads. I
adjudicated the top-confidence band by hand: 15 of 17 were rejected — documentation links,
Compose preview fixtures, an XMP namespace, marketing URLs. The best genuine lead in the
whole run sat in the middle of the ranking, and it was not a secret at all: an enum
shipping thirteen environment names, including pre-production, eight QA and three staging.

So in thirty minutes I would state my question, acquire correctly, verify that my tools
actually processed the file, run one targeted sweep against the question, and reserve the
last ten minutes to *disprove* my own best lead. What I hand back is one answered question
with its evidence, plus an explicit list of what I did not look at.

### C / Staff Engineer

I would treat "thirty minutes" as the interesting constraint, because it is a question
about triage economics, not about tooling.

Thirty minutes buys exactly one of three things and I would say which I am buying: a
go/no-go on whether a deeper engagement is justified; an answer to one specific question
someone already has; or a coverage map that says where the risk plausibly lives. Those
produce different artefacts and mixing them produces the worst of each.

I would also be explicit that a thirty-minute pass cannot produce a negative result. "We
looked and found nothing" is a claim about the looking, and at this budget the looking is
shallow enough that the claim is not worth making. The output should therefore state the
denominator: how many components were examined out of how many exist, whether splits were
included, whether the decompiler refused anything. I have seen a session measure 67% or
50% coverage of the same app depending purely on whether the manifest or the device's
resolver tables defined the total, and the flattering number is the one that lets the
device define it.

### C / Principal Engineer

I would ask why the thirty minutes exists. It is usually a proxy for a real constraint —
an intake queue with more apps than analysts, a release gate someone wants to keep short,
or an executive who wants a number by Friday — and each of those has a better answer than
a rushed manual pass.

If it is intake volume, the answer is a pipeline that mechanically answers the cheap
questions on every app and escalates on evidence, and the thirty minutes of human time
goes to the escalations. If it is a release gate, the answer is that a gate should test
invariants, not hunt for bugs: a build that fails when a token appears in a log, when a new
exported component appears without review, when `allowBackup` flips, is worth more than
thirty minutes of anybody's attention and it does not decay.

The one thing I would push back on hardest is the ritual thirty-minute review whose real
function is to let someone write "security reviewed" in a ticket. That produces the worst
outcome available: the organisation pays for the time, gets a shallow pass, and acquires
false confidence, which is strictly worse than no review because it stops the next
question from being asked. If the budget is genuinely thirty minutes, I would rather spend
it building the mechanical check than performing the review — and I would say so, in those
words, in the room.

---

## Using this file

Cover the answers below your chosen tier and write your own. Then lint it:

```bash
# host — from this directory
python3 -B ../scripts/answer-shape-lint.py --budget 240 my-answer.md
```

Then compare against the tier above yours and ask the only question that matters: **what
is that answer about that mine is not?**
