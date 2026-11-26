# 75 — Interview Questions: Cheat Sheet

Printable. Tables and commands only.

---

## The answer shape — five moves, 90–150 s

| # | Move | Time | Pattern |
|---|---|---|---|
| 1 | Plain statement | 10–15 s | "X is …" — answer the literal question |
| 2 | Precise version | 15–20 s | the real vocabulary, the real distinctions |
| 3 | Mechanism | 30–60 s | one level below the API. **Load-bearing** |
| 4 | Consequence | 15–30 s | "…which matters because…" |
| 5 | Limit | 10–15 s | "what I have not established is…" |

Degrades gracefully: interrupted after 2 it is complete; after 3 it is good.

---

## The five tiers — what escalates

| Tier | About | Silent question | Length |
|---|---|---|---|
| Beginner | mechanism | "what is it?" | short |
| Intermediate | failure modes | "when does it not work?" | longer |
| Senior | evidence | "how do you know, what would change your mind?" | **longest** |
| Staff | system and trade | "should we build it, what does it cost?" | shorter |
| Principal | the premise | "what are we actually trying to achieve?" | shortest |

| Transition | The one thing that changes |
|---|---|
| Beginner → Intermediate | how it works → how it breaks |
| Intermediate → Senior | facts → evidence with provenance |
| Senior → Staff | the finding → the system |
| Staff → Principal | the system → the question |

---

## Not knowing — four parts, 20 s

| Part | Wording |
|---|---|
| Boundary | "I don't know X, and I'd rather not guess." |
| Shape | "What I do know is…" |
| Method | "I'd find out by…" ← **this is the part that gets hired** |
| Receipt | "I've been caught by that: on device D, I saw…" |

**Wrong answer for:** design questions. They want a position, a trade-off and a cost.

| Response | Score |
|---|---|
| Bluff | worst — discounts everything else you said |
| Retreat ("I don't know", stop) | honest, weak |
| Deflect to prepared material | recognised |
| Over-hedge everything | self-cancelling |
| Four-part answer | strong |
| Reframe + answer anyway | strongest, riskiest |

---

## Stage → what is measured

| Stage | Asks | Measures | Budget |
|---|---|---|---|
| Recruiter screen | background | describability to a non-specialist | 5–8 × 60 s |
| Phone screen | breadth | absence of holes + clock control | 10–15 × 90–180 s |
| Take-home | findings | **method**, severity discipline, false-positive rate | 2–3 h capped |
| Deep technical | depth | where your floor is | 3–6 × 5–10 min |
| System design | design | what you know you cannot control | 1–2 × 20–40 min |
| Behavioural | stories | relationship with evidence | 4–6 × 4–6 min |

---

## Where candidates are lost (most → least common)

| # | Cause | Fix |
|---|---|---|
| 1 | Scope | decide your last sentence first |
| 2 | Calibration | four-part refusal |
| 3 | Altitude | mechanism vs system vs programme |
| 4 | Severity | hold, locate the disagreement |
| 5 | Tool-first | never open with a tool name |
| 6 | Knowledge | the other chapters |

---

## Situation → move

| Situation | Move |
|---|---|
| Broad opener | choose your ground; do not spend 6 min |
| Phone screen | answer briefly, **offer** depth |
| "underneath that?" | go down, or name your floor |
| Interrupted | one sentence stating your conclusion, no apology |
| Caught constructing | name it in the same breath; never build a second layer |
| Severity pushback | hold + locate in the **scale**, name what would change your mind |
| Tool fails live | expected vs got → one hypothesis → cheapest test → named fallback |
| NDA material | "can't discuss that one — here's an equivalent public case" |
| Silence | 3 s is fine; "give me 20 seconds to read this" is better |
| "Any questions?" | "what did the team last measure that surprised them?" |

---

## Severity vocabulary

| Term | Means |
|---|---|
| Reachability | can a non-privileged actor trigger it |
| Precondition | what must already be true (rooted? debuggable? physical?) |
| Blast radius | one user / one device / everyone |
| Honest severity | the rating you'd give if paid to say otherwise |
| Denominator | out of how many components / apps / devices |
| Confidence | **separate axis from severity** |

---

## Take-home rubric (100 pts)

| Pts | Section |
|---:|---|
| 25 | Method and scope — incl. verifying your tools actually worked |
| 25 | Findings quality — preconditions, reachability, real output, bounded impact |
| 20 | Severity discipline — argued, plausible distribution, confidence separated |
| 15 | **False-positive discipline** — rejected-leads section |
| 10 | Communicability — specific remediation, reproducible, ordered by importance |
| 5 | Limitations — coverage **with denominator** |

| Penalty | Trigger |
|---:|---|
| −10 | scanner dump |
| −10 | confidently wrong finding |
| −5 | overran cap silently |
| −5 | "no issues found", no method |
| −5 | whole-app negative from a string search |
| −20 | tested an unauthorised target |

---

## Measured contradictions — one per interview, with device + method

| Question | Received | Measured |
|---|---|---|
| detect an emulator | fingerprint `generic`, `/dev/qemu_pipe` | **all false** on stock API 35 AVD; node is `/dev/goldfish_pipe_dprctd`. `ro.kernel.qemu` still `1` |
| `qemu.*` property = emulator | true | **inverted** — retail Xiaomi sets `qemu.hw.mainkeys`, AVD does not |
| emulators are slower | true | **inverted 1.47×** — 2.398 vs 3.516 ns/iter |
| check `/system/xbin/su` | file test | `0750 root:shell` → app gets `EACCES`; `exists()` reads `false` on a **rooted** device. Magisk grants root from `/debug_ramdisk` |
| biometric = secure | callback proves auth | `accept: 3` / `acceptCrypto: 0`. 24 h key encrypted with **no auth**; 30 s key opened by an **unrelated process** |
| grep for `FLAG_SECURE` | works | **true-positive rate 0** — javac folds `0x2000` |
| valid attestation chain | proves hardware | emulator: every key `SOFTWARE`, `hardwareEnforced` empty, **chain verifies** |
| "grepped, found nothing" | no secrets | a statement about your grep |
| `--disable-verity` | turns verity off | **one byte**, inside the AVB-hashed region → breaks its own signature |
| 1,141 keyword hits | 58 apps reference it | **all 1,141 = the substring in "exposed"**, 0 findings |
| `TracerPid` detects debuggers | yes | `jdb` attached, `TracerPid: 0` throughout |
| DEX CRC detects repackaging | yes | re-signing left `classes.dex` CRC **identical** |

**Always attach:** the device, the method, and what it does **not** establish.

---

## Vantage — the standing rule

**A probe verified from `adb shell` has not been verified.**

API 35 AVD, corrected figures, three stable runs:

| | root | `shell` | app |
|---|---:|---:|---:|
| all properties | ~1,062 | ~678 | ~638 |
| `ro.boottime.*` | **111** | **0** | **0** |
| `init.svc.*` naming qemu/goldfish/ranchu | — | 36 | 35 |

**shell→app gap ≈ 40. shell→root gap ≈ 400.** So a shell test is a decent proxy for **app**
reachability and a terrible proxy for **root**. The expensive mistake is not "I tested from
the shell" — it is *"I tested from root and called it shell"*.

> A previously published "shell 1,053 / app 634" was a **root** measurement mislabelled. The
> tell was in the same table: root 1,050 next to shell 1,053, when only one domain is subject
> to `boottime_prop`. **Re-run the number; do not quote a remembered one.**

Run it as the app — `run-as`, a probe APK, Frida in-process — or **say it is a shell
measurement**.

---

## Emulator command traps

| Trap | Fix |
|---|---|
| `adb shell su -c 'a; b'` runs only `a` | `adb shell "su -c 'a; b'"` | <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- trap table: the "Trap" cell IS the wrong form, the "Fix" cell is the fix -->
| `su -c` on an AVD → `invalid uid/gid '-c'` | `su 0 <cmd>` |
| loop over `adb shell` prints one row | add `< /dev/null` |
| binary exits 139 on a 16 KiB-page AVD | `-Wl,-z,max-page-size=16384` |
| `grep -q` in a `pipefail` pipeline "fails" on a match | test content, not exit status |
| hook installs, nothing changes | inlining — `cmd package compile -m verify -f <pkg>` |

---

## Cross-cutting questions (no chapter owns these)

| # | Question | One-line skeleton |
|---:|---|---|
| 1 | coverage 3 of 4? | name the denominator; 69% of receiver surface is runtime-only |
| 2 | grep found nothing | 4 mechanisms: constant-folded, refused methods, wrong artefact, compressed entry |
| 3 | hook installed, no effect | inlining / classloader / interface / native / verdict elsewhere |
| 4 | attestation chain | proves the chain; read the **hardware-enforced** list |
| 5 | four protection families | rate the **shape**, not the list |
| 6 | app is obfuscated | orientation cost only; short signatures false-positive *more* |
| 7 | good testbed? | establish posture first — CA store, no bootloader on AVD, shell ≠ app |
| 8 | did the tool do it? | check the artefact, not the summary; liveness check first |
| 9 | lead vs finding | 16,836→168→2 of 17; 132/132 FP; 1,141/1,141 explained |
| 10 | bad news for the client | reproduce → preconditions → rate → notify → say what would change it |

---

## Commands — drilling with this chapter

```bash
# build the question bank (1,300+ questions; run --stats for today's number)
python3 -B scripts/build-interview-index.py --format json --out /tmp/bank.json

# counts, and the all-tiers-present gate
python3 -B scripts/build-interview-index.py --stats
python3 -B scripts/build-interview-index.py --check

# regenerate the three committed index files
python3 -B scripts/build-interview-index.py --by tier
python3 -B scripts/build-interview-index.py --by role  --out references/question-index-by-role.md
python3 -B scripts/build-interview-index.py --by round --out references/question-index-by-round.md

# what pools exist
python3 -B scripts/mock-round.py --bank /tmp/bank.json --list-pools

# a timed round; --seed for a repeatable one
python3 -B scripts/mock-round.py --bank /tmp/bank.json --round "Technical phone screen" --timed
python3 -B scripts/mock-round.py --bank /tmp/bank.json --tier Senior --seed 7

# lint a written answer / a whole submission
python3 -B scripts/answer-shape-lint.py --budget 150 answer.md
python3 -B scripts/answer-shape-lint.py --split --min 7 submission.md

# receipts, in ~20 seconds, read-only, against a device you own
./examples/04-evidence-behind-the-answer.sh emulator-5554
```

Always `python3 -B` — otherwise `__pycache__` lands in the repository.

---

## Corpus — a timestamped measurement, not a constant

Two real `--stats` runs on 2026-08-16, ninety minutes apart, with sibling chapters landing in
between. **Run `--stats` and quote your own number.**

| Tier | Run 1 | Run 2 | | Round | Pool | | Role | Pool |
|---|---:|---:|---|---|---:|---|---|---:|
| Beginner | 321 | 337 | | Recruiter screen | 15 | | Mobile App Pentester | 493 |
| Intermediate | 333 | 346 | | Technical phone screen | 96 | | Platform / OS Security | 302 |
| Senior | 272 | 286 | | Deep technical | 143 | | RE / Malware Analyst | 365 |
| Staff | 177 | 187 | | Practical / take-home | 90 | | Product Security | 314 |
| Principal | 155 | 164 | | System design | 77 | | Vuln Research / Exploit | 234 |
| **Total** | **1,258** | **1,320** | | Behavioural | 46 | | Detection / Anti-Fraud | 146 |
| **Chapters** | **71** | **75** | | | | | | |

Pool sizes are from run 1 and move with the corpus. All five tiers present in every chapter
that has a section.

---

## Four-week programme

| Week | Do |
|---|---|
| 1 | Lab 01 **cold**. Record the over-budget count |
| 2 | 20 written answers from your role index, lint each, rewrite anything < 7/12 |
| 3 | Measure 5 things yourself. Write the device down each time |
| 4 | Lab 02 full + self-mark; then Lab 03; then Lab 04 |

---

## Ethics — non-negotiable

| Rule |
|---|
| Class of system and shape of finding: shareable. Client identity: never |
| Nothing under embargo, ever |
| "I can't discuss that one — here's an equivalent public case" is a strong answer |
| A take-home naming a real third-party app is an **authorisation** question. Raise it |
| Never fabricate a CVE ID, a bounty URL, or an AOSP line number. Describe the class instead |
| Public availability is not authorisation |
