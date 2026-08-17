# Evidence ledger — template and worked example

> Copy this file **outside the repository** before using it. It will fill with paths and output
> from your machine, which is exactly the kind of artefact the repository's checks reject.
>
> ```bash
> # host
> cp 73-Labs/examples/evidence-ledger.md ~/my-engagement-ledger.md
> ```

Used by [Lab 02](../labs/lab-02-the-chain-no-chapter-can-host.md) and
[Lab 04](../labs/lab-04-ctf-the-gauntlet.md).

---

## 1. What a ledger is for

A finding that enters your static stage and never leaves it is invisible. Nobody notices an absence.
The ledger exists so that **every claim has to be discharged in writing** — confirmed, refuted, or
explicitly recorded as untested — and so that the reason a severity moved is written down at the
moment it moved, rather than reconstructed from memory a week later.

Three columns do most of the work:

| Column | Why it earns its place |
|---|---|
| **Vantage** | The most repeated methodology error in this repository is a result measured from one identity and reported as though from another. A column forces the question |
| **Evidence type** | "I read the manifest" and "I ran the command and saw the output" are different claims. A report that does not distinguish them cannot be reviewed |
| **Verdict** | Includes `NOT TESTED` and `DIVERGED`. A ledger with only `CONFIRMED` and `REFUTED` is a ledger that hides its gaps |

> **📖 Definition — vantage.** The security identity a command ran as. On Android, the four that
> matter are: an **unprivileged third-party app** (its own uid, e.g. 10213), the **`shell`** user
> (uid 2000, over `adb`), **root**, and **the target app itself** (via instrumentation or a hook).
> They have different permissions, different SELinux domains, and different answers to the same
> question.

---

## 2. Verdict vocabulary

Use exactly these. Inventing a sixth is how a report becomes unreviewable.

| Verdict | Meaning | When to use it |
|---|---|---|
| `HYPOTHESIS` | Consistent with what you read; not yet tested against behaviour | Every static finding starts here. **None may end here** |
| `CONFIRMED` | Observed, from a stated vantage, with reproducible output | The command and its output are in the Evidence column |
| `REFUTED` | Tested and did not occur | Say what you tried, not just that you tried |
| `NOT TESTED` | You did not test it, and you are saying so | Always better than silence. Pair with the reason |
| `DIVERGED` | You reproduced someone else's claim and got a different result | **Not a synonym for "they were wrong."** See §5 |

> **⚠️ Warning.** `REFUTED` requires that you know your test could have succeeded. A test blocked by
> your own tooling — a command that printed success and did nothing, a hook that never attached — is
> `NOT TESTED`, not `REFUTED`. Lab 02 §5.2 contains a worked example of exactly this
> misclassification, where `am start` reported `Starting:` and delivered nothing.

---

## 3. The ledger

Copy this table. One row per claim; add rows, never merge them.

| # | Claim | Stage | Vantage | Evidence type | Evidence | Verdict | Severity | Moved because |
|---|---|---|---|---|---|---|---|---|
| 1 | | static / dynamic | app / shell / root / in-app | manifest / decompiled / observed output / log | | HYPOTHESIS | | |
| 2 | | | | | | | | |
| 3 | | | | | | | | |
| 4 | | | | | | | | |

### 3.1 Header block — fill this in first

```
Target            :
Version / build   :
Device            :                      (model, API, ABI, build type)
Serial            :
Root              : yes / no             working su form:
SELinux           :
Date              :
Vantages used     :
Vantages NOT used :
Tools             :                      (with versions)
```

The last two lines are the ones people skip and reviewers read first.

---

## 4. Worked example — the four claims from Lab 02

Reproduced from a real run against the chapter's chain target, on the AVD
`sdk_gphone16k_x86_64` (`emulator-5554`, Android 15 / API 35, x86_64, `userdebug`), 2026-08-16.

```
Target            : com.pentest.ch73.chain  (73-Labs/examples/chain-target)
Version / build   : built out of tree, targetSdk 35, debug key generated per build
Device            : sdk_gphone16k_x86_64, API 35, x86_64, userdebug
Serial            : emulator-5554
Root              : yes                   working su form: su 0 <cmd>
SELinux           : Enforcing
Date              : 2026-08-16
Vantages used     : shell (uid 2000); root for claim 3 only
Vantages NOT used : an unprivileged third-party app  <-- the important gap
Tools             : adb 1.0.41, aapt2 2.19, jadx 1.5.3, JDK 24.0.2
```

| # | Claim | Stage | Vantage | Evidence type | Evidence | Verdict | Severity | Moved because |
|---|---|---|---|---|---|---|---|---|
| 1 | `VaultActivity` opens on an attacker-set Intent extra | static | — | decompiled | `getBooleanExtra("...UNLOCK", false)` with no caller check | HYPOTHESIS | Medium | — |
| 1 | as above | dynamic | shell | observed log | after `am force-stop`, `am start --ez ...UNLOCK true` → `vault opened via extra; secret=CH73{...}` | CONFIRMED | Medium | unchanged |
| 1a | The first attempt appeared to refute claim 1 | dynamic | shell | observed output | `Warning: Activity not started, intent has been delivered to currently running top-most instance` | NOT TESTED → retested | — | tooling, not target |
| 2 | `NotesProvider` is exported with no permission | static | — | manifest | `<provider ... exported="true">`, no `permission` attribute | HYPOTHESIS | Medium | — |
| 2 | as above | dynamic | shell | observed output | `content query` returns 3 rows including `Bearer ch73...` | CONFIRMED | **High** | the table holds a credential; static could not see the contents |
| 2a | `query()` ignores `selection` | dynamic | shell | observed output | `--where "_id=1"` still returns 3 rows | CONFIRMED | Low, but changes the fix | discovered while testing claim 2 |
| 3 | `AdminReceiver` is exported and destructive | static | — | manifest | `exported="true"`, `WIPE` action | HYPOTHESIS | **High** | — |
| 3 | as above | dynamic | shell | observed log | `am broadcast` printed `Broadcast completed: result=0`; **receiver never logged** | REFUTED | — | guarded by a `signature` permission; no co-signed package exists |
| 3 | as above | dynamic | root | observed log | identical `am` output; receiver **did** log | CONFIRMED for root only | Informational | severity is a function of the caller |
| 4 | The "encryption" is a repeating-key XOR with an embedded key | static | — | decompiled | 16-byte constant feeding an XOR loop, then Base64 | HYPOTHESIS | Low | — |
| 4 | as above | dynamic | none needed | reproduced offline | XOR of the exported row with the constant → `CH73{the-chain-is-the-lesson}` | CONFIRMED | **Medium** | combined with claim 2: recoverable with no device and no execution |

### 4.1 What the worked example is trying to show

Read down the Verdict column, not across the rows.

- **Three of four static severity predictions were wrong**, and the most confident one — claim 3, the
  only `High` — was the one that did not survive.
- **Two severities went up**, and neither went up for a reason available to static analysis. Claim 2
  rose because the data was visible only at run time; claim 4 rose because of its *combination* with
  claim 2, which no per-topic methodology would have composed.
- **Claim 1a exists.** A row recording that your own tooling produced a false negative is a row most
  people delete. Keeping it is what makes the reproduction steps correct for the next person.
- **Claim 3 has two rows with different vantages and opposite verdicts**, rather than one row with a
  hedge. That is the shape to copy.

---

## 5. `DIVERGED`, and what it does and does not mean

When you re-run a claim from another chapter, another report, or your own earlier session, and get a
different answer, the verdict is `DIVERGED` — **not** "the original was wrong".

A divergence has at least five plausible causes, and you usually cannot tell which from one run:

1. The device is different (version, OEM, root stack, patch level).
2. The vantage is different — the commonest cause by a wide margin.
3. The tool version is different.
4. The original was measured incorrectly.
5. You measured incorrectly.

Record it as `DIVERGED, cause not established` and move on. Resolving it by assertion — picking
whichever of the five flatters you — costs more than leaving the question open, because it converts
an honest unknown into a confident error that the next reader inherits.

[74-CaseStudies](../../74-CaseStudies/README.md) is six worked examples of this, and its
[`examples/reproduction-log.md`](../../74-CaseStudies/examples/reproduction-log.md) is the reference
implementation of a divergence written up properly. See also
[`divergence-report.md`](divergence-report.md) in this directory for the short form.

---

## 6. Before you hand it over

- [ ] Every row has a verdict. No row is still `HYPOTHESIS`.
- [ ] Every `CONFIRMED` row names a vantage.
- [ ] Every `CONFIRMED` row's Evidence column contains output, not a description of output.
- [ ] The header block's `Vantages NOT used` line is filled in and non-empty. If it is empty, you
      have not thought about it.
- [ ] Every severity that moved has a reason in the last column.
- [ ] Anything you could not test is a `NOT TESTED` row, not an absence.
