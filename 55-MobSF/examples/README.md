# 55-MobSF — examples

Six files. Two are fixtures you feed to the scripts, two are unedited tool output, and two are the
deliverables a scanner run is supposed to end in.

> **Warning — read this before quoting anything here**
> **MobSF was not run while this chapter was written.** Docker's Linux engine does not start on the
> authoring machine and MobSF is not installed as a Python package; the evidence is in
> [README §1.6](../README.md#16-installation-reality--mobsf-was-not-run-here). The two `.json` files
> are therefore **hand-built fixtures in MobSF's report shape**, not MobSF output. Every *value* in
> them is a real measurement of the APK named in the file; every *structural* element — key names,
> rule identifiers, severity strings, CVSS numbers, the security score — is a reconstruction. Each
> file says so in its own `_fixture` block, which is the first key in the file precisely so it cannot
> be missed.
>
> Nothing in this directory is a transcript of a scan that did not happen.

---

## The files

| File | What it is | Real or reconstructed |
|---|---|---|
| [`synthetic-mobsf-report.json`](synthetic-mobsf-report.json) | Fixture: `CMPen-Android-App-v1.2.apk`, R8-processed | Values measured; structure reconstructed |
| [`synthetic-mobsf-report-v1.0.json`](synthetic-mobsf-report-v1.0.json) | Fixture: the same app at v1.0, **unobfuscated** | Values measured; structure reconstructed |
| [`validate-output-cmpen-v1.2.txt`](validate-output-cmpen-v1.2.txt) | Unedited output of `mobsf-validate.py` | **Real tool output, real measurements** |
| [`triage-output-two-apks.txt`](triage-output-two-apks.txt) | Unedited output of `mobsf-triage.py --explain` | **Real tool output** |
| [`findings-ledger.csv`](findings-ledger.csv) | The hand-adjudicated ledger: every item, every rejection, every reason | Human adjudication of the above |
| [`finding-rewritten.md`](finding-rewritten.md) | Four scanner outputs rewritten as defensible report entries | Human writing, measured evidence |

---

## The target, and why these two APKs

Both fixtures describe **CMPen-Android-App**, a public, deliberately-vulnerable Android training
application. Naming it is fine — it is a teaching target, not a commercial product, and
[52-StaticAnalysis §9](../../52-StaticAnalysis/README.md#9-examples) sets the same precedent. Any
commercial application this repository discusses is anonymised.

| | v1.0 | v1.2 |
|---|---|---|
| SHA-256 | `f7daada6…f501ff` | `13718667…c39638` |
| Size | 5,646,105 bytes | 287,060 bytes |
| `minSdk` / `targetSdk` | 20 / 33 | 24 / 35 |
| DEX files | 1 | 1 |
| Decompiled `.java` files | 1,995 | 234 |
| jadx result | `finished with errors, count: 8`, 1,757 classes | clean, 171 classes |
| R8 / obfuscation | **no** — `RetrofitClient`, `CertificatePinner` intact | **yes** — the pinner is `m.e`, `m.d`, `m.g` |
| `android:debuggable` | **true** | absent |
| Signer | `CN=Android Debug` (`045bc19b…`) | `CN=Android Debug` (`5b571963…`) |
| Configured SPKI pins | **3**, for `ninja.secops.group` | **1**, for `ninja.secops.group` |

**That last pair of rows is why there are two fixtures.** The two builds differ in exactly one
property that matters to a scanner — whether R8 ran — and they produce opposite pinning verdicts from
the same name-based rule. A single sample would have made that a claim; two make it a controlled
comparison. It is worked in full in
[`finding-rewritten.md` rewrite 2](finding-rewritten.md#rewrite-2--the-finding-the-scan-got-backwards).

---

## Reproducing the tool output

Both text files were produced by the shipped scripts, and both can be regenerated. You need the APK;
the fixtures ship here.

```bash
# host - decompile once
jadx -d out CMPen-Android-App-v1.2.apk        # or: java -cp .../jadx-gui-*-all.jar jadx.cli.JadxCLI -d out ...

# host - validation. This is the run in validate-output-cmpen-v1.2.txt
python3 -B ../scripts/mobsf-validate.py \
    --report ../examples/synthetic-mobsf-report.json \
    --apk ./CMPen-Android-App-v1.2.apk \
    --tree ./out \
    --csv ledger-raw.csv

# host - triage across both fixtures. This is triage-output-two-apks.txt
python3 -B ../scripts/mobsf-triage.py --from-reports ../examples/ --explain
```

The validator wants `aapt2` on `PATH` for an authoritative manifest parse. Without it, it falls back
to `aapt`, and then to a raw AXML string scan — and it **says which link of the chain answered**, on
the `manifest via:` line, so you never have to guess how strong a check was.

---

## The numbers these runs produced

Measured, on this machine, on 2026-08-12. They are the numbers quoted in
[README §9](../README.md#9-examples) and [§13](../README.md#13-summary).

| | v1.2 (R8) | v1.0 (no R8) |
|---|---|---|
| Report items normalised | 39 | 29 |
| CORROBORATED | 16 | 10 |
| UNDER-RATED (severity too low) | 1 | 0 |
| OVER-RATED (severity too high) | 3 | 3 |
| REFUTED (measurement contradicts the report) | 2 | 3 |
| RESTATES (scorecard duplicating another section) | 11 | 8 |
| NEEDS-HUMAN | 6 | 5 |
| Survival, all items | 17/39 = **43.6%** | 10/29 = **34.5%** |
| Survival, excluding the scorecard | 17/27 = **63.0%** | 9/19 = **47.4%** |

Then the ledger — which is the *human* pass, and the only one that produces findings:

| Outcome after hand adjudication (v1.2) | Count |
|---|---|
| **FINDING** | 8 |
| MERGED into another finding | 6 |
| LEAD (real, not yet a finding) | 2 |
| **REJECTED, with a written reason** | 15 |
| Findings the scan **did not report at all** | 2, plus 1 recorded limit |

**Eight findings from thirty-nine report items, and two of the eight are things the scan never
mentioned.** That ratio, not the scan's item count, is what the engagement produced.

> **Mental Model**
> The survival rate is a property of the *pairing* — this rule set against this application — and not
> a property of MobSF. Run it on a well-built app with three components and it will be higher; run it
> on a 200-component enterprise app and it will be far lower, because the exported-component rules
> fire once per component and almost none of them will matter. Measure it on your own corpus; do not
> quote 63% at anyone.

---

## Reading `findings-ledger.csv`

One row per item, in the order the validator emitted them, plus the rows nothing emitted.

| Column | What it holds |
|---|---|
| `id` | The validator's `V0nn`, so a row can be traced back to the raw output |
| `mobsf_section` | Which part of the report it came from — `manifest`, `code`, `certificate`, `secrets`, `appsec` |
| `mobsf_severity`, `mobsf_cvss` | **The scanner's** numbers, kept so the disagreement is visible |
| `tool_verdict` | What `mobsf-validate.py` concluded from evidence alone |
| `human_verdict` | `FINDING` / `MERGED` / `LEAD` / `REJECTED` / `LIMIT` — a person's call |
| `human_severity` | Only filled for `FINDING` rows, and it is a severity, not a CVSS |
| `reason` | **The point of the file.** Why this row ended where it did |
| `evidence` | The command, file and line that settles it |
| `owning_chapter` | Which chapter of this repository owns the analysis, so the reader can go deeper |

Rows `NOT-REPORTED-1` through `-3` have no `id` from the tool because **nothing generated them**.
They are the two findings and one limit that came out of reading the code the scanner pointed at,
rather than out of the scanner. `NOT-REPORTED-1` — a SHA-256 digest truncated to 16 bytes and used
directly as an AES key, with no KDF and no IV — has the widest blast radius of anything in the
application, and no rule exists for it.

---

## Related

| Chapter | Why |
|---|---|
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Owns the validation discipline this ledger applies. Its `examples/findings-ledger.csv` is the same artefact for a hand-run sweep |
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | The pinning measurement and `pinning-surface.py`, used to refute rewrite 2 |
| [32-Manifest](../../32-Manifest/README.md) | `manifest-audit.py`, the right validator for every manifest row above |
| [43-WebView](../../43-WebView/README.md) | The bridge finding in rewrite 1 |
| [34-Cryptography](../../34-Cryptography/README.md) | The ECB row, and the KDF defect no rule reported |
| [80-Appendix](../../80-Appendix/README.md) | The report template and severity rubric |
