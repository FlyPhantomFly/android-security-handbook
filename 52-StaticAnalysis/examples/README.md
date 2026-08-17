# 52 — Static Analysis · Examples

Three files, meant to be read together and in this order.

| File | What it is |
|---|---|
| [`sweep-output-fridathree.txt`](sweep-output-fridathree.txt) | The **real, unedited** output of [`../scripts/static-sweep.py`](../scripts/static-sweep.py) against a public training APK pulled from the test device. The only edit is the absolute scratch path, replaced with `./out` |
| [`triage-worksheet.md`](triage-worksheet.md) | What a human then did with that output: nine leads, worked top-down, with the four questions answered and a reason recorded against every verdict |
| [`findings-ledger.csv`](findings-ledger.csv) | The ledger. Two runs — the training APK and an anonymised 17 MB commercial application — with `verdict` and `reason` columns filled in. **Most rows are rejections, and that is the point** |

---

## Why the rejections are the deliverable

A report that shows only what survived looks like luck. A ledger that shows 35 leads worked down to
3 findings, with a checkable reason against each of the 32 rejections, looks like a method — and it
is the artefact that makes a client trust the ones that did survive.

The two runs in `findings-ledger.csv`:

| Run | Leads recorded | Findings | Informational | Deferred | Rejected |
|---|---|---|---|---|---|
| `fridathree` (public training APK, named) | 9 | 1 | 1 | 0 | 7 |
| `hrapp` (commercial app, anonymised) | 26 | 2 | 0 | 2 | 22 |

`hrapp` records the 17 highest-confidence leads plus a selection of the lower bands, not all 96 —
the full queue is in the chapter, and the ledger's job here is to show the *shape* of a worked queue
rather than to be exhaustive.

---

## Anonymisation, stated plainly

This repository may be published.

- **`fridathree` is named**, because `com.mobilehackinglab.FridaThree` is a public, deliberately
  vulnerable training application and naming it is both safe and useful. Its APK hash is printed so
  you can confirm you have the same artefact.
- **`hrapp` is anonymised.** It is a real 17 MB commercial application that was installed on the test
  device. Its package is written `com.vendor.hrapp`, bundled SDK names are written `<sdk>`, internal
  hostnames are substituted, the credential value is **redacted**, and the APK hash is omitted
  deliberately because publishing it would identify the app.
- **Every count, ratio, confidence and timing is the real measured number.** Nothing was rounded to
  make a point.

Redacting a credential you found is not just courtesy to the vendor; it is the same discipline you
apply in a client report, where the finding is "a token is embedded at `Class.method`" and the value
itself goes in a separately-handled evidence pack.

---

## Reproducing the `fridathree` run

```bash
# host — you need the APK; it is a public MobileHackingLab training target
sha256sum base.apk
# 37299c1488934e53e316a57bd0a0d9ea8145598888c193ebdfa77971eb611d49

jadx -d out base.apk
python3 -B ../scripts/static-sweep.py ./out --show-suppressed
```

Your output should match `sweep-output-fridathree.txt` line for line except for the tree path. If it
does not, the most likely causes are a different jadx version producing a slightly different tree, or
a modified rule catalogue — `--print-catalogue` will tell you which rules you are running.

---

## Using the ledger as a template

The CSV columns are the ones [`static-sweep.py --csv`](../scripts/static-sweep.py) emits, plus the
two it deliberately leaves empty for you:

```
run,lead_id,rule_id,category,confidence,band,value,n_sites,n_files,first_site,scope,verdict,reason
```

| Column | Filled by |
|---|---|
| `run` … `scope` | The tool |
| `verdict` | **You.** One of FINDING / INFORMATIONAL / REJECTED / DEFERRED |
| `reason` | **You.** One sentence, required even for FINDING |

Keep the ledger between engagements and between releases. Re-import it, carry previous verdicts
forward on a `(rule_id, value)` match, and surface only leads with no recorded verdict. After three
releases a team is triaging a handful of new leads per cycle instead of the whole queue — see
[README §9.5](../README.md#95-enterprise--sweeping-every-build-and-reporting-the-delta).
