# 71 — OWASP MAS · Examples

Four artefacts and two data fixtures. Two of them are documents you read; two are files you feed to
the scripts.

Everything here is **illustrative**. The apps, findings, evidence filenames and states are invented
to make a teaching point. None of it is an assessment of any real or published build, and no state
in these files may be quoted as one.

---

## Documents

| File | What it shows | Read it |
|---|---|---|
| [`assessment-result-table.md`](assessment-result-table.md) | A control-by-control coverage table at report quality: methodology header, scope statement, state vocabulary, the table itself, an evidence index, a stated coverage denominator — and the same table done badly, row by row | **After** you have built your own in [`labs/lab-02`](../labs/lab-02-map-a-known-app.md) |
| [`finding-mapped-twice.md`](finding-mapped-twice.md) | One observation written up mechanically and then written up after thinking. The two reach different severities, different control sets and different remediations | Any time; it is the shortest statement of what this chapter is for |

---

## Fixtures

| File | Feeds | Contains a deliberate defect |
|---|---|---|
| [`findings-ovaa.csv`](findings-ovaa.csv) | `mas-coverage.py` — single-app mode | Yes: one control marked `PASS` with no evidence, so you can watch it be refused |
| [`portfolio-findings.csv`](portfolio-findings.csv) | `mas-coverage.py --heatmap` | Yes: one row carries a retired `MSTG-*` identifier, which is refused and leaves a visible hole in the matrix |
| [`profile-banking.json`](profile-banking.json) | `scope-checklist.py` | No — this is the profile where resilience is correctly in scope, with a named adversary |
| [`profile-internal-tool.json`](profile-internal-tool.json) | `scope-checklist.py` | No — this is the profile where resilience is correctly out of scope, with a defensible reason |

The defects are the point. A fixture that only exercises the happy path teaches you nothing about
what the tool is for.

---

## Run them

```bash
# host — from 71-OWASP-Mobile/
python3 scripts/mas-coverage.py examples/findings-ovaa.csv
python3 scripts/mas-coverage.py examples/portfolio-findings.csv --heatmap
python3 scripts/scope-checklist.py examples/profile-internal-tool.json
python3 scripts/scope-checklist.py examples/profile-banking.json --markdown
```

```bash
# host — the mode that refuses to pass a table with unsubstantiated rows
python3 scripts/mas-coverage.py examples/findings-ovaa.csv --strict
echo "exit status: $?"
```

---

## The two profiles, side by side

They exist as a pair, and the pair is the lesson. Same script, same rules, opposite answers on the
category that testers most often get wrong.

| | `profile-internal-tool.json` | `profile-banking.json` |
|---|---|---|
| `hostile_device_owner` | `false` | `true` |
| Named adversary | none, and none is needed | fraud rings on emulator farms; SIM-swap account takeover |
| MASVS-RESILIENCE | **Excluded**, with a reason and the event that would reverse it | **In scope**, with the adversary quoted into the justification |
| MASVS-NETWORK-2 | Excluded — the client controls both endpoints and the CA | In scope |
| Blocked controls | STORAGE-1, for want of a rooted device | AUTH-1, for want of a second account |
| Days | 3 — and the allocator will tell you that is fewer than the scope needs | 10 |

Set `hostile_device_owner` to `true` in the internal-tool profile and blank the adversary field. The
script keeps resilience in scope but marks it provisional and tells you to name an adversary or
reconsider — because a resilience recommendation with no named adversary is the most expensive bad
advice in mobile security.

---

## Related

| Where | For |
|---|---|
| [`../scripts/mas-coverage.py`](../scripts/mas-coverage.py) and [`../scripts/scope-checklist.py`](../scripts/scope-checklist.py) | Both carry a full header comment: purpose, usage, requirements, and an honest "what this will NOT tell you" |
| [`../cheatsheet.md`](../cheatsheet.md) | The control list and the finding-to-control lookup these fixtures use |
| [`../labs/lab-01-build-the-checklist.md`](../labs/lab-01-build-the-checklist.md) | Where the profiles come from |
| [`../labs/lab-02-map-a-known-app.md`](../labs/lab-02-map-a-known-app.md) | Where the single-app fixture's shape comes from |
| [`../labs/lab-04-portfolio-heatmap.md`](../labs/lab-04-portfolio-heatmap.md) | Where the portfolio fixture's shape comes from |
