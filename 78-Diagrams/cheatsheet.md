# 78 — Diagrams · Cheat Sheet

Notation, conventions, commands and failure modes on one page. Chapter: [README.md](README.md).

---

## Mermaid families

| Family | Question it answers | Count in repo | Share |
|---|---|---:|---:|
| `flowchart` | What connects to what | 422 | 51.2% |
| `mindmap` | What are the parts of this topic | 169 | 20.5% |
| `sequenceDiagram` | Who, in what order | 157 | 19.1% |
| `stateDiagram-v2` | What state, and what changes it | 36 | 4.4% |
| `block-beta` | Where it sits in memory or on disk | 28 | 3.4% |
| `classDiagram` | The shape of the data | 12 | 1.5% |

---

## Flowchart notation

| Syntax | Meaning |
|---|---|
| `A --> B` | Directed edge: control or data flows this way |
| `A --- B` | Undirected: association with no direction of trust |
| `A -.-> B` | Dotted: conditional, optional, indirect, or **not observed** |
| `A ==> B` | Thick: the primary path when several are drawn |
| `A -- "text" --> B` | Labelled edge. **Label names the transport** |
| `A["x"]` | Rectangle — user-space process or component |
| `A(["x"])` | Stadium — **kernel space** |
| `A[["x"]]` | Subroutine — **hardware / TEE / secure element** |
| `A(("x"))` | Circle — endpoint |
| `A{"x"}` | Diamond — a decision |
| `A[/"x"/]` | Parallelogram — data in or out |
| `subgraph N["name"] … end` | **Trust boundary**, name says whose |
| `style A fill:#f9d0d0` | **Attacker-controlled** |
| `flowchart TB / TD / BT / LR / RL` | Direction |

---

## Sequence notation

| Syntax | Meaning |
|---|---|
| `A->>B: m` | Call or message out |
| `A-->>B: m` | **Return / reply** (dashed) |
| `A-)B: m` | Asynchronous, no reply expected |
| `A--)B: m` | Asynchronous reply |
| `A-xB: m` | Message with an end cross |
| `A->>A: m` | Self-message — **no boundary crossed** |
| `A->>+B: m` / `B-->>-A: r` | Activate / deactivate the participant bar |
| `participant X as Display Name` | Declare with a short id and a readable label |
| `actor X` | Draw a stick figure instead of a box |
| `Note over A,B: text` | Statement spanning participants |
| `Note left of A:` / `Note right of A:` | Statement beside one participant |
| `alt` / `else` / `end` | Mutually exclusive paths |
| `opt` / `end` | May not happen at all |
| `loop cond` / `end` | Repetition |
| `par` / `and` / `end` | Concurrent branches |
| `critical` / `option` / `end` | Must-happen with fallbacks |
| `rect rgb(249,208,208)` … `end` | The only way to colour a region here |
| `autonumber` | Number every message |

---

## State and class notation

| Syntax | Meaning |
|---|---|
| `[*] --> S` | Start pseudo-state |
| `S --> [*]` | Terminal pseudo-state |
| `A --> B: event` | **Label is the event that causes the transition** |
| `state S { … }` | Composite state |
| `state fork_state <<fork>>` | Fork / join |
| `note right of S … end note` | Note attached to a state |
| `--` inside a composite | Concurrency separator |
| `class C { +field -priv Method() }` | Class with members |
| `A <\|-- B` | B inherits A |
| `A *-- B` | Composition |
| `A o-- B` | Aggregation |
| `A --> B` | Association |
| `A ..> B` | Dependency |

---

## Repository conventions (STYLE-GUIDE.md §6)

| Convention | Written as |
|---|---|
| Trust boundary | `subgraph Name["whose boundary this is"]` |
| Attacker-controlled input | `style X fill:#f9d0d0` |
| Kernel space | `X(["name"])` |
| Hardware / TEE | `X[["name"]]` |
| Transport on an edge | `-- "Binder" -->`, `-- "syscall" -->`, `-- "HTTPS" -->` |
| Deliberate non-boundary | `subgraph` whose name says so, members joined `---` |
| Unobserved edge | `-.->` |

---

## Commands

```bash
# host, from 78-Diagrams/ — regenerate both index artefacts
python3 -B scripts/diagram-census.py

# host — census numbers only, writes nothing
python3 -B scripts/diagram-census.py --stats

# host — least-illustrated chapter READMEs
python3 -B scripts/diagram-census.py --poor

# host — CI gate: every teaching chapter README has >= 2 diagrams
python3 -B scripts/diagram-census.py --check

# host — machine-readable block list
python3 -B scripts/diagram-census.py --format json --out - > blocks.json
python3 -B scripts/diagram-census.py --format csv  --out - > blocks.csv
```

```bash
# host — ONE-TIME setup, out of tree so no node_modules lands in the repo
mkdir -p /tmp/mmv && cd /tmp/mmv && npm init -y && npm install mermaid@11 jsdom
export MERMAID_MODULES=/tmp/mmv

# host, from 78-Diagrams/ — parse every diagram in the repository
node scripts/validate-mermaid.mjs

# host — this chapter only
node scripts/validate-mermaid.mjs --root .

# host — one file
node scripts/validate-mermaid.mjs ../25-Binder/README.md

# host — machine-readable, includes a likely-cause per failure
node scripts/validate-mermaid.mjs --json
```

```bash
# host, from 78-Diagrams/ — resolve every relative link and anchor
python3 -B scripts/verify-index-links.py

# host — the whole repository
python3 -B scripts/verify-index-links.py --all

# host — print every link checked, not only the broken ones
python3 -B scripts/verify-index-links.py --verbose
```

---

## Parse failures measured in the 2026-08-16 snapshot

753 of 812 blocks parsed; 59 failed, across 44 files in 40 chapters. None was in chapter 78. The
current validator reports 824 of 824 sources parsing and 0 failures, but the six causes below are
still the checklist to run when an edit breaks a diagram.

| Count (2026-08-16) | Cause | Fix |
|---:|---|---|
| 35 | `;` in message or label text | Comma, or `<br/>` |
| 10 | Unquoted `(` `[` `{` in **mindmap** node text | `id["the text (here)"]` |
| 6 | `\"` inside a quoted label | `#quot;` or drop the inner quotes |
| 6 | `style` / `classDef` inside `sequenceDiagram` | `rect rgb(...)` block, or a `Note` |
| 1 | Participant id collides with a keyword (`Opt`) | Rename the id, keep the label via `as` |
| 1 | Unquoted parentheses in flowchart node text | Quote the whole label |
| — | Mindmap leaf text **starting** with a type keyword | Reword the leaf |

Reserved sequence ids, matched **case-insensitively**:
`opt` `alt` `else` `loop` `par` `and` `rect` `break` `critical` `option` `note` `end`
`activate` `deactivate` `autonumber` `link` `links` `box` `over` `right` `left` `of` `title`

---

## Escapes and entities

| Want | Write |
|---|---|
| `"` inside a label | `#quot;` |
| `(` `)` inside a label | Quote the whole label: `A["f(x)"]` |
| `<` `>` | `&lt;` `&gt;` |
| Line break in a label | `<br/>` |
| `#` | `#35;` |
| `;` in text | Avoid it — use a comma |
| Unicode | Works as-is; the file must be BOM-less UTF-8 |

---

## Family selection

| Reader's question | Draw | Do not draw |
|---|---|---|
| What can reach what | `flowchart` + `subgraph` | Sequence |
| Who talks to whom, in what order | `sequenceDiagram` | Flowchart |
| What state, and what changes it | `stateDiagram-v2` | Flowchart |
| What is in this structure | `classDiagram` or a table | Flowchart |
| Where in memory or on disk | `block-beta` or ASCII | Flowchart |
| What are the parts of this topic | `mindmap` | Anything, for mechanism |

Tell that a flowchart should have been a sequence diagram: **past-tense verbs on the edges.**

---

## Pre-ship checklist

- [ ] Every `subgraph` name says *whose* boundary
- [ ] Attacker-controlled **input** coloured, not the vulnerable component
- [ ] Every sequence edge names its transport
- [ ] Returns are `-->>`, calls are `->>`
- [ ] A failure or denial path exists, not only the happy one
- [ ] No arrow drawn that was not observed — or it is dotted
- [ ] Prose beside it saying what the reader is looking at
- [ ] `node scripts/validate-mermaid.mjs --root .` passes
- [ ] `python3 -B scripts/verify-index-links.py` passes

---

## Boxes that are drawn as boundaries and are not

| Drawn as separate | Reality |
|---|---|
| App code vs third-party SDK | One address space, one UID, one permission set |
| App code vs bundled `.so` | Same process, same memory |
| App vs its WebView | A component of the app process |
| `exported="false"` | Blocks other **apps**; not `shell`, not privileged components |
| Root | Defeats DAC only. SELinux still enforcing (`u:r:su:s0`) |
| Obfuscated code | Cost, not a boundary |
| Key "in KeyStore" | Extraction blocked, **use** is not |

---

## The one claim every diagram makes

**The arrows drawn are all the arrows there are.** Measured counter-examples in this repository:

| Case | The omitted path | Chapter |
|---|---|---|
| App sandbox drawn as one UID box | `UiAutomation.executeShellCommand` runs at **uid 2000** from inside the app process | [66](../66-Instrumentation/README.md) |
| Licence gate drawn as a chain | An upstream guard short-circuits before the check is reached | [74](../74-CaseStudies/README.md), [59](../59-radare2/README.md) |
| Root detection drawn as "path exists → rooted" | `/data/adb/lspd` returns `EACCES` present **or** absent — the check carries no information | [37](../37-RootDetection/README.md), [63](../63-LSPosed/README.md) |
| Magisk drawn with `su` at `/system/bin/su` | Measured device has `/system/xbin/su`, `u:object_r:su_exec:s0`, from the `userdebug` build, bypassing `magiskd` entirely | [62](../62-Magisk/README.md) |
