# 78 — Diagrams · References

Annotated. Chapter: [../README.md](../README.md).

---

## Generated artefacts in this directory

These two files are **built mechanically** by
[`../scripts/diagram-census.py`](../scripts/diagram-census.py) and must never be hand-edited. Rebuild
them with `python3 -B scripts/diagram-census.py` from the chapter directory, then verify with
`python3 -B scripts/verify-index-links.py`.

| File | What it is | Use it when |
|---|---|---|
| [`diagram-index.md`](diagram-index.md) | Every Mermaid diagram in the repository, grouped by chapter, in order of appearance | You know roughly which chapter and want to scan its pictures |
| [`diagram-index-by-type.md`](diagram-index-by-type.md) | The same set, grouped by Mermaid family, largest family first | You want a worked example of a diagram *shape*, regardless of subject |

Both carry the same columns: **Depicts** (the diagram's own title, or the heading above it — never
invented), **Type**, **Nodes** (a crude size signal), **Boundaries** (`subgraph` count, which is how
this repository draws a trust boundary), **Atk** (whether it colours attacker-controlled input
`#f9d0d0`), and a link to the section.

### What the index measured, on 2026-08-16

| Measurement | Value |
|---|---:|
| Diagrams outside this chapter | 775 |
| Files containing at least one | 172 |
| In a chapter `README.md` | 663 |
| Elsewhere — `mindmap.md`, `faq.md`, labs | 112 |
| Drawing at least one `subgraph` boundary | 215 |
| Colouring attacker input `#f9d0d0` | 300 |
| Median node count | 7 |
| Largest node count | 46 |
| Parsing under Mermaid 11.16.1 | 753 of 812 |
| **Failing to parse** | **59**, in 44 files across 40 chapters |

Re-run before quoting. Every number moves when a chapter is edited.

---

## Mermaid

| Link | Note |
|---|---|
| https://mermaid.js.org/ | The project. Start here |
| https://mermaid.js.org/intro/syntax-reference.html | The syntax index, by diagram type. The only page you need bookmarked |
| https://mermaid.js.org/syntax/flowchart.html | Node shapes, edge types, subgraphs, styling. Section 5.2 of the chapter is the security-relevant subset |
| https://mermaid.js.org/syntax/sequenceDiagram.html | **Read the "Notes" and "Loops/Alt/Opt" sections.** This is also where the reserved keywords that break participant ids are implicitly documented |
| https://mermaid.js.org/syntax/stateDiagram.html | Composite states, forks, concurrency |
| https://mermaid.js.org/syntax/classDiagram.html | Relationship arrows and member visibility |
| https://mermaid.js.org/syntax/mindmap.html | Note the node-shape delimiters — the reason unquoted parentheses in leaf text break the diagram |
| https://mermaid.js.org/syntax/block.html | `block-beta`, used here for memory and filesystem layouts |
| https://mermaid.live/ | Live editor. Parses a pasted block instantly; the fastest way to isolate one failure |
| https://github.com/mermaid-js/mermaid | Source. The `packages/mermaid/src/diagrams/*/parser` directories are the actual grammars |

---

## GitHub rendering

| Link | Note |
|---|---|
| https://github.blog/2022-02-14-include-diagrams-markdown-files-mermaid/ | The announcement of native Mermaid rendering in GitHub Markdown. Why this repository can use text diagrams at all |
| https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/creating-diagrams | GitHub's own documentation, including the version of Mermaid it ships |
| https://github.com/Flet/github-slugger | The heading-to-anchor algorithm GitHub uses. Both scripts here reimplement it, and both got it wrong twice before matching this |
| https://spec.commonmark.org/ | CommonMark. The fenced-code-block section is what the fence state machine in both scripts implements |

---

## Diagramming systems well

| Link | Note |
|---|---|
| https://c4model.com/ | The clearest public treatment of *levels of abstraction* in a diagram. Its central discipline — one level per diagram — is what stops the 40-node monsters |
| https://learn.microsoft.com/en-us/security/engineering/threat-modeling-with-stride | Data-flow diagrams where **trust boundaries are the primary object**, not decoration. The closest formal relative of section 6.1 |
| https://owasp.org/www-community/Threat_Modeling | OWASP's overview, including the four questions a threat model answers |
| https://www.threatmodelingmanifesto.org/ | Short, and the "values" section is a good corrective to template-filling |
| https://cisa.gov/securebydesign | Design-level security guidance. Useful vocabulary when a diagram has to be defended to a non-technical audience |
| https://en.wikipedia.org/wiki/Unified_Modeling_Language | UML. Mermaid's class and sequence notation is a subset of it, and knowing that explains several syntax choices |

---

## Platform sources behind the repository-level diagrams

Each of these backs one diagram in [section 4](../README.md#4-repository-level-diagrams).

| Link | Backs |
|---|---|
| https://developer.android.com/guide/platform | 4.1 — the security stack |
| https://source.android.com/docs/security | 4.1 — the security model overview |
| https://source.android.com/docs/security/features/verifiedboot | 4.2 — the boot chain and the boot state |
| https://source.android.com/docs/security/features/verifiedboot/boot-flow | 4.2 — the stage-by-stage flow |
| https://source.android.com/docs/core/architecture/hidl/binder-ipc | 4.5 — Binder transactions |
| https://developer.android.com/develop/background-work/services/aidl | 4.5 — the generated Proxy and Stub |
| https://source.android.com/docs/security/app-sandbox | 4.4 — where the sandbox boundary actually is |
| https://source.android.com/docs/security/features/selinux | 4.7 — why root is not unconfined |
| https://developer.android.com/about/versions | 4.6 — behaviour that changes what you must test |

---

## The measured cases in section 7

| Case | Where it was measured |
|---|---|
| `UiAutomation.executeShellCommand` runs at uid 2000 from inside an app process | [66-Instrumentation](../../66-Instrumentation/README.md) |
| A patched licence check that changed nothing, because an upstream guard short-circuits | [74-CaseStudies lab 02](../../74-CaseStudies/labs/lab-02-the-patch-that-changed-nothing.md) and [59-radare2 lab 04](../../59-radare2/labs/lab-04-ctf-the-gate-that-was-not-there.md) |
| `/data/adb/lspd` returns the same answer present or absent | Measured here, on the emulator described in [section 3](../README.md#3-the-census--what-the-repository-actually-contains); background in [37-RootDetection](../../37-RootDetection/README.md) and [63-LSPosed](../../63-LSPosed/README.md) |
| The `su` binary is not where the canonical Magisk diagram puts it | Measured here; background in [62-Magisk](../../62-Magisk/README.md) |

---

## Tooling this chapter depends on

| Tool | Version used | Note |
|---|---|---|
| Node.js | v20.19.1 | Runs `validate-mermaid.mjs` |
| `mermaid` | 11.16.1 | Installed **out of tree**. Never commit `node_modules` |
| `jsdom` | current at the time | Supplies the DOM Mermaid needs during initialisation |
| CPython | 3.13.3 | Runs both Python scripts. Always with `-B` so no `__pycache__` appears |

---

## Related chapters

- [06-Android-Architecture](../../06-Android-Architecture/README.md) — the layering compressed into section 4.1
- [20-Security-Architecture](../../20-Security-Architecture/README.md) — Verified Boot in full
- [21-App-Sandbox](../../21-App-Sandbox/README.md) — the boundary section 4.4 says is misdrawn
- [22-SELinux](../../22-SELinux/README.md) — why root is not unconfined
- [25-Binder](../../25-Binder/README.md) — the transaction section 4.5 traces
- [62-Magisk](../../62-Magisk/README.md) — the rooting mechanism case 4 measures
- [66-Instrumentation](../../66-Instrumentation/README.md) — the uid 2000 case
- [74-CaseStudies](../../74-CaseStudies/README.md) — the patch that changed nothing
- [75-InterviewQuestions](../../75-InterviewQuestions/README.md) — the generated-index pattern this chapter borrows
- [76-CheatSheets](../../76-CheatSheets/README.md) — condensed operational references
- [77-UsefulCommands](../../77-UsefulCommands/README.md) — the commands behind the measurements
- [79-Glossary](../../79-Glossary/README.md) — terminology
- [80-Appendix](../../80-Appendix/README.md) — severity, reporting, version matrix
