# 78 — Diagrams · FAQ

The questions people actually ask about the diagrams in this repository, including the ones that feel
too basic to ask. Chapter: [README.md](README.md).

---

### 1. Why doesn't this chapter just contain all the diagrams?

Because a copied diagram is wrong twice over.

It is **stale on arrival**: the moment [25-Binder](../25-Binder/README.md) refines its transaction
diagram, this chapter holds a second, contradictory version of the same claim, and nothing tells a
reader which one is current.

It is also **separated from its prose**. STYLE-GUIDE.md section 2 requires that every diagram is
followed by prose explaining what the reader is looking at. Copy 787 diagrams without their prose and
you have broken that rule 787 times. Copy both and you have copied the repository.

An index cannot go stale in that way, because it is regenerated rather than transcribed. Re-run
`python3 -B scripts/diagram-census.py` and it is correct again.

---

### 2. What actually is a "Mermaid diagram"?

Text that a renderer turns into a picture. You write it inside a fenced code block whose info string
is `mermaid`, GitHub renders it as an image when it displays the file, and the *source of truth stays
text* — which means it diffs, greps and reviews like code.

That last property is why this repository uses Mermaid rather than exported PNGs. A PNG in a Git
repository is an opaque blob that nobody updates. A diagram you can grep for is a diagram that gets
maintained.

---

### 3. I opened a chapter and one diagram is a red error box. Is my browser broken?

Not necessarily. A red box means the renderer could not draw the diagram. Every one of the
repository's 824 sources currently parses, so the cause is usually a local edit, a stale cache, or
GitHub's Mermaid iframe timing out before it draws. The validator separates the first two from the
third:

```bash
# host, from 78-Diagrams/
node scripts/validate-mermaid.mjs --modules /tmp/mmv
```

The 2026-08-16 snapshot did have 59 failures in 812 blocks, across 44 files and 40 chapters. The
commonest single cause then, 35 of the 59, was a **semicolon in message text**. Mermaid treats `;` as
a statement separator, so everything after it is parsed as a new statement and the diagram collapses.
`K-->>SH: SIGCHLD; wait4() returns status` is broken; `K-->>SH: SIGCHLD, then wait4() returns status`
is fine.

---

### 4. Why do I need Node and jsdom just to check a diagram?

Because the only reliable check is Mermaid's own parser, and Mermaid is a browser library — it touches
`document` while it initialises, even for a parse that produces no picture. `jsdom` supplies a DOM so
it can run under Node.

A regex approximation would not be worth having. The failures in this repository are grammar
failures — a reserved word used as an identifier, a statement separator inside a string — and only the
real grammar finds those.

If you cannot install anything, [mermaid.live](https://mermaid.live/) parses a pasted block in a
browser. That works for one diagram and does not scale to 824.

---

### 5. What is the difference between `->>` and `-->>`? They look identical.

They are the two halves of one interaction and confusing them changes the system being described.

`A->>B` is a **call**: A initiates, B receives. `A-->>B` — with the dashed line — is a **return**: it is
the answer to something B already asked.

`A->>B` then `B->>A` is **two independent calls in two directions**, meaning both parties can initiate.
`A->>B` then `B-->>A` is **one call and its reply**, meaning only A can initiate. In an authorisation
flow those are different systems with different attack surfaces.

---

### 6. What does a `subgraph` mean? Everyone seems to use them differently.

In this repository it means exactly one thing: **a trust boundary**. Crossing that line changes who is
trusted. That is STYLE-GUIDE.md section 6, and it is why the index has a **Boundaries** column counting
them.

Elsewhere on the internet a `subgraph` is often just visual grouping — "these three things are
related". That usage is why the convention has to be stated: a reader arriving from other Mermaid
diagrams will read grouping where this repository means enforcement.

Which is also why the subgraph's *name* matters. `subgraph Kernel["Kernel space"]` says whose boundary
it is. `subgraph G1["Group 1"]` says nothing and should not exist.

---

### 7. Why does `style X fill:#f9d0d0` break my sequence diagram?

Because `sequenceDiagram` has no `style` statement at all. It is not that the syntax is slightly
different — the grammar does not contain that production.

Six diagrams in this repository apply the repository's own attacker-marking convention to a sequence
diagram and fail to parse as a direct result. It is a good illustration of a convention outrunning the
tool.

To mark hostility in a sequence diagram, wrap the messages in `rect rgb(249,208,208) … end`, or say it
in a `Note over`. The `Note` is usually clearer, because it can say *why* the thing is hostile.

---

### 8. My diagram worked, then I added one line and the whole thing broke. What happened?

Most likely a **participant id that collides with a keyword**.

Sequence keywords are matched without regard to case. `participant Opt as Optimiser` declares an id
called `Opt`, which the lexer reads as the `opt` block keyword. With one message you may get away with
it. Add a second and the diagram collapses, and the error points at the second message rather than at
the declaration.

The reserved ids are `opt`, `alt`, `else`, `loop`, `par`, `and`, `rect`, `break`, `critical`, `option`,
`note`, `end`, `activate`, `deactivate`, `autonumber`, `link`, `links`, `box`, `over`, `right`, `left`,
`of` and `title`. Rename the id to something short and meaningless. The readable label survives via
`as`.

---

### 9. Mermaid says "Parse error on line 12" but line 12 looks fine.

It usually is fine. Mermaid reports the line where the parser **gave up**, which is frequently the line
*after* the one that broke it: an unterminated message swallows the next line before failing.

Read the line above the reported one first. `validate-mermaid.mjs` prints the reported line, the source
at that line, and a suggested cause drawn from the patterns actually observed here — but the suggestion
is a heuristic, not a second parser.

---

### 10. How do I put a quote mark inside a label?

Use the HTML entity `#quot;`. Do **not** use a backslash — Mermaid has no backslash escape inside
`[" "]`, and six diagrams in this repository are broken for exactly that reason:
`A["getDeclaredMethod(\"x\")"]` does not parse.

Similarly `&lt;` and `&gt;` for angle brackets, `<br/>` for a line break, and `#35;` for a literal `#`.

---

### 11. Why are half the diagrams here flowcharts?

422 of 824, which is 51.2%. Flowchart is the general-purpose family and the first one everybody
learns, so it gets reached for by default.

That is not automatically wrong, but it has a specific failure mode: **flowcharts hide ordering**. If
you see a flowchart describing a protocol, ask whether the author meant a sequence diagram. The tell is
past-tense verbs on the edges — "sent the token", "returned the key". Verbs on edges usually mean
somebody meant to draw time and drew boxes instead.

---

### 12. Is a chapter with only four diagrams a defect?

Not necessarily, and the chapter README says so explicitly for five of the eight least-illustrated
chapters. [77-UsefulCommands](../77-UsefulCommands/README.md) has three diagrams because a command
surface is a table, not a picture. [79-Glossary](../79-Glossary/README.md) has one because its contract
asks for one.

The count is a **prompt to ask**, and "no, that chapter is genuinely a list" is a legitimate answer.
Treat automated findings on your own repository exactly as you would treat them on a client's: as
something to investigate, not something to fix.

---

### 13. What does the "Nodes" column in the index actually measure?

Distinct node, participant or class identifiers, found by a regex. It is a **size signal, not a quality
score**. Four means a sketch. Thirty means a map. Above thirty is usually two diagrams that have not
been separated yet.

It is deliberately crude. A precise count would require parsing every family's grammar, and the extra
precision would not change any decision the column is used for.

---

### 14. Should I draw the diagram before or after I test?

After, for anything you will publish.

A diagram drawn from documentation shows the **intended** flow. A diagram drawn from measurement shows
the **actual** one, and they routinely differ in the way that decides whether there is a finding. The
chapter has four measured cases where the obvious diagram omits the path that actually matters.

Sketching before you test is fine and useful — as a list of hypotheses. Just do not ship the sketch.

---

### 15. What do I do about a path I suspect exists but have not observed?

Draw it dotted, `-.->`, and say in the prose that it is unverified. Then go and verify it.

An honest gap in a diagram is information: it tells a reviewer where to look. A confident guess is a
liability, and it is the thing a client will quote back at you six months later.

---

### 16. Why does the chapter keep saying "eyes cannot count `../`"?

Because a sibling chapter in this repository generated an index into `references/` and emitted
`../NN-Chapter/README.md`. A file in `references/` is *two* levels below the repository root, so the
correct prefix is `../../`. That single missing level produced **1,495 dead links**, and they survived
for months because a "forward reference" exemption in the repository checker swallowed exactly that
shape of failure.

Nobody reviewing the output noticed, because a wrong `../` count looks identical to a right one. The
only fix is to resolve every link on disk, which is what `verify-index-links.py` does.

---

### 17. The scripts found bugs in themselves. Should I trust the numbers?

Trust them more, not less. Four defects were found and fixed while this chapter was written, and each
one is documented in the script that carried it:

| Defect | Symptom | Found by |
|---|---|---|
| Stripping `_` from heading text when building anchors | 18 phantom broken anchors | Running the checker |
| Collapsing runs of whitespace to one hyphen | Every em-dashed heading pointed at a non-existent anchor | Comparing against hand-written tables of contents |
| A fence regex not anchored to the end of the line | 20 more phantom broken anchors | Running the checker on this chapter's own README |
| An off-by-one mapping from block line to file line | Every failure report pointed at an innocent line | Checking three known failures by hand |

A tool that has never disagreed with reality has never been tested against it. The numbers quoted in
the chapter are the ones produced *after* those fixes, and the commands to reproduce them are in the
chapter.

---

### 18. Can I use these diagrams in a client report?

The repository-level ones in section 4, yes — with the caveat the chapter states: they describe AOSP's
shape, not a specific device. Section 7.2 case 4 is a measured example of that shape being wrong on a
device sitting on the same desk. Verify on the target and cite the target.

For per-chapter diagrams, prefer to redraw. A diagram in a report should be a diagram of *the system
you tested*, and redrawing it forces you to notice which arrows you actually observed.

---

### 19. What is the single most useful habit from this chapter?

Read every security diagram twice.

The first pass reads the arrows. The second pass asks: *what edge would have to exist for this diagram
to be dangerously wrong, and has anyone checked?*

The second pass is where findings come from.

---

### 20. Where do I go next?

- [Section 5](README.md#5-how-to-read-the-notation) if you cannot read the notation yet.
- [Section 7](README.md#7-confusions-and-misuse--how-diagrams-mislead) if you can, because that is the
  part that changes how you work.
- [`labs/`](labs/) to practise: draw a real app's trust boundaries from evidence, find what a chapter's
  diagram omits, redraw an intended flow as the actual one, and finish with a CTF whose flag is only
  reachable by noticing a path no diagram shows.
