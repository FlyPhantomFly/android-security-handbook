# 68 — Reverse Engineering · Mind Map

One picture of the whole chapter. Read it outward from the centre.

The single organising idea is that **reverse engineering is investigation, not translation**. A
translator is finished when every line has been converted; an investigator is finished when a
question is answered and the answer survives an attempt to break it. Every branch below is a
consequence of taking that distinction seriously, and the branches correspond to the README's
sections: the loop is §2.1 and §3, the ladder is §2.3, the crossing is §3.8, the tool failures are
§3.10, notes are §3.12, stopping is §3.15 and the residue is §3.17.

```mermaid
mindmap
  root((Reverse Engineering<br/>the method))
    The unit of work
      a hypothesis not a file
      400 classes read and no question closed is no progress
      a hypothesis you cannot refute is a belief
      most hypotheses die in a healthy session
      seven of nine died writing this chapter
    Stage 0 the question
      answerable bounded falsifiable
      written in a file before any tool runs
      a goal is not a question decompose it
      no question means no criterion for stopping
    Acquire
      pm path returns EVERY apk not the first
      Chrome ships seven
      one base apk was three hundred and thirty four kilobytes
      hash it record the version
      extractNativeLibs false means mapped from the apk
    Triage twenty minutes
      no method bodies allowed
      eight questions about shape
      the app own package prefix is the best noise filter
      dynamic first when it is available
      static only is legitimate but say so in the report
    The funnel
      static reduction and dynamic reduction
      run both branches then diff them
      agreed static only runtime only
      runtime only means fix your acquisition
      rank by distance to the question not by name
    The loop
      hypothesis prediction refutation verdict
      refutation written before the experiment
      cheapest experiment that is decisive
      reading is rarely decisive
      inconclusive is a real verdict
      record what you saw not what you concluded
    Evidence ladder
      one inference is a reason to look never to believe
      two artefact shape says the file contains
      three decompiled code is a reconstruction
      four encoding is what the file says
      five execution is what it did
      six controlled experiment is the only causal rung
      believe one to three provisionally write four to six down
    Correlation
      two independent sources or it is a lead
      independent means an error in one would not repeat in the other
      disagreement is the better finding
      the property said green the hardware said unverified
      can you make it not happen
    Crossing the boundary
      discovery binding versus explicit binding
      symbol lookup answers one in eight
      twelve point nine percent over eighteen apks
      hook RegisterNatives for the truth
      four causes of an unresolved method never pick one
      arriving at an address is the halfway point
      come back and ask who calls it with what
    When the artefact disagrees with the source
      the compiler is a party to the investigation
      a source function may have no counterpart in the binary
      constants survive inlining names do not
      the check that guards the secret told the compiler the secret
      findings that rest on the optimiser are build dependent
    When tools lie
      refusal under reported thirty fold
      silent wrongness needs a lower tier
      scope error answers a question you did not ask
      self agreement means suspect the detector
      if it matches every sample it has not been shown able to say no
    Liveness
      a void run and a clean negative look identical
      did the instrument install
      does it fire on a known positive
      was the target alive for the window
    Symptom to root cause
      the error names where it surfaced not where it started
      suspect your own environment before the target
      establish a known good then bisect the layers
      two devices attached and minus U picked the wrong one
    Notes as technique
      they externalise the frontier
      journal name map residue
      prefix a guess so it stays a guess
      observations survive revision conclusions do not
      if you cannot write it you do not understand it
    Time boxing
      the box is when you must reassess not how long you may take
      what have I learned in the last box
      what is the cheapest thing I have not tried
      understand it or only predict it
    Stopping
      state the answer in one sentence
      name two independent sources
      name what would have changed your mind
      say what you did not look at
      apps are never understood questions are answered
    Writing up
      claim evidence limits impact
      limits before impact calibrates the impact
      tag every source with its tier
      rate the consequence not the technique
      a bypassed control is not a finding
    The residue
      chosen and structural
      naming the blind spot is what makes the coverage honest
      a report with no residue implies a completeness no method delivers
      coverage is a fraction and the numerator is the easy half
```

---

## The one-sentence version of each branch

| Branch | The sentence |
|---|---|
| **The unit of work** | Progress is questions closed, not files read — and in a healthy session most of your hypotheses die. |
| **Stage 0 the question** | Without a written, falsifiable question there is no criterion for what to do next or when to stop. |
| **Acquire** | Prove you have the program before analysing it; `pm path` returns every APK and Chrome ships seven. |
| **Triage** | Twenty timed minutes with no method bodies, because reading is how you spend the budget triage exists to allocate. |
| **The funnel** | Reduce from both ends and diff the results; the pile that is in the runtime and not the artefact means your acquisition is wrong. |
| **The loop** | Write the refutation before the experiment, then run the cheapest experiment that could produce it. |
| **Evidence ladder** | Every observation has a strength, only the controlled experiment is causal, and a finding must say which rung it stands on. |
| **Correlation** | One source is a lead; two independent sources are a finding; two that disagree are a better one. |
| **Crossing the boundary** | Symbol lookup answers about one native method in eight, so the crossing is a runtime question, and it is not finished until you come back to the managed side. |
| **When the artefact disagrees with the source** | The compiler inlines the function you are looking for and will publish a secret the source hid — twice, if the guard proves the value. |
| **When tools lie** | Four named failure modes, and the most dangerous is the one that produces clean confident output. |
| **Liveness** | Silence means nothing until the same instrument has been shown to speak. |
| **Symptom to root cause** | An error message names the layer where the failure surfaced, and your own environment is the likelier culprit. |
| **Notes as technique** | Notes externalise the frontier and record whether a name is a guess or a fact; skipping them changes your results, not just your paperwork. |
| **Time boxing** | The box is a forced reassessment, and the cheapest reassessment is asking whether you need to understand this or only predict it. |
| **Stopping** | Answer, two sources, what would have changed your mind, and what you did not look at. |
| **Writing up** | Claim, evidence with tiers, limits, impact — and writing the limits first is what keeps the impact honest. |
| **The residue** | Naming your blind spots is the only thing that stops a report implying coverage no method delivers. |

---

## Related chapters

- [51-DynamicAnalysis](../51-DynamicAnalysis/README.md) and
  [52-StaticAnalysis](../52-StaticAnalysis/README.md) — the two pipelines this chapter runs at once
  and then diffs.
- [56-JADX](../56-JADX/README.md) — decompilation as reconstruction, and the five checks before
  absence is evidence.
- [57-Ghidra](../57-Ghidra/README.md) — names this chapter a prerequisite; §3.6 is where its "you
  will read three functions" gets chosen.
- [40-Obfuscation](../40-Obfuscation/README.md) — its §6.1 is the obfuscation-specialised instance of
  §3 here.
- [67-BypassingProtections](../67-BypassingProtections/README.md) — owns when to stop *hooking*;
  this chapter owns when to stop *understanding*.
- [69-MalwareAnalysis](../69-MalwareAnalysis/README.md) and
  [70-VulnerabilityResearch](../70-VulnerabilityResearch/README.md) — what consumes this chapter's
  output.
