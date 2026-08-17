# 75 — Interview Questions: FAQ

Real questions, including the ones people are embarrassed to ask. Answered directly.

---

### 1. Why doesn't this chapter just list all the questions with their answers?

Because that document already exists, once per chapter, next to the mechanism each answer
depends on.
Concatenating them would produce something enormous, immediately stale, and actively harmful:
an answer separated from the chapter that derives it is a claim you can recite and cannot
defend under one follow-up. Interviewers ask follow-ups.

What this chapter ships instead is an **index** — three generated files linking every question
in the repository by tier, by role and by round — plus the four things no individual chapter can hold:
the meta-layer, the answer shape, the tiering across topics, and the cross-cutting questions
that belong to no chapter. See [README §3.16](README.md#316-the-curated-index-by-role-and-by-round).

---

### 2. I have three days before an interview. What do I actually do?

In this order, and stop when you run out of time:

1. **Day 1, first thing:** [Lab 01](labs/lab-01-timed-mock-technical-round.md), cold. It takes
   45 minutes and tells you whether your problem is scope or knowledge. Most people discover
   it is scope, which is fixable in a day.
2. **Day 1, rest:** read [README §3.3](README.md#33-the-answer-shape-and-why-it-is-this-repositorys-own-house-style)
   (the shape) and [§3.8](README.md#38-saying-i-do-not-know-so-that-it-gains-ground) (not
   knowing). Those two sections change more outcomes per minute read than anything else here.
3. **Day 2:** your role's file in [`references/`](references/), 20–30 questions, answered
   aloud. Read the answer in the chapter afterwards, not before.
4. **Day 3, morning:** run [`examples/04-evidence-behind-the-answer.sh`](examples/04-evidence-behind-the-answer.sh)
   on your own device so you have three receipts you produced yourself.
5. **Day 3, afternoon:** rest. Cramming on the last afternoon reliably makes people worse,
   because it replaces a rehearsed shape with a pile of unconsolidated facts.

---

### 3. Is it actually true that I should say "I don't know"?

Yes, and the reason is arithmetic rather than moral. An interviewer takes perhaps eight samples
of your reasoning. A stated gap is one narrow sample: "does not know X". A confident wrong
answer is a sample saying "confidence is uncorrelated with correctness" — which is unbounded,
and it retroactively devalues the seven other things you said, because the interviewer can no
longer tell which of your confident claims to trust.

The caveat is that "I don't know" *on its own* is honest and weak. The version that gains
ground has four parts and takes twenty seconds: boundary, shape, method, receipt.

---

### 4. Won't "I would measure it" sound like I'm dodging?

It can, and there is one place it definitely does: **design questions**. "How would you
architect credential storage?" is not answered by a device measurement, and reaching for the
phrase there reads as avoidance. Design questions want a position, a trade-off and a stated
cost.

It also sounds like dodging when it has no second half. "I'd measure it" and stop is a dodge;
"I'd measure it *by generating a key with those parameters, pulling the attestation, and
reading the security level out of the hardware-enforced list*" is a method, and methods are
what get hired.

---

### 5. How many facts do I actually need to know?

Fewer than you think, and this is the finding that most annoys people who have spent months
memorising.

Past a fairly low threshold — enough that you have no obvious holes at the tier you are
interviewing for — the next hundred facts you memorise change your outcomes very little,
because they change the *surface* of your answers and not the *signal*. The five most common
causes of failure are scope, calibration, altitude, severity language and tool-first answers.
Knowledge is sixth. See [README §2.4](README.md#24-where-candidates-are-actually-lost).

That does not mean facts do not matter. It means the marginal fact is worth much less than the
marginal hour spent on shape.

---

### 6. Should I really contradict the interviewer with a measurement?

Yes, and carefully, and once.

Three rules. **Answer the question first** — give the standard answer briefly and without
irony, so they know you know it, and *then* "though when I measured it…". A correction that
arrives before the answer reads as a dodge. **Name the device and the method**, because "on a
stock Android 15 emulator, from the shell" is the difference between a measurement and a boast.
And **say what it does not establish**, because overclaiming a contradiction converts a
calibration signal into its opposite.

One per interview is plenty. Two is a conversation. Three is a personality.

---

### 7. What if the interviewer says I'm wrong and I know I'm right?

Ask what they are seeing, offer your method and your device, and say what would change your
mind. If they are wrong, that exchange is the strongest thing that happens in the whole
interview — you have demonstrated evidence-driven disagreement, live, without heat.

If they mark you down for it anyway, you have learned something important about the
organisation at zero cost. A team that punishes evidence selects against exactly the people it
claims to want.

---

### 8. The interviewer asked something I answered three months ago and I've forgotten. Help.

Say so. "I knew this three months ago and it's gone — let me reconstruct it." Then reconstruct
it out loud from mechanism rather than recall. That is a better answer than the remembered one
would have been, because it demonstrates the model rather than the cache.

---

### 9. What's the difference between a "lead" and a "finding"? Everyone says this and nobody defines it.

A **lead** is something worth spending twenty minutes on. A **finding** is something you can
defend in a room with the developer who wrote the code.

The conversion rate is brutal and this repository has published it four times: 16,836 raw hits
became 168 leads, of which 15 of the top 17 were rejected by hand; 132 high-confidence hits
against real browser data were 132 false positives; 12 of 14 apps had a pinning surface and
only 4 actually pinned; and 1,141 keyword occurrences were all explained by the substring
inside the English word "exposed" — zero findings.

The test that closes it: **explain every hit, or the signature is not evidence.**

---

### 10. Do I have to do the labs? They look like a lot of work.

Lab 01 is 45 minutes and it is the one that matters most, because it converts "I should
practise more" into a number. Do that one.

The others are optional in the sense that anything is optional, and each targets a specific
stage: Lab 02 the take-home, Lab 03 the live round, Lab 04 the adversarial panel. If you know
which stage you fail, do that lab.

If you do none of them, read [README §3.3](README.md#33-the-answer-shape-and-why-it-is-this-repositorys-own-house-style)
and [§3.8](README.md#38-saying-i-do-not-know-so-that-it-gains-ground) and practise those two
things aloud. That is a real fraction of the value.

---

### 11. Why does Lab 01 tell me to do it before reading the chapter?

Because the measurement is of your *unprepared* behaviour, and reading first contaminates it.
Unconstrained answers feel appropriately long while you are giving them, which is precisely why
you cannot detect the problem by introspection. If you have already read §3.9, run it anyway
and treat the number as post-instruction rather than as a baseline.

---

### 12. The lint gave my answer 4/12 and I think it's a good answer. Who's right?

Probably you. It counts word shapes and cannot read; its own header says so.

But check two things before dismissing it, because these are the two humans reliably miss in
their own writing: does your first sentence name a tool, and does the answer contain any
provenance vocabulary at all — anything distinguishing what you measured from what you read? A
low score on Shape and Evidence together usually means the lint is right and the answer feels
good because *you* know the reasoning behind it.

Its calibration is published so you know what you are trusting: on the matched weak/strong pairs
in [`examples/02-weak-and-strong-at-the-same-tier.md`](examples/02-weak-and-strong-at-the-same-tier.md)
it scores 5/3/3 against 11/9/10. Every pair separates the right way. That is the only claim
made for it.

---

### 13. I'm not interviewing. Is this chapter useless to me?

Three other uses.

**You will interview other people**, probably sooner than you expect, and
[§3.14](README.md#314-red-flags-from-the-interviewers-side-of-the-table) and
[§11.2](README.md#112-interviewer-mistakes) are written for that seat. The highest-leverage
change most interviewers can make is to write down what a question is *for* before asking it.

**The answer shape is a writing shape.** It is the same structure this repository's style guide
mandates for chapters, and it works for a finding write-up, a design document, or an incident
summary for the same reason.

**Section 3.10 is about reports, not interviews.** Severity language, preconditions,
reachability, denominators — you will use those on Monday whether or not anyone is hiring.

---

### 14. What do I say when they ask about something covered by an NDA?

> "I can't go into that engagement, but here's an equivalent finding from a public target."

And then actually give the equivalent. The refusal without a substitute is a dead end; the
refusal with one is a strong answer, and interviewers in this field respect it instantly
because they are under the same constraints.

You *can* describe the class of system ("a retail banking application") and the shape of the
finding ("a session token that survived logout because the deletion path only cleared the
in-memory copy"). You cannot name the client, give enough detail to identify them, or discuss
anything under embargo. This repository's own convention — "a 17 MB commercial app" — is worth
copying verbatim.

---

### 15. A take-home asked me to find bugs in a real, named company's app. Is that OK?

No, and the correct move is to raise it rather than to refuse silently or comply quietly:

> "Happy to do this. Before I start — what's the authorisation position for this target? I test
> against systems I have permission to test, and I'd want that in writing, or I'd be glad to do
> the same exercise against an intentionally vulnerable app instead."

Public availability is not authorisation, and a request from a prospective employer is not
authorisation either. In a well-run process, raising this is a passing answer. In a badly-run
one, the reaction tells you something valuable at zero cost. See
[README §5.2](README.md#52-the-take-home-that-is-unpaid-work-or-worse).

---

### 16. How long should my answers be, really?

Ninety seconds to two and a half minutes in a phone screen. Five to ten minutes in a deep
round. Twenty to forty in a design round.

The number that matters more than any of those: **decide your last sentence before you start
your first.** Knowing where you are landing is what converts an open-ended answer into a
bounded one, and it is the single highest-leverage habit in this chapter.

---

### 17. Why does a Staff-level answer get *shorter*? That feels backwards.

Because it has stopped enumerating. A Senior answer is long because it is doing the most
work — the evidence, the provenance, the counter-case. A Staff answer does not need to list
the detection signals; it needs to price the programme and say who owns the false positives. A
Principal answer is usually a reframe plus a decision.

A candidate who has learned "more senior means say more" will overshoot at exactly the point
where restraint is the signal.

---

### 18. I froze. Total blank. What now?

Say so, out loud, in five words: "I've lost the thread — one second." Then restart from the
question rather than from where you stopped.

Interviewers do not remember freezes; they remember what you did about one. The failure is not
the blank, it is filling it with thirty seconds of hedging while you hunt for the answer, which
reads as uncertainty about the *content* rather than a momentary lapse.

---

### 19. Are these measured contradictions still true? The chapter is dated.

**Treat every one of them as a timestamped fact about a specific device, not as a constant.**
That is the whole point of the section they live in.

Two of them moved while this chapter was being written, and one of them was outright **wrong**.

The property count on the same emulator differed between two runs minutes apart — normal drift,
because properties are set at runtime. More instructively, a figure this repository had
published and several chapters had repeated — *"`shell` sees 1,053 properties, `untrusted_app`
sees 634"* — turned out to be a **root** measurement mislabelled as a shell one. The corrected
counts are root ~1,062, shell ~678, app ~638, and the correction **changes the conclusion**: the
shell-to-app gap is about forty, not about four hundred, so a shell test is a fair proxy for app
reachability and a terrible proxy for root. The full story is
[README §3.7.1](README.md#371-the-number-i-nearly-quoted-and-why-it-was-wrong), and it is the
best worked example in the chapter of a candidate sounding authoritative while repeating a
number nobody re-ran.

So: run [`examples/04-evidence-behind-the-answer.sh`](examples/04-evidence-behind-the-answer.sh)
on your own device the morning of the interview and quote today's output. If your device
disagrees with this chapter, **your device is right**, and the interesting exercise is working
out why.

---

### 20. Which questions in the repository are the highest value for a senior interview?

The ten in [README §3.6](README.md#36-cross-cutting-questions-the-ones-no-chapter-owns). They
each span three or more chapters, which is exactly why they appear in no chapter's own §10 —
and why they are disproportionately what senior candidates are actually asked.

If you only prepare three: *what have you established when a grep finds nothing*, *what does a
valid attestation chain prove*, and *what is the difference between a lead and a finding*.

---

### 21. Is `python3 -B` important or is that just style?

Important. Without `-B`, Python writes `__pycache__` directories, and this repository treats
committed bytecode as an artefact defect. It has happened twice before, both times because an
interrupted run never reached its cleanup step.

---

### 22. The scripts need a bank file. Where should it live?

Anywhere outside the repository. `/tmp/bank.json` on Unix, or your scratch directory on
Windows. It is generated in about a second from the chapter READMEs and it is deliberately not
committed, because a committed copy would be a stale duplicate of the thing the script exists
to keep current.

---

### 23. Can I use this chapter to prepare for iOS or web security interviews?

The meta-layer transfers completely: the stages, the answer shape, the tiering, the four-part
refusal, severity discipline, the take-home rubric. None of that is Android-specific.

The measured contradictions do not transfer at all — they are facts about specific Android
devices. Do not carry them across. Find your own platform's equivalents, which exist, and
measure them yourself.

---

### 24. What is the single most important thing in this chapter?

That the question is a probe, not the thing being measured — and that the property being probed
is almost always **calibration**: whether your confidence tracks your correctness.

Everything else is a consequence. The answer shape ends with a stated limit because of it. The
four-part refusal exists because of it. The take-home rubric weights rejected leads because of
it. The CTF's hidden scoring function is it.
