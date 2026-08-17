# Example 03 — six transcripts of not knowing the answer

Every technical interview reaches a question you cannot answer. That moment is not a
failure state; it is the most informative part of the interview, and it is the part
candidates practise least. What the interviewer learns is not whether you knew the fact —
they already know you don't, that is why they asked — but **what you do at the edge of
your knowledge**, which is exactly what they are hiring.

There are six ways this goes. Five of them are bad, and four of the five are bad in ways
that feel, in the room, like the safe option.

Each transcript below uses the same question, so the only variable is the response. `I` is
the interviewer, `C` the candidate.

> **🧠 Mental Model**
> An interview is a sampling exercise. The interviewer takes a handful of samples of your
> reasoning and extrapolates to the thousands of decisions you will make unsupervised. A
> candidate who bluffs once has told them what happens to the other thousand.

---

## The question

> **I:** On Android 14 and 15, where does the system CA trust store physically live, and
> what changed?

This is a deliberately good question for this purpose: there is a real, specific answer;
it changed at a specific API level; and the change is recent enough that a competent
candidate might genuinely not have it loaded. It is also a question where a confident
wrong answer is easy to produce, because the *old* answer was true for a decade.

---

## Transcript 1 — the bluff

> **C:** It's in `/system/etc/security/cacerts`. That's where the system certificates live,
> and user certificates go in `/data/misc/user/0/cacerts-added`. Nothing significant
> changed; the split has been stable since the user-CA change in Nougat.

**What the interviewer heard.** The candidate produced an answer with no hedge, at full
confidence, and it is stale. The interviewer now has to assume that every other confident
statement in the interview carries the same unknown error rate — including the ones they
cannot check.

**Why candidates do this.** Because it feels like the professional option. Uncertainty
reads to the candidate as weakness. It reads to the interviewer as calibration.

**The cost is not the wrong fact.** It is that the candidate has removed the interviewer's
ability to distinguish their strong claims from their weak ones. Everything after this is
discounted.

---

## Transcript 2 — the retreat

> **C:** I don't know.
> **I:** …okay. Moving on, then.

**What the interviewer heard.** Honest — genuinely better than transcript 1 — and nothing
else. The candidate has given away a free opportunity to demonstrate method, and the
interviewer has lost a minute of signal.

"I don't know" is a *complete* sentence in ethics and an *incomplete* one in an interview.
It is the first half of the strong answer, not the whole of it.

---

## Transcript 3 — the deflection

> **C:** That's more of a platform-internals thing. In my work I'd just be checking whether
> the app trusts user CAs, which is the network security config, and I know that
> thoroughly — shall I talk about that instead?

**What the interviewer heard.** A candidate steering toward their prepared material. It is
a recognisable move and interviewers see it several times a week.

The uncomfortable part is that the *content* is defensible: the network security config
genuinely is what matters operationally, and a senior tester might well never need the
store's path. Had the candidate said that as an argument — "I think the store's location
is the less important half of this question, and here is why" — it would have been a strong
answer. Presented as an escape, it is an escape.

---

## Transcript 4 — the over-hedge

> **C:** I'm not sure, it might have moved, I think possibly to an APEX, or maybe it was
> Conscrypt, I'm honestly not certain, it could be either, I'd have to look it up, I don't
> want to say something wrong…

**What the interviewer heard.** The correct answer is somewhere in there, buried under so
much hedging that the interviewer cannot tell whether the candidate knows it. Hedging is a
precision instrument. Applied to everything, it carries no information — exactly like a
detector that fires on every sample.

**The fix is arithmetic, not attitude.** Say the thing you are most confident about, at
the confidence you actually hold, once. Then stop.

---

## Transcript 5 — the good answer

> **C:** I don't know the exact API level, and I'd rather not guess at it. What I do know
> is the shape: the store used to be `/system/etc/security/cacerts`, and there has been a
> move toward the Conscrypt APEX, which is the modular-updatability pattern the platform
> has applied to several components. I'd want to check whether that has landed on the
> device in front of me rather than rely on a version table, because I've been caught by
> that: on an API 30 device I looked at, `/apex/com.android.conscrypt/` existed but had no
> `cacerts` directory at all, and the live store was still the `/system` path with 139
> files in it. So my answer is: I would run `ls -d` on both paths and believe the device.
>
> **I:** Good. What would you look at in the files themselves?
>
> **C:** Filenames are the subject hash with a `.0` suffix, and — this one catches people —
> it's `subject_hash_old`, the MD5 variant, not `subject_hash`. And the files are DER, not
> PEM, so `openssl x509 -in <file> -text` fails until you add `-inform der`. I verified
> that end to end once: `9a5ba575.0` hashes to `9a5ba575`.

**What the interviewer heard.** Four separate positive signals, none of which is the fact
that was asked for:

1. **Calibration.** The candidate distinguished what they know from what they don't,
   inside one sentence, and did not blur the boundary.
2. **A method.** "I would `ls -d` both and believe the device" is a procedure that works
   without the memorised fact, which means it works on the API level that ships next year.
3. **Evidence with provenance.** A specific device, a specific observation, and the
   observation *contradicts the simple version of the story* — which is the strongest kind
   of evidence a candidate can offer, because nobody invents an inconvenient measurement.
4. **Adjacent depth.** The follow-up showed the candidate has been inside these files.

The candidate did not answer the question. They comfortably passed it.

---

## Transcript 6 — the strongest version, and it is a refusal

> **C:** I'd want to push back on the question slightly, because the location is the less
> load-bearing half of it. Wherever the store lives, the thing that decides whether my
> intercepting proxy works is the app's `targetSdk` and its network security config, and
> whether the store on this particular device has been *modified*. That last one has bitten
> me hard enough that I now check it first. I once measured `getDefaultBuilder()` returning
> 139 trust anchors at every `targetSdk` I tried — 23, 24, 28, 30, 34 — which looks like
> proof that the API 24 user-CA rule doesn't exist. It does. What had actually happened was
> that a module had promoted my interception CA *into the system store*, so it wasn't a user
> CA any more. A device whose posture you haven't established will teach you the opposite of
> the truth. So: I'll answer the path question, and then I'd like to say what I'd check
> before trusting any answer I gave.

**What the interviewer heard.** A candidate who reframed the question toward the thing that
actually determines the outcome, backed the reframe with a measurement that
*they got wrong first*, and offered the original answer anyway rather than dodging.

**The risk is real and worth naming.** This move fails badly against an interviewer who
wants the specific fact and reads reframing as evasion. Two things make it safe: offer the
literal answer as well ("I'll answer the path question"), and make the reframe *shorter*
than the answer would have been. A reframe that takes three minutes is a filibuster.

---

## The pattern, extracted

A strong "I don't know" has four parts and takes about twenty seconds:

| Part | Example wording | Why it earns its place |
|---|---|---|
| **1. The boundary** | "I don't know the exact API level, and I'd rather not guess." | Tells the interviewer where your certainty ends, which makes everything else you said more credible, not less |
| **2. The shape** | "What I do know is that it moved toward the Conscrypt APEX…" | Shows the fact is missing from an otherwise-populated model, rather than the model being missing |
| **3. The method** | "I'd `ls -d` both paths and believe the device." | A procedure that survives the next API level. This is the part that gets hired |
| **4. The receipt** | "I've been caught by that: on an API 30 device…" | Converts the whole answer from a claim about you into evidence about a device |

> **🔍 Pentester's Note**
> Part 3 is this repository's entire thesis compressed into one interview sentence.
> Every chapter here prefers a measurement to a table, and "I would measure it" is the
> spoken form of that preference. It is also, conveniently, the only answer that is still
> correct after the platform changes.

---

## What to practise, and how

The failure is not knowing fewer facts than the interviewer. It is having no *rehearsed
behaviour* for the moment the facts run out, so you default to whichever of transcripts
1–4 matches your temperament under stress.

Rehearse it deliberately:

1. Run [`../scripts/mock-round.py`](../scripts/mock-round.py) with `--tier "Staff Engineer"`
   while you are at Intermediate. The point is to generate questions you cannot answer.
2. Answer out loud anyway, using the four-part structure above. Time it. Twenty seconds.
3. Only afterwards, open the chapter and read what the answer was.

Step 3 in that order matters. If you read the answer first you are practising recall. If
you answer first you are practising the thing that will actually happen.

> **⚠️ Warning**
> There is one place where "I would measure it" is the wrong answer, and it is worth
> knowing so the move does not become a tic: when the interviewer is asking a *design*
> question. "How would you architect credential storage" cannot be answered with "I'd
> measure it", and reaching for the phrase there reads as avoidance. Measurement answers
> questions about what is true on a device. Design questions are about what should be
> built, and they want a position, a trade-off, and a stated cost.

---

## Related

- [`01-one-question-five-tiers.md`](01-one-question-five-tiers.md) — what escalates between tiers
- [`02-weak-and-strong-at-the-same-tier.md`](02-weak-and-strong-at-the-same-tier.md) — the same tier, two qualities
- [`04-evidence-behind-the-answer.sh`](04-evidence-behind-the-answer.sh) — produce your own receipts
- [`../labs/lab-03-live-triage-and-honest-uncertainty.md`](../labs/lab-03-live-triage-and-honest-uncertainty.md) — the graded version of this file
