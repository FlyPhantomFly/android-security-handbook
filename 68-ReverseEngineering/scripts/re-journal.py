#!/usr/bin/env python3
# scripts/re-journal.py
#
# PURPOSE
#   The hypothesis ledger from chapter 68 section 3.12, made mechanical.
#
#   Reverse engineering is a search through a space too large to hold in your
#   head. The journal externalises the frontier: what you know, what you have
#   ruled out, and -- the part everyone loses -- what you have not looked at.
#   Without it the frontier lives in short-term memory, shrinks at every
#   interruption, and you re-cover ground you already covered while never
#   entering the region you never entered.
#
#   The one rule this tool enforces, and the reason it exists rather than a
#   text file: A HYPOTHESIS WITHOUT A REFUTATION TEST IS NOT ACCEPTED.
#   You must say, before running anything, what result would make you abandon
#   the idea. Afterwards, any result can be explained away -- "it must be called
#   through a function pointer", "the hook must be wrong" -- and those excuses
#   are infinitely available if you did not close them off in advance.
#
#   It also records OBSERVATIONS separately from VERDICTS. Conclusions get
#   revised; observations do not. When a later finding contradicts an earlier
#   one, the raw observation is what lets you work out which of you was wrong.
#
# USAGE
#   All commands take --file (default: ./re-journal.json).
#
#   # start a target, and pin what you are analysing
#   python3 -B re-journal.py init --target com.example.app \
#           --sha256 3f2a... --version 4.3.1 --device 84f7a024
#
#   # a question. Must be answerable, bounded and falsifiable (section 3.1)
#   python3 -B re-journal.py ask "What decides whether the Export button enables?"
#
#   # a hypothesis. --refute is MANDATORY; the tool refuses without it
#   python3 -B re-journal.py hypothesise Q1 \
#           --claim  "iv_check_license is the gate" \
#           --predict "at least one call site targets it" \
#           --refute  "zero call sites target it"
#
#   # the experiment you ran and what you SAW (not what you concluded)
#   python3 -B re-journal.py observe H1 \
#           --experiment "llvm-objdump -d lib.so | grep -c 'bl.*<iv_check_license>'" \
#           --observed   "0"
#
#   # the verdict: refuted | supported | inconclusive
#   python3 -B re-journal.py verdict H1 refuted --note "exported, obvious, dead"
#
#   # something you noticed and are NOT pursuing -- this is the residue
#   python3 -B re-journal.py residue "analytics SDK excluded by scope" --kind chosen
#
#   # close a question: answered | blocked | deferred
#   python3 -B re-journal.py close Q1 answered \
#           --answer "The gate is an inlined seed comparison in iv_open_vault" \
#           --source "tier4: disassembly, cmp w8,#0xbd" \
#           --source "tier6: key 'measure' opens it, 'wrongkey' does not"
#
#   # where am I?
#   python3 -B re-journal.py status
#
#   # the report skeleton, straight out of the ledger
#   python3 -B re-journal.py report > findings.md
#
#   # self-test (no files touched outside a temp dir)
#   python3 -B re-journal.py selftest
#
# EXIT STATUS
#   0 ok, 1 usage/validation error, 2 a check failed in selftest.
#
# REQUIREMENTS
#   Python 3.8+. No third-party packages. The ledger is plain JSON; read it with
#   anything, and commit it next to your notes.
#
# ETHICS
#   The `init` fields exist because every claim you make is a claim about one
#   specific build on one specific device. Fill them in.

import argparse
import datetime
import json
import os
import sys
import tempfile

VERDICTS = ("refuted", "supported", "inconclusive")
CLOSURES = ("answered", "blocked", "deferred")
RESIDUE_KINDS = ("chosen", "structural")

TIER_HINTS = {
    1: "inference -- 'apps like this usually'. A reason to look, never to believe",
    2: "artefact shape -- a name, a string, a manifest entry",
    3: "decompiled code -- a RECONSTRUCTION, not the code",
    4: "encoding -- Smali, disassembly, raw bytes. What the file says",
    5: "observed execution -- it ran, with these values, on this device",
    6: "controlled experiment -- changed one input, outcome changed. Causal",
}


def now():
    return datetime.datetime.now().replace(microsecond=0).isoformat()


def load(path):
    if not os.path.exists(path):
        return {"target": {}, "questions": [], "hypotheses": [], "residue": []}
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def save(path, data):
    blob = json.dumps(data, indent=1, ensure_ascii=False).encode("utf-8")
    with open(path, "wb") as f:          # BOM-less UTF-8, always
        f.write(blob)


def next_id(items, prefix):
    return "%s%d" % (prefix, len(items) + 1)


def find(items, ident):
    for it in items:
        if it["id"] == ident:
            return it
    return None


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_init(a, d):
    d["target"] = {
        "package": a.target,
        "sha256": a.sha256,
        "version": a.version,
        "device": a.device,
        "started": now(),
    }
    missing = [k for k in ("sha256", "version", "device") if not d["target"][k]]
    if missing:
        print("NOTE: %s not recorded. Every claim you make is a claim about one\n"
              "      build on one device; fill these in before you report."
              % ", ".join(missing))
    print("initialised for %s" % a.target)
    return 0


def cmd_ask(a, d):
    q = {
        "id": next_id(d["questions"], "Q"),
        "text": a.text,
        "state": "open",
        "opened": now(),
        "answer": None,
        "sources": [],
        "closed": None,
    }
    d["questions"].append(q)
    print("%s  %s" % (q["id"], q["text"]))
    print()
    print("Three tests before you go further (section 3.1):")
    print("  answerable  -- some observation could settle it")
    print("  bounded     -- it does not require understanding the whole program")
    print("  falsifiable -- not every outcome confirms it")
    return 0


def cmd_hypothesise(a, d):
    q = find(d["questions"], a.question)
    if not q:
        print("ERROR: no such question %s. Run `ask` first." % a.question,
              file=sys.stderr)
        return 1
    if q["state"] != "open":
        print("ERROR: %s is %s, not open." % (q["id"], q["state"]), file=sys.stderr)
        return 1

    # THE RULE. argparse marks --refute required, but check the content too:
    # a blank or trivially short refutation is the same failure wearing a hat.
    refute = (a.refute or "").strip()
    if len(refute) < 8:
        print("REFUSED: a refutation test of '%s' is not a refutation test.\n"
              "\n"
              "  Say what you would OBSERVE if this hypothesis were false. If you\n"
              "  cannot, you are not investigating -- you are looking for support,\n"
              "  and you will find it, because confirming evidence is cheap and\n"
              "  abundant. See chapter 68 section 3.5." % refute, file=sys.stderr)
        return 1

    h = {
        "id": next_id(d["hypotheses"], "H"),
        "question": q["id"],
        "claim": a.claim,
        "predict": a.predict,
        "refute": refute,
        "opened": now(),
        "experiment": None,
        "observed": None,
        "verdict": None,
        "tier": a.tier,
        "note": None,
    }
    d["hypotheses"].append(h)
    print("%s (%s)  %s" % (h["id"], q["id"], h["claim"]))
    print("  predict : %s" % h["predict"])
    print("  refute  : %s" % h["refute"])
    print()
    print("Now run the CHEAPEST experiment that is DECISIVE -- one whose result")
    print("could produce the refutation above. Not the most thorough. (3.6)")
    return 0


def cmd_observe(a, d):
    h = find(d["hypotheses"], a.hypothesis)
    if not h:
        print("ERROR: no such hypothesis %s" % a.hypothesis, file=sys.stderr)
        return 1
    h["experiment"] = a.experiment
    h["observed"] = a.observed
    h["observed_at"] = now()
    if a.tier:
        h["tier"] = a.tier
    print("%s observed: %s" % (h["id"], a.observed))
    print()
    print("That is what you SAW. Record the verdict separately -- observations")
    print("survive revision, conclusions do not. (section 3.5)")
    return 0


def cmd_verdict(a, d):
    h = find(d["hypotheses"], a.hypothesis)
    if not h:
        print("ERROR: no such hypothesis %s" % a.hypothesis, file=sys.stderr)
        return 1
    if h["observed"] is None:
        print("ERROR: %s has no recorded observation. Run `observe` first --\n"
              "       a verdict with no observation behind it is an opinion."
              % h["id"], file=sys.stderr)
        return 1
    h["verdict"] = a.verdict
    h["note"] = a.note
    h["closed"] = now()
    print("%s %s" % (h["id"], a.verdict.upper()))
    if a.verdict == "supported":
        print()
        print("SUPPORTED IS NOT ANSWERED. One source is a lead. Get a second,")
        print("independent one -- independent meaning an error in the first")
        print("would not produce the same error in the second. (section 3.7)")
    return 0


def cmd_residue(a, d):
    d["residue"].append({"kind": a.kind, "text": a.text, "at": now()})
    print("residue (%s): %s" % (a.kind, a.text))
    return 0


def cmd_close(a, d):
    q = find(d["questions"], a.question)
    if not q:
        print("ERROR: no such question %s" % a.question, file=sys.stderr)
        return 1

    if a.state == "answered":
        if not a.answer:
            print("ERROR: --answer is required to close a question as answered.\n"
                  "       If you cannot state it in one sentence, you have\n"
                  "       material, not an answer. (section 3.15)", file=sys.stderr)
            return 1
        if len(a.source or []) < 2:
            print("ERROR: 'answered' needs TWO independent sources; got %d.\n"
                  "       One source is a lead. If the second is genuinely not\n"
                  "       available, close as `blocked` and say so -- that is a\n"
                  "       result, and an honest one. (sections 3.7, 3.15)"
                  % len(a.source or []), file=sys.stderr)
            return 1

    q["state"] = a.state
    q["answer"] = a.answer
    q["sources"] = a.source or []
    q["reason"] = a.reason
    q["closed"] = now()
    print("%s -> %s" % (q["id"], a.state))
    return 0


def cmd_status(a, d):
    t = d.get("target") or {}
    print("target   : %s  %s  %s" % (t.get("package", "?"),
                                     t.get("version", "?"),
                                     t.get("sha256", "?")))
    print("device   : %s" % t.get("device", "?"))
    print()

    for q in d["questions"]:
        mark = {"open": "[ ]", "answered": "[x]",
                "blocked": "[!]", "deferred": "[-]"}.get(q["state"], "[?]")
        print("%s %s  %s" % (mark, q["id"], q["text"]))
        for h in d["hypotheses"]:
            if h["question"] != q["id"]:
                continue
            v = h["verdict"] or "open"
            print("      %s  %-12s %s" % (h["id"], v, h["claim"]))
        if q["answer"]:
            print("      => %s" % q["answer"])

    openq = [q for q in d["questions"] if q["state"] == "open"]
    hyp = d["hypotheses"]
    refuted = sum(1 for h in hyp if h["verdict"] == "refuted")

    print()
    print("questions: %d open, %d closed" % (len(openq),
                                             len(d["questions"]) - len(openq)))
    print("hypotheses: %d total, %d refuted" % (len(hyp), refuted))
    print("residue entries: %d" % len(d["residue"]))

    if hyp and refuted == 0:
        print()
        print("WARNING: no hypothesis has been refuted. In a healthy")
        print("investigation most of them die. If yours all survive, they are")
        print("probably too weak to be refuted. (section 1.5)")
    if not d["residue"] and any(q["state"] != "open" for q in d["questions"]):
        print()
        print("WARNING: questions are closing and the residue is empty. You have")
        print("not written down what you did NOT look at. (section 3.17)")
    return 0


def cmd_report(a, d):
    t = d.get("target") or {}
    out = []
    out.append("# Findings — %s" % t.get("package", "(target not recorded)"))
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append("| Package | `%s` |" % t.get("package", "?"))
    out.append("| Version | `%s` |" % t.get("version", "?"))
    out.append("| Artefact SHA-256 | `%s` |" % t.get("sha256", "?"))
    out.append("| Device | `%s` |" % t.get("device", "?"))
    out.append("")

    answered = [q for q in d["questions"] if q["state"] == "answered"]
    if answered:
        out.append("## Findings")
        out.append("")
        for q in answered:
            out.append("### %s — %s" % (q["id"], q["text"]))
            out.append("")
            out.append("**Claim.** %s" % q["answer"])
            out.append("")
            out.append("**Evidence.**")
            out.append("")
            for s in q["sources"]:
                out.append("- %s" % s)
            out.append("")
            hs = [h for h in d["hypotheses"] if h["question"] == q["id"]]
            if hs:
                out.append("**How it was established.**")
                out.append("")
                out.append("| Hypothesis | Experiment | Observed | Verdict |")
                out.append("|---|---|---|---|")
                for h in hs:
                    out.append("| %s | `%s` | `%s` | %s |" % (
                        h["claim"], h["experiment"] or "-",
                        h["observed"] or "-", h["verdict"] or "open"))
                out.append("")

    unresolved = [q for q in d["questions"] if q["state"] in ("blocked", "deferred")]
    if unresolved:
        out.append("## Questions not answered")
        out.append("")
        out.append("| Question | State | Reason |")
        out.append("|---|---|---|")
        for q in unresolved:
            out.append("| %s | %s | %s |" % (q["text"], q["state"],
                                             q.get("reason") or "-"))
        out.append("")

    out.append("## Limits and residue")
    out.append("")
    if not d["residue"]:
        out.append("*Nothing recorded — which is almost certainly wrong. A report "
                   "with no residue implies a completeness no method delivers.*")
    else:
        for kind, title in (("chosen", "Seen and not pursued"),
                            ("structural", "Not visible to the method used")):
            items = [r for r in d["residue"] if r["kind"] == kind]
            if items:
                out.append("**%s.**" % title)
                out.append("")
                for r in items:
                    out.append("- %s" % r["text"])
                out.append("")

    still_open = [q for q in d["questions"] if q["state"] == "open"]
    if still_open:
        out.append("**Still open at the time of writing.**")
        out.append("")
        for q in still_open:
            out.append("- %s" % q["text"])
        out.append("")

    print("\n".join(out))
    return 0


def cmd_tiers(a, d):
    print("The evidence ladder (chapter 68 section 2.3). Tag each source.")
    print()
    for k in sorted(TIER_HINTS):
        print("  tier %d  %s" % (k, TIER_HINTS[k]))
    print()
    print("Tiers 1-3 tell you what to believe provisionally.")
    print("Tiers 4-6 tell you what to write down.")
    return 0


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------
def cmd_selftest(a, d):
    failures = []

    def check(name, cond):
        print("  %-58s %s" % (name, "ok" if cond else "FAIL"))
        if not cond:
            failures.append(name)

    with tempfile.TemporaryDirectory(prefix="re-journal-test-") as tmp:
        path = os.path.join(tmp, "j.json")

        def run(argv):
            return main(["--file", path] + argv)

        print("re-journal selftest")
        check("init", run(["init", "--target", "com.example.t",
                           "--sha256", "deadbeef", "--version", "1.0",
                           "--device", "serial0"]) == 0)
        check("ask", run(["ask", "What gates the vault?"]) == 0)

        # the central rule: no refutation test -> refusal
        check("hypothesis with blank refutation is REFUSED",
              run(["hypothesise", "Q1", "--claim", "c",
                   "--predict", "p", "--refute", "  "]) == 1)
        check("hypothesis with a real refutation is accepted",
              run(["hypothesise", "Q1", "--claim", "iv_check_license gates it",
                   "--predict", "a call site targets it",
                   "--refute", "zero call sites target it"]) == 0)

        # a verdict with no observation behind it is an opinion
        check("verdict before observation is REFUSED",
              run(["verdict", "H1", "refuted"]) == 1)
        check("observe", run(["observe", "H1", "--experiment", "grep -c bl",
                              "--observed", "0", "--tier", "4"]) == 0)
        check("verdict after observation", run(["verdict", "H1", "refuted"]) == 0)

        # closing as answered needs an answer and TWO sources
        check("close answered with no answer is REFUSED",
              run(["close", "Q1", "answered"]) == 1)
        check("close answered with one source is REFUSED",
              run(["close", "Q1", "answered", "--answer", "x",
                   "--source", "tier4: only one"]) == 1)
        check("close answered with two sources",
              run(["close", "Q1", "answered", "--answer",
                   "An inlined seed comparison in iv_open_vault",
                   "--source", "tier4: cmp w8,#0xbd",
                   "--source", "tier6: key flips the outcome both ways"]) == 0)

        check("residue", run(["residue", "splits not pulled",
                              "--kind", "structural"]) == 0)

        # persistence and encoding
        raw = open(path, "rb").read()
        check("ledger is BOM-less UTF-8", not raw.startswith(b"\xef\xbb\xbf"))
        d2 = json.loads(raw.decode("utf-8"))
        check("one question, closed answered",
              len(d2["questions"]) == 1 and d2["questions"][0]["state"] == "answered")
        check("one hypothesis, refuted",
              len(d2["hypotheses"]) == 1 and d2["hypotheses"][0]["verdict"] == "refuted")
        check("observation preserved verbatim", d2["hypotheses"][0]["observed"] == "0")
        check("two sources recorded", len(d2["questions"][0]["sources"]) == 2)
        check("residue recorded", len(d2["residue"]) == 1)
        check("status", run(["status"]) == 0)
        check("report", run(["report"]) == 0)

    print()
    if failures:
        print("FAILED: %d check(s): %s" % (len(failures), ", ".join(failures)))
        return 2
    print("PASS: all checks")
    return 0


# --------------------------------------------------------------------------
def build_parser():
    ap = argparse.ArgumentParser(
        description="Hypothesis ledger for a reverse-engineering session.")
    ap.add_argument("--file", default="re-journal.json")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init"); p.set_defaults(fn=cmd_init)
    p.add_argument("--target", required=True)
    p.add_argument("--sha256", default="")
    p.add_argument("--version", default="")
    p.add_argument("--device", default="")

    p = sub.add_parser("ask"); p.set_defaults(fn=cmd_ask)
    p.add_argument("text")

    p = sub.add_parser("hypothesise", aliases=["hypothesize"])
    p.set_defaults(fn=cmd_hypothesise)
    p.add_argument("question")
    p.add_argument("--claim", required=True)
    p.add_argument("--predict", required=True)
    p.add_argument("--refute", required=True,
                   help="MANDATORY: what you would observe if this were false")
    p.add_argument("--tier", type=int, choices=list(TIER_HINTS))

    p = sub.add_parser("observe"); p.set_defaults(fn=cmd_observe)
    p.add_argument("hypothesis")
    p.add_argument("--experiment", required=True)
    p.add_argument("--observed", required=True,
                   help="what you SAW, not what you concluded")
    p.add_argument("--tier", type=int, choices=list(TIER_HINTS))

    p = sub.add_parser("verdict"); p.set_defaults(fn=cmd_verdict)
    p.add_argument("hypothesis")
    p.add_argument("verdict", choices=VERDICTS)
    p.add_argument("--note", default=None)

    p = sub.add_parser("residue"); p.set_defaults(fn=cmd_residue)
    p.add_argument("text")
    p.add_argument("--kind", choices=RESIDUE_KINDS, default="chosen")

    p = sub.add_parser("close"); p.set_defaults(fn=cmd_close)
    p.add_argument("question")
    p.add_argument("state", choices=CLOSURES)
    p.add_argument("--answer", default=None)
    p.add_argument("--source", action="append")
    p.add_argument("--reason", default=None)

    p = sub.add_parser("status"); p.set_defaults(fn=cmd_status)
    p = sub.add_parser("report"); p.set_defaults(fn=cmd_report)
    p = sub.add_parser("tiers");  p.set_defaults(fn=cmd_tiers)
    p = sub.add_parser("selftest"); p.set_defaults(fn=cmd_selftest)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd == "selftest":
        return cmd_selftest(args, None)
    data = load(args.file)
    rc = args.fn(args, data)
    if rc == 0 and args.cmd not in ("status", "report", "tiers"):
        save(args.file, data)
    return rc


if __name__ == "__main__":
    sys.exit(main())
