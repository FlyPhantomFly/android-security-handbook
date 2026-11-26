#!/usr/bin/env node
// 78-Diagrams/scripts/validate-mermaid.mjs
//
// PURPOSE
//   Parse every fenced ```mermaid block and every standalone .mmd source in this
//   repository with the REAL Mermaid parser and report the ones that do not parse.
//
//   A diagram that does not parse renders on GitHub as a red error box. It is the
//   one defect in this repository that every reader sees and no author does,
//   because Markdown previewers vary and a broken block often still looks fine in
//   an editor. Several chapters state a parse count ("11/11 parsing"); this is the
//   script that makes such a claim checkable rather than decorative.
//
//   It uses mermaid's own `mermaid.parse()`, not a regex approximation, so a block
//   that passes here is a block GitHub will draw.
//
// REAL PARSE, OR HEURISTIC? — BOTH, AND THE TWO ARE KEPT APART
//   The pass/fail verdict is a REAL PARSE. Every block is handed to the actual
//   Mermaid parser (`mermaid.parse()`) from the actual `mermaid` package, the same
//   grammar GitHub runs. It is not a regex, and the exit status depends on nothing
//   else. If this script says a block parses, it parsed.
//
//   Two things in the output are NOT a parse and are labelled as such wherever
//   they appear:
//     * the WIDE report  — a proxy for rendered width (source geometry), because
//                          real width needs a browser doing layout. Advisory only;
//                          it never affects the exit status.
//     * the `likely :` line on a failure — a hand-written guess at WHY, since
//                          Mermaid says only WHERE. The failure itself is real.
//
// DEPENDENCIES — deliberately NOT vendored into the repository
//   `mermaid` and `jsdom` are installed OUT OF TREE so no `node_modules` artefact
//   ever lands here. Point the script at that directory:
//
//     mkdir -p /tmp/mmv && cd /tmp/mmv && npm init -y && npm install mermaid@11 jsdom
//     cd <repo>/78-Diagrams
//     node scripts/validate-mermaid.mjs --modules /tmp/mmv
//
//   or set MERMAID_MODULES=/tmp/mmv once and omit the flag.
//
//   jsdom is required because Mermaid is a browser library: its parser touches
//   `document` during initialisation even though parsing itself produces no SVG.
//
// USAGE
//   node scripts/validate-mermaid.mjs --modules DIR              # whole repository
//   node scripts/validate-mermaid.mjs --modules DIR --root .     # this chapter only
//   node scripts/validate-mermaid.mjs --modules DIR --json       # machine-readable
//   node scripts/validate-mermaid.mjs --modules DIR --verbose    # print every block
//   node scripts/validate-mermaid.mjs --modules DIR path/to/file.md
//
// WAS THIS EXECUTED?
//   YES, repeatedly. Latest run 2026-08-17, Node v20.19.1, mermaid 11.16.1 under
//   jsdom 29.1.1, Windows 11, over the whole repository:
//
//       files scanned   : 828
//       blocks          : 818
//       parsed OK       : 818
//       FAILED (parse)  :   0
//       host errors     :   0
//       wide (reported) :  13
//
//   818, not 833. `grep -c '```mermaid'` counts 833 across the repository; the
//   other 15 are not diagrams and must not be validated as such:
//       13  ```mermaid shown as an EXAMPLE inside a wider ````markdown fence
//           (78-Diagrams/README.md, examples/01, examples/02, labs/lab-04)
//        2  the words "```mermaid block" in an HTML comment at the top of the two
//           generated files in ../references/
//   The fence state machine below is what draws that distinction; a naive grep
//   would report 15 phantom diagrams.
//
//   THE PREVIOUS RUN (2026-08-16) FOUND 59 FAILURES AND THEY ARE NOW FIXED.
//   A repo-wide run on 2026-08-17 found 60 (one diagram had been added since):
//
//       35  a semicolon in sequence message or note text  -> `#59;`
//       11  unquoted ( ) or [ ] in mindmap node text      -> wrap in ["..."]
//        6  a backslash-escaped quote in a quoted label   -> `#quot;`
//        6  a `style` line inside a sequenceDiagram       -> `box #f9d0d0`
//         1  `&lt;`/`&gt;` in an UNQUOTED sequence message -> `#60;`/`#62;`
//         1  participant id `Opt` == sequence keyword `opt` -> renamed `Optim`
//        1  three EMPTY `block:`/`end` groups in block-beta -> plain spanning row
//
//   The entity forms are exact: `#59;` renders as a literal `;` and `#quot;` as a
//   literal `"`. That was confirmed by RENDERING to SVG, not by parsing alone, so
//   no diagram's text changed -- see ../examples/02-broken-diagrams-and-their-fixes.md.
//
//   TWO DEFECTS HAVE BEEN FOUND IN THIS SCRIPT AND FIXED:
//   1. The mapping from Mermaid's in-block line number to a file line number was
//      off by one, so every failure report named an innocent line. `b.line` is the
//      OPENING FENCE, so body line N is at b.line + N.
//   2. It reported a FALSE FAILURE on any diagram using a sequence `box`: jsdom
//      keeps `Option` on `window` but not on `globalThis`, and mermaid's sequence
//      grammar reaches for the bare global. The result was
//      `ReferenceError: Option is not defined`, indistinguishable in the old
//      output from a genuine parse error. Fixed twice over: the global is now
//      shimmed, AND any non-parse throw is quarantined as a host error and exits 2
//      instead of being counted as a broken diagram.
//
//   Re-run before quoting any number here.
//
// EXIT STATUS
//   0 if every block parses; 1 if any block fails a REAL parse; 2 if the Mermaid
//   dependency could not be located, or if Mermaid threw a non-parse runtime error
//   (both are setup problems, not diagram problems — the distinction matters,
//   because exiting 1 there would look like a false failure). The WIDE report
//   never changes the exit status.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, relative, sep } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';

// --- argument handling -----------------------------------------------------

const argv = process.argv.slice(2);
const opt = { modules: process.env.MERMAID_MODULES || '', root: '', json: false,
              verbose: false, files: [] };
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--modules') opt.modules = argv[++i];
  else if (a === '--root') opt.root = argv[++i];
  else if (a === '--json') opt.json = true;
  else if (a === '--verbose') opt.verbose = true;
  else if (a === '--help' || a === '-h') { usage(); process.exit(0); }
  else opt.files.push(a);
}

function usage() {
  console.log('usage: node validate-mermaid.mjs --modules DIR [--root DIR] ' +
              '[--json] [--verbose] [files...]');
}

// fileURLToPath, not `.pathname`: this repository lives under a path containing a
// space, and `.pathname` hands back "Android%20Learning", which readdir cannot open.
const SCRIPT_DIR = resolve(fileURLToPath(new URL('.', import.meta.url)));
const CHAPTER_DIR = resolve(SCRIPT_DIR, '..');
const REPO_ROOT = opt.root ? resolve(opt.root) : resolve(CHAPTER_DIR, '..');

// --- load mermaid from the out-of-tree module directory --------------------

async function loadMermaid() {
  const candidates = [];
  if (opt.modules) candidates.push(resolve(opt.modules));
  candidates.push(CHAPTER_DIR, REPO_ROOT, process.cwd());

  for (const dir of candidates) {
    try {
      const req = createRequire(join(dir, 'noop.cjs'));
      const jsdomPath = req.resolve('jsdom');
      const mermaidPath = req.resolve('mermaid');

      // Mermaid is a browser library. Stand up a DOM before importing it.
      const { JSDOM } = await import(pathToFileURL(jsdomPath).href);
      const dom = new JSDOM('<!doctype html><html><body></body></html>',
                            { pretendToBeVisual: true });
      globalThis.window = dom.window;
      globalThis.document = dom.window.document;
      // Node 24 defines `globalThis.navigator` as a getter, so a plain assignment
      // throws. Redefine it instead; the validator needs jsdom's navigator for
      // Mermaid's browser feature checks.
      Object.defineProperty(globalThis, 'navigator', {
        value: dom.window.navigator, configurable: true, writable: true,
      });
      // These four are NOT decoration. jsdom keeps them on `window` but not on
      // `globalThis`, and mermaid's sequence grammar reaches for the bare global
      // `Option` when a diagram uses a `box`. Without this line every `box`
      // diagram fails with `ReferenceError: Option is not defined` — which LOOKS
      // exactly like a broken diagram and is not one. That false negative was
      // measured: `box #f9d0d0 / participant X / end` failed here and parses
      // fine on GitHub. A validator that invents failures is worse than none.
      for (const g of ['Option', 'Image', 'HTMLElement', 'SVGElement']) {
        if (globalThis[g] === undefined && dom.window[g] !== undefined) {
          globalThis[g] = dom.window[g];
        }
      }

      const mod = await import(pathToFileURL(mermaidPath).href);
      const mermaid = mod.default ?? mod;
      mermaid.initialize({ startOnLoad: false, securityLevel: 'loose' });
      return { mermaid, dir };
    } catch (e) {
      if (e && (e.code === 'MODULE_NOT_FOUND' || e.code === 'ERR_MODULE_NOT_FOUND')) continue;
      throw e;
    }
  }
  return null;
}

// --- markdown scanning -----------------------------------------------------
//
// The same fence state machine as diagram-census.py. A fence is closed only by a
// run of at least as many backticks with no info string, which is what stops a
// ```mermaid shown as an EXAMPLE inside a ````markdown fence from being treated
// as a real diagram.

const FENCE = /^\s*(`{3,})\s*([A-Za-z0-9_-]*)\s*$/;

function blocksIn(file) {
  const text = readFileSync(file, 'utf8').replace(/^﻿/, '').replace(/\r\n?/g, '\n');
  // A standalone .mmd file is one diagram. Chapter 81 keeps its sources this way
  // because GitHub's Mermaid iframe can time out; the rendered page uses SVG.
  if (file.toLowerCase().endsWith('.mmd')) return [{ file, line: 1, src: text }];
  const lines = text.split('\n');
  const out = [];
  let ticks = null, info = null, start = 0, body = [];
  for (let i = 0; i < lines.length; i++) {
    const m = FENCE.exec(lines[i]);
    if (ticks === null) {
      if (m) { ticks = m[1].length; info = (m[2] || '').toLowerCase(); start = i + 1; body = []; }
      continue;
    }
    if (m && m[1].length >= ticks && !m[2]) {
      if (info === 'mermaid') out.push({ file, line: start, src: body.join('\n') });
      ticks = null; info = null; body = [];
      continue;
    }
    body.push(lines[i]);
  }
  return out;
}

// --- diagnosis -------------------------------------------------------------
//
// Mermaid's own error says WHERE, never WHY. These six patterns account for every
// failure measured in this repository on 2026-08-16, and each was confirmed by
// reducing it to a two-line diagram that fails and a one-character edit that
// fixes it. This is a HEURISTIC applied to the failing source, not a second
// parser: treat it as a first suggestion, not a verdict.

// Sequence-diagram block keywords. A participant or alias that equals one of
// these -- case-insensitively -- is lexed as the keyword and takes the rest of
// the diagram down with it. `Opt` for "Optimiser" is the case in this repository.
const SEQ_KEYWORDS = new Set([
  'opt', 'alt', 'else', 'loop', 'par', 'and', 'rect', 'break', 'critical',
  'option', 'note', 'end', 'activate', 'deactivate', 'autonumber', 'link',
  'links', 'box', 'over', 'right', 'left', 'of', 'title',
]);

function diagnose(src, failLineInBlock) {
  const lines = src.split('\n');
  const at = lines[failLineInBlock - 1] || '';
  const before = lines.slice(0, failLineInBlock).join('\n');
  const kind = (lines.find((l) => l.trim()) || '').trim().split(/\s+/)[0];
  const isSequence = /^sequenceDiagram/i.test(kind);

  if (isSequence && /^\s*(style|classDef|class)\b/.test(at)) {
    return 'a `style`/`classDef` line inside a sequenceDiagram — that grammar has ' +
           'no styling statement. To keep the STYLE-GUIDE §6 attacker colour, wrap ' +
           'the participant DECLARATION in an unlabelled box:\n' +
           '                  box #f9d0d0 / participant X as ... / end\n' +
           '                which tints that actor and adds no new text.';
  }
  for (const m of before.matchAll(/^\s*(?:participant|actor)\s+([A-Za-z0-9_]+)(?:\s+as\s+(.*))?$/gm)) {
    const id = m[1];
    if (SEQ_KEYWORDS.has(id.toLowerCase())) {
      return `participant id \`${id}\` collides with the sequence keyword ` +
             `\`${id.toLowerCase()}\` (matching is case-insensitive). Rename the id; ` +
             'the display name can stay via `as`.';
    }
  }
  if (/\\"/.test(at)) {
    return 'a backslash-escaped double quote inside a quoted label. Mermaid has no ' +
           'backslash escape there — use `#quot;` or drop the inner quotes.';
  }
  // Must be tested BEFORE the bare-semicolon rule: the `;` that breaks the line is
  // the one that terminates the entity, so the generic advice ("use a comma")
  // would silently mangle `&lt;` into `&lt,`.
  if (isSequence && /&(lt|gt|amp|quot);/.test(at)) {
    return 'an HTML entity in an UNQUOTED sequence message — the `;` that ends ' +
           '`&lt;` also ends the statement. Use Mermaid entity codes instead: ' +
           '`#60;` `#62;` `#38;` `#quot;`.';
  }
  if (/^\s*block:/.test(at) || /^\s*block:/.test((lines[failLineInBlock - 2] || ''))) {
    return 'an EMPTY `block:<id>` group in block-beta — a group must contain at ' +
           'least one child. For a full-width heading row drop the `block:`/`end` ' +
           'and use a plain spanning node: `id["label"]:3`.';
  }
  if (/;/.test(at)) {
    return 'a semicolon in message or label text. `;` is a statement separator, so ' +
           'the rest of the line is parsed as a new statement. Write it `#59;`, ' +
           'which renders as a literal `;` and so keeps code snippets exact. ' +
           '(A comma or `<br/>` also parses, but changes the text.)';
  }
  // A mindmap node whose TEXT begins with a diagram-type keyword restarts type
  // detection and blows up. `mindmap the parts of a topic` as a leaf is the case
  // that hit this chapter's own summary map while it was being written.
  if (/^mindmap/i.test(kind) &&
      /^\s*(mindmap|flowchart|graph|sequenceDiagram|classDiagram|stateDiagram|erDiagram|journey|gantt|pie|timeline)\b/i.test(at)) {
    return 'a mindmap leaf whose text STARTS with a diagram-type keyword. Mermaid ' +
           're-detects the diagram type and fails. Reword the leaf, or quote it.';
  }
  if (/^mindmap/i.test(kind) && /[()[\]{}]/.test(at)) {
    return 'unquoted brackets or parentheses in mindmap text — those are the node ' +
           'SHAPE delimiters. Wrap the text: `id["the text (with parens)"]`.';
  }
  if (/[()[\]{}]/.test(at)) {
    return 'unquoted brackets or parentheses in node text. Quote the whole label: ' +
           '`A["exit_group(0)"]`.';
  }
  return 'no known pattern matched — read the excerpt and the line above it.';
}

function walk(dir, acc) {
  for (const name of readdirSync(dir).sort()) {
    if (name === '.git' || name === 'node_modules' || name === '__pycache__') continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, acc);
    else if (name.toLowerCase().endsWith('.md') ||
             name.toLowerCase().endsWith('.mmd')) acc.push(p);
  }
  return acc;
}

// --- main ------------------------------------------------------------------

const loaded = await loadMermaid();
if (!loaded) {
  console.error('error: could not resolve `mermaid` and `jsdom`.');
  console.error('       Install them OUT OF TREE and pass --modules, e.g.:');
  console.error('         mkdir -p /tmp/mmv && cd /tmp/mmv && npm init -y && ' +
                'npm install mermaid@11 jsdom');
  console.error('         node scripts/validate-mermaid.mjs --modules /tmp/mmv');
  console.error('       Exiting 2: this is a setup problem, not a diagram problem.');
  process.exit(2);
}
const { mermaid, dir: modulesDir } = loaded;

const files = opt.files.length ? opt.files.map((f) => resolve(f))
                              : walk(REPO_ROOT, []);
const blocks = files.flatMap(blocksIn);

const failures = [];
const hostErrors = [];
const wide = [];
const byType = new Map();

// A diagram can parse perfectly and still be unreadable on GitHub, which renders
// into a fixed-width column and does not let the reader pan. Nothing in the
// parser knows or cares about this, so measure it separately. These are REPORTED,
// never failed on: width is a judgement call and a genuinely wide diagram is
// sometimes the honest way to draw the thing.
//
// HEIGHT IS NOT A DEFECT and is deliberately not measured. A tall diagram
// scrolls; a wide one is clipped. The first version of this check also flagged
// >60 rows and reported 122 diagrams, almost all of them ordinary per-chapter
// mindmaps — a report nobody would read. These four thresholds sit at roughly
// the 99th percentile of this repository as measured on 2026-08-17:
//
//     longest source line   p50  80   p90 123   p99 205   max 300
//     participants          p50   0   p90   5   p99   7   max  17
//     widest single label   p50  30   p90  52   p99  78   max 154
//     mindmap depth         p50   0   p90   4   p99   5   max   7
//
// They are a PROXY for rendered width, not a measurement of it: real width comes
// from layout, which needs a browser. Treat a hit as "go and look at this one".
const WIDE_COLS   = 200;  // longest source line, in characters
const WIDE_ACTORS = 12;   // participants in a sequenceDiagram
const WIDE_LABEL  = 100;  // longest single label segment between <br/> breaks
const WIDE_DEPTH  = 7;    // mindmap nesting depth

for (const b of blocks) {
  try {
    const r = await mermaid.parse(b.src);
    const t = (r && r.diagramType) || 'unknown';
    byType.set(t, (byType.get(t) || 0) + 1);
    const srcLines = b.src.split('\n');
    const cols = srcLines.reduce((m, l) => Math.max(m, l.length), 0);
    const actors = srcLines.filter((l) => /^\s*(participant|actor)\b/.test(l)).length;
    let label = 0;
    for (const m of b.src.matchAll(/"([^"]*)"/g)) {
      // <br/> is a real line break in the rendered box, so measure the SEGMENTS,
      // not the whole label: a long label that wraps is not a wide one.
      for (const seg of m[1].split(/<br\s*\/?>/)) label = Math.max(label, seg.length);
    }
    let depth = 0;
    if (/^mindmap/i.test(t) || /^mindmap/i.test(srcLines.find((l) => l.trim()) || '')) {
      for (const l of srcLines) {
        if (!l.trim()) continue;
        depth = Math.max(depth, Math.floor((l.length - l.trimStart().length) / 2));
      }
    }
    const why = [];
    if (cols > WIDE_COLS) why.push(`${cols} col source line`);
    if (actors > WIDE_ACTORS) why.push(`${actors} participants`);
    if (label > WIDE_LABEL) why.push(`${label}-char label`);
    if (depth > WIDE_DEPTH) why.push(`nested ${depth} deep`);
    if (why.length) {
      wide.push({
        file: relative(REPO_ROOT, b.file).split(sep).join('/'),
        line: b.line, type: t, cols, why: why.join(', '),
      });
    }
    if (opt.verbose) {
      console.log(`ok   ${relative(REPO_ROOT, b.file).split(sep).join('/')}:${b.line}  ${t}`);
    }
  } catch (e) {
    const full = String((e && e.message) || e);
    const lines = full.split('\n');
    // A ReferenceError/TypeError from inside mermaid is a HOST problem (a missing
    // browser global under jsdom), not a diagram problem. Counting it as a broken
    // diagram would send someone to "fix" valid Mermaid. Collect separately and
    // exit 2, the same status used for a missing dependency.
    if (!/Parse error|Syntax error|No diagram type detected|Expecting /i.test(full)) {
      hostErrors.push({
        file: relative(REPO_ROOT, b.file).split(sep).join('/'),
        line: b.line,
        error: `${(e && e.name) || 'Error'}: ${lines[0].slice(0, 160)}`,
      });
      continue;
    }
    // Mermaid's parse error is three useful lines: "Parse error on line N:",
    // an excerpt of the offending text, and a caret. The excerpt is what tells
    // you WHICH character upset it, so keep it rather than only the first line.
    const offset = Number((/on line (\d+)/.exec(lines[0]) || [])[1] || 0);
    failures.push({
      file: relative(REPO_ROOT, b.file).split(sep).join('/'),
      line: b.line,
      // Line number in the FILE, not in the block: what you paste into an editor.
      // b.line is the OPENING FENCE, so body line N is at b.line + N. Getting
      // this off by one was the first bug in this script and it pointed at the
      // wrong (innocent) line in every report until it was checked against three
      // known failures by hand.
      fileLine: offset ? b.line + offset : b.line,
      error: lines[0].slice(0, 200),
      excerpt: (lines[1] || '').trim().slice(0, 160),
      detail: full.replace(/\s+/g, ' ').slice(0, 400),
      firstLine: (b.src.split('\n').find((l) => l.trim()) || '').trim().slice(0, 80),
      source: (b.src.split('\n')[offset - 1] || '').trim().slice(0, 160),
      likelyCause: offset ? diagnose(b.src, offset) : 'could not locate the line',
    });
  }
}

if (opt.json) {
  console.log(JSON.stringify({
    modulesDir, root: REPO_ROOT, files: files.length, blocks: blocks.length,
    parsed: blocks.length - failures.length - hostErrors.length,
    failed: failures.length, hostErrors: hostErrors.length,
    byType: Object.fromEntries([...byType].sort((a, b2) => b2[1] - a[1])),
    failures, hostErrorDetail: hostErrors, wide,
  }, null, 2));
} else {
  for (const f of failures) {
    console.log(`FAIL ${f.file}:${f.fileLine}  [${f.firstLine}]`);
    if (f.source) console.log(`       source : ${f.source}`);
    console.log(`       likely : ${f.likelyCause}`);
  }
  console.log('');
  console.log(`mermaid modules : ${modulesDir}`);
  console.log(`root            : ${REPO_ROOT}`);
  console.log(`files scanned   : ${files.length}`);
  console.log('');
  for (const [t, n] of [...byType].sort((a, b2) => b2[1] - a[1])) {
    console.log(`  ${t.padEnd(28)} ${String(n).padStart(5)}`);
  }
  if (wide.length) {
    console.log('WIDE diagrams (reported, NOT failed) — likely clipped in GitHub\'s');
    console.log('fixed-width column. Height is not measured: tall diagrams scroll.');
    for (const w of wide.sort((a, b2) => b2.cols - a.cols)) {
      console.log(`  ${w.file}:${w.line}  [${w.type}]  ${w.why}`);
    }
    console.log('');
  }
  if (hostErrors.length) {
    console.log('HOST/SETUP ERRORS — these are NOT broken diagrams. Mermaid threw a');
    console.log('runtime error (usually a browser global jsdom does not expose).');
    for (const h of hostErrors) console.log(`  ${h.file}:${h.line}  ${h.error}`);
    console.log('');
  }
  console.log(`blocks          : ${blocks.length}`);
  console.log(`parsed OK       : ${blocks.length - failures.length - hostErrors.length}`);
  console.log(`FAILED (parse)  : ${failures.length}`);
  console.log(`host errors     : ${hostErrors.length}`);
  console.log(`wide (reported) : ${wide.length}`);
}

// Host errors exit 2 (setup problem), parse failures exit 1 (diagram problem).
// Wide diagrams never change the exit status: they are advice, not a defect.
if (hostErrors.length) process.exit(2);
process.exit(failures.length ? 1 : 0);
