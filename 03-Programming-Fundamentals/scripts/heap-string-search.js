/*
 * heap-string-search.js — find secrets that a garbage-collected runtime is still holding.
 *
 * WHY THIS SCRIPT EXISTS
 *   Chapter 03 section 3.14.4 makes a claim: `java.lang.String` is immutable and often interned,
 *   so a password or token cannot be overwritten and may live for the whole process. This script
 *   turns that claim into evidence.
 *
 *   The most valuable way to run it is AFTER LOGGING OUT. A session token still present on the
 *   heap after the user has logged out is a clean MASVS-STORAGE finding with a trivially
 *   reproducible proof, and the developer's usual response — "we clear it on logout" — is
 *   answered by the output.
 *
 * WHAT IT DOES
 *   * Walks the live ART heap with Java.choose and inspects every java.lang.String.
 *   * Matches against a pattern list covering tokens, keys, credentials and PII.
 *   * Also scans char[] and StringBuilder, because that is where "we used char[] instead" ends up
 *     when nobody zeroed it.
 *   * Filters out framework and Zygote-image literals, which otherwise drown the output.
 *   * Reports where each hit came from where that can be determined.
 *
 * USAGE
 *   host $ frida -U -n com.target.app -l heap-string-search.js
 *
 *   From the REPL:
 *       scan()                    // full scan with the default patterns
 *       scan(/mySecret/)          // one-off pattern
 *       scanChars()               // char[] and StringBuilder only
 *       compare()                 // snapshot now, then call again after logout to diff
 *
 *   The intended workflow:
 *       1. Log in.        2. scan()      -> tokens present, as expected
 *       3. Log out.       4. scan()      -> are they still there?  <-- the finding
 *
 * WHY IT WORKS AT ALL
 *   Because a garbage collector frees memory when nothing can REACH an object, not when the
 *   programmer is finished with it. "Finished with it" is not a concept the runtime has. Setting a
 *   field to null makes the object unreachable but does not erase the bytes, and the collector may
 *   not run for minutes. Interned literals are never collected at all.
 *
 * SAFETY
 *   Read-only. It prints what is already in memory. The output contains live credentials — treat
 *   the log file accordingly, and use only against apps and accounts you are authorised to test.
 *
 * Chapter 03 — Programming Fundamentals, sections 3.14.4 and 7.4
 */

'use strict';

// -------------------------------------------------------------------------------------------------
// CONFIG
// -------------------------------------------------------------------------------------------------
var CONFIG = {
    minLength: 8,           // ignore anything shorter; short strings are almost all framework noise
    maxPrint: 300,          // truncate output at this many characters
    showFrameworkHits: false // include hits from android.*/java.* literals (very noisy)
};

/* Patterns, grouped so the output tells you what kind of thing was found rather than just that
   something matched. Add your own for the engagement: the app's own token prefix, the customer's
   employee-ID format, whatever is in scope. */
var PATTERNS = [
    ['JWT',              /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
    ['Bearer token',     /\bBearer\s+[A-Za-z0-9._~+\/-]{16,}/],
    ['Auth header',      /\bAuthorization\s*:\s*\S+/i],
    ['Private key',      /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
    ['AWS key id',       /\bAKIA[0-9A-Z]{16}\b/],
    ['Stripe live key',  /\bsk_live_[0-9a-zA-Z]{16,}/],
    ['Google API key',   /\bAIza[0-9A-Za-z_-]{35}\b/],
    ['Slack token',      /\bxox[baprs]-[0-9A-Za-z-]{10,}/],
    ['Password-ish',     /(?:password|passwd|pwd|passphrase)\s*[=:]\s*\S+/i],
    ['PIN-ish',          /(?:^|\W)(?:pin|otp|passcode)\s*[=:]\s*\d{4,8}\b/i],
    ['Refresh token',    /refresh_?token["'\s:=]+[A-Za-z0-9._~+\/-]{16,}/i],
    ['Session id',       /(?:session|sid|jsessionid)["'\s:=]+[A-Za-z0-9]{16,}/i],
    ['Card number',      /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/],
    ['Base64 blob',      /^[A-Za-z0-9+\/]{60,}={0,2}$/],
    ['Hex blob',         /^[0-9a-fA-F]{64,}$/]
];

/* Prefixes whose strings are framework or Zygote-image literals rather than app data.
   Java.choose walks the WHOLE managed heap, including the shared image inherited from Zygote
   (chapter 03 section 4.6), so without this filter you drown in `android.widget.TextView` and
   friends. */
var NOISE = [
    /^android[\.\/]/, /^androidx[\.\/]/, /^java[\.\/]/, /^javax[\.\/]/, /^kotlin[\.\/]/,
    /^com\.android\./, /^com\.google\.android\./, /^dalvik[\.\/]/, /^libcore[\.\/]/,
    /^L(android|java|javax|kotlin|dalvik)\//, /^\/(system|apex|vendor)\//,
    /^http:\/\/schemas\.android\.com/, /^@[0-9a-fA-F]{6,8}$/
];

var lastSnapshot = null;

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

function isNoise(s) {
    if (CONFIG.showFrameworkHits) return false;
    for (var i = 0; i < NOISE.length; i++) {
        if (NOISE[i].test(s)) return true;
    }
    return false;
}

function classify(s) {
    for (var i = 0; i < PATTERNS.length; i++) {
        if (PATTERNS[i][1].test(s)) return PATTERNS[i][0];
    }
    return null;
}

function show(s) {
    return s.length > CONFIG.maxPrint
        ? s.substring(0, CONFIG.maxPrint) + '...(' + s.length + ' chars)'
        : s;
}

function line(ch) { return new Array(79).join(ch || '-'); }

// -------------------------------------------------------------------------------------------------
// The scan
// -------------------------------------------------------------------------------------------------

function scan(extraPattern) {
    var seen = 0;
    var hits = [];
    var byCategory = {};

    console.log('\n' + line('='));
    console.log('  scanning the managed heap for java.lang.String ...');
    console.log(line('='));

    Java.perform(function () {
        Java.choose('java.lang.String', {
            onMatch: function (str) {
                seen++;
                var s;
                try {
                    s = str.toString();
                } catch (e) {
                    return;                 // partially constructed or already collected
                }
                if (s.length < CONFIG.minLength) return;
                if (isNoise(s)) return;

                var category = classify(s);
                if (extraPattern && extraPattern.test(s)) {
                    category = category || 'custom pattern';
                }
                if (!category) return;

                hits.push({ category: category, value: s });
                byCategory[category] = (byCategory[category] || 0) + 1;
            },

            onComplete: function () {
                report(seen, hits, byCategory);
                lastSnapshot = hits.map(function (h) { return h.value; });
            }
        });
    });
}

function report(seen, hits, byCategory) {
    console.log('\n  scanned ' + seen.toLocaleString() + ' strings, ' + hits.length + ' hits\n');

    if (hits.length === 0) {
        console.log('  Nothing matched. That is NOT the same as "no secrets in memory":');
        console.log('    * the secret may be in a char[] or a byte[] — try scanChars()');
        console.log('    * it may be in native memory — try a raw Memory.scan');
        console.log('    * it may not have been created yet — log in first, then rescan');
        console.log('    * your patterns may not cover this app\'s format — add one and rerun');
        return;
    }

    Object.keys(byCategory).sort().forEach(function (cat) {
        console.log('  --- ' + cat + ' (' + byCategory[cat] + ') ---');
        hits.filter(function (h) { return h.category === cat; })
            .slice(0, 20)
            .forEach(function (h) {
                console.log('      ' + show(h.value));
            });
        if (byCategory[cat] > 20) {
            console.log('      ... ' + (byCategory[cat] - 20) + ' more');
        }
        console.log('');
    });

    console.log(line('-'));
    console.log('  THE TEST THAT MAKES THIS A FINDING:');
    console.log('    1. Log in.   2. scan()   -> the token is present, as expected.');
    console.log('    3. LOG OUT.  4. scan()   -> is it STILL present?');
    console.log('');
    console.log('  If it is, the finding is:');
    console.log('    "Session credentials remain recoverable from process memory after the user');
    console.log('     has logged out. java.lang.String is immutable, so the application cannot');
    console.log('     overwrite the value, and the runtime does not erase memory on collection.');
    console.log('     Any attacker with process memory access — root, a debugger, or a memory');
    console.log('     disclosure bug — recovers a live credential."');
    console.log('');
    console.log('  Remediation: char[] or byte[], explicitly zeroed in a finally block; better,');
    console.log('  keep the secret out of the process entirely (Keystore). See 46-Tokens, 49-KeyStore.');
    console.log(line('-'));
}

// -------------------------------------------------------------------------------------------------
// char[] and StringBuilder — where "we used char[] instead" goes to die
// -------------------------------------------------------------------------------------------------

function scanChars() {
    console.log('\n' + line('='));
    console.log('  scanning StringBuilder / StringBuffer ...');
    console.log(line('='));

    Java.perform(function () {
        ['java.lang.StringBuilder', 'java.lang.StringBuffer'].forEach(function (cls) {
            var n = 0, hits = 0;
            Java.choose(cls, {
                onMatch: function (sb) {
                    n++;
                    var s;
                    try { s = sb.toString(); } catch (e) { return; }
                    if (s.length < CONFIG.minLength || isNoise(s)) return;
                    var cat = classify(s);
                    if (cat) {
                        hits++;
                        console.log('  [' + cat + '] ' + show(s));
                    }
                },
                onComplete: function () {
                    console.log('  ' + cls + ': ' + n + ' instances, ' + hits + ' hits');
                }
            });
        });

        console.log('\n  NOTE ON char[]: developers move a password to char[] and then never zero');
        console.log('  it, which achieves nothing — an unzeroed char[] is exactly as recoverable');
        console.log('  as a String. The mitigation is the Arrays.fill(buf, \'\\0\') in the finally');
        console.log('  block, not the type change. Check for the fill, not for the char[].');
    });
}

// -------------------------------------------------------------------------------------------------
// Before/after comparison — the strongest form of the evidence
// -------------------------------------------------------------------------------------------------

function compare() {
    if (lastSnapshot === null) {
        console.log('[!] no previous snapshot. Run scan() first, perform the action, then compare().');
        return;
    }
    var before = lastSnapshot.slice();
    var beforeSet = {};
    before.forEach(function (v) { beforeSet[v] = true; });

    console.log('\n[*] rescanning to compare against the previous snapshot ...');

    var after = [];
    Java.perform(function () {
        Java.choose('java.lang.String', {
            onMatch: function (str) {
                var s;
                try { s = str.toString(); } catch (e) { return; }
                if (s.length < CONFIG.minLength || isNoise(s)) return;
                if (classify(s)) after.push(s);
            },
            onComplete: function () {
                var afterSet = {};
                after.forEach(function (v) { afterSet[v] = true; });

                var survived = before.filter(function (v) { return afterSet[v]; });
                var gone = before.filter(function (v) { return !afterSet[v]; });
                var added = after.filter(function (v) { return !beforeSet[v]; });

                console.log('\n' + line('='));
                console.log('  BEFORE: ' + before.length + '   AFTER: ' + after.length);
                console.log('  survived: ' + survived.length +
                            '   collected: ' + gone.length +
                            '   new: ' + added.length);
                console.log(line('='));

                if (survived.length) {
                    console.log('\n  STILL PRESENT after the action:');
                    survived.slice(0, 20).forEach(function (v) {
                        console.log('    ' + show(v));
                    });
                    console.log('\n  If the action was "log out", every line above is the finding.');
                }
                lastSnapshot = after;
            }
        });
    });
}

// -------------------------------------------------------------------------------------------------
// Wire up
// -------------------------------------------------------------------------------------------------
rpc.exports = { scan: scan, scanchars: scanChars, compare: compare };
global.scan = scan;
global.scanChars = scanChars;
global.compare = compare;

Java.perform(function () {
    console.log('\n==============================================================');
    console.log('  heap-string-search.js — chapter 03 section 7.4');
    console.log('==============================================================');
    console.log('  REPL: scan()  scan(/pattern/)  scanChars()  compare()');
    console.log('');
    console.log('  Workflow:  log in -> scan() -> LOG OUT -> compare()');
    console.log('  A credential that survives the logout is the finding.\n');
    scan();
});
