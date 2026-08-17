// scripts/root-disable-equivalent.js
//
// PURPOSE
//   Reproduce `objection android root disable` -- exactly, hook for hook -- and
//   then report everything the canned version hides.
//
//   This script installs the SAME three hooks objection 1.11.0 installs, using
//   the SAME thirteen hard-coded paths, with the SAME semantics. Run it against
//   an app and the app cannot tell the difference. What differs is what YOU are
//   told:
//
//     objection says      : "Registering job 370560. Type: root-detection-disable"
//     this script says    : which checks the app actually performed, which of
//                           them the canned envelope covers, which it does not,
//                           and -- at the end -- a coverage summary naming the
//                           calls that no version of this hook set can ever see.
//
//   Both take about the same time to run. Only one produces a finding you can
//   hand to a developer. That is the whole argument of chapter 54, expressed as
//   a diff between two scripts that do the same thing.
//
//   The three hooks, taken verbatim from objection's agent.js module 90
//   (android/root). Read them yourself with scripts/split-agent.py:
//
//     1. java.lang.String.contains(String)  -> false when the argument is "test-keys"
//     2. java.lang.Runtime.exec(String)     -> IOException when the command ends in "su"
//     3. java.io.File.exists()              -> false when the path is one of 13 strings
//
// USAGE
//   # host -- spawn the app so hooks are in place before any of its code runs
//   frida -U -f com.pentest.ch54.target -l scripts/root-disable-equivalent.js
//
//   # host -- attach to a running app (you will MISS everything that already ran)
//   frida -U -n "CH54 Target" -l scripts/root-disable-equivalent.js
//
//   # host -- observe only: report every check, suppress NOTHING.
//   #         Run this FIRST, always. It tells you what the app checks before
//   #         you change any answer, which is the measurement objection cannot make.
//   frida -U -f com.pentest.ch54.target -l scripts/root-disable-equivalent.js \
//         -e 'OBSERVE_ONLY=true'
//
//   In the Frida REPL, at any time:
//     rpc.exports.summary()     -> the coverage report as an object
//     rpc.exports.reset()       -> clear the counters
//
//   Configuration is at the top of the CONFIG block below; edit it, or set
//   globals before load as shown above.
//
// REQUIREMENTS
//   * frida-server on the device matching your host `frida --version`, or a
//     gadget-patched APK. Same precondition as objection -- this script is not
//     a way around needing Frida.
//   * An app you own. See the safety note at the bottom.
//
// WHAT THIS WILL *NOT* TELL YOU
//   * It will NOT catch native checks. A `stat()` or `access()` inside a .so
//     never enters java.io.File, so no Java hook can see it, and neither this
//     script nor objection will report it. If the summary says the app made
//     zero File.exists() calls and the app still knows it is rooted, the check
//     is native -- and that is a real result, not a failure. Continue in
//     37-RootDetection section 7.5 and 53-Frida.
//   * It will NOT catch checks that ran before it loaded. Use -f, not -n.
//   * It will NOT make the app work. Defeating three Java checks is not a
//     bypass of a real hardened app, and this script does not pretend otherwise.
//     Its output is a MAP of the Java-layer surface, which is what tells you
//     whether to keep going at this layer or move down one.
//   * It will NOT tell you the app is not rooted-aware. A silent app may simply
//     not have run its gate yet. Drive the UI.
//   * `String.contains` may be hooked and never fire: ART is free to intrinsify
//     and inline core-library methods, so the hook can install and have no
//     effect. This was MEASURED while writing chapter 54 -- the hook was
//     present, the argument was exactly "test-keys", and it never fired. The
//     summary reports installed-but-never-called separately from not-installed
//     for exactly this reason.
//
// AUTHORISED TESTING ONLY. Instrument applications you own or are explicitly
// authorised to test. This chapter's own target is examples/target-app/.

'use strict';

// --------------------------------------------------------------------------- //
// CONFIG
// --------------------------------------------------------------------------- //
var CONFIG = {
    // true  = report only, change nothing (run this FIRST)
    // false = behave exactly like `android root disable`
    observeOnly: (typeof OBSERVE_ONLY !== 'undefined') ? !!OBSERVE_ONLY : false,

    // Log every File.exists() call, not just the ones on the list. Noisy, and
    // the noise is the point: it shows you how much of the app's filesystem
    // activity the canned envelope never looks at.
    verboseFileExists: (typeof VERBOSE !== 'undefined') ? !!VERBOSE : true,

    // Print a coverage summary this many milliseconds after load. 0 disables.
    autoSummaryMs: 15000
};

// The thirteen paths, verbatim from objection agent.js module 90.
// Do not "improve" this list. Its value is that it is EXACTLY objection's, so
// that a difference in behaviour between this script and objection is a bug in
// one of them rather than a difference in configuration.
var OBJECTION_PATHS = [
    '/data/local/bin/su',
    '/data/local/su',
    '/data/local/xbin/su',
    '/dev/com.koushikdutta.superuser.daemon/',
    '/sbin/su',
    '/system/app/Superuser.apk',
    '/system/bin/failsafe/su',
    '/system/bin/su',
    '/system/etc/init.d/99SuperSUDaemon',
    '/system/sd/xbin/su',
    '/system/xbin/busybox',
    '/system/xbin/daemonsu',
    '/system/xbin/su'
];

// Paths a real checker probes that are NOT on objection's list. Purely for
// reporting: when one of these is seen, the script says so loudly, because
// that single line is the finding.
var COMMON_BUT_UNCOVERED = [
    '/sbin/magisk', '/sbin/.magisk', '/data/adb/magisk', '/data/adb/modules',
    '/system/bin/magisk', '/data/adb/ksu', '/system/xbin/which',
    '/system/bin/which', '/su/bin/su', '/data/adb/su', '/dev/su',
    '/system/usr/we-need-root/su', '/cache/su', '/magisk'
];

// --------------------------------------------------------------------------- //
// STATE
// --------------------------------------------------------------------------- //
var stats = null;

function freshStats() {
    return {
        startedAt: Date.now(),
        hooksInstalled: {},          // name -> true/false
        hookInstallError: {},        // name -> message
        fileExists: { total: 0, onList: 0, uncoveredKnown: 0, other: 0,
                      pathsSeen: {}, listHits: {}, uncoveredHits: {} },
        execString: { total: 0, suLike: 0, commands: {} },
        execArray: { total: 0, suLike: 0, commands: {} },     // NOT hooked by objection
        processBuilder: { total: 0, suLike: 0, commands: {} },// NOT hooked by objection
        stringContains: { testKeysCalls: 0 }
    };
}

stats = freshStats();

function log(msg) { console.log(msg); }

function bump(obj, key) { obj[key] = (obj[key] || 0) + 1; }

function pad(s, n) {
    s = String(s);
    while (s.length < n) { s += ' '; }
    return s;
}

// --------------------------------------------------------------------------- //
// HOOK 1 -- java.lang.String.contains(String)
//
// objection: returns false (disable) or true (simulate) when the argument is
// exactly "test-keys"; otherwise calls the original.
// --------------------------------------------------------------------------- //
function hookStringContains() {
    var name = 'String.contains';
    try {
        var JavaString = Java.use('java.lang.String');

        JavaString.contains.implementation = function (needle) {
            var arg = needle ? needle.toString() : '';

            if (arg !== 'test-keys') {
                return this.contains(needle);
            }

            stats.stringContains.testKeysCalls++;
            var real = this.contains(needle);
            var self = this.toString();

            if (CONFIG.observeOnly) {
                log('[String.contains ] "test-keys" tested against "' + self +
                    '" -> real: ' + real + '   (OBSERVE, unchanged)');
                return real;
            }

            log('[String.contains ] "test-keys" tested against "' + self +
                '" -> FORCED false   (was ' + real + ')');
            return false;
        };

        stats.hooksInstalled[name] = true;
        log('[+] hook 1/3 installed: java.lang.String.contains(String)');
    } catch (e) {
        stats.hooksInstalled[name] = false;
        stats.hookInstallError[name] = String(e);
        log('[-] hook 1/3 FAILED: ' + e);
    }
}

// --------------------------------------------------------------------------- //
// HOOK 2 -- java.lang.Runtime.exec(String)
//
// objection: throws IOException("objection anti-root") when the command ends
// with "su". Note it hooks ONLY the single-String overload.
// --------------------------------------------------------------------------- //
function hookRuntimeExecString() {
    var name = 'Runtime.exec(String)';
    try {
        var Runtime = Java.use('java.lang.Runtime');
        var IOException = Java.use('java.io.IOException');
        var target = Runtime.exec.overload('java.lang.String');

        target.implementation = function (command) {
            var cmd = command ? command.toString() : '';
            stats.execString.total++;
            bump(stats.execString.commands, cmd);

            if (!cmd.endsWith('su')) {
                return target.call(this, command);
            }

            stats.execString.suLike++;

            if (CONFIG.observeOnly) {
                log('[Runtime.exec   ] "' + cmd +
                    '"  -> matches objection filter, OBSERVE, passed through');
                return target.call(this, command);
            }

            log('[Runtime.exec   ] "' + cmd +
                '"  -> IOException forced   (objection envelope: COVERED)');
            throw IOException.$new('objection anti-root');
        };

        stats.hooksInstalled[name] = true;
        log('[+] hook 2/3 installed: java.lang.Runtime.exec(java.lang.String)');
    } catch (e) {
        stats.hooksInstalled[name] = false;
        stats.hookInstallError[name] = String(e);
        log('[-] hook 2/3 FAILED: ' + e);
    }
}

// --------------------------------------------------------------------------- //
// HOOK 3 -- java.io.File.exists()
//
// objection: returns false when getAbsolutePath() is EXACTLY one of the
// thirteen strings; otherwise calls the original.
// --------------------------------------------------------------------------- //
function hookFileExists() {
    var name = 'File.exists';
    try {
        var JavaFile = Java.use('java.io.File');

        JavaFile.exists.implementation = function () {
            var path;
            try { path = this.getAbsolutePath(); } catch (e) { path = '<unknown>'; }

            var real = this.exists();
            stats.fileExists.total++;
            bump(stats.fileExists.pathsSeen, path);

            var onList = OBJECTION_PATHS.indexOf(path) >= 0;
            var knownUncovered = COMMON_BUT_UNCOVERED.indexOf(path) >= 0;

            if (onList) {
                stats.fileExists.onList++;
                bump(stats.fileExists.listHits, path);
                if (CONFIG.observeOnly) {
                    log('[File.exists    ] ' + pad(path, 42) +
                        ' -> real: ' + real + '   (COVERED, OBSERVE)');
                    return real;
                }
                log('[File.exists    ] ' + pad(path, 42) +
                    ' -> FORCED false  (was ' + real + ')  (COVERED)');
                return false;
            }

            if (knownUncovered) {
                stats.fileExists.uncoveredKnown++;
                bump(stats.fileExists.uncoveredHits, path);
                // This line is the finding. objection prints nothing here.
                log('[File.exists    ] ' + pad(path, 42) +
                    ' -> real: ' + real +
                    '   *** NOT IN OBJECTION\'S 13-PATH LIST ***');
                return real;
            }

            stats.fileExists.other++;
            if (CONFIG.verboseFileExists) {
                log('[File.exists    ] ' + pad(path, 42) +
                    ' -> real: ' + real + '   (not a root path)');
            }
            return real;
        };

        stats.hooksInstalled[name] = true;
        log('[+] hook 3/3 installed: java.io.File.exists()');
    } catch (e) {
        stats.hooksInstalled[name] = false;
        stats.hookInstallError[name] = String(e);
        log('[-] hook 3/3 FAILED: ' + e);
    }
}

// --------------------------------------------------------------------------- //
// OBSERVERS -- deliberately NOT part of objection's three hooks.
//
// These change nothing. They exist to COUNT the calls that sit outside the
// canned envelope, so the summary can state the gap as a number rather than as
// an opinion. Every call these observers see is a check that
// `android root disable` cannot influence, no matter what it reports.
// --------------------------------------------------------------------------- //
function observeExecArray() {
    var name = 'Runtime.exec(String[]) [OBSERVER]';
    try {
        var Runtime = Java.use('java.lang.Runtime');
        var target = Runtime.exec.overload('[Ljava.lang.String;');

        target.implementation = function (argv) {
            var joined = '';
            try { joined = Java.array('java.lang.String', argv).join(' '); }
            catch (e) { joined = '<unreadable argv>'; }

            stats.execArray.total++;
            bump(stats.execArray.commands, joined);
            if (/(^|[\s\/])su($|\s)|which\s+su/.test(joined)) {
                stats.execArray.suLike++;
                log('[exec(String[]) ] "' + joined +
                    '"  *** OUTSIDE OBJECTION\'S ENVELOPE -- not hooked ***');
            }
            return target.call(this, argv);
        };

        stats.hooksInstalled[name] = true;
        log('[+] observer installed: java.lang.Runtime.exec(String[])  (reports only)');
    } catch (e) {
        stats.hooksInstalled[name] = false;
        stats.hookInstallError[name] = String(e);
        log('[-] observer failed: exec(String[]): ' + e);
    }
}

function observeProcessBuilder() {
    var name = 'ProcessBuilder.start() [OBSERVER]';
    try {
        var PB = Java.use('java.lang.ProcessBuilder');

        PB.start.implementation = function () {
            var joined = '';
            try { joined = this.command().toString(); } catch (e) { joined = '<unreadable>'; }

            stats.processBuilder.total++;
            bump(stats.processBuilder.commands, joined);
            if (joined.indexOf('su') >= 0) {
                stats.processBuilder.suLike++;
                log('[ProcessBuilder ] ' + joined +
                    '  *** OUTSIDE OBJECTION\'S ENVELOPE -- not hooked ***');
            }
            return this.start();
        };

        stats.hooksInstalled[name] = true;
        log('[+] observer installed: java.lang.ProcessBuilder.start()  (reports only)');
    } catch (e) {
        stats.hooksInstalled[name] = false;
        stats.hookInstallError[name] = String(e);
        log('[-] observer failed: ProcessBuilder.start(): ' + e);
    }
}

// --------------------------------------------------------------------------- //
// SUMMARY -- the part objection does not have
// --------------------------------------------------------------------------- //
function keysByCount(obj, limit) {
    return Object.keys(obj)
        .sort(function (a, b) { return obj[b] - obj[a]; })
        .slice(0, limit || 12);
}

function summary() {
    var s = stats;
    var seconds = Math.round((Date.now() - s.startedAt) / 1000);

    log('');
    log('==============================================================');
    log(' COVERAGE SUMMARY -- objection android root disable equivalent');
    log(' mode: ' + (CONFIG.observeOnly ? 'OBSERVE ONLY (nothing changed)'
                                        : 'ACTIVE (behaves as objection does)'));
    log(' window: ' + seconds + 's');
    log('==============================================================');

    log('');
    log(' INSIDE the canned envelope -- these three hooks ARE what');
    log(' `android root disable` installs:');
    log('   File.exists()      calls seen : ' + s.fileExists.total);
    log('     on objection\'s 13-path list : ' + s.fileExists.onList);
    log('   Runtime.exec(String) calls    : ' + s.execString.total +
        '   (ending in "su": ' + s.execString.suLike + ')');
    log('   String.contains("test-keys")  : ' + s.stringContains.testKeysCalls);

    if (s.fileExists.onList > 0) {
        log('');
        log('   paths matched from the list:');
        keysByCount(s.fileExists.listHits).forEach(function (p) {
            log('     ' + pad(p, 44) + ' x' + s.fileExists.listHits[p]);
        });
    }

    log('');
    log(' OUTSIDE the canned envelope -- no configuration of');
    log(' `android root disable` can influence any of these:');
    log('   File.exists() on known-uncovered root paths : ' + s.fileExists.uncoveredKnown);
    log('   Runtime.exec(String[]) calls                : ' + s.execArray.total +
        '   (su-like: ' + s.execArray.suLike + ')');
    log('   ProcessBuilder.start() calls                : ' + s.processBuilder.total +
        '   (su-like: ' + s.processBuilder.suLike + ')');

    if (s.fileExists.uncoveredKnown > 0) {
        log('');
        log('   uncovered paths the app actually probed:');
        keysByCount(s.fileExists.uncoveredHits).forEach(function (p) {
            log('     ' + pad(p, 44) + ' x' + s.fileExists.uncoveredHits[p]);
        });
    }

    log('');
    log(' HOOK STATUS');
    Object.keys(s.hooksInstalled).forEach(function (k) {
        var ok = s.hooksInstalled[k];
        log('   ' + (ok ? '[installed] ' : '[FAILED   ] ') + k +
            (ok ? '' : '  -- ' + s.hookInstallError[k]));
    });

    // The distinction that matters, and that no tool's output gives you.
    if (s.hooksInstalled['String.contains'] && s.stringContains.testKeysCalls === 0) {
        log('');
        log('   NOTE: String.contains is hooked but was never called with');
        log('   "test-keys". Installed-but-never-fired is NOT the same as');
        log('   not-installed. Either the app does not check build tags, or');
        log('   ART inlined the call so the hook is unreachable. Chapter 54');
        log('   section 3.5.2 measured exactly this.');
    }

    log('');
    log(' READ THIS BEFORE CONCLUDING ANYTHING');
    if (s.fileExists.total === 0 && s.execString.total === 0 &&
        s.execArray.total === 0 && s.processBuilder.total === 0) {
        log('   The app made NO Java-layer probes at all in this window.');
        log('   Either you attached too late (use -f), or you did not drive');
        log('   the code path, or every check is NATIVE. A silent report is');
        log('   not a clean report -- see 51-DynamicAnalysis section 7.9.');
    } else if (s.fileExists.uncoveredKnown > 0 || s.execArray.suLike > 0 ||
               s.processBuilder.suLike > 0) {
        log('   This app probes root artefacts that `android root disable`');
        log('   structurally cannot reach. If the canned command "worked",');
        log('   it worked by coincidence. Write the specific hook.');
    } else {
        log('   Everything observed sits inside the canned envelope. That is');
        log('   a genuine, reportable characterisation: the app\'s root');
        log('   detection is Java-layer and conventional. Say so in those');
        log('   words rather than "objection defeated it".');
    }
    log('==============================================================');
    log('');

    return s;
}

// --------------------------------------------------------------------------- //
// MAIN
// --------------------------------------------------------------------------- //
Java.perform(function () {
    log('');
    log('root-disable-equivalent.js  --  chapter 54');
    log('reproducing `objection android root disable`, with the reporting it lacks');
    log('mode: ' + (CONFIG.observeOnly ? 'OBSERVE ONLY' : 'ACTIVE'));
    log('');

    // The three hooks objection installs.
    hookStringContains();
    hookRuntimeExecString();
    hookFileExists();

    // The observers objection does not have. These are the difference.
    observeExecArray();
    observeProcessBuilder();

    log('');
    log('[*] 3 hooks + 2 observers active. Drive the app, then call');
    log('[*] rpc.exports.summary() -- or wait ' +
        Math.round(CONFIG.autoSummaryMs / 1000) + 's for it automatically.');
    log('');

    if (CONFIG.autoSummaryMs > 0) {
        setTimeout(summary, CONFIG.autoSummaryMs);
    }
});

rpc.exports = {
    summary: function () { return summary(); },
    reset: function () { stats = freshStats(); return true; },
    stats: function () { return stats; }
};
