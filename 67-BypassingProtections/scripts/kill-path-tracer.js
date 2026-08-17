/*
 * scripts/kill-path-tracer.js
 * ---------------------------------------------------------------------------
 * WHAT IT DOES
 *   Intercepts every way an Android process can deliberately end itself, prints
 *   the stack that led there, and (optionally) refuses to let it happen.
 *
 *   Covered, Java side:
 *     System.exit, Runtime.exit, Runtime.halt,
 *     android.os.Process.killProcess, android.os.Process.sendSignal,
 *     Thread.setDefaultUncaughtExceptionHandler (to see a handler being armed)
 *
 *   Covered, native side:
 *     abort, exit, _exit, _Exit, kill, raise, pthread_kill,
 *     __android_log_assert
 *
 * WHY THIS IS THE SECOND THING YOU RUN
 *   ../scripts/bypass-triage.py tells you HOW the process died from the
 *   outside: reason=1 EXIT_SELF status=42, or reason=2 SIGNALED status=9. That
 *   narrows the response but not the decision. This script runs INSIDE the
 *   process and answers the next question - which stack frame decided.
 *
 *   The frame directly above the kill is the BRANCH. The frame above that is
 *   usually the VERDICT. Chapter 67 section 3.7 argues at length that you
 *   should then go DOWN from there rather than hooking either of them, but you
 *   cannot go down from a place you have not found.
 *
 * HOW TO RUN
 *   # host - spawn, so that load-time kills are caught too
 *   frida -U -f com.target.app -l kill-path-tracer.js --no-pause
 *
 *   # host - together with the early harness (order matters)
 *   frida -U -f com.target.app \
 *         -l early-instrument.js -l kill-path-tracer.js --no-pause
 *
 *   # REPL:
 *   #   kpt.block()     stop the process dying; log and return instead
 *   #   kpt.allow()     resume letting it die (the default)
 *   #   kpt.status()    what was hooked, what has fired
 *
 * REQUIREMENTS
 *   frida-server on the device, matching your client. Root, or a gadget build.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - It will NOT catch a kill delivered from OUTSIDE the process. If the
 *     platform, an MDM agent or another app kills you, nothing here fires and
 *     the triage script's exit record is your only evidence.
 *   - It will NOT catch a process that ends by returning from main or by
 *     letting the runtime abort on an uncaught exception - use the exit record
 *     and logcat for those.
 *   - kpt.block() is NOT a bypass. Blocking the kill leaves the app running in
 *     the state it decided was unsafe: half-initialised, with the gated code
 *     still gated. It is a DIAGNOSTIC that buys you a live process to inspect.
 *     Treating it as the fix is the single most common mistake in this
 *     chapter - see README section 11.
 *   - It will NOT survive a check that inlines its own syscall. `kill` and
 *     `abort` are libc symbols; `svc #0` is not.
 *
 * AUTHORISATION
 *   Use only on an application you own or are contracted to assess.
 * ---------------------------------------------------------------------------
 */

'use strict';

var CFG = {
    // Print a full stack for each kill attempt. Almost always what you want.
    stacks: true,
    // Refuse to die. Off by default: an app kept alive against its will
    // behaves strangely, and you should choose that deliberately.
    block: false,
    // Deduplicate identical (function, stack-top) pairs.
    dedupe: true
};

var kpt = {
    hooked: [],
    missing: [],
    fired: {},
    _seen: {}
};

function once(key) {
    if (!CFG.dedupe) return true;
    if (kpt._seen[key]) return false;
    kpt._seen[key] = true;
    return true;
}

function note(where, detail) {
    kpt.fired[where] = (kpt.fired[where] || 0) + 1;
    console.log('');
    console.log('############################################################');
    console.log('# KILL PATH: ' + where);
    if (detail) console.log('# ' + detail);
    console.log('############################################################');
}

function javaStack() {
    try {
        var Exception = Java.use('java.lang.Exception');
        var Log = Java.use('android.util.Log');
        return Log.getStackTraceString(Exception.$new('kill-path-tracer'));
    } catch (e) {
        return '(java stack unavailable: ' + e + ')';
    }
}

function nativeStack(ctx) {
    try {
        return Thread.backtrace(ctx, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join('\n    ');
    } catch (e) {
        try {
            return Thread.backtrace(ctx, Backtracer.FUZZY)
                .map(DebugSymbol.fromAddress)
                .join('\n    ');
        } catch (e2) {
            return '(native stack unavailable)';
        }
    }
}

/*
 * Reading a Java stack: the frames to care about are the FIRST ones that
 * belong to the app's own package. Everything above them is the platform
 * carrying out an instruction it was given, and everything below is your own
 * hook. Chapter 67 calls the first app frame "the branch".
 */
function hookJava() {
    if (!Java.available) {
        console.log('[*] no Java runtime in this process');
        return;
    }

    Java.perform(function () {

        function guard(className, methodName, describe) {
            var clazz;
            try { clazz = Java.use(className); }
            catch (e) { kpt.missing.push(className); return; }

            var method = clazz[methodName];
            if (method === undefined) { kpt.missing.push(className + '.' + methodName); return; }

            method.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var args = Array.prototype.slice.call(arguments);
                    var detail = describe ? describe(args) : args.join(', ');
                    var stack = javaStack();

                    if (once(className + '.' + methodName + ':' + stack.slice(0, 200))) {
                        note(className + '.' + methodName + '(' + detail + ')');
                        if (CFG.stacks) console.log(stack);
                    } else {
                        kpt.fired[className + '.' + methodName] =
                            (kpt.fired[className + '.' + methodName] || 0) + 1;
                    }

                    if (CFG.block) {
                        console.log('[kpt] BLOCKED - the process was told to die and was not '
                            + 'allowed to. It is now running in a state it considers unsafe.');
                        return;
                    }
                    return ov.apply(this, arguments);
                };
            });
            kpt.hooked.push(className + '.' + methodName);
        }

        guard('java.lang.System', 'exit', function (a) { return 'status=' + a[0]; });
        guard('java.lang.Runtime', 'exit', function (a) { return 'status=' + a[0]; });
        guard('java.lang.Runtime', 'halt', function (a) { return 'status=' + a[0]; });
        guard('android.os.Process', 'killProcess', function (a) { return 'pid=' + a[0]; });
        guard('android.os.Process', 'sendSignal', function (a) {
            return 'pid=' + a[0] + ' signal=' + a[1];
        });

        /*
         * Not a kill, but worth seeing: an app that arms its own uncaught
         * exception handler is very often about to convert a detection into a
         * "clean" crash that looks like an ordinary bug in your report.
         */
        try {
            var Thread_ = Java.use('java.lang.Thread');
            Thread_.setDefaultUncaughtExceptionHandler.implementation = function (h) {
                console.log('[kpt] the app armed a default uncaught-exception handler: '
                    + (h === null ? 'null' : h.$className));
                console.log('      any "crash" you see after this may be that handler, not');
                console.log('      the exception you think you are looking at.');
                return this.setDefaultUncaughtExceptionHandler(h);
            };
            kpt.hooked.push('Thread.setDefaultUncaughtExceptionHandler');
        } catch (e) { kpt.missing.push('Thread.setDefaultUncaughtExceptionHandler'); }
    });
}

function hookNative() {
    var fns = [
        ['abort',  'void', []],
        ['exit',   'void', ['int']],
        ['_exit',  'void', ['int']],
        ['_Exit',  'void', ['int']],
        ['kill',   'int',  ['int', 'int']],
        ['raise',  'int',  ['int']],
        ['pthread_kill', 'int', ['pointer', 'int']],
        ['__android_log_assert', 'void', ['pointer', 'pointer', 'pointer']]
    ];

    fns.forEach(function (spec) {
        var name = spec[0];
        var p = null;
        try { p = Module.findExportByName('libc.so', name); } catch (e) { p = null; }
        if (p === null) {
            try { p = Module.findExportByName(null, name); } catch (e) { p = null; }
        }
        if (p === null) { kpt.missing.push(name); return; }

        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    var detail = '';
                    if (name === 'exit' || name === '_exit' || name === '_Exit') {
                        detail = 'status=' + args[0].toInt32();
                    } else if (name === 'kill') {
                        detail = 'pid=' + args[0].toInt32() + ' sig=' + args[1].toInt32();
                    } else if (name === 'raise') {
                        detail = 'sig=' + args[0].toInt32();
                    }

                    var stack = CFG.stacks ? nativeStack(this.context) : '';
                    if (once('n:' + name + ':' + stack.slice(0, 200))) {
                        note('native ' + name + '()', detail);
                        if (CFG.stacks) console.log('    ' + stack);
                    } else {
                        kpt.fired[name] = (kpt.fired[name] || 0) + 1;
                    }

                    if (!CFG.block) return;

                    /*
                     * Blocking a native kill is cruder than blocking a Java
                     * one: there is no "return early" for abort(), so we
                     * redirect the instruction pointer past it by replacing
                     * the function outright. Doing that for abort() is
                     * usually safe because the caller does not expect it to
                     * return; doing it for exit() is NOT, because the caller
                     * genuinely intended to stop.
                     */
                    console.log('[kpt] BLOCK requested for native ' + name
                        + ' - use kpt.blockNative() to install the replacement, '
                        + 'and read the caveat in the source first.');
                }
            });
            kpt.hooked.push(name);
        } catch (e) {
            console.log('[!] could not hook ' + name + ': ' + e);
        }
    });
}

kpt.blockNative = function () {
    ['abort'].forEach(function (name) {
        var p = null;
        try { p = Module.findExportByName('libc.so', name); } catch (e) { return; }
        if (p === null) return;
        var cb = new NativeCallback(function () {
            console.log('[kpt] abort() neutralised - the process is now in a state its own '
                + 'author considered unrecoverable. Expect follow-on failures.');
        }, 'void', []);
        kpt._keep = kpt._keep || [];
        kpt._keep.push(cb);
        try {
            Interceptor.replace(p, cb);
            console.log('[*] abort() replaced with a no-op');
        } catch (e) {
            console.log('[!] could not replace abort: ' + e);
        }
    });
};

kpt.block = function () {
    CFG.block = true;
    console.log('[*] Java kill paths will be BLOCKED. Native abort() needs kpt.blockNative().');
    console.log('    Remember: a process that refused to die is not a bypassed control.');
};

kpt.allow = function () {
    CFG.block = false;
    console.log('[*] kill paths will be allowed to proceed (default)');
};

kpt.status = function () {
    console.log('');
    console.log('=== kill-path-tracer status ===');
    console.log('mode    : ' + (CFG.block ? 'BLOCKING' : 'observing'));
    console.log('hooked  : ' + kpt.hooked.join(', '));
    if (kpt.missing.length) console.log('absent  : ' + kpt.missing.join(', '));
    var keys = Object.keys(kpt.fired);
    if (keys.length === 0) {
        console.log('fired   : NOTHING.');
        console.log('  The process has not tried to kill itself. If it died anyway, the');
        console.log('  kill came from outside, or from a path this script does not cover');
        console.log('  (an uncaught exception, or an inline syscall). Check the exit record');
        console.log('  with ../scripts/bypass-triage.py --postmortem.');
    } else {
        console.log('fired   :');
        keys.forEach(function (k) { console.log('  ' + kpt.fired[k] + 'x  ' + k); });
    }
    console.log('');
};

(function bootstrap() {
    console.log('');
    console.log('=====================================================================');
    console.log(' kill-path-tracer.js - who decided to end this process, and where');
    console.log('=====================================================================');
    hookNative();
    hookJava();
    console.log('[*] ' + kpt.hooked.length + ' kill path(s) hooked, '
        + kpt.missing.length + ' absent.');
    console.log('[*] kpt.status() for a summary, kpt.block() to keep the process alive.');
    console.log('');
})();
