/*
 * 02-force-decision.js — change a client-side decision, and PROVE the app
 *                        honours it.
 *
 * WHAT IT DOES
 *   Forces a boolean-returning method to return a chosen value, while still
 *   calling the original so that both the real answer and the forced answer are
 *   logged. Then observes the consequence: which Activity the app navigates to,
 *   and which network calls it makes afterwards.
 *
 * WHY THE ORIGINAL IS STILL CALLED
 *   Because "I forced it true and the app unlocked" is a tool anecdote. "The
 *   real answer was false, I returned true, and the app resumed
 *   DashboardActivity and issued an authenticated request" is a finding. The
 *   evidence is the PAIR of values, and the observable consequence. A report
 *   built on the pair gets fixed; one built on the anecdote gets closed as
 *   "requires root".
 *
 * HOW TO RUN
 *   adb shell cmd package compile -m verify -f com.example.app
 *   adb shell am force-stop com.example.app
 *   frida -U -f com.example.app -l 02-force-decision.js --no-pause
 *
 *   AFTERWARDS, before writing anything up:
 *     adb shell cmd package compile --reset com.example.app
 *   and confirm the issue still reproduces in the app's normal state.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

/* ------------------------------------------------------------------ config */

var TARGETS = [
    // [class, method, signature (or null for all), forced return value]
    ['com.example.auth.PinValidator', 'check',      ['java.lang.String'], true],
    ['com.example.auth.SessionGuard', 'isExpired',  [],                   false],
    ['com.example.security.Integrity', 'isTampered', [],                  false]
];

var OBSERVE_NAVIGATION = true;
var OBSERVE_NETWORK    = true;

/* ------------------------------------------------------------------ helper */

var forced = 0;
var skipped = [];

function forceReturn(className, methodName, signature, value) {
    var Klass;
    try {
        Klass = Java.use(className);
    } catch (e) {
        skipped.push(className + ' (class not found)');
        return 0;
    }

    var member = Klass[methodName];
    if (member === undefined) {
        skipped.push(className + '.' + methodName + ' (no such method)');
        return 0;
    }

    var overloads = member.overloads || [member];
    var count = 0;

    overloads.forEach(function (ov) {
        var args, ret;
        try {
            args = ov.argumentTypes.map(function (t) { return t.className; });
            ret = ov.returnType.className;
        } catch (e) { return; }

        if (signature !== null) {
            if (args.length !== signature.length) return;
            for (var i = 0; i < args.length; i++) {
                if (args[i] !== signature[i]) return;
            }
        }

        ov.implementation = function () {
            var real;
            var threw = null;

            // Call the original FIRST. If it throws, that is itself evidence —
            // some checks signal failure by exception rather than by return
            // value, and forcing the return would hide that.
            try {
                real = ov.apply(this, arguments);
            } catch (e) {
                threw = e;
            }

            var argList = [].slice.call(arguments).map(function (a) {
                return a === null ? 'null' : String(a);
            }).join(', ');

            if (threw !== null) {
                console.log('[force] ' + className + '.' + methodName +
                            '(' + argList + ') THREW ' + threw +
                            '  -> returning ' + value + ' instead');
            } else {
                console.log('[force] ' + className + '.' + methodName +
                            '(' + argList + ') real=' + real +
                            '  -> forced=' + value);
            }
            return value;
        };

        count++;
        console.log('[+] forcing ' + className + '.' + methodName +
                    '(' + args.join(', ') + ') : ' + ret + ' = ' + value);
    });

    if (count === 0) {
        skipped.push(className + '.' + methodName + ' (no matching overload)');
    }
    return count;
}

/* ------------------------------------------------- consequence observation */

function observeNavigation() {
    try {
        var Activity = Java.use('android.app.Activity');

        Activity.onResume.implementation = function () {
            console.log('[nav] onResume  ' + this.$className);
            return this.onResume();
        };

        // startActivity shows INTENT, which is often more informative than the
        // resumed class name.
        var ContextWrapper = Java.use('android.content.ContextWrapper');
        ContextWrapper.startActivity.overload('android.content.Intent')
            .implementation = function (intent) {
                try {
                    console.log('[nav] startActivity ' + intent.getComponent());
                } catch (e) { console.log('[nav] startActivity <intent>'); }
                return this.startActivity(intent);
            };

        console.log('[+] navigation observation installed');
    } catch (e) {
        console.log('[.] navigation observation unavailable: ' + e.message);
    }
}

function observeNetwork() {
    // The point of observing network after a forced decision: if the app makes
    // an authenticated request that the SERVER accepts, the weakness is real.
    // If the server rejects it, the client-side check was defence in depth and
    // the finding is much weaker. That distinction belongs in the report.
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            console.log('[net] ' + this.toString());
            return this.openConnection();
        };
    } catch (e) { /* skip */ }

    try {
        var Builder = Java.use('okhttp3.Request$Builder');
        Builder.build.implementation = function () {
            var req = this.build();
            try {
                console.log('[net] okhttp ' + req.method() + ' ' + req.url());
                var auth = req.header('Authorization');
                if (auth !== null) {
                    console.log('[net]   Authorization: ' +
                                String(auth).substring(0, 80));
                }
            } catch (e) { /* older okhttp API */ }
            return req;
        };
        console.log('[+] okhttp observation installed');
    } catch (e) {
        console.log('[.] okhttp not present');
    }
}

/* ------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== 02-force-decision ===');
    console.log('');

    TARGETS.forEach(function (t) {
        forced += forceReturn(t[0], t[1], t[2], t[3]);
    });

    if (OBSERVE_NAVIGATION) observeNavigation();
    if (OBSERVE_NETWORK) observeNetwork();

    console.log('');
    console.log('[*] ' + forced + ' method(s) forced, ' + skipped.length + ' skipped:');
    skipped.forEach(function (s) { console.log('    - ' + s); });

    console.log('');
    console.log('[*] Exercise the app. What you are looking for is a line where');
    console.log('    real=false is followed by a [nav] into a privileged screen');
    console.log('    and a [net] request the server ACCEPTS. That triple is the');
    console.log('    finding. See ../README.md section 9.2.');
    console.log('');
});
