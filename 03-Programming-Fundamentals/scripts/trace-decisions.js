/*
 * trace-decisions.js — hook every method of a class, print arguments and return values, and
 * highlight the boolean returns, because a boolean return is almost always a security decision.
 *
 * WHY THIS SCRIPT EXISTS
 *   Chapter 03 section 3.6 makes a claim: every `if` in every language becomes a comparison and a
 *   branch, and every security check is ultimately one branch on one boolean. This script makes
 *   that claim operational. Point it at a class, use the app, and watch the decisions go past.
 *
 *   The moment you can SEE every boolean a security class returns, you can CHOOSE what it returns.
 *   That single step is the whole of 67-BypassingProtections, and the FORCE option below is it.
 *
 * WHAT IT DOES
 *   * Enumerates every declared method on the target class, including private and static ones.
 *   * Hooks every overload of each.
 *   * Prints  ClassName.method(args) -> return  with sensible formatting for arrays and byte[].
 *   * Marks boolean returns as [DECISION].
 *   * Optionally prints a Java stack trace, so you learn WHO is asking the question.
 *   * Optionally FORCES every boolean return to a chosen value.
 *   * Optionally hooks a whole package rather than one class, when you do not yet know the name.
 *
 * USAGE
 *   host $ frida -U -f com.target.app -l trace-decisions.js --no-pause
 *   host $ frida -U -n com.target.app -l trace-decisions.js
 *
 *   Edit CONFIG below, or drive it from the REPL:
 *       trace('com.target.app.security.RootChecker')
 *       tracePackage('com.target.app.security')
 *       force(true)          // every boolean return becomes true
 *       force(null)          // stop forcing
 *
 * FINDING THE CLASS NAME WHEN YOU DO NOT KNOW IT
 *       Java.enumerateLoadedClasses({ onMatch: function (n) {
 *           if (/Root|Secur|Integr|Tamper|Debug|Emulat|Frida/i.test(n)) console.log(n);
 *       }, onComplete: function () {} });
 *   Or use tracePackage() below and let the output tell you.
 *
 * SAFETY
 *   Read-only unless you switch FORCE on. Use only against apps you are authorised to test.
 *
 * Chapter 03 — Programming Fundamentals, sections 3.6, 3.17 and 7.3
 */

'use strict';

// -------------------------------------------------------------------------------------------------
// CONFIG
// -------------------------------------------------------------------------------------------------
var CONFIG = {
    // The class to trace. Change this, or call trace('...') from the REPL.
    targetClass: 'com.target.app.security.RootChecker',

    // Or trace an entire package. Leave empty to use targetClass only.
    targetPackage: '',

    // Print a Java stack trace for each call. Very noisy; extremely useful when you want to know
    // WHICH caller is asking the security question. Obfuscation hides the class name but not the
    // call structure, so the trace often names the interesting caller.
    printStack: false,

    // Force every boolean return value. null = do not force. true / false = force that value.
    // THIS MODIFIES THE APP'S BEHAVIOUR. Leave null while you are still observing.
    forceBoolean: null,

    // Skip these method names — they generate enormous noise and never carry a decision.
    skipMethods: ['toString', 'hashCode', 'equals', 'access$', 'getClass', 'wait', 'notify'],

    // Truncate long values at this many characters.
    maxValueLength: 220
};

// -------------------------------------------------------------------------------------------------
// Formatting helpers
// -------------------------------------------------------------------------------------------------

function truncate(s) {
    s = String(s);
    return s.length > CONFIG.maxValueLength
        ? s.substring(0, CONFIG.maxValueLength) + '...(' + s.length + ' chars)'
        : s;
}

/* Render a Java value in a way that is actually informative.
   The tricky cases are byte[] (show hex, it is usually a key or a MAC) and null. */
function describe(v) {
    if (v === null || v === undefined) return 'null';
    try {
        if (typeof v === 'boolean') return v ? 'true' : 'false';
        if (typeof v === 'number') return String(v);

        if (Array.isArray(v)) {
            // A Java byte[] arrives as a JS array of signed numbers. Hex is far more useful
            // than decimal here, because these are nearly always keys, digests or MACs.
            if (v.length > 0 && v.every(function (x) { return typeof x === 'number'; })) {
                var hex = v.slice(0, 48).map(function (b) {
                    return ('0' + (b & 0xff).toString(16)).slice(-2);
                }).join('');
                return 'byte[' + v.length + '] ' + hex + (v.length > 48 ? '...' : '');
            }
            return '[' + v.map(describe).join(', ') + ']';
        }

        return truncate(v.toString());
    } catch (e) {
        return '<' + e.message + '>';
    }
}

function javaStack() {
    try {
        var Log = Java.use('android.util.Log');
        var Exception = Java.use('java.lang.Exception');
        return Log.getStackTraceString(Exception.$new())
            .split('\n')
            .filter(function (l) {
                return !/frida|java\.lang\.reflect|com\.android\.internal\.os|dalvik\.system/i.test(l);
            })
            .slice(1, 9)
            .map(function (l) { return '        ' + l.trim(); })
            .join('\n');
    } catch (e) {
        return '        <stack unavailable>';
    }
}

function shouldSkip(name) {
    for (var i = 0; i < CONFIG.skipMethods.length; i++) {
        if (name.indexOf(CONFIG.skipMethods[i]) === 0) return true;
    }
    return false;
}

// -------------------------------------------------------------------------------------------------
// The tracer
// -------------------------------------------------------------------------------------------------

var stats = { classes: 0, methods: 0, calls: 0, decisions: 0, forced: 0 };

function traceClass(className) {
    var clazz;
    try {
        clazz = Java.use(className);
    } catch (e) {
        console.log('[!] class not found: ' + className);
        console.log('    It may not be loaded yet (try spawning rather than attaching), or it');
        console.log('    may live in a non-default ClassLoader. See 13-ART for the latter.');
        return false;
    }

    var methods;
    try {
        methods = clazz.class.getDeclaredMethods();
    } catch (e) {
        console.log('[!] could not enumerate methods on ' + className + ': ' + e);
        return false;
    }

    var hooked = 0;
    var shortName = className.split('.').pop();

    methods.forEach(function (m) {
        var name = m.getName();
        if (shouldSkip(name)) return;

        var overloads;
        try {
            overloads = clazz[name].overloads;
        } catch (e) {
            return;                         // synthetic, bridge, or otherwise inaccessible
        }

        overloads.forEach(function (ovl) {
            try {
                ovl.implementation = function () {
                    var args = Array.prototype.slice.call(arguments);

                    // Call the original FIRST, so we report what actually happened rather than
                    // what we predicted. If the original throws, we let it propagate — swallowing
                    // an exception here would change behaviour, which a tracer must never do.
                    var ret = ovl.apply(this, args);

                    stats.calls++;
                    var isDecision = (typeof ret === 'boolean');
                    if (isDecision) stats.decisions++;

                    var argStr = args.map(describe).join(', ');
                    var retStr = describe(ret);
                    var tag = isDecision ? '[DECISION]' : '[call]    ';

                    console.log(tag + ' ' + shortName + '.' + name + '(' + argStr + ') -> ' +
                                retStr);

                    if (CONFIG.printStack) {
                        console.log(javaStack());
                    }

                    // ---------------------------------------------------------------------------
                    // THE ONE LINE THAT TURNS OBSERVATION INTO A BYPASS.
                    //
                    // Once you can see every boolean a security class returns, you can choose
                    // what it returns. That is the entirety of client-side control bypass, and
                    // it is why a check evaluated inside a process the attacker controls is a
                    // usability feature rather than a security boundary.
                    // ---------------------------------------------------------------------------
                    if (isDecision && CONFIG.forceBoolean !== null) {
                        if (ret !== CONFIG.forceBoolean) {
                            stats.forced++;
                            console.log('           ^^ FORCED to ' + CONFIG.forceBoolean);
                        }
                        return CONFIG.forceBoolean;
                    }

                    return ret;
                };
                hooked++;
            } catch (e) {
                // Some overloads cannot be replaced (abstract, native without a body, etc.)
            }
        });
    });

    stats.classes++;
    stats.methods += hooked;
    console.log('[+] ' + className + ' — ' + hooked + ' method overloads hooked');
    return true;
}

/* Trace every loaded class whose name starts with a prefix. Use this when you do not yet know
   which class holds the check — the output tells you, and then you can narrow to one class. */
function tracePackage(prefix) {
    var found = [];
    Java.enumerateLoadedClassesSync().forEach(function (name) {
        if (name.indexOf(prefix) === 0 &&
            name.indexOf('$') === -1) {          // skip inner/anonymous classes on the first pass
            found.push(name);
        }
    });
    console.log('[*] ' + found.length + ' classes under ' + prefix);
    found.forEach(traceClass);
    return found;
}

/* Change the forcing behaviour at any time from the REPL. */
function force(value) {
    CONFIG.forceBoolean = value;
    console.log('[*] forceBoolean = ' + value);
}

function summary() {
    console.log('\n=========== trace summary ===========');
    console.log('  classes hooked   : ' + stats.classes);
    console.log('  method overloads : ' + stats.methods);
    console.log('  calls observed   : ' + stats.calls);
    console.log('  boolean decisions: ' + stats.decisions);
    console.log('  values forced    : ' + stats.forced);
    console.log('=====================================\n');
    if (stats.decisions > 0 && CONFIG.forceBoolean === null) {
        console.log('  You have observed ' + stats.decisions + ' decisions. To flip them:');
        console.log('      force(true)   or   force(false)');
    }
}

// Expose everything to the Frida REPL.
rpc.exports = {
    trace: traceClass,
    tracepackage: tracePackage,
    force: force,
    summary: summary
};
global.trace = traceClass;
global.tracePackage = tracePackage;
global.force = force;
global.summary = summary;

// -------------------------------------------------------------------------------------------------
// Go
// -------------------------------------------------------------------------------------------------
Java.perform(function () {
    console.log('\n==============================================================');
    console.log('  trace-decisions.js — chapter 03 section 7.3');
    console.log('==============================================================');
    console.log('  REPL commands: trace(cls)  tracePackage(pkg)  force(bool)  summary()');
    console.log('');

    if (CONFIG.targetPackage) {
        tracePackage(CONFIG.targetPackage);
    }
    if (CONFIG.targetClass) {
        traceClass(CONFIG.targetClass);
    }

    if (stats.classes === 0) {
        console.log('\n[i] Nothing hooked. Find candidate classes with:');
        console.log("      Java.enumerateLoadedClasses({ onMatch: function (n) {");
        console.log("        if (/Root|Secur|Integr|Tamper|Debug|Emulat|Frida|Auth/i.test(n))");
        console.log("          console.log(n);");
        console.log("      }, onComplete: function () {} });");
    }

    console.log('\n[*] Now use the app. Type summary() when you are done.\n');
});
