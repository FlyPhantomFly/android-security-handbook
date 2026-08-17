/*
 * 01-observe-method.js — the simplest useful Frida script.
 *
 * WHAT IT DOES
 *   Lists every overload of one Java method, then hooks the one you chose and
 *   prints its arguments and return value on every call.
 *
 * WHY IT IS STRUCTURED THIS WAY
 *   The overload listing is not decoration. Assigning `.implementation` on a
 *   method group with more than one signature throws; assigning it on the WRONG
 *   single overload silently never fires. Listing first costs one line and
 *   removes the second most common cause of "my hook does not work"
 *   (../README.md section 7.4.3).
 *
 * HOW TO RUN
 *   adb shell cmd package compile -m verify -f com.example.app
 *   adb shell am force-stop com.example.app
 *   frida -U -f com.example.app -l 01-observe-method.js --no-pause
 *
 * ADAPTING IT
 *   Change TARGET_CLASS, TARGET_METHOD and TARGET_SIGNATURE below. Set
 *   TARGET_SIGNATURE to null to hook EVERY overload.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var TARGET_CLASS     = 'com.example.auth.PinValidator';
var TARGET_METHOD    = 'check';
var TARGET_SIGNATURE = ['java.lang.String'];   // null = hook every overload

Java.perform(function () {

    console.log('');
    console.log('=== 01-observe-method ===');

    /* ---- resolve the class, with a useful error if it is not there ------- */

    var Klass;
    try {
        Klass = Java.use(TARGET_CLASS);
    } catch (e) {
        console.log('[-] ' + TARGET_CLASS + ' not found in the default ClassLoader.');
        console.log('    That is failure mode 2 — see ../README.md section 7.4.2.');
        console.log('    Try scripts/class-enumerator.js:  cls.use("' + TARGET_CLASS + '")');
        return;
    }

    var member = Klass[TARGET_METHOD];
    if (member === undefined) {
        console.log('[-] ' + TARGET_CLASS + ' has no member named "' + TARGET_METHOD + '".');
        console.log('    Either the name is wrong, or R8 renamed/inlined it.');
        console.log('    Dump the class with scripts/class-enumerator.js:');
        console.log('      cls.dump("' + TARGET_CLASS + '")');
        return;
    }

    /* ---- ALWAYS list the overloads first --------------------------------- */

    var overloads = member.overloads || [member];
    console.log('[*] ' + TARGET_CLASS + '.' + TARGET_METHOD + ' has ' +
                overloads.length + ' overload(s):');

    overloads.forEach(function (ov, i) {
        var args, ret;
        try {
            args = ov.argumentTypes.map(function (t) { return t.className; });
            ret = ov.returnType.className;
        } catch (e) { return; }
        console.log('    [' + i + '] ' + ret + ' ' + TARGET_METHOD +
                    '(' + args.join(', ') + ')');
    });

    /* ---- render a Java value usefully ------------------------------------ */

    function fmt(v, typeName) {
        if (v === null || v === undefined) return 'null';
        try {
            // A byte[] printed with String() is "[object Object]" — useless.
            if (typeName === '[B') {
                var hex = '', ascii = '';
                var n = Math.min(v.length, 48);
                for (var i = 0; i < n; i++) {
                    var b = v[i] & 0xff;
                    hex += (b < 16 ? '0' : '') + b.toString(16);
                    ascii += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
                }
                return 'byte[' + v.length + '] ' + hex +
                       (v.length > n ? '…' : '') + ' |' + ascii + '|';
            }
            if (typeName === 'java.lang.String') {
                var s = String(v);
                return '"' + (s.length > 200 ? s.substring(0, 200) + '…' : s) + '"';
            }
            var out = String(v);
            return out.length > 200 ? out.substring(0, 200) + '…' : out;
        } catch (e) {
            return '<unrenderable ' + typeName + '>';
        }
    }

    /* ---- install ---------------------------------------------------------- */

    var installed = 0;

    overloads.forEach(function (ov) {
        var args, ret;
        try {
            args = ov.argumentTypes.map(function (t) { return t.className; });
            ret = ov.returnType.className;
        } catch (e) { return; }

        // Skip overloads that do not match the requested signature.
        if (TARGET_SIGNATURE !== null) {
            if (args.length !== TARGET_SIGNATURE.length) return;
            for (var i = 0; i < args.length; i++) {
                if (args[i] !== TARGET_SIGNATURE[i]) return;
            }
        }

        ov.implementation = function () {
            var rendered = [];
            for (var i = 0; i < arguments.length; i++) {
                rendered.push(fmt(arguments[i], args[i]));
            }
            console.log('[>] ' + TARGET_METHOD + '(' + rendered.join(', ') + ')');

            // `ov.apply(this, arguments)` calls the ORIGINAL implementation with
            // the exact argument list. Writing Klass[TARGET_METHOD](...) here
            // would re-enter this hook and overflow the stack.
            var result = ov.apply(this, arguments);

            if (ret === 'void') {
                console.log('[<] ' + TARGET_METHOD + ' (void)');
            } else {
                console.log('[<] ' + TARGET_METHOD + ' = ' + fmt(result, ret));
            }
            return result;
        };

        installed++;
        console.log('[+] hooked ' + TARGET_METHOD + '(' + args.join(', ') + ')');
    });

    if (installed === 0) {
        console.log('[-] No overload matched TARGET_SIGNATURE = ' +
                    JSON.stringify(TARGET_SIGNATURE));
        console.log('    Copy an exact signature from the list above.');
    } else {
        console.log('[*] ' + installed + ' hook(s) installed. Exercise the app.');
        console.log('    If nothing prints, read ../README.md section 7.4 BEFORE');
        console.log('    concluding the app detected you.');
    }
    console.log('');
});
