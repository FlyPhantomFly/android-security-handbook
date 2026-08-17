// scripts/fragment-trace.js
//
// PURPOSE
//     Watch every Fragment come into existence in a running app, and say WHERE
//     each one came from -- the app's own code, the platform's PreferenceActivity
//     reflective path, an AndroidX FragmentFactory, a state restore, or a raw
//     Class.forName. That last distinction is the whole of chapter 31: an
//     injected Fragment and a legitimate one look identical once they are on
//     screen, and differ completely in how they were constructed.
//
//     It also prints the two things a report needs and a screenshot cannot
//     give you: the exact class name that was asked for, and the Java stack
//     that asked for it.
//
// USAGE
//     # host -- spawn, so onCreate of the first Activity is not missed
//     frida -U -f com.pentest.ch31.victim -l scripts/fragment-trace.js
//
//     # host -- attach to something already running
//     frida -U -n "CH31 Victim" -l scripts/fragment-trace.js
//
//     # host -- turn every isValidFragment answer into `false`, to prove that
//     #         the gate is the only thing standing between the Intent and the
//     #         Fragment. Set BLOCK=true below, or from the REPL:
//     #             rpc.exports.block(true)
//
// WHAT IT HOOKS
//     android.preference.PreferenceActivity.isValidFragment       the gate
//     android.app.Fragment.instantiate(Context,String,Bundle)     platform loader
//     androidx.fragment.app.FragmentFactory.instantiate           AndroidX loader
//     androidx.fragment.app.FragmentFactory.loadFragmentClass     AndroidX loader
//     android.app.FragmentTransaction.replace / add               attachment
//     androidx.fragment.app.FragmentTransaction.replace / add     attachment
//     android.app.Fragment.setArguments                           the Bundle
//     androidx.fragment.app.Fragment.setArguments                 the Bundle
//     java.lang.ClassLoader.loadClass                             only when the
//                                                                 name looks
//                                                                 like a Fragment
//
//     Every AndroidX hook is optional. An app that ships only platform
//     Fragments will report "not present", which is information, not an error.
//
// EXECUTION STATUS
//     REVIEWED AND UNRUN, and that is stated here rather than implied away.
//     The API 35 AVD used for this chapter carries a frida-server binary its
//     own dynamic linker refuses:
//
//         CANNOT LINK EXECUTABLE "/data/local/tmp/frida-server":
//           empty/missing DT_HASH/DT_GNU_HASH ... (new hash type from the future?)
//
//     That is a frida-version problem, not a root problem -- `su 0 id` returns
//     uid 0 on the same device seconds later -- and 61-Fastboot recorded the
//     identical failure on the identical image. No physical device was attached
//     during this chapter's session. So: the script is syntax-checked with
//     `node --check`, every hooked signature was verified to exist by reading
//     the device's own framework.jar with dexdump and the API 35 android.jar
//     with javap, and it has NOT been executed against a live process.
//
//     An unrun script honestly marked is more useful than one implied to work.
//     If your frida-server does load, everything below is ordinary Java-layer
//     hooking with no native code and no version-specific offsets.
//
// AUTHORISED TESTING ONLY.

'use strict';

var BLOCK = false;          // force isValidFragment to return false
var SHOW_STACKS = true;     // print the Java stack for each instantiation
var STACK_DEPTH = 12;

function line(s) { console.log('[ch31] ' + s); }

function stack() {
    if (!SHOW_STACKS) return;
    try {
        var Log = Java.use('android.util.Log');
        var Exception = Java.use('java.lang.Exception');
        var t = Log.getStackTraceString(Exception.$new());
        var rows = t.split('\n').slice(1, 1 + STACK_DEPTH);
        for (var i = 0; i < rows.length; i++) {
            line('        ' + rows[i].trim());
        }
    } catch (e) {
        line('        (stack unavailable: ' + e + ')');
    }
}

function describeBundle(b) {
    if (b === null || b === undefined) return 'null';
    try {
        var keys = b.keySet().toArray();
        var out = [];
        for (var i = 0; i < keys.length; i++) {
            var k = '' + keys[i];
            var v;
            try { v = '' + b.get(k); } catch (e) { v = '<unreadable>'; }
            if (v.length > 80) v = v.substring(0, 80) + '...';
            out.push(k + '=' + v);
        }
        return '{' + out.join(', ') + '}';
    } catch (e) {
        return '<bundle: ' + e + '>';
    }
}

function tryUse(name) {
    try { return Java.use(name); } catch (e) { return null; }
}

Java.perform(function () {

    // ------------------------------------------------------------------ //
    // 1. The gate. This is the only thing between :android:show_fragment and
    //    a constructed Fragment on the platform path.
    // ------------------------------------------------------------------ //
    var PrefAct = tryUse('android.preference.PreferenceActivity');
    if (PrefAct === null) {
        line('android.preference.PreferenceActivity not loadable -- unexpected on any API level');
    } else {
        PrefAct.isValidFragment.implementation = function (name) {
            var real;
            try {
                real = this.isValidFragment(name);
            } catch (e) {
                // The BASE implementation THROWS at targetSdkVersion >= 19.
                // A subclass that forgot to override is not "returning false";
                // it is crashing, and that difference is a finding of its own.
                line('isValidFragment("' + name + '") on ' + this.getClass().getName()
                     + ' THREW: ' + e);
                throw e;
            }
            line('isValidFragment("' + name + '") on ' + this.getClass().getName()
                 + ' -> ' + real + (BLOCK ? '  [forced false]' : ''));
            if (real === true && !BLOCK) {
                line('        gate is OPEN for this name');
            }
            return BLOCK ? false : real;
        };
        line('hooked PreferenceActivity.isValidFragment');
    }

    // ------------------------------------------------------------------ //
    // 2. The platform loader. Note the ORDER inside it, measured from the
    //    device's framework.jar: isAssignableFrom BEFORE newInstance, so a
    //    non-Fragment class is refused without its constructor running.
    // ------------------------------------------------------------------ //
    var Frag = tryUse('android.app.Fragment');
    if (Frag !== null) {
        Frag.instantiate.overload(
            'android.content.Context', 'java.lang.String', 'android.os.Bundle'
        ).implementation = function (ctx, name, args) {
            line('PLATFORM Fragment.instantiate("' + name + '") args=' + describeBundle(args));
            stack();
            return this.instantiate(ctx, name, args);
        };
        Frag.setArguments.implementation = function (args) {
            line('platform setArguments on ' + this.getClass().getName()
                 + ' -> ' + describeBundle(args));
            return this.setArguments(args);
        };
        line('hooked android.app.Fragment.instantiate / setArguments');
    }

    // ------------------------------------------------------------------ //
    // 3. The AndroidX loader. Different order, measured with javap against
    //    fragment-1.3.6: the checkcast to Fragment sits AFTER
    //    Constructor.newInstance, so the constructor of an arbitrary class
    //    runs before the type is checked.
    // ------------------------------------------------------------------ //
    var Factory = tryUse('androidx.fragment.app.FragmentFactory');
    if (Factory === null) {
        line('androidx.fragment.app.FragmentFactory not present in this process');
    } else {
        Factory.instantiate.implementation = function (cl, name) {
            line('ANDROIDX FragmentFactory.instantiate("' + name + '")');
            stack();
            return this.instantiate(cl, name);
        };
        Factory.loadFragmentClass.implementation = function (cl, name) {
            line('ANDROIDX loadFragmentClass("' + name + '")  '
                 + '(no type check happens here -- the cast is erased)');
            return this.loadFragmentClass(cl, name);
        };
        line('hooked androidx FragmentFactory');
    }

    var AxFrag = tryUse('androidx.fragment.app.Fragment');
    if (AxFrag !== null) {
        AxFrag.setArguments.implementation = function (args) {
            line('androidx setArguments on ' + this.getClass().getName()
                 + ' -> ' + describeBundle(args));
            return this.setArguments(args);
        };
    }

    // ------------------------------------------------------------------ //
    // 4. Attachment. A Fragment that is constructed but never committed is
    //    not on screen; a report that stops at "instantiate was called" has
    //    not shown reachability.
    // ------------------------------------------------------------------ //
    function hookTx(clsName, label) {
        var Tx = tryUse(clsName);
        if (Tx === null) return;
        ['replace', 'add'].forEach(function (m) {
            if (Tx[m] === undefined) return;
            Tx[m].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var frag = null;
                    for (var i = 0; i < arguments.length; i++) {
                        var a = arguments[i];
                        if (a !== null && a !== undefined && a.getClass !== undefined) {
                            try {
                                var n = '' + a.getClass().getName();
                                if (n.toLowerCase().indexOf('fragment') >= 0 || i === 1) {
                                    frag = n;
                                }
                            } catch (e) { /* not a Java object we can name */ }
                        }
                    }
                    line(label + ' transaction.' + m + '(' + (frag || '?') + ')');
                    return ov.apply(this, arguments);
                };
            });
        });
        line('hooked ' + clsName);
    }
    hookTx('android.app.FragmentTransaction', 'PLATFORM');
    hookTx('androidx.fragment.app.FragmentTransaction', 'ANDROIDX');

    // ------------------------------------------------------------------ //
    // 5. The raw reflective route, for hosts that do not use either factory.
    //    Filtered, because loadClass fires thousands of times and an unfiltered
    //    hook makes the log useless.
    // ------------------------------------------------------------------ //
    var CL = tryUse('java.lang.ClassLoader');
    if (CL !== null) {
        CL.loadClass.overload('java.lang.String').implementation = function (n) {
            var s = '' + n;
            if (s.toLowerCase().indexOf('fragment') >= 0) {
                line('ClassLoader.loadClass("' + s + '")');
                stack();
            }
            return this.loadClass(n);
        };
        line('hooked ClassLoader.loadClass (filtered on "fragment")');
    }

    // ------------------------------------------------------------------ //
    // 6. The Intent that started it all. Printing the extras of every Activity
    //    launch is how you find the extra key a host uses when you do not have
    //    the source.
    // ------------------------------------------------------------------ //
    var Activity = tryUse('android.app.Activity');
    if (Activity !== null) {
        Activity.onCreate.overload('android.os.Bundle').implementation = function (b) {
            try {
                var i = this.getIntent();
                if (i !== null) {
                    var ex = i.getExtras();
                    if (ex !== null) {
                        line('START ' + this.getClass().getName()
                             + '  extras=' + describeBundle(ex));
                    } else {
                        line('START ' + this.getClass().getName() + '  (no extras)'
                             + (i.getData() !== null ? '  data=' + i.getData() : ''));
                    }
                    if (b !== null) {
                        line('        savedInstanceState present -- this launch is a RESTORE');
                    }
                }
            } catch (e) {
                line('START ' + this.getClass().getName() + ' (intent unreadable: ' + e + ')');
            }
            return this.onCreate(b);
        };
        line('hooked Activity.onCreate');
    }

    line('ready. Fragment traffic will be printed as it happens.');
});

rpc.exports = {
    // frida REPL:  rpc.exports.block(true)
    block: function (on) {
        BLOCK = !!on;
        return 'BLOCK=' + BLOCK;
    },
    stacks: function (on) {
        SHOW_STACKS = !!on;
        return 'SHOW_STACKS=' + SHOW_STACKS;
    }
};
