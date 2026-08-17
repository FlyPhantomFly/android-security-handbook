// scripts/bootprop-observer.js
//
// PURPOSE
//   Log every read of a boot-state / lock-state / verified-boot property that an
//   app performs, by ALL FOUR routes an app can use, with the calling stack.
//
//   It is an OBSERVER. It changes no return value and spoofs nothing. That is
//   deliberate, and it is the discipline chapter 61 section 7.2 argues for:
//   run this first and read the log, because a spoofing script tells you that
//   your hook installed, not that the app has a check. This repository measured
//   `objection android sslpinning disable` reporting three successful hooks
//   against an app with no network code at all -- a hook installing is not the
//   same as a control existing.
//
//   Set SPOOF below to a non-empty object only after you have observed.
//
// USAGE
//   frida -U -f com.example.target -l scripts/bootprop-observer.js
//   frida -U -n com.example.target -l scripts/bootprop-observer.js      # attach
//   frida -U -f com.example.target -l scripts/bootprop-observer.js --no-pause
//
//   Then exercise the app: launch it, log in, open the screen you suspect
//   performs an integrity check. Read the log bottom-up from the first hit.
//
// OUTPUT
//   [J-get]   android.os.SystemProperties.get      (the hidden API, via reflection)
//   [J-exec]  Runtime.exec / ProcessBuilder        (shelling out to `getprop`)
//   [N-get]   __system_property_get                (bionic, legacy native API)
//   [N-find]  __system_property_find               (bionic, modern native API)
//   [SUMMARY] printed on unload: every property seen, and how many times
//
// REQUIREMENTS
//   frida-server running on the device, matching your frida CLI version.
//   Root is needed to run frida-server, not to run this script.
//
// SEE ALSO
//   scripts/bootstate-audit.sh   -- the same questions asked of the device, not the app
//   ../37-RootDetection/         -- the wider family of checks this belongs to
//   ../50-HardwareBackedSecurity/-- what a non-forgeable answer looks like

'use strict';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Properties whose reads we care about. Substring match, so "ro.boot." catches
// the whole family including OEM additions we have not enumerated.
const WATCH = [
    'ro.boot.',                     // the whole bootloader-reported family
    'ro.bootloader',
    'ro.boot.verifiedbootstate',
    'ro.boot.flash.locked',
    'ro.boot.vbmeta',
    'ro.boot.veritymode',
    'ro.boot.slot_suffix',
    'ro.oem_unlock',
    'sys.oem_unlock_allowed',
    'ro.secure',
    'ro.debuggable',
    'ro.build.type',
    'ro.build.tags',
];

// Leave EMPTY to observe only. Populate ONLY after you have read the log and
// know which property the decision actually depends on.
//   const SPOOF = { 'ro.boot.verifiedbootstate': 'green',
//                   'ro.boot.flash.locked': '1' };
const SPOOF = {};

// Print a Java stack trace for each Java-side hit. Very noisy; worth it.
const STACKS = true;

// ---------------------------------------------------------------------------

const seen = {};          // property -> { count, values:Set, routes:Set }

function watched(name) {
    if (typeof name !== 'string') return false;
    for (let i = 0; i < WATCH.length; i++) {
        if (name.indexOf(WATCH[i]) !== -1) return true;
    }
    return false;
}

function record(route, name, value) {
    if (!seen[name]) seen[name] = { count: 0, values: {}, routes: {} };
    seen[name].count += 1;
    seen[name].values[String(value)] = true;
    seen[name].routes[route] = true;
}

function show(route, name, value) {
    record(route, name, value);
    console.log('[' + route + '] ' + name + ' -> ' + JSON.stringify(String(value)));
}

// ---------------------------------------------------------------------------
// Java side
// ---------------------------------------------------------------------------

function javaHooks() {
    let SystemProperties;
    try {
        SystemProperties = Java.use('android.os.SystemProperties');
    } catch (e) {
        console.log('[!] android.os.SystemProperties not loadable: ' + e);
        return;
    }

    const Exception = Java.use('java.lang.Exception');
    const Log = Java.use('android.util.Log');

    function stack() {
        try {
            return Log.getStackTraceString(Exception.$new());
        } catch (e) {
            return '(stack unavailable: ' + e + ')';
        }
    }

    ['get', 'getInt', 'getLong', 'getBoolean'].forEach(function (mname) {
        let m;
        try { m = SystemProperties[mname]; } catch (e) { return; }
        if (!m) return;

        m.overloads.forEach(function (ov) {
            ov.implementation = function () {
                const name = arguments.length > 0 ? arguments[0] : null;
                const ret = ov.apply(this, arguments);
                if (watched(name)) {
                    // SPOOF applies to the String overload only; the typed
                    // overloads parse their own result and are rarely used for
                    // these properties.
                    if (mname === 'get' && Object.keys(SPOOF).length &&
                        Object.prototype.hasOwnProperty.call(SPOOF, name)) {
                        console.log('[SPOOF] ' + name + ' ' +
                                    JSON.stringify(String(ret)) + ' -> ' +
                                    JSON.stringify(SPOOF[name]));
                        record('J-get', name, SPOOF[name]);
                        return SPOOF[name];
                    }
                    show('J-' + mname, name, ret);
                    if (STACKS) console.log(stack());
                }
                return ret;
            };
        });
    });

    // Route 2a -- Runtime.exec("getprop ...")
    try {
        const Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (String(cmd).indexOf('getprop') !== -1) {
                console.log('[J-exec] Runtime.exec: ' + cmd);
                if (STACKS) console.log(stack());
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmd) {
            const joined = Java.array('Ljava.lang.String;', cmd).join(' ');
            if (joined.indexOf('getprop') !== -1) {
                console.log('[J-exec] Runtime.exec: ' + joined);
                if (STACKS) console.log(stack());
            }
            return this.exec(cmd);
        };
    } catch (e) {
        console.log('[!] Runtime.exec hooks failed: ' + e);
    }

    // Route 2b -- ProcessBuilder, which is what modern code actually uses
    try {
        const ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function () {
            let cmd = '';
            try { cmd = this.command().toString(); } catch (e) { /* ignore */ }
            if (cmd.indexOf('getprop') !== -1) {
                console.log('[J-exec] ProcessBuilder: ' + cmd);
                if (STACKS) console.log(stack());
            }
            return this.start();
        };
    } catch (e) {
        console.log('[!] ProcessBuilder hook failed: ' + e);
    }

    console.log('[*] Java hooks installed');
}

// ---------------------------------------------------------------------------
// Native side -- bionic's property API
// ---------------------------------------------------------------------------

function nativeHooks() {
    // Route 3 -- the legacy API. Signature:
    //   int __system_property_get(const char *name, char *value);
    const spg = Module.findExportByName('libc.so', '__system_property_get');
    if (spg !== null) {
        Interceptor.attach(spg, {
            onEnter(args) {
                try { this.name = args[0].readCString(); } catch (e) { this.name = null; }
                this.out = args[1];
            },
            onLeave(retval) {
                if (!watched(this.name)) return;
                let v = '';
                try { v = this.out.readCString(); } catch (e) { v = '(unreadable)'; }
                if (Object.prototype.hasOwnProperty.call(SPOOF, this.name)) {
                    const fake = SPOOF[this.name];
                    try {
                        this.out.writeUtf8String(fake);
                        retval.replace(ptr(fake.length));
                        console.log('[SPOOF] ' + this.name + ' ' +
                                    JSON.stringify(v) + ' -> ' + JSON.stringify(fake));
                        record('N-get', this.name, fake);
                        return;
                    } catch (e) {
                        console.log('[!] native spoof failed: ' + e);
                    }
                }
                show('N-get', this.name, v);
            },
        });
        console.log('[*] hooked __system_property_get');
    } else {
        console.log('[!] __system_property_get not exported from libc.so -- ' +
                    'unusual. Native reads will not be visible.');
    }

    // Route 4 -- the modern API. A library trying to be quiet uses this,
    // because the value comes back through a callback rather than a buffer.
    //   const prop_info *__system_property_find(const char *name);
    const spf = Module.findExportByName('libc.so', '__system_property_find');
    if (spf !== null) {
        Interceptor.attach(spf, {
            onEnter(args) {
                try { this.name = args[0].readCString(); } catch (e) { this.name = null; }
            },
            onLeave(retval) {
                if (!watched(this.name)) return;
                show('N-find', this.name, retval.isNull() ? '(not found)' : '(found)');
            },
        });
        console.log('[*] hooked __system_property_find');
    }

    // Bonus: catch an app that opens /proc/cmdline or /proc/bootconfig directly.
    // Measured on API 35: both are Permission denied to an app, so a hit here is
    // an app trying something that will fail -- which is itself informative.
    const openat = Module.findExportByName('libc.so', 'openat');
    if (openat !== null) {
        Interceptor.attach(openat, {
            onEnter(args) {
                let p = null;
                try { p = args[1].readCString(); } catch (e) { return; }
                if (p && (p.indexOf('/proc/cmdline') !== -1 ||
                          p.indexOf('/proc/bootconfig') !== -1 ||
                          p.indexOf('/dev/block/by-name') !== -1)) {
                    console.log('[N-open] ' + p);
                }
            },
        });
        console.log('[*] hooked openat for /proc/cmdline, /proc/bootconfig');
    }
}

// ---------------------------------------------------------------------------

function summary() {
    const names = Object.keys(seen).sort();
    console.log('');
    console.log('=================== SUMMARY ===================');
    if (names.length === 0) {
        console.log('No watched property was read.');
        console.log('');
        console.log('That is a RESULT, not a failure -- but confirm it is a real');
        console.log('negative before reporting it. A dynamic session that captured');
        console.log('nothing looks identical to a well-behaved app doing nothing');
        console.log('wrong. Prove the hooks were live: read a property the app');
        console.log('certainly reads (ro.build.version.sdk is in WATCH via');
        console.log('ro.build.type only, so add it temporarily), or exercise a');
        console.log('screen you know performs a check.');
    } else {
        names.forEach(function (n) {
            const e = seen[n];
            console.log('  ' + n);
            console.log('      reads   ' + e.count);
            console.log('      routes  ' + Object.keys(e.routes).join(', '));
            console.log('      values  ' + Object.keys(e.values).join(' | '));
        });
        console.log('');
        console.log('Next: read the stack traces above to find WHERE the decision');
        console.log('is made. The finding is the decision, not the read.');
    }
    console.log('===============================================');
}

console.log('[*] boot-property observer loading ' +
            (Object.keys(SPOOF).length ? '(SPOOFING ACTIVE)' : '(observe only)'));

if (Java.available) {
    Java.perform(javaHooks);
} else {
    console.log('[!] no Java VM in this process -- native hooks only');
}
nativeHooks();

console.log('[*] installed. Exercise the app now. Ctrl-D / detach for a summary.');

Script.bindWeak(globalThis, summary);
rpc.exports = {
    summary: function () { summary(); return seen; },
    reset: function () { for (const k in seen) delete seen[k]; return true; },
};
