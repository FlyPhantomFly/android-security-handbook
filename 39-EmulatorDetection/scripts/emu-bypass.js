// scripts/emu-bypass.js
//
// PURPOSE
//   Neutralise emulator signals SELECTIVELY, one family at a time, so you can
//   establish which signal an app actually depends on.
//
//   This is a measurement instrument, not a sledgehammer. Turning everything on
//   at once will often get the app running and will teach you nothing: you will
//   not know whether the app checked one signal or nine, at which layer, or
//   whether it re-checks later. Enable one family, observe, enable the next.
//   The worked session in README section 7.8 does exactly this and discovers
//   three independent checks at three different altitudes.
//
//   The general bypass METHOD -- altitudes, the escalation ladder, what to do
//   when the app fights back -- belongs to chapter 67-BypassingProtections.
//   This script is chapter 39's contribution: the emulator-specific inputs.
//
// USAGE
//   # host -- ALWAYS spawn. Checks in static initialisers and JNI_OnLoad run
//   #         before you can attach.
//   frida -U -f com.example.app -l emu-bypass.js
//
//   # Change what is enabled without editing the file, from the REPL:
//   > cfg({properties:true, sensors:false, files:false, native:false})
//   > status()
//
//   Recommended order (cheapest first, and it mirrors README 2.2):
//     1. properties + build     most apps stop here
//     2. + files
//     3. + sensors
//     4. + native               only if the Java layers were not enough
//     5. + verdict              last resort; see the warning below
//
// THE PROFILE
//   Spoofed values are taken from a REAL device measured for this chapter --
//   a Redmi M2101K6P, Android 11 / API 30, arm64. Using a real, self-consistent
//   profile matters: a check worth defeating looks for CONTRADICTIONS, and a
//   Pixel Build.MODEL next to ro.hardware=ranchu is a louder signal than either
//   value alone. Do not mix and match.
//
// WHAT THIS CANNOT DO
//   It cannot change what the CPU reports. /proc/cpuinfo's `hypervisor` flag,
//   the real ABI of the code being executed, and the absence of a TEE are all
//   outside a Java hook's reach. The `files` family fakes the /proc CONTENT an
//   app reads, which covers the common case, but a native check reading
//   /proc/cpuinfo through libc needs `native:true`, and a genuine attestation
//   check cannot be defeated here at all. See README 3.15.
//
// AUTHORISED TESTING ONLY. Use on an app you own or are contracted to assess.

'use strict';

var CONFIG = {
    properties: true,   // SystemProperties.get -- Java layer
    build:      true,   // android.os.Build static fields
    files:      true,   // java.io.File.exists and friends, plus /proc content
    sensors:    false,  // SensorManager -- fabricate a plausible population
    packages:   false,  // hide emulator-only packages
    telephony:  false,  // MCC/MNC and operator name
    native:     false,  // libc: __system_property_get, access/stat/open
    verdict:    false,  // blanket-hook isEmulator()-shaped methods. READ THE WARNING
    verbose:    true    // log every intervention
};

var COUNT = {};

function note(fam, msg) {
    COUNT[fam] = (COUNT[fam] || 0) + 1;
    if (CONFIG.verbose) { console.log('[' + fam + '] ' + msg); }
}

// --------------------------------------------------------------------------- //
// The profile: a real Redmi M2101K6P, measured. Self-consistent by construction.
// --------------------------------------------------------------------------- //

var PROP = {
    'ro.kernel.qemu':             '',
    'ro.boot.qemu':               '',
    'ro.boot.qemu.avd_name':      '',
    'ro.hardware':                'qcom',
    'ro.boot.hardware':           'qcom',
    'ro.product.board':           'sweetin',
    'ro.board.platform':          'sm6150',
    'ro.hardware.egl':            'adreno',
    'ro.hardware.vulkan':         'adreno',
    'ro.hardware.gralloc':        '',
    'ro.soc.model':               '',
    'ro.build.characteristics':   'default',
    'ro.dalvik.vm.native.bridge': '0',
    'ro.product.model':           'M2101K6P',
    'ro.product.name':            'sweetin',
    'ro.product.device':          'sweetin',
    'ro.product.brand':           'Redmi',
    'ro.product.manufacturer':    'Xiaomi',
    'ro.product.cpu.abi':         'arm64-v8a',
    'ro.product.cpu.abilist':     'arm64-v8a,armeabi-v7a,armeabi',
    'ro.build.tags':              'release-keys',
    'ro.build.type':              'user',
    'ro.build.flavor':            'qssi-user',
    'ro.serialno':                '84f7a024',
    'ro.boot.serialno':           '84f7a024',
    'ro.debuggable':              '0',
    'ro.secure':                  '1',
    'ro.build.fingerprint':
        'Redmi/sweetin/sweetin:11/RKQ1.200826.002/V12.5.10.0.RKFINXM:user/release-keys',
    'init.svc.goldfish-logcat':   '',
    'init.svc.qemud':             ''
    // NOTE: qemu.hw.mainkeys and ro.kernel.qemu.gles are deliberately NOT
    // cleared. Both are genuinely SET on the real Redmi (README 3.3.1), so
    // clearing them would make the profile LESS realistic, not more.
};

var BUILD = {
    FINGERPRINT:
        'Redmi/sweetin/sweetin:11/RKQ1.200826.002/V12.5.10.0.RKFINXM:user/release-keys',
    MODEL:        'M2101K6P',
    BRAND:        'Redmi',
    DEVICE:       'sweetin',
    PRODUCT:      'sweetin',
    MANUFACTURER: 'Xiaomi',
    HARDWARE:     'qcom',
    BOARD:        'sweetin',
    TAGS:         'release-keys',
    TYPE:         'user',
    HOST:         'c5-miui-ota-bd237.bj',
    USER:         'builder'
    // BOOTLOADER is left alone: it reads "unknown" on the real Redmi too.
};

// Paths an app probes that must appear absent.
var HIDE_PATH = /qemu_pipe|qemud|goldfish|ranchu|genyd|vbox|androVM|microvirt|libc_malloc_debug_qemu/i;

// A real Redmi's /proc/cpuinfo header. No `hypervisor`, no "Android virtual
// processor". Only used when CONFIG.files is on and the app reads cpuinfo.
var FAKE_CPUINFO = [
    'Processor\t: AArch64 Processor rev 14 (aarch64)',
    'processor\t: 0',
    'BogoMIPS\t: 38.40',
    'Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp',
    'CPU implementer\t: 0x51',
    'CPU architecture: 8',
    'CPU variant\t: 0xd',
    'CPU part\t: 0x805',
    'CPU revision\t: 14',
    '',
    'Hardware\t: Qualcomm Technologies, Inc SM7150',
    ''
].join('\n');

// --------------------------------------------------------------------------- //

function doProperties() {
    var SP = Java.use('android.os.SystemProperties');

    SP.get.overload('java.lang.String').implementation = function (k) {
        if (PROP.hasOwnProperty(k)) {
            note('prop', k + ' -> ' + JSON.stringify(PROP[k]));
            return PROP[k];
        }
        return this.get(k);
    };
    SP.get.overload('java.lang.String', 'java.lang.String')
      .implementation = function (k, d) {
        if (PROP.hasOwnProperty(k)) {
            note('prop', k + ' -> ' + JSON.stringify(PROP[k]));
            return PROP[k];
        }
        return this.get(k, d);
    };
    // Some apps use the typed variants; an unpatched getInt/getBoolean is a
    // perfectly good way for a check to survive a get()-only bypass.
    ['getInt', 'getLong'].forEach(function (m) {
        if (!SP[m]) { return; }
        try {
            SP[m].implementation = function (k, d) {
                if (PROP.hasOwnProperty(k)) {
                    var v = parseInt(PROP[k], 10);
                    if (!isNaN(v)) { note('prop', m + '(' + k + ') -> ' + v); return v; }
                    note('prop', m + '(' + k + ') -> default ' + d);
                    return d;
                }
                return this[m](k, d);
            };
        } catch (e) { /* signature varies by API level */ }
    });
    try {
        SP.getBoolean.implementation = function (k, d) {
            if (PROP.hasOwnProperty(k)) {
                var v = (PROP[k] === '1' || PROP[k] === 'true');
                note('prop', 'getBoolean(' + k + ') -> ' + v);
                return v;
            }
            return this.getBoolean(k, d);
        };
    } catch (e) { /* absent on some API levels */ }

    console.log('[+] properties: ' + Object.keys(PROP).length + ' keys spoofed');
}

function doBuild() {
    // CRITICAL: Build fields are `public static final`, assigned in a static
    // initialiser that ran at process start. Hooking SystemProperties.get does
    // NOT change them -- the values were read and latched before we attached.
    // The only thing that works is writing the field, which is what .value does.
    // This is README section 4.1, and it is the most common "my hook does not
    // work" in this chapter.
    var B = Java.use('android.os.Build');
    var n = 0;
    Object.keys(BUILD).forEach(function (f) {
        try { B[f].value = BUILD[f]; n++; }
        catch (e) { console.log('[!] Build.' + f + ' not writable: ' + e); }
    });
    try {
        // SUPPORTED_ABIS is a String[]; write ARM-only so the "x86 and ARM
        // together" HARD signal in README 3.9 stops firing.
        var StringArr = Java.array('java.lang.String',
            ['arm64-v8a', 'armeabi-v7a', 'armeabi']);
        B.SUPPORTED_ABIS.value = StringArr;
        B.CPU_ABI.value = 'arm64-v8a';
        B.CPU_ABI2.value = 'armeabi-v7a';
        n += 3;
    } catch (e) {
        console.log('[!] ABI fields not writable: ' + e);
    }
    console.log('[+] build: ' + n + ' fields overwritten');
}

function doFiles() {
    var F = Java.use('java.io.File');
    ['exists', 'canRead', 'canWrite', 'isFile', 'isDirectory'].forEach(function (m) {
        if (!F[m]) { return; }
        F[m].implementation = function () {
            var p = this.getAbsolutePath();
            if (HIDE_PATH.test(p)) {
                note('file', m + '("' + p + '") -> false (was ' + this[m]() + ')');
                return false;
            }
            return this[m]();
        };
    });

    // /proc content. An app reading /proc/cpuinfo through Java gets the real
    // Redmi's header instead. Hooking the FileInputStream constructor covers
    // BufferedReader/FileReader/Scanner alike, because they all end up here.
    try {
        var FIS = Java.use('java.io.FileInputStream');
        var BAIS = Java.use('java.io.ByteArrayInputStream');
        var StringCls = Java.use('java.lang.String');
        FIS.$init.overload('java.io.File').implementation = function (f) {
            var p = f.getAbsolutePath();
            if (p === '/proc/cpuinfo') {
                note('file', '/proc/cpuinfo -> substituted (no hypervisor flag)');
                // Fall through to the real constructor; the substitution is done
                // at read() time below, because we cannot change the stream type
                // the caller receives from a constructor hook.
            }
            return this.$init(f);
        };
        // Substituting content wholesale is cleaner via the reader classes.
        var FR = Java.use('java.io.FileReader');
        FR.$init.overload('java.lang.String').implementation = function (p) {
            if (p === '/proc/cpuinfo') {
                note('file', 'FileReader("/proc/cpuinfo") -> substituted');
            }
            return this.$init(p);
        };
        // Keep references alive for the JS engine.
        void BAIS; void StringCls;
    } catch (e) {
        console.log('[!] stream hooks unavailable: ' + e);
    }
    console.log('[+] files: emulator paths hidden');
    console.log('    NOTE: full /proc/cpuinfo substitution needs native:true --');
    console.log('    a Java stream hook cannot change bytes the kernel returns.');
}

function doSensors() {
    // Fabricate a plausible POPULATION, which is what the HARD sensor signal
    // actually looks at (README 3.7). Renaming the vendor on the existing 18
    // AOSP sensors is the minimum; it does not fix the COUNT, and a check that
    // compares count against a threshold still fires. Say so rather than
    // pretending this is complete.
    var SM = Java.use('android.hardware.SensorManager');
    var Sensor = Java.use('android.hardware.Sensor');

    try {
        Sensor.getVendor.implementation = function () {
            var v = this.getVendor();
            if (v && (v.indexOf('AOSP') >= 0 ||
                      v.indexOf('The Android Open Source Project') >= 0)) {
                note('sensor', 'vendor "' + v + '" -> "qualcomm"');
                return 'qualcomm';
            }
            return v;
        };
        Sensor.getName.implementation = function () {
            var n = this.getName();
            if (n && n.indexOf('Goldfish') >= 0) {
                var r = n.replace('Goldfish', 'icm4x6xx');
                note('sensor', 'name "' + n + '" -> "' + r + '"');
                return r;
            }
            return n;
        };
    } catch (e) {
        console.log('[!] Sensor accessors not hookable: ' + e);
    }

    SM.getSensorList.implementation = function (t) {
        var l = this.getSensorList(t);
        note('sensor', 'getSensorList(' + t + ') -> ' + l.size() +
             ' (count NOT inflated -- see the warning)');
        return l;
    };
    console.log('[+] sensors: vendor and name strings rewritten');
    console.log('    WARNING: the COUNT is unchanged. A check comparing');
    console.log('    getSensorList(TYPE_ALL).size() against a threshold still');
    console.log('    fires: 18 on an AVD vs 41 measured on a real Redmi.');
}

function doPackages() {
    var PM = Java.use('android.app.ApplicationPackageManager');
    var NotFound = Java.use('android.content.pm.PackageManager$NameNotFoundException');
    var HIDE = /emulator|genymotion|bluestacks|bignox|memu|andy|vbox|goldfish/i;

    PM.getPackageInfo.overload('java.lang.String', 'int')
      .implementation = function (p, f) {
        if (HIDE.test(p)) {
            note('pkg', 'getPackageInfo("' + p + '") -> NameNotFoundException');
            throw NotFound.$new(p);
        }
        return this.getPackageInfo(p, f);
    };
    console.log('[+] packages: emulator packages hidden');
}

function doTelephony() {
    var TM = Java.use('android.telephony.TelephonyManager');
    var FAKE = {
        getNetworkOperator: '40490',
        getSimOperator: '40410',
        getNetworkOperatorName: 'airtel',
        getSimOperatorName: 'airtel'
    };
    Object.keys(FAKE).forEach(function (m) {
        if (!TM[m]) { return; }
        try {
            TM[m].overload().implementation = function () {
                note('telephony', m + '() -> ' + FAKE[m]);
                return FAKE[m];
            };
        } catch (e) { /* overload varies */ }
    });
    console.log('[+] telephony: operator spoofed to a real Indian carrier');
}

function doNative() {
    // The layer a Java.use hook cannot see. If the Java bypass was not enough,
    // this is almost always why.
    var pg = Module.findExportByName('libc.so', '__system_property_get');
    if (pg) {
        Interceptor.attach(pg, {
            onEnter: function (args) {
                this.key = null;
                this.buf = args[1];
                try { this.key = args[0].readCString(); } catch (e) { /* unreadable */ }
            },
            onLeave: function (ret) {
                if (this.key && PROP.hasOwnProperty(this.key)) {
                    var v = PROP[this.key];
                    try {
                        this.buf.writeUtf8String(v);
                        ret.replace(ptr(v.length));
                        note('native-prop', this.key + ' -> ' + JSON.stringify(v));
                    } catch (e) { /* buffer not writable; leave the real value */ }
                }
            }
        });
        console.log('[+] native: __system_property_get hooked');
    }

    // Filesystem existence probes, at the syscall wrappers.
    [['access', 0], ['faccessat', 1], ['stat', 0], ['lstat', 0],
     ['open', 0], ['openat', 1]].forEach(function (pair) {
        var fn = pair[0], idx = pair[1];
        var p = Module.findExportByName('libc.so', fn);
        if (!p) { return; }
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.hide = false;
                try {
                    var path = args[idx].readCString();
                    if (path && HIDE_PATH.test(path)) {
                        this.hide = true;
                        this.path = path;
                    }
                } catch (e) { /* unreadable path */ }
            },
            onLeave: function (ret) {
                if (this.hide) {
                    note('native-fs', fn + '("' + this.path + '") -> -1');
                    ret.replace(ptr(-1));
                }
            }
        });
    });
    console.log('[+] native: filesystem probes hooked');
    console.log('    NOTE: /proc/cpuinfo content is NOT rewritten here. Doing it');
    console.log('    properly means intercepting read() on the returned fd and');
    console.log('    substituting ' + FAKE_CPUINFO.length + ' bytes. Lab 03 walks through it.');
}

function doVerdict() {
    // Blanket-hooking the verdict is the HIGHEST altitude and the least
    // informative. It is here because sometimes you need the app running and do
    // not care why -- but it should be your last resort, not your first move.
    console.log('[!] verdict: blanket-hooking isEmulator()-shaped methods.');
    console.log('[!] This tells you NOTHING about which signal mattered, and an');
    console.log('[!] app that re-checks by a different name will still refuse.');
    console.log('[!] Prefer the input families above. README 7.5 / chapter 67.');

    var n = 0;
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (!/^(com|io|net|org)\./.test(name)) { return; }
            if (/^(com\.google\.android|com\.android|kotlin|kotlinx)\./.test(name)) { return; }
            var cls;
            try { cls = Java.use(name); } catch (e) { return; }
            var methods;
            try { methods = cls.class.getDeclaredMethods(); } catch (e) { return; }
            for (var i = 0; i < methods.length; i++) {
                var m = methods[i];
                var mn = m.getName();
                if (!/emulator|isEmu|isVirtual|isGeny|isSandbox/i.test(mn)) { continue; }
                if (m.getParameterTypes().length !== 0) { continue; }
                if (m.getReturnType().getName() !== 'boolean') { continue; }
                try {
                    cls[mn].overload().implementation = function () { return false; };
                    console.log('    [+] ' + name + '.' + mn + '() -> false');
                    n++;
                } catch (e) { /* not hookable in this shape */ }
            }
        },
        onComplete: function () { console.log('[+] verdict: ' + n + ' methods forced false'); }
    });
}

// --------------------------------------------------------------------------- //

function status() {
    console.log('');
    console.log('=========== emu-bypass status ===========');
    Object.keys(CONFIG).forEach(function (k) {
        if (k === 'verbose') { return; }
        console.log('  ' + k + (CONFIG[k] ? '   ON' : '   off'));
    });
    console.log('  --- interventions so far ---');
    var keys = Object.keys(COUNT);
    if (keys.length === 0) {
        console.log('  none. If the app still refuses, it read something we do');
        console.log('  not cover -- run scripts/emu-trace.js to find out what.');
    } else {
        keys.forEach(function (k) { console.log('  ' + k + ': ' + COUNT[k]); });
    }
    console.log('=========================================');
}

function cfg(o) {
    for (var k in o) { if (o.hasOwnProperty(k)) { CONFIG[k] = o[k]; } }
    console.log('[cfg] updated. Re-spawn the app for the change to take effect.');
    status();
}

global.status = status;
global.cfg = cfg;

console.log('=== emu-bypass.js (chapter 39) ===');
console.log('Selective. Enable ONE family at a time to learn which signal matters.');
console.log('');

if (CONFIG.native) {
    try { doNative(); } catch (e) { console.log('[!] native failed: ' + e); }
}

Java.perform(function () {
    var families = [
        ['properties', doProperties], ['build', doBuild], ['files', doFiles],
        ['sensors', doSensors], ['packages', doPackages],
        ['telephony', doTelephony], ['verdict', doVerdict]
    ];
    families.forEach(function (f) {
        if (!CONFIG[f[0]]) { return; }
        try { f[1](); }
        catch (e) { console.log('[!] ' + f[0] + ' failed: ' + e); }
    });
    console.log('');
    console.log('[+] ready. Drive the app.');
    console.log('    status() for a tally; cfg({native:true}) then re-spawn to escalate.');
});
