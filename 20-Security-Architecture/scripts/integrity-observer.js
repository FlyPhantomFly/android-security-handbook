// Frida — integrity-observer.js
// Run: frida -U -f com.target.app -l scripts/integrity-observer.js --no-pause
// Purpose: log every device-state / integrity signal the app reads, with stack traces.

'use strict';

function stack() {
    return Java.use('android.util.Log')
        .getStackTraceString(Java.use('java.lang.Exception').$new());
}

Java.perform(function () {
    console.log('[*] integrity-observer attached');

    // ---- 1. System properties, the most common check ----
    try {
        const SP = Java.use('android.os.SystemProperties');
        SP.get.overload('java.lang.String').implementation = function (k) {
            const v = this.get(k);
            console.log('[prop] ' + k + ' = ' + v);
            if (/verifiedboot|debuggable|secure|tags|fingerprint|veritymode|crypto/.test(k)) {
                console.log(stack());
            }
            return v;
        };
        SP.get.overload('java.lang.String', 'java.lang.String').implementation = function (k, d) {
            const v = this.get(k, d);
            console.log('[prop] ' + k + ' = ' + v + '  (default ' + d + ')');
            return v;
        };
    } catch (e) { console.log('[!] SystemProperties hook failed: ' + e); }

    // ---- 2. Build fields are read directly; log who reads them via Build.getRadioVersion etc.
    //         Instead we log the values once so you can compare with getprop output.
    try {
        const B = Java.use('android.os.Build');
        console.log('[build] FINGERPRINT = ' + B.FINGERPRINT.value);
        console.log('[build] TAGS        = ' + B.TAGS.value);
        console.log('[build] TYPE        = ' + B.TYPE.value);
        console.log('[build] MANUFACTURER= ' + B.MANUFACTURER.value);
    } catch (e) { console.log('[!] Build read failed: ' + e); }

    // ---- 3. File existence checks — the classic su/magisk hunt ----
    try {
        const F = Java.use('java.io.File');
        F.exists.implementation = function () {
            const p = this.getAbsolutePath();
            const r = this.exists();
            if (/su$|magisk|supersu|busybox|frida|xposed|\/system\/|\/sbin\//i.test(p)) {
                console.log('[file] exists("' + p + '") -> ' + r);
                console.log(stack());
            }
            return r;
        };
        F.canRead.implementation = function () {
            const p = this.getAbsolutePath();
            const r = this.canRead();
            if (/su$|magisk|\/proc\/self\/maps/i.test(p)) {
                console.log('[file] canRead("' + p + '") -> ' + r);
            }
            return r;
        };
    } catch (e) { console.log('[!] File hook failed: ' + e); }

    // ---- 4. Process execution — "which su", "getprop", "mount" ----
    try {
        const RT = Java.use('java.lang.Runtime');
        RT.exec.overload('java.lang.String').implementation = function (c) {
            console.log('[exec] ' + c);
            console.log(stack());
            return this.exec(c);
        };
        RT.exec.overload('[Ljava.lang.String;').implementation = function (c) {
            console.log('[exec] ' + c.join(' '));
            console.log(stack());
            return this.exec(c);
        };
    } catch (e) { console.log('[!] Runtime hook failed: ' + e); }

    // ---- 5. Play Integrity ----
    try {
        const IMF = Java.use('com.google.android.play.core.integrity.IntegrityManagerFactory');
        IMF.create.implementation = function (ctx) {
            console.log('[integrity] IntegrityManagerFactory.create() called');
            console.log(stack());
            return this.create(ctx);
        };
    } catch (e) { /* library not present — normal */ }

    try {
        const ITRB = Java.use('com.google.android.play.core.integrity.IntegrityTokenRequest$Builder');
        ITRB.setNonce.implementation = function (n) {
            console.log('[integrity] nonce = ' + n);
            console.log('[integrity] ^ trace this backwards: server-issued or locally generated?');
            console.log(stack());
            return this.setNonce(n);
        };
    } catch (e) { /* not present */ }

    // ---- 6. Package manager queries — signature and installer checks ----
    try {
        const PM = Java.use('android.app.ApplicationPackageManager');
        PM.getInstallerPackageName.implementation = function (p) {
            const r = this.getInstallerPackageName(p);
            console.log('[pm] getInstallerPackageName(' + p + ') -> ' + r);
            return r;
        };
    } catch (e) { console.log('[!] PM hook failed: ' + e); }

    // ---- 7. Native property reads, for apps that check from C ----
    try {
        const spg = Module.findExportByName('libc.so', '__system_property_get');
        if (spg !== null) {
            Interceptor.attach(spg, {
                onEnter: function (args) { this.key = args[0].readCString(); },
                onLeave: function (retval) {
                    console.log('[native prop] ' + this.key);
                }
            });
        }
    } catch (e) { console.log('[!] native prop hook failed: ' + e); }
});
