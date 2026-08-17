/*
 * dump-build-config.js — recover a running app's effective build configuration.
 *
 * PURPOSE
 *   Everything an Android build injects into an app — BuildConfig constants,
 *   manifest <meta-data>, string resources produced by resValue or by the
 *   Google Services plugin, the ApplicationInfo flags that record debuggable /
 *   allowBackup / testOnly, and the split APK set — is readable from inside the
 *   running process. Doing it at runtime rather than with `strings` catches
 *   values that were assembled from obfuscated pieces, and it proves what the
 *   app actually sees rather than what you inferred from the file.
 *
 * USAGE
 *   frida -U -f com.example.app -l dump-build-config.js --no-pause
 *   frida -U -n com.example.app -l dump-build-config.js        # already running
 *
 *   Optional: set FILTER below to a regex to restrict the resource dump, which
 *   is otherwise very large on real applications.
 *
 * OUTPUT
 *   Sections, in order:
 *     [1] ApplicationInfo    — the build's manifest decisions as the platform sees them
 *     [2] BuildConfig        — every BuildConfig class loaded, with all fields
 *     [3] meta-data          — application, activity, service and receiver meta-data
 *     [4] String resources   — resValue / google-services output, filtered
 *     [5] Signing            — the certificate the platform verified
 *     [6] Splits             — whether this install came from an AAB
 *
 * NOTES
 *   Run this AFTER exercising the app, so that lazily loaded library
 *   BuildConfig classes are present. Re-run it later and diff the output.
 *
 * SEE ALSO
 *   ../README.md sections 3.12, 5.3.1 and 7.4.
 */

'use strict';

// Restrict section [4] to resources whose name matches this. Set to /./ for all.
var FILTER = /key|token|secret|password|url|endpoint|api|host|client|project|firebase|sender|bucket/i;

function line(s) { console.log(s); }
function header(n, title) {
    line('');
    line('================================================================');
    line('  [' + n + '] ' + title);
    line('================================================================');
}

Java.perform(function () {

    var ActivityThread = Java.use('android.app.ActivityThread');
    var app = ActivityThread.currentApplication();
    if (app === null) {
        line('[!] No Application instance yet. Spawn with -f and --no-pause, or '
           + 'attach after the app has started.');
        return;
    }
    var ctx = app.getApplicationContext();
    var pkg = ctx.getPackageName();
    var pm  = ctx.getPackageManager();

    /* -------------------------------------------------------------- */
    /* [1] ApplicationInfo — the manifest decisions the build made      */
    /* -------------------------------------------------------------- */
    header(1, 'ApplicationInfo — build decisions as the platform sees them');

    var PM = Java.use('android.content.pm.PackageManager');
    var ai = pm.getApplicationInfo(pkg, PM.GET_META_DATA.value);

    // Constants from android.content.pm.ApplicationInfo
    var FLAGS = {
        FLAG_DEBUGGABLE:                  0x00000002,
        FLAG_HAS_CODE:                    0x00000004,
        FLAG_PERSISTENT:                  0x00000008,
        FLAG_SYSTEM:                      0x00000001,
        FLAG_ALLOW_BACKUP:                0x00008000,
        FLAG_TEST_ONLY:                   0x00000100,
        FLAG_ALLOW_CLEAR_USER_DATA:       0x00000040,
        FLAG_EXTERNAL_STORAGE:            0x00040000,
        FLAG_USES_CLEARTEXT_TRAFFIC:      0x08000000,
        FLAG_EXTRACT_NATIVE_LIBS:         0x10000000
    };

    line('  packageName        = ' + ai.packageName.value);
    line('  processName        = ' + ai.processName.value);
    line('  uid                = ' + ai.uid.value);
    line('  targetSdkVersion   = ' + ai.targetSdkVersion.value);
    try { line('  minSdkVersion      = ' + ai.minSdkVersion.value); } catch (e) {}
    line('  sourceDir          = ' + ai.sourceDir.value);
    line('  dataDir            = ' + ai.dataDir.value);
    line('  nativeLibraryDir   = ' + ai.nativeLibraryDir.value);

    var flags = ai.flags.value;
    line('  flags              = 0x' + (flags >>> 0).toString(16));
    Object.keys(FLAGS).forEach(function (name) {
        var set = (flags & FLAGS[name]) !== 0;
        var mark = '';
        if (set && name === 'FLAG_DEBUGGABLE')             mark = '   <-- run-as + JDWP for ANY user';
        if (set && name === 'FLAG_ALLOW_BACKUP')           mark = '   <-- adb backup / cloud backup';
        if (set && name === 'FLAG_TEST_ONLY')              mark = '   <-- IDE-installed artefact';
        if (set && name === 'FLAG_USES_CLEARTEXT_TRAFFIC') mark = '   <-- plaintext HTTP permitted';
        line('    ' + (set ? '[x] ' : '[ ] ') + name + mark);
    });

    try {
        var nsc = ai.networkSecurityConfigRes.value;
        line('  networkSecurityConfigRes = ' + (nsc !== 0 ? '0x' + nsc.toString(16)
                                                          : '(none declared)'));
    } catch (e) { }

    /* -------------------------------------------------------------- */
    /* [2] BuildConfig classes                                         */
    /* -------------------------------------------------------------- */
    header(2, 'BuildConfig classes (app and libraries)');

    var seen = {};
    var candidates = [pkg + '.BuildConfig'];

    Java.enumerateLoadedClassesSync().forEach(function (name) {
        if (name.indexOf('.BuildConfig') === name.length - '.BuildConfig'.length
            && name.length > '.BuildConfig'.length) {
            candidates.push(name);
        }
    });

    var dumped = 0;
    candidates.forEach(function (name) {
        if (seen[name]) return;
        seen[name] = true;
        var C;
        try { C = Java.use(name); } catch (e) { return; }
        var fields;
        try { fields = C.class.getDeclaredFields(); } catch (e) { return; }
        if (fields.length === 0) return;

        line('');
        line('  --- ' + name);
        fields.forEach(function (f) {
            try {
                f.setAccessible(true);
                var v = f.get(null);
                var t = f.getType().getSimpleName();
                var suspicious = /key|secret|token|password|credential|auth/i
                                    .test(f.getName());
                line('      ' + (suspicious ? '(!) ' : '    ')
                     + t + ' ' + f.getName() + ' = ' + v);
            } catch (e) { }
        });
        dumped++;
    });
    if (dumped === 0) {
        line('  No BuildConfig class is loaded.');
        line('  This does NOT mean the values are absent: javac inlines');
        line('  static final constants, after which R8 may delete the class.');
        line('  Search classes.dex for the VALUES instead. See README 6.2.');
    }

    /* -------------------------------------------------------------- */
    /* [3] Manifest meta-data                                          */
    /* -------------------------------------------------------------- */
    header(3, 'Manifest <meta-data> (application and components)');

    function dumpBundle(label, bundle) {
        if (bundle === null) return;
        var keys;
        try { keys = bundle.keySet().toArray(); } catch (e) { return; }
        if (keys.length === 0) return;
        line('');
        line('  --- ' + label);
        for (var i = 0; i < keys.length; i++) {
            var k = keys[i];
            var v;
            try { v = bundle.get(k); } catch (e) { v = '<unreadable>'; }
            line('      ' + k + ' = ' + v);
        }
    }

    dumpBundle('<application>', ai.metaData.value);

    var GET = PM.GET_ACTIVITIES.value | PM.GET_SERVICES.value
            | PM.GET_RECEIVERS.value  | PM.GET_PROVIDERS.value
            | PM.GET_META_DATA.value;
    try {
        var pi = pm.getPackageInfo(pkg, GET);
        ['activities', 'services', 'receivers', 'providers'].forEach(function (kind) {
            var arr = pi[kind].value;
            if (arr === null) return;
            for (var i = 0; i < arr.length; i++) {
                var comp = arr[i];
                var md = comp.metaData.value;
                if (md !== null) {
                    dumpBundle(kind + ': ' + comp.name.value, md);
                }
            }
        });
    } catch (e) {
        line('  (component meta-data enumeration failed: ' + e + ')');
    }

    /* -------------------------------------------------------------- */
    /* [4] String resources — resValue and google-services output      */
    /* -------------------------------------------------------------- */
    header(4, 'String resources matching the filter (resValue, google-services)');
    line('  filter = ' + FILTER);

    try {
        var res = ctx.getResources();
        var RClass = null;
        try { RClass = Java.use(pkg + '.R$string'); } catch (e) { }

        if (RClass !== null) {
            var rfields = RClass.class.getDeclaredFields();
            var hits = 0;
            for (var i = 0; i < rfields.length; i++) {
                var f = rfields[i];
                var rname = f.getName();
                if (!FILTER.test(rname)) continue;
                try {
                    f.setAccessible(true);
                    var id = f.getInt(null);
                    var value = res.getString(id);
                    line('      ' + rname + ' = ' + value);
                    hits++;
                } catch (e) { }
            }
            if (hits === 0) line('      (no matching string resources)');
        } else {
            // R$string is often shrunk away; brute-force by name instead.
            var probes = [
                'google_api_key', 'google_app_id', 'google_crash_reporting_api_key',
                'google_storage_bucket', 'firebase_database_url',
                'gcm_defaultSenderId', 'project_id', 'default_web_client_id',
                'api_base_url', 'api_key', 'base_url'
            ];
            var found = 0;
            probes.forEach(function (name) {
                try {
                    var id = res.getIdentifier(name, 'string', pkg);
                    if (id !== 0) {
                        line('      ' + name + ' = ' + res.getString(id));
                        found++;
                    }
                } catch (e) { }
            });
            if (found === 0) {
                line('      R$string not loaded and no well-known name matched.');
                line('      Use: aapt2 dump resources app.apk | grep -i key');
            }
        }
    } catch (e) {
        line('  (resource enumeration failed: ' + e + ')');
    }

    /* -------------------------------------------------------------- */
    /* [5] Signing certificate                                         */
    /* -------------------------------------------------------------- */
    header(5, 'Signing certificate as the platform verified it');

    try {
        var Build = Java.use('android.os.Build$VERSION');
        var sdk = Build.SDK_INT.value;
        var sigs = null;

        if (sdk >= 28) {
            var GET_SIGNING = 0x08000000;   // PackageManager.GET_SIGNING_CERTIFICATES
            var pinfo = pm.getPackageInfo(pkg, GET_SIGNING);
            var si = pinfo.signingInfo.value;
            if (si !== null) {
                sigs = si.hasMultipleSigners()
                     ? si.getApkContentsSigners()
                     : si.getSigningCertificateHistory();
                line('  hasMultipleSigners = ' + si.hasMultipleSigners());
            }
        } else {
            var GET_SIGNATURES = 0x00000040;
            sigs = pm.getPackageInfo(pkg, GET_SIGNATURES).signatures.value;
        }

        if (sigs !== null) {
            var MessageDigest = Java.use('java.security.MessageDigest');
            for (var i = 0; i < sigs.length; i++) {
                var bytes = sigs[i].toByteArray();
                ['SHA-256', 'SHA-1'].forEach(function (alg) {
                    var md = MessageDigest.getInstance(alg);
                    var digest = md.digest(bytes);
                    var hex = '';
                    for (var j = 0; j < digest.length; j++) {
                        var b = (digest[j] & 0xff).toString(16);
                        hex += (b.length === 1 ? '0' + b : b);
                    }
                    line('  signer[' + i + '] ' + alg + ' = ' + hex);
                });
            }
            line('');
            line('  Compare against `apksigner verify --print-certs` on the file.');
            line('  Under Play App Signing this is Google\'s signing of the app');
            line('  key, NOT the developer\'s upload key. See README 3.14.');
        }
    } catch (e) {
        line('  (signature read failed: ' + e + ')');
    }

    /* -------------------------------------------------------------- */
    /* [6] Split APK set                                               */
    /* -------------------------------------------------------------- */
    header(6, 'Split APKs — did this install come from an AAB?');

    try {
        var splits = ai.splitSourceDirs.value;
        if (splits === null || splits.length === 0) {
            line('  No splits. This is a single, self-contained APK.');
        } else {
            line('  ' + splits.length + ' split(s) installed. This came from an AAB,');
            line('  so analysing base.apk ALONE would have been incomplete:');
            for (var i = 0; i < splits.length; i++) {
                line('      ' + splits[i]);
            }
            line('');
            line('  Pull all of them: adb shell pm path ' + pkg);
        }
    } catch (e) {
        line('  (split enumeration failed: ' + e + ')');
    }

    line('');
    line('  Done. Exercise the app further and re-run to catch lazily loaded');
    line('  library BuildConfig classes and dynamic feature splits.');
    line('');
});
