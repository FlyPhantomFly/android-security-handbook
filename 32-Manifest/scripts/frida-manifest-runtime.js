/*
 * frida-manifest-runtime.js — read the manifest as PackageManager ACTUALLY parsed it.
 *
 * WHAT IT DOES
 *   Runs inside the target process and asks the platform, through
 *   PackageManager.getPackageInfo(pkg, GET_ACTIVITIES | GET_SERVICES |
 *   GET_RECEIVERS | GET_PROVIDERS | GET_PERMISSIONS | GET_META_DATA |
 *   GET_INTENT_FILTERS), what components and permissions it believes this
 *   application declared, and what their effective `exported`, `permission`,
 *   `readPermission`, `writePermission`, `grantUriPermissions`, `launchMode`,
 *   `taskAffinity`, `directBootAware` and flag values are.
 *
 *   It also reports:
 *     - the resolved protectionLevel of every permission the app DEFINES
 *       (the value that decides whether "permission-protected" means anything)
 *     - ApplicationInfo flags: FLAG_DEBUGGABLE, FLAG_ALLOW_BACKUP, FLAG_TEST_ONLY,
 *       plus privateFlags where readable
 *     - the live component enabled-state, which the app can change at runtime
 *     - dynamically registered BroadcastReceivers, which do NOT appear in the
 *       manifest at all
 *     - <meta-data> keys the app actually reads
 *
 * WHY IT MATTERS
 *   This is the THIRD LEG of the three-way comparison in README section 3.2.
 *
 *     1. apktool          — an independent AXML decoder written in Java
 *     2. aapt2 dump xmltree — libandroidfw, the same code the platform uses
 *     3. THIS SCRIPT      — what PackageManagerService actually parsed and stored
 *
 *   AXML attributes are matched by resource ID, not by name, and booleans are
 *   "non-zero is true". A deliberately malformed manifest can therefore make an
 *   independent decoder print a benign document while the device installs a
 *   malicious one. Real malware families have used exactly this to evade
 *   automated store scanning. If (1) and (2) disagree, the APK is deliberately
 *   malformed and that is itself a finding. If either disagrees with (3), trust
 *   (3): the platform is authoritative, because the platform is what enforces.
 *
 *   `adb shell dumpsys package <pkg>` gives you almost the same view without
 *   Frida and should be your first move. Use this script when you want the
 *   view from INSIDE the app's own process (so you also see runtime changes),
 *   when dumpsys output is truncated or unavailable, or when you want to watch
 *   the surface change while the app runs.
 *
 * HOW TO RUN
 *   # host
 *   frida -U -f com.example.target -l frida-manifest-runtime.js
 *   frida -U -n com.example.target -l frida-manifest-runtime.js
 *
 *   Then, from the REPL:
 *     mf.all()                     full report for the current package
 *     mf.pkg("com.other.app")      full report for another visible package
 *     mf.components()              components only
 *     mf.permissions()             declared + requested permissions
 *     mf.flags()                   ApplicationInfo flags
 *     mf.enabled()                 live enabled-state of every component
 *     mf.watchReceivers()          log dynamically registered receivers
 *     mf.watchMetadata()           log <meta-data> reads
 *     mf.watchIntents()            log Intents arriving at components
 *     mf.export()                  emit a compact JSON blob for diffing
 *     mf.help()
 *
 *   To diff against the host-side view:
 *     # host
 *     aapt2 dump xmltree --file AndroidManifest.xml target.apk > aapt2.txt
 *     apktool d -f target.apk -o work/
 *     frida -U -n com.example.target -l frida-manifest-runtime.js -q \
 *           -e 'mf.export()' > runtime.json
 *
 * REQUIREMENTS
 *   frida-server running on the device and matching the host frida version.
 *   No root strictly required if the app is debuggable, but a rooted device or
 *   emulator is the normal setup. Android 5 through 15+ — every symbol lookup
 *   below is guarded, and the script degrades to a partial report rather than
 *   throwing when a field or class is missing on a given release.
 *
 *   NOTE on <queries>: from targetSdk 30 a package the app cannot "see" will
 *   raise NameNotFoundException even for getPackageInfo. That is a platform
 *   behaviour, not a script failure, and the script says so.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var mf = {

    /* ------------------------------------------------------------ constants */

    // android.content.pm.PackageManager
    GET_ACTIVITIES:      0x00000001,
    GET_RECEIVERS:       0x00000002,
    GET_SERVICES:        0x00000004,
    GET_PROVIDERS:       0x00000008,
    GET_INSTRUMENTATION: 0x00000010,
    GET_INTENT_FILTERS:  0x00000020,
    GET_META_DATA:       0x00000080,
    GET_PERMISSIONS:     0x00001000,
    GET_DISABLED:        0x00000200,   // MATCH_DISABLED_COMPONENTS on newer APIs
    MATCH_DISABLED:      0x00000200,

    // ApplicationInfo flags that matter
    FLAG_DEBUGGABLE:  1 << 1,
    FLAG_HAS_CODE:    1 << 2,
    FLAG_PERSISTENT:  1 << 3,
    FLAG_ALLOW_BACKUP: 1 << 14,
    FLAG_TEST_ONLY:   1 << 8,
    FLAG_ALLOW_CLEAR_USER_DATA: 1 << 6,
    FLAG_EXTERNAL_STORAGE: 1 << 18,
    FLAG_USES_CLEARTEXT_TRAFFIC: 1 << 27,

    // PermissionInfo.protection / protectionLevel
    PROTECTION_NORMAL:    0,
    PROTECTION_DANGEROUS: 1,
    PROTECTION_SIGNATURE: 2,
    PROTECTION_SIGNATURE_OR_SYSTEM: 3,
    PROTECTION_MASK_BASE: 0xf,

    _ctx: null,
    _pm: null,
    _pkg: null,

    /* ---------------------------------------------------------------- utils */

    _safe: function (fn, fallback) {
        try { return fn(); } catch (e) { return fallback; }
    },

    _use: function (name) {
        try { return Java.use(name); } catch (e) { return null; }
    },

    _log: function (s) { console.log(s); },

    _hdr: function (title) {
        console.log('');
        console.log('=== ' + title + ' ' + Array(Math.max(2, 62 - title.length)).join('='));
    },

    _field: function (obj, name) {
        // Java field access through Frida is version-sensitive. Try the direct
        // property first, then the ".value" accessor, then give up quietly.
        try {
            var v = obj[name];
            if (v === undefined || v === null) return null;
            if (typeof v === 'object' && 'value' in v) return v.value;
            return v;
        } catch (e) {
            try { return obj[name].value; } catch (e2) { return null; }
        }
    },

    _bool: function (v) {
        if (v === null || v === undefined) return '?';
        return v ? 'true' : 'false';
    },

    /* ----------------------------------------------------------------- init */

    init: function () {
        var self = this;
        var ok = false;
        Java.perform(function () {
            var ActivityThread = self._use('android.app.ActivityThread');
            if (ActivityThread === null) {
                self._log('[-] android.app.ActivityThread not found — is this an app process?');
                return;
            }
            var app = self._safe(function () {
                return ActivityThread.currentApplication();
            }, null);

            if (app === null) {
                self._log('[!] currentApplication() returned null.');
                self._log('    The Application object is not created yet. If you spawned the');
                self._log('    process with -f, wait a moment and call mf.init() again, or');
                self._log('    attach with -n instead of spawning.');
                return;
            }

            self._ctx = self._safe(function () { return app.getApplicationContext(); }, app);
            self._pm = self._safe(function () { return self._ctx.getPackageManager(); }, null);
            self._pkg = self._safe(function () { return self._ctx.getPackageName(); }, null);

            if (self._pm === null || self._pkg === null) {
                self._log('[-] Could not obtain PackageManager / package name.');
                return;
            }
            self._log('[+] context   = ' + self._ctx);
            self._log('[+] package   = ' + self._pkg);
            ok = true;
        });
        return ok;
    },

    _info: function (pkg, flags) {
        var self = this;
        var out = null;
        var err = null;
        Java.perform(function () {
            try {
                out = self._pm.getPackageInfo(pkg, flags);
            } catch (e) {
                err = '' + e;
            }
        });
        if (out === null && err !== null) {
            this._log('[-] getPackageInfo("' + pkg + '") failed: ' + err);
            if (err.indexOf('NameNotFound') !== -1) {
                this._log('    From targetSdk 30 a package this app cannot "see" is reported');
                this._log('    as not found. That is package-visibility filtering, not an');
                this._log('    error. The app would need a <queries> entry or');
                this._log('    QUERY_ALL_PACKAGES to observe it.');
            }
        }
        return out;
    },

    /* ------------------------------------------------------------ top level */

    all: function (pkg) {
        this.flags(pkg);
        this.components(pkg);
        this.permissions(pkg);
        this.instrumentation(pkg);
        this.enabled(pkg);
        this._hdr('REMINDER');
        this._log('This is the PLATFORM view. Compare it against:');
        this._log('  aapt2 dump xmltree --file AndroidManifest.xml target.apk');
        this._log('  apktool d -f target.apk -o work/ && cat work/AndroidManifest.xml');
        this._log('Any disagreement between the two host tools is itself a finding.');
        this._log('If either disagrees with THIS output, trust this output.');
        this._log('');
        this._log('And remember: an exported component is not a vulnerability until you');
        this._log('have reached it from an UNPRIVILEGED APP. adb shell is UID 2000 and');
        this._log('holds privileges an ordinary app does not.');
    },

    pkg: function (name) { this.all(name); },

    /* ---------------------------------------------------------------- flags */

    flags: function (pkg) {
        var self = this;
        pkg = pkg || this._pkg;
        this._hdr('ApplicationInfo — ' + pkg);

        Java.perform(function () {
            var pi = self._info(pkg, self.GET_META_DATA);
            if (pi === null) return;
            var ai = self._safe(function () { return pi.applicationInfo.value; }, null);
            if (ai === null) {
                self._log('[-] applicationInfo unavailable.');
                return;
            }

            var f = self._safe(function () { return ai.flags.value; }, 0);
            var rows = [
                ['debuggable          ', (f & self.FLAG_DEBUGGABLE) !== 0,
                 'run-as + JDWP + Frida without root. CRITICAL in a release build.'],
                ['allowBackup         ', (f & self.FLAG_ALLOW_BACKUP) !== 0,
                 'private data may leave the device via Auto Backup / adb backup.'],
                ['testOnly            ', (f & self.FLAG_TEST_ONLY) !== 0,
                 'a debug artefact reached this build.'],
                ['hasCode             ', (f & self.FLAG_HAS_CODE) !== 0, ''],
                ['persistent          ', (f & self.FLAG_PERSISTENT) !== 0, ''],
                ['allowClearUserData  ', (f & self.FLAG_ALLOW_CLEAR_USER_DATA) !== 0, ''],
                ['usesCleartextTraffic', (f & self.FLAG_USES_CLEARTEXT_TRAFFIC) !== 0,
                 'plaintext HTTP permitted (superseded by networkSecurityConfig).']
            ];
            self._log('  raw flags = 0x' + (f >>> 0).toString(16));
            rows.forEach(function (r) {
                self._log('  ' + r[0] + ' : ' + (r[1] ? 'TRUE ' : 'false') +
                          (r[1] && r[2] ? '   <-- ' + r[2] : ''));
            });

            [['targetSdkVersion', 'targetSdkVersion'],
             ['minSdkVersion', 'minSdkVersion'],
             ['processName', 'processName'],
             ['taskAffinity', 'taskAffinity'],
             ['className', 'className'],
             ['appComponentFactory', 'appComponentFactory'],
             ['backupAgentName', 'backupAgentName'],
             ['networkSecurityConfigRes', 'networkSecurityConfigRes'],
             ['dataDir', 'dataDir'],
             ['sourceDir', 'sourceDir'],
             ['nativeLibraryDir', 'nativeLibraryDir'],
             ['uid', 'uid']].forEach(function (p) {
                var v = self._safe(function () { return ai[p[1]].value; }, undefined);
                if (v !== undefined && v !== null) {
                    self._log('  ' + (p[0] + '                        ').slice(0, 20) +
                              ' : ' + v);
                }
            });

            // sharedUserId lives on PackageInfo.
            var suid = self._safe(function () { return pi.sharedUserId.value; }, null);
            if (suid) {
                self._log('  sharedUserId         : ' + suid +
                          '   <-- the sandbox does not exist between members of this group');
            }
            var vc = self._safe(function () { return pi.versionCode.value; }, null);
            var vn = self._safe(function () { return pi.versionName.value; }, null);
            self._log('  versionCode/Name     : ' + vc + ' / ' + vn);

            // meta-data on the application
            var md = self._safe(function () { return ai.metaData.value; }, null);
            if (md !== null) {
                self._hdr('<application> meta-data (as the platform stored it)');
                self._dumpBundle(md, '  ');
            }
        });
    },

    _dumpBundle: function (bundle, indent) {
        var self = this;
        try {
            var keys = bundle.keySet().toArray();
            if (keys.length === 0) { self._log(indent + '(none)'); return; }
            for (var i = 0; i < keys.length; i++) {
                var k = '' + keys[i];
                var v = self._safe(function () { return '' + bundle.get(k); }, '<unreadable>');
                var mark = '';
                if (/secret|password|token|api[_.-]?key|apikey|private/i.test(k)) {
                    mark = '   <-- CANDIDATE credential — validate before reporting';
                }
                self._log(indent + k + ' = ' + v + mark);
            }
        } catch (e) {
            self._log(indent + '<bundle unreadable: ' + e + '>');
        }
    },

    /* ----------------------------------------------------------- components */

    components: function (pkg) {
        var self = this;
        pkg = pkg || this._pkg;

        var flags = this.GET_ACTIVITIES | this.GET_SERVICES | this.GET_RECEIVERS |
                    this.GET_PROVIDERS | this.GET_META_DATA;
        // Ask for disabled components too, so a runtime-disabled component is
        // still visible. Some releases reject unknown bits; fall back if so.
        var pi = null;
        Java.perform(function () {
            pi = self._info(pkg, flags | self.MATCH_DISABLED);
            if (pi === null) pi = self._info(pkg, flags);
        });
        if (pi === null) return;

        Java.perform(function () {
            self._hdr('ACTIVITIES — ' + pkg);
            self._dumpArray(pi, 'activities', function (a) { self._activity(a); });

            self._hdr('SERVICES — ' + pkg);
            self._dumpArray(pi, 'services', function (a) { self._service(a); });

            self._hdr('RECEIVERS — ' + pkg);
            self._dumpArray(pi, 'receivers', function (a) { self._activity(a); });

            self._hdr('PROVIDERS — ' + pkg);
            self._dumpArray(pi, 'providers', function (a) { self._provider(a); });
        });
    },

    _dumpArray: function (pi, field, fn) {
        var self = this;
        var arr = self._safe(function () { return pi[field].value; }, null);
        if (arr === null) {
            self._log('  (none declared, or this GET_ flag was not honoured)');
            return;
        }
        var n = 0;
        try { n = arr.length; } catch (e) { n = 0; }
        if (n === 0) { self._log('  (none)'); return; }
        for (var i = 0; i < n; i++) {
            try { fn(arr[i]); } catch (e) { self._log('  <entry ' + i + ': ' + e + '>'); }
        }
    },

    _common: function (info) {
        var self = this;
        var name = self._safe(function () { return info.name.value; }, '?');
        var exported = self._safe(function () { return info.exported.value; }, null);
        var perm = self._safe(function () { return info.permission.value; }, null);
        var enabled = self._safe(function () { return info.enabled.value; }, null);
        var proc = self._safe(function () { return info.processName.value; }, null);
        var dba = self._safe(function () { return info.directBootAware.value; }, null);

        var mark = '';
        if (exported === true && !perm) {
            mark = '   <-- EXPORTED, NO PERMISSION';
        } else if (exported === true && perm) {
            mark = '   <-- EXPORTED, permission=' + perm +
                   '  (resolve its protectionLevel — mf.perm("' + perm + '"))';
        }

        self._log('  ' + name + mark);
        self._log('      exported=' + self._bool(exported) +
                  '  enabled=' + self._bool(enabled) +
                  '  directBootAware=' + self._bool(dba) +
                  (proc ? '  process=' + proc : ''));
        if (perm) self._log('      permission=' + perm);

        var md = self._safe(function () { return info.metaData.value; }, null);
        if (md !== null) {
            self._log('      meta-data:');
            self._dumpBundle(md, '        ');
        }
        return { name: name, exported: exported, permission: perm };
    },

    _activity: function (info) {
        var self = this;
        var base = self._common(info);
        var lm = self._safe(function () { return info.launchMode.value; }, null);
        var aff = self._safe(function () { return info.taskAffinity.value; }, null);
        var f = self._safe(function () { return info.flags.value; }, null);
        var target = self._safe(function () { return info.targetActivity.value; }, null);

        var lmNames = ['standard', 'singleTop', 'singleTask', 'singleInstance',
                       'singleInstancePerTask'];
        var lmName = (lm !== null && lm >= 0 && lm < lmNames.length) ? lmNames[lm] : lm;

        var line = '      launchMode=' + lmName + '  taskAffinity=' +
                   (aff === null ? '?' : (aff === '' ? '"" (none — hardened)' : aff));
        if (f !== null) line += '  flags=0x' + (f >>> 0).toString(16);
        self._log(line);

        if (target) {
            self._log('      targetActivity=' + target +
                      '   <-- this is an activity-alias: its exported/permission are its OWN');
        }
        if ((lmName === 'singleTask' || lmName === 'singleInstance') && aff && aff !== '') {
            self._log('      <-- singleTask/singleInstance with a non-empty taskAffinity:');
            self._log('          this is the task-hijacking (StrandHogg family) shape.');
        }
    },

    _service: function (info) {
        var self = this;
        self._common(info);
        var f = self._safe(function () { return info.flags.value; }, null);
        var fst = self._safe(function () {
            return info.getForegroundServiceType();
        }, null);
        var bits = [];
        if (f !== null) {
            // ServiceInfo.FLAG_ISOLATED_PROCESS = 0x0002,
            // FLAG_EXTERNAL_SERVICE = 0x0004, FLAG_STOP_WITH_TASK = 0x0001
            if (f & 0x0001) bits.push('stopWithTask');
            if (f & 0x0002) bits.push('isolatedProcess  <-- POSITIVE: sandboxed parser');
            if (f & 0x0004) bits.push('externalService');
            if (f & 0x0008) bits.push('singleUser');
        }
        if (bits.length) self._log('      serviceFlags: ' + bits.join(', '));
        if (fst !== null && fst !== 0) {
            self._log('      foregroundServiceType=0x' + (fst >>> 0).toString(16) +
                      '   <-- a declaration of background capability; audit it against behaviour');
        }
    },

    _provider: function (info) {
        var self = this;
        self._common(info);
        var auth = self._safe(function () { return info.authority.value; }, null);
        var rp = self._safe(function () { return info.readPermission.value; }, null);
        var wp = self._safe(function () { return info.writePermission.value; }, null);
        var gup = self._safe(function () { return info.grantUriPermissions.value; }, null);
        var mp = self._safe(function () { return info.multiprocess.value; }, null);
        var io = self._safe(function () { return info.initOrder.value; }, null);
        var forceUri = self._safe(function () { return info.forceUriPermissions.value; }, null);

        self._log('      authority=' + auth);
        self._log('      readPermission=' + (rp || 'NONE') +
                  '  writePermission=' + (wp || 'NONE') +
                  '  grantUriPermissions=' + self._bool(gup));
        if (io !== null) self._log('      initOrder=' + io +
                                   '  (providers run BEFORE Application.onCreate)');
        if (mp !== null && mp) self._log('      multiprocess=true');
        if (forceUri) self._log('      forceUriPermissions=true   <-- POSITIVE');

        var exported = self._safe(function () { return info.exported.value; }, null);
        if (exported === true) {
            if (!rp) self._log('      <-- EXPORTED with NO readPermission: query() open to all apps');
            if (!wp) self._log('      <-- EXPORTED with NO writePermission: insert/update/delete open');
        }

        // <path-permission> and <grant-uri-permission> children.
        var pps = self._safe(function () { return info.pathPermissions.value; }, null);
        if (pps !== null) {
            var n = 0;
            try { n = pps.length; } catch (e) { n = 0; }
            for (var i = 0; i < n; i++) {
                var pp = pps[i];
                self._log('      path-permission[' + i + '] ' + pp +
                          '  read=' + self._safe(function () { return pp.getReadPermission(); }, '?') +
                          '  write=' + self._safe(function () { return pp.getWritePermission(); }, '?'));
            }
            if (n > 0) {
                self._log('      <-- path-permission is an OR, not an AND. A caller satisfying');
                self._log('          EITHER the component permission OR a matching path');
                self._log('          permission is allowed, so these usually WIDEN access.');
            }
        }
        var gups = self._safe(function () { return info.uriPermissionPatterns.value; }, null);
        if (gups !== null) {
            var m = 0;
            try { m = gups.length; } catch (e) { m = 0; }
            for (var j = 0; j < m; j++) {
                self._log('      grant-uri-permission[' + j + '] ' + gups[j]);
            }
        }
        self._log('      NOTE: call() is not described here at all. Decompile the provider');
        self._log('            and enumerate its method strings — it is an untyped RPC.');
    },

    /* ---------------------------------------------------------- permissions */

    permissions: function (pkg) {
        var self = this;
        pkg = pkg || this._pkg;
        this._hdr('PERMISSIONS — ' + pkg);

        Java.perform(function () {
            var pi = self._info(pkg, self.GET_PERMISSIONS);
            if (pi === null) return;

            // Permissions this app DEFINES — their protectionLevel decides whether
            // "permission-protected" means anything at all.
            var defined = self._safe(function () { return pi.permissions.value; }, null);
            self._log('  -- declared by this app --');
            if (defined === null) {
                self._log('     (none)');
            } else {
                var n = 0;
                try { n = defined.length; } catch (e) { n = 0; }
                if (n === 0) self._log('     (none)');
                for (var i = 0; i < n; i++) {
                    var p = defined[i];
                    var nm = self._safe(function () { return p.name.value; }, '?');
                    self._log('     ' + nm + '   ' + self._describeProtection(p));
                }
            }

            // Permissions this app REQUESTS, with their current grant state.
            var req = self._safe(function () { return pi.requestedPermissions.value; }, null);
            var fl = self._safe(function () { return pi.requestedPermissionsFlags.value; }, null);
            self._log('');
            self._log('  -- requested by this app --');
            if (req === null) {
                self._log('     (none)');
            } else {
                var m = 0;
                try { m = req.length; } catch (e) { m = 0; }
                for (var j = 0; j < m; j++) {
                    var granted = '?';
                    if (fl !== null) {
                        try {
                            // PackageInfo.REQUESTED_PERMISSION_GRANTED = 0x2
                            granted = (fl[j] & 0x2) ? 'GRANTED' : 'not granted';
                        } catch (e) { granted = '?'; }
                    }
                    self._log('     ' + req[j] + '  [' + granted + ']');
                }
            }
        });
    },

    _describeProtection: function (permInfo) {
        var self = this;
        var lvl = self._safe(function () { return permInfo.protectionLevel.value; }, null);
        if (lvl === null) {
            lvl = self._safe(function () { return permInfo.getProtection(); }, null);
        }
        if (lvl === null) return '(protectionLevel unreadable)';
        var base = lvl & self.PROTECTION_MASK_BASE;
        var names = { 0: 'normal', 1: 'dangerous', 2: 'signature', 3: 'signatureOrSystem',
                      4: 'internal' };
        var s = 'protectionLevel=' + (names[base] || base) + ' (raw 0x' +
                (lvl >>> 0).toString(16) + ')';
        if (base === 0) {
            s += '   <-- NORMAL: granted automatically to ANY app that declares it. ' +
                 'This permission protects NOTHING.';
        } else if (base === 2) {
            s += '   <-- signature: only same-signed apps. A real control.';
        } else if (base === 1) {
            s += '   <-- dangerous: the user prompt is the only control.';
        }
        // Useful flag bits.
        if (lvl & 0x20)   s += ' |privileged';
        if (lvl & 0x40)   s += ' |development';
        if (lvl & 0x1000) s += ' |instant';
        if (lvl & 0x2000) s += ' |appop';
        if (lvl & 0x80000) s += ' |knownSigner';
        return s;
    },

    perm: function (name) {
        var self = this;
        Java.perform(function () {
            try {
                var pi = self._pm.getPermissionInfo(name, 0);
                self._log('[*] ' + name);
                self._log('    package=' + self._safe(function () {
                    return pi.packageName.value; }, '?'));
                self._log('    ' + self._describeProtection(pi));
            } catch (e) {
                self._log('[-] getPermissionInfo("' + name + '") failed: ' + e);
                self._log('    An undefined permission cannot be granted, so a component');
                self._log('    "protected" by it is unreachable — but confirm, because the');
                self._log('    defining app may simply not be installed on THIS device.');
            }
        });
    },

    /* ------------------------------------------------------ instrumentation */

    instrumentation: function (pkg) {
        var self = this;
        pkg = pkg || this._pkg;
        this._hdr('INSTRUMENTATION — ' + pkg);
        Java.perform(function () {
            var pi = self._info(pkg, self.GET_INSTRUMENTATION);
            if (pi === null) return;
            var arr = self._safe(function () { return pi.instrumentation.value; }, null);
            if (arr === null) { self._log('  (none)'); return; }
            var n = 0;
            try { n = arr.length; } catch (e) { n = 0; }
            if (n === 0) { self._log('  (none)'); return; }
            for (var i = 0; i < n; i++) {
                var ii = arr[i];
                self._log('  ' + self._safe(function () { return ii.name.value; }, '?') +
                          '  targetPackage=' +
                          self._safe(function () { return ii.targetPackage.value; }, '?'));
            }
            self._log('  <-- HIGH. `am instrument` runs this INSIDE the target process with');
            self._log('      the target app UID and permissions. It also proves a test');
            self._log('      artefact reached the shipped build. It sits outside');
            self._log('      <application> at the bottom of the manifest, where nobody looks.');
        });
    },

    /* -------------------------------------------------------------- enabled */

    enabled: function (pkg) {
        var self = this;
        pkg = pkg || this._pkg;
        this._hdr('LIVE COMPONENT ENABLED-STATE — ' + pkg);
        this._log('  The manifest value is not the final word: the app can change any');
        this._log('  component\'s enabled state at runtime with setComponentEnabledSetting.');

        Java.perform(function () {
            var ComponentName = self._use('android.content.ComponentName');
            if (ComponentName === null) { self._log('  <ComponentName unavailable>'); return; }

            var flags = self.GET_ACTIVITIES | self.GET_SERVICES | self.GET_RECEIVERS |
                        self.GET_PROVIDERS | self.MATCH_DISABLED;
            var pi = self._info(pkg, flags);
            if (pi === null) return;

            var states = { 0: 'DEFAULT (manifest)', 1: 'ENABLED', 2: 'DISABLED',
                           3: 'DISABLED_USER', 4: 'DISABLED_UNTIL_USED' };

            ['activities', 'services', 'receivers', 'providers'].forEach(function (field) {
                var arr = self._safe(function () { return pi[field].value; }, null);
                if (arr === null) return;
                var n = 0;
                try { n = arr.length; } catch (e) { return; }
                for (var i = 0; i < n; i++) {
                    var info = arr[i];
                    var nm = self._safe(function () { return info.name.value; }, null);
                    if (!nm) continue;
                    var cn = ComponentName.$new(pkg, nm);
                    var st = self._safe(function () {
                        return self._pm.getComponentEnabledSetting(cn);
                    }, null);
                    if (st !== null && st !== 0) {
                        self._log('  ' + nm + '  -> ' + (states[st] || st) +
                                  '   <-- CHANGED FROM THE MANIFEST VALUE');
                    }
                }
            });
            self._log('  (only components whose state differs from DEFAULT are listed)');
        });
    },

    /* --------------------------------------------- runtime-only surface */

    watchReceivers: function () {
        var self = this;
        this._hdr('WATCHING registerReceiver — invisible in the manifest');
        Java.perform(function () {
            var CW = self._use('android.content.ContextWrapper');
            if (CW === null) { self._log('[-] ContextWrapper not found'); return; }

            function dumpFilter(filter, indent) {
                if (!filter) return;
                try {
                    var n = filter.countActions();
                    for (var i = 0; i < n; i++) {
                        self._log(indent + 'action: ' + filter.getAction(i));
                    }
                    var p = filter.getPriority();
                    if (p !== 0) self._log(indent + 'priority: ' + p);
                } catch (e) { /* older/newer signature */ }
            }

            var hooked = 0;

            // 2-arg overload: on targetSdk < 33 this receiver is effectively EXPORTED.
            try {
                CW.registerReceiver.overload(
                    'android.content.BroadcastReceiver', 'android.content.IntentFilter'
                ).implementation = function (recv, filter) {
                    self._log('[registerReceiver 2-arg] ' +
                              (recv ? recv.$className : 'null') +
                              '   <-- no export flag: EXPORTED on targetSdk < 33');
                    dumpFilter(filter, '    ');
                    return this.registerReceiver(recv, filter);
                };
                hooked++;
            } catch (e) { /* overload absent */ }

            // 4-arg overload (permission + handler).
            try {
                CW.registerReceiver.overload(
                    'android.content.BroadcastReceiver', 'android.content.IntentFilter',
                    'java.lang.String', 'android.os.Handler'
                ).implementation = function (recv, filter, perm, h) {
                    self._log('[registerReceiver 4-arg] ' +
                              (recv ? recv.$className : 'null') +
                              '  broadcastPermission=' + perm);
                    dumpFilter(filter, '    ');
                    return this.registerReceiver(recv, filter, perm, h);
                };
                hooked++;
            } catch (e) { /* overload absent */ }

            // 3-arg (flags) — API 26+ for the int form.
            try {
                CW.registerReceiver.overload(
                    'android.content.BroadcastReceiver', 'android.content.IntentFilter', 'int'
                ).implementation = function (recv, filter, flags) {
                    // RECEIVER_EXPORTED = 0x2, RECEIVER_NOT_EXPORTED = 0x4
                    var state = (flags & 0x2) ? 'EXPORTED'
                              : ((flags & 0x4) ? 'NOT_EXPORTED' : 'UNSPECIFIED');
                    self._log('[registerReceiver 3-arg] flags=0x' + flags.toString(16) +
                              ' -> ' + state + '  ' +
                              (recv ? recv.$className : 'null'));
                    dumpFilter(filter, '    ');
                    return this.registerReceiver(recv, filter, flags);
                };
                hooked++;
            } catch (e) { /* overload absent */ }

            // 5-arg (permission + handler + flags).
            try {
                CW.registerReceiver.overload(
                    'android.content.BroadcastReceiver', 'android.content.IntentFilter',
                    'java.lang.String', 'android.os.Handler', 'int'
                ).implementation = function (recv, filter, perm, h, flags) {
                    var state = (flags & 0x2) ? 'EXPORTED'
                              : ((flags & 0x4) ? 'NOT_EXPORTED' : 'UNSPECIFIED');
                    self._log('[registerReceiver 5-arg] flags=0x' + flags.toString(16) +
                              ' -> ' + state + '  perm=' + perm + '  ' +
                              (recv ? recv.$className : 'null'));
                    dumpFilter(filter, '    ');
                    return this.registerReceiver(recv, filter, perm, h, flags);
                };
                hooked++;
            } catch (e) { /* overload absent */ }

            self._log('[*] hooked ' + hooked + ' registerReceiver overload(s).');
            if (hooked === 0) {
                self._log('[!] None matched on this release. Enumerate them yourself:');
                self._log('    Java.use("android.content.ContextWrapper")' +
                          '.registerReceiver.overloads.forEach(o => console.log(o));');
            }

            // Component enable/disable at runtime.
            var APM = self._use('android.app.ApplicationPackageManager');
            if (APM !== null) {
                try {
                    APM.setComponentEnabledSetting.implementation =
                        function (cn, state, flags) {
                            self._log('[setComponentEnabledSetting] ' +
                                      (cn ? cn.flattenToString() : 'null') +
                                      ' state=' + state +
                                      ' (1=ENABLED, 2=DISABLED)');
                            return this.setComponentEnabledSetting(cn, state, flags);
                        };
                } catch (e) {
                    self._log('[!] setComponentEnabledSetting hook unavailable: ' + e);
                }
            }
        });
    },

    watchMetadata: function () {
        var self = this;
        this._hdr('WATCHING <meta-data> reads');
        Java.perform(function () {
            var Bundle = self._use('android.os.Bundle');
            if (Bundle === null) { self._log('[-] android.os.Bundle not found'); return; }
            ['getString', 'getInt', 'getBoolean'].forEach(function (m) {
                try {
                    Bundle[m].overload('java.lang.String').implementation = function (k) {
                        var v = this[m](k);
                        // Metadata keys are dotted; app extras usually are not.
                        if (k && k.indexOf('.') !== -1) {
                            self._log('[Bundle.' + m + '] ' + k + ' = ' + v);
                        }
                        return v;
                    };
                } catch (e) { /* overload absent on this release */ }
            });
            self._log('[*] Exercise the app now. SDK initialisation happens early, so');
            self._log('    spawn with -f rather than attaching if you want to see it.');
        });
    },

    watchIntents: function () {
        var self = this;
        this._hdr('WATCHING Intents delivered to components');

        Java.perform(function () {
            function describe(intent) {
                if (!intent) return 'null';
                var s = self._safe(function () { return '' + intent.getAction(); }, '?') +
                        ' data=' + self._safe(function () {
                            return '' + intent.getDataString(); }, '?') +
                        ' comp=' + self._safe(function () {
                            var c = intent.getComponent();
                            return c ? c.flattenToString() : '-';
                        }, '-');
                try {
                    var ex = intent.getExtras();
                    if (ex !== null) {
                        var keys = ex.keySet().toArray();
                        for (var i = 0; i < keys.length; i++) {
                            s += '\n      extra[' + keys[i] + '] = ' +
                                 self._safe(function () {
                                     return '' + ex.get('' + keys[i]); }, '<unreadable>');
                        }
                    }
                } catch (e) { /* ignore */ }
                return s;
            }

            var Activity = self._use('android.app.Activity');
            if (Activity !== null) {
                try {
                    Activity.onCreate.overload('android.os.Bundle').implementation =
                        function (b) {
                            self._log('[Activity.onCreate] ' + this.$className +
                                      '\n      ' + describe(this.getIntent()));
                            return this.onCreate(b);
                        };
                } catch (e) { self._log('[!] Activity.onCreate hook failed: ' + e); }
            }

            var Service = self._use('android.app.Service');
            if (Service !== null) {
                try {
                    Service.onStartCommand.implementation = function (i, f, id) {
                        self._log('[Service.onStartCommand] ' + this.$className +
                                  '\n      ' + describe(i));
                        return this.onStartCommand(i, f, id);
                    };
                } catch (e) { /* abstract on some releases */ }
                try {
                    Service.onBind.implementation = function (i) {
                        self._log('[Service.onBind] ' + this.$className +
                                  '\n      ' + describe(i) +
                                  '\n      <-- the caller now holds an IBinder: every method');
                        self._log('          on that interface is reachable with arbitrary args');
                        return this.onBind(i);
                    };
                } catch (e) { /* ignore */ }
            }

            // Receivers: hooking the abstract base does not work, so walk the
            // loaded classes and hook concrete onReceive implementations.
            var count = 0;
            try {
                Java.enumerateLoadedClassesSync().forEach(function (name) {
                    if (name.indexOf('android.') === 0 || name.indexOf('java.') === 0 ||
                        name.indexOf('androidx.') === 0) return;
                    try {
                        var k = Java.use(name);
                        if (!k.onReceive) return;
                        k.onReceive.overload('android.content.Context',
                                             'android.content.Intent')
                         .implementation = function (ctx, intent) {
                            self._log('[onReceive] ' + name + '\n      ' + describe(intent));
                            return this.onReceive(ctx, intent);
                        };
                        count++;
                    } catch (e) { /* not a receiver / not loaded yet */ }
                });
            } catch (e) { self._log('[!] class enumeration failed: ' + e); }
            self._log('[*] hooked onReceive on ' + count + ' loaded class(es).');
            self._log('    Classes not yet loaded are not covered — re-run after the app');
            self._log('    has been exercised, or hook the ClassLoader.');
        });
    },

    /* --------------------------------------------------------------- export */

    export: function (pkg) {
        var self = this;
        pkg = pkg || this._pkg;
        var out = { package: pkg, components: [], permissions: [], flags: {} };

        Java.perform(function () {
            var flags = self.GET_ACTIVITIES | self.GET_SERVICES | self.GET_RECEIVERS |
                        self.GET_PROVIDERS | self.GET_PERMISSIONS;
            var pi = self._info(pkg, flags);
            if (pi === null) return;

            var ai = self._safe(function () { return pi.applicationInfo.value; }, null);
            if (ai !== null) {
                var f = self._safe(function () { return ai.flags.value; }, 0);
                out.flags = {
                    raw: '0x' + (f >>> 0).toString(16),
                    debuggable: (f & self.FLAG_DEBUGGABLE) !== 0,
                    allowBackup: (f & self.FLAG_ALLOW_BACKUP) !== 0,
                    testOnly: (f & self.FLAG_TEST_ONLY) !== 0,
                    targetSdkVersion: self._safe(function () {
                        return ai.targetSdkVersion.value; }, null)
                };
            }

            [['activities', 'activity'], ['services', 'service'],
             ['receivers', 'receiver'], ['providers', 'provider']].forEach(function (p) {
                var arr = self._safe(function () { return pi[p[0]].value; }, null);
                if (arr === null) return;
                var n = 0;
                try { n = arr.length; } catch (e) { return; }
                for (var i = 0; i < n; i++) {
                    var info = arr[i];
                    var rec = {
                        type: p[1],
                        name: self._safe(function () { return info.name.value; }, null),
                        exported: self._safe(function () { return info.exported.value; }, null),
                        permission: self._safe(function () {
                            return info.permission.value; }, null)
                    };
                    if (p[1] === 'provider') {
                        rec.authority = self._safe(function () {
                            return info.authority.value; }, null);
                        rec.readPermission = self._safe(function () {
                            return info.readPermission.value; }, null);
                        rec.writePermission = self._safe(function () {
                            return info.writePermission.value; }, null);
                        rec.grantUriPermissions = self._safe(function () {
                            return info.grantUriPermissions.value; }, null);
                    }
                    out.components.push(rec);
                }
            });

            var defined = self._safe(function () { return pi.permissions.value; }, null);
            if (defined !== null) {
                var m = 0;
                try { m = defined.length; } catch (e) { m = 0; }
                for (var j = 0; j < m; j++) {
                    var p2 = defined[j];
                    out.permissions.push({
                        name: self._safe(function () { return p2.name.value; }, null),
                        protectionLevel: self._safe(function () {
                            return p2.protectionLevel.value; }, null)
                    });
                }
            }
        });

        console.log(JSON.stringify(out, null, 2));
        return out;
    },

    /* ----------------------------------------------------------------- help */

    help: function () {
        console.log([
            '',
            'mf.all([pkg])          full platform-side manifest report',
            'mf.flags([pkg])        ApplicationInfo flags (debuggable, allowBackup, …)',
            'mf.components([pkg])   activities / services / receivers / providers',
            'mf.permissions([pkg])  declared (with protectionLevel) + requested',
            'mf.perm(name)          resolve ONE permission\'s protectionLevel',
            'mf.instrumentation()   <instrumentation> entries',
            'mf.enabled([pkg])      components whose live state differs from the manifest',
            'mf.watchReceivers()    log dynamically registered receivers + enable changes',
            'mf.watchMetadata()     log <meta-data> reads',
            'mf.watchIntents()      log Intents arriving at components',
            'mf.export([pkg])       JSON for diffing against aapt2 / apktool',
            'mf.init()              re-initialise if the Application was not ready',
            '',
            'Compare this output against `aapt2 dump xmltree` and `apktool`.',
            'The platform is authoritative. Disagreement between the host tools',
            'is itself a finding.',
            ''
        ].join('\n'));
    }
};

/* --------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== frida-manifest-runtime ===');
    if (mf.init()) {
        console.log('[+] Ready. Type mf.help() for commands, mf.all() for the full report.');
    } else {
        console.log('[-] Initialisation incomplete. Call mf.init() again once the app');
        console.log('    process is up, or attach with -n instead of spawning with -f.');
    }
    console.log('');
});
