/*
 * in-process-reach.js — what an attacker who is ALREADY INSIDE the process can reach.
 *
 * WHAT IT DOES
 *   Runs inside a target application and enumerates everything reachable from
 *   code executing with that app's identity: its private data directory and
 *   every file in it, its SharedPreferences and their values, its SQLite
 *   databases, its in-memory strings and live objects, its Keystore aliases,
 *   its network stack, its clipboard, and the components it exposes to others.
 *
 *   In other words: it draws the line the sandbox actually draws, from the
 *   inside, and shows that the line is around the PROCESS — not around any
 *   construct inside it.
 *
 * WHY IT MATTERS
 *   The chapter's closing argument is that the real boundary is the kernel —
 *   UID, page tables, seccomp, SELinux — and that it is drawn BETWEEN processes,
 *   never inside one. This script is that argument made empirical.
 *
 *   Inside a single process there is no boundary at all:
 *     * `private` is a compiler and verifier convention. Reflection walks
 *       through it, and so does this script.
 *     * Native code shares the address space with the managed heap.
 *     * A hooking framework rewrites method entry points at will.
 *     * An "encrypted" preference is decrypted by code in this process, using a
 *       key this process can use, at a moment this script can observe.
 *
 *   The practical consequence for a report: any control an app implements
 *   against an attacker who is already executing in the app's own process is a
 *   speed bump, and must be described that way. The correct place for a decision
 *   the user must not be able to change is a server you control.
 *
 *   The practical consequence for testing: everything this script prints is
 *   reachable by an attacker who has ANY code execution in the process — a
 *   malicious SDK, a native library bug, a repackaged build, or you with frida.
 *   That is a very different adversary from "another installed app", and your
 *   finding must say which one it assumes.
 *
 *   See ../README.md sections 3.14 and 5, and ../faq.md question 26.
 *
 * HOW TO RUN
 *   # host
 *   frida -U -f com.example.target -l in-process-reach.js
 *   frida -U -n com.example.target -l in-process-reach.js
 *
 *   Then from the REPL:
 *     reach.all()             run every section
 *     reach.identity()        UID, GIDs, caps, seccomp, SELinux
 *     reach.files()           walk the whole data directory
 *     reach.prefs()           every SharedPreferences file and value
 *     reach.databases()       every SQLite database, tables and row counts
 *     reach.memory()          live Strings on the heap (secret hunting)
 *     reach.keystore()        AndroidKeyStore aliases visible to this process
 *     reach.network()         can this process open a socket?
 *     reach.exposed()         what THIS app exposes to other apps
 *     reach.watchFiles()      log every file the app opens from now on
 *
 * REQUIREMENTS
 *   frida-server on the device matching your host frida version. No root needed
 *   for the results to be meaningful — the app's own UID is what is being
 *   exercised throughout, and that is exactly the adversary being modelled.
 *
 * SAFETY
 *   Read-only. It opens files, reads preferences, and runs SELECT COUNT(*).
 *   It writes nothing and changes no state. `reach.memory()` can be slow on a
 *   large heap; it is capped.
 *
 * AUTHORISED TESTING ONLY. Everything here operates on data belonging to the
 * app you are instrumenting. Run it only against software you own or have
 * written authorisation to test.
 */

'use strict';

var reach = {

    _ctx: null,

    /* ---------------------------------------------------------------- util */

    ctx: function () {
        if (this._ctx !== null) return this._ctx;
        try {
            this._ctx = Java.use('android.app.ActivityThread')
                            .currentApplication().getApplicationContext();
        } catch (e) {
            console.log('[-] No Application context yet. If you used -f, wait for the');
            console.log('    app to finish starting, then re-run the command.');
        }
        return this._ctx;
    },

    hr: function (t) {
        console.log('');
        console.log('=== ' + t + ' ===');
    },

    readText: function (path, limit) {
        limit = limit || 4096;
        var out = null;
        try {
            var FIS = Java.use('java.io.FileInputStream');
            var s = FIS.$new(path);
            var buf = Java.array('byte', new Array(limit).fill(0));
            var n = s.read(buf);
            s.close();
            if (n <= 0) return '';
            out = Java.use('java.lang.String').$new(buf, 0, n);
        } catch (e) { return null; }
        return out;
    },

    /* ------------------------------------------------------------ identity */

    identity: function () {
        var self = this;
        Java.perform(function () {
            var ctx = self.ctx(); if (!ctx) return;
            var P  = Java.use('android.os.Process');
            var ai = ctx.getApplicationInfo();
            var uid = P.myUid();

            self.hr('1. WHO THIS PROCESS IS');
            console.log('  package          = ' + ctx.getPackageName());
            console.log('  uid              = ' + uid);
            console.log('  userId           = ' + Math.floor(uid / 100000) +
                        '   (uid / 100000)');
            console.log('  appId            = ' + (uid % 100000) +
                        '   (uid % 100000)');
            console.log('  pid              = ' + P.myPid());
            console.log('  processName      = ' +
                Java.use('android.app.ActivityThread').currentProcessName());
            console.log('  dataDir          = ' + ai.dataDir.value);
            console.log('  sourceDir (APK)  = ' + ai.sourceDir.value);
            console.log('  nativeLibraryDir = ' + ai.nativeLibraryDir.value);
            console.log('  targetSdkVersion = ' + ai.targetSdkVersion.value);
            console.log('  FLAG_DEBUGGABLE  = ' + ((ai.flags.value & 2) !== 0));

            if (uid % 100000 >= 99000) {
                console.log('  >>> This is an ISOLATED process. No permissions, no network,');
                console.log('  >>> no data directory. Most sections below will be empty, and');
                console.log('  >>> that emptiness IS the result.');
            }

            self.hr('2. THE KERNEL\'S VIEW  (this is the authoritative answer)');
            var st = self.readText('/proc/self/status', 8192);
            if (st !== null) {
                st.split('\n').forEach(function (l) {
                    if (/^(Uid|Gid|Groups|CapPrm|CapEff|CapBnd|Seccomp|Seccomp_filters|NoNewPrivs):/.test(l))
                        console.log('  ' + l.replace(/\s+/g, ' ').trim());
                });
            }
            var sec = self.readText('/proc/self/attr/current', 256);
            if (sec !== null) console.log('  SELinux: ' + sec.replace(/\0/g, '').trim());

            console.log('');
            console.log('  Groups containing 3003 => this process holds INTERNET (AID_INET).');
            console.log('  Cap* all zero and Seccomp: 2 are what an app looks like. Your');
            console.log('  adb shell looks nothing like this — see ../faq.md question 9.');
        });
    },

    /* --------------------------------------------------------------- files */

    files: function (maxEntries) {
        maxEntries = maxEntries || 400;
        var self = this;
        Java.perform(function () {
            var ctx = self.ctx(); if (!ctx) return;
            var File = Java.use('java.io.File');
            var root = File.$new(ctx.getApplicationInfo().dataDir.value);

            self.hr('3. EVERY FILE IN THE PRIVATE DATA DIRECTORY');
            console.log('  The sandbox keeps other apps out of here. It does nothing at all');
            console.log('  about code running inside this process — including this script.');
            console.log('');

            var count = 0;
            (function walk(dir, depth) {
                if (count >= maxEntries || depth > 6) return;
                var kids = dir.listFiles();
                if (kids === null) return;
                for (var i = 0; i < kids.length && count < maxEntries; i++) {
                    var f = kids[i];
                    var p = f.getAbsolutePath();
                    if (f.isDirectory()) {
                        console.log('  [dir ] ' + p);
                        count++;
                        walk(f, depth + 1);
                    } else {
                        console.log('  [file] ' + p + '  (' + f.length() + ' bytes)');
                        count++;
                    }
                }
            })(root, 0);

            if (count >= maxEntries)
                console.log('  ... truncated at ' + maxEntries + ' entries; call reach.files(N)');
        });
    },

    /* --------------------------------------------------------------- prefs */

    prefs: function () {
        var self = this;
        Java.perform(function () {
            var ctx = self.ctx(); if (!ctx) return;
            var File = Java.use('java.io.File');
            var dir = File.$new(ctx.getApplicationInfo().dataDir.value + '/shared_prefs');

            self.hr('4. SHARED PREFERENCES — NAMES AND VALUES');
            if (!dir.exists()) { console.log('  (none)'); return; }

            var names = dir.list();
            if (names === null || names.length === 0) { console.log('  (none)'); return; }

            for (var i = 0; i < names.length; i++) {
                var n = names[i].replace(/\.xml$/, '');
                console.log('');
                console.log('  --- ' + names[i] + ' ---');
                try {
                    var sp = ctx.getSharedPreferences(n, 0);
                    var map = sp.getAll();
                    var it = map.keySet().iterator();
                    while (it.hasNext()) {
                        var k = it.next();
                        var v = '' + map.get(k);
                        console.log('    ' + k + ' = ' + (v.length > 200 ? v.substring(0, 200) + '…' : v));
                    }
                } catch (e) {
                    console.log('    could not read via SharedPreferences: ' + e);
                    var raw = self.readText(dir.getAbsolutePath() + '/' + names[i], 2048);
                    if (raw) console.log('    raw XML:\n' + raw);
                }
            }
            console.log('');
            console.log('  If any value here is an "encrypted" blob, note that the key that');
            console.log('  decrypts it is usable BY THIS PROCESS. Hook the decryption call and');
            console.log('  you get plaintext. See ../../49-KeyStore/ — the Keystore prevents key');
            console.log('  EXTRACTION, never key USE.');
        });
    },

    /* ----------------------------------------------------------- databases */

    databases: function () {
        var self = this;
        Java.perform(function () {
            var ctx = self.ctx(); if (!ctx) return;
            var File = Java.use('java.io.File');
            var dir  = File.$new(ctx.getApplicationInfo().dataDir.value + '/databases');

            self.hr('5. SQLITE DATABASES');
            if (!dir.exists()) { console.log('  (none)'); return; }

            var files = dir.list();
            if (files === null) { console.log('  (none)'); return; }

            var SQL = null;
            try { SQL = Java.use('android.database.sqlite.SQLiteDatabase'); }
            catch (e) { console.log('  SQLiteDatabase unavailable: ' + e); return; }

            for (var i = 0; i < files.length; i++) {
                var name = files[i];
                if (/-journal$|-wal$|-shm$/.test(name)) continue;
                var path = dir.getAbsolutePath() + '/' + name;
                console.log('');
                console.log('  --- ' + name + ' ---');
                var db = null;
                try {
                    db = SQL.openDatabase(path, null, SQL.OPEN_READONLY.value);
                    var c = db.rawQuery(
                        "SELECT name FROM sqlite_master WHERE type='table'", null);
                    while (c.moveToNext()) {
                        var t = c.getString(0);
                        var n = '?';
                        try {
                            var c2 = db.rawQuery('SELECT COUNT(*) FROM "' + t + '"', null);
                            if (c2.moveToFirst()) n = c2.getInt(0);
                            c2.close();
                        } catch (e2) { /* virtual tables etc. */ }
                        console.log('    table ' + t + '  rows=' + n);
                    }
                    c.close();
                } catch (e) {
                    console.log('    could not open: ' + e);
                    console.log('    (an encrypted database — SQLCipher — fails here. That is a');
                    console.log('     finding in the app\'s FAVOUR. Then go and find where the');
                    console.log('     passphrase comes from, because it is in this process too.)');
                } finally {
                    if (db !== null) { try { db.close(); } catch (e3) {} }
                }
            }
        });
    },

    /* -------------------------------------------------------------- memory */

    memory: function (pattern, max) {
        max = max || 40;
        var re = pattern ? new RegExp(pattern, 'i')
                         : /(token|secret|password|passwd|bearer|apikey|api_key|jwt|eyJ|session|private_key|BEGIN )/i;
        var self = this;
        Java.perform(function () {
            self.hr('6. LIVE STRINGS ON THE MANAGED HEAP');
            console.log('  Pattern: ' + re);
            console.log('  Java Strings are immutable and often interned, so a credential');
            console.log('  loaded once may stay resident for the process lifetime. This is');
            console.log('  why char[]/byte[] that you can zero is the correct container.');
            console.log('');
            var hits = 0;
            Java.choose('java.lang.String', {
                onMatch: function (s) {
                    if (hits >= max) return 'stop';
                    var v;
                    try { v = s.toString(); } catch (e) { return; }
                    if (v.length < 8 || v.length > 4096) return;
                    if (re.test(v)) {
                        console.log('  [' + (++hits) + '] ' + v.substring(0, 220));
                    }
                },
                onComplete: function () {
                    console.log('');
                    console.log('  ' + hits + ' match(es). Adjust with reach.memory("regex", max).');
                }
            });
        });
    },

    /* ------------------------------------------------------------ keystore */

    keystore: function () {
        var self = this;
        Java.perform(function () {
            self.hr('7. ANDROID KEYSTORE ALIASES VISIBLE TO THIS PROCESS');
            try {
                var KS = Java.use('java.security.KeyStore');
                var ks = KS.getInstance('AndroidKeyStore');
                ks.load(null);
                var e = ks.aliases();
                var n = 0;
                while (e.hasMoreElements()) {
                    console.log('  alias: ' + e.nextElement());
                    n++;
                }
                if (n === 0) console.log('  (no aliases — this app does not use the Keystore)');
                console.log('');
                console.log('  Note what this proves and what it does not. The KEY MATERIAL is');
                console.log('  not here and cannot be extracted. But this process can USE every');
                console.log('  key listed, which for an in-process attacker is usually just as');
                console.log('  good. See ../../49-KeyStore/labs/lab-02-extraction-vs-use.md.');
            } catch (err) {
                console.log('  Keystore unavailable: ' + err);
            }
        });
    },

    /* ------------------------------------------------------------- network */

    network: function () {
        var self = this;
        Java.perform(function () {
            self.hr('8. NETWORK — DOES THIS PROCESS HOLD AID_INET?');
            try {
                var s = Java.use('java.net.Socket').$new();
                s.close();
                console.log('  Socket() constructed OK -> the process is in GID 3003.');
            } catch (e) {
                console.log('  Socket creation FAILED: ' + e);
                console.log('  That is a KERNEL denial (EACCES from socket()), not a framework');
                console.log('  check. It cannot be hooked away from inside this process.');
            }
        });

        // And observe the syscall itself, which is the honest evidence.
        var sp = Module.findExportByName('libc.so', 'socket');
        if (sp === null) {
            console.log('  (libc.so!socket not exported on this build — skipping syscall trace)');
            return;
        }
        Interceptor.attach(sp, {
            onEnter: function (args) { this.dom = args[0].toInt32(); },
            onLeave: function (rv) {
                if (this.dom === 2 || this.dom === 10) {
                    console.log('  [syscall] socket(AF_INET' + (this.dom === 10 ? '6' : '') +
                                ') = ' + rv.toInt32() +
                                (rv.toInt32() < 0 ? '   <- kernel refused' : ''));
                }
            }
        });
        console.log('  Now watching socket() calls. Exercise the app.');
    },

    /* ------------------------------------------------------------- exposed */

    exposed: function () {
        var self = this;
        Java.perform(function () {
            var ctx = self.ctx(); if (!ctx) return;
            self.hr('9. WHAT THIS APP EXPOSES TO OTHER APPS');
            console.log('  The sandbox does not protect IPC you volunteered. Everything');
            console.log('  listed here is a door the developer cut into the wall.');
            console.log('');
            try {
                var PM = Java.use('android.content.pm.PackageManager');
                var pm = ctx.getPackageManager();
                var GET = PM.GET_ACTIVITIES.value | PM.GET_SERVICES.value |
                          PM.GET_RECEIVERS.value  | PM.GET_PROVIDERS.value;
                var pi = pm.getPackageInfo(ctx.getPackageName(), GET);

                function dump(title, arr, isProvider) {
                    console.log('  --- ' + title + ' ---');
                    if (arr === null) { console.log('    (none)'); return; }
                    for (var i = 0; i < arr.length; i++) {
                        var c = arr[i];
                        if (!c.exported.value) continue;
                        var perm = isProvider
                            ? ('read=' + c.readPermission.value + ' write=' + c.writePermission.value)
                            : ('permission=' + c.permission.value);
                        console.log('    EXPORTED  ' + c.name.value +
                            (isProvider ? '   authority=' + c.authority.value : '') +
                            '   ' + perm);
                    }
                }
                dump('activities',  pi.activities.value,  false);
                dump('services',    pi.services.value,    false);
                dump('receivers',   pi.receivers.value,   false);
                dump('providers',   pi.providers.value,   true);

                console.log('');
                console.log('  A null permission on an exported component means ANY installed');
                console.log('  app can invoke it. Confirm from an actual probe APK before');
                console.log('  reporting it — not from adb shell:');
                console.log('    ../examples/attacker-app/  ../labs/lab-03-attacker-app.md');
            } catch (e) {
                console.log('  ' + e);
            }
        });
    },

    /* ---------------------------------------------------------- watchFiles */

    watchFiles: function () {
        console.log('');
        console.log('=== 10. WATCHING FILE OPENS ===');
        console.log('  Every path this app opens from now on. Look for anything OUTSIDE');
        console.log('  the data directory — that data has left the sandbox.');
        console.log('');
        var op = Module.findExportByName('libc.so', 'openat');
        if (op === null) op = Module.findExportByName('libc.so', 'open');
        if (op === null) {
            console.log('  Neither openat nor open is exported on this build. Fall back to');
            console.log('  the Java layer instead:');
            console.log('    Java.use("java.io.FileOutputStream").$init.overload(...)');
            return;
        }
        var isOpenat = op.toString() === (Module.findExportByName('libc.so', 'openat') || '').toString();
        Interceptor.attach(op, {
            onEnter: function (args) {
                try {
                    this.path = (isOpenat ? args[1] : args[0]).readUtf8String();
                } catch (e) { this.path = null; }
            },
            onLeave: function (rv) {
                if (!this.path) return;
                if (this.path.indexOf('/dev/') === 0) return;
                if (this.path.indexOf('/proc/') === 0) return;
                if (this.path.indexOf('/apex/') === 0) return;
                if (this.path.indexOf('/system/fonts') === 0) return;
                var outside = this.path.indexOf('/data/data/') !== 0 &&
                              this.path.indexOf('/data/user/') !== 0;
                console.log('  ' + (rv.toInt32() < 0 ? 'FAIL ' : 'open ') +
                            this.path + (outside ? '    <-- OUTSIDE THE DATA DIR' : ''));
            }
        });
    },

    /* ------------------------------------------------------------------ all */

    all: function () {
        this.identity();
        this.files();
        this.prefs();
        this.databases();
        this.keystore();
        this.network();
        this.exposed();
        console.log('');
        console.log('=== WHAT THIS RUN ESTABLISHED ===');
        console.log('  Everything printed above is reachable by ANY code executing in this');
        console.log('  process: a malicious SDK, a native library bug, a repackaged build,');
        console.log('  or an instrumentation framework. Inside a process there is no');
        console.log('  boundary — `private` is a convention, reflection walks through it,');
        console.log('  and native code shares the address space.');
        console.log('');
        console.log('  The real boundary is the kernel: UID, page tables, seccomp, SELinux.');
        console.log('  It is drawn BETWEEN processes and never inside one.');
        console.log('');
        console.log('  So when you write this up, name the adversary. "An attacker with code');
        console.log('  execution in the app process can read the token" is a different, and');
        console.log('  much weaker, claim than "another installed app can read the token".');
        console.log('  Only the second is proven by a probe APK.');
        console.log('');
        console.log('  Next: reach.memory(), reach.watchFiles()');
    },

    help: function () {
        console.log([
            '',
            'reach.all()                 every section',
            'reach.identity()            uid, gids, caps, seccomp, selinux',
            'reach.files([n])            walk the private data directory',
            'reach.prefs()               SharedPreferences names and values',
            'reach.databases()           SQLite databases, tables, row counts',
            'reach.memory([re],[max])    live Strings matching a pattern',
            'reach.keystore()            AndroidKeyStore aliases',
            'reach.network()             AID_INET check + socket() trace',
            'reach.exposed()             this app\'s exported components',
            'reach.watchFiles()          log every file opened from now on',
            ''
        ].join('\n'));
    }
};

/* --------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== in-process-reach — Chapter 21 sections 3.14 and 5 ===');
    console.log('[*] The sandbox is a boundary between PROCESSES. This script is inside');
    console.log('[*] one. Watch how little that boundary constrains us here.');
    console.log('[+] Ready. reach.help() for commands, reach.all() to start.');
    console.log('');
});
