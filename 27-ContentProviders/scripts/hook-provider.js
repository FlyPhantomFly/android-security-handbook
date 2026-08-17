/*
 * hook-provider.js — observe a ContentProvider from the SERVER side.
 *
 * WHAT IT DOES
 *   Attaches to the app that OWNS a provider and logs every incoming provider
 *   operation — query, insert, update, delete, call, openFile, openAssetFile,
 *   getType — together with:
 *
 *     * the Uri, projection, selection, sortOrder / method / arg / mode,
 *     * Binder.getCallingUid() and the resolved calling package(s), so you can
 *       tell WHO is calling and whether it is an external app or the app itself,
 *     * the return shape (row count, returned Uri, affected count, Bundle,
 *       ParcelFileDescriptor target path),
 *     * and, when hooked in tandem, the exact SQL string that SQLiteDatabase
 *       finally compiled (via rawQuery/execSQL/query) — which is the whole proof
 *       of an injection: you see your input reach a raw statement verbatim.
 *
 *   It also (optionally) taps UriMatcher.addURI to print every route the
 *   provider registers at startup — in PLAINTEXT even when the app is obfuscated
 *   or string-encrypted, because the strings are decrypted by the time addURI
 *   compares them.
 *
 * WHY IT MATTERS
 *   The client side (adb content, Drozer, a probe app) can only see what comes
 *   BACK. It cannot answer the question that decides an injection finding: "what
 *   did the provider DO with my input?" A marker that appears verbatim in the
 *   compiled SQL is injectable; a marker that was bound as a parameter is not.
 *   Only a server-side hook shows you which. This script is the server-side half
 *   of the methodology in README sections 5.1, 6.2 and 7.5.
 *
 *   It is also how you discover call() method names and provider routes when you
 *   have no source: run this, then USE THE APP normally, and watch its own
 *   components exercise every method and path in plaintext.
 *
 *   DEFENSIVE CODING. Every symbol lookup and every overload resolution is
 *   guarded. ART ships as a Mainline module and app method sets vary, so a script
 *   that assumes an overload exists throws and instruments nothing. This one logs
 *   what it could not hook and keeps going — partial visibility beats none.
 *
 * HOW TO RUN
 *   Spawn (preferred — catches onCreate and early calls):
 *     frida -U -f com.example.app -l hook-provider.js
 *   Attach to a running process:
 *     frida -U -n com.example.app -l hook-provider.js
 *
 *   For reliable hooks on a heavily-AOT-compiled app, force interpretation first
 *   so inlining does not swallow your target (see 13-ART):
 *     adb shell cmd package compile -m verify -f com.example.app
 *     adb shell am force-stop com.example.app
 *
 *   From the REPL:
 *     hp.summary()        // per-method call counts seen so far
 *     hp.routes()         // routes captured from UriMatcher.addURI
 *     hp.verbose(true)    // dump full stack traces on each call
 *
 * REQUIREMENTS
 *   frida-server running on the device, matching your host frida version.
 *   USB or networked device reachable by `frida -U`.
 *
 * NOTE ON PRIVILEGE
 *   This observes the provider from INSIDE its own process, so it sees calls
 *   from every caller regardless of uid. Distinguishing an external attacker's
 *   call from the app's own is done by reading the logged callerUid against the
 *   app's own uid — both are printed on every line. See README section 7.6 on
 *   using the backtrace for the same purpose.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var hp = {
    counts: {},
    routes: [],
    _verbose: false,
    _ownUid: -1,
    _pmCache: {},

    /* ------------------------------------------------------------- helpers */

    verbose: function (v) { this._verbose = !!v; return this._verbose; },

    _bump: function (name) {
        this.counts[name] = (this.counts[name] || 0) + 1;
    },

    summary: function () {
        console.log('\n[hp] operations observed:');
        var k;
        for (k in this.counts) {
            if (this.counts.hasOwnProperty(k)) {
                console.log('     ' + k + ' : ' + this.counts[k]);
            }
        }
        console.log('[hp] routes captured: ' + this.routes.length);
    },

    dumpRoutes: function () {
        if (this.routes.length === 0) {
            console.log('[hp] no routes captured (addURI may run before attach — use -f to spawn)');
        }
        this.routes.forEach(function (r) { console.log('     ' + r); });
    },

    _callerUid: function () {
        try {
            var Binder = Java.use('android.os.Binder');
            return Binder.getCallingUid();
        } catch (e) { return -1; }
    },

    _callerPkgs: function (uid) {
        if (uid < 0) return '?';
        if (this._pmCache[uid]) return this._pmCache[uid];
        var out = '?';
        try {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var app = ActivityThread.currentApplication();
            if (app !== null) {
                var pm = app.getPackageManager();
                var pkgs = pm.getPackagesForUid(uid);
                if (pkgs !== null) {
                    out = ''.concat.apply('', []); // placeholder
                    var arr = [];
                    for (var i = 0; i < pkgs.length; i++) { arr.push(pkgs[i]); }
                    out = arr.join(',');
                }
            }
        } catch (e) { out = '? (' + e + ')'; }
        this._pmCache[uid] = out;
        return out;
    },

    _tag: function (uid) {
        if (uid === this._ownUid) return 'SELF';
        if (uid === 0) return 'ROOT';
        if (uid === 2000) return 'SHELL(uid2000 — not an app!)';
        if (uid === 1000) return 'SYSTEM';
        return 'EXTERNAL uid=' + uid + ' pkg=' + this._callerPkgs(uid);
    },

    _arr: function (a) {
        if (a === null) return 'null';
        try {
            var out = [];
            for (var i = 0; i < a.length; i++) { out.push(a[i]); }
            return '[' + out.join(', ') + ']';
        } catch (e) { return '<unreadable>'; }
    },

    _bt: function () {
        if (!this._verbose) return;
        try {
            var Exception = Java.use('java.lang.Exception');
            var Log = Java.use('android.util.Log');
            console.log(Log.getStackTraceString(Exception.$new()));
        } catch (e) { /* ignore */ }
    },

    /* ---------------------------------------------------------- safe hook */
    //
    // Wrap a hook so a missing class or overload is reported, not fatal.

    _safe: function (label, fn) {
        try {
            fn();
        } catch (e) {
            console.log('[hp] skip ' + label + ' (' + e + ')');
        }
    },

    _overload: function (clazz, method, sig) {
        // Return the overload if it exists, else null — never throw.
        try {
            var m = clazz[method];
            if (!m) return null;
            if (sig) { return m.overload.apply(m, sig); }
            return m.overload();
        } catch (e) { return null; }
    },

    /* --------------------------------------------------------------- init */

    init: function () {
        var self = this;

        Java.perform(function () {
            try {
                self._ownUid = Java.use('android.os.Process').myUid();
            } catch (e) { self._ownUid = -1; }
            console.log('[hp] own uid = ' + self._ownUid);

            self._hookRoutes();
            self._hookProvider();
            self._hookSqlite();
            console.log('[hp] instrumentation installed. Exercise the provider now.');
            console.log('[hp] REPL: hp.summary(), hp.routes(), hp.verbose(true)');
        });
    },

    /* --------------------------------------------------- UriMatcher.addURI */

    _hookRoutes: function () {
        var self = this;
        this._safe('UriMatcher.addURI', function () {
            var UM = Java.use('android.content.UriMatcher');
            UM.addURI.implementation = function (auth, path, code) {
                var route = 'content://' + auth + '/' + path + '  -> ' + code;
                self.routes.push(route);
                console.log('[route] ' + route);
                return this.addURI(auth, path, code);
            };
        });
    },

    /* ------------------------------------------ ContentProvider entry points */

    _hookProvider: function () {
        var self = this;
        var CP;
        try {
            CP = Java.use('android.content.ContentProvider');
        } catch (e) {
            console.log('[hp] android.content.ContentProvider not found?! (' + e + ')');
            return;
        }

        // query(Uri, String[], String, String[], String)  — legacy 5-arg form
        this._safe('query/5', function () {
            var ov = self._overload(CP, 'query',
                ['android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
                 '[Ljava.lang.String;', 'java.lang.String']);
            if (!ov) { console.log('[hp] query/5 overload absent'); return; }
            ov.implementation = function (uri, proj, sel, args, sort) {
                var uid = self._callerUid();
                self._bump('query');
                console.log('\n[QUERY] ' + (uri ? uri.toString() : 'null') +
                            '  <- ' + self._tag(uid));
                console.log('   projection = ' + self._arr(proj));
                console.log('   selection  = ' + sel);
                console.log('   selArgs    = ' + self._arr(args));
                console.log('   sortOrder  = ' + sort);
                self._bt();
                var c = this.query(uri, proj, sel, args, sort);
                try {
                    console.log('   -> rows = ' + (c === null ? 'null' : c.getCount()));
                } catch (e) { console.log('   -> cursor (count unavailable)'); }
                return c;
            };
        });

        // query(Uri, String[], Bundle, CancellationSignal) — modern bundle form
        this._safe('query/bundle', function () {
            var ov = self._overload(CP, 'query',
                ['android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle',
                 'android.os.CancellationSignal']);
            if (!ov) return;
            ov.implementation = function (uri, proj, bundle, sig) {
                var uid = self._callerUid();
                self._bump('query(bundle)');
                console.log('\n[QUERY bundle] ' + (uri ? uri.toString() : 'null') +
                            '  <- ' + self._tag(uid));
                console.log('   projection = ' + self._arr(proj));
                console.log('   queryArgs  = ' + (bundle ? bundle.toString() : 'null'));
                return this.query(uri, proj, bundle, sig);
            };
        });

        // insert(Uri, ContentValues)
        this._safe('insert', function () {
            var ov = self._overload(CP, 'insert',
                ['android.net.Uri', 'android.content.ContentValues']);
            if (!ov) return;
            ov.implementation = function (uri, values) {
                var uid = self._callerUid();
                self._bump('insert');
                console.log('\n[INSERT] ' + (uri ? uri.toString() : 'null') +
                            '  <- ' + self._tag(uid));
                console.log('   values = ' + (values ? values.toString() : 'null'));
                var r = this.insert(uri, values);
                console.log('   -> ' + (r ? r.toString() : 'null'));
                return r;
            };
        });

        // update(Uri, ContentValues, String, String[])
        this._safe('update', function () {
            var ov = self._overload(CP, 'update',
                ['android.net.Uri', 'android.content.ContentValues',
                 'java.lang.String', '[Ljava.lang.String;']);
            if (!ov) return;
            ov.implementation = function (uri, values, sel, args) {
                var uid = self._callerUid();
                self._bump('update');
                console.log('\n[UPDATE] ' + (uri ? uri.toString() : 'null') +
                            '  <- ' + self._tag(uid));
                console.log('   values    = ' + (values ? values.toString() : 'null'));
                console.log('   selection = ' + sel + '  selArgs = ' + self._arr(args));
                var n = this.update(uri, values, sel, args);
                console.log('   -> affected = ' + n);
                return n;
            };
        });

        // delete(Uri, String, String[])
        this._safe('delete', function () {
            var ov = self._overload(CP, 'delete',
                ['android.net.Uri', 'java.lang.String', '[Ljava.lang.String;']);
            if (!ov) return;
            ov.implementation = function (uri, sel, args) {
                var uid = self._callerUid();
                self._bump('delete');
                console.log('\n[DELETE] ' + (uri ? uri.toString() : 'null') +
                            '  <- ' + self._tag(uid));
                console.log('   selection = ' + sel + '  selArgs = ' + self._arr(args));
                var n = this.delete(uri, sel, args);
                console.log('   -> affected = ' + n);
                return n;
            };
        });

        // getType(Uri) — unprotected by the framework; watch for DB-backed impls
        this._safe('getType', function () {
            var ov = self._overload(CP, 'getType', ['android.net.Uri']);
            if (!ov) return;
            ov.implementation = function (uri) {
                self._bump('getType');
                var t = this.getType(uri);
                console.log('[getType] ' + (uri ? uri.toString() : 'null') +
                            ' -> ' + t + '   (framework does NOT permission-check this)');
                return t;
            };
        });

        // call(String, String, Bundle)  — 3-arg
        this._safe('call/3', function () {
            var ov = self._overload(CP, 'call',
                ['java.lang.String', 'java.lang.String', 'android.os.Bundle']);
            if (!ov) return;
            ov.implementation = function (method, arg, extras) {
                var uid = self._callerUid();
                self._bump('call');
                console.log('\n[CALL] method=' + method + ' arg=' + arg +
                            '  <- ' + self._tag(uid) +
                            '   (NO automatic permission check)');
                console.log('   extras = ' + (extras ? extras.toString() : 'null'));
                self._bt();
                var r = this.call(method, arg, extras);
                console.log('   -> ' + (r ? r.toString() : 'null'));
                return r;
            };
        });

        // call(String authority, String, String, Bundle)  — 4-arg
        this._safe('call/4', function () {
            var ov = self._overload(CP, 'call',
                ['java.lang.String', 'java.lang.String', 'java.lang.String',
                 'android.os.Bundle']);
            if (!ov) return;
            ov.implementation = function (auth, method, arg, extras) {
                var uid = self._callerUid();
                self._bump('call');
                console.log('\n[CALL] auth=' + auth + ' method=' + method +
                            ' arg=' + arg + '  <- ' + self._tag(uid));
                var r = this.call(auth, method, arg, extras);
                console.log('   -> ' + (r ? r.toString() : 'null'));
                return r;
            };
        });

        // openFile(Uri, String) — the traversal surface
        this._safe('openFile', function () {
            var ov = self._overload(CP, 'openFile',
                ['android.net.Uri', 'java.lang.String']);
            if (!ov) return;
            ov.implementation = function (uri, mode) {
                var uid = self._callerUid();
                self._bump('openFile');
                console.log('\n[openFile] ' + (uri ? uri.toString() : 'null') +
                            ' mode=' + mode + '  <- ' + self._tag(uid));
                var pfd = this.openFile(uri, mode);
                return pfd;
            };
        });

        // openAssetFile(Uri, String) — default openFile delegates here; audit both
        this._safe('openAssetFile', function () {
            var ov = self._overload(CP, 'openAssetFile',
                ['android.net.Uri', 'java.lang.String']);
            if (!ov) return;
            ov.implementation = function (uri, mode) {
                var uid = self._callerUid();
                self._bump('openAssetFile');
                console.log('\n[openAssetFile] ' + (uri ? uri.toString() : 'null') +
                            ' mode=' + mode + '  <- ' + self._tag(uid));
                return this.openAssetFile(uri, mode);
            };
        });
    },

    /* --------------------------- SQLite: the compiled statement is the proof */

    _hookSqlite: function () {
        var self = this;
        var DB;
        try {
            DB = Java.use('android.database.sqlite.SQLiteDatabase');
        } catch (e) {
            console.log('[hp] SQLiteDatabase not found — skipping SQL hooks (' + e + ')');
            return;
        }

        // rawQuery(String, String[])
        this._safe('rawQuery', function () {
            var ov = self._overload(DB, 'rawQuery',
                ['java.lang.String', '[Ljava.lang.String;']);
            if (!ov) return;
            ov.implementation = function (sql, args) {
                self._bump('sql:rawQuery');
                console.log('[SQL rawQuery] ' + sql);
                if (args !== null) { console.log('          args = ' + self._arr(args)); }
                return this.rawQuery(sql, args);
            };
        });

        // execSQL(String)
        this._safe('execSQL/1', function () {
            var ov = self._overload(DB, 'execSQL', ['java.lang.String']);
            if (!ov) return;
            ov.implementation = function (sql) {
                self._bump('sql:execSQL');
                console.log('[SQL execSQL] ' + sql);
                return this.execSQL(sql);
            };
        });

        // The big query() overload most providers ultimately reach.
        this._safe('SQLiteDatabase.query/full', function () {
            var ov = self._overload(DB, 'query',
                ['boolean', 'java.lang.String', '[Ljava.lang.String;',
                 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String',
                 'java.lang.String', 'java.lang.String', 'java.lang.String',
                 'android.os.CancellationSignal']);
            if (!ov) return;
            ov.implementation = function (d, table, cols, sel, selArgs,
                                          group, having, order, limit, cs) {
                self._bump('sql:query');
                console.log('[SQL query] table=' + table +
                            ' cols=' + (cols === null ? '*' : self._arr(cols)) +
                            ' sel=' + sel +
                            ' order=' + order + ' limit=' + limit);
                if (selArgs !== null) { console.log('          selArgs = ' + self._arr(selArgs)); }
                return this.query(d, table, cols, sel, selArgs, group, having, order, limit, cs);
            };
        });
    }
};

hp.init();
