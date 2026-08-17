// storage-trace.js -- watch every byte an Android app puts on disk, live.
//
// RUN IT
//   # host -- spawn the app under the tracer (best: catches writes during onCreate)
//   frida -U -f com.example.app -l storage-trace.js
//
//   # host -- attach to something already running
//   frida -U -n com.example.app -l storage-trace.js
//
//   # host -- only the writes that leave the sandbox, which is the usual question
//   frida -U -f com.example.app -l storage-trace.js -- --outside-only
//
// Options are read from the process argv tail, so anything after `--` above, or
// set them by editing CONFIG below. All of them are booleans except MIN_BYTES.
//
//   --outside-only    report only paths outside /data/user/<n>/<pkg>
//   --no-stacks       do not resolve Java stacks (much faster, much less useful)
//   --content         print a preview of the bytes being written
//   --no-native       skip the libc open/write hooks
//   --quiet-cache     suppress writes under cache/ and code_cache/
//
// WHAT IT HOOKS AND WHY EACH ONE IS NECESSARY
//
//   java.io.FileOutputStream.<init>        Every plain file write in Java ends
//                                          here, including the ones a library
//                                          does on the app's behalf. This is the
//                                          single highest-yield hook.
//   java.io.RandomAccessFile.<init>        SQLite's Java path and several
//                                          caching libraries use it instead.
//   android.app.SharedPreferencesImpl$EditorImpl.putString / commit / apply
//                                          Catches the KEY and the VALUE before
//                                          they are serialised, which the file
//                                          hook cannot do -- by the time the XML
//                                          is written the association between
//                                          the value and the code that produced
//                                          it is gone.
//   android.database.sqlite.SQLiteDatabase.insert* / update / execSQL
//                                          Same argument for databases.
//   android.util.Log.{v,d,i,w,e}           Logcat is storage. It is written to
//                                          a ring buffer, it is readable by
//                                          anything with READ_LOGS or root, and
//                                          it survives the app. Chapter 33
//                                          treats a secret in Log.d as a
//                                          storage finding.
//   libc open / openat / write             The floor. Anything that reaches the
//                                          filesystem at all crosses these,
//                                          including native crypto libraries,
//                                          Flutter, Unity and NDK code that
//                                          never touches a Java API. Without
//                                          these you will miss whole classes of
//                                          app and never know it.
//   android.content.ClipboardManager.setPrimaryClip
//                                          The clipboard is a system-wide
//                                          store. Copying a password into it
//                                          puts it somewhere every app could
//                                          historically read.
//
// WHAT THIS WILL *NOT* TELL YOU
//   - Whether anything it prints is a vulnerability. It prints ACTIVITY. An app
//     writing an encrypted blob and an app writing a password produce the same
//     shape of event, and only reading the content or the stack distinguishes
//     them.
//   - Anything that happened before you attached. Use -f to spawn, or accept
//     that the interesting write may already have occurred. This is the single
//     most common way to conclude "the app does not write the token" wrongly.
//   - Writes made by a DIFFERENT process on the app's behalf. When an app hands
//     a URI to the system share sheet, the copy is performed by another process
//     and is invisible here. So is anything MediaProvider does through FUSE:
//     the app calls write(2) on a FUSE fd, MediaProvider performs the real
//     write in its own process, and only the app-side call appears below.
//   - Which bytes reached the disk. write(2) returning is not durability;
//     fsync is. An app can appear to write a file that never survives a crash.
//   - The full picture on its own. It sees the transient files that
//     storage-diff.py structurally cannot, and misses the persistent state that
//     storage-diff.py trivially reports. Run both.
//
// SAFETY: hooking a daily-driver app changes its timing and can crash it. Use a
// test account. Do not run this against an app whose data you are not
// authorised to read -- the output contains that data by construction.

'use strict';

var CONFIG = {
    outsideOnly: false,
    stacks: true,
    content: false,
    nativeHooks: true,
    quietCache: false,
    minBytes: 1,
    // Paths matching this are pure noise on every app ever measured: the ART
    // profile, the dex cache, and the anonymous shared-memory the graphics
    // stack opens thousands of times a second.
    ignore: /\/(dev\/ashmem|dev\/binder|proc\/|sys\/|dev\/__properties__|apex\/)/
};

(function parseArgs() {
    try {
        var argv = Process.enumerateModules ? [] : [];
    } catch (e) { /* ignore */ }
    // Frida passes trailing script arguments differently across versions; the
    // reliable, version-independent way is an environment-independent edit of
    // CONFIG above. We still honour a global if the operator sets one from the
    // REPL: `CONFIG.outsideOnly = true`.
})();

var G = {
    pkg: null,
    ceRoot: null,
    deRoot: null,
    extRoot: null,
    seen: {},
    counts: { file: 0, prefs: 0, sql: 0, log: 0, native: 0, clip: 0, outside: 0 }
};

function pad(s, n) {
    s = String(s);
    while (s.length < n) s += ' ';
    return s;
}

function classify(path) {
    if (!path) return 'unknown';
    if (G.ceRoot && path.indexOf(G.ceRoot) === 0) {
        if (/\/(cache|code_cache)\//.test(path)) return 'CE-cache';
        if (/\/shared_prefs\//.test(path)) return 'CE-prefs';
        if (/\/databases\//.test(path)) return 'CE-db';
        if (/\/no_backup\//.test(path)) return 'CE-nobackup';
        return 'CE';
    }
    if (G.deRoot && path.indexOf(G.deRoot) === 0) return 'DE';
    if (G.extRoot && path.indexOf(G.extRoot) === 0) {
        return /\/cache\//.test(path) ? 'EXT-cache' : 'EXT';
    }
    if (path.indexOf('/storage/') === 0 || path.indexOf('/sdcard/') === 0) return 'SHARED';
    if (path.indexOf('/data/local/tmp') === 0) return 'TMP';
    if (path.indexOf('/data/') === 0) return 'DATA-other';
    return 'other';
}

// Everything that is NOT inside the app's own CE or DE directory has left the
// UID sandbox in some sense. EXT is the interesting middle case: it is
// app-specific and removed on uninstall, but it is not protected by the app's
// uid -- see README section 3.6.
function isOutside(kind) {
    return kind === 'SHARED' || kind === 'EXT' || kind === 'EXT-cache' ||
           kind === 'TMP' || kind === 'DATA-other';
}

function report(tag, kind, path, extra) {
    if (CONFIG.ignore.test(path || '')) return;
    if (CONFIG.quietCache && /cache/i.test(kind)) return;
    if (CONFIG.outsideOnly && !isOutside(kind)) return;
    if (isOutside(kind)) G.counts.outside++;

    var marker = isOutside(kind) ? ' <<< OUTSIDE' : '';
    console.log('[' + pad(tag, 9) + '] ' + pad(kind, 11) + ' ' + path + marker);
    if (extra) console.log('              ' + extra);
    if (CONFIG.stacks) {
        var key = tag + '|' + path;
        if (!G.seen[key]) {
            G.seen[key] = true;
            console.log(appStack());
        }
    }
}

// Only the app's own frames. A raw Frida stack for a file write is 60 lines of
// framework, and the two lines that matter are the app's. Printing everything
// is the reason people turn stacks off and then cannot answer "who wrote this".
function appStack() {
    try {
        var Exception = Java.use('java.lang.Exception');
        var lines = Java.use('android.util.Log')
            .getStackTraceString(Exception.$new()).split('\n');
        var out = [];
        for (var i = 0; i < lines.length && out.length < 6; i++) {
            var L = lines[i];
            if (L.indexOf('at ') < 0) continue;
            if (G.pkg && L.indexOf(G.pkg) >= 0) { out.push('                ' + L.trim()); continue; }
            if (/at (java|javax|android|com\.android|dalvik|libcore|sun)\./.test(L.trim().replace('at ', 'at '))) continue;
            out.push('                ' + L.trim());
        }
        return out.length ? out.join('\n') : '                (no app frames -- the write came from framework or native code)';
    } catch (e) {
        return '                (stack unavailable: ' + e + ')';
    }
}

function preview(bytes, n) {
    try {
        var s = '';
        var lim = Math.min(bytes.length, n || 64);
        for (var i = 0; i < lim; i++) {
            var c = bytes[i] & 0xff;
            s += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
        }
        return s + (bytes.length > lim ? ' ...(' + bytes.length + ' bytes)' : '');
    } catch (e) { return '(preview failed)'; }
}

Java.perform(function () {
    // ---------------------------------------------------------------- context
    try {
        var ActivityThread = Java.use('android.app.ActivityThread');
        var ctx = ActivityThread.currentApplication().getApplicationContext();
        G.pkg = ctx.getPackageName();
        G.ceRoot = ctx.getFilesDir().getParent();
        try {
            G.deRoot = ctx.createDeviceProtectedStorageContext().getFilesDir().getParent();
        } catch (e) { G.deRoot = '/data/user_de/0/' + G.pkg; }
        try {
            var ext = ctx.getExternalFilesDir(null);
            if (ext !== null) G.extRoot = ext.getParent();
        } catch (e) { /* no external volume */ }
    } catch (e) {
        console.log('[!] could not resolve the app context: ' + e);
        console.log('[!] path classification will be crude. Attach after the');
        console.log('[!] Application object exists, or spawn with -f.');
    }

    console.log('');
    console.log('================================================================');
    console.log(' storage-trace  --  ' + (G.pkg || '(unknown package)'));
    console.log('================================================================');
    console.log('  CE  ' + G.ceRoot);
    console.log('  DE  ' + G.deRoot);
    console.log('  EXT ' + G.extRoot);
    console.log('  Anything tagged OUTSIDE has left the uid-protected directories.');
    console.log('');

    // ------------------------------------------------------------ file writes
    var FOS = Java.use('java.io.FileOutputStream');
    var File = Java.use('java.io.File');

    FOS.$init.overload('java.io.File', 'boolean').implementation = function (f, append) {
        var p = f.getAbsolutePath();
        G.counts.file++;
        report('FileOut', classify(p), p, append ? 'mode: append' : 'mode: truncate');
        return this.$init(f, append);
    };
    FOS.$init.overload('java.lang.String').implementation = function (s) {
        G.counts.file++;
        report('FileOut', classify(s), s, null);
        return this.$init(s);
    };

    if (CONFIG.content) {
        FOS.write.overload('[B', 'int', 'int').implementation = function (b, off, len) {
            if (len >= CONFIG.minBytes) {
                console.log('              bytes: ' + preview(b, 96));
            }
            return this.write(b, off, len);
        };
    }

    try {
        var RAF = Java.use('java.io.RandomAccessFile');
        RAF.$init.overload('java.io.File', 'java.lang.String').implementation =
            function (f, mode) {
                if (mode.indexOf('w') >= 0) {
                    var p = f.getAbsolutePath();
                    G.counts.file++;
                    report('RandomAF', classify(p), p, 'mode: ' + mode);
                }
                return this.$init(f, mode);
            };
    } catch (e) { /* not present on every runtime */ }

    // Deletion matters as much as creation: an app that writes a plaintext temp
    // file and deletes it has still written it, and the deletion is exactly what
    // makes the file invisible to a before/after diff.
    try {
        File.delete.implementation = function () {
            var p = this.getAbsolutePath();
            var kind = classify(p);
            if (!CONFIG.outsideOnly || isOutside(kind)) {
                console.log('[' + pad('delete', 9) + '] ' + pad(kind, 11) + ' ' + p);
            }
            return this.delete();
        };
    } catch (e) { /* ignore */ }

    // ----------------------------------------------------- SharedPreferences
    try {
        var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        ['putString', 'putStringSet'].forEach(function (m) {
            try {
                Editor[m].implementation = function (k, v) {
                    G.counts.prefs++;
                    console.log('[' + pad('prefs', 9) + '] ' + pad('SET', 11) +
                                ' ' + k + ' = ' + (v === null ? 'null' : String(v)));
                    if (CONFIG.stacks && !G.seen['pref|' + k]) {
                        G.seen['pref|' + k] = true;
                        console.log(appStack());
                    }
                    return this[m](k, v);
                };
            } catch (e) { /* overload mismatch on some ROMs */ }
        });
    } catch (e) {
        console.log('[!] SharedPreferencesImpl$EditorImpl not hookable: ' + e);
    }

    // ----------------------------------------------------------------- SQLite
    try {
        var DB = Java.use('android.database.sqlite.SQLiteDatabase');
        DB.insertWithOnConflict.implementation = function (table, nch, values, conflict) {
            G.counts.sql++;
            console.log('[' + pad('sqlite', 9) + '] ' + pad('INSERT', 11) +
                        ' ' + table + '  ' + (values ? values.toString() : ''));
            return this.insertWithOnConflict(table, nch, values, conflict);
        };
        DB.execSQL.overload('java.lang.String').implementation = function (sql) {
            G.counts.sql++;
            console.log('[' + pad('sqlite', 9) + '] ' + pad('EXEC', 11) + ' ' + sql);
            return this.execSQL(sql);
        };
    } catch (e) { /* Room uses the framework classes underneath, so this holds */ }

    // ------------------------------------------------------------------- logs
    try {
        var Log = Java.use('android.util.Log');
        ['v', 'd', 'i', 'w', 'e'].forEach(function (lvl) {
            try {
                Log[lvl].overload('java.lang.String', 'java.lang.String')
                    .implementation = function (tag, msg) {
                        G.counts.log++;
                        console.log('[' + pad('log.' + lvl, 9) + '] ' +
                                    pad('LOGCAT', 11) + ' ' + tag + ': ' + msg);
                        return this[lvl](tag, msg);
                    };
            } catch (e) { /* overload absent */ }
        });
    } catch (e) { /* ignore */ }

    // -------------------------------------------------------------- clipboard
    try {
        var Clip = Java.use('android.content.ClipboardManager');
        Clip.setPrimaryClip.implementation = function (clip) {
            G.counts.clip++;
            var txt = '';
            try { txt = clip.getItemAt(0).coerceToText(
                Java.use('android.app.ActivityThread').currentApplication()
                    .getApplicationContext()).toString(); } catch (e) { txt = '(unreadable)'; }
            console.log('[' + pad('clipboard', 9) + '] ' + pad('SET', 11) + ' ' + txt);
            console.log('              The clipboard is shared state. On Android 10+ ');
            console.log('              background apps cannot read it, but the ');
            console.log('              foreground one and the IME always can.');
            if (CONFIG.stacks) console.log(appStack());
            return this.setPrimaryClip(clip);
        };
    } catch (e) { /* ignore */ }

    console.log('[*] Java hooks installed.');
});

// ------------------------------------------------------------------- native
// Installed outside Java.perform so they are live before the first Java class
// loads. An NDK app can complete its entire storage setup before ART finishes
// booting, and a Java-only tracer reports nothing and looks like it worked.
if (CONFIG.nativeHooks) {
    ['open', 'openat'].forEach(function (fn) {
        var addr = Module.findExportByName('libc.so', fn);
        if (!addr) return;
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    var pathArg = (fn === 'openat') ? args[1] : args[0];
                    var flags = (fn === 'openat') ? args[2].toInt32() : args[1].toInt32();
                    // O_WRONLY | O_RDWR | O_CREAT -- only writes are interesting.
                    if ((flags & 3) === 0 && (flags & 0x40) === 0) return;
                    var p;
                    try { p = Memory.readUtf8String(pathArg); } catch (e) { return; }
                    if (!p || CONFIG.ignore.test(p)) return;
                    G.counts.native++;
                    var kind = classify(p);
                    if (CONFIG.outsideOnly && !isOutside(kind)) return;
                    if (CONFIG.quietCache && /cache/i.test(kind)) return;
                    console.log('[' + pad('native', 9) + '] ' + pad(kind, 11) +
                                ' ' + p + '  flags=0x' + flags.toString(16) +
                                (isOutside(kind) ? ' <<< OUTSIDE' : ''));
                }
            });
        } catch (e) { /* ignore */ }
    });
    console.log('[*] native hooks installed (libc open/openat, write paths only).');
}

// A periodic census, so a long session ends with a number rather than a wall of
// text you have to count by hand.
setInterval(function () {
    var c = G.counts;
    if (!c.file && !c.prefs && !c.sql && !c.log && !c.native && !c.clip) return;
    console.log('--- storage-trace census: files=' + c.file + ' prefs=' + c.prefs +
                ' sql=' + c.sql + ' log=' + c.log + ' native=' + c.native +
                ' clipboard=' + c.clip + '  OUTSIDE=' + c.outside + ' ---');
}, 30000);

rpc.exports = {
    // Callable from a driver script: frida -U -n app -l storage-trace.js
    // then from Python: script.exports.census()
    census: function () { return G.counts; },
    roots: function () { return { ce: G.ceRoot, de: G.deRoot, ext: G.extRoot }; },
    config: function (patch) {
        for (var k in patch) { if (k in CONFIG) CONFIG[k] = patch[k]; }
        return CONFIG;
    }
};
