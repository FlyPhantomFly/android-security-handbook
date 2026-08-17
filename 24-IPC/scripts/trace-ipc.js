/*
 * trace-ipc.js — trace every IPC mechanism an Android app uses, as it happens.
 *
 * WHAT IT DOES
 *   Instruments the whole IPC surface from inside the target process and logs
 *   each operation with full argument detail:
 *
 *     Intents out   startActivity / startActivityForResult / startService /
 *                   startForegroundService / bindService / sendBroadcast /
 *                   sendOrderedBroadcast / sendStickyBroadcast, with the
 *                   complete extras bundle and its runtime types
 *     Intents in    Activity.getIntent, BroadcastReceiver.onReceive,
 *                   Service.onStartCommand / onBind, and the *Extra getters,
 *                   so you see exactly which fields the app trusts
 *     Redirection   flags any forwarded Intent that arrived from outside —
 *                   the confused-deputy signature
 *     Providers     ContentResolver query / insert / update / delete / call /
 *                   openInputStream, plus grantUriPermission
 *     Sockets       LocalServerSocket and LocalSocket (abstract namespace
 *                   loudly flagged), java.net.ServerSocket and Socket
 *     Binder        Binder.onTransact with the caller's uid and pid,
 *                   IBinder.transact on the client side, and Stub descriptors
 *     Adjacent      ClipboardManager, PendingIntent creation and its
 *                   mutability, Settings.Secure/Global reads, world-mode file
 *                   permission changes
 *
 *   Every single symbol lookup and every overload resolution is wrapped. A
 *   class that does not exist on this Android version, an overload that was
 *   added in a later API level, or a method R8 stripped will produce one
 *   "[skip]" line and the rest of the script keeps working. A Frida script for
 *   IPC that dies on the first missing overload is useless in the field,
 *   because you meet a different set of missing overloads on every device.
 *
 * WHY IT MATTERS
 *   Static analysis tells you which channels EXIST. This tells you which ones
 *   the app actually USES, with what data, in what order, and — critically —
 *   what it does with input that arrived from another process. The two
 *   questions you cannot answer from a manifest are "does this exported
 *   component forward what it received?" and "what is on the wire of that
 *   socket?", and both are answered here in one run.
 *
 *   See ../README.md sections 3.10, 3.11, 3.20 and 7.3.
 *
 * HOW TO RUN
 *   # host
 *   frida -U -f com.example.target -l trace-ipc.js            # spawn
 *   frida -U -n com.example.target -l trace-ipc.js            # attach
 *   frida -U -f com.example.target -l trace-ipc.js -o ipc.log # and record it
 *
 *   Then, from the REPL, tune it live:
 *     ipc.only(['socket', 'binder'])   // restrict to these categories
 *     ipc.all()                        // everything again
 *     ipc.stacks(true)                 // print a Java stack for every event
 *     ipc.quiet(true)                  // suppress extras dumps
 *     ipc.summary()                    // what has been seen so far
 *
 *   Categories: intent-out, intent-in, provider, socket, binder, clipboard,
 *               pendingintent, settings, filemode
 *
 * REQUIREMENTS
 *   frida-server running on the device and matching your host frida version.
 *   Android 5+ (API 21+). Root or a repackaged/patched app, as usual.
 *
 *   If hooks install but never fire, the methods were compiled and inlined.
 *   Force interpretation first — this is the single highest-value command in
 *   Android dynamic analysis:
 *     adb shell cmd package compile -m verify -f com.example.target
 *     adb shell am force-stop com.example.target
 *   See ../../13-ART/README.md.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var ipc = {
    /* ------------------------------------------------------------- config -- */

    categories: ['intent-out', 'intent-in', 'provider', 'socket', 'binder',
                 'clipboard', 'pendingintent', 'settings', 'filemode'],
    enabled: null,          // null == all
    showStacks: false,
    quietExtras: false,
    maxStringLen: 400,

    counts: {},
    installed: 0,
    skipped: 0,

    /* ------------------------------------------------------------ plumbing -- */

    on: function (cat) {
        return this.enabled === null || this.enabled.indexOf(cat) !== -1;
    },

    log: function (cat, msg) {
        if (!this.on(cat)) return;
        this.counts[cat] = (this.counts[cat] || 0) + 1;
        console.log('[' + cat + '] ' + msg);
        if (this.showStacks) this.stack();
    },

    warn: function (msg) { console.log('  !! ' + msg); },

    trunc: function (s) {
        if (s === null || s === undefined) return String(s);
        s = String(s);
        return s.length > this.maxStringLen
            ? s.substring(0, this.maxStringLen) + '…(' + s.length + ' chars)'
            : s;
    },

    stack: function () {
        try {
            var Log = Java.use('android.util.Log');
            var Exception = Java.use('java.lang.Exception');
            console.log(Log.getStackTraceString(Exception.$new()));
        } catch (e) { /* stack printing is best-effort, never fatal */ }
    },

    /*
     * Every hook goes through here.
     *
     * `fn` is expected to install one or more hooks and may throw for any of
     * the ordinary reasons: the class is absent on this API level, the overload
     * signature changed, the method was removed, or R8 stripped it. We record
     * and continue. Nothing in this script is allowed to abort the rest of it.
     */
    guard: function (label, fn) {
        try {
            fn();
            this.installed++;
        } catch (e) {
            this.skipped++;
            console.log('[skip] ' + label + ' — ' + e.message);
        }
    },

    /** Java.use that returns null instead of throwing. */
    cls: function (name) {
        try { return Java.use(name); } catch (e) { return null; }
    },

    /**
     * Resolve one overload out of a method, tolerating signature drift.
     * Returns null if no overload matches, so the caller can skip cleanly.
     */
    ovl: function (method, sig) {
        if (!method) return null;
        try {
            return sig ? method.overload.apply(method, sig) : method;
        } catch (e) {
            return null;
        }
    },

    /* --------------------------------------------------- Intent rendering -- */

    dumpIntent: function (tag, i) {
        if (i === null || i === undefined) {
            console.log('    ' + tag + ': <null Intent>');
            return;
        }
        var line = '    ' + tag + ':';
        try { line += ' action=' + i.getAction(); } catch (e) { }
        try { line += ' data=' + i.getData(); } catch (e) { }
        try { line += ' type=' + i.getType(); } catch (e) { }
        try {
            var c = i.getComponent();
            line += ' comp=' + (c ? c.flattenToShortString() : 'null');
        } catch (e) { }
        try { line += ' pkg=' + i.getPackage(); } catch (e) { }
        try {
            var f = i.getFlags();
            line += ' flags=0x' + (f >>> 0).toString(16);
            line += this.describeFlags(f);
        } catch (e) { }
        console.log(line);

        if (this.quietExtras) return;

        try {
            var b = i.getExtras();
            if (b === null) return;
            var it = b.keySet().iterator();
            while (it.hasNext()) {
                var k = it.next();
                var v = null, tname = 'null';
                try {
                    v = b.get(k);
                    tname = (v === null) ? 'null' : v.$className || (typeof v);
                } catch (e) {
                    tname = '<undeserialisable: ' + e.message + '>';
                }
                console.log('        extra[' + k + '] (' + tname + ') = '
                            + this.trunc(v));

                /*
                 * The type of an extra matters more than its value.
                 *
                 * A nested Intent, ComponentName or PendingIntent is not data,
                 * it is a CAPABILITY. If the app later acts on it, that is the
                 * raw material of intent redirection (README 3.20). Flag it
                 * every time so it cannot be missed in a long log.
                 */
                if (tname.indexOf('android.content.Intent') !== -1) {
                    this.warn('nested INTENT in extra "' + k
                              + '" — redirection material');
                } else if (tname.indexOf('PendingIntent') !== -1) {
                    this.warn('PENDING INTENT in extra "' + k
                              + '" — fires with the CREATOR\'s identity');
                } else if (tname.indexOf('ComponentName') !== -1) {
                    this.warn('COMPONENT NAME in extra "' + k + '"');
                } else if (tname.indexOf('ParcelFileDescriptor') !== -1) {
                    this.warn('FILE DESCRIPTOR in extra "' + k
                              + '" — the peer chose what this points at');
                }
            }
        } catch (e) {
            console.log('        <extras could not be read: ' + e.message + '>');
        }
    },

    describeFlags: function (f) {
        var out = [];
        // The four grant flags are the ones that matter for URI-grant theft.
        if (f & 0x00000001) out.push('GRANT_READ_URI');
        if (f & 0x00000002) out.push('GRANT_WRITE_URI');
        if (f & 0x00000040) out.push('GRANT_PERSISTABLE_URI');
        if (f & 0x00000080) out.push('GRANT_PREFIX_URI');
        if (f & 0x10000000) out.push('ACTIVITY_NEW_TASK');
        if (f & 0x00008000) out.push('ACTIVITY_CLEAR_TASK');
        if (out.length === 0) return '';
        var s = ' [' + out.join('|') + ']';
        if ((f & 0x03) !== 0) {
            s += '  <-- URI GRANT FLAGS SET';
        }
        return s;
    },

    /* -------------------------------------------------- Intents (outbound) -- */

    hookIntentsOut: function () {
        var self = this;
        var CW = this.cls('android.content.ContextWrapper');
        var Act = this.cls('android.app.Activity');

        function wrap(clazz, name, sigList, label) {
            self.guard(label, function () {
                if (!clazz) throw new Error('class not present');
                var m = clazz[name];
                if (!m) throw new Error('method ' + name + ' not present');
                var hooked = 0;
                m.overloads.forEach(function (o) {
                    // Hook every overload we can, not just one signature. This
                    // is what makes the script survive API-level drift.
                    try {
                        o.implementation = function () {
                            var args = Array.prototype.slice.call(arguments);
                            self.log('intent-out', label);
                            for (var n = 0; n < args.length; n++) {
                                var a = args[n];
                                if (a && a.$className === 'android.content.Intent') {
                                    self.dumpIntent(label + ' arg' + n, a);
                                }
                            }
                            return o.apply(this, args);
                        };
                        hooked++;
                    } catch (e) { /* one bad overload must not kill the rest */ }
                });
                if (hooked === 0) throw new Error('no overload could be hooked');
            });
        }

        wrap(Act, 'startActivity', null, 'Activity.startActivity');
        wrap(Act, 'startActivityForResult', null, 'Activity.startActivityForResult');
        wrap(Act, 'setResult', null, 'Activity.setResult');
        wrap(CW, 'startActivity', null, 'Context.startActivity');
        wrap(CW, 'startService', null, 'Context.startService');
        wrap(CW, 'startForegroundService', null, 'Context.startForegroundService');
        wrap(CW, 'bindService', null, 'Context.bindService');
        wrap(CW, 'sendBroadcast', null, 'Context.sendBroadcast');
        wrap(CW, 'sendOrderedBroadcast', null, 'Context.sendOrderedBroadcast');
        wrap(CW, 'sendStickyBroadcast', null, 'Context.sendStickyBroadcast');
        wrap(CW, 'sendBroadcastAsUser', null, 'Context.sendBroadcastAsUser');
        wrap(CW, 'grantUriPermission', null, 'Context.grantUriPermission');

        /*
         * A broadcast with no receiver permission and no setPackage() goes to
         * the WHOLE DEVICE. Any app that registers for the action reads the
         * extras. This is the sending-direction leak that manifest analysis
         * never shows, because there is no component to inspect.
         */
        this.guard('sendBroadcast leak detector', function () {
            if (!CW) throw new Error('ContextWrapper not present');
            CW.sendBroadcast.overload('android.content.Intent').implementation =
                function (i) {
                    self.log('intent-out', 'sendBroadcast (UNRESTRICTED)');
                    self.dumpIntent('broadcast', i);
                    var pkg = null;
                    try { pkg = i.getPackage(); } catch (e) { }
                    if (pkg === null) {
                        self.warn('no receiver permission and no setPackage() — '
                                  + 'this Intent and every extra above is '
                                  + 'readable by EVERY app on the device');
                    }
                    return this.sendBroadcast(i);
                };
        });
    },

    /* --------------------------------------------------- Intents (inbound) -- */

    hookIntentsIn: function () {
        var self = this;

        this.guard('Activity.getIntent', function () {
            var Act = Java.use('android.app.Activity');
            Act.getIntent.implementation = function () {
                var i = this.getIntent();
                self.log('intent-in', 'getIntent <- ' + this.$className);
                self.dumpIntent('received', i);
                return i;
            };
        });

        this.guard('BroadcastReceiver.onReceive', function () {
            var BR = Java.use('android.content.BroadcastReceiver');
            BR.onReceive.implementation = function (ctx, i) {
                self.log('intent-in', 'onReceive <- ' + this.$className);
                self.dumpIntent('received', i);
                return this.onReceive(ctx, i);
            };
        });

        this.guard('Service.onStartCommand / onBind', function () {
            var Svc = Java.use('android.app.Service');
            Svc.onStartCommand.implementation = function (i, flags, id) {
                self.log('intent-in', 'onStartCommand <- ' + this.$className);
                self.dumpIntent('received', i);
                return this.onStartCommand(i, flags, id);
            };
            Svc.onBind.implementation = function (i) {
                self.log('intent-in', 'onBind <- ' + this.$className);
                self.dumpIntent('received', i);
                return this.onBind(i);
            };
        });

        /*
         * Which extras does the app actually READ?
         *
         * That list is far more useful than the list it was sent. An exported
         * component reading "url", "next", "token" or "is_admin" tells you
         * exactly what to put in your attack Intent.
         */
        this.guard('Intent extra getters', function () {
            var I = Java.use('android.content.Intent');
            ['getStringExtra', 'getBooleanExtra', 'getIntExtra',
             'getParcelableExtra', 'getSerializableExtra', 'getBundleExtra',
             'getStringArrayListExtra'].forEach(function (name) {
                var m = I[name];
                if (!m) return;
                m.overloads.forEach(function (o) {
                    try {
                        o.implementation = function () {
                            var args = Array.prototype.slice.call(arguments);
                            var r = o.apply(this, args);
                            self.log('intent-in', 'READ ' + name + '("'
                                     + args[0] + '") = ' + self.trunc(r));
                            if (name === 'getParcelableExtra' && r !== null) {
                                var t = r.$className || '';
                                if (t.indexOf('Intent') !== -1) {
                                    self.warn('the app read a NESTED INTENT from '
                                        + 'an extra. If it now calls '
                                        + 'startActivity/startService/'
                                        + 'sendBroadcast on it, that is intent '
                                        + 'redirection — README 3.20');
                                }
                            }
                            return r;
                        };
                    } catch (e) { }
                });
            });
        });
    },

    /* ------------------------------------------------------- ContentProvider */

    hookProviders: function () {
        var self = this;

        this.guard('ContentResolver.*', function () {
            var CR = Java.use('android.content.ContentResolver');
            ['query', 'insert', 'update', 'delete', 'call',
             'openInputStream', 'openOutputStream', 'openFileDescriptor',
             'takePersistableUriPermission'].forEach(function (name) {
                var m = CR[name];
                if (!m) return;
                m.overloads.forEach(function (o) {
                    try {
                        o.implementation = function () {
                            var args = Array.prototype.slice.call(arguments);
                            var desc = name + '(' + self.trunc(args[0]);
                            // query(uri, projection, selection, args, sort)
                            if (name === 'query' && args.length >= 5) {
                                desc += ', projection=' + self.trunc(args[1])
                                      + ', selection=' + self.trunc(args[2])
                                      + ', selArgs=' + self.trunc(args[3])
                                      + ', sort=' + self.trunc(args[4]);
                            } else if (name === 'call' && args.length >= 3) {
                                desc += ', method=' + self.trunc(args[1])
                                      + ', arg=' + self.trunc(args[2]);
                            }
                            desc += ')';
                            self.log('provider', desc);
                            return o.apply(this, args);
                        };
                    } catch (e) { }
                });
            });
        });

        /*
         * Server side. If the app HOSTS a provider, this is where
         * attacker-controlled selection / projection / sortOrder arrive. Watch
         * for any of them being concatenated into SQL downstream.
         */
        this.guard('ContentProvider.query/call (server side)', function () {
            var CP = Java.use('android.content.ContentProvider');
            CP.query.overloads.forEach(function (o) {
                try {
                    o.implementation = function () {
                        var a = Array.prototype.slice.call(arguments);
                        self.log('provider', 'SERVED query uri=' + self.trunc(a[0])
                                 + ' projection=' + self.trunc(a[1])
                                 + ' selection=' + self.trunc(a[2])
                                 + ' sort=' + self.trunc(a[4]));
                        self.warn('selection/projection/sortOrder above are '
                                  + 'CALLER-CONTROLLED. If any reaches rawQuery '
                                  + 'or string concatenation, that is SQL '
                                  + 'injection.');
                        return o.apply(this, a);
                    };
                } catch (e) { }
            });
        });

        this.guard('SQLiteDatabase.rawQuery/execSQL', function () {
            var DB = Java.use('android.database.sqlite.SQLiteDatabase');
            ['rawQuery', 'execSQL'].forEach(function (name) {
                var m = DB[name];
                if (!m) return;
                m.overloads.forEach(function (o) {
                    try {
                        o.implementation = function () {
                            var a = Array.prototype.slice.call(arguments);
                            self.log('provider', name + ': ' + self.trunc(a[0]));
                            return o.apply(this, a);
                        };
                    } catch (e) { }
                });
            });
        });
    },

    /* ------------------------------------------------------------- Sockets -- */

    hookSockets: function () {
        var self = this;

        /*
         * THE HIGH-VALUE HOOK IN THIS WHOLE SCRIPT.
         *
         * LocalServerSocket(String) creates a socket in the Linux ABSTRACT
         * namespace: no inode, no owner, no group, no mode bits. There is not
         * even a permission to get wrong. Every app on the device can connect
         * if it knows the name. Nothing in the manifest hints that it exists.
         */
        this.guard('LocalServerSocket', function () {
            var LSS = Java.use('android.net.LocalServerSocket');
            var one = self.ovl(LSS.$init, ['java.lang.String']);
            if (one) {
                one.implementation = function (name) {
                    self.log('socket', 'LocalServerSocket("' + name + '")');
                    self.warn('ABSTRACT NAMESPACE (@' + name + '). No inode, no '
                        + 'owner, no mode bits — NOTHING protects this. Any app '
                        + 'on the device can connect. README 3.10.');
                    self.warn('probe it:  python3 abstract-socket-probe.py '
                        + '--name ' + name + ' --probe-all');
                    return one.call(this, name);
                };
            }
            var fd = self.ovl(LSS.$init, ['java.io.FileDescriptor']);
            if (fd) {
                fd.implementation = function (f) {
                    self.log('socket', 'LocalServerSocket(FileDescriptor) — '
                             + 'namespace depends on how the fd was bound');
                    return fd.call(this, f);
                };
            }
        });

        this.guard('LocalSocketAddress', function () {
            var LSA = Java.use('android.net.LocalSocketAddress');
            LSA.$init.overloads.forEach(function (o) {
                try {
                    o.implementation = function () {
                        var a = Array.prototype.slice.call(arguments);
                        var ns = (a.length > 1) ? String(a[1]) : 'ABSTRACT (default!)';
                        self.log('socket', 'LocalSocketAddress name=' + a[0]
                                 + ' namespace=' + ns);
                        if (a.length === 1) {
                            self.warn('single-argument constructor selects '
                                + 'ABSTRACT. FILESYSTEM inside getFilesDir() '
                                + 'is the safe choice.');
                        }
                        return o.apply(this, a);
                    };
                } catch (e) { }
            });
        });

        this.guard('LocalSocket.connect', function () {
            var LS = Java.use('android.net.LocalSocket');
            LS.connect.overloads.forEach(function (o) {
                try {
                    o.implementation = function () {
                        var a = Array.prototype.slice.call(arguments);
                        self.log('socket', 'LocalSocket.connect(' + a[0] + ')');
                        return o.apply(this, a);
                    };
                } catch (e) { }
            });
        });

        /*
         * TCP. new ServerSocket(port) binds 0.0.0.0 — ALL interfaces — not
         * loopback. That is the mistake hiding inside "it's only local".
         */
        this.guard('java.net.ServerSocket', function () {
            var SS = Java.use('java.net.ServerSocket');
            SS.$init.overloads.forEach(function (o) {
                try {
                    o.implementation = function () {
                        var a = Array.prototype.slice.call(arguments);
                        self.log('socket', 'new ServerSocket(' + a.join(', ') + ')');
                        if (a.length <= 2) {
                            self.warn('no bind address given — this binds '
                                + '0.0.0.0, i.e. ALL INTERFACES, so it is '
                                + 'reachable from the local network as well as '
                                + 'from every app on the device. README 3.11.');
                        }
                        return o.apply(this, a);
                    };
                } catch (e) { }
            });
            SS.bind.overloads.forEach(function (o) {
                try {
                    o.implementation = function () {
                        var a = Array.prototype.slice.call(arguments);
                        self.log('socket', 'ServerSocket.bind(' + a[0] + ')');
                        var s = String(a[0]);
                        if (s.indexOf('0.0.0.0') !== -1 || s.indexOf('/::') !== -1) {
                            self.warn('bound to ALL INTERFACES');
                        } else if (s.indexOf('127.0.0.1') !== -1) {
                            self.warn('loopback — still reachable by any app '
                                + 'holding INTERNET, which is every app');
                        }
                        return o.apply(this, a);
                    };
                } catch (e) { }
            });
        });

        this.guard('java.net.Socket.connect', function () {
            var S = Java.use('java.net.Socket');
            S.connect.overloads.forEach(function (o) {
                try {
                    o.implementation = function () {
                        var a = Array.prototype.slice.call(arguments);
                        self.log('socket', 'Socket.connect(' + a[0] + ')');
                        return o.apply(this, a);
                    };
                } catch (e) { }
            });
        });

        /*
         * Native fallback. If the socket is opened by a bundled .so, none of
         * the Java hooks above fire. libc's bind/connect always do.
         */
        this.guard('native bind/connect', function () {
            ['bind', 'connect'].forEach(function (sym) {
                var addr = Module.findExportByName('libc.so', sym);
                if (addr === null) return;
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        try {
                            var sa = args[1];
                            var family = sa.readU16() & 0xffff;
                            if (family === 1) {           // AF_UNIX
                                var first = sa.add(2).readU8();
                                var name = (first === 0)
                                    ? '@' + sa.add(3).readCString()
                                    : sa.add(2).readCString();
                                ipc.log('socket', 'native ' + sym
                                        + ' AF_UNIX ' + name);
                                if (first === 0) {
                                    ipc.warn('ABSTRACT namespace, from native '
                                        + 'code. No Java hook would have seen '
                                        + 'this.');
                                }
                            } else if (family === 2) {    // AF_INET
                                var port = ((sa.add(2).readU8() << 8)
                                            | sa.add(3).readU8());
                                var b = sa.add(4);
                                var ip = b.readU8() + '.' + b.add(1).readU8()
                                       + '.' + b.add(2).readU8() + '.'
                                       + b.add(3).readU8();
                                ipc.log('socket', 'native ' + sym + ' AF_INET '
                                        + ip + ':' + port);
                                if (sym === 'bind' && ip === '0.0.0.0') {
                                    ipc.warn('bound to ALL INTERFACES from '
                                        + 'native code');
                                }
                            }
                        } catch (e) { /* malformed sockaddr — ignore */ }
                    }
                });
            });
        });
    },

    /* -------------------------------------------------------------- Binder -- */

    hookBinder: function () {
        var self = this;

        /*
         * Server side. onTransact is where an app's own AIDL / Messenger
         * interface receives calls. getCallingUid() here is kernel-supplied and
         * trustworthy; getCallingPid() is truthful only at this instant.
         *
         * Watch for: a transaction code being handled with no getCallingUid()
         * check anywhere in the call. That is a privileged method callable by
         * any app that can bind.
         */
        this.guard('Binder.onTransact', function () {
            var B = Java.use('android.os.Binder');
            B.onTransact.implementation = function (code, data, reply, flags) {
                var uid = -1, pid = -1;
                try { uid = B.getCallingUid(); } catch (e) { }
                try { pid = B.getCallingPid(); } catch (e) { }
                self.log('binder', 'onTransact ' + this.$className
                         + ' code=' + code
                         + ' callingUid=' + uid
                         + ' callingPid=' + pid
                         + ' oneway=' + ((flags & 1) === 1));
                if (uid >= 10000) {
                    self.warn('caller is an ordinary APP uid (' + uid + '). '
                        + 'Does this method check it?');
                }
                return this.onTransact(code, data, reply, flags);
            };
        });

        this.guard('Binder.attachInterface (Stub descriptors)', function () {
            var B = Java.use('android.os.Binder');
            B.attachInterface.implementation = function (owner, descriptor) {
                self.log('binder', 'Stub descriptor "' + descriptor + '" on '
                         + (owner ? owner.$className : '?'));
                self.warn('this survives string encryption — it is set at '
                    + 'runtime. Use it to identify the AIDL interface even in '
                    + 'a heavily obfuscated app. README 6.4.');
                return this.attachInterface(owner, descriptor);
            };
        });

        this.guard('BinderProxy.transact (client side)', function () {
            var BP = Java.use('android.os.BinderProxy');
            BP.transact.implementation = function (code, data, reply, flags) {
                var desc = '?';
                try { desc = this.getInterfaceDescriptor(); } catch (e) { }
                self.log('binder', 'transact -> ' + desc + ' code=' + code);
                return this.transact(code, data, reply, flags);
            };
        });
    },

    /* ------------------------------------------------------------ adjacent -- */

    hookClipboard: function () {
        var self = this;
        this.guard('ClipboardManager', function () {
            var CM = Java.use('android.content.ClipboardManager');
            ['setPrimaryClip', 'getPrimaryClip', 'hasPrimaryClip',
             'clearPrimaryClip'].forEach(function (name) {
                var m = CM[name];
                if (!m) return;
                m.overloads.forEach(function (o) {
                    try {
                        o.implementation = function () {
                            var a = Array.prototype.slice.call(arguments);
                            var r = o.apply(this, a);
                            self.log('clipboard', name + '('
                                     + self.trunc(a[0]) + ') -> '
                                     + self.trunc(r));
                            if (name === 'setPrimaryClip') {
                                self.warn('the clipboard is a system-wide '
                                    + 'buffer. On API<=28 any app reads it at '
                                    + 'will; on 29+ whatever app the user '
                                    + 'focuses next reads it. Never a place '
                                    + 'for an OTP, password or seed phrase.');
                            }
                            return r;
                        };
                    } catch (e) { }
                });
            });
        });
    },

    hookPendingIntent: function () {
        var self = this;
        this.guard('PendingIntent.get*', function () {
            var PI = Java.use('android.app.PendingIntent');
            ['getActivity', 'getBroadcast', 'getService',
             'getForegroundService'].forEach(function (name) {
                var m = PI[name];
                if (!m) return;
                m.overloads.forEach(function (o) {
                    try {
                        o.implementation = function () {
                            var a = Array.prototype.slice.call(arguments);
                            var flags = 0;
                            for (var n = 0; n < a.length; n++) {
                                if (typeof a[n] === 'number') flags = a[n];
                            }
                            var mutable   = (flags & 0x02000000) !== 0;
                            var immutable = (flags & 0x04000000) !== 0;
                            self.log('pendingintent', 'PendingIntent.' + name
                                     + ' flags=0x' + (flags >>> 0).toString(16)
                                     + (immutable ? ' [IMMUTABLE]' : '')
                                     + (mutable ? ' [MUTABLE]' : ''));
                            for (var k = 0; k < a.length; k++) {
                                if (a[k] && a[k].$className === 'android.content.Intent') {
                                    self.dumpIntent('base intent', a[k]);
                                }
                            }
                            if (!immutable) {
                                self.warn('NOT immutable. Whoever obtains this '
                                    + 'PendingIntent can fill in its blank '
                                    + 'fields and fire it — and it executes '
                                    + 'with THIS app\'s identity and '
                                    + 'permissions. Add FLAG_IMMUTABLE.');
                            }
                            return o.apply(this, a);
                        };
                    } catch (e) { }
                });
            });
        });
    },

    hookSettings: function () {
        var self = this;
        this.guard('Settings.Secure/Global reads', function () {
            ['android.provider.Settings$Secure',
             'android.provider.Settings$Global',
             'android.provider.Settings$System'].forEach(function (cn) {
                var C = self.cls(cn);
                if (!C) return;
                ['getString', 'getInt', 'getLong'].forEach(function (name) {
                    var m = C[name];
                    if (!m) return;
                    m.overloads.forEach(function (o) {
                        try {
                            o.implementation = function () {
                                var a = Array.prototype.slice.call(arguments);
                                var r = o.apply(this, a);
                                self.log('settings', cn.split('$')[1] + '.'
                                         + name + '("' + a[1] + '") = '
                                         + self.trunc(r));
                                return r;
                            };
                        } catch (e) { }
                    });
                });
            });
        });
    },

    hookFileModes: function () {
        var self = this;
        this.guard('File.setReadable/setWritable', function () {
            var F = Java.use('java.io.File');
            ['setReadable', 'setWritable', 'setExecutable'].forEach(function (name) {
                var m = F[name];
                if (!m) return;
                m.overloads.forEach(function (o) {
                    try {
                        o.implementation = function () {
                            var a = Array.prototype.slice.call(arguments);
                            var r = o.apply(this, a);
                            self.log('filemode', name + '(' + a.join(', ')
                                     + ') on ' + this.getAbsolutePath());
                            // setReadable(true, false) == readable by EVERYONE
                            if (a.length === 2 && a[0] === true && a[1] === false) {
                                self.warn('ownerOnly=false makes this file '
                                    + 'world-readable/writable — the same '
                                    + 'exposure as MODE_WORLD_READABLE, with '
                                    + 'no SecurityException to warn anyone. '
                                    + 'README 3.14.');
                            }
                            return r;
                        };
                    } catch (e) { }
                });
            });
        });

        this.guard('Context.openFileOutput / getSharedPreferences modes', function () {
            var CW = Java.use('android.content.ContextWrapper');
            ['openFileOutput', 'getSharedPreferences', 'getDir',
             'openOrCreateDatabase'].forEach(function (name) {
                var m = CW[name];
                if (!m) return;
                m.overloads.forEach(function (o) {
                    try {
                        o.implementation = function () {
                            var a = Array.prototype.slice.call(arguments);
                            var mode = -1;
                            for (var n = 0; n < a.length; n++) {
                                if (typeof a[n] === 'number') { mode = a[n]; break; }
                            }
                            self.log('filemode', name + '("' + a[0]
                                     + '", mode=' + mode + ')');
                            if (mode & 1) self.warn('MODE_WORLD_READABLE');
                            if (mode & 2) self.warn('MODE_WORLD_WRITEABLE');
                            return o.apply(this, a);
                        };
                    } catch (e) { }
                });
            });
        });
    },

    /* ------------------------------------------------------------- control -- */

    only: function (cats) { this.enabled = cats; console.log('[*] tracing: ' + cats); },
    all:  function () { this.enabled = null; console.log('[*] tracing everything'); },
    stacks: function (b) { this.showStacks = !!b; },
    quiet: function (b) { this.quietExtras = !!b; },

    summary: function () {
        console.log('');
        console.log('=========== trace-ipc summary ===========');
        console.log(' hooks installed : ' + this.installed);
        console.log(' hooks skipped   : ' + this.skipped
                    + '  (absent on this Android version, or stripped)');
        console.log(' events by category:');
        var keys = Object.keys(this.counts).sort();
        if (keys.length === 0) {
            console.log('   (nothing yet — exercise the app)');
            console.log('   If hooks installed but never fire, the methods were');
            console.log('   compiled and inlined. Force interpretation:');
            console.log('     adb shell cmd package compile -m verify -f <pkg>');
        }
        keys.forEach(function (k) {
            console.log('   ' + k + ': ' + ipc.counts[k]);
        });
        console.log('=========================================');
    },

    start: function () {
        console.log('');
        console.log('================================================');
        console.log(' trace-ipc.js — 24-IPC');
        console.log('================================================');
        this.hookIntentsOut();
        this.hookIntentsIn();
        this.hookProviders();
        this.hookSockets();
        this.hookBinder();
        this.hookClipboard();
        this.hookPendingIntent();
        this.hookSettings();
        this.hookFileModes();
        console.log('[*] ' + this.installed + ' hook groups installed, '
                    + this.skipped + ' skipped');
        console.log('[*] REPL: ipc.only([...]), ipc.all(), ipc.stacks(true),');
        console.log('          ipc.quiet(true), ipc.summary()');
        console.log('[*] Categories: ' + this.categories.join(', '));
        console.log('');
        console.log('[!] Everything logged here happens INSIDE the target');
        console.log('    process. It shows which channels the app uses. It does');
        console.log('    NOT show whether another app can reach them — for that,');
        console.log('    build ../examples/attacker-app/ and run it.');
        console.log('');
    }
};

Java.perform(function () {
    ipc.start();
});
