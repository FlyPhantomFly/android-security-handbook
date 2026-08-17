/*
 * hook-broadcast.js -- watch an app's whole broadcast surface from inside its process.
 *
 * PURPOSE
 *   `dumpsys activity broadcasts` tells you that a process registered a filter
 *   for an action. It does NOT tell you which Java class handles it, what the
 *   handler does, whether an ordered broadcast was aborted, or what the app
 *   itself sends. This script answers all four, from inside the process.
 *
 *   It reports, for every runtime registration:
 *       receiver class name          <- absent from dumpsys entirely
 *       every action / category / scheme / data type in the filter
 *       the filter priority
 *       the broadcastPermission a sender must hold, if any
 *       the EXPORT STATE, decoded from the registerReceiver overload and flags
 *       whether a sticky Intent came back from the registration
 *
 *   and for every delivery:
 *       the receiving class, the full Intent, every extra
 *       ordered / sticky / initialSticky
 *       the incoming result code and data, for ordered chains
 *       any abortBroadcast() / setResult*() the receiver performs
 *
 *   and for every send:
 *       which sendBroadcast* overload
 *       the receiverPermission argument -- the send-side control that is
 *       invisible in any manifest
 *       whether the Intent was made explicit with setPackage/setComponent
 *
 * WHY A DISPATCHER HOOK, NOT A CLASS SWEEP
 *   The obvious approach is to enumerate loaded classes and hook every
 *   onReceive. That misses every receiver whose class is not loaded yet, which
 *   on a cold start is most of them. This script instead hooks the single
 *   choke point every context-registered receiver passes through --
 *   android.app.LoadedApk$ReceiverDispatcher$Args.getRunnable (falling back to
 *   InnerReceiver.performReceive) -- and android.app.ActivityThread's
 *   handleReceiver for manifest-declared ones. One hook, complete coverage,
 *   including classes loaded later and receivers written as lambdas or
 *   anonymous inner classes.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   * WHO SENT THE BROADCAST. This is the honest and important limitation.
 *     Every broadcast is re-dispatched by ActivityManagerService, so at the
 *     moment of delivery the Binder caller is always system_server (uid 1000),
 *     never the originating app. `bc.senderProbe()` demonstrates this rather
 *     than asserting it. The originator is recorded in exactly one place:
 *     `dumpsys activity broadcasts` -> Historical Broadcast -> `caller=`. Use
 *     scripts/receiver-surface.py --history for that.
 *   * Whether an unguarded receiver is exploitable. It shows you the handler
 *     runs; you must still show it CHANGES something.
 *   * Anything about a process you are not attached to.
 *   * Manifest-declared receivers in a process that has not started. A static
 *     receiver only wakes when a matching broadcast arrives; nothing is loaded
 *     until then. Enumerate those with `dumpsys package` or
 *     `cmd package query-receivers`, not with this.
 *   * LocalBroadcastManager traffic, unless you call bc.local(). It never
 *     touches the framework dispatcher, so the default hooks do not see it --
 *     which is also exactly why it is not attack surface.
 *   * Export state below API 33 with any precision. The flag does not exist
 *     there. The script says "EXPORTED (pre-33 default)" and means it: on those
 *     releases the only real control is broadcastPermission.
 *
 * HOW TO RUN
 *   # host -- spawn, so registrations made during Application.onCreate are seen
 *   frida -U -f com.example.target -l hook-broadcast.js
 *
 *   # host -- attach to something already running
 *   frida -U -n com.example.target -l hook-broadcast.js
 *
 *   Then, in the REPL:
 *     bc.watch()          hook everything (registrations + deliveries + sends)
 *     bc.registrations()  registerReceiver only
 *     bc.deliveries()     onReceive only
 *     bc.sends()          sendBroadcast* only
 *     bc.ordered()        abortBroadcast / setResultCode / setResultData
 *     bc.sticky()         sticky send + the sticky Intent returned by register
 *     bc.local()          androidx LocalBroadcastManager, if the app bundles it
 *     bc.senderProbe()    prove that the sender's uid is NOT visible on delivery
 *     bc.stacks(true)     include a Java stack trace with each event
 *     bc.summary()        everything observed so far, as a table
 *     bc.help()
 *
 * REQUIREMENTS
 *   frida-server on the device, matching the host frida version. Root, or a
 *   debuggable target. Tested against Android 11 / API 30 (Redmi M2101K6P) with
 *   frida 16.1.6. Every lookup is guarded, so on a release where a symbol is
 *   absent the script prints a note and continues rather than throwing.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var bc = {

    /* ---------------------------------------------------------- constants */

    // android.content.Context, added in API 33 (Tiramisu).
    RECEIVER_EXPORTED:      0x2,
    RECEIVER_NOT_EXPORTED:  0x4,
    RECEIVER_VISIBLE_TO_INSTANT_APPS: 0x1,

    // The AndroidX ContextCompat backport of RECEIVER_NOT_EXPORTED for
    // pre-33 devices: a self-defined signature permission named
    //   <package>.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
    ANDROIDX_SHIM: 'DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION',

    _withStacks: false,
    _probeSender: false,
    _deliveriesHooked: false,
    _lastKey: null,
    _lastAt: 0,
    _dupNoted: false,
    _sdk: 0,
    _pkg: '?',

    _seen: {
        registrations: [],
        deliveries: [],
        sends: [],
        aborts: []
    },

    /* -------------------------------------------------------------- utils */

    _use: function (n) { try { return Java.use(n); } catch (e) { return null; } },
    _safe: function (f, d) { try { return f(); } catch (e) { return d; } },

    _log: function (s) { console.log(s); },

    _hdr: function (t) {
        console.log('');
        console.log('=== ' + t + ' ' + new Array(Math.max(2, 68 - t.length)).join('='));
    },

    _stack: function () {
        if (!this._withStacks) return '';
        try {
            var Exception = Java.use('java.lang.Exception');
            var Log = Java.use('android.util.Log');
            return '\n' + Log.getStackTraceString(Exception.$new());
        } catch (e) {
            return '';
        }
    },

    /*
     * Render an IntentFilter the way a reviewer needs to read it: every action,
     * every category, every scheme, every data type, and the priority -- because
     * priority is the whole ordered-broadcast interception primitive and it is
     * the one field people forget to look at.
     */
    _filter: function (f, indent) {
        var self = this;
        var out = [];
        if (!f) return indent + '(null filter)';
        self._safe(function () {
            var n = f.countActions();
            for (var i = 0; i < n; i++) out.push(indent + 'action   : ' + f.getAction(i));
        });
        self._safe(function () {
            var n = f.countCategories();
            for (var i = 0; i < n; i++) out.push(indent + 'category : ' + f.getCategory(i));
        });
        self._safe(function () {
            var n = f.countDataSchemes();
            for (var i = 0; i < n; i++) out.push(indent + 'scheme   : ' + f.getDataScheme(i));
        });
        self._safe(function () {
            var n = f.countDataTypes();
            for (var i = 0; i < n; i++) out.push(indent + 'type     : ' + f.getDataType(i));
        });
        self._safe(function () {
            var n = f.countDataAuthorities();
            for (var i = 0; i < n; i++) {
                var a = f.getDataAuthority(i);
                out.push(indent + 'authority: ' + a.getHost() + ':' + a.getPort());
            }
        });
        var p = self._safe(function () { return f.getPriority(); }, 0);
        out.push(indent + 'priority : ' + p +
                 (p > 0 ? '   <-- ordered broadcasts reach this filter EARLY; it can '
                        + 'abortBroadcast()' : ''));
        if (p >= 1000) {
            out.push(indent + '           <-- 1000 and above is documented as reserved for '
                            + 'the system.');
            out.push(indent + '               A third-party app here is trying to get in '
                            + 'front of someone.');
        }
        return out.join('\n');
    },

    _intent: function (i, indent) {
        var self = this;
        if (!i) return indent + '(null intent)';
        var out = [];
        out.push(indent + 'action   : ' + self._safe(function () { return i.getAction(); }, '?'));
        var data = self._safe(function () { return i.getDataString(); }, null);
        if (data) out.push(indent + 'data     : ' + data);
        var comp = self._safe(function () {
            var c = i.getComponent();
            return c ? c.flattenToString() : null;
        }, null);
        if (comp) out.push(indent + 'component: ' + comp + '   (EXPLICIT)');
        var pkgOnly = self._safe(function () { return i.getPackage(); }, null);
        if (pkgOnly) out.push(indent + 'setPackage: ' + pkgOnly + '   (restricted to one app)');
        if (!comp && !pkgOnly) {
            out.push(indent + '           <-- IMPLICIT: every matching receiver on the '
                            + 'device is a candidate recipient');
        }
        var flags = self._safe(function () { return i.getFlags(); }, 0);
        out.push(indent + 'flags    : 0x' + (flags >>> 0).toString(16) +
                 self._decodeFlags(flags));
        self._safe(function () {
            var ex = i.getExtras();
            if (ex === null) return;
            var keys = ex.keySet().toArray();
            for (var k = 0; k < keys.length; k++) {
                var key = '' + keys[k];
                var val = self._safe(function () { return '' + ex.get(key); }, '<unreadable>');
                var mark = '';
                if (/token|secret|password|api[_.\-]?key|auth|session|jwt|otp|pin|credential/i
                        .test(key)) {
                    mark = '   <-- CANDIDATE secret travelling in a broadcast extra';
                }
                out.push(indent + 'extra[' + key + '] = ' + val + mark);
            }
        });
        return out.join('\n');
    },

    _decodeFlags: function (f) {
        // The broadcast-relevant subset of android.content.Intent flags.
        var names = [];
        if (f & 0x40000000) names.push('RECEIVER_REGISTERED_ONLY');
        if (f & 0x08000000) names.push('RECEIVER_NO_ABORT');
        if (f & 0x10000000) names.push('RECEIVER_REGISTERED_ONLY_BEFORE_BOOT');
        if (f & 0x00000010) names.push('EXCLUDE_STOPPED_PACKAGES');
        if (f & 0x00000020) names.push('INCLUDE_STOPPED_PACKAGES');
        if (f & 0x01000000) names.push('RECEIVER_FOREGROUND');
        if (f & 0x00400000) names.push('FROM_BACKGROUND');
        return names.length ? '  [' + names.join(', ') + ']' : '';
    },

    /*
     * Decode the export state of one registration.
     *
     * Below API 33 there is no flag: a context-registered receiver is reachable
     * by any sender, full stop, unless a broadcastPermission is supplied. From
     * API 33 a targetSdk-33 app MUST pass one of the two flags for a
     * non-system action, and the platform throws if it does not.
     */
    _exportState: function (perm, flags, overload) {
        var self = this;
        if (flags !== null && flags !== undefined) {
            if (flags & self.RECEIVER_NOT_EXPORTED) {
                return 'NOT_EXPORTED (explicit)  -- only this app and the system reach it';
            }
            if (flags & self.RECEIVER_EXPORTED) {
                return 'EXPORTED (explicit)  <-- any app may send to it' +
                       (perm ? ', if it holds ' + perm : ', with NO permission required');
            }
        }
        if (perm) {
            if (('' + perm).indexOf(self.ANDROIDX_SHIM) !== -1) {
                return 'NOT_EXPORTED (AndroidX backport)  -- the library invented a ' +
                       'signature permission\n                     to emulate a flag ' +
                       'this API level does not have';
            }
            return 'guarded: sender must hold ' + perm +
                   '\n                     <-- resolve its protectionLevel; a `normal` ' +
                   'permission guards nothing';
        }
        if (self._sdk >= 33) {
            return 'UNSPECIFIED on API ' + self._sdk + ' -- if targetSdk >= 33 this call ' +
                   'should have thrown;\n                     the app is probably ' +
                   'targeting lower. Treat as EXPORTED.';
        }
        return 'EXPORTED (pre-33 default, ' + overload + ')  <-- ANY app can send to this ' +
               'receiver';
    },

    /* --------------------------------------------------------------- init */

    init: function () {
        var self = this;
        Java.perform(function () {
            var Build = self._use('android.os.Build$VERSION');
            self._sdk = Build ? self._safe(function () { return Build.SDK_INT.value; }, 0) : 0;
            var AT = self._use('android.app.ActivityThread');
            if (AT) {
                var app = self._safe(function () { return AT.currentApplication(); }, null);
                if (app) {
                    self._pkg = self._safe(function () { return app.getPackageName(); }, '?');
                }
            }
        });
        this._log('[+] package = ' + this._pkg + '   API = ' + this._sdk);
        if (this._sdk && this._sdk < 33) {
            this._log('[!] API ' + this._sdk + ' < 33: RECEIVER_EXPORTED / '
                      + 'RECEIVER_NOT_EXPORTED do not exist here.');
            this._log('    Every runtime registration without a broadcastPermission is '
                      + 'reachable by any app.');
        }
        return true;
    },

    /* ------------------------------------------------------ registrations */

    registrations: function () {
        var self = this;
        self._hdr('registerReceiver -- the surface no manifest contains');

        Java.perform(function () {
            var targets = ['android.content.ContextWrapper', 'android.app.ContextImpl'];
            var hooked = 0;

            targets.forEach(function (cls) {
                var C = self._use(cls);
                if (C === null || !C.registerReceiver) return;

                var overloads = self._safe(function () {
                    return C.registerReceiver.overloads;
                }, []);

                overloads.forEach(function (ov) {
                    var argTypes = self._safe(function () {
                        return ov.argumentTypes.map(function (t) { return t.className; });
                    }, []);
                    // Only the public app-facing shapes; skip the *AsUser variants'
                    // UserHandle forms, which an app cannot call without a system
                    // permission anyway.
                    if (argTypes.length < 2) return;
                    if (argTypes[0] !== 'android.content.BroadcastReceiver') return;

                    try {
                        ov.implementation = function () {
                            var args = Array.prototype.slice.call(arguments);
                            var recv = args[0];
                            var filter = args[1];
                            var perm = null;
                            var flags = null;
                            for (var i = 2; i < args.length; i++) {
                                if (argTypes[i] === 'java.lang.String') perm = args[i];
                                if (argTypes[i] === 'int') flags = args[i];
                            }

                            var cname = recv ? recv.$className : 'null';
                            var state = self._exportState(perm, flags,
                                                          argTypes.length + '-arg');

                            /*
                             * ONE registerReceiver call reaches us more than once.
                             * ContextWrapper.registerReceiver delegates to
                             * ContextImpl.registerReceiver, which delegates again to
                             * the widest internal overload. Hooking every layer is
                             * what guarantees we also catch code that holds a
                             * ContextImpl directly -- but it means the same
                             * registration logs two or three times. Collapse the
                             * repeats, and say so once rather than silently.
                             */
                            var key = cname + '|' + self._filter(filter, '');
                            var now = Date.now();
                            if (self._lastKey === key && (now - self._lastAt) < 100) {
                                self._lastAt = now;
                                if (!self._dupNoted) {
                                    self._dupNoted = true;
                                    self._log('    (later layers of this same call are ' +
                                              'collapsed; see the script header)');
                                }
                                return ov.apply(this, args);
                            }
                            self._lastKey = key;
                            self._lastAt = now;

                            self._log('');
                            self._log('[registerReceiver] ' + cls.split('.').pop() +
                                      '(' + argTypes.length + ' args)');
                            self._log('    class      : ' + cname);
                            self._log('    export     : ' + state);
                            if (flags !== null) {
                                self._log('    flags      : 0x' + (flags >>> 0).toString(16));
                            }
                            self._log(self._filter(filter, '    '));

                            var ret = ov.apply(this, args);

                            // The return value of registerReceiver is the last STICKY
                            // Intent matching the filter, or null. A non-null return is
                            // proof that a sticky broadcast is being used -- and that
                            // its contents are readable by anyone who registers.
                            if (ret !== null && ret !== undefined) {
                                self._log('    STICKY     : registration returned a ' +
                                          'retained Intent.');
                                self._log('                 Anyone who registers for this ' +
                                          'filter reads the same value.');
                                self._log(self._intent(ret, '                 '));
                            }

                            self._seen.registrations.push({
                                cls: cname, perm: '' + perm, flags: flags, state: state
                            });
                            self._log(self._stack());
                            return ret;
                        };
                        hooked++;
                    } catch (e) { /* overload not hookable on this release */ }
                });
            });

            self._log('[*] hooked ' + hooked + ' registerReceiver overload(s).');
            if (hooked === 0) {
                self._log('[!] none matched. Enumerate them yourself:');
                self._log('    Java.use("android.content.ContextWrapper")' +
                          '.registerReceiver.overloads.forEach(o => console.log(o))');
            }

            // unregisterReceiver closes the window. Knowing WHEN a receiver
            // disappears matters: a receiver registered in onResume and
            // unregistered in onPause is reachable only while the app is in the
            // foreground, which changes both severity and how you reproduce it.
            var CW = self._use('android.content.ContextWrapper');
            if (CW && CW.unregisterReceiver) {
                try {
                    CW.unregisterReceiver.implementation = function (r) {
                        self._log('[unregisterReceiver] ' +
                                  (r ? r.$className : 'null') +
                                  '   <-- the window for this receiver just closed');
                        return this.unregisterReceiver(r);
                    };
                } catch (e) { /* ignore */ }
            }
        });
    },

    /* ---------------------------------------------------------- deliveries */

    deliveries: function () {
        var self = this;
        self._hdr('onReceive -- every delivery, from one dispatcher choke point');

        Java.perform(function () {
            var hooked = 0;

            /*
             * Context-registered receivers.
             *
             * android.app.LoadedApk$ReceiverDispatcher$Args carries the delivery
             * across the Handler hop and calls onReceive from its Runnable. Hooking
             * it catches every context-registered receiver in the process,
             * including classes not yet loaded when this script ran.
             */
            var Args = self._use('android.app.LoadedApk$ReceiverDispatcher$Args');
            if (Args !== null && Args.getRunnable) {
                try {
                    Args.getRunnable.implementation = function () {
                        self._report(this, 'context-registered');
                        return this.getRunnable();
                    };
                    hooked++;
                } catch (e) {
                    self._log('[!] Args.getRunnable hook failed: ' + e);
                }
            }

            /*
             * The binder-thread entry point, present on every release. Hooking it
             * as well gives ordered/sticky flags directly from the framework and
             * covers releases where Args.getRunnable is absent or inlined.
             */
            var Inner = self._use('android.app.LoadedApk$ReceiverDispatcher$InnerReceiver');
            if (Inner !== null && Inner.performReceive) {
                self._safe(function () {
                    Inner.performReceive.overload(
                        'android.content.Intent', 'int', 'java.lang.String',
                        'android.os.Bundle', 'boolean', 'boolean', 'int'
                    ).implementation = function (intent, code, data, extras,
                                                 ordered, sticky, user) {
                        self._log('');
                        self._log('[deliver] context-registered receiver, from the ' +
                                  'binder thread');
                        if (self._probeSender) self._senderLines(intent);
                        self._log('    ordered=' + ordered + '  sticky=' + sticky +
                                  '  resultCode=' + code +
                                  '  resultData=' + data + '  user=' + user);
                        if (ordered) {
                            self._log('    <-- ORDERED: this receiver may call ' +
                                      'abortBroadcast() and stop the chain,');
                            self._log('        or setResultData() and change what the ' +
                                      'next receiver sees.');
                        }
                        if (sticky) {
                            self._log('    <-- STICKY: this value was retained by the ' +
                                      'system and is replayed');
                            self._log('        to every later registrant. It is not ' +
                                      'protectable.');
                        }
                        self._log(self._intent(intent, '    '));
                        self._seen.deliveries.push({
                            action: self._safe(function () { return '' + intent.getAction(); }, '?'),
                            ordered: ordered, sticky: sticky
                        });
                        return this.performReceive(intent, code, data, extras,
                                                   ordered, sticky, user);
                    };
                    hooked++;
                });
            }

            /*
             * Manifest-declared receivers take a different path entirely: AMS
             * starts the process if needed and ActivityThread.handleReceiver
             * instantiates the class and calls onReceive directly.
             */
            var AT = self._use('android.app.ActivityThread');
            if (AT !== null && AT.handleReceiver) {
                self._safe(function () {
                    AT.handleReceiver.implementation = function (data) {
                        var intent = self._safe(function () { return data.intent.value; }, null);
                        var info = self._safe(function () { return data.info.value; }, null);
                        self._log('');
                        self._log('[deliver] MANIFEST-declared receiver');
                        if (info) {
                            self._log('    component  : ' +
                                      self._safe(function () { return info.name.value; }, '?'));
                            self._log('    exported   : ' +
                                      self._safe(function () { return info.exported.value; }, '?'));
                            self._log('    permission : ' +
                                      self._safe(function () { return info.permission.value; },
                                                 'NONE'));
                        }
                        if (intent) self._log(self._intent(intent, '    '));
                        self._log('    <-- this delivery started a process if one was not ' +
                                  'running. That is the');
                        self._log('        difference that matters: a manifest receiver is ' +
                                  'reachable even when');
                        self._log('        the app has never been opened.');
                        return this.handleReceiver(data);
                    };
                    hooked++;
                });
            }

            self._log('[*] hooked ' + hooked + ' delivery path(s).');
            self._log('    Coverage is by DISPATCHER, not by class, so receivers whose');
            self._log('    classes load later are still caught.');
            self._deliveriesHooked = true;
        });
    },

    _report: function (argsObj, kind) {
        var self = this;
        var intent = self._safe(function () { return argsObj.mCurIntent.value; }, null);
        if (intent === null) {
            intent = self._safe(function () { return argsObj.getIntent(); }, null);
        }
        self._log('');
        self._log('[deliver] ' + kind);
        self._log(self._intent(intent, '    '));
    },

    /* --------------------------------------------------------------- sends */

    sends: function () {
        var self = this;
        self._hdr('sendBroadcast* -- what this app puts on the bus');

        Java.perform(function () {
            var names = ['sendBroadcast', 'sendBroadcastAsUser', 'sendOrderedBroadcast',
                         'sendOrderedBroadcastAsUser', 'sendStickyBroadcast',
                         'sendStickyOrderedBroadcast', 'removeStickyBroadcast'];
            var hooked = 0;

            ['android.content.ContextWrapper', 'android.app.ContextImpl'].forEach(function (cls) {
                var C = self._use(cls);
                if (C === null) return;

                names.forEach(function (m) {
                    if (!C[m]) return;
                    var overloads = self._safe(function () { return C[m].overloads; }, []);
                    overloads.forEach(function (ov) {
                        var argTypes = self._safe(function () {
                            return ov.argumentTypes.map(function (t) { return t.className; });
                        }, []);
                        if (argTypes.length === 0 ||
                            argTypes[0] !== 'android.content.Intent') return;
                        try {
                            ov.implementation = function () {
                                var args = Array.prototype.slice.call(arguments);
                                var intent = args[0];
                                // The receiverPermission argument, when the overload
                                // has one, is the send-side control: only apps holding
                                // it will receive. It appears in NO manifest.
                                var rperm = null;
                                for (var i = 1; i < args.length; i++) {
                                    if (argTypes[i] === 'java.lang.String' &&
                                        args[i] !== null) { rperm = args[i]; break; }
                                }
                                self._log('');
                                self._log('[' + m + '] (' + argTypes.length + ' args)');
                                if (m.indexOf('Sticky') !== -1) {
                                    self._log('    <-- STICKY. Deprecated since API 21 ' +
                                              'because there is NO way to protect it:');
                                    self._log('        the value is retained by the ' +
                                              'system and handed to every app that');
                                    self._log('        later registers a matching ' +
                                              'filter, permission or not.');
                                }
                                if (m.indexOf('Ordered') !== -1) {
                                    self._log('    <-- ORDERED. Delivered one receiver ' +
                                              'at a time, highest priority first.');
                                    self._log('        A higher-priority receiver in ' +
                                              'another app can abort it or');
                                    self._log('        rewrite the result before this ' +
                                              'app\'s own receiver runs.');
                                }
                                self._log('    receiverPermission: ' +
                                          (rperm === null
                                              ? 'NONE  <-- every app with a matching ' +
                                                'filter receives this'
                                              : rperm + '  (only holders receive it)'));
                                self._log(self._intent(intent, '    '));
                                self._seen.sends.push({
                                    method: m,
                                    perm: '' + rperm,
                                    action: self._safe(function () {
                                        return '' + intent.getAction(); }, '?')
                                });
                                self._log(self._stack());
                                return ov.apply(this, args);
                            };
                            hooked++;
                        } catch (e) { /* ignore */ }
                    });
                });
            });
            self._log('[*] hooked ' + hooked + ' send overload(s).');
        });
    },

    /* ------------------------------------------------------------ ordered */

    ordered: function () {
        var self = this;
        self._hdr('ordered-broadcast controls -- abort and result rewriting');

        Java.perform(function () {
            var BR = self._use('android.content.BroadcastReceiver');
            if (BR === null) { self._log('[-] BroadcastReceiver not found'); return; }

            var pairs = [
                ['abortBroadcast', 'ABORTED the chain -- no lower-priority receiver in ' +
                                   'ANY app will see this broadcast'],
                ['clearAbortBroadcast', 'cleared a previous abort'],
                ['setResultCode', 'rewrote the result CODE the next receiver sees'],
                ['setResultData', 'rewrote the result DATA the next receiver sees'],
                ['setResultExtras', 'rewrote the result EXTRAS the next receiver sees'],
                ['goAsync', 'took the delivery off the main thread -- the receiver is ' +
                            'still alive after onReceive returns']
            ];

            pairs.forEach(function (p) {
                if (!BR[p[0]]) return;
                self._safe(function () {
                    BR[p[0]].overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            var args = Array.prototype.slice.call(arguments);
                            self._log('[' + p[0] + '] ' + this.$className +
                                      (args.length ? '  args=' + args.join(', ') : ''));
                            self._log('    <-- ' + p[1]);
                            self._seen.aborts.push({ method: p[0], cls: this.$className });
                            return ov.apply(this, args);
                        };
                    });
                });
            });
            self._log('[*] ordered-broadcast controls hooked.');
            self._log('    If you see abortBroadcast from a receiver you did not write,');
            self._log('    on an action you care about, that is interception -- and the');
            self._log('    filter priority in the registration log tells you how it won.');
        });
    },

    /* ------------------------------------------------------------- sticky */

    sticky: function () {
        this._hdr('sticky broadcasts');
        this._log('  Sticky sends are covered by bc.sends(); the sticky Intent handed');
        this._log('  back by registerReceiver is covered by bc.registrations().');
        this._log('');
        this._log('  Why sticky is deprecated, in one sentence: the retained value has');
        this._log('  no sender permission, no receiver permission and no expiry, so any');
        this._log('  app that registers a matching filter -- at any later time, without');
        this._log('  having been running when it was sent -- reads it.');
        this.registrations();
        this.sends();
    },

    /* -------------------------------------------------------------- local */

    local: function () {
        var self = this;
        self._hdr('LocalBroadcastManager -- in-process, and therefore NOT attack surface');
        Java.perform(function () {
            var names = ['androidx.localbroadcastmanager.content.LocalBroadcastManager',
                         'android.support.v4.content.LocalBroadcastManager'];
            var found = 0;
            names.forEach(function (n) {
                var L = self._use(n);
                if (L === null) return;
                found++;
                ['sendBroadcast', 'sendBroadcastSync', 'registerReceiver'].forEach(function (m) {
                    if (!L[m]) return;
                    self._safe(function () {
                        L[m].overloads.forEach(function (ov) {
                            ov.implementation = function () {
                                var args = Array.prototype.slice.call(arguments);
                                self._log('[LBM.' + m + '] ' +
                                          (args[0] ? args[0].toString() : 'null'));
                                return ov.apply(this, args);
                            };
                        });
                    });
                });
            });
            if (found === 0) {
                self._log('  This app does not bundle LocalBroadcastManager.');
            } else {
                self._log('  Hooked. Note that none of this traffic reaches AMS, so it');
                self._log('  appears in no dumpsys and cannot be sent or read by another');
                self._log('  app. Seeing an app move to LocalBroadcastManager is a FIX,');
                self._log('  not a finding.');
            }
        });
    },

    /* -------------------------------------------------------- sender probe */

    /*
     * The measurement behind this chapter's "you cannot see who sent it" claim.
     *
     * Inside onReceive, Binder.getCallingUid() does not return the app that
     * called sendBroadcast. Every broadcast is re-dispatched BY
     * ActivityManagerService, so the Binder peer at delivery time is
     * system_server. This prints the numbers so you can see it rather than
     * being told it.
     */
    _senderLines: function (intent) {
        var self = this;
        Java.perform(function () {
            var Binder = self._use('android.os.Binder');
            var Process = self._use('android.os.Process');
            if (Binder === null) return;
            var callingUid = self._safe(function () { return Binder.getCallingUid(); }, -1);
            var callingPid = self._safe(function () { return Binder.getCallingPid(); }, -1);
            var myUid = Process ? self._safe(function () { return Process.myUid(); }, -1) : -1;
            self._log('    [senderProbe] Binder.getCallingUid() = ' + callingUid +
                      (callingUid === 1000
                          ? '   <-- system_server, NOT the app that sent it'
                          : ''));
            self._log('                  Binder.getCallingPid() = ' + callingPid);
            self._log('                  Process.myUid()        = ' + myUid +
                      '   (this app)');
            self._log('                  The originating app is recorded ONLY in AMS:');
            self._log('                  dumpsys activity broadcasts -> Historical ' +
                      'Broadcast -> caller=');
        });
    },

    senderProbe: function () {
        this._hdr('who sent it? -- measuring, not asserting');
        this._probeSender = true;
        if (!this._deliveriesHooked) {
            this.deliveries();
        }
        this._log('[*] probe armed; it rides along with the delivery hook rather than');
        this._log('    replacing it. Send a broadcast the app listens for, e.g.');
        this._log('    adb shell am broadcast -a <action>');
    },

    /* ------------------------------------------------------------- extras */

    stacks: function (on) {
        this._withStacks = (on !== false);
        this._log('[*] Java stack traces ' + (this._withStacks ? 'ON' : 'OFF'));
    },

    watch: function () {
        this.registrations();
        this.deliveries();
        this.sends();
        this.ordered();
        this._hdr('ARMED');
        this._log('  Exercise the app. Then, from the host, fire at it:');
        this._log('    adb shell am broadcast -a <action> --es key value');
        this._log('  Remember that `am broadcast` sends an ORDERED broadcast and that');
        this._log('  adb shell is uid 2000 -- neither is what an ordinary attacker app');
        this._log('  looks like. Confirm from a real app before you report anything.');
    },

    summary: function () {
        var self = this;
        self._hdr('OBSERVED SO FAR');

        self._log('  registrations : ' + self._seen.registrations.length);
        self._seen.registrations.forEach(function (r) {
            self._log('    ' + r.cls);
            self._log('        ' + r.state);
        });
        self._log('');
        self._log('  deliveries    : ' + self._seen.deliveries.length);
        var byAction = {};
        self._seen.deliveries.forEach(function (d) {
            byAction[d.action] = (byAction[d.action] || 0) + 1;
        });
        Object.keys(byAction).forEach(function (a) {
            self._log('    ' + byAction[a] + '  ' + a);
        });
        self._log('');
        self._log('  sends         : ' + self._seen.sends.length);
        self._seen.sends.forEach(function (s) {
            self._log('    ' + s.method + '  ' + s.action + '  perm=' + s.perm);
        });
        self._log('');
        self._log('  abort/result  : ' + self._seen.aborts.length);
        self._seen.aborts.forEach(function (a) {
            self._log('    ' + a.method + '  ' + a.cls);
        });
        self._log('');
        self._log('  None of this is a finding on its own. Pair an unguarded receiver');
        self._log('  with a forgeable action and a demonstrated state change.');
    },

    help: function () {
        console.log([
            '',
            'bc.watch()          registrations + deliveries + sends + ordered controls',
            'bc.registrations()  registerReceiver: class, filter, priority, export state',
            'bc.deliveries()     onReceive, via the dispatcher (catches unloaded classes)',
            'bc.sends()          sendBroadcast* incl. the receiverPermission argument',
            'bc.ordered()        abortBroadcast / setResultCode / setResultData / goAsync',
            'bc.sticky()         sticky sends and retained Intents',
            'bc.local()          LocalBroadcastManager, if bundled',
            'bc.senderProbe()    measure that the sender uid is NOT visible on delivery',
            'bc.stacks(true)     add Java stack traces to every event',
            'bc.summary()        table of everything observed',
            '',
            'The sender of a broadcast is recorded ONLY by AMS. For that, use',
            '  python3 receiver-surface.py --history --with-extras',
            ''
        ].join('\n'));
    }
};

/* ------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== hook-broadcast ===');
    bc.init();
    console.log('[+] Ready. bc.help() for commands, bc.watch() to hook everything.');
    console.log('');
});
