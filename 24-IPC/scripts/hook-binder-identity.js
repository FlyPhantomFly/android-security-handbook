/*
 * hook-binder-identity.js — expose the confused-deputy pattern by watching how
 * an app handles the identity of its Binder callers.
 *
 * WHAT IT DOES
 *   Hooks the four methods that decide, in every Android service, whether a
 *   caller is allowed to do what it just asked for:
 *
 *     Binder.getCallingUid()          who is calling — kernel-supplied, safe
 *     Binder.getCallingUidOrThrow()   the same, but refuses outside a transaction
 *     Binder.getCallingPid()          which PROCESS is calling — racy, log only
 *     Binder.clearCallingIdentity()   "run the next bit as ME, not as them"
 *     Binder.restoreCallingIdentity() put the caller's identity back
 *
 *   plus the permission-check helpers (checkCallingPermission,
 *   enforceCallingPermission, checkCallingOrSelfPermission and friends) and
 *   Binder.onTransact, which brackets each incoming call.
 *
 *   From that it maintains a small state machine per binder thread and reports,
 *   with a Java stack trace, the four vulnerability patterns from README 3.21.2:
 *
 *     Pattern 1  clearCallingIdentity() called BEFORE the caller was checked,
 *                so the check evaluates the service against itself and always
 *                passes
 *     Pattern 2  the cleared window is too WIDE — attacker-influenced work runs
 *                with elevated identity
 *     Pattern 3  a transaction ended with identity still cleared, i.e. the
 *                restore was not in a finally block. The binder thread is
 *                POOLED and reused, so the NEXT transaction inherits it
 *     Pattern 4  restores that are not strictly LIFO, or a token restored twice
 *
 *   It also flags every getCallingPid() whose value is used to look something
 *   up, because that is a time-of-check-to-time-of-use race (see below).
 *
 * WHY IT MATTERS
 *   Binder tells the receiver, truthfully, who is calling — and then does
 *   nothing else. Deciding whether that caller is allowed is entirely the
 *   receiver's job. Every application-level IPC vulnerability in this chapter is
 *   ultimately a failure of that decision, and the failures cluster in exactly
 *   these five methods.
 *
 *   ------------------------------------------------------------------------
 *   WHY getCallingUid() IS TRUSTWORTHY AND getCallingPid() IS NOT
 *   ------------------------------------------------------------------------
 *
 *   getCallingUid() returns a UID. A UID is a property of the INSTALLATION of
 *   an application: PackageManagerService assigns it at install time and it
 *   does not change while the app remains installed. Crucially, the value does
 *   not come from anything the caller put in the message. When the binder
 *   driver builds a transaction in binder_transaction() it copies the sender's
 *   effective UID out of the calling task's kernel-held credentials, and
 *   IPCThreadState stores it in thread-local state for the duration of the
 *   call. There is nothing in the parcel a caller could alter to change it. If
 *   getCallingUid() returns 10250, then UID 10250 really made this call.
 *   Authorise on it.
 *
 *   getCallingPid() returns a PID, and a PID identifies a RUNNING PROCESS.
 *   Processes are short-lived. The value is truthful at the instant the driver
 *   stamped it, but by the time your code reads it, decides something, and goes
 *   and looks something up with it, the calling process may have exited and the
 *   kernel may have recycled that PID number for a completely different — and
 *   possibly more privileged — process. Linux allocates PIDs sequentially and
 *   wraps at /proc/sys/kernel/pid_max, so an attacker who can spawn processes
 *   rapidly can, with patience, arrange for a chosen number to come back
 *   around. The dangerous shape is therefore not "reading the PID" but
 *   "reading the PID and then LOOKING SOMETHING UP with it":
 *
 *       int pid = Binder.getCallingPid();
 *       String name = readAll(new File("/proc/" + pid + "/cmdline"));   // race
 *       if ("com.example.trusted".equals(name.trim())) doPrivilegedThing();
 *
 *   Between the transaction arriving and that file being read, /proc/<pid> may
 *   describe somebody else entirely. Use the PID for log lines and for
 *   diagnostics. Never use it for a decision.
 *
 *   See ../README.md sections 3.20 and 3.21.
 *
 * HOW TO RUN
 *   # host
 *   frida -U -f com.example.target -l hook-binder-identity.js
 *   frida -U -n com.example.target -l hook-binder-identity.js -o identity.log
 *
 *   REPL controls:
 *     bid.stacks(true)     print a Java stack for every event, not just alerts
 *     bid.verbose(true)    log every getCallingUid/Pid, not just the notable ones
 *     bid.report()         the per-pattern tally and the alert list so far
 *     bid.reset()          clear counters between test cases
 *
 * REQUIREMENTS
 *   frida-server matching your host frida. Android 5+ (API 21+).
 *
 *   Most useful against apps that HOST an AIDL or Messenger service — a
 *   companion-app pairing, an SDK with a bound service, an OEM or system app.
 *   In an ordinary third-party app clearCallingIdentity is rare. In a
 *   privileged APK it is where the interesting bugs live, because that is where
 *   there is authority worth borrowing.
 *
 *   If nothing fires at all, the methods were compiled and inlined:
 *     adb shell cmd package compile -m verify -f com.example.target
 *     adb shell am force-stop com.example.target
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var bid = {

    /* --------------------------------------------------------------- state -- */

    showStacks: false,
    isVerbose: false,

    // Per-thread state. Binder threads are pooled and reused, which is exactly
    // why Pattern 3 matters, so everything is keyed by thread id.
    threads: {},

    alerts: [],
    counts: { p1: 0, p2: 0, p3: 0, p4: 0, pidUse: 0, uidCheck: 0, cleared: 0 },
    installed: 0,
    skipped: 0,

    tid: function () {
        return Process.getCurrentThreadId();
    },

    st: function () {
        var t = this.tid();
        if (!this.threads[t]) {
            this.threads[t] = {
                inTransact: false,
                transactClass: null,
                transactCode: -1,
                callingUid: -1,
                checkedUid: false,      // did the code ask who is calling?
                checkedPerm: false,     // did it run a permission check?
                clearDepth: 0,
                tokens: [],             // stack of tokens, for LIFO checking
                clearedAt: null,        // stack where the clear happened
                opsWhileCleared: 0      // how much work ran with elevated identity
            };
        }
        return this.threads[t];
    },

    /* ------------------------------------------------------------ plumbing -- */

    guard: function (label, fn) {
        try { fn(); this.installed++; }
        catch (e) { this.skipped++; console.log('[skip] ' + label + ' — ' + e.message); }
    },

    log: function (msg) { console.log('[identity] ' + msg); },

    alert: function (pattern, msg) {
        var line = '\n!! ' + pattern + ' !! ' + msg;
        console.log(line);
        this.alerts.push(pattern + ': ' + msg);
        this.stack();
    },

    stack: function () {
        try {
            var Log = Java.use('android.util.Log');
            var Ex = Java.use('java.lang.Exception');
            console.log(Log.getStackTraceString(Ex.$new()));
        } catch (e) { /* best effort */ }
    },

    shortStack: function () {
        try {
            var Log = Java.use('android.util.Log');
            var Ex = Java.use('java.lang.Exception');
            var s = Log.getStackTraceString(Ex.$new()).split('\n');
            // Skip the frames belonging to the hook itself.
            return s.slice(1, 5).join(' | ').replace(/\s+at\s+/g, ' ');
        } catch (e) { return '<no stack>'; }
    },

    /* ---------------------------------------------------------- the hooks --- */

    hookOnTransact: function () {
        var self = this;

        /*
         * onTransact brackets one incoming call. We use those brackets for two
         * things:
         *
         *   - to know whether a getCallingUid() we see is a genuine caller
         *     check or just incidental;
         *   - to detect Pattern 3, by asserting at the END of the transaction
         *     that identity was restored. If it was not, the pooled thread
         *     carries the elevated identity into the next, unrelated call.
         */
        this.guard('Binder.onTransact', function () {
            var B = Java.use('android.os.Binder');
            B.onTransact.implementation = function (code, data, reply, flags) {
                var s = self.st();
                s.inTransact = true;
                s.transactClass = this.$className;
                s.transactCode = code;
                s.checkedUid = false;
                s.checkedPerm = false;
                s.opsWhileCleared = 0;
                var depthAtEntry = s.clearDepth;

                var uid = -1, pid = -1;
                try { uid = B.getCallingUid(); } catch (e) { }
                try { pid = B.getCallingPid(); } catch (e) { }
                s.callingUid = uid;

                self.log('--> onTransact ' + this.$className + ' code=' + code
                         + ' uid=' + uid + ' pid=' + pid);

                var result;
                try {
                    result = this.onTransact(code, data, reply, flags);
                } finally {
                    // ---- Pattern 3: identity not restored -------------------
                    if (s.clearDepth > depthAtEntry) {
                        self.counts.p3++;
                        self.alert('PATTERN 3 — IDENTITY NOT RESTORED',
                            this.$className + ' code=' + code + ' returned with '
                            + (s.clearDepth - depthAtEntry) + ' outstanding '
                            + 'clearCallingIdentity() call(s).\n'
                            + '   The restore was not in a finally block, or an '
                            + 'exception escaped it.\n'
                            + '   Binder threads are POOLED AND REUSED: the next '
                            + 'transaction on this thread\n'
                            + '   will run with the wrong identity, and its '
                            + 'permission checks will evaluate\n'
                            + '   the service against itself.\n'
                            + '   Fix: long t = Binder.clearCallingIdentity(); '
                            + 'try { ... } finally { Binder.restoreCallingIdentity(t); }');
                        s.clearDepth = depthAtEntry;
                        s.tokens = [];
                    }

                    // ---- no caller check at all ------------------------------
                    if (uid >= 10000 && !s.checkedUid && !s.checkedPerm) {
                        self.alert('NO CALLER CHECK',
                            this.$className + ' handled transaction code ' + code
                            + ' for APP uid ' + uid + '\n'
                            + '   without calling getCallingUid(), '
                            + 'getCallingUidOrThrow() or any permission check.\n'
                            + '   If this service is exported, that method is '
                            + 'callable by ANY app on the device.\n'
                            + '   Confirm the export state and the guarding '
                            + 'permission\'s protectionLevel:\n'
                            + '     adb shell dumpsys package <pkg> | grep -A3 '
                            + '<ServiceName>');
                    }
                    s.inTransact = false;
                    self.log('<-- onTransact ' + this.$className
                             + ' code=' + code
                             + ' checkedUid=' + s.checkedUid
                             + ' checkedPerm=' + s.checkedPerm);
                }
                return result;
            };
        });
    },

    hookIdentityReads: function () {
        var self = this;

        this.guard('Binder.getCallingUid', function () {
            var B = Java.use('android.os.Binder');
            B.getCallingUid.implementation = function () {
                var r = this.getCallingUid();
                var s = self.st();
                self.counts.uidCheck++;

                if (s.clearDepth > 0) {
                    /*
                     * PATTERN 1, in its purest and most dangerous form.
                     *
                     * Identity was already cleared, so getCallingUid() no longer
                     * returns the CALLER's uid — it returns this process's OWN
                     * uid. Any comparison made against it therefore compares the
                     * service with itself and always succeeds. The check reads
                     * like a check and enforces nothing.
                     */
                    self.counts.p1++;
                    self.alert('PATTERN 1 — CHECK AFTER CLEAR',
                        'getCallingUid() returned ' + r + ' while identity was '
                        + 'CLEARED.\n'
                        + '   This is NOT the caller. It is this process\'s own '
                        + 'uid, so any comparison\n'
                        + '   against it passes unconditionally. The '
                        + 'authorisation check is inert.\n'
                        + '   Fix: capture and check the identity FIRST, then '
                        + 'clear only around the\n'
                        + '        privileged step:\n'
                        + '          int uid = Binder.getCallingUidOrThrow();\n'
                        + '          enforceCallerIsTrusted(uid);\n'
                        + '          long t = Binder.clearCallingIdentity();\n'
                        + '          try { privilegedStep(); } finally { '
                        + 'Binder.restoreCallingIdentity(t); }');
                } else {
                    s.checkedUid = true;
                    if (self.isVerbose) {
                        self.log('getCallingUid() = ' + r + '  '
                                 + self.shortStack());
                    }
                }
                return r;
            };
        });

        this.guard('Binder.getCallingUidOrThrow', function () {
            var B = Java.use('android.os.Binder');
            if (!B.getCallingUidOrThrow) throw new Error('not present on this API level');
            B.getCallingUidOrThrow.implementation = function () {
                var r = this.getCallingUidOrThrow();
                self.st().checkedUid = true;
                if (self.isVerbose) {
                    self.log('getCallingUidOrThrow() = ' + r
                             + '  (good: throws outside a transaction, so it '
                             + 'cannot silently return our own uid)');
                }
                return r;
            };
        });

        this.guard('Binder.getCallingPid', function () {
            var B = Java.use('android.os.Binder');
            B.getCallingPid.implementation = function () {
                var r = this.getCallingPid();
                self.counts.pidUse++;
                self.log('getCallingPid() = ' + r + '  ' + self.shortStack());
                self.log('   PID values are safe for LOGGING ONLY. A PID '
                         + 'identifies a running process,\n'
                         + '   and PIDs are recycled. If the next few frames '
                         + 'read /proc/' + r + '/... or\n'
                         + '   map this PID to a package, that is a '
                         + 'time-of-check-to-time-of-use race:\n'
                         + '   the caller may have exited and the number been '
                         + 'reused. Authorise on the UID.');
                return r;
            };
        });
    },

    hookClearRestore: function () {
        var self = this;

        this.guard('Binder.clearCallingIdentity', function () {
            var B = Java.use('android.os.Binder');
            B.clearCallingIdentity.implementation = function () {
                var s = self.st();
                var token = this.clearCallingIdentity();
                s.clearDepth++;
                s.tokens.push(String(token));
                s.clearedAt = self.shortStack();
                s.opsWhileCleared = 0;
                self.counts.cleared++;

                self.log('clearCallingIdentity() depth=' + s.clearDepth
                         + ' token=' + token);
                self.log('   at ' + s.clearedAt);

                if (s.inTransact && !s.checkedUid && !s.checkedPerm) {
                    /*
                     * Clearing before any check has happened is the shape of
                     * Pattern 1 even when the (now meaningless) check comes
                     * afterwards. Flag it at the clear, because that is where a
                     * reader of the decompiled code can see the mistake.
                     */
                    self.counts.p1++;
                    self.alert('PATTERN 1 — CLEAR BEFORE CHECK',
                        'identity cleared inside ' + s.transactClass
                        + ' code=' + s.transactCode + '\n'
                        + '   before any getCallingUid() or permission check '
                        + 'ran. Every authorisation\n'
                        + '   decision from here on evaluates the service '
                        + 'against itself.');
                }
                return token;
            };
        });

        this.guard('Binder.restoreCallingIdentity', function () {
            var B = Java.use('android.os.Binder');
            B.restoreCallingIdentity.implementation = function (token) {
                var s = self.st();
                var t = String(token);

                if (s.clearDepth === 0) {
                    /*
                     * PATTERN 4. Restoring without a matching clear corrupts the
                     * thread's identity state, and it usually means an
                     * exception path left the pairing inconsistent somewhere
                     * upstream.
                     */
                    self.counts.p4++;
                    self.alert('PATTERN 4 — UNBALANCED RESTORE',
                        'restoreCallingIdentity(' + t + ') with no outstanding '
                        + 'clear on this thread.\n'
                        + '   Clear/restore pairs must be strictly LIFO and '
                        + 'strictly nested. One token,\n'
                        + '   one restore.');
                } else {
                    var expected = s.tokens[s.tokens.length - 1];
                    if (expected !== t) {
                        self.counts.p4++;
                        self.alert('PATTERN 4 — NON-LIFO RESTORE',
                            'restored token ' + t + ' but the innermost '
                            + 'outstanding token is ' + expected + '.\n'
                            + '   Nested clear/restore pairs that are not '
                            + 'strictly LIFO leave the thread\'s\n'
                            + '   identity in a state neither the author nor '
                            + 'the next caller expects.');
                    }
                    s.tokens.pop();
                    s.clearDepth--;
                }

                /*
                 * PATTERN 2 — the cleared window was wide.
                 *
                 * We approximate "wide" by counting the observable operations
                 * that ran while identity was cleared: ContentResolver calls,
                 * Intent launches, file opens. Each of those is a chance for
                 * attacker-supplied data to be acted upon with the service's
                 * authority rather than the caller's.
                 */
                if (s.opsWhileCleared > 0) {
                    self.counts.p2++;
                    self.alert('PATTERN 2 — WIDE CLEARED WINDOW',
                        s.opsWhileCleared + ' privileged operation(s) ran while '
                        + 'identity was cleared.\n'
                        + '   Each one was evaluated against THIS app\'s '
                        + 'permissions, not the caller\'s.\n'
                        + '   If any of them acted on caller-supplied data — a '
                        + 'Uri, a path, an Intent —\n'
                        + '   the caller borrowed this app\'s authority. That '
                        + 'is the confused deputy.\n'
                        + '   Fix: clear only around the single privileged step '
                        + 'that needs it.');
                }
                s.opsWhileCleared = 0;

                self.log('restoreCallingIdentity(' + t + ') depth=' + s.clearDepth);
                return this.restoreCallingIdentity(token);
            };
        });
    },

    hookPermissionChecks: function () {
        var self = this;
        this.guard('permission check helpers', function () {
            var CW = Java.use('android.content.ContextWrapper');
            ['checkCallingPermission', 'enforceCallingPermission',
             'checkCallingOrSelfPermission', 'enforceCallingOrSelfPermission',
             'checkPermission', 'enforcePermission'].forEach(function (name) {
                var m = CW[name];
                if (!m) return;
                m.overloads.forEach(function (o) {
                    try {
                        o.implementation = function () {
                            var a = Array.prototype.slice.call(arguments);
                            var s = self.st();
                            s.checkedPerm = true;
                            var r = o.apply(this, a);
                            self.log(name + '("' + a[0] + '") -> ' + r
                                     + (r === 0 ? '  (GRANTED)' : '  (DENIED)'));
                            if (name.indexOf('OrSelf') !== -1) {
                                self.log('   NOTE: the *OrSelf* variants also '
                                    + 'succeed when the CALLER is this app.\n'
                                    + '   Inside a cleared window that is '
                                    + 'always true, so the check passes\n'
                                    + '   unconditionally. Prefer the '
                                    + 'non-OrSelf form in a Binder entry point.');
                            }
                            return r;
                        };
                    } catch (e) { }
                });
            });
        });
    },

    hookPrivilegedOps: function () {
        var self = this;

        /*
         * Count operations that run while identity is cleared. These are the
         * ones whose authorisation outcome CHANGES depending on whose identity
         * the thread is carrying — which is precisely what makes a wide cleared
         * window dangerous.
         */
        function watch(clazz, names, label) {
            self.guard(label, function () {
                var C = Java.use(clazz);
                names.forEach(function (n) {
                    var m = C[n];
                    if (!m) return;
                    m.overloads.forEach(function (o) {
                        try {
                            o.implementation = function () {
                                var a = Array.prototype.slice.call(arguments);
                                var s = self.st();
                                if (s.clearDepth > 0) {
                                    s.opsWhileCleared++;
                                    self.log('   [cleared window] ' + n + '('
                                             + String(a[0]).substring(0, 120)
                                             + ') — running with OUR identity, '
                                             + 'not the caller\'s');
                                }
                                return o.apply(this, a);
                            };
                        } catch (e) { }
                    });
                });
            });
        }

        watch('android.content.ContentResolver',
              ['query', 'insert', 'update', 'delete', 'call',
               'openInputStream', 'openFileDescriptor'],
              'ContentResolver during cleared window');
        watch('android.content.ContextWrapper',
              ['startActivity', 'startService', 'bindService', 'sendBroadcast',
               'grantUriPermission', 'openFileOutput'],
              'Context ops during cleared window');
        watch('java.io.FileInputStream', ['$init'],
              'file reads during cleared window');
    },

    /* ------------------------------------------------------------- control -- */

    stacks: function (b) { this.showStacks = !!b; },
    verbose: function (b) { this.isVerbose = !!b; },

    reset: function () {
        this.threads = {};
        this.alerts = [];
        for (var k in this.counts) this.counts[k] = 0;
        console.log('[*] counters reset');
    },

    report: function () {
        console.log('');
        console.log('============ binder identity report ============');
        console.log(' getCallingUid / OrThrow calls : ' + this.counts.uidCheck);
        console.log(' getCallingPid calls           : ' + this.counts.pidUse
                    + '   (safe only for logging)');
        console.log(' clearCallingIdentity calls    : ' + this.counts.cleared);
        console.log('');
        console.log(' PATTERN 1  check after clear  : ' + this.counts.p1);
        console.log(' PATTERN 2  wide window        : ' + this.counts.p2);
        console.log(' PATTERN 3  no restore         : ' + this.counts.p3);
        console.log(' PATTERN 4  unbalanced/non-LIFO: ' + this.counts.p4);
        console.log('');
        if (this.alerts.length === 0) {
            console.log(' No alerts. Either the app handles identity correctly,');
            console.log(' or you have not yet exercised the code path. Bind its');
            console.log(' exported services from ../examples/attacker-app/ and');
            console.log(' sweep the transaction codes, then re-check.');
        } else {
            console.log(' Alerts (' + this.alerts.length + '):');
            this.alerts.forEach(function (a, i) {
                console.log('   ' + (i + 1) + '. ' + a.split('\n')[0]);
            });
        }
        console.log('');
        console.log(' Every alert is a CANDIDATE. Confirm it by reading the');
        console.log(' decompiled method and answering three questions:');
        console.log('   1. was the caller\'s identity checked BEFORE the clear?');
        console.log('   2. how much code runs inside the cleared window, and');
        console.log('      does any of it act on caller-supplied data?');
        console.log('   3. is the restore inside a finally block?');
        console.log('   grep -rn -A20 "clearCallingIdentity" out/sources/');
        console.log('================================================');
    },

    start: function () {
        console.log('');
        console.log('================================================');
        console.log(' hook-binder-identity.js — 24-IPC');
        console.log('================================================');
        console.log(' getCallingUid() is kernel-supplied and cannot be forged.');
        console.log(' AUTHORISE ON IT.');
        console.log('');
        console.log(' getCallingPid() names a process, and PIDs are recycled.');
        console.log(' LOG ON IT, NEVER DECIDE ON IT.');
        console.log('');
        this.hookOnTransact();
        this.hookIdentityReads();
        this.hookClearRestore();
        this.hookPermissionChecks();
        this.hookPrivilegedOps();
        console.log('[*] ' + this.installed + ' hook groups installed, '
                    + this.skipped + ' skipped');
        console.log('[*] REPL: bid.report(), bid.verbose(true), bid.stacks(true),');
        console.log('          bid.reset()');
        console.log('');
        console.log('[!] Exercise the app\'s bound services to make this useful.');
        console.log('    ../examples/attacker-app/ binds every exported service');
        console.log('    and sweeps transaction codes 1-24, which is usually');
        console.log('    enough to reach the interesting methods.');
        console.log('');
    }
};

Java.perform(function () {
    bid.start();
});
