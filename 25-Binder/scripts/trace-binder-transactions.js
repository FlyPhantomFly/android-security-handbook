/*
 * trace-binder-transactions.js -- watch every Binder transaction a process
 *                                 sends and receives, with its code, its
 *                                 interface token, its parcel, and the caller
 *                                 UID the KERNEL stamped on it.
 *
 * WHAT IT DOES
 *   Instruments both directions and both layers:
 *
 *     OUT (Java)     BinderProxy.transact -- what this process calls, with the
 *                    transaction code decoded, the interface token read out of
 *                    the parcel without disturbing it, the payload size and,
 *                    on request, a hex dump
 *     IN  (Java)     Binder.execTransact -- the single funnel every Java-side
 *                    onTransact goes through. Reports the caller's uid and pid
 *                    as the driver delivered them, and flags pid == 0, which
 *                    means the transaction was ONEWAY
 *     IDENTITY       clearCallingIdentity / restoreCallingIdentity /
 *                    getCallingUid / getCallingUidOrThrow / getCallingPid /
 *                    getCallingWorkSourceUid, with a per-thread state machine
 *                    that raises the alarms listed below
 *     NATIVE         ioctl(BINDER_WRITE_READ) on /dev/binder, decoding
 *                    struct binder_write_read and struct binder_transaction_data
 *                    directly. This is the only layer that works on a process
 *                    with no Java at all -- surfaceflinger, a HAL, mediaserver
 *
 *   The alarms, which are the point of the script:
 *
 *     [ALARM 1]  getCallingUid() called AFTER clearCallingIdentity() on the
 *                same thread, inside the same transaction. The value it
 *                returned is almost certainly this process's OWN uid, so any
 *                check using it is comparing the service against itself.
 *                README 3.12 and 24-IPC 3.21.2 pattern 1.
 *     [ALARM 2]  A transaction ENDED with identity still cleared. The restore
 *                was not in a finally block, and this thread goes back into
 *                the POOL dirty. Pattern 3.
 *     [ALARM 3]  restoreCallingIdentity() called with a token this thread
 *                never obtained, or out of LIFO order. Pattern 4.
 *     [ALARM 4]  getCallingWorkSourceUid() called. That value is written by
 *                the CALLER into the parcel. If it is being used for a
 *                security decision, it is trivially forged. README 3.11.4.
 *     [ALARM 5]  A transaction reached the service with NO interface token,
 *                or with a token that does not match the object's descriptor.
 *                Means no enforceInterface. README 3.9.
 *     [ALARM 6]  An incoming parcel larger than a threshold (default 200 KiB),
 *                which is where TransactionTooLargeException starts and where
 *                availability testing starts. README 3.14.
 *
 * HOW TO RUN
 *   # host
 *   frida -U -f com.example.target -l trace-binder-transactions.js       # spawn
 *   frida -U -n com.example.target -l trace-binder-transactions.js       # attach
 *   frida -U -n system_server      -l trace-binder-transactions.js       # needs root
 *   frida -U -f com.example.target -l trace-binder-transactions.js -o binder.log
 *
 *   Then tune it live from the REPL. Everything is on a global `bt` object:
 *
 *     bt.help()                    // print this list
 *     bt.hex(true)                 // hex-dump every parcel (LOUD)
 *     bt.hex(false)
 *     bt.maxHex(256)               // cap the dump length
 *     bt.only(/Notification/)      // only interfaces matching a regex
 *     bt.onlyCode(3)               // only one transaction code
 *     bt.mute(/IActivityManager/)  // hide the noisy ones
 *     bt.dirOut(false)             // stop tracing outgoing calls
 *     bt.dirIn(true)               // keep tracing incoming ones
 *     bt.native(true)              // turn on the ioctl layer (LOUD)
 *     bt.stats()                   // per code + interface counts
 *     bt.reset()                   // clear the statistics
 *     bt.alarmsOnly(true)          // suppress everything except alarms
 *     bt.sizeAlarm(65536)          // lower the parcel-size threshold
 *
 * REQUIREMENTS
 *   - frida-server running on the device and matching your host frida version.
 *   - To trace an APP: a debuggable build, or root, or a frida gadget.
 *   - To trace system_server or a native daemon: ROOT. There is no way around
 *     this, and it is the reason the README's measured results were produced
 *     with a raw C client rather than with Frida.
 *   - The native layer assumes a 64-BIT process. The struct offsets below are
 *     the arm64/x86_64 ones. On a 32-bit process every offset after `code` is
 *     wrong, and the script says so rather than printing rubbish.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - Whether anything it prints is a vulnerability. It shows you the traffic
 *     and the identity handling. Deciding whether a missing check matters is
 *     your job. Most [ALARM 1] hits in framework code are, on inspection,
 *     correct code that reads getCallingUid() for LOGGING after a clear.
 *   - Anything about transactions that never reach Java. A native service's
 *     onTransact is invisible to the Java hooks; use bt.native(true).
 *   - Anything about SELinux. A transaction the kernel refused never appears
 *     here at all, because it was never delivered. If a call seems to vanish,
 *     check dmesg for an avc record. See 22-SELinux.
 *   - The transaction's MEANING. Binder carries no schema. Code 7 is whatever
 *     the .aidl said it was, and the .aidl is not on the device.
 *   - Reliable results under heavy load. Hooking execTransact on a busy
 *     process costs real time and will change its behaviour. Filter early
 *     with bt.only() rather than logging everything and grepping afterwards.
 *
 * SAFETY
 *   Hooking system_server slows every IPC on the device. With hex dumps on it
 *   can slow it enough to trigger watchdog reboots. Filter first.
 */

'use strict';

/* ======================================================================
 * 0. Configuration
 * ====================================================================== */

var CFG = {
    hex:        false,
    maxHex:     192,
    traceOut:   true,
    traceIn:    true,
    traceNative: false,
    alarmsOnly: false,
    sizeAlarm:  200 * 1024,     // where TransactionTooLargeException begins
    only:       null,           // RegExp on the interface descriptor
    mute:       null,
    onlyCode:   null
};

var STATS = {};                 // "iface#code" -> count
var ALARMS = 0;

/* ======================================================================
 * 1. Constants -- README sections 3.4, 3.5 and 3.8
 * ====================================================================== */

var WELL_KNOWN = {
    1598968902: "INTERFACE_TRANSACTION ('_NTF')",
    1598311760: "DUMP_TRANSACTION ('_DMP')",
    1598246212: "SHELL_COMMAND_TRANSACTION ('_CMD')",
    1599098439: "PING_TRANSACTION ('_PNG')",
    1599295570: "SYSPROPS_TRANSACTION ('_SPR')",
    1599362900: "TWEET_TRANSACTION ('_TWT')",
    1598835019: "LIKE_TRANSACTION ('_LIK')"
};

var BINDER_WRITE_READ = 0xc0306201;   // arm64; measured on Android 11
var BC_TRANSACTION    = 0x40406300;
var BC_REPLY          = 0x40406301;

/* struct binder_transaction_data, 64-bit. See cheatsheet.md section 3. */
var TR = {
    target:       0,
    cookie:       8,
    code:        16,
    flags:       20,
    sender_pid:  24,
    sender_euid: 28,
    data_size:   32,
    offsets_size:40,
    buffer:      48,
    offsets:     56
};

var TF_ONE_WAY    = 0x01;
var TF_ACCEPT_FDS = 0x10;
var TF_CLEAR_BUF  = 0x20;

function codeName(c) {
    c = c >>> 0;
    if (WELL_KNOWN[c]) return WELL_KNOWN[c];
    if (c >= 1 && c <= 0x00ffffff) {
        return "method #" + c + "  (position " + c + " in the .aidl, 1-based)";
    }
    return "0x" + c.toString(16);
}

function flagNames(f) {
    var out = [];
    if (f & TF_ONE_WAY)    out.push("ONEWAY");
    if (f & TF_ACCEPT_FDS) out.push("ACCEPT_FDS");
    if (f & TF_CLEAR_BUF)  out.push("CLEAR_BUF");
    return out.length ? " [" + out.join(",") + "]" : "";
}

function log(s)   { if (!CFG.alarmsOnly) console.log(s); }
function alarm(s) { ALARMS++; console.warn(s); }

function wanted(iface) {
    if (CFG.only && !CFG.only.test(iface || "")) return false;
    if (CFG.mute && CFG.mute.test(iface || "")) return false;
    return true;
}

function bump(iface, code) {
    var k = (iface || "<none>") + "#" + code;
    STATS[k] = (STATS[k] || 0) + 1;
}

/* ======================================================================
 * 2. Java layer
 * ====================================================================== */

Java.perform(function () {

    var Binder, BinderProxy, Parcel, Log, Throwable;
    try {
        Binder      = Java.use('android.os.Binder');
        BinderProxy = Java.use('android.os.BinderProxy');
        Parcel      = Java.use('android.os.Parcel');
        Log         = Java.use('android.util.Log');
        Throwable   = Java.use('java.lang.Throwable');
    } catch (e) {
        console.error('[!] no Java runtime in this process. ' +
                      'Only the native layer is available: bt.native(true)');
        return;
    }

    function stack() {
        try { return Log.getStackTraceString(Throwable.$new()); }
        catch (e) { return '<no stack>'; }
    }

    /*
     * Read the interface token WITHOUT disturbing the parcel's read position.
     * Getting this wrong corrupts the very transaction you are observing, so
     * the position is saved and restored on every path including the error
     * one.
     *
     * Layout (README 3.9): int32 policy, int32 work-source, int32 'SYST',
     * then String16 descriptor.
     */
    var SYST = 0x53595354;
    function peekToken(p) {
        if (p === null) return null;
        var pos = -1;
        try {
            pos = p.dataPosition();
            if (p.dataSize() < 16) return null;
            p.setDataPosition(0);
            p.readInt();                 // strict-mode policy
            var ws = p.readInt();        // work-source uid
            var hdr = p.readInt();       // 'SYST'
            if ((hdr | 0) !== (SYST | 0)) return null;
            var d = p.readString();
            return { desc: d, workSource: ws };
        } catch (e) {
            return null;
        } finally {
            if (pos >= 0) { try { p.setDataPosition(pos); } catch (e2) {} }
        }
    }

    function dumpParcel(p, label) {
        if (!CFG.hex || p === null) return;
        try {
            var pos = p.dataPosition();
            var n = Math.min(p.dataSize(), CFG.maxHex);
            p.setDataPosition(0);
            var bytes = p.marshall();     // may throw if the parcel holds objects
            p.setDataPosition(pos);
            var buf = Memory.alloc(n);
            for (var i = 0; i < n; i++) buf.add(i).writeU8(bytes[i] & 0xff);
            console.log('    ' + label + ' first ' + n + ' of ' + p.dataSize() + ' bytes');
            console.log(hexdump(buf, { length: n, ansi: false, header: false }));
        } catch (e) {
            // marshall() refuses a parcel containing file descriptors or
            // binder objects. That refusal is itself informative.
            console.log('    ' + label + ' cannot be marshalled: it contains ' +
                        'binder objects or file descriptors (README 3.7.3)');
        }
    }

    /* ------------------------------------------------------------------
     * Per-thread identity state machine.
     * ------------------------------------------------------------------ */
    var TH = {};                 // tid -> { depth, tokens[], sawUidAfterClear, inTxn }

    function th() {
        var tid = Process.getCurrentThreadId();
        if (!TH[tid]) TH[tid] = { tokens: [], inTxn: 0, warned: false };
        return TH[tid];
    }

    /* ------------------------------------------------------------------
     * OUTGOING -- BinderProxy.transact
     * ------------------------------------------------------------------ */
    if (BinderProxy.transact) {
        BinderProxy.transact.overloads.forEach(function (ov) {
            ov.implementation = function (code, data, reply, flags) {
                if (!CFG.traceOut) return ov.apply(this, arguments);
                if (CFG.onlyCode !== null && code !== CFG.onlyCode) {
                    return ov.apply(this, arguments);
                }
                var tok = peekToken(data);
                var iface = tok ? tok.desc : null;
                if (!wanted(iface)) return ov.apply(this, arguments);

                bump(iface, code);
                var size = 0;
                try { size = data === null ? 0 : data.dataSize(); } catch (e) {}

                log('[OUT] ' + codeName(code) + flagNames(flags) +
                    '\n      iface = ' + (iface === null
                        ? '<NO TOKEN> -- this parcel carries no interface token'
                        : iface) +
                    '\n      bytes = ' + size);

                if (tok && tok.workSource !== -1) {
                    log('      workSource = ' + tok.workSource +
                        '  (caller-written; never a security input)');
                }
                dumpParcel(data, 'request');

                var rv = ov.apply(this, arguments);

                if (reply !== null) {
                    try {
                        var rpos = reply.dataPosition();
                        reply.setDataPosition(0);
                        if (reply.dataSize() >= 4) {
                            var exc = reply.readInt();
                            if (exc !== 0) {
                                var msg = '';
                                try { msg = reply.readString(); } catch (e) {}
                                log('      <- exception ' + exc + ' ' + excName(exc) +
                                    (msg ? '  "' + msg + '"' : ''));
                                log('         a refusal names the guard and the uid it saw.' +
                                    ' Read it. (README 3.7.5)');
                            }
                        }
                        reply.setDataPosition(rpos);
                    } catch (e) {}
                }
                return rv;
            };
        });
    }

    function excName(c) {
        switch (c) {
            case -1: return 'SecurityException';
            case -2: return 'BadParcelableException';
            case -3: return 'IllegalArgumentException';
            case -4: return 'NullPointerException';
            case -5: return 'IllegalStateException';
            case -7: return 'UnsupportedOperationException';
            case -8: return 'ServiceSpecificException';
            case -129: return 'transaction failed';
            default: return '';
        }
    }

    /* ------------------------------------------------------------------
     * INCOMING -- Binder.execTransact
     *
     * Every Java-side onTransact in the process funnels through here, which
     * is what makes this a complete view rather than a per-class hook.
     * ------------------------------------------------------------------ */
    Binder.execTransact.overloads.forEach(function (ov) {
        ov.implementation = function () {
            if (!CFG.traceIn) return ov.apply(this, arguments);

            var code = arguments[0];
            if (CFG.onlyCode !== null && code !== CFG.onlyCode) {
                return ov.apply(this, arguments);
            }

            var uid = -1, pid = -1;
            try { uid = Binder.getCallingUid(); } catch (e) {}
            try { pid = Binder.getCallingPid(); } catch (e) {}

            var cls = '<unknown>';
            try { cls = this.$className; } catch (e) {}

            var descriptor = null;
            try { descriptor = this.getInterfaceDescriptor(); } catch (e) {}

            if (!wanted(descriptor)) return ov.apply(this, arguments);
            bump(descriptor, code);

            var st = th();
            st.inTxn++;
            var depthAtEntry = st.tokens.length;
            st.sawUidAfterClear = false;

            log('[IN ] ' + codeName(code) +
                '\n      on    = ' + cls +
                '\n      iface = ' + (descriptor === null || descriptor === ''
                    ? '<EMPTY> -- raw Binder, no enforceInterface. ' +
                      'EVERY code is reachable. (ALARM 5)'
                    : descriptor) +
                '\n      from  = uid ' + uid + ', pid ' + pid);

            if (descriptor === null || descriptor === '') {
                alarm('[ALARM 5] incoming transaction on an object with NO interface ' +
                      'descriptor: ' + cls + ' code ' + code);
            }
            if (pid === 0) {
                log('      pid 0 => this was a ONEWAY transaction. The driver records ' +
                    'no sending thread, so getCallingPid() is 0 and any pid-based ' +
                    'check is silently disabled here. (README 3.10)');
            }

            // Parcel size -- the availability signal.
            try {
                var d = arguments[1];
                if (d !== null && d.dataSize() > CFG.sizeAlarm) {
                    alarm('[ALARM 6] incoming parcel of ' + d.dataSize() +
                          ' bytes on ' + cls + ' code ' + code +
                          ' -- above ' + CFG.sizeAlarm + '. The per-PROCESS budget is ' +
                          '1040384 bytes shared by every incoming transaction. ' +
                          '(README 3.14)');
                }
                dumpParcel(d, 'incoming');
            } catch (e) {}

            var rv;
            try {
                rv = ov.apply(this, arguments);
            } finally {
                // Did the transaction end with identity still cleared?
                if (st.tokens.length > depthAtEntry) {
                    alarm('[ALARM 2] transaction ended with identity STILL CLEARED on ' +
                          cls + ' code ' + code + '. ' + (st.tokens.length - depthAtEntry) +
                          ' unmatched clearCallingIdentity(). The restore was not in a ' +
                          'finally block, and this thread is POOLED. ' +
                          '(24-IPC 3.21.2 pattern 3)\n' + stack());
                    st.tokens.length = depthAtEntry;
                }
                st.inTxn--;
            }
            return rv;
        };
    });

    /* ------------------------------------------------------------------
     * THE IDENTITY BOUNDARY
     * ------------------------------------------------------------------ */

    Binder.clearCallingIdentity.implementation = function () {
        var st = th();
        var before = -1;
        try { before = Binder.getCallingUid(); } catch (e) {}
        var token = this.clearCallingIdentity();
        var after = -1;
        try { after = Binder.getCallingUid(); } catch (e) {}

        st.tokens.push(token.toString());
        log('[ID ] clearCallingIdentity()  uid ' + before + ' -> ' + after +
            '   token=0x' + token.toString(16) +
            '\n      the token is (uid << 32) | pid. It is a save slot, not a ' +
            'capability: nothing validates it and nothing enforces pairing.');
        if (CFG.hex) log(stack());
        return token;
    };

    Binder.restoreCallingIdentity.implementation = function (token) {
        var st = th();
        var key = token.toString();
        var top = st.tokens.length ? st.tokens[st.tokens.length - 1] : null;

        if (top === null) {
            alarm('[ALARM 3] restoreCallingIdentity(0x' + token.toString(16) +
                  ') with NO matching clear on this thread. Either the token came ' +
                  'from a FIELD written by another thread, or it was fabricated. ' +
                  'Both are 24-IPC 3.21.2 pattern 4.\n' + stack());
        } else if (top !== key) {
            alarm('[ALARM 3] restoreCallingIdentity() out of LIFO order on this ' +
                  'thread: expected 0x' + parseInt(top, 10).toString(16) +
                  ', got 0x' + token.toString(16) + '. Nested clear/restore pairs ' +
                  'that are not strictly LIFO corrupt the thread identity.\n' + stack());
            var i = st.tokens.lastIndexOf(key);
            if (i >= 0) st.tokens.splice(i, 1);
        } else {
            st.tokens.pop();
        }

        this.restoreCallingIdentity(token);
        var now = -1;
        try { now = Binder.getCallingUid(); } catch (e) {}
        log('[ID ] restoreCallingIdentity(0x' + token.toString(16) + ')  uid now ' + now);
        st.sawUidAfterClear = false;
    };

    /*
     * getCallingUid AFTER a clear, inside a transaction, is pattern 1: the
     * value is this process's own uid, so any comparison against it passes.
     *
     * Deliberately reported once per transaction rather than once per call,
     * because framework code legitimately reads it for logging after a clear
     * and reporting every occurrence buries the real hits.
     */
    function hookUidGetter(name) {
        if (!Binder[name]) return;
        Binder[name].implementation = function () {
            var v = this[name]();
            var st = th();
            if (st.tokens.length > 0 && st.inTxn > 0 && !st.sawUidAfterClear) {
                st.sawUidAfterClear = true;
                alarm('[ALARM 1] ' + name + '() called AFTER clearCallingIdentity() ' +
                      'inside a transaction. It returned ' + v +
                      ', which is almost certainly THIS process\'s own uid. Any check ' +
                      'using it compares the service against itself and always passes. ' +
                      '(24-IPC 3.21.2 pattern 1)\n' + stack());
            }
            return v;
        };
    }
    hookUidGetter('getCallingUid');
    hookUidGetter('getCallingUidOrThrow');

    if (Binder.getCallingWorkSourceUid) {
        Binder.getCallingWorkSourceUid.implementation = function () {
            var v = this.getCallingWorkSourceUid();
            alarm('[ALARM 4] getCallingWorkSourceUid() returned ' + v + '. This value ' +
                  'is written by the CALLER into the parcel (it is the second int32 of ' +
                  'the interface token). It is battery-attribution metadata and is NOT ' +
                  'an identity. If the code below uses it for a decision, it is ' +
                  'trivially forged. (README 3.11.4)\n' + stack());
            return v;
        };
    }

    console.log('[*] Java layer active. Type bt.help() for controls.');
});

/* ======================================================================
 * 3. Native layer -- ioctl(BINDER_WRITE_READ)
 *
 * The only layer that works on a process with no Java. Decodes the two
 * structures directly. 64-bit only; see REQUIREMENTS.
 * ====================================================================== */

var nativeHook = null;

function installNative() {
    if (nativeHook) return;
    if (Process.pointerSize !== 8) {
        console.error('[!] native layer needs a 64-bit process; this one is ' +
                      (Process.pointerSize * 8) + '-bit. The struct offsets would ' +
                      'all be wrong, so it is disabled rather than printing rubbish.');
        return;
    }
    var ioctl;
    try {
        ioctl = Module.getExportByName('libc.so', 'ioctl');
    } catch (e) {
        console.error('[!] cannot resolve ioctl: ' + e);
        return;
    }

    nativeHook = Interceptor.attach(ioctl, {
        onEnter: function (args) {
            if (!CFG.traceNative) return;
            var req = args[1].toInt32() >>> 0;
            if (req !== BINDER_WRITE_READ) return;

            var bwr = args[2];
            var writeSize, writeBuf;
            try {
                writeSize = bwr.readU64().valueOf();
                writeBuf  = bwr.add(16).readPointer();
            } catch (e) { return; }
            if (!writeSize || writeBuf.isNull()) return;

            var off = 0;
            while (off + 4 <= writeSize) {
                var cmd;
                try { cmd = writeBuf.add(off).readU32(); } catch (e) { return; }
                off += 4;
                if (cmd !== BC_TRANSACTION && cmd !== BC_REPLY) {
                    // Other BC_ commands have argument sizes we are not
                    // decoding here; stop rather than guess and misalign.
                    return;
                }
                var t = writeBuf.add(off);
                off += 64;
                try {
                    var handle = t.add(TR.target).readU32();
                    var code   = t.add(TR.code).readU32();
                    var flags  = t.add(TR.flags).readU32();
                    var dsize  = t.add(TR.data_size).readU64().valueOf();
                    var osize  = t.add(TR.offsets_size).readU64().valueOf();
                    var dptr   = t.add(TR.buffer).readPointer();

                    console.log('[NAT] ' + (cmd === BC_TRANSACTION ? 'BC_TRANSACTION' : 'BC_REPLY') +
                                '  handle=' + handle +
                                '  code=' + codeName(code) +
                                '  flags=0x' + flags.toString(16) + flagNames(flags) +
                                '  data=' + dsize + 'B  objects=' + (osize / 8));
                    if (CFG.hex && dsize > 0 && !dptr.isNull()) {
                        var n = Math.min(dsize, CFG.maxHex);
                        console.log(hexdump(dptr, { length: n, ansi: false }));
                    }
                } catch (e) {
                    console.log('[NAT] could not decode a transaction: ' + e);
                    return;
                }
            }
        }
    });
    console.log('[*] native ioctl layer attached.');
}

/* ======================================================================
 * 4. REPL controls
 * ====================================================================== */

var bt = {
    help: function () {
        console.log([
            'bt.hex(bool)          hex-dump every parcel (LOUD)',
            'bt.maxHex(n)          cap the dump length (default 192)',
            'bt.only(/regex/)      only interfaces matching this',
            'bt.mute(/regex/)      hide interfaces matching this',
            'bt.onlyCode(n)        only this transaction code',
            'bt.dirOut(bool)       trace outgoing calls (default on)',
            'bt.dirIn(bool)        trace incoming calls (default on)',
            'bt.native(bool)       trace ioctl(BINDER_WRITE_READ) (LOUD, 64-bit only)',
            'bt.alarmsOnly(bool)   suppress everything except alarms',
            'bt.sizeAlarm(n)       parcel-size alarm threshold (default 204800)',
            'bt.stats()            per interface + code counts',
            'bt.reset()            clear the statistics',
            '',
            'Alarms: 1 uid-after-clear, 2 identity leaked past a transaction,',
            '        3 token misuse, 4 work-source uid used, 5 no interface',
            '        token, 6 oversized parcel.'
        ].join('\n'));
    },
    hex:        function (b) { CFG.hex = !!b; return CFG.hex; },
    maxHex:     function (n) { CFG.maxHex = n | 0; return CFG.maxHex; },
    only:       function (r) { CFG.only = r || null; return String(CFG.only); },
    mute:       function (r) { CFG.mute = r || null; return String(CFG.mute); },
    onlyCode:   function (n) { CFG.onlyCode = (n === undefined || n === null) ? null : (n | 0);
                               return CFG.onlyCode; },
    dirOut:     function (b) { CFG.traceOut = !!b; return CFG.traceOut; },
    dirIn:      function (b) { CFG.traceIn = !!b; return CFG.traceIn; },
    alarmsOnly: function (b) { CFG.alarmsOnly = !!b; return CFG.alarmsOnly; },
    sizeAlarm:  function (n) { CFG.sizeAlarm = n | 0; return CFG.sizeAlarm; },
    native:     function (b) {
        CFG.traceNative = !!b;
        if (CFG.traceNative) installNative();
        return CFG.traceNative;
    },
    stats: function () {
        var keys = Object.keys(STATS).sort(function (a, b) { return STATS[b] - STATS[a]; });
        if (!keys.length) { console.log('(nothing observed yet)'); return; }
        console.log('count  interface#code');
        keys.forEach(function (k) {
            console.log(('     ' + STATS[k]).slice(-5) + '  ' + k);
        });
        console.log('alarms raised: ' + ALARMS);
    },
    reset: function () { STATS = {}; ALARMS = 0; return 'cleared'; }
};

global.bt = bt;

console.log('[*] trace-binder-transactions.js loaded.');
console.log('    bt.help() for controls. Start with bt.only(/YourInterface/) on a');
console.log('    busy process -- tracing everything on system_server can be slow');
console.log('    enough to trip the watchdog.');
