/*
 * seccomp-probe.js — measure the app's seccomp filter from INSIDE the app.
 *
 * WHAT IT DOES
 *   Attaches to a running application process and attempts a set of system
 *   calls directly, via libc's raw syscall(2) wrapper, recording for each one
 *   whether it was allowed, refused with an errno, or would have killed the
 *   process. It then reports the process's declared seccomp state
 *   (/proc/self/status) alongside the empirical result, so you can see the
 *   filter's effect rather than infer it from a text file.
 *
 *   It also demonstrates the boundary's shape from the other direction: the
 *   syscalls an app is ALLOWED to make are just as informative as the blocked
 *   ones. openat() on another app's data directory is permitted by seccomp and
 *   refused by DAC — a completely different mechanism producing a superficially
 *   identical EACCES.
 *
 * WHY IT MATTERS
 *   Three reasons.
 *
 *   1. It is the only way to measure the filter that applies to APPS. Running
 *      the same experiment in `adb shell` measures nothing: the shell is UID
 *      2000 in the SELinux domain `shell` with `Seccomp: 0` — no filter at all.
 *      A syscall that works in your shell may be physically unreachable from an
 *      app, and vice versa.
 *
 *   2. It teaches the difference between the three denial mechanisms, which
 *      look alike in a log and are not alike in a report:
 *          seccomp  -> the syscall never reaches its handler (ENOSYS/EPERM,
 *                      or SIGSYS / process kill)
 *          DAC      -> the handler ran and the kernel's credential check failed
 *                      (EACCES / EPERM)
 *          SELinux  -> the LSM hook refused (EACCES, plus an `avc:` line in
 *                      dmesg — the distinguishing evidence)
 *      Naming the wrong one is the fastest way to have a developer dismiss a
 *      finding.
 *
 *   3. Blocklists change between releases and between vendors. The
 *      authoritative source is bionic/libc/seccomp/SECCOMP_BLOCKLIST_APP.TXT in
 *      the AOSP branch matching your target — but a device in your hand is a
 *      better source than any written list, including the one in this
 *      repository's README.
 *
 *   See ../README.md section 3.5, and ../labs/lab-01-mapping-the-sandbox.md.
 *
 * HOW TO RUN
 *   # host
 *   frida -U -n com.example.target -l seccomp-probe.js
 *   frida -U -f com.example.target -l seccomp-probe.js          # spawn + attach
 *
 *   Then from the REPL:
 *     seccomp.status()          show the declared state from /proc/self/status
 *     seccomp.probe()           run the safe probes (default set)
 *     seccomp.probe(true)       ALSO run probes that may kill the process
 *     seccomp.one("chroot")     probe a single named syscall
 *     seccomp.dac()             show DAC/SELinux denials for contrast
 *     seccomp.list()            list what this script knows how to probe
 *
 * REQUIREMENTS
 *   frida-server running on the device, matching your host frida version.
 *   An arm64 or x86_64 Android device or emulator. Root is required to RUN
 *   frida-server, but NOT to make the results meaningful: everything measured
 *   here is measured inside an ordinary app process with an ordinary app's
 *   filter, because Zygote installed that filter before the app started and
 *   nothing — including frida — can remove it.
 *
 * SAFETY
 *   Some seccomp verdicts are SECCOMP_RET_KILL_PROCESS. A probe that trips one
 *   terminates the app instantly. Every such probe is OFF by default and is
 *   only run when you pass `true`. Run those on a scratch app, never on a
 *   target mid-engagement.
 *
 *   This script makes no persistent change to the device. It calls syscalls
 *   with deliberately invalid arguments so that an ALLOWED call still fails
 *   harmlessly with EINVAL/EBADF rather than doing anything.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var seccomp = {

    _syscall: null,
    _errnoLoc: null,
    _arch: null,

    /* ------------------------------------------------------------- setup */

    init: function () {
        this._arch = Process.arch;

        var sc = Module.findExportByName('libc.so', 'syscall');
        if (sc === null) {
            console.log('[-] libc.so!syscall not found. Cannot probe raw syscalls on');
            console.log('    this build. Falling back to wrapper-based probes only.');
        } else {
            try {
                this._syscall = new NativeFunction(sc, 'long',
                    ['long', 'long', 'long', 'long', 'long', 'long', 'long']);
            } catch (e) {
                console.log('[-] Could not bind syscall(): ' + e);
                this._syscall = null;
            }
        }

        var errloc = Module.findExportByName('libc.so', '__errno');
        if (errloc !== null) {
            try {
                this._errnoLoc = new NativeFunction(errloc, 'pointer', []);
            } catch (e) { this._errnoLoc = null; }
        }

        console.log('[*] arch      = ' + this._arch);
        console.log('[*] syscall() = ' + (this._syscall ? 'bound' : 'UNAVAILABLE'));
        console.log('[*] __errno   = ' + (this._errnoLoc ? 'bound' : 'UNAVAILABLE'));
        return true;
    },

    _errno: function () {
        if (this._errnoLoc === null) return -1;
        try { return this._errnoLoc().readS32(); } catch (e) { return -1; }
    },

    _errName: function (e) {
        var m = {
            1: 'EPERM', 2: 'ENOENT', 9: 'EBADF', 13: 'EACCES', 14: 'EFAULT',
            16: 'EBUSY', 22: 'EINVAL', 38: 'ENOSYS', 95: 'EOPNOTSUPP'
        };
        return m[e] || ('errno ' + e);
    },

    /*
     * Syscall numbers. arm64 and x86_64 use the generic table for most of
     * these, but they are NOT identical, so both are listed explicitly and an
     * unknown architecture degrades to "skipped" rather than probing a wrong
     * number — which would be worse than not probing at all.
     *
     * `kill: true` means a SECCOMP_RET_KILL_PROCESS verdict is plausible.
     */
    _table: {
        arm64: {
            setuid:          { nr: 146, kill: true,  why: 'identity change — the most valuable blocklist entry' },
            setgid:          { nr: 144, kill: true,  why: 'identity change' },
            setresuid:       { nr: 147, kill: true,  why: 'identity change' },
            setgroups:       { nr: 159, kill: true,  why: 'identity change' },
            capset:          { nr: 91,  kill: true,  why: 'capability manipulation' },
            chroot:          { nr: 51,  kill: true,  why: 'reshaping the filesystem view' },
            pivot_root:      { nr: 41,  kill: true,  why: 'reshaping the filesystem view' },
            mount:           { nr: 40,  kill: true,  why: 'reshaping the filesystem view' },
            umount2:         { nr: 39,  kill: true,  why: 'reshaping the filesystem view' },
            keyctl:          { nr: 219, kill: true,  why: 'kernel keyring — fscrypt keys, own bug history' },
            add_key:         { nr: 217, kill: true,  why: 'kernel keyring' },
            request_key:     { nr: 218, kill: true,  why: 'kernel keyring' },
            perf_event_open: { nr: 241, kill: true,  why: 'large, bug-rich LPE surface and a side-channel primitive' },
            swapon:          { nr: 224, kill: true,  why: 'no app use; privileged and fragile' },
            init_module:     { nr: 105, kill: true,  why: 'module loading is total compromise' },
            delete_module:   { nr: 106, kill: true,  why: 'module loading' },
            reboot:          { nr: 142, kill: true,  why: 'administrative' },
            quotactl:        { nr: 60,  kill: true,  why: 'administrative' },
            /* Allowed — the control group. */
            getpid:          { nr: 172, kill: false, why: 'CONTROL: must be allowed' },
            getuid:          { nr: 174, kill: false, why: 'CONTROL: must be allowed' },
            gettid:          { nr: 178, kill: false, why: 'CONTROL: must be allowed' },
            ptrace:          { nr: 117, kill: false, why: 'NOT blocked — an app may ptrace itself' },
            prctl:           { nr: 167, kill: false, why: 'allowed; how NO_NEW_PRIVS was set in the first place' },
            openat:          { nr: 56,  kill: false, why: 'allowed by seccomp; DAC/SELinux decide the outcome' },
            socket:          { nr: 198, kill: false, why: 'allowed by seccomp; AID_INET decides the outcome' }
        },
        x64: {
            setuid:          { nr: 105, kill: true,  why: 'identity change — the most valuable blocklist entry' },
            setgid:          { nr: 106, kill: true,  why: 'identity change' },
            setresuid:       { nr: 117, kill: true,  why: 'identity change' },
            setgroups:       { nr: 116, kill: true,  why: 'identity change' },
            capset:          { nr: 126, kill: true,  why: 'capability manipulation' },
            chroot:          { nr: 161, kill: true,  why: 'reshaping the filesystem view' },
            pivot_root:      { nr: 155, kill: true,  why: 'reshaping the filesystem view' },
            mount:           { nr: 165, kill: true,  why: 'reshaping the filesystem view' },
            umount2:         { nr: 166, kill: true,  why: 'reshaping the filesystem view' },
            keyctl:          { nr: 250, kill: true,  why: 'kernel keyring' },
            add_key:         { nr: 248, kill: true,  why: 'kernel keyring' },
            request_key:     { nr: 249, kill: true,  why: 'kernel keyring' },
            perf_event_open: { nr: 298, kill: true,  why: 'large, bug-rich LPE surface' },
            swapon:          { nr: 167, kill: true,  why: 'no app use' },
            init_module:     { nr: 175, kill: true,  why: 'module loading is total compromise' },
            delete_module:   { nr: 176, kill: true,  why: 'module loading' },
            reboot:          { nr: 169, kill: true,  why: 'administrative' },
            quotactl:        { nr: 179, kill: true,  why: 'administrative' },
            getpid:          { nr: 39,  kill: false, why: 'CONTROL: must be allowed' },
            getuid:          { nr: 102, kill: false, why: 'CONTROL: must be allowed' },
            gettid:          { nr: 186, kill: false, why: 'CONTROL: must be allowed' },
            ptrace:          { nr: 101, kill: false, why: 'NOT blocked — an app may ptrace itself' },
            prctl:           { nr: 157, kill: false, why: 'allowed' },
            openat:          { nr: 257, kill: false, why: 'allowed by seccomp; DAC/SELinux decide' },
            socket:          { nr: 41,  kill: false, why: 'allowed by seccomp; AID_INET decides' }
        }
    },

    _tableForArch: function () {
        if (this._arch === 'arm64') return this._table.arm64;
        if (this._arch === 'x64')   return this._table.x64;
        return null;
    },

    /* ------------------------------------------------------- declared state */

    status: function () {
        console.log('');
        console.log('=== DECLARED SECCOMP STATE (/proc/self/status) ===');
        var wanted = ['Uid', 'Gid', 'Groups', 'CapBnd', 'CapEff',
                      'Seccomp', 'Seccomp_filters', 'NoNewPrivs'];
        try {
            var txt = this._readFile('/proc/self/status');
            txt.split('\n').forEach(function (line) {
                for (var i = 0; i < wanted.length; i++) {
                    if (line.indexOf(wanted[i] + ':') === 0) {
                        console.log('  ' + line.replace(/\s+/g, ' ').trim());
                    }
                }
            });
        } catch (e) {
            console.log('  could not read /proc/self/status: ' + e);
        }

        try {
            console.log('  SELinux: ' + this._readFile('/proc/self/attr/current')
                                            .replace(/\0/g, '').trim());
        } catch (e) { /* ignore */ }

        console.log('');
        console.log('  Seccomp: 2 = SECCOMP_MODE_FILTER. Your adb shell shows 0.');
        console.log('  That single difference is why an experiment run in the shell');
        console.log('  cannot answer "can an app do this".');
        console.log('');
    },

    _readFile: function (path) {
        var out = '';
        Java.perform(function () {
            var FIS = Java.use('java.io.FileInputStream');
            var BR  = Java.use('java.io.BufferedReader');
            var ISR = Java.use('java.io.InputStreamReader');
            var r = BR.$new(ISR.$new(FIS.$new(path)));
            var line;
            while ((line = r.readLine()) !== null) out += line + '\n';
            r.close();
        });
        return out;
    },

    /* --------------------------------------------------------------- probes */

    list: function () {
        var t = this._tableForArch();
        if (t === null) {
            console.log('[-] No syscall table for arch "' + this._arch + '".');
            console.log('    Refusing to guess numbers — a wrong number would produce a');
            console.log('    confidently wrong result, which is worse than no result.');
            return;
        }
        console.log('');
        console.log('  name              nr    may-kill  why');
        Object.keys(t).forEach(function (k) {
            console.log('  ' + k.padEnd(18) + String(t[k].nr).padEnd(6) +
                        (t[k].kill ? 'YES       ' : 'no        ') + t[k].why);
        });
        console.log('');
    },

    one: function (name) {
        var t = this._tableForArch();
        if (t === null || t[name] === undefined) {
            console.log('[-] Unknown syscall for this arch: ' + name);
            return;
        }
        this._run(name, t[name], true);
    },

    /*
     * probe(includeDangerous)
     *   Without an argument, runs only probes that cannot kill the process.
     *   Pass true to include the ones that may trip SECCOMP_RET_KILL_PROCESS.
     */
    probe: function (includeDangerous) {
        var t = this._tableForArch();
        if (t === null) { this.list(); return; }
        if (this._syscall === null) {
            console.log('[-] syscall() unavailable; cannot probe.');
            return;
        }

        console.log('');
        console.log('=== SECCOMP PROBE ===');
        if (!includeDangerous) {
            console.log('  Running SAFE probes only. Pass true to include probes that may');
            console.log('  terminate the process:  seccomp.probe(true)');
        } else {
            console.log('  *** DANGEROUS MODE. A SECCOMP_RET_KILL_PROCESS verdict will kill');
            console.log('  *** this app instantly. Use a scratch app, never a live target.');
        }
        console.log('');
        console.log('  syscall            result');
        console.log('  ------------------ ------------------------------------------');

        var self = this;
        Object.keys(t).forEach(function (name) {
            var entry = t[name];
            if (entry.kill && !includeDangerous) {
                console.log('  ' + name.padEnd(18) + 'SKIPPED (may kill the process)');
                return;
            }
            self._run(name, entry, false);
        });

        console.log('');
        console.log('  Reading the results:');
        console.log('    EPERM / ENOSYS on a blocklisted call  -> seccomp refused it');
        console.log('    process died                          -> SECCOMP_RET_KILL_PROCESS');
        console.log('    EINVAL / EBADF / EFAULT               -> the call was ALLOWED and');
        console.log('                                             reached its handler; our');
        console.log('                                             deliberately bogus args');
        console.log('                                             then failed harmlessly');
        console.log('    EACCES                                -> ALLOWED by seccomp, then');
        console.log('                                             refused by DAC or SELinux.');
        console.log('                                             Check dmesg for an avc line');
        console.log('                                             to tell those two apart.');
        console.log('');
    },

    _run: function (name, entry, verbose) {
        // Deliberately invalid arguments: if the call is permitted it still
        // does nothing, and fails with EINVAL/EBADF/EFAULT.
        var a = [ptr(0), ptr(0), ptr(0), ptr(0), ptr(0), ptr(0)];
        switch (name) {
            case 'setuid': case 'setgid':
                a[0] = ptr(0xFFFFFFFF); break;          // an invalid id
            case 'setresuid':
                a[0] = ptr(0xFFFFFFFF); a[1] = ptr(0xFFFFFFFF); a[2] = ptr(0xFFFFFFFF); break;
            case 'openat':
                a[0] = ptr(-100 >>> 0); break;          // AT_FDCWD, NULL path -> EFAULT
            case 'ptrace':
                a[0] = ptr(0xFFFF); break;              // invalid request
            case 'prctl':
                a[0] = ptr(0xFFFF); break;              // invalid option -> EINVAL
            case 'socket':
                a[0] = ptr(2); a[1] = ptr(1); a[2] = ptr(0); break;  // AF_INET, SOCK_STREAM
        }

        var r, err;
        try {
            r = this._syscall(ptr(entry.nr), a[0], a[1], a[2], a[3], a[4], a[5]);
            err = (r.toInt32 ? r.toInt32() : Number(r)) < 0 ? this._errno() : 0;
        } catch (e) {
            console.log('  ' + name.padEnd(18) + 'EXCEPTION: ' + e);
            return;
        }

        var rv = (typeof r === 'object' && r.toInt32) ? r.toInt32() : Number(r);
        var verdict;
        if (rv >= 0) {
            verdict = 'ALLOWED (returned ' + rv + ')';
            // Close anything we accidentally opened.
            if (name === 'socket' && rv >= 0) {
                var close = Module.findExportByName('libc.so', 'close');
                if (close) { new NativeFunction(close, 'int', ['int'])(rv); }
            }
        } else {
            var en = this._errno();
            var nm = this._errName(en);
            if (nm === 'EPERM' || nm === 'ENOSYS') {
                verdict = 'REFUSED  ' + nm + '   <- consistent with a seccomp verdict';
            } else if (nm === 'EACCES') {
                verdict = 'REFUSED  EACCES  <- reached the handler; DAC or SELinux said no';
            } else {
                verdict = 'ALLOWED  (' + nm + ' from our deliberately invalid arguments)';
            }
        }
        console.log('  ' + name.padEnd(18) + verdict);
        if (verbose) console.log('  ' + ''.padEnd(18) + 'why blocked: ' + entry.why);
    },

    /* ------------------------------------------ contrast: DAC and SELinux */

    dac: function () {
        console.log('');
        console.log('=== NOT SECCOMP: DAC AND SELINUX, FOR CONTRAST ===');
        console.log('  Every path below is reachable by an ALLOWED syscall (openat).');
        console.log('  The refusals come from a different layer entirely.');
        console.log('');
        var self = this;
        Java.perform(function () {
            var File = Java.use('java.io.File');
            var ctx = Java.use('android.app.ActivityThread')
                          .currentApplication().getApplicationContext();
            var me  = ctx.getPackageName();

            var paths = [
                '/data/data/' + me,
                '/data/data/' + me + '/shared_prefs',
                '/data/system/packages.list',
                '/data/local/tmp',
                '/proc/1/status',
                '/system/etc/permissions/platform.xml',
                '/sys/fs/selinux/enforce',
                ctx.getApplicationInfo().sourceDir.value
            ];

            // Add another app's data directory, which is the interesting case.
            try {
                var pm = ctx.getPackageManager();
                var apps = pm.getInstalledApplications(0);
                for (var i = 0; i < apps.size() && i < 40; i++) {
                    var ai = Java.cast(apps.get(i),
                        Java.use('android.content.pm.ApplicationInfo'));
                    if (ai.packageName.value !== me) {
                        paths.push(ai.dataDir.value);
                        paths.push(ai.sourceDir.value);
                        break;
                    }
                }
            } catch (e) { /* package visibility may hide everything — that is a result */ }

            paths.forEach(function (p) {
                var f = File.$new(p);
                console.log('  ' + p);
                console.log('      exists=' + f.exists() +
                            ' read=' + f.canRead() +
                            ' write=' + f.canWrite() +
                            (f.isDirectory() ? ' [dir]' : ''));
            });
        });
        console.log('');
        console.log('  Your OWN data dir reads true. Another app\'s reads false — that is');
        console.log('  DAC (mode 0700, different owner) with SELinux MCS behind it.');
        console.log('  Another app\'s APK reads TRUE — mode 0644, by design. Nothing');
        console.log('  shipped inside an APK is secret.');
        console.log('');
        console.log('  To attribute a denial correctly, watch the kernel while you');
        console.log('  reproduce it:');
        console.log('    # adb shell as root');
        console.log('    dmesg -w | grep -iE "avc|seccomp"');
        console.log('  An avc: line means SELinux. No avc line plus EACCES means DAC.');
        console.log('');
    },

    help: function () {
        console.log([
            '',
            'seccomp.status()        declared state from /proc/self/status',
            'seccomp.list()          what this script can probe on this arch',
            'seccomp.probe()         run the SAFE probes',
            'seccomp.probe(true)     also run probes that may KILL the process',
            'seccomp.one("chroot")   probe one syscall by name',
            'seccomp.dac()           DAC/SELinux denials, for contrast',
            ''
        ].join('\n'));
    }
};

/* --------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== seccomp-probe — Chapter 21 section 3.5 ===');
    seccomp.init();
    seccomp.status();
    console.log('[+] Ready. seccomp.help() for commands.');
    console.log('[!] probe(true) can terminate the process. Read the header first.');
    console.log('');
});
