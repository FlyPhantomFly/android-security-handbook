// frida -U -f com.example.target -l root-check-observer.js --no-pause
//
// Purpose : Observe (do NOT bypass) every root-detection-shaped operation the app performs,
//           so you can build an accurate inventory before deciding how to neutralise it.
// Usage   : frida -U -f <package> -l root-check-observer.js
// Requires: frida-server running on the device as root, at a version matching the host
//           frida/frida-tools; a SPAWN session (-f), because many checks run in a static
//           initialiser that has already executed by the time you could attach.
// Notes   : Observation only. Nothing is modified. Use bypass-root-checks.js afterwards.
//
// What this will NOT tell you:
//   * Checks that never enter libc through an exported symbol. A probe issued as
//     syscall(__NR_faccessat, ...) or as inline "svc #0" is invisible here.
//   * Checks in a library that is dlopen()ed after this script loads: the native hooks
//     are installed once, against whatever libc is already mapped.
//   * What the app DID with the answer. This prints probes, not decisions; a check whose
//     consequence is decoupled from its detection will look completely benign.
//   * Anything decided off-device. A Play Integrity verdict is computed on a server and
//     no amount of client-side observation reaches it.

'use strict';

function stack() {
  return Java.use('android.util.Log')
    .getStackTraceString(Java.use('java.lang.Exception').$new());
}

const INTERESTING = [
  'su', 'magisk', 'busybox', 'supersu', 'superuser', 'xposed', 'frida',
  '/data/adb', 'test-keys', 'mountinfo', '/proc/mounts', 'daemonsu', 'kernelsu'
];

function isInteresting(s) {
  if (s === null || s === undefined) return false;
  const l = String(s).toLowerCase();
  return INTERESTING.some(k => l.indexOf(k) !== -1);
}

Java.perform(function () {
  // ---- java.io.File construction and existence probes -----------------------
  const File = Java.use('java.io.File');

  File.$init.overload('java.lang.String').implementation = function (path) {
    if (isInteresting(path)) {
      console.log('[File.<init>] "' + path + '"\n' + stack());
    }
    return this.$init(path);
  };

  File.exists.implementation = function () {
    const r = this.exists();
    const p = this.getAbsolutePath();
    if (isInteresting(p)) {
      console.log('[File.exists] "' + p + '" -> ' + r);
    }
    return r;
  };

  File.canRead.implementation = function () {
    const r = this.canRead();
    if (isInteresting(this.getAbsolutePath())) {
      console.log('[File.canRead] "' + this.getAbsolutePath() + '" -> ' + r);
    }
    return r;
  };

  // ---- Runtime.exec --------------------------------------------------------
  const Runtime = Java.use('java.lang.Runtime');

  Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
    console.log('[Runtime.exec] "' + cmd + '"\n' + stack());
    return this.exec(cmd);
  };

  Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
    console.log('[Runtime.exec[]] ' + JSON.stringify(cmds) + '\n' + stack());
    return this.exec(cmds);
  };

  // ---- System properties ---------------------------------------------------
  const SystemProperties = Java.use('android.os.SystemProperties');
  SystemProperties.get.overload('java.lang.String').implementation = function (k) {
    const v = this.get(k);
    console.log('[SystemProperties.get] ' + k + ' = "' + v + '"');
    return v;
  };
  SystemProperties.get.overload('java.lang.String', 'java.lang.String')
    .implementation = function (k, d) {
      const v = this.get(k, d);
      console.log('[SystemProperties.get] ' + k + ' = "' + v + '" (default "' + d + '")');
      return v;
    };

  // ---- PackageManager lookups ---------------------------------------------
  const PM = Java.use('android.app.ApplicationPackageManager');
  PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (p, f) {
    if (isInteresting(p)) console.log('[getPackageInfo] "' + p + '"\n' + stack());
    return this.getPackageInfo(p, f);
  };

  console.log('[*] Root-check observer installed. Exercise the app now.');
});

// ---- Native layer: catch checks that never touch Java ----------------------
['open', 'openat', 'access', 'stat', 'lstat', 'fopen'].forEach(function (name) {
  const addr = Module.findExportByName('libc.so', name);
  if (addr === null) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      // The path argument index differs: openat/stat family put it in different slots.
      const idx = (name === 'openat') ? 1 : 0;
      try {
        const p = args[idx].readUtf8String();
        if (p && INTERESTING.some(k => p.toLowerCase().indexOf(k) !== -1)) {
          console.log('[native ' + name + '] "' + p + '"\n' +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
              .map(DebugSymbol.fromAddress).join('\n'));
        }
      } catch (e) { /* unreadable pointer */ }
    }
  });
});
