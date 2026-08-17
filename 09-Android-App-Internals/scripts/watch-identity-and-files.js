// scripts/watch-identity-and-files.js
//
// WHAT IT DOES
//   1. Prints every call the app makes to identity-related PackageManager APIs, which is how
//      you find naive package-name checks, installer-attribution checks and signature checks.
//   2. Hooks libc open()/openat() so you see every file the app touches, with the path,
//      including paths outside its own data directory (the shared-UID smoking gun).
//
// HOW TO RUN
//   frida -U -f com.example.app --no-pause -l scripts/watch-identity-and-files.js
//
// NOTE
//   The libc hook is noisy. Narrow FILTER below before using it on a busy app.

'use strict';

const FILTER = /\/data\/(user|user_de|data|app)\//;   // only report interesting paths

Java.perform(function () {
  const PM = Java.use('android.content.pm.PackageManager');
  const Binder = Java.use('android.os.Binder');

  // --- naive identity checks -------------------------------------------------
  PM.getPackagesForUid.implementation = function (uid) {
    const r = this.getPackagesForUid(uid);
    console.log('[identity] getPackagesForUid(' + uid + ') -> ' + (r ? r.join(',') : 'null'));
    return r;
  };

  try {
    PM.getInstallerPackageName.implementation = function (pkg) {
      const r = this.getInstallerPackageName(pkg);
      console.log('[identity] getInstallerPackageName("' + pkg + '") -> ' + r +
                  '   <-- WEAK check if the result is compared to com.android.vending');
      return r;
    };
  } catch (e) { /* removed on some releases */ }

  try {
    PM.hasSigningCertificate.overload('java.lang.String', '[B', 'int').implementation =
      function (pkg, cert, type) {
        const r = this.hasSigningCertificate(pkg, cert, type);
        console.log('[identity] hasSigningCertificate("' + pkg + '", …, ' + type + ') -> ' + r +
                    '   <-- GOOD check');
        return r;
      };
  } catch (e) { /* not called by this app */ }

  Binder.getCallingUid.implementation = function () {
    const r = this.getCallingUid();
    console.log('[identity] Binder.getCallingUid() -> ' + r +
                ' (userId=' + Math.floor(r / 100000) + ', appId=' + (r % 100000) + ')');
    return r;
  };
});

// --- native file access ------------------------------------------------------
['open', 'openat'].forEach(function (fn) {
  const p = Module.findExportByName('libc.so', fn);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (args) {
      // open(path, flags) ; openat(dirfd, path, flags)
      const pathArg = (fn === 'open') ? args[0] : args[1];
      try {
        const path = pathArg.readUtf8String();
        if (path && FILTER.test(path)) {
          console.log('[file] ' + fn + '("' + path + '")');
        }
      } catch (e) { /* unreadable pointer */ }
    }
  });
});
