// scripts/trace-app-startup.js
//
// WHAT IT DOES
//   Traces the Android app bootstrap in order: attachBaseContext -> every ContentProvider
//   onCreate -> Application.onCreate -> first Activity onCreate. Also prints the process's
//   own identity (uid, pid, process name, data dir) and every System.loadLibrary call, so
//   you can see which native code ran before any of your other hooks were installed.
//
// HOW TO RUN
//   frida -U -f com.example.app --no-pause -l scripts/trace-app-startup.js
//   (SPAWN, not attach — attaching means the bootstrap has already finished.)
//
// REQUIREMENTS
//   frida-server running as root on the device, OR a repackaged APK with the Frida Gadget.

'use strict';

const t0 = Date.now();
function ts() {
  const d = Date.now() - t0;
  return '[' + String(d).padStart(6, ' ') + ' ms]';
}
function log(msg) {
  console.log(ts() + ' ' + msg);
}

Java.perform(function () {
  // ---------------------------------------------------------------- identity
  try {
    const Process_ = Java.use('android.os.Process');
    const ActivityThread = Java.use('android.app.ActivityThread');
    const uid = Process_.myUid();
    const pid = Process_.myPid();
    const procName = ActivityThread.currentProcessName
      ? ActivityThread.currentProcessName()
      : '(unknown)';
    const userId = Math.floor(uid / 100000);
    const appId = uid % 100000;
    log('=== process identity ===');
    log('  uid          : ' + uid + '  (userId=' + userId + ', appId=' + appId + ')');
    log('  pid          : ' + pid);
    log('  process name : ' + procName);
  } catch (e) {
    log('identity probe failed: ' + e);
  }

  // ------------------------------------------------- Application.attachBaseContext
  const Application = Java.use('android.app.Application');
  Application.attachBaseContext.overload('android.content.Context').implementation = function (ctx) {
    log('(1) Application.attachBaseContext  class=' + this.$className);
    try {
      const ai = ctx.getApplicationInfo();
      log('    packageName      : ' + ctx.getPackageName());
      log('    dataDir          : ' + ai.dataDir.value);
      log('    deviceProtected  : ' + ai.deviceProtectedDataDir.value);
      log('    nativeLibraryDir : ' + ai.nativeLibraryDir.value);
      log('    sourceDir        : ' + ai.sourceDir.value);
      // FLAG_DEBUGGABLE == 0x2
      log('    debuggable       : ' + ((ai.flags.value & 0x2) !== 0));
    } catch (e) {
      log('    (context not fully usable yet: ' + e + ')');
    }
    return this.attachBaseContext(ctx);
  };

  // ----------------------------------------------------- ContentProvider.onCreate
  // Every provider in the MERGED manifest runs here, before Application.onCreate.
  // This is where androidx.startup and most SDK initialisation actually happens.
  const ContentProvider = Java.use('android.content.ContentProvider');
  ContentProvider.onCreate.implementation = function () {
    log('(2) ContentProvider.onCreate  ' + this.$className);
    const r = this.onCreate();
    log('    -> returned ' + r);
    return r;
  };

  // androidx.startup initialisers, when present.
  try {
    const Initializer = Java.use('androidx.startup.AppInitializer');
    Initializer.doInitialize.overload('java.lang.Class', 'java.util.Set').implementation =
      function (cls, set) {
        log('(2a) androidx.startup doInitialize  ' + cls.getName());
        return this.doInitialize(cls, set);
      };
  } catch (e) {
    // androidx.startup is simply not present; not an error.
  }

  // ------------------------------------------------------- Application.onCreate
  Application.onCreate.implementation = function () {
    log('(3) Application.onCreate  class=' + this.$className);
    return this.onCreate();
  };

  // ------------------------------------------------------------ Activity.onCreate
  const Activity = Java.use('android.app.Activity');
  Activity.onCreate.overload('android.os.Bundle').implementation = function (b) {
    log('(4) Activity.onCreate  ' + this.$className);
    return this.onCreate(b);
  };

  // ------------------------------------------------------- native library loading
  const System = Java.use('java.lang.System');
  System.loadLibrary.overload('java.lang.String').implementation = function (name) {
    log('    System.loadLibrary("' + name + '")  <-- JNI_OnLoad and any .so ' +
        'constructors run inside this call');
    return this.loadLibrary(name);
  };
  const Runtime = Java.use('java.lang.Runtime');
  Runtime.loadLibrary0.overload('java.lang.Class', 'java.lang.String').implementation =
    function (cls, name) {
      log('    Runtime.loadLibrary0("' + name + '") from ' + cls.getName());
      return this.loadLibrary0(cls, name);
    };
});
