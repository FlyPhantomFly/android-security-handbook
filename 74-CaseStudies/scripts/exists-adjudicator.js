// scripts/exists-adjudicator.js  --  frida -U -f <pkg> -l scripts/exists-adjudicator.js
// Reports, per path: what the app concluded, and what the app COULD have concluded.
// A path that is FORBIDDEN from the app uid can only ever yield `false` -- so the check is inert.
Java.perform(function () {
    var File = Java.use("java.io.File");
    var Os = Java.use("android.system.Os");
    var Errno = Java.use("android.system.ErrnoException");
    var C = Java.use("android.system.OsConstants");
    var seen = {};

    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        var answer = this.exists();

        if (!(path in seen)) {
            var truth;
            try { Os.stat(path); truth = "PRESENT"; }
            catch (e) {
                var err = Java.cast(e.$h, Errno);
                if (err.errno.value === C.ENOENT.value)      truth = "ABSENT";
                else if (err.errno.value === C.EACCES.value) truth = "FORBIDDEN";
                else                                         truth = "ERRNO " + err.errno.value;
            }
            seen[path] = truth;
            var verdict = (truth === "FORBIDDEN")
                ? "  <== INERT: this check cannot distinguish present from absent"
                : "";
            console.log("[exists] " + path + "  app_saw=" + answer +
                        "  reality=" + truth + verdict);
        }
        return answer;
    };
    console.log("[*] exists-adjudicator installed");
});
