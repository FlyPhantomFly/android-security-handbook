// scripts/trace-equals.js — Frida
// Purpose: log every String.equals call with both operands, plus a stack trace when
//          the comparison involves a value that looks like a secret.
// Run:     frida -U -f com.target.app -l trace-equals.js
Java.perform(function () {
    var JavaString = Java.use('java.lang.String');
    var Log = Java.use('android.util.Log');
    var Exception = Java.use('java.lang.Exception');

    var SUSPICIOUS = /token|secret|key|pass|pin|otp|licen[cs]e|su\b|magisk|root/i;

    JavaString.equals.overload('java.lang.Object').implementation = function (other) {
        var result = this.equals(other);
        var self = this.toString();
        var arg = (other === null) ? 'null' : other.toString();

        if (SUSPICIOUS.test(self) || SUSPICIOUS.test(arg)) {
            console.log('[equals] "' + self + '"  vs  "' + arg + '"  =>  ' + result);
            console.log(Log.getStackTraceString(Exception.$new()));
        }
        return result;
    };
});
