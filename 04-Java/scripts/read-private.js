// scripts/read-private.js — Frida
// Purpose: read a private instance field from every live instance of a class.
// Run:     frida -U -n com.target.app -l read-private.js
Java.perform(function () {
    Java.choose('com.target.app.SessionManager', {
        onMatch: function (instance) {
            // Frida applies the same reflective access as setAccessible(true).
            console.log('[+] instance ' + instance);
            console.log('    token  = ' + instance.authToken.value);
            console.log('    userId = ' + instance.userId.value);
        },
        onComplete: function () { console.log('[*] scan complete'); }
    });
});
