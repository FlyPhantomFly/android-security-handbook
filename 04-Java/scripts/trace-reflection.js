// scripts/trace-reflection.js — Frida
// Purpose: reveal reflective class loading and method invocation, defeating string obfuscation.
// Run:     frida -U -f com.target.app -l trace-reflection.js --no-pause
Java.perform(function () {
    var Class = Java.use('java.lang.Class');
    var Method = Java.use('java.lang.reflect.Method');

    Class.forName.overload('java.lang.String').implementation = function (name) {
        console.log('[forName] ' + name);
        return this.forName(name);
    };

    Class.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader')
        .implementation = function (name, init, loader) {
            console.log('[forName] ' + name + '   (loader ' + loader + ')');
            return this.forName(name, init, loader);
        };

    Class.getDeclaredMethod.overload('java.lang.String', '[Ljava.lang.Class;')
        .implementation = function (name, types) {
            console.log('[getDeclaredMethod] ' + this.getName() + '.' + name);
            return this.getDeclaredMethod(name, types);
        };

    Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;')
        .implementation = function (target, args) {
            console.log('[invoke] ' + this.getDeclaringClass().getName() + '.' + this.getName());
            return this.invoke(target, args);
        };
});
