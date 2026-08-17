// scripts/trace-classloader.js — Frida
// Purpose: detect DEX loaded from outside the APK, including in-memory loading.
// Run:     frida -U -f com.target.app -l trace-classloader.js --no-pause
Java.perform(function () {
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.implementation = function (path, opt, lib, parent) {
        console.log('[DexClassLoader] path=' + path + ' optimizedDir=' + opt);
        return this.$init(path, opt, lib, parent);
    };

    try {
        var InMem = Java.use('dalvik.system.InMemoryDexClassLoader');
        InMem.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
            .implementation = function (buf, parent) {
                console.log('[InMemoryDexClassLoader] ' + buf.remaining() + ' bytes');
                // Dump the DEX so it can be analysed statically.
                var bytes = Java.array('byte', []);   // placeholder; see chapter 68 for full dumper
                return this.$init(buf, parent);
            };
    } catch (e) {
        console.log('[i] InMemoryDexClassLoader not present on this API level');
    }
});
