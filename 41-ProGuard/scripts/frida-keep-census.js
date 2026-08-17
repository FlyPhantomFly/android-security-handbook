// scripts/frida-keep-census.js
//
// PURPOSE
//   Answer, at RUNTIME, the two questions a static name census cannot:
//
//     1. Of the classes actually LOADED by this process, which kept
//        human-written names and which were renamed? The loaded set is far
//        smaller than the shipped set, and it tells you which of an app's
//        18,000 classes the code path you just exercised really touches.
//     2. Given that you cannot search by name any more, can you find a class
//        by its SHAPE -- superclass, interfaces, field types, method count,
//        presence of native methods? That is the practical substitute for
//        names in an obfuscated app.
//
//   It also flags classes that exist at runtime but are NOT in any classes*.dex
//   of the installed APK, which is the signature of dynamically loaded code.
//
// USAGE
//   # host -- spawn paused so the census sees class loading from the start
//   frida -U -f com.the.app -l scripts/frida-keep-census.js
//   # then, in the Frida REPL:
//   #   %resume
//   #   rpc.exports.census()
//   #   rpc.exports.census({package: "com.the.app"})
//   #   rpc.exports.shape({implements: "java.io.Serializable"})
//   #   rpc.exports.shape({hasNative: true})
//   #   rpc.exports.shape({fieldType: "java.lang.String", methodCount: 3})
//   #   rpc.exports.members("a.a.b")
//   #   rpc.exports.loaders()
//
//   # host -- attach to an already-running app instead
//   frida -U -n com.the.app -l scripts/frida-keep-census.js
//
// REQUIREMENTS
//   * frida-server running on the device, matching your frida client version.
//   * Root, on any normal device.
//   * Frida 14+ (uses Java.enumerateLoadedClassesSync and Java.enumerateClassLoaders).
//
// WHAT THIS WILL *NOT* TELL YOU
//   * It will NOT tell you what a class DOES. It reports names and shapes.
//     Reading the code is jadx's job -- see chapter 56.
//   * It will NOT recover original names. They are gone. A mapping.txt
//     recovers them; nothing else does. This script helps you work WITHOUT
//     them.
//   * The "looks renamed" test is a HEURISTIC -- simple name of three
//     characters or fewer, no underscore. It miscounts a developer's own `Db`
//     and misses an obfuscator that emits long names. It is printed alongside
//     the raw list so you can disagree with it.
//   * enumerateLoadedClassesSync reports classes loaded SO FAR. Run it again
//     after exercising more of the app; the set grows. A class absent from the
//     census may simply not have been touched yet.
//   * It does NOT prove code is dynamically loaded. It reports classes whose
//     defining loader is not the application loader, which is a strong hint
//     and not a proof; see chapter 40 section 3.5 for the real methodology.
//   * It does NOT run on the device this chapter was written against. The
//     attached device (i9000S, Android 13 / API 33) is not rooted and has no
//     frida-server. This script was written and syntax-checked, not executed.
//     Every ADB-based measurement in the chapter WAS executed; this one was
//     not, and the chapter says so rather than implying otherwise.
//
// AUTHORISED TESTING ONLY.

'use strict';

// --------------------------------------------------------------------------- //
// Heuristics
// --------------------------------------------------------------------------- //

// A machine-generated identifier, as every shrinker on this platform emits
// them: one to three characters from the default dictionary, optionally with a
// digit. Deliberately the SAME rule as scripts/what-survived.py, so the static
// and dynamic censuses are comparable.
const RENAMED = /^[a-zA-Z][a-zA-Z0-9]{0,2}$/;

function simpleName(fq) {
    let s = fq.substring(fq.lastIndexOf('.') + 1);
    if (s.indexOf('$') >= 0) {
        s = s.substring(s.lastIndexOf('$') + 1);
    }
    return s;
}

function looksRenamed(fq) {
    const s = simpleName(fq);
    if (/^\d+$/.test(s)) return false;        // Foo$1 -- an anonymous class
    return RENAMED.test(s);
}

function packageOf(fq) {
    const i = fq.lastIndexOf('.');
    return i < 0 ? '(default)' : fq.substring(0, i);
}

// Classes that are never the app's own and only add noise to a census.
const FRAMEWORK = [
    'android.', 'androidx.', 'java.', 'javax.', 'sun.', 'com.sun.',
    'dalvik.', 'libcore.', 'org.w3c.', 'org.xml.', 'org.json.',
    'org.apache.harmony.', 'com.android.internal.',
];

function isFramework(fq) {
    for (let i = 0; i < FRAMEWORK.length; i++) {
        if (fq.indexOf(FRAMEWORK[i]) === 0) return true;
    }
    return false;
}

function loadedClasses(includeFramework) {
    const all = Java.enumerateLoadedClassesSync();
    if (includeFramework) return all;
    return all.filter(function (c) { return !isFramework(c); });
}

// --------------------------------------------------------------------------- //
// 1. The census
// --------------------------------------------------------------------------- //
function census(opts) {
    opts = opts || {};
    let out = '';
    Java.perform(function () {
        let list = loadedClasses(!!opts.includeFramework);
        if (opts.package) {
            // Renaming rewrites the PACKAGE as well as the class, so filtering
            // by the original package systematically hides the renamed
            // classes. Report both halves so the number is not misleading.
            const inPkg = list.filter(function (c) { return c.indexOf(opts.package) === 0; });
            const outPkg = list.filter(function (c) {
                return c.indexOf(opts.package) !== 0 && looksRenamed(c);
            });
            out += '[!] --package hides renamed classes: renaming moves them out of\n';
            out += '    your package entirely. ' + outPkg.length + ' renamed class(es) sit\n';
            out += '    outside "' + opts.package + '". Examples: '
                + outPkg.slice(0, 5).join(', ') + '\n\n';
            list = inPkg;
        }

        const renamed = list.filter(looksRenamed);
        const kept = list.filter(function (c) { return !looksRenamed(c); });

        out += '=== RUNTIME NAME CENSUS ===\n';
        out += 'loaded classes considered : ' + list.length + '\n';
        out += 'machine-generated names   : ' + renamed.length
            + ' (' + pct(renamed.length, list.length) + ')\n';
        out += 'original-looking names    : ' + kept.length
            + ' (' + pct(kept.length, list.length) + ')\n\n';

        // Package distribution. The interesting output is a SPLIT: some
        // packages fully mangled, some fully intact. An intact package in an
        // otherwise mangled app is a package somebody wrote a keep rule for,
        // and it is where they thought the value was.
        const pkgs = {};
        list.forEach(function (c) {
            const p = packageOf(c);
            if (!pkgs[p]) pkgs[p] = { r: 0, k: 0 };
            if (looksRenamed(c)) pkgs[p].r++; else pkgs[p].k++;
        });
        const rows = Object.keys(pkgs).sort(function (a, b) {
            return (pkgs[b].r + pkgs[b].k) - (pkgs[a].r + pkgs[a].k);
        });
        out += '--- packages, by loaded class count ---\n';
        rows.slice(0, 40).forEach(function (p) {
            out += '  ' + pad(p, 54) + ' renamed=' + pad(String(pkgs[p].r), 5)
                + ' kept=' + pkgs[p].k + '\n';
        });

        out += '\n--- classes that kept their names (first 60) ---\n';
        kept.slice(0, 60).forEach(function (c) { out += '  ' + c + '\n'; });
        if (kept.length > 60) out += '  ... and ' + (kept.length - 60) + ' more\n';

        out += '\nThese are ENTRY POINTS, native-bound classes, reflection targets\n';
        out += 'and serialisation models -- or the fallout of an over-broad -keep.\n';
        out += 'Compare against the static census:\n';
        out += '  python3 -B scripts/what-survived.py app.apk --rules rules.pro\n';
    });
    console.log(out);
    return out;
}

// --------------------------------------------------------------------------- //
// 2. Shape search -- finding a class when you cannot search by name
// --------------------------------------------------------------------------- //
//
// Every filter is optional; all supplied filters must match.
//
//   extends      : fully qualified superclass name
//   implements   : fully qualified interface name (direct interfaces only)
//   hasNative    : true  -- the class declares at least one native method
//   methodCount  : exact number of DECLARED methods
//   fieldType    : a declared field of this type exists
//   methodNamed  : a declared method with this exact name exists (useful for
//                  members kept by a -keepclassmembers rule while the class
//                  itself was renamed -- section 6.3 of the README)
//   returns      : a declared method with this return type exists
//   package      : class name prefix
//   limit        : cap the result list (default 80)
//
function shape(filter) {
    filter = filter || {};
    const limit = filter.limit || 80;
    const hits = [];
    let out = '';

    Java.perform(function () {
        const Modifier = Java.use('java.lang.reflect.Modifier');
        const NATIVE = Modifier.NATIVE.value;
        const list = loadedClasses(!!filter.includeFramework);

        for (let i = 0; i < list.length && hits.length < limit; i++) {
            const name = list[i];
            if (filter.package && name.indexOf(filter.package) !== 0) continue;

            let cls;
            try {
                cls = Java.use(name).class;
            } catch (e) {
                continue;                       // not resolvable through this loader
            }

            try {
                if (filter.extends) {
                    const sup = cls.getSuperclass();
                    if (!sup || sup.getName() !== filter.extends) continue;
                }
                if (filter.implements) {
                    const ifaces = cls.getInterfaces();
                    let found = false;
                    for (let k = 0; k < ifaces.length; k++) {
                        if (ifaces[k].getName() === filter.implements) { found = true; break; }
                    }
                    if (!found) continue;
                }

                const methods = cls.getDeclaredMethods();
                if (filter.methodCount !== undefined && methods.length !== filter.methodCount) continue;

                if (filter.hasNative) {
                    let nat = false;
                    for (let k = 0; k < methods.length; k++) {
                        if ((methods[k].getModifiers() & NATIVE) !== 0) { nat = true; break; }
                    }
                    if (!nat) continue;
                }
                if (filter.methodNamed) {
                    let ok = false;
                    for (let k = 0; k < methods.length; k++) {
                        if (methods[k].getName() === filter.methodNamed) { ok = true; break; }
                    }
                    if (!ok) continue;
                }
                if (filter.returns) {
                    let ok = false;
                    for (let k = 0; k < methods.length; k++) {
                        if (methods[k].getReturnType().getName() === filter.returns) { ok = true; break; }
                    }
                    if (!ok) continue;
                }
                if (filter.fieldType) {
                    const fields = cls.getDeclaredFields();
                    let ok = false;
                    for (let k = 0; k < fields.length; k++) {
                        if (fields[k].getType().getName() === filter.fieldType) { ok = true; break; }
                    }
                    if (!ok) continue;
                }
            } catch (e) {
                continue;                       // reflection refused; skip rather than abort
            }

            hits.push(name);
        }

        out += '=== SHAPE SEARCH ===\n';
        out += 'filter: ' + JSON.stringify(filter) + '\n';
        out += 'matches: ' + hits.length + (hits.length >= limit ? ' (capped)' : '') + '\n\n';
        hits.forEach(function (h) {
            out += '  ' + h + (looksRenamed(h) ? '   [renamed]' : '') + '\n';
        });
        out += '\nNext: rpc.exports.members("<one of the above>")\n';
    });

    console.log(out);
    return hits;
}

// --------------------------------------------------------------------------- //
// 3. Members of one class -- the post-rename truth
// --------------------------------------------------------------------------- //
function members(name) {
    let out = '';
    Java.perform(function () {
        let cls;
        try {
            cls = Java.use(name).class;
        } catch (e) {
            console.log('cannot resolve ' + name + ': ' + e);
            return;
        }
        out += '=== ' + name + ' ===\n';
        const sup = cls.getSuperclass();
        out += 'extends    : ' + (sup ? sup.getName() : '(none)') + '\n';
        const ifaces = cls.getInterfaces();
        out += 'implements : ' + (ifaces.length
            ? Array.prototype.map.call(ifaces, function (i) { return i.getName(); }).join(', ')
            : '(none)') + '\n\n';

        out += 'fields:\n';
        const fields = cls.getDeclaredFields();
        for (let i = 0; i < fields.length; i++) {
            const f = fields[i];
            out += '  ' + pad(f.getType().getName(), 40) + ' ' + f.getName()
                + (looksRenamed(f.getName()) ? '' : '     <-- name kept') + '\n';
        }

        out += '\nmethods:\n';
        const methods = cls.getDeclaredMethods();
        for (let i = 0; i < methods.length; i++) {
            const m = methods[i];
            const params = Array.prototype.map.call(m.getParameterTypes(),
                function (p) { return p.getName(); }).join(', ');
            out += '  ' + pad(m.getReturnType().getName(), 30) + ' ' + m.getName()
                + '(' + params + ')'
                + (looksRenamed(m.getName()) ? '' : '     <-- name kept') + '\n';
        }

        out += '\nA member whose name was KEPT while the class was renamed is a\n';
        out += '-keepclassmembers rule made visible. Ask what reads it by name:\n';
        out += 'serialisation, JSON, reflection, or JNI.\n';
    });
    console.log(out);
    return out;
}

// --------------------------------------------------------------------------- //
// 4. Class loaders -- where dynamically loaded code shows up
// --------------------------------------------------------------------------- //
function loaders() {
    let out = '';
    Java.perform(function () {
        out += '=== CLASS LOADERS ===\n';
        Java.enumerateClassLoaders({
            onMatch: function (l) {
                out += '  ' + l.toString() + '\n';
            },
            onComplete: function () {
                out += '\nMore than the expected PathClassLoader/BootClassLoader pair means\n';
                out += 'code is being loaded from somewhere other than the installed APK.\n';
                out += 'That code is invisible to any static analysis of classes*.dex,\n';
                out += 'including scripts/what-survived.py. See chapter 40 section 3.5.\n';
            },
        });
    });
    console.log(out);
    return out;
}

// --------------------------------------------------------------------------- //
// helpers
// --------------------------------------------------------------------------- //
function pad(s, n) {
    s = String(s);
    while (s.length < n) s += ' ';
    return s;
}

function pct(a, b) {
    if (!b) return '0.0%';
    return (100.0 * a / b).toFixed(1) + '%';
}

rpc.exports = {
    census: census,
    shape: shape,
    members: members,
    loaders: loaders,
};

console.log('[ch41] keep census loaded. Try:');
console.log('  rpc.exports.census()');
console.log('  rpc.exports.shape({implements: "java.io.Serializable"})');
console.log('  rpc.exports.shape({hasNative: true})');
console.log('  rpc.exports.members("<class>")');
console.log('  rpc.exports.loaders()');
