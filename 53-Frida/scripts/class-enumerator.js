/*
 * class-enumerator.js — class loaders, loaded classes, and class structure.
 *
 * WHAT IT DOES
 *   Answers the four questions you ask at the start of every Java-side
 *   engagement, and solves the single most common Frida error on Android:
 *
 *     1. WHICH CLASS LOADERS EXIST?  An app routinely has several: the
 *        BootClassLoader, the PathClassLoader for base.apk, split-APK loaders,
 *        and — for packed apps — a DexClassLoader or InMemoryDexClassLoader
 *        holding the classes you actually care about.
 *
 *     2. WHERE IS THIS CLASS?  Java.use resolves through
 *        Java.classFactory.loader only. A class in a CHILD loader is invisible
 *        from there, which produces ClassNotFoundException for a class you can
 *        see plainly in JADX. This script finds it in any loader and hands you
 *        a working wrapper.
 *
 *     3. WHAT CLASSES EXIST?  Filtered enumeration of loaded classes, plus a
 *        "wait for it" mode that hooks ClassLoader.loadClass so you catch a
 *        class that does not exist yet.
 *
 *     4. WHAT IS IN THIS CLASS?  Full member dump: fields with values, methods
 *        with exact overload signatures ready to paste into .overload(),
 *        superclass, interfaces, and the loader that defined it.
 *
 * WHY IT WORKS
 *   Class loading in Java delegates UPWARD: a loader asks its parent before
 *   searching its own path. A parent therefore cannot see a child's classes.
 *   See ../README.md section 7.4.2 for the full explanation and
 *   ../../40-Obfuscation/README.md for why packers exploit this.
 *
 * HOW TO RUN
 *   frida -U -f com.example.app -l class-enumerator.js --no-pause
 *
 *   Then from the REPL:
 *     cls.help()
 *     cls.loaders()                              list every loader
 *     cls.find("com.example.secret.Engine")      locate a class in ANY loader
 *     cls.use("com.example.secret.Engine")       get a WORKING wrapper
 *     cls.list("com.example.*")                  loaded classes matching a pattern
 *     cls.dump("com.example.auth.PinValidator")  full member listing
 *     cls.overloads("com.example.A", "check")    exact .overload() strings
 *     cls.waitFor("com.example.secret.*", cb)    act when a class appears
 *     cls.instances("com.example.Session")       live objects on the heap
 *     cls.implementers("com.example.Validator")  concrete implementations
 *     cls.dexes()                                DEX files each loader knows about
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

var cls = {

    /* ------------------------------------------------------------- state */

    _loaders: [],
    _watchers: [],
    _loadClassHooked: false,

    /* ==================================================================
     * 1. CLASS LOADERS
     * ================================================================== */

    loaders: function () {
        var self = this;
        this._loaders = [];

        Java.perform(function () {
            var i = 0;
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    self._loaders.push(loader);
                    var desc = String(loader);
                    var kind = self._loaderKind(desc);

                    console.log('[' + i + '] ' + kind);
                    // The toString of a BaseDexClassLoader includes its whole
                    // DexPathList, which is long but informative. Wrap it.
                    self._wrap(desc, '      ').forEach(function (line) {
                        console.log(line);
                    });

                    // Show the delegation parent, which is what determines
                    // visibility.
                    try {
                        var parent = loader.getParent();
                        console.log('      parent: ' +
                            (parent === null ? '<none — this is the boot loader>'
                                             : self._loaderKind(String(parent))));
                    } catch (e) { /* some loaders refuse */ }

                    console.log('');
                    i++;
                },
                onComplete: function () {
                    console.log('[*] ' + i + ' class loader(s)');
                    if (i > 2) {
                        console.log('    More than two loaders usually means either');
                        console.log('    split APKs or a packer. If Java.use throws');
                        console.log('    ClassNotFoundException, use cls.use(name).');
                    }
                }
            });
        });

        return this._loaders.length;
    },

    _loaderKind: function (desc) {
        if (desc.indexOf('BootClassLoader') !== -1) return 'BootClassLoader (java.*, android.*)';
        if (desc.indexOf('InMemoryDexClassLoader') !== -1)
            return 'InMemoryDexClassLoader  ← DEX from a ByteBuffer; a PACKER signature';
        if (desc.indexOf('DexClassLoader') !== -1)
            return 'DexClassLoader  ← dynamically loaded DEX from disk';
        if (desc.indexOf('PathClassLoader') !== -1) return 'PathClassLoader (the app APK)';
        if (desc.indexOf('DelegateLastClassLoader') !== -1) return 'DelegateLastClassLoader';
        return desc.split('[')[0];
    },

    _wrap: function (text, indent) {
        var out = [];
        var chunk = 100;
        for (var i = 0; i < text.length && i < 1200; i += chunk) {
            out.push(indent + text.substring(i, i + chunk));
        }
        if (text.length > 1200) out.push(indent + '… (truncated)');
        return out;
    },

    /* Show which DEX files each loader has, which tells you where code came from. */
    dexes: function () {
        var self = this;
        Java.perform(function () {
            var i = 0;
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    var desc = String(loader);
                    // Extract quoted paths from the DexPathList representation.
                    var paths = desc.match(/"[^"]+"/g) || [];
                    if (paths.length === 0) { i++; return; }
                    console.log('[' + i + '] ' + self._loaderKind(desc));
                    paths.forEach(function (p) {
                        console.log('      ' + p.replace(/"/g, ''));
                    });
                    console.log('');
                    i++;
                },
                onComplete: function () {}
            });
        });
    },

    /* ==================================================================
     * 2. FINDING A CLASS ANYWHERE
     * ================================================================== */

    /*
     * Locate a class in any loaded ClassLoader. Returns the loader, or null.
     * This is the diagnostic; cls.use() is the thing you actually call.
     */
    find: function (className) {
        var result = null;

        Java.perform(function () {
            var checked = 0;
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    checked++;
                    if (result !== null) return;
                    try {
                        loader.loadClass(className);
                        result = loader;
                    } catch (e) { /* not in this loader */ }
                },
                onComplete: function () {
                    if (result !== null) {
                        console.log('[+] ' + className + ' found in:');
                        console.log('      ' + String(result).substring(0, 200));
                        console.log('    Get a working wrapper with:');
                        console.log('      cls.use("' + className + '")');
                    } else {
                        console.log('[-] ' + className + ' is not in any of the ' +
                                    checked + ' currently loaded loader(s).');
                        console.log('    Two possibilities:');
                        console.log('      a) It has not been loaded YET. Use:');
                        console.log('           cls.waitFor("' + className + '", fn)');
                        console.log('      b) The name is wrong. Check for an inner class');
                        console.log('         (Outer$Inner) or an R8-renamed name. Try:');
                        console.log('           cls.list("*' +
                                    className.split('.').pop() + '*")');
                    }
                }
            });
        });

        return result;
    },

    /*
     * Return a WORKING class wrapper regardless of which loader owns the class.
     * This is a drop-in replacement for Java.use that does not throw
     * ClassNotFoundException for child-loader classes.
     *
     * Prefers Java.ClassFactory.get(loader), which yields a factory bound to
     * that loader without disturbing the global default. Falls back to the
     * save/restore dance on older Frida.
     */
    use: function (className) {
        var wrapper = null;

        Java.perform(function () {
            // Fast path: the default loader already sees it.
            try {
                wrapper = Java.use(className);
                return;
            } catch (e) { /* fall through to the search */ }

            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    if (wrapper !== null) return;
                    try {
                        loader.loadClass(className);
                    } catch (e) { return; }

                    try {
                        if (typeof Java.ClassFactory !== 'undefined' &&
                            typeof Java.ClassFactory.get === 'function') {
                            // Preferred: a factory bound to THIS loader. Leaves
                            // Java.classFactory.loader untouched, so other
                            // modules keep working (../README.md section 7.4.2).
                            wrapper = Java.ClassFactory.get(loader).use(className);
                        } else {
                            var previous = Java.classFactory.loader;
                            Java.classFactory.loader = loader;
                            wrapper = Java.use(className);
                            Java.classFactory.loader = previous;   // ALWAYS restore
                        }
                        console.log('[+] resolved ' + className + ' via a non-default loader');
                    } catch (e2) {
                        console.log('[-] loader claimed the class but use() failed: ' +
                                    e2.message);
                    }
                },
                onComplete: function () {}
            });
        });

        if (wrapper === null) {
            console.log('[-] could not resolve ' + className + ' in any loader');
        }
        return wrapper;
    },

    /* ==================================================================
     * 3. ENUMERATION
     * ================================================================== */

    _wild: function (pattern) {
        var escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
                             .replace(/\*/g, '.*')
                             .replace(/\?/g, '.');
        return new RegExp('^' + escaped + '$');
    },

    list: function (pattern, limit) {
        var re = this._wild(pattern || '*');
        limit = limit || 300;
        var matches = [];

        Java.perform(function () {
            var total = 0;
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    total++;
                    if (re.test(name)) matches.push(name);
                },
                onComplete: function () {
                    matches.sort();
                    console.log('[*] ' + matches.length + ' of ' + total +
                                ' loaded classes match "' + pattern + '"');
                    matches.slice(0, limit).forEach(function (n) {
                        console.log('      ' + n);
                    });
                    if (matches.length > limit) {
                        console.log('      … ' + (matches.length - limit) + ' more');
                    }
                    if (matches.length === 0) {
                        console.log('    Nothing matched. Remember enumerateLoadedClasses');
                        console.log('    only reports classes that have been LOADED, and');
                        console.log('    only from loaders ART knows about. For a packed');
                        console.log('    app, run cls.loaders() first.');
                    }
                }
            });
        });

        return matches;
    },

    /*
     * Classes present in a specific loader, which is how you see what a packer
     * actually delivered.
     */
    listInLoader: function (loaderIndex, pattern) {
        var self = this;
        if (this._loaders.length === 0) this.loaders();
        var loader = this._loaders[loaderIndex];
        if (loader === undefined) {
            console.log('[-] no loader at index ' + loaderIndex + '. Run cls.loaders().');
            return [];
        }

        var re = this._wild(pattern || '*');
        var out = [];

        Java.perform(function () {
            try {
                var factory = (typeof Java.ClassFactory.get === 'function')
                            ? Java.ClassFactory.get(loader) : null;
                if (factory === null) {
                    console.log('[-] Java.ClassFactory.get unavailable on this Frida');
                    return;
                }
                factory.enumerateLoadedClasses({
                    onMatch: function (name) { if (re.test(name)) out.push(name); },
                    onComplete: function () {
                        console.log('[*] ' + out.length + ' class(es) in loader ' +
                                    loaderIndex);
                        out.slice(0, 200).forEach(function (n) {
                            console.log('      ' + n);
                        });
                    }
                });
            } catch (e) {
                console.log('[-] per-loader enumeration failed: ' + e.message);
            }
        });

        return out;
    },

    /*
     * Act when a class appears. Essential for packed apps, where the classes
     * you care about are defined seconds after startup.
     */
    waitFor: function (pattern, callback) {
        var self = this;
        var re = this._wild(pattern);

        // If it is already there, fire immediately.
        var already = null;
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    if (already === null && re.test(name)) already = name;
                },
                onComplete: function () {}
            });
        });

        if (already !== null) {
            console.log('[+] ' + already + ' is already loaded');
            if (typeof callback === 'function') {
                Java.perform(function () { callback(already, null); });
            }
            return true;
        }

        this._watchers.push({ re: re, cb: callback, pattern: pattern });

        if (!this._loadClassHooked) {
            Java.perform(function () {
                try {
                    var CL = Java.use('java.lang.ClassLoader');
                    CL.loadClass.overload('java.lang.String', 'boolean').implementation =
                        function (name, resolve) {
                            var result = this.loadClass(name, resolve);
                            self._watchers.forEach(function (w) {
                                if (w.fired) return;
                                if (!w.re.test(name)) return;
                                w.fired = true;
                                console.log('[+] watched class appeared: ' + name);
                                try {
                                    if (typeof w.cb === 'function') w.cb(name, this);
                                } catch (e) {
                                    console.log('[-] watcher callback threw: ' + e.message);
                                }
                            }, this);
                            return result;
                        };
                    self._loadClassHooked = true;
                    console.log('[+] ClassLoader.loadClass hooked — watching for ' + pattern);
                } catch (e) {
                    console.log('[-] could not hook ClassLoader.loadClass: ' + e.message);
                }
            });
        } else {
            console.log('[+] watching for ' + pattern);
        }

        return false;
    },

    /* ==================================================================
     * 4. CLASS STRUCTURE
     * ================================================================== */

    dump: function (className) {
        var self = this;
        var k = this.use(className);
        if (k === null) return;

        Java.perform(function () {
            var jc;
            try { jc = k.class; } catch (e) {
                console.log('[-] no Class object: ' + e.message); return;
            }

            console.log('\n================================================');
            console.log(' ' + className);
            console.log('================================================');

            /* --- provenance ------------------------------------------- */
            try {
                var loader = jc.getClassLoader();
                console.log('loader:      ' +
                    (loader === null ? 'BootClassLoader'
                                     : self._loaderKind(String(loader))));
            } catch (e) { /* ignore */ }

            try {
                var mods = Java.use('java.lang.reflect.Modifier');
                console.log('modifiers:   ' + mods.toString(jc.getModifiers()));
            } catch (e) { /* ignore */ }

            try {
                var sup = jc.getSuperclass();
                console.log('extends:     ' + (sup === null ? '-' : sup.getName()));
            } catch (e) { /* ignore */ }

            try {
                var ifs = jc.getInterfaces();
                if (ifs.length > 0) {
                    var names = [];
                    for (var i = 0; i < ifs.length; i++) names.push(ifs[i].getName());
                    console.log('implements:  ' + names.join(', '));
                }
            } catch (e) { /* ignore */ }

            /* --- fields ------------------------------------------------ */
            console.log('\n--- FIELDS ---');
            try {
                var fields = jc.getDeclaredFields();
                if (fields.length === 0) console.log('  (none)');
                for (var f = 0; f < fields.length; f++) {
                    var fld = fields[f];
                    var fname = fld.getName();
                    var ftype = fld.getType().getName();
                    var fmods = '';
                    try {
                        fmods = Java.use('java.lang.reflect.Modifier')
                                    .toString(fld.getModifiers());
                    } catch (e) { /* ignore */ }

                    var value = '';
                    // Static field values are readable without an instance,
                    // which is where hard-coded keys usually live.
                    try {
                        if (fmods.indexOf('static') !== -1) {
                            fld.setAccessible(true);
                            var v = fld.get(null);
                            value = ' = ' + (v === null ? 'null'
                                : String(v).substring(0, 120));
                        }
                    } catch (e) { value = ' = <not readable>'; }

                    console.log('  ' + (fmods ? fmods + ' ' : '') + ftype + ' ' +
                                fname + value);
                }
            } catch (e) {
                console.log('  <field enumeration failed: ' + e.message + '>');
            }

            /* --- constructors ----------------------------------------- */
            console.log('\n--- CONSTRUCTORS ---');
            try {
                var ctors = jc.getDeclaredConstructors();
                if (ctors.length === 0) console.log('  (none)');
                for (var c = 0; c < ctors.length; c++) {
                    var ptypes = ctors[c].getParameterTypes();
                    var plist = [];
                    for (var p = 0; p < ptypes.length; p++) plist.push(ptypes[p].getName());
                    console.log('  $init(' + plist.join(', ') + ')');
                    console.log('    .overload(' +
                        plist.map(function (t) { return '"' + t + '"'; }).join(', ') + ')');
                }
            } catch (e) { /* ignore */ }

            /* --- methods ---------------------------------------------- */
            console.log('\n--- METHODS ---');
            try {
                var methods = jc.getDeclaredMethods();
                if (methods.length === 0) console.log('  (none)');
                for (var m = 0; m < methods.length; m++) {
                    var mm = methods[m];
                    var mname = mm.getName();
                    var rt = mm.getReturnType().getName();
                    var pts = mm.getParameterTypes();
                    var args = [];
                    for (var q = 0; q < pts.length; q++) args.push(pts[q].getName());
                    var mmods = '';
                    try {
                        mmods = Java.use('java.lang.reflect.Modifier')
                                    .toString(mm.getModifiers());
                    } catch (e) { /* ignore */ }

                    console.log('  ' + (mmods ? mmods + ' ' : '') + rt + ' ' +
                                mname + '(' + args.join(', ') + ')');
                    // The exact string to paste into a hook. This is the single
                    // most useful line of output in this whole script.
                    console.log('    .overload(' +
                        args.map(function (t) { return '"' + t + '"'; }).join(', ') + ')');
                }
            } catch (e) {
                console.log('  <method enumeration failed: ' + e.message + '>');
            }

            console.log('');
        });
    },

    /*
     * Just the overload strings for one method — the thing you need 90% of the
     * time, without the rest of the dump.
     */
    overloads: function (className, methodName) {
        var k = this.use(className);
        if (k === null) return [];

        var out = [];
        Java.perform(function () {
            var member = k[methodName];
            if (member === undefined) {
                console.log('[-] no member named "' + methodName + '" on ' + className);
                console.log('    Run cls.dump("' + className + '") to see what exists.');
                return;
            }
            var list = member.overloads || [member];
            console.log('[*] ' + className + '.' + methodName +
                        ' — ' + list.length + ' overload(s):');
            list.forEach(function (ov, i) {
                var args, ret;
                try {
                    args = ov.argumentTypes.map(function (t) { return t.className; });
                    ret = ov.returnType.className;
                } catch (e) { return; }
                out.push(args);
                console.log('  [' + i + '] ' + ret + ' ' + methodName +
                            '(' + args.join(', ') + ')');
                console.log('      Java.use("' + className + '").' + methodName +
                            '.overload(' +
                            args.map(function (t) { return '"' + t + '"'; }).join(', ') +
                            ').implementation = function (' +
                            args.map(function (_, j) { return 'a' + j; }).join(', ') +
                            ') { … }');
            });
        });
        return out;
    },

    /*
     * Find concrete implementations of an interface or subclasses of a class.
     * Hooking an interface method does nothing — virtual dispatch resolves to
     * the implementation's ArtMethod. See ../README.md section 7.4.3.
     */
    implementers: function (typeName, packagePrefix) {
        var found = [];
        var prefix = packagePrefix || '';

        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    if (prefix && name.indexOf(prefix) !== 0) return;
                    if (name.indexOf('$$') !== -1) return;          // synthetic
                    var k;
                    try { k = Java.use(name); } catch (e) { return; }
                    try {
                        var ifs = k.class.getInterfaces();
                        for (var i = 0; i < ifs.length; i++) {
                            if (ifs[i].getName() === typeName) {
                                found.push(name);
                                console.log('  [implements] ' + name);
                                return;
                            }
                        }
                        var sup = k.class.getSuperclass();
                        if (sup !== null && sup.getName() === typeName) {
                            found.push(name);
                            console.log('  [extends] ' + name);
                        }
                    } catch (e) { /* not inspectable */ }
                },
                onComplete: function () {
                    console.log('[*] ' + found.length + ' implementer(s)/subclass(es) of ' +
                                typeName);
                    if (found.length === 0 && prefix === '') {
                        console.log('    Nothing found. This scan is slow across all classes;');
                        console.log('    narrow it: cls.implementers("' + typeName +
                                    '", "com.example")');
                    }
                }
            });
        });

        return found;
    },

    /* Live instances on the heap, with their real runtime class. */
    instances: function (className, limit) {
        limit = limit || 20;
        var out = [];
        Java.perform(function () {
            var n = 0;
            Java.choose(className, {
                onMatch: function (inst) {
                    n++;
                    if (n > limit) return 'stop';
                    var desc;
                    try { desc = inst.toString(); } catch (e) { desc = '<toString threw>'; }
                    out.push({ cls: inst.$className, desc: desc });
                    console.log('  [' + n + '] ' + inst.$className);
                    console.log('       ' + String(desc).substring(0, 160));
                },
                onComplete: function () {
                    console.log('[*] ' + out.length + ' live instance(s) of ' + className);
                    if (out.length === 0) {
                        console.log('    None on the heap right now. Either nothing has');
                        console.log('    constructed one yet, or the class name is an');
                        console.log('    interface — try cls.implementers("' + className + '").');
                    }
                }
            });
        });
        return out;
    },

    help: function () {
        console.log([
            '',
            'CLASS LOADERS',
            '  cls.loaders()                       list every loader with its parent',
            '  cls.dexes()                         DEX paths each loader knows about',
            '',
            'FINDING A CLASS  (fixes ClassNotFoundException)',
            '  cls.find("com.example.X")           which loader owns it',
            '  cls.use("com.example.X")            a WORKING wrapper from any loader',
            '  cls.waitFor("com.example.*", cb)    act when a class is defined',
            '',
            'ENUMERATION',
            '  cls.list("com.example.*")           loaded classes matching a pattern',
            '  cls.listInLoader(2, "*")            classes in one specific loader',
            '',
            'STRUCTURE',
            '  cls.dump("com.example.X")           fields (with static values) + methods',
            '  cls.overloads("com.example.X","m")  ready-to-paste .overload() strings',
            '  cls.implementers("com.example.I")   concrete implementations',
            '  cls.instances("com.example.X")      live objects on the heap',
            '',
            'See ../README.md section 7.4.2 for why the loader matters.',
            ''
        ].join('\n'));
    }
};

/* ---------------------------------------------------------- RPC surface */

rpc.exports = {
    init: function (stage) {
        console.log('[*] class-enumerator loaded (stage=' + stage + ')');
    },
    loaders: function () { return cls.loaders(); },
    list: function (pattern) { return cls.list(pattern, 10000); },
    find: function (name) {
        var l = cls.find(name);
        return l === null ? null : String(l);
    },
    overloads: function (c, m) { return cls.overloads(c, m); },
    implementers: function (t, p) { return cls.implementers(t, p); }
};

/* --------------------------------------------------------------- bootstrap */

Java.perform(function () {
    console.log('');
    console.log('=== class-enumerator ===');
    try {
        var pkg = Java.use('android.app.ActivityThread').currentPackageName();
        console.log('[*] package: ' + pkg);
    } catch (e) {
        console.log('[.] not an app process, or ActivityThread unavailable');
    }
    console.log('[*] default loader: ' +
        String(Java.classFactory.loader).substring(0, 120));
    console.log('[+] ready — type cls.help()');
    console.log('');
});
