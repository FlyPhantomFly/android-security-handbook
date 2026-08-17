/*
 * hook-from-jadx.js -- the mechanical translation from a jadx signature to a Frida hook.
 *
 * PURPOSE
 *   Chapter 56 section 7.2. jadx answers "where" -- which class, which method, which
 *   signature. Frida answers "what" -- the actual arguments and the actual return value.
 *   Neither answers the other's question, so the loop between them is the whole job, and
 *   the seam where it breaks is almost always the overload string.
 *
 *   Part 1 of this file is the worked example from the chapter, verbatim: given
 *   `private String buildAuthHeader(String, byte[], boolean)` as jadx printed it, this is
 *   the hook. It will not run against an app you do not have -- `com.example.auth` is a
 *   teaching name -- so treat it as the shape to copy, not a script to fire.
 *
 *   Part 2 is the part you actually reuse: a signature translator that takes the method
 *   declaration as jadx rendered it, converts the parameter types to Frida's overload
 *   strings, and hooks it. Paste the jadx line in, get a working hook out.
 *
 * USAGE
 *   frida -U -f com.example.app -l hook-from-jadx.js --no-pause
 *   frida -U -n com.example.app -l hook-from-jadx.js
 *
 *   From the Frida REPL, using Part 2 against a real target:
 *     rpc.exports.fromjadx('com.example.auth.TokenManager',
 *                          'private String buildAuthHeader(String userId, byte[] nonce, boolean refresh)')
 *     rpc.exports.overloads('com.example.auth.TokenManager', 'buildAuthHeader')
 *     rpc.exports.sig('Map<String, String> headers, String[] tags, Outer.Inner ctx')
 *
 * THE TRANSLATION RULES (chapter section 7.2, the ones people get wrong)
 *   String            -> 'java.lang.String'   fully qualified; jadx's imports are not the type
 *   byte[]            -> '[B'
 *   String[]          -> '[Ljava.lang.String;'
 *   int/boolean/long  -> 'int' / 'boolean' / 'long'    primitives keep their bare names
 *   Map<String,String>-> 'java.util.Map'      generics are ERASED; never include them
 *   Outer.Inner       -> 'com.example.Outer$Inner'     dollar, not dot
 *   private methods     hook exactly the same -- access modifiers do not constrain Frida
 *   native methods      hook at the Java boundary; for the native side see ../../16-JNI/
 *
 * TWO TRAPS SPECIFIC TO READING FROM jadx
 *   - Access modifiers may have been rewritten by jadx (`JADX INFO: Access modifiers changed
 *     from: private`). Harmless for hooking, but the printed modifier is not evidence.
 *   - The class name may be a jadx alias. Under `--deobf`, `C0000a` is a jadx invention and
 *     `Java.use('C0000a')` throws ClassNotFoundException. The real name is in the
 *     `/* renamed from: * /` comment. Use that one.
 *
 * REQUIREMENTS
 *   - frida-server on the device, version matching the host `frida --version`.
 *   - Root, or a gadget-embedded APK. See ../../53-Frida/README.md.
 *
 * SAFETY
 *   Read-only: every hook calls the original and returns its value unchanged. Nothing here
 *   modifies app behaviour. Only run it against apps you are authorised to test.
 */

'use strict';

/* ------------------------------------------------------------------ *
 * Part 1 -- the chapter's worked example, verbatim.
 *
 * Set RUN_EXAMPLE to true only if you actually have a target that declares
 * com.example.auth.TokenManager. Left false so that loading this file against
 * a real app does not spray ClassNotFoundException at you on startup.
 * ------------------------------------------------------------------ */

var RUN_EXAMPLE = false;

function example() {
    Java.perform(function () {
        var TokenManager = Java.use('com.example.auth.TokenManager');

        TokenManager.buildAuthHeader.overload('java.lang.String', '[B', 'boolean')
            .implementation = function (userId, nonce, refresh) {
                var out = this.buildAuthHeader(userId, nonce, refresh);
                console.log('[buildAuthHeader] userId=' + userId +
                            ' refresh=' + refresh +
                            ' nonce=' + Java.use('android.util.Base64')
                                            .encodeToString(nonce, 2) +
                            '\n  -> ' + out);
                return out;
            };
    });
}

/* ------------------------------------------------------------------ *
 * Part 2 -- the reusable translator.
 * ------------------------------------------------------------------ */

var PRIMITIVES = {
    'int': 'int', 'long': 'long', 'short': 'short', 'byte': 'byte',
    'char': 'char', 'float': 'float', 'double': 'double',
    'boolean': 'boolean', 'void': 'void'
};

/* JVM descriptor letters, needed only for array element types. */
var PRIM_DESC = {
    'int': 'I', 'long': 'J', 'short': 'S', 'byte': 'B',
    'char': 'C', 'float': 'F', 'double': 'D', 'boolean': 'Z'
};

/* The java.lang types jadx prints bare because they are auto-imported. Anything
 * else that arrives without a dot, we cannot resolve from text alone -- see the
 * warning emitted by translateType(). */
var JAVA_LANG = [
    'String', 'Object', 'Integer', 'Long', 'Short', 'Byte', 'Character',
    'Float', 'Double', 'Boolean', 'CharSequence', 'Number', 'Class',
    'Throwable', 'Exception', 'RuntimeException', 'StringBuilder', 'Thread'
];

/* Types jadx prints bare from java.util, which its imports also hide. */
var JAVA_UTIL = [
    'List', 'ArrayList', 'Map', 'HashMap', 'Set', 'HashSet', 'Collection',
    'Iterator', 'LinkedList', 'LinkedHashMap', 'TreeMap', 'Arrays'
];

/*
 * Strip generics. `Map<String, List<Foo>>` -> `Map`. Bracket-counting rather
 * than a regex because generics nest and regexes do not.
 */
function stripGenerics(t) {
    var out = '', depth = 0;
    for (var i = 0; i < t.length; i++) {
        var c = t.charAt(i);
        if (c === '<') { depth++; continue; }
        if (c === '>') { depth--; continue; }
        if (depth === 0) { out += c; }
    }
    return out.trim();
}

/*
 * One jadx type -> one Frida overload string.
 *
 * The array rule is the one that surprises people: Frida wants the JVM
 * descriptor for arrays ('[B', '[Ljava.lang.String;') but the source-level name
 * for everything else ('java.lang.String'). They are two different notations
 * and the boundary is the bracket.
 */
function translateType(raw) {
    var t = stripGenerics(String(raw).trim());

    /* varargs are an array at the bytecode level */
    if (t.slice(-3) === '...') { t = t.slice(0, -3) + '[]'; }

    var dims = 0;
    while (t.slice(-2) === '[]') { dims++; t = t.slice(0, -2).trim(); }

    var base;
    if (PRIMITIVES[t]) {
        base = dims ? PRIM_DESC[t] : t;
        if (dims && !base) { throw new Error('void[] is not a type: ' + raw); }
    } else {
        var fq = t;
        if (fq.indexOf('.') === -1) {
            if (JAVA_LANG.indexOf(fq) !== -1) {
                fq = 'java.lang.' + fq;
            } else if (JAVA_UTIL.indexOf(fq) !== -1) {
                fq = 'java.util.' + fq;
            } else {
                /* Cannot be resolved from the declaration alone: jadx hid the
                 * package in an import. Scroll to the top of the .java file. */
                console.log('[!] "' + fq + '" has no package. jadx put it in an import; ' +
                            'the overload string needs the fully qualified name.');
            }
        } else {
            /* Outer.Inner -> Outer$Inner, but only for the segments after the
             * package. Heuristic, and it is the standard one: package segments
             * start lower-case, class segments upper-case. */
            var parts = fq.split('.');
            var firstClass = 0;
            while (firstClass < parts.length &&
                   parts[firstClass].charAt(0) === parts[firstClass].charAt(0).toLowerCase()) {
                firstClass++;
            }
            if (firstClass < parts.length - 1) {
                fq = parts.slice(0, firstClass + 1).join('.') + '$' +
                     parts.slice(firstClass + 1).join('$');
            }
        }
        base = dims ? 'L' + fq + ';' : fq;
    }

    return new Array(dims + 1).join('[') + base;
}

/*
 * Parse a method declaration exactly as jadx printed it and return
 * { name: ..., overload: [ ... ] }.
 *
 *   'private String buildAuthHeader(String userId, byte[] nonce, boolean refresh)'
 *     -> { name: 'buildAuthHeader', overload: ['java.lang.String', '[B', 'boolean'] }
 */
function parseDeclaration(decl) {
    var open = decl.indexOf('(');
    var close = decl.lastIndexOf(')');
    if (open === -1 || close === -1 || close < open) {
        throw new Error('not a method declaration (no parentheses): ' + decl);
    }

    var head = decl.slice(0, open).trim().split(/\s+/);
    var name = head[head.length - 1];

    var inner = decl.slice(open + 1, close).trim();
    if (!inner) { return { name: name, overload: [] }; }

    /* Split on top-level commas only -- Map<String, String> contains one that
     * is not a parameter boundary. */
    var params = [], depth = 0, cur = '';
    for (var i = 0; i < inner.length; i++) {
        var c = inner.charAt(i);
        if (c === '<') { depth++; }
        else if (c === '>') { depth--; }
        if (c === ',' && depth === 0) { params.push(cur); cur = ''; continue; }
        cur += c;
    }
    params.push(cur);

    var overload = params.map(function (p) {
        var tok = stripGenerics(p).trim().split(/\s+/)
                    .filter(function (w) { return w !== 'final'; });
        /* last token is the parameter name; everything before it is the type */
        var type = tok.length > 1 ? tok.slice(0, -1).join(' ') : tok[0];
        /* `byte[] nonce` splits cleanly; `byte []nonce` does not. Normalise. */
        if (tok.length > 1 && tok[tok.length - 1].indexOf('[]') === 0) { type += '[]'; }
        return translateType(type);
    });

    return { name: name, overload: overload };
}

function fmt(v) {
    if (v === null || v === undefined) { return String(v); }
    try {
        if (Array.isArray(v)) {
            return '[' + v.length + ' items] ' +
                   (v.length <= 16 ? v.join(',') : v.slice(0, 16).join(',') + ',...');
        }
        return String(v);
    } catch (e) {
        return '<' + e.message + '>';
    }
}

/*
 * Hook one method, given the class name and the jadx declaration.
 * Read-only: calls through and returns the original value.
 */
function fromJadx(className, declaration, opts) {
    opts = opts || {};
    var parsed = parseDeclaration(declaration);

    Java.perform(function () {
        var klass;
        try {
            klass = Java.use(className);
        } catch (e) {
            console.log('[!] Java.use("' + className + '") failed: ' + e.message);
            console.log('    If you decompiled with --deobf this may be a jadx alias. ' +
                        'The real name is in the /* renamed from: */ comment.');
            return;
        }

        var target = klass[parsed.name];
        if (!target) {
            console.log('[!] no method "' + parsed.name + '" on ' + className);
            return;
        }

        var impl;
        try {
            impl = target.overload.apply(target, parsed.overload);
        } catch (e) {
            console.log('[!] overload(' + parsed.overload.map(JSON.stringify).join(', ') +
                        ') did not match. Available:');
            target.overloads.forEach(function (o) {
                console.log('      ' + o.argumentTypes.map(function (a) {
                    return a.className;
                }).join(', '));
            });
            return;
        }

        impl.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            var out = impl.apply(this, args);
            console.log('[' + parsed.name + '] ' +
                        args.map(fmt).join(' | ') + '\n  -> ' + fmt(out));
            if (opts.stacks) {
                console.log(Java.use('android.util.Log')
                    .getStackTraceString(Java.use('java.lang.Exception').$new()));
            }
            return out;
        };

        console.log('[+] hooked ' + className + '.' + parsed.name +
                    '(' + parsed.overload.join(', ') + ')');
    });
}

/* Print every real overload of a method -- the ground truth to check a
 * translation against when the guess did not match. */
function overloads(className, methodName) {
    Java.perform(function () {
        try {
            Java.use(className)[methodName].overloads.forEach(function (o) {
                console.log('  ' + o.argumentTypes.map(function (a) {
                    return a.className;
                }).join(', '));
            });
        } catch (e) {
            console.log('[!] ' + e.message);
        }
    });
}

rpc.exports = {
    /* translate + hook, from a pasted jadx declaration */
    fromjadx: fromJadx,
    /* translate only -- 'Map<String,String> h, byte[] n' -> ['java.util.Map','[B'] */
    sig: function (params) { return parseDeclaration('void _(' + params + ')').overload; },
    /* ground truth from the running VM */
    overloads: overloads
};

if (RUN_EXAMPLE) { example(); }

console.log('[*] hook-from-jadx.js loaded. ' +
            'rpc.exports.fromjadx(class, declaration) / .sig(params) / .overloads(class, method)');
