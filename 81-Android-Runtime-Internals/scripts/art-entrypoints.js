/*
 * art-entrypoints.js — inspect ArtMethod entrypoints in a live Android process.
 *
 * WHAT IT DOES
 *   Resolves a Java method, obtains its ArtMethod pointer through JNI, derives
 *   the quick-entrypoint offset by scanning pointer-sized words for values in
 *   executable mappings, and classifies the destination (AOT, JIT, nterp/stub,
 *   or an injected library).
 *
 *   It deliberately does NOT hard-code an offset. ART is a Mainline module and
 *   the layout changes. The scan is a heuristic: it prints every executable
 *   candidate so you can see what it chose and why.
 *
 * HOW TO RUN
 *   frida -U -p <pid> -l 81-Android-Runtime-Internals/scripts/art-entrypoints.js
 *
 *   Then at the Frida prompt:
 *     art.inspect("com.example.Target", "check")
 *     art.inspectClass("com.example.Target")
 *     art.watch("com.example.Target", "check", 1000)
 *     art.offset()
 *
 * LIMITS
 *   - A method can have several executable-looking words; the last is usually
 *     the quick entrypoint, but verify against the ART build you are testing.
 *   - A JIT-compiled method can change state while you are looking at it.
 *   - This is a measurement tool, not a detector. An entrypoint outside a known
 *     mapping is a question, not a verdict.
 */

"use strict";

const POINTER = Process.pointerSize;
const SCAN_WORDS = 16; // 128 bytes on 64-bit; enough for the pointer-sized tail.

let cachedOffset = null;

function mappingFor(address) {
    const range = Process.findRangeByAddress(address);
    if (range === null) {
        return { label: "unmapped", detail: "no range", file: null };
    }
    const file = range.file ? range.file.path : null;
    let label = "anonymous";
    if (file !== null) {
        label = file;
    } else if (range.protection.indexOf("x") !== -1) {
        label = "anonymous-executable";
    }
    return { label: label, detail: range.protection, file: file };
}

function classify(address) {
    const map = mappingFor(address);
    const text = (map.label + " " + (map.file || "")).toLowerCase();

    if (text.indexOf("libart.so") !== -1 || text.indexOf("libartd.so") !== -1) {
        return { state: "interpreter/stub", mapping: map };
    }
    if (text.indexOf("jit") !== -1) {
        return { state: "JIT", mapping: map };
    }
    if (text.indexOf("boot.art") !== -1 || text.indexOf("boot.odex") !== -1 ||
        text.indexOf("base.odex") !== -1 || text.indexOf("base.oat") !== -1) {
        return { state: "AOT", mapping: map };
    }
    if (text.indexOf("frida") !== -1 || text.indexOf("gum") !== -1 ||
        text.indexOf("linjector") !== -1 || text.indexOf("lsplant") !== -1 ||
        text.indexOf("vector") !== -1) {
        return { state: "injected/unknown", mapping: map };
    }
    return { state: "unknown", mapping: map };
}

function artMethodFromMethod(methodWrapper) {
    // Preferred: ask JNI to convert the reflected Method to an ArtMethod*.
    try {
        const env = Java.vm.getEnv();
        if (typeof env.fromReflectedMethod === "function") {
            return env.fromReflectedMethod(methodWrapper.$handle);
        }
    } catch (e) {
        // fall through
    }

    // Fallback: read the private long field that holds the ArtMethod pointer.
    try {
        const value = methodWrapper.artMethod.value;
        if (value !== undefined && value !== null) {
            return ptr(value);
        }
    } catch (e) {
        // fall through
    }

    return null;
}

function executableCandidates(artMethod) {
    const candidates = [];
    for (let i = 0; i < SCAN_WORDS; i++) {
        const offset = i * POINTER;
        let value;
        try {
            value = artMethod.add(offset).readPointer();
        } catch (e) {
            break;
        }
        if (value.isNull()) continue;
        const range = Process.findRangeByAddress(value);
        if (range === null) continue;
        if (range.protection.indexOf("x") === -1) continue;
        candidates.push({ offset: offset, address: value, range: range });
    }
    return candidates;
}

function deriveOffset(artMethod) {
    if (cachedOffset !== null) return cachedOffset;
    const candidates = executableCandidates(artMethod);
    if (candidates.length === 0) {
        throw new Error("no executable pointer found in the first " + SCAN_WORDS + " words");
    }
    // The quick entrypoint is conventionally the last pointer-sized field.
    cachedOffset = candidates[candidates.length - 1].offset;
    return cachedOffset;
}

function describe(artMethod, label) {
    const offset = deriveOffset(artMethod);
    const entry = artMethod.add(offset).readPointer();
    const verdict = classify(entry);
    const module = Process.findModuleByAddress(entry);

    console.log("");
    console.log(label);
    console.log("  ArtMethod: " + artMethod);
    console.log("  offset:    0x" + offset.toString(16));
    console.log("  entry:     " + entry);
    console.log("  module:    " + (module ? module.name : "(none)"));
    console.log("  mapping:   " + verdict.mapping.label + " [" + verdict.mapping.detail + "]");
    console.log("  state:     " + verdict.state);

    const candidates = executableCandidates(artMethod);
    if (candidates.length > 1) {
        console.log("  candidates:");
        candidates.forEach(function (c) {
            const v = classify(c.address);
            console.log("    0x" + c.offset.toString(16) + " -> " + c.address +
                        "  " + v.state + "  " + v.mapping.label);
        });
    }
    return { offset: offset, entry: entry, state: verdict.state, mapping: verdict.mapping };
}

function methodsNamed(className, methodName) {
    const Cls = Java.use(className);
    const methods = Cls.class.getDeclaredMethods();
    const out = [];
    for (let i = 0; i < methods.length; i++) {
        const m = methods[i];
        if (m.getName() === methodName) out.push(m);
    }
    return out;
}

const art = {
    offset: function () {
        if (cachedOffset === null) {
            console.log("offset not derived yet; call art.inspect(...) first");
            return null;
        }
        console.log("entrypoint offset: 0x" + cachedOffset.toString(16) +
                    " (" + (cachedOffset / POINTER) + " pointers)");
        return cachedOffset;
    },

    inspect: function (className, methodName) {
        Java.perform(function () {
            const methods = methodsNamed(className, methodName);
            if (methods.length === 0) {
                console.log("no method named " + methodName + " in " + className);
                return;
            }
            methods.forEach(function (m, i) {
                const artMethod = artMethodFromMethod(m);
                if (artMethod === null) {
                    console.log("could not obtain ArtMethod for overload " + i);
                    return;
                }
                describe(artMethod, className + "." + methodName + " #" + i);
            });
        });
    },

    inspectClass: function (className) {
        Java.perform(function () {
            const Cls = Java.use(className);
            const methods = Cls.class.getDeclaredMethods();
            console.log("class " + className + ": " + methods.length + " declared methods");
            for (let i = 0; i < methods.length; i++) {
                const m = methods[i];
                const artMethod = artMethodFromMethod(m);
                if (artMethod === null) continue;
                try {
                    describe(artMethod, className + "." + m.getName() + " #" + i);
                } catch (e) {
                    console.log(className + "." + m.getName() + ": " + e.message);
                }
            }
        });
    },

    watch: function (className, methodName, intervalMs) {
        const period = intervalMs || 1000;
        Java.perform(function () {
            const methods = methodsNamed(className, methodName);
            if (methods.length === 0) {
                console.log("no method named " + methodName + " in " + className);
                return;
            }
            const artMethod = artMethodFromMethod(methods[0]);
            if (artMethod === null) {
                console.log("could not obtain ArtMethod");
                return;
            }
            const offset = deriveOffset(artMethod);
            let last = null;
            setInterval(function () {
                const entry = artMethod.add(offset).readPointer();
                if (last === null || !entry.equals(last)) {
                    const v = classify(entry);
                    console.log("[" + new Date().toISOString() + "] " + entry +
                                "  " + v.state + "  " + v.mapping.label);
                    last = entry;
                }
            }, period);
        });
    }
};

console.log("art-entrypoints loaded. Pointer size: " + POINTER + " bytes.");
console.log("Try: art.inspect(\"com.example.Target\", \"check\")");
