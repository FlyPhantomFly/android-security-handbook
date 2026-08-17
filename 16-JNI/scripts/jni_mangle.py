#!/usr/bin/env python3
"""
jni_mangle.py -- mangle, demangle and parse JNI names and type descriptors.

WHAT IT DOES
    Implements, from the JNI specification, the four mechanical transformations
    that chapter 16 sections 3.3 to 3.6 describe:

      1. Java type            ->  type descriptor          (int[]  -> [I)
      2. type descriptor      ->  Java type                 ([B     -> byte[])
      3. class + method       ->  exported C symbol         (static registration)
      4. exported C symbol    ->  class + method + params   (demangling)

    The escape table it implements is exactly:

        '.' or '/'  ->  '_'          (package separator)
        '_'         ->  '_1'
        ';'         ->  '_2'
        '['         ->  '_3'
        any other non-ASCII-alphanumeric character c
                    ->  '_0' + four lowercase hex digits of its UTF-16 unit

    So '$' (U+0024) becomes '_00024' -- six characters, four hex digits after
    the '_0'. That is the single most frequently mis-remembered rule in JNI.

WHY YOU WANT IT
    Two reasons, both practical.

    First, grepping a shared object for a Java method name fails silently when
    the name contains an underscore or lives on an inner class. 'check_root'
    is 'check_1root' in the symbol table and 'Outer$Inner' is
    'Outer_00024Inner'. Analysts conclude "the symbol is not there" when it is.

    Second, when you have recovered a symbol from 'nm -D' you want the Java
    class and method back, so you know where to look in jadx. Demangling by
    eye goes wrong on the overload marker: 'Java_pkg_C_f_1__I' is C.f_(int),
    not C.f(...). This script decodes escapes BEFORE splitting on the '__'
    marker, which is the ordering that makes that case come out right.

HOW TO RUN
    # class + method -> short symbol
    python3 jni_mangle.py --mangle com.example.Crypto.decrypt

    # with a signature -> short symbol AND the overloaded long symbol
    python3 jni_mangle.py --mangle 'com.example.Codec.write([BII)V'

    # symbol -> class, method, parameters
    python3 jni_mangle.py --demangle Java_com_example_Codec_write___3BII

    # decode a signature into a readable prototype and an args[] map
    python3 jni_mangle.py --parse '(I[BLjava/lang/String;)Z'
    python3 jni_mangle.py --parse '(I[B)Z' --static

    # Java type -> descriptor
    python3 jni_mangle.py --descriptor 'java.lang.String[]'

    # feed it the output of:  grep -rh '^\\.method.*native' smali/
    grep -rh '^\\.method.*\\bnative\\b' app_out/smali/com/example/ \\
      | python3 jni_mangle.py --smali --class com.example.Codec

    # verify the implementation against the worked examples in the README
    python3 jni_mangle.py --selftest

REQUIREMENTS
    Python 3.8 or newer. Standard library only. No device, no APK, no NDK.

WHAT THIS WILL NOT TELL YOU
    - Whether the symbol actually exists in any library. This is pure string
      manipulation; use 'nm -D --defined-only lib.so | grep Java_' for that.
    - The RETURN TYPE of a demangled method. The JNI long name encodes the
      parameters only, deliberately. Get the return type from the Java side
      (jadx, or the DEX method_id).
    - Anything about dynamically registered methods. Those have no symbol at
      all; their name and signature live in a JNINativeMethod table that only
      exists at runtime. Use scripts/dump-registernatives.js.
    - Whether a method is @CriticalNative, which changes the calling
      convention (no JNIEnv*, no jclass). That annotation is in the DEX, not
      in the symbol. --parse assumes the standard convention and says so.
    - Which of two same-named methods a short symbol refers to when the class
      has overloads; that is exactly why the long form exists.
"""

import argparse
import re
import sys

# ---------------------------------------------------------------------------
# Section 3.3 -- type descriptors
# ---------------------------------------------------------------------------

PRIMITIVE_TO_DESCRIPTOR = {
    "boolean": "Z",
    "byte": "B",
    "char": "C",
    "short": "S",
    "int": "I",
    "long": "J",
    "float": "F",
    "double": "D",
    "void": "V",
}

DESCRIPTOR_TO_PRIMITIVE = {v: k for k, v in PRIMITIVE_TO_DESCRIPTOR.items()}

# A courtesy table so '--descriptor String' does the obvious thing. Any name
# containing a dot is used verbatim; any other unknown bare name is an error,
# because silently guessing a package is how wrong signatures get shipped.
JAVA_LANG_SHORTCUTS = {
    "Object", "String", "CharSequence", "Class", "Throwable", "Exception",
    "Integer", "Long", "Short", "Byte", "Boolean", "Character", "Float",
    "Double", "Number", "Thread", "Runnable", "StringBuilder",
}


def java_type_to_descriptor(java_type):
    """'int[]' -> '[I';  'java.lang.String' -> 'Ljava/lang/String;'."""
    t = java_type.strip()
    dims = 0
    while t.endswith("[]"):
        dims += 1
        t = t[:-2].strip()
    if t in PRIMITIVE_TO_DESCRIPTOR:
        base = PRIMITIVE_TO_DESCRIPTOR[t]
    else:
        if "." not in t and "/" not in t:
            if t in JAVA_LANG_SHORTCUTS:
                t = "java.lang." + t
            else:
                raise ValueError(
                    "unqualified class name %r: give the fully qualified name "
                    "(guessing a package produces signatures that silently do "
                    "not match)" % t)
        base = "L" + t.replace(".", "/") + ";"
    return "[" * dims + base


def parse_descriptor(desc, pos=0):
    """Parse ONE descriptor starting at pos. Returns (java_type, next_pos)."""
    if pos >= len(desc):
        raise ValueError("truncated descriptor %r" % desc)
    c = desc[pos]
    if c == "[":
        inner, nxt = parse_descriptor(desc, pos + 1)
        return inner + "[]", nxt
    if c == "L":
        end = desc.find(";", pos)
        if end < 0:
            raise ValueError("unterminated object descriptor in %r" % desc)
        return desc[pos + 1:end].replace("/", "."), end + 1
    if c in DESCRIPTOR_TO_PRIMITIVE:
        return DESCRIPTOR_TO_PRIMITIVE[c], pos + 1
    raise ValueError("unknown descriptor character %r in %r" % (c, desc))


def split_signature(sig):
    """'(I[B)Z' -> (['I', '[B'], 'Z'). Returns raw descriptors, not Java names."""
    if not sig.startswith("("):
        raise ValueError("signature must start with '(': %r" % sig)
    close = sig.find(")")
    if close < 0:
        raise ValueError("signature has no ')': %r" % sig)
    params_blob = sig[1:close]
    ret_blob = sig[close + 1:]

    params = []
    pos = 0
    while pos < len(params_blob):
        start = pos
        _java, pos = parse_descriptor(params_blob, pos)
        params.append(params_blob[start:pos])
    if not ret_blob:
        raise ValueError("signature has no return descriptor: %r" % sig)
    _rj, endpos = parse_descriptor(ret_blob, 0)
    if endpos != len(ret_blob):
        raise ValueError("trailing junk after return descriptor: %r" % sig)
    return params, ret_blob


# ---------------------------------------------------------------------------
# Section 3.5 -- mangling
# ---------------------------------------------------------------------------

def mangle_fragment(text):
    """Apply the JNI escape table to one fragment of a name."""
    out = []
    for ch in text:
        if ch in (".", "/"):
            out.append("_")
        elif ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        elif ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9"):
            out.append(ch)
        else:
            # '_0' followed by FOUR lowercase hex digits of the UTF-16 unit.
            # Characters outside the BMP occupy two units and therefore two
            # escapes; encode('utf-16-be') gives us the units directly.
            units = ch.encode("utf-16-be")
            for i in range(0, len(units), 2):
                unit = (units[i] << 8) | units[i + 1]
                out.append("_0%04x" % unit)
    return "".join(out)


def mangle(class_name, method_name, param_descriptors=None):
    """Return (short_symbol, long_symbol_or_None)."""
    short = "Java_" + mangle_fragment(class_name) + "_" + mangle_fragment(method_name)
    long_sym = None
    if param_descriptors is not None:
        long_sym = short + "__" + mangle_fragment("".join(param_descriptors))
    return short, long_sym


# ---------------------------------------------------------------------------
# Section 3.6 -- demangling
# ---------------------------------------------------------------------------

_SEP = object()      # an unescaped '_': a package/method separator
_MARKER = object()   # an unescaped '__': the overload marker


def _decode_tokens(text):
    """Decode escapes into a token list of characters, _SEP and _MARKER.

    Escapes are decoded BEFORE the overload marker is located, which is what
    makes 'Java_pkg_C_f_1__I' resolve to C.f_(int) rather than being split in
    the wrong place. A separator can never be followed by '0'..'3' because a
    Java identifier cannot begin with a digit, so the grammar is unambiguous.
    """
    tokens = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch != "_":
            tokens.append(ch)
            i += 1
            continue
        nxt = text[i + 1] if i + 1 < n else ""
        if nxt == "1":
            tokens.append("_")
            i += 2
        elif nxt == "2":
            tokens.append(";")
            i += 2
        elif nxt == "3":
            tokens.append("[")
            i += 2
        elif nxt == "0":
            hexpart = text[i + 2:i + 6]
            if len(hexpart) != 4 or not re.fullmatch(r"[0-9a-fA-F]{4}", hexpart):
                raise ValueError("malformed _0XXXX escape at offset %d in %r" % (i, text))
            tokens.append(chr(int(hexpart, 16)))
            i += 6
        elif nxt == "_":
            tokens.append(_MARKER)
            i += 2
        else:
            tokens.append(_SEP)
            i += 1
    return tokens


def demangle(symbol):
    """Return a dict describing the Java method a JNI symbol implements."""
    sym = symbol.strip()
    if not sym.startswith("Java_"):
        raise ValueError("not a JNI entry point (no 'Java_' prefix): %r" % symbol)
    tokens = _decode_tokens(sym[len("Java_"):])

    # Split on the first overload marker, if any.
    marker_at = None
    for idx, tok in enumerate(tokens):
        if tok is _MARKER:
            marker_at = idx
            break

    if marker_at is None:
        head, tail = tokens, []
    else:
        head, tail = tokens[:marker_at], tokens[marker_at + 1:]

    # Rebuild the qualified name; the last separator splits class from method.
    parts = [[]]
    for tok in head:
        if tok is _SEP:
            parts.append([])
        elif tok is _MARKER:
            raise ValueError("unexpected second overload marker in %r" % symbol)
        else:
            parts[-1].append(tok)
    words = ["".join(p) for p in parts]
    if len(words) < 2:
        raise ValueError("symbol has no method component: %r" % symbol)

    class_name = ".".join(words[:-1])
    method_name = words[-1]

    if tail:
        # Inside an argument signature an unescaped '_' is the encoding of the
        # '/' package separator of an object descriptor -- 'Ljava/lang/String;'
        # mangles to 'Ljava_lang_String_2'. A second overload marker cannot
        # occur, because two separators never appear in a row.
        if any(t is _MARKER for t in tail):
            raise ValueError("second overload marker inside the arguments of %r" % symbol)
        args_blob = "".join("/" if t is _SEP else t for t in tail)
        param_descs = []
        pos = 0
        while pos < len(args_blob):
            start = pos
            _java, pos = parse_descriptor(args_blob, pos)
            param_descs.append(args_blob[start:pos])
    else:
        args_blob = None
        param_descs = None

    return {
        "symbol": sym,
        "class": class_name,
        "method": method_name,
        "params_descriptor": args_blob,
        "params": param_descs,
        "params_java": [parse_descriptor(d, 0)[0] for d in param_descs] if param_descs else None,
        "overloaded": marker_at is not None,
    }


# ---------------------------------------------------------------------------
# Section 3.9 -- the argument layout of a hook
# ---------------------------------------------------------------------------

def arg_layout(sig, is_static=False, critical=False):
    """Return the args[] table for a native method with this signature."""
    params, ret = split_signature(sig)
    rows = []
    if critical:
        base = 0
    else:
        rows.append(("args[0]", "JNIEnv *", "synthetic: the per-thread JNI interface pointer"))
        rows.append(("args[1]", "jclass" if is_static else "jobject",
                     "synthetic: the declaring class" if is_static else "synthetic: the receiver"))
        base = 2
    for i, d in enumerate(params):
        java, _ = parse_descriptor(d, 0)
        rows.append(("args[%d]" % (base + i), d, "parameter %d: %s" % (i + 1, java)))
    ret_java, _ = parse_descriptor(ret, 0)
    return rows, ret_java


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_MANGLE_RE = re.compile(r"^(?P<fq>[^(]+?)(?P<sig>\(.*)?$")


def cmd_mangle(spec):
    m = _MANGLE_RE.match(spec.strip())
    fq = m.group("fq")
    sig = m.group("sig")
    if "." not in fq:
        raise ValueError("expected package.Class.method, got %r" % fq)
    class_name, method_name = fq.rsplit(".", 1)

    params = None
    if sig:
        params, _ret = split_signature(sig)

    short, long_sym = mangle(class_name, method_name, params)
    print("class            : %s" % class_name)
    print("method           : %s" % method_name)
    if params is not None:
        print("parameters       : %s" % ("".join(params) or "(none)"))
    print("short symbol     : %s" % short)
    if long_sym:
        print("long symbol      : %s" % long_sym)
        print("                   (ART tries the short name first, then this one)")
    else:
        print("long symbol      : pass a signature to compute the overloaded form")
    print()
    print("grep it with     : nm -D --defined-only lib*.so | grep '%s'" % short)


def cmd_demangle(symbol):
    info = demangle(symbol)
    print("symbol           : %s" % info["symbol"])
    print("class            : %s" % info["class"])
    print("method           : %s" % info["method"])
    if info["params"] is None:
        print("parameters       : not encoded (short name; method is not overloaded)")
    else:
        print("parameters       : %s" % info["params_descriptor"])
        print("                 : (%s)" % ", ".join(info["params_java"]))
    print("return type      : NOT recoverable from a symbol -- read it from the Java side")


def cmd_parse(sig, is_static, critical):
    params, ret = split_signature(sig)
    rows, ret_java = arg_layout(sig, is_static=is_static, critical=critical)
    java_params = [parse_descriptor(d, 0)[0] for d in params]
    print("signature        : %s" % sig)
    print("prototype        : %s m(%s)" % (ret_java, ", ".join(java_params)))
    if critical:
        # @CriticalNative implies static, primitives only, and no JNIEnv*.
        print("kind             : static, @CriticalNative "
              "(no JNIEnv*, no jclass -- the convention does NOT apply)")
    else:
        print("kind             : %s" % ("static" if is_static else "instance"))
    print()
    width = max(len(r[1]) for r in rows) if rows else 8
    for slot, typ, note in rows:
        print("  %-8s %-*s  %s" % (slot, width, typ, note))
    if not critical:
        print()
        print("  Real arguments start at args[2]. See README section 3.9.")


def cmd_smali(class_name, stream):
    """Turn '.method public native encrypt([BI)[B' lines into symbols."""
    rx = re.compile(r"^\s*\.method\b(?P<mods>[^(]*?)\s(?P<name>[A-Za-z0-9_$<>]+)"
                    r"(?P<sig>\(.*\))(?P<ret>.+)$")
    seen = 0
    for line in stream:
        line = line.rstrip("\n")
        if "native" not in line:
            continue
        m = rx.match(line)
        if not m:
            continue
        seen += 1
        name = m.group("name")
        sig = m.group("sig") + m.group("ret")
        try:
            params, _ret = split_signature(sig)
        except ValueError as exc:
            print("  ! %s: %s" % (line.strip(), exc), file=sys.stderr)
            continue
        short, long_sym = mangle(class_name, name, params)
        static = " static " in (" " + m.group("mods").strip() + " ")
        print("%s%s" % (short, "   [static]" if static else ""))
        print("    long: %s" % long_sym)
    if seen == 0:
        print("(no native methods on stdin)", file=sys.stderr)


# ---------------------------------------------------------------------------
# Self-test: the worked examples from README sections 3.5 and 3.6
# ---------------------------------------------------------------------------

MANGLE_CASES = [
    # (class, method, param descriptors or None, expected symbol, why)
    ("com.example.Crypto", "decrypt", None,
     "Java_com_example_Crypto_decrypt",
     "the simple case: dots become underscores"),
    ("com.my_app.core.Guard", "check_root", None,
     "Java_com_my_1app_core_Guard_check_1root",
     "an underscore in the PACKAGE and in the METHOD both become _1"),
    ("com.example.Outer$Inner", "compute", None,
     "Java_com_example_Outer_00024Inner_compute",
     "'$' is _0 plus FOUR hex digits: _00024"),
    ("com.example.Codec", "write", ["I"],
     "Java_com_example_Codec_write__I",
     "overload marker '__' then the parameter descriptors"),
    ("com.example.Codec", "write", ["[B"],
     "Java_com_example_Codec_write___3B",
     "'__' + '_3B' gives THREE underscores in a row"),
    ("com.example.Codec", "write", ["[B", "I", "I"],
     "Java_com_example_Codec_write___3BII",
     "descriptors are concatenated with no separator"),
    ("com.example.Codec", "log", ["Ljava/lang/String;"],
     "Java_com_example_Codec_log__Ljava_lang_String_2",
     "'/' becomes '_' and ';' becomes '_2'"),
    ("com.example.A", "f_", ["I"],
     "Java_com_example_A_f_1__I",
     "a method name ending in '_' followed by the overload marker"),
    ("a.b.C", "m", ["[[Ljava/lang/Object;", "Z"],
     "Java_a_b_C_m___3_3Ljava_lang_Object_2Z",
     "two array dimensions give two _3 escapes"),
    ("com.x.Y$Z$W", "go", None,
     "Java_com_x_Y_00024Z_00024W_go",
     "doubly nested inner class"),
]

DESCRIPTOR_CASES = [
    ("int", "I"),
    ("int[]", "[I"),
    ("int[][][]", "[[[I"),
    ("java.lang.String", "Ljava/lang/String;"),
    ("java.lang.String[]", "[Ljava/lang/String;"),
    ("byte[]", "[B"),
    ("boolean[][]", "[[Z"),
    ("long", "J"),
    ("com.example.Outer$Inner", "Lcom/example/Outer$Inner;"),
    ("android.content.Context", "Landroid/content/Context;"),
]

SIGNATURE_CASES = [
    ("()V", [], "void"),
    ("(I)V", ["int"], "void"),
    ("(II)V", ["int", "int"], "void"),
    ("(Ljava/lang/String;)Ljava/lang/String;", ["java.lang.String"], "java.lang.String"),
    ("([BI)[B", ["byte[]", "int"], "byte[]"),
    ("(I[BLjava/lang/String;)Z", ["int", "byte[]", "java.lang.String"], "boolean"),
    ("([BIILjava/lang/String;)[B",
     ["byte[]", "int", "int", "java.lang.String"], "byte[]"),
    ("(Landroid/content/Context;[[JZ)Ljava/lang/String;",
     ["android.content.Context", "long[][]", "boolean"], "java.lang.String"),
]


def selftest():
    failures = 0

    print("== mangling (README section 3.5) ==")
    for cls, meth, params, expected, why in MANGLE_CASES:
        short, long_sym = mangle(cls, meth, params)
        got = long_sym if params is not None else short
        ok = (got == expected)
        failures += 0 if ok else 1
        print("  [%s] %s.%s%s" % ("ok" if ok else "FAIL", cls, meth,
                                  "(" + "".join(params) + ")" if params else ""))
        print("        -> %s" % got)
        if not ok:
            print("        expected %s" % expected)
        print("        %s" % why)

    print()
    print("== demangling round trip (README section 3.6) ==")
    for cls, meth, params, expected, _why in MANGLE_CASES:
        info = demangle(expected)
        ok = (info["class"] == cls and info["method"] == meth)
        if params is not None:
            ok = ok and info["params"] == params
        failures += 0 if ok else 1
        print("  [%s] %s" % ("ok" if ok else "FAIL", expected))
        print("        -> class=%s method=%s params=%s"
              % (info["class"], info["method"], info["params_descriptor"]))
        if not ok:
            print("        expected class=%s method=%s params=%s" % (cls, meth, params))

    print()
    print("== Java type -> descriptor (README section 3.3) ==")
    for java, expected in DESCRIPTOR_CASES:
        got = java_type_to_descriptor(java)
        ok = (got == expected)
        failures += 0 if ok else 1
        print("  [%s] %-28s -> %s" % ("ok" if ok else "FAIL", java, got))

    print()
    print("== signatures (README section 3.4) ==")
    for sig, exp_params, exp_ret in SIGNATURE_CASES:
        params, ret = split_signature(sig)
        got_params = [parse_descriptor(d, 0)[0] for d in params]
        got_ret, _ = parse_descriptor(ret, 0)
        ok = (got_params == exp_params and got_ret == exp_ret)
        failures += 0 if ok else 1
        print("  [%s] %-46s -> %s (%s)"
              % ("ok" if ok else "FAIL", sig, got_ret, ", ".join(got_params) or "no args"))

    print()
    print("== negative cases ==")
    for bad, what in [
        ("com_example_Crypto_decrypt", "missing Java_ prefix"),
        ("Java_com_example_Codec_write___3Q", "unknown descriptor character"),
        ("Java_", "no method component"),
    ]:
        try:
            demangle(bad)
            print("  [FAIL] %-40s should have raised (%s)" % (bad, what))
            failures += 1
        except ValueError as exc:
            print("  [ok]   %-40s rejected: %s" % (bad, exc))

    print()
    if failures:
        print("%d FAILURE(S)" % failures)
    else:
        print("all cases pass")
    return 1 if failures else 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Mangle, demangle and parse JNI names and descriptors.",
        epilog="See ../README.md sections 3.3 to 3.6 and 3.9.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--mangle", metavar="pkg.Class.method[(sig)ret]",
                   help="produce the exported C symbol")
    g.add_argument("--demangle", metavar="SYMBOL",
                   help="recover the class, method and parameters from a symbol")
    g.add_argument("--parse", metavar="SIGNATURE",
                   help="decode a method signature and print the args[] layout")
    g.add_argument("--descriptor", metavar="JAVATYPE",
                   help="convert a Java type to its descriptor")
    g.add_argument("--smali", action="store_true",
                   help="read smali .method lines on stdin (needs --class)")
    g.add_argument("--selftest", action="store_true",
                   help="run the worked examples from the README")
    ap.add_argument("--class", dest="klass", metavar="pkg.Class",
                    help="declaring class, for --smali")
    ap.add_argument("--static", action="store_true",
                    help="for --parse: the method is static, so args[1] is a jclass")
    ap.add_argument("--critical", action="store_true",
                    help="for --parse: the method is @CriticalNative, so there "
                         "are no synthetic arguments at all")
    args = ap.parse_args(argv)

    try:
        if args.selftest:
            return selftest()
        if args.mangle:
            cmd_mangle(args.mangle)
        elif args.demangle:
            cmd_demangle(args.demangle)
        elif args.parse:
            cmd_parse(args.parse, args.static, args.critical)
        elif args.descriptor:
            print(java_type_to_descriptor(args.descriptor))
        elif args.smali:
            if not args.klass:
                ap.error("--smali requires --class pkg.Class")
            cmd_smali(args.klass, sys.stdin)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
