#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webview-audit.py -- report every WebView setting an APK actually applies, every
                    JavaScript bridge it registers, and -- the part no Network
                    Security Config auditor can see -- what its
                    `onReceivedSslError` implementation does with the error.

WHAT IT DOES
    A WebView's security posture is the sum of two things, and almost every tool
    reports only one of them:

      1. The settings the app EXPLICITLY sets, by calling WebSettings setters.
      2. The settings it never touches, whose values come from a default that
         depends on the app's `targetSdkVersion`.

    A grep for `setAllowFileAccess` finds (1) and is blind to (2). That blindness
    is the wrong way round: an app that never calls `setAllowFileAccess` at all
    has file access ENABLED if it targets API 29 or lower, and DISABLED if it
    targets 30 or higher. The dangerous configuration is the one nobody wrote.

    So this script does both. It decodes AndroidManifest.xml for
    `targetSdkVersion`, `minSdkVersion`, `android:debuggable` and the exported
    components carrying a BROWSABLE deep link; then it walks every DEX method's
    bytecode, finds every call into `android.webkit.WebSettings` and
    `android.webkit.WebView`, and -- for boolean and int setters -- backtracks
    through the instruction stream to recover the CONSTANT that was passed.
    Explicit calls override defaults; the report shows both, and says which one
    is in force.

    It then reports four things that are not settings at all:

      BRIDGES     every `addJavascriptInterface` call site, the class of the
                  object being bridged where that is statically recoverable, and
                  every class in the APK that declares a method annotated
                  `@android.webkit.JavascriptInterface`. The annotation is what
                  makes a method reachable from JavaScript on API 17+; a bridge
                  object with no annotated methods is inert, and one with five is
                  a five-function API exposed to whatever HTML loads.

      SSL ERRORS  every override of `WebViewClient.onReceivedSslError`, and what
                  its body does: whether it calls `SslErrorHandler.proceed()`,
                  whether it calls `cancel()`, whether it calls `super`, and
                  whether it branches at all. A method that calls `proceed()`,
                  never calls `cancel()`, and contains no conditional branch
                  accepts EVERY certificate error unconditionally -- and no
                  network security config, no `<pin-set>`, and no
                  `cleartextTrafficPermitted="false"` can prevent it. This is the
                  single reason the script exists.

      NAVIGATION  overrides of `shouldOverrideUrlLoading` and
                  `shouldInterceptRequest`. Both are controls and both are attack
                  surface: they are where an app decides which URLs it will load,
                  and where it very often decides wrongly.

      SINKS       `loadUrl`, `loadData`, `loadDataWithBaseURL`, `postUrl` and
                  `evaluateJavascript` call sites, with the constant string where
                  the argument is a literal. A literal `https://` asset URL is a
                  different risk from a `loadUrl(getIntent().getData())`.

WHY IT IS NOT A GREP, AND WHERE A GREP WOULD LIE TO YOU
    `grep -r setJavaScriptEnabled` cannot tell `setJavaScriptEnabled(true)` from
    `setJavaScriptEnabled(false)`, cannot tell you that the app never called it,
    and cannot tell you the default for that app's targetSdk. All three of those
    change the verdict. This script recovers the literal argument from the
    bytecode by finding the last `const` instruction that wrote the argument
    register before the call. Where the value is computed rather than constant --
    read from a field, returned by a method, chosen by a branch -- it says
    COMPUTED rather than guessing, and that is a result too: a setting whose value
    is decided at runtime is a setting you must go and measure with Frida.

WHAT THIS WILL *NOT* TELL YOU
    - What the WebView is actually configured to at runtime. This is a static
      read. Reflection, a settings object passed through a helper, a value read
      from a remote config, a build flavour, and an OEM WebView patch all defeat
      it. `./trace-webview.js` under Frida is the authority; where the two
      disagree, the device is right and the difference is itself the finding.
    - Whether `onReceivedSslError`'s `proceed()` is reachable. The script reports
      the shape of the method -- proceed present, cancel present, branches
      present. A method with a branch MIGHT be pinning correctly (compare the
      certificate, proceed only on a match) or MIGHT be checking
      `BuildConfig.DEBUG`. Read it. The script marks it UNRESOLVED, not SAFE.
    - Whether a bridge is reachable by an attacker. A bridge exposed only to a
      `file:///android_asset` page you ship is a very different finding from the
      same bridge on a page whose URL comes from an Intent. The script prints the
      deep-link surface and the loadUrl sinks so you can join them; it does not
      do the join for you, because that is a reachability question and reachability
      is where automated tools invent findings.
    - Anything about the network security config. Chapter 44 owns that file and
      ../../44-NetworkSecurityConfig/scripts/nsc-audit.py reads it properly. Run
      BOTH: 44 gives you the cleartext verdict, this gives you the certificate-error
      verdict, and neither is visible to the other.
    - Anything about pinning in Java. Chapter 36 owns that, and OkHttp's
      CertificatePinner has no effect on WebView traffic anyway -- WebView uses
      Chromium's own network stack, in a different process, and never touches the
      app's OkHttp client.
    - Native code. A WebView driven from C++ through JNI is invisible here.
    - Whether any of it matters. Severity here is the SHAPE of the defect.

HOW TO RUN
    # host - the normal case
    python3 -B webview-audit.py base.apk

    # host - a bare DEX (apktool/baksmali output, or a dumped classes.dex)
    python3 -B webview-audit.py classes.dex --target-sdk 30

    # host - split APKs: pass them all, WebView code often lives in a feature split
    python3 -B webview-audit.py base.apk split_config.arm64_v8a.apk

    # host - machine readable, and CI gating
    python3 -B webview-audit.py base.apk --json
    python3 -B webview-audit.py base.apk --fail-on HIGH

    # host - pull the APK off the device first
    adb shell pm path com.example.app
    adb pull /data/app/.../base.apk

    Run it with `python3 -B`. It imports two helper modules from other chapters by
    path, and an import writes a __pycache__ next to the IMPORTED file unless
    bytecode is disabled. The script sets sys.dont_write_bytecode before importing,
    but -B is the belt to that braces.

REQUIREMENTS
    Python 3.8+, standard library only.
    ../../12-DEX-Internals/examples/dex_parser.py   (DEX header, strings, type and
                                                     method tables)
    ../../10-APK-Internals/examples/parse_axml.py   (binary AndroidManifest.xml)
    Both locations can be overridden with --dex-parser / --parse-axml or with the
    WEBVIEW_DEX_PARSER / WEBVIEW_PARSE_AXML environment variables. If a helper is
    missing the script says so and stops, rather than guessing.

EXIT CODES
    0  ran, and nothing at or above --fail-on
    1  a finding at or above --fail-on (default: nothing fails)
    2  input could not be read or decoded

AUTHORISED TESTING ONLY. Reading an APK you were given, or one you pulled off a
device you own, is fine. Reading one you took off somebody else's phone is not.
"""

import sys

# Set BEFORE the two helper imports below. importlib's SourceLoader consults this
# flag when deciding whether to cache bytecode, so setting it here is what stops a
# __pycache__ appearing under another chapter's examples/ directory.
sys.dont_write_bytecode = True

import argparse                      # noqa: E402
import importlib.util                # noqa: E402
import json                          # noqa: E402
import os                            # noqa: E402
import re                            # noqa: E402
import struct                        # noqa: E402
import zipfile                       # noqa: E402
from collections import OrderedDict  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

DEFAULT_DEX_PARSER = os.path.join(REPO, "12-DEX-Internals", "examples", "dex_parser.py")
DEFAULT_PARSE_AXML = os.path.join(REPO, "10-APK-Internals", "examples", "parse_axml.py")

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# --------------------------------------------------------------------------- #
# Helper module loading
# --------------------------------------------------------------------------- #

def load_module(path, name):
    """Import a helper module from another chapter by absolute path."""
    if not os.path.isfile(path):
        return None
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


# --------------------------------------------------------------------------- #
# The measured default table
#
# Every row was MEASURED, not copied from documentation. See ../README.md §3.4.
# The measurement app set `getApplicationInfo().targetSdkVersion` to each value
# in turn and constructed a fresh WebView, on a Redmi M2101K6P running
# Android 11 / API 30 with WebView provider 150.0.7871.181.
#
# Each entry maps a setting to a list of (min_target_sdk, value) tuples, sorted
# descending: the first tuple whose min_target_sdk is <= the app's targetSdk wins.
# --------------------------------------------------------------------------- #

MEASURED_DEFAULTS = OrderedDict([
    ("setJavaScriptEnabled",                  [(0, False)]),
    ("setAllowFileAccess",                    [(30, False), (0, True)]),
    ("setAllowFileAccessFromFileURLs",        [(16, False), (0, True)]),
    ("setAllowUniversalAccessFromFileURLs",   [(16, False), (0, True)]),
    ("setAllowContentAccess",                 [(0, True)]),
    ("setDomStorageEnabled",                  [(0, False)]),
    ("setDatabaseEnabled",                    [(0, False)]),
    ("setMixedContentMode",                   [(21, 1), (0, 0)]),
    ("setSafeBrowsingEnabled",                [(0, True)]),
    ("setJavaScriptCanOpenWindowsAutomatically", [(0, False)]),
    ("setMediaPlaybackRequiresUserGesture",   [(0, True)]),
    ("setCacheMode",                          [(0, -1)]),
    ("setBlockNetworkLoads",                  [(0, False)]),
    ("setLoadsImagesAutomatically",           [(0, True)]),
    ("setGeolocationEnabled",                 [(0, True)]),
    ("setSavePassword",                       [(0, None)]),
    ("setSaveFormData",                       [(0, None)]),
])

# Human-readable notes for the report. Keep these one line each.
SETTING_NOTES = {
    "setJavaScriptEnabled":
        "Runs page script. A precondition for most WebView findings, not a finding itself.",
    "setAllowFileAccess":
        "Lets the WebView load file:// URLs at all. Default flipped to false at targetSdk 30.",
    "setAllowFileAccessFromFileURLs":
        "A file:// page may read other file:// URLs via XHR. Same-origin relaxation.",
    "setAllowUniversalAccessFromFileURLs":
        "A file:// page may read ANY origin, including https:// and content://. The worst one.",
    "setAllowContentAccess":
        "JavaScript may fetch content:// URIs -- reaching providers AS THE HOST APP. Default true, always.",
    "setDomStorageEnabled":
        "localStorage/sessionStorage. A storage finding when secrets land in it.",
    "setDatabaseEnabled":
        "The deprecated WebSQL database. Storage surface.",
    "setMixedContentMode":
        "0=ALWAYS_ALLOW, 1=NEVER_ALLOW, 2=COMPATIBILITY_MODE. 0 lets http subresources into an https page.",
    "setSafeBrowsingEnabled":
        "Google Safe Browsing lookups for navigations. On by default; can be killed by manifest meta-data.",
    "setJavaScriptCanOpenWindowsAutomatically":
        "window.open() without a user gesture.",
    "setMediaPlaybackRequiresUserGesture":
        "Autoplay gate. Privacy-relevant when a page can start the microphone-adjacent pipeline.",
    "setCacheMode":
        "-1=LOAD_DEFAULT, 1=LOAD_CACHE_ELSE_NETWORK, 2=LOAD_NO_CACHE, 3=LOAD_CACHE_ONLY.",
    "setBlockNetworkLoads":
        "Blocks all network loads. Rarely set; when set, a strong hardening signal.",
    "setLoadsImagesAutomatically":
        "Image loading. Not a security control by itself.",
    "setGeolocationEnabled":
        "Whether the geolocation API is offered to the page. Still gated by app permission and a prompt.",
    "setSavePassword":
        "Removed/ignored from API 18 onward. Presence usually means very old code.",
    "setSaveFormData":
        "Deprecated and a no-op from API 26. Presence usually means very old code.",
}

BOOL_SETTERS = {
    "setJavaScriptEnabled", "setAllowFileAccess", "setAllowFileAccessFromFileURLs",
    "setAllowUniversalAccessFromFileURLs", "setAllowContentAccess",
    "setDomStorageEnabled", "setDatabaseEnabled", "setSafeBrowsingEnabled",
    "setJavaScriptCanOpenWindowsAutomatically", "setMediaPlaybackRequiresUserGesture",
    "setBlockNetworkLoads", "setLoadsImagesAutomatically", "setGeolocationEnabled",
    "setSavePassword", "setSaveFormData", "setAppCacheEnabled",
    "setBuiltInZoomControls", "setDisplayZoomControls", "setUseWideViewPort",
    "setSupportMultipleWindows", "setSupportZoom",
}
INT_SETTERS = {"setMixedContentMode", "setCacheMode"}

# WebView-level statics and instance methods worth reporting on their own.
WEBVIEW_METHODS = {
    "addJavascriptInterface", "removeJavascriptInterface",
    "setWebContentsDebuggingEnabled", "setWebViewClient", "setWebChromeClient",
    "loadUrl", "loadData", "loadDataWithBaseURL", "postUrl", "evaluateJavascript",
    "setSafeBrowsingEnabled", "startSafeBrowsing", "clearCache", "clearHistory",
}

SINK_METHODS = {"loadUrl", "loadData", "loadDataWithBaseURL", "postUrl", "evaluateJavascript"}

# Client callbacks. Reported when an app DEFINES them, not when it calls them.
CLIENT_OVERRIDES = {
    "onReceivedSslError": "certificate errors",
    "onReceivedClientCertRequest": "client certificate selection",
    "onReceivedHttpAuthRequest": "HTTP authentication",
    "shouldOverrideUrlLoading": "navigation gate",
    "shouldInterceptRequest": "request interception",
    "onReceivedError": "load errors",
    "onJsAlert": "JS dialogs",
    "onPermissionRequest": "web permission grants (camera, mic, MIDI, protected media)",
    "onGeolocationPermissionsShowPrompt": "geolocation grants",
    "onShowFileChooser": "file upload picker",
    "onConsoleMessage": "console output",
}

WEBSETTINGS_TYPES = {
    "android.webkit.WebSettings",
    "android.webkit.WebSettingsClassic",
}
WEBVIEW_TYPES = {
    "android.webkit.WebView",
}
SSL_HANDLER_TYPE = "android.webkit.SslErrorHandler"
JS_ANNOTATION = "android.webkit.JavascriptInterface"


def default_for(setting, target_sdk):
    """The measured default for `setting` at `target_sdk`, or None if untracked."""
    rows = MEASURED_DEFAULTS.get(setting)
    if rows is None:
        return None
    for min_sdk, value in rows:
        if target_sdk >= min_sdk:
            return value
    return None


# --------------------------------------------------------------------------- #
# DEX bytecode: instruction widths
#
# The width of a Dalvik instruction, in 16-bit code units, is fixed by its
# opcode's FORMAT. This table is the format widths, expanded per opcode. It is
# the one piece of this script that must be exactly right: an off-by-one here
# desynchronises the decoder and every subsequent instruction in the method is
# garbage. The decoder cross-checks by requiring that the stream lands exactly on
# insns_size; a method that does not is reported as UNDECODED rather than as
# clean, so a bug here fails loudly instead of quietly.
# --------------------------------------------------------------------------- #

def _build_width_table():
    w = [1] * 256

    def setr(lo, hi, n):
        for i in range(lo, hi + 1):
            w[i] = n

    setr(0x00, 0x01, 1)          # nop, move
    w[0x02] = 2                  # move/from16
    w[0x03] = 3                  # move/16
    w[0x04] = 1                  # move-wide
    w[0x05] = 2                  # move-wide/from16
    w[0x06] = 3                  # move-wide/16
    w[0x07] = 1                  # move-object
    w[0x08] = 2                  # move-object/from16
    w[0x09] = 3                  # move-object/16
    setr(0x0a, 0x11, 1)          # move-result*, move-exception, return*
    w[0x12] = 1                  # const/4          11n
    w[0x13] = 2                  # const/16         21s
    w[0x14] = 3                  # const            31i
    w[0x15] = 2                  # const/high16     21h
    w[0x16] = 2                  # const-wide/16    21s
    w[0x17] = 3                  # const-wide/32    31i
    w[0x18] = 5                  # const-wide       51l
    w[0x19] = 2                  # const-wide/high16
    w[0x1a] = 2                  # const-string     21c
    w[0x1b] = 3                  # const-string/jumbo 31c
    w[0x1c] = 2                  # const-class      21c
    setr(0x1d, 0x1e, 1)          # monitor-enter/exit
    w[0x1f] = 2                  # check-cast       21c
    w[0x20] = 2                  # instance-of      22c
    w[0x21] = 1                  # array-length     12x
    w[0x22] = 2                  # new-instance     21c
    w[0x23] = 2                  # new-array        22c
    w[0x24] = 3                  # filled-new-array 35c
    w[0x25] = 3                  # filled-new-array/range 3rc
    w[0x26] = 3                  # fill-array-data  31t
    w[0x27] = 1                  # throw            11x
    w[0x28] = 1                  # goto             10t
    w[0x29] = 2                  # goto/16          20t
    w[0x2a] = 3                  # goto/32          30t
    setr(0x2b, 0x2c, 3)          # packed-switch, sparse-switch  31t
    setr(0x2d, 0x31, 2)          # cmp*             23x
    setr(0x32, 0x37, 2)          # if-test          22t
    setr(0x38, 0x3d, 2)          # if-testz         21t
    setr(0x3e, 0x43, 1)          # unused
    setr(0x44, 0x51, 2)          # aget/aput        23x
    setr(0x52, 0x5f, 2)          # iget/iput        22c
    setr(0x60, 0x6d, 2)          # sget/sput        21c
    setr(0x6e, 0x72, 3)          # invoke-kind      35c
    w[0x73] = 1                  # unused
    setr(0x74, 0x78, 3)          # invoke-kind/range 3rc
    setr(0x79, 0x7a, 1)          # unused
    setr(0x7b, 0x8f, 1)          # unop             12x
    setr(0x90, 0xaf, 2)          # binop            23x
    setr(0xb0, 0xcf, 1)          # binop/2addr      12x
    setr(0xd0, 0xd7, 2)          # binop/lit16      22s
    setr(0xd8, 0xe2, 2)          # binop/lit8       22b
    setr(0xe3, 0xf9, 1)          # unused
    w[0xfa] = 4                  # invoke-polymorphic        45cc
    w[0xfb] = 4                  # invoke-polymorphic/range  4rcc
    w[0xfc] = 3                  # invoke-custom             35c
    w[0xfd] = 3                  # invoke-custom/range       3rc
    w[0xfe] = 2                  # const-method-handle       21c
    w[0xff] = 2                  # const-method-type         21c
    return w


WIDTH = _build_width_table()

INVOKE_35C = {0x6e, 0x6f, 0x70, 0x71, 0x72}
INVOKE_3RC = {0x74, 0x75, 0x76, 0x77, 0x78}
INVOKE_NAME = {
    0x6e: "invoke-virtual", 0x6f: "invoke-super", 0x70: "invoke-direct",
    0x71: "invoke-static", 0x72: "invoke-interface",
    0x74: "invoke-virtual/range", 0x75: "invoke-super/range",
    0x76: "invoke-direct/range", 0x77: "invoke-static/range",
    0x78: "invoke-interface/range",
}
IF_OPS = set(range(0x32, 0x3e))          # if-eq .. if-lez
SWITCH_OPS = {0x2b, 0x2c}


class Insn:
    __slots__ = ("off", "op", "size", "args", "idx", "lit", "dest")

    def __init__(self, off, op, size):
        self.off = off
        self.op = op
        self.size = size
        self.args = []       # register numbers, for invokes
        self.idx = None      # method_idx / string_idx / type_idx
        self.lit = None      # literal value, for const forms
        self.dest = None     # destination register, for const forms


def decode_method(data, insns_off, insns_size):
    """Decode one method's instruction stream. Returns (list, ok)."""
    out = []
    off = insns_off
    end = insns_off + insns_size * 2
    while off < end:
        op = data[off]
        if op == 0x00 and off + 2 <= end:
            ident = struct.unpack_from("<H", data, off)[0]
            if ident == 0x0100:                       # packed-switch-payload
                size = struct.unpack_from("<H", data, off + 2)[0]
                units = (size * 2) + 4
                off += units * 2
                continue
            if ident == 0x0200:                       # sparse-switch-payload
                size = struct.unpack_from("<H", data, off + 2)[0]
                units = (size * 4) + 2
                off += units * 2
                continue
            if ident == 0x0300:                       # fill-array-data-payload
                width = struct.unpack_from("<H", data, off + 2)[0]
                count = struct.unpack_from("<I", data, off + 4)[0]
                units = (count * width + 1) // 2 + 4
                off += units * 2
                continue
        size = WIDTH[op]
        if off + size * 2 > end:
            return out, False
        ins = Insn(off, op, size)

        if op in INVOKE_35C:
            b1 = data[off + 1]
            count = (b1 >> 4) & 0xF
            g = b1 & 0xF
            ins.idx = struct.unpack_from("<H", data, off + 2)[0]
            fedc = struct.unpack_from("<H", data, off + 4)[0]
            c = fedc & 0xF
            d = (fedc >> 4) & 0xF
            e = (fedc >> 8) & 0xF
            f = (fedc >> 12) & 0xF
            ins.args = [c, d, e, f, g][:count]
        elif op in INVOKE_3RC:
            count = data[off + 1]
            ins.idx = struct.unpack_from("<H", data, off + 2)[0]
            first = struct.unpack_from("<H", data, off + 4)[0]
            ins.args = list(range(first, first + count))
        elif op == 0x12:                              # const/4
            b1 = data[off + 1]
            ins.dest = b1 & 0xF
            v = (b1 >> 4) & 0xF
            ins.lit = v - 16 if v > 7 else v
        elif op == 0x13:                              # const/16
            ins.dest = data[off + 1]
            ins.lit = struct.unpack_from("<h", data, off + 2)[0]
        elif op == 0x14:                              # const
            ins.dest = data[off + 1]
            ins.lit = struct.unpack_from("<i", data, off + 2)[0]
        elif op == 0x15:                              # const/high16
            ins.dest = data[off + 1]
            ins.lit = struct.unpack_from("<h", data, off + 2)[0] << 16
        elif op == 0x1a:                              # const-string
            ins.dest = data[off + 1]
            ins.idx = struct.unpack_from("<H", data, off + 2)[0]
        elif op == 0x1b:                              # const-string/jumbo
            ins.dest = data[off + 1]
            ins.idx = struct.unpack_from("<I", data, off + 2)[0]
        elif op == 0x01:                              # move vA, vB
            b1 = data[off + 1]
            ins.dest = b1 & 0xF
            ins.args = [(b1 >> 4) & 0xF]
        elif op == 0x07:                              # move-object vA, vB
            b1 = data[off + 1]
            ins.dest = b1 & 0xF
            ins.args = [(b1 >> 4) & 0xF]
        elif op in (0x0a, 0x0b, 0x0c):                # move-result*
            ins.dest = data[off + 1]

        out.append(ins)
        off += size * 2
    return out, off == end


def backtrack_const(insns, i, reg):
    """
    Recover the constant most recently written to `reg` before instruction i.

    Walks backwards from the call site. Returns (value, "CONST") when a const
    instruction wrote the register, ("<move>", "ALIAS") when a move did (the
    value came from somewhere we would have to follow), or (None, "COMPUTED")
    when the last writer was anything else -- a field read, a method return, a
    phi across a branch. COMPUTED is a real answer, not a failure: it means the
    value is decided at runtime and you must measure it.
    """
    j = i - 1
    while j >= 0:
        ins = insns[j]
        if ins.dest == reg:
            if ins.op in (0x12, 0x13, 0x14, 0x15):
                return ins.lit, "CONST"
            if ins.op in (0x1a, 0x1b):
                return ins.idx, "STRING"
            if ins.op in (0x01, 0x07):
                return None, "ALIAS"
            return None, "COMPUTED"
        # An invoke writes its result to the pseudo-register read by a following
        # move-result; if that move-result targets our register we have already
        # matched it above, so nothing to do here.
        j -= 1
    return None, "PARAM"      # never written in this method: it is a parameter


# --------------------------------------------------------------------------- #
# DEX walking
# --------------------------------------------------------------------------- #

def jvm_type_to_dotted(t):
    """Turn a DEX type descriptor or already-dotted name into a dotted name."""
    if not t:
        return t
    if t.startswith("L") and t.endswith(";"):
        return t[1:-1].replace("/", ".")
    return t.replace("/", ".")


class DexScan:
    """One DEX file, walked for everything this chapter cares about."""

    def __init__(self, data, dexmod, source_name):
        self.data = data
        self.source = source_name
        self.dex = dexmod.DexFile(data)
        self.read_uleb128 = dexmod.read_uleb128
        self.h = self.dex.header
        self._mref_cache = {}
        self.setting_calls = []      # dicts
        self.webview_calls = []      # dicts
        self.overrides = []          # dicts
        self.bridge_classes = {}     # dotted class -> [method names]
        self.undecoded = 0
        self.methods_scanned = 0
        self.js_annotation_present = False

    # -- name helpers ------------------------------------------------------- #

    def mref(self, idx):
        m = self._mref_cache.get(idx)
        if m is None:
            m = self.dex.method_ref(idx)
            if m is None:
                m = {"cls": "?", "name": "?", "shorty": "?", "ret": "?"}
            m = dict(m)
            m["cls_dotted"] = jvm_type_to_dotted(m["cls"])
            self._mref_cache[idx] = m
        return m

    def sref(self, idx):
        try:
            return self.dex.string(idx)
        except Exception:
            return None

    # -- class_def / class_data --------------------------------------------- #

    def _class_def_raw(self, i):
        base = self.h["class_defs_off"] + i * 32
        return struct.unpack_from("<8I", self.data, base)

    def _encoded_methods(self, class_data_off):
        """Yield (method_idx, access_flags, code_off) for every method."""
        d = self.data
        off = class_data_off
        sf, off = self.read_uleb128(d, off)
        inf, off = self.read_uleb128(d, off)
        dm, off = self.read_uleb128(d, off)
        vm, off = self.read_uleb128(d, off)
        for _ in range(sf + inf):
            _, off = self.read_uleb128(d, off)     # field_idx_diff
            _, off = self.read_uleb128(d, off)     # access_flags
        for group in (dm, vm):
            idx = 0
            for _ in range(group):
                diff, off = self.read_uleb128(d, off)
                idx += diff
                access, off = self.read_uleb128(d, off)
                code_off, off = self.read_uleb128(d, off)
                yield idx, access, code_off

    def _annotated_js_methods(self, annotations_off):
        """
        Return the set of method_idx values on this class carrying
        @android.webkit.JavascriptInterface.

        annotations_directory_item:
            u4 class_annotations_off
            u4 fields_size, u4 annotated_methods_size, u4 annotated_parameters_size
            field_annotation[]      (u4 field_idx, u4 annotations_off)
            method_annotation[]     (u4 method_idx, u4 annotations_off)
        annotation_set_item: u4 size, u4 entries[size] -> annotation_item
        annotation_item: u1 visibility, encoded_annotation (uleb type_idx, ...)
        """
        d = self.data
        out = set()
        if not annotations_off:
            return out
        try:
            (_cls_ann, fields_size, methods_size,
             _params_size) = struct.unpack_from("<4I", d, annotations_off)
        except Exception:
            return out
        base = annotations_off + 16 + fields_size * 8
        for k in range(methods_size):
            try:
                m_idx, set_off = struct.unpack_from("<2I", d, base + k * 8)
            except Exception:
                break
            if not set_off:
                continue
            try:
                size = struct.unpack_from("<I", d, set_off)[0]
            except Exception:
                continue
            for e in range(size):
                try:
                    item_off = struct.unpack_from("<I", d, set_off + 4 + e * 4)[0]
                except Exception:
                    break
                if not item_off:
                    continue
                try:
                    type_idx, _ = self.read_uleb128(d, item_off + 1)
                    tname = jvm_type_to_dotted(self.dex.type_name(type_idx))
                except Exception:
                    continue
                if tname == JS_ANNOTATION:
                    out.add(m_idx)
                    self.js_annotation_present = True
        return out

    # -- the walk ----------------------------------------------------------- #

    def scan(self):
        d = self.data
        h = self.h
        for i in range(h["class_defs_size"]):
            (class_idx, access_flags, super_idx, _iface_off, _src_idx,
             annotations_off, class_data_off, _static_off) = self._class_def_raw(i)
            if not class_data_off:
                continue
            cls_name = jvm_type_to_dotted(self.dex.type_name(class_idx))
            super_name = jvm_type_to_dotted(self.dex.type_name(super_idx))
            js_methods = self._annotated_js_methods(annotations_off)

            try:
                methods = list(self._encoded_methods(class_data_off))
            except Exception:
                continue

            for m_idx, m_access, code_off in methods:
                m = self.mref(m_idx)
                if m_idx in js_methods:
                    self.bridge_classes.setdefault(cls_name, [])
                    sig = "%s(%s)" % (m["name"], m["shorty"][1:])
                    if sig not in self.bridge_classes[cls_name]:
                        self.bridge_classes[cls_name].append(sig)

                # A DEFINED method whose name matches a WebViewClient /
                # WebChromeClient callback is an override worth reporting.
                if m["name"] in CLIENT_OVERRIDES and code_off:
                    self._record_override(cls_name, super_name, m, code_off)

                if not code_off:
                    continue
                self.methods_scanned += 1
                self._scan_code(cls_name, m, code_off)

    def _code_insns(self, code_off):
        try:
            (_regs, _ins, _outs, _tries, _dbg,
             insns_size) = struct.unpack_from("<4H2I", self.data, code_off)
        except Exception:
            return None, False
        return decode_method(self.data, code_off + 16, insns_size)

    def _record_override(self, cls_name, super_name, m, code_off):
        insns, ok = self._code_insns(code_off)
        if insns is None:
            return
        rec = {
            "source": self.source,
            "class": cls_name,
            "super": super_name,
            "method": m["name"],
            "shorty": m["shorty"],
            "purpose": CLIENT_OVERRIDES[m["name"]],
            "insn_count": len(insns),
            "decoded": ok,
            "calls": [],
            "branches": 0,
            "calls_super": False,
        }
        for ins in insns:
            if ins.op in IF_OPS or ins.op in SWITCH_OPS:
                rec["branches"] += 1
            if ins.op in INVOKE_35C or ins.op in INVOKE_3RC:
                tm = self.mref(ins.idx)
                rec["calls"].append(tm["cls_dotted"] + "." + tm["name"])
                if ins.op in (0x6f, 0x75):
                    rec["calls_super"] = True
        if m["name"] == "onReceivedSslError":
            rec["proceed"] = any(
                c == SSL_HANDLER_TYPE + ".proceed" for c in rec["calls"])
            rec["cancel"] = any(
                c == SSL_HANDLER_TYPE + ".cancel" for c in rec["calls"])
            rec["reads_error"] = any(
                c.startswith("android.webkit.SslError.") for c in rec["calls"])
        self.overrides.append(rec)

    def _scan_code(self, cls_name, m, code_off):
        insns, ok = self._code_insns(code_off)
        if insns is None:
            return
        if not ok:
            self.undecoded += 1
            return
        for i, ins in enumerate(insns):
            if ins.op not in INVOKE_35C and ins.op not in INVOKE_3RC:
                continue
            tm = self.mref(ins.idx)
            tcls = tm["cls_dotted"]
            tname = tm["name"]

            if tcls in WEBSETTINGS_TYPES and (
                    tname in BOOL_SETTERS or tname in INT_SETTERS):
                value, how = (None, "NOARG")
                if len(ins.args) >= 2:
                    value, how = backtrack_const(insns, i, ins.args[1])
                if how == "CONST" and tname in BOOL_SETTERS:
                    value = bool(value)
                self.setting_calls.append({
                    "source": self.source,
                    "setting": tname,
                    "value": value,
                    "how": how,
                    "caller": cls_name + "." + m["name"],
                    "insn": INVOKE_NAME.get(ins.op, hex(ins.op)),
                })
                continue

            if tname in WEBVIEW_METHODS and (
                    tcls in WEBVIEW_TYPES or tcls.endswith("WebView")
                    or tname == "setWebContentsDebuggingEnabled"):
                rec = {
                    "source": self.source,
                    "target": tcls,
                    "method": tname,
                    "caller": cls_name + "." + m["name"],
                    "args": [],
                }
                for a_i, reg in enumerate(ins.args):
                    if a_i == 0 and ins.op != 0x71 and ins.op != 0x77:
                        continue          # `this`
                    v, how = backtrack_const(insns, i, reg)
                    if how == "STRING":
                        rec["args"].append(("str", self.sref(v)))
                    elif how == "CONST":
                        rec["args"].append(("const", v))
                    else:
                        rec["args"].append((how.lower(), None))
                self.webview_calls.append(rec)


# --------------------------------------------------------------------------- #
# Manifest
# --------------------------------------------------------------------------- #

def parse_manifest(axml_bytes, axmlmod):
    """Return a dict of the manifest facts that change a WebView verdict."""
    info = {
        "package": None, "target_sdk": None, "min_sdk": None,
        "debuggable": False, "browsable": [], "uses_cleartext": None,
        "nsc_ref": None, "xml": None,
    }
    # Chapter 10's decoder exposes Axml(data).to_xml(). The alternatives below are
    # tolerated so a differently-named local copy still works rather than silently
    # producing an empty manifest.
    text = None
    cls = getattr(axmlmod, "Axml", None) or getattr(axmlmod, "AXMLParser", None)
    if cls is not None:
        try:
            text = cls(axml_bytes).to_xml()
        except Exception:
            text = None
    if text is None:
        for fname in ("decode", "decode_axml", "axml_to_xml"):
            fn = getattr(axmlmod, fname, None)
            if callable(fn):
                try:
                    text = fn(axml_bytes)
                    break
                except Exception:
                    text = None
    # Chapter 10's to_xml() returns a LIST OF LINES in a diagnostic dialect, not a
    # single XML string: element names and attributes sit on separate lines, values
    # are single-quoted for strings and bare for integers, and each carries a
    # `(TYPE_..., data=0x...)` trailer. Handle that shape first, then fall back to
    # ordinary double-quoted XML so a different decoder still works.
    if isinstance(text, (list, tuple)):
        lines = [str(x) for x in text]
        text = "\n".join(lines)
    elif isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
        lines = text.splitlines()
    elif isinstance(text, str):
        lines = text.splitlines()
    else:
        return info
    info["xml"] = text

    def attr(name):
        """Value of an attribute, in either dialect. Strings lose their quotes."""
        m = re.search(r"(?:android:)?%s\s*=\s*'([^']*)'" % re.escape(name), text)
        if m:
            return m.group(1)
        m = re.search(r'(?:android:)?%s\s*=\s*"([^"]*)"' % re.escape(name), text)
        if m:
            return m.group(1)
        m = re.search(r"(?:android:)?%s\s*=\s*([^\s]+)" % re.escape(name), text)
        if m:
            return m.group(1)
        return None

    info["package"] = attr("package")
    for key, name in (("target_sdk", "targetSdkVersion"), ("min_sdk", "minSdkVersion")):
        v = attr(name)
        if v is not None:
            m = re.search(r"\d+", v)
            if m:
                info[key] = int(m.group(0))
    v = attr("debuggable")
    if v is not None:
        info["debuggable"] = v.lower() in ("true", "1", "0x1", "0xffffffff")
    v = attr("usesCleartextTraffic")
    if v is not None:
        info["uses_cleartext"] = v.lower() in ("true", "1", "0x1")
    if "networkSecurityConfig" in text:
        info["nsc_ref"] = True

    # Activities carrying a BROWSABLE category -- the usual way an attacker URL
    # reaches loadUrl. The element and its android:name arrive on separate lines,
    # so this is a small state machine rather than one regex: remember the most
    # recent <activity>/<activity-alias> name, and credit any BROWSABLE seen before
    # the element closes to it.
    current = None
    awaiting_name = False
    for line in lines:
        s = line.strip()
        if s.startswith("<activity") or s.startswith("<activity-alias"):
            current, awaiting_name = None, True
            continue
        if s.startswith("</activity"):
            current, awaiting_name = None, False
            continue
        if awaiting_name:
            m = re.search(r"(?:android:)?name\s*=\s*['\"]([^'\"]+)['\"]", s)
            if m:
                current = m.group(1)
                awaiting_name = False
        if "BROWSABLE" in s and current and current not in info["browsable"]:
            info["browsable"].append(current)
    return info


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

class Finding:
    def __init__(self, sev, code, title, evidence, note):
        self.sev = sev
        self.code = code
        self.title = title
        self.evidence = evidence
        self.note = note

    def as_dict(self):
        return {"severity": self.sev, "id": self.code, "title": self.title,
                "evidence": self.evidence, "note": self.note}


def effective_settings(setting_calls, target_sdk):
    """
    Merge explicit calls with measured defaults.

    Returns an ordered dict: setting -> dict(default, explicit=[values], effective,
    conflict, source).
    """
    by_setting = {}
    for c in setting_calls:
        by_setting.setdefault(c["setting"], []).append(c)

    out = OrderedDict()
    names = list(MEASURED_DEFAULTS.keys())
    for extra in sorted(by_setting):
        if extra not in names:
            names.append(extra)

    for name in names:
        calls = by_setting.get(name, [])
        dflt = default_for(name, target_sdk)
        values = set()
        unresolved = False
        for c in calls:
            if c["how"] == "CONST":
                values.add(c["value"])
            else:
                unresolved = True
        if not calls:
            eff, src = dflt, "default"
        elif unresolved:
            eff, src = "RUNTIME", "computed"
        elif len(values) == 1:
            eff, src = next(iter(values)), "explicit"
        else:
            eff, src = "CONFLICT", "explicit (differs by call site)"
        out[name] = {
            "default": dflt,
            "explicit": sorted(values, key=str),
            "calls": calls,
            "effective": eff,
            "source": src,
            "unresolved": unresolved,
        }
    return out


def build_findings(manifest, eff, scans):
    f = []
    target = manifest.get("target_sdk") or 0
    bridges = {}
    for s in scans:
        for k, v in s.bridge_classes.items():
            bridges.setdefault(k, []).extend(x for x in v if x not in bridges.get(k, []))
    add_js_calls = [c for s in scans for c in s.webview_calls
                    if c["method"] == "addJavascriptInterface"]
    dbg_calls = [c for s in scans for c in s.webview_calls
                 if c["method"] == "setWebContentsDebuggingEnabled"]
    ssl_overrides = [o for s in scans for o in s.overrides
                     if o["method"] == "onReceivedSslError"]
    sinks = [c for s in scans for c in s.webview_calls if c["method"] in SINK_METHODS]

    js_on = eff.get("setJavaScriptEnabled", {}).get("effective")

    # --- certificate errors: the reason this script exists ------------------ #
    for o in ssl_overrides:
        if o.get("proceed") and not o.get("cancel") and o["branches"] == 0:
            f.append(Finding(
                "CRITICAL", "WV-001",
                "onReceivedSslError accepts every certificate error unconditionally",
                "%s.onReceivedSslError -> SslErrorHandler.proceed(), no cancel(), "
                "no branch, %d instructions" % (o["class"], o["insn_count"]),
                "No network security config can prevent this. The WebView will load "
                "any host presenting any certificate, expired, self-signed or "
                "attacker-issued. Verify on device with ../scripts/trace-webview.js, "
                "then capture the traffic."))
        elif o.get("proceed"):
            f.append(Finding(
                "HIGH", "WV-002",
                "onReceivedSslError may accept certificate errors",
                "%s.onReceivedSslError calls proceed(); cancel=%s branches=%d "
                "reads SslError=%s" % (o["class"], o.get("cancel"), o["branches"],
                                       o.get("reads_error")),
                "The method branches, so proceed() might be gated -- on a certificate "
                "comparison (a hand-rolled pin, fine) or on BuildConfig.DEBUG (not "
                "fine, and it ships). UNRESOLVED: read the method."))
        elif not o.get("proceed") and not o.get("cancel") and not o["calls_super"]:
            f.append(Finding(
                "MEDIUM", "WV-003",
                "onReceivedSslError overridden but neither proceeds, cancels nor calls super",
                "%s.onReceivedSslError, %d instructions" % (o["class"], o["insn_count"]),
                "An empty override. The default behaviour (cancel) is lost because "
                "super is not called; the handler is never told anything, so the load "
                "stalls. Usually a bug rather than a vulnerability, but check."))

    # --- file URL origins --------------------------------------------------- #
    if eff.get("setAllowUniversalAccessFromFileURLs", {}).get("effective") is True:
        f.append(Finding(
            "HIGH", "WV-010",
            "setAllowUniversalAccessFromFileURLs(true)",
            _sites(eff, "setAllowUniversalAccessFromFileURLs"),
            "A file:// page may read any origin: other local files, remote https "
            "sites with the app's cookies, and content:// providers. Combined with "
            "any path by which an attacker controls a local HTML file, this is "
            "same-origin policy removed."))
    if eff.get("setAllowFileAccessFromFileURLs", {}).get("effective") is True:
        f.append(Finding(
            "MEDIUM", "WV-011",
            "setAllowFileAccessFromFileURLs(true)",
            _sites(eff, "setAllowFileAccessFromFileURLs"),
            "A file:// page may XHR other file:// URLs -- including the app's own "
            "private data directory. Local file exfiltration if any attacker-influenced "
            "HTML is ever loaded from file://."))

    fa = eff.get("setAllowFileAccess", {})
    if fa.get("effective") is True:
        sev = "MEDIUM" if fa.get("source") == "explicit" and target >= 30 else "LOW"
        f.append(Finding(
            sev, "WV-012",
            "file:// URL loading is enabled",
            "%s (targetSdk %d; measured default at this target is %s)"
            % (_sites(eff, "setAllowFileAccess") or "no explicit call", target,
               fa.get("default")),
            "At targetSdk 30 and above the default is false, so an explicit true is a "
            "deliberate re-enable and deserves a reason. Below 30 this is simply the "
            "default and is only a finding in combination -- with a file:// load whose "
            "path an attacker influences, or with the two settings above."))

    mcm = eff.get("setMixedContentMode", {})
    if mcm.get("effective") == 0:
        f.append(Finding(
            "MEDIUM", "WV-013",
            "MIXED_CONTENT_ALWAYS_ALLOW",
            "%s (targetSdk %d; measured default at this target is %s)"
            % (_sites(eff, "setMixedContentMode") or "no explicit call", target,
               mcm.get("default")),
            "http:// subresources load inside an https:// page. Scripts among them "
            "execute with the page's origin, so a network attacker gets script "
            "execution in a TLS-protected context. Note the network security config "
            "still governs whether the http request is permitted at all -- see "
            "../../44-NetworkSecurityConfig/README.md."))
    elif mcm.get("effective") == 2:
        f.append(Finding(
            "LOW", "WV-014",
            "MIXED_CONTENT_COMPATIBILITY_MODE",
            _sites(eff, "setMixedContentMode"),
            "Chromium's own heuristics decide: active content (script, iframes) is "
            "blocked, passive content (images) is allowed. Better than ALWAYS_ALLOW, "
            "weaker than NEVER_ALLOW, and the exact boundary moves with the WebView "
            "version -- which updates independently of the OS."))

    # --- bridges ------------------------------------------------------------ #
    if add_js_calls:
        bridge_names = ", ".join(sorted(bridges)) or "(no annotated class found in this APK)"
        annotated = sum(len(v) for v in bridges.values())
        sev = "HIGH" if js_on is True else "MEDIUM"
        f.append(Finding(
            sev, "WV-020",
            "addJavascriptInterface: a Java bridge is exposed to page JavaScript",
            "%d call site(s); %d @JavascriptInterface method(s) across %d class(es): %s"
            % (len(add_js_calls), annotated, len(bridges), bridge_names),
            "Every annotated method is callable by any script running in this WebView, "
            "in the host app's process and with the host app's UID and permissions. "
            "The risk is the BRIDGE, not the annotation: the annotation narrows which "
            "methods are reachable, it does not make the reachable ones safe. Severity "
            "here is the shape; impact depends on what the methods do and on whether "
            "attacker-controlled content can reach the WebView."))
        if js_on is not True:
            f.append(Finding(
                "INFO", "WV-021",
                "Bridge registered but JavaScript not statically proven enabled",
                "setJavaScriptEnabled effective value: %r" % (js_on,),
                "A bridge with JavaScript off is inert. Confirm at runtime before "
                "downgrading -- setJavaScriptEnabled is very often called on a "
                "settings object obtained through a helper, which this static read "
                "cannot follow."))
    elif bridges:
        f.append(Finding(
            "LOW", "WV-022",
            "@JavascriptInterface methods exist but no addJavascriptInterface call was found",
            "%d class(es): %s" % (len(bridges), ", ".join(sorted(bridges))),
            "Either the registration is in another split/DEX, or it is done by "
            "reflection, or the class is dead code. Do not close this without "
            "checking at runtime."))

    # --- content:// from JavaScript ----------------------------------------- #
    ca = eff.get("setAllowContentAccess", {})
    if ca.get("effective") is not False and js_on is True:
        f.append(Finding(
            "MEDIUM", "WV-030",
            "JavaScript can fetch content:// URIs (setAllowContentAccess)",
            "effective=%r via %s; JavaScript enabled" % (ca.get("effective"), ca.get("source")),
            "Script in this WebView may issue requests to content:// URIs, and the "
            "provider sees the request as coming from THIS app. Every provider the app "
            "can read -- its own, and every exported provider on the device it holds "
            "permission for -- is reachable from a web page. Default is true at every "
            "targetSdk measured, so this is usually a setting nobody wrote. See "
            "../../27-ContentProviders/README.md for what is on the other end."))

    # --- remote debugging ---------------------------------------------------- #
    for c in dbg_calls:
        val = next((v for k, v in c["args"] if k == "const"), None)
        if val:
            f.append(Finding(
                "HIGH" if not manifest.get("debuggable") else "MEDIUM", "WV-040",
                "setWebContentsDebuggingEnabled(true)",
                "%s (manifest debuggable=%s)" % (c["caller"], manifest.get("debuggable")),
                "Opens an abstract-namespace unix socket named @<process>_devtools_remote. "
                "Abstract sockets carry NO filesystem permissions, so any local process "
                "that can reach the namespace can attach a full DevTools session: read "
                "the DOM, run script in the page, and call every bridge method. In a "
                "release build this is a finding on its own. Verify with "
                "`adb shell cat /proc/net/unix | grep devtools`."))

    # --- navigation gates ---------------------------------------------------- #
    nav = [o for s in scans for o in s.overrides
           if o["method"] in ("shouldOverrideUrlLoading", "shouldInterceptRequest")]
    if nav:
        f.append(Finding(
            "INFO", "WV-050",
            "Navigation is filtered in app code",
            "; ".join(sorted({"%s.%s" % (o["class"], o["method"]) for o in nav})),
            "Read these. They are the app's allow-list, and allow-lists written with "
            "String.contains(), startsWith() or endsWith() are routinely bypassable -- "
            "`https://trusted.example.com.attacker.net`, `https://attacker/?x=trusted.example.com`, "
            "or a userinfo prefix. This is also where `intent:` and custom schemes are "
            "handled; see ../../26-Intent/README.md."))

    # --- deep link to sink --------------------------------------------------- #
    dyn_sinks = [c for c in sinks
                 if c["method"] in ("loadUrl", "loadDataWithBaseURL", "postUrl")
                 and not any(k == "str" for k, _ in c["args"])]
    if manifest.get("browsable") and dyn_sinks:
        f.append(Finding(
            "MEDIUM", "WV-060",
            "BROWSABLE deep link plus a non-constant loadUrl argument",
            "%d BROWSABLE activity/activities: %s; %d dynamic sink(s), e.g. %s"
            % (len(manifest["browsable"]), ", ".join(manifest["browsable"][:4]),
               len(dyn_sinks), dyn_sinks[0]["caller"]),
            "This is the standard chain: a link in a browser or another app reaches an "
            "exported Activity, whose Intent data ends up in loadUrl. Prove the path "
            "before you report it -- `adb shell am start -a android.intent.action.VIEW "
            "-d '<url>'`. Chapter 26 owns Intent resolution, chapter 30 owns the "
            "activity; this chapter owns what happens once the URL lands."))

    # --- honest severity on JS itself ---------------------------------------- #
    if js_on is True and not add_js_calls:
        f.append(Finding(
            "INFO", "WV-070",
            "JavaScript enabled",
            _sites(eff, "setJavaScriptEnabled"),
            "NOT a finding on its own. Almost every WebView that renders real content "
            "needs it. It is the precondition that turns other settings into findings: "
            "a bridge, content:// access, universal file access, a permissive "
            "navigation gate. Report it as context, never as the headline."))

    if eff.get("setDomStorageEnabled", {}).get("effective") is True:
        f.append(Finding(
            "INFO", "WV-071",
            "DOM storage enabled",
            _sites(eff, "setDomStorageEnabled"),
            "localStorage is written to the app's data directory in plain text under "
            "app_webview/Local Storage/. A storage finding only if something sensitive "
            "goes into it -- go and look. See ../../33-Storage/README.md."))

    f.sort(key=lambda x: -SEVERITY_ORDER.get(x.sev, 0))
    return f


def _sites(eff, name):
    e = eff.get(name)
    if not e or not e["calls"]:
        return ""
    parts = []
    for c in e["calls"][:6]:
        parts.append("%s -> %s(%s)" % (c["caller"], name,
                                       c["value"] if c["how"] == "CONST" else c["how"]))
    if len(e["calls"]) > 6:
        parts.append("... %d more" % (len(e["calls"]) - 6))
    return "; ".join(parts)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def fmt(v):
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def report_text(target_name, manifest, eff, scans, findings, show_all):
    w = sys.stdout.write
    w("\n")
    w("=" * 78 + "\n")
    w("  WebView configuration audit -- %s\n" % target_name)
    w("=" * 78 + "\n\n")

    w("  package        %s\n" % fmt(manifest.get("package")))
    w("  targetSdk      %s\n" % fmt(manifest.get("target_sdk")))
    w("  minSdk         %s\n" % fmt(manifest.get("min_sdk")))
    w("  debuggable     %s\n" % fmt(manifest.get("debuggable")))
    if manifest.get("nsc_ref"):
        w("  networkSecurityConfig present -- run "
          "../../44-NetworkSecurityConfig/scripts/nsc-audit.py for the cleartext half\n")
    if manifest.get("browsable"):
        w("  BROWSABLE      %s\n" % ", ".join(manifest["browsable"][:6]))
    w("  DEX scanned    %s (%d method bodies)\n"
      % (", ".join(s.source for s in scans),
         sum(s.methods_scanned for s in scans)))
    undec = sum(s.undecoded for s in scans)
    if undec:
        w("  UNDECODED      %d method bodies did not decode cleanly -- results are "
          "incomplete for those\n" % undec)
    w("\n")

    w("-- effective settings " + "-" * 56 + "\n")
    w("   %-42s %-9s %-9s %s\n" % ("setting", "default", "effective", "from"))
    for name, e in eff.items():
        if not show_all and not e["calls"] and e["effective"] == e["default"] \
                and name not in ("setAllowContentAccess", "setAllowFileAccess",
                                 "setJavaScriptEnabled", "setMixedContentMode"):
            continue
        flag = " " if e["source"] == "default" else "*"
        w(" %s %-42s %-9s %-9s %s\n"
          % (flag, name, fmt(e["default"]), fmt(e["effective"]), e["source"]))
        for c in e["calls"][:4]:
            w("     %s -> %s\n"
              % (c["caller"], c["value"] if c["how"] == "CONST" else "<" + c["how"] + ">"))
        if len(e["calls"]) > 4:
            w("     ... %d more call sites\n" % (len(e["calls"]) - 4))
    w("\n   * = the app sets this explicitly. Unmarked rows are the measured default\n")
    w("     for this targetSdk (see ../README.md 3.4), which nobody wrote down.\n\n")

    bridges = {}
    for s in scans:
        for k, v in s.bridge_classes.items():
            bridges.setdefault(k, [])
            for x in v:
                if x not in bridges[k]:
                    bridges[k].append(x)
    w("-- JavaScript bridge " + "-" * 57 + "\n")
    reg = [c for s in scans for c in s.webview_calls if c["method"] == "addJavascriptInterface"]
    if not reg and not bridges:
        w("   none found\n\n")
    else:
        for c in reg:
            names = [v for k, v in c["args"] if k == "str"]
            w("   addJavascriptInterface at %s   name=%s\n"
              % (c["caller"], names[0] if names else "<computed>"))
        for cls, methods in sorted(bridges.items()):
            w("   @JavascriptInterface  %s\n" % cls)
            for m in methods:
                w("       %s\n" % m)
        w("\n")

    w("-- certificate error handling " + "-" * 48 + "\n")
    ssl = [o for s in scans for o in s.overrides if o["method"] == "onReceivedSslError"]
    if not ssl:
        w("   no onReceivedSslError override found.\n")
        w("   Default behaviour applies: WebViewClient.onReceivedSslError cancels the\n")
        w("   load. That is the SAFE default and the absence of an override is good news.\n\n")
    else:
        for o in ssl:
            w("   %s\n" % o["class"])
            w("       instructions=%d branches=%d proceed=%s cancel=%s super=%s "
              "readsSslError=%s\n"
              % (o["insn_count"], o["branches"], o.get("proceed"), o.get("cancel"),
                 o["calls_super"], o.get("reads_error")))
        w("\n")

    other = [o for s in scans for o in s.overrides
             if o["method"] != "onReceivedSslError"]
    if other:
        w("-- other WebView client callbacks overridden " + "-" * 33 + "\n")
        seen = set()
        for o in sorted(other, key=lambda x: (x["method"], x["class"])):
            key = (o["class"], o["method"])
            if key in seen:
                continue
            seen.add(key)
            w("   %-34s %s  (%s)\n" % (o["method"], o["class"], o["purpose"]))
        w("\n")

    sinks = [c for s in scans for c in s.webview_calls if c["method"] in SINK_METHODS]
    if sinks:
        w("-- content loading sinks " + "-" * 53 + "\n")
        counts = {}
        for c in sinks:
            counts[c["method"]] = counts.get(c["method"], 0) + 1
        w("   " + "  ".join("%s=%d" % kv for kv in sorted(counts.items())) + "\n")
        lit = [(c, v) for c in sinks for k, v in c["args"] if k == "str" and v]
        shown = 0
        for c, v in lit:
            if shown >= 12:
                w("   ... and more literal URLs; use --all to see every call site\n")
                break
            if v.startswith(("http://", "https://", "file://", "content://", "javascript:",
                             "about:", "data:")):
                w("   %-22s %s\n" % (c["method"], v[:96]))
                shown += 1
        dyn = [c for c in sinks if not any(k == "str" for k, _ in c["args"])]
        if dyn:
            w("   %d call site(s) with a NON-CONSTANT argument -- these are the ones that\n"
              % len(dyn))
            w("   matter. Where does the string come from?\n")
            for c in dyn[:8]:
                w("       %-22s %s\n" % (c["method"], c["caller"]))
        w("\n")

    w("-- findings " + "-" * 66 + "\n")
    if not findings:
        w("   nothing to report. Note that 'nothing statically visible' and 'secure'\n")
        w("   are different claims -- run ../scripts/trace-webview.js against the\n")
        w("   running app before you write the second one.\n")
    for fi in findings:
        w("\n   [%s] %s  %s\n" % (fi.sev, fi.code, fi.title))
        if fi.evidence:
            w("        evidence: %s\n" % fi.evidence)
        for line in _wrap(fi.note, 68):
            w("        %s\n" % line)
    w("\n")


def _wrap(text, width):
    words = text.split()
    lines, cur = [], ""
    for word in words:
        if len(cur) + len(word) + 1 > width:
            lines.append(cur)
            cur = word
        else:
            cur = (cur + " " + word).strip()
    if cur:
        lines.append(cur)
    return lines


# --------------------------------------------------------------------------- #
# Input handling
# --------------------------------------------------------------------------- #

def read_inputs(paths, axmlmod, dexmod, forced_target):
    manifest = {"package": None, "target_sdk": forced_target, "min_sdk": None,
                "debuggable": False, "browsable": [], "uses_cleartext": None,
                "nsc_ref": None, "xml": None}
    dexes = []
    for path in paths:
        if not os.path.isfile(path):
            sys.stderr.write("error: no such file: %s\n" % path)
            return None, None
        with open(path, "rb") as fh:
            head = fh.read(8)
        if head[:4] == b"PK\x03\x04":
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                if "AndroidManifest.xml" in names and axmlmod is not None \
                        and manifest["package"] is None:
                    m = parse_manifest(z.read("AndroidManifest.xml"), axmlmod)
                    for k, v in m.items():
                        if v not in (None, [], False) or manifest.get(k) is None:
                            manifest[k] = v
                for n in sorted(names):
                    if re.fullmatch(r"classes\d*\.dex", n):
                        dexes.append((os.path.basename(path) + "!" + n, z.read(n)))
        elif head[:4] in (b"dex\n", b"dey\n"):
            with open(path, "rb") as fh:
                dexes.append((os.path.basename(path), fh.read()))
        else:
            sys.stderr.write("error: not an APK or DEX: %s\n" % path)
            return None, None
    if forced_target is not None:
        manifest["target_sdk"] = forced_target
    if manifest.get("target_sdk") is None:
        sys.stderr.write(
            "warning: targetSdkVersion unknown -- defaults cannot be computed.\n"
            "         Pass --target-sdk N. Assuming 30 for now.\n")
        manifest["target_sdk"] = 30
    return manifest, dexes


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit the WebView configuration an APK actually applies.")
    ap.add_argument("inputs", nargs="+", help="APK or DEX file(s)")
    ap.add_argument("--target-sdk", type=int, default=None,
                    help="override targetSdkVersion (required for a bare DEX)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--all", action="store_true",
                    help="print every tracked setting, not just the interesting rows")
    ap.add_argument("--fail-on", choices=sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get),
                    default=None, help="exit 1 if a finding at or above this severity exists")
    ap.add_argument("--dex-parser", default=os.environ.get("WEBVIEW_DEX_PARSER",
                                                           DEFAULT_DEX_PARSER))
    ap.add_argument("--parse-axml", default=os.environ.get("WEBVIEW_PARSE_AXML",
                                                           DEFAULT_PARSE_AXML))
    args = ap.parse_args(argv)

    dexmod = load_module(args.dex_parser, "ch12_dex_parser")
    if dexmod is None:
        sys.stderr.write(
            "error: could not load the DEX parser from\n    %s\n"
            "This script does not reimplement DEX parsing -- chapter 12 owns it.\n"
            "Point at it with --dex-parser or WEBVIEW_DEX_PARSER.\n" % args.dex_parser)
        return 2
    axmlmod = load_module(args.parse_axml, "ch10_parse_axml")
    if axmlmod is None:
        sys.stderr.write(
            "warning: could not load the AXML decoder from\n    %s\n"
            "Manifest facts (targetSdk, debuggable, BROWSABLE) will be missing.\n"
            "Pass --target-sdk N so defaults can still be computed.\n" % args.parse_axml)

    manifest, dexes = read_inputs(args.inputs, axmlmod, dexmod, args.target_sdk)
    if manifest is None:
        return 2
    if not dexes:
        sys.stderr.write("error: no DEX found in the input.\n")
        return 2

    scans = []
    for name, data in dexes:
        try:
            s = DexScan(data, dexmod, name)
            s.scan()
            scans.append(s)
        except Exception as exc:
            sys.stderr.write("warning: %s did not parse: %s\n" % (name, exc))

    if not scans:
        sys.stderr.write("error: no DEX parsed successfully.\n")
        return 2

    all_calls = [c for s in scans for c in s.setting_calls]
    eff = effective_settings(all_calls, manifest["target_sdk"])
    findings = build_findings(manifest, eff, scans)

    if args.json:
        bridges = {}
        for s in scans:
            for k, v in s.bridge_classes.items():
                bridges.setdefault(k, [])
                for x in v:
                    if x not in bridges[k]:
                        bridges[k].append(x)
        payload = {
            "target": args.inputs,
            "manifest": {k: v for k, v in manifest.items() if k != "xml"},
            "settings": {k: {kk: vv for kk, vv in v.items() if kk != "calls"}
                         for k, v in eff.items()},
            "setting_calls": all_calls,
            "bridges": bridges,
            "overrides": [o for s in scans for o in s.overrides],
            "webview_calls": [c for s in scans for c in s.webview_calls],
            "findings": [f.as_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2, default=str))
    else:
        report_text(", ".join(os.path.basename(p) for p in args.inputs),
                    manifest, eff, scans, findings, args.all)

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.sev, 0) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
