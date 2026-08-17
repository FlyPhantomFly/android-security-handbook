/*
 * trace-webview.js -- watch an app configure, load and defend (or not defend)
 *                     every WebView it creates, live.
 *
 * WHAT IT DOES
 *   ../scripts/webview-audit.py reads an APK and tells you what the code says.
 *   This tells you what the process does, which is the authority whenever the two
 *   disagree. It reports, as it happens:
 *
 *     SETTINGS    every WebSettings setter the app calls, with the value it
 *                 actually passed, tagged with the WebView instance it was
 *                 called on. Then, on demand, the FULL effective configuration
 *                 read back from each live WebSettings object -- including the
 *                 settings nobody set, whose values came from the targetSdk
 *                 default. That read-back is the part static analysis cannot do.
 *
 *     BRIDGES     every addJavascriptInterface(obj, name) call: the exposed
 *                 name, the Java class of the object, and -- resolved by
 *                 reflection at the moment of registration -- the exact list of
 *                 methods carrying @android.webkit.JavascriptInterface. That is
 *                 the API the page gets, enumerated for you before the page has
 *                 loaded.
 *
 *     LOADS       loadUrl, loadData, loadDataWithBaseURL, postUrl and
 *                 evaluateJavascript, with the argument. This is where an
 *                 attacker-controlled URL becomes visible: run the app's deep
 *                 link and watch your string arrive.
 *
 *     SSL         every onReceivedSslError override that is ENTERED, the
 *                 SslError it was handed (primary error code, failing URL,
 *                 certificate subject and issuer), and -- the answer everyone
 *                 actually wants -- whether the app called proceed() or
 *                 cancel(). Static analysis can see that proceed() exists in the
 *                 method; only this can tell you it ran.
 *
 *     DEBUG       setWebContentsDebuggingEnabled, with the value.
 *
 *   And on demand:
 *
 *     settings()  dump the live, effective configuration of every WebView seen.
 *     bridges()   re-list every registered bridge and its exposed methods.
 *     eval(js)    run JavaScript in the newest WebView, from the Frida REPL.
 *     forceCancel(true|false)
 *                 make every onReceivedSslError call cancel() instead of
 *                 proceed(). This is the CONTROL for a certificate finding: if
 *                 the page loads with tracing only and fails with forceCancel on,
 *                 you have proved that the app's proceed() is what made it load,
 *                 rather than the certificate having been acceptable all along.
 *
 * WHY THE HOOK POINTS ARE WHERE THEY ARE
 *   android.webkit.WebSettings is ABSTRACT. The object an app holds is really
 *   android.webkit.WebSettingsWrapper or, on modern WebView,
 *   com.android.webview.chromium.ContentSettingsAdapter, loaded from the WebView
 *   provider APK into the app process by a separate ClassLoader. Hooking
 *   "WebSettings" by name therefore hooks nothing useful on some devices and
 *   everything on others. This script hooks the abstract class where Java.use
 *   resolves it, and ALSO walks the concrete class of the first live settings
 *   object it sees and hooks that -- so it works either way, and prints which
 *   path fired.
 *
 *   onReceivedSslError is likewise not hookable as "WebViewClient": apps override
 *   it in their own subclasses, very often anonymous inner classes that are not
 *   loaded until the first navigation. So the script hooks
 *   WebView.setWebViewClient, reads the class name off the live object, and wraps
 *   that exact class on the spot. No guessing, no class sweep.
 *
 * WHAT THIS SCRIPT DELIBERATELY DOES NOT DO
 *   It does not bypass anything by default. Nothing is stubbed, forced or
 *   neutralised unless you call forceCancel(true) explicitly, and that direction
 *   is the SAFE one -- it makes the app stricter, not weaker. If you neutralise a
 *   check before measuring it, "the page loaded" stops being evidence of
 *   anything.
 *
 *   It does not touch the renderer. Everything here is in the browser process,
 *   which is the app's own process. The renderer is a separate, isolated process
 *   (see ../../21-App-Sandbox/README.md) and Frida attached to the app cannot see
 *   into it.
 *
 *   It cannot see native code driving a WebView through JNI, a WebView created
 *   before you attached (always spawn), or a Chrome Custom Tab -- a Custom Tab is
 *   a different process belonging to the browser, and none of these hooks exist
 *   in it.
 *
 *   It does not read the network security config. Chapter 44 owns that:
 *   ../../44-NetworkSecurityConfig/scripts/nsc-runtime.js.
 *
 * HOW TO RUN
 *   # host - make hooks land reliably. The JIT can inline a hot method out from
 *   # under you; forcing verify-only compilation stops that.
 *   adb shell cmd package compile -m verify -f com.example.app
 *
 *   # host - ALWAYS spawn. A WebView is usually configured in onCreate, and an
 *   # attach arrives after the settings you wanted to see were already applied.
 *   frida -U -f com.example.app -l trace-webview.js
 *
 *   # then, in the Frida REPL:
 *   [Device::app]-> settings()
 *   [Device::app]-> bridges()
 *   [Device::app]-> eval("Object.keys(window).join(',')")
 *   [Device::app]-> forceCancel(true)
 *
 *   # non-interactive capture
 *   frida -U -f com.example.app -l trace-webview.js -o trace.txt
 *
 * REQUIREMENTS
 *   frida-server running on the device, matching your host frida version.
 *   Verified against frida 16.1.6 on Android 11 / API 30, WebView 150.0.7871.181.
 *
 * AUTHORISED TESTING ONLY.
 */

'use strict';

// --------------------------------------------------------------------------- //
// Tunables
// --------------------------------------------------------------------------- //
var CFG = {
    stacks: false,        // print a Java stack trace for each bridge and SSL event
    maxArg: 400,          // truncate long URLs and script bodies at this length
    quietSettings: false  // suppress the per-call SETTINGS lines, keep the summary
};

var state = {
    webviews: [],         // live WebView instances, newest last
    settingsObjs: [],     // live WebSettings instances
    bridges: [],          // {name, cls, methods:[...]}
    clients: {},          // WebViewClient class name -> true, so we hook once
    seenSettings: [],     // identity keys, so each WebSettings is recorded once
    handlers: {},         // concrete SslErrorHandler class name -> true
    sslEvents: [],
    forceCancel: false,
    concreteHooked: false,
    provider: null
};

function log(tag, msg) {
    console.log('[' + tag + '] ' + msg);
}

function trunc(s) {
    if (s === null || s === undefined) { return String(s); }
    s = String(s);
    return s.length > CFG.maxArg ? s.substring(0, CFG.maxArg) + ' ...(' + s.length + ')' : s;
}

function stack() {
    if (!CFG.stacks) { return ''; }
    try {
        var Exception = Java.use('java.lang.Exception');
        var Log = Java.use('android.util.Log');
        return '\n' + Log.getStackTraceString(Exception.$new());
    } catch (e) {
        return '';
    }
}

function safeUse(name) {
    try {
        return Java.use(name);
    } catch (e) {
        return null;
    }
}

// --------------------------------------------------------------------------- //
// The settings we read back. Name -> getter. A missing getter is reported as
// "n/a" rather than guessed: getSafeBrowsingEnabled only exists from API 26, and
// several of these have no getter at all.
// --------------------------------------------------------------------------- //
var READBACK = [
    ['javaScriptEnabled',                    'getJavaScriptEnabled'],
    ['allowFileAccess',                      'getAllowFileAccess'],
    ['allowFileAccessFromFileURLs',          'getAllowFileAccessFromFileURLs'],
    ['allowUniversalAccessFromFileURLs',     'getAllowUniversalAccessFromFileURLs'],
    ['allowContentAccess',                   'getAllowContentAccess'],
    ['domStorageEnabled',                    'getDomStorageEnabled'],
    ['databaseEnabled',                      'getDatabaseEnabled'],
    ['mixedContentMode',                     'getMixedContentMode'],
    ['safeBrowsingEnabled',                  'getSafeBrowsingEnabled'],
    ['javaScriptCanOpenWindowsAutomatically', 'getJavaScriptCanOpenWindowsAutomatically'],
    ['mediaPlaybackRequiresUserGesture',     'getMediaPlaybackRequiresUserGesture'],
    ['cacheMode',                            'getCacheMode'],
    ['blockNetworkLoads',                    'getBlockNetworkLoads'],
    ['loadsImagesAutomatically',             'getLoadsImagesAutomatically'],
    ['userAgentString',                      'getUserAgentString']
];

// The boolean setters worth tracing, and the int ones.
var BOOL_SETTERS = [
    'setJavaScriptEnabled', 'setAllowFileAccess', 'setAllowFileAccessFromFileURLs',
    'setAllowUniversalAccessFromFileURLs', 'setAllowContentAccess',
    'setDomStorageEnabled', 'setDatabaseEnabled', 'setSafeBrowsingEnabled',
    'setJavaScriptCanOpenWindowsAutomatically', 'setMediaPlaybackRequiresUserGesture',
    'setBlockNetworkLoads', 'setLoadsImagesAutomatically', 'setGeolocationEnabled',
    'setSavePassword', 'setSaveFormData', 'setBuiltInZoomControls',
    'setSupportMultipleWindows', 'setUseWideViewPort'
];
var INT_SETTERS = ['setMixedContentMode', 'setCacheMode'];

var MIXED = {0: 'ALWAYS_ALLOW', 1: 'NEVER_ALLOW', 2: 'COMPATIBILITY_MODE'};

// SslError primary error codes, from android.net.http.SslError.
var SSL_ERR = {
    0: 'SSL_NOTYETVALID  - certificate is not yet valid',
    1: 'SSL_EXPIRED      - certificate has expired',
    2: 'SSL_IDMISMATCH   - hostname does not match the certificate',
    3: 'SSL_UNTRUSTED    - certificate authority is not trusted',
    4: 'SSL_DATE_INVALID - date is invalid',
    5: 'SSL_INVALID      - a generic error occurred'
};

// --------------------------------------------------------------------------- //

function hookSettersOn(clazz, label) {
    var hooked = 0;

    BOOL_SETTERS.forEach(function (name) {
        if (typeof clazz[name] === 'undefined') { return; }
        try {
            clazz[name].overload('boolean').implementation = function (v) {
                if (!CFG.quietSettings) {
                    log('SETTINGS', label + '.' + name + '(' + v + ')' + stack());
                }
                return this[name].overload('boolean').call(this, v);
            };
            hooked++;
        } catch (e) { /* not present on this platform build */ }
    });

    INT_SETTERS.forEach(function (name) {
        if (typeof clazz[name] === 'undefined') { return; }
        try {
            clazz[name].overload('int').implementation = function (v) {
                var extra = (name === 'setMixedContentMode' && MIXED[v]) ? ' /* ' + MIXED[v] + ' */' : '';
                if (!CFG.quietSettings) {
                    log('SETTINGS', label + '.' + name + '(' + v + ')' + extra + stack());
                }
                return this[name].overload('int').call(this, v);
            };
            hooked++;
        } catch (e) { /* ignore */ }
    });

    log('HOOK', 'settings setters hooked on ' + label + ': ' + hooked);
}

/**
 * Read every setting back off a live WebSettings object.
 *
 * This is the function that answers "what is this WebView ACTUALLY configured
 * to", including every value the app never set. A getter that throws or does not
 * exist prints n/a; nothing is inferred.
 */
function readback(s, idx) {
    var out = [];
    READBACK.forEach(function (pair) {
        var label = pair[0], getter = pair[1];
        var v;
        try {
            v = s[getter]();
            if (label === 'mixedContentMode' && MIXED[v] !== undefined) {
                v = v + ' (' + MIXED[v] + ')';
            }
        } catch (e) {
            v = 'n/a';
        }
        out.push('    ' + rpad(label, 38) + ' ' + trunc(v));
    });
    log('EFFECTIVE', 'WebSettings #' + idx + '  [' + s.$className + ']\n' + out.join('\n'));
}

function rpad(s, n) {
    s = String(s);
    while (s.length < n) { s += ' '; }
    return s;
}

/**
 * Report the installed WebView provider and its version, ONCE, and only after a
 * WebView exists.
 *
 * Calling WebView.getCurrentWebViewPackage() during early startup returns null or
 * throws, because the provider has not been loaded into the process yet -- which
 * is why the first version of this script printed "<unavailable>" every time.
 * Deferring it until the first getSettings() call is what makes it work.
 *
 * This number matters more than most people expect: WebView ships as a Mainline
 * module and updates through the Play Store, so the Chromium in an app is
 * unrelated to the Android version underneath it. Record both in every finding.
 */
function reportProvider() {
    if (state.provider !== null) { return; }
    try {
        var WV = Java.use('android.webkit.WebView');
        var pi = WV.getCurrentWebViewPackage();
        if (pi === null) { return; }
        state.provider = pi.packageName.value + ' ' + pi.versionName.value;
        log('PROVIDER', state.provider
            + '   (device is Android ' + Java.use('android.os.Build$VERSION').RELEASE.value
            + ' / API ' + Java.use('android.os.Build$VERSION').SDK_INT.value + ')'
            + '\n           The WebView version is NOT the OS version. Record both.');
    } catch (e) {
        /* still too early, or an OEM stub. Try again on the next WebView. */
    }
}

/**
 * Enumerate the methods of a bridge object that carry @JavascriptInterface.
 *
 * This is what the page sees. Doing it by reflection at registration time beats
 * reading the APK: it works through obfuscation, through dynamically loaded DEX,
 * and it tells you the ACTUAL object, not the declared type.
 */
function bridgeMethods(obj) {
    var names = [];
    try {
        var cls = Java.use('java.lang.Class');
        var jsAnn = Java.use('android.webkit.JavascriptInterface').class;
        var klass = Java.cast(obj.getClass(), cls);
        var methods = klass.getMethods();
        for (var i = 0; i < methods.length; i++) {
            try {
                if (methods[i].isAnnotationPresent(jsAnn)) {
                    names.push(methods[i].getName() + '(' + methods[i].getParameterTypes().length + ')');
                }
            } catch (e) { /* ignore one bad method */ }
        }
    } catch (e) {
        names.push('<reflection failed: ' + e + '>');
    }
    return names;
}

/**
 * Wrap the CONCRETE SslErrorHandler class, discovered from a live instance.
 *
 * This is what turns "the app has a proceed() in its bytecode" into "the app
 * called proceed(), on this navigation, for this certificate". It is also where
 * forceCancel() takes effect.
 */
function hookSslHandlerClass(handler) {
    var clsName = handler.$className;
    if (state.handlers[clsName]) { return; }
    state.handlers[clsName] = true;

    // Java.use searches the app's own ClassLoader. The concrete handler lives in
    // the WebView PROVIDER's APK, loaded by a different ClassLoader, and on this
    // device its obfuscated name is something like `WV.e53` -- so Java.use throws
    // ClassNotFoundException and the first version of this script printed
    // "could not resolve" and gave up. The fix is to build a ClassFactory bound
    // to the loader that actually defined the object.
    var H = safeUse(clsName);
    if (H === null) {
        try {
            var loader = handler.getClass().getClassLoader();
            H = Java.ClassFactory.get(loader).use(clsName);
            log('HOOK', 'resolved ' + clsName + ' through the WebView provider ClassLoader');
        } catch (e) {
            H = null;
        }
    }
    if (H === null) {
        log('WARN', 'could not resolve SslErrorHandler class ' + clsName
            + ' -- proceed/cancel will not be reported');
        return;
    }
    try {
        H.proceed.implementation = function () {
            state.sslEvents.push({action: 'proceed'});
            if (state.forceCancel) {
                log('SSL', '  --> app called handler.proceed(), '
                    + 'forceCancel is ON so cancel() is being sent instead');
                return this.cancel();
            }
            log('SSL', '  --> app called handler.proceed()   THE LOAD CONTINUES, '
                + 'certificate error and all');
            return this.proceed();
        };
        H.cancel.implementation = function () {
            state.sslEvents.push({action: 'cancel'});
            log('SSL', '  --> app called handler.cancel()    the load is refused');
            return this.cancel();
        };
        log('HOOK', 'SslErrorHandler concrete class hooked: ' + clsName);
    } catch (e) {
        log('WARN', 'could not hook ' + clsName + ': ' + e);
    }
}

/**
 * Wrap one concrete WebViewClient subclass. Called with the class NAME read off
 * a live object, so anonymous inner classes are handled without guessing.
 */
function hookClientClass(clsName) {
    if (state.clients[clsName]) { return; }
    state.clients[clsName] = true;

    var C = safeUse(clsName);
    if (C === null) {
        log('WARN', 'could not resolve WebViewClient class ' + clsName);
        return;
    }

    var hooked = [];

    // The one that matters.
    try {
        C.onReceivedSslError.implementation = function (view, handler, error) {
            var info = [];
            var primary = -1;
            try {
                primary = error.getPrimaryError();
                info.push('primaryError=' + primary + '  ' + (SSL_ERR[primary] || '?'));
                info.push('url=' + trunc(error.getUrl()));
                var cert = error.getCertificate();
                if (cert !== null) {
                    info.push('subject=' + cert.getIssuedTo().getDName());
                    info.push('issuer=' + cert.getIssuedBy().getDName());
                    info.push('validNotAfter=' + cert.getValidNotAfterDate());
                }
            } catch (e) {
                info.push('<could not read SslError: ' + e + '>');
            }

            // Wrap the handler so we learn what the app DID, not what it could do.
            //
            // android.webkit.SslErrorHandler is ABSTRACT. Hooking it by name
            // hooks nothing, because the object the framework passes is a
            // concrete subclass supplied by the WebView provider -- on this
            // device com.android.webview.chromium.WebViewContentsClientAdapter's
            // inner handler class, loaded from a different ClassLoader. So read
            // the class name off the live object and hook THAT, once.
            hookSslHandlerClass(handler);

            log('SSL', 'onReceivedSslError in ' + clsName + '\n    ' + info.join('\n    ') + stack());
            return this.onReceivedSslError(view, handler, error);
        };
        hooked.push('onReceivedSslError');
    } catch (e) { /* class does not override it: good news */ }

    try {
        C.shouldOverrideUrlLoading.overload(
            'android.webkit.WebView', 'android.webkit.WebResourceRequest'
        ).implementation = function (view, req) {
            var r = this.shouldOverrideUrlLoading(view, req);
            log('NAV', 'shouldOverrideUrlLoading(' + trunc(req.getUrl().toString()) + ') -> ' + r
                + (r ? '   [BLOCKED or handled by the app]' : '   [allowed to load]'));
            return r;
        };
        hooked.push('shouldOverrideUrlLoading(request)');
    } catch (e) { /* ignore */ }

    try {
        C.shouldOverrideUrlLoading.overload(
            'android.webkit.WebView', 'java.lang.String'
        ).implementation = function (view, url) {
            var r = this.shouldOverrideUrlLoading(view, url);
            log('NAV', 'shouldOverrideUrlLoading("' + trunc(url) + '") -> ' + r);
            return r;
        };
        hooked.push('shouldOverrideUrlLoading(String)');
    } catch (e) { /* ignore */ }

    try {
        C.shouldInterceptRequest.overload(
            'android.webkit.WebView', 'android.webkit.WebResourceRequest'
        ).implementation = function (view, req) {
            var r = this.shouldInterceptRequest(view, req);
            log('NAV', 'shouldInterceptRequest(' + trunc(req.getUrl().toString()) + ') -> '
                + (r === null ? 'null [fetch normally]' : 'a WebResourceResponse [intercepted]'));
            return r;
        };
        hooked.push('shouldInterceptRequest');
    } catch (e) { /* ignore */ }

    try {
        C.onReceivedClientCertRequest.implementation = function (view, req) {
            log('SSL', 'onReceivedClientCertRequest for ' + req.getHost() + ':' + req.getPort()
                + ' -- the server is asking this app for a client certificate' + stack());
            return this.onReceivedClientCertRequest(view, req);
        };
        hooked.push('onReceivedClientCertRequest');
    } catch (e) { /* ignore */ }

    log('HOOK', 'WebViewClient ' + clsName + ' -- overrides hooked: '
        + (hooked.length ? hooked.join(', ') : 'none of interest'));
}

// --------------------------------------------------------------------------- //

Java.perform(function () {

    // ---- WebSettings: the abstract class ---------------------------------- //
    var WebSettings = safeUse('android.webkit.WebSettings');
    if (WebSettings !== null) {
        hookSettersOn(WebSettings, 'WebSettings');
    } else {
        log('WARN', 'android.webkit.WebSettings did not resolve');
    }

    // ---- WebView ----------------------------------------------------------- //
    var WebView = safeUse('android.webkit.WebView');
    if (WebView === null) {
        log('ERROR', 'android.webkit.WebView did not resolve. Is this really an Android app?');
        return;
    }

    // getSettings: remember the object AND hook its concrete class the first
    // time we see one. On modern WebView the concrete class lives in the
    // provider APK's ClassLoader, so this is the path that actually fires.
    WebView.getSettings.implementation = function () {
        var s = this.getSettings();
        var cls = s.$className;
        if (state.seenSettings.indexOf(cls + '@' + s.hashCode()) === -1) {
            state.seenSettings.push(cls + '@' + s.hashCode());

            // Java.retain is not optional here. A wrapper obtained inside a hook
            // is only valid for that JNI frame; keeping the bare reference and
            // calling a getter later fails with "expected a pointer", which is
            // exactly what the first version of this script did.
            state.settingsObjs.push(Java.retain(s));

            log('WEBVIEW', 'getSettings() #' + (state.settingsObjs.length - 1) + ' -> ' + cls);

            if (!state.concreteHooked && cls !== 'android.webkit.WebSettings') {
                state.concreteHooked = true;
                var concrete = safeUse(cls);
                if (concrete !== null) {
                    hookSettersOn(concrete, cls.split('.').pop());
                }
            }
            reportProvider();
        }
        return s;
    };

    WebView.setWebViewClient.implementation = function (client) {
        if (client !== null) {
            log('WEBVIEW', 'setWebViewClient(' + client.$className + ')');
            hookClientClass(client.$className);
        }
        return this.setWebViewClient(client);
    };

    WebView.addJavascriptInterface.implementation = function (obj, name) {
        var cls = (obj === null) ? 'null' : obj.$className;
        var methods = (obj === null) ? [] : bridgeMethods(obj);
        state.bridges.push({name: name, cls: cls, methods: methods});
        log('BRIDGE', 'addJavascriptInterface(' + cls + ', "' + name + '")\n'
            + '    exposed to page script as window.' + name + '\n'
            + '    @JavascriptInterface methods (' + methods.length + '): '
            + (methods.length ? methods.join(', ') : 'NONE -- this bridge is inert')
            + stack());
        return this.addJavascriptInterface(obj, name);
    };

    WebView.setWebContentsDebuggingEnabled.implementation = function (v) {
        log('DEBUG', 'setWebContentsDebuggingEnabled(' + v + ')'
            + (v ? '   -> an abstract socket @webview_devtools_remote_<pid> is now open;'
                 + ' check with: adb shell cat /proc/net/unix | grep devtools' : '')
            + stack());
        return this.setWebContentsDebuggingEnabled(v);
    };

    ['loadUrl', 'loadData', 'loadDataWithBaseURL', 'postUrl', 'evaluateJavascript']
        .forEach(function (name) {
            if (typeof WebView[name] === 'undefined') { return; }
            WebView[name].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var args = [];
                    for (var i = 0; i < arguments.length; i++) {
                        args.push(trunc(arguments[i]));
                    }
                    // Retained, for the same JNI-frame reason as WebSettings
                    // above -- eval() calls into this object much later.
                    state.webviews.push(Java.retain(this));
                    if (state.webviews.length > 8) { state.webviews.shift(); }
                    log('LOAD', name + '(' + args.join(', ') + ')' + stack());
                    return ov.apply(this, arguments);
                };
            });
        });

    // WebChromeClient carries the permission prompts and the console. Hooking
    // the base class catches apps that use the default and misses nothing an
    // override does, because an override calls through or replaces it entirely
    // -- either way the app's own class is caught by setWebChromeClient below.
    WebView.setWebChromeClient.implementation = function (client) {
        if (client !== null) {
            log('WEBVIEW', 'setWebChromeClient(' + client.$className + ')');
            var C = safeUse(client.$className);
            if (C !== null) {
                try {
                    C.onPermissionRequest.implementation = function (req) {
                        var res = req.getResources();
                        var list = [];
                        for (var i = 0; i < res.length; i++) { list.push(res[i]); }
                        log('PERM', 'onPermissionRequest from ' + req.getOrigin()
                            + ' for [' + list.join(', ') + ']'
                            + '  -- a WEB PAGE is asking for a device capability' + stack());
                        return this.onPermissionRequest(req);
                    };
                } catch (e) { /* not overridden */ }
                try {
                    C.onConsoleMessage.overload('android.webkit.ConsoleMessage')
                        .implementation = function (m) {
                        log('CONSOLE', m.sourceId() + ':' + m.lineNumber() + '  ' + m.message());
                        return this.onConsoleMessage(m);
                    };
                } catch (e) { /* not overridden */ }
            }
        }
        return this.setWebChromeClient(client);
    };

    log('READY',
        'tracing. Exercise the app, then call settings() / bridges() / verdict().\n'
        + '        The WebView provider and version are printed as soon as the first\n'
        + '        WebView exists -- asking earlier returns nothing, because the\n'
        + '        provider APK has not been loaded into this process yet.');
});

// --------------------------------------------------------------------------- //
// REPL exports
// --------------------------------------------------------------------------- //

rpc.exports = {

    /** Dump the live, effective configuration of every WebSettings seen. */
    settings: function () {
        Java.perform(function () {
            if (state.settingsObjs.length === 0) {
                log('EFFECTIVE', 'no WebSettings object has been created yet. '
                    + 'Navigate to a screen with a WebView first.');
                return;
            }
            state.settingsObjs.forEach(function (s, i) { readback(s, i); });
        });
        return 'ok';
    },

    /** Re-list every registered bridge and the methods the page can call. */
    bridges: function () {
        if (state.bridges.length === 0) {
            log('BRIDGE', 'no addJavascriptInterface call has been made.');
            return 'none';
        }
        state.bridges.forEach(function (b) {
            log('BRIDGE', 'window.' + b.name + '  <- ' + b.cls + '\n    '
                + (b.methods.length ? b.methods.join('\n    ') : 'NONE (inert)'));
        });
        return state.bridges.length + ' bridge(s)';
    },

    /**
     * Evaluate JavaScript in the most recently loaded WebView.
     *
     * This is the fastest way to confirm a bridge is genuinely reachable:
     *     eval("Object.keys(window.AndroidBridge).join(',')")
     * It must run on the UI thread, which is why it goes through
     * Java.scheduleOnMainThread.
     */
    eval: function (js) {
        if (state.webviews.length === 0) {
            return 'no WebView seen yet';
        }
        var wv = state.webviews[state.webviews.length - 1];
        Java.scheduleOnMainThread(function () {
            Java.perform(function () {
                try {
                    wv.evaluateJavascript(js, null);
                    log('EVAL', 'dispatched: ' + trunc(js));
                } catch (e) {
                    log('EVAL', 'failed: ' + e);
                }
            });
        });
        return 'dispatched (result appears in the page, not here -- use a bridge or console to return it)';
    },

    /**
     * Turn every proceed() into a cancel().
     *
     * This is a CONTROL, not a bypass. Run the same navigation twice: once
     * tracing only, once with this on. If the page loads the first time and
     * fails the second, the app's proceed() is what made it load, and the
     * certificate was never acceptable. Without that pair you are guessing.
     */
    forceCancel: function (on) {
        state.forceCancel = !!on;
        log('SSL', 'forceCancel is now ' + (state.forceCancel ? 'ON' : 'OFF'));
        return state.forceCancel;
    },

    /** Turn Java stack traces on or off for bridge, SSL and load events. */
    stacks: function (on) {
        CFG.stacks = !!on;
        return CFG.stacks;
    },

    /** A one-line verdict for a report. */
    verdict: function () {
        var lines = [];
        lines.push('WebSettings objects seen : ' + state.settingsObjs.length);
        lines.push('bridges registered       : ' + state.bridges.length
            + ' (' + state.bridges.reduce(function (a, b) { return a + b.methods.length; }, 0)
            + ' exposed methods)');
        lines.push('WebViewClient classes    : ' + Object.keys(state.clients).join(', '));
        var proceeds = state.sslEvents.filter(function (e) { return e.action === 'proceed'; }).length;
        var cancels = state.sslEvents.filter(function (e) { return e.action === 'cancel'; }).length;
        lines.push('SSL error decisions      : proceed=' + proceeds + '  cancel=' + cancels);
        if (proceeds > 0) {
            lines.push('  >>> this app accepted at least one INVALID CERTIFICATE at runtime.');
            lines.push('  >>> No network security config can prevent that. Capture the traffic.');
        }
        log('VERDICT', '\n  ' + lines.join('\n  '));
        return 'ok';
    }
};
