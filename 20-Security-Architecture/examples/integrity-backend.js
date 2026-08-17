/*
 * integrity-backend.js
 * ===========================================================================
 * THE RIGHT WAY -- server half. Runnable, dependency-free, offline.
 *
 * PURPOSE
 *   Chapter 20's central claim is that a device-integrity verdict only means
 *   something when a party the attacker does not control produces it and a
 *   party the attacker does not control verifies it. That claim is easy to
 *   state and easy to nod along to. This file makes it something you can run.
 *
 *   It is the counterpart to ServerVerifiedGate.kt, and the thing
 *   labs/lab-04-ctf-the-lying-phone.md asks you to stand up at the end, after
 *   you have forged your way past three locally-evaluated checks, so that you
 *   can watch the same forgery fail against a correct implementation and
 *   understand exactly which line stops it.
 *
 * THE THREE ROLES, KEPT SEPARATE ON PURPOSE
 *   provider  -- stands in for Google. Holds an Ed25519 PRIVATE key, observes
 *                the device, and signs a verdict. In reality this is Play
 *                services plus Google's servers; the private key has never
 *                been on your device and never will be.
 *   client    -- your app. Holds NOTHING. Receives a nonce, receives an opaque
 *                token, forwards both. Cannot mint, cannot alter, cannot read.
 *   backend   -- you. Holds the provider's PUBLIC key, the nonce store, and
 *                the protected payload. Makes the decision.
 *
 *   Run `mint` and `serve` in two terminals and the separation becomes
 *   physical: the terminal running `serve` never sees the private key.
 *
 * USAGE
 *   # host -- one-time: create the provider keypair
 *   node integrity-backend.js keygen
 *
 *   # host -- terminal 1: the backend (nonce issuer + verifier + asset holder)
 *   node integrity-backend.js serve --port 8099
 *
 *   # host -- terminal 2: play the client
 *   curl -s -XPOST localhost:8099/v1/nonce \
 *        -H 'content-type: application/json' \
 *        -d '{"sessionId":"s-1","operation":"vault.unlock"}'
 *
 *   # host -- terminal 3: play GOOGLE, not the client. Needs the private key.
 *   node integrity-backend.js mint --nonce <NONCE> --package com.archlab.gate \
 *        --verdict MEETS_DEVICE_INTEGRITY
 *
 *   # host -- back to the client: submit the token
 *   curl -s -XPOST localhost:8099/v1/authorise \
 *        -H 'content-type: application/json' \
 *        -d '{"sessionId":"s-1","operation":"vault.unlock","token":"<TOKEN>"}'
 *
 * REQUIREMENTS
 *   Node 16 or newer (uses node:crypto Ed25519 and the modern http API).
 *   No npm install. Writes provider-key.json in the working directory --
 *   run it from a scratch directory, not from inside the repository.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - It is not a Play Integrity implementation. A real token is produced and
 *     encrypted by Google and decoded by the server-to-server
 *     `playintegrity.googleapis.com/v1/{pkg}:decodeIntegrityToken` call, whose
 *     place is marked below. The Ed25519 stand-in exists so the lab runs
 *     offline; it models the *trust structure*, not the wire format.
 *   - Passing every check here does not mean the device is honest. It means
 *     the statement about the device came from the provider, was bound to a
 *     request you issued, and is recent. That is all any attestation ever
 *     claims, and reading this file is the fastest way to internalise it.
 *   - It says nothing about your transport. Without TLS and certificate
 *     validation on the client, none of this survives a network attacker.
 *   - It is a teaching artefact: the nonce store is in memory, the payload is
 *     a string constant, and there is no authentication of the session id.
 *     Do not deploy it.
 * ===========================================================================
 */

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');

const KEYFILE = 'provider-key.json';
const EXPECTED_PACKAGE = 'com.archlab.gate';
const MAX_TOKEN_AGE_MS = 5 * 60 * 1000;
const NONCE_TTL_MS = 5 * 60 * 1000;

// Policy, per operation. A browse action and a money movement do not deserve
// the same bar, and a single global boolean is how teams end up either
// blocking legitimate users or protecting nothing.
const POLICY = {
    'vault.unlock': {
        accept: ['MEETS_DEVICE_INTEGRITY', 'MEETS_STRONG_INTEGRITY'],
        stepUpOn: ['MEETS_BASIC_INTEGRITY'],
        payload: 'ARCHLAB{the_secret_was_never_on_your_device}'
    },
    'account.view': {
        accept: ['MEETS_BASIC_INTEGRITY', 'MEETS_DEVICE_INTEGRITY',
                 'MEETS_STRONG_INTEGRITY'],
        stepUpOn: [],
        payload: 'balance: 1,204.55'
    }
};

// ---------------------------------------------------------------------------
// base64url
// ---------------------------------------------------------------------------

function b64u(buf) {
    return Buffer.from(buf).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64u(str) {
    return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

// ---------------------------------------------------------------------------
// Provider keypair. The private half is the whole point: the client never has
// it, so the client can never mint a verdict about itself.
// ---------------------------------------------------------------------------

function keygen() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const out = {
        note: 'Stands in for Google. Keep `private` away from the device.',
        public: publicKey.export({ type: 'spki', format: 'pem' }),
        private: privateKey.export({ type: 'pkcs8', format: 'pem' })
    };
    fs.writeFileSync(KEYFILE, JSON.stringify(out, null, 2));
    console.log('wrote ' + KEYFILE);
    console.log('\n--- public key (this is what the BACKEND holds) ---');
    console.log(out.public);
    console.log('The private half is what Google holds. In lab 04, the moment');
    console.log('you find yourself needing it is the moment you have found the');
    console.log('answer to the closing question.');
}

function loadKeys() {
    if (!fs.existsSync(KEYFILE)) {
        console.error('no ' + KEYFILE + ' -- run: node integrity-backend.js keygen');
        process.exit(1);
    }
    return JSON.parse(fs.readFileSync(KEYFILE, 'utf8'));
}

// ---------------------------------------------------------------------------
// `mint` -- the provider's job, NOT the client's and NOT the backend's.
// ---------------------------------------------------------------------------

function mint(args) {
    const keys = loadKeys();
    const nonce = args.nonce;
    if (!nonce) {
        console.error('--nonce is required (get one from POST /v1/nonce)');
        process.exit(1);
    }
    const header = { alg: 'EdDSA', typ: 'JWT' };
    const payload = {
        requestDetails: {
            requestPackageName: args.package || EXPECTED_PACKAGE,
            timestampMillis: Number(args.timestamp || Date.now()),
            nonce: nonce
        },
        deviceIntegrity: {
            deviceRecognitionVerdict: args.verdict ? [args.verdict] : []
        },
        appIntegrity: { appRecognitionVerdict: 'PLAY_RECOGNIZED' },
        accountDetails: { appLicensingVerdict: 'LICENSED' }
    };
    const signingInput = b64u(JSON.stringify(header)) + '.' +
                         b64u(JSON.stringify(payload));
    const sig = crypto.sign(null, Buffer.from(signingInput, 'ascii'),
                            crypto.createPrivateKey(keys.private));
    console.log(signingInput + '.' + b64u(sig));
}

// ---------------------------------------------------------------------------
// The nonce store. Single-use is enforced by DELETING on read.
// ---------------------------------------------------------------------------

const nonces = new Map();

function issueNonce(sessionId, operation) {
    const nonce = b64u(crypto.randomBytes(32));
    nonces.set(nonce, {
        sessionId: sessionId,
        operation: operation,
        expiresAt: Date.now() + NONCE_TTL_MS
    });
    return nonce;
}

function consumeNonce(nonce) {
    const rec = nonces.get(nonce);
    if (rec === undefined) {
        return null;
    }
    nonces.delete(nonce);   // <- this line is the anti-replay control
    return rec;
}

// ---------------------------------------------------------------------------
// Verification. Six checks, in this order, no exceptions.
// ---------------------------------------------------------------------------

function decodeIntegrityToken(token, publicKeyPem) {
    /*
     * In production this function is replaced by a server-to-server call:
     *
     *   POST https://playintegrity.googleapis.com/v1/{packageName}:decodeIntegrityToken
     *        Authorization: Bearer <service account token>
     *        { "integrityToken": "<token>" }
     *
     * Note what that call is: your server asking Google to decrypt something
     * your server cannot decrypt alone. Google also offers on-device
     * "classic" decryption with keys you hold. Do not use it for security
     * decisions -- it moves the verification back inside the attacker's
     * process, which is the entire mistake this file exists to avoid.
     */
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('malformed token: expected 3 parts, got ' + parts.length);
    }
    const header = JSON.parse(unb64u(parts[0]).toString('utf8'));
    if (header.alg !== 'EdDSA') {
        // "none", "HS256" with a key from the APK, or an unexpected algorithm:
        // all of these are attacks. Refuse; never negotiate down.
        throw new Error('unacceptable alg: ' + header.alg);
    }
    const ok = crypto.verify(
        null,
        Buffer.from(parts[0] + '.' + parts[1], 'ascii'),
        crypto.createPublicKey(publicKeyPem),
        unb64u(parts[2]));
    if (!ok) {
        throw new Error('signature does not verify against the provider key');
    }
    return JSON.parse(unb64u(parts[1]).toString('utf8'));
}

function authorise(body, publicKeyPem) {
    const checks = [];
    const add = (name, ok, detail) => {
        checks.push({ name: name, ok: ok, detail: detail });
        return ok;
    };

    const policy = POLICY[body.operation];
    if (!policy) {
        return { decision: 'DENY', reason: 'unknown operation', checks: checks };
    }

    // 1 + 2. Parse and verify the signature BEFORE reading any claim.
    let decoded;
    try {
        decoded = decodeIntegrityToken(body.token || '', publicKeyPem);
        add('signature', true, 'EdDSA verified against provider public key');
    } catch (e) {
        add('signature', false, e.message);
        return { decision: 'DENY', reason: e.message, checks: checks };
    }

    const req = decoded.requestDetails || {};

    // 3. Package binding. Omit this and a token minted for ANY other app --
    //    including one the attacker publishes themselves -- is accepted here.
    add('packageBinding', req.requestPackageName === EXPECTED_PACKAGE,
        'requestPackageName=' + req.requestPackageName);

    // 4. Freshness. Omit this and one token from one clean device is a
    //    permanent skeleton key.
    const age = Date.now() - Number(req.timestampMillis || 0);
    add('freshness', age >= 0 && age <= MAX_TOKEN_AGE_MS,
        'age ' + Math.round(age / 1000) + 's');

    // 5. Nonce: ours, for this session and operation, unused, unexpired.
    const rec = consumeNonce(req.nonce);
    if (rec === null) {
        add('nonce', false, 'unknown or already consumed');
    } else {
        add('nonce',
            rec.sessionId === body.sessionId &&
            rec.operation === body.operation &&
            Date.now() < rec.expiresAt,
            'bound to session=' + rec.sessionId + ' operation=' + rec.operation);
    }

    if (checks.some(c => !c.ok)) {
        return {
            decision: 'DENY',
            reason: checks.filter(c => !c.ok).map(c => c.name).join(','),
            checks: checks
        };
    }

    // 6. Only now does the verdict mean anything.
    const verdicts = (decoded.deviceIntegrity || {}).deviceRecognitionVerdict || [];
    const accepted = verdicts.some(v => policy.accept.includes(v));
    const stepUp = verdicts.some(v => policy.stepUpOn.includes(v));
    add('deviceVerdict', accepted || stepUp,
        'verdicts=[' + verdicts.join(',') + ']');

    // The evidence the client sent is recorded, never trusted. It is useful
    // for fraud analytics and for support, and it is worth logging the cases
    // where it disagrees with the token -- that disagreement is itself signal.
    const evidence = body.evidence || {};
    const disagreement =
        evidence.verifiedBootState === 'green' && verdicts.length === 0;

    if (accepted) {
        return {
            decision: 'ALLOW',
            payload: policy.payload,          // <- the asset lives HERE
            checks: checks,
            note: disagreement
                ? 'client-reported evidence disagrees with the attested verdict'
                : undefined
        };
    }
    if (stepUp) {
        return {
            decision: 'STEP_UP',
            challenge: b64u(crypto.randomBytes(16)),
            reason: 'device integrity below the bar for this operation',
            checks: checks
        };
    }
    return {
        decision: 'DENY',
        reason: 'device verdict not acceptable for ' + body.operation,
        checks: checks
    };
}

// ---------------------------------------------------------------------------
// HTTP surface
// ---------------------------------------------------------------------------

function readJson(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', c => {
            data += c;
            if (data.length > 64 * 1024) {
                reject(new Error('body too large'));
                req.destroy();
            }
        });
        req.on('end', () => {
            try {
                resolve(data ? JSON.parse(data) : {});
            } catch (e) {
                reject(e);
            }
        });
        req.on('error', reject);
    });
}

function serve(args) {
    const keys = loadKeys();
    const port = Number(args.port || 8099);

    const server = http.createServer(async (req, res) => {
        const send = (code, obj) => {
            const body = JSON.stringify(obj, null, 2);
            res.writeHead(code, { 'content-type': 'application/json' });
            res.end(body);
            console.log('%s %s -> %d %s', req.method, req.url, code,
                        obj.decision || '');
        };
        try {
            if (req.method === 'GET' && req.url === '/v1/provider-key') {
                // The backend publishes only the PUBLIC key. If your design
                // ever needs the client to hold a verification key, ask why
                // the client is verifying anything.
                return send(200, { publicKey: keys.public });
            }
            if (req.method === 'POST' && req.url === '/v1/nonce') {
                const b = await readJson(req);
                if (!b.sessionId || !b.operation) {
                    return send(400, { error: 'sessionId and operation required' });
                }
                return send(200, { nonce: issueNonce(b.sessionId, b.operation) });
            }
            if (req.method === 'POST' && req.url === '/v1/authorise') {
                const b = await readJson(req);
                const result = authorise(b, keys.public);
                return send(result.decision === 'ALLOW' ? 200 : 403, result);
            }
            return send(404, { error: 'no such endpoint' });
        } catch (e) {
            return send(400, { error: String(e && e.message ? e.message : e) });
        }
    });

    server.listen(port, '127.0.0.1', () => {
        console.log('backend on http://127.0.0.1:' + port);
        console.log('  POST /v1/nonce      {sessionId, operation}');
        console.log('  POST /v1/authorise  {sessionId, operation, token, evidence}');
        console.log('  GET  /v1/provider-key');
        console.log('\nThis process holds the public key and the payload.');
        console.log('It does NOT hold the signing key, and neither does the app.');
    });
}

// ---------------------------------------------------------------------------

function parseArgs(argv) {
    const out = {};
    for (let i = 0; i < argv.length; i++) {
        if (argv[i].startsWith('--')) {
            const k = argv[i].slice(2);
            const v = (i + 1 < argv.length && !argv[i + 1].startsWith('--'))
                ? argv[++i] : 'true';
            out[k] = v;
        }
    }
    return out;
}

function main() {
    const mode = process.argv[2];
    const args = parseArgs(process.argv.slice(3));
    if (mode === 'keygen') {
        return keygen();
    }
    if (mode === 'mint') {
        return mint(args);
    }
    if (mode === 'serve') {
        return serve(args);
    }
    console.error('usage: node integrity-backend.js <keygen|serve|mint> [--flags]');
    console.error('see the header comment for the full walkthrough');
    process.exit(1);
}

main();
