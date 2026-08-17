#!/usr/bin/env bash
# 36-CertificatePinning/scripts/spki-pin.sh
#
# PURPOSE
#   Compute the pin value for a host or a certificate, in the exact format
#   OkHttp's CertificatePinner and Android's <pin-set> both expect:
#
#       sha256/<base64 of SHA-256 over the DER SubjectPublicKeyInfo>
#
#   And -- the part every other one-liner on the internet leaves out -- print
#   the pin for EVERY certificate in the chain, labelled leaf / intermediate /
#   root, so you can see what you are choosing between. Choosing the wrong one
#   is the difference between a pin that survives certificate renewal and a pin
#   that takes your app offline on renewal day.
#
#   Read section 3.4 of ../README.md before choosing. In one line: the leaf
#   changes at every renewal, the intermediate changes when the CA rotates its
#   issuing CA (years, but it happens and it happens without telling you), and
#   the root changes almost never but pins you to a CA rather than to yourself.
#
# USAGE
#   # every pin in the chain for a live host
#   ./spki-pin.sh --host api.example.com
#   ./spki-pin.sh --host api.example.com --port 8443 --sni api.example.com
#
#   # a certificate you already have
#   ./spki-pin.sh --cert leaf.pem
#
#   # a private key or a CSR you are about to have signed -- this is how you
#   # generate the BACKUP pin for a key that has never been used yet
#   ./spki-pin.sh --key backup.key
#   ./spki-pin.sh --csr backup.csr
#
#   # emit ready-to-paste config
#   ./spki-pin.sh --host api.example.com --emit okhttp
#   ./spki-pin.sh --host api.example.com --emit nsc
#
# REQUIREMENTS
#   bash, openssl (1.1.1 or 3.x), and `base64`. On Windows use Git Bash or WSL.
#   --host additionally needs outbound network access to the host.
#
# WHAT THIS WILL NOT TELL YOU
#   * Whether the app you are testing actually pins any of these values. It
#     computes what a pin WOULD be; use ../scripts/pinning-surface.py to find
#     configured pins and ../scripts/pin-attribution.js to see one enforced.
#   * Whether the server will still present this chain tomorrow. Large sites
#     serve different chains from different edges and rotate leaves weekly.
#     Run this from more than one network before pinning a leaf.
#   * Which pin is "correct". That is an availability decision about your own
#     PKI, not a security one, and the script deliberately refuses to guess.
#   * Anything about a chain the server does not send. A cross-signed root that
#     the client supplies from its own store will not appear here.
#   * It cannot see certificate transparency, OCSP, or revocation state.
#
# NEVER commit the private key you pass to --key. This script only reads it.

set -u

HOST=""; PORT=443; SNI=""; CERT=""; KEY=""; CSR=""; EMIT=""

die() { echo "error: $*" >&2; exit 1; }

usage() {
    sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --host)  HOST="${2:-}"; shift 2 ;;
        --port)  PORT="${2:-}"; shift 2 ;;
        --sni)   SNI="${2:-}";  shift 2 ;;
        --cert)  CERT="${2:-}"; shift 2 ;;
        --key)   KEY="${2:-}";  shift 2 ;;
        --csr)   CSR="${2:-}";  shift 2 ;;
        --emit)  EMIT="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

command -v openssl >/dev/null 2>&1 || die "openssl not found on PATH"

[ -n "$HOST$CERT$KEY$CSR" ] || usage
[ -n "$SNI" ] || SNI="$HOST"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------------------
# The pin, in one function.
#
# `openssl x509 -pubkey -noout` prints the SubjectPublicKeyInfo in PEM. Piping
# that through `openssl pkey -pubin -outform der` gives the DER bytes of the
# SPKI structure -- algorithm identifier plus BIT STRING. SHA-256 of exactly
# those bytes, base64 encoded, is the pin.
#
# Two traps that produce a plausible-looking WRONG pin:
#   1. Hashing the certificate instead of the SPKI. `openssl x509 -fingerprint
#      -sha256` gives the certificate fingerprint. It is a valid thing to pin,
#      but it is NOT what `sha256/` means to OkHttp, and it does not survive
#      renewal.
#   2. Forgetting -noout, so the certificate PEM is included in the input.
# ---------------------------------------------------------------------------
pin_from_cert_file() {
    openssl x509 -in "$1" -pubkey -noout 2>/dev/null \
        | openssl pkey -pubin -outform der 2>/dev/null \
        | openssl dgst -sha256 -binary 2>/dev/null \
        | base64
}

pin_from_privkey_file() {
    # A backup pin is computed from a key that has never signed anything. This
    # is the whole trick: you generate the key now, pin it now, and keep it
    # offline until you need it.
    openssl pkey -in "$1" -pubout -outform der 2>/dev/null \
        | openssl dgst -sha256 -binary 2>/dev/null \
        | base64
}

pin_from_csr_file() {
    openssl req -in "$1" -pubkey -noout 2>/dev/null \
        | openssl pkey -pubin -outform der 2>/dev/null \
        | openssl dgst -sha256 -binary 2>/dev/null \
        | base64
}

cert_line() {
    local f="$1"
    local subj issuer notafter keyalg
    subj=$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed 's/^subject= *//')
    issuer=$(openssl x509 -in "$f" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')
    notafter=$(openssl x509 -in "$f" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    keyalg=$(openssl x509 -in "$f" -noout -text 2>/dev/null \
             | sed -n 's/.*Public Key Algorithm: *//p' | head -1)
    echo "        subject : $subj"
    echo "        issuer  : $issuer"
    echo "        expires : $notafter"
    echo "        key alg : ${keyalg:-unknown}"
}

PINS=()
LABELS=()

# ------------------------------------------------------------------ --cert
if [ -n "$CERT" ]; then
    [ -f "$CERT" ] || die "no such file: $CERT"
    P=$(pin_from_cert_file "$CERT")
    [ -n "$P" ] || die "could not parse $CERT as a PEM certificate"
    echo ""
    echo "certificate: $CERT"
    cert_line "$CERT"
    echo "        PIN     : sha256/$P"
    PINS+=("$P"); LABELS+=("cert:$CERT")
fi

# ------------------------------------------------------------------- --key
if [ -n "$KEY" ]; then
    [ -f "$KEY" ] || die "no such file: $KEY"
    P=$(pin_from_privkey_file "$KEY")
    [ -n "$P" ] || die "could not derive a public key from $KEY"
    echo ""
    echo "private key: $KEY   (backup pin -- key need never have been used)"
    echo "        PIN     : sha256/$P"
    PINS+=("$P"); LABELS+=("backup-key")
fi

# ------------------------------------------------------------------- --csr
if [ -n "$CSR" ]; then
    [ -f "$CSR" ] || die "no such file: $CSR"
    P=$(pin_from_csr_file "$CSR")
    [ -n "$P" ] || die "could not parse $CSR as a CSR"
    echo ""
    echo "CSR: $CSR"
    echo "        PIN     : sha256/$P"
    PINS+=("$P"); LABELS+=("csr")
fi

# ------------------------------------------------------------------ --host
if [ -n "$HOST" ]; then
    echo ""
    echo "connecting to $HOST:$PORT (SNI: $SNI) ..."

    # -showcerts prints the whole chain the SERVER sends. That distinction
    # matters: the chain a browser builds may include a root the server never
    # sent, and you cannot pin what is not on the wire unless the client has it.
    if ! echo | openssl s_client -connect "$HOST:$PORT" -servername "$SNI" \
            -showcerts </dev/null >"$TMP/chain.txt" 2>"$TMP/err.txt"; then
        if ! grep -q "BEGIN CERTIFICATE" "$TMP/chain.txt"; then
            echo "  connection failed:"
            sed 's/^/    /' "$TMP/err.txt" | head -10
            die "could not retrieve a chain from $HOST:$PORT"
        fi
    fi

    # Split the concatenated PEM blocks into individual files, in order.
    #
    # The `inc` flag is load-bearing and the obvious version of this awk is
    # wrong. `s_client -showcerts` interleaves human-readable "s:/i:/a:/v:"
    # lines between the PEM blocks, so a rule of `n>0 {print > f}` also writes
    # those lines -- and worse, awk's `>` REOPENS a closed file in truncate
    # mode, so each stray line after `close(f)` wipes the certificate that was
    # just written. The result is a file full of metadata and a pin that is
    # SHA-256 of the empty string (sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=).
    # If you ever see that value, this is why: you hashed nothing.
    awk 'BEGIN{n=0; inc=0}
         /-----BEGIN CERTIFICATE-----/{n++; f=sprintf("'"$TMP"'/cert-%02d.pem", n); inc=1}
         inc==1 {print > f}
         /-----END CERTIFICATE-----/{inc=0; close(f)}' "$TMP/chain.txt"

    N=$(ls "$TMP"/cert-*.pem 2>/dev/null | wc -l | tr -d ' ')
    [ "$N" -gt 0 ] || die "server sent no certificates"

    echo "  server sent $N certificate(s)"
    echo ""

    i=0
    for f in "$TMP"/cert-*.pem; do
        i=$((i + 1))
        if [ "$i" -eq 1 ]; then
            ROLE="LEAF          changes at EVERY renewal -- pin this ONLY with a backup"
        elif [ "$i" -eq "$N" ]; then
            ROLE="ROOT/last     stable for years, but pins you to the CA, not to you"
        else
            ROLE="INTERMEDIATE  a compromise: survives leaf renewal, breaks on CA rotation"
        fi
        P=$(pin_from_cert_file "$f")
        echo "    [$i/$N] $ROLE"
        cert_line "$f"
        echo "        PIN     : sha256/$P"
        echo ""
        PINS+=("$P"); LABELS+=("chain[$i]")
    done

    # Self-signed check: a single self-signed certificate is a different
    # situation entirely and people pin it without realising the implication.
    if [ "$N" -eq 1 ]; then
        S=$(openssl x509 -in "$TMP/cert-01.pem" -noout -subject 2>/dev/null)
        I=$(openssl x509 -in "$TMP/cert-01.pem" -noout -issuer 2>/dev/null)
        if [ "${S#subject=}" = "${I#issuer=}" ]; then
            echo "    NOTE: this certificate is self-signed. Pinning it is the only"
            echo "          way to trust it, and there is no renewal path that keeps"
            echo "          the pin valid unless you reuse the key."
            echo ""
        fi
    fi
fi

# ---------------------------------------------------------------- emit config
if [ -n "$EMIT" ] && [ "${#PINS[@]}" -gt 0 ]; then
    H="${HOST:-api.example.com}"
    echo ""
    case "$EMIT" in
      okhttp)
        echo "// OkHttp -- paste into your client construction."
        echo "// EVERY pin listed is accepted; the connection succeeds if ANY matches."
        echo "// That is why a backup pin does not weaken the control: an attacker"
        echo "// still needs a key you pinned, and you still need one you control."
        echo "val pinner = CertificatePinner.Builder()"
        for i in "${!PINS[@]}"; do
            echo "    .add(\"$H\", \"sha256/${PINS[$i]}\")   // ${LABELS[$i]}"
        done
        echo "    .build()"
        echo ""
        echo "val client = OkHttpClient.Builder().certificatePinner(pinner).build()"
        ;;
      nsc)
        echo "<!-- res/xml/network_security_config.xml -->"
        echo "<!-- expiration is MANDATORY in practice: past it the pin set is"
        echo "     ignored rather than enforced, which is the platform's own"
        echo "     answer to bricking. Choose it deliberately. -->"
        echo "<network-security-config>"
        echo "    <domain-config>"
        echo "        <domain includeSubdomains=\"true\">$H</domain>"
        echo "        <pin-set expiration=\"$(date -u -d '+180 days' '+%Y-%m-%d' 2>/dev/null || echo 'YYYY-MM-DD')\">"
        for i in "${!PINS[@]}"; do
            echo "            <pin digest=\"SHA-256\">${PINS[$i]}</pin>  <!-- ${LABELS[$i]} -->"
        done
        echo "        </pin-set>"
        echo "    </domain-config>"
        echo "</network-security-config>"
        ;;
      *)
        die "--emit takes 'okhttp' or 'nsc'"
        ;;
    esac
    echo ""
fi

# --------------------------------------------------------------------- advice
if [ "${#PINS[@]}" -gt 1 ] || [ -n "$HOST" ]; then
    cat <<'ADVICE'

------------------------------------------------------------------------------
Before you pin any of the above, answer these three questions. If you cannot,
you are not ready to pin, and shipping a pin you cannot rotate is worse than
shipping no pin at all.

  1. What is the BACKUP pin, and where is the key that produces it?
     A pin set with one pin has a single point of failure that is not under
     your CA's control and not fixable by a server-side change. Generate a
     second key now, pin it now, keep it offline:
         openssl genrsa -out backup.key 4096       # or: openssl ecparam ...
         ./spki-pin.sh --key backup.key

  2. What happens on the day the pin is wrong?
     Not "if". Name the mechanism: an expiration date on the <pin-set>, a
     remote kill switch, a forced-update prompt, or a support queue. "We would
     ship a hotfix" is not a mechanism -- users who cannot reach your API also
     cannot always reach your update.

  3. What does pinning actually buy YOUR app?
     It stops a mis-issued or attacker-installed CA. It does not stop a
     compromised server, a leaky log, a malicious SDK, or an attacker with root
     on the device. If your threat model is "someone with root on the phone",
     pinning is not the control you want and no amount of it will help.
------------------------------------------------------------------------------
ADVICE
fi
