#!/usr/bin/env bash
#
# examples/05-research-env/setup.sh
# ============================================================================
# Build a reproducible AOSP research environment: pinned sync, reviewed patch
# series, build, boot, and a recorded evidence file describing exactly what
# was produced.
#
# PURPOSE
#     Section 9.5 of ../../README.md. The difference between "I have an AOSP
#     tree somewhere" and a research environment is reproducibility: being able
#     to say precisely which source produced the image an experiment ran on,
#     and being able to rebuild both the instrumented image and a clean one on
#     demand.
#
#     This script enforces that discipline. It records a pinned manifest, keeps
#     instrumentation as a reviewed patch series rather than ad-hoc edits, and
#     writes a build record you attach to findings.
#
# USAGE
#     ./setup.sh                                  # defaults below
#     ./setup.sh -t android-15.0.0_r1
#     ./setup.sh -t android-14.0.0_r1 -l aosp_cf_x86_64_phone-userdebug
#     ./setup.sh -p ~/my-patches                  # a different patch series
#     ./setup.sh --clean                          # build WITHOUT the patches
#     ./setup.sh --no-build                       # sync and patch only
#
# THE CLEAN/INSTRUMENTED PAIR
#     Run it twice: once with --clean and once without, into different trees.
#     You then have an instrumented image for investigation and a clean image
#     for reproducing findings. Reporting a finding from a patched image is one
#     of the mistakes in ../../README.md section 11 — this makes doing it right
#     the path of least resistance.
#
# REQUIREMENTS
#     Linux (Ubuntu 22.04 / Debian 12 are the well-trodden paths).
#     ~400 GB free SSD, 32 GB RAM comfortable, KVM available for Cuttlefish.
#     Build dependencies: see ../../labs/lab-02-build-and-boot-aosp.md
#
# SEE ALSO
#     ../../README.md sections 3.9, 3.10, 9.5
#     ../04-binder-trace.patch  (the instrumentation this applies)
#     ../../labs/lab-02-build-and-boot-aosp.md
#     ../../../08-Build-System/README.md  (what `m` actually does)
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

AOSP_TAG="android-15.0.0_r1"
LUNCH_TARGET="aosp_cf_x86_64_phone-trunk_staging-userdebug"
PATCH_DIR="${HOME}/aosp-research-patches"
TREE_ROOT="${HOME}/aosp"
CLEAN=0
DO_BUILD=1
JOBS="$(nproc 2>/dev/null || echo 8)"

usage() { sed -n '3,45p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        -t) AOSP_TAG="$2"; shift 2 ;;
        -l) LUNCH_TARGET="$2"; shift 2 ;;
        -p) PATCH_DIR="$2"; shift 2 ;;
        -r) TREE_ROOT="$2"; shift 2 ;;
        -j) JOBS="$2"; shift 2 ;;
        --clean) CLEAN=1; shift ;;
        --no-build) DO_BUILD=0; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 2 ;;
    esac
done

if [ "$CLEAN" -eq 1 ]; then
    TREE="${TREE_ROOT}/${AOSP_TAG}-clean"
else
    TREE="${TREE_ROOT}/${AOSP_TAG}-instrumented"
fi

STAMP="$(date -u +%Y%m%d-%H%M%S)"
RECORD="${TREE}/RESEARCH-BUILD-RECORD.txt"

say() { printf '\n\033[1;36m[*] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m[x] %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 0. Preflight
# ---------------------------------------------------------------------------

say "preflight"

command -v repo >/dev/null 2>&1 || die "repo is not on PATH. Install it:
    mkdir -p ~/bin && export PATH=~/bin:\$PATH
    curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
    chmod a+x ~/bin/repo"

command -v git >/dev/null 2>&1 || die "git is not installed"
command -v python3 >/dev/null 2>&1 || die "python3 is not installed"

AVAIL_GB=$(df -BG --output=avail "$(dirname "$TREE_ROOT")" 2>/dev/null | tail -1 | tr -dc '0-9')
if [ -n "${AVAIL_GB:-}" ] && [ "$AVAIL_GB" -lt 400 ]; then
    warn "only ${AVAIL_GB} GB free. A synced tree plus out/ needs ~400 GB."
    warn "Continuing, but expect the build to fail if this is not enough."
fi

echo "    tag           : $AOSP_TAG"
echo "    lunch target  : $LUNCH_TARGET"
echo "    tree          : $TREE"
echo "    mode          : $([ "$CLEAN" -eq 1 ] && echo 'CLEAN (no patches)' || echo 'INSTRUMENTED')"
echo "    patch series  : $([ "$CLEAN" -eq 1 ] && echo '(none)' || echo "$PATCH_DIR")"
echo "    parallelism   : $JOBS"

# ---------------------------------------------------------------------------
# 1. Sync a pinned tree
# ---------------------------------------------------------------------------

say "1. sync ${AOSP_TAG}"

mkdir -p "$TREE"
cd "$TREE"

if [ ! -d .repo ]; then
    repo init -u https://android.googlesource.com/platform/manifest \
              -b "$AOSP_TAG" --depth=1
else
    echo "    .repo already present — re-initialising to $AOSP_TAG"
    repo init -b "$AOSP_TAG"
fi

repo sync -c -j"$JOBS" --no-tags --no-clone-bundle

# ---------------------------------------------------------------------------
# 2. RECORD what was synced
#
# This is the step people skip, and it is the one that makes findings
# defensible. `repo manifest -r` emits a manifest with EVERY project pinned to
# the exact commit currently checked out. Attach it to any finding that
# references source.
# ---------------------------------------------------------------------------

say "2. record the pinned manifest"

PINNED="${TREE}/pinned-manifest-${STAMP}.xml"
repo manifest -r -o "$PINNED"
PINNED_SHA=$(sha256sum "$PINNED" | cut -d' ' -f1)

echo "    $PINNED"
echo "    sha256 = $PINNED_SHA"

{
    echo "========================================================================"
    echo "  AOSP RESEARCH BUILD RECORD"
    echo "  generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "========================================================================"
    echo
    echo "AOSP tag          : $AOSP_TAG"
    echo "lunch target      : $LUNCH_TARGET"
    echo "tree              : $TREE"
    echo "mode              : $([ "$CLEAN" -eq 1 ] && echo 'CLEAN' || echo 'INSTRUMENTED')"
    echo "pinned manifest   : $(basename "$PINNED")"
    echo "  sha256          : $PINNED_SHA"
    echo "host              : $(uname -a)"
    echo
} > "$RECORD"

# ---------------------------------------------------------------------------
# 3. Apply the research patch series
#
# Patches are named  <project_path_with_underscores>.<description>.patch
# e.g.  frameworks_base.binder-trace.patch  ->  frameworks/base
# ---------------------------------------------------------------------------

if [ "$CLEAN" -eq 1 ]; then
    say "3. skipping patches (--clean)"
    echo "patches applied   : NONE (clean build)" >> "$RECORD"
elif [ ! -d "$PATCH_DIR" ]; then
    warn "patch directory $PATCH_DIR does not exist — building unpatched"
    warn "See ../04-binder-trace.patch for the instrumentation to put there."
    echo "patches applied   : NONE (patch dir missing)" >> "$RECORD"
else
    say "3. apply the research patch series from $PATCH_DIR"

    echo "patches applied   :" >> "$RECORD"
    APPLIED=0

    shopt -s nullglob
    for patch in "$PATCH_DIR"/*.patch; do
        base="$(basename "$patch" .patch)"
        # frameworks_base.binder-trace  ->  frameworks/base
        projkey="${base%%.*}"
        project="${projkey//_//}"

        if [ ! -d "${TREE}/${project}" ]; then
            warn "  project '$project' not in the tree — skipping $(basename "$patch")"
            continue
        fi

        if ! git -C "${TREE}/${project}" apply --check "$patch" 2>/dev/null; then
            warn "  $(basename "$patch") does NOT apply to $project."
            warn "  This usually means AOSP moved since the patch was written."
            warn "  Rebase it against $AOSP_TAG — a patch that stops applying is a"
            warn "  visible, reviewable event, which is the point of keeping a series."
            echo "  FAILED  $(basename "$patch") -> $project" >> "$RECORD"
            continue
        fi

        git -C "${TREE}/${project}" apply "$patch"
        echo "    applied $(basename "$patch") -> $project"
        echo "  OK      $(basename "$patch") -> $project ($(sha256sum "$patch" | cut -c1-16))" >> "$RECORD"
        APPLIED=$((APPLIED + 1))
    done
    shopt -u nullglob

    if [ "$APPLIED" -eq 0 ]; then
        warn "no patches applied — this build is effectively clean"
    else
        echo "    $APPLIED patch(es) applied"
    fi
fi

# ---------------------------------------------------------------------------
# 4. Build
# ---------------------------------------------------------------------------

if [ "$DO_BUILD" -eq 0 ]; then
    say "4. skipping build (--no-build)"
    echo
    echo "Tree is synced and patched at: $TREE"
    echo "To build manually:"
    echo "    cd $TREE"
    echo "    source build/envsetup.sh"
    echo "    lunch $LUNCH_TARGET"
    echo "    m -j$JOBS"
    exit 0
fi

say "4. build (this takes hours on a first run)"

cd "$TREE"
# shellcheck disable=SC1091
source build/envsetup.sh
lunch "$LUNCH_TARGET"

# Measure the parse phase first. This number is the entire justification for
# Soong's existence, and it validates that the tree is well-formed before you
# commit hours to a full build. See 08-Build-System/README.md section 1.
say "4a. m nothing (parse only — validates the tree, measures null-build time)"
NULLBUILD_START=$(date +%s)
m nothing
NULLBUILD_SEC=$(( $(date +%s) - NULLBUILD_START ))
echo "    null build: ${NULLBUILD_SEC}s"
echo "null build (s)    : $NULLBUILD_SEC" >> "$RECORD"

say "4b. full build"
BUILD_START=$(date +%s)
m -j"$JOBS"
BUILD_SEC=$(( $(date +%s) - BUILD_START ))
echo "    full build: $((BUILD_SEC / 60)) minutes"
echo "full build (min)  : $((BUILD_SEC / 60))" >> "$RECORD"

# ---------------------------------------------------------------------------
# 5. Record what was produced
# ---------------------------------------------------------------------------

say "5. record the build output"

PRODUCT_OUT="${TREE}/out/target/product/vsoc_x86_64"
if [ ! -d "$PRODUCT_OUT" ]; then
    # Non-Cuttlefish targets land elsewhere; find it.
    PRODUCT_OUT=$(find "${TREE}/out/target/product" -maxdepth 1 -mindepth 1 -type d | head -1)
fi

{
    echo
    echo "------------------------------------------------------------------------"
    echo "BUILD OUTPUT"
    echo "------------------------------------------------------------------------"
    echo "product out       : $PRODUCT_OUT"
    if [ -f "${PRODUCT_OUT}/system/build.prop" ]; then
        echo
        echo "build.prop identity:"
        grep -E "^ro\.(build\.fingerprint|build\.id|build\.type|build\.version\.(release|sdk|security_patch))=" \
             "${PRODUCT_OUT}/system/build.prop" | sed 's/^/  /'
    fi
    echo
    echo "images:"
    ls -lh "${PRODUCT_OUT}"/*.img 2>/dev/null | awk '{print "  " $9 "  " $5}'
    echo
    echo "artefacts worth knowing about:"
    echo "  ${PRODUCT_OUT}/symbols/            unstripped binaries with full symbols"
    echo "  ${PRODUCT_OUT}/module-info.json    module name -> installed path"
    echo "  ${PRODUCT_OUT}/installed-files.txt complete image inventory"
    echo "  ${TREE}/out/soong/soong.variables  the entire product config as JSON"
    echo
    echo "------------------------------------------------------------------------"
    echo "USING THIS RECORD"
    echo "------------------------------------------------------------------------"
    echo
    echo "Attach this file, and $(basename "$PINNED"), to any finding that"
    echo "references AOSP source or was demonstrated on this image. Together they"
    echo "answer, precisely:"
    echo "  - which source was this built from (every project, pinned to a SHA)"
    echo "  - which instrumentation was active"
    echo "  - what the resulting image identifies itself as"
    echo
    if [ "$CLEAN" -eq 0 ]; then
        echo "*** THIS IS AN INSTRUMENTED IMAGE. ***"
        echo "It is a research instrument, not evidence. Reproduce every finding on"
        echo "a clean image (re-run this script with --clean) before reporting, and"
        echo "state in the report which image each piece of evidence came from."
        echo
    fi
    echo "REMEMBER: this image has NO Google Mobile Services. Controls that depend"
    echo "on Play Integrity, Play Protect or Play services are absent, and may fail"
    echo "OPEN. Confirm findings on a retail device. See README section 1.5."
} >> "$RECORD"

# ---------------------------------------------------------------------------
# 6. Boot
# ---------------------------------------------------------------------------

say "6. boot Cuttlefish"

if command -v launch_cvd >/dev/null 2>&1; then
    if [ ! -e /dev/kvm ]; then
        warn "/dev/kvm is not present — Cuttlefish needs KVM."
        warn "Enable nested virtualisation, or add yourself to the kvm group."
    else
        launch_cvd --daemon --cpus 4 --memory_mb 8192 || \
            warn "launch_cvd failed; run it manually from $TREE"
        sleep 5
        adb wait-for-device || true
        adb root || true
        echo
        echo "    fingerprint : $(adb shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r')"
        echo "    build type  : $(adb shell getprop ro.build.type 2>/dev/null | tr -d '\r')"
        echo "    debuggable  : $(adb shell getprop ro.debuggable 2>/dev/null | tr -d '\r')"
        echo "    selinux     : $(adb shell getenforce 2>/dev/null | tr -d '\r')"
        echo "    web UI      : https://localhost:8443"
    fi
else
    warn "launch_cvd not found — did lunch succeed? Run manually:"
    warn "    cd $TREE && source build/envsetup.sh && lunch $LUNCH_TARGET && launch_cvd --daemon"
fi

# ---------------------------------------------------------------------------

say "done"
cat "$RECORD"
echo
echo "Build record : $RECORD"
echo "Pinned tree  : $PINNED"
echo
echo "Fast iteration loop from here:"
echo "    cd $TREE && source build/envsetup.sh && lunch $LUNCH_TARGET"
echo "    <edit a file>"
echo "    m framework          # or: m services / m libbinder"
echo "    m snod               # repack system.img in under a minute"
echo "    stop_cvd && launch_cvd --daemon"
