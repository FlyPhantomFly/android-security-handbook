#!/usr/bin/env bash
#
# firmware-triage.sh — audit an UNPACKED Android firmware image offline.
#
# WHAT IT DOES
#   Runs the static checks from ../README.md section 8 against a mounted or
#   extracted firmware tree:
#
#     - build properties: fingerprint, build type, tags, patch level
#     - boot-ramdisk properties: ro.debuggable, ro.secure, ro.adb.secure
#     - INIT SERVICE PRIVILEGE AUDIT   <- the highest-value check
#     - privileged application inventory and their permission grants
#     - APEX module versions
#     - world-accessible sockets declared in .rc files
#     - SELinux policy presence
#
#   The init .rc audit is the one that finds things. It shows every service's
#   user, groups, capabilities and SELinux domain — its entire privilege budget
#   — in a form you can grep. A service with no 'user' line runs as root.
#
# HOW TO RUN
#   # 1. unpack the factory image
#   unzip factory-image.zip && tar xvf image-*.tar.gz
#
#   # 2. unpack super.img into its logical partitions
#   lpunpack super.img out/
#
#   # 3. mount them read-only
#   sudo mkdir -p /mnt/system /mnt/vendor /mnt/product
#   sudo mount -o loop,ro out/system.img  /mnt/system
#   sudo mount -o loop,ro out/vendor.img  /mnt/vendor
#   sudo mount -o loop,ro out/product.img /mnt/product
#
#   # 4. run this
#   ./firmware-triage.sh /mnt/system /mnt/vendor /mnt/product
#
#   You can also point it at an extracted tree rather than a mount.
#
# REQUIREMENTS
#   Standard POSIX tools. aapt2 optional (improves APK inventory).
#   No device needed.

set -uo pipefail

SYSTEM="${1:-}"
VENDOR="${2:-}"
PRODUCT="${3:-}"

if [[ -z "$SYSTEM" || ! -d "$SYSTEM" ]]; then
    sed -n '3,34p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

OUT="firmware-triage-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

hr()  { printf '\n===== %s %s\n' "$1" "$(printf '=%.0s' $(seq 1 $((58 - ${#1}))))"; }
sub() { printf '\n--- %s\n' "$1"; }

# Some images mount as <root>/system/... and some as <root>/...
SYSROOT="$SYSTEM"
[[ -d "$SYSTEM/system" ]] && SYSROOT="$SYSTEM/system"

{
hr "INPUT"
echo "  system : $SYSTEM  (root: $SYSROOT)"
echo "  vendor : ${VENDOR:-<not supplied>}"
echo "  product: ${PRODUCT:-<not supplied>}"

# ------------------------------------------------------- build properties --

hr "BUILD PROPERTIES"
for f in "$SYSROOT/build.prop" "$SYSTEM/build.prop" \
         "${VENDOR:-/nonexistent}/build.prop" "${PRODUCT:-/nonexistent}/etc/build.prop"; do
    [[ -f "$f" ]] || continue
    sub "$f"
    grep -E '^(ro\.build\.fingerprint|ro\.build\.type|ro\.build\.tags|ro\.build\.version\.(release|sdk|security_patch)|ro\.product\.(model|manufacturer|cpu\.abilist)|ro\.debuggable|ro\.secure|ro\.adb\.secure|ro\.crypto)' \
        "$f" 2>/dev/null | sed 's/^/  /'
done

sub "verdict"
TAGS=$(grep -h '^ro.build.tags=' "$SYSROOT/build.prop" 2>/dev/null | head -1 | cut -d= -f2)
TYPE=$(grep -h '^ro.build.type=' "$SYSROOT/build.prop" 2>/dev/null | head -1 | cut -d= -f2)
DBG=$(grep -rh '^ro.debuggable=' "$SYSROOT/build.prop" "$SYSTEM"/*.prop 2>/dev/null | head -1 | cut -d= -f2)

if [[ "$TAGS" == *test-keys* ]]; then
    echo "  !! CRITICAL  ro.build.tags=$TAGS"
    echo "     Signed with the PUBLIC AOSP test keys. Anyone can sign an APK that"
    echo "     receives signature-level platform permissions. See README 5.3."
else
    echo "  OK          ro.build.tags=${TAGS:-<not found>}"
fi
[[ "$TYPE" != "user" && -n "$TYPE" ]] && \
    echo "  !! HIGH      ro.build.type=$TYPE  (non-production variant)"
[[ "$DBG" == "1" ]] && \
    echo "  !! CRITICAL  ro.debuggable=1  (every app debuggable; run-as works for any package)"

echo
echo "  NOTE: ro.debuggable often lives in the BOOT RAMDISK's default.prop,"
echo "        not in /system/build.prop. Unpack boot.img and check there too:"
echo "          magiskboot unpack boot.img && cpio -idmv < ramdisk.cpio"
echo "          cat default.prop prop.default 2>/dev/null | grep -E 'debuggable|secure'"

# ------------------------------------------------- INIT SERVICE AUDIT ------

hr "INIT SERVICE PRIVILEGE AUDIT"
echo "  The highest-value static check. Every service's user, groups,"
echo "  capabilities and SELinux domain — its whole privilege budget."

RCDIRS=()
for d in "$SYSROOT/etc/init" "${VENDOR:-/nonexistent}/etc/init" \
         "${PRODUCT:-/nonexistent}/etc/init" "$SYSTEM/etc/init"; do
    [[ -d "$d" ]] && RCDIRS+=("$d")
done

if [[ ${#RCDIRS[@]} -eq 0 ]]; then
    echo "  no init directories found"
else
    RCFILES=$(find "${RCDIRS[@]}" -name '*.rc' 2>/dev/null)
    COUNT=$(echo "$RCFILES" | grep -c . || true)
    echo "  scanning $COUNT .rc files"

    # Parse each service block, defaulting user to root when absent.
    awk '
      /^service /   { if (svc != "") emit(); svc=$2; bin=$3; usr="root(DEFAULT)"; grp=""; cap=""; sec=""; sock="" }
      /^[ \t]+user /          { usr=$2 }
      /^[ \t]+group /         { $1=""; grp=substr($0,2) }
      /^[ \t]+capabilities/   { $1=""; cap=substr($0,2) }
      /^[ \t]+seclabel /      { sec=$2 }
      /^[ \t]+socket /        { sock=sock" "$2"("$4")" }
      END { if (svc != "") emit() }
      function emit() {
        printf "%s|%s|%s|%s|%s|%s\n", usr, svc, bin, cap, sec, sock
      }
    ' $RCFILES > "$OUT/services.txt" 2>/dev/null

    sub "services running as ROOT"
    grep '^root' "$OUT/services.txt" | while IFS='|' read -r usr svc bin cap sec sock; do
        printf '  %-28s %s\n' "$svc" "$bin"
        [[ -n "$cap"  ]] && echo "      capabilities: $cap"
        [[ -n "$sec"  ]] && echo "      seclabel    : $sec"
        [[ -n "$sock" ]] && echo "      sockets     :$sock"
        [[ "$usr" == "root(DEFAULT)" ]] && echo "      !! no 'user' line — runs as root BY DEFAULT"
    done

    sub "services with capabilities"
    grep -v '^|' "$OUT/services.txt" | awk -F'|' '$4 != "" {printf "  %-28s caps: %s\n", $2, $4}'

    sub "world-accessible sockets declared in .rc"
    grep -hE '^[ \t]+socket .*0(6|7)(6|7)(6|7)' $RCFILES 2>/dev/null | sed 's/^/  !! /' \
        || echo "  none with mode 066x/077x"
    echo
    echo "  A mode-0666 socket is reachable by ANY app on the device, entirely"
    echo "  outside the framework permission model. See ../../24-IPC/."

    sub "services with no seclabel"
    awk -F'|' '$5 == "" {printf "  %-28s %s\n", $2, $3}' "$OUT/services.txt" | head -20
    echo "  (may still get a domain via a type_transition — verify in sepolicy)"
fi

# --------------------------------------------------- privileged apps -------

hr "PRIVILEGED APPLICATION INVENTORY"
echo "  On an OEM device this is where findings concentrate (README 5.2)."

for d in "$SYSROOT/priv-app" "$SYSROOT/app" \
         "${PRODUCT:-/nonexistent}/priv-app" "${PRODUCT:-/nonexistent}/app" \
         "${VENDOR:-/nonexistent}/app" "${VENDOR:-/nonexistent}/priv-app"; do
    [[ -d "$d" ]] || continue
    N=$(find "$d" -name '*.apk' 2>/dev/null | wc -l | tr -d ' ')
    sub "$d  ($N APKs)"
    find "$d" -name '*.apk' 2>/dev/null | sed "s|$d/||" | head -40 | sed 's/^/  /'
done

sub "privileged permission grants"
for f in "$SYSROOT/etc/permissions"/privapp-permissions-*.xml \
         "${VENDOR:-/nonexistent}/etc/permissions"/privapp-permissions-*.xml \
         "${PRODUCT:-/nonexistent}/etc/permissions"/privapp-permissions-*.xml; do
    [[ -f "$f" ]] || continue
    echo "  $f"
    grep -oE '<privapp-permissions package="[^"]*"' "$f" 2>/dev/null \
        | sed 's/.*package="/    /; s/"$//' | sort -u | head -30
done

echo
echo "  For each interesting package, continue with:"
echo "    ../../10-APK-Internals/  (unpack and verify)"
echo "    ../../32-Manifest/       (exported components and permissions)"

# ---------------------------------------------------------- APEX -----------

hr "APEX / MAINLINE MODULES"
for d in "$SYSROOT/apex" "$SYSTEM/apex"; do
    [[ -d "$d" ]] || continue
    ls -la "$d" 2>/dev/null | grep -E '\.apex|\.capex' | awk '{print "  " $NF, "(" $5 " bytes)"}'
done
echo
echo "  Module versions are independent of the OS build. On a live device also"
echo "  record the Google Play system update level — README 3.11.5."

# --------------------------------------------------------- SELinux --------

hr "SELINUX POLICY"
for f in "$SYSROOT/etc/selinux/plat_sepolicy.cil" "$SYSROOT/etc/selinux/precompiled_sepolicy" \
         "${VENDOR:-/nonexistent}/etc/selinux/vendor_sepolicy.cil" "$SYSTEM/sepolicy"; do
    [[ -f "$f" ]] && printf '  %-60s %s bytes\n' "$f" "$(wc -c < "$f" | tr -d ' ')"
done
for f in "$SYSROOT/etc/selinux/plat_property_contexts" \
         "${VENDOR:-/nonexistent}/etc/selinux/vendor_property_contexts"; do
    [[ -f "$f" ]] && echo "  $f  ($(wc -l < "$f" | tr -d ' ') lines)"
done
echo
echo "  Analyse with sesearch / sepolicy-analyze — see ../../22-SELinux/."

# ------------------------------------------------------------ summary ------

hr "NEXT STEPS"
cat <<'EOF'
  1. Read services.txt in full. Every root service with capabilities is a
     candidate for review:
         less <outdir>/services.txt

  2. Unpack boot.img and check the ramdisk's default.prop for ro.debuggable
     and ro.secure — they are frequently NOT in /system/build.prop.

  3. Verify AVB descriptors and the rollback index:
         python3 external/avb/avbtool.py info_image --image vbmeta.img

  4. Triage the privileged APKs. An exported component in /system/priv-app is
     worth far more to an attacker than the same bug in a normal app.

  5. Cross-check against a live device with ./device-posture.sh and
     ./layer-census.sh.

  Everything above is a LEAD. Validate before it enters a report.
EOF

hr "DONE"
echo "  Output: $OUT"

} 2>&1 | tee "$OUT/triage-report.txt"
