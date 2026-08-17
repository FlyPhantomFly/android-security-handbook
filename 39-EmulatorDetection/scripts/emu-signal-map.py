#!/usr/bin/env python3
# scripts/emu-signal-map.py
#
# PURPOSE
#   Map the emulator-detection surface of an APK, and -- the part that makes this
#   different from a grep -- GRADE every hit against the measurements in
#   README section 3.14.
#
#   Existing tools tell you an app contains the string "/dev/qemu_pipe". This
#   tells you that string names a check which, measured on a stock Android 15
#   API 35 AVD, DOES NOT FIRE. That distinction is the whole point: the most
#   valuable finding in an emulator-detection assessment is usually that the
#   control the developer believes they have has never worked.
#
#   Grades (see README section 3.0):
#     HARD   costly to fake; survives a naive Java hook
#     SOFT   one value, one API; one hook or one resetprop defeats it
#     DEAD   published everywhere, MEASURED not to fire on a current AVD
#     NOISY  fires on real devices too -- a false-positive source
#     INFO   context, never a verdict alone
#
# USAGE
#   # host -- map an APK (uses apktool if present, else falls back to raw scan)
#   python3 -B emu-signal-map.py app.apk
#
#   # host -- map an already-unpacked directory (apktool or jadx output)
#   python3 -B emu-signal-map.py out/
#
#   # host -- JSON, for piping into something else
#   python3 -B emu-signal-map.py app.apk --json
#
#   # host -- show every hit rather than a capped sample per signal
#   python3 -B emu-signal-map.py app.apk --all
#
#   Run with `python3 -B` so no __pycache__ is written next to the script.
#
# REQUIREMENTS
#   Python 3.7+. No third-party packages.
#   `apktool` on PATH is optional but recommended: without it the script scans
#   the APK's raw members, which finds strings in classes.dex and in native
#   libraries but cannot resolve them to smali file/line positions.
#
# WHAT THIS DOES NOT DO
#   It does NOT tell you the app performs emulator detection. A string is not a
#   check: analytics SDKs read ro.hardware for crash reports, and a device-info
#   library reads every property in this list. Every hit is a LEAD. Cross-
#   reference it to a branch before calling it a finding -- README section 8.2,
#   and chapter 52's measured 16,836 hits -> 168 leads -> 2 survivors.
#
# AUTHORISED TESTING ONLY. Analyse APKs you own or are contracted to assess.

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import OrderedDict

# --------------------------------------------------------------------------- #
# The signal table. Every grade here is backed by a measurement recorded in
# README section 3.14, taken on a Redmi M2101K6P (Android 11 / API 30) and a
# Pixel_6_Pro_API_35 AVD (Android 15 / API 35, x86_64).
#
# Fields: (regex, grade, family, note)
# --------------------------------------------------------------------------- #
SIGNALS = [
    # ---------------- properties ----------------
    (r'ro\.kernel\.qemu(?!\.gles)', 'SOFT', 'property',
     'Classic. Still set to 1 on the AVD. One resetprop or one hook defeats it.'),
    (r'ro\.boot\.qemu(?!\.)', 'SOFT', 'property',
     'From bootconfig. Same strength as ro.kernel.qemu.'),
    (r'ro\.boot\.qemu\.avd_name', 'SOFT', 'property',
     'Literally contains the AVD name. Rarely checked, works well.'),
    (r'ro\.hardware(?![.\w])', 'SOFT', 'property',
     'Best single property: ranchu/goldfish, sourced from bootconfig not the build.'),
    (r'ro\.boot\.hardware', 'SOFT', 'property',
     'Same value as ro.hardware, bootconfig origin.'),
    (r'ro\.build\.characteristics', 'SOFT', 'property',
     'Reads "emulator" on the AVD, "default" on the Redmi. Explicit and effective.'),
    (r'ro\.hardware\.(egl|gralloc|vulkan)', 'SOFT', 'property',
     'Graphics stack: "emulation"/"ranchu" on the AVD.'),
    (r'ro\.soc\.model', 'SOFT', 'property',
     'Reads "ranchu" on the AVD; unset on the Redmi.'),
    (r'ro\.dalvik\.vm\.native\.bridge', 'HARD', 'property',
     'libndk_translation.so means a binary translator is installed. Expensive to fake.'),
    (r'ro\.product\.cpu\.abilist?', 'HARD', 'property',
     'ABI list. x86 + ARM together implies translation. See README 3.9.'),
    (r'ro\.build\.tags', 'NOISY', 'property',
     'test-keys/dev-keys is true of EVERY custom ROM on real hardware.'),
    (r'ro\.(secure|debuggable)', 'NOISY', 'property',
     'Development-image signal, not an emulator signal. True of userdebug phones.'),
    (r'ro\.kernel\.qemu\.gles', 'NOISY', 'property',
     'MEASURED SET (value 0) ON A RETAIL REDMI. Matching this flags real phones.'),
    (r'qemu\.hw\.mainkeys', 'NOISY', 'property',
     'MEASURED SET (value 0) ON A RETAIL REDMI, and UNSET on the AVD. Inverted.'),
    (r'ro\.boottime\.(qemu|ranchu|goldfish)', 'DEAD', 'property',
     'SELinux type boottime_prop: invisible to untrusted_app. Shell sees it; an app cannot.'),

    # ---------------- Build fields ----------------
    (r'Landroid/os/Build;->FINGERPRINT', 'INFO', 'build',
     'The field itself is fine; what matters is what it is compared against.'),
    (r'"generic"', 'DEAD', 'build',
     'MEASURED: the API 35 AVD fingerprint/brand/device contain no "generic". Never fires.'),
    (r'"google_sdk"', 'DEAD', 'build',
     'Legacy AVD product name. Current images are sdk_gphone*.'),
    (r'"Android SDK built for', 'DEAD', 'build',
     'Legacy Build.MODEL. Current images read sdk_gphone16k_x86_64 etc.'),
    (r'sdk_gphone', 'SOFT', 'build',
     'The CURRENT model/product naming. This one works.'),
    (r'Landroid/os/Build;->(HARDWARE|BOARD|PRODUCT|DEVICE|BRAND|MODEL|MANUFACTURER)',
     'SOFT', 'build',
     'Build fields are latched at class-init; hooking SystemProperties.get will not change them.'),
    (r'Landroid/os/Build;->SUPPORTED_ABIS', 'HARD', 'build',
     'x86 and ARM advertised together implies a native bridge. Strongest Java-reachable signal.'),
    (r'Landroid/os/Build;->BOOTLOADER', 'NOISY', 'build',
     'MEASURED "unknown" on BOTH the AVD and the retail Redmi. Flags real phones.'),

    # ---------------- filesystem ----------------
    (r'/dev/qemu_pipe', 'DEAD', 'file',
     'MEASURED ABSENT on API 35. The most-cited check in the field, and it never fires.'),
    (r'/dev/socket/qemud', 'DEAD', 'file',
     'MEASURED ABSENT on API 35.'),
    (r'/system/bin/qemu[-_]?props', 'DEAD', 'file',
     'MEASURED ABSENT on API 35.'),
    (r'/system/bin/qemud', 'DEAD', 'file',
     'MEASURED ABSENT on API 35.'),
    (r'libc_malloc_debug_qemu', 'DEAD', 'file',
     'MEASURED ABSENT on API 35. Removed from the platform years ago.'),
    (r'/dev/goldfish_pipe(?!_)', 'DEAD', 'file',
     'MEASURED ABSENT: the node is now /dev/goldfish_pipe_dprctd.'),
    (r'/dev/goldfish_pipe_dprctd', 'SOFT', 'file',
     'The CURRENT node, mode 666, present on API 35. Very rarely checked.'),
    (r'/dev/goldfish_sync', 'SOFT', 'file',
     'MEASURED PRESENT on API 35.'),
    (r'/dev/goldfish_address_space', 'SOFT', 'file',
     'MEASURED PRESENT on API 35.'),
    (r'/sys/(module|bus/platform/drivers)/goldfish', 'SOFT', 'file',
     'MEASURED PRESENT on API 35; readable by apps, unlike /proc/modules.'),
    (r'/dev/socket/(genyd|baseband_genyd)', 'SOFT', 'file',
     'Genymotion. Not tested here -- no Genymotion instance was available.'),
    (r'/dev/vbox(guest|user)', 'SOFT', 'file',
     'VirtualBox-backed stacks. Not tested here.'),
    (r'(androVM|microvirt)-prop', 'SOFT', 'file',
     'Older VirtualBox-based emulators. Not tested here.'),

    # ---------------- /proc ----------------
    (r'/proc/tty/drivers', 'DEAD', 'proc',
     'MEASURED EACCES from an app on BOTH devices, and contains no goldfish even as root.'),
    (r'/proc/cmdline', 'DEAD', 'proc',
     'MEASURED EACCES from an app on BOTH devices. androidboot.* moved to bootconfig anyway.'),
    (r'/proc/modules', 'DEAD', 'proc',
     'MEASURED EACCES from an app on BOTH devices. Readable from adb shell -- a classic trap.'),
    (r'/proc/cpuinfo', 'HARD', 'proc',
     'Readable by apps. Carries the x86 hypervisor CPUID bit, which the guest cannot clear.'),
    (r'hypervisor', 'HARD', 'proc',
     'CPUID leaf 1 ECX bit 31. x86 ONLY -- absence proves nothing on arm64.'),
    (r'Android virtual processor', 'SOFT', 'proc',
     'The AVD /proc/cpuinfo model name. One read to hook.'),
    (r'/proc/self/(mounts|maps)', 'INFO', 'proc',
     'Readable by apps. Mount COUNT is a usable INFO signal: 263 vs 156 measured.'),

    # ---------------- sensors / packages / telephony ----------------
    (r'getSensorList|getDefaultSensor', 'HARD', 'sensor',
     'Sensor POPULATION is the best Java signal: 41 vs 18, and 0/41 vs 18/18 AOSP-vendored.'),
    (r'Goldfish 3-axis', 'SOFT', 'sensor',
     'The literal AVD accelerometer name. One string to hook.'),
    (r'getInstalledPackages|getInstalledApplications', 'NOISY', 'package',
     'API 30+ FILTERS this silently. A pre-2020 package-count check now flags real devices.'),
    (r'com\.android\.emulator\.(multidisplay|radio\.config)', 'SOFT', 'package',
     'MEASURED PRESENT on the AVD, absent on the Redmi. Match full names, not "emulat".'),
    (r'(bluestacks|genymotion|com\.bignox|andy(roid)?|memu)', 'SOFT', 'package',
     'Third-party emulator packages. Not tested here.'),
    (r'15555215554', 'DEAD', 'telephony',
     'The classic AVD line-1 number. getLine1Number is PRIVILEGED since API 29 -- unreachable.'),
    (r'getImei|getDeviceId', 'DEAD', 'telephony',
     'READ_PRIVILEGED_PHONE_STATE since API 29. Dead code in any third-party app.'),
    (r'"310260"', 'SOFT', 'telephony',
     'The AVD default MCC/MNC. Still works; one emulator console command changes it.'),
    (r'getNetworkOperatorName|getSimOperatorName', 'DEAD', 'telephony',
     'MEASURED "T-Mobile" on the AVD, not "Android". A name check never fires.'),

    # ---------------- native ----------------
    (r'__system_property_(get|find|read|foreach)', 'HARD', 'native',
     'Native property read. A Java hook on SystemProperties.get does NOT see this.'),
    (r'ptrace|TracerPid', 'INFO', 'native',
     'Anti-debug, not emulator detection. Belongs to chapter 38.'),
]

# Grade ordering for the summary, worst news first.
GRADE_ORDER = ['DEAD', 'NOISY', 'HARD', 'SOFT', 'INFO']

# Files worth scanning inside an unpacked tree.
TEXT_EXT = {'.smali', '.java', '.xml', '.kt', '.json', '.txt', '.properties'}
BIN_EXT = {'.so', '.dex', '.bin', '.dat'}

MAX_SAMPLES = 4          # hits shown per signal unless --all
MIN_STR_LEN = 4          # for the crude `strings` implementation


def eprint(*a):
    print(*a, file=sys.stderr)


def extract_strings(data, min_len=MIN_STR_LEN):
    """A minimal `strings(1)`: runs of printable ASCII.

    Implemented here rather than shelling out because `strings` is not present
    on every Windows host, and this script has to work where the rest of the
    chapter's tooling works.
    """
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode('ascii', 'replace'))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode('ascii', 'replace'))
    return out


def try_apktool(apk, workdir):
    """Unpack with apktool if available. Returns the output dir, or None."""
    if not shutil.which('apktool'):
        return None
    out = os.path.join(workdir, 'apktool-out')
    try:
        subprocess.run(['apktool', 'd', '-f', '-o', out, apk],
                       check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=600)
        return out
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        eprint('[!] apktool failed; falling back to a raw scan of the APK members')
        return None


def iter_sources(target, workdir):
    """Yield (label, text) pairs to scan.

    Three modes, in decreasing fidelity:
      1. a directory  -> walk it
      2. an APK with apktool available -> unpack, then walk
      3. an APK without apktool -> scan raw zip members
    """
    if os.path.isdir(target):
        yield from _walk_dir(target, target)
        return

    unpacked = try_apktool(target, workdir)
    if unpacked:
        yield from _walk_dir(unpacked, unpacked)
        return

    # Raw scan. Finds the strings, loses file/line resolution.
    with zipfile.ZipFile(target) as z:
        for name in z.namelist():
            if name.endswith('/'):
                continue
            try:
                data = z.read(name)
            except (KeyError, RuntimeError, zipfile.BadZipFile):
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in TEXT_EXT or name == 'AndroidManifest.xml':
                yield name, data.decode('utf-8', 'replace')
            elif ext in BIN_EXT or name.endswith('.dex'):
                yield name, '\n'.join(extract_strings(data))


def _walk_dir(root, base):
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, base)
            ext = os.path.splitext(fn)[1].lower()
            try:
                if ext in BIN_EXT:
                    with open(path, 'rb') as fh:
                        yield rel, '\n'.join(extract_strings(fh.read()))
                elif ext in TEXT_EXT or ext == '':
                    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                        yield rel, fh.read()
            except (OSError, MemoryError):
                continue


def scan(target):
    """Returns an OrderedDict keyed by signal pattern."""
    compiled = [(re.compile(p), p, g, f, n) for (p, g, f, n) in SIGNALS]
    results = OrderedDict()
    for (_rx, pat, grade, fam, note) in compiled:
        results[pat] = {
            'pattern': pat, 'grade': grade, 'family': fam,
            'note': note, 'hits': [], 'count': 0,
            'native': False, 'java': False,
        }

    with tempfile.TemporaryDirectory(prefix='emu-signal-map-') as workdir:
        for label, text in iter_sources(target, workdir):
            is_native = label.endswith('.so') or '/lib/' in label.replace('\\', '/')
            for (rx, pat, _g, _f, _n) in compiled:
                for m in rx.finditer(text):
                    r = results[pat]
                    r['count'] += 1
                    if is_native:
                        r['native'] = True
                    else:
                        r['java'] = True
                    if len(r['hits']) < 1000:
                        line_no = text.count('\n', 0, m.start()) + 1
                        r['hits'].append({'file': label, 'line': line_no,
                                          'match': m.group(0)[:80]})
    return results


def report(results, show_all):
    found = [r for r in results.values() if r['count'] > 0]
    if not found:
        print('No emulator-detection signals found.')
        print()
        print('That is a result, not an error. Either the app performs no emulator')
        print('detection, or its strings are encrypted. Check the native imports:')
        print('  llvm-readelf --dyn-syms lib/*/*.so | grep system_property')
        print('An app with __system_property_get imported and no readable property')
        print('strings is doing exactly that -- see README section 6.4.')
        return 0

    by_grade = {g: [] for g in GRADE_ORDER}
    for r in found:
        by_grade[r['grade']].append(r)

    total = sum(r['count'] for r in found)
    print('=' * 78)
    print('EMULATOR-DETECTION SURFACE')
    print('=' * 78)
    print('{} distinct signals, {} total hits'.format(len(found), total))
    print()
    print('  {:<6} {:>3}  {}'.format('GRADE', 'N', 'meaning'))
    print('  {:<6} {:>3}  {}'.format('-----', '--', '-------'))
    meanings = {
        'DEAD':  'MEASURED not to fire on a current AVD -- the control does not work',
        'NOISY': 'fires on real devices too -- false positives against your users',
        'HARD':  'costly to fake; survives a naive Java hook',
        'SOFT':  'one hook or one resetprop defeats it',
        'INFO':  'context only, never a verdict alone',
    }
    for g in GRADE_ORDER:
        if by_grade[g]:
            print('  {:<6} {:>3}  {}'.format(g, len(by_grade[g]), meanings[g]))
    print()

    for g in GRADE_ORDER:
        if not by_grade[g]:
            continue
        print('-' * 78)
        print('{}  ({} signals)'.format(g, len(by_grade[g])))
        print('-' * 78)
        for r in sorted(by_grade[g], key=lambda x: -x['count']):
            where = []
            if r['java']:
                where.append('java/dex')
            if r['native']:
                where.append('NATIVE')
            print('  [{}] {}  ({} hits, {})'.format(
                r['family'], r['pattern'], r['count'], '+'.join(where) or '?'))
            print('        {}'.format(r['note']))
            shown = r['hits'] if show_all else r['hits'][:MAX_SAMPLES]
            for h in shown:
                print('        - {}:{}  {!r}'.format(h['file'], h['line'], h['match']))
            if not show_all and r['count'] > len(shown):
                print('        ... {} more (use --all)'.format(r['count'] - len(shown)))
            print()

    # The verdict block. This is the part worth reading.
    print('=' * 78)
    print('WHAT TO DO WITH THIS')
    print('=' * 78)
    n_dead = len(by_grade['DEAD'])
    n_noisy = len(by_grade['NOISY'])
    n_hard = len(by_grade['HARD'])
    any_native = any(r['native'] for r in found)

    if n_dead:
        print('* {} DEAD signal(s). These were measured NOT to fire on a stock'.format(n_dead))
        print('  Android 15 / API 35 AVD. If they are this app\'s only emulator')
        print('  detection, the control has never worked in production -- and saying')
        print('  so is usually worth more to the developer than any bypass.')
        print('  Confirm it: run the app on a stock AVD and watch it work. README 5.3.2.')
        print()
    if n_noisy:
        print('* {} NOISY signal(s). These fire on REAL devices. A retail Redmi'.format(n_noisy))
        print('  M2101K6P was measured setting qemu.hw.mainkeys and ro.kernel.qemu.gles,')
        print('  and reporting Build.BOOTLOADER == "unknown". If the app blocks on')
        print('  these it is refusing service to real customers. README 5.3.3.')
        print()
    if n_hard:
        print('* {} HARD signal(s). Budget real time: a Java hook will not be'.format(n_hard))
        print('  enough. Expect to work at the libc layer or to fake a population')
        print('  (sensors) rather than a value.')
        print()
    if any_native:
        print('* NATIVE hits present. Checks run before any Java code (JNI_OnLoad),')
        print('  so spawn with `frida -U -f`, never attach with -p. README 7.3.')
        print()
    print('* EVERY hit above is a LEAD, not a finding. A string is not a check:')
    print('  analytics SDKs read ro.hardware too. Cross-reference each to a BRANCH')
    print('  and find what that branch gates. Chapter 52 measured this funnel at')
    print('  16,836 hits -> 168 leads -> 2 survivors.')
    print()
    print('* Next: scripts/emu-trace.js to see which signal actually FIRES at run')
    print('  time. Tracing before hooking saves hours.')
    return 0


def main():
    ap = argparse.ArgumentParser(
        description='Map and grade the emulator-detection surface of an APK.')
    ap.add_argument('target', help='APK file, or an already-unpacked directory')
    ap.add_argument('--json', action='store_true', help='machine-readable output')
    ap.add_argument('--all', action='store_true',
                    help='show every hit rather than a sample per signal')
    args = ap.parse_args()

    if not os.path.exists(args.target):
        eprint('error: no such file or directory: {}'.format(args.target))
        return 2

    results = scan(args.target)

    if args.json:
        out = [r for r in results.values() if r['count'] > 0]
        print(json.dumps(out, indent=2))
        return 0
    return report(results, args.all)


if __name__ == '__main__':
    sys.exit(main())
