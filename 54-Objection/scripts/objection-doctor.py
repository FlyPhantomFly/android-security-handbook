#!/usr/bin/env python3
# scripts/objection-doctor.py
#
# PURPOSE
#   Report the objection / frida-tools / frida / frida-server version quadruple,
#   the device ABI, and whether the combination can work -- BEFORE you waste an
#   afternoon on a session that was never going to connect.
#
#   Version skew is the single most common real-world Objection blocker, and it
#   is confusing because THREE independent relationships must hold and only one
#   of them produces a clear error message:
#
#     1. objection  -> frida python package    (a pip dependency; fails loudly)
#     2. frida      -> frida-server on device  (a wire protocol; MAJOR must match)
#     3. agent.js   -> the Frida JS API in the server  (nothing checks this at
#                      all -- it fails per-command, at run time, after a
#                      perfectly successful "Agent injected and responds ok!")
#
#   Relationship 3 is why "it connected, so my versions are fine" is wrong, and
#   why this script exists rather than a one-line `frida --version`.
#
# USAGE
#   # host -- check everything it can reach
#   python3 -B scripts/objection-doctor.py
#
#   # host -- pick a device when several are attached
#   python3 -B scripts/objection-doctor.py --serial 84f7a024
#
#   # host -- tell it where frida-server lives on the device
#   python3 -B scripts/objection-doctor.py --server-path /data/local/tmp/fs
#
#   # host -- machine-readable, for CI or a session manifest
#   python3 -B scripts/objection-doctor.py --json
#
#   Run with `python3 -B`. Without -B, an import of the objection package can
#   leave a __pycache__ directory behind, and this repository treats build
#   artefacts as a defect.
#
# REQUIREMENTS
#   * Python 3.7+
#   * Nothing else is mandatory. Every probe degrades gracefully: if objection
#     is not installed, or adb is missing, or no device is attached, the script
#     reports UNKNOWN for that row rather than failing.
#
# EXIT CODES
#   0  everything it could check is consistent
#   1  a definite incompatibility was found
#   2  it could not check enough to have an opinion
#
# WHAT THIS WILL *NOT* TELL YOU
#   * It will NOT tell you that your session will work. It checks versions.
#     Injection can still fail for reasons that have nothing to do with
#     versions: no root, SELinux denying execution from /data/local/tmp, a
#     32-bit target process under a 64-bit server, an app that kills itself when
#     instrumented, or a device with no frida-server running at all.
#   * It will NOT verify relationship 3 above. Nothing can, statically -- the
#     only test is to run a command that exercises the Java bridge and see
#     whether it throws. The script tells you WHEN to suspect it, not whether it
#     is true. If `env` works and `android hooking list classes` throws, that is
#     relationship 3, and no version number on this report will have predicted it.
#   * It will NOT check the ABI of the TARGET PROCESS, only of the device. A
#     64-bit device runs 32-bit processes, and a 64-bit frida-server cannot
#     inject into one. Read /proc/<pid>/maps for the real answer -- see
#     53-Frida section 7.1.1.
#   * It does NOT contact the network and will not tell you that a newer
#     objection exists. Objection itself does that, loudly, on every run.
#
# AUTHORISED TESTING ONLY.

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

UNKNOWN = None


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def run(cmd, timeout=25):
    """Run a command, return (rc, stdout+stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, shell=False)
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except FileNotFoundError:
        return 127, 'not found'
    except subprocess.TimeoutExpired:
        return 124, 'timed out'
    except Exception as e:                                   # pragma: no cover
        return 1, str(e)


def semver(v):
    """'16.1.6' -> (16, 1, 6). Missing parts become 0. None on failure."""
    if not v:
        return None
    m = re.match(r'^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?', str(v))
    if not m:
        return None
    return tuple(int(g) if g else 0 for g in m.groups())


def pkg_version(name):
    """Version of an installed distribution, without importing it."""
    try:
        from importlib.metadata import version, PackageNotFoundError
        try:
            return version(name)
        except PackageNotFoundError:
            return UNKNOWN
    except ImportError:                                       # Python < 3.8
        return UNKNOWN


# --------------------------------------------------------------------------- #
# probes
# --------------------------------------------------------------------------- #
def probe_host():
    """objection, frida and frida-tools versions on this workstation."""
    out = {
        'objection': pkg_version('objection'),
        'frida': pkg_version('frida'),
        'frida_tools': pkg_version('frida-tools'),
        'python': '%d.%d.%d' % sys.version_info[:3],
        'agent_js': UNKNOWN,
        'agent_js_bytes': UNKNOWN,
    }

    # The frida CLI may resolve to a different install than the python package.
    if out['frida'] is UNKNOWN and shutil.which('frida'):
        rc, txt = run(['frida', '--version'])
        if rc == 0:
            out['frida'] = txt.strip().splitlines()[0].strip()

    # Locate agent.js without importing objection, so no __pycache__ is written
    # and a broken install cannot take this script down with it.
    for base in sys.path:
        cand = os.path.join(base, 'objection', 'agent.js')
        if os.path.isfile(cand):
            out['agent_js'] = cand
            out['agent_js_bytes'] = os.path.getsize(cand)
            break

    return out


def probe_device(serial=None, server_path=None):
    """Device model, API, ABI, root, and the frida-server version if reachable."""
    dev = {
        'adb': bool(shutil.which('adb')),
        'serial': serial,
        'model': UNKNOWN, 'sdk': UNKNOWN, 'abi': UNKNOWN,
        'rooted': UNKNOWN,
        'server_path': server_path,
        'server_version': UNKNOWN,
        'server_running': UNKNOWN,
        'note': None,
    }
    if not dev['adb']:
        dev['note'] = 'adb is not on PATH'
        return dev

    base = ['adb'] + (['-s', serial] if serial else [])

    rc, txt = run(base + ['devices'])
    lines = [l for l in txt.splitlines()[1:] if l.strip() and '\tdevice' in l]
    if not lines:
        dev['note'] = 'no device in state "device"'
        return dev
    if len(lines) > 1 and not serial:
        dev['note'] = ('%d devices attached -- pass --serial, or every adb call '
                       'below is ambiguous' % len(lines))
        return dev
    if not serial:
        dev['serial'] = lines[0].split('\t')[0]

    for key, prop in (('model', 'ro.product.model'),
                      ('sdk', 'ro.build.version.sdk'),
                      ('abi', 'ro.product.cpu.abi')):
        rc, txt = run(base + ['shell', 'getprop', prop])
        if rc == 0 and txt.strip():
            dev[key] = txt.strip()

    rc, txt = run(base + ['shell', 'su -c id'])
    dev['rooted'] = ('uid=0' in txt)

    # Is a frida-server process alive? Cheap, and it answers the question people
    # actually have when a connect fails.
    rc, txt = run(base + ['shell', 'ps -A -o NAME'])
    if rc == 0:
        dev['server_running'] = ('frida-server' in txt or 'frida' in txt.lower())

    # The version of the binary on disk. Try the caller's path, then the usual
    # one. Note this is the binary's version, which is not necessarily the
    # version of the process currently RUNNING -- if someone swapped the file
    # without restarting, those differ, and that is a real way to lose an hour.
    candidates = [server_path] if server_path else []
    candidates += ['/data/local/tmp/frida-server']
    for path in candidates:
        if not path:
            continue
        rc, txt = run(base + ['shell', "su -c '%s --version'" % path], timeout=30)
        m = re.search(r'(\d+\.\d+\.\d+)', txt)
        if m:
            dev['server_version'] = m.group(1)
            dev['server_path'] = path
            break

    return dev


def probe_wire():
    """Can the frida python bindings actually see a device? Uses frida-ps."""
    if not shutil.which('frida-ps'):
        return {'reachable': UNKNOWN, 'detail': 'frida-ps not on PATH'}
    rc, txt = run(['frida-ps', '-U'], timeout=40)
    if rc == 0 and 'PID' in txt:
        return {'reachable': True, 'detail': '%d process rows' % max(0, len(txt.splitlines()) - 2)}
    return {'reachable': False, 'detail': txt.strip().splitlines()[0] if txt.strip() else 'no output'}


# --------------------------------------------------------------------------- #
# adjudication
# --------------------------------------------------------------------------- #
def adjudicate(host, dev, wire):
    """Return (verdicts, worst) where worst is 'ok' | 'warn' | 'fail' | 'unknown'."""
    v = []
    rank = {'ok': 0, 'unknown': 1, 'warn': 2, 'fail': 3}
    worst = 'ok'

    def add(level, headline, detail):
        nonlocal worst
        v.append({'level': level, 'headline': headline, 'detail': detail})
        if rank[level] > rank[worst]:
            worst = level

    o, f, ft = host['objection'], host['frida'], host['frida_tools']
    fs = dev['server_version']
    so, sf, sfs = semver(o), semver(f), semver(fs)

    # 1. objection <- frida.  objection 1.11 declares frida>=14, frida-tools>=6.
    if so and sf:
        if sf[0] < 14:
            add('fail', 'objection requires frida >= 14.0.0',
                'found frida %s. objection will not import cleanly.' % f)
        elif so < (1, 12) and sf[0] >= 17:
            add('fail', 'objection %s predates frida 17' % o,
                'objection 1.11.x ships an agent built against the frida 16 '
                'JavaScript API. It will inject, print "Agent injected and '
                'responds ok!", and then throw on Java-bridge commands. '
                'Use objection >= 1.12 with frida 17.x.')
        else:
            add('ok', 'objection %s with frida %s' % (o, f), 'dependency satisfied')
    else:
        add('unknown', 'could not read objection and/or frida version',
            'objection=%s frida=%s' % (o, f))

    # frida-tools is a dependency but not on the critical path; note only.
    if ft:
        add('ok', 'frida-tools %s' % ft,
            'supplies frida-ps / frida-ls-devices; not on the injection path')

    # 2. frida <-> frida-server.  MAJOR must match. This is the loud one.
    if sf and sfs:
        if sf[0] != sfs[0]:
            add('fail', 'frida MAJOR mismatch: host %s vs device %s' % (f, fs),
                'The wire protocol changes between major versions and frida '
                'does not negotiate down. Every command will fail at connect.')
        elif sf[:2] != sfs[:2]:
            add('warn', 'frida MINOR skew: host %s vs device %s' % (f, fs),
                'Same major, so the protocol should hold, but this pairing is '
                'not the one either side was tested against. If commands '
                'misbehave, align them exactly before investigating anything else.')
        elif sf != sfs:
            add('warn', 'frida PATCH skew: host %s vs device %s' % (f, fs),
                'Almost certainly fine. Align them anyway if you are about to '
                'spend a day on this target.')
        else:
            add('ok', 'frida %s on both sides' % f, 'exact match')
    else:
        add('unknown', 'could not compare host frida to frida-server',
            'host=%s device=%s. If the device row is unknown, frida-server may '
            'simply not be deployed -- which is its own answer.' % (f, fs))

    # 3. root / gadget precondition.
    if dev['rooted'] is True:
        add('ok', 'device is rooted', 'frida-server injection is available')
    elif dev['rooted'] is False:
        add('warn', 'device is NOT rooted',
            'frida-server cannot inject. objection will report "Unable to '
            'connect to the frida server: need Gadget to attach on jailed '
            'Android". Your path is `objection patchapk`, and it changes the '
            'app signature. See README section 3.9.')

    # 4. is anything actually listening?
    if dev['server_running'] is False and dev['rooted'] is True:
        add('warn', 'no frida-server process seen on the device',
            'The binary may exist without running. Start it as root.')

    if wire.get('reachable') is True:
        add('ok', 'frida-ps -U reached the device', wire['detail'])
    elif wire.get('reachable') is False:
        add('warn', 'frida-ps -U did not return a process list', wire['detail'])

    # 5. agent presence -- the thing every command depends on.
    if host['agent_js']:
        add('ok', 'agent.js found (%s bytes)' % host['agent_js_bytes'],
            host['agent_js'])
    else:
        add('warn', 'agent.js not located on sys.path',
            'A development install needs the agent built. Every command will '
            'fail with "Unable to locate Objection agent sources".')

    return v, worst


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #
MARK = {'ok': '[ ok ]', 'warn': '[warn]', 'fail': '[FAIL]', 'unknown': '[ ?? ]'}


def human(host, dev, wire, verdicts, worst):
    def row(k, val):
        print('  %-22s %s' % (k, '(unknown)' if val in (None, '') else val))

    print()
    print('objection-doctor -- version triage for an Objection session')
    print('=' * 66)
    print('\nHOST')
    row('objection', host['objection'])
    row('frida (python)', host['frida'])
    row('frida-tools', host['frida_tools'])
    row('python', host['python'])
    row('agent.js', host['agent_js'])
    row('agent.js size', host['agent_js_bytes'])

    print('\nDEVICE')
    if dev.get('note'):
        print('  %s' % dev['note'])
    row('serial', dev['serial'])
    row('model', dev['model'])
    row('api level', dev['sdk'])
    row('device abi', dev['abi'])
    row('rooted', dev['rooted'])
    row('frida-server path', dev['server_path'])
    row('frida-server version', dev['server_version'])
    row('frida-server running', dev['server_running'])

    print('\nVERDICT')
    for item in verdicts:
        print('  %s %s' % (MARK[item['level']], item['headline']))
        for line in _wrap(item['detail'], 62):
            print('         %s' % line)

    print()
    if worst == 'fail':
        print('  RESULT: a definite incompatibility. Fix it before you start.')
    elif worst == 'warn':
        print('  RESULT: usable, with caveats above.')
    elif worst == 'unknown':
        print('  RESULT: not enough information to have an opinion.')
    else:
        print('  RESULT: consistent.')
    print('\n  Reminder: versions are necessary, not sufficient. A clean report')
    print('  here and a failing session means the problem is not versions --')
    print('  see README section 7.3, the four failure modes.')
    print()


def _wrap(text, width):
    if not text:
        return []
    words, line, out = str(text).split(), '', []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = (line + ' ' + w).strip()
    if line:
        out.append(line)
    return out


def main():
    ap = argparse.ArgumentParser(
        description='Report and adjudicate the objection/frida version triple.')
    ap.add_argument('--serial', '-s', default=None,
                    help='adb serial, when more than one device is attached')
    ap.add_argument('--server-path', default=None,
                    help='path to frida-server on the device')
    ap.add_argument('--json', action='store_true', help='machine-readable output')
    ap.add_argument('--no-device', action='store_true',
                    help='skip every device probe (host-only report)')
    args = ap.parse_args()

    host = probe_host()
    if args.no_device:
        dev = {'adb': False, 'serial': None, 'model': None, 'sdk': None,
               'abi': None, 'rooted': None, 'server_path': None,
               'server_version': None, 'server_running': None,
               'note': 'device probes skipped (--no-device)'}
        wire = {'reachable': None, 'detail': 'skipped'}
    else:
        dev = probe_device(args.serial, args.server_path)
        wire = probe_wire()

    verdicts, worst = adjudicate(host, dev, wire)

    if args.json:
        print(json.dumps({'host': host, 'device': dev, 'wire': wire,
                          'verdicts': verdicts, 'result': worst},
                         indent=2, sort_keys=True))
    else:
        human(host, dev, wire, verdicts, worst)

    return {'ok': 0, 'warn': 0, 'fail': 1, 'unknown': 2}[worst]


if __name__ == '__main__':
    sys.exit(main())
