/*
 * adbd-trace.js -- watch the ADB wire protocol from INSIDE adbd, by decoding
 *                  the 24-byte headers as they are read from and written to
 *                  the transport file descriptors.
 *
 * WHY THIS EXISTS
 *     Chapter 60's Python client shows you the protocol from the host end.
 *     This shows you the same messages from the device end, in the process
 *     that actually implements them. Two things become obvious only from this
 *     side:
 *
 *       1. The USB transport really is just read(2) and write(2) on two file
 *          descriptors -- /dev/usb-ffs/adb/ep1 (bulk OUT, host to device) and
 *          ep2 (bulk IN, device to host). There is no magic USB layer inside
 *          adbd; the kernel's FunctionFS does that part.
 *       2. Every stream you have open -- your shell, a running logcat, an
 *          install -- is interleaved on those same two descriptors, and the
 *          only thing separating them is the id pair in arg0/arg1.
 *
 * HOW TO RUN
 *     # device must be ROOTED; adbd runs as uid 2000 and Frida needs to
 *     # ptrace it. frida-server must already be running as root.
 *     frida -U -n adbd -l adbd-trace.js
 *
 *     # only the headers, no payload preview
 *     frida -U -n adbd -l adbd-trace.js -e 'PREVIEW=0'   # see CONFIG below
 *
 *     Then, in a second terminal on the host, do something over adb:
 *         adb shell id
 *         adb shell logcat -d | tail
 *         adb install some.apk
 *     and watch the message sequence appear.
 *
 * REQUIREMENTS
 *     Frida 15+ on the host, a matching frida-server running as root on the
 *     device, and root on the device. Nothing else. It hooks libc's read and
 *     write, which are always exported, so it does not depend on any adbd
 *     symbol and will not break when adbd is updated through its APEX.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *     - The contents of an authenticated session's key material. It prints
 *       message TYPES and lengths; for A_AUTH it deliberately prints only the
 *       length and the auth type, never the token, the signature or the key.
 *     - Anything on a device you are not root on. adbd is uid 2000 in the
 *       adbd SELinux domain; attaching to it needs root, and on some builds
 *       needs SELinux to be permissive for the ptrace to succeed.
 *     - A complete picture on the TCP transport. Over TCP adbd may use
 *       recv/send rather than read/write depending on the build; this script
 *       hooks read/write and also recv/send where they exist, but if your
 *       build routes through another syscall wrapper you will see nothing and
 *       should check with `strace -p $(pidof adbd)` first.
 *     - Reassembled stream content. It previews the first bytes of a payload
 *       so you can recognise a service string or a shell response; it does
 *       not reassemble a stream across messages. Use the Python client for
 *       that.
 *     - Anything if adbd dies. Attaching to the daemon you are attached
 *       THROUGH is inherently risky: if the hook throws, you lose your shell
 *       and `adb kill-server` will not bring it back. Use a device you can
 *       physically reach.
 */

'use strict';

/* ---------------------------------------------------------------- CONFIG */

var PREVIEW = 48;      /* bytes of payload to preview; 0 disables it */
var SHOW_EMPTY = true; /* show A_OKAY, which carries no payload */

/* ------------------------------------------------------------- PROTOCOL */

/*
 * Four ASCII characters read as a little-endian uint32. "OPEN" is
 * 4f 50 45 4e on the wire, which read LE is 0x4e45504f.
 */
var NAMES = {
  0x434e5953: 'A_SYNC',
  0x4e584e43: 'A_CNXN',
  0x48545541: 'A_AUTH',
  0x534c5453: 'A_STLS',
  0x4e45504f: 'A_OPEN',
  0x59414b4f: 'A_OKAY',
  0x45545257: 'A_WRTE',
  0x45534c43: 'A_CLSE',
};

var AUTH_TYPE = { 1: 'TOKEN', 2: 'SIGNATURE', 3: 'RSAPUBLICKEY' };

/*
 * A 24-byte buffer is a header only if the command is one we know AND the
 * magic field is its complement. That second test is what stops us decoding
 * ordinary 24-byte payload chunks as headers -- the chance of a random
 * 24-byte read satisfying it is about one in four billion.
 */
function decodeHeader(p, n) {
  if (n !== 24) return null;
  var cmd = p.readU32() >>> 0;
  var name = NAMES[cmd];
  if (!name) return null;
  var magic = p.add(20).readU32() >>> 0;
  if (magic !== ((cmd ^ 0xffffffff) >>> 0)) return null;
  return {
    cmd: cmd,
    name: name,
    arg0: p.add(4).readU32() >>> 0,
    arg1: p.add(8).readU32() >>> 0,
    len: p.add(12).readU32() >>> 0,
    check: p.add(16).readU32() >>> 0,
  };
}

function printable(bytes) {
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i];
    out += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
  }
  return out;
}

/* Per-fd state: after a header we expect `len` bytes of payload. */
var expect = {};

function describe(dir, fd, h) {
  var extra = '';
  if (h.name === 'A_AUTH') {
    /* type only. Never the token, never the signature, never the key. */
    extra = '  type=' + (AUTH_TYPE[h.arg0] || h.arg0);
  } else if (h.name === 'A_CNXN') {
    extra = '  version=0x' + h.arg0.toString(16) + ' maxdata=' + h.arg1;
  } else {
    extra = '  ids=(' + h.arg0 + ',' + h.arg1 + ')';
  }
  return dir + ' fd=' + fd + '  ' + h.name + extra +
         '  len=' + h.len + '  check=0x' + h.check.toString(16);
}

function onData(dir, fd, buf, n) {
  var h = decodeHeader(buf, n);
  if (h) {
    if (h.len === 0 && !SHOW_EMPTY) return;
    console.log(describe(dir, fd, h));
    if (h.len > 0) expect[dir + fd] = h;
    return;
  }

  var pending = expect[dir + fd];
  if (!pending) return;
  delete expect[dir + fd];

  if (PREVIEW > 0 && pending.name !== 'A_AUTH') {
    var take = Math.min(PREVIEW, n);
    var bytes = buf.readByteArray(take);
    console.log('        payload[' + n + '] |' +
                printable(new Uint8Array(bytes)) + '|');
  } else if (pending.name === 'A_AUTH') {
    console.log('        payload[' + n + '] (auth material -- not printed)');
  }
}

/* ---------------------------------------------------------------- HOOKS */

function hookRead(name) {
  var addr = Module.findExportByName(null, name);
  if (addr === null) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.fd = args[0].toInt32();
      this.buf = args[1];
    },
    onLeave: function (retval) {
      var n = retval.toInt32();
      if (n <= 0) return;
      onData('<-', this.fd, this.buf, n);
    },
  });
  return true;
}

function hookWrite(name) {
  var addr = Module.findExportByName(null, name);
  if (addr === null) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      onData('->', args[0].toInt32(), args[1], args[2].toInt32());
    },
  });
  return true;
}

var hooked = [];
['read', 'recv'].forEach(function (n) { if (hookRead(n)) hooked.push(n); });
['write', 'send'].forEach(function (n) { if (hookWrite(n)) hooked.push(n); });

console.log('[+] adbd-trace: hooked ' + hooked.join(', '));
console.log('[+] "->" is adbd writing to the host, "<-" is adbd reading from it.');
console.log('[+] Run an adb command in another terminal now.');
console.log('[+] A_AUTH payloads are deliberately not printed.');

/*
 * Optional: show which file descriptors are the USB endpoints, so the fd
 * numbers above mean something. Reading /proc/self/fd is cheap and this runs
 * once at attach time.
 */
try {
  var listdir = new NativeFunction(
      Module.getExportByName(null, 'readlink'), 'long',
      ['pointer', 'pointer', 'ulong']);
  for (var fd = 0; fd < 64; fd++) {
    var path = Memory.allocUtf8String('/proc/self/fd/' + fd);
    var out = Memory.alloc(256);
    var r = listdir(path, out, 255);
    if (r > 0) {
      var target = out.readUtf8String(r.toNumber ? r.toNumber() : r);
      if (target && target.indexOf('usb-ffs') !== -1) {
        console.log('[+] fd ' + fd + ' -> ' + target);
      }
    }
  }
} catch (e) {
  console.log('[!] could not enumerate fds: ' + e.message);
}
