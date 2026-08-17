// enumerate-ranges.js -- what Process.enumerateRanges() is actually looking at,
//                        proved by reading /proc/self/maps from inside the same
//                        process and diffing the two.
//
// WHY THIS SCRIPT EXISTS
//     Frida's Process.enumerateRanges() and Process.enumerateModules() feel like
//     magic the first time. They are not: they are a parse of /proc/self/maps
//     performed inside the target process, plus a little tidying. Once you have
//     seen the two side by side you stop guessing about what the API can and
//     cannot tell you, and you stop being surprised when a region you can see in
//     maps is missing from the JavaScript, or vice versa.
//
//     There is also a practical reason. On a stock Android 13 device an ordinary
//     `adb shell` CANNOT read another app's maps:
//
//         $ adb shell head -3 /proc/$(pidof zygote64)/maps
//         head: /proc/541/maps: Permission denied
//
//     SELinux denies the shell domain access to an app's /proc entries. But an
//     agent injected into the app is running AS the app, so /proc/self/maps is
//     its own file and opens without complaint. That is the whole trick, and it
//     is why the maps-reading labs in this chapter go through Frida rather than
//     through adb.
//
// HOW TO RUN
//     # host -- attach to a running app
//     frida -U -n com.example.target -l enumerate-ranges.js
//
//     # host -- spawn, so you see the address space before it settles
//     frida -U -f com.example.target -l enumerate-ranges.js --no-pause
//
//     # host -- non-interactive, capture to a file
//     frida -U -n com.example.target -l enumerate-ranges.js -o ranges.txt
//
//     Then, from the REPL:
//         rpc.exports.summary()               // counts and totals
//         rpc.exports.diff()                  // enumerateRanges vs maps
//         rpc.exports.maps()                  // the raw /proc/self/maps text
//         rpc.exports.modules()               // every loaded module and its base
//         rpc.exports.rwx()                   // writable+executable ranges only
//         rpc.exports.find('libnative-lib')   // one module, segment by segment
//         rpc.exports.dumpMapsTo('/data/local/tmp/target-maps.txt')
//
//     The last one is the bridge to the rest of this chapter: pull the file off
//     the device and feed it to maps-analyse.py.
//
//         # host
//         adb pull /data/local/tmp/target-maps.txt
//         python3 maps-analyse.py target-maps.txt
//
// REQUIREMENTS
//     Frida 12 or newer on the host, frida-server of the same version on the
//     device, and the ability to attach -- which in practice means a rooted
//     device, an emulator, or a debuggable build. See 53-Frida for getting that
//     far; this script assumes you already have.
//
//     It reads /proc/self/maps through libc's fopen/fgets rather than through
//     Frida's File API, because the File API gained its read methods only in
//     recent versions and this script should not stop working on an older
//     frida-server that somebody is stuck with.
//
// WHAT THIS SCRIPT WILL *NOT* TELL YOU
//     - What is inside any range. It reports boundaries, permissions and
//       provenance. Reading contents is Memory.readByteArray and Memory.scan,
//       and the honest warning that goes with them is in README section 7.4.
//     - Whether an RWX range is malicious. ART's JIT owns one in every app.
//       See maps-analyse.py, which applies the same reasoning to a capture.
//     - Anything about the Java heap's CONTENTS. Frida's Java API and a heap
//       dump are the tools for that; 13-ART is the chapter.
//     - Whether the layout is randomised. One snapshot cannot show that. And an
//       Android app is forked from the Zygote without exec, so its library
//       layout is INHERITED and identical across every app on the device until
//       reboot -- which is README section 3.5, and which is the single most
//       important thing to understand before you draw any ASLR conclusion from
//       what this script prints.
//     - Ranges belonging to any other process. Everything here is self.
//
// A NOTE ON HONESTY
//     This agent is itself mapped into the target. Some of the ranges it reports
//     are Frida's own -- frida-agent, gum-js-loop, the V8 or QuickJS heap. They
//     were not there before you attached. The diff below labels them rather than
//     hiding them, because a report that quietly filters out the observer's own
//     footprint is a report that has started lying to you.

'use strict';

// ---------------------------------------------------------------------------
// Reading /proc/self/maps from inside the target, via libc
// ---------------------------------------------------------------------------

var libcName = Process.platform === 'darwin' ? 'libSystem.B.dylib' : 'libc.so';

function resolve(name, ret, args) {
  var addr = Module.findExportByName(libcName, name);
  if (addr === null) {
    addr = Module.findExportByName(null, name);
  }
  if (addr === null) {
    throw new Error('cannot resolve ' + name + ' in ' + libcName);
  }
  return new NativeFunction(addr, ret, args);
}

var fopen = resolve('fopen', 'pointer', ['pointer', 'pointer']);
var fgets = resolve('fgets', 'pointer', ['pointer', 'int', 'pointer']);
var fclose = resolve('fclose', 'int', ['pointer']);

/**
 * Read a text file the way C would. Returns the whole thing as one string.
 *
 * Note the buffer size: 4096. A /proc/<pid>/maps line is at most a few hundred
 * bytes because PATH_MAX is 4096 and the fixed fields are short, so one fgets
 * per line is safe. If you copy this for a file with longer lines, fgets will
 * silently split them and your parser will see fragments.
 */
function readTextFile(path) {
  var pathBuf = Memory.allocUtf8String(path);
  var modeBuf = Memory.allocUtf8String('r');
  var fp = fopen(pathBuf, modeBuf);
  if (fp.isNull()) {
    throw new Error('cannot open ' + path);
  }
  var buf = Memory.alloc(4096);
  var chunks = [];
  try {
    while (!fgets(buf, 4096, fp).isNull()) {
      chunks.push(buf.readUtf8String());
    }
  } finally {
    fclose(fp);
  }
  return chunks.join('');
}

// ---------------------------------------------------------------------------
// Parsing maps
// ---------------------------------------------------------------------------

var MAPS_RE =
  /^([0-9a-f]+)-([0-9a-f]+)\s+([rwxsp-]{4})\s+([0-9a-f]+)\s+(\S+)\s+(\d+)\s*(.*)$/;

function parseMaps(text) {
  var out = [];
  var lines = text.split('\n');
  for (var i = 0; i < lines.length; i++) {
    var m = MAPS_RE.exec(lines[i]);
    if (m === null) {
      continue;
    }
    out.push({
      start: m[1],
      end: m[2],
      perms: m[3],
      offset: m[4],
      dev: m[5],
      inode: parseInt(m[6], 10),
      path: m[7].trim(),
      size: parseInt(m[2], 16) - parseInt(m[1], 16)
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

function hex(p) {
  // Frida NativePointers print with a 0x prefix and no leading zeros; maps
  // prints bare hex. Normalising both to a padded bare form is the only way
  // the two lists line up when you read them side by side.
  var s = (typeof p === 'string') ? p : p.toString(16).replace(/^0x/, '');
  while (s.length < 12) {
    s = '0' + s;
  }
  return s;
}

function human(n) {
  var units = ['B', 'KiB', 'MiB', 'GiB'];
  var i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return (i === 0 ? n + ' B' : n.toFixed(1) + ' ' + units[i]);
}

function isFridaOwn(path) {
  if (!path) {
    return false;
  }
  return /frida|gum-js-loop|gmain|linjector|re\.frida/i.test(path);
}

// ---------------------------------------------------------------------------
// The core: enumerateRanges, and the same thing read from maps
// ---------------------------------------------------------------------------

function collectRanges() {
  // '---' means "every protection, including none". Passing 'r--' would give
  // you only readable ranges and silently drop every PROT_NONE guard page --
  // which is exactly the set you want when you are looking for guard pages.
  return Process.enumerateRanges('---');
}

function summary() {
  var ranges = collectRanges();
  var mapsText = readTextFile('/proc/self/maps');
  var maps = parseMaps(mapsText);

  var totalR = 0, execR = 0, wxR = 0, noneR = 0;
  ranges.forEach(function (r) {
    totalR += r.size;
    if (r.protection.indexOf('x') >= 0) {
      execR += r.size;
      if (r.protection.indexOf('w') >= 0) {
        wxR += r.size;
      }
    }
    if (r.protection === '---') {
      noneR += r.size;
    }
  });

  var totalM = 0;
  maps.forEach(function (m) { totalM += m.size; });

  var lines = [];
  lines.push('=== Process ===');
  lines.push('  pid          ' + Process.id);
  lines.push('  arch         ' + Process.arch);
  lines.push('  platform     ' + Process.platform);
  lines.push('  pointer size ' + Process.pointerSize + ' bytes');
  lines.push('  page size    ' + Process.pageSize + ' bytes');
  lines.push('');
  lines.push('=== Process.enumerateRanges("---") ===');
  lines.push('  ranges                  ' + ranges.length);
  lines.push('  total size              ' + human(totalR));
  lines.push('  executable              ' + human(execR));
  lines.push('  writable AND executable ' + human(wxR));
  lines.push('  PROT_NONE (guard pages) ' + human(noneR));
  lines.push('');
  lines.push('=== /proc/self/maps, read from inside this process ===');
  lines.push('  lines                   ' + maps.length);
  lines.push('  total size              ' + human(totalM));
  lines.push('');
  lines.push('  If those two counts differ, that is expected and the reason is');
  lines.push('  in diff(). Frida coalesces adjacent ranges with identical');
  lines.push('  permissions; the kernel does not always merge the same ones.');
  lines.push('');
  lines.push('=== Modules ===');
  var mods = Process.enumerateModules();
  lines.push('  loaded modules          ' + mods.length);
  var fridaMods = mods.filter(function (m) { return isFridaOwn(m.path || m.name); });
  lines.push('  of which are Frida\'s    ' + fridaMods.length +
             '   <- these were not here before you attached');
  return lines.join('\n');
}

/**
 * The point of the whole script: line the two views up and report every place
 * they disagree.
 */
function diff() {
  var ranges = collectRanges();
  var maps = parseMaps(readTextFile('/proc/self/maps'));

  var byStart = {};
  maps.forEach(function (m) { byStart[m.start.replace(/^0+/, '')] = m; });

  var lines = [];
  lines.push('=== ranges reported by Frida but NOT starting at a maps line ===');
  lines.push('');
  var mismatched = 0;
  ranges.forEach(function (r) {
    var key = r.base.toString(16).replace(/^0x/, '').replace(/^0+/, '');
    if (!(key in byStart)) {
      mismatched++;
      if (mismatched <= 20) {
        lines.push('  ' + hex(r.base) + ' ' + r.protection + ' ' +
                   pad(human(r.size), 10) + '  ' +
                   (r.file ? r.file.path : '(anonymous)'));
      }
    }
  });
  if (mismatched === 0) {
    lines.push('  none -- every Frida range begins exactly at a maps line.');
  } else {
    lines.push('');
    lines.push('  ' + mismatched + ' range(s). This is normal: Frida COALESCES');
    lines.push('  adjacent ranges that share a protection into one object, so a');
    lines.push('  coalesced range begins at the first of the group and the');
    lines.push('  others have no line of their own. It is not a sign that Frida');
    lines.push('  is hiding anything, but it does mean you must not treat one');
    lines.push('  Frida range as one kernel VMA.');
  }

  lines.push('');
  lines.push('=== fields maps has that Frida does not expose ===');
  lines.push('');
  lines.push('  MAP_SHARED vs MAP_PRIVATE   maps prints the 4th permission');
  lines.push('                              character, s or p. Frida\'s');
  lines.push('                              protection string is three');
  lines.push('                              characters and drops it. A shared');
  lines.push('                              writable mapping is a very');
  lines.push('                              different security proposition');
  lines.push('                              from a private one, so if that');
  lines.push('                              matters, read maps.');
  lines.push('  inode and device            gone. You cannot tell from Frida');
  lines.push('                              alone whether two mappings of the');
  lines.push('                              same path are the same FILE.');
  lines.push('  " (deleted)"                gone. Frida reports file.path');
  lines.push('                              without the marker, so a mapping');
  lines.push('                              whose file has been unlinked looks');
  lines.push('                              exactly like one whose file is');
  lines.push('                              still there. That is the single');
  lines.push('                              most important omission for');
  lines.push('                              anyone hunting dropped payloads.');
  lines.push('');
  var deleted = maps.filter(function (m) { return /\(deleted\)$/.test(m.path); });
  lines.push('  deleted-but-mapped files in THIS process: ' + deleted.length);
  deleted.slice(0, 15).forEach(function (m) {
    lines.push('      ' + m.start + '-' + m.end + ' ' + m.perms + '  ' + m.path);
  });

  lines.push('');
  lines.push('=== Frida\'s own footprint ===');
  lines.push('');
  var own = maps.filter(function (m) { return isFridaOwn(m.path); });
  lines.push('  ' + own.length + ' mapping(s) in maps look like Frida\'s.');
  own.slice(0, 20).forEach(function (m) {
    lines.push('      ' + m.start + '-' + m.end + ' ' + m.perms + '  ' + m.path);
  });
  lines.push('');
  lines.push('  Anything you report about this process\'s memory has to');
  lines.push('  subtract these. An anti-tamper check that counts RWX regions');
  lines.push('  will count yours too -- which is how instrumentation gets');
  lines.push('  detected, and is 37-RootDetection\'s subject.');
  return lines.join('\n');
}

function pad(s, n) {
  s = String(s);
  while (s.length < n) {
    s = ' ' + s;
  }
  return s;
}

function rwx() {
  var out = [];
  Process.enumerateRanges('rwx').forEach(function (r) {
    out.push(hex(r.base) + ' ' + pad(human(r.size), 10) + '  ' +
             (r.file ? r.file.path : '(anonymous)'));
  });
  if (out.length === 0) {
    return 'No writable+executable ranges. Unusual for an app process with a ' +
           'live JIT, so check that the app has actually started running Java ' +
           'code before concluding anything.';
  }
  return out.join('\n') +
    '\n\nEvery one of these is a QUESTION, not a finding. ART\'s JIT code cache' +
    '\nis RWX in every Android app ever shipped. What matters is who wrote the' +
    '\nbytes and whether attacker-controlled input reaches them.';
}

function modules() {
  var out = [];
  out.push(pad('BASE', 14) + ' ' + pad('SIZE', 10) + '  NAME');
  Process.enumerateModules().forEach(function (m) {
    out.push(hex(m.base) + ' ' + pad(human(m.size), 10) + '  ' + m.name +
             (isFridaOwn(m.path || m.name) ? '   <- Frida\'s own' : ''));
  });
  out.push('');
  out.push('BASE is what you add to a static address from Ghidra. It is the');
  out.push('same number maps-analyse.py calls LOAD BASE, and Frida computes it');
  out.push('the same way: the lowest mapping of the file at file offset 0.');
  return out.join('\n');
}

function find(needle) {
  var maps = parseMaps(readTextFile('/proc/self/maps'));
  var hits = maps.filter(function (m) {
    return m.path.toLowerCase().indexOf(needle.toLowerCase()) >= 0;
  });
  if (hits.length === 0) {
    return 'no mapping whose path contains ' + JSON.stringify(needle);
  }
  var out = [];
  hits.forEach(function (m) {
    out.push(m.start + '-' + m.end + ' ' + m.perms + ' off=' + m.offset +
             ' ' + pad(human(m.size), 10) + '  ' + m.path);
  });
  var zero = hits.filter(function (m) { return parseInt(m.offset, 16) === 0; });
  out.push('');
  if (zero.length > 0) {
    out.push('load base = 0x' + zero[0].start +
             '   (lowest mapping at file offset 0)');
    var fridaBase = Module.findBaseAddress(needle);
    if (fridaBase !== null) {
      out.push('Module.findBaseAddress = ' + fridaBase +
               (('0x' + zero[0].start) === fridaBase.toString()
                 ? '   -- agrees' : '   -- DISAGREES, investigate'));
    }
  } else {
    out.push('No mapping of this file has file offset 0. It is probably mapped');
    out.push('straight out of an APK, where the .so starts part way into the');
    out.push('ZIP. Do NOT use the lowest address as a load base here.');
  }
  return out.join('\n');
}

function mapsText() {
  return readTextFile('/proc/self/maps');
}

function dumpMapsTo(path) {
  var text = readTextFile('/proc/self/maps');
  var f = new File(path, 'w');
  f.write(text);
  f.flush();
  f.close();
  return 'wrote ' + text.split('\n').length + ' lines to ' + path +
         '\nNow: adb pull ' + path + ' && python3 maps-analyse.py ' +
         path.split('/').pop();
}

// ---------------------------------------------------------------------------

rpc.exports = {
  summary: summary,
  diff: diff,
  rwx: rwx,
  modules: modules,
  find: find,
  maps: mapsText,
  dumpMapsTo: dumpMapsTo
};

console.log(summary());
console.log('');
console.log('rpc.exports: summary() diff() rwx() modules() find(name) maps() ' +
            'dumpMapsTo(path)');
