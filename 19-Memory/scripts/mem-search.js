// mem-search.js -- find a value in a live process's memory, and know what you
//                  have found when you do.
//
// WHY THIS SCRIPT EXISTS
//     Three other chapters point here for the same thing. 03 warns that a
//     secret held in memory can be recovered and says chapter 19 shows how; 13
//     says "see 19 for raw-memory scanning when the class name is unknown"; 53
//     says 19 owns "what Memory.scan is actually searching". This is that
//     script.
//
//     It exists in this form -- scan, then EXPLAIN THE HIT -- because the scan
//     is the easy half. Anyone can call Memory.scan. The half that decides
//     whether you have a finding is: which region did the hit land in, is that
//     region the native heap or the Java heap or a read-only page of a mapped
//     file, is it still live or is it residue in a freed block, and is it one
//     copy or fourteen? A hit with no answer to those questions is a screenshot,
//     not evidence.
//
// HOW TO RUN
//     # host
//     frida -U -n com.example.target -l mem-search.js
//
//     # from the REPL
//     rpc.exports.text('Bearer ')                 // a UTF-8 substring
//     rpc.exports.text('hunter2', 'rw-')          // only writable memory
//     rpc.exports.hex('de ad be ef')              // a byte pattern
//     rpc.exports.hex('41 ?? 43')                 // ?? is a wildcard byte
//     rpc.exports.utf16('password')               // Java String backing store
//     rpc.exports.where('0x7311223344')           // explain one address
//     rpc.exports.context('0x7311223344', 128)    // hexdump around it
//     rpc.exports.regions()                       // what would be searched
//     rpc.exports.scrubTest('hunter2')            // is it STILL there after
//                                                 // the app says it cleared it
//
// REQUIREMENTS
//     Frida 12+ and a matching frida-server; attach permission on the target.
//
// WHAT THIS SCRIPT WILL *NOT* TELL YOU
//     - That finding a secret in memory is, by itself, a vulnerability. It
//       usually is not. A process that is using a token has to hold it
//       somewhere, and an attacker who can read that process's memory has
//       already won by other means. The finding is real when the secret is
//       still present LONG AFTER it should have been cleared, when it is in a
//       region that outlives the session, when it is written somewhere it can
//       be reached without code execution -- a heap dump collected by a crash
//       reporter, a file, a log -- or when the threat model explicitly includes
//       a local attacker with debugging access. Say which of those applies, or
//       report it as informational and mean it.
//     - Where the value CAME FROM. A hit is an address, not a provenance. To
//       tie it to code you have to hook whatever wrote it.
//     - Everything. It searches mapped, readable regions of the process it is
//       in. A value that has been swapped out, that lives in a register, that
//       is in another process, or that is inside a region the scan skipped
//       because it was not readable, will not be found. A negative result from
//       this script is NOT proof that a secret is absent.
//     - Anything about the Java object graph. A hit inside
//       [anon:dalvik-main space] is a hit inside some object's bytes, and this
//       script cannot tell you which object. That is a heap dump's job:
//       `am dumpheap`, then MAT or Android Studio. Chapter 13.
//
// A NOTE ON SCALE
//     A modern app process reserves tens of gigabytes of address space, almost
//     all of it untouched. Scanning all of it is pointless and slow. This
//     script therefore skips regions with no read permission, skips regions
//     backed by read-only system files unless you ask for them, and caps how
//     much it will scan. Those defaults are stated in the output rather than
//     hidden, because a scan whose limits you cannot see is a scan whose
//     negative result means nothing.

'use strict';

var MAX_REGION_BYTES = 512 * 1024 * 1024;   // skip anything bigger than this
var MAX_HITS = 200;

// ---------------------------------------------------------------------------
// Choosing what to search
// ---------------------------------------------------------------------------

function isSystemFile(path) {
  return /^(\/system|\/apex|\/vendor|\/product|\/system_ext|\/odm)\//.test(path);
}

function candidateRanges(protection, includeSystem) {
  var out = [];
  Process.enumerateRanges(protection || 'r--').forEach(function (r) {
    if (r.size > MAX_REGION_BYTES) {
      return;
    }
    if (!includeSystem && r.file && isSystemFile(r.file.path)) {
      // Read-only pages of a system library are the same bytes on every
      // device. A hit there is a constant in a shipped file, not a secret the
      // app is holding, and including them buries the interesting hits.
      return;
    }
    out.push(r);
  });
  return out;
}

function describeRange(r) {
  if (r.file) {
    return r.file.path + '+0x' + r.file.offset.toString(16);
  }
  return '(anonymous)';
}

/**
 * Classify a region into something a report can say out loud.
 *
 * This is the part that turns a hit into a sentence. The names come from
 * Android's own PR_SET_VMA_ANON_NAME labels, which is why they can be trusted
 * to mean what they say.
 */
function classify(r) {
  // Frida does not expose the [anon:NAME] label, so fall back to the module
  // list and to what the protection implies.
  var m = Process.findModuleByAddress(r.base);
  if (m !== null) {
    return {
      what: 'inside module ' + m.name,
      note: (r.protection.indexOf('w') < 0)
        ? 'a read-only page of a mapped file: this value is a CONSTANT in the ' +
          'file on disk, not runtime state. Find it with strings(1) instead.'
        : 'a writable data page of a loaded module: a global or static variable.'
    };
  }
  if (r.file) {
    return {
      what: 'file-backed anonymous-looking region ' + r.file.path,
      note: 'backed by a file; check whether that file is readable from disk.'
    };
  }
  return {
    what: 'anonymous memory',
    note: 'the native heap, a thread stack, or an ART space. Use where() on ' +
          'the exact address and read the [anon:] label in /proc/self/maps ' +
          '(enumerate-ranges.js dumps it) to say which.'
  };
}

// ---------------------------------------------------------------------------
// Pattern helpers
// ---------------------------------------------------------------------------

function textToPattern(s) {
  var bytes = [];
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c > 0x7f) {
      throw new Error('text() takes ASCII. For anything else use hex().');
    }
    bytes.push(('0' + c.toString(16)).slice(-2));
  }
  return bytes.join(' ');
}

/**
 * UTF-16LE, which is how a Java String's char[] is stored in the ART heap.
 *
 * This matters more than it sounds. Searching for the ASCII bytes of a
 * password will MISS it entirely if it is held in a Java String, because every
 * character is two bytes with a zero in between. Half the "we could not find
 * the secret" conclusions in the wild are this mistake.
 *
 * Since Android 6, ART also stores Latin-1 strings compressed to one byte per
 * character, so a plain ASCII search may find it after all. Try both. Never
 * conclude absence from one encoding.
 */
function utf16Pattern(s) {
  var bytes = [];
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    bytes.push(('0' + (c & 0xff).toString(16)).slice(-2));
    bytes.push(('0' + ((c >> 8) & 0xff).toString(16)).slice(-2));
  }
  return bytes.join(' ');
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

function scan(pattern, protection, includeSystem) {
  var ranges = candidateRanges(protection, includeSystem);
  var hits = [];
  var scanned = 0;
  var failed = 0;

  ranges.forEach(function (r) {
    if (hits.length >= MAX_HITS) {
      return;
    }
    try {
      var found = Memory.scanSync(r.base, r.size, pattern);
      scanned += r.size;
      found.forEach(function (h) {
        if (hits.length < MAX_HITS) {
          hits.push({ address: h.address, range: r });
        }
      });
    } catch (e) {
      // A range can disappear between enumeration and scan, or be
      // execute-only, or be a device mapping that faults on read. Counting
      // those rather than swallowing them is the difference between "not
      // found" and "not looked at".
      failed++;
    }
  });

  return { hits: hits, ranges: ranges.length, scanned: scanned, failed: failed };
}

function pad(s, n) {
  s = String(s);
  while (s.length < n) {
    s = s + ' ';
  }
  return s;
}

function human(n) {
  var u = ['B', 'KiB', 'MiB', 'GiB'];
  var i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return (i === 0 ? n + ' B' : n.toFixed(1) + ' ' + u[i]);
}

function reportScan(label, pattern, res) {
  var out = [];
  out.push('=== ' + label + ' ===');
  out.push('  pattern   ' + pattern);
  out.push('  regions   ' + res.ranges + ' searched, ' + res.failed +
           ' could not be read');
  out.push('  volume    ' + human(res.scanned));
  out.push('  hits      ' + res.hits.length +
           (res.hits.length >= MAX_HITS ? ' (capped)' : ''));
  out.push('');
  if (res.hits.length === 0) {
    out.push('  Nothing found. Before you write "the secret is not in memory":');
    out.push('    - a Java String is UTF-16 or Latin-1, not ASCII. Try utf16().');
    out.push('    - the value may be base64, URL-encoded, or a hash of what you');
    out.push('      searched for.');
    out.push('    - ' + res.failed + ' region(s) could not be read at all.');
    out.push('    - the app may not have produced it yet. Drive the feature');
    out.push('      first, then scan.');
    out.push('  A negative scan is weak evidence. Say so in the report.');
    return out.join('\n');
  }

  var byClass = {};
  res.hits.forEach(function (h) {
    var c = classify(h.range);
    var k = c.what;
    if (!(k in byClass)) {
      byClass[k] = { note: c.note, addrs: [] };
    }
    byClass[k].addrs.push(h.address);
  });

  Object.keys(byClass).forEach(function (k) {
    var e = byClass[k];
    out.push('  ' + e.addrs.length + ' hit(s) ' + k);
    out.push('      ' + e.note);
    e.addrs.slice(0, 8).forEach(function (a) {
      out.push('      ' + a);
    });
    if (e.addrs.length > 8) {
      out.push('      ... and ' + (e.addrs.length - 8) + ' more');
    }
    out.push('');
  });

  out.push('  Next: context(<address>) for a hexdump around one of them, and');
  out.push('  where(<address>) for the region it sits in. A single hit in a');
  out.push('  writable anonymous region while the value is IN USE is normal.');
  out.push('  Fourteen hits, or one that survives logging out, is a finding.');
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

function where(addrStr) {
  var a = ptr(addrStr);
  var r = Process.findRangeByAddress(a);
  if (r === null) {
    return addrStr + ' is not inside any mapped range. If you copied it from ' +
           'a malloc return value, strip the top byte first -- Android tags ' +
           'heap pointers and the tag is not part of the address.';
  }
  var m = Process.findModuleByAddress(a);
  var c = classify(r);
  var out = [];
  out.push('address    ' + a);
  out.push('range      ' + r.base + ' + ' + human(r.size) +
           '  (' + r.protection + ')');
  out.push('backing    ' + describeRange(r));
  out.push('module     ' + (m === null ? '(none)' : m.name + ' base ' + m.base));
  if (m !== null) {
    out.push('offset     0x' + a.sub(m.base).toString(16) +
             '   <- this is the address to type into Ghidra');
  }
  out.push('classified ' + c.what);
  out.push('           ' + c.note);
  return out.join('\n');
}

function context(addrStr, bytes) {
  var a = ptr(addrStr);
  var n = bytes || 96;
  var start = a.sub(n / 2);
  try {
    return hexdump(start, { length: n, header: true, ansi: false });
  } catch (e) {
    return 'cannot read ' + n + ' bytes around ' + a + ': ' + e.message +
           '\nThe hit may be near the start or end of its region.';
  }
}

function regions() {
  var rs = candidateRanges('r--', false);
  var total = 0;
  rs.forEach(function (r) { total += r.size; });
  var out = [];
  out.push('=== what a default scan would cover ===');
  out.push('  ' + rs.length + ' region(s), ' + human(total));
  out.push('');
  out.push('  Excluded by default:');
  out.push('    - anything without read permission (nothing to scan)');
  out.push('    - anything larger than ' + human(MAX_REGION_BYTES));
  out.push('    - read-only pages of /system, /apex, /vendor and friends,');
  out.push('      because a hit there is a constant compiled into a shipped');
  out.push('      file. Pass includeSystem=true to search them anyway.');
  out.push('');
  out.push('  Largest included regions:');
  rs.sort(function (a, b) { return b.size - a.size; });
  rs.slice(0, 12).forEach(function (r) {
    out.push('    ' + pad(r.base.toString(), 16) + pad(human(r.size), 11) +
             r.protection + '  ' + describeRange(r));
  });
  return out.join('\n');
}

/**
 * The test that produces an actual finding rather than a screenshot.
 *
 * Call it once while the secret is legitimately in use to establish the
 * baseline, then have the app log out / clear the field / finish the
 * transaction, then call it again. A count that does not drop is the evidence:
 * the application believes it disposed of the value and it did not.
 */
var scrubBaseline = {};

function scrubTest(text) {
  var pat = textToPattern(text);
  var res = scan(pat, 'rw-', false);
  var n = res.hits.length;
  var out = [];

  if (!(text in scrubBaseline)) {
    scrubBaseline[text] = n;
    out.push('BASELINE recorded: ' + n + ' copy/copies of ' +
             JSON.stringify(text) + ' in writable memory.');
    out.push('');
    out.push('Now make the app dispose of it -- log out, close the screen,');
    out.push('complete the payment, whatever the code claims clears it -- then');
    out.push('call scrubTest(' + JSON.stringify(text) + ') again.');
    return out.join('\n');
  }

  var before = scrubBaseline[text];
  out.push('baseline ' + before + '   now ' + n);
  out.push('');
  if (n === 0) {
    out.push('CLEARED. Every copy this scan can see is gone. Note the limits:');
    out.push('the scan covers writable, readable, non-system regions only.');
  } else if (n >= before) {
    out.push('NOT CLEARED. The value is still present in writable memory after');
    out.push('the operation that was supposed to dispose of it. THIS is the');
    out.push('finding -- not the fact that it was there in the first place.');
    out.push('');
    out.push('Severity depends on what else can read this process. On a');
    out.push('non-rooted device with no debuggable flag, another app cannot.');
    out.push('It matters when a crash reporter uploads heap dumps, when the');
    out.push('device is rooted, when the app is debuggable in production, or');
    out.push('when the value outlives the session in a background process.');
    out.push('Write the caveat into the report; do not let the reader assume');
    out.push('remote exploitability.');
  } else {
    out.push('PARTIALLY cleared: ' + (before - n) + ' copy/copies went away,');
    out.push(n + ' remain. Usually one owner scrubs and another does not --');
    out.push('a cache, a logging buffer, or a Java String nobody can clear.');
  }
  out.push('');
  out.push('Reset the baseline with scrubTest.reset() before testing another');
  out.push('value.');
  return out.join('\n');
}

rpc.exports = {
  text: function (s, prot, includeSystem) {
    var p = textToPattern(s);
    return reportScan('ASCII search for ' + JSON.stringify(s), p,
                      scan(p, prot || 'r--', !!includeSystem));
  },
  utf16: function (s, prot, includeSystem) {
    var p = utf16Pattern(s);
    return reportScan('UTF-16LE search for ' + JSON.stringify(s) +
                      ' (Java String storage)', p,
                      scan(p, prot || 'r--', !!includeSystem));
  },
  hex: function (pattern, prot, includeSystem) {
    return reportScan('byte-pattern search', pattern,
                      scan(pattern, prot || 'r--', !!includeSystem));
  },
  where: where,
  context: context,
  regions: regions,
  scrubTest: scrubTest,
  resetBaseline: function () {
    scrubBaseline = {};
    return 'baselines cleared';
  }
};

console.log('mem-search.js loaded.');
console.log('');
console.log('  rpc.exports.regions()            what a scan would cover');
console.log('  rpc.exports.text("Bearer ")      ASCII');
console.log('  rpc.exports.utf16("password")    Java String storage');
console.log('  rpc.exports.hex("de ad ?? ef")   byte pattern, ?? is a wildcard');
console.log('  rpc.exports.where(addr)          explain one hit');
console.log('  rpc.exports.context(addr, 128)   hexdump around it');
console.log('  rpc.exports.scrubTest("secret")  call twice: before and after');
console.log('');
console.log('Finding a secret in memory is normally NOT a finding. Finding it');
console.log('still there after the app claims to have cleared it is.');
