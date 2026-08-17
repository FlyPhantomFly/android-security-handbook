// malloc-trace.js -- watch the native allocator work, from inside the process
//                    that is using it.
//
// WHY THIS SCRIPT EXISTS
//     Chapter 19 makes claims about allocator behaviour: that Scudo hands a
//     freed block straight back on Android because the quarantine is off by
//     default, that allocations of the same size come from the same region,
//     that the order within a region is randomised, that crossing a size
//     threshold moves an allocation to a completely different part of the
//     address space.
//
//     Every one of those is measurable in the app in front of you, and none of
//     them should be taken on faith -- allocator configuration varies by
//     Android version, by OEM, by whether the device is low-RAM, and by whether
//     the app opted into GWP-ASan. This script is the measurement.
//
//     It is also the honest way to answer the question a report has to answer:
//     "if this overflow writes N bytes past the end, what is it writing into?"
//     The answer is not in any documentation. It is in the address deltas
//     between consecutive allocations of the sizes the app actually uses.
//
// HOW TO RUN
//     # host
//     frida -U -n com.example.target -l malloc-trace.js
//
//     # from the REPL, once the app has done something interesting:
//     rpc.exports.start()                 // begin recording
//     rpc.exports.stats()                 // size histogram, region summary
//     rpc.exports.reuse()                 // free-then-realloc: same address?
//     rpc.exports.neighbours(64)          // what sits next to a 64-byte block
//     rpc.exports.stop()
//     rpc.exports.probe()                 // a controlled experiment: allocate
//                                         // a known ladder of sizes and report
//                                         // where each landed
//
//     Start with probe(). It answers most questions in one call and does not
//     require the app to be doing anything.
//
// REQUIREMENTS
//     Frida 12+ with a matching frida-server. Attaching to a release app needs
//     root or an emulator; see 53-Frida.
//
// WHAT THIS SCRIPT WILL *NOT* TELL YOU
//     - Which allocation belongs to which piece of app logic. It sees sizes and
//       addresses, not meaning. Correlating an allocation with the object it
//       holds means hooking the code that fills it, which is a different job.
//     - Anything about the Java heap. `new byte[1024]` in Java does not call
//       malloc; ART allocates from its own spaces. Chapter 13.
//     - The full picture, if the app allocates through operator new, calloc,
//       posix_memalign, memalign, aligned_alloc, strdup, asprintf or any
//       library with its own pool. This script hooks malloc, calloc, realloc
//       and free by default; everything else is invisible to it. A library that
//       carves objects out of one big malloc'd arena will show you ONE
//       allocation and nothing about the hundreds of objects inside it.
//     - Whether a bug is exploitable. Knowing that two objects are adjacent is
//       the beginning of that argument, not the end of it. README section 5.6.
//
// A WARNING ABOUT OVERHEAD
//     malloc is called thousands of times per second in a running app. An
//     Interceptor callback on it is a JavaScript call each time, and enabling
//     backtraces makes it far worse. This script therefore:
//       - records into a fixed-size ring buffer rather than an unbounded array,
//       - is OFF until you call start(),
//       - has a re-entrancy guard, because console.log itself allocates and an
//         unguarded hook on malloc will recurse until the stack dies.
//     Even so, expect the app to feel slow while recording. If it times out a
//     network call or trips a watchdog, record for a shorter window rather than
//     trying to make the hook cheaper.

'use strict';

var LIBC = 'libc.so';

// ---------------------------------------------------------------------------
// Resolving the allocator entry points
//
// Note that we resolve from libc.so specifically rather than passing null. On
// Android an app can ship its own allocator, and a null lookup takes whichever
// module the linker resolved first -- which may not be the one the app's own
// code calls. Being explicit means the output describes bionic's allocator,
// and if the app is using a different one, the counts will look wrong in a way
// you can notice rather than in a way you cannot.
// ---------------------------------------------------------------------------

function mustFind(name) {
  var p = Module.findExportByName(LIBC, name);
  if (p === null) {
    p = Module.findExportByName(null, name);
  }
  return p;
}

var pMalloc = mustFind('malloc');
var pCalloc = mustFind('calloc');
var pRealloc = mustFind('realloc');
var pFree = mustFind('free');

if (pMalloc === null || pFree === null) {
  throw new Error('cannot find malloc/free in ' + LIBC +
                  ' -- is this process using bionic?');
}

var mallocFn = new NativeFunction(pMalloc, 'pointer', ['size_t']);
var freeFn = new NativeFunction(pFree, 'void', ['pointer']);

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var RING = 4096;                 // remembered allocations, most recent wins
var ring = new Array(RING);
var ringPos = 0;
var recording = false;
var inHook = false;              // re-entrancy guard; see the warning above
var counts = {};                 // size -> number of mallocs
var liveBySize = {};             // size -> [addresses currently live]
var freedRecently = [];          // {addr, size} for the reuse test
var FREED_KEEP = 256;

var stats = {
  malloc: 0, calloc: 0, realloc: 0, free: 0, bytes: 0
};

// ---------------------------------------------------------------------------
// The tag byte
//
// On a 64-bit Android 11+ process whose app targets API 30 or higher, malloc
// returns a pointer with a tag in its top byte -- 0xb4 with plain Scudo, a
// per-allocation random value under HWASan or MTE. /proc/<pid>/maps prints
// untagged addresses, so every comparison between the two has to strip it, and
// so does every delta between two pointers.
// ---------------------------------------------------------------------------

function untag(ptr) {
  if (Process.pointerSize !== 8) {
    return ptr;                  // 32-bit: no spare byte, no tagging
  }
  return ptr.and(ptr_('0x00ffffffffffffff'));
}

function ptr_(s) {
  return ptr(s);
}

function tagOf(p) {
  if (Process.pointerSize !== 8) {
    return null;
  }
  return p.shr(56).and(0xff).toNumber();
}

function keyOf(p) {
  return untag(p).toString();
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

function record(kind, size, addr) {
  ring[ringPos % RING] = {
    seq: ringPos, kind: kind, size: size,
    addr: addr === null ? null : untag(addr).toString(),
    tag: addr === null ? null : tagOf(addr)
  };
  ringPos++;
}

function noteAlloc(size, addr) {
  stats.bytes += size;
  counts[size] = (counts[size] || 0) + 1;
  var k = String(size);
  if (!(k in liveBySize)) {
    liveBySize[k] = [];
  }
  liveBySize[k].push(untag(addr).toString());
  if (liveBySize[k].length > 512) {
    liveBySize[k].shift();
  }
}

Interceptor.attach(pMalloc, {
  onEnter: function (args) {
    this.size = args[0].toInt32();
  },
  onLeave: function (retval) {
    if (!recording || inHook || retval.isNull()) {
      return;
    }
    inHook = true;
    try {
      stats.malloc++;
      noteAlloc(this.size, retval);
      record('malloc', this.size, retval);
    } finally {
      inHook = false;
    }
  }
});

if (pCalloc !== null) {
  Interceptor.attach(pCalloc, {
    onEnter: function (args) {
      this.size = args[0].toInt32() * args[1].toInt32();
    },
    onLeave: function (retval) {
      if (!recording || inHook || retval.isNull()) {
        return;
      }
      inHook = true;
      try {
        stats.calloc++;
        noteAlloc(this.size, retval);
        record('calloc', this.size, retval);
      } finally {
        inHook = false;
      }
    }
  });
}

if (pRealloc !== null) {
  Interceptor.attach(pRealloc, {
    onEnter: function (args) {
      this.old = args[0];
      this.size = args[1].toInt32();
    },
    onLeave: function (retval) {
      if (!recording || inHook || retval.isNull()) {
        return;
      }
      inHook = true;
      try {
        stats.realloc++;
        record('realloc', this.size, retval);
        // realloc that MOVES the block is the classic source of a stale
        // pointer: every other copy of the old address is now dangling, and
        // nothing in the language tells the code holding them.
        if (!this.old.isNull() && keyOf(this.old) !== keyOf(retval)) {
          record('realloc-moved', this.size, retval);
        }
      } finally {
        inHook = false;
      }
    }
  });
}

Interceptor.attach(pFree, {
  onEnter: function (args) {
    if (!recording || inHook || args[0].isNull()) {
      return;
    }
    inHook = true;
    try {
      stats.free++;
      var k = keyOf(args[0]);
      record('free', 0, args[0]);
      freedRecently.push(k);
      if (freedRecently.length > FREED_KEEP) {
        freedRecently.shift();
      }
      // Remove it from the live lists so neighbours() does not report a
      // freed block as a neighbour of a live one.
      Object.keys(liveBySize).forEach(function (sz) {
        var idx = liveBySize[sz].indexOf(k);
        if (idx >= 0) {
          liveBySize[sz].splice(idx, 1);
        }
      });
    } finally {
      inHook = false;
    }
  }
});

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

function pad(s, n) {
  s = String(s);
  while (s.length < n) {
    s = ' ' + s;
  }
  return s;
}

function regionOf(addrStr) {
  var a = ptr(addrStr);
  var r = Process.findRangeByAddress(a);
  if (r === null) {
    return '(no range)';
  }
  if (r.file) {
    return r.file.path;
  }
  return r.protection + ' anonymous @' + r.base;
}

function report() {
  var out = [];
  out.push('=== counts since start() ===');
  out.push('  malloc  ' + stats.malloc);
  out.push('  calloc  ' + stats.calloc);
  out.push('  realloc ' + stats.realloc);
  out.push('  free    ' + stats.free);
  out.push('  bytes requested ' + stats.bytes);
  out.push('');
  out.push('  malloc minus free is NOT a leak count. Allocations made before');
  out.push('  start() are freed while recording and inflate the free count;');
  out.push('  allocations still live at stop() inflate the malloc count. Use');
  out.push('  malloc_debug leak_track or a heap profiler for leak numbers.');
  out.push('');

  var sizes = Object.keys(counts).map(Number).sort(function (a, b) {
    return counts[b] - counts[a];
  });
  out.push('=== most frequent request sizes ===');
  out.push('  ' + pad('SIZE', 8) + pad('COUNT', 8) + '  REGION OF THE LAST ONE');
  sizes.slice(0, 20).forEach(function (s) {
    var live = liveBySize[String(s)] || [];
    var where = live.length ? regionOf(live[live.length - 1]) : '(none live)';
    out.push('  ' + pad(s, 8) + pad(counts[s], 8) + '  ' + where);
  });
  out.push('');
  out.push('  Requested size is not allocated size. Every allocator rounds up');
  out.push('  to a size class, so a 33-byte request and a 48-byte request may');
  out.push('  land in the same class and be adjacent in memory. neighbours()');
  out.push('  measures the real stride instead of guessing it.');
  return out.join('\n');
}

/**
 * Consecutive live allocations of one size, sorted by address, with the gap
 * between them. The gap is the allocator's true stride for that size class,
 * and it is the number that decides what an N-byte overflow can reach.
 */
function neighbours(size) {
  var live = (liveBySize[String(size)] || []).slice();
  if (live.length < 2) {
    return 'fewer than two live allocations of size ' + size +
           ' were seen. Try probe(), or record for longer.';
  }
  live.sort(function (a, b) {
    return ptr(a).compare(ptr(b));
  });
  var out = [];
  out.push('=== live ' + size + '-byte allocations, by address ===');
  out.push('');
  for (var i = 0; i < live.length && i < 40; i++) {
    var line = '  ' + live[i];
    if (i > 0) {
      var gap = ptr(live[i]).sub(ptr(live[i - 1])).toInt32();
      line += '   +' + gap + ' bytes from the previous';
      if (gap === size) {
        line += '  <- ADJACENT, no padding at all';
      }
    }
    out.push(line);
  }
  out.push('');
  out.push('  Read the gaps. If the smallest gap equals the requested size,');
  out.push('  there is no padding between blocks, and a one-byte overflow');
  out.push('  writes into the first byte of the next object. If the smallest');
  out.push('  gap is larger, the difference is header plus padding, and an');
  out.push('  overflow has to cross it before it reaches anything an attacker');
  out.push('  would want. That distance is the whole reachability argument,');
  out.push('  and it is device- and version-specific, which is why you measure');
  out.push('  it here rather than quoting a blog post.');
  return out.join('\n');
}

/**
 * Did the allocator hand a freed block straight back?
 *
 * The textbook answer is "no, there is a quarantine". Measure it. On the
 * Android 13 arm64 device this chapter was written against, the answer for
 * Scudo was YES, immediately, because Android ships Scudo with the quarantine
 * disabled.
 */
function reuse() {
  var out = [];
  var seen = {};
  var hits = 0, misses = 0;
  for (var i = 0; i < ringPos && i < RING; i++) {
    var e = ring[i];
    if (!e) {
      continue;
    }
    if (e.kind === 'free') {
      seen[e.addr] = e.seq;
    } else if (e.addr in seen) {
      hits++;
      if (hits <= 15) {
        out.push('  ' + e.addr + ' freed at seq ' + seen[e.addr] +
                 ', handed back at seq ' + e.seq +
                 ' after ' + (e.seq - seen[e.addr]) + ' events' +
                 (e.tag !== null ? '  (tag now 0x' + e.tag.toString(16) + ')'
                                 : ''));
      }
      delete seen[e.addr];
    }
  }
  misses = Object.keys(seen).length;
  var head = [];
  head.push('=== freed blocks handed back by a later allocation ===');
  head.push('');
  head.push('  reused   ' + hits);
  head.push('  not yet  ' + misses);
  head.push('');
  if (hits === 0) {
    head.push('  Nothing was reused within the recorded window. That is either');
    head.push('  a quarantine at work, or simply too short a window. Increase');
    head.push('  the recording time before concluding the first.');
  } else {
    head.push('  Reuse is happening. Where the tag is shown and CHANGES between');
    head.push('  the free and the reallocation, that is HWASan or MTE: the same');
    head.push('  memory, a new tag, so the old pointer no longer matches and a');
    head.push('  use-after-free through it is caught. Where the tag does not');
    head.push('  change, or there is no tag, a stale pointer still works and');
    head.push('  the use-after-free is silent.');
    head.push('');
  }
  return head.concat(out).join('\n');
}

/**
 * A controlled experiment. Allocates a ladder of sizes through the app's own
 * allocator, reports where each landed and in which named region, frees them,
 * and reallocates to test immediate reuse.
 *
 * This is the fastest way to characterise an unfamiliar device's allocator,
 * and it does not depend on the app doing anything at all.
 */
function probe() {
  var sizes = [8, 16, 32, 48, 64, 128, 256, 1024, 4096, 16384,
               65536, 262144, 1048576, 4194304];
  var out = [];
  var ptrs = [];

  out.push('=== allocation ladder ===');
  out.push('  ' + pad('SIZE', 9) + '  ' + pad('ADDRESS', 18) + ' TAG  REGION');
  sizes.forEach(function (s) {
    var p = mallocFn(s);
    ptrs.push({ size: s, p: p });
    var t = tagOf(p);
    out.push('  ' + pad(s, 9) + '  ' + pad(untag(p).toString(), 18) + '  ' +
             (t === null ? '--' : ('0x' + t.toString(16))) + '  ' +
             regionOf(untag(p).toString()));
  });

  out.push('');
  out.push('  Where the region name changes as the size grows, you have found');
  out.push('  the threshold at which this allocator stops carving from its own');
  out.push('  pool and asks the kernel directly. Scudo calls the two halves');
  out.push('  primary and secondary, and they appear in maps as');
  out.push('  [anon:scudo:primary] and [anon:scudo:secondary]. Allocations in');
  out.push('  the secondary get their own mapping and, usually, guard pages --');
  out.push('  so an overflow there is far more likely to fault immediately.');
  out.push('');

  out.push('=== immediate reuse test ===');
  ptrs.forEach(function (e) {
    var before = untag(e.p).toString();
    var beforeTag = tagOf(e.p);
    freeFn(e.p);
    var again = mallocFn(e.size);
    var after = untag(again).toString();
    var afterTag = tagOf(again);
    var verdict;
    if (after === before) {
      verdict = 'SAME ADDRESS';
      if (beforeTag !== null && afterTag !== null && beforeTag !== afterTag) {
        verdict += ', NEW TAG (0x' + beforeTag.toString(16) + ' -> 0x' +
                   afterTag.toString(16) + ')';
      }
    } else {
      verdict = 'different address';
    }
    out.push('  ' + pad(e.size, 9) + '  ' + verdict);
    freeFn(again);
  });
  out.push('');
  out.push('  SAME ADDRESS with no tag change means a stale pointer to a freed');
  out.push('  block of this size will still reach live data. That is the');
  out.push('  precondition for turning a use-after-free into something useful,');
  out.push('  and measuring it is more honest than assuming it.');
  out.push('');
  out.push('  SAME ADDRESS with a NEW TAG means the memory is reused eagerly');
  out.push('  but the old pointer no longer matches, so the stale access is');
  out.push('  caught. That is HWASan or MTE doing exactly what it exists for.');
  return out.join('\n');
}

// ---------------------------------------------------------------------------

rpc.exports = {
  start: function () {
    recording = true;
    return 'recording. Expect the app to slow down. Call stop() when done.';
  },
  stop: function () {
    recording = false;
    return 'stopped after ' + ringPos + ' recorded events.';
  },
  stats: report,
  neighbours: neighbours,
  reuse: reuse,
  probe: probe,
  reset: function () {
    ring = new Array(RING);
    ringPos = 0;
    counts = {};
    liveBySize = {};
    freedRecently = [];
    stats = { malloc: 0, calloc: 0, realloc: 0, free: 0, bytes: 0 };
    return 'cleared';
  }
};

console.log('malloc-trace.js loaded. Hooks are installed but recording is OFF.');
console.log('');
console.log('  rpc.exports.probe()        controlled experiment, start here');
console.log('  rpc.exports.start()        begin recording the app\'s own calls');
console.log('  rpc.exports.stats()        size histogram');
console.log('  rpc.exports.neighbours(64) address deltas for one size class');
console.log('  rpc.exports.reuse()        did freed blocks come back?');
console.log('  rpc.exports.stop()');
