#!/usr/bin/env python3
"""
hashmap_from_scratch.py — build a hash map from nothing, reproduce Java's string hash EXACTLY,
and demonstrate hash-collision denial of service on your own machine.

WHY THIS FILE EXISTS
  The DEX string pool, ART's intern table, java.util.HashMap and android.util.ArrayMap are all
  the same idea under different constraints. Once you have built one by hand, the DEX format
  stops being a specification to memorise and becomes a set of choices you can predict.

  It also contains a real, live vulnerability class: an O(1) lookup that an attacker can turn
  into O(n) by choosing the keys.

USAGE
  python3 hashmap_from_scratch.py --demo               # build one and show the bucket layout
  python3 hashmap_from_scratch.py --verify-hash        # check against known Java hashCode values
  python3 hashmap_from_scratch.py --collide 12         # 2^12 colliding keys, timed
  python3 hashmap_from_scratch.py --compare 50000      # assoc list vs hash map, timed
  python3 hashmap_from_scratch.py --all

DEPENDENCIES
  Python 3.8+, standard library only.

Chapter 03 — Programming Fundamentals, sections 3.10 and 9.3; labs/lab-02
"""

import argparse
import sys
import time
from itertools import product


# =================================================================================================
# 1. Java's String.hashCode, reproduced exactly.
#
#    This is SPECIFIED behaviour, not an implementation detail: the Java Language Specification
#    defines it, so every JVM, ART, and every DEX tool computes the same value. Your version must
#    agree to the bit, including for negative results.
#
#        h = s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1]
#
#    computed in 32-bit SIGNED arithmetic, which wraps.
# =================================================================================================

def java_string_hash(s: str) -> int:
    """Bit-exact reimplementation of java.lang.String.hashCode()."""
    h = 0
    for ch in s:
        # Mask to 32 bits after every step. This is the wraparound that C and Java get for free
        # from the hardware and that Python, whose integers are unbounded, must be told to do.
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    # Reinterpret the 32-bit pattern as a signed two's-complement integer, exactly as Java does.
    if h >= 0x80000000:
        h -= 0x100000000
    return h


# Known-good values, taken from `javac` output. If your implementation disagrees with any of
# these, the bug is almost certainly the signed conversion above.
KNOWN_HASHES = {
    "": 0,
    "a": 97,
    "hello": 99162322,
    "Aa": 2112,
    "BB": 2112,                       # <-- the collision the DoS section uses
    "onCreate": 1046116283,
    "Ljava/lang/String;": 1379658506,
}


def verify_hash() -> bool:
    """Check java_string_hash against values produced by a real JVM."""
    print("verifying java_string_hash against known javac output\n")
    ok = True
    width = max(len(repr(k)) for k in KNOWN_HASHES)
    for s, expected in KNOWN_HASHES.items():
        got = java_string_hash(s)
        mark = "ok " if got == expected else "FAIL"
        if got != expected:
            ok = False
        print(f"  [{mark}] {repr(s).ljust(width)}  expected {expected:>12}  got {got:>12}")

    print(f"\n  'Aa' and 'BB' both hash to {java_string_hash('Aa')}.")
    print("  Why: 'A'=65, 'a'=97, 'B'=66.  65*31 + 97 = 2112.  66*31 + 66 = 2112.")
    print("  Collisions COMPOSE: 'AaAa', 'AaBB', 'BBAa' and 'BBBB' all share one hash too.")
    print("\n  Cross-check it yourself:")
    print('    $ jshell -q  ->  "Aa".hashCode()')
    return ok


# =================================================================================================
# 2. The thing a hash map replaces: an association list. Correct, and O(n).
# =================================================================================================

class AssocList:
    """A key-value store that scans every entry. Included so the comparison is honest."""

    def __init__(self):
        self._items = []                       # list of (key, value)

    def put(self, key, value):
        for i, (k, _) in enumerate(self._items):
            if k == key:
                self._items[i] = (key, value)
                return
        self._items.append((key, value))

    def get(self, key, default=None):
        for k, v in self._items:               # scans EVERY entry — this is the whole problem
            if k == key:
                return v
        return default

    def __len__(self):
        return len(self._items)


# =================================================================================================
# 3. The hash map.
#
#    Separate chaining: each bucket is a list of (key, value) pairs. This is what java.util.HashMap
#    does, except that HashMap converts an overfull bucket into a red-black tree — which is
#    precisely a mitigation for the attack demonstrated below.
# =================================================================================================

class TinyHashMap:
    """A hash map with separate chaining, power-of-two capacity, and load-factor resizing."""

    DEFAULT_CAPACITY = 16
    LOAD_FACTOR = 0.75

    def __init__(self, capacity: int = DEFAULT_CAPACITY, hash_fn=java_string_hash):
        # Capacity must be a power of two so that `& (capacity - 1)` can replace `% capacity`.
        # A bitwise AND is one CPU instruction; an integer division is on the order of twenty.
        assert capacity & (capacity - 1) == 0, "capacity must be a power of two"
        self._buckets = [[] for _ in range(capacity)]
        self._size = 0
        self._hash_fn = hash_fn
        self.probe_count = 0                   # instrumentation: comparisons performed

    # ---- the two lines that make it a hash map --------------------------------------------------

    def _index(self, key) -> int:
        """Reduce a key to a bucket index."""
        h = self._hash_fn(str(key))
        # Mix the high bits down into the low bits before masking. Without this, a hash function
        # whose entropy lives in the high bits (as many do) would map everything to a few buckets
        # once the mask throws the high bits away. java.util.HashMap does exactly this.
        h ^= (h >> 16) & 0xFFFF
        return h & (len(self._buckets) - 1)

    # ---- the map interface ----------------------------------------------------------------------

    def put(self, key, value):
        bucket = self._buckets[self._index(key)]
        for i, (k, _) in enumerate(bucket):
            self.probe_count += 1
            if k == key:
                bucket[i] = (key, value)       # replace, do not append: keys are unique
                return
        bucket.append((key, value))
        self._size += 1
        if self._size > len(self._buckets) * self.LOAD_FACTOR:
            self._resize()

    def get(self, key, default=None):
        for k, v in self._buckets[self._index(key)]:
            self.probe_count += 1
            if k == key:
                return v
        return default

    def remove(self, key) -> bool:
        bucket = self._buckets[self._index(key)]
        for i, (k, _) in enumerate(bucket):
            if k == key:
                del bucket[i]
                self._size -= 1
                return True
        return False

    def _resize(self):
        """Double the capacity and rehash everything.

        Rehashing is unavoidable: the bucket index depends on the capacity, so every existing
        key maps somewhere different once the capacity changes. This is why a resize is O(n) and
        why choosing a sensible initial capacity matters for a map you will fill.
        """
        old = self._buckets
        self._buckets = [[] for _ in range(len(old) * 2)]
        self._size = 0
        for bucket in old:
            for k, v in bucket:
                self.put(k, v)

    def __len__(self):
        return self._size

    # ---- instrumentation -------------------------------------------------------------------------

    def stats(self) -> dict:
        lengths = [len(b) for b in self._buckets]
        used = [n for n in lengths if n > 0]
        return {
            "entries": self._size,
            "buckets": len(self._buckets),
            "used_buckets": len(used),
            "empty_buckets": len(lengths) - len(used),
            "longest_chain": max(lengths) if lengths else 0,
            "mean_chain_used": (sum(used) / len(used)) if used else 0.0,
            "load_factor": self._size / len(self._buckets),
        }

    def show(self, max_buckets: int = 16):
        print(f"\n  {len(self)} entries in {len(self._buckets)} buckets\n")
        for i, bucket in enumerate(self._buckets[:max_buckets]):
            bar = "#" * len(bucket)
            keys = ", ".join(str(k) for k, _ in bucket[:4])
            more = ", ..." if len(bucket) > 4 else ""
            print(f"   [{i:3d}] {bar:<12} {keys}{more}")
        if len(self._buckets) > max_buckets:
            print(f"   ... {len(self._buckets) - max_buckets} more buckets")

        s = self.stats()
        print(f"\n  longest chain    : {s['longest_chain']}")
        print(f"  empty buckets    : {s['empty_buckets']} of {s['buckets']}")
        print(f"  mean used chain  : {s['mean_chain_used']:.2f}")
        print(f"  load factor      : {s['load_factor']:.2f}")


# =================================================================================================
# 4. Hash collision denial of service.
#
#    "Aa" and "BB" share a hash, and the property composes: any concatenation of them of the same
#    length shares one hash. So 2^n strings can be generated that all land in ONE bucket, turning
#    an O(1) map into an O(n) list and every insertion into an O(n) scan — O(n^2) overall.
#
#    This is not theoretical. It has been used against web frameworks, JSON parsers and any
#    service that builds a map keyed on names taken from a request.
# =================================================================================================

def colliding_keys(n_pairs: int):
    """Generate 2**n_pairs strings that all share one Java hash value."""
    return ["".join(p) for p in product(("Aa", "BB"), repeat=n_pairs)]


def demonstrate_collision_dos(n_pairs: int = 12):
    keys_bad = colliding_keys(n_pairs)
    keys_good = [f"key{i}" for i in range(len(keys_bad))]

    print(f"generated {len(keys_bad)} colliding keys")
    print(f"distinct hashes among them: {len({java_string_hash(k) for k in keys_bad})}")
    print(f"distinct hashes among {len(keys_good)} normal keys: "
          f"{len({java_string_hash(k) for k in keys_good})}\n")

    results = []
    for label, keys in (("normal", keys_good), ("colliding", keys_bad)):
        m = TinyHashMap()
        t0 = time.perf_counter()
        for k in keys:
            m.put(k, 1)
        t1 = time.perf_counter()
        for k in keys:
            m.get(k)
        t2 = time.perf_counter()
        results.append((label, t1 - t0, t2 - t1, m.probe_count, m.stats()["longest_chain"]))

    print(f"  {'keys':<12}{'insert (s)':>12}{'lookup (s)':>12}{'comparisons':>14}{'longest':>10}")
    for label, ins, look, probes, longest in results:
        print(f"  {label:<12}{ins:>12.4f}{look:>12.4f}{probes:>14,}{longest:>10}")

    slowdown = results[1][1] / max(results[0][1], 1e-9)
    print(f"\n  insertion slowdown: {slowdown:.0f}x")
    print(f"\n  The colliding run performed {results[1][3]:,} comparisons against "
          f"{results[0][3]:,}.")
    print("  Every one of those is CPU time an attacker bought with a single HTTP request.\n")

    print("  THE FINDING, written the way it belongs in a report:")
    print("    An unauthenticated request whose parameter names are attacker-chosen is used to")
    print("    populate a hash map. By supplying keys engineered to share a hash value, an")
    print("    attacker degrades every insertion from O(1) to O(n), making the handler O(n^2) in")
    print("    the number of parameters. A single request of a few hundred kilobytes consumes")
    print("    seconds of CPU, and a small number of concurrent requests exhausts the server.")
    print("\n  DEFENCES, and what each costs:")
    print("    1. Randomised hash seeding — per-process secret mixed into the hash, so collisions")
    print("       cannot be precomputed. Cost: hash values are no longer stable across runs, and")
    print("       java.lang.String.hashCode() CANNOT change because it is specified.")
    print("    2. Treeify overfull buckets — java.util.HashMap converts a bucket to a red-black")
    print("       tree past a threshold, capping the worst case at O(log n). Cost: only helps for")
    print("       Comparable keys; adds memory and complexity.")
    print("    3. Bound the input — cap the number of parameters accepted. Cost: it is a limit,")
    print("       not a fix, and it must be applied at every entry point rather than in one place.")


# =================================================================================================
# 5. The honest comparison: association list versus hash map.
# =================================================================================================

def compare(n: int = 50000):
    keys = [f"key{i}" for i in range(n)]
    lookups = [f"key{i}" for i in range(0, n, max(n // 1000, 1))]

    print(f"inserting {n:,} entries, then performing {len(lookups):,} lookups\n")

    for label, store in (("AssocList  O(n)", AssocList()), ("TinyHashMap O(1)", TinyHashMap())):
        t0 = time.perf_counter()
        for k in keys:
            store.put(k, 1)
        t1 = time.perf_counter()
        for k in lookups:
            store.get(k)
        t2 = time.perf_counter()
        print(f"  {label:<18} insert {t1-t0:8.3f}s    lookup {t2-t1:8.3f}s")

    print("\n  Now double n and run it again. The association list's time roughly quadruples")
    print("  (O(n^2) to fill); the hash map's roughly doubles (O(n)). That difference in GROWTH,")
    print("  not in the absolute numbers, is what Big-O describes.")


# =================================================================================================
# 6. Demo
# =================================================================================================

def demo():
    m = TinyHashMap()
    for word in ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
                 "golf", "hotel", "india", "juliet", "kilo", "lima"):
        m.put(word, len(word))

    print("a hash map holding twelve words")
    m.show()

    print("\n  lookups:")
    for k in ("charlie", "kilo", "missing"):
        print(f"    get({k!r}) -> {m.get(k)}   (bucket {m._index(k)})")

    print("\n  Now add enough entries to force a resize past the 0.75 load factor:")
    before = len(m._buckets)
    for i in range(20):
        m.put(f"extra{i}", i)
    print(f"    capacity {before} -> {len(m._buckets)}   (every key was rehashed)")

    print("\n  CONNECTION TO ANDROID:")
    print("    A DEX file stores its strings as a SORTED ARRAY, not a hash table, because the")
    print("    file is memory-mapped and read-only and must be as small as possible — a sorted")
    print("    array needs no extra structure and supports O(log n) binary search.")
    print("    ART then builds a HASH TABLE over those strings at load time (the intern table),")
    print("    because it performs millions of lookups and O(log n) is not good enough.")
    print("    Two different structures, two different constraints, one correct answer each.")
    print("    See 12-DEX-Internals and labs/lab-02.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--demo", action="store_true", help="build a map and show the buckets")
    ap.add_argument("--verify-hash", action="store_true",
                    help="check java_string_hash against known javac output")
    ap.add_argument("--collide", type=int, metavar="N",
                    help="demonstrate collision DoS with 2**N colliding keys (try 12)")
    ap.add_argument("--compare", type=int, metavar="N",
                    help="time an association list against the hash map with N entries")
    ap.add_argument("--all", action="store_true", help="run everything")
    args = ap.parse_args()

    ran = False
    if args.verify_hash or args.all:
        print("=" * 78); verify_hash(); ran = True
    if args.demo or args.all:
        print("\n" + "=" * 78); demo(); ran = True
    if args.collide is not None or args.all:
        print("\n" + "=" * 78)
        demonstrate_collision_dos(args.collide if args.collide is not None else 12)
        ran = True
    if args.compare is not None or args.all:
        print("\n" + "=" * 78); compare(args.compare if args.compare is not None else 50000)
        ran = True

    if not ran:
        ap.print_help()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
