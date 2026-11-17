# Lab 02 — Hash maps by hand, then in a real DEX

**Difficulty:** Intermediate
**Time:** 2–4 hours
**Prerequisites:** [Lab 01](lab-01-first-program-all-the-way-down.md),
[Chapter 03 §3.9, §3.10, §3.12](../README.md)

---

## Objective

Build a hash map from nothing, reproduce Java's string hash function **exactly**, demonstrate hash
collision denial of service on your own laptop, and then find the string pool inside a real Android
APK and explain why it uses a different data structure.

The payoff is that [12-DEX-Internals](../../12-DEX-Internals/README.md) and
[13-ART](../../13-ART/README.md) will read as obvious rather than arbitrary. Right now the DEX
format probably looks like a pile of tables somebody invented. By the end of this lab you will be
able to say *why* each one is shaped the way it is, from first principles.

> **Mental Model.** A file format is a data structure that has been written to disk. Every
> decision in the DEX format is a data-structure decision — sorted or hashed, contiguous or linked,
> indexed or scanned — made under the constraints of "must be memory-mapped" and "must be looked up a
> million times per second". Once you think of it that way, the format stops being a specification to
> memorise and becomes a set of choices you can predict.

---

## Setup

```bash
# host
python3 --version
javac -version
mkdir -p ~/lab02 && cd ~/lab02
```

For Part 4 you need an APK and the Android SDK build tools:

```bash
# host
which dexdump || echo "install Android SDK build-tools, or use `apkanalyzer`"
# any APK will do — grab one from your own device:
adb shell pm list packages -3 | head
adb shell pm path com.some.app
adb pull /data/app/.../base.apk ./target.apk
```

If you have no device, download any free APK from a reputable source, or build the sample app from
[Lab 01](lab-01-first-program-all-the-way-down.md) into an APK.

---

## Part 1 — Build a hash map

The reference implementation is
[`../examples/hashmap_from_scratch.py`](../examples/hashmap_from_scratch.py). Write your own first;
compare afterwards.

### Step 1.1 — Start with the thing a hash map replaces

```python
# assoc_list.py — an association list: correct, and O(n)
class AssocList:
    def __init__(self):
        self._items = []            # list of (key, value) pairs

    def put(self, key, value):
        for i, (k, _) in enumerate(self._items):
            if k == key:
                self._items[i] = (key, value)
                return
        self._items.append((key, value))

    def get(self, key):
        for k, v in self._items:    # <-- scans EVERY entry
            if k == key:
                return v
        return None
```

**Q1.** With 1 000 000 entries, how many comparisons does a failed `get` perform? What is the Big-O?

**Q2.** Time it. Insert 50 000 entries, then do 1 000 lookups, and record the wall time.

### Step 1.2 — Add the hash

The idea in one sentence: **compute a number from the key's content, use it to pick one bucket, and
look only in that bucket.**

```python
# tiny_hashmap.py
class TinyHashMap:
    def __init__(self, capacity=16):
        self._buckets = [[] for _ in range(capacity)]
        self._size = 0

    def _hash(self, key):
        raise NotImplementedError    # Part 2

    def _index(self, key):
        return self._hash(key) & (len(self._buckets) - 1)

    def put(self, key, value):
        bucket = self._buckets[self._index(key)]
        for i, (k, _) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, value)
                return
        bucket.append((key, value))
        self._size += 1
        if self._size > len(self._buckets) * 0.75:
            self._resize()

    def get(self, key):
        for k, v in self._buckets[self._index(key)]:
            if k == key:
                return v
        return None

    def _resize(self):
        old = self._buckets
        self._buckets = [[] for _ in range(len(old) * 2)]
        self._size = 0
        for bucket in old:
            for k, v in bucket:
                self.put(k, v)      # rehash everything — indices change with capacity
```

**Q3.** `self._index` uses `& (len - 1)` instead of `% len`. That only works when the capacity is a
power of two. Why is it done that way? (Hint: what does `x & 7` compute, and how many CPU cycles does
each operation take?)

**Q4.** `_resize` rehashes every entry rather than copying buckets across. Why is that necessary?

**Q5.** The load factor is 0.75. What happens to lookup time if you set it to 5.0? To 0.1? What is
being traded against what?

---

## Part 2 — Reproduce Java's string hash exactly

This is the part that connects to Android. Java's `String.hashCode()` is **specified**, not
implementation-defined, which means every JVM, ART, and every DEX tool computes the same value — and
so must you.

The specification: `h = s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1]`, computed in 32-bit signed
arithmetic, which is equivalent to the loop below.

```python
def java_string_hash(s):
    h = 0
    for ch in s:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF     # keep it 32-bit; this WRAPS, exactly like Java
    if h >= 0x80000000:                          # reinterpret as signed two's complement
        h -= 0x100000000
    return h
```

Verify against the real thing:

```java
// HashCheck.java
public class HashCheck {
    public static void main(String[] a) {
        String[] tests = {"", "a", "hello", "Ljava/lang/String;", "onCreate",
                          "com.example.app.MainActivity", "Aa", "BB"};
        for (String s : tests) {
            System.out.println(s + " -> " + s.hashCode());
        }
    }
}
```

```bash
# host
javac HashCheck.java && java HashCheck
python3 -c "
from tiny_hashmap import java_string_hash
for s in ['', 'a', 'hello', 'Ljava/lang/String;', 'onCreate',
          'com.example.app.MainActivity', 'Aa', 'BB']:
    print(s, '->', java_string_hash(s))
"
```

**Q6.** Do all values match exactly, including the negative ones? If not, the bug is almost certainly
in your signed conversion — fix it before continuing. Getting this *exactly* right is the point.

**Q7.** `"Aa"` and `"BB"` produce the same hash. Verify it. Now explain why, using the formula.
(`'A'=65, 'a'=97, 'B'=66`. Work out `65*31 + 97` and `66*31 + 66`.)

**Q8.** Why is the multiplier 31 rather than 32? (Hint: `x * 31` can be computed as `(x << 5) - x`,
and 32 is a power of two — what would multiplying by a power of two do to the low bits?)

---

## Part 3 — Collision denial of service

You now hold the tool that makes this attack trivial: `"Aa"` and `"BB"` collide, and collisions
**compose**. `"AaAa"`, `"AaBB"`, `"BBAa"` and `"BBBB"` all have the same hash.

```python
# collide.py — generate 2^n strings that all share one hash
from itertools import product

def colliding_strings(n):
    """Every combination of 'Aa' and 'BB' of length 2n has an identical Java hash."""
    return ["".join(p) for p in product(["Aa", "BB"], repeat=n)]

keys = colliding_strings(12)          # 4096 strings, one hash value
print(len(keys), "keys")
print("distinct hashes:", len({java_string_hash(k) for k in keys}))
```

**Q9.** How many distinct hashes did 4 096 strings produce?

Now measure the damage:

```python
import time
from tiny_hashmap import TinyHashMap

for label, keys in [("random", [f"key{i}" for i in range(4096)]),
                    ("colliding", colliding_strings(12))]:
    m = TinyHashMap()
    t0 = time.time()
    for k in keys:
        m.put(k, 1)
    t1 = time.time()
    for k in keys:
        m.get(k)
    t2 = time.time()
    print(f"{label:10} insert {t1-t0:7.3f}s   lookup {t2-t1:7.3f}s")
```

**Q10.** What is the ratio between the two? Sketch what happens to the ratio as you go from 2 048 to
4 096 to 8 192 keys — is the growth linear or quadratic, and why?

**Q11.** Now make it a security finding. A web API or an Android content provider builds a `HashMap`
keyed on parameter names from the request. An attacker sends 10 000 colliding keys. Write the finding
in one paragraph: mechanism, impact, and severity.

**Q12.** Name three defences, and state the drawback of each.

<details>
<summary>Check your answer on Q12</summary>

**Randomised hash seeding** — mix a per-process random value into the hash so an attacker cannot
precompute colliding keys. Drawback: hash values are no longer stable across runs, which breaks
anything that persisted them, and Java's `String.hashCode()` cannot change because it is specified.

**Convert overfull buckets to trees** — Java's `HashMap` does exactly this, switching a bucket to a
red-black tree past a threshold, which caps the worst case at O(log n). Drawback: only helps for
`Comparable` keys, and adds memory and complexity.

**Bound the input** — limit the number of parameters accepted. Drawback: it is a limit, not a fix,
and it must be applied at every entry point rather than in one place.
</details>

---

## Part 4 — Find a hash map's cousin in a real DEX

Now the payoff. Every DEX file contains a table of every string it uses: class names, method names,
field names and literals, each stored exactly once.

### Step 4.1 — Look at the table

```bash
# host
unzip -o target.apk 'classes*.dex' -d dex/
ls -l dex/
dexdump -f dex/classes.dex | head -30
```

Find `string_ids_size` and `string_ids_off` in that header output.

**Q13.** How many strings does this DEX contain? At what file offset does the table start?

### Step 4.2 — Parse it yourself

```python
# dex_strings.py — a minimal DEX string-pool reader
import struct, sys

data = open(sys.argv[1], "rb").read()
assert data[:4] == b"dex\n", "not a DEX file"

# The header is 0x70 bytes. string_ids_size is at 0x38, string_ids_off at 0x3C.
string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
print(f"{string_ids_size} strings, table at 0x{string_ids_off:x}")

def read_uleb128(buf, pos):
    """DEX lengths are ULEB128: 7 bits per byte, high bit means 'more follows'."""
    result, shift = 0, 0
    while True:
        b = buf[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7

strings = []
for i in range(string_ids_size):
    # Each entry in string_ids is a 4-byte offset to a string_data_item.
    off, = struct.unpack_from("<I", data, string_ids_off + i * 4)
    length, p = read_uleb128(data, off)          # length in UTF-16 code units
    end = data.index(b"\x00", p)
    strings.append(data[p:end].decode("utf-8", "replace"))

for s in strings[:40]:
    print(repr(s))
```

```bash
# host
python3 dex_strings.py dex/classes.dex | head -40
```

**Q14.** Are the strings **sorted**? Check:

```bash
# host
python3 dex_strings.py dex/classes.dex > /tmp/strs.txt
sort /tmp/strs.txt > /tmp/strs_sorted.txt
diff /tmp/strs.txt /tmp/strs_sorted.txt && echo "SORTED" || echo "not sorted"
```

**Q15.** The DEX string pool is a **sorted array**, not a hash table. Why? Think about the three
constraints: the file is memory-mapped, it must be read-only, and it must be as small as possible.
What does a hash table cost that a sorted array does not?

**Q16.** What is the lookup complexity of a binary search over a sorted array? How does that compare
with a hash map, and why is the difference acceptable *on disk* but not *at runtime*?

### Step 4.3 — Where the hash map actually appears

Sorted-array lookup is O(log n) and ART performs millions of string lookups, so at load time ART
builds a hash table over the strings — the **intern table**.

```bash
# host — confirm ART agrees with your Part 2 implementation
adb shell 'am start -n com.example.app/.MainActivity' 2>/dev/null
frida -U -n com.example.app -e "
Java.perform(function () {
  var S = Java.use('java.lang.String');
  ['', 'a', 'hello', 'onCreate'].forEach(function (s) {
    console.log(s + ' -> ' + S.\$new(s).hashCode());
  });
});"
```

**Q17.** Do ART's values match your Python implementation and `javac`'s? All three must agree,
because the algorithm is specified. Confirming agreement across three independent implementations is
how you build confidence that your model of a mechanism is *correct* rather than merely plausible.

**Q18.** Interning means identical string literals become the same object. Verify:

```java
String a = "hello";
String b = "hello";
String c = new String("hello");
System.out.println(a == b);            // ?
System.out.println(a == c);            // ?
System.out.println(a.equals(c));       // ?
```

Explain each result, and connect it to the "use `.equals()` not `==`" rule and to why a secret in a
`String` may live for the whole process.

---

## Success criteria

- [ ] An association list and a hash map both implemented, and timed against each other
- [ ] You can explain the power-of-two capacity, the `& (len-1)` trick, and why resizing rehashes
- [ ] Your Java string hash matches `javac` output **exactly**, including negative values
- [ ] You verified the `"Aa"` / `"BB"` collision and explained it arithmetically
- [ ] You generated 4 096 colliding keys and measured the slowdown
- [ ] You wrote the collision-DoS finding as a paragraph with mechanism, impact and severity
- [ ] You named three defences and the drawback of each
- [ ] You parsed a real DEX string pool with your own code and confirmed it is sorted
- [ ] You can explain why the DEX uses a sorted array on disk and ART uses a hash table in memory
- [ ] Python, `javac` and ART all produced identical hash values

---

## Debrief

1. Explain, to someone who has never programmed, how a hash map achieves constant-time lookup and
   what has to go wrong for it to stop.
2. The DEX format stores strings sorted; ART hashes them at load time. Both are correct choices.
   Describe the constraints that make each one correct in its own context.
3. `"Aa"` and `"BB"` collide because of the specific multiplier 31 and the specific characters. If
   you were designing a new hash for a format like DEX today, what would you do differently, and what
   would it cost you?
4. Java's `String.hashCode()` cannot be changed to a randomised hash. Explain why not, and say what
   Java did instead.
5. You now know that the DEX string pool contains every class name, method name and literal in the
   app, exactly once, sorted. Name three things you could learn about an app from that table alone,
   without decompiling anything.
6. Someone tells you an app is "fully obfuscated". What can you still learn from the string pool, and
   why can obfuscation not remove it?

---

## Where this goes next

[12-DEX-Internals](../../12-DEX-Internals/README.md) parses the rest of the format the same way you
just parsed the string pool, and [13-ART](../../13-ART/README.md) explains what the runtime does with
it. Both should now read as consequences rather than as facts to memorise.

[Lab 03](lab-03-debugging-challenge.md) switches from data structures to the skill of finding a bug
you did not plant.
