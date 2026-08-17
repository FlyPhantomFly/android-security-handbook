/*
 * CollectionsDemo.java
 * ====================
 *
 * WHAT THIS DOES
 * --------------
 * Makes the collections theory in ../README.md measurable instead of memorised. Everything below
 * is something you can watch happen rather than take on trust:
 *
 *   1. ArrayList vs LinkedList, timed, for the two access patterns where they differ most.
 *   2. HashMap bucket assignment computed by hand, so you can see WHICH bucket a key lands in.
 *   3. A deliberately terrible hashCode that forces every key into one bucket, timed against a
 *      good one, showing the O(1) to O(n) collapse and the treeification that partly rescues it.
 *   4. HashMap vs ConcurrentHashMap under concurrent writes, showing real lost updates.
 *   5. The equals/hashCode contract broken three different ways, with the consequence of each.
 *
 * WHY A SECURITY PERSON CARES
 * ---------------------------
 *   - Item 3 is the mechanism behind hash-collision denial of service. An endpoint that puts
 *     attacker-controlled strings into a HashMap can be driven from O(1) to O(n) per insert, so
 *     n insertions cost O(n^2). This has been a real, repeatedly rediscovered vulnerability class
 *     in web frameworks, JSON parsers and form-field handling.
 *   - Item 4 is why "it worked in testing" is not evidence of thread safety, and why a permission
 *     or session cache implemented on a plain HashMap can serve one user's data to another.
 *   - Item 5 is why an authorisation set can appear to contain a principal that it does not, or
 *     fail to contain one that it does. Auth decisions built on Set.contains and Map.get inherit
 *     every bug in equals and hashCode.
 *
 * HOW TO RUN
 * ----------
 *   Single file, no compilation step, JDK 11 or newer:
 *
 *       # host
 *       java CollectionsDemo.java
 *
 *   Or compile first:
 *
 *       # host
 *       javac -g CollectionsDemo.java
 *       java CollectionsDemo
 *
 *   The timing sections take a few seconds. Numbers vary by machine and JIT state; the ORDER of
 *   magnitude is the result, not the exact milliseconds. Run it twice and compare.
 *
 * Requires JDK 17+ (tested on 17, 21 and 24). No external dependencies.
 */

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class CollectionsDemo {

    public static void main(String[] args) throws Exception {
        section("1. ArrayList vs LinkedList, timed");
        listShootout();

        section("2. Which bucket does a key land in?");
        bucketWalkthrough();

        section("3. A deliberately bad hashCode");
        badHashCodeCost();

        section("4. HashMap vs ConcurrentHashMap under threads");
        concurrencyShootout();

        section("5. Breaking the equals/hashCode contract");
        brokenEqualsAndHashCode();

        section("6. Ordering guarantees, side by side");
        orderingComparison();

        section("Done");
    }

    // ==============================================================================================
    // 1. ArrayList vs LinkedList
    // ==============================================================================================
    /*
     * ArrayList is a resizable Object[] with a size counter. Index access is one array read.
     * Inserting at the front means copying every existing element one slot to the right.
     *
     * LinkedList is a doubly-linked chain of Node objects. Index access must walk the chain from
     * whichever end is nearer. Inserting at the front is three pointer writes.
     *
     * So each wins decisively on one of these two operations, and the gap grows with size.
     *
     * IN DECOMPILED CODE both appear as invoke-interface on Ljava/util/List;, because well-written
     * code declares the variable as List. The concrete type is only visible at the new-instance
     * that created it, which may be in a different method or a different class entirely. When you
     * are looking for a performance-driven bug, find the allocation site, not the usage site.
     */
    private static void listShootout() {
        final int n = 60_000;

        List<Integer> arrayList = new ArrayList<>();
        List<Integer> linkedList = new LinkedList<>();
        for (int i = 0; i < n; i++) {
            arrayList.add(i);
            linkedList.add(i);
        }

        // Warm up the JIT so the first measurement is not just interpretation cost.
        for (int w = 0; w < 3; w++) {
            randomAccessSum(arrayList, 20_000);
            randomAccessSum(linkedList, 2_000);
        }

        long a1 = time(() -> randomAccessSum(arrayList, 20_000));
        long l1 = time(() -> randomAccessSum(linkedList, 2_000));

        System.out.println("Random access by index");
        System.out.printf("  ArrayList  20000 gets : %6d ms%n", a1);
        System.out.printf("  LinkedList  2000 gets : %6d ms   (one tenth as many gets)%n", l1);
        System.out.println("  ArrayList indexes an array. LinkedList walks the chain, so its cost");
        System.out.println("  per get grows with the list length. Note the different get counts.");

        List<Integer> a2list = new ArrayList<>();
        List<Integer> l2list = new LinkedList<>();
        long a2 = time(() -> { for (int i = 0; i < 40_000; i++) a2list.add(0, i); });
        long l2 = time(() -> { for (int i = 0; i < 40_000; i++) l2list.add(0, i); });

        System.out.println();
        System.out.println("Insertion at the front, 40000 times");
        System.out.printf("  ArrayList             : %6d ms   (System.arraycopy every time)%n", a2);
        System.out.printf("  LinkedList            : %6d ms   (three pointer writes)%n", l2);

        System.out.println();
        System.out.println("Practical rule: use ArrayList unless you have measured a reason not to.");
        System.out.println("LinkedList wins only on head and tail work through an explicit iterator,");
        System.out.println("and ArrayDeque beats it at that too while using far less memory,");
        System.out.println("because every LinkedList element carries two extra references plus an");
        System.out.println("object header.");
    }

    private static long randomAccessSum(List<Integer> list, int gets) {
        Random r = new Random(42);
        long sum = 0;
        int n = list.size();
        for (int i = 0; i < gets; i++) {
            sum += list.get(r.nextInt(n));
        }
        return sum;
    }

    // ==============================================================================================
    // 2. Bucket assignment
    // ==============================================================================================
    /*
     * HashMap does NOT use hashCode() directly as the bucket index. It does two things first.
     *
     *   1. SPREAD:  h = key.hashCode(); h = h ^ (h >>> 16);
     *      This mixes the high 16 bits down into the low 16 bits.
     *
     *   2. MASK:    index = (table.length - 1) & h;
     *      Because table.length is always a power of two, this is a cheap modulo.
     *
     * Step 1 exists because of step 2. Masking only looks at the low bits, so two keys whose hash
     * codes differ ONLY in the high bits would collide every time. Integer.hashCode() returns the
     * value itself, so without spreading, the keys 0, 65536, 131072 would all map to bucket 0.
     *
     * We reproduce both steps here rather than reflecting into HashMap's private `table` field,
     * because on JDK 9+ that field is inside the java.base module and setAccessible(true) on it
     * throws InaccessibleObjectException unless you pass --add-opens. That module boundary is,
     * incidentally, a genuine access control mechanism, unlike `private` on your own classes -
     * although it too is only a JVM-level control, and does not exist on Android.
     */
    private static void bucketWalkthrough() {
        final int tableLength = 16;      // HashMap's DEFAULT_INITIAL_CAPACITY

        System.out.printf("%-14s %12s %12s %8s%n", "key", "hashCode", "spread", "bucket");
        for (String key : new String[] { "alice", "bob", "carol", "dave", "Aa", "BB", "AaAa", "BBBB" }) {
            int h = key.hashCode();
            int spread = h ^ (h >>> 16);
            int bucket = (tableLength - 1) & spread;
            System.out.printf("%-14s %12d %12d %8d%n", key, h, spread, bucket);
        }

        System.out.println();
        System.out.println("Look at \"Aa\" and \"BB\": identical hashCode, so identical bucket, always.");
        System.out.println("\"AaAa\" and \"BBBB\" collide too, and so does every string built by");
        System.out.println("concatenating those pairs. That family of collisions is not a bug in");
        System.out.println("String.hashCode - it is an unavoidable property of any 32-bit hash, and");
        System.out.println("it is how hash-collision denial-of-service payloads are generated.");
        System.out.println();
        System.out.println("String.hashCode is s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1].");
        System.out.println("It is public, unsalted, and identical on every JVM and every Android");
        System.out.println("device, so an attacker can compute colliding keys offline.");
    }

    // ==============================================================================================
    // 3. The cost of a bad hashCode
    // ==============================================================================================
    /*
     * BadKey.hashCode() returns a constant. Every key therefore lands in bucket 0, and the map
     * degenerates into a single long chain. Lookup becomes a linear scan calling equals() on every
     * entry, which is O(n) per lookup and O(n^2) to fill.
     *
     * Since Java 8, a bucket holding 8 or more entries is converted to a red-black tree provided
     * the table has at least 64 slots, which drags the worst case back from O(n) to O(log n). That
     * mitigation only works if the keys are Comparable. BadKey below is deliberately NOT
     * Comparable, so treeification cannot order the nodes and the rescue is partial.
     *
     * IN DECOMPILED CODE this is easy to spot and worth grepping for: a hashCode() method whose
     * body is a single `return <constant>`, or one that ignores most of the fields that equals()
     * examines. In Smali:
     *
     *     .method public hashCode()I
     *         .registers 2
     *         const/16 v0, 0x2a
     *         return v0
     *     .end method
     */
    private static void badHashCodeCost() {
        final int n = 12_000;

        Map<GoodKey, Integer> good = new HashMap<>();
        Map<BadKey, Integer> bad = new HashMap<>();

        long fillGood = time(() -> { for (int i = 0; i < n; i++) good.put(new GoodKey(i), i); });
        long fillBad = time(() -> { for (int i = 0; i < n; i++) bad.put(new BadKey(i), i); });

        long lookGood = time(() -> {
            long acc = 0;
            for (int i = 0; i < n; i++) acc += good.get(new GoodKey(i));
            return acc;
        });
        long lookBad = time(() -> {
            long acc = 0;
            for (int i = 0; i < n; i++) acc += bad.get(new BadKey(i));
            return acc;
        });

        System.out.printf("%-34s %8s %8s%n", "", "fill ms", "look ms");
        System.out.printf("%-34s %8d %8d%n", "GoodKey (hashCode uses the id)", fillGood, lookGood);
        System.out.printf("%-34s %8d %8d%n", "BadKey  (hashCode returns 42)", fillBad, lookBad);
        System.out.println();
        System.out.printf("Both maps hold %d entries and both are correct. Only the cost differs.%n", n);
        System.out.println();
        System.out.println("THREAT MODEL: if the keys of a server-side or IPC-facing map are");
        System.out.println("attacker-controlled strings, the attacker picks colliding keys and turns");
        System.out.println("an O(n) request handler into an O(n^2) one. The defences are: bound the");
        System.out.println("number of keys you will accept from one request, use a keyed or");
        System.out.println("randomised hash for untrusted input, or use a TreeMap so that the worst");
        System.out.println("case is O(log n) by construction rather than by rescue.");
    }

    // ==============================================================================================
    // 4. Concurrency
    // ==============================================================================================
    /*
     * Eight threads each insert 20000 distinct keys into a shared map. The correct final size is
     * 160000 in both cases.
     *
     * A plain HashMap has no synchronisation at all. Two threads can compute the same bucket, both
     * read the current head node, and both write their own node as the new head - so one insertion
     * silently vanishes. Resizing concurrently is worse: in Java 7 it could produce a circular
     * chain and hang a CPU core forever. Java 8 changed the resize algorithm so the infinite loop
     * is gone, but lost updates, a wrong `size` field, and occasional ArrayIndexOutOfBoundsException
     * or ClassCastException remain entirely possible.
     *
     * ConcurrentHashMap locks or CASes per bin, so writers to different buckets never contend, and
     * writers to the same bucket serialise correctly.
     *
     * IMPORTANT AND OFTEN MISSED: ConcurrentHashMap makes each individual operation atomic. It does
     * NOT make a sequence of operations atomic. The classic bug is
     *
     *     if (!map.containsKey(k)) { map.put(k, expensive()); }
     *
     * which is a check-then-act race even on a ConcurrentHashMap. Use putIfAbsent, computeIfAbsent,
     * merge or compute, all of which are atomic as a unit.
     */
    private static void concurrencyShootout() throws Exception {
        final int threads = 8;
        final int perThread = 20_000;
        final int expected = threads * perThread;

        Map<Integer, Integer> plain = new HashMap<>();
        Map<Integer, Integer> safe = new ConcurrentHashMap<>();

        int plainSize = hammer(plain, threads, perThread);
        int safeSize = hammer(safe, threads, perThread);

        System.out.printf("expected entries      : %d%n", expected);
        System.out.printf("HashMap  final size   : %d   %s%n", plainSize,
                plainSize == expected ? "(got lucky this run - run it again)" : "<-- WRONG, entries lost");
        System.out.printf("ConcurrentHashMap size: %d   %s%n", safeSize,
                safeSize == expected ? "correct" : "<-- unexpected, please report");
        System.out.println();
        System.out.println("The HashMap result is not deterministic. Run this program several times;");
        System.out.println("you may occasionally see the correct number, and you may see an exception");
        System.out.println("reported above. That non-determinism is exactly why concurrency bugs");
        System.out.println("survive code review and testing, and why finding one in a security cache");
        System.out.println("is worth reporting even when you cannot reproduce it on demand.");
    }

    private static int hammer(Map<Integer, Integer> map, int threads, int perThread) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        for (int t = 0; t < threads; t++) {
            final int base = t * perThread;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        map.put(base + i, i);
                    }
                } catch (Throwable e) {
                    // A plain HashMap can genuinely throw from concurrent structural modification.
                    System.out.println("  thread threw: " + e.getClass().getSimpleName());
                }
            });
        }
        start.countDown();
        pool.shutdown();
        if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
            pool.shutdownNow();
        }
        return map.size();
    }

    // ==============================================================================================
    // 5. The equals/hashCode contract
    // ==============================================================================================
    /*
     * THE CONTRACT, in full:
     *   a) If a.equals(b) then a.hashCode() == b.hashCode(). Mandatory.
     *   b) If a.hashCode() == b.hashCode(), a.equals(b) may still be false. That is just a
     *      collision, and it is only a performance concern.
     *   c) equals must be reflexive, symmetric, transitive, and consistent, and x.equals(null)
     *      must return false.
     *   d) Neither result may change while the object is a key in a hash-based collection.
     *
     * Three violations are demonstrated below, each with a different failure mode.
     */
    private static void brokenEqualsAndHashCode() {
        // --- Violation of (a): equals overridden, hashCode not ------------------------------------
        System.out.println("A. equals overridden but hashCode inherited from Object");
        Map<HalfBroken, String> m1 = new HashMap<>();
        m1.put(new HalfBroken("admin"), "granted");
        HalfBroken lookup = new HalfBroken("admin");
        System.out.println("   the two keys are equal        : " + new HalfBroken("admin").equals(lookup));
        System.out.println("   but map.get returns           : " + m1.get(lookup));
        System.out.println("   and map.containsKey returns   : " + m1.containsKey(lookup));
        System.out.println("   Object.hashCode is identity based, so the two equal keys hash to");
        System.out.println("   different buckets and the lookup never even reaches the equals call.");
        System.out.println();

        Set<HalfBroken> s1 = new HashSet<>();
        s1.add(new HalfBroken("admin"));
        s1.add(new HalfBroken("admin"));
        System.out.println("   a Set now contains " + s1.size() + " elements that are equal to each other");
        System.out.println("   SECURITY CONSEQUENCE: a revocation list, a blocklist, or a set of");
        System.out.println("   granted permissions built like this silently fails to match.");
        System.out.println();

        // --- Violation of (d): the key mutates after insertion ------------------------------------
        System.out.println("B. a mutable key changed after it was inserted");
        Map<Mutable, String> m2 = new HashMap<>();
        Mutable key = new Mutable("user");
        m2.put(key, "session-token");
        System.out.println("   before mutation, get(key)     : " + m2.get(key));
        key.name = "admin";                       // changes hashCode
        System.out.println("   after  mutation, get(key)     : " + m2.get(key));
        System.out.println("   size still reports            : " + m2.size());
        System.out.println("   The entry is still physically in the table, but it is filed under the");
        System.out.println("   OLD bucket, so it can never be found again - not even with the very");
        System.out.println("   object used to insert it. Never use a mutable object as a map key.");
        System.out.println();

        // --- Violation of (c): asymmetric equals --------------------------------------------------
        System.out.println("C. asymmetric equals");
        Asymmetric parent = new Asymmetric("token");
        AsymmetricChild child = new AsymmetricChild("token", "extra");
        System.out.println("   parent.equals(child)          : " + parent.equals(child));
        System.out.println("   child.equals(parent)          : " + child.equals(parent));
        System.out.println("   Whether a comparison succeeds now depends on which operand is on the");
        System.out.println("   left. List.contains, Set.contains and Map.get do not promise you which");
        System.out.println("   side they will use, so the result becomes implementation dependent.");
        System.out.println();

        // --- The correct implementation -----------------------------------------------------------
        System.out.println("D. a correct implementation, for comparison");
        Map<GoodKey, String> m3 = new HashMap<>();
        m3.put(new GoodKey(7), "granted");
        System.out.println("   map.get(new GoodKey(7))       : " + m3.get(new GoodKey(7)));
        System.out.println("   Use Objects.equals and Objects.hash, include exactly the same fields");
        System.out.println("   in both methods, and make those fields final.");
    }

    // ==============================================================================================
    // 6. Ordering
    // ==============================================================================================
    private static void orderingComparison() {
        String[] keys = { "delta", "alpha", "charlie", "bravo", "echo" };

        Map<String, Integer> hash = new HashMap<>();
        Map<String, Integer> linked = new LinkedHashMap<>();
        Map<String, Integer> tree = new TreeMap<>();
        for (int i = 0; i < keys.length; i++) {
            hash.put(keys[i], i);
            linked.put(keys[i], i);
            tree.put(keys[i], i);
        }

        System.out.println("inserted in order : " + Arrays.toString(keys));
        System.out.println("HashMap           : " + hash.keySet() + "   (bucket order, do not rely on it)");
        System.out.println("LinkedHashMap     : " + linked.keySet() + "   (insertion order, guaranteed)");
        System.out.println("TreeMap           : " + tree.keySet() + "   (sorted, guaranteed)");
        System.out.println();
        System.out.println("HashMap's iteration order is an implementation detail. It is stable for a");
        System.out.println("given JDK and a given set of keys, which is exactly what makes it");
        System.out.println("dangerous: code accidentally depends on it, passes every test, and then");
        System.out.println("breaks on a different runtime. On Android that different runtime is a");
        System.out.println("different OEM's device.");
    }

    // ==============================================================================================
    // Supporting types
    // ==============================================================================================

    /** Correct: equals and hashCode use the same single field, and that field is final. */
    static final class GoodKey {
        private final int id;

        GoodKey(int id) { this.id = id; }

        @Override public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof GoodKey)) return false;
            return id == ((GoodKey) o).id;
        }

        @Override public int hashCode() { return Integer.hashCode(id); }
    }

    /** Deliberately terrible: correct but constant, so every instance lands in one bucket. */
    static final class BadKey {
        private final int id;

        BadKey(int id) { this.id = id; }

        @Override public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof BadKey)) return false;
            return id == ((BadKey) o).id;
        }

        @Override public int hashCode() { return 42; }   // legal, contract-compliant, catastrophic
    }

    /** Violates rule (a): equals overridden, hashCode left as Object's identity hash. */
    static final class HalfBroken {
        private final String name;

        HalfBroken(String name) { this.name = name; }

        @Override public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof HalfBroken)) return false;
            return Objects.equals(name, ((HalfBroken) o).name);
        }
        // hashCode deliberately NOT overridden.
    }

    /** Violates rule (d): the field used by equals and hashCode is mutable. */
    static final class Mutable {
        String name;                                   // not final: that is the bug

        Mutable(String name) { this.name = name; }

        @Override public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Mutable)) return false;
            return Objects.equals(name, ((Mutable) o).name);
        }

        @Override public int hashCode() { return Objects.hash(name); }
    }

    /** Violates rule (c): equals is not symmetric across the subclass boundary. */
    static class Asymmetric {
        final String value;

        Asymmetric(String value) { this.value = value; }

        @Override public boolean equals(Object o) {
            if (!(o instanceof Asymmetric)) return false;
            return Objects.equals(value, ((Asymmetric) o).value);   // accepts subclasses
        }

        @Override public int hashCode() { return Objects.hash(value); }
    }

    static final class AsymmetricChild extends Asymmetric {
        final String extra;

        AsymmetricChild(String value, String extra) { super(value); this.extra = extra; }

        @Override public boolean equals(Object o) {
            if (!(o instanceof AsymmetricChild)) return false;       // rejects the parent
            AsymmetricChild other = (AsymmetricChild) o;
            return Objects.equals(value, other.value) && Objects.equals(extra, other.extra);
        }

        @Override public int hashCode() { return Objects.hash(value, extra); }
    }

    // ==============================================================================================
    // Tiny timing helpers. Not a substitute for JMH - good enough to show orders of magnitude.
    // ==============================================================================================

    private interface Body { void run(); }

    private interface ValueBody { long run(); }

    private static long time(Body body) {
        long t0 = System.nanoTime();
        body.run();
        return (System.nanoTime() - t0) / 1_000_000;
    }

    private static long time(ValueBody body) {
        long t0 = System.nanoTime();
        long sink = body.run();
        long ms = (System.nanoTime() - t0) / 1_000_000;
        if (sink == Long.MIN_VALUE) System.out.print("");   // stop the JIT eliminating the work
        return ms;
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("=== " + title + " " + "=".repeat(Math.max(0, 60 - title.length())));
    }
}
