/*
 * SerializationDemo.java
 * ======================
 *
 * WHAT THIS DOES
 * --------------
 * Answers, as running code, the question in ../faq.md #21: "why is deserialization dangerous if
 * the data is just my own app's data?" It shows the vulnerable pattern first — with an honest
 * explanation of why a competent developer writes it — and then the three mitigations in the
 * order of preference the FAQ states:
 *
 *   1. Do not deserialize untrusted input at all. Use an explicitly parsed format such as JSON
 *      with a schema, so the parser can only ever produce data, never arbitrary objects.
 *   2. If you must, install an ObjectInputFilter allow-list, so a class that is not on the list
 *      is rejected BEFORE it is resolved and BEFORE its readObject runs.
 *   3. Validate before you construct, never after, so no code path can produce an object that
 *      was never checked.
 *
 * Section 0 builds the intuition the whole topic rests on: readObject is not a getter. It is
 * attacker-chosen code that runs before your first line does.
 *
 * HOW TO RUN
 * ----------
 *   Single file, no compilation step and no .class files left on disk, JDK 17 or newer:
 *
 *       # host
 *       java SerializationDemo.java
 *
 *   Or compile first, if you then want to feed it to d8 and jadx:
 *
 *       # host
 *       javac SerializationDemo.java
 *       java SerializationDemo
 *
 *   Requires JDK 17+ because it uses java.io.ObjectInputFilter, which is Java 9+ and is the
 *   API the JDK documents for this problem. Everything else here is Java 8 vintage. No external
 *   dependencies; standard library only.
 *
 * A NOTE ON ANDROID
 * -----------------
 * ObjectInputFilter is a comparatively recent addition to the Android API surface, so before you
 * recommend it in a report, check whether it exists at the application's minSdk. Section 3 also
 * shows the portable fallback — subclassing ObjectInputStream and overriding resolveClass — which
 * works on every Android version ever shipped and gives you the same allow-list gate, minus the
 * resource limits.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 * -----------------------------
 *   - It contains no real gadget chain. Building one requires a classpath with the right library
 *     versions on it, and shipping one in a teaching repository would be irresponsible. The
 *     Trigger class in section 0 stands in for the real thing: it proves the mechanism (your code
 *     runs during readObject) without weaponising it.
 *   - An allow-list filter does not make a stream trustworthy. It stops class instantiation; it
 *     does nothing about the VALUES inside an allowed class. Section 4 demonstrates that with a
 *     byte-level tamper that survives every mitigation here.
 *   - None of this provides integrity. If a value must not be changed by whoever holds the bytes,
 *     the answer is a MAC or keeping the value on the server, not a better parser.
 *
 * RELATED
 * -------
 *   ../faq.md                       #21 and #22, the questions this file answers
 *   ../README.md                    section 3, the language mechanics underneath
 *   ReflectionDemo.java             how readObject reaches private members in the first place
 *   ../../34-Cryptography/README.md MACs, which are what you actually want for integrity
 *
 * AUTHORISED TESTING ONLY.
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.InvalidObjectException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class SerializationDemo {

    public static void main(String[] args) throws Exception {
        section("0. The intuition: readObject is code, and it runs before your code does");
        gadgetIntuition();

        section("1. The vulnerable version, and why a good developer writes it");
        vulnerableVersion();

        section("2. Mitigation 1 (best) — do not deserialize; parse an explicit format");
        mitigationOneExplicitFormat();

        section("3. Mitigation 2 — if you must, install an ObjectInputFilter allow-list");
        mitigationTwoAllowList();

        section("4. Mitigation 3 — validate BEFORE you construct, never after");
        mitigationThreeValidateFirst();

        section("5. What to take away");
        takeaways();
    }

    /* =====================================================================================
     * The value object the application actually wants to move around.
     *
     * Note what it does NOT have: a public constructor, a setter, or a mutable field. Every
     * instance that exists came through Session.of, which is the whole point of section 4.
     * ===================================================================================== */

    static final class Session implements Serializable {

        private static final long serialVersionUID = 1L;

        // Five characters each, deliberately, so that the byte-level tamper in section 4 is a
        // clean same-length substitution. Real role names are rarely so convenient; the attack
        // is not limited to equal lengths, it is just easier to demonstrate that way.
        static final Set<String> VALID_ROLES = Set.of("guest", "admin", "staff");

        private final String user;
        private final String role;
        private final long expiresAtEpochSecond;

        private Session(String user, String role, long expiresAtEpochSecond) {
            this.user = user;
            this.role = role;
            this.expiresAtEpochSecond = expiresAtEpochSecond;
        }

        /**
         * The ONLY way to build a Session. Validation happens before the constructor is reached,
         * so there is no window in which a half-checked Session exists, and no second code path
         * that a future maintainer can add which skips the check.
         */
        static Session of(String user, String role, long expiresAtEpochSecond) {
            requireValid(user, role, expiresAtEpochSecond);
            return new Session(user, role, expiresAtEpochSecond);
        }

        private static void requireValid(String user, String role, long expires) {
            if (user == null || user.isEmpty() || user.length() > 64) {
                throw new IllegalArgumentException("user must be 1..64 characters");
            }
            for (int i = 0; i < user.length(); i++) {
                char c = user.charAt(i);
                boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                        || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
                if (!ok) {
                    throw new IllegalArgumentException("user contains an illegal character: " + c);
                }
            }
            if (role == null || !VALID_ROLES.contains(role)) {
                throw new IllegalArgumentException("role is not one of " + VALID_ROLES
                        + " (got " + role + ")");
            }
            if (expires < 0 || expires > 4_102_444_800L) {   // 2100-01-01, a sanity ceiling
                throw new IllegalArgumentException("expiry out of range: " + expires);
            }
        }

        /**
         * Mitigation 3 applied to the serialization path.
         *
         * defaultReadObject has already populated every field by the time this runs, so this is
         * validation AFTER construction, which is exactly what the FAQ tells you not to rely on.
         * It is here because it is better than nothing and because you will be asked to write it
         * in a remediation. Understand precisely what it buys and what it does not:
         *
         *   IT DOES     stop an invalid Session from escaping into the rest of the program.
         *   IT DOES NOT stop a gadget, because a gadget is a DIFFERENT class. Its readObject ran
         *               to completion long before the stream ever got to a Session.
         *
         * That asymmetry is the entire reason mitigations 1 and 2 rank above this one.
         */
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            try {
                requireValid(user, role, expiresAtEpochSecond);
            } catch (IllegalArgumentException e) {
                throw new InvalidObjectException("rejected deserialized Session: " + e.getMessage());
            }
        }

        @Override
        public String toString() {
            return "Session{user=" + user + ", role=" + role
                    + ", expires=" + expiresAtEpochSecond + "}";
        }
    }

    /* =====================================================================================
     * SECTION 0 — the intuition
     * ===================================================================================== */

    /**
     * A stand-in for a gadget. It does nothing harmful; it only proves WHEN it runs.
     *
     * A real gadget chain is a sequence of classes already on your classpath whose readObject,
     * readResolve, finalize, hashCode, equals, or toString implementations do something useful
     * when composed: one of them calls a method on a field, that field is a proxy the attacker
     * chose, the proxy dispatches reflectively, and the reflective call ends at Runtime.exec or a
     * JNDI lookup. The attacker writes no code. They assemble an object graph out of YOUR
     * dependencies and let ObjectInputStream build it.
     *
     * The attacker's leverage is therefore your dependency list, and it grows every time you add
     * a library.
     */
    static final class Trigger implements Serializable {

        private static final long serialVersionUID = 1L;

        private final String note;

        Trigger(String note) {
            this.note = note;
        }

        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // In a real chain, this line is where Runtime.exec or a reflective invoke happens.
            System.out.println("      [!] Trigger.readObject just executed: \"" + note + "\"");
        }
    }

    static void gadgetIntuition() throws Exception {
        byte[] hostile = serialize(new Trigger("attacker-chosen code, running inside your process"));

        System.out.println("  The application expects a Session. It is handed a Trigger.");
        System.out.println("  Watch the ORDER of what follows:\n");
        System.out.println("      calling readObject()...");

        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(hostile))) {
            Session s = (Session) ois.readObject();   // the cast is the developer's "type check"
            System.out.println("      got " + s);
        } catch (ClassCastException e) {
            System.out.println("      ClassCastException: " + e.getMessage());
        }

        System.out.println();
        System.out.println("  Read that again. The Trigger's code ran, and THEN the cast failed.");
        System.out.println("  A cast is not a check. readObject reads a class name out of the");
        System.out.println("  stream, resolves it, allocates it, populates its fields and calls");
        System.out.println("  its readObject — all before it returns a reference for you to cast.");
        System.out.println("  By the time your type check runs, the attacker's code is finished.");
    }

    /* =====================================================================================
     * SECTION 1 — the vulnerable version
     * ===================================================================================== */

    /**
     * The code that ships.
     *
     * WHY A GOOD DEVELOPER WRITES THIS, and it is worth understanding sincerely before you put
     * it in a report:
     *
     *   - It is three lines and it works on the first try.
     *   - It round-trips the entire object graph — nested objects, collections, maps, cycles —
     *     with no mapping code, no schema, and nothing to keep in sync when a field is added.
     *   - Every tutorial, every StackOverflow answer, and Java's own documentation present it as
     *     the normal way to persist an object.
     *   - The bytes "come from our own app": SharedPreferences, a cache file in the app's private
     *     directory, an Intent extra we sent to ourselves. The developer is not being careless.
     *     They are reasoning about the SOURCE of the data, and their reasoning is correct right
     *     up to the moment the device is rooted, the file is in shared storage, the Intent
     *     arrives from a component that turned out to be exported, or a backup is restored from
     *     another device.
     *
     * The defect is not the trust decision. It is that the mechanism gives an attacker who beats
     * that trust decision far more than bad data: it gives them class instantiation.
     */
    static Session loadSessionVulnerable(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            Session session = (Session) ois.readObject();   // <-- everything already happened here
            // Validation lives down here, which is "validate after you construct".
            if (session.expiresAtEpochSecond < 0) {
                throw new IllegalStateException("expired");
            }
            return session;
        }
    }

    static void vulnerableVersion() throws Exception {
        Session good = Session.of("alice", "guest", 1_900_000_000L);
        byte[] bytes = serialize(good);

        System.out.println("  Happy path — the developer's test, which passes:");
        System.out.println("      " + loadSessionVulnerable(bytes));
        System.out.println();
        System.out.println("  Serialized size: " + bytes.length + " bytes, of which the class name,");
        System.out.println("  the field names and their type descriptors are plaintext:");
        System.out.println();
        System.out.println("      " + previewAscii(bytes, 96));
        System.out.println();
        System.out.println("  That plaintext is the reverse engineer's way in. A Serializable");
        System.out.println("  stream is SELF-DESCRIBING: it names the class it wants built. That is");
        System.out.println("  what makes it convenient, and it is the same property that lets an");
        System.out.println("  attacker name a different class instead. See ../faq.md #22 for how");
        System.out.println("  Parcelable differs — it is positional and names nothing.");
    }

    /* =====================================================================================
     * SECTION 2 — Mitigation 1: do not deserialize. Parse.
     * ===================================================================================== */

    static void mitigationOneExplicitFormat() {
        Session good = Session.of("alice", "guest", 1_900_000_000L);

        String json = toJson(good);
        System.out.println("  Stored as an explicitly parsed format instead of an object stream:");
        System.out.println("      " + json);
        System.out.println();

        Session back = fromJson(json);
        System.out.println("  Parsed back: " + back);
        System.out.println();

        // The same hostile input, expressed in this format. There is nothing to express it WITH.
        String hostile = "{\"@class\":\"SerializationDemo$Trigger\",\"note\":\"pwn\"}";
        System.out.println("  Now the hostile input, in the same format:");
        System.out.println("      " + hostile);
        try {
            fromJson(hostile);
            System.out.println("      accepted — which would be a bug in this demo");
        } catch (IllegalArgumentException e) {
            System.out.println("      rejected: " + e.getMessage());
        }

        System.out.println();
        System.out.println("  WHY THIS IS THE BEST MITIGATION, and it is not about JSON:");
        System.out.println("    The parser below can produce exactly four things — String, Long,");
        System.out.println("    Boolean and null. It has no mechanism for naming a class, so there");
        System.out.println("    is no gadget surface to filter, no allow-list to maintain, and");
        System.out.println("    nothing for a new dependency to add to the attack surface. The");
        System.out.println("    security property comes from the parser being unable to construct");
        System.out.println("    arbitrary types, not from the data looking like JSON.");
        System.out.println();
        System.out.println("    Which is also the warning: a JSON library configured with");
        System.out.println("    polymorphic type handling — an \"@class\" or \"$type\" field that");
        System.out.println("    selects the class to build — reintroduces the identical bug. Jackson");
        System.out.println("    default typing and Gson RuntimeTypeAdapter are the two you will meet.");
        System.out.println("    Turn it off, or grep for it during review.");
    }

    /** Serialise a Session by hand. Explicit, boring, and it names no classes. */
    static String toJson(Session s) {
        return "{\"user\":\"" + escapeJson(s.user) + "\","
                + "\"role\":\"" + escapeJson(s.role) + "\","
                + "\"expires\":" + s.expiresAtEpochSecond + "}";
    }

    /**
     * Parse a Session, schema first.
     *
     * The order of operations is the lesson: parse into plain data, check the SHAPE against a
     * schema we declared, then hand validated arguments to Session.of, which validates again and
     * is the only thing that can produce a Session. At no point does the input choose a type.
     */
    static Session fromJson(String json) {
        Map<String, Object> fields = TinyJson.parseFlatObject(json);

        // Schema check: exactly these keys, no more and no fewer. An unexpected key is not
        // ignored, it is an error — because "ignore what you do not understand" is how
        // polymorphic-typing bugs stay hidden for years.
        List<String> expected = List.of("user", "role", "expires");
        if (!fields.keySet().equals(new java.util.LinkedHashSet<>(expected))) {
            throw new IllegalArgumentException("schema mismatch: expected keys " + expected
                    + ", got " + fields.keySet());
        }
        Object user = fields.get("user");
        Object role = fields.get("role");
        Object expires = fields.get("expires");
        if (!(user instanceof String) || !(role instanceof String) || !(expires instanceof Long)) {
            throw new IllegalArgumentException("schema mismatch: wrong types");
        }

        return Session.of((String) user, (String) role, (Long) expires);
    }

    /* =====================================================================================
     * SECTION 3 — Mitigation 2: ObjectInputFilter allow-list
     * ===================================================================================== */

    static void mitigationTwoAllowList() throws Exception {
        // Pattern syntax: resource limits first, then class patterns, then a final "!*" that
        // rejects everything not named above. Build the class name from the class literal so the
        // filter cannot drift out of sync with a rename.
        String pattern = "maxdepth=5;maxrefs=50;maxbytes=4096;"
                + Session.class.getName() + ";"
                + "java.lang.String;"
                + "!*";
        ObjectInputFilter allowList = ObjectInputFilter.Config.createFilter(pattern);

        System.out.println("  Filter pattern:");
        System.out.println("      " + pattern);
        System.out.println();
        System.out.println("      maxdepth / maxrefs / maxbytes bound the resources a stream may");
        System.out.println("      consume, which is a separate denial-of-service problem: a stream");
        System.out.println("      of a few kilobytes can describe an object graph that exhausts");
        System.out.println("      the heap. The trailing !* is the important part — an allow-list");
        System.out.println("      is a list of what is permitted, ending in a refusal of");
        System.out.println("      everything else. A deny-list of known gadgets is not a");
        System.out.println("      mitigation, it is a list of the gadgets somebody has published.");
        System.out.println();

        byte[] legitimate = serialize(Session.of("alice", "guest", 1_900_000_000L));
        byte[] hostile = serialize(new Trigger("this must never print"));

        System.out.println("  Legitimate stream:");
        System.out.println("      " + readFiltered(legitimate, allowList));

        System.out.println("  Hostile stream:");
        System.out.println("      " + readFiltered(hostile, allowList));
        System.out.println();
        System.out.println("      Note what did NOT appear above: Trigger.readObject printed");
        System.out.println("      nothing. The filter is consulted while the class is being");
        System.out.println("      resolved, which is before allocation and therefore before any of");
        System.out.println("      the class's own code can run. That is the property that makes it");
        System.out.println("      a real control rather than a late check.");
        System.out.println();

        // The portable form, for an API level without ObjectInputFilter.
        System.out.println("  The portable fallback — override resolveClass:");
        System.out.println("      Legitimate: " + readWithResolveClassGate(legitimate));
        System.out.println("      Hostile:    " + readWithResolveClassGate(hostile));
        System.out.println();
        System.out.println("      resolveClass is called at the same point in the stream and gives");
        System.out.println("      you the same gate, on every Android version. What it does not");
        System.out.println("      give you is maxdepth, maxrefs and maxbytes, so the resource");
        System.out.println("      exhaustion problem remains yours to bound.");
    }

    static String readFiltered(byte[] bytes, ObjectInputFilter filter) throws IOException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
            ois.setObjectInputFilter(filter);   // must be set before the first readObject
            return "accepted -> " + ois.readObject();
        } catch (InvalidClassException e) {
            return "REJECTED by the filter -> " + e.getMessage();
        } catch (ClassNotFoundException | ClassCastException e) {
            return "rejected -> " + e;
        }
    }

    /**
     * An allow-list gate that works on any JDK and any Android version.
     *
     * resolveClass is ObjectInputStream's hook for turning a class name from the stream into a
     * Class object. Throwing here stops the stream before the class is instantiated.
     */
    static final class AllowListObjectInputStream extends ObjectInputStream {

        private final Set<String> allowed;

        AllowListObjectInputStream(ByteArrayInputStream in, Set<String> allowed) throws IOException {
            super(in);
            this.allowed = allowed;
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            if (!allowed.contains(desc.getName())) {
                throw new InvalidClassException(desc.getName(), "not on the allow-list");
            }
            return super.resolveClass(desc);
        }
    }

    static String readWithResolveClassGate(byte[] bytes) throws IOException {
        Set<String> allowed = Set.of(Session.class.getName(), "java.lang.String");
        try (ObjectInputStream ois =
                     new AllowListObjectInputStream(new ByteArrayInputStream(bytes), allowed)) {
            return "accepted -> " + ois.readObject();
        } catch (InvalidClassException e) {
            return "REJECTED -> " + e.getMessage() + " (" + e.classname + ")";
        } catch (ClassNotFoundException | ClassCastException e) {
            return "rejected -> " + e;
        }
    }

    /* =====================================================================================
     * SECTION 4 — Mitigation 3: validate before you construct
     * ===================================================================================== */

    static void mitigationThreeValidateFirst() throws Exception {
        System.out.println("  Validate-before-construct means Session has a private constructor");
        System.out.println("  and one static factory, Session.of, that checks its arguments before");
        System.out.println("  the constructor is reached. There is no code path to an unchecked");
        System.out.println("  Session, today or after the next three maintainers have edited it.");
        System.out.println();
        System.out.println("      Session.of(\"alice\", \"guest\", ...)  -> ok");
        try {
            Session.of("alice", "root", 1_900_000_000L);
        } catch (IllegalArgumentException e) {
            System.out.println("      Session.of(\"alice\", \"root\",  ...)  -> " + e.getMessage());
        }
        System.out.println();

        // Now the byte-level tamper. Roles here are all five characters, so swapping one for
        // another is a same-length substitution in the serialized bytes and needs no re-encoding
        // of any length prefix. This is exactly what an attacker with the file does.
        byte[] original = serialize(Session.of("alice", "guest", 1_900_000_000L));

        byte[] invalid = tamperAscii(original, "guest", "r00t!");
        System.out.println("  Tampered stream, role \"guest\" -> \"r00t!\" (not a valid role):");
        try {
            System.out.println("      " + loadSessionVulnerable(invalid));
        } catch (InvalidObjectException e) {
            System.out.println("      readObject validation caught it: " + e.getMessage());
        }
        System.out.println();
        System.out.println("      That is mitigation 3 doing its job on the serialization path.");
        System.out.println("      An invalid Session never escapes into the rest of the program.");
        System.out.println();

        byte[] privileged = tamperAscii(original, "guest", "admin");
        System.out.println("  Tampered stream, role \"guest\" -> \"admin\" (a perfectly valid role):");
        System.out.println("      " + loadSessionVulnerable(privileged));
        System.out.println();
        System.out.println("      And that is the limit of every mitigation in this file. The value");
        System.out.println("      is well-formed, the class is allow-listed, the schema matches,");
        System.out.println("      the constructor's validation passes — and the user is now an");
        System.out.println("      administrator. Validation answers \"is this data well-formed?\".");
        System.out.println("      It cannot answer \"did the holder of these bytes change them?\".");
        System.out.println();
        System.out.println("      For that you need integrity, which means one of:");
        System.out.println("        - keep the value server-side and hand the client an opaque");
        System.out.println("          reference, which is the correct answer for a session role;");
        System.out.println("        - or sign the blob with a key the client cannot read, and");
        System.out.println("          verify the MAC BEFORE parsing anything. See");
        System.out.println("          ../../34-Cryptography/README.md and");
        System.out.println("          ../../49-KeyStore/README.md.");
        System.out.println();
        System.out.println("      Note the ordering in that last sentence. Verify, then parse. A MAC");
        System.out.println("      checked after deserialization protects nothing, for exactly the");
        System.out.println("      same reason the cast in section 0 protected nothing.");
    }

    /* =====================================================================================
     * SECTION 5
     * ===================================================================================== */

    static void takeaways() {
        String[] lines = {
            "1. readObject is not a parser, it is a constructor the attacker gets to drive.",
            "   Class resolution, allocation, field population and the class's own readObject",
            "   all happen before your first line of code runs.",
            "",
            "2. A cast is not a type check. It happens after.",
            "",
            "3. Mitigation ranking, and why the order is what it is:",
            "     (a) Do not deserialize untrusted input. A parser that cannot name a class has",
            "         no gadget surface, so there is nothing to maintain and nothing for a new",
            "         dependency to widen. Strongest, and usually the least work in the long run.",
            "     (b) ObjectInputFilter allow-list. Runs before instantiation, so it is a real",
            "         gate — but you now own a list that must be kept correct forever.",
            "     (c) Validate before you construct. Necessary, and it stops bad values, but a",
            "         gadget is a different class entirely and never reaches your validation.",
            "",
            "4. On Android the untrusted sources are more numerous than developers expect:",
            "   Intent extras from another app, files in shared storage, network responses,",
            "   SharedPreferences on a rooted device, and a backup restored from another device.",
            "",
            "5. As a pentester: grep for readObject, ObjectInputStream, getSerializableExtra and",
            "   Jackson/Gson polymorphic typing. Then ask where the bytes come from. The finding",
            "   is the path from an attacker-influenced source to a readObject call, not the",
            "   presence of Serializable.",
            "",
            "6. As a reviewer, the remediation you write is: replace the object stream with an",
            "   explicit schema-checked format; if that is impossible this quarter, add an",
            "   ObjectInputFilter allow-list with resource limits AND keep the validation.",
        };
        for (String line : lines) {
            System.out.println("  " + line);
        }
    }

    /* =====================================================================================
     * A deliberately tiny, deliberately strict JSON parser.
     *
     * It handles a FLAT object whose values are strings, integers, booleans or null. It rejects
     * nesting, arrays, duplicate keys, trailing data and oversized input. That is not a
     * limitation, it is the design: the smaller the set of things a parser can produce, the
     * smaller the set of things an attacker can ask it to produce.
     *
     * In a real Android app you would use Moshi, Gson or kotlinx.serialization with a declared
     * data class and polymorphic typing switched off. The security property is identical and
     * comes from the same place: the input selects VALUES, never TYPES.
     * ===================================================================================== */

    static final class TinyJson {

        private static final int MAX_INPUT = 8 * 1024;
        private static final int MAX_KEYS = 32;

        private final String src;
        private int pos;

        private TinyJson(String src) {
            this.src = src;
        }

        static Map<String, Object> parseFlatObject(String json) {
            if (json == null) {
                throw new IllegalArgumentException("input is null");
            }
            if (json.length() > MAX_INPUT) {
                // Bound the input before you look at it. This is the maxbytes idea from the
                // ObjectInputFilter, applied by hand.
                throw new IllegalArgumentException("input longer than " + MAX_INPUT + " bytes");
            }
            TinyJson p = new TinyJson(json);
            Map<String, Object> out = p.object();
            p.skipWhitespace();
            if (p.pos != json.length()) {
                throw new IllegalArgumentException("trailing data at offset " + p.pos);
            }
            return out;
        }

        private Map<String, Object> object() {
            Map<String, Object> out = new LinkedHashMap<>();
            expect('{');
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return out;
            }
            while (true) {
                skipWhitespace();
                String key = string();
                if (out.containsKey(key)) {
                    throw new IllegalArgumentException("duplicate key: " + key);
                }
                if (out.size() >= MAX_KEYS) {
                    throw new IllegalArgumentException("more than " + MAX_KEYS + " keys");
                }
                skipWhitespace();
                expect(':');
                skipWhitespace();
                out.put(key, value());
                skipWhitespace();
                char c = next();
                if (c == '}') {
                    return out;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("expected ',' or '}' at offset " + (pos - 1));
                }
            }
        }

        private Object value() {
            char c = peek();
            if (c == '"') {
                return string();
            }
            if (c == '-' || (c >= '0' && c <= '9')) {
                return number();
            }
            if (src.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            }
            if (src.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            if (src.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            // Everything else — including '{' and '[' — is refused outright. No nesting means no
            // depth limit to get wrong, and no way to describe a graph.
            throw new IllegalArgumentException(
                    "only strings, integers, booleans and null are accepted; found '" + c
                            + "' at offset " + pos);
        }

        private String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = next();
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    char esc = next();
                    switch (esc) {
                        case '"':  sb.append('"');  break;
                        case '\\': sb.append('\\'); break;
                        case '/':  sb.append('/');  break;
                        case 'b':  sb.append('\b'); break;
                        case 'f':  sb.append('\f'); break;
                        case 'n':  sb.append('\n'); break;
                        case 'r':  sb.append('\r'); break;
                        case 't':  sb.append('\t'); break;
                        case 'u':
                            if (pos + 4 > src.length()) {
                                throw new IllegalArgumentException("truncated \\u escape");
                            }
                            sb.append((char) Integer.parseInt(src.substring(pos, pos + 4), 16));
                            pos += 4;
                            break;
                        default:
                            throw new IllegalArgumentException("bad escape \\" + esc);
                    }
                } else if (c < 0x20) {
                    throw new IllegalArgumentException("raw control character in string");
                } else {
                    sb.append(c);
                }
            }
        }

        private Long number() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            while (pos < src.length() && src.charAt(pos) >= '0' && src.charAt(pos) <= '9') {
                pos++;
            }
            if (pos == start) {
                throw new IllegalArgumentException("expected a number at offset " + start);
            }
            try {
                return Long.valueOf(src.substring(start, pos));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("number out of range at offset " + start);
            }
        }

        private void skipWhitespace() {
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    return;
                }
            }
        }

        private char peek() {
            if (pos >= src.length()) {
                throw new IllegalArgumentException("unexpected end of input");
            }
            return src.charAt(pos);
        }

        private char next() {
            char c = peek();
            pos++;
            return c;
        }

        private void expect(char c) {
            if (next() != c) {
                throw new IllegalArgumentException("expected '" + c + "' at offset " + (pos - 1));
            }
        }
    }

    /* =====================================================================================
     * Small helpers
     * ===================================================================================== */

    static byte[] serialize(Serializable value) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(buffer)) {
            oos.writeObject(value);
        }
        return buffer.toByteArray();
    }

    /**
     * Replace the first occurrence of an ASCII needle with a same-length replacement.
     *
     * Same length, so no length prefix anywhere in the stream needs adjusting. This is the
     * cheapest possible tamper and it is what someone with your cache file will try first.
     */
    static byte[] tamperAscii(byte[] data, String from, String to) {
        if (from.length() != to.length()) {
            throw new IllegalArgumentException("this demo only does same-length substitution");
        }
        byte[] needle = from.getBytes(StandardCharsets.US_ASCII);
        byte[] patch = to.getBytes(StandardCharsets.US_ASCII);
        byte[] out = Arrays.copyOf(data, data.length);

        outer:
        for (int i = 0; i + needle.length <= out.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (out[i + j] != needle[j]) {
                    continue outer;
                }
            }
            System.arraycopy(patch, 0, out, i, patch.length);
            return out;
        }
        throw new IllegalArgumentException("needle not found: " + from);
    }

    /** Render bytes with printable ASCII kept and everything else shown as a dot. */
    static String previewAscii(byte[] data, int limit) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(limit, data.length); i++) {
            int b = data[i] & 0xFF;
            sb.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
        }
        if (data.length > limit) {
            sb.append("...");
        }
        return sb.toString();
    }

    static String escapeJson(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    static void section(String title) {
        System.out.println();
        System.out.println("==============================================================================");
        System.out.println(" " + title);
        System.out.println("==============================================================================");
    }
}
