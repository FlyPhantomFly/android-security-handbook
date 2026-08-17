/*
 * Bug4.java — Debugging challenge 4: reference versus value.
 * Difficulty: * * - - -   (and it catches experienced people)
 *
 * BUILD AND RUN
 *   host $ javac Bug4.java && java Bug4
 *
 * Both printed lines are the opposite of what the developer expected. There is no compiler warning,
 * no exception, and no crash. This is the shape of bug that survives testing.
 *
 * See labs/lab-03-debugging-challenge.md.
 */

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Bug4 {

    /** Intended to add a default role to the caller's list. */
    static void addDefaults(List<String> roles) {
        roles = new ArrayList<>(roles);      // a "defensive copy"
        roles.add("user");
        // The caller sees nothing. Why?
    }

    /** Intended to build a promoted name WITHOUT touching the caller's object. */
    static void promote(StringBuilder role) {
        role.append("-admin");
        // The caller sees the change. Why?
    }

    /** Intended to wipe key material. */
    static void wipe(byte[] key) {
        key = new byte[key.length];          // "clears" it
        // Does it?
    }

    public static void main(String[] args) {
        List<String> roles = new ArrayList<>();
        roles.add("guest");
        addDefaults(roles);
        System.out.println("roles = " + roles + "        (developer expected [guest, user])");

        StringBuilder r = new StringBuilder("editor");
        promote(r);
        System.out.println("role  = " + r + "     (developer expected editor)");

        byte[] key = {1, 2, 3, 4, 5, 6, 7, 8};
        wipe(key);
        System.out.println("key   = " + Arrays.toString(key) +
                           "   (developer expected all zeros)");
    }
}

/*
 * QUESTIONS
 *   1. Explain each of the three results using this sentence: "Java is ALWAYS pass by value, and
 *      for objects the value being copied is the REFERENCE."
 *   2. Why does REASSIGNING the parameter (addDefaults, wipe) have no effect on the caller, while
 *      MUTATING the object (promote) does?
 *   3. The `wipe` case is a real security bug. The developer believes the key material has been
 *      erased. What is actually still in memory, and where does it go from there?
 *      (See chapter 03 section 3.14.4 and scripts/heap-string-search.js.)
 *   4. Which of the three would a unit test have caught? Which would not, and why?
 *
 * THE FIXES
 *   addDefaults : mutate the list the caller passed —  roles.add("user");
 *                 or, better, return a new list and make the method's contract honest.
 *   promote     : take a String and return a new one, so the signature says what it does.
 *   wipe        : Arrays.fill(key, (byte) 0);   — overwrite the array's CONTENTS, not the variable.
 *
 * THE GENERAL RULE
 *   If a method's name says it changes something, its signature should show what. A method that
 *   takes a mutable object and quietly mutates it, and a method that takes one and quietly does
 *   not, are indistinguishable at the call site — which is why this bug is so durable.
 */
