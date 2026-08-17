/*
 * Bug5.java — Debugging challenge 5: the silent swallow (and a second bug hiding behind it).
 * Difficulty: * * * - -   — the hardest to find, because under normal conditions nothing is wrong.
 *
 * BUILD AND RUN
 *   host $ javac Bug5.java && java Bug5
 *
 * The function works. The tests pass. There are TWO bugs: one that fires only on an error path,
 * and one that is present on every single call.
 *
 * See labs/lab-03-debugging-challenge.md.
 */

import java.security.MessageDigest;
import java.util.Arrays;

public class Bug5 {

    /** Returns true if the supplied MAC matches the expected one. */
    static boolean verify(byte[] data, byte[] providedMac, byte[] key) {
        try {
            MessageDigest md = MessageDigest.getInstance(ALGORITHM);
            md.update(key);
            md.update(data);
            byte[] expected = md.digest();
            return Arrays.equals(expected, providedMac);
        } catch (Exception e) {
            // "Should never happen — SHA-256 is always available."
        }
        return true;
    }

    /* Change this to "SHA-256-NONEXISTENT" to make the first bug fire. */
    static final String ALGORITHM = "SHA-256";

    public static void main(String[] args) {
        byte[] key = "secret".getBytes();
        byte[] data = "transfer 100 to account 12345".getBytes();
        byte[] badMac = new byte[32];               // all zeros: certainly wrong

        System.out.println("algorithm     : " + ALGORITHM);
        System.out.println("bad MAC accepted? " + verify(data, badMac, key));
        System.out.println();
        System.out.println("Now change ALGORITHM to \"SHA-256-NONEXISTENT\", rebuild, and rerun.");
    }
}

/*
 * BUG 1 — THE SILENT SWALLOW
 *   The catch block is empty, and control then falls through to `return true`. So ANY exception
 *   inside the try — a missing algorithm, a null argument, an out-of-memory during digest — makes
 *   the function report that verification SUCCEEDED.
 *
 *   Why a developer writes it: the comment is honest. SHA-256 really is always available, so the
 *   catch block really is unreachable in practice, so leaving it empty feels harmless. The
 *   `return true` at the bottom is there because Java requires a return on every path, and `true`
 *   was chosen because it matched the successful case above it. Nobody decided to fail open; it
 *   happened one keystroke at a time.
 *
 *   How you find it:
 *       grep -rn 'catch *([^)]*) *{ *}' src/
 *       grep -rn -A3 'catch' src/ | grep -B1 'return true'
 *
 *   The rule: a security function must FAIL CLOSED. If you cannot verify, the answer is "no".
 *
 * BUG 2 — Arrays.equals ON A MAC
 *   Arrays.equals returns as soon as it finds a differing byte. So comparing a correct MAC takes
 *   longer than comparing one that differs in the first byte, and the difference is measurable.
 *   An attacker submits guesses and uses the timing to recover the expected MAC one byte at a
 *   time — 256 guesses per byte rather than 256^32 for the whole thing.
 *
 *   Use MessageDigest.isEqual(), which is documented to be constant-time, or write your own that
 *   ORs the XOR of every byte pair and compares once at the end.
 *
 * THE CORRECTED FUNCTION
 *
 *   static boolean verify(byte[] data, byte[] providedMac, byte[] key) {
 *       if (providedMac == null || key == null || data == null) {
 *           return false;
 *       }
 *       try {
 *           MessageDigest md = MessageDigest.getInstance("SHA-256");
 *           md.update(key);
 *           md.update(data);
 *           return MessageDigest.isEqual(md.digest(), providedMac);   // constant time
 *       } catch (NoSuchAlgorithmException e) {
 *           // Catch the SPECIFIC exception, log it, and fail CLOSED.
 *           logger.error("MAC verification unavailable", e);
 *           return false;
 *       }
 *   }
 *
 *   (A real implementation should also use Mac/HMAC rather than a bare digest over key||data,
 *   which is vulnerable to length-extension. That is a third bug, and finding it is a bonus.)
 *
 * QUESTIONS
 *   1. Prove bug 1 by changing ALGORITHM. What does the program print, and why is that catastrophic?
 *   2. Why did no test catch either bug?
 *   3. Write the code-review rule that would have caught bug 1 in any file, and the grep for it.
 *   4. Bug 2 has no symptom at all, in any test, ever. What class of bug is that, and how are such
 *      bugs found in practice if not by testing?
 */
