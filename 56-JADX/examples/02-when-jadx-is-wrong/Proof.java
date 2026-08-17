/*
 * examples/02-when-jadx-is-wrong/Proof.java
 *
 * Chapter 56 (JADX) section 6.6 / section 9.3 -- proving a silent decompilation failure
 * by execution rather than by argument.
 *
 * Two methods:
 *   original()    -- what Accumulate.smali actually does, written out as Java
 *   jadxVersion() -- exactly what jadx 1.5.3 printed for Accumulate.smali, pasted verbatim
 *
 * They agree on every input where nothing throws. They disagree by 5 when the second array
 * read throws, because jadx folded the accumulator into a single return expression and
 * thereby discarded the partial value that was live on the exception edge.
 *
 * BUILD AND RUN (no Android, no device, no SDK -- just a JDK):
 *
 *   javac -d . Proof.java
 *   java -cp . Proof
 *
 * EXPECTED OUTPUT (measured on JDK 24):
 *
 *   original(new int[]{5})    = 105
 *   jadx output(new int[]{5}) = 100
 *   original(new int[]{5,7})    = 12
 *   jadx output(new int[]{5,7}) = 12
 *
 * WHAT THIS WILL NOT TELL YOU
 *   - It does not run the Smali. It runs a Java transcription of the Smali next to jadx's
 *     Java. The transcription's fidelity is established separately: compile original() with
 *     javac --release 8 and d8 --release, then `jadx -m fallback` it and compare the
 *     instruction dump with `jadx -m fallback Accumulate.smali`. They match.
 *   - It does not prove WHY jadx got it wrong. See VariantV4.smali for how far that
 *     narrowing got, and for the caveat that must accompany any report of it.
 *   - It does not show that jadx is unreliable in general. The overwhelming majority of
 *     compiler-produced methods decompile correctly. It shows that when jadx is wrong, it
 *     can be wrong QUIETLY -- and that is the fact your methodology has to survive.
 */
public class Proof {

    /** What the bytecode in Accumulate.smali does, transcribed. */
    static int original(int[] xs) {
        int acc = 0;
        try {
            acc += xs[0];
            acc += xs[1];
        } catch (Exception e) {
            acc += 100;
        }
        return acc;
    }

    /** Exactly what jadx 1.5.3 printed for that bytecode. Pasted, not paraphrased. */
    static int jadxVersion(int[] iArr) {
        try {
            return 0 + iArr[0] + iArr[1];
        } catch (Exception e) {
            return 0 + 100;
        }
    }

    public static void main(String[] args) {
        int[] shortArray = { 5 };          // the second read throws
        System.out.println("original(new int[]{5})    = " + original(shortArray));
        System.out.println("jadx output(new int[]{5}) = " + jadxVersion(shortArray));

        int[] ok = { 5, 7 };               // nothing throws
        System.out.println("original(new int[]{5,7})    = " + original(ok));
        System.out.println("jadx output(new int[]{5,7}) = " + jadxVersion(ok));

        if (original(shortArray) != jadxVersion(shortArray)) {
            System.out.println();
            System.out.println("DIVERGENCE on the exception path: "
                    + original(shortArray) + " vs " + jadxVersion(shortArray)
                    + "  -- and jadx printed no warning.");
        }
    }
}
