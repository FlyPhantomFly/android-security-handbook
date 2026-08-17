package com.artlab.hotmethod

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.ScrollView
import android.widget.TextView
import kotlin.system.measureNanoTime

/**
 * HotMethodDemo — watch ART move a method from interpreted to compiled.
 *
 * WHAT IT DEMONSTRATES
 *   The state machine from ../README.md section 2.4, made observable without
 *   any tooling. The app times the same method repeatedly. Early rounds run
 *   interpreted and are slow; once the hotness counter crosses the JIT
 *   threshold the method is compiled and the timings drop sharply.
 *
 *   It also provides the inlining target used by
 *   ../labs/lab-02-compiler-filters-and-hooks.md.
 *
 * HOW TO RUN
 *   Build as a RELEASE app — a debuggable build forces interpretation and
 *   suppresses the entire effect.
 *
 *     ./gradlew assembleRelease
 *     adb install -r app-release.apk
 *     adb shell cmd package compile --reset com.artlab.hotmethod
 *     adb shell am force-stop com.artlab.hotmethod
 *     adb logcat -s HOTMETHOD
 *
 *   Then compare against fully-compiled:
 *
 *     adb shell cmd package compile -m speed -f com.artlab.hotmethod
 *     adb shell am force-stop com.artlab.hotmethod
 *
 * WHY KOTLIN HERE
 *   To show that none of this is Java-specific. Kotlin compiles to the same
 *   DEX bytecode and is executed by the same runtime, so every ART concept in
 *   this chapter applies identically. The one Kotlin-specific note is that
 *   `inline` functions are inlined by the KOTLIN COMPILER at the bytecode
 *   level — a completely different mechanism from ART's runtime inlining, and
 *   one that removes the method before ART ever sees it. See the note below.
 */
class HotMethodDemo : Activity() {

    companion object {
        private const val TAG = "HOTMETHOD"
        private const val ROUNDS = 40
        private const val ITERATIONS = 200_000
    }

    private val log = StringBuilder()
    private lateinit var view: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        view = TextView(this).apply {
            textSize = 11f
            setPadding(24, 24, 24, 24)
        }
        setContentView(ScrollView(this).apply { addView(view) })

        emit("HOT METHOD DEMO")
        emit("Watch the per-round time drop when the JIT compiles the method.")
        emit("Rounds: $ROUNDS  Iterations per round: $ITERATIONS")
        emit("")

        runRounds()
    }

    private fun emit(line: String) {
        log.append(line).append('\n')
        Log.i(TAG, line)
        view.text = log
    }

    // ----------------------------------------------------------------- //

    /**
     * The measurement loop. Each round is posted separately so the UI can
     * update and so the runtime gets a chance to compile between rounds.
     */
    private fun runRounds() {
        val handler = Handler(Looper.getMainLooper())
        var round = 0
        var baseline = -1L
        var reported = false

        handler.post(object : Runnable {
            override fun run() {
                var sink = 0L

                val nanos = measureNanoTime {
                    for (i in 0 until ITERATIONS) {
                        sink += Workload.compute(i)
                    }
                }

                val micros = nanos / 1_000
                if (baseline < 0) baseline = micros

                val ratio = if (micros > 0) baseline.toDouble() / micros else 0.0
                val bar = "#".repeat(minOf(40, (micros * 40 / maxOf(1, baseline)).toInt()))

                emit(String.format("round %2d  %7d us  x%.1f  %s (sink=%d)",
                        round, micros, ratio, bar, sink and 0xFF))

                // Announce the moment the speedup becomes unmistakable.
                if (!reported && round > 3 && ratio > 3.0) {
                    emit("")
                    emit(">>> Timing dropped sharply. The JIT has compiled Workload.compute().")
                    emit(">>> The ArtMethod entry point just changed from the interpreter")
                    emit(">>> bridge to an address in the JIT code cache.")
                    emit(">>> See README section 3.16, and watch it live with:")
                    emit(">>>   frida -U -n com.artlab.hotmethod -l ../scripts/artmethod-inspect.js")
                    emit(">>>   art.watch(\"com.artlab.hotmethod.Workload\", \"compute\")")
                    emit("")
                    reported = true
                }

                round++
                if (round < ROUNDS) {
                    handler.postDelayed(this, 120)
                } else {
                    summarise(baseline)
                }
            }
        })
    }

    private fun summarise(baseline: Long) {
        emit("")
        emit("== DONE ==")
        emit("First round: ${baseline}us (interpreted)")
        emit("")
        emit("Now compare compilation states:")
        emit("")
        emit("  # everything interpreted — hooks land reliably")
        emit("  adb shell cmd package compile -m verify -f $packageName")
        emit("  adb shell am force-stop $packageName")
        emit("")
        emit("  # everything compiled and inlined — hooks may silently miss")
        emit("  adb shell cmd package compile -m speed -f $packageName")
        emit("  adb shell am force-stop $packageName")
        emit("")
        emit("Under 'speed' the first round should already be fast, because the")
        emit("method was compiled ahead of time and there is nothing to warm up.")
    }
}

/**
 * The workload. Deliberately split into a small callee and a larger caller so
 * that ART's runtime inliner has an obvious candidate.
 *
 * Used by lab-02 as the hook target.
 */
object Workload {

    /**
     * Tiny, final, side-effect free: the ideal inlining candidate.
     *
     * A Frida hook on THIS method will stop firing once the app is compiled
     * with `-m speed`, because the optimizing compiler folds its body into
     * compute(). That is the entire lesson of lab 02.
     */
    fun mix(x: Int): Int = (x * 31) xor (x ushr 3)

    /**
     * Larger, so it is much less likely to be inlined into ITS caller.
     * Hook this instead when mix() has vanished.
     */
    fun compute(seed: Int): Long {
        var acc = seed.toLong()
        for (i in 0 until 8) {
            acc += mix(seed + i).toLong()
            acc = acc xor (acc ushr 7)
        }
        return acc
    }

    /*
     * KOTLIN NOTE — two different kinds of inlining.
     *
     * If mix() were declared `inline fun mix(...)`, the KOTLIN COMPILER would
     * splice its body into every call site at compile time, and the method
     * would not exist as a separate entry in the DEX at all. No amount of
     * `cmd package compile -m verify` would bring it back, because ART never
     * saw a call to inline.
     *
     * That is categorically different from ART's runtime inlining, which
     * happens in the optimizing compiler and IS reversed by forcing the
     * interpreter.
     *
     * When a hook target simply does not exist in the decompiled output,
     * suspect compile-time inlining and look for the code in the caller.
     * See ../../05-Kotlin/README.md and ../../42-R8/README.md.
     */
}
