/*
 * ============================================================================
 * CoroutinesDemo.kt — chapter 05 (Kotlin), Android Security Handbook
 * ============================================================================
 *
 * WHAT THIS FILE DOES
 *   Runs seven self-contained demonstrations of Kotlin coroutines and, for each
 *   one, states in a comment exactly what the compiler generates: which extra
 *   classes appear, what the invokeSuspend state machine looks like, which values
 *   the `label` field takes, and which local variables get spilled into
 *   continuation fields. Everything prints to stdout with a thread name, so you
 *   can see for yourself that a coroutine is not a thread.
 *
 *   Demonstrations:
 *     1. A suspend function with TWO suspension points (the canonical state machine)
 *     2. launch — fire and forget, returning a Job
 *     3. async / await — concurrent work returning a Deferred
 *     4. withContext and Dispatchers — switching threads without a new coroutine
 *     5. Structured concurrency — coroutineScope, supervisorScope, and failure
 *     6. Cancellation — cooperative, check-point based, with NonCancellable cleanup
 *     7. Flow — a cold asynchronous stream with operators and flowOn
 *
 * EXACT DEPENDENCY
 *   org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.8.1
 *   Maven coordinates resolve to this file:
 *     kotlinx-coroutines-core-jvm-1.8.1.jar
 *   Any 1.7.x or 1.8.x release produces identical generated shapes. The
 *   kotlin-stdlib that ships with your kotlinc is also required at runtime.
 *
 * HOW TO RUN IT
 *     # host — fetch the one dependency
 *     curl -LO https://repo1.maven.org/maven2/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.8.1/kotlinx-coroutines-core-jvm-1.8.1.jar
 *
 *     # host — compile
 *     kotlinc CoroutinesDemo.kt -cp kotlinx-coroutines-core-jvm-1.8.1.jar -d classes/
 *
 *     # host — run (Linux and macOS use ':' as the classpath separator)
 *     java -cp "classes:kotlinx-coroutines-core-jvm-1.8.1.jar:$KOTLIN_HOME/lib/kotlin-stdlib.jar" \
 *          CoroutinesDemoKt
 *
 *     # host — run (Windows PowerShell uses ';')
 *     java -cp "classes;kotlinx-coroutines-core-jvm-1.8.1.jar;$env:KOTLIN_HOME\lib\kotlin-stdlib.jar" `
 *          CoroutinesDemoKt
 *
 *   If $KOTLIN_HOME is not set, find the stdlib with:
 *     # host
 *     dirname $(dirname $(readlink -f $(which kotlinc)))
 *
 * HOW TO INSPECT WHAT THE COMPILER PRODUCED
 *     # host — count the classes; you wrote none of the ones ending in $1
 *     find classes -name '*.class' | sort
 *
 *     # host — decompile and read the state machines
 *     jar cf coro.jar -C classes .
 *     jadx --no-res -d jadx_out coro.jar
 *     grep -n "invokeSuspend\|label\|COROUTINE_SUSPENDED" jadx_out/sources/CoroutinesDemoKt.java
 *
 *     # host — see the raw bytecode of one state machine
 *     javap -p -c -cp classes 'CoroutinesDemoKt$verifyToken$1'
 *
 * HOW TO OBSERVE IT LIVE
 *     # host — terminal 1
 *     java -cp "classes:kotlinx-coroutines-core-jvm-1.8.1.jar:$KOTLIN_HOME/lib/kotlin-stdlib.jar" CoroutinesDemoKt
 *     # host — terminal 2
 *     frida -n java -l ../scripts/hook-kotlin.js
 *
 * WHERE THIS FITS
 *   Chapter README:  ../README.md
 *   Cheat sheet:     ../cheatsheet.md
 *   CTF lab:         ../labs/lab-03-coroutine-state-machine.md
 *   Frida script:    ../scripts/hook-kotlin.js
 * ============================================================================
 */

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onCompletion
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withContext
import kotlin.system.measureTimeMillis

// ---------------------------------------------------------------------------
// Helper — every line shows which thread it ran on
// ---------------------------------------------------------------------------

private fun log(msg: String) =
    println("  [%-24s] %s".format(Thread.currentThread().name, msg))

private fun section(n: Int, title: String) {
    println()
    println("-".repeat(78))
    println("[$n] $title")
    println("-".repeat(78))
}

// ===========================================================================
// SECTION 1 — A suspend function with two suspension points
// ===========================================================================

/*
 * Two "remote" calls, each of which suspends.
 *
 * WHAT `suspend` CHANGES ABOUT THE SIGNATURE
 *   Source:   suspend fun fetchNonce(): String
 *   Compiled: public static final Object fetchNonce(Continuation<? super String> $completion)
 *
 *   Two changes, always:
 *     - an extra final parameter of type kotlin.coroutines.Continuation
 *     - the return type becomes Object, because the method may return either the
 *       real value or the COROUTINE_SUSPENDED sentinel, which share no supertype
 *
 * WHY CONTINUATION PASSING STYLE
 *   A suspending call gives the thread back. When the answer arrives, some other
 *   thread must resume the function exactly where it stopped. The thread stack is
 *   gone by then, so the compiler moves "where I am" and "what I was holding"
 *   into a heap object — the continuation — and hands that object to the callee
 *   as the callback to invoke on completion.
 */
private suspend fun fetchNonce(): String {
    delay(80)                       // suspension point
    return "N-" + (System.nanoTime() % 100_000)
}

private suspend fun resolveToken(nonce: String): String {
    delay(120)                      // suspension point
    return "T-" + nonce.hashCode().toUInt().toString(16)
}

/*
 * THE CANONICAL TWO-SUSPENSION-POINT FUNCTION.
 *
 * COMPILER EMITS
 *   1. A rewritten static method:
 *        public static final Object verifyToken(String supplied, Continuation $completion)
 *   2. A synthetic class CoroutinesDemoKt$verifyToken$1 extending
 *        kotlin.coroutines.jvm.internal.ContinuationImpl
 *      with fields:  Object L$0;  Object L$1;  int label;  Object result;
 *   3. A @DebugMetadata annotation on that class naming the original file,
 *      function, suspension-point line numbers, spilled local names, and the
 *      field each local was spilled into.
 *
 * WHAT invokeSuspend LOOKS LIKE IN JADX
 *
 *   public static final Object verifyToken(String supplied, Continuation $completion) {
 *       CoroutinesDemoKt$verifyToken$1 $c;
 *       if ($completion instanceof CoroutinesDemoKt$verifyToken$1) {
 *           $c = (CoroutinesDemoKt$verifyToken$1) $completion;
 *           if (($c.label & Integer.MIN_VALUE) != 0) { $c.label -= Integer.MIN_VALUE; }
 *           else { $c = new CoroutinesDemoKt$verifyToken$1($completion); }
 *       } else { $c = new CoroutinesDemoKt$verifyToken$1($completion); }
 *
 *       Object $result = $c.result;
 *       Object suspended = IntrinsicsKt.getCOROUTINE_SUSPENDED();
 *
 *       switch ($c.label) {
 *           case 0:
 *               ResultKt.throwOnFailure($result);
 *               $c.L$0 = supplied;              // spill: needed after suspension
 *               $c.label = 1;
 *               Object a = fetchNonce($c);
 *               if (a == suspended) return suspended;
 *               $result = a;
 *               // fall through
 *           case 1:
 *               supplied = (String) $c.L$0;     // restore
 *               ResultKt.throwOnFailure($result);
 *               String nonce = (String) $result;
 *               $c.L$0 = supplied;
 *               $c.L$1 = nonce;                 // spill: used in the final expression
 *               $c.label = 2;
 *               Object b = resolveToken(nonce, $c);
 *               if (b == suspended) return suspended;
 *               $result = b;
 *               // fall through
 *           case 2:
 *               String nonce2 = (String) $c.L$1;
 *               supplied      = (String) $c.L$0;
 *               ResultKt.throwOnFailure($result);
 *               String token = (String) $result;
 *               return Intrinsics.areEqual(supplied, token)
 *                    ? "OK " + nonce2 : "DENIED (expected " + token + ")";
 *           default:
 *               throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
 *       }
 *   }
 *
 * HOW TO READ THE LABEL VALUES
 *   label 0  : first entry, nothing has run yet
 *   label 1  : resuming after suspension point 1; $result holds fetchNonce's return
 *   label 2  : resuming after suspension point 2; $result holds resolveToken's return
 *   label with the sign bit set (a large negative number): invokeSuspend has just
 *              marked the object and is re-entering the function; the prologue
 *              clears the bit and falls into the real state
 *   anything else: impossible; the default branch throws
 *
 * THE RULE FOR SPILLING
 *   A local is written into an L$n field if and only if it is still live across a
 *   suspension. `supplied` is used in the final comparison, so it survives both
 *   suspensions. `nonce` is produced by suspension 1 and used after suspension 2,
 *   so it survives one. A local used and discarded between two suspension points
 *   never leaves the JVM stack and never appears as a field.
 *
 * PENTESTER VALUE
 *   Those L$n fields are where in-flight secrets live: request bodies waiting on a
 *   response, decrypted payloads, session keys, the plaintext of something about
 *   to be encrypted. They are readable with one Frida hook and they exist nowhere
 *   else. See ../labs/lab-03-coroutine-state-machine.md.
 */
private suspend fun verifyToken(supplied: String): String {
    val nonce = fetchNonce()                  // suspension point 1  -> label 1
    val token = resolveToken(nonce)           // suspension point 2  -> label 2
    return if (supplied == token) "OK $nonce" else "DENIED (expected $token)"
}

// ===========================================================================
// SECTION 2 — launch
// ===========================================================================

/*
 * launch starts a coroutine and returns a Job. It does not return a result.
 *
 * COMPILER EMITS
 *   The lambda body becomes a class extending kotlin.coroutines.jvm.internal.SuspendLambda
 *   and implementing Function2<CoroutineScope, Continuation<? super Unit>, Object>.
 *   That class has its own invokeSuspend, its own `label`, and its own L$n fields —
 *   a suspending lambda is a state machine exactly like a named suspend function,
 *   minus the sign-bit trick, because it is never re-entered through a static method.
 *
 * IN JADX
 *   static final class CoroutinesDemoKt$demoLaunch$1$1 extends SuspendLambda
 *           implements Function2<CoroutineScope, Continuation<? super Unit>, Object> {
 *       int I$0;       // the captured loop index, spilled as a primitive
 *       int label;
 *       public final Object invokeSuspend(Object obj) { switch (this.label) { ... } }
 *       public final Continuation<Unit> create(Object value, Continuation<?> c) { ... }
 *       public final Object invoke(CoroutineScope s, Continuation<? super Unit> c) {
 *           return ((CoroutinesDemoKt$demoLaunch$1$1) create(s, c)).invokeSuspend(Unit.INSTANCE);
 *       }
 *   }
 *
 *   Note the primitive spill field is named I$0, not L$0. Object references use
 *   L$n; int uses I$n; long uses J$n; double uses D$n; float F$n; boolean Z$n.
 *
 *   The three-method shape — invokeSuspend, create, invoke — is the fingerprint of
 *   a suspending lambda. `create` clones the state object for each invocation so
 *   the same lambda can drive many concurrent coroutines.
 */
private suspend fun demoLaunch() = coroutineScope {
    val jobs = mutableListOf<Job>()
    repeat(3) { i ->
        jobs += launch {
            delay(50L * (3 - i))
            log("launch worker $i finished")
        }
    }
    log("all three launched; none has finished yet")
    jobs.forEach { it.join() }
    log("joined all three")
}

// ===========================================================================
// SECTION 3 — async and await
// ===========================================================================

/*
 * async returns a Deferred<T>, which is a Job that also carries a value.
 *
 * COMPILER EMITS
 *   Structurally identical to launch: one SuspendLambda subclass per async block.
 *   The difference is entirely in the library, not in the generated code —
 *   async installs a DeferredCoroutine instead of a StandaloneCoroutine.
 *
 * WHAT `await()` COMPILES TO
 *   await() is itself a suspend function, so calling it adds a suspension point
 *   to the ENCLOSING state machine. Two awaits mean two extra labels in the
 *   caller. In JADX you will see:
 *       $c.label = 1;
 *       if (deferred.await($c) == suspended) return suspended;
 *
 * THE SEQUENTIAL TRAP
 *   Writing `val a = fetchA().await()` on one line and `val b = fetchB().await()`
 *   on the next still runs them concurrently, because the async calls started
 *   before either await. But writing `async { }.await()` inline makes the work
 *   sequential, because the await happens before the next async is even created.
 *   In decompiled code you can tell them apart by whether both async blocks are
 *   constructed before the first `label` assignment.
 */
private suspend fun demoAsync() = coroutineScope {
    val elapsedConcurrent = measureTimeMillis {
        val a = async { delay(150); "alpha" }
        val b = async { delay(150); "beta" }
        log("concurrent result: ${a.await()} + ${b.await()}")
    }
    log("concurrent took ${elapsedConcurrent}ms (roughly one delay, not two)")

    val elapsedSequential = measureTimeMillis {
        val a = async { delay(150); "alpha" }.await()
        val b = async { delay(150); "beta" }.await()
        log("sequential result: $a + $b")
    }
    log("sequential took ${elapsedSequential}ms (roughly two delays)")

    val all = listOf("x", "y", "z").map { s -> async { delay(60); s.uppercase() } }
    log("awaitAll: ${all.awaitAll()}")
}

// ===========================================================================
// SECTION 4 — withContext and Dispatchers
// ===========================================================================

/*
 * withContext switches the dispatcher for a block WITHOUT starting a new coroutine.
 *
 * COMPILER EMITS
 *   Two things at once: a SuspendLambda for the block, and a suspension point in
 *   the caller. In JADX the caller shows
 *       $c.label = 1;
 *       if (BuildersKt.withContext(Dispatchers.getIO(),
 *               new CoroutinesDemoKt$demoContext$result$1(null), $c) == suspended)
 *           return suspended;
 *
 *   Note Dispatchers.IO appears as Dispatchers.getIO() because Kotlin properties
 *   become getters. Dispatchers.Default is getDefault(), Main is getMain().
 *
 * DISPATCHERS, AND WHAT THEY REALLY ARE
 *   Dispatchers.Default   CPU-count-sized pool, minimum 2 threads. CPU work.
 *   Dispatchers.IO        Elastic pool, default limit 64. Blocking disk/network.
 *   Dispatchers.Main      On Android, the main looper (see ../../24-Handler-Looper/README.md).
 *                         On the plain JVM this demo does not use it, because
 *                         there is no main looper outside Android.
 *   Dispatchers.Unconfined Runs on the caller's thread until the first suspension.
 *
 * ANALYSIS CONSEQUENCE
 *   Thread identity is meaningless across a withContext boundary. Any Frida logic
 *   that keys state on Thread.currentThread().getId() will break inside coroutines.
 *   Key on the continuation object instead.
 */
private suspend fun demoContext() {
    log("before withContext")
    val result = withContext(Dispatchers.IO) {
        log("inside withContext(Dispatchers.IO) — different thread")
        delay(40)
        "io-result"
    }
    log("after withContext, got '$result'")

    val computed = withContext(Dispatchers.Default) {
        log("inside withContext(Dispatchers.Default)")
        (1..200_000).sumOf { it.toLong() }
    }
    log("CPU-bound result: $computed")
}

// ===========================================================================
// SECTION 5 — Structured concurrency
// ===========================================================================

/*
 * Structured concurrency: every coroutine has a parent, and the parent waits.
 *
 * THE THREE RULES
 *   1. A coroutine launched in a scope cannot outlive that scope.
 *   2. If a child fails, the failure propagates up and cancels its siblings.
 *   3. The parent does not complete until every child has completed.
 *
 * coroutineScope    — rule 2 applies: one failure takes down all siblings.
 * supervisorScope   — rule 2 is suspended: a child's failure is isolated.
 *
 * COMPILER EMITS
 *   coroutineScope and supervisorScope are ordinary suspend functions taking a
 *   suspending lambda, so each produces one SuspendLambda subclass plus one
 *   suspension point in the caller. There is no special bytecode for structure;
 *   the whole mechanism lives in the Job hierarchy inside the library.
 *
 * IN JADX
 *   Look for CoroutineScopeKt.coroutineScope(new Xxx$1(null), $c) and
 *   CoroutineScopeKt.supervisorScope(...). The Job tree they build is a runtime
 *   data structure; you will not see it in decompiled code, only at runtime.
 *
 * PENTESTER VALUE
 *   Scope cancellation is a control point. If you can reach an app's scope object
 *   from a hook and call cancel() on it, you stop every network call, poll, and
 *   timer inside it at once — a very direct way to neutralise a licence-check
 *   loop or an anti-tamper heartbeat without touching the check itself.
 */
private suspend fun demoStructuredConcurrency() {
    log("coroutineScope: one child fails, siblings are cancelled")
    try {
        coroutineScope {
            launch { delay(300); log("  this sibling should NEVER print") }
            launch { delay(50); throw IllegalStateException("child A exploded") }
        }
    } catch (e: IllegalStateException) {
        log("  caught at the scope boundary: ${e.message}")
    }

    log("supervisorScope: one child fails, siblings survive")
    supervisorScope {
        launch {
            delay(50)
            throw IllegalStateException("child B exploded")
        }.invokeOnCompletion { t -> log("  child B completed with $t") }

        launch { delay(200); log("  this sibling DOES print") }
    }
}

// ===========================================================================
// SECTION 6 — Cancellation
// ===========================================================================

/*
 * Cancellation is cooperative. Nothing kills a coroutine; the coroutine notices.
 *
 * HOW A COROUTINE NOTICES
 *   - Every suspend function in kotlinx.coroutines checks the Job state and
 *     throws CancellationException on resume if the job is cancelled.
 *   - A tight computational loop with no suspension checks nothing, and keeps
 *     running after cancel(). Insert ensureActive() or yield() to make it
 *     cancellable.
 *
 * COMPILER EMITS
 *   Nothing specific to cancellation. It is entirely a library mechanism built on
 *   the Job hierarchy plus the resume path. In decompiled code the only trace is
 *   calls to JobKt.ensureActive(...) or YieldKt.yield(...) inside loops.
 *
 * CancellationException IS NOT AN ERROR
 *   The framework treats it as normal control flow and does not report it to an
 *   exception handler. This is why a suspend function's work can stop mid-way with
 *   nothing in the log — a common source of confusion during dynamic analysis.
 *
 * NonCancellable
 *   Cleanup code that must run after cancellation has to be wrapped in
 *   withContext(NonCancellable), because a cancelled coroutine cannot suspend
 *   normally. In JADX this appears as
 *       BuildersKt.withContext(NonCancellable.INSTANCE, new Xxx$1(null), $c)
 *   and the INSTANCE field tells you NonCancellable is a Kotlin object declaration.
 */
private suspend fun demoCancellation() = coroutineScope {
    val cooperative = launch {
        try {
            repeat(20) { i ->
                delay(30)                    // delay checks for cancellation on resume
                log("  cooperative tick $i")
            }
        } finally {
            withContext(NonCancellable) {
                delay(20)                    // would throw immediately without NonCancellable
                log("  cooperative cleanup ran")
            }
        }
    }
    delay(100)
    cooperative.cancelAndJoin()
    log("cooperative job cancelled after ~100ms")

    val stubborn = launch(Dispatchers.Default) {
        var n = 0L
        val started = System.currentTimeMillis()
        while (System.currentTimeMillis() - started < 400) {
            n += 1
            // Remove this line and the loop ignores cancel() entirely.
            if (n % 100_000L == 0L) ensureActive()
        }
        log("  stubborn loop finished on its own with n=$n")
    }
    delay(80)
    stubborn.cancel(CancellationException("caller lost interest"))
    stubborn.join()
    log("stubborn job cancelled=${stubborn.isCancelled}")
}

// ===========================================================================
// SECTION 7 — Flow
// ===========================================================================

/*
 * A Flow is a cold asynchronous stream: nothing runs until someone collects.
 *
 * COMPILER EMITS
 *   The flow { } builder lambda becomes a SuspendLambda implementing
 *   Function2<FlowCollector<T>, Continuation<? super Unit>, Object>, with its own
 *   invokeSuspend and label. Every `emit` call is a suspension point, so a builder
 *   with three emits produces labels 0 through 3.
 *
 *   Each intermediate operator (map, filter, onCompletion) creates ANOTHER
 *   SuspendLambda for its transform, plus a library wrapper object. A five-operator
 *   chain therefore produces five or more synthetic classes. This is why
 *   coroutine-heavy apps have such large class counts.
 *
 * IN JADX
 *   You will see FlowKt.flow(new Xxx$sensorFlow$1(null)) for the builder, then
 *   FlowKt.map(flow, new Xxx$demoFlow$2(null)) and so on. Following a flow chain
 *   in decompiled output means following a sequence of wrapper constructions;
 *   the operators do not appear as loops.
 *
 * flowOn
 *   Changes the context of everything UPSTREAM of it, never downstream. In JADX:
 *   FlowKt.flowOn(flow, Dispatchers.getDefault()). If you are tracing which
 *   dispatcher a network call ran on, find the nearest flowOn above it.
 *
 * COLD VERSUS HOT
 *   flow { } is cold: each collector gets its own independent execution, and the
 *   builder body runs once per collector. StateFlow and SharedFlow are hot: the
 *   producer runs regardless of collectors. In decompiled code the tell is the
 *   type name, not the shape of the code.
 */
private fun sensorFlow(): Flow<Int> = flow {
    log("  flow builder started (only when collected)")
    for (i in 1..6) {
        delay(30)              // suspension point inside the builder
        emit(i * i)            // emit is a suspend call: another suspension point
    }
    log("  flow builder finished")
}

private suspend fun demoFlow() {
    log("flow declared but not yet collected — nothing has run")
    val f = sensorFlow()
        .map { it + 1 }
        .filter { it % 2 == 0 }
        .onCompletion { cause -> log("  onCompletion, cause=$cause") }
        .flowOn(Dispatchers.Default)      // affects the builder and map/filter above

    log("collecting now")
    f.collect { value -> log("  collected $value") }

    log("collecting the SAME flow object a second time — the builder runs again")
    var count = 0
    f.collect { count++ }
    log("second collection produced $count values")
}

// ===========================================================================
// Driver
// ===========================================================================

/*
 * runBlocking bridges blocking code and suspending code by BLOCKING the calling
 * thread until the coroutine completes. It is the correct tool for a `main`
 * function or a unit test, and it is the wrong tool everywhere else — on Android
 * calling it from the main thread freezes the UI and produces an ANR.
 *
 * COMPILER EMITS
 *   fun main() = runBlocking { ... } becomes:
 *       public static final void main() {
 *           BuildersKt.runBlocking$default(null, new CoroutinesDemoKt$main$1(null), 1, null);
 *       }
 *       public static void main(String[] args) { main(); }
 *
 *   Note runBlocking$default — the $default suffix is the synthetic bridge for
 *   default arguments, here supplying the omitted CoroutineContext. The `1` is the
 *   bitmask saying "parameter index 0 was omitted".
 */
fun main() = runBlocking {
    println("=".repeat(78))
    println("CoroutinesDemo — coroutines, and the state machines they compile into")
    println("thread of runBlocking: ${Thread.currentThread().name}")
    println("=".repeat(78))

    section(1, "A suspend function with two suspension points")
    log("verifyToken(\"wrong\") -> " + verifyToken("wrong"))
    log("each call above allocated one CoroutinesDemoKt\$verifyToken\$1 continuation")

    section(2, "launch — fire and forget, returns a Job")
    demoLaunch()

    section(3, "async / await — concurrent work, returns a Deferred")
    demoAsync()

    section(4, "withContext and Dispatchers — same coroutine, different thread")
    demoContext()

    section(5, "Structured concurrency — coroutineScope vs supervisorScope")
    demoStructuredConcurrency()

    section(6, "Cancellation — cooperative, and what happens when you ignore it")
    demoCancellation()

    section(7, "Flow — a cold asynchronous stream")
    demoFlow()

    section(8, "A scope you own, and cancelling it")
    /*
     * A CoroutineScope built by hand. On Android the equivalents are
     * lifecycleScope, viewModelScope, and application-level scopes.
     *
     * SupervisorJob() means a failing child does not cancel the whole scope.
     * In JADX: `new ContextScope(JobKt.SupervisorJob(null).plus(Dispatchers.getIO()))`
     * where the `plus` is Kotlin operator overloading on CoroutineContext.
     */
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    scope.launch { delay(500); log("  this never prints, the scope is cancelled first") }
    scope.launch { delay(20); log("  this one wins the race") }
    delay(60)
    scope.coroutineContext[Job]?.cancelAndJoin()
    log("scope cancelled; every child inside it stopped at once")

    println(
        """

        ${"=".repeat(78)}
        THE THREE THINGS TO REMEMBER

        1. A suspend function is a normal method with a Continuation parameter and
           an Object return type. There is no magic in the JVM; the magic is a
           source-to-source transformation the compiler performs.

        2. `label` is the coroutine's program counter and the L${'$'}n fields are its
           saved registers. Read them and you know exactly where an asynchronous
           operation is and what it is carrying.

        3. Thread identity means nothing inside a coroutine. Track the continuation
           object, never the thread.
        ${"=".repeat(78)}
        """.trimIndent()
    )
}
