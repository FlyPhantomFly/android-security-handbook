// examples/MultiProcessDemo/Counter.kt
package com.example.multiproc

/**
 * A textbook singleton. Exactly one instance... per PROCESS.
 * Two processes means two instances, two heaps, two values, no synchronisation between them.
 */
object Counter {
    var value: Int = 0
}
