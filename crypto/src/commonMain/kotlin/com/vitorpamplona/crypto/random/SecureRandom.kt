/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.vitorpamplona.crypto.random

/**
 * The platform's cryptographically secure random generator: `java.security.SecureRandom`
 * on JVM and Android, `SecRandomCopyBytes` on Apple, `getrandom(2)` on Linux.
 *
 * The bounded draws are computed here from the raw ones with [boundedNextInt] and
 * [boundedNextLong], so every platform turns the same random bits into the same value.
 */
expect class SecureRandom() {
    /** A uniform [Int] in `0 until bound`. Throws [IllegalArgumentException] unless `bound > 0`. */
    fun nextInt(bound: Int): Int

    /** A uniform [Long] in `0 until bound`. Throws [IllegalArgumentException] unless `bound > 0`. */
    fun nextLong(bound: Long): Long

    fun nextInt(): Int

    fun nextLong(): Long

    fun nextBytes(output: ByteArray)
}

/**
 * A uniform draw in `0 until bound` from [next], a source of uniform 32-bit values.
 *
 * The JDK's algorithm (`RandomSupport.boundedNextInt`): a power of two keeps the low bits;
 * any other bound reduces a non-negative 31-bit draw and rejects the draws from the last,
 * incomplete run of `bound` values, which would otherwise make the small results more likely.
 */
internal inline fun boundedNextInt(
    bound: Int,
    next: () -> Int,
): Int {
    require(bound > 0) { "bound must be positive, was $bound" }
    val m = bound - 1
    if ((bound and m) == 0) return next() and m
    var u = next() ushr 1
    var r = u % bound
    // u - r is the start of u's run of bound values; the run is incomplete when it
    // would end past Int.MAX_VALUE, which shows as an overflow to negative.
    while (u - r + m < 0) {
        u = next() ushr 1
        r = u % bound
    }
    return r
}

/** [boundedNextInt] for [Long]s: the JDK's `RandomSupport.boundedNextLong`. */
internal inline fun boundedNextLong(
    bound: Long,
    next: () -> Long,
): Long {
    require(bound > 0) { "bound must be positive, was $bound" }
    val m = bound - 1
    if ((bound and m) == 0L) return next() and m
    var u = next() ushr 1
    var r = u % bound
    while (u - r + m < 0) {
        u = next() ushr 1
        r = u % bound
    }
    return r
}
