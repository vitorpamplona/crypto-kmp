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

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * [SecureRandom] and [RandomInstance] on every platform, and the bounded-draw helpers
 * they share, driven by fixed sources to reach the edge cases a real generator rarely hits.
 */
class SecureRandomTest {
    private val random = SecureRandom()

    private val intBounds =
        listOf(1, 2, 3, 5, 7, 10, 16, 62, 64, 100, 1000, 1 shl 20, (1 shl 30) + 1, 1 shl 30, Int.MAX_VALUE - 1, Int.MAX_VALUE)

    private val longBounds =
        listOf(
            1L,
            2L,
            3L,
            16L,
            1000L,
            Int.MAX_VALUE.toLong(),
            Int.MAX_VALUE.toLong() + 1,
            Int.MAX_VALUE.toLong() * 3,
            1L shl 40,
            (1L shl 62) + 1,
            1L shl 62,
            Long.MAX_VALUE - 1,
            Long.MAX_VALUE,
        )

    @Test
    fun nextIntStaysInBounds() {
        for (bound in intBounds) {
            repeat(2000) {
                val value = random.nextInt(bound)
                assertTrue(value in 0 until bound, "nextInt($bound) returned $value")
            }
        }
    }

    @Test
    fun nextLongStaysInBounds() {
        for (bound in longBounds) {
            repeat(2000) {
                val value = random.nextLong(bound)
                assertTrue(value in 0 until bound, "nextLong($bound) returned $value")
            }
        }
    }

    @Test
    fun largeLongBoundsReachAboveIntRange() {
        // With a bound of 2^62, every draw below 2^31 would mean the bound was being ignored.
        val bound = 1L shl 62
        assertTrue((0 until 64).any { random.nextLong(bound) > Int.MAX_VALUE })
    }

    @Test
    fun smallBoundsHitEveryValue() {
        for (bound in listOf(2, 3, 7, 16)) {
            val seen = BooleanArray(bound)
            repeat(1000) { seen[random.nextInt(bound)] = true }
            assertTrue(seen.all { it }, "nextInt($bound) missed a value in 1000 draws")
        }
        val seen = BooleanArray(5)
        repeat(1000) { seen[random.nextLong(5L).toInt()] = true }
        assertTrue(seen.all { it })
    }

    @Test
    fun rejectsNonPositiveBounds() {
        for (bound in listOf(0, -1, Int.MIN_VALUE)) {
            assertFailsWith<IllegalArgumentException> { random.nextInt(bound) }
            assertFailsWith<IllegalArgumentException> { random.nextLong(bound.toLong()) }
        }
        assertFailsWith<IllegalArgumentException> { random.nextLong(Long.MIN_VALUE) }
        assertFailsWith<IllegalArgumentException> { RandomInstance.int(0) }
        assertFailsWith<IllegalArgumentException> { RandomInstance.long(0) }
    }

    @Test
    fun nextBytesOfAnEmptyArrayDoesNothing() {
        random.nextBytes(ByteArray(0))
        assertEquals(0, RandomInstance.bytes(0).size)
    }

    @Test
    fun bytesHasTheRequestedSize() {
        for (size in listOf(1, 12, 32, 255, 256, 257, 4096, 100_000)) {
            assertEquals(size, RandomInstance.bytes(size).size)
        }
        assertFailsWith<IllegalArgumentException> { RandomInstance.bytes(-1) }
    }

    @Test
    fun outputIsNotConstant() {
        // Each of these fails by chance with probability below 2^-200.
        assertTrue(List(8) { RandomInstance.bytes(32).toList() }.toSet().size == 8)
        assertTrue(List(8) { random.nextLong() }.toSet().size > 1)
        assertTrue(List(8) { random.nextInt() }.toSet().size > 1)
        // A large buffer is filled all the way, not just its first chunk.
        val big = RandomInstance.bytes(100_000)
        assertTrue(big.copyOfRange(99_000, 100_000).any { it.toInt() != 0 })
        assertTrue(RandomInstance.randomChars().length == 16)
        assertTrue(RandomInstance.randomChars(40).all { it in RandomInstance.charPool })
    }

    /** A source that replays [values], then throws if asked for more. */
    private class Replay<T>(
        vararg values: T,
    ) {
        private val iterator = values.iterator()
        var calls = 0

        fun next(): T {
            calls++
            return iterator.next()
        }
    }

    @Test
    fun boundedIntNeverGoesNegative() {
        // nextPositiveInt() used to negate, and -Int.MIN_VALUE is still Int.MIN_VALUE:
        // nextInt(16) could return -16. Now the extreme raw values all land in range.
        for (raw in listOf(Int.MIN_VALUE, -1, 0, 1, Int.MAX_VALUE, Int.MIN_VALUE + 1)) {
            for (bound in listOf(1, 2, 3, 16, 1 shl 30, Int.MAX_VALUE)) {
                // raw first, then 0 in case raw falls in the rejected run and is redrawn.
                val source = Replay(raw, 0)
                val value = boundedNextInt(bound) { source.next() }
                assertTrue(value in 0 until bound, "raw $raw, bound $bound gave $value")
            }
        }
        assertEquals(0, boundedNextInt(16) { Int.MIN_VALUE })
        assertEquals(15, boundedNextInt(16) { -1 })
    }

    @Test
    fun boundedLongNeverGoesNegative() {
        for (raw in listOf(Long.MIN_VALUE, -1L, 0L, 1L, Long.MAX_VALUE, Long.MIN_VALUE + 1)) {
            for (bound in listOf(1L, 2L, 3L, 16L, 1L shl 40, Long.MAX_VALUE - 1, Long.MAX_VALUE)) {
                val source = Replay(raw, 0L)
                val value = boundedNextLong(bound) { source.next() }
                assertTrue(value in 0 until bound, "raw $raw, bound $bound gave $value")
            }
        }
    }

    @Test
    fun boundedIntRejectsTheIncompleteLastRun() {
        // bound 3 * 2^29: the 31-bit draws hold one full run of it (0 until 3 * 2^29), and
        // the rest, up to 2^31 - 1, is an incomplete second run that must be redrawn.
        val bound = 3 shl 29
        // -2 ushr 1 is Int.MAX_VALUE, in the incomplete run: rejected. The second raw value
        // shifts down to bound - 1, the top of the full run: accepted as is.
        val source = Replay(-2, (bound - 1) shl 1)
        assertEquals(bound - 1, boundedNextInt(bound) { source.next() })
        assertEquals(2, source.calls)
    }

    @Test
    fun boundedLongRejectsTheIncompleteLastRun() {
        val bound = 3L shl 61
        val source = Replay(-2L, (bound - 1) shl 1)
        assertEquals(bound - 1, boundedNextLong(bound) { source.next() })
        assertEquals(2, source.calls)
    }

    @Test
    fun powerOfTwoBoundsKeepTheLowBits() {
        assertEquals(0x5, boundedNextInt(16) { 0x12345675 })
        assertEquals(0x5L, boundedNextLong(16L) { 0x1234567812345675L })
        assertEquals(0, boundedNextInt(1) { -1 })
    }
}
