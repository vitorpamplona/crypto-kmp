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
package com.vitorpamplona.crypto

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail

/** [mul64] is `*` and [toUnsignedLong] is a masked `toLong`: on JS both are rebuilt from pieces. */
class Mul64Test {
    @Test
    fun knownProducts() {
        assertEquals(0x2236D88FE5618CF0L, mul64(0x123456789ABCDEF0L, 0x0FEDCBA987654321L))
        assertEquals(-0x1FFFFFFFFL, mul64(0xFFFFFFFFL, 0xFFFFFFFFL))
        assertEquals(-0x48D159E26AF37C0L, mul64(-0x7777777777777778L, -0x7777777777777778L))
        // A Curve25519 limb times a 19-scaled one, the widest product the field takes.
        assertEquals(0x12FFFFF68000013L, mul64(0x3FFFFFFL, 0x4BFFFFEDL))
        assertEquals(1L, mul64(-1L, -1L))
        assertEquals(Long.MIN_VALUE, mul64(Long.MIN_VALUE, 3L))
        assertEquals(0L, mul64(Long.MIN_VALUE, 2L))
        assertEquals(0L, mul64(0L, -1L))
    }

    @Test
    fun matchesTheOperator() {
        val edges = longArrayOf(0, 1, -1, 2, 5, 19, 121665, 0xFFFF, 0x10000, 0xFFFFFF, 0x1000000, 0x3FFFFFF, Int.MAX_VALUE.toLong(), Int.MIN_VALUE.toLong(), 0xFFFFFFFFL, 0x100000000L, Long.MAX_VALUE, Long.MIN_VALUE)
        for (a in edges) {
            for (b in edges) {
                assertProduct(a, b)
                assertProduct(-a, b)
            }
        }
        val random = Random(0x6d756c)
        repeat(10_000) {
            val a = random.nextLong()
            val b = random.nextLong()
            assertProduct(a, b)
            // Limb-sized operands, as the field and Poly1305 multiply them.
            assertProduct(random.nextLong(-(1L shl 31), 1L shl 31), random.nextLong(-(1L shl 31), 1L shl 31))
        }
    }

    @Test
    fun toUnsignedLongZeroExtends() {
        for (value in intArrayOf(0, 1, -1, 2, 0x7FFF_FFFF, Int.MIN_VALUE, 0x1234_5678, -0x1234_5678)) {
            assertEquals(value.toLong() and 0xFFFF_FFFFL, value.toUnsignedLong(), "$value")
        }
        val random = Random(0x7a78)
        repeat(1000) {
            val value = random.nextInt()
            if (value.toUnsignedLong() != (value.toLong() and 0xFFFF_FFFFL)) fail("toUnsignedLong($value)")
        }
    }

    // The message only on failure: Long.toString is slow on Kotlin/JS, and this runs 10^4 times.
    private fun assertProduct(
        a: Long,
        b: Long,
    ) {
        val product = mul64(a, b)
        if (product != a * b) fail("mul64($a, $b) = $product, expected ${a * b}")
    }
}
