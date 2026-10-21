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

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** [equalsConstantTime] gives the same answers as [ByteArray.contentEquals]. */
class ConstantTimeTest {
    @Test
    fun equalArrays() {
        val a = ByteArray(32) { it.toByte() }
        assertTrue(a.equalsConstantTime(a.copyOf()))
        assertTrue(a.equalsConstantTime(a))
        assertTrue(byteArrayOf(-1, 0, 127, -128).equalsConstantTime(byteArrayOf(-1, 0, 127, -128)))
    }

    @Test
    fun differentContents() {
        val a = ByteArray(32) { it.toByte() }
        // A difference in any position, including only the first or only the last byte.
        for (i in a.indices) {
            val b = a.copyOf().also { it[i] = (it[i].toInt() xor 0x80).toByte() }
            assertFalse(a.equalsConstantTime(b), "differs at $i")
            assertFalse(b.equalsConstantTime(a), "differs at $i")
        }
        assertFalse(ByteArray(16).equalsConstantTime(ByteArray(16) { -1 }))
    }

    @Test
    fun differentLengths() {
        val a = ByteArray(32) { it.toByte() }
        assertFalse(a.equalsConstantTime(a.copyOf(31)))
        assertFalse(a.copyOf(31).equalsConstantTime(a))
        assertFalse(a.equalsConstantTime(a.copyOf(33)))
        assertFalse(ByteArray(0).equalsConstantTime(ByteArray(1)))
    }

    @Test
    fun emptyArrays() {
        assertTrue(ByteArray(0).equalsConstantTime(ByteArray(0)))
    }
}
