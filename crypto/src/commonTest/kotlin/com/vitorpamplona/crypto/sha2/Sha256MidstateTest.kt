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
package com.vitorpamplona.crypto.sha2

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** [Sha256Midstate] resumes SHA-256 from a saved state: its digest must equal a plain one. */
class Sha256MidstateTest {
    @Test
    fun digestMatchesPlainSha256AtEverySplit() {
        val random = Random(5)
        for (length in listOf(0, 1, 55, 56, 63, 64, 65, 127, 128, 200)) {
            val message = random.nextBytes(length)
            for (changesFrom in 0..length step maxOf(1, length / 7)) {
                val midstate = Sha256Midstate(message, changesFrom)
                assertEquals(0, midstate.prefixLength % Sha256Midstate.BLOCK)
                assertTrue(midstate.prefixLength <= changesFrom)
                assertContentEquals(sha256(message), midstate.digestInto(ByteArray(32)), "length $length, from $changesFrom")
            }
        }
    }

    @Test
    fun tailEditsChangeTheDigestLikeTheMessage() {
        val message = Random(6).nextBytes(150)
        val midstate = Sha256Midstate(message, 140)
        val edited = message.copyOf().also { it[145] = (it[145] + 1).toByte() }
        midstate.tail[145 - midstate.prefixLength] = edited[145]
        assertContentEquals(sha256(edited), midstate.digestInto(ByteArray(32)))
    }

    @Test
    fun leadingZeroBitsCountsTheDigest() {
        val message = "abc".encodeToByteArray()
        val digest = sha256(message)
        val zeros = digest.indexOfFirst { it.toInt() != 0 }.let { it * 8 + (digest[it].toInt() and 0xFF).countLeadingZeroBits() - 24 }
        assertTrue(Sha256Midstate(message, 0).hasLeadingZeroBits(zeros))
        assertTrue(!Sha256Midstate(message, 0).hasLeadingZeroBits(zeros + 1))
    }
}
