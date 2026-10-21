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
package com.vitorpamplona.crypto.digest

import com.vitorpamplona.crypto.toHexKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The official RIPEMD-160 test vectors (Bosselaers' page), through [RIPEMD160Digest]
 * directly and through [DigestInstance], plus inputs on each side of the padding
 * boundaries: 55 bytes still fit the length in the same block, 56 do not, and 64 fill one.
 */
class RIPEMD160DigestTest {
    private val official =
        listOf(
            "" to "9c1185a5c5e9fc54612808977ee8f548b2258d31",
            "a" to "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
            "abc" to "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
            "message digest" to "5d0689ef49d2fae572b881b123a85ffa21595f36",
            "abcdefghijklmnopqrstuvwxyz" to "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" to "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "b0e20b6e3116640286ed3a87a5713079b21f5189",
            "1234567890".repeat(8) to "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
        )

    // n times 'a', across the padding boundaries of the first and second block.
    private val boundaries =
        listOf(
            55 to "0d8a8c9063a48576a7c97e9f95253a6e53ff6765",
            56 to "e72334b46c83cc70bef979e15453706c95b888be",
            57 to "eed82d19d597ab275b550ff3d6e0bc2a75350388",
            63 to "e640041293fe663b9bf3f8c21ffecac03819e6b2",
            64 to "9dfb7d374ad924f3f88de96291c33e9abed53e32",
            65 to "99724bb11811e7166af38f671b6a082d8ab4960b",
            119 to "23e398ff2bac815aa1bbb57ca2a669c841872919",
            120 to "c476770a6dae31fcee8d25efe6559a05c8024595",
            128 to "8dfdfb32b2ed5cb41a73478b4fd60cc5b4648b15",
        )

    private fun RIPEMD160Digest.hash(input: ByteArray): String {
        update(input, 0, input.size)
        return ByteArray(getDigestSize()).also { doFinal(it, 0) }.toHexKey()
    }

    @Test
    fun officialVectors() {
        val digest = RIPEMD160Digest()
        for ((input, expected) in official) {
            assertEquals(expected, digest.hash(input.encodeToByteArray()), input)
            assertEquals(expected, DigestInstance("RIPEMD-160").digest(input.encodeToByteArray()).toHexKey(), input)
        }
    }

    @Test
    fun paddingBoundaries() {
        for ((length, expected) in boundaries) {
            val input = ByteArray(length) { 'a'.code.toByte() }
            assertEquals(expected, RIPEMD160Digest().hash(input), "$length bytes")
            assertEquals(expected, DigestInstance("ripemd160").digest(input).toHexKey(), "$length bytes")
        }
    }

    @Test
    fun oneMillionAs() {
        val expected = "52783243c1697bdbe16d37f97f68f08325dc1528"
        assertEquals(expected, RIPEMD160Digest().hash(ByteArray(1_000_000) { 'a'.code.toByte() }))

        // The same in uneven pieces, so the word buffer is mid-word at most updates.
        val digest = DigestInstance("RIPEMD-160")
        val piece = ByteArray(999) { 'a'.code.toByte() }
        var fed = 0
        while (fed + piece.size <= 1_000_000) {
            digest.update(piece)
            fed += piece.size
        }
        while (fed < 1_000_000) {
            digest.update('a'.code.toByte())
            fed++
        }
        assertEquals(expected, digest.digest().toHexKey())
    }

    @Test
    fun copyContinuesFromTheSameState() {
        val prefix = RIPEMD160Digest()
        prefix.update("message ".encodeToByteArray(), 0, 8)
        val copy = RIPEMD160Digest(prefix)
        assertEquals("5d0689ef49d2fae572b881b123a85ffa21595f36", prefix.hash("digest".encodeToByteArray()))
        assertEquals("5d0689ef49d2fae572b881b123a85ffa21595f36", copy.hash("digest".encodeToByteArray()))
    }

    @Test
    fun rejectsBadRangesAndShortOutputs() {
        val digest = RIPEMD160Digest()
        assertFailsWith<IllegalArgumentException> { digest.update(ByteArray(4), 2, 3) }
        assertFailsWith<IllegalArgumentException> { digest.update(ByteArray(4), -1, 1) }
        assertFailsWith<IllegalArgumentException> { digest.update(ByteArray(4), 0, -1) }
        digest.update("abc".encodeToByteArray(), 0, 3)
        assertFailsWith<IllegalArgumentException> { digest.doFinal(ByteArray(19), 0) }
        assertFailsWith<IllegalArgumentException> { digest.doFinal(ByteArray(20), 1) }
        // The message fed before the failed calls is still there.
        val out = ByteArray(25)
        assertEquals(20, digest.doFinal(out, 5))
        assertEquals("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", out.copyOfRange(5, 25).toHexKey())
    }
}
