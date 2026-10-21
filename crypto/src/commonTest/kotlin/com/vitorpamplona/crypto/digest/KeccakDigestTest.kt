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
 * Keccak (original padding, not FIPS 202 SHA-3) known answers. The values were computed
 * with an independent Keccak-f[1600] sponge that matches Python's `hashlib.sha3_*` when
 * given the SHA-3 padding byte, then run with Keccak's.
 */
class KeccakDigestTest {
    private fun KeccakDigest.hash(input: ByteArray): String {
        update(input, 0, input.size)
        return ByteArray(getDigestSize()).also { doFinal(it, 0) }.toHexKey()
    }

    private fun a(count: Int) = ByteArray(count) { 'a'.code.toByte() }

    @Test
    fun keccak256KnownAnswers() {
        assertEquals("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", KeccakDigest().hash(ByteArray(0)))
        assertEquals("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", KeccakDigest().hash("abc".encodeToByteArray()))
        // The rate is 136 bytes: one byte short of a block, exactly one block, and two blocks.
        assertEquals("34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446", KeccakDigest().hash(a(135)))
        assertEquals("a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e", KeccakDigest().hash(a(136)))
        assertEquals("96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d", KeccakDigest().hash(a(200)))
    }

    @Test
    fun defaultIsKeccak256() {
        val digest = KeccakDigest()
        assertEquals(32, digest.getDigestSize())
        assertEquals("Keccak-256", digest.getAlgorithmName())
        assertEquals(KeccakDigest(256).hash(a(10)), digest.hash(a(10)))
    }

    @Test
    fun otherSizes() {
        val abc = "abc".encodeToByteArray()
        assertEquals("c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8", KeccakDigest(224).hash(abc))
        assertEquals(
            "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e",
            KeccakDigest(384).hash(abc),
        )
        assertEquals(
            "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5" +
                "d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
            KeccakDigest(512).hash(abc),
        )
        assertFailsWith<IllegalArgumentException> { KeccakDigest(160) }
    }

    @Test
    fun streamingMatchesOneShotAndResets() {
        val expected = "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d"
        val digest = KeccakDigest()
        repeat(2) {
            // A byte at a time, then uneven pieces: the queue is mid-block at every update.
            repeat(7) { digest.update('a'.code.toByte()) }
            digest.update(a(100), 0, 100)
            digest.update(a(93), 0, 93)
            assertEquals(expected, ByteArray(32).also { digest.doFinal(it, 0) }.toHexKey())
        }
    }

    @Test
    fun copyContinuesFromTheSameState() {
        val prefix = KeccakDigest()
        prefix.update(a(150), 0, 150)
        val copy = KeccakDigest(prefix)
        assertEquals("96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d", prefix.hash(a(50)))
        assertEquals("96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d", copy.hash(a(50)))
    }

    @Test
    fun rejectsBadRangesAndShortOutputs() {
        val digest = KeccakDigest()
        assertFailsWith<IllegalArgumentException> { digest.update(ByteArray(4), 2, 3) }
        assertFailsWith<IllegalArgumentException> { digest.update(ByteArray(4), -1, 1) }
        assertFailsWith<IllegalArgumentException> { digest.update(ByteArray(4), 0, -1) }
        digest.update("abc".encodeToByteArray(), 0, 3)
        assertFailsWith<IllegalArgumentException> { digest.doFinal(ByteArray(31), 0) }
        // The message fed before the failed calls is still there.
        val out = ByteArray(32)
        digest.doFinal(out, 0)
        assertEquals("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", out.toHexKey())
    }
}
