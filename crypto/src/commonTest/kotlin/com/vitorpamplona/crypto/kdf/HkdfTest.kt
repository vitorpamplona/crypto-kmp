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
package com.vitorpamplona.crypto.kdf

import com.vitorpamplona.crypto.hexToByteArray
import com.vitorpamplona.crypto.toHexKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** RFC 5869 Appendix A.1, the SHA-256 basic test case. */
class HkdfTest {
    private val ikm = ByteArray(22) { 0x0b }
    private val salt = "000102030405060708090a0b0c".hexToByteArray()
    private val info = "f0f1f2f3f4f5f6f7f8f9".hexToByteArray()
    private val prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    private val okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

    @Test
    fun extractAndExpand() {
        val hkdf = Hkdf()
        val extracted = hkdf.extract(ikm, salt)
        assertEquals(prk, extracted.toHexKey())
        assertEquals(okm, hkdf.expand(extracted, info, 42).toHexKey())
    }

    @Test
    fun extractOfTwoPartsMatchesTheirConcatenation() {
        val hkdf = Hkdf()
        assertEquals(prk, hkdf.extract(ikm.copyOfRange(0, 9), ikm.copyOfRange(9, 22), salt).toHexKey())
    }

    @Test
    fun rejectsOutputLongerThan255Blocks() {
        assertFailsWith<IllegalArgumentException> { Hkdf().expand(prk.hexToByteArray(), info, 255 * 32 + 1) }
    }
}
