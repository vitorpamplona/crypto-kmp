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
package com.vitorpamplona.crypto.aes

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

/**
 * CommonCrypto's AES under [CtrGcmKey] against the bitsliced [AesGcmKey], at every short length,
 * at counters around the 32-bit wrap, and through the public [AESGCM], which runs it here.
 */
class CommonCryptoGcmTest {
    private val random = Random(0x6363)

    @Test
    fun theBlockAndTheStreamMatchTheBitslicedAes() {
        for (size in intArrayOf(16, 24, 32)) {
            val key = random.nextBytes(size)
            val block = random.nextBytes(16)
            assertContentEquals(CarryingCtr(key).encryptBlock(block), CommonCryptoAesCtr(key).encryptBlock(block), "key $size")
            val iv = random.nextBytes(16).also { it[12] = 0 }
            val message = random.nextBytes(1000)
            val expected = ByteArray(1000)
            val actual = ByteArray(1000)
            CarryingCtr(key).stream(iv).xor(message, 0, 1000, expected, 0)
            // In uneven pieces, each a whole number of blocks but the last, as CtrGcmKey calls it.
            val stream = CommonCryptoAesCtr(key).stream(iv)
            stream.xor(message, 0, 16, actual, 0)
            stream.xor(message, 16, 480, actual, 16)
            stream.xor(message, 496, 504, actual, 496)
            stream.close()
            assertContentEquals(expected, actual, "key $size")
        }
    }

    @Test
    fun gcmMatchesTheBitslicedGcm() {
        for (keySize in intArrayOf(16, 24, 32)) {
            val key = random.nextBytes(keySize)
            val reference = AesGcmKey(key)
            val commonCrypto = CtrGcmKey(CommonCryptoAesCtr(key))
            for (size in (0..100) + listOf(4096 + 3, 65536 + 17)) {
                val nonce = random.nextBytes(if (size % 3 == 0) 12 else 1 + size % 40)
                val plaintext = random.nextBytes(size)
                val aad = random.nextBytes(size % 33)
                val sealed = reference.encrypt(nonce, plaintext, aad)
                assertContentEquals(sealed, commonCrypto.encrypt(nonce, plaintext, aad), "key $keySize, size $size")
                assertContentEquals(plaintext, commonCrypto.decrypt(nonce, sealed, aad), "key $keySize, size $size")
            }
            for (counter in longArrayOf(0xFFFF_FFFF, 0xFFFF_FFFE, 0xFFFF_FFF0)) {
                val j0 = ByteArray(16) { -1 }
                for (i in 0 until 4) j0[15 - i] = (counter ushr (8 * i)).toByte()
                val plaintext = random.nextBytes(300)
                assertContentEquals(reference.encryptFromJ0(j0, plaintext, ByteArray(0)), commonCrypto.encryptFromJ0(j0, plaintext, ByteArray(0)), "counter $counter")
            }
        }
    }

    @Test
    fun theApplePlatformRunsCommonCrypto() {
        assertIs<CtrGcmKey>(gcmKey(ByteArray(32)))
        assertFailsWith<IllegalArgumentException> { gcmKey(ByteArray(20)) }
    }
}
