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

import com.vitorpamplona.crypto.hexToByteArray
import com.vitorpamplona.crypto.wycheproof.AES_GCM_VECTORS
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * An [AesCtr] on the bitsliced AES that counts the way CommonCrypto does: the whole 16-byte
 * block, big-endian, carrying past the low 32 bits. Run under [CtrGcmKey], it shows the GCM
 * logic Apple uses gives [AesGcmKey]'s bytes on every platform, wraps included.
 */
internal class CarryingCtr(
    key: ByteArray,
) : AesCtr {
    private val aes = AesBitsliced(key)

    override fun encryptBlock(block: ByteArray): ByteArray = ByteArray(16).also { aes.encryptBlocks(block, 0, it, 0, 1, AesBitsliced.Scratch()) }

    override fun stream(iv: ByteArray): AesCtrStream =
        object : AesCtrStream {
            private val counter = iv.copyOf()
            private var keystream = ByteArray(16)
            private var used = 16

            override fun xor(
                input: ByteArray,
                inputOffset: Int,
                length: Int,
                output: ByteArray,
                outputOffset: Int,
            ) {
                for (i in 0 until length) {
                    if (used == 16) {
                        keystream = encryptBlock(counter)
                        increment(counter)
                        used = 0
                    }
                    output[outputOffset + i] = (input[inputOffset + i].toInt() xor keystream[used++].toInt()).toByte()
                }
            }

            override fun close() {}
        }

    companion object {
        /** The 128-bit big-endian increment, carry and all. */
        fun increment(block: ByteArray) {
            for (i in 15 downTo 0) {
                block[i]++
                if (block[i] != 0.toByte()) return
            }
        }
    }
}

class CtrGcmKeyTest {
    private val random = Random(0x6763)

    @Test
    fun theCarryingCtrCarries() {
        // Were it to count inc32, the wrap tests below would pass without CtrGcmKey's restart.
        val block = ByteArray(16) { if (it < 12) 0 else -1 }
        CarryingCtr.increment(block)
        assertContentEquals(ByteArray(16) { if (it == 11) 1 else 0 }, block)
    }

    @Test
    fun wycheproofGivesTheBitslicedBytes() {
        var compared = 0
        for (vector in AES_GCM_VECTORS) {
            val f = vector.split('|')
            val bytes = f.drop(3).map { it.hexToByteArray() }
            val (key, iv, aad, msg, ct) = bytes
            val tag = bytes[5]
            if (iv.isEmpty()) {
                assertFailsWith<IllegalArgumentException> { CtrGcmKey(CarryingCtr(key)).encrypt(iv, msg, aad) }
                continue
            }
            val reference = AesGcmKey(key)
            val ctr = CtrGcmKey(CarryingCtr(key))
            assertContentEquals(reference.encrypt(iv, msg, aad), ctr.encrypt(iv, msg, aad), "tcId ${f[0]} encrypt")
            val opened = runCatching { reference.decrypt(iv, ct + tag, aad) }
            val ctrOpened = runCatching { ctr.decrypt(iv, ct + tag, aad) }
            assertEquals(opened.isSuccess, ctrOpened.isSuccess, "tcId ${f[0]} decrypt")
            if (opened.isSuccess) assertContentEquals(opened.getOrThrow(), ctrOpened.getOrThrow(), "tcId ${f[0]}")
            if (ctrOpened.isFailure) assertTrue(ctrOpened.exceptionOrNull() is IllegalArgumentException, "tcId ${f[0]}")
            compared++
        }
        assertTrue(compared > 300)
    }

    @Test
    fun countersAroundTheWrapGiveTheBitslicedBytes() {
        // All-ones above the counter, so a carry out of the low 32 bits changes every block after.
        val counters = longArrayOf(0xFFFF_FFFF, 0xFFFF_FFFE, 0xFFFF_FFFD, 0xFFFF_FFF0, 0x7FFF_FFFF, 0, 1)
        for (key in listOf(random.nextBytes(16), random.nextBytes(24), random.nextBytes(32))) {
            val reference = AesGcmKey(key)
            val ctr = CtrGcmKey(CarryingCtr(key))
            for (counter in counters) {
                val j0 = ByteArray(16) { -1 }
                for (i in 0 until 4) j0[15 - i] = (counter ushr (8 * i)).toByte()
                for (size in (0..70) + listOf(255, 256, 257, 1000)) {
                    val plaintext = random.nextBytes(size)
                    val aad = random.nextBytes(size % 20)
                    assertContentEquals(reference.encryptFromJ0(j0, plaintext, aad), ctr.encryptFromJ0(j0, plaintext, aad), "counter $counter, size $size")
                }
            }
        }
    }

    @Test
    fun decryptChecksTheTagBeforeItDecrypts() {
        val key = random.nextBytes(32)
        val nonce = random.nextBytes(12)
        val ctr = CtrGcmKey(CarryingCtr(key))
        val sealed = ctr.encrypt(nonce, random.nextBytes(100), random.nextBytes(7))
        sealed[sealed.size - 1] = (sealed[sealed.size - 1].toInt() xor 1).toByte()
        assertFailsWith<IllegalArgumentException> { ctr.decrypt(nonce, sealed, ByteArray(7)) }
        assertFailsWith<IllegalArgumentException> { ctr.decrypt(nonce, ByteArray(15), ByteArray(0)) }
    }
}
