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
package com.vitorpamplona.crypto.chacha

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The pure-Kotlin ChaCha20 and ChaCha20-Poly1305 the platforms without JCA's run, against JCA:
 * every plaintext length from 0 to 300 plus a few large ones, AAD lengths around the 16-byte
 * Poly1305 block, and the stream cipher at counters in both halves of the unsigned range. The
 * public [ChaCha20Poly1305], which is JCA's here, is held to the same bytes.
 */
class ChaChaJcaTest {
    private val random = Random(2026)
    private val adSizes = intArrayOf(0, 1, 15, 16, 17, 33, 64)

    private fun jcaSeal(
        key: ByteArray,
        nonce: ByteArray,
        ad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray =
        Cipher.getInstance("ChaCha20-Poly1305").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            updateAAD(ad)
            doFinal(plaintext)
        }

    private fun jcaOpen(
        key: ByteArray,
        nonce: ByteArray,
        ad: ByteArray,
        sealed: ByteArray,
    ): ByteArray =
        Cipher.getInstance("ChaCha20-Poly1305").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            updateAAD(ad)
            doFinal(sealed)
        }

    private fun assertMatchesJca(
        plaintextSize: Int,
        adSize: Int,
    ) {
        val key = random.nextBytes(32)
        val nonce = random.nextBytes(12)
        val plaintext = random.nextBytes(plaintextSize)
        val ad = random.nextBytes(adSize)
        val label = "plaintext $plaintextSize, ad $adSize"

        val jca = jcaSeal(key, nonce, ad, plaintext)
        val kotlin = ChaCha20Poly1305.kotlinSeal(plaintext, ad, nonce, key)
        assertContentEquals(jca, kotlin, label)
        assertContentEquals(plaintext, ChaCha20Poly1305.kotlinOpen(jca, ad, nonce, key), label)
        assertContentEquals(plaintext, jcaOpen(key, nonce, ad, kotlin), label)
        assertContentEquals(jca, ChaCha20Poly1305.encrypt(plaintext, ad, nonce, key), label)
        assertContentEquals(plaintext, ChaCha20Poly1305.decrypt(jca, ad, nonce, key), label)
    }

    @Test
    fun aeadMatchesJcaForEveryShortLength() {
        for (size in 0..300) {
            for (adSize in adSizes) {
                assertMatchesJca(size, adSize)
            }
        }
    }

    @Test
    fun aeadMatchesJcaForLargeMessages() {
        for (size in intArrayOf(1000, 4096 + 3, 65536 + 17, 1 shl 20)) {
            for (adSize in adSizes) {
                assertMatchesJca(size, adSize)
            }
        }
    }

    @Test
    fun aeadRejectsWhatJcaRejects() {
        repeat(50) { round ->
            val key = random.nextBytes(32)
            val nonce = random.nextBytes(12)
            val ad = random.nextBytes(round % 20)
            val sealed = jcaSeal(key, nonce, ad, random.nextBytes(round * 3))
            val i = random.nextInt(sealed.size)
            sealed[i] = (sealed[i].toInt() xor (1 shl random.nextInt(8))).toByte()

            assertFailsWith<AEADBadTagException> { jcaOpen(key, nonce, ad, sealed) }
            assertNull(ChaCha20Poly1305.kotlinOpen(sealed, ad, nonce, key))
            assertFailsWith<IllegalArgumentException> { ChaCha20Poly1305.decrypt(sealed, ad, nonce, key) }
            assertNull(ChaCha20Poly1305.decryptOrNull(sealed, ad, nonce, key))
        }
    }

    @Test
    fun jcaIsUsedExactlyWhenHotSpotAcceleratesIt() {
        val accelerated =
            JcaChaCha20Poly1305.hotSpotFlag("UseChaCha20Intrinsics") && JcaChaCha20Poly1305.hotSpotFlag("UsePoly1305Intrinsics")
        if (accelerated) assertIs<JcaChaCha20Poly1305>(platformChaCha20Poly1305) else assertNull(platformChaCha20Poly1305)
    }

    @Test
    fun hotSpotFlagsReadTrueFalseAndAbsent() {
        // Boolean product flags with fixed defaults: TLABs on, flag printing off.
        assertTrue(JcaChaCha20Poly1305.hotSpotFlag("UseTLAB"))
        assertFalse(JcaChaCha20Poly1305.hotSpotFlag("PrintFlagsFinal"))
        assertFalse(JcaChaCha20Poly1305.hotSpotFlag("NoSuchFlagAnywhere"))
    }

    @Test
    fun streamMatchesJcaAcrossTheCounterRange() {
        // JCA reads the counter as unsigned too: -1 is block 0xffffffff
        val counters = intArrayOf(0, 1, 7, Int.MAX_VALUE - 3, Int.MAX_VALUE, Int.MIN_VALUE, -5, -2, -1)
        for (counter in counters) {
            val blocksLeft = 0x1_0000_0000L - counter.toUInt().toLong()
            for (size in intArrayOf(0, 1, 63, 64, 65, 200)) {
                if ((size + 63) / 64 > blocksLeft) continue
                val key = random.nextBytes(32)
                val nonce = random.nextBytes(12)
                val message = random.nextBytes(size)
                val jca =
                    Cipher.getInstance("ChaCha20").run {
                        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), ChaCha20ParameterSpec(nonce, counter))
                        doFinal(message)
                    }
                assertContentEquals(jca, ChaCha20Core.chaCha20Xor(message, key, nonce, counter), "counter $counter, size $size")
            }
        }
    }
}
