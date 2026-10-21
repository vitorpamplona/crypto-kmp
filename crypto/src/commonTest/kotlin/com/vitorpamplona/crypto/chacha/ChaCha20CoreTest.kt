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

import com.vitorpamplona.crypto.hexToByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Test vectors from RFC 8439 and the XChaCha20 draft (draft-irtf-cfrg-xchacha-03), plus
 * the size checks and the 32-bit block counter limit of the low-level functions.
 */
class ChaCha20CoreTest {
    private fun hex(s: String): ByteArray = s.replace(" ", "").hexToByteArray()

    private val key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private val nonce = hex("000000090000004a00000000")
    private val xNonce = hex("000102030405060708090a0b0c0d0e0f1011121314151617")

    // ===== RFC 8439 §2.3.2: ChaCha20 Block Function Test Vector =====
    @Test
    fun testChaCha20Block_RFC8439() {
        val counter = 1

        val block = ChaCha20Core.chaCha20Block(key, counter, nonce)

        val expected =
            hex(
                "10f1e7e4d13b5915500fdd1fa32071c4" +
                    "c7d1f4c733c068030422aa9ac3d46c4e" +
                    "d2826446079faa0914c2d705d98b02a2" +
                    "b5129cd1de164eb9cbd083e8a2503c4e",
            )
        assertContentEquals(expected, block)
    }

    // ===== RFC 8439 §2.4.2: ChaCha20 Encryption Test Vector =====
    @Test
    fun testChaCha20Encrypt_RFC8439() {
        val nonce = hex("000000000000004a00000000")
        val counter = 1
        val plaintext =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
                .encodeToByteArray()

        val ciphertext = ChaCha20Core.chaCha20Xor(plaintext, key, nonce, counter)

        val expected =
            hex(
                "6e2e359a2568f98041ba0728dd0d6981" +
                    "e97e7aec1d4360c20a27afccfd9fae0b" +
                    "f91b65c5524733ab8f593dabcd62b357" +
                    "1639d624e65152ab8f530c359f0861d8" +
                    "07ca0dbf500d6a6156a38e088a22b65e" +
                    "52bc514d16ccf806818ce91ab7793736" +
                    "5af90bbf74a35be6b40b8eedf2785e42" +
                    "874d",
            )
        assertContentEquals(expected, ciphertext)
    }

    // ===== RFC 8439 §2.5.2: Poly1305 Test Vector =====
    @Test
    fun testPoly1305_RFC8439() {
        val key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        val message =
            "Cryptographic Forum Research Group".encodeToByteArray()

        val tag = Poly1305.mac(message, key)

        val expected = hex("a8061dc1305136c6c22b8baf0c0127a9")
        assertContentEquals(expected, tag)
    }

    // ===== RFC 8439 §2.6.2: Poly1305 Key Generation =====
    @Test
    fun testPoly1305KeyGeneration_RFC8439() {
        val key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val nonce = hex("000000000001020304050607")

        val expected = hex("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646")
        assertContentEquals(expected, ChaCha20Core.chaCha20Block(key, 0, nonce).copyOfRange(0, 32))
        assertContentEquals(expected, ChaCha20Core.chaCha20PolyKey(key, nonce))
    }

    // ===== XChaCha20 draft §2.2.1: HChaCha20 Test Vector =====
    @Test
    fun testHChaCha20_Draft() {
        val input = hex("000000090000004a0000000031415927")

        val subKey = ChaCha20Core.hChaCha20(key, input)

        val expected = hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
        assertContentEquals(expected, subKey)
    }

    // ===== ChaCha20 stream cipher (counter=0) =====
    @Test
    fun testChaCha20Xor_SymmetricEncryptDecrypt() {
        val plaintext = "Symmetric cipher test".encodeToByteArray()

        val encrypted = ChaCha20Core.chaCha20Xor(plaintext, key, nonce, counter = 0)
        val decrypted = ChaCha20Core.chaCha20Xor(encrypted, key, nonce, counter = 0)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testChaCha20Xor_IsKeystreamBlocksInOrder() {
        // Every length around the word and block boundaries XORs the same keystream bytes
        val keystream = ChaCha20Core.chaCha20Block(key, 7, nonce) + ChaCha20Core.chaCha20Block(key, 8, nonce)
        for (size in 0..128) {
            val message = ByteArray(size) { (it * 31).toByte() }
            val expected = ByteArray(size) { (message[it].toInt() xor keystream[it].toInt()).toByte() }
            assertContentEquals(expected, ChaCha20Core.chaCha20Xor(message, key, nonce, counter = 7), "size $size")
        }
    }

    // ===== XChaCha20 stream cipher symmetry =====
    @Test
    fun testXChaCha20Xor_SymmetricEncryptDecrypt() {
        val plaintext = "XChaCha20 symmetric test".encodeToByteArray()

        val encrypted = ChaCha20Core.xChaCha20Xor(plaintext, xNonce, key)
        val decrypted = ChaCha20Core.xChaCha20Xor(encrypted, xNonce, key)

        assertContentEquals(plaintext, decrypted)
    }

    // ===== 32-bit block counter: RFC 8439 §2.4 forbids wrapping round to block 0 =====

    @Test
    fun testCounterWrapThrows() {
        // Two blocks from 0xffffffff would reuse block 0's keystream for the second
        assertFailsWith<IllegalArgumentException> { ChaCha20Core.chaCha20Xor(ByteArray(128), key, nonce, counter = -1) }
        // One byte past the last block is enough
        assertFailsWith<IllegalArgumentException> { ChaCha20Core.chaCha20Xor(ByteArray(65), key, nonce, counter = -1) }
        assertFailsWith<IllegalArgumentException> { ChaCha20Core.chaCha20Xor(ByteArray(64 * 16 + 1), key, nonce, counter = -16) }
    }

    @Test
    fun testLastValidBlockWorks() {
        // Block 0xffffffff, the last one, is usable on its own
        val last = ChaCha20Core.chaCha20Block(key, -1, nonce)
        assertContentEquals(last, ChaCha20Core.chaCha20Xor(ByteArray(64), key, nonce, counter = -1))
        assertContentEquals(last.copyOf(10), ChaCha20Core.chaCha20Xor(ByteArray(10), key, nonce, counter = -1))
        // and so is a run ending on it
        val lastTwo = ChaCha20Core.chaCha20Block(key, -2, nonce) + last
        assertContentEquals(lastTwo, ChaCha20Core.chaCha20Xor(ByteArray(128), key, nonce, counter = -2))
        // An empty message needs no block at all
        assertContentEquals(ByteArray(0), ChaCha20Core.chaCha20Xor(ByteArray(0), key, nonce, counter = -1))
        // The keystream of the last block isn't block 0's
        assertTrue(!last.contentEquals(ChaCha20Core.chaCha20Block(key, 0, nonce)))
    }

    @Test
    fun testCounterCrossesFromSignedMaxToUnsignedHighRange() {
        // Int.MAX_VALUE + 1 is block 2^31, which an Int holds as Int.MIN_VALUE
        val expected = ChaCha20Core.chaCha20Block(key, Int.MAX_VALUE, nonce) + ChaCha20Core.chaCha20Block(key, Int.MIN_VALUE, nonce)
        assertContentEquals(expected, ChaCha20Core.chaCha20Xor(ByteArray(128), key, nonce, counter = Int.MAX_VALUE))
    }

    // ===== Size checks =====

    @Test
    fun testChaCha20RejectsBadKeyAndNonceSizes() {
        for (size in intArrayOf(0, 16, 31, 33, 64)) {
            val badKey = ByteArray(size)
            assertFailsWith<IllegalArgumentException> { ChaCha20Core.chaCha20Xor(ByteArray(4), badKey, nonce) }
            assertFailsWith<IllegalArgumentException> { ChaCha20Core.chaCha20Block(badKey, 0, nonce) }
        }
        for (size in intArrayOf(0, 8, 11, 13, 16, 24)) {
            val badNonce = ByteArray(size)
            assertFailsWith<IllegalArgumentException> { ChaCha20Core.chaCha20Xor(ByteArray(4), key, badNonce) }
            assertFailsWith<IllegalArgumentException> { ChaCha20Core.chaCha20Block(key, 0, badNonce) }
        }
        // Even an empty message is checked
        assertFailsWith<IllegalArgumentException> { ChaCha20Core.chaCha20Xor(ByteArray(0), key, ByteArray(8)) }
    }

    @Test
    fun testHChaCha20RejectsBadKeyAndInputSizes() {
        val input = ByteArray(16)
        for (size in intArrayOf(0, 16, 31, 33, 64)) {
            assertFailsWith<IllegalArgumentException> { ChaCha20Core.hChaCha20(ByteArray(size), input) }
        }
        for (size in intArrayOf(0, 12, 15, 17, 24)) {
            assertFailsWith<IllegalArgumentException> { ChaCha20Core.hChaCha20(key, ByteArray(size)) }
        }
    }

    @Test
    fun testXChaCha20RejectsBadKeyAndNonceSizes() {
        for (size in intArrayOf(0, 16, 31, 33, 64)) {
            assertFailsWith<IllegalArgumentException> { ChaCha20Core.xChaCha20Xor(ByteArray(4), xNonce, ByteArray(size)) }
        }
        for (size in intArrayOf(0, 12, 16, 23, 25, 32)) {
            assertFailsWith<IllegalArgumentException> { ChaCha20Core.xChaCha20Xor(ByteArray(4), ByteArray(size), key) }
        }
    }

    // ===== Argument order: chaCha20Xor is (message, key, nonce), xChaCha20Xor (message, nonce, key) =====

    @Test
    fun testSwappedKeyAndNonceFailLoudly() {
        val message = ByteArray(4)

        val chacha = assertFailsWith<IllegalArgumentException> { ChaCha20Core.chaCha20Xor(message, nonce, key) }
        assertEquals("ChaCha20 key must be 32 bytes, was 12", chacha.message)

        val xchacha = assertFailsWith<IllegalArgumentException> { ChaCha20Core.xChaCha20Xor(message, key, xNonce) }
        assertEquals("XChaCha20 key must be 32 bytes, was 24", xchacha.message)

        val block = assertFailsWith<IllegalArgumentException> { ChaCha20Core.chaCha20Block(nonce, 0, key) }
        assertEquals("ChaCha20 key must be 32 bytes, was 12", block.message)
    }
}
