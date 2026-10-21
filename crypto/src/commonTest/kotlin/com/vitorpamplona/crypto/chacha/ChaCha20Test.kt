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

/** The [ChaCha20] stream cipher object: (message, nonce, key), counter 0. */
class ChaCha20Test {
    private fun hex(s: String): ByteArray = s.hexToByteArray()

    private val key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

    // ===== RFC 8439 §2.4.2: ChaCha20 Encryption Test Vector =====
    @Test
    fun testRfc8439Section242() {
        // The RFC starts at counter 1 and the object at 0, so a 64-byte prefix takes up block 0
        val nonce = hex("000000000000004a00000000")
        val plaintext =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
                .encodeToByteArray()
        val expected =
            hex(
                "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
                    "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
                    "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
                    "5af90bbf74a35be6b40b8eedf2785e42874d",
            )

        val encrypted = ChaCha20.encrypt(ByteArray(64) + plaintext, nonce, key)
        assertContentEquals(ChaCha20Core.chaCha20Block(key, 0, nonce), encrypted.copyOfRange(0, 64))
        assertContentEquals(expected, encrypted.copyOfRange(64, encrypted.size))

        val decrypted = ChaCha20.decrypt(encrypted, nonce, key)
        assertContentEquals(plaintext, decrypted.copyOfRange(64, decrypted.size))
    }

    // ===== RFC 8439 A.2 Test Vector #1: all-zero key and nonce, counter 0 =====
    @Test
    fun testRfc8439A2Vector1() {
        val expected =
            hex(
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7" +
                    "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
            )
        assertContentEquals(expected, ChaCha20.encrypt(ByteArray(64), ByteArray(12), ByteArray(32)))
    }

    @Test
    fun testRoundTrip() {
        val nonce = hex("000102030405060708090a0b")
        val plaintext = ByteArray(300) { (it * 7).toByte() }
        val encrypted = ChaCha20.encrypt(plaintext, nonce, key)
        assertContentEquals(ChaCha20Core.chaCha20Xor(plaintext, key, nonce, counter = 0), encrypted)
        assertContentEquals(plaintext, ChaCha20.decrypt(encrypted, nonce, key))
    }

    @Test
    fun testRejectsBadSizes() {
        val nonce = ByteArray(12)
        for (size in intArrayOf(0, 8, 11, 13, 24)) {
            assertFailsWith<IllegalArgumentException> { ChaCha20.encrypt(ByteArray(4), ByteArray(size), key) }
            assertFailsWith<IllegalArgumentException> { ChaCha20.decrypt(ByteArray(4), ByteArray(size), key) }
        }
        for (size in intArrayOf(0, 16, 31, 33, 64)) {
            assertFailsWith<IllegalArgumentException> { ChaCha20.encrypt(ByteArray(4), nonce, ByteArray(size)) }
            assertFailsWith<IllegalArgumentException> { ChaCha20.decrypt(ByteArray(4), nonce, ByteArray(size)) }
        }
    }

    @Test
    fun testSwappedKeyAndNonceFailLoudly() {
        // ChaCha20 takes (message, nonce, key) but ChaCha20Core.chaCha20Xor (message, key, nonce):
        // a caller mixing them up gets an error, not a ciphertext under the wrong key.
        val nonce = hex("000102030405060708090a0b")
        val e = assertFailsWith<IllegalArgumentException> { ChaCha20.encrypt(ByteArray(4), key, nonce) }
        assertEquals("ChaCha20 key must be 32 bytes, was 12", e.message)
    }
}
