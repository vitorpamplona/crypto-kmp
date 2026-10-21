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
import kotlin.test.assertNull

/**
 * XChaCha20-Poly1305 against draft-irtf-cfrg-xchacha-03 §A.3.1, round trips, and every
 * way a decryption must fail.
 */
class XChaCha20Poly1305Test {
    private fun hex(s: String): ByteArray = s.hexToByteArray()

    private val key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private val nonce = hex("000102030405060708090a0b0c0d0e0f1011121314151617")
    private val ad = hex("feedfacedeadbeef")

    private val sunscreen =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

    // ===== XChaCha20 draft §A.3.1: XChaCha20-Poly1305 AEAD Test Vector =====
    private val draftKey = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    private val draftNonce = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
    private val draftAd = hex("50515253c0c1c2c3c4c5c6c7")
    private val draftCiphertext =
        hex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
                "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
                "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
                "21f9664c97637da9768812f615c68b13b52e",
        )
    private val draftTag = hex("c0875924c1c7987947deafd8780acf49")

    @Test
    fun testEncrypt_Draft() {
        val result = XChaCha20Poly1305.encrypt(sunscreen.encodeToByteArray(), draftAd, draftNonce, draftKey)
        assertContentEquals(draftCiphertext + draftTag, result)
    }

    @Test
    fun testDecrypt_Draft() {
        val plaintext = XChaCha20Poly1305.decrypt(draftCiphertext + draftTag, draftAd, draftNonce, draftKey)
        assertEquals(sunscreen, plaintext.decodeToString())
        assertEquals(sunscreen, XChaCha20Poly1305.decryptOrNull(draftCiphertext + draftTag, draftAd, draftNonce, draftKey)?.decodeToString())
    }

    @Test
    fun testMatchesChaCha20Poly1305UnderTheSubkey() {
        // draft-irtf-cfrg-xchacha §2.3: HChaCha20 subkey, then 4 zero bytes || nonce[16..24]
        val subKey = ChaCha20Core.hChaCha20(draftKey, draftNonce.copyOfRange(0, 16))
        val subNonce = ByteArray(4) + draftNonce.copyOfRange(16, 24)
        val result = ChaCha20Poly1305.encrypt(sunscreen.encodeToByteArray(), draftAd, subNonce, subKey)
        assertContentEquals(draftCiphertext + draftTag, result)
    }

    // ===== Round trips =====

    @Test
    fun testRoundTrip() {
        val plaintext = "This is a round-trip test.".encodeToByteArray()

        val encrypted = XChaCha20Poly1305.encrypt(plaintext, ad, nonce, key)
        val decrypted = XChaCha20Poly1305.decrypt(encrypted, ad, nonce, key)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testEmptyPlaintext() {
        val plaintext = ByteArray(0)

        val encrypted = XChaCha20Poly1305.encrypt(plaintext, ad, nonce, key)
        assertEquals(16, encrypted.size) // Just the tag
        val decrypted = XChaCha20Poly1305.decrypt(encrypted, ad, nonce, key)
        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testEmptyAD() {
        val plaintext = "No additional data".encodeToByteArray()

        val encrypted = XChaCha20Poly1305.encrypt(plaintext, ByteArray(0), nonce, key)
        val decrypted = XChaCha20Poly1305.decrypt(encrypted, ByteArray(0), nonce, key)
        assertContentEquals(plaintext, decrypted)
    }

    // ===== Failures: decrypt throws IllegalArgumentException, decryptOrNull returns null =====

    private fun assertRejected(
        ciphertextWithTag: ByteArray,
        ad: ByteArray = this.ad,
        nonce: ByteArray = this.nonce,
        key: ByteArray = this.key,
    ) {
        assertFailsWith<IllegalArgumentException> { XChaCha20Poly1305.decrypt(ciphertextWithTag, ad, nonce, key) }
        assertNull(XChaCha20Poly1305.decryptOrNull(ciphertextWithTag, ad, nonce, key))
    }

    private fun sealed() = XChaCha20Poly1305.encrypt("Tamper detection test".encodeToByteArray(), ad, nonce, key)

    private fun ByteArray.flip(index: Int) = copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }

    @Test
    fun testTamperedCiphertext() {
        assertRejected(sealed().flip(0))
    }

    @Test
    fun testTamperedTag() {
        val encrypted = sealed()
        assertRejected(encrypted.flip(encrypted.size - 16))
        assertRejected(encrypted.flip(encrypted.size - 1))
    }

    @Test
    fun testTamperedAD() {
        assertRejected(sealed(), ad = ad.flip(7))
        assertRejected(sealed(), ad = ByteArray(0))
    }

    @Test
    fun testWrongKey() {
        assertRejected(sealed(), key = key.flip(31))
    }

    @Test
    fun testWrongNonce() {
        // The first 16 bytes go to HChaCha20, the last 8 to the subnonce: both must matter
        assertRejected(sealed(), nonce = nonce.flip(0))
        assertRejected(sealed(), nonce = nonce.flip(23))
    }

    @Test
    fun testTruncatedInput() {
        val encrypted = sealed()
        for (size in 0 until 16) {
            assertRejected(encrypted.copyOf(size))
        }
        assertRejected(encrypted.copyOf(encrypted.size - 1))
    }

    @Test
    fun testInvalidNonceLength() {
        // 12 used to throw ArrayIndexOutOfBoundsException, 32 used to be truncated to 24
        for (size in intArrayOf(0, 12, 16, 23, 25, 32)) {
            val badNonce = ByteArray(size)
            assertFailsWith<IllegalArgumentException> { XChaCha20Poly1305.encrypt(ByteArray(4), ad, badNonce, key) }
            assertFailsWith<IllegalArgumentException> { XChaCha20Poly1305.decrypt(sealed(), ad, badNonce, key) }
            assertFailsWith<IllegalArgumentException> { XChaCha20Poly1305.decryptOrNull(sealed(), ad, badNonce, key) }
        }
    }

    @Test
    fun testInvalidKeyLength() {
        // 64 used to be truncated to 32
        for (size in intArrayOf(0, 16, 24, 31, 33, 64)) {
            val badKey = ByteArray(size)
            assertFailsWith<IllegalArgumentException> { XChaCha20Poly1305.encrypt(ByteArray(4), ad, nonce, badKey) }
            assertFailsWith<IllegalArgumentException> { XChaCha20Poly1305.decrypt(sealed(), ad, nonce, badKey) }
            assertFailsWith<IllegalArgumentException> { XChaCha20Poly1305.decryptOrNull(sealed(), ad, nonce, badKey) }
        }
    }

    @Test
    fun testSwappedKeyAndNonceFail() {
        val e = assertFailsWith<IllegalArgumentException> { XChaCha20Poly1305.encrypt(ByteArray(4), ad, key, nonce) }
        assertEquals("XChaCha20 key must be 32 bytes, was 24", e.message)
    }
}
