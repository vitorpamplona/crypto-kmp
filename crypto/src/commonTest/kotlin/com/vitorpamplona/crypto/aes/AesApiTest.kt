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

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * How the public [AESGCM] and [AESCBC] behave on bad sizes, tampered input and reuse. The
 * exceptions are part of the contract, so these hold every platform (JCA, CommonCrypto and the
 * Kotlin cores) to the same ones.
 */
class AesApiTest {
    private fun pattern(
        size: Int,
        mul: Int,
        add: Int,
    ) = ByteArray(size) { ((it * mul + add) and 0xFF).toByte() }

    private fun ByteArray.flipBit(
        index: Int,
        bit: Int = 0,
    ) = copyOf().also { it[index] = (it[index].toInt() xor (1 shl bit)).toByte() }

    private val key = pattern(32, 7, 1)
    private val nonce = pattern(12, 11, 3)
    private val iv = pattern(16, 11, 3)
    private val plaintext = pattern(40, 13, 5)
    private val aad = pattern(20, 17, 9)

    private fun assertGcmRejects(
        cipher: AESGCM,
        input: ByteArray,
        aad: ByteArray,
        label: String,
    ) {
        assertFailsWith<IllegalArgumentException>(label) { cipher.decrypt(input, aad) }
        assertNull(cipher.decryptOrNull(input, aad), label)
        if (aad.isEmpty()) {
            assertFailsWith<IllegalArgumentException>(label) { cipher.decrypt(input) }
            assertNull(cipher.decryptOrNull(input), label)
        }
    }

    private fun assertCbcRejects(
        cipher: AESCBC,
        input: ByteArray,
        label: String,
    ) {
        assertFailsWith<IllegalArgumentException>(label) { cipher.decrypt(input) }
        assertNull(cipher.decryptOrNull(input), label)
    }

    @Test
    fun namesAreTheCommonConstants() {
        assertEquals(AES_GCM_NAME, AESGCM(key, nonce).name())
        assertEquals(AES_CBC_NAME, AESCBC(key, iv).name())
    }

    @Test
    fun defaultsAre32ByteKeysAnd16ByteNonces() {
        // 16, not 12: earlier versions used 16, and existing ciphertexts depend on it.
        val gcm = AESGCM()
        assertEquals(32, gcm.keyBytes.size)
        assertEquals(16, gcm.nonce.size)
        val sealed = gcm.encrypt(plaintext)
        assertContentEquals(plaintext, AESGCM(gcm.keyBytes, gcm.nonce).decrypt(sealed))

        val cbc = AESCBC()
        assertEquals(32, cbc.keyBytes.size)
        assertEquals(16, cbc.iv.size)
        assertContentEquals(plaintext, cbc.decrypt(cbc.encrypt(plaintext)))
    }

    @Test
    fun wrongKeySizesThrowAtConstruction() {
        for (size in intArrayOf(0, 15, 17, 33)) {
            assertFailsWith<IllegalArgumentException>("key $size") { AESGCM(ByteArray(size), nonce) }
            assertFailsWith<IllegalArgumentException>("key $size") { AESCBC(ByteArray(size), iv) }
        }
        for (size in intArrayOf(16, 24, 32)) {
            assertContentEquals(plaintext, AESGCM(ByteArray(size), nonce).let { it.decrypt(it.encrypt(plaintext)) })
            assertContentEquals(plaintext, AESCBC(ByteArray(size), iv).let { it.decrypt(it.encrypt(plaintext)) })
        }
    }

    @Test
    fun wrongIvSizesThrowAtConstruction() {
        for (size in intArrayOf(0, 8, 12, 15, 17, 32)) {
            assertFailsWith<IllegalArgumentException>("iv $size") { AESCBC(key, ByteArray(size)) }
        }
    }

    @Test
    fun emptyNonceThrowsAtConstruction() {
        assertFailsWith<IllegalArgumentException> { AESGCM(key, ByteArray(0)) }
        // Any other length is valid GCM.
        for (size in intArrayOf(1, 8, 12, 16, 60)) {
            val cipher = AESGCM(key, pattern(size, 11, 3))
            assertContentEquals(plaintext, cipher.decrypt(cipher.encrypt(plaintext)), "nonce $size")
        }
    }

    @Test
    fun gcmRejectsInputShorterThanTheTag() {
        val cipher = AESGCM(key, nonce)
        for (size in intArrayOf(0, 1, 15)) {
            assertGcmRejects(cipher, ByteArray(size), ByteArray(0), "size $size")
            assertGcmRejects(cipher, ByteArray(size), aad, "size $size with aad")
        }
    }

    @Test
    fun gcmEmptyPlaintextIsJustATag() {
        val sealed = AESGCM(key, nonce).encrypt(ByteArray(0), aad)
        assertEquals(16, sealed.size)
        assertContentEquals(ByteArray(0), AESGCM(key, nonce).decrypt(sealed, aad))
    }

    @Test
    fun gcmRejectsTamperingUnderTheRightAad() {
        val sealed = AESGCM(key, nonce).encrypt(plaintext, aad)
        val cipher = AESGCM(key, nonce)
        assertContentEquals(plaintext, cipher.decrypt(sealed, aad))
        assertContentEquals(plaintext, cipher.decryptOrNull(sealed, aad))

        assertGcmRejects(cipher, sealed.flipBit(0), aad, "ciphertext first bit")
        assertGcmRejects(cipher, sealed.flipBit(plaintext.size - 1, 7), aad, "ciphertext last bit")
        assertGcmRejects(cipher, sealed.flipBit(plaintext.size), aad, "tag first bit")
        assertGcmRejects(cipher, sealed.flipBit(sealed.size - 1, 7), aad, "tag last bit")
        assertGcmRejects(cipher, sealed, aad.flipBit(0), "aad first bit")
        assertGcmRejects(cipher, sealed, aad.flipBit(aad.size - 1, 7), "aad last bit")
        assertGcmRejects(cipher, sealed, aad.copyOf(aad.size - 1), "aad truncated")
        assertGcmRejects(cipher, sealed.copyOf(sealed.size - 1), aad, "truncated by one byte")
        assertGcmRejects(cipher, sealed.copyOf(sealed.size - 16), aad, "tag dropped")
        assertGcmRejects(cipher, sealed.copyOfRange(1, sealed.size), aad, "first byte dropped")
        assertGcmRejects(cipher, sealed + 0, aad, "byte appended")

        // The right bytes still open afterwards: a failure leaves nothing behind.
        assertContentEquals(plaintext, cipher.decrypt(sealed, aad))
    }

    @Test
    fun gcmSealedWithAadDoesNotOpenWithoutIt() {
        val sealed = AESGCM(key, nonce).encrypt(plaintext, aad)
        assertGcmRejects(AESGCM(key, nonce), sealed, ByteArray(0), "no aad")
        assertNotNull(AESGCM(key, nonce).decryptOrNull(sealed, aad))
    }

    @Test
    fun gcmEncryptsOncePerInstance() {
        val cipher = AESGCM(key, nonce)
        val sealed = cipher.encrypt(plaintext, aad)
        assertFailsWith<IllegalStateException> { cipher.encrypt(plaintext, aad) }
        assertFailsWith<IllegalStateException> { cipher.encrypt(plaintext) }
        assertFailsWith<IllegalStateException> { cipher.encrypt(ByteArray(0), ByteArray(0)) }

        val other = AESGCM(key, nonce)
        other.encrypt(plaintext)
        assertFailsWith<IllegalStateException> { other.encrypt(plaintext, aad) }

        // Decrypting is not limited, before or after the instance has encrypted.
        repeat(3) {
            assertContentEquals(plaintext, cipher.decrypt(sealed, aad))
            assertContentEquals(plaintext, cipher.decryptOrNull(sealed, aad))
        }
        val reader = AESGCM(key, nonce)
        repeat(3) { assertContentEquals(plaintext, reader.decrypt(sealed, aad)) }
    }

    @Test
    fun gcmIgnoresLaterChangesToTheCallersArrays() {
        val expected = AESGCM(key, nonce).encrypt(plaintext, aad)
        val keyCopy = key.copyOf()
        val nonceCopy = nonce.copyOf()
        val cipher = AESGCM(keyCopy, nonceCopy)
        keyCopy.fill(0)
        nonceCopy.fill(0)
        assertContentEquals(expected, cipher.encrypt(plaintext, aad))
        assertContentEquals(plaintext, cipher.decrypt(expected, aad))
    }

    @Test
    fun cbcIgnoresLaterChangesToTheCallersArrays() {
        val expected = AESCBC(key, iv).encrypt(plaintext)
        val keyCopy = key.copyOf()
        val ivCopy = iv.copyOf()
        val cipher = AESCBC(keyCopy, ivCopy)
        keyCopy.fill(0)
        ivCopy.fill(0)
        assertContentEquals(expected, cipher.encrypt(plaintext))
        assertContentEquals(plaintext, cipher.decrypt(expected))
    }

    @Test
    fun cbcEmptyPlaintextIsAFullPaddingBlock() {
        val cipher = AESCBC(key, iv)
        val sealed = cipher.encrypt(ByteArray(0))
        assertEquals(16, sealed.size)
        assertContentEquals(ByteArray(0), cipher.decrypt(sealed))
        assertContentEquals(ByteArray(0), cipher.decryptOrNull(sealed))
    }

    @Test
    fun cbcRejectsEmptyAndPartialBlocks() {
        val cipher = AESCBC(key, iv)
        val sealed = cipher.encrypt(plaintext)
        for (size in intArrayOf(0, 1, 15, 17, 31, sealed.size - 1, sealed.size + 1)) {
            val input = if (size <= sealed.size) sealed.copyOf(size) else sealed + 0
            assertCbcRejects(cipher, input, "size $size")
        }
    }

    @Test
    fun cbcRejectsBadPadding() {
        val cipher = AESCBC(key, iv)
        val sealed = cipher.encrypt(pattern(20, 13, 5))
        // Flipping a bit of the second-to-last block's last byte changes the last plaintext
        // byte, which is the padding length.
        assertCbcRejects(cipher, sealed.flipBit(sealed.size - 17, 6), "padding length")
        // A padding byte other than the last one.
        assertCbcRejects(cipher, sealed.flipBit(sealed.size - 20), "padding byte")
        // A last byte of 0, and of 17: neither is a padding length.
        assertCbcRejects(cipher, sealed.flipBit(sealed.size - 17, 2).flipBit(sealed.size - 17, 3), "zero padding")
        assertCbcRejects(
            cipher,
            sealed
                .flipBit(sealed.size - 17, 2)
                .flipBit(sealed.size - 17, 3)
                .flipBit(sealed.size - 17, 4)
                .flipBit(sealed.size - 17, 0),
            "padding 17",
        )
    }

    @Test
    fun cbcAcceptsOnlyValidPaddingBytes() {
        val plaintext = pattern(20, 13, 5)
        // 20 bytes pad with twelve 0x0c bytes. XOR-ing the second-to-last block's last byte with
        // delta turns the final padding byte into 0x0c xor delta. Only 0x01 (delta 13) is still valid
        // PKCS#7, since the bytes before it are 0x0c; every other value must be rejected.
        val cipher = AESCBC(key, iv)
        val sealed = cipher.encrypt(plaintext)
        for (delta in 1..255) {
            val tampered = sealed.copyOf().also { it[it.size - 17] = (it[it.size - 17].toInt() xor delta).toByte() }
            val opened = cipher.decryptOrNull(tampered)
            if (delta == 13) {
                assertEquals(31, opened?.size, "delta $delta")
            } else {
                assertNull(opened, "delta $delta")
                assertFailsWith<IllegalArgumentException>("delta $delta") { cipher.decrypt(tampered) }
            }
        }
    }
}
