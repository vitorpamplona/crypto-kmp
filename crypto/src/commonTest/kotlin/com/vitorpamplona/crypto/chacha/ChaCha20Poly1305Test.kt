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
 * Tests for standard ChaCha20-Poly1305 AEAD (RFC 8439) with 12-byte nonces.
 * Includes the official RFC 8439 §2.8.2 and A.5 test vectors, length-boundary vectors
 * generated with JCA, round-trip tests and every way a decryption must fail.
 */
class ChaCha20Poly1305Test {
    private fun hex(s: String): ByteArray = s.replace(" ", "").hexToByteArray()

    private val key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private val nonce = hex("000102030405060708090a0b")
    private val ad = hex("feedfacedeadbeef")

    // ===== RFC 8439 §2.8.2: AEAD_CHACHA20_POLY1305 Test Vector =====
    @Test
    fun testEncrypt_RFC8439() {
        val key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val nonce = hex("070000004041424344454647")
        val ad = hex("50515253c0c1c2c3c4c5c6c7")
        val plaintext =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
                .encodeToByteArray()

        val result = ChaCha20Poly1305.encrypt(plaintext, ad, nonce, key)

        val expectedCiphertext =
            hex(
                "d31a8d34648e60db7b86afbc53ef7ec2" +
                    "a4aded51296e08fea9e2b5a736ee62d6" +
                    "3dbea45e8ca9671282fafb69da92728b" +
                    "1a71de0a9e060b2905d6a5b67ecd3b36" +
                    "92ddbd7f2d778b8c9803aee328091b58" +
                    "fab324e4fad675945585808b4831d7bc" +
                    "3ff4def08e4b7a9de576d26586cec64b" +
                    "6116",
            )
        val expectedTag = hex("1ae10b594f09e26a7e902ecbd0600691")

        val ciphertext = result.copyOfRange(0, result.size - 16)
        val tag = result.copyOfRange(result.size - 16, result.size)

        assertContentEquals(expectedCiphertext, ciphertext)
        assertContentEquals(expectedTag, tag)
    }

    @Test
    fun testDecrypt_RFC8439() {
        val key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val nonce = hex("070000004041424344454647")
        val ad = hex("50515253c0c1c2c3c4c5c6c7")
        val ciphertextWithTag =
            hex(
                "d31a8d34648e60db7b86afbc53ef7ec2" +
                    "a4aded51296e08fea9e2b5a736ee62d6" +
                    "3dbea45e8ca9671282fafb69da92728b" +
                    "1a71de0a9e060b2905d6a5b67ecd3b36" +
                    "92ddbd7f2d778b8c9803aee328091b58" +
                    "fab324e4fad675945585808b4831d7bc" +
                    "3ff4def08e4b7a9de576d26586cec64b" +
                    "6116" +
                    "1ae10b594f09e26a7e902ecbd0600691",
            )

        val plaintext = ChaCha20Poly1305.decrypt(ciphertextWithTag, ad, nonce, key)

        val expected =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        assertEquals(expected, plaintext.decodeToString())
    }

    // ===== RFC 8439 Appendix A.5: ChaCha20-Poly1305 AEAD Decryption =====
    @Test
    fun testDecrypt_RFC8439_A5() {
        val key = hex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
        val nonce = hex("000000000102030405060708")
        val ad = hex("f33388860000000000004e91")
        val ciphertext =
            hex(
                "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2" +
                    "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf" +
                    "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855" +
                    "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4" +
                    "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e" +
                    "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a" +
                    "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10" +
                    "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29" +
                    "a6ad5cb4022b02709b",
            )
        val tag = hex("eead9d67890cbb22392336fea1851f38")

        val plaintext = ChaCha20Poly1305.decrypt(ciphertext + tag, ad, nonce, key)

        val expected =
            "Internet-Drafts are draft documents valid for a maximum of six months and may be updated, replaced, " +
                "or obsoleted by other documents at any time. It is inappropriate to use Internet-Drafts as reference " +
                "material or to cite them other than as /“work in progress./”"
        assertEquals(265, plaintext.size)
        assertEquals(expected, plaintext.decodeToString())
        assertContentEquals(ciphertext + tag, ChaCha20Poly1305.encrypt(plaintext, ad, nonce, key))
    }

    // ===== Length boundaries: plaintext around the 16-byte Poly1305 and 64-byte ChaCha20 blocks =====

    private class Kat(
        val plaintextSize: Int,
        val adSize: Int,
        val ciphertextWithTag: String,
    )

    // key = 80..9f, nonce = RFC 8439 §2.8.2's, plaintext[i] = i, ad[i] = 0xa0 + i.
    // Expected bytes from JCA's ChaCha20-Poly1305 (JDK 17).
    private val kats =
        listOf(
            Kat(0, 0, "a0784d7a4716f3feb4f64e7f4b39bf04"),
            Kat(0, 16, "d3ac60ba14d5de4ca14248c17f7923bd"),
            Kat(0, 17, "0b23caa529a4f0de6151c4f5e28463a5"),
            Kat(1, 0, "9fbb758e737cb56e18df4748421b085bb0"),
            Kat(1, 16, "9f29e6549b8c5839a44ddbe473304e01fc"),
            Kat(1, 17, "9f9de37fdc25ec1dace417300a9b151e84"),
            Kat(15, 0, "9f7aeb5e05f846bd1deb85f03a8c042241a7ff265a8a3cdd12672385e17a53"),
            Kat(15, 16, "9f7aeb5e05f846bd1deb85f03a8c0495b16d2737fd54c84ba603559a27219f"),
            Kat(15, 17, "9f7aeb5e05f846bd1deb85f03a8c0404af9868d09039d0e2e24eeb04ef3d27"),
            Kat(16, 0, "9f7aeb5e05f846bd1deb85f03a8c04a18351907c91debbdc2fcb4c3b4796d53d"),
            Kat(16, 16, "9f7aeb5e05f846bd1deb85f03a8c04a1f6c156a4a18186689e5ee96c5cdc7b89"),
            Kat(16, 17, "9f7aeb5e05f846bd1deb85f03a8c04a165bf81e53a156b70359b3403c7a39811"),
            Kat(17, 0, "9f7aeb5e05f846bd1deb85f03a8c04a1d1b8e7ec417f0c23fa1fceda25ad92a437"),
            Kat(17, 16, "9f7aeb5e05f846bd1deb85f03a8c04a1d1cb5d6edc79eef87abf215b0e5d77c781"),
            Kat(17, 17, "9f7aeb5e05f846bd1deb85f03a8c04a1d1caa24ff62f231b2c588fe945fa40f63a"),
            Kat(
                63,
                0,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852523" +
                    "9ad1703171ac732de465caecd07f39",
            ),
            Kat(
                63,
                16,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "666b0a44b239fbea028622297a2b8e",
            ),
            Kat(
                63,
                17,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d8525dc" +
                    "cd1f0e75a3abd15d3ff052b4604d63",
            ),
            Kat(
                64,
                0,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "d30306a99c3f066fd64b5d0622fb0fe5",
            ),
            Kat(
                64,
                16,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "16d09f42af8093f6936a7d5e5ea4bb39",
            ),
            Kat(
                64,
                17,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "8c375446e07105cd06a7e78ee98add0e",
            ),
            Kat(
                65,
                0,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "bccecf73080e0b7a93a04054ea7b181a9e",
            ),
            Kat(
                65,
                16,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "bcb3c5813910f95250c069ed2909236f47",
            ),
            Kat(
                65,
                17,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "bc1b33ed24d826ae797815423a9b817fef",
            ),
            Kat(
                128,
                0,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "bcf0861c065ca8eba4239488022b2737de8a1397c8f657b67fb9f6f06719e790" +
                    "3ce7d9f6840e6b95f873dc2e88c6884d65497e70ba401aa0de0f1980a192811b" +
                    "e578a346d58b65faa349f72af62f048a",
            ),
            Kat(
                128,
                16,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "bcf0861c065ca8eba4239488022b2737de8a1397c8f657b67fb9f6f06719e790" +
                    "3ce7d9f6840e6b95f873dc2e88c6884d65497e70ba401aa0de0f1980a192811b" +
                    "e98370db45812f07afe50af3c715afd8",
            ),
            Kat(
                128,
                17,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "bcf0861c065ca8eba4239488022b2737de8a1397c8f657b67fb9f6f06719e790" +
                    "3ce7d9f6840e6b95f873dc2e88c6884d65497e70ba401aa0de0f1980a192811b" +
                    "35f2fd5c82523a3c3276ac52cb9de40d",
            ),
            Kat(
                129,
                0,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "bcf0861c065ca8eba4239488022b2737de8a1397c8f657b67fb9f6f06719e790" +
                    "3ce7d9f6840e6b95f873dc2e88c6884d65497e70ba401aa0de0f1980a192811b" +
                    "f5f6d11199077a38dad0354dc6fc19590a",
            ),
            Kat(
                129,
                16,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "bcf0861c065ca8eba4239488022b2737de8a1397c8f657b67fb9f6f06719e790" +
                    "3ce7d9f6840e6b95f873dc2e88c6884d65497e70ba401aa0de0f1980a192811b" +
                    "f56dbe36c11a11f3992dcfbdbabe0a20b6",
            ),
            Kat(
                129,
                17,
                "9f7aeb5e05f846bd1deb85f03a8c04a1d1d19a2c1d1478c9c593ca9c499f1dba" +
                    "6ebfe91b88ab780c90f39824d6f67cc74535805d8a5c5b78589dbff42d852566" +
                    "bcf0861c065ca8eba4239488022b2737de8a1397c8f657b67fb9f6f06719e790" +
                    "3ce7d9f6840e6b95f873dc2e88c6884d65497e70ba401aa0de0f1980a192811b" +
                    "f55f51d9d8b4bca502365086b5f62041e3",
            ),
        )

    @Test
    fun testLengthBoundaryVectors() {
        val key = ByteArray(32) { (0x80 + it).toByte() }
        val nonce = hex("070000004041424344454647")
        for (kat in kats) {
            val plaintext = ByteArray(kat.plaintextSize) { it.toByte() }
            val ad = ByteArray(kat.adSize) { (0xa0 + it).toByte() }
            val expected = hex(kat.ciphertextWithTag)
            val label = "plaintext ${kat.plaintextSize}, ad ${kat.adSize}"
            assertContentEquals(expected, ChaCha20Poly1305.encrypt(plaintext, ad, nonce, key), label)
            assertContentEquals(plaintext, ChaCha20Poly1305.decrypt(expected, ad, nonce, key), label)
        }
    }

    // ===== Round trips =====

    @Test
    fun testRoundTrip() {
        val plaintext = "Round-trip test with 12-byte nonce.".encodeToByteArray()

        val encrypted = ChaCha20Poly1305.encrypt(plaintext, ad, nonce, key)
        val decrypted = ChaCha20Poly1305.decrypt(encrypted, ad, nonce, key)

        assertContentEquals(plaintext, decrypted)
        assertContentEquals(plaintext, ChaCha20Poly1305.decryptOrNull(encrypted, ad, nonce, key))
    }

    @Test
    fun testRoundTrip_EmptyAD() {
        val plaintext = "Empty AAD test".encodeToByteArray()

        val encrypted = ChaCha20Poly1305.encrypt(plaintext, ByteArray(0), nonce, key)
        val decrypted = ChaCha20Poly1305.decrypt(encrypted, ByteArray(0), nonce, key)

        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testRoundTrip_EmptyPlaintext() {
        val plaintext = ByteArray(0)

        val encrypted = ChaCha20Poly1305.encrypt(plaintext, ByteArray(0), nonce, key)
        assertEquals(16, encrypted.size) // Just the 16-byte tag
        val decrypted = ChaCha20Poly1305.decrypt(encrypted, ByteArray(0), nonce, key)
        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testLargeMessage() {
        // Test with a message larger than a single ChaCha20 block (64 bytes)
        val plaintext = ByteArray(1000) { (it % 256).toByte() }

        val encrypted = ChaCha20Poly1305.encrypt(plaintext, ByteArray(0), nonce, key)
        assertEquals(1000 + 16, encrypted.size)
        val decrypted = ChaCha20Poly1305.decrypt(encrypted, ByteArray(0), nonce, key)

        assertContentEquals(plaintext, decrypted)
    }

    // ===== Failures: decrypt throws IllegalArgumentException, decryptOrNull returns null =====

    private fun assertRejected(
        ciphertextWithTag: ByteArray,
        ad: ByteArray = this.ad,
        key: ByteArray = this.key,
    ) {
        assertFailsWith<IllegalArgumentException> { ChaCha20Poly1305.decrypt(ciphertextWithTag, ad, nonce, key) }
        assertNull(ChaCha20Poly1305.decryptOrNull(ciphertextWithTag, ad, nonce, key))
    }

    private fun sealed() = ChaCha20Poly1305.encrypt("Tamper detection test".encodeToByteArray(), ad, nonce, key)

    private fun ByteArray.flip(index: Int) = copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }

    @Test
    fun testTamperedCiphertext() {
        assertRejected(sealed().flip(0))
    }

    @Test
    fun testTamperedTag() {
        val encrypted = sealed()
        // Flip a bit in the first and the last byte of the tag
        assertRejected(encrypted.flip(encrypted.size - 16))
        assertRejected(encrypted.flip(encrypted.size - 1))
    }

    @Test
    fun testTamperedAD() {
        assertRejected(sealed(), ad = ad.flip(3))
        assertRejected(sealed(), ad = ad + byteArrayOf(0))
        assertRejected(sealed(), ad = ByteArray(0))
    }

    @Test
    fun testWrongKey() {
        val key2 = key.flip(0)
        assertRejected(sealed(), key = key2)
    }

    @Test
    fun testTruncatedInput() {
        val encrypted = sealed()
        for (size in 0 until 16) {
            assertRejected(encrypted.copyOf(size))
        }
        // A tag-sized input whose tag is wrong
        assertRejected(encrypted.copyOf(16))
        // Dropping the last byte of a longer input
        assertRejected(encrypted.copyOf(encrypted.size - 1))
    }

    @Test
    fun testInvalidNonceLength() {
        for (size in intArrayOf(0, 8, 11, 13, 24, 32)) {
            val badNonce = ByteArray(size)
            assertFailsWith<IllegalArgumentException> { ChaCha20Poly1305.encrypt(ByteArray(4), ad, badNonce, key) }
            assertFailsWith<IllegalArgumentException> { ChaCha20Poly1305.decrypt(sealed(), ad, badNonce, key) }
            assertFailsWith<IllegalArgumentException> { ChaCha20Poly1305.decryptOrNull(sealed(), ad, badNonce, key) }
        }
    }

    @Test
    fun testInvalidKeyLength() {
        for (size in intArrayOf(0, 12, 16, 31, 33, 64)) {
            val badKey = ByteArray(size)
            assertFailsWith<IllegalArgumentException> { ChaCha20Poly1305.encrypt(ByteArray(4), ad, nonce, badKey) }
            assertFailsWith<IllegalArgumentException> { ChaCha20Poly1305.decrypt(sealed(), ad, nonce, badKey) }
            assertFailsWith<IllegalArgumentException> { ChaCha20Poly1305.decryptOrNull(sealed(), ad, nonce, badKey) }
        }
    }

    @Test
    fun testSwappedKeyAndNonceFail() {
        // (key, nonce) passed as (nonce, key): the sizes give it away
        val e = assertFailsWith<IllegalArgumentException> { ChaCha20Poly1305.encrypt(ByteArray(4), ad, key, nonce) }
        assertEquals("ChaCha20-Poly1305 key must be 32 bytes, was 12", e.message)
    }
}
