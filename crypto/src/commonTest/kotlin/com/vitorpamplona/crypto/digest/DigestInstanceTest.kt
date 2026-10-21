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
 * [DigestInstance] on every platform (JCA, CommonCrypto, pure Kotlin): the same four
 * algorithms under the same names, with FIPS 180-4 and RIPEMD-160 known answers.
 */
class DigestInstanceTest {
    private fun hash(
        algorithm: String,
        input: String,
    ) = DigestInstance(algorithm).digest(input.encodeToByteArray()).toHexKey()

    private val abc =
        mapOf(
            "SHA-1" to "a9993e364706816aba3e25717850c26c9cd0d89d",
            "SHA-256" to "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-512" to
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "RIPEMD-160" to "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        )

    @Test
    fun knownAnswers() {
        for ((algorithm, digest) in abc) assertEquals(digest, hash(algorithm, "abc"), algorithm)
        assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", hash("SHA-1", ""))
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash("SHA-256", ""))
        assertEquals(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            hash("SHA-512", ""),
        )
        assertEquals("9c1185a5c5e9fc54612808977ee8f548b2258d31", hash("RIPEMD-160", ""))
    }

    @Test
    fun namesMatchIgnoringCaseAndDash() {
        for (name in listOf("SHA-256", "sha-256", "SHA256", "sha256")) assertEquals(abc["SHA-256"], hash(name, "abc"), name)
        for (name in listOf("SHA-1", "sha-1", "SHA1", "sha1")) assertEquals(abc["SHA-1"], hash(name, "abc"), name)
        for (name in listOf("SHA-512", "sha-512", "SHA512", "sha512")) assertEquals(abc["SHA-512"], hash(name, "abc"), name)
        for (name in listOf("RIPEMD-160", "ripemd-160", "RIPEMD160", "ripemd160")) assertEquals(abc["RIPEMD-160"], hash(name, "abc"), name)
    }

    @Test
    fun unknownAlgorithmsThrowIllegalArgument() {
        for (name in listOf("", "MD5", "SHA-384", "SHA-224", "SHA3-256", "keccak256", "SHA", "RIPEMD", "sha-2 56")) {
            assertFailsWith<IllegalArgumentException>(name) { DigestInstance(name) }
        }
    }

    @Test
    fun streamsInPieces() {
        for ((algorithm, digest) in abc) {
            val instance = DigestInstance(algorithm)
            instance.update('a'.code.toByte())
            instance.update(ByteArray(0))
            instance.update("bc".encodeToByteArray())
            assertEquals(digest, instance.digest().toHexKey(), algorithm)
        }
    }

    @Test
    fun resetsAfterEachDigest() {
        for ((algorithm, digest) in abc) {
            val instance = DigestInstance(algorithm)
            repeat(3) {
                instance.update("abc".encodeToByteArray())
                assertEquals(digest, instance.digest().toHexKey(), algorithm)
            }
            assertEquals(digest, instance.digest("abc".encodeToByteArray()).toHexKey(), algorithm)
            assertEquals(digest, instance.digest("abc".encodeToByteArray()).toHexKey(), algorithm)
        }
    }
}
