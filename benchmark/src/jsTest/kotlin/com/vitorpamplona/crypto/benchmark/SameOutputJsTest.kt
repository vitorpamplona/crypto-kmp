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
package com.vitorpamplona.crypto.benchmark

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The JavaScript libraries' benchmarks compute the same bytes as this library's. */
class SameOutputJsTest {
    private fun kmp() = CryptoKmp().apply { setup() }

    private fun noble() = Noble().apply { setup() }

    private fun nacl() = TweetNacl().apply { setup() }

    private fun node() = NodeCrypto().apply { setup() }

    @Test
    fun hashesAndMacs() {
        same(kmp().sha256(), noble().sha256(), node().sha256())
        same(kmp().sha512(), noble().sha512(), node().sha512(), nacl().sha512())
        same(kmp().hmacSha256(), noble().hmacSha256(), node().hmacSha256())
        same(kmp().hkdfSha256(), noble().hkdfSha256(), node().hkdfSha256())
    }

    @Test
    fun aeads() {
        same(kmp().aesGcm1k(), noble().aesGcm1k(), node().aesGcm1k())
        same(kmp().aesGcm16k(), noble().aesGcm16k(), node().aesGcm16k())
        same(kmp().chaChaPoly1k(), noble().chaChaPoly1k(), node().chaChaPoly1k())
        same(kmp().chaChaPoly16k(), noble().chaChaPoly16k(), node().chaChaPoly16k())
        same(kmp().xChaChaPoly1k(), noble().xChaChaPoly1k())
    }

    @Test
    fun curves() {
        same(kmp().x25519PublicKey(), noble().x25519PublicKey(), nacl().x25519PublicKey())
        same(kmp().x25519SharedSecret(), noble().x25519SharedSecret(), nacl().x25519SharedSecret(), node().x25519SharedSecret())
        same(kmp().p256PublicKey(), noble().p256PublicKey(), node().p256PublicKey())
        same(kmp().p256SharedSecret(), noble().p256SharedSecret(), node().p256SharedSecret())
        same(kmp().ed25519Sign(), noble().ed25519Sign(), nacl().ed25519Sign(), node().ed25519Sign())
        assertTrue(kmp().ed25519Verify())
        assertTrue(noble().ed25519Verify())
        assertTrue(nacl().ed25519Verify())
        assertTrue(node().ed25519Verify())
    }

    /** Compares as hex: the libraries return Int8Array, Uint8Array, Buffer or [ciphertext, tag]. */
    private fun same(
        expected: ByteArray,
        vararg others: Any,
    ) {
        for (other in others) assertEquals(hex(expected), hex(other))
    }

    private fun hex(value: Any): String {
        val parts: dynamic = if (js("Array").isArray(value) as Boolean) value else arrayOf(value)
        // hkdfSync gives a bare ArrayBuffer; everything else is a view of one.
        val joined: dynamic =
            js("Buffer").concat(
                parts.map { p: dynamic -> if (p.buffer == undefined) js("Buffer").from(p) else js("Buffer").from(p.buffer, p.byteOffset, p.byteLength) },
            )
        return joined.toString("hex") as String
    }
}
