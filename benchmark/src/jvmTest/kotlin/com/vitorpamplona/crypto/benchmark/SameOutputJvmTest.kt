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
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

/**
 * Every library's benchmark computes the same bytes as this library's, so the numbers compare
 * the same work. Each check takes fresh instances, whose nonce counters start together.
 */
class SameOutputJvmTest {
    private fun kmp() = CryptoKmp().apply { setup() }

    private fun jca() = Jca().apply { setup() }

    private fun bc() = BouncyCastle().apply { setup() }

    @Test
    fun hashesAndMacs() {
        assertContentEquals(kmp().sha256(), jca().sha256())
        assertContentEquals(kmp().sha256(), bc().sha256())
        assertContentEquals(kmp().sha512(), jca().sha512())
        assertContentEquals(kmp().sha512(), bc().sha512())
        assertContentEquals(kmp().hmacSha256(), jca().hmacSha256())
        assertContentEquals(kmp().hmacSha256(), bc().hmacSha256())
        assertContentEquals(kmp().hkdfSha256(), bc().hkdfSha256())
    }

    @Test
    fun aeads() {
        assertContentEquals(kmp().aesGcm1k(), jca().aesGcm1k())
        assertContentEquals(kmp().aesGcm1k(), bc().aesGcm1k())
        assertContentEquals(kmp().aesGcm16k(), jca().aesGcm16k())
        assertContentEquals(kmp().aesGcm16k(), bc().aesGcm16k())
        assertContentEquals(kmp().chaChaPoly1k(), jca().chaChaPoly1k())
        assertContentEquals(kmp().chaChaPoly1k(), bc().chaChaPoly1k())
        assertContentEquals(kmp().chaChaPoly16k(), jca().chaChaPoly16k())
        assertContentEquals(kmp().chaChaPoly16k(), bc().chaChaPoly16k())
    }

    @Test
    fun curves() {
        assertContentEquals(kmp().x25519PublicKey(), bc().x25519PublicKey())
        assertContentEquals(kmp().x25519SharedSecret(), jca().x25519SharedSecret())
        assertContentEquals(kmp().x25519SharedSecret(), bc().x25519SharedSecret())
        // Ed25519 signatures are deterministic.
        assertContentEquals(kmp().ed25519Sign(), jca().ed25519Sign())
        assertContentEquals(kmp().ed25519Sign(), bc().ed25519Sign())
        assertTrue(kmp().ed25519Verify())
        assertTrue(jca().ed25519Verify())
        assertTrue(bc().ed25519Verify())
    }
}
