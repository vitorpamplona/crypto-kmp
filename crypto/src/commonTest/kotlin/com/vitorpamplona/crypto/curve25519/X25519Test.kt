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
package com.vitorpamplona.crypto.curve25519

import com.vitorpamplona.crypto.hexToByteArray
import com.vitorpamplona.crypto.toHexKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/** RFC 7748 §5.2 and §6.1 vectors, checked against OpenSSL. */
class X25519Test {
    private val alicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    private val alicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    private val bobPrivate = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    private val bobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    private val shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    @Test
    fun scalarMultiplication() {
        val out =
            X25519.dh(
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4".hexToByteArray(),
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c".hexToByteArray(),
            )
        assertEquals("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", out.toHexKey())
    }

    @Test
    fun diffieHellman() {
        assertEquals(alicePublic, X25519.publicFromPrivate(alicePrivate.hexToByteArray()).toHexKey())
        assertEquals(bobPublic, X25519.publicFromPrivate(bobPrivate.hexToByteArray()).toHexKey())
        assertEquals(shared, X25519.dh(alicePrivate.hexToByteArray(), bobPublic.hexToByteArray()).toHexKey())
        assertEquals(shared, X25519.dh(bobPrivate.hexToByteArray(), alicePublic.hexToByteArray()).toHexKey())
    }

    @Test
    fun generatedPairsAgree() {
        val a = X25519.generateKeyPair()
        val b = X25519.generateKeyPair()
        assertContentEquals(X25519.publicFromPrivate(a.privateKey), a.publicKey)
        assertContentEquals(X25519.dh(a.privateKey, b.publicKey), X25519.dh(b.privateKey, a.publicKey))
    }
}
