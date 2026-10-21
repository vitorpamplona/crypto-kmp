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
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals

/** RFC 7748 §5.2 and §6.1 vectors, checked against JCA, plus the input edge cases of §5 and §6.1. */
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
    fun scalarMultiplicationSecondVector() {
        // Its u-coordinate has the top bit set, which X25519 must ignore.
        val out =
            X25519.dh(
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d".hexToByteArray(),
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493".hexToByteArray(),
            )
        assertEquals("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", out.toHexKey())
    }

    /** RFC 7748 §5.2: k = u = 9, then k, u = X25519(k, u), k for [iterations] rounds. */
    private fun iterate(iterations: Int): String {
        var k = ByteArray(32).also { it[0] = 9 }
        var u = k.copyOf()
        repeat(iterations) {
            val next = X25519.dh(k, u)
            u = k
            k = next
        }
        return k.toHexKey()
    }

    @Test
    fun oneIteration() {
        assertEquals("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", iterate(1))
    }

    @Test
    fun thousandIterations() {
        // The 1,000,000-iteration vector is left out: it takes minutes.
        assertEquals("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", iterate(1000))
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

    @Test
    fun highBitOfUIsIgnored() {
        val bob = bobPublic.hexToByteArray()
        bob[31] = (bob[31].toInt() or 0x80).toByte()
        assertEquals(shared, X25519.dh(alicePrivate.hexToByteArray(), bob).toHexKey())
    }

    @Test
    fun uAtOrAbovePIsReducedModP() {
        // u = p + 9 = 2^255 - 10 is the base point 9 written unreduced.
        val pPlus9 = "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f".hexToByteArray()
        assertEquals(alicePublic, X25519.dh(alicePrivate.hexToByteArray(), pPlus9).toHexKey())
        // And with the ignored top bit set on top of that.
        pPlus9[31] = 0xff.toByte()
        assertEquals(alicePublic, X25519.dh(alicePrivate.hexToByteArray(), pPlus9).toHexKey())
    }

    @Test
    fun lowOrderPointsAreRejected() {
        // libsodium's blacklist: every u of order 1, 2, 4 or 8, and the unreduced
        // encodings of 0 and 1. A clamped scalar is a multiple of 8, so each
        // gives an all-zero shared secret, which dh() refuses.
        val lowOrder =
            listOf(
                "0000000000000000000000000000000000000000000000000000000000000000", // 0
                "0100000000000000000000000000000000000000000000000000000000000000", // 1
                "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", // order 8
                "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", // order 8
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p - 1
                "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p, which is 0
                "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p + 1, which is 1
            )
        for (u in lowOrder) {
            for (topBit in listOf(0, 0x80)) {
                val point = u.hexToByteArray()
                point[31] = (point[31].toInt() or topBit).toByte()
                assertFailsWith<IllegalArgumentException>(point.toHexKey()) {
                    X25519.dh(alicePrivate.hexToByteArray(), point)
                }
            }
        }
    }

    @Test
    fun keyPairsCompareByContentAndPrintNoKeyBytes() {
        val a = X25519KeyPair(alicePrivate.hexToByteArray(), alicePublic.hexToByteArray())
        val b = X25519KeyPair(alicePrivate.hexToByteArray(), alicePublic.hexToByteArray())
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, X25519KeyPair(bobPrivate.hexToByteArray(), bobPublic.hexToByteArray()))

        val text = a.toString()
        for (key in listOf(a.privateKey, a.publicKey)) {
            assertFalse(key.toHexKey().take(8) in text.lowercase(), text)
            assertFalse(key.contentToString() in text, text)
        }
    }

    @Test
    fun wrongKeySizesAreRejected() {
        assertFailsWith<IllegalArgumentException> { X25519.dh(ByteArray(31), bobPublic.hexToByteArray()) }
        assertFailsWith<IllegalArgumentException> { X25519.dh(alicePrivate.hexToByteArray(), ByteArray(33)) }
        assertFailsWith<IllegalArgumentException> { X25519.publicFromPrivate(ByteArray(0)) }
    }
}
