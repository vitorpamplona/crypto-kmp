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
package com.vitorpamplona.crypto.ec

import com.vitorpamplona.crypto.hexToByteArray
import com.vitorpamplona.crypto.toHexKey
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * P-256 ECDH on every platform: RFC 5903's example, NIST CAVP's CDH vectors (Wycheproof's run in
 * WycheproofTest), agreement between random key pairs, every rejected input, and the group law.
 */
class P256Test {
    private val g =
        (
            "04" +
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        ).hexToByteArray()
    private val order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551".hexToByteArray()

    @Test
    fun rfc5903Section8_1() {
        val i = "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433".hexToByteArray()
        val r = "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53".hexToByteArray()
        val gi = "04dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c37725811805271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3"
        val gr = "04d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf6356fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab"
        val girx = "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de"
        assertEquals(gi, P256.publicFromPrivate(i).toHexKey())
        assertEquals(gr, P256.publicFromPrivate(r).toHexKey())
        assertEquals(girx, P256.dh(i, gr.hexToByteArray()).toHexKey())
        assertEquals(girx, P256.dh(r, gi.hexToByteArray()).toHexKey())
    }

    @Test
    fun nistCavpCdhPrimitive() {
        for (vector in CAVP_P256_CDH_VECTORS) {
            val (count, qCavsX, qCavsY, dIut, qIutX) = vector.split('|')
            val (qIutY, zIut) = vector.split('|').drop(5)
            val label = "COUNT $count"
            assertEquals(zIut, P256.dh(dIut.hexToByteArray(), "04$qCavsX$qCavsY".hexToByteArray()).toHexKey(), label)
            assertEquals("04$qIutX$qIutY", P256.publicFromPrivate(dIut.hexToByteArray()).toHexKey(), label)
        }
        assertEquals(25, CAVP_P256_CDH_VECTORS.size)
    }

    @Test
    fun keyPairsAgree() {
        repeat(4) {
            val alice = P256.generateKeyPair()
            val bob = P256.generateKeyPair()
            assertEquals(32, alice.privateKey.size)
            assertEquals(65, alice.publicKey.size)
            assertEquals(0x04, alice.publicKey[0].toInt())
            assertContentEquals(alice.publicKey, P256.publicFromPrivate(alice.privateKey))
            val shared = P256.dh(alice.privateKey, bob.publicKey)
            assertEquals(32, shared.size)
            assertContentEquals(shared, P256.dh(bob.privateKey, alice.publicKey))
            assertNotEquals(alice, bob)
        }
    }

    @Test
    fun theEdgesOfTheScalarRange() {
        val one = ByteArray(32).also { it[31] = 1 }
        assertContentEquals(g, P256.publicFromPrivate(one))
        // (n - 1)·G = -G: G's x, and p - Gy.
        val nMinus1 = order.copyOf().also { it[31] = (it[31] - 1).toByte() }
        assertEquals(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
                "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
            P256.publicFromPrivate(nMinus1).toHexKey(),
        )
        assertEquals("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", P256.dh(one, g).toHexKey())
    }

    @Test
    fun rejectsInvalidPrivateKeys() {
        val nPlus1 = order.copyOf().also { it[31] = (it[31] + 1).toByte() }
        val bad = listOf(ByteArray(32), order, nPlus1, ByteArray(32) { -1 }, ByteArray(31) { 1 }, ByteArray(33) { 1 }, ByteArray(0))
        for (key in bad) {
            assertFailsWith<IllegalArgumentException>(key.toHexKey()) { P256.publicFromPrivate(key) }
            assertFailsWith<IllegalArgumentException>(key.toHexKey()) { P256.dh(key, g) }
        }
    }

    @Test
    fun rejectsInvalidPublicKeys() {
        val key = ByteArray(32).also { it[31] = 7 }
        val p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
        val x = g.copyOfRange(1, 33).toHexKey()
        val y = g.copyOfRange(33, 65).toHexKey()
        // (0, y0) is on the curve: x = 0 is accepted as 32 zero bytes, and only as those.
        val y0 = "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4"
        P256.dh(key, ("04" + "00".repeat(32) + y0).hexToByteArray())
        val bad =
            listOf(
                "",
                "00",
                // Compressed G: not supported.
                "03$x",
                "02$x",
                // Uncompressed G with the wrong prefix, truncated, or with a byte too many.
                "02$x$y",
                "06$x$y",
                "04$x${y.dropLast(2)}",
                "04$x${y}00",
                // A coordinate at or above p: x = p, y = p, and (0, y0) with x written as 0 + p,
                // which would decode to that curve point if it were reduced instead of rejected.
                "04$p$y",
                "04$x$p",
                "04$p$y0",
                // (0, 0) and off-curve points.
                "04" + "00".repeat(64),
                "04$x" + y.dropLast(2) + "f4",
                "04$y$x",
            )
        for (encoded in bad) {
            assertFailsWith<IllegalArgumentException>(encoded) { P256.dh(key, encoded.hexToByteArray()) }
        }
    }

    @Test
    fun theGroupLaw() {
        val random = Random(256)
        val points = List(3) { P256Point.scalarMult(randomScalar(random), P256Point.generator()) }
        for (p in points) {
            // Doubling is adding a point to itself, and the identity changes nothing.
            val doubled = P256Point()
            val added = P256Point()
            P256Point.double(doubled, p)
            P256Point.add(added, p, p)
            assertTrue(samePoint(doubled, added))
            P256Point.add(added, p, P256Point())
            assertTrue(samePoint(added, p))
        }
        // Addition commutes and associates.
        val ab = P256Point().also { P256Point.add(it, points[0], points[1]) }
        val ba = P256Point().also { P256Point.add(it, points[1], points[0]) }
        assertTrue(samePoint(ab, ba))
        val abC = P256Point().also { P256Point.add(it, ab, points[2]) }
        val bc = P256Point().also { P256Point.add(it, points[1], points[2]) }
        val aBc = P256Point().also { P256Point.add(it, points[0], bc) }
        assertTrue(samePoint(abC, aBc))
        // n·G is the identity: G has order n.
        assertEquals(1, P256Field.isZero(P256Point.scalarMult(order, P256Point.generator()).z))
        assertFalse(samePoint(points[0], points[1]))
    }

    @Test
    fun theGeneratorCombAgreesWithTheWindow() {
        val random = Random(384)
        val one = ByteArray(32).also { it[31] = 1 }
        // Scalars with only the top tooth set, only the bottom one, and every bit set.
        val edges = listOf(one, ByteArray(32).also { it[0] = 0x80.toByte() }, ByteArray(32) { -1 })
        for (k in List(8) { randomScalar(random) } + edges) {
            assertTrue(samePoint(P256Point.generatorMult(k), P256Point.scalarMult(k, P256Point.generator())), k.toHexKey())
        }
        assertEquals(1, P256Field.isZero(P256Point.generatorMult(order).z))
    }

    @Test
    fun keyPairsHideTheirKeys() {
        val pair = P256.generateKeyPair()
        assertEquals("P256KeyPair(privateKey=<32 bytes>, publicKey=<65 bytes>)", pair.toString())
        assertEquals(pair, P256KeyPair(pair.privateKey.copyOf(), pair.publicKey.copyOf()))
        assertEquals(pair.hashCode(), P256KeyPair(pair.privateKey.copyOf(), pair.publicKey.copyOf()).hashCode())
    }

    private fun randomScalar(random: Random): ByteArray = random.nextBytes(32).also { it[0] = (it[0].toInt() and 0x7f).toByte() }

    /** Whether two projective points are the same: X1·Z2 = X2·Z1 and Y1·Z2 = Y2·Z1. */
    private fun samePoint(
        a: P256Point,
        b: P256Point,
    ): Boolean {
        val l = P256Field.zero()
        val r = P256Field.zero()
        P256Field.mul(l, a.x, b.z)
        P256Field.mul(r, b.x, a.z)
        if (!l.contentEquals(r)) return false
        P256Field.mul(l, a.y, b.z)
        P256Field.mul(r, b.y, a.z)
        return l.contentEquals(r)
    }
}
