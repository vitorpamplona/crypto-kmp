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
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * [Ed25519Group]'s fast paths (the fixed-base table, the constant-time
 * fixed-base multiplication, the variable-time double-scalar multiplication
 * and the dedicated doubling) against a slow, independent reference: affine
 * Edwards addition with one inversion per step and a plain double-and-add.
 */
class Ed25519GroupTest {
    private val f = Curve25519Field
    private val random = Random(2008)

    /** An affine point (x, y). */
    private class Affine(
        val x: LongArray,
        val y: LongArray,
    )

    private val identity = Affine(f.GF0, f.GF1)
    private val base = Affine(f.BX, f.BY)

    /**
     * The twisted Edwards addition law for a = -1, complete on this curve:
     * x3 = (x1 y2 + y1 x2) / (1 + d x1 x2 y1 y2), y3 = (y1 y2 + x1 x2) / (1 - d x1 x2 y1 y2).
     */
    private fun affineAdd(
        p: Affine,
        q: Affine,
    ): Affine {
        val x1x2 = f.mul(p.x, q.x)
        val y1y2 = f.mul(p.y, q.y)
        val dxy = f.mul(f.D, f.mul(x1x2, y1y2))
        val den1 = f.add(f.GF1, dxy)
        val den2 = f.sub(f.GF1, dxy)
        val inv = f.inv25519(f.mul(den1, den2))
        val x3 = f.mul(f.mul(f.add(f.mul(p.x, q.y), f.mul(p.y, q.x)), den2), inv)
        val y3 = f.mul(f.mul(f.add(y1y2, x1x2), den1), inv)
        return Affine(x3, y3)
    }

    /** [k]P by double-and-add from the top set bit; k is little-endian. */
    private fun referenceMul(
        k: ByteArray,
        p: Affine,
    ): Affine {
        var r = identity
        var started = false
        for (i in k.size * 8 - 1 downTo 0) {
            if (started) r = affineAdd(r, r)
            if ((k[i shr 3].toInt() shr (i and 7)) and 1 == 1) {
                r = affineAdd(r, p)
                started = true
            }
        }
        return r
    }

    private fun encode(p: Affine): ByteArray {
        val r = f.pack25519(p.y)
        r[31] = (r[31].toInt() xor (f.par25519(p.x) shl 7)).toByte()
        return r
    }

    private fun affineOf(p: GeP3): Affine {
        val zi = f.inv25519(p.z)
        return Affine(f.mul(p.x, zi), f.mul(p.y, zi))
    }

    /** A random point of the whole curve, torsion component included: decode random y until one is on it. */
    private fun randomPoint(): GeP3 {
        while (true) {
            val p = Ed25519Group.decodeVartime(random.nextBytes(32))
            if (p != null) return p
        }
    }

    /** L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
    private val groupOrder = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010".hexToByteArray()

    /** [a] with its lowest byte moved by [delta], which must not carry or borrow. */
    private fun nudged(
        a: ByteArray,
        delta: Int,
    ): ByteArray = a.copyOf().also { it[0] = (it[0] + delta).toByte() }

    /** Scalars that stress the recodings: zero, one, around L, the largest with the top bit clear, and clamped ones. */
    private val edgeScalars =
        listOf(
            ByteArray(32),
            nudged(ByteArray(32), 1),
            nudged(groupOrder, -1),
            groupOrder,
            nudged(groupOrder, 1),
            ByteArray(32) { 0xFF.toByte() }.also { it[31] = 0x7F },
            ByteArray(32) { 0x88.toByte() }.also { it[31] = 0x08 }, // every digit 8 before the carries
            ByteArray(32).also { it[31] = 0x40 }, // 2^254, the smallest clamped X25519 scalar
            ByteArray(32) { 0xFF.toByte() }.also {
                it[0] = 0xF8.toByte()
                it[31] = 0x7F
            }, // the largest clamped X25519 scalar
        )

    private fun randomScalar(topByteMask: Int): ByteArray {
        val k = random.nextBytes(32)
        k[31] = (k[31].toInt() and topByteMask).toByte()
        return k
    }

    /** A random scalar clamped as X25519 clamps it: used whole, between 2^254 and 2^255. */
    private fun randomClampedScalar(): ByteArray {
        val k = random.nextBytes(32)
        k[0] = (k[0].toInt() and 0xF8).toByte()
        k[31] = ((k[31].toInt() and 0x7F) or 0x40).toByte()
        return k
    }

    @Test
    fun edgeScalarsAreWhatTheyClaim() {
        assertEquals("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", edgeScalars[2].toHexKey())
        assertEquals("eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", edgeScalars[4].toHexKey())
    }

    @Test
    fun baseTableHoldsTheMultiplesOfB() {
        val table = Ed25519Group.baseTable
        assertEquals(256, table.size)
        var row = base // 256^i * B
        for (i in 0 until 32) {
            var entry = row
            for (j in 0 until 8) {
                val expected = table[8 * i + j]
                val x = entry.x
                val y = entry.y
                val where = "i=$i j=$j"
                assertContentEquals(f.pack25519(f.add(y, x)), f.pack25519(expected.yPlusX), where)
                assertContentEquals(f.pack25519(f.sub(y, x)), f.pack25519(expected.yMinusX), where)
                assertContentEquals(f.pack25519(f.mul(f.mul(x, y), f.D2)), f.pack25519(expected.xy2d), where)
                entry = affineAdd(entry, row)
            }
            repeat(8) { row = affineAdd(row, row) }
        }
    }

    @Test
    fun fixedBaseMatchesTheReference() {
        val scalars =
            edgeScalars +
                List(24) { randomScalar(0x7F) } +
                List(8) { randomScalar(0x1F) } +
                List(8) { randomClampedScalar() }
        val point = GeP3()
        for (k in scalars) {
            Ed25519Group.scalarMultBase(point, k)
            assertEquals(encode(referenceMul(k, base)).toHexKey(), Ed25519Group.encode(point).toHexKey(), k.toHexKey())
        }
    }

    @Test
    fun doubleScalarMatchesTheReference() {
        // Scalars below 2^253, as verify passes (both are reduced mod L), and
        // points with a torsion component, which verify has to handle too.
        val scalars = edgeScalars.take(5) + List(12) { randomScalar(0x1F) }
        val r = GeP2()
        for ((n, a) in scalars.withIndex()) {
            val b = scalars[(n * 7 + 3) % scalars.size]
            val aPoint = randomPoint()
            Ed25519Group.doubleScalarMultVartime(r, a, aPoint, b)
            val expected = affineAdd(referenceMul(a, affineOf(aPoint)), referenceMul(b, base))
            assertEquals(encode(expected).toHexKey(), Ed25519Group.encode(r).toHexKey(), "a=${a.toHexKey()} b=${b.toHexKey()}")
        }
    }

    @Test
    fun doublingMatchesAddingAPointToItself() {
        val t = GeP1P1()
        val doubled = GeP3()
        val cached = GeCached()
        val added = GeP3()
        repeat(32) {
            val p = randomPoint()
            Ed25519Group.dbl(t, p)
            Ed25519Group.toP3(doubled, t)
            Ed25519Group.toCached(cached, p)
            Ed25519Group.add(t, p, cached)
            Ed25519Group.toP3(added, t)
            assertContentEquals(Ed25519Group.encode(added), Ed25519Group.encode(doubled))
            assertContentEquals(encode(affineAdd(affineOf(p), affineOf(p))), Ed25519Group.encode(doubled))
        }
    }

    @Test
    fun subtractionUndoesAddition() {
        val t = GeP1P1()
        val sum = GeP3()
        val back = GeP3()
        val cached = GeCached()
        repeat(16) {
            val p = randomPoint()
            val q = randomPoint()
            Ed25519Group.toCached(cached, q)
            Ed25519Group.add(t, p, cached)
            Ed25519Group.toP3(sum, t)
            Ed25519Group.sub(t, sum, cached)
            Ed25519Group.toP3(back, t)
            assertContentEquals(Ed25519Group.encode(p), Ed25519Group.encode(back))
        }
    }

    @Test
    fun decodeThenEncodeIsTheIdentityOnValidPoints() {
        repeat(32) {
            val bytes = random.nextBytes(32)
            val p = Ed25519Group.decodeVartime(bytes) ?: return@repeat
            assertContentEquals(bytes, Ed25519Group.encode(p))
        }
        val b = assertNotNull(Ed25519Group.decodeVartime(encode(base)))
        assertContentEquals(encode(base), Ed25519Group.encode(b))
    }
}
