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

import com.vitorpamplona.crypto.ec.P256Field.add
import com.vitorpamplona.crypto.ec.P256Field.mul
import com.vitorpamplona.crypto.ec.P256Field.sqr
import com.vitorpamplona.crypto.ec.P256Field.sub

/*
 * The group law follows Renes, Costello and Batina, "Complete addition formulas for prime
 * order elliptic curves" (EUROCRYPT 2016), Algorithms 4 and 6 for a = -3: complete, so the
 * same steps add any two points, equal ones and the identity included, with no branch that
 * could depend on a secret.
 */

/**
 * A P-256 point in projective coordinates (X:Y:Z), x = X/Z and y = Y/Z, each coordinate in
 * [P256Field]'s Montgomery domain. The identity is (0:1:0).
 */
internal class P256Point(
    val x: LongArray = P256Field.zero(),
    val y: LongArray = P256Field.ONE.copyOf(),
    val z: LongArray = P256Field.zero(),
) {
    fun copyFrom(other: P256Point) {
        other.x.copyInto(x)
        other.y.copyInto(y)
        other.z.copyInto(z)
    }

    fun wipe() {
        x.fill(0)
        y.fill(0)
        z.fill(0)
    }

    /** this = [other] when [flag] is 1, left as is when it is 0. */
    fun cmov(
        other: P256Point,
        flag: Int,
    ) {
        P256Field.cmov(x, other.x, flag)
        P256Field.cmov(y, other.y, flag)
        P256Field.cmov(z, other.z, flag)
    }

    companion object {
        /** b, the curve constant in y^2 = x^3 - 3x + b, in the Montgomery domain. */
        private val B = longArrayOf(0x29c4bddfL, 0xd89cdf62L, 0x78843090L, 0xacf005cdL, 0xf7212ed6L, 0xe5a220abL, 0x04874834L, 0xdc30061dL)

        private val GX = longArrayOf(0x18a9143cL, 0x79e730d4L, 0x5fedb601L, 0x75ba95fcL, 0x77622510L, 0x79fb732bL, 0xa53755c6L, 0x18905f76L)
        private val GY = longArrayOf(0xce95560aL, 0xddf25357L, 0xba19e45cL, 0x8b4ab8e4L, 0xdd21f325L, 0xd2e88688L, 0x25885d85L, 0x8571ff18L)

        /** The generator G (SEC 2 §2.4.2). */
        fun generator() = P256Point(GX.copyOf(), GY.copyOf(), P256Field.ONE.copyOf())

        /** out = p + q, by RCB Algorithm 4. [out] may be [p] or [q]. */
        fun add(
            out: P256Point,
            p: P256Point,
            q: P256Point,
        ) {
            val t0 = LongArray(8)
            val t1 = LongArray(8)
            val t2 = LongArray(8)
            val t3 = LongArray(8)
            val t4 = LongArray(8)
            val x3 = LongArray(8)
            val y3 = LongArray(8)
            val z3 = LongArray(8)
            mul(t0, p.x, q.x)
            mul(t1, p.y, q.y)
            mul(t2, p.z, q.z)
            add(t3, p.x, p.y)
            add(t4, q.x, q.y)
            mul(t3, t3, t4)
            add(t4, t0, t1)
            sub(t3, t3, t4)
            add(t4, p.y, p.z)
            add(x3, q.y, q.z)
            mul(t4, t4, x3)
            add(x3, t1, t2)
            sub(t4, t4, x3)
            add(x3, p.x, p.z)
            add(y3, q.x, q.z)
            mul(x3, x3, y3)
            add(y3, t0, t2)
            sub(y3, x3, y3)
            mul(z3, B, t2)
            sub(x3, y3, z3)
            add(z3, x3, x3)
            add(x3, x3, z3)
            sub(z3, t1, x3)
            add(x3, t1, x3)
            mul(y3, B, y3)
            add(t1, t2, t2)
            add(t2, t1, t2)
            sub(y3, y3, t2)
            sub(y3, y3, t0)
            add(t1, y3, y3)
            add(y3, t1, y3)
            add(t1, t0, t0)
            add(t0, t1, t0)
            sub(t0, t0, t2)
            mul(t1, t4, y3)
            mul(t2, t0, y3)
            mul(y3, x3, z3)
            add(y3, y3, t2)
            mul(x3, t3, x3)
            sub(x3, x3, t1)
            mul(z3, t4, z3)
            mul(t1, t3, t0)
            add(z3, z3, t1)
            x3.copyInto(out.x)
            y3.copyInto(out.y)
            z3.copyInto(out.z)
            wipe(t0, t1, t2, t3, t4, x3, y3, z3)
        }

        /** out = 2p, by RCB Algorithm 6. [out] may be [p]. */
        fun double(
            out: P256Point,
            p: P256Point,
        ) {
            val t0 = LongArray(8)
            val t1 = LongArray(8)
            val t2 = LongArray(8)
            val t3 = LongArray(8)
            val x3 = LongArray(8)
            val y3 = LongArray(8)
            val z3 = LongArray(8)
            sqr(t0, p.x)
            sqr(t1, p.y)
            sqr(t2, p.z)
            mul(t3, p.x, p.y)
            add(t3, t3, t3)
            mul(z3, p.x, p.z)
            add(z3, z3, z3)
            mul(y3, B, t2)
            sub(y3, y3, z3)
            add(x3, y3, y3)
            add(y3, x3, y3)
            sub(x3, t1, y3)
            add(y3, t1, y3)
            mul(y3, x3, y3)
            mul(x3, x3, t3)
            add(t3, t2, t2)
            add(t2, t2, t3)
            mul(z3, B, z3)
            sub(z3, z3, t2)
            sub(z3, z3, t0)
            add(t3, z3, z3)
            add(z3, z3, t3)
            add(t3, t0, t0)
            add(t0, t3, t0)
            sub(t0, t0, t2)
            mul(t0, t0, z3)
            add(y3, y3, t0)
            mul(t0, p.y, p.z)
            add(t0, t0, t0)
            mul(z3, t0, z3)
            sub(x3, x3, z3)
            mul(z3, t0, t1)
            add(z3, z3, z3)
            add(z3, z3, z3)
            x3.copyInto(out.x)
            y3.copyInto(out.y)
            z3.copyInto(out.z)
            wipe(t0, t1, t2, t3, x3, y3, z3)
        }

        private fun wipe(vararg temporaries: LongArray) {
            for (t in temporaries) t.fill(0)
        }

        /**
         * [k]P for a 32-byte big-endian scalar, by a fixed 4-bit window: 4 doublings and one
         * addition of a table entry per nibble, the entry picked by reading all 16 under masks.
         * Every scalar takes the same steps; the identity at the start and nibbles of 0 are
         * handled by the complete formulas.
         */
        fun scalarMult(
            k: ByteArray,
            p: P256Point,
        ): P256Point {
            val table = Array(16) { P256Point() }
            table[1].copyFrom(p)
            for (i in 2 until 16) add(table[i], table[i - 1], p)

            val q = P256Point()
            val t = P256Point()
            for (byte in k) {
                for (nibble in intArrayOf((byte.toInt() ushr 4) and 15, byte.toInt() and 15)) {
                    double(q, q)
                    double(q, q)
                    double(q, q)
                    double(q, q)
                    t.copyFrom(table[0])
                    for (i in 1 until 16) t.cmov(table[i], equal(i, nibble))
                    add(q, q, t)
                }
            }
            t.wipe()
            for (entry in table) entry.wipe()
            return q
        }

        /** 1 when a == b, else 0, for a and b in 0..15. No branch. */
        private fun equal(
            a: Int,
            b: Int,
        ): Int = ((a xor b) - 1) ushr 31

        /** Whether affine (x, y), in the Montgomery domain, is on y^2 = x^3 - 3x + b. */
        fun isOnCurve(
            x: LongArray,
            y: LongArray,
        ): Boolean {
            val rhs = LongArray(8)
            val threeX = LongArray(8)
            sqr(rhs, x)
            mul(rhs, rhs, x)
            add(threeX, x, x)
            add(threeX, threeX, x)
            sub(rhs, rhs, threeX)
            add(rhs, rhs, B)
            val lhs = LongArray(8)
            sqr(lhs, y)
            return lhs.contentEquals(rhs)
        }
    }
}
