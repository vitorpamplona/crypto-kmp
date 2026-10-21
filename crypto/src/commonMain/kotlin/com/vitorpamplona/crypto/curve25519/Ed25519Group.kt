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

import com.vitorpamplona.crypto.curve25519.Curve25519Field.GF0
import com.vitorpamplona.crypto.curve25519.Curve25519Field.GF1
import com.vitorpamplona.crypto.curve25519.Curve25519Field.LIMBS
import com.vitorpamplona.crypto.curve25519.Curve25519Field.addInto
import com.vitorpamplona.crypto.curve25519.Curve25519Field.inv25519Into
import com.vitorpamplona.crypto.curve25519.Curve25519Field.mulInto
import com.vitorpamplona.crypto.curve25519.Curve25519Field.sel25519
import com.vitorpamplona.crypto.curve25519.Curve25519Field.sqrInto
import com.vitorpamplona.crypto.curve25519.Curve25519Field.subInto

/*
 * The point representations, the addition and doubling formulas, the signed
 * radix-16 fixed-base multiplication and the sliding-window double-scalar
 * multiplication follow ref10, the Ed25519 reference code in SUPERCOP by
 * Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe and Bo-Yin Yang
 * (public domain): ge_p2, ge_p3, ge_p1p1, ge_precomp, ge_cached, ge_add,
 * ge_madd, ge_p2_dbl, ge_scalarmult_base and ge_double_scalarmult_vartime.
 * Unlike ref10, the precomputed tables are computed from B at first use rather
 * than compiled in.
 */

/** Projective point (X : Y : Z) with x = X/Z, y = Y/Z: ref10's `ge_p2`, enough to double. */
internal class GeP2 {
    val x = LongArray(LIMBS)
    val y = LongArray(LIMBS)
    val z = LongArray(LIMBS)

    fun wipe() {
        x.fill(0)
        y.fill(0)
        z.fill(0)
    }
}

/** Extended point (X : Y : Z : T) with x = X/Z, y = Y/Z and xy = T/Z: ref10's `ge_p3`. */
internal class GeP3 {
    val x = LongArray(LIMBS)
    val y = LongArray(LIMBS)
    val z = LongArray(LIMBS)
    val t = LongArray(LIMBS)

    fun setIdentity() {
        x.fill(0)
        GF1.copyInto(y)
        GF1.copyInto(z)
        t.fill(0)
    }

    fun copyFrom(p: GeP3) {
        p.x.copyInto(x)
        p.y.copyInto(y)
        p.z.copyInto(z)
        p.t.copyInto(t)
    }

    fun wipe() {
        x.fill(0)
        y.fill(0)
        z.fill(0)
        t.fill(0)
    }
}

/**
 * Completed point ((X : Z), (Y : T)) with x = X/Z and y = Y/T: ref10's
 * `ge_p1p1`, what an addition or a doubling produces before it is converted
 * back with [Ed25519Group.toP2] or [Ed25519Group.toP3]. Converting to [GeP2]
 * costs three multiplications against [GeP3]'s four, so a doubling that is
 * followed by another doubling skips T.
 */
internal class GeP1P1 {
    val x = LongArray(LIMBS)
    val y = LongArray(LIMBS)
    val z = LongArray(LIMBS)
    val t = LongArray(LIMBS)

    /** Scratch for the formulas that write this point. */
    val t0 = LongArray(LIMBS)

    fun wipe() {
        x.fill(0)
        y.fill(0)
        z.fill(0)
        t.fill(0)
        t0.fill(0)
    }
}

/** Affine point in Niels form (y + x, y - x, 2dxy): ref10's `ge_precomp`, what the tables hold. */
internal class GePrecomp {
    val yPlusX = LongArray(LIMBS)
    val yMinusX = LongArray(LIMBS)
    val xy2d = LongArray(LIMBS)

    /** The identity, (1, 1, 0). */
    fun setIdentity() {
        GF1.copyInto(yPlusX)
        GF1.copyInto(yMinusX)
        xy2d.fill(0)
    }

    fun wipe() {
        yPlusX.fill(0)
        yMinusX.fill(0)
        xy2d.fill(0)
    }
}

/** Extended point ready to be added (Y + X, Y - X, Z, 2dT): ref10's `ge_cached`. */
internal class GeCached {
    val yPlusX = LongArray(LIMBS)
    val yMinusX = LongArray(LIMBS)
    val z = LongArray(LIMBS)
    val t2d = LongArray(LIMBS)
}

/**
 * The edwards25519 group: point formulas, encoding and decoding, and the two
 * scalar multiplications Ed25519 needs, ported from ref10.
 *
 * - [scalarMultBase] computes [a]B in constant time from a lazily computed
 *   table of multiples of B. Keys, signatures' R and X25519 public keys go
 *   through it.
 * - [doubleScalarMultVartime] computes [a]A + [b]B in variable time, for
 *   verification only, where every input is public.
 *
 * Doubling uses its own formula (dbl-2008-hwcd for a = -1), four squarings
 * and four multiplications to completed form, rather than the general
 * addition of a point to itself.
 */
internal object Ed25519Group {
    // --- Conversions ---

    /** r = p, dropping T: three multiplications. */
    fun toP2(
        r: GeP2,
        p: GeP1P1,
    ) {
        mulInto(r.x, p.x, p.t)
        mulInto(r.y, p.y, p.z)
        mulInto(r.z, p.z, p.t)
    }

    /** r = p in extended coordinates: four multiplications. */
    fun toP3(
        r: GeP3,
        p: GeP1P1,
    ) {
        mulInto(r.x, p.x, p.t)
        mulInto(r.y, p.y, p.z)
        mulInto(r.z, p.z, p.t)
        mulInto(r.t, p.x, p.y)
    }

    /** r = p in the form [add] and [sub] take. */
    fun toCached(
        r: GeCached,
        p: GeP3,
    ) {
        addInto(r.yPlusX, p.y, p.x)
        subInto(r.yMinusX, p.y, p.x)
        p.z.copyInto(r.z)
        mulInto(r.t2d, p.t, Curve25519Field.D2)
    }

    // --- Doubling ---

    /**
     * r = 2p for p = (X : Y : Z): ref10's `ge_p2_dbl`, which is dbl-2008-hwcd
     * for a = -1. With A = X^2, B = Y^2, C = 2Z^2 and E = (X + Y)^2 - A - B, the
     * completed result is x = E / (B - A), y = (B + A) / (C - (B - A)).
     */
    private fun dbl(
        r: GeP1P1,
        x: LongArray,
        y: LongArray,
        z: LongArray,
    ) {
        sqrInto(r.x, x)
        sqrInto(r.z, y)
        sqrInto(r.t, z)
        addInto(r.t, r.t, r.t)
        addInto(r.y, x, y)
        sqrInto(r.t0, r.y)
        addInto(r.y, r.z, r.x)
        subInto(r.z, r.z, r.x)
        subInto(r.x, r.t0, r.y)
        subInto(r.t, r.t, r.z)
    }

    fun dbl(
        r: GeP1P1,
        p: GeP2,
    ) = dbl(r, p.x, p.y, p.z)

    /** Doubling ignores T, so an extended point doubles as its projective part. */
    fun dbl(
        r: GeP1P1,
        p: GeP3,
    ) = dbl(r, p.x, p.y, p.z)

    // --- Addition ---

    /**
     * r = p + q or p - q (when [subtract]): ref10's `ge_add` and `ge_sub`, the
     * extended-coordinate addition add-2008-hwcd-3, complete on this curve.
     */
    private fun add(
        r: GeP1P1,
        p: GeP3,
        qYPlusX: LongArray,
        qYMinusX: LongArray,
        qT2d: LongArray,
        qZ: LongArray?,
        subtract: Boolean,
    ) {
        addInto(r.x, p.y, p.x)
        subInto(r.y, p.y, p.x)
        // Subtracting q adds -q = (-x, y): Y + X and Y - X trade places and T
        // changes sign, which the last two lines apply.
        mulInto(r.z, r.x, if (subtract) qYMinusX else qYPlusX)
        mulInto(r.y, r.y, if (subtract) qYPlusX else qYMinusX)
        mulInto(r.t, qT2d, p.t)
        // 2 * Z1 * Z2, with Z2 = 1 for an affine (precomputed) q.
        if (qZ == null) {
            addInto(r.t0, p.z, p.z)
        } else {
            mulInto(r.x, p.z, qZ)
            addInto(r.t0, r.x, r.x)
        }
        subInto(r.x, r.z, r.y)
        addInto(r.y, r.z, r.y)
        if (subtract) {
            subInto(r.z, r.t0, r.t)
            addInto(r.t, r.t0, r.t)
        } else {
            addInto(r.z, r.t0, r.t)
            subInto(r.t, r.t0, r.t)
        }
    }

    /** r = p + q: ref10's `ge_add`. */
    fun add(
        r: GeP1P1,
        p: GeP3,
        q: GeCached,
    ) = add(r, p, q.yPlusX, q.yMinusX, q.t2d, q.z, false)

    /** r = p - q: ref10's `ge_sub`. */
    fun sub(
        r: GeP1P1,
        p: GeP3,
        q: GeCached,
    ) = add(r, p, q.yPlusX, q.yMinusX, q.t2d, q.z, true)

    /** r = p + q for an affine q: ref10's `ge_madd`, one multiplication less than [add]. */
    fun madd(
        r: GeP1P1,
        p: GeP3,
        q: GePrecomp,
    ) = add(r, p, q.yPlusX, q.yMinusX, q.xy2d, null, false)

    /** r = p - q for an affine q: ref10's `ge_msub`. */
    fun msub(
        r: GeP1P1,
        p: GeP3,
        q: GePrecomp,
    ) = add(r, p, q.yPlusX, q.yMinusX, q.xy2d, null, true)

    /** p = -p, in place. */
    fun negate(p: GeP3) {
        subInto(p.x, GF0, p.x)
        subInto(p.t, GF0, p.t)
    }

    // --- Encoding ---

    /** The 32-byte encoding of (X : Y : Z): y, with the parity of x in the top bit. */
    fun encode(
        x: LongArray,
        y: LongArray,
        z: LongArray,
    ): ByteArray {
        val zi = LongArray(LIMBS)
        val tx = LongArray(LIMBS)
        val ty = LongArray(LIMBS)
        inv25519Into(zi, z)
        mulInto(tx, x, zi)
        mulInto(ty, y, zi)
        val r = Curve25519Field.pack25519(ty)
        r[31] = (r[31].toInt() xor (Curve25519Field.par25519(tx) shl 7)).toByte()
        zi.fill(0)
        tx.fill(0)
        ty.fill(0)
        return r
    }

    fun encode(p: GeP2): ByteArray = encode(p.x, p.y, p.z)

    fun encode(p: GeP3): ByteArray = encode(p.x, p.y, p.z)

    /**
     * Decode a 32-byte compressed Edwards point (RFC 8032 §5.1.3).
     *
     * Returns null if the point is not on the curve or the encoding is not
     * canonical: y at or above p (a second encoding of y - p), or x = 0 with
     * the sign bit set (a second encoding of the same point). Only ever
     * called on public data, so the early returns leak nothing.
     */
    fun decodeVartime(s: ByteArray): GeP3? {
        val r = Curve25519Field.unpack25519(s)
        // unpack25519 keeps y as given, so y >= p is caught by re-encoding:
        // pack25519 reduces, and only a canonical y comes back unchanged.
        val canonical = Curve25519Field.pack25519(r)
        canonical[31] = (canonical[31].toInt() or (s[31].toInt() and 0x80)).toByte()
        if (!canonical.contentEquals(s)) return null
        val sign = (s[31].toInt() shr 7) and 1

        // Recover x from y: x^2 = u / v, with u = y^2 - 1 and v = d * y^2 + 1.
        // ref10's square root of a ratio takes one exponentiation and no
        // inversion: x = u * v^3 * (u * v^7)^((p - 5) / 8).
        val y2 = Curve25519Field.sqr(r)
        val u = Curve25519Field.sub(y2, GF1)
        val v = Curve25519Field.add(Curve25519Field.mul(Curve25519Field.D, y2), GF1)
        val v3 = Curve25519Field.mul(Curve25519Field.sqr(v), v)
        val uv7 = Curve25519Field.mul(Curve25519Field.mul(Curve25519Field.sqr(v3), v), u)
        var x = Curve25519Field.mul(Curve25519Field.mul(u, v3), Curve25519Field.pow2523(uv7))

        // v * x^2 is u when x is a root, or -u when x * sqrt(-1) is one.
        // Anything else means u / v is not a square: no point has this y.
        val vx2 = Curve25519Field.mul(v, Curve25519Field.sqr(x))
        if (!Curve25519Field.isZero(Curve25519Field.sub(vx2, u))) {
            if (!Curve25519Field.isZero(Curve25519Field.add(vx2, u))) return null
            x = Curve25519Field.mul(x, Curve25519Field.I)
        }

        // x = 0 has no negative, so a sign bit on it is a second encoding.
        if (sign == 1 && Curve25519Field.isZero(x)) return null

        if (Curve25519Field.par25519(x) != sign) {
            x = Curve25519Field.sub(GF0, x)
        }

        val p = GeP3()
        x.copyInto(p.x)
        r.copyInto(p.y)
        GF1.copyInto(p.z)
        mulInto(p.t, p.x, p.y)
        return p
    }

    /**
     * True when [p] has small order: [8]P is the identity, which covers the
     * eight points of the torsion subgroup. Three doublings, then the identity
     * test in projective form: X = 0 and Y = Z. For public points only.
     */
    fun hasSmallOrder(p: GeP3): Boolean {
        val t = GeP1P1()
        val q = GeP2()
        dbl(t, p)
        toP2(q, t)
        dbl(t, q)
        toP2(q, t)
        dbl(t, q)
        toP2(q, t)
        return Curve25519Field.isZero(q.x) && Curve25519Field.isZero(Curve25519Field.sub(q.y, q.z))
    }

    // --- Fixed-base scalar multiplication ---

    /** The base point B, with x positive and y = 4/5. */
    private fun basePoint(): GeP3 {
        val b = GeP3()
        Curve25519Field.BX.copyInto(b.x)
        Curve25519Field.BY.copyInto(b.y)
        GF1.copyInto(b.z)
        mulInto(b.t, b.x, b.y)
        return b
    }

    /**
     * Affine Niels forms of [points], with one shared inversion (Montgomery's
     * trick). Every coordinate comes out of a multiplication, or is the sum or
     * difference of two that did, so its limbs stay within what [mulInto]
     * takes.
     */
    private fun toPrecomp(points: Array<GeP3>): Array<GePrecomp> {
        val n = points.size
        // prefix[k] = Z_0 * ... * Z_k
        val prefix = Array(n) { LongArray(LIMBS) }
        points[0].z.copyInto(prefix[0])
        for (k in 1 until n) mulInto(prefix[k], prefix[k - 1], points[k].z)
        val inv = LongArray(LIMBS)
        inv25519Into(inv, prefix[n - 1])

        val zi = LongArray(LIMBS)
        val x = LongArray(LIMBS)
        val y = LongArray(LIMBS)
        val out = Array(n) { GePrecomp() }
        for (k in n - 1 downTo 0) {
            if (k > 0) {
                mulInto(zi, inv, prefix[k - 1])
                mulInto(inv, inv, points[k].z)
            } else {
                inv.copyInto(zi)
            }
            mulInto(x, points[k].x, zi)
            mulInto(y, points[k].y, zi)
            val e = out[k]
            addInto(e.yPlusX, y, x)
            subInto(e.yMinusX, y, x)
            mulInto(e.xy2d, x, y)
            mulInto(e.xy2d, e.xy2d, Curve25519Field.D2)
        }
        return out
    }

    /**
     * `(j + 1) * 16^(2i) * B` for i in 0..31 and j in 0..7, at index `8 * i + j`:
     * ref10's `base` table, which ref10 ships as source. Computed here at first
     * use instead, from B with the formulas above: 248 doublings and 224
     * additions, then one batched inversion. `lazy` is synchronized, so
     * concurrent first callers compute it once.
     */
    internal val baseTable: Array<GePrecomp> by lazy {
        val points = Array(32 * 8) { GeP3() }
        val step = basePoint() // 256^i * B
        val cached = GeCached()
        val t = GeP1P1()
        val q = GeP2()
        for (i in 0 until 32) {
            points[8 * i].copyFrom(step)
            toCached(cached, step)
            for (j in 1 until 8) {
                add(t, points[8 * i + j - 1], cached)
                toP3(points[8 * i + j], t)
            }
            if (i < 31) {
                dbl(t, step)
                repeat(7) {
                    toP2(q, t)
                    dbl(t, q)
                }
                toP3(step, t)
            }
        }
        toPrecomp(points)
    }

    /** 1 when a == b, else 0, for a and b in 0..255. No branch. */
    private fun equal(
        a: Int,
        b: Int,
    ): Int = ((a xor b) - 1) ushr 31

    /** t = u when [flag] is 1, unchanged when it is 0. No branch. */
    private fun cmov(
        t: GePrecomp,
        u: GePrecomp,
        flag: Int,
    ) {
        val mask = -flag.toLong()
        for (i in 0 until LIMBS) {
            t.yPlusX[i] = t.yPlusX[i] xor (mask and (t.yPlusX[i] xor u.yPlusX[i]))
            t.yMinusX[i] = t.yMinusX[i] xor (mask and (t.yMinusX[i] xor u.yMinusX[i]))
            t.xy2d[i] = t.xy2d[i] xor (mask and (t.xy2d[i] xor u.xy2d[i]))
        }
    }

    /**
     * t = [b] * 16^(2 * pos) * B for a digit b in -8..8, in constant time:
     * ref10's `select`. Every one of the eight entries of row [pos] is read and
     * masked in, whatever b is, and the sign is applied with a mask too, so
     * neither the memory accessed nor the branches taken depend on b.
     */
    private fun select(
        t: GePrecomp,
        table: Array<GePrecomp>,
        pos: Int,
        b: Int,
    ) {
        val negative = b ushr 31
        val abs = b - ((-negative and b) shl 1)
        t.setIdentity()
        for (j in 0 until 8) cmov(t, table[8 * pos + j], equal(abs, j + 1))
        // -(x, y) = (-x, y): y + x and y - x trade places and 2dxy changes sign.
        sel25519(t.yPlusX, t.yMinusX, negative.toLong())
        val mask = -negative.toLong()
        for (i in 0 until LIMBS) {
            val v = t.xy2d[i]
            t.xy2d[i] = v xor (mask and (v xor -v))
        }
    }

    /**
     * r = [a]B in constant time: ref10's `ge_scalarmult_base`.
     *
     * [a] is 32 little-endian bytes with the top bit clear (a[31] <= 127),
     * which a clamped Ed25519 or X25519 scalar and anything reduced mod L all
     * satisfy; it is used as the full integer, not reduced mod L. It is
     * recoded into 64 signed radix-16 digits e_i in -8..8 with
     * a = sum e_i * 16^i. The odd digits are added first, each from the row
     * of [baseTable] for its power of 256, then the sum is multiplied by 16
     * with four doublings, then the even digits are added: 64 table additions
     * and 4 doublings in all, against 256 doublings and 256 additions for a
     * double-and-add.
     */
    fun scalarMultBase(
        r: GeP3,
        a: ByteArray,
    ) {
        val table = baseTable
        val e = ByteArray(64)
        for (i in 0 until 32) {
            val ai = a[i].toInt() and 0xFF
            e[2 * i] = (ai and 15).toByte()
            e[2 * i + 1] = (ai ushr 4).toByte()
        }
        // Each e_i is in 0..15 and e_63 in 0..7. Carry so each lies in -8..7,
        // the last in -8..8. Arithmetic only: no branch on the digits.
        var carry = 0
        for (i in 0 until 63) {
            val v = e[i] + carry
            carry = (v + 8) shr 4
            e[i] = (v - (carry shl 4)).toByte()
        }
        e[63] = (e[63] + carry).toByte()

        val t = GePrecomp()
        val p1 = GeP1P1()
        val p2 = GeP2()
        r.setIdentity()
        for (i in 1 until 64 step 2) {
            select(t, table, i / 2, e[i].toInt())
            madd(p1, r, t)
            toP3(r, p1)
        }

        dbl(p1, r)
        toP2(p2, p1)
        dbl(p1, p2)
        toP2(p2, p1)
        dbl(p1, p2)
        toP2(p2, p1)
        dbl(p1, p2)
        toP3(r, p1)

        for (i in 0 until 64 step 2) {
            select(t, table, i / 2, e[i].toInt())
            madd(p1, r, t)
            toP3(r, p1)
        }

        // The digits are the scalar; the temporaries are steps towards [a]B.
        e.fill(0)
        t.wipe()
        p1.wipe()
        p2.wipe()
    }

    // --- Variable-time double-scalar multiplication, for verification ---

    /** B, 3B, 5B, ..., 15B: ref10's `Bi`, computed at first use. */
    private val oddMultiplesOfB: Array<GePrecomp> by lazy {
        val b = basePoint()
        val points = Array(8) { GeP3() }
        points[0].copyFrom(b)
        val t = GeP1P1()
        val b2 = GeP3()
        dbl(t, b)
        toP3(b2, t)
        val cached = GeCached()
        toCached(cached, b2)
        for (k in 1 until 8) {
            add(t, points[k - 1], cached)
            toP3(points[k], t)
        }
        toPrecomp(points)
    }

    /**
     * Width-5 sliding-window recoding of [a]: ref10's `slide`. Returns 256
     * digits, each 0 or odd in -15..15, with a = sum r_i * 2^i and every
     * non-zero digit followed by at least four zeros. Variable time: for
     * public scalars only. [a] must be below 2^255, as anything reduced mod L is.
     */
    private fun slide(a: ByteArray): IntArray {
        val r = IntArray(256)
        for (i in 0 until 256) r[i] = 1 and (a[i shr 3].toInt() shr (i and 7))
        for (i in 0 until 256) {
            if (r[i] == 0) continue
            var b = 1
            while (b <= 6 && i + b < 256) {
                if (r[i + b] != 0) {
                    if (r[i] + (r[i + b] shl b) <= 15) {
                        r[i] += r[i + b] shl b
                        r[i + b] = 0
                    } else if (r[i] - (r[i + b] shl b) >= -15) {
                        r[i] -= r[i + b] shl b
                        for (k in i + b until 256) {
                            if (r[k] == 0) {
                                r[k] = 1
                                break
                            }
                            r[k] = 0
                        }
                    } else {
                        break
                    }
                }
                b++
            }
        }
        return r
    }

    /**
     * r = [a]A + [b]B: ref10's `ge_double_scalarmult_vartime`, for
     * [Ed25519.verify]. Both scalars are recoded with [slide] and processed
     * together, one doubling per bit and an addition per non-zero digit, from
     * a per-call table of A, 3A, ..., 15A and the static [oddMultiplesOfB].
     *
     * VARIABLE TIME: the branches and table indices follow the digits of [a]
     * and [b]. That is safe only because everything verification handles is
     * public (the key A, the challenge, S and R), and it must never be called
     * with a secret scalar or point. [a] and [b] must be below 2^255.
     */
    fun doubleScalarMultVartime(
        r: GeP2,
        a: ByteArray,
        aPoint: GeP3,
        b: ByteArray,
    ) {
        val aSlide = slide(a)
        val bSlide = slide(b)
        val bTable = oddMultiplesOfB

        // aTable[k] = (2k + 1) * A
        val aTable = Array(8) { GeCached() }
        val t = GeP1P1()
        val u = GeP3()
        val a2 = GeP3()
        toCached(aTable[0], aPoint)
        dbl(t, aPoint)
        toP3(a2, t)
        for (k in 1 until 8) {
            add(t, a2, aTable[k - 1])
            toP3(u, t)
            toCached(aTable[k], u)
        }

        r.x.fill(0)
        GF1.copyInto(r.y)
        GF1.copyInto(r.z)

        var i = 255
        while (i >= 0 && aSlide[i] == 0 && bSlide[i] == 0) i--

        while (i >= 0) {
            dbl(t, r)
            val ai = aSlide[i]
            if (ai > 0) {
                toP3(u, t)
                add(t, u, aTable[ai / 2])
            } else if (ai < 0) {
                toP3(u, t)
                sub(t, u, aTable[-ai / 2])
            }
            val bi = bSlide[i]
            if (bi > 0) {
                toP3(u, t)
                madd(t, u, bTable[bi / 2])
            } else if (bi < 0) {
                toP3(u, t)
                msub(t, u, bTable[-bi / 2])
            }
            toP2(r, t)
            i--
        }
    }
}
