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

import com.vitorpamplona.crypto.mul64
import com.vitorpamplona.crypto.toUnsignedLong

/**
 * Arithmetic modulo the P-256 prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1 (FIPS 186-5,
 * SEC 2), in constant time: no branch or array index depends on an element's value.
 *
 * An element is a `LongArray(8)` of 32-bit limbs, least significant first, each in
 * 0..2^32-1, and always fully reduced (below p). Products of two limbs fit an unsigned
 * 64-bit Long, and every multiply goes through [mul64], so Kotlin/JS's emulated Long stays
 * branch-free too.
 *
 * Multiplication is Montgomery's, by coarsely integrated operand scanning (CIOS), with
 * R = 2^256: [mul] gives a·b·R^-1, with p's 0, 1 and 2^32-1 limbs folded into the reduction. So elements live in the Montgomery domain (a·R mod p)
 * between [toMontgomery] and [fromMontgomery]; addition and subtraction work the same in
 * both. Since p ≡ -1 mod 2^32, -p^-1 ≡ 1 mod 2^32 and the reduction factor of each round is
 * just the low limb.
 *
 * Scratch arrays hold values derived from secrets, so every function zeroes its own before it
 * returns.
 */
internal object P256Field {
    const val LIMBS = 8

    private const val MASK = 0xFFFF_FFFFL

    /** p, least significant limb first. */
    private val P = longArrayOf(0xffffffffL, 0xffffffffL, 0xffffffffL, 0L, 0L, 0L, 0x00000001L, 0xffffffffL)

    /** R^2 mod p, which [toMontgomery] multiplies by. */
    private val R2 = longArrayOf(0x00000003L, 0x00000000L, 0xffffffffL, 0xfffffffbL, 0xfffffffeL, 0xffffffffL, 0xfffffffdL, 0x00000004L)

    /** 1, outside the Montgomery domain: [fromMontgomery] multiplies by it. */
    private val PLAIN_ONE = longArrayOf(1L, 0L, 0L, 0L, 0L, 0L, 0L, 0L)

    /** 1 in the Montgomery domain: R mod p. */
    val ONE = longArrayOf(0x00000001L, 0x00000000L, 0x00000000L, 0xffffffffL, 0xffffffffL, 0xffffffffL, 0xfffffffeL, 0x00000000L)

    /** p as 32 big-endian bytes, for range checks on encoded coordinates. */
    val P_BYTES: ByteArray = ByteArray(32) { i -> (P[LIMBS - 1 - i / 4] ushr (24 - 8 * (i % 4))).toByte() }

    fun zero() = LongArray(LIMBS)

    /** out = a·b·R^-1 mod p. [out] may be [a] or [b]. */
    fun mul(
        out: LongArray,
        a: LongArray,
        b: LongArray,
    ) {
        val t = LongArray(LIMBS + 2)
        for (i in 0 until LIMBS) {
            // t += a·b[i]: each step is at most (2^32-1) + (2^32-1)^2 + (2^32-1) = 2^64 - 1.
            val bi = b[i]
            var c = 0L
            for (j in 0 until LIMBS) {
                val s = t[j] + mul64(a[j], bi) + c
                t[j] = s and MASK
                c = s ushr 32
            }
            var s = t[LIMBS] + c
            t[LIMBS] = s and MASK
            t[LIMBS + 1] = s ushr 32

            // t = (t + m·p) / 2^32 with m = t[0], which zeroes the low limb. p's limbs are
            // 2^32-1, 0 or 1, so m·p[j] needs no multiply: m·(2^32-1) = m·2^32 - m, which
            // fits 64 unsigned bits like the products above.
            val m = t[0]
            val mm = (m shl 32) - m
            c = (t[0] + mm) ushr 32
            s = t[1] + mm + c
            t[0] = s and MASK
            c = s ushr 32
            s = t[2] + mm + c
            t[1] = s and MASK
            c = s ushr 32
            s = t[3] + c
            t[2] = s and MASK
            c = s ushr 32
            s = t[4] + c
            t[3] = s and MASK
            c = s ushr 32
            s = t[5] + c
            t[4] = s and MASK
            c = s ushr 32
            s = t[6] + m + c
            t[5] = s and MASK
            c = s ushr 32
            s = t[7] + mm + c
            t[6] = s and MASK
            c = s ushr 32
            s = t[LIMBS] + c
            t[LIMBS - 1] = s and MASK
            t[LIMBS] = t[LIMBS + 1] + (s ushr 32)
        }
        // t < 2p: one conditional subtraction makes it canonical.
        reduceOnce(out, t, t[LIMBS])
        t.fill(0)
    }

    fun sqr(
        out: LongArray,
        a: LongArray,
    ) = mul(out, a, a)

    /** out = a + b mod p. [out] may be [a] or [b]. */
    fun add(
        out: LongArray,
        a: LongArray,
        b: LongArray,
    ) {
        val t = LongArray(LIMBS)
        var c = 0L
        for (i in 0 until LIMBS) {
            val s = a[i] + b[i] + c
            t[i] = s and MASK
            c = s ushr 32
        }
        reduceOnce(out, t, c)
        t.fill(0)
    }

    /** out = a - b mod p. [out] may be [a] or [b]. */
    fun sub(
        out: LongArray,
        a: LongArray,
        b: LongArray,
    ) {
        val t = LongArray(LIMBS)
        var borrow = 0L
        for (i in 0 until LIMBS) {
            val d = a[i] - b[i] - borrow
            t[i] = d and MASK
            borrow = d ushr 63
        }
        // Add p back exactly when it went below zero.
        val mask = -borrow
        var c = 0L
        for (i in 0 until LIMBS) {
            val s = t[i] + (P[i] and mask) + c
            out[i] = s and MASK
            c = s ushr 32
        }
        t.fill(0)
    }

    /**
     * out = t - p if t (with [carry] as its bit 256) is at least p, else t: for a t below 2p.
     * Both are computed; a mask picks one.
     */
    private fun reduceOnce(
        out: LongArray,
        t: LongArray,
        carry: Long,
    ) {
        val u = LongArray(LIMBS)
        var borrow = 0L
        for (i in 0 until LIMBS) {
            val d = t[i] - P[i] - borrow
            u[i] = d and MASK
            borrow = d ushr 63
        }
        // Keep u when t >= p: the subtraction didn't borrow, or t had a 257th bit.
        val keepU = -((1L - borrow) or carry)
        for (i in 0 until LIMBS) out[i] = (u[i] and keepU) or (t[i] and keepU.inv())
        u.fill(0)
    }

    fun toMontgomery(
        out: LongArray,
        a: LongArray,
    ) = mul(out, a, R2)

    fun fromMontgomery(
        out: LongArray,
        a: LongArray,
    ) = mul(out, a, PLAIN_ONE)

    /**
     * out = a^-1 = a^(p-2) (Fermat), in the Montgomery domain; 0 for 0. The exponent is the
     * public p - 2, so branching on its bits leaks nothing about [a].
     */
    fun invert(
        out: LongArray,
        a: LongArray,
    ) {
        val r = ONE.copyOf()
        val base = a.copyOf()
        for (bit in 255 downTo 0) {
            sqr(r, r)
            if (exponentBit(bit)) mul(r, r, base)
        }
        r.copyInto(out)
        r.fill(0)
        base.fill(0)
    }

    /** Bit [bit] of p - 2, whose low limb is 0xfffffffd and the rest p's. */
    private fun exponentBit(bit: Int): Boolean {
        val limb = if (bit < 32) 0xfffffffdL else P[bit / 32]
        return (limb ushr (bit % 32)) and 1L == 1L
    }

    /** 1 if [a] is zero, else 0, without a branch on its value. */
    fun isZero(a: LongArray): Int {
        var acc = 0L
        for (limb in a) acc = acc or limb
        // acc is below 2^32: acc - 1 goes negative exactly when acc is 0.
        return ((acc - 1) ushr 63).toInt()
    }

    /** out = [a] when [flag] is 1, left as is when it is 0. */
    fun cmov(
        out: LongArray,
        a: LongArray,
        flag: Int,
    ) {
        val mask = -(flag and 1).toLong()
        for (i in 0 until LIMBS) out[i] = (a[i] and mask) or (out[i] and mask.inv())
    }

    /** The 32 big-endian bytes at [offset] as limbs, not reduced: callers check them against p. */
    fun fromBytes(
        bytes: ByteArray,
        offset: Int,
    ): LongArray {
        val out = LongArray(LIMBS)
        for (i in 0 until LIMBS) {
            val o = offset + 28 - 4 * i
            out[i] = (bytes[o].toUnsignedLong() shl 24) or (bytes[o + 1].toUnsignedLong() shl 16) or
                (bytes[o + 2].toUnsignedLong() shl 8) or bytes[o + 3].toUnsignedLong()
        }
        return out
    }

    /** [a], a reduced element outside the Montgomery domain, as 32 big-endian bytes at [offset]. */
    fun toBytes(
        a: LongArray,
        out: ByteArray,
        offset: Int,
    ) {
        for (i in 0 until LIMBS) {
            val o = offset + 28 - 4 * i
            out[o] = (a[i] ushr 24).toByte()
            out[o + 1] = (a[i] ushr 16).toByte()
            out[o + 2] = (a[i] ushr 8).toByte()
            out[o + 3] = a[i].toByte()
        }
    }
}
