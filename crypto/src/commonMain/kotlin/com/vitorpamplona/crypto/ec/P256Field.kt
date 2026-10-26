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
 * R = 2^256: [mul] gives a·b·R^-1, with p's 0, 1 and 2^32-1 limbs folded into the reduction.
 * So elements live in the Montgomery domain (a·R mod p) between [toMontgomery] and
 * [fromMontgomery]; addition and subtraction work the same in both. Since p ≡ -1 mod 2^32,
 * -p^-1 ≡ 1 mod 2^32 and the reduction factor of each round is just the low limb.
 *
 * Nothing here allocates scratch: [mul] works in locals and [add], [sub] in the output, so no
 * secret-derived temporary is left in an array to wipe; [invert] wipes its two copies.
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

    /**
     * out = a·b·R^-1 mod p. [out] may be [a] or [b].
     *
     * Straight-line over locals, so it allocates nothing: CIOS unrolled, eight rounds of
     * t += a·b[i] then t = (t + m·p) / 2^32 with m = t0. In each, t's limbs stay below 2^32
     * plus a top limb of at most 1, and every sum fits an unsigned 64-bit Long: at most
     * (2^32-1) + (2^32-1)^2 + (2^32-1) = 2^64 - 1 in the products, and in the reduction m·p
     * needs no multiply, p's limbs being 2^32-1, 0 or 1. Its low three limbs are all ones, so
     * adding m·(2^96-1) to a t whose low limb is m leaves limbs 1 and 2 as they were, shifted
     * down, with a carry of m into limb 3. The eight rounds are one pattern written out, so
     * t lives in locals rather than a scratch array; P256JcaTest checks them against
     * BigInteger.
     */
    fun mul(
        out: LongArray,
        a: LongArray,
        b: LongArray,
    ) {
        val a0 = a[0]
        val a1 = a[1]
        val a2 = a[2]
        val a3 = a[3]
        val a4 = a[4]
        val a5 = a[5]
        val a6 = a[6]
        val a7 = a[7]
        var t0: Long
        var t1: Long
        var t2: Long
        var t3: Long
        var t4: Long
        var t5: Long
        var t6: Long
        var t7: Long
        var t8: Long
        var t9: Long
        var s: Long
        var c: Long
        var bi: Long
        var m: Long

        // Round 0: t += a·b[0], then t = (t + m·p) / 2^32 with m = t0.
        bi = b[0]
        s = mul64(a0, bi)
        t0 = s and MASK
        c = s ushr 32
        s = mul64(a1, bi) + c
        t1 = s and MASK
        c = s ushr 32
        s = mul64(a2, bi) + c
        t2 = s and MASK
        c = s ushr 32
        s = mul64(a3, bi) + c
        t3 = s and MASK
        c = s ushr 32
        s = mul64(a4, bi) + c
        t4 = s and MASK
        c = s ushr 32
        s = mul64(a5, bi) + c
        t5 = s and MASK
        c = s ushr 32
        s = mul64(a6, bi) + c
        t6 = s and MASK
        c = s ushr 32
        s = mul64(a7, bi) + c
        t7 = s and MASK
        c = s ushr 32
        t8 = c
        t9 = 0L
        m = t0
        t0 = t1
        t1 = t2
        s = t3 + m
        t2 = s and MASK
        c = s ushr 32
        s = t4 + c
        t3 = s and MASK
        c = s ushr 32
        s = t5 + c
        t4 = s and MASK
        c = s ushr 32
        s = t6 + m + c
        t5 = s and MASK
        c = s ushr 32
        s = t7 + (m shl 32) - m + c
        t6 = s and MASK
        c = s ushr 32
        s = t8 + c
        t7 = s and MASK
        t8 = t9 + (s ushr 32)

        // Round 1: t += a·b[1], then t = (t + m·p) / 2^32 with m = t0.
        bi = b[1]
        s = t0 + mul64(a0, bi)
        t0 = s and MASK
        c = s ushr 32
        s = t1 + mul64(a1, bi) + c
        t1 = s and MASK
        c = s ushr 32
        s = t2 + mul64(a2, bi) + c
        t2 = s and MASK
        c = s ushr 32
        s = t3 + mul64(a3, bi) + c
        t3 = s and MASK
        c = s ushr 32
        s = t4 + mul64(a4, bi) + c
        t4 = s and MASK
        c = s ushr 32
        s = t5 + mul64(a5, bi) + c
        t5 = s and MASK
        c = s ushr 32
        s = t6 + mul64(a6, bi) + c
        t6 = s and MASK
        c = s ushr 32
        s = t7 + mul64(a7, bi) + c
        t7 = s and MASK
        c = s ushr 32
        s = t8 + c
        t8 = s and MASK
        t9 = s ushr 32
        m = t0
        t0 = t1
        t1 = t2
        s = t3 + m
        t2 = s and MASK
        c = s ushr 32
        s = t4 + c
        t3 = s and MASK
        c = s ushr 32
        s = t5 + c
        t4 = s and MASK
        c = s ushr 32
        s = t6 + m + c
        t5 = s and MASK
        c = s ushr 32
        s = t7 + (m shl 32) - m + c
        t6 = s and MASK
        c = s ushr 32
        s = t8 + c
        t7 = s and MASK
        t8 = t9 + (s ushr 32)

        // Round 2: t += a·b[2], then t = (t + m·p) / 2^32 with m = t0.
        bi = b[2]
        s = t0 + mul64(a0, bi)
        t0 = s and MASK
        c = s ushr 32
        s = t1 + mul64(a1, bi) + c
        t1 = s and MASK
        c = s ushr 32
        s = t2 + mul64(a2, bi) + c
        t2 = s and MASK
        c = s ushr 32
        s = t3 + mul64(a3, bi) + c
        t3 = s and MASK
        c = s ushr 32
        s = t4 + mul64(a4, bi) + c
        t4 = s and MASK
        c = s ushr 32
        s = t5 + mul64(a5, bi) + c
        t5 = s and MASK
        c = s ushr 32
        s = t6 + mul64(a6, bi) + c
        t6 = s and MASK
        c = s ushr 32
        s = t7 + mul64(a7, bi) + c
        t7 = s and MASK
        c = s ushr 32
        s = t8 + c
        t8 = s and MASK
        t9 = s ushr 32
        m = t0
        t0 = t1
        t1 = t2
        s = t3 + m
        t2 = s and MASK
        c = s ushr 32
        s = t4 + c
        t3 = s and MASK
        c = s ushr 32
        s = t5 + c
        t4 = s and MASK
        c = s ushr 32
        s = t6 + m + c
        t5 = s and MASK
        c = s ushr 32
        s = t7 + (m shl 32) - m + c
        t6 = s and MASK
        c = s ushr 32
        s = t8 + c
        t7 = s and MASK
        t8 = t9 + (s ushr 32)

        // Round 3: t += a·b[3], then t = (t + m·p) / 2^32 with m = t0.
        bi = b[3]
        s = t0 + mul64(a0, bi)
        t0 = s and MASK
        c = s ushr 32
        s = t1 + mul64(a1, bi) + c
        t1 = s and MASK
        c = s ushr 32
        s = t2 + mul64(a2, bi) + c
        t2 = s and MASK
        c = s ushr 32
        s = t3 + mul64(a3, bi) + c
        t3 = s and MASK
        c = s ushr 32
        s = t4 + mul64(a4, bi) + c
        t4 = s and MASK
        c = s ushr 32
        s = t5 + mul64(a5, bi) + c
        t5 = s and MASK
        c = s ushr 32
        s = t6 + mul64(a6, bi) + c
        t6 = s and MASK
        c = s ushr 32
        s = t7 + mul64(a7, bi) + c
        t7 = s and MASK
        c = s ushr 32
        s = t8 + c
        t8 = s and MASK
        t9 = s ushr 32
        m = t0
        t0 = t1
        t1 = t2
        s = t3 + m
        t2 = s and MASK
        c = s ushr 32
        s = t4 + c
        t3 = s and MASK
        c = s ushr 32
        s = t5 + c
        t4 = s and MASK
        c = s ushr 32
        s = t6 + m + c
        t5 = s and MASK
        c = s ushr 32
        s = t7 + (m shl 32) - m + c
        t6 = s and MASK
        c = s ushr 32
        s = t8 + c
        t7 = s and MASK
        t8 = t9 + (s ushr 32)

        // Round 4: t += a·b[4], then t = (t + m·p) / 2^32 with m = t0.
        bi = b[4]
        s = t0 + mul64(a0, bi)
        t0 = s and MASK
        c = s ushr 32
        s = t1 + mul64(a1, bi) + c
        t1 = s and MASK
        c = s ushr 32
        s = t2 + mul64(a2, bi) + c
        t2 = s and MASK
        c = s ushr 32
        s = t3 + mul64(a3, bi) + c
        t3 = s and MASK
        c = s ushr 32
        s = t4 + mul64(a4, bi) + c
        t4 = s and MASK
        c = s ushr 32
        s = t5 + mul64(a5, bi) + c
        t5 = s and MASK
        c = s ushr 32
        s = t6 + mul64(a6, bi) + c
        t6 = s and MASK
        c = s ushr 32
        s = t7 + mul64(a7, bi) + c
        t7 = s and MASK
        c = s ushr 32
        s = t8 + c
        t8 = s and MASK
        t9 = s ushr 32
        m = t0
        t0 = t1
        t1 = t2
        s = t3 + m
        t2 = s and MASK
        c = s ushr 32
        s = t4 + c
        t3 = s and MASK
        c = s ushr 32
        s = t5 + c
        t4 = s and MASK
        c = s ushr 32
        s = t6 + m + c
        t5 = s and MASK
        c = s ushr 32
        s = t7 + (m shl 32) - m + c
        t6 = s and MASK
        c = s ushr 32
        s = t8 + c
        t7 = s and MASK
        t8 = t9 + (s ushr 32)

        // Round 5: t += a·b[5], then t = (t + m·p) / 2^32 with m = t0.
        bi = b[5]
        s = t0 + mul64(a0, bi)
        t0 = s and MASK
        c = s ushr 32
        s = t1 + mul64(a1, bi) + c
        t1 = s and MASK
        c = s ushr 32
        s = t2 + mul64(a2, bi) + c
        t2 = s and MASK
        c = s ushr 32
        s = t3 + mul64(a3, bi) + c
        t3 = s and MASK
        c = s ushr 32
        s = t4 + mul64(a4, bi) + c
        t4 = s and MASK
        c = s ushr 32
        s = t5 + mul64(a5, bi) + c
        t5 = s and MASK
        c = s ushr 32
        s = t6 + mul64(a6, bi) + c
        t6 = s and MASK
        c = s ushr 32
        s = t7 + mul64(a7, bi) + c
        t7 = s and MASK
        c = s ushr 32
        s = t8 + c
        t8 = s and MASK
        t9 = s ushr 32
        m = t0
        t0 = t1
        t1 = t2
        s = t3 + m
        t2 = s and MASK
        c = s ushr 32
        s = t4 + c
        t3 = s and MASK
        c = s ushr 32
        s = t5 + c
        t4 = s and MASK
        c = s ushr 32
        s = t6 + m + c
        t5 = s and MASK
        c = s ushr 32
        s = t7 + (m shl 32) - m + c
        t6 = s and MASK
        c = s ushr 32
        s = t8 + c
        t7 = s and MASK
        t8 = t9 + (s ushr 32)

        // Round 6: t += a·b[6], then t = (t + m·p) / 2^32 with m = t0.
        bi = b[6]
        s = t0 + mul64(a0, bi)
        t0 = s and MASK
        c = s ushr 32
        s = t1 + mul64(a1, bi) + c
        t1 = s and MASK
        c = s ushr 32
        s = t2 + mul64(a2, bi) + c
        t2 = s and MASK
        c = s ushr 32
        s = t3 + mul64(a3, bi) + c
        t3 = s and MASK
        c = s ushr 32
        s = t4 + mul64(a4, bi) + c
        t4 = s and MASK
        c = s ushr 32
        s = t5 + mul64(a5, bi) + c
        t5 = s and MASK
        c = s ushr 32
        s = t6 + mul64(a6, bi) + c
        t6 = s and MASK
        c = s ushr 32
        s = t7 + mul64(a7, bi) + c
        t7 = s and MASK
        c = s ushr 32
        s = t8 + c
        t8 = s and MASK
        t9 = s ushr 32
        m = t0
        t0 = t1
        t1 = t2
        s = t3 + m
        t2 = s and MASK
        c = s ushr 32
        s = t4 + c
        t3 = s and MASK
        c = s ushr 32
        s = t5 + c
        t4 = s and MASK
        c = s ushr 32
        s = t6 + m + c
        t5 = s and MASK
        c = s ushr 32
        s = t7 + (m shl 32) - m + c
        t6 = s and MASK
        c = s ushr 32
        s = t8 + c
        t7 = s and MASK
        t8 = t9 + (s ushr 32)

        // Round 7: t += a·b[7], then t = (t + m·p) / 2^32 with m = t0.
        bi = b[7]
        s = t0 + mul64(a0, bi)
        t0 = s and MASK
        c = s ushr 32
        s = t1 + mul64(a1, bi) + c
        t1 = s and MASK
        c = s ushr 32
        s = t2 + mul64(a2, bi) + c
        t2 = s and MASK
        c = s ushr 32
        s = t3 + mul64(a3, bi) + c
        t3 = s and MASK
        c = s ushr 32
        s = t4 + mul64(a4, bi) + c
        t4 = s and MASK
        c = s ushr 32
        s = t5 + mul64(a5, bi) + c
        t5 = s and MASK
        c = s ushr 32
        s = t6 + mul64(a6, bi) + c
        t6 = s and MASK
        c = s ushr 32
        s = t7 + mul64(a7, bi) + c
        t7 = s and MASK
        c = s ushr 32
        s = t8 + c
        t8 = s and MASK
        t9 = s ushr 32
        m = t0
        t0 = t1
        t1 = t2
        s = t3 + m
        t2 = s and MASK
        c = s ushr 32
        s = t4 + c
        t3 = s and MASK
        c = s ushr 32
        s = t5 + c
        t4 = s and MASK
        c = s ushr 32
        s = t6 + m + c
        t5 = s and MASK
        c = s ushr 32
        s = t7 + (m shl 32) - m + c
        t6 = s and MASK
        c = s ushr 32
        s = t8 + c
        t7 = s and MASK
        t8 = t9 + (s ushr 32)

        // t < 2p: subtract p once if t >= p, that is, if t - p doesn't borrow or t has bit 256.
        var borrow = 0L
        borrow = (t0 - MASK - borrow) ushr 63
        borrow = (t1 - MASK - borrow) ushr 63
        borrow = (t2 - MASK - borrow) ushr 63
        borrow = (t3 - borrow) ushr 63
        borrow = (t4 - borrow) ushr 63
        borrow = (t5 - borrow) ushr 63
        borrow = (t6 - 1L - borrow) ushr 63
        borrow = (t7 - MASK - borrow) ushr 63
        val keep = -((1L - borrow) or t8)
        borrow = 0L
        s = t0 - (keep and MASK) - borrow
        out[0] = s and MASK
        borrow = s ushr 63
        s = t1 - (keep and MASK) - borrow
        out[1] = s and MASK
        borrow = s ushr 63
        s = t2 - (keep and MASK) - borrow
        out[2] = s and MASK
        borrow = s ushr 63
        s = t3 - borrow
        out[3] = s and MASK
        borrow = s ushr 63
        s = t4 - borrow
        out[4] = s and MASK
        borrow = s ushr 63
        s = t5 - borrow
        out[5] = s and MASK
        borrow = s ushr 63
        s = t6 - (keep and 1L) - borrow
        out[6] = s and MASK
        borrow = s ushr 63
        s = t7 - (keep and MASK) - borrow
        out[7] = s and MASK
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
        var c = 0L
        for (i in 0 until LIMBS) {
            val s = a[i] + b[i] + c
            out[i] = s and MASK
            c = s ushr 32
        }
        subtractPIfAtLeastP(out, c)
    }

    /** out = a - b mod p. [out] may be [a] or [b]. */
    fun sub(
        out: LongArray,
        a: LongArray,
        b: LongArray,
    ) {
        var borrow = 0L
        for (i in 0 until LIMBS) {
            val d = a[i] - b[i] - borrow
            out[i] = d and MASK
            borrow = d ushr 63
        }
        // Add p back exactly when it went below zero.
        val mask = -borrow
        var c = 0L
        for (i in 0 until LIMBS) {
            val s = out[i] + (P[i] and mask) + c
            out[i] = s and MASK
            c = s ushr 32
        }
    }

    /**
     * t = t - p if t (with [carry] as its bit 256) is at least p, for a t below 2p. One pass
     * finds whether t - p borrows; a second subtracts p under a mask, so no branch and no
     * scratch array.
     */
    private fun subtractPIfAtLeastP(
        t: LongArray,
        carry: Long,
    ) {
        var borrow = 0L
        for (i in 0 until LIMBS) borrow = (t[i] - P[i] - borrow) ushr 63
        // Subtract when t >= p: the subtraction didn't borrow, or t had a 257th bit.
        val keep = -((1L - borrow) or carry)
        borrow = 0L
        for (i in 0 until LIMBS) {
            val d = t[i] - (P[i] and keep) - borrow
            t[i] = d and MASK
            borrow = d ushr 63
        }
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
