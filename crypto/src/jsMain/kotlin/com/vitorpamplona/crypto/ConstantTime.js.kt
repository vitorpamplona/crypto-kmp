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
package com.vitorpamplona.crypto

/**
 * The low 64 bits of `a * b` from the 32-bit halves, with no branch on the values: an [Int]
 * multiply is `Math.imul`, and the emulated [Long] operations used here (`toInt`, constant
 * shifts, `or`, and `toLong` of non-negative values) run the same steps for every input.
 *
 * With a = aHi·2^32 + aLo and b likewise, the product mod 2^64 is aLo·bLo plus the low 32
 * bits of aHi·bLo + aLo·bHi in the top half. aLo·bLo is the one full 32x32 product, built
 * from 16-bit pieces so that no partial sum overflows.
 */
internal actual fun mul64(
    a: Long,
    b: Long,
): Long {
    val aLo = a.toInt()
    val aHi = (a ushr 32).toInt()
    val bLo = b.toInt()
    val bHi = (b ushr 32).toInt()

    val a0 = aLo and 0xFFFF
    val a1 = aLo ushr 16
    val b0 = bLo and 0xFFFF
    val b1 = bLo ushr 16

    // Each 16x16 product fits in 32 unsigned bits; ushr reads it as unsigned.
    val p00 = a0 * b0
    val p01 = a0 * b1
    val p10 = a1 * b0
    val mid = (p00 ushr 16) + (p01 and 0xFFFF) + (p10 and 0xFFFF)
    val lo = (mid shl 16) or (p00 and 0xFFFF)
    val hi = a1 * b1 + (mid ushr 16) + (p01 ushr 16) + (p10 ushr 16) + aHi * bLo + aLo * bHi

    // Rebuilt from 16-bit pieces: Int.toLong() sets the top half by testing the sign, and
    // a piece is never negative, so that test always comes out the same way.
    return ((hi ushr 16).toLong() shl 48) or
        ((hi and 0xFFFF).toLong() shl 32) or
        ((lo ushr 16).toLong() shl 16) or
        (lo and 0xFFFF).toLong()
}
