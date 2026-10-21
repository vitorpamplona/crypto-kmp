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
package com.vitorpamplona.crypto.chacha

/*
 * The limb layout, multiply and final reduction follow the 32-bit poly1305-donna
 * (poly1305-donna-32.h, https://github.com/floodyberry/poly1305-donna) by Andrew Moon,
 * released into the public domain or, where that is not recognised, under the MIT license.
 */

/**
 * Pure Kotlin implementation of Poly1305 one-time authenticator (RFC 8439 §2.5).
 *
 * Uses 130-bit arithmetic with 5 limbs of 26 bits each, following Andrew Moon's
 * poly1305-donna-32. The final reduction and the choice between h and h - p are masked,
 * not branched. All functions are stateless and thread-safe.
 *
 * The 32-byte key is split into:
 * - r (first 16 bytes): clamped per spec, used as the multiplier
 * - s (last 16 bytes): added at the end
 */
object Poly1305 {
    /**
     * Compute a 16-byte Poly1305 MAC.
     *
     * @param message the data to authenticate
     * @param key 32-byte one-time key (r || s)
     * @return 16-byte authentication tag
     * @throws IllegalArgumentException if [key] is not 32 bytes
     */
    fun mac(
        message: ByteArray,
        key: ByteArray,
    ): ByteArray {
        val state = Poly1305State(key)
        state.update(message)
        return state.finish()
    }
}

/**
 * Incremental Poly1305: [update] as often as needed, then [finish] once. [finish] wipes the
 * key and the accumulator, so a state makes one tag.
 */
internal class Poly1305State(
    key: ByteArray,
) {
    // Clamped r, and 5*r for the reduction step
    private var r0: Long
    private var r1: Long
    private var r2: Long
    private var r3: Long
    private var r4: Long
    private var s1: Long
    private var s2: Long
    private var s3: Long
    private var s4: Long

    // s, the second half of the key
    private var pad0: Long
    private var pad1: Long
    private var pad2: Long
    private var pad3: Long

    // Accumulator: 5 limbs of 26 bits
    private var h0 = 0L
    private var h1 = 0L
    private var h2 = 0L
    private var h3 = 0L
    private var h4 = 0L

    // A partial block waiting for more input
    private val buffer = ByteArray(16)
    private var buffered = 0

    init {
        require(key.size == 32) { "Poly1305 key must be 32 bytes, was ${key.size}" }
        r0 = (key.littleEndianToLong(0)) and 0x3ffffff
        r1 = (key.littleEndianToLong(3) ushr 2) and 0x3ffff03
        r2 = (key.littleEndianToLong(6) ushr 4) and 0x3ffc0ff
        r3 = (key.littleEndianToLong(9) ushr 6) and 0x3f03fff
        r4 = (key.littleEndianToLong(12) ushr 8) and 0x00fffff
        s1 = r1 * 5
        s2 = r2 * 5
        s3 = r3 * 5
        s4 = r4 * 5
        pad0 = key.littleEndianToLong(16)
        pad1 = key.littleEndianToLong(20)
        pad2 = key.littleEndianToLong(24)
        pad3 = key.littleEndianToLong(28)
    }

    fun update(
        data: ByteArray,
        offset: Int = 0,
        length: Int = data.size - offset,
    ) {
        var pos = offset
        var remaining = length
        if (buffered > 0) {
            val take = minOf(16 - buffered, remaining)
            data.copyInto(buffer, buffered, pos, pos + take)
            buffered += take
            pos += take
            remaining -= take
            if (buffered < 16) return
            block(buffer, 0, FULL_BLOCK)
            buffered = 0
        }
        while (remaining >= 16) {
            block(data, pos, FULL_BLOCK)
            pos += 16
            remaining -= 16
        }
        if (remaining > 0) {
            data.copyInto(buffer, 0, pos, pos + remaining)
            buffered = remaining
        }
    }

    /** Zero-pads the input so far to a multiple of 16 bytes: RFC 8439's pad16. */
    fun padToBlock() {
        if (buffered == 0) return
        buffer.fill(0, buffered, 16)
        block(buffer, 0, FULL_BLOCK)
        buffered = 0
    }

    /** Returns the 16-byte tag and wipes the state. */
    fun finish(): ByteArray {
        // Process remaining bytes (if any): pad with 0x01, and no 2^128 bit
        if (buffered > 0) {
            buffer[buffered] = 1
            buffer.fill(0, buffered + 1, 16)
            block(buffer, 0, 0L)
        }

        // Final reduction: fully carry and reduce mod 2^130 - 5
        var c: Long
        c = h1 ushr 26
        h1 = h1 and 0x3ffffff
        h2 += c
        c = h2 ushr 26
        h2 = h2 and 0x3ffffff
        h3 += c
        c = h3 ushr 26
        h3 = h3 and 0x3ffffff
        h4 += c
        c = h4 ushr 26
        h4 = h4 and 0x3ffffff
        h0 += c * 5
        c = h0 ushr 26
        h0 = h0 and 0x3ffffff
        h1 += c

        // Compute h + -(2^130 - 5) = h - 2^130 + 5
        var g0 = h0 + 5
        c = g0 ushr 26
        g0 = g0 and 0x3ffffff
        var g1 = h1 + c
        c = g1 ushr 26
        g1 = g1 and 0x3ffffff
        var g2 = h2 + c
        c = g2 ushr 26
        g2 = g2 and 0x3ffffff
        var g3 = h3 + c
        c = g3 ushr 26
        g3 = g3 and 0x3ffffff
        var g4 = h4 + c - (1L shl 26)

        // Select h if g4 is negative (bit 63 set), else select g
        val mask = (g4 ushr 63) - 1 // 0 if h, all-ones if g
        g0 = g0 and mask
        g1 = g1 and mask
        g2 = g2 and mask
        g3 = g3 and mask
        g4 = g4 and mask
        val nmask = mask.inv()
        h0 = (h0 and nmask) or g0
        h1 = (h1 and nmask) or g1
        h2 = (h2 and nmask) or g2
        h3 = (h3 and nmask) or g3
        h4 = (h4 and nmask) or g4

        // Assemble h into 4 32-bit words
        var f0 = ((h0) or (h1 shl 26)) and 0xffffffffL
        var f1 = ((h1 ushr 6) or (h2 shl 20)) and 0xffffffffL
        var f2 = ((h2 ushr 12) or (h3 shl 14)) and 0xffffffffL
        var f3 = ((h3 ushr 18) or (h4 shl 8)) and 0xffffffffL

        // Add s (second half of the key)
        f0 += pad0
        c = f0 ushr 32
        f1 += pad1 + c
        c = f1 ushr 32
        f2 += pad2 + c
        c = f2 ushr 32
        f3 += pad3 + c

        // Output as little-endian bytes
        val tag = ByteArray(16)
        f0.toInt().intToLittleEndian(tag, 0)
        f1.toInt().intToLittleEndian(tag, 4)
        f2.toInt().intToLittleEndian(tag, 8)
        f3.toInt().intToLittleEndian(tag, 12)

        wipe()
        return tag
    }

    /** Absorbs the 16 bytes at [offset]; [hibit] is the 2^128 bit, as it sits in limb 4. */
    private fun block(
        message: ByteArray,
        offset: Int,
        hibit: Long,
    ) {
        h0 += (message.littleEndianToLong(offset)) and 0x3ffffff
        h1 += (message.littleEndianToLong(offset + 3) ushr 2) and 0x3ffffff
        h2 += (message.littleEndianToLong(offset + 6) ushr 4) and 0x3ffffff
        h3 += (message.littleEndianToLong(offset + 9) ushr 6) and 0x3ffffff
        h4 += (message.littleEndianToLong(offset + 12) ushr 8) or hibit

        // Multiply and reduce
        val d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
        val d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
        val d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
        val d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
        val d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

        // Partial reduction mod 2^130 - 5
        var c: Long
        c = d0 ushr 26
        h0 = d0 and 0x3ffffff
        h1 = d1 + c
        c = h1 ushr 26
        h1 = h1 and 0x3ffffff
        h2 = d2 + c
        c = h2 ushr 26
        h2 = h2 and 0x3ffffff
        h3 = d3 + c
        c = h3 ushr 26
        h3 = h3 and 0x3ffffff
        h4 = d4 + c
        c = h4 ushr 26
        h4 = h4 and 0x3ffffff
        h0 += c * 5
        c = h0 ushr 26
        h0 = h0 and 0x3ffffff
        h1 += c
    }

    private fun wipe() {
        r0 = 0
        r1 = 0
        r2 = 0
        r3 = 0
        r4 = 0
        s1 = 0
        s2 = 0
        s3 = 0
        s4 = 0
        pad0 = 0
        pad1 = 0
        pad2 = 0
        pad3 = 0
        h0 = 0
        h1 = 0
        h2 = 0
        h3 = 0
        h4 = 0
        buffer.fill(0)
        buffered = 0
    }

    private companion object {
        /** The 2^128 bit every full 16-byte block carries (RFC 8439 §2.5.1), in limb 4. */
        const val FULL_BLOCK = 1L shl 24
    }
}

/** Read 4 bytes as unsigned little-endian Long starting at [offset]. */
private fun ByteArray.littleEndianToLong(offset: Int): Long =
    (this[offset].toLong() and 0xFF) or
        ((this[offset + 1].toLong() and 0xFF) shl 8) or
        ((this[offset + 2].toLong() and 0xFF) shl 16) or
        ((this[offset + 3].toLong() and 0xFF) shl 24)
