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
package com.vitorpamplona.crypto.kdf

import com.vitorpamplona.crypto.mac.HmacAlgorithm
import com.vitorpamplona.crypto.mac.MacInstance

/**
 * HKDF (RFC 5869) over the HMAC named by [algorithm]: HmacSHA1, HmacSHA256, HmacSHA384 or
 * HmacSHA512. [hashLen] follows it: 20, 32, 48 or 64 bytes.
 * Any other name throws [IllegalArgumentException].
 */
public class Hkdf(
    public val algorithm: String = "HmacSHA256",
) {
    /** The HMAC's output size in bytes; [expand] produces at most `255 * hashLen` bytes. */
    public val hashLen: Int = HmacAlgorithm.of(algorithm).macLength

    public fun extract(
        key: ByteArray,
        salt: ByteArray,
    ): ByteArray {
        val mac = MacInstance(algorithm, salt)
        mac.update(key)
        return mac.doFinal()
    }

    public fun extract(
        key1: ByteArray,
        key2: ByteArray,
        salt: ByteArray,
    ): ByteArray {
        val mac = MacInstance(algorithm, salt)
        mac.update(key1)
        mac.update(key2)
        return mac.doFinal()
    }

    /**
     * General-purpose HKDF-Expand per RFC 5869 §2.3.
     *
     * `T(0) = empty; T(i) = HMAC(prk, T(i-1) || info || i)` and the output is
     * the first [length] bytes of `T(1) || T(2) || ...`. The PRK should already
     * be at least [hashLen] bytes (typically the output of [extract]).
     *
     * Output length is capped at `255 * hashLen` per RFC 5869.
     */
    public fun expand(
        prk: ByteArray,
        info: ByteArray,
        length: Int,
    ): ByteArray {
        require(length >= 0) { "negative length: $length" }
        require(length <= 255 * hashLen) { "HKDF expand length too large: $length > ${255 * hashLen}" }
        if (length == 0) return ByteArray(0)

        val mac = MacInstance(algorithm, prk)
        val out = ByteArray(length)
        // T(i): secret, reused across rounds and wiped at the end. doFinal leaves the MAC
        // keyed with prk, ready for the next round.
        val t = ByteArray(hashLen)
        var written = 0
        var counter = 1
        while (written < length) {
            if (counter > 1) mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            mac.doFinal(t, 0)
            val toCopy = minOf(hashLen, length - written)
            t.copyInto(out, written, 0, toCopy)
            written += toCopy
            counter++
        }
        t.fill(0)
        return out
    }

    /**
     * RFC 8446 §7.1 HKDF-Expand-Label.
     *
     * Builds the labeled HKDFLabel structure:
     *   uint16 length
     *   opaque label<7..255>   = "tls13 " + label
     *   opaque context<0..255> = transcript hash bytes
     * and feeds it into [expand].
     */
    public fun expandLabel(
        prk: ByteArray,
        label: String,
        context: ByteArray,
        length: Int,
    ): ByteArray {
        val labelBytes = "tls13 $label".encodeToByteArray()
        require(labelBytes.size <= 255) { "label too long: ${labelBytes.size}" }
        require(context.size <= 255) { "context too long: ${context.size}" }
        // 2 (length) + 1 (label-len) + label + 1 (context-len) + context
        val info = ByteArray(2 + 1 + labelBytes.size + 1 + context.size)
        info[0] = (length ushr 8 and 0xFF).toByte()
        info[1] = (length and 0xFF).toByte()
        info[2] = labelBytes.size.toByte()
        labelBytes.copyInto(info, 3)
        info[3 + labelBytes.size] = context.size.toByte()
        context.copyInto(info, 3 + labelBytes.size + 1)
        return expand(prk, info, length)
    }
}
