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
package com.vitorpamplona.crypto.mac

/**
 * HMAC (RFC 2104) keyed with `key`. Supports exactly HmacSHA1, HmacSHA256 and HmacSHA512
 * on every platform, matching names ignoring case; any other name throws
 * [IllegalArgumentException]. Any key length works, including an empty key.
 *
 * Like JCA's `Mac`, [doFinal] leaves it keyed and ready for the next message.
 */
expect class MacInstance(
    algorithm: String,
    key: ByteArray,
) {
    /** Re-keys, switching to [algorithm] if it differs, and drops any message in progress. */
    fun init(
        key: ByteArray,
        algorithm: String,
    )

    fun getMacLength(): Int

    fun update(array: ByteArray)

    fun update(byte: Byte)

    fun doFinal(): ByteArray

    /**
     * Writes the MAC into [output] at [offset]. Throws [IllegalArgumentException], leaving
     * the message in progress intact, when there is no room for [getMacLength] bytes.
     */
    fun doFinal(
        output: ByteArray,
        offset: Int = 0,
    )
}
