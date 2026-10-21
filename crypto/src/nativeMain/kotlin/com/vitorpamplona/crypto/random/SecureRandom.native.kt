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
package com.vitorpamplona.crypto.random

/**
 * The native [SecureRandom]: every draw is built from [fillSecureRandom], the platform's
 * entropy source, so Apple and Linux share one implementation of the rest.
 */
actual class SecureRandom actual constructor() {
    actual fun nextInt(): Int {
        val bytes = ByteArray(4)
        fillSecureRandom(bytes)
        return ((bytes[0].toInt() and 0xFF) shl 24) or
            ((bytes[1].toInt() and 0xFF) shl 16) or
            ((bytes[2].toInt() and 0xFF) shl 8) or
            (bytes[3].toInt() and 0xFF)
    }

    actual fun nextLong(): Long {
        val bytes = ByteArray(8)
        fillSecureRandom(bytes)
        return ((bytes[0].toLong() and 0xFFL) shl 56) or
            ((bytes[1].toLong() and 0xFFL) shl 48) or
            ((bytes[2].toLong() and 0xFFL) shl 40) or
            ((bytes[3].toLong() and 0xFFL) shl 32) or
            ((bytes[4].toLong() and 0xFFL) shl 24) or
            ((bytes[5].toLong() and 0xFFL) shl 16) or
            ((bytes[6].toLong() and 0xFFL) shl 8) or
            (bytes[7].toLong() and 0xFFL)
    }

    actual fun nextInt(bound: Int): Int = boundedNextInt(bound) { nextInt() }

    actual fun nextLong(bound: Long): Long = boundedNextLong(bound) { nextLong() }

    actual fun nextBytes(output: ByteArray) {
        if (output.isEmpty()) return
        fillSecureRandom(output)
    }
}

/** Fills [output] from the platform's entropy source, or throws [IllegalStateException]. */
internal expect fun fillSecureRandom(output: ByteArray)
