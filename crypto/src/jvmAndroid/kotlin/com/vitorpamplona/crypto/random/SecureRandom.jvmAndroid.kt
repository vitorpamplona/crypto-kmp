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

import java.security.SecureRandom as JvmSecureRandom

/**
 * `java.security.SecureRandom` behind the common API. Not a typealias: the bounded
 * `nextLong` a typealias would expose comes from `java.util.random.RandomGenerator`,
 * which Android only has from API 34, so the bounded draws are computed here instead.
 */
actual class SecureRandom actual constructor() {
    private val random = JvmSecureRandom()

    actual fun nextInt(): Int = random.nextInt()

    actual fun nextLong(): Long = random.nextLong()

    actual fun nextInt(bound: Int): Int = boundedNextInt(bound) { random.nextInt() }

    actual fun nextLong(bound: Long): Long = boundedNextLong(bound) { random.nextLong() }

    actual fun nextBytes(output: ByteArray) = random.nextBytes(output)
}
