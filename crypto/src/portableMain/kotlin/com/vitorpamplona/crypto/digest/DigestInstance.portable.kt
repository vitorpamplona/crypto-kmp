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
package com.vitorpamplona.crypto.digest

public actual class DigestInstance private constructor(
    private val digest: StreamingDigest,
) {
    public actual constructor(algorithm: String) : this(kotlinStreamingDigest(DigestAlgorithm.of(algorithm)))

    public actual fun update(array: ByteArray): Unit = digest.update(array)

    public actual fun update(byte: Byte): Unit = digest.update(byte)

    public actual fun digest(): ByteArray = digest.digest()

    public actual fun digest(input: ByteArray): ByteArray {
        digest.update(input)
        return digest.digest()
    }

    public actual fun copy(): DigestInstance = DigestInstance(digest.copy())
}
