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

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/** SHA-1 and SHA-2 on JCA; RIPEMD-160, which the default JDK providers lack, in Kotlin. */
actual class DigestInstance actual constructor(
    algorithm: String,
) {
    private val digest: StreamingDigest =
        when (val known = DigestAlgorithm.of(algorithm)) {
            DigestAlgorithm.RIPEMD_160 -> kotlinStreamingDigest(known)
            else -> JcaStreamingDigest(known.jcaName)
        }

    actual fun update(array: ByteArray) = digest.update(array)

    actual fun update(byte: Byte) = digest.update(byte)

    actual fun digest(): ByteArray = digest.digest()

    actual fun digest(input: ByteArray): ByteArray {
        digest.update(input)
        return digest.digest()
    }
}

private class JcaStreamingDigest(
    jcaName: String,
) : StreamingDigest {
    private val md =
        try {
            MessageDigest.getInstance(jcaName)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalArgumentException("Unsupported digest algorithm: $jcaName", e)
        }

    override fun update(array: ByteArray) = md.update(array)

    override fun update(byte: Byte) = md.update(byte)

    override fun digest(): ByteArray = md.digest()
}
