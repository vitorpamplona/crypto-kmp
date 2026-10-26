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

import com.vitorpamplona.crypto.sha2.Sha1Digest
import com.vitorpamplona.crypto.sha2.Sha256Digest
import com.vitorpamplona.crypto.sha2.Sha384Digest
import com.vitorpamplona.crypto.sha2.Sha512Digest
import com.vitorpamplona.crypto.sha2.ShaDigest

/** The algorithms [DigestInstance] supports: the same set, under the same names, on every platform. */
internal enum class DigestAlgorithm(
    val jcaName: String,
    private val alias: String,
) {
    SHA_1("SHA-1", "SHA1"),
    SHA_256("SHA-256", "SHA256"),
    SHA_384("SHA-384", "SHA384"),
    SHA_512("SHA-512", "SHA512"),
    RIPEMD_160("RIPEMD-160", "RIPEMD160"),
    ;

    companion object {
        /** Looks [name] up ignoring case, or throws [IllegalArgumentException]. */
        fun of(name: String): DigestAlgorithm =
            entries.firstOrNull { it.jcaName.equals(name, ignoreCase = true) || it.alias.equals(name, ignoreCase = true) }
                ?: throw IllegalArgumentException("Unsupported digest algorithm: $name. Use SHA-1, SHA-256, SHA-384, SHA-512 or RIPEMD-160.")
    }
}

/** What a [DigestInstance] drives, so each algorithm is picked once, at construction. */
internal interface StreamingDigest {
    fun update(array: ByteArray)

    fun update(byte: Byte)

    /** Returns the digest and resets for the next message, like JCA's `MessageDigest.digest()`. */
    fun digest(): ByteArray

    /** An independent digest that has seen what this one has. */
    fun copy(): StreamingDigest
}

/** The pure-Kotlin digests: all of them on Linux and the web, and whatever the platform lacks elsewhere. */
internal fun kotlinStreamingDigest(algorithm: DigestAlgorithm): StreamingDigest =
    when (algorithm) {
        DigestAlgorithm.SHA_1 -> ShaStreamingDigest(Sha1Digest())
        DigestAlgorithm.SHA_256 -> ShaStreamingDigest(Sha256Digest())
        DigestAlgorithm.SHA_384 -> ShaStreamingDigest(Sha384Digest())
        DigestAlgorithm.SHA_512 -> ShaStreamingDigest(Sha512Digest())
        DigestAlgorithm.RIPEMD_160 -> Ripemd160StreamingDigest()
    }

private class ShaStreamingDigest(
    private val sha: ShaDigest,
) : StreamingDigest {
    override fun update(array: ByteArray) = sha.update(array)

    override fun update(byte: Byte) = sha.update(byte)

    override fun digest(): ByteArray = sha.digest()

    override fun copy(): StreamingDigest = ShaStreamingDigest(sha.newInstance().also { it.copyFrom(sha) })
}

private class Ripemd160StreamingDigest(
    private val ripemd: RIPEMD160Digest = RIPEMD160Digest(),
) : StreamingDigest {
    override fun update(array: ByteArray) = ripemd.update(array, 0, array.size)

    override fun update(byte: Byte) = ripemd.update(byte)

    override fun digest(): ByteArray = ByteArray(ripemd.getDigestSize()).also { ripemd.doFinal(it, 0) }

    override fun copy(): StreamingDigest = Ripemd160StreamingDigest(RIPEMD160Digest(ripemd))
}
