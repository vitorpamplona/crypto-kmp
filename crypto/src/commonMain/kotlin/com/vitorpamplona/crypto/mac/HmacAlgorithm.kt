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

import com.vitorpamplona.crypto.sha2.Sha1Digest
import com.vitorpamplona.crypto.sha2.Sha256Digest
import com.vitorpamplona.crypto.sha2.Sha384Digest
import com.vitorpamplona.crypto.sha2.Sha512Digest
import com.vitorpamplona.crypto.sha2.ShaDigest

/** The algorithms [MacInstance] supports: the same set, under the same names, on every platform. */
internal enum class HmacAlgorithm(
    val jcaName: String,
    val macLength: Int,
) {
    HMAC_SHA1("HmacSHA1", 20),
    HMAC_SHA256("HmacSHA256", 32),
    HMAC_SHA384("HmacSHA384", 48),
    HMAC_SHA512("HmacSHA512", 64),
    ;

    /** A fresh pure-Kotlin digest for the [Hmac] that Linux and the web run. */
    fun newDigest(): ShaDigest =
        when (this) {
            HMAC_SHA1 -> Sha1Digest()
            HMAC_SHA256 -> Sha256Digest()
            HMAC_SHA384 -> Sha384Digest()
            HMAC_SHA512 -> Sha512Digest()
        }

    companion object {
        /** Looks [name] up ignoring case, or throws [IllegalArgumentException]. */
        fun of(name: String): HmacAlgorithm =
            entries.firstOrNull { it.jcaName.equals(name, ignoreCase = true) }
                ?: throw IllegalArgumentException("Unsupported MAC algorithm: $name. Use HmacSHA1, HmacSHA256, HmacSHA384 or HmacSHA512.")
    }
}
