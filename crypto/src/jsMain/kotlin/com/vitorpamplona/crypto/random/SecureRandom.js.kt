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
 * Web Crypto's `crypto.getRandomValues`, present in browsers, workers, Node.js 19+, Deno and
 * Bun. A Kotlin/JS [ByteArray] is an `Int8Array`, so it fills [output] in place, through
 * views of at most [MAX_GET_RANDOM_VALUES] bytes: the most one call accepts.
 */
internal actual fun fillSecureRandom(output: ByteArray) {
    if (output.isEmpty()) return
    val crypto = webCrypto() ?: throw IllegalStateException("crypto.getRandomValues is not available")
    var filled = 0
    while (filled < output.size) {
        val end = minOf(output.size, filled + MAX_GET_RANDOM_VALUES)
        crypto.getRandomValues(output.asDynamic().subarray(filled, end).unsafeCast<ByteArray>())
        filled = end
    }
}

private const val MAX_GET_RANDOM_VALUES = 65536

private external interface WebCrypto {
    fun getRandomValues(array: ByteArray): ByteArray
}

private fun webCrypto(): WebCrypto? {
    val crypto: dynamic = js("globalThis.crypto")
    if (crypto == null || jsTypeOf(crypto.getRandomValues) != "function") return null
    return crypto.unsafeCast<WebCrypto>()
}
