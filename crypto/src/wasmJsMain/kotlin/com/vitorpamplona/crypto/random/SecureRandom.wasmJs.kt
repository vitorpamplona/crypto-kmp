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
@file:OptIn(ExperimentalWasmJsInterop::class)

package com.vitorpamplona.crypto.random

/**
 * Web Crypto's `crypto.getRandomValues`, present in browsers, workers, Node.js 19+, Deno and
 * Bun. A Kotlin/Wasm [ByteArray] lives in Wasm memory, out of JavaScript's reach, so each
 * chunk of at most [MAX_GET_RANDOM_VALUES] bytes (the most one call accepts) is drawn into a
 * JavaScript `Int8Array`, copied over and wiped: the bytes may become a key.
 */
internal actual fun fillSecureRandom(output: ByteArray) {
    if (output.isEmpty()) return
    if (!hasGetRandomValues()) throw IllegalStateException("crypto.getRandomValues is not available")
    var filled = 0
    while (filled < output.size) {
        val end = minOf(output.size, filled + MAX_GET_RANDOM_VALUES)
        val chunk = randomInt8Array(end - filled)
        for (i in filled until end) output[i] = byteAt(chunk, i - filled).toByte()
        wipe(chunk)
        filled = end
    }
}

private const val MAX_GET_RANDOM_VALUES = 65536

private fun hasGetRandomValues(): Boolean = js("typeof globalThis.crypto?.getRandomValues === 'function'")

private fun randomInt8Array(size: Int): JsAny = js("globalThis.crypto.getRandomValues(new Int8Array(size))")

private fun byteAt(
    array: JsAny,
    index: Int,
): Int = js("array[index]")

private fun wipe(array: JsAny): Unit = js("{ array.fill(0); }")
