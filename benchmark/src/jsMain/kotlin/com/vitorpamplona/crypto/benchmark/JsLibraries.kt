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
@file:Suppress("ktlint:standard:property-naming")

package com.vitorpamplona.crypto.benchmark

@JsModule("@noble/hashes/sha2.js")
@JsNonModule
external object NobleSha2 {
    fun sha256(data: dynamic): dynamic

    fun sha512(data: dynamic): dynamic
}

@JsModule("@noble/hashes/hmac.js")
@JsNonModule
external object NobleHmac {
    fun hmac(
        hash: dynamic,
        key: dynamic,
        message: dynamic,
    ): dynamic
}

@JsModule("@noble/hashes/hkdf.js")
@JsNonModule
external object NobleHkdf {
    fun hkdf(
        hash: dynamic,
        ikm: dynamic,
        salt: dynamic,
        info: dynamic,
        length: Int,
    ): dynamic
}

@JsModule("@noble/ciphers/aes.js")
@JsNonModule
external object NobleAes {
    fun gcm(
        key: dynamic,
        nonce: dynamic,
        aad: dynamic,
    ): dynamic
}

@JsModule("@noble/ciphers/chacha.js")
@JsNonModule
external object NobleChacha {
    fun chacha20poly1305(
        key: dynamic,
        nonce: dynamic,
        aad: dynamic,
    ): dynamic

    fun xchacha20poly1305(
        key: dynamic,
        nonce: dynamic,
        aad: dynamic,
    ): dynamic
}

@JsModule("@noble/curves/ed25519.js")
@JsNonModule
external object NobleEd25519 {
    val ed25519: dynamic
    val x25519: dynamic
}

@JsModule("tweetnacl")
@JsNonModule
external val nacl: dynamic

@JsModule("node:crypto")
@JsNonModule
external val nodeCrypto: dynamic

/** A Uint8Array over the same memory: noble and TweetNaCl take nothing else, and a Kotlin/JS ByteArray is an Int8Array. */
fun uint8(bytes: ByteArray): dynamic = js("new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.length)")
