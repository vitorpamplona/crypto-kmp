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
package com.vitorpamplona.crypto.benchmark

import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State

/** TweetNaCl-js: the curves only, since its symmetric side is XSalsa20-Poly1305. */
@State(Scope.Benchmark)
class TweetNacl {
    private val message1k = uint8(Inputs.message1k)
    private val x25519Private = uint8(Inputs.x25519Private)
    private val x25519Public = uint8(Inputs.x25519Public)
    private var ed25519Secret: dynamic = null
    private var ed25519Public: dynamic = null
    private var ed25519Signature: dynamic = null

    @Setup
    fun setup() {
        val pair = nacl.sign.keyPair.fromSeed(uint8(Inputs.ed25519Seed))
        ed25519Secret = pair.secretKey
        ed25519Public = pair.publicKey
        ed25519Signature = nacl.sign.detached(message1k, ed25519Secret)
    }

    @Benchmark
    fun sha512(): Any = nacl.hash(message1k)

    @Benchmark
    fun x25519PublicKey(): Any = nacl.scalarMult.base(x25519Private)

    @Benchmark
    fun x25519SharedSecret(): Any = nacl.scalarMult(x25519Private, x25519Public)

    @Benchmark
    fun ed25519Sign(): Any = nacl.sign.detached(message1k, ed25519Secret)

    @Benchmark
    fun ed25519Verify(): Boolean = nacl.sign.detached.verify(message1k, ed25519Signature, ed25519Public) as Boolean
}
