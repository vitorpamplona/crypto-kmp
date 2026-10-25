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

/**
 * An incremental message digest. Supports exactly SHA-1, SHA-256, SHA-384, SHA-512 and
 * RIPEMD-160, on every platform. Names match ignoring case, with or without the dash
 * (`SHA-256`, `sha256`, `RIPEMD-160`, `ripemd160`); any other name throws
 * [IllegalArgumentException].
 *
 * [digest] returns the hash and resets, ready for the next message. [copy] snapshots the state
 * without finishing it, as a TLS transcript hash needs: the digest of the messages so far, while
 * the original carries on.
 */
public expect class DigestInstance(
    algorithm: String,
) {
    public fun update(array: ByteArray)

    public fun update(byte: Byte)

    public fun digest(): ByteArray

    public fun digest(input: ByteArray): ByteArray

    /**
     * A new, independent [DigestInstance] of the same algorithm that has seen everything this one
     * has: updating or finishing either one leaves the other as it was.
     */
    public fun copy(): DigestInstance
}
