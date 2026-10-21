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
package com.vitorpamplona.crypto.sha2

import java.io.InputStream
import java.security.MessageDigest

/**
 * Thread-local MessageDigest for lock-free SHA256 hashing.
 *
 * The previous ArrayBlockingQueue pool added ~10µs of synchronization overhead per call
 * (lock acquire + release) for ~2µs of actual hashing. ThreadLocal eliminates all locking
 * since each thread gets its own MessageDigest instance. digest() implicitly resets state,
 * and every path that can fail halfway resets it explicitly, so a digest is never handed
 * to the next caller on the thread with data already in it.
 */
private val threadLocalDigest: ThreadLocal<MessageDigest> =
    ThreadLocal.withInitial {
        MessageDigest.getInstance("SHA-256")
    }

public actual fun sha256(data: ByteArray): ByteArray = threadLocalDigest.get()!!.digest(data)

public actual fun sha256Into(
    out: ByteArray,
    data: ByteArray,
    len: Int,
): ByteArray {
    // Checked before the digest sees any data: with these in range, neither call below can
    // throw, so a failure never leaves the thread's digest half-fed.
    checkSha256IntoArgs(out, data, len)
    val md = threadLocalDigest.get()!!
    md.update(data, 0, len)
    md.digest(out, 0, 32)
    return out
}

/**
 * Calculate SHA256 hash while counting bytes read from the stream.
 * Returns both the hash and the number of bytes processed.
 * This is more efficient than reading the stream twice.
 *
 * Errors from the stream propagate unchanged; the digest is reset either way.
 *
 * @param inputStream The input stream to hash
 * @param bufferSize Size of chunks to read (default 8KB)
 * @return Pair of (hash bytes, bytes read count)
 */
public fun sha256StreamWithCount(
    inputStream: InputStream,
    bufferSize: Int = 8192,
): Pair<ByteArray, Long> {
    val countingStream = CountingInputStream(inputStream)
    val digest = threadLocalDigest.get()!!
    try {
        val buffer = ByteArray(bufferSize)
        var bytesRead: Int
        while (countingStream.read(buffer).also { bytesRead = it } != -1) {
            digest.update(buffer, 0, bytesRead)
        }
        return Pair(digest.digest(), countingStream.bytesRead)
    } finally {
        // digest() already reset it on success; this covers a stream that threw halfway.
        digest.reset()
    }
}
