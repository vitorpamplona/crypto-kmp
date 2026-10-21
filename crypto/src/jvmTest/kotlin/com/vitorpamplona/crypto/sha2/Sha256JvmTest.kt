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

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotSame
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** The JVM-only SHA-256 helpers: [Sha256Pool], [Sha256Hasher], [sha256StreamWithCount], [CountingInputStream]. */
class Sha256JvmTest {
    private val random = Random(11)

    private fun jca(data: ByteArray) = MessageDigest.getInstance("SHA-256").digest(data)

    /** Serves [data], then throws instead of reporting the end of the stream. */
    private class FailingStream(
        data: ByteArray,
    ) : InputStream() {
        private val inner = ByteArrayInputStream(data)

        override fun read(): Int = inner.read().also { if (it == -1) throw IOException("broken") }

        override fun read(
            b: ByteArray,
            off: Int,
            len: Int,
        ): Int = inner.read(b, off, len).also { if (it == -1) throw IOException("broken") }
    }

    @Test
    fun poolHashesLikeJca() {
        val pool = Sha256Pool(2)
        for (length in listOf(0, 1, 55, 56, 64, 1000)) {
            val data = random.nextBytes(length)
            assertContentEquals(jca(data), pool.hash(data))
            assertContentEquals(jca(data), pool.hashStream(ByteArrayInputStream(data), bufferSize = 7))
            assertContentEquals(jca(data), pool.hasher { it.hash(data) })
        }
    }

    @Test
    fun releasingTwiceDoesNotBlockOrDuplicate() {
        val pool = Sha256Pool(2)
        val first = pool.acquire()
        pool.release(first)
        // Used to block forever: the queue was full again, and put() waited for room.
        pool.release(first)

        // Had the second release gone in, the pool would hand the same hasher out twice.
        val a = pool.acquire()
        val b = pool.acquire()
        assertNotSame(a, b)
        pool.release(a)
        pool.release(b)
    }

    @Test
    fun releasingAForeignHasherIsIgnored() {
        val pool = Sha256Pool(1)
        pool.release(Sha256Hasher())
        val only = pool.acquire()
        pool.release(only)
        assertSame(only, pool.acquire())
    }

    @Test
    fun releaseResetsAHalfFedHasher() {
        val pool = Sha256Pool(1)
        val hasher = pool.acquire()
        hasher.update(byteArrayOf(1, 2, 3), 0, 3)
        pool.release(hasher)
        val data = "abc".encodeToByteArray()
        assertContentEquals(jca(data), pool.hash(data))
    }

    @Test
    fun poolSharedAcrossThreads() {
        val pool = Sha256Pool(3)
        val executor = Executors.newFixedThreadPool(8)
        val inputs = List(200) { random.nextBytes(it) }
        val results = inputs.map { data -> executor.submit<Boolean> { jca(data).contentEquals(pool.hash(data)) } }
        executor.shutdown()
        assertTrue(executor.awaitTermination(30, TimeUnit.SECONDS))
        assertTrue(results.all { it.get() })
    }

    @Test
    fun hasherMatchesJca() {
        val hasher = Sha256Hasher()
        val data = random.nextBytes(300)
        assertContentEquals(jca(data), hasher.hash(data))
        assertContentEquals(jca(data), hasher.digest(data))
        hasher.update(data, 0, 100)
        hasher.update(data, 100, 200)
        assertContentEquals(jca(data), hasher.digest())
        assertContentEquals(jca(data), hasher.hashStream(ByteArrayInputStream(data), bufferSize = 64))

        hasher.update(data, 0, 10)
        hasher.reset()
        assertContentEquals(jca(ByteArray(0)), hasher.digest())
    }

    @Test
    fun hasherResetsAfterAFailedStream() {
        val hasher = Sha256Hasher()
        assertFailsWith<IOException> { hasher.hashStream(FailingStream(random.nextBytes(100))) }
        val data = "abc".encodeToByteArray()
        assertContentEquals(jca(data), hasher.hash(data))
    }

    @Test
    fun streamWithCountHashesAndCounts() {
        for (length in listOf(0, 1, 8191, 8192, 8193, 50_000)) {
            val data = random.nextBytes(length)
            val (hash, count) = sha256StreamWithCount(ByteArrayInputStream(data))
            assertContentEquals(jca(data), hash, "length $length")
            assertEquals(length.toLong(), count)
        }
        val (hash, count) = sha256StreamWithCount(ByteArrayInputStream(ByteArray(100)), bufferSize = 3)
        assertContentEquals(jca(ByteArray(100)), hash)
        assertEquals(100L, count)
    }

    @Test
    fun streamWithCountPropagatesErrorsAndLeavesTheThreadDigestClean() {
        val error = assertFailsWith<IOException> { sha256StreamWithCount(FailingStream(random.nextBytes(100))) }
        assertEquals("broken", error.message)
        // Same thread, same thread-local digest: it must not still hold the 100 bytes.
        val data = "abc".encodeToByteArray()
        assertContentEquals(jca(data), sha256(data))
        assertContentEquals(jca(data), sha256StreamWithCount(ByteArrayInputStream(data)).first)
    }

    @Test
    fun countingInputStreamCountsEveryWayOfReading() {
        val stream = CountingInputStream(ByteArrayInputStream(ByteArray(100) { it.toByte() }))
        assertEquals(0, stream.read())
        assertEquals(1L, stream.bytesRead)
        assertEquals(10, stream.read(ByteArray(10)))
        assertEquals(11L, stream.bytesRead)
        assertEquals(5, stream.read(ByteArray(20), 3, 5))
        assertEquals(16L, stream.bytesRead)
        assertEquals(4L, stream.skip(4))
        assertEquals(20L, stream.bytesRead)
        assertEquals(80, stream.readAllBytes().size)
        assertEquals(100L, stream.bytesRead)
        // End of stream counts nothing.
        assertEquals(-1, stream.read())
        assertEquals(-1, stream.read(ByteArray(4)))
        assertEquals(100L, stream.bytesRead)
    }
}
