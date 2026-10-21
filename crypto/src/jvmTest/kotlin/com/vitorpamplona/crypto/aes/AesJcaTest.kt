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
package com.vitorpamplona.crypto.aes

import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The pure-Kotlin AES-GCM and AES-CBC the native targets run, and the public classes, against
 * JCA on random keys of every size, nonces from 1 to 64 bytes and lengths across the block and
 * four-block batch boundaries.
 */
class AesJcaTest {
    private val random = Random(2026)
    private val keySizes = intArrayOf(16, 24, 32)

    private fun jcaGcm(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(aad)
            doFinal(plaintext)
        }

    private fun jcaCbc(
        transformation: String,
        key: ByteArray,
        iv: ByteArray,
        plaintext: ByteArray,
    ): ByteArray =
        Cipher.getInstance(transformation).run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            doFinal(plaintext)
        }

    @Test
    fun gcmMatchesJca() {
        repeat(400) { round ->
            val key = random.nextBytes(keySizes[round % 3])
            val nonce = random.nextBytes(if (round % 2 == 0) 12 else random.nextInt(1, 65))
            val plaintext = random.nextBytes(random.nextInt(0, 300))
            val aad = random.nextBytes(random.nextInt(0, 40))
            val jca = jcaGcm(key, nonce, plaintext, aad)
            val label = "round $round"
            val gcm = AesGcmKey(key)
            assertContentEquals(jca, gcm.encrypt(nonce, plaintext, aad), label)
            assertContentEquals(plaintext, gcm.decrypt(nonce, jca, aad), label)
        }
    }

    @Test
    fun gcmWithTheDefault16ByteNonceMatchesJca() {
        repeat(100) { round ->
            val cipher = AESGCM(random.nextBytes(keySizes[round % 3]))
            assertEquals(16, cipher.nonce.size)
            val plaintext = random.nextBytes(random.nextInt(0, 100))
            val aad = random.nextBytes(random.nextInt(0, 40))
            val jca = jcaGcm(cipher.keyBytes, cipher.nonce, plaintext, aad)
            val label = "round $round"
            assertContentEquals(jca, AesGcmKey(cipher.keyBytes).encrypt(cipher.nonce, plaintext, aad), label)
            assertContentEquals(jca, cipher.encrypt(plaintext, aad), label)
        }
    }

    @Test
    fun gcmCounterWrapMatchesJcaBlocks() {
        // CTR from a J0 whose low word is 0xFFFFFFFD, with JCA's raw AES making the keystream:
        // the counter must wrap to 0 in the last four bytes and leave the first twelve alone.
        val key = random.nextBytes(32)
        val prefix = random.nextBytes(12)
        val j0 = prefix + byteArrayOf(-1, -1, -1, -3)
        val plaintext = random.nextBytes(16 * 9 + 5)
        val ecb = Cipher.getInstance("AES/ECB/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES")) }
        val expected = ByteArray(plaintext.size)
        var counter = -3
        for (o in plaintext.indices step 16) {
            counter++
            val block = prefix + byteArrayOf((counter ushr 24).toByte(), (counter ushr 16).toByte(), (counter ushr 8).toByte(), counter.toByte())
            val keystream = ecb.doFinal(block)
            for (i in o until minOf(o + 16, plaintext.size)) {
                expected[i] = (plaintext[i].toInt() xor keystream[i - o].toInt()).toByte()
            }
        }
        val sealed = AesGcmKey(key).encryptFromJ0(j0, plaintext, ByteArray(0))
        assertContentEquals(expected, sealed.copyOf(plaintext.size))
    }

    @Test
    fun cbcMatchesJca() {
        repeat(400) { round ->
            val key = random.nextBytes(keySizes[round % 3])
            val iv = random.nextBytes(16)
            val plaintext = random.nextBytes(random.nextInt(0, 300))
            val blocks = plaintext.copyOf(plaintext.size / 16 * 16)
            val label = "round $round"

            val raw = jcaCbc("AES/CBC/NoPadding", key, iv, blocks)
            val cbc = AesCbcKey(key)
            assertContentEquals(raw, cbc.encrypt(iv, blocks), label)
            assertContentEquals(blocks, cbc.decrypt(iv, raw), label)

            // The common padding, on the Kotlin core (as on Linux) and on JCA (the public class).
            val padded = jcaCbc("AES/CBC/PKCS5Padding", key, iv, plaintext)
            assertContentEquals(padded, cbcEncrypt(plaintext) { cbc.encrypt(iv, it) }, label)
            assertContentEquals(plaintext, cbcDecrypt(padded) { cbc.decrypt(iv, it) }, label)
            val cipher = AESCBC(key, iv)
            assertContentEquals(padded, cipher.encrypt(plaintext), label)
            assertContentEquals(plaintext, cipher.decrypt(padded), label)
        }
    }

    @Test
    fun gcmNonceGuardAdmitsOneEncryptionAcrossThreads() {
        val threads = 16
        val pool = Executors.newFixedThreadPool(threads)
        try {
            repeat(20) {
                val cipher = AESGCM(random.nextBytes(32), random.nextBytes(12))
                val barrier = CyclicBarrier(threads)
                val successes = AtomicInteger()
                val refusals = AtomicInteger()
                val tasks =
                    List(threads) {
                        pool.submit {
                            barrier.await()
                            try {
                                cipher.encrypt(ByteArray(16))
                                successes.incrementAndGet()
                            } catch (_: IllegalStateException) {
                                refusals.incrementAndGet()
                            }
                        }
                    }
                tasks.forEach { it.get(10, TimeUnit.SECONDS) }
                assertEquals(1, successes.get())
                assertEquals(threads - 1, refusals.get())
            }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun jcaFailuresSurfaceAsIllegalArgumentWithTheCause() {
        val cipher = AESGCM(random.nextBytes(32), random.nextBytes(12))
        val sealed = cipher.encrypt(random.nextBytes(32))
        sealed[0] = (sealed[0].toInt() xor 1).toByte()
        val error = runCatching { cipher.decrypt(sealed) }.exceptionOrNull()
        assertTrue(error is IllegalArgumentException, "was $error")
        assertTrue(error.cause is AEADBadTagException, "cause was ${error.cause}")
    }
}
