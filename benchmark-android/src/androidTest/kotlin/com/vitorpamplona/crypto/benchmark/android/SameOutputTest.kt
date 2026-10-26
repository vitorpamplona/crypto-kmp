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
package com.vitorpamplona.crypto.benchmark.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Every library computes this library's bytes for each operation it has, on this device, so the
 * benchmarks compare the same work. Fresh instances per check keep the nonce counters together.
 */
@RunWith(AndroidJUnit4::class)
class SameOutputTest {
    private val others = listOf("Android JCA" to ::AndroidJcaOperations, "Bouncy Castle" to ::BouncyCastleOperations)

    private fun same(operation: Operations.() -> Any?) {
        val expected = CryptoKmpOperations().operation()
        for ((name, other) in others) {
            val actual = other().operation() ?: continue
            when (expected) {
                is ByteArray -> assertContentEquals(expected, actual as ByteArray, name)
                else -> assertEquals(expected, actual, name)
            }
        }
    }

    @Test
    fun hashesAndMacs() {
        same { sha256() }
        same { sha512() }
        same { hmacSha256() }
        same { hkdfSha256() }
    }

    @Test
    fun aeads() {
        same { aesGcm1k() }
        same { aesGcm16k() }
        same { chaChaPoly1k() }
        same { chaChaPoly16k() }
    }

    @Test
    fun curves() {
        same { x25519PublicKey() }
        same { x25519SharedSecret() }
        same { p256PublicKey() }
        same { p256SharedSecret() }
        same { ed25519Sign() }
        same { ed25519Verify() }
    }
}
