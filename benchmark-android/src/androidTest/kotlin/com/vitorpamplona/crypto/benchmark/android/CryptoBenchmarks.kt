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

import androidx.benchmark.junit4.BenchmarkRule
import androidx.benchmark.junit4.measureRepeated
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Every operation, measured for one library. The subclasses name the library, so the report reads
 * as CryptoKmpBenchmark.aesGcm1k, AndroidJcaBenchmark.aesGcm1k and so on, as :benchmark's does.
 */
abstract class CryptoBenchmark(
    private val operations: Operations,
) {
    @get:Rule
    val benchmarkRule = BenchmarkRule()

    private fun measure(operation: Operations.() -> Any?) {
        assumeTrue("not in this library on this device", operations.operation() != null)
        benchmarkRule.measureRepeated { operations.operation() }
    }

    @Test fun sha256() = measure { sha256() }

    @Test fun sha512() = measure { sha512() }

    @Test fun hmacSha256() = measure { hmacSha256() }

    @Test fun hkdfSha256() = measure { hkdfSha256() }

    @Test fun aesGcm1k() = measure { aesGcm1k() }

    @Test fun aesGcm16k() = measure { aesGcm16k() }

    @Test fun chaChaPoly1k() = measure { chaChaPoly1k() }

    @Test fun chaChaPoly16k() = measure { chaChaPoly16k() }

    @Test fun xChaChaPoly1k() = measure { xChaChaPoly1k() }

    @Test fun x25519PublicKey() = measure { x25519PublicKey() }

    @Test fun x25519SharedSecret() = measure { x25519SharedSecret() }

    @Test fun ed25519Sign() = measure { ed25519Sign() }

    @Test fun ed25519Verify() = measure { ed25519Verify() }
}

@RunWith(AndroidJUnit4::class)
class CryptoKmpBenchmark : CryptoBenchmark(CryptoKmpOperations())

@RunWith(AndroidJUnit4::class)
class AndroidJcaBenchmark : CryptoBenchmark(AndroidJcaOperations())

@RunWith(AndroidJUnit4::class)
class BouncyCastleBenchmark : CryptoBenchmark(BouncyCastleOperations())
