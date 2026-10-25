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
package com.vitorpamplona.crypto

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The Kotlin/JS sign test that no known-answer test can see: `x.toLong() and mask` gives the
 * right bytes everywhere, but on JS its `toLong()` branches on the sign of a secret. So this
 * reads the sources that run off the JVM and fails on the pattern; widen with
 * [Int.toUnsignedLong] or [Byte.toUnsignedLong] instead. jvmAndroid is JCA's and exempt.
 */
class ConstantTimeSourceTest {
    private val widening = Regex("""\.toLong\(\)\s*and\s*(0x|\d)""")

    @Test
    fun noSignTestingWidening() {
        // Gradle runs the JVM tests in the module directory.
        val sources = File("src")
        assertTrue(sources.isDirectory, "run from the crypto module: ${sources.absolutePath}")
        val hits =
            sources
                .walkTopDown()
                .filter { it.isFile && it.extension == "kt" }
                .filter { file -> file.path.split(File.separatorChar).none { it.endsWith("Test") || it == "jvmAndroid" } }
                .flatMap { file ->
                    file.readLines().mapIndexedNotNull { i, line ->
                        val code = line.trim()
                        val comment = code.startsWith("*") || code.startsWith("//") || code.startsWith("/*")
                        if (!comment && widening.containsMatchIn(code)) "${file.path}:${i + 1}: $code" else null
                    }
                }.toList()
        if (hits.isNotEmpty()) fail("Widen with toUnsignedLong(), not toLong() and mask:\n" + hits.joinToString("\n"))
    }
}
