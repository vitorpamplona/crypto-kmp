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
package com.vitorpamplona.crypto.random

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.Pinned
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.linux.SYS_getrandom
import platform.posix.EINTR
import platform.posix.ENOSYS
import platform.posix.O_CLOEXEC
import platform.posix.O_RDONLY
import platform.posix.close
import platform.posix.errno
import platform.posix.open
import platform.posix.read
import platform.posix.size_t
import platform.posix.syscall

/**
 * `getrandom(2)` with no flags: it blocks only until the kernel's pool is first seeded,
 * and after that fails only when a signal interrupts it. Called through `syscall`
 * because the glibc Kotlin/Native links against predates the `getrandom` wrapper.
 * Kernels without the call (before 3.17) fall back to reading `/dev/urandom`.
 */
@OptIn(ExperimentalForeignApi::class)
internal actual fun fillSecureRandom(output: ByteArray) {
    if (output.isEmpty()) return
    output.usePinned { pinned ->
        var filled = 0
        while (filled < output.size) {
            val result = syscall(SYS_getrandom.convert(), pinned.addressOf(filled), (output.size - filled).convert<size_t>(), 0u)
            if (result >= 0) {
                // A large request can come back short: ask again for the rest.
                filled += result.toInt()
                continue
            }
            when (val error = errno) {
                EINTR -> continue
                ENOSYS -> return readUrandom(pinned, filled, output.size)
                else -> throw IllegalStateException("getrandom failed with errno $error")
            }
        }
    }
}

/** Fills `pinned[from until to]` from `/dev/urandom`, for kernels without `getrandom`. */
@OptIn(ExperimentalForeignApi::class)
private fun readUrandom(
    pinned: Pinned<ByteArray>,
    from: Int,
    to: Int,
) {
    val fd = open("/dev/urandom", O_RDONLY or O_CLOEXEC)
    if (fd == -1) throw IllegalStateException("Failed to open /dev/urandom: errno $errno")
    try {
        var filled = from
        while (filled < to) {
            val result = read(fd, pinned.addressOf(filled), (to - filled).convert())
            when {
                result > 0 -> filled += result.toInt()
                result < 0 && errno == EINTR -> continue
                else -> throw IllegalStateException("Failed to read /dev/urandom: errno $errno")
            }
        }
    } finally {
        close(fd)
    }
}
