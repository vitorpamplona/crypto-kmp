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

import android.os.Build
import com.vitorpamplona.crypto.chacha.JcaChaCha20Poly1305
import com.vitorpamplona.crypto.chacha.platformChaCha20Poly1305
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

/**
 * What only a device can show: which of Android's own providers the JCA-backed primitives get.
 * The shared tests (Wycheproof among them) run here too, through those providers.
 */
class AndroidProvidersTest {
    @Test
    fun chaCha20Poly1305RunsOnBoringSslFromApi28() {
        // Android 9 added ChaCha20-Poly1305 to its platform Conscrypt; older ones keep the Kotlin code.
        if (Build.VERSION.SDK_INT >= 28) {
            assertIs<JcaChaCha20Poly1305>(platformChaCha20Poly1305)
        } else {
            assertNull(platformChaCha20Poly1305)
        }
    }

    @Test
    fun aesGcmAndCbcComeFromAndroidOpenSsl() {
        // AESGCM and AESCBC ask JCA by transformation alone. Android picks the provider at init,
        // past the Keystore's, which takes only Keystore keys: with a raw key that is BoringSSL.
        val key = SecretKeySpec(ByteArray(32), "AES")
        val gcm = Cipher.getInstance("AES/GCM/NoPadding")
        gcm.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, ByteArray(12)))
        assertEquals("AndroidOpenSSL", gcm.provider.name)
        val cbc = Cipher.getInstance("AES/CBC/NoPadding")
        cbc.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(ByteArray(16)))
        assertEquals("AndroidOpenSSL", cbc.provider.name)
    }
}
