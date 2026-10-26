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
package com.vitorpamplona.crypto.chacha

import java.security.GeneralSecurityException
import java.security.Provider
import java.security.Security
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal actual val platformChaCha20Poly1305: ChaCha20Poly1305Backend? = JcaChaCha20Poly1305.find()

/**
 * JCA's ChaCha20-Poly1305 from one named [provider], never whichever is registered first: an
 * app that puts Bouncy Castle at the front would otherwise get an AEAD twice as slow as the
 * Kotlin one. A fresh [Cipher] per call, as in AESGCM: SunJCE refuses to re-init one for
 * encryption under its previous key and nonce.
 */
internal class JcaChaCha20Poly1305(
    private val transformation: String,
    private val provider: Provider,
) : ChaCha20Poly1305Backend {
    override fun seal(
        plaintext: ByteArray,
        ad: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): ByteArray = cipher(Cipher.ENCRYPT_MODE, ad, nonce, key).doFinal(plaintext)

    override fun open(
        ciphertextWithTag: ByteArray,
        ad: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): ByteArray? =
        try {
            cipher(Cipher.DECRYPT_MODE, ad, nonce, key).doFinal(ciphertextWithTag)
        } catch (e: AEADBadTagException) {
            null
        }

    private fun cipher(
        mode: Int,
        ad: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): Cipher =
        Cipher.getInstance(transformation, provider).apply {
            init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            updateAAD(ad)
        }

    /**
     * Whether this provider gives the Kotlin implementation's bytes, opens its own output and
     * rejects a changed tag: checked once, before anything relies on it, so a missing or
     * broken provider falls back to Kotlin instead of failing or diverging per call.
     */
    private fun agreesWithKotlin(): Boolean {
        val key = ByteArray(32) { (it * 3 + 1).toByte() }
        val nonce = ByteArray(12) { (it + 7).toByte() }
        val ad = ByteArray(13) { (it * 5).toByte() }
        val plaintext = ByteArray(70) { (it * 11).toByte() }
        val sealed = seal(plaintext, ad, nonce, key)
        if (!sealed.contentEquals(ChaCha20Poly1305.kotlinSeal(plaintext, ad, nonce, key))) return false
        if (open(sealed, ad, nonce, key)?.contentEquals(plaintext) != true) return false
        sealed[sealed.size - 1] = (sealed[sealed.size - 1].toInt() xor 1).toByte()
        return open(sealed, ad, nonce, key) == null
    }

    companion object {
        /**
         * The providers worth calling, by how they compare with the Kotlin implementation:
         * BoringSSL in C for Android's platform Conscrypt (AndroidOpenSSL, API 28+) and for a
         * bundled Conscrypt, at any size; SunJCE only when HotSpot compiles both ChaCha20 and
         * Poly1305 to vector instructions (JDK 20+ on a CPU that has them). Without both, SunJCE
         * is pure Java and slower than the Kotlin code: 1.3-1.8x at 1 KiB, as on Java 17.
         */
        private val CANDIDATES =
            listOf(
                Triple("ChaCha20/Poly1305/NoPadding", "AndroidOpenSSL") { true },
                Triple("ChaCha20/Poly1305/NoPadding", "Conscrypt") { true },
                Triple("ChaCha20-Poly1305", "SunJCE") { hotSpotFlag("UseChaCha20Intrinsics") && hotSpotFlag("UsePoly1305Intrinsics") },
            )

        /** The first candidate that is present, worth it, and passes [agreesWithKotlin]; else null. */
        fun find(): JcaChaCha20Poly1305? =
            CANDIDATES.firstNotNullOfOrNull { (transformation, providerName, worthIt) ->
                val provider = Security.getProvider(providerName) ?: return@firstNotNullOfOrNull null
                try {
                    if (!worthIt()) return@firstNotNullOfOrNull null
                    JcaChaCha20Poly1305(transformation, provider).takeIf { it.agreesWithKotlin() }
                } catch (e: GeneralSecurityException) {
                    null
                } catch (e: RuntimeException) {
                    // A provider that throws ProviderException or the like: not one to rely on.
                    null
                }
            }

        /**
         * Whether a boolean HotSpot flag is on, through com.sun.management by reflection: this
         * source set compiles for Android too, which has no java.lang.management. False on any
         * JVM that lacks the bean or the flag (Java 19 and older have neither intrinsic).
         */
        internal fun hotSpotFlag(name: String): Boolean =
            try {
                val bean =
                    Class
                        .forName("java.lang.management.ManagementFactory")
                        .getMethod("getPlatformMXBean", Class::class.java)
                        .invoke(null, Class.forName("com.sun.management.HotSpotDiagnosticMXBean"))
                val option =
                    Class
                        .forName("com.sun.management.HotSpotDiagnosticMXBean")
                        .getMethod("getVMOption", String::class.java)
                        .invoke(bean, name)
                Class.forName("com.sun.management.VMOption").getMethod("getValue").invoke(option) == "true"
            } catch (e: Exception) {
                false
            } catch (e: LinkageError) {
                false
            }
    }
}
