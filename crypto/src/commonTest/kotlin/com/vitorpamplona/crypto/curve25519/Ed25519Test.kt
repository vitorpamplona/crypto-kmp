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
package com.vitorpamplona.crypto.curve25519

import com.vitorpamplona.crypto.hexToByteArray
import com.vitorpamplona.crypto.toHexKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Ed25519 key derivation, signing and verification: the RFC 8032 §7.1 vectors
 * (checked against JCA), round trips, and the regression for signing with a
 * tampered public half. jvmTest also compares the whole API with JCA on random
 * keys and messages.
 */
class Ed25519Test {
    private class Rfc8032Vector(
        val seed: String,
        val publicKey: String,
        val message: String,
        val signature: String,
    )

    private val rfc8032 =
        listOf(
            // RFC 8032 §7.1, TEST 1
            Rfc8032Vector(
                seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                publicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                message = "",
                signature = (
                    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
                        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
                ),
            ),
            // RFC 8032 §7.1, TEST 2
            Rfc8032Vector(
                seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                publicKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                message = "72",
                signature = (
                    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
                        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
                ),
            ),
            // RFC 8032 §7.1, TEST 3
            Rfc8032Vector(
                seed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                publicKey = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                message = "af82",
                signature = (
                    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
                        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
                ),
            ),
            // RFC 8032 §7.1, TEST 1024
            Rfc8032Vector(
                seed = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
                publicKey = "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
                message = (
                    "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98" +
                        "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8" +
                        "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d" +
                        "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc" +
                        "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe" +
                        "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e" +
                        "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef" +
                        "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7" +
                        "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1" +
                        "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2" +
                        "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24" +
                        "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270" +
                        "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc" +
                        "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07" +
                        "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba" +
                        "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a" +
                        "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e" +
                        "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7" +
                        "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c" +
                        "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8" +
                        "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df" +
                        "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08" +
                        "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649" +
                        "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4" +
                        "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3" +
                        "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e" +
                        "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f" +
                        "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5" +
                        "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1" +
                        "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d" +
                        "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c" +
                        "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
                ),
                signature = (
                    "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350" +
                        "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
                ),
            ),
            // RFC 8032 §7.1, TEST SHA(abc)
            Rfc8032Vector(
                seed = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                publicKey = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                message = (
                    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
                        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                ),
                signature = (
                    "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589" +
                        "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
                ),
            ),
        )

    @Test
    fun rfc8032PublicKeys() {
        for (v in rfc8032) {
            val kp = Ed25519.keyPairFromSeed(v.seed.hexToByteArray())
            assertEquals(v.publicKey, kp.publicKey.toHexKey())
            assertEquals(v.seed + v.publicKey, kp.privateKey.toHexKey())
            assertEquals(v.publicKey, Ed25519.publicFromPrivate(kp.privateKey).toHexKey())
        }
    }

    @Test
    fun rfc8032Signatures() {
        for (v in rfc8032) {
            val message = v.message.hexToByteArray()
            val privateKey = (v.seed + v.publicKey).hexToByteArray()
            assertEquals(v.signature, Ed25519.sign(message, privateKey).toHexKey())
            assertTrue(Ed25519.verify(message, v.signature.hexToByteArray(), v.publicKey.hexToByteArray()))
        }
    }

    @Test
    fun signIgnoresATamperedPublicHalf() {
        // Signing one message under seed||A and seed||A' would reveal the secret
        // scalar if A' reached the challenge hash. sign() must derive A itself.
        val v = rfc8032[2]
        val seed = v.seed.hexToByteArray()
        val message = v.message.hexToByteArray()
        val genuine = Ed25519.sign(message, seed + v.publicKey.hexToByteArray())
        for (otherHalf in listOf(ByteArray(32), Ed25519.keyPairFromSeed(ByteArray(32) { 7 }).publicKey)) {
            val tampered = seed + otherHalf
            assertContentEquals(genuine, Ed25519.sign(message, tampered))
            assertEquals(v.signature, Ed25519.sign(message, tampered).toHexKey())
            assertEquals(v.publicKey, Ed25519.publicFromPrivate(tampered).toHexKey())
        }
    }

    @Test
    fun testKeyPairGeneration() {
        val kp = Ed25519.generateKeyPair()
        assertEquals(64, kp.privateKey.size, "Private key should be 64 bytes (seed + public)")
        assertEquals(32, kp.publicKey.size, "Public key should be 32 bytes")
    }

    @Test
    fun testPublicFromPrivate() {
        val kp = Ed25519.generateKeyPair()
        val derived = Ed25519.publicFromPrivate(kp.privateKey)
        assertContentEquals(kp.publicKey, derived)
    }

    @Test
    fun testSignAndVerify() {
        val kp = Ed25519.generateKeyPair()
        val message = "Hello, world!".encodeToByteArray()

        val signature = Ed25519.sign(message, kp.privateKey)
        assertEquals(64, signature.size, "Ed25519 signature should be 64 bytes")

        assertTrue(Ed25519.verify(message, signature, kp.publicKey), "Signature should verify")
    }

    @Test
    fun testSignatureFailsWithWrongKey() {
        val kp1 = Ed25519.generateKeyPair()
        val kp2 = Ed25519.generateKeyPair()
        val message = "Hello, world!".encodeToByteArray()

        val signature = Ed25519.sign(message, kp1.privateKey)

        assertFalse(Ed25519.verify(message, signature, kp2.publicKey), "Signature should not verify with wrong key")
    }

    @Test
    fun testSignatureFailsWithWrongMessage() {
        val kp = Ed25519.generateKeyPair()
        val message = "Hello, world!".encodeToByteArray()
        val wrongMessage = "Hello Wrong!".encodeToByteArray()

        val signature = Ed25519.sign(message, kp.privateKey)

        assertFalse(Ed25519.verify(wrongMessage, signature, kp.publicKey), "Signature should not verify with wrong message")
    }

    @Test
    fun testDeterministicSignatures() {
        val kp = Ed25519.generateKeyPair()
        val message = "Deterministic test".encodeToByteArray()

        val sig1 = Ed25519.sign(message, kp.privateKey)
        val sig2 = Ed25519.sign(message, kp.privateKey)

        // Ed25519 signatures are deterministic (RFC 8032)
        assertContentEquals(sig1, sig2)
    }

    @Test
    fun testEmptyMessage() {
        val kp = Ed25519.generateKeyPair()
        val message = ByteArray(0)

        val signature = Ed25519.sign(message, kp.privateKey)
        assertTrue(Ed25519.verify(message, signature, kp.publicKey))
    }

    @Test
    fun testLargeMessage() {
        val kp = Ed25519.generateKeyPair()
        val message = ByteArray(10000) { it.toByte() }

        val signature = Ed25519.sign(message, kp.privateKey)
        assertTrue(Ed25519.verify(message, signature, kp.publicKey))
    }

    @Test
    fun keyPairFromSeedSignsLikeTheGeneratedPair() {
        val generated = Ed25519.generateKeyPair()
        val rebuilt = Ed25519.keyPairFromSeed(generated.privateKey.copyOfRange(0, 32))
        assertEquals(generated, rebuilt)
        val msg = "hi".encodeToByteArray()
        assertTrue(Ed25519.verify(msg, Ed25519.sign(msg, rebuilt.privateKey), generated.publicKey))
    }

    // --- Rejections ---

    /** L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
    private val groupOrder = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010".hexToByteArray()

    /** Little-endian a + b over 32 bytes, dropping the final carry. */
    private fun add256(
        a: ByteArray,
        b: ByteArray,
    ): ByteArray {
        val out = ByteArray(32)
        var carry = 0
        for (i in 0 until 32) {
            val sum = (a[i].toInt() and 0xFF) + (b[i].toInt() and 0xFF) + carry
            out[i] = sum.toByte()
            carry = sum shr 8
        }
        return out
    }

    @Test
    fun rejectsSEqualToL() {
        val v = rfc8032[0]
        val signature = v.signature.hexToByteArray()
        groupOrder.copyInto(signature, 32)
        assertFalse(Ed25519.verify(v.message.hexToByteArray(), signature, v.publicKey.hexToByteArray()))
    }

    @Test
    fun rejectsSPlusL() {
        // [S + L]B = [S]B, so S + L satisfies the verification equation. Only
        // the S < L check stops this second signature for the same message.
        for (v in rfc8032) {
            val signature = v.signature.hexToByteArray()
            add256(signature.copyOfRange(32, 64), groupOrder).copyInto(signature, 32)
            assertFalse(Ed25519.verify(v.message.hexToByteArray(), signature, v.publicKey.hexToByteArray()))
        }
    }

    private class Forgery(
        val name: String,
        val publicKey: String,
        val message: String,
        val signature: String,
    )

    /**
     * Signatures that satisfy the cofactorless equation [S]B = R + [k]A once the
     * encodings are decoded leniently (y reduced mod p, a sign bit on x = 0
     * dropped), so only the canonical-encoding and small-order checks reject
     * them. JCA accepts the two small-order ones. Built with a Python reference
     * from the RFC 8032 test 1 key: R = identity with S = k*a for the R cases,
     * and R = [r]B with S = r for keys that act as the identity or, with the
     * message chosen so 8 divides k, as an order-8 point.
     */
    private val forgeries =
        listOf(
            Forgery(
                name = "small-order R (the identity)",
                publicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                message = "72656a656374696f6e2074657374",
                signature =
                    "0100000000000000000000000000000000000000000000000000000000000000" +
                        "401fe764dca6a9962a784cde6fe6c57e4cf18724514e6bac983026501800520a",
            ),
            Forgery(
                name = "non-canonical R (y = p + 1)",
                publicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                message = "72656a656374696f6e2074657374",
                signature =
                    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" +
                        "faea7f9fd67cda262c47f4fca72694084e11a0ab8eba0c224ab20c39dfcc7f0c",
            ),
            Forgery(
                name = "non-canonical A (y = p + 1)",
                publicKey = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                message = "72656a656374696f6e2074657374",
                signature =
                    "c4c1227d7fff941a976049ecefad7b663fa5121d769cbbd79a53d344e4773e98" +
                        "efcdab9078563412000000000000000000000000000000000000000000000000",
            ),
            Forgery(
                name = "A with x = 0 and the sign bit set",
                publicKey = "0100000000000000000000000000000000000000000000000000000000000080",
                message = "72656a656374696f6e2074657374",
                signature =
                    "c4c1227d7fff941a976049ecefad7b663fa5121d769cbbd79a53d344e4773e98" +
                        "efcdab9078563412000000000000000000000000000000000000000000000000",
            ),
            Forgery(
                name = "small-order A (order 8)",
                publicKey = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
                message = "72656a656374696f6e207465737401",
                signature =
                    "c4c1227d7fff941a976049ecefad7b663fa5121d769cbbd79a53d344e4773e98" +
                        "efcdab9078563412000000000000000000000000000000000000000000000000",
            ),
        )

    @Test
    fun rejectsNonCanonicalAndSmallOrderPoints() {
        for (f in forgeries) {
            assertFalse(
                Ed25519.verify(f.message.hexToByteArray(), f.signature.hexToByteArray(), f.publicKey.hexToByteArray()),
                f.name,
            )
        }
    }

    @Test
    fun rejectsEveryEncodingOfASmallOrderKey() {
        val v = rfc8032[0]
        val smallOrder =
            listOf(
                "0100000000000000000000000000000000000000000000000000000000000000", // identity
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // (0, -1), order 2
                "0000000000000000000000000000000000000000000000000000000000000080", // (sqrt(-1), 0) with x odd, order 4
                "0000000000000000000000000000000000000000000000000000000000000000", // (sqrt(-1), 0) with x even, order 4
                "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
                "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
            )
        for (key in smallOrder) {
            assertFalse(Ed25519.verify(v.message.hexToByteArray(), v.signature.hexToByteArray(), key.hexToByteArray()), key)
        }
    }

    @Test
    fun rejectsOffCurveKey() {
        // y = 2: (y^2 - 1) / (d y^2 + 1) has no square root, so no x exists.
        val v = rfc8032[0]
        val offCurve = "0200000000000000000000000000000000000000000000000000000000000000".hexToByteArray()
        assertFalse(Ed25519.verify(v.message.hexToByteArray(), v.signature.hexToByteArray(), offCurve))
    }

    @Test
    fun wrongLengthsReturnFalse() {
        val v = rfc8032[1]
        val message = v.message.hexToByteArray()
        val signature = v.signature.hexToByteArray()
        val publicKey = v.publicKey.hexToByteArray()
        for (size in listOf(0, 31, 33, 64)) {
            assertFalse(Ed25519.verify(message, signature, publicKey.copyOf(size)), "public key of $size bytes")
        }
        for (size in listOf(0, 32, 63, 65, 128)) {
            assertFalse(Ed25519.verify(message, signature.copyOf(size), publicKey), "signature of $size bytes")
        }
    }

    @Test
    fun rejectsEveryFlippedBit() {
        val v = rfc8032[2]
        val message = v.message.hexToByteArray()
        val signature = v.signature.hexToByteArray()
        val publicKey = v.publicKey.hexToByteArray()
        assertTrue(Ed25519.verify(message, signature, publicKey))

        fun ByteArray.flip(bit: Int) = copyOf().also { it[bit shr 3] = (it[bit shr 3].toInt() xor (1 shl (bit and 7))).toByte() }

        for (bit in 0 until message.size * 8) {
            assertFalse(Ed25519.verify(message.flip(bit), signature, publicKey), "message bit $bit")
        }
        for (bit in 0 until 512) {
            assertFalse(Ed25519.verify(message, signature.flip(bit), publicKey), "signature bit $bit")
        }
        for (bit in 0 until 256) {
            assertFalse(Ed25519.verify(message, signature, publicKey.flip(bit)), "public key bit $bit")
        }
    }
}
