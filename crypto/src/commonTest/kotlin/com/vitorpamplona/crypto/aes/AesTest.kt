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

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * Known answers for the pure-Kotlin AES the native targets use, and for the public [AESGCM]
 * and [AESCBC], which are JCA on the JVM, so every platform is held to the same bytes.
 *
 * The block, GCM and CBC standard vectors come from FIPS 197 Appendix C, the GCM spec's test
 * cases (McGrew and Viega, as used in NIST SP 800-38D validation) and NIST SP 800-38A F.2.
 * The other GCM and CBC vectors were produced with OpenSSL (Python's `cryptography`) from the
 * inputs [pattern] builds, to cover lengths and nonce sizes the standard ones don't.
 */
class AesTest {
    private fun ByteArray.hex() = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun String.unhex() = ByteArray(length / 2) { substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private fun pattern(
        size: Int,
        mul: Int,
        add: Int,
    ) = ByteArray(size) { ((it * mul + add) and 0xFF).toByte() }

    private class GcmCase(
        val keySize: Int,
        val nonceSize: Int,
        val plaintextSize: Int,
        val aadSize: Int,
        val expected: String,
    )

    private class CbcCase(
        val keySize: Int,
        val plaintextSize: Int,
        val expected: String,
    )

    private class StandardGcmCase(
        val name: String,
        val key: String,
        val nonce: String,
        val plaintext: String,
        val aad: String,
        val ciphertext: String,
        val tag: String,
    )

    private val gcmCases =
        listOf(
            GcmCase(16, 12, 0, 0, "0ec52f1d77032e793e18692d5b13cf90"),
            GcmCase(16, 12, 16, 0, "1e90635456aeb043b5a520f9d8142eca4232ca9f27d04bcbc2131ee67752f7da"),
            GcmCase(16, 12, 17, 20, "1e90635456aeb043b5a520f9d8142eca4c660ade4ab7088749960ea9754bcb5cae"),
            GcmCase(24, 12, 65, 13, "206d8766423da4cbb3292ffd68a1b700320f8bba414758015d604d71d671e4273a32b44a3c2e72da1ce278692996c056aa96ca7c4d980404bc5a69dd699d3270bab3e970bdad1ee02a74d53cd81422cb72"),
            GcmCase(32, 12, 100, 0, "f71a467fdddd4aa95ea757ff293010a257cf8ff6905d29a1e1fa8e71c36f0efc88026031f22a0db2fdf5d8bea2b1d0d7282c5ab1cfa6f8ce47da46742ff16646402a814340be9e529810cacc8eda6060c55d01c440b780bd5d4e92a95fcbe163f02be8090a87bf046f46c8c0b940fdaf6dab7d4f"),
            GcmCase(32, 16, 0, 0, "4a000a1457fdd8bc63bda5f06b1eff82"),
            GcmCase(32, 16, 33, 7, "8953a3d8271245b62f52eda23656f34a7d3e03ac1656439ce19f542c80992bf14bb99f323ce98330bb3ed6a67e88a33813"),
            GcmCase(16, 8, 5, 0, "a28133671ab0ac8996a0ea73bae5d7ee92ca40f0b9"),
            GcmCase(32, 60, 64, 16, "33b5bddc35828cb3a2a6115fb38396ae64c0bbee0980ff1883e881f20f66361ae07d212ae66dd652be64f182361179e501626d643b7dba6f5b8cb7a52ee201b0a511d2f3710649b38a1166d05f17137d"),
            GcmCase(16, 16, 255, 3, "b2e5f6ba6b4de27431a20531e4b4c8b847266cac5f1de2882408f8717d538a637670f59eb2f834cbc99a3edb5e29058d8f017b4491fd4e18036240f8c77df4c62f9e95d77cdb1fcb25c5955dc6b85b73d5522d01f8e22293b2cad6602df2511f7cdc2521bf1008eaf08d88771bf6001920cdba4a929f1f57900ab9c9fa0d3692a5e0806213b480639c384fa5fc96ffb8845fcc940759cdff22062c3447c2c12380b098250701d00fe38e422ad6f5e23557d894dc83fc046a3fc89e8c07c85dfb975d2ee2f7d2b40aef28f04c952642eba85025a01586df76ac919efb2ff7227916fab36f4dfb6f679b5bf3204764db8a755f5627f0995c581a4a95586abc95396ec6896acda1d8eb186cf07d5c3321"),
        )

    private val cbcCases =
        listOf(
            CbcCase(16, 0, "bbf293057225748007152d34e9e41765"),
            CbcCase(16, 15, "510b005e0454ed8f14d74a4eba5e14d1"),
            CbcCase(16, 16, "82a32de8a3becd3223f4b018ed3ebfae2b49f10978ddb2b6cdc4ff3e2e0a7aaa"),
            CbcCase(24, 31, "c7ce6aed9a857220cc41269b61757bc38337c837b7dad1c33b707bcbea9db271"),
            CbcCase(32, 32, "3cb885d105d4b9d0806935d5af7f6f9b44ff7ebc8c174ee4b17783e5a2fb00487f231d5c2352e4d065a78bc6f0ea406c"),
            CbcCase(32, 100, "3cb885d105d4b9d0806935d5af7f6f9b44ff7ebc8c174ee4b17783e5a2fb0048c8270939b17ebf05ccb765fd8548523ba64cd8512894b7d940e2e9a4542a3ecb1a877b329a87b6ba5788b1aa5c9f6f82ee0a65c47ab4655619acd8ff96ae8a68f79766183962e21565d94e0b91ce9def"),
            CbcCase(32, 257, "3cb885d105d4b9d0806935d5af7f6f9b44ff7ebc8c174ee4b17783e5a2fb0048c8270939b17ebf05ccb765fd8548523ba64cd8512894b7d940e2e9a4542a3ecb1a877b329a87b6ba5788b1aa5c9f6f82ee0a65c47ab4655619acd8ff96ae8a6852194964f00c319c37891ed4977f2f70fde0df9154070c37d77bab02774ef017a8eaddb0df9925c5200b24f398762e780da30110e36f9c4a469cd12c24e2a1833f5d4cc3686ff5b496c0f85a5a4543f027146a5d003c9da62723c0fb7c2a896f4efefe216587e1572fd8861851b46045a30b1d3fc919e41eef4e7cf77826a20469cebd92ce14033397ed43d82b72aef5a37896dbcd406863514eaf1213c80f655129b8e4611b63a276e53afc37f0b796"),
        )

    // The GCM spec's test cases 1 to 18: AES-128, -192 and -256, each with 12-byte, 8-byte
    // and 60-byte nonces.
    private val standardGcmCases =
        run {
            val zero16 = "00000000000000000000000000000000"
            val zero24 = "000000000000000000000000000000000000000000000000"
            val zero32 = zero16 + zero16
            val zeroNonce = "000000000000000000000000"
            val key128 = "feffe9928665731c6d6a8f9467308308"
            val key192 = "feffe9928665731c6d6a8f9467308308feffe9928665731c"
            val key256 = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
            val nonce12 = "cafebabefacedbaddecaf888"
            val nonce8 = "cafebabefacedbad"
            val nonce60 =
                "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728" +
                    "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b"
            val plaintext64 =
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
            val plaintext60 = plaintext64.substring(0, 120)
            val aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
            listOf(
                StandardGcmCase("1", zero16, zeroNonce, "", "", "", "58e2fccefa7e3061367f1d57a4e7455a"),
                StandardGcmCase("2", zero16, zeroNonce, zero16, "", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"),
                StandardGcmCase("3", key128, nonce12, plaintext64, "", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985", "4d5c2af327cd64a62cf35abd2ba6fab4"),
                StandardGcmCase("4", key128, nonce12, plaintext60, aad, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", "5bc94fbc3221a5db94fae95ae7121a47"),
                StandardGcmCase("5", key128, nonce8, plaintext60, aad, "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598", "3612d2e79e3b0785561be14aaca2fccb"),
                StandardGcmCase("6", key128, nonce60, plaintext60, aad, "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5", "619cc5aefffe0bfa462af43c1699d050"),
                StandardGcmCase("7", zero24, zeroNonce, "", "", "", "cd33b28ac773f74ba00ed1f312572435"),
                StandardGcmCase("8", zero24, zeroNonce, zero16, "", "98e7247c07f0fe411c267e4384b0f600", "2ff58d80033927ab8ef4d4587514f0fb"),
                StandardGcmCase("9", key192, nonce12, plaintext64, "", "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256", "9924a7c8587336bfb118024db8674a14"),
                StandardGcmCase("10", key192, nonce12, plaintext60, aad, "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710", "2519498e80f1478f37ba55bd6d27618c"),
                StandardGcmCase("11", key192, nonce8, plaintext60, aad, "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7", "65dcc57fcf623a24094fcca40d3533f8"),
                StandardGcmCase("12", key192, nonce60, plaintext60, aad, "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b", "dcf566ff291c25bbb8568fc3d376a6d9"),
                StandardGcmCase("13", zero32, zeroNonce, "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"),
                StandardGcmCase("14", zero32, zeroNonce, zero16, "", "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"),
                StandardGcmCase("15", key256, nonce12, plaintext64, "", "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad", "b094dac5d93471bdec1a502270e3cc6c"),
                StandardGcmCase("16", key256, nonce12, plaintext60, aad, "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662", "76fc6ece0f4e1768cddf8853bb2d551b"),
                StandardGcmCase("17", key256, nonce8, plaintext60, aad, "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f", "3a337dbf46a792c45e454913fe2ea8f2"),
                StandardGcmCase("18", key256, nonce60, plaintext60, aad, "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f", "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"),
            )
        }

    @Test
    fun fips197Blocks() {
        val plaintext = "00112233445566778899aabbccddeeff".unhex()
        val cases =
            listOf(
                "000102030405060708090a0b0c0d0e0f" to "69c4e0d86a7b0430d8cdb78070b4c55a",
                "000102030405060708090a0b0c0d0e0f1011121314151617" to "dda97ca4864cdfe06eaf70a0ec0d7191",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" to "8ea2b7ca516745bfeafc49904b496089",
            )
        for ((key, ciphertext) in cases) {
            val aes = AesBitsliced(key.unhex())
            val scratch = AesBitsliced.Scratch()
            val block = plaintext.copyOf()
            aes.encryptBlocks(block, 0, block, 0, 1, scratch)
            assertEquals(ciphertext, block.hex())
            aes.decryptBlocks(block, 0, block, 0, 1, scratch)
            assertContentEquals(plaintext, block)
        }
    }

    @Test
    fun fourBlocksAtOnceMatchOneAtATime() {
        val aes = AesBitsliced(pattern(32, 7, 1))
        val scratch = AesBitsliced.Scratch()
        val input = pattern(64, 13, 5)
        val together = input.copyOf()
        aes.encryptBlocks(together, 0, together, 0, 4, scratch)
        for (b in 0 until 4) {
            val single = input.copyOfRange(16 * b, 16 * b + 16)
            aes.encryptBlocks(single, 0, single, 0, 1, scratch)
            assertContentEquals(single, together.copyOfRange(16 * b, 16 * b + 16), "block $b")
        }
        aes.decryptBlocks(together, 0, together, 0, 4, scratch)
        assertContentEquals(input, together)
    }

    @Test
    fun standardGcmVectors() {
        for (case in standardGcmCases) {
            val key = case.key.unhex()
            val nonce = case.nonce.unhex()
            val plaintext = case.plaintext.unhex()
            val aad = case.aad.unhex()
            val sealed = case.ciphertext + case.tag
            val label = "test case ${case.name}"

            val gcm = AesGcmKey(key)
            assertEquals(sealed, gcm.encrypt(nonce, plaintext, aad).hex(), label)
            assertContentEquals(plaintext, gcm.decrypt(nonce, sealed.unhex(), aad), label)

            val cipher = AESGCM(key, nonce)
            assertEquals(sealed, cipher.encrypt(plaintext, aad).hex(), label)
            assertContentEquals(plaintext, cipher.decrypt(sealed.unhex(), aad), label)
        }
    }

    @Test
    fun standardCbcVectors() {
        // NIST SP 800-38A F.2.1, F.2.3 and F.2.5: CBC without padding over four blocks.
        val iv = "000102030405060708090a0b0c0d0e0f".unhex()
        val plaintext =
            (
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
                    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
            ).unhex()
        val cases =
            listOf(
                "2b7e151628aed2a6abf7158809cf4f3c" to
                    "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2" +
                    "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" to
                    "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a" +
                    "571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" to
                    "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d" +
                    "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
            )
        for ((key, ciphertext) in cases) {
            val cbc = AesCbcKey(key.unhex())
            assertEquals(ciphertext, cbc.encrypt(iv, plaintext).hex(), key)
            assertContentEquals(plaintext, cbc.decrypt(iv, ciphertext.unhex()), key)

            // With padding, the same four blocks come first and a full padding block follows.
            val cipher = AESCBC(key.unhex(), iv)
            val sealed = cipher.encrypt(plaintext)
            assertEquals(80, sealed.size, key)
            assertEquals(ciphertext, sealed.copyOf(64).hex(), key)
            assertContentEquals(plaintext, cipher.decrypt(sealed), key)
        }
    }

    @Test
    fun gcmVectors() {
        for (case in gcmCases) {
            val key = pattern(case.keySize, 7, 1)
            val nonce = pattern(case.nonceSize, 11, 3)
            val plaintext = pattern(case.plaintextSize, 13, 5)
            val aad = pattern(case.aadSize, 17, 9)
            val label = "key ${case.keySize}, nonce ${case.nonceSize}, data ${case.plaintextSize}, aad ${case.aadSize}"

            val gcm = AesGcmKey(key)
            assertEquals(case.expected, gcm.encrypt(nonce, plaintext, aad).hex(), label)
            assertContentEquals(plaintext, gcm.decrypt(nonce, case.expected.unhex(), aad), label)

            val cipher = AESGCM(key, nonce)
            assertEquals(case.expected, cipher.encrypt(plaintext, aad).hex(), label)
            assertContentEquals(plaintext, cipher.decrypt(case.expected.unhex(), aad), label)
        }
    }

    @Test
    fun reusedGcmKeyServesManyNonces() {
        // One AesGcmKey per key size across every nonce, in both orders and twice over, so a
        // call never depends on what an earlier one left behind.
        val keys = mutableMapOf<Int, AesGcmKey>()
        for (order in listOf(gcmCases, gcmCases.reversed())) {
            repeat(2) { pass ->
                for (case in order) {
                    val key = pattern(case.keySize, 7, 1)
                    val nonce = pattern(case.nonceSize, 11, 3)
                    val plaintext = pattern(case.plaintextSize, 13, 5)
                    val aad = pattern(case.aadSize, 17, 9)
                    val label = "pass $pass, key ${case.keySize}, nonce ${case.nonceSize}, data ${case.plaintextSize}"

                    val gcm = keys.getOrPut(case.keySize) { AesGcmKey(key) }
                    assertEquals(case.expected, gcm.encrypt(nonce, plaintext, aad).hex(), label)
                    assertContentEquals(plaintext, gcm.decrypt(nonce, case.expected.unhex(), aad), label)
                }
            }
        }
    }

    @Test
    fun gcmCounterWrapsInLow32Bits() {
        // inc32 increments only the last four bytes of the counter block, mod 2^32. Starting
        // from a J0 whose low word is 0xFFFFFFFE, the five data blocks run under counters
        // FFFFFFFF, 0, 1, 2 and 3 with the first twelve bytes unchanged, across the four-block
        // batch boundary.
        val key = pattern(32, 7, 1)
        val prefix = pattern(12, 11, 3)
        val j0 = prefix + byteArrayOf(-1, -1, -1, -2)
        val plaintext = pattern(80, 13, 5)

        val aes = AesBitsliced(key)
        val scratch = AesBitsliced.Scratch()
        val expected = ByteArray(80)
        for ((block, low) in listOf(-1, 0, 1, 2, 3).withIndex()) {
            val counter = prefix + byteArrayOf((low ushr 24).toByte(), (low ushr 16).toByte(), (low ushr 8).toByte(), low.toByte())
            aes.encryptBlocks(counter, 0, counter, 0, 1, scratch)
            for (i in 0 until 16) {
                expected[16 * block + i] = (plaintext[16 * block + i].toInt() xor counter[i].toInt()).toByte()
            }
        }

        val sealed = AesGcmKey(key).encryptFromJ0(j0, plaintext, ByteArray(0))
        assertEquals(expected.hex(), sealed.copyOf(80).hex())
    }

    @Test
    fun cbcVectors() {
        val iv = pattern(16, 11, 3)
        val keys = mutableMapOf<Int, AesCbcKey>()
        repeat(2) { pass ->
            for (case in cbcCases) {
                val key = pattern(case.keySize, 7, 1)
                val plaintext = pattern(case.plaintextSize, 13, 5)
                val label = "pass $pass, key ${case.keySize}, data ${case.plaintextSize}"

                // What AESCBC runs on Linux, with one key schedule reused across messages.
                val cbc = keys.getOrPut(case.keySize) { AesCbcKey(key) }
                assertEquals(case.expected, cbcEncrypt(plaintext) { cbc.encrypt(iv, it) }.hex(), label)
                assertContentEquals(plaintext, cbcDecrypt(case.expected.unhex()) { cbc.decrypt(iv, it) }, label)

                val cipher = AESCBC(key, iv)
                assertEquals(case.expected, cipher.encrypt(plaintext).hex(), label)
                assertContentEquals(plaintext, cipher.decrypt(case.expected.unhex()), label)
            }
        }
    }

    @Test
    fun gcmRejectsAnyTamperedByte() {
        val case = gcmCases.first { it.aadSize > 0 && it.plaintextSize > 0 }
        val key = pattern(case.keySize, 7, 1)
        val nonce = pattern(case.nonceSize, 11, 3)
        val aad = pattern(case.aadSize, 17, 9)
        val sealed = case.expected.unhex()
        val gcm = AesGcmKey(key)
        val cipher = AESGCM(key, nonce)
        for (i in sealed.indices) {
            val tampered = sealed.copyOf()
            tampered[i] = (tampered[i].toInt() xor 0x01).toByte()
            assertFailsWith<IllegalArgumentException>("byte $i") { gcm.decrypt(nonce, tampered, aad) }
            assertNull(cipher.decryptOrNull(tampered, aad), "byte $i")
        }
    }

    @Test
    fun rejectsBadKeySizes() {
        for (size in intArrayOf(0, 15, 17, 33)) {
            assertFailsWith<IllegalArgumentException>("key $size") { AesBitsliced(ByteArray(size)) }
            assertFailsWith<IllegalArgumentException>("key $size") { AesGcmKey(ByteArray(size)) }
            assertFailsWith<IllegalArgumentException>("key $size") { AesCbcKey(ByteArray(size)) }
        }
    }
}
