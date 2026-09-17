/*
 * TencentBlueKing is pleased to support the open source community by making
 * 蓝鲸智云 - 凭证管理服务(BlueKing - Key Management Service) available.
 * Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
 * Licensed under the MIT License (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * http://opensource.org/licenses/MIT
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.We undertake not
 * to change the open source license (MIT license) applicable to the current version
 * of the project delivered to anyone in the future.
 */

package com.tencent.bk.kms.internal.crypto;

import com.tencent.bk.kms.types.CryptoMode;
import com.tencent.bk.kms.types.CryptoType;
import com.tencent.bk.kms.types.KmsException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Round-trip and validation tests for {@link HybridCrypto}.
 */
class HybridCryptoTest {

    private static final String PLAINTEXT = "hello, bk-kms java sdk!";
    private static final byte[] KEY_16 = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);

    /**
     * A 16-byte key that intentionally contains bytes which form an invalid
     * UTF-8 sequence (0x80..0xBF are continuation bytes that cannot appear on
     * their own). If any layer of the SDK routes the symmetric key through
     * {@code new String(bytes, UTF_8)}, U+FFFD substitution will corrupt it
     * and the round-trip will fail.
     */
    private static final byte[] KEY_16_INVALID_UTF8 = new byte[]{
            (byte) 0xC3, (byte) 0x28, (byte) 0xA0, (byte) 0xA1,
            (byte) 0xE2, (byte) 0x28, (byte) 0xA1, (byte) 0xFF,
            (byte) 0xFE, (byte) 0x80, (byte) 0x81, (byte) 0x82,
            (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86,
    };

    @Test
    void rsa_aes_cbc_round_trip() {
        KeyPair pair = KeyPairs.newKeyPair(CryptoType.RSA);
        String envelope = HybridEnvelopeTestFactory.build(
                CryptoType.RSA, CryptoType.AES, CryptoMode.CBC,
                PLAINTEXT, pair.publicKey(), KEY_16);

        assertEquals(PLAINTEXT, HybridCrypto.hybridDecrypt(envelope, pair.privateKey()));
    }

    @Test
    void rsa_aes_ctr_round_trip() {
        KeyPair pair = KeyPairs.newKeyPair(CryptoType.RSA);
        String envelope = HybridEnvelopeTestFactory.build(
                CryptoType.RSA, CryptoType.AES, CryptoMode.CTR,
                PLAINTEXT, pair.publicKey(), KEY_16);

        assertEquals(PLAINTEXT, HybridCrypto.hybridDecrypt(envelope, pair.privateKey()));
    }

    @Test
    void sm2_sm4_cbc_round_trip() {
        KeyPair pair = KeyPairs.newKeyPair(CryptoType.SM2);
        String envelope = HybridEnvelopeTestFactory.build(
                CryptoType.SM2, CryptoType.SM4, CryptoMode.CBC,
                PLAINTEXT, pair.publicKey(), KEY_16);

        assertEquals(PLAINTEXT, HybridCrypto.hybridDecrypt(envelope, pair.privateKey()));
    }

    @Test
    void sm2_sm4_ctr_round_trip() {
        KeyPair pair = KeyPairs.newKeyPair(CryptoType.SM2);
        String envelope = HybridEnvelopeTestFactory.build(
                CryptoType.SM2, CryptoType.SM4, CryptoMode.CTR,
                PLAINTEXT, pair.publicKey(), KEY_16);

        assertEquals(PLAINTEXT, HybridCrypto.hybridDecrypt(envelope, pair.privateKey()));
    }

    @Test
    void invalid_symmetric_key_length_is_reported() {
        KeyPair pair = KeyPairs.newKeyPair(CryptoType.RSA);
        // 8-byte key -> after decryption, length != 16, must throw.
        byte[] shortKey = "01234567".getBytes(StandardCharsets.UTF_8);
        // Manually forge an envelope whose encrypted_key decrypts to 8 bytes.
        String forged = forgeShortKeyEnvelope(
                pair.publicKey(), shortKey,
                HybridEnvelopeTestFactory.build(
                        CryptoType.RSA, CryptoType.AES, CryptoMode.CBC,
                        PLAINTEXT, pair.publicKey(), padTo16(shortKey)));
        KmsException ex = assertThrows(KmsException.class,
                () -> HybridCrypto.hybridDecrypt(forged, pair.privateKey()));
        // Message must contain "invalid symmetric key length".
        assertTrue(
                ex.getMessage().contains("invalid symmetric key length"),
                "unexpected message: " + ex.getMessage());
    }

    /**
     * Guards against a regression where the symmetric key is routed through
     * {@code new String(bytes, UTF_8).getBytes(UTF_8)} inside
     * {@link HybridCrypto#hybridDecrypt(String, String)}. When the underlying
     * 16-byte key contains invalid UTF-8 byte sequences, that round-trip
     * silently replaces them with U+FFFD (0xEF 0xBF 0xBD, 3 bytes each),
     * inflating the length beyond 16 and either throwing
     * {@code invalid symmetric key length} or producing a garbled plaintext.
     * The key must be treated as raw bytes.
     */
    @Test
    void rsa_aes_cbc_round_trip_with_binary_symmetric_key() {
        KeyPair pair = KeyPairs.newKeyPair(CryptoType.RSA);
        String envelope = HybridEnvelopeTestFactory.build(
                CryptoType.RSA, CryptoType.AES, CryptoMode.CBC,
                PLAINTEXT, pair.publicKey(), KEY_16_INVALID_UTF8);

        assertEquals(PLAINTEXT, HybridCrypto.hybridDecrypt(envelope, pair.privateKey()));
    }

    @Test
    void rsa_aes_ctr_round_trip_with_binary_symmetric_key() {
        KeyPair pair = KeyPairs.newKeyPair(CryptoType.RSA);
        String envelope = HybridEnvelopeTestFactory.build(
                CryptoType.RSA, CryptoType.AES, CryptoMode.CTR,
                PLAINTEXT, pair.publicKey(), KEY_16_INVALID_UTF8);

        assertEquals(PLAINTEXT, HybridCrypto.hybridDecrypt(envelope, pair.privateKey()));
    }

    @Test
    void sm2_sm4_cbc_round_trip_with_binary_symmetric_key() {
        KeyPair pair = KeyPairs.newKeyPair(CryptoType.SM2);
        String envelope = HybridEnvelopeTestFactory.build(
                CryptoType.SM2, CryptoType.SM4, CryptoMode.CBC,
                PLAINTEXT, pair.publicKey(), KEY_16_INVALID_UTF8);

        assertEquals(PLAINTEXT, HybridCrypto.hybridDecrypt(envelope, pair.privateKey()));
    }

    @Test
    void sm2_sm4_ctr_round_trip_with_binary_symmetric_key() {
        KeyPair pair = KeyPairs.newKeyPair(CryptoType.SM2);
        String envelope = HybridEnvelopeTestFactory.build(
                CryptoType.SM2, CryptoType.SM4, CryptoMode.CTR,
                PLAINTEXT, pair.publicKey(), KEY_16_INVALID_UTF8);

        assertEquals(PLAINTEXT, HybridCrypto.hybridDecrypt(envelope, pair.privateKey()));
    }

    /**
     * Fuzz-style guard: random 16-byte keys almost always contain invalid
     * UTF-8 sequences, mirroring what the server actually produces. Repeat
     * the round-trip enough times that any lingering UTF-8 detour would be
     * exposed with overwhelming probability.
     */
    @Test
    void random_binary_symmetric_key_round_trip_stress() {
        KeyPair rsaPair = KeyPairs.newKeyPair(CryptoType.RSA);
        KeyPair sm2Pair = KeyPairs.newKeyPair(CryptoType.SM2);
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < 32; i++) {
            byte[] key = new byte[16];
            rnd.nextBytes(key);

            String rsaEnvelope = HybridEnvelopeTestFactory.build(
                    CryptoType.RSA, CryptoType.AES, CryptoMode.CBC,
                    PLAINTEXT, rsaPair.publicKey(), key);
            assertEquals(PLAINTEXT,
                    HybridCrypto.hybridDecrypt(rsaEnvelope, rsaPair.privateKey()),
                    "rsa/aes-cbc round-trip failed at iteration " + i);

            String sm2Envelope = HybridEnvelopeTestFactory.build(
                    CryptoType.SM2, CryptoType.SM4, CryptoMode.CTR,
                    PLAINTEXT, sm2Pair.publicKey(), key);
            assertEquals(PLAINTEXT,
                    HybridCrypto.hybridDecrypt(sm2Envelope, sm2Pair.privateKey()),
                    "sm2/sm4-ctr round-trip failed at iteration " + i);
        }
    }

    /**
     * Directly asserts that {@link HybridCrypto#asymmetricDecryptToBytes} is
     * a byte-preserving round-trip for RSA, even when the plaintext contains
     * invalid UTF-8 byte sequences.
     */
    @Test
    void rsa_asymmetric_decrypt_to_bytes_preserves_binary_payload() {
        KeyPair pair = KeyPairs.newKeyPair(CryptoType.RSA);
        String cipher = com.tencent.bk.kms.internal.crypto.rsa.Rsa
                .encryptBytes(KEY_16_INVALID_UTF8, pair.publicKey());

        byte[] roundTrip = HybridCrypto.asymmetricDecryptToBytes(
                cipher, CryptoType.RSA, pair.privateKey());

        org.junit.jupiter.api.Assertions.assertArrayEquals(KEY_16_INVALID_UTF8, roundTrip);
    }

    /**
     * Same as above for SM2.
     */
    @Test
    void sm2_asymmetric_decrypt_to_bytes_preserves_binary_payload() {
        KeyPair pair = KeyPairs.newKeyPair(CryptoType.SM2);
        String cipher = com.tencent.bk.kms.internal.crypto.sm2.Sm2
                .encryptBytes(KEY_16_INVALID_UTF8, pair.publicKey());

        byte[] roundTrip = HybridCrypto.asymmetricDecryptToBytes(
                cipher, CryptoType.SM2, pair.privateKey());

        org.junit.jupiter.api.Assertions.assertArrayEquals(KEY_16_INVALID_UTF8, roundTrip);
    }

    /**
     * Builds a new envelope that reuses the ciphertext but re-encrypts an 8-byte
     * symmetric key with the caller's public key. The resulting envelope will
     * trip the 16-byte length check.
     */
    private static String forgeShortKeyEnvelope(String publicKey, byte[] shortKey, String templateEnvelope) {
        try {
            byte[] raw = java.util.Base64.getDecoder().decode(templateEnvelope);
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            HybridEnvelope env = mapper.readValue(raw, HybridEnvelope.class);
            String badKey = com.tencent.bk.kms.internal.crypto.rsa.Rsa.encryptBytes(shortKey, publicKey);
            HybridEnvelope forged = new HybridEnvelope(
                    env.asymmetricType(), env.symmetricType(), env.symmetricMode(),
                    badKey, env.ciphertext());
            return java.util.Base64.getEncoder().encodeToString(mapper.writeValueAsBytes(forged));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] padTo16(byte[] shortKey) {
        byte[] padded = new byte[16];
        System.arraycopy(shortKey, 0, padded, 0, Math.min(shortKey.length, 16));
        return padded;
    }
}
