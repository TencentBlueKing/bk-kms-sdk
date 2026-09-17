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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tencent.bk.kms.internal.crypto.aes.Aes;
import com.tencent.bk.kms.internal.crypto.rsa.Rsa;
import com.tencent.bk.kms.internal.crypto.sm2.Sm2;
import com.tencent.bk.kms.internal.crypto.sm4.Sm4;
import com.tencent.bk.kms.types.CryptoMode;
import com.tencent.bk.kms.types.CryptoType;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Test-only helper that builds hybrid envelopes so that
 * {@link HybridCrypto#hybridDecrypt(String, String)} can be exercised via
 * round-trip tests.
 */
final class HybridEnvelopeTestFactory {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private HybridEnvelopeTestFactory() {
    }

    static String build(
            CryptoType asymmetric, CryptoType symmetric, CryptoMode mode,
            String plaintext, String publicKeyBase64, byte[] symmetricKey) {
        try {
            String ciphertext;
            if (symmetric == CryptoType.AES) {
                ciphertext = mode == CryptoMode.CBC
                        ? Aes.encryptCbc(plaintext.getBytes(StandardCharsets.UTF_8), symmetricKey)
                        : Aes.encryptCtr(plaintext.getBytes(StandardCharsets.UTF_8), symmetricKey);
            } else {
                ciphertext = mode == CryptoMode.CBC
                        ? Sm4.encryptCbc(plaintext.getBytes(StandardCharsets.UTF_8), symmetricKey)
                        : Sm4.encryptCtr(plaintext.getBytes(StandardCharsets.UTF_8), symmetricKey);
            }

            // Encrypt the symmetric key as raw bytes so that binary keys (which
            // may contain invalid UTF-8 sequences) survive the round-trip
            // untouched.
            String encryptedKey = asymmetric == CryptoType.RSA
                    ? Rsa.encryptBytes(symmetricKey, publicKeyBase64)
                    : Sm2.encryptBytes(symmetricKey, publicKeyBase64);

            HybridEnvelope envelope = new HybridEnvelope(
                    asymmetric, symmetric, mode, encryptedKey, ciphertext);
            byte[] json = MAPPER.writeValueAsBytes(envelope);
            return Base64.getEncoder().encodeToString(json);
        } catch (Exception e) {
            throw new RuntimeException("failed to build hybrid envelope for tests", e);
        }
    }
}
