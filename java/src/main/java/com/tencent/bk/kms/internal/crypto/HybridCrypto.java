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
import com.tencent.bk.kms.types.CryptoInfo;
import com.tencent.bk.kms.types.CryptoMode;
import com.tencent.bk.kms.types.CryptoType;
import com.tencent.bk.kms.types.KmsException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Hybrid asymmetric+symmetric envelope decryption.
 *
 * <p><b>Internal API.</b> Do not depend on this class from outside the SDK.
 */
public final class HybridCrypto {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private HybridCrypto() {
    }

    /**
     * Decrypts a Base64-encoded hybrid envelope with the given private key,
     * returning the plaintext as a UTF-8 string.
     *
     * @throws KmsException on any decode / validation / decryption failure
     */
    public static String hybridDecrypt(String envelopeBase64, String privateKeyBase64) {
        if (envelopeBase64 == null || envelopeBase64.isEmpty()) {
            return "";
        }

        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(envelopeBase64);
        } catch (IllegalArgumentException e) {
            throw new KmsException("decode hybrid envelope error(" + e.getMessage() + ")", e);
        }

        HybridEnvelope envelope;
        try {
            envelope = MAPPER.readValue(raw, HybridEnvelope.class);
        } catch (Exception e) {
            throw new KmsException("unmarshal hybrid envelope error(" + e.getMessage() + ")", e);
        }

        if (envelope.asymmetricType() == null) {
            throw new KmsException("invalid asymmetric crypto type(null)");
        }
        envelope.asymmetricType().validateAsymmetric();
        if (envelope.symmetricType() == null) {
            throw new KmsException("invalid symmetric crypto type(null)");
        }
        envelope.symmetricType().validateSymmetric();
        if (envelope.symmetricMode() == null) {
            throw new KmsException("invalid crypto mode(null)");
        }
        envelope.symmetricMode().validate();

        byte[] keyBytes = asymmetricDecryptToBytes(
                envelope.encryptedKey(), envelope.asymmetricType(), privateKeyBase64);
        if (keyBytes.length != CryptoInfo.CRYPTO_KEY_LENGTH) {
            throw new KmsException("invalid symmetric key length(" + keyBytes.length + ")");
        }

        byte[] plaintext = symmetricDecrypt(
                envelope.ciphertext(), envelope.symmetricType(), envelope.symmetricMode(), keyBytes);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /** Symmetric decrypt dispatcher. */
    public static byte[] symmetricDecrypt(String encodedText, CryptoType type, CryptoMode mode, byte[] key) {
        if (encodedText == null || encodedText.isEmpty()) {
            return new byte[0];
        }
        type.validateSymmetric();
        mode.validate();

        if (key.length != CryptoInfo.CRYPTO_KEY_LENGTH) {
            throw new KmsException("invalid crypto key length(" + key.length + ")");
        }

        if (type == CryptoType.AES) {
            return mode == CryptoMode.CBC ? Aes.decryptCbc(encodedText, key) : Aes.decryptCtr(encodedText, key);
        }
        // SM4
        return mode == CryptoMode.CBC ? Sm4.decryptCbc(encodedText, key) : Sm4.decryptCtr(encodedText, key);
    }

    /** Asymmetric decrypt dispatcher, returns plaintext as UTF-8 string.
     *
     * <p><b>Warning:</b> only use this when the plaintext is known to be valid
     * UTF-8 text. For binary payloads (e.g. symmetric keys inside a hybrid
     * envelope) use {@link #asymmetricDecryptToBytes(String, CryptoType, String)}
     * instead, otherwise malformed UTF-8 bytes will be silently replaced with
     * U+FFFD and the resulting bytes will no longer match the original.
     */
    public static String asymmetricDecrypt(String encodedText, CryptoType type, String privateKeyBase64) {
        if (encodedText == null || encodedText.isEmpty()) {
            return "";
        }
        type.validateAsymmetric();
        return type == CryptoType.RSA
                ? Rsa.decrypt(encodedText, privateKeyBase64)
                : Sm2.decrypt(encodedText, privateKeyBase64);
    }

    /**
     * Asymmetric decrypt dispatcher that returns the raw plaintext bytes.
     */
    public static byte[] asymmetricDecryptToBytes(String encodedText, CryptoType type, String privateKeyBase64) {
        if (encodedText == null || encodedText.isEmpty()) {
            return new byte[0];
        }
        type.validateAsymmetric();
        return type == CryptoType.RSA
                ? Rsa.decryptToBytes(encodedText, privateKeyBase64)
                : Sm2.decryptToBytes(encodedText, privateKeyBase64);
    }
}
