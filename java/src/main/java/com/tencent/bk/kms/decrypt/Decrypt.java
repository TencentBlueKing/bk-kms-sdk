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

package com.tencent.bk.kms.decrypt;

import com.tencent.bk.kms.internal.crypto.HybridCrypto;
import com.tencent.bk.kms.types.KmsException;

/**
 * Public entry point of the BK-KMS foundation SDK.
 *
 * <p>Decrypts a hybrid envelope produced by the BK-KMS server using the caller's
 * private key. The envelope format is fully defined by the KMS server contract
 * and callers do not need to inspect it directly. This class mirrors the
 * {@code decrypt.Decrypt} function exposed by the Go SDK.
 */
public final class Decrypt {

    private Decrypt() {
    }

    /**
     * Decrypts a Base64-encoded hybrid envelope with the given Base64-encoded
     * private key (Base64-of-PEM), returning the plaintext as a UTF-8 string.
     *
     * @param envelope   Base64-encoded hybrid envelope returned by the KMS server
     * @param privateKey Base64-encoded PEM private key that matches the ephemeral
     *                   public key sent to the KMS server
     * @return the plaintext string (typically a JSON payload defined by the
     *         server contract)
     * @throws KmsException on empty inputs, decode / validation / decryption
     *         failures
     */
    public static String decrypt(String envelope, String privateKey) {
        if (envelope == null || envelope.isEmpty()) {
            throw new KmsException("empty envelope");
        }
        if (privateKey == null || privateKey.isEmpty()) {
            throw new KmsException("empty private key");
        }
        try {
            return HybridCrypto.hybridDecrypt(envelope, privateKey);
        } catch (KmsException e) {
            throw new KmsException("hybrid decrypt error(" + e.getMessage() + ")", e);
        }
    }
}
