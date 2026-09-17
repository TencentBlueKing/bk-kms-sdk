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

package com.tencent.bk.kms.consume;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tencent.bk.kms.internal.crypto.HybridCrypto;
import com.tencent.bk.kms.types.ConsumeEnvelope;
import com.tencent.bk.kms.types.ConsumeResult;
import com.tencent.bk.kms.types.KmsException;

import java.util.List;

/**
 * Static helper: decrypts a hybrid envelope into a list of consume results.
 */
final class DecryptEnvelope {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<ConsumeResult>> RESULT_LIST =
            new TypeReference<>() {
            };

    private DecryptEnvelope() {
    }

    static List<ConsumeResult> decrypt(ConsumeEnvelope envelope) {
        if (envelope == null || envelope.envelope() == null || envelope.envelope().isEmpty()
                || envelope.privateKey() == null || envelope.privateKey().isEmpty()) {
            throw new KmsException("empty envelope or private key");
        }

        String plaintext;
        try {
            plaintext = HybridCrypto.hybridDecrypt(envelope.envelope(), envelope.privateKey());
        } catch (KmsException e) {
            throw new KmsException("decrypt consume result error(" + e.getMessage() + ")", e);
        }

        try {
            return MAPPER.readValue(plaintext, RESULT_LIST);
        } catch (Exception e) {
            throw new KmsException("unmarshal consume result error(" + e.getMessage() + ")", e);
        }
    }
}
