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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.tencent.bk.kms.types.CryptoMode;
import com.tencent.bk.kms.types.CryptoType;

/**
 * JSON-encoded envelope embedded inside the Base64 envelope returned by the
 * KMS server.
 *
 * <p><b>Internal API.</b> Do not depend on this class from outside the SDK.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record HybridEnvelope(
        @JsonProperty("asymmetric_type") CryptoType asymmetricType,
        @JsonProperty("symmetric_type") CryptoType symmetricType,
        @JsonProperty("symmetric_mode") CryptoMode symmetricMode,
        @JsonProperty("encrypted_key") String encryptedKey,
        @JsonProperty("ciphertext") String ciphertext) {

    @JsonCreator
    public HybridEnvelope(
            @JsonProperty("asymmetric_type") CryptoType asymmetricType,
            @JsonProperty("symmetric_type") CryptoType symmetricType,
            @JsonProperty("symmetric_mode") CryptoMode symmetricMode,
            @JsonProperty("encrypted_key") String encryptedKey,
            @JsonProperty("ciphertext") String ciphertext) {
        this.asymmetricType = asymmetricType;
        this.symmetricType = symmetricType;
        this.symmetricMode = symmetricMode;
        this.encryptedKey = encryptedKey;
        this.ciphertext = ciphertext;
    }
}
