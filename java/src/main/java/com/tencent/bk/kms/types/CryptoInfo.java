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

package com.tencent.bk.kms.types;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * Carries the asymmetric algorithm, symmetric algorithm and symmetric mode for
 * a hybrid consume-credential request.
 */
@JsonPropertyOrder({"asymmetric_type", "symmetric_type", "symmetric_mode"})
public record CryptoInfo(
        @JsonProperty("asymmetric_type") CryptoType asymmetricType,
        @JsonProperty("symmetric_type") CryptoType symmetricType,
        @JsonProperty("symmetric_mode") CryptoMode symmetricMode) {

    /** Length in bytes of the symmetric key negotiated by the KMS server. */
    public static final int CRYPTO_KEY_LENGTH = 16;

    @JsonCreator
    public CryptoInfo(
            @JsonProperty("asymmetric_type") CryptoType asymmetricType,
            @JsonProperty("symmetric_type") CryptoType symmetricType,
            @JsonProperty("symmetric_mode") CryptoMode symmetricMode) {
        this.asymmetricType = asymmetricType;
        this.symmetricType = symmetricType;
        this.symmetricMode = symmetricMode;
    }

    /** Returns the default hybrid combination: RSA + AES(CBC). */
    public static CryptoInfo defaultHybrid() {
        return new CryptoInfo(CryptoType.RSA, CryptoType.AES, CryptoMode.CBC);
    }

    /**
     * Validates that the asymmetric/symmetric/mode triple is a legal combination.
     *
     * @throws KmsException when any component is null or invalid
     */
    public void validateHybrid() {
        if (asymmetricType == null) {
            throw new KmsException("invalid asymmetric crypto type(null)");
        }
        asymmetricType.validateAsymmetric();

        if (symmetricType == null) {
            throw new KmsException("invalid symmetric crypto type(null)");
        }
        symmetricType.validateSymmetric();

        if (symmetricMode == null) {
            throw new KmsException("invalid crypto mode(null)");
        }
        symmetricMode.validate();
    }
}
