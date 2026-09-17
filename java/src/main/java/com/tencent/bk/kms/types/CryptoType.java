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
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Cryptographic algorithm type.
 */
public enum CryptoType {

    AES("AES"),
    SM4("SM4"),
    RSA("RSA"),
    SM2("SM2");

    private final String value;

    CryptoType(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    /**
     * Resolves the enum from its wire value using case-sensitive matching.
     * The server always emits upper-case values ({@code AES}, {@code SM4},
     * {@code RSA}, {@code SM2}), so any lower-case variant coming from a
     * non-conforming caller is rejected.
     */
    @JsonCreator
    public static CryptoType fromValue(String value) {
        if (value == null) {
            return null;
        }
        for (CryptoType t : values()) {
            if (t.value.equals(value)) {
                return t;
            }
        }
        throw new KmsException("unknown crypto type(" + value + ")");
    }

    /**
     * Validates that this instance is an asymmetric algorithm (RSA or SM2).
     */
    public void validateAsymmetric() {
        if (this != RSA && this != SM2) {
            throw new KmsException("invalid asymmetric crypto type(" + value + ")");
        }
    }

    /**
     * Validates that this instance is a symmetric algorithm (AES or SM4).
     */
    public void validateSymmetric() {
        if (this != AES && this != SM4) {
            throw new KmsException("invalid symmetric crypto type(" + value + ")");
        }
    }
}
