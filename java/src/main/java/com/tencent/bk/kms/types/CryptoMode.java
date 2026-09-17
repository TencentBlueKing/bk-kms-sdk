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
 * Symmetric encryption mode.
 */
public enum CryptoMode {

    CBC("CBC"),
    CTR("CTR");

    private final String value;

    CryptoMode(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    /**
     * Resolves the enum from its wire value using case-sensitive matching.
     * The server always emits upper-case values ({@code CBC}, {@code CTR});
     * any deviation is rejected.
     */
    @JsonCreator
    public static CryptoMode fromValue(String value) {
        if (value == null) {
            return null;
        }
        for (CryptoMode m : values()) {
            if (m.value.equals(value)) {
                return m;
            }
        }
        throw new KmsException("invalid crypto mode(" + value + ")");
    }

    /**
     * Validates this crypto mode.
     */
    public void validate() {
        if (this != CBC && this != CTR) {
            throw new KmsException("invalid crypto mode(" + value + ")");
        }
    }
}
