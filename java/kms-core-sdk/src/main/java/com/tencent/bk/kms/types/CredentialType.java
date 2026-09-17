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
 * Credential type enumeration.
 */
public enum CredentialType {

    SINGLE_PASSWORD("single_password"),
    USERNAME_PASSWORD("username_password"),
    SINGLE_SECRET_KEY("single_secret_key"),
    APP_ID_SECRET_KEY("app_id_secret_key");

    private final String value;

    CredentialType(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    @JsonCreator
    public static CredentialType fromValue(String value) {
        if (value == null) {
            return null;
        }
        for (CredentialType t : values()) {
            if (t.value.equals(value)) {
                return t;
            }
        }
        throw new KmsException("unknown credential type(" + value + ")");
    }
}
