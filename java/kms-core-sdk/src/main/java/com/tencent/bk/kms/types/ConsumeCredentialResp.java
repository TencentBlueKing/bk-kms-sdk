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
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Envelope for the {@code consume_credential} HTTP response.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ConsumeCredentialResp(
        @JsonProperty("code") int code,
        @JsonProperty("message") String message,
        @JsonProperty("data") ConsumeCredentialData data) {

    @JsonCreator
    public ConsumeCredentialResp(
            @JsonProperty("code") int code,
            @JsonProperty("message") String message,
            @JsonProperty("data") ConsumeCredentialData data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }
}
