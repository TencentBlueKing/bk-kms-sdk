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
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Single credential consume result. A non-zero {@link #errCode} indicates the
 * per-credential lookup failed while the overall envelope request succeeded.
 */
public record ConsumeResult(
        @JsonProperty("credential_id") long credentialId,
        @JsonProperty("err_code") int errCode,
        @JsonProperty("err_msg") String errMsg,
        @JsonInclude(JsonInclude.Include.NON_NULL) @JsonProperty("credential") Credential credential) {

    @JsonCreator
    public ConsumeResult(
            @JsonProperty("credential_id") long credentialId,
            @JsonProperty("err_code") int errCode,
            @JsonProperty("err_msg") String errMsg,
            @JsonProperty("credential") Credential credential) {
        this.credentialId = credentialId;
        this.errCode = errCode;
        this.errMsg = errMsg;
        this.credential = credential;
    }
}
