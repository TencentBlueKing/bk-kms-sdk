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

import java.util.List;

/**
 * Consume credential HTTP request body. Field order is fixed to
 * {@code credential_id_list -> credential_name_list -> crypto -> public_key},
 * so signatures are byte-identical.
 * <p>
 * Empty ID / name lists MUST be serialized as {@code []} instead of {@code null}.
 */
@JsonPropertyOrder({"credential_id_list", "credential_name_list", "crypto", "public_key"})
public record ConsumeCredentialReq(
        @JsonProperty("credential_id_list") List<Long> credentialIdList,
        @JsonProperty("credential_name_list") List<String> credentialNameList,
        @JsonProperty("crypto") CryptoInfo crypto,
        @JsonProperty("public_key") String publicKey) {

    @JsonCreator
    public ConsumeCredentialReq(
            @JsonProperty("credential_id_list") List<Long> credentialIdList,
            @JsonProperty("credential_name_list") List<String> credentialNameList,
            @JsonProperty("crypto") CryptoInfo crypto,
            @JsonProperty("public_key") String publicKey) {
        this.credentialIdList = credentialIdList == null ? List.of() : credentialIdList;
        this.credentialNameList = credentialNameList == null ? List.of() : credentialNameList;
        this.crypto = crypto;
        this.publicKey = publicKey;
    }
}
