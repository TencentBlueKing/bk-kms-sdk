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

import com.tencent.bk.kms.types.CryptoInfo;

import java.util.ArrayList;
import java.util.List;

/**
 * Per-call options for {@link Client#consumeCredential(ConsumeOptions)} and
 * {@link Client#consumeCredentialEnvelope(ConsumeOptions)}.
 */
public final class ConsumeOptions {

    private final String tenantId;
    private final String accessKey;
    private final String secretKey;
    private final List<String> credentialNameList;
    private final CryptoInfo crypto;

    private ConsumeOptions(Builder builder) {
        this.tenantId = builder.tenantId;
        this.accessKey = builder.accessKey;
        this.secretKey = builder.secretKey;
        this.credentialNameList = builder.credentialNameList == null
                ? List.of()
                : List.copyOf(builder.credentialNameList);
        this.crypto = builder.crypto == null ? CryptoInfo.defaultHybrid() : builder.crypto;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getAccessKey() {
        return accessKey;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public List<String> getCredentialNameList() {
        return credentialNameList;
    }

    public CryptoInfo getCrypto() {
        return crypto;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Fluent builder for {@link ConsumeOptions}. */
    public static final class Builder {

        private String tenantId;
        private String accessKey;
        private String secretKey;
        private List<String> credentialNameList;
        private CryptoInfo crypto;

        public Builder tenantId(String tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder accessKeySecret(String accessKey, String secretKey) {
            this.accessKey = accessKey;
            this.secretKey = secretKey;
            return this;
        }

        public Builder credentialNameList(List<String> names) {
            this.credentialNameList = names == null ? null : new ArrayList<>(names);
            return this;
        }

        public Builder credentialNameList(String... names) {
            if (names == null) {
                this.credentialNameList = null;
            } else {
                this.credentialNameList = new ArrayList<>();
                for (String n : names) {
                    this.credentialNameList.add(n);
                }
            }
            return this;
        }

        public Builder crypto(CryptoInfo crypto) {
            this.crypto = crypto;
            return this;
        }

        public ConsumeOptions build() {
            return new ConsumeOptions(this);
        }
    }
}
