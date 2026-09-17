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

package com.tencent.bk.kms.spring;

import com.tencent.bk.kms.consume.Client;
import com.tencent.bk.kms.consume.ClientOptions;
import com.tencent.bk.kms.consume.ConsumeOptions;
import com.tencent.bk.kms.types.CryptoInfo;

/**
 * Internal helper that translates {@link KmsProperties} into SDK options,
 * with clear error messages for missing mandatory fields.
 */
final class KmsPropertiesSupport {

    private KmsPropertiesSupport() {
    }

    /**
     * Builds a {@link Client} instance from properties, validating required fields.
     */
    static Client buildClient(KmsProperties props) {
        return Client.create(buildClientOptions(props));
    }

    /**
     * Builds {@link ClientOptions} from properties.
     */
    static ClientOptions buildClientOptions(KmsProperties props) {
        if (props == null) {
            throw new IllegalStateException("bk.kms properties are not configured");
        }
        if (isBlank(props.getBaseUrl())) {
            throw new IllegalStateException("bk.kms.base-url must be configured");
        }
        if (isBlank(props.getAppCode())) {
            throw new IllegalStateException("bk.kms.app-code must be configured");
        }
        if (!props.isDirect() && isBlank(props.getAppSecret())) {
            throw new IllegalStateException(
                    "bk.kms.app-secret must be configured when bk.kms.direct=false");
        }

        ClientOptions.Builder builder = ClientOptions.builder()
                .baseUrl(props.getBaseUrl())
                .direct(props.isDirect())
                .timeout(props.getTimeout())
                .appCode(props.getAppCode());

        if (!props.isDirect()) {
            builder.appSecret(props.getAppSecret());
        }
        return builder.build();
    }

    /**
     * Builds a {@link ConsumeOptions} template from properties. Callers may
     * override individual fields (e.g. {@code credentialNameList}) as needed.
     */
    static ConsumeOptions.Builder consumeOptionsTemplate(KmsProperties props) {
        if (isBlank(props.getAccessKey())) {
            throw new IllegalStateException("bk.kms.access-key must be configured");
        }
        if (isBlank(props.getSecretKey())) {
            throw new IllegalStateException("bk.kms.secret-key must be configured");
        }

        KmsProperties.Crypto c = props.getCrypto();
        CryptoInfo crypto = new CryptoInfo(c.getAsymmetricType(), c.getSymmetricType(), c.getSymmetricMode());

        ConsumeOptions.Builder builder = ConsumeOptions.builder()
                .accessKeySecret(props.getAccessKey(), props.getSecretKey())
                .crypto(crypto);
        if (!isBlank(props.getTenantId())) {
            builder.tenantId(props.getTenantId());
        }
        return builder;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
