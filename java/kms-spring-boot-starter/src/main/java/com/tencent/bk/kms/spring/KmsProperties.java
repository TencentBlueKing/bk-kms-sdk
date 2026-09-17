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

import com.tencent.bk.kms.types.CryptoMode;
import com.tencent.bk.kms.types.CryptoType;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Configuration properties for the BlueKing KMS Spring Boot starter.
 * Bound to keys under the {@code bk.kms} prefix.
 */
@ConfigurationProperties(prefix = "bk.kms")
public class KmsProperties {

    /** Master switch for the starter. Defaults to {@code true}. */
    private boolean enabled = true;

    /** Base URL of the KMS service (API gateway or direct backend). */
    private String baseUrl;

    /** When {@code true}, the client talks directly to the KMS backend. */
    private boolean direct = true;

    /** BlueKing app code. Required in both direct and APIGW modes. */
    private String appCode;

    /** BlueKing app secret, required when {@link #direct} is {@code false}. */
    private String appSecret;

    /** HTTP request timeout. */
    private Duration timeout = Duration.ofSeconds(30);

    /** KMS access key (per-caller credential). */
    private String accessKey;

    /** KMS secret key (per-caller credential). */
    private String secretKey;

    /** Optional multi-tenant identifier. Sent as {@code X-Bk-Tenant-Id}. */
    private String tenantId;

    /** Hybrid crypto algorithm selection. */
    private Crypto crypto = new Crypto();

    /** Configuration placeholder resolver settings. */
    private Placeholder placeholder = new Placeholder();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public boolean isDirect() {
        return direct;
    }

    public void setDirect(boolean direct) {
        this.direct = direct;
    }

    public String getAppCode() {
        return appCode;
    }

    public void setAppCode(String appCode) {
        this.appCode = appCode;
    }

    public String getAppSecret() {
        return appSecret;
    }

    public void setAppSecret(String appSecret) {
        this.appSecret = appSecret;
    }

    public Duration getTimeout() {
        return timeout;
    }

    public void setTimeout(Duration timeout) {
        this.timeout = timeout;
    }

    public String getAccessKey() {
        return accessKey;
    }

    public void setAccessKey(String accessKey) {
        this.accessKey = accessKey;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public Crypto getCrypto() {
        return crypto;
    }

    public void setCrypto(Crypto crypto) {
        this.crypto = crypto;
    }

    public Placeholder getPlaceholder() {
        return placeholder;
    }

    public void setPlaceholder(Placeholder placeholder) {
        this.placeholder = placeholder;
    }

    /** Hybrid encryption algorithm settings. */
    public static class Crypto {

        private CryptoType asymmetricType = CryptoType.RSA;
        private CryptoType symmetricType = CryptoType.AES;
        private CryptoMode symmetricMode = CryptoMode.CBC;

        public CryptoType getAsymmetricType() {
            return asymmetricType;
        }

        public void setAsymmetricType(CryptoType asymmetricType) {
            this.asymmetricType = asymmetricType;
        }

        public CryptoType getSymmetricType() {
            return symmetricType;
        }

        public void setSymmetricType(CryptoType symmetricType) {
            this.symmetricType = symmetricType;
        }

        public CryptoMode getSymmetricMode() {
            return symmetricMode;
        }

        public void setSymmetricMode(CryptoMode symmetricMode) {
            this.symmetricMode = symmetricMode;
        }
    }

    /** {@code KMS:xxx} placeholder resolver settings. */
    public static class Placeholder {

        private boolean enabled = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }
}
