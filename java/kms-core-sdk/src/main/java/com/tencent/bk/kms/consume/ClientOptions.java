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

import java.net.http.HttpClient;
import java.time.Duration;

/**
 * Immutable {@link Client} construction options. Use {@link #builder()} to build.
 */
public final class ClientOptions {

    /** Default HTTP request timeout when {@link Builder#timeout(Duration)} is not set. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private final String baseUrl;
    private final boolean direct;
    private final String appCode;
    private final String appSecret;
    private final Duration timeout;
    private final HttpClient httpClient;

    private ClientOptions(Builder builder) {
        this.baseUrl = builder.baseUrl;
        this.direct = builder.direct;
        this.appCode = builder.appCode;
        this.appSecret = builder.appSecret;
        this.timeout = builder.timeout;
        this.httpClient = builder.httpClient;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public boolean isDirect() {
        return direct;
    }

    public String getAppCode() {
        return appCode;
    }

    public String getAppSecret() {
        return appSecret;
    }

    public Duration getTimeout() {
        return timeout;
    }

    public HttpClient getHttpClient() {
        return httpClient;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Fluent builder for {@link ClientOptions}. */
    public static final class Builder {

        private String baseUrl;
        private boolean direct;
        private String appCode;
        private String appSecret;
        private Duration timeout = DEFAULT_TIMEOUT;
        private HttpClient httpClient;

        /** Sets the KMS base URL. Trailing slashes are stripped. */
        public Builder baseUrl(String baseUrl) {
            if (baseUrl != null) {
                String v = baseUrl;
                while (v.endsWith("/")) {
                    v = v.substring(0, v.length() - 1);
                }
                this.baseUrl = v;
            } else {
                this.baseUrl = null;
            }
            return this;
        }

        /**
         * Enables direct mode against the KMS backend. In direct mode, app
         * secret is not required, but app code is still required and will be
         * sent as {@code X-Bk-AppCode} for caller identification.
         */
        public Builder direct(boolean direct) {
            this.direct = direct;
            return this;
        }

        /** Convenience for {@code direct(true)}. */
        public Builder direct() {
            return direct(true);
        }

        /** Sets the BlueKing app code. Required in both direct and APIGW modes. */
        public Builder appCode(String appCode) {
            this.appCode = appCode;
            return this;
        }

        /** Sets the BlueKing app secret. Required only in APIGW mode. */
        public Builder appSecret(String appSecret) {
            this.appSecret = appSecret;
            return this;
        }

        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        public ClientOptions build() {
            if (baseUrl == null || baseUrl.isBlank()) {
                throw new IllegalArgumentException("invalid client options, base url cannot be empty");
            }
            if (appCode == null || appCode.isBlank()) {
                throw new IllegalArgumentException("invalid client options, app code cannot be empty");
            }
            if (!direct && (appSecret == null || appSecret.isBlank())) {
                throw new IllegalArgumentException("invalid client options, app secret cannot be empty");
            }
            if (timeout == null || timeout.isZero() || timeout.isNegative()) {
                throw new IllegalArgumentException("invalid client options, timeout is invalid");
            }
            return new ClientOptions(this);
        }
    }
}
