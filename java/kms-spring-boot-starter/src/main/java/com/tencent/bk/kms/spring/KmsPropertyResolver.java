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
import com.tencent.bk.kms.consume.ConsumeOptions;
import com.tencent.bk.kms.types.AuthInfo;
import com.tencent.bk.kms.types.ConsumeResult;
import com.tencent.bk.kms.types.Credential;
import com.tencent.bk.kms.types.CredentialType;
import com.tencent.bk.kms.types.ErrorCodes;
import com.tencent.bk.kms.types.KmsException;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Resolves {@code KMS:credential_name[#field]} placeholders into decrypted
 * credential values. Results are cached per {@code credentialName} so each
 * credential is fetched from KMS at most once per JVM start-up.
 */
public final class KmsPropertyResolver {

    /** Prefix that identifies a KMS-managed placeholder value. */
    public static final String PLACEHOLDER_PREFIX = "KMS:";

    private static final String FIELD_SEPARATOR = "#";

    // Supported field names for multi-field credentials.
    private static final String FIELD_PASSWORD = "password";
    private static final String FIELD_USERNAME = "username";
    private static final String FIELD_SECRET_KEY = "secret_key";
    private static final String FIELD_APP_ID = "app_id";

    private static final ConcurrentHashMap<String, List<ConsumeResult>> CACHE = new ConcurrentHashMap<>();

    private static volatile Client client;
    private static volatile Supplier<Client> clientFactory;
    private static volatile Supplier<ConsumeOptions.Builder> consumeOptionsFactory;

    private KmsPropertyResolver() {
    }

    /**
     * Registers the primary (bean-managed) {@link Client} so subsequent
     * placeholder resolutions can reuse it.
     */
    public static void registerClient(Client c) {
        client = c;
    }

    /**
     * Provides a lazy fallback {@link Client} factory. Invoked when a
     * placeholder is resolved before the {@link Client} bean is initialised
     * (e.g. DataSource beans that are created earlier in the graph).
     */
    public static void registerLazyClientFactory(
            Supplier<Client> clientSupplier,
            Supplier<ConsumeOptions.Builder> consumeOptionsSupplier) {
        clientFactory = clientSupplier;
        consumeOptionsFactory = consumeOptionsSupplier;
    }

    /**
     * Clears cached credentials and registered clients. Primarily used by tests.
     */
    public static void reset() {
        CACHE.clear();
        client = null;
        clientFactory = null;
        consumeOptionsFactory = null;
    }

    /**
     * Resolves a raw property value. Values that do not start with
     * {@code KMS:} are returned unchanged.
     */
    public static String resolve(String rawValue) {
        if (rawValue == null || !rawValue.startsWith(PLACEHOLDER_PREFIX)) {
            return rawValue;
        }

        String spec = rawValue.substring(PLACEHOLDER_PREFIX.length());
        String credentialName;
        String field;
        int hashIndex = spec.indexOf(FIELD_SEPARATOR);
        if (hashIndex < 0) {
            credentialName = spec;
            field = null;
        } else {
            credentialName = spec.substring(0, hashIndex);
            field = spec.substring(hashIndex + 1);
        }
        if (credentialName.isBlank()) {
            throw new KmsException("invalid KMS placeholder: credential name is empty");
        }

        List<ConsumeResult> results = CACHE.computeIfAbsent(credentialName, KmsPropertyResolver::fetch);
        ConsumeResult target = pickResult(credentialName, results);

        if (!ErrorCodes.isOk(target.errCode())) {
            throw new KmsException("consume credential '" + credentialName + "' failed: code="
                    + target.errCode() + ", message=" + target.errMsg());
        }

        Credential credential = target.credential();
        if (credential == null || credential.authInfo() == null) {
            throw new KmsException("credential '" + credentialName + "' has no auth info");
        }
        return extractField(credentialName, credential, field);
    }

    private static ConsumeResult pickResult(String credentialName, List<ConsumeResult> results) {
        if (results == null || results.isEmpty()) {
            throw new KmsException("credential '" + credentialName + "' not found");
        }
        // Prefer a result whose credential name matches.
        for (ConsumeResult r : results) {
            if (r.credential() != null && credentialName.equals(r.credential().name())) {
                return r;
            }
        }
        // Otherwise pick the first (single-credential case).
        return results.get(0);
    }

    private static String extractField(String credentialName, Credential credential, String field) {
        CredentialType type = credential.type();
        AuthInfo auth = credential.authInfo();

        if (field == null || field.isEmpty()) {
            return switch (Objects.requireNonNull(type, "credential type")) {
                case SINGLE_PASSWORD -> requireNonBlank(auth.password(), credentialName, FIELD_PASSWORD);
                case SINGLE_SECRET_KEY -> requireNonBlank(auth.secretKey(), credentialName, FIELD_SECRET_KEY);
                case USERNAME_PASSWORD, APP_ID_SECRET_KEY -> throw new KmsException(
                        "credential '" + credentialName + "' has type " + type.getValue()
                                + " and requires a '#field' suffix (password / username / secret_key / app_id)");
            };
        }

        return switch (field) {
            case FIELD_PASSWORD -> requireNonBlank(auth.password(), credentialName, FIELD_PASSWORD);
            case FIELD_USERNAME -> requireNonBlank(auth.username(), credentialName, FIELD_USERNAME);
            case FIELD_SECRET_KEY -> requireNonBlank(auth.secretKey(), credentialName, FIELD_SECRET_KEY);
            case FIELD_APP_ID -> requireNonBlank(auth.appId(), credentialName, FIELD_APP_ID);
            default -> throw new KmsException(
                    "unknown KMS placeholder field '" + field + "' for credential '" + credentialName + "'");
        };
    }

    private static String requireNonBlank(String value, String credentialName, String fieldName) {
        if (value == null || value.isEmpty()) {
            throw new KmsException("credential '" + credentialName + "' field '" + fieldName + "' is empty");
        }
        return value;
    }

    private static List<ConsumeResult> fetch(String credentialName) {
        Client c = obtainClient();
        ConsumeOptions.Builder builder = obtainConsumeOptionsBuilder();
        builder.credentialNameList(credentialName);
        return c.consumeCredential(builder.build());
    }

    private static Client obtainClient() {
        Client local = client;
        if (local != null) {
            return local;
        }
        Supplier<Client> factory = clientFactory;
        if (factory == null) {
            throw new KmsException(
                    "BK-KMS Client is not available yet; ensure bk.kms.* properties are configured");
        }
        synchronized (KmsPropertyResolver.class) {
            if (client == null) {
                client = factory.get();
            }
            return client;
        }
    }

    private static ConsumeOptions.Builder obtainConsumeOptionsBuilder() {
        Supplier<ConsumeOptions.Builder> factory = consumeOptionsFactory;
        if (factory == null) {
            throw new KmsException(
                    "BK-KMS ConsumeOptions template is not available; ensure bk.kms.access-key and "
                            + "bk.kms.secret-key are configured");
        }
        return factory.get();
    }
}
