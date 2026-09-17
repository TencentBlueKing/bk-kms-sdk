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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;

import java.util.ArrayList;
import java.util.List;

/**
 * Wraps every {@link PropertySource} in the environment with a
 * {@link KmsPropertySource} so that values starting with {@code KMS:} are
 * decrypted transparently at property lookup time.
 *
 * <p>Runs after configuration data has been contributed to the environment.
 */
public class KmsEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    private static final Logger LOGGER = LoggerFactory.getLogger(KmsEnvironmentPostProcessor.class);

    /**
     * Order: after {@code ConfigDataEnvironmentPostProcessor}
     * (order = {@code Ordered.HIGHEST_PRECEDENCE + 10}) so that user-visible
     * application.yml sources exist before we wrap them.
     */
    public static final int ORDER = Ordered.HIGHEST_PRECEDENCE + 11;

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        KmsProperties properties;
        try {
            properties = Binder.get(environment)
                    .bind("bk.kms", KmsProperties.class)
                    .orElse(null);
        } catch (Exception ex) {
            // Binding failed (e.g. unresolved ${...} placeholders in bk.kms.*).
            // Skip placeholder wiring and surface a clear warning so that users
            // can distinguish this from a genuine KMS runtime failure.
            LOGGER.warn("failed to bind bk.kms properties, BK-KMS placeholder resolver will be disabled: {}",
                    ex.getMessage());
            return;
        }

        if (properties == null) {
            LOGGER.info("no bk.kms configuration found, BK-KMS placeholder resolver is disabled");
            return;
        }
        if (!properties.isEnabled()) {
            LOGGER.info("bk.kms.enabled=false, BK-KMS placeholder resolver is disabled");
            return;
        }

        // Fail fast when the starter is enabled but mandatory credentials are missing,
        // so that startup does not silently fall back to unresolved placeholders.
        validateMandatoryProperties(properties);

        if (!properties.getPlaceholder().isEnabled()) {
            LOGGER.info("bk.kms.placeholder.enabled=false, KMS:xxx placeholders will not be resolved");
            return;
        }

        // Register a lazy Client factory. The factory is only invoked if a
        // placeholder is resolved before the auto-configured bean is ready.
        KmsPropertyResolver.registerLazyClientFactory(
                () -> Client.create(KmsPropertiesSupport.buildClientOptions(properties)),
                () -> KmsPropertiesSupport.consumeOptionsTemplate(properties));

        wrap(environment.getPropertySources());
        LOGGER.info("BK-KMS placeholder resolver enabled, baseUrl={}", properties.getBaseUrl());
    }

    /**
     * Validates that {@code base-url}, {@code app-code}, {@code access-key}
     * and {@code secret-key} are present when the starter is enabled.
     * Throws {@link IllegalStateException} to abort application startup with
     * an actionable message.
     */
    private static void validateMandatoryProperties(KmsProperties properties) {
        List<String> missing = new ArrayList<>(4);
        if (isBlank(properties.getBaseUrl())) {
            missing.add("bk.kms.base-url");
        }
        if (isBlank(properties.getAppCode())) {
            missing.add("bk.kms.app-code");
        }
        if (isBlank(properties.getAccessKey())) {
            missing.add("bk.kms.access-key");
        }
        if (isBlank(properties.getSecretKey())) {
            missing.add("bk.kms.secret-key");
        }
        if (!missing.isEmpty()) {
            String message = "BK-KMS is enabled but required properties are missing: " + String.join(", ", missing)
                    + ". Please configure them or set bk.kms.enabled=false to disable the starter.";
            LOGGER.error(message);
            throw new IllegalStateException(message);
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /**
     * The name of the aggregating {@code PropertySource} that Spring Boot
     * attaches to the environment. It has no data of its own but iterates over
     * the other sources at lookup time, so wrapping it would cause infinite
     * recursion (the wrapper's delegate would call back into this wrapper).
     */
    private static final String ATTACHED_CONFIGURATION_PROPERTY_SOURCE_NAME = "configurationProperties";

    private static void wrap(MutablePropertySources sources) {
        List<PropertySource<?>> snapshot = new ArrayList<>();
        for (PropertySource<?> source : sources) {
            snapshot.add(source);
        }
        for (PropertySource<?> source : snapshot) {
            if (source instanceof KmsPropertySource) {
                continue;
            }
            // Skip the aggregating "configurationProperties" source to avoid
            // infinite recursion (see field javadoc above).
            if (ATTACHED_CONFIGURATION_PROPERTY_SOURCE_NAME.equals(source.getName())) {
                continue;
            }
            sources.replace(source.getName(), new KmsPropertySource(source));
        }
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
