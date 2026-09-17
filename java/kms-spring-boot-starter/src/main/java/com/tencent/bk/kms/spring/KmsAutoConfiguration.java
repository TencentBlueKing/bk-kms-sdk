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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for the BlueKing KMS Spring Boot starter. Registers a
 * {@link Client} bean when {@code bk.kms.enabled=true} (default) and no user
 * bean is already present.
 */
@AutoConfiguration
@EnableConfigurationProperties(KmsProperties.class)
@ConditionalOnProperty(prefix = "bk.kms", name = "enabled", havingValue = "true", matchIfMissing = true)
public class KmsAutoConfiguration {

    private static final Logger LOGGER = LoggerFactory.getLogger(KmsAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public Client kmsClient(KmsProperties properties) {
        try {
            Client client = KmsPropertiesSupport.buildClient(properties);
            KmsPropertyResolver.registerClient(client);
            return client;
        } catch (RuntimeException e) {
            LOGGER.error("failed to initialize BK-KMS client: {}", e.getMessage(), e);
            throw e;
        }
    }
}
