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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link KmsEnvironmentPostProcessor} placeholder wrapping.
 */
class KmsEnvironmentPostProcessorTest {

    private Client client;

    @BeforeEach
    void setUp() {
        client = Mockito.mock(Client.class);
        KmsPropertyResolver.reset();
    }

    @AfterEach
    void tearDown() {
        KmsPropertyResolver.reset();
    }

    @Test
    void placeholder_values_are_decrypted_on_lookup() {
        when(client.consumeCredential(ArgumentMatchers.any(ConsumeOptions.class)))
                .thenReturn(List.of(new ConsumeResult(
                        1L, 0, "",
                        new Credential("db-password", CredentialType.SINGLE_PASSWORD,
                                new AuthInfo("plain-secret", null, null, null), ""))));

        StandardEnvironment env = new StandardEnvironment();
        Map<String, Object> config = new HashMap<>();
        config.put("bk.kms.enabled", true);
        config.put("bk.kms.placeholder.enabled", true);
        config.put("bk.kms.base-url", "http://localhost:23681");
        config.put("bk.kms.direct", true);
        config.put("bk.kms.app-code", "app_code");
        config.put("bk.kms.access-key", "ak");
        config.put("bk.kms.secret-key", "sk");
        config.put("spring.datasource.password", "KMS:db-password");
        env.getPropertySources().addFirst(new MapPropertySource("test-config", config));

        new KmsEnvironmentPostProcessor().postProcessEnvironment(env, new SpringApplication());
        KmsPropertyResolver.registerClient(client);

        assertEquals("plain-secret", env.getProperty("spring.datasource.password"));
        assertEquals("http://localhost:23681", env.getProperty("bk.kms.base-url"));
    }

    @Test
    void disabled_placeholder_leaves_value_untouched() {
        StandardEnvironment env = new StandardEnvironment();
        Map<String, Object> config = new HashMap<>();
        config.put("bk.kms.enabled", true);
        config.put("bk.kms.placeholder.enabled", false);
        config.put("bk.kms.base-url", "http://localhost:23681");
        config.put("bk.kms.access-key", "ak");
        config.put("bk.kms.secret-key", "sk");
        config.put("spring.datasource.password", "KMS:db-password");
        env.getPropertySources().addFirst(new MapPropertySource("test-config", config));

        new KmsEnvironmentPostProcessor().postProcessEnvironment(env, new SpringApplication());

        assertEquals("KMS:db-password", env.getProperty("spring.datasource.password"));
    }
}
