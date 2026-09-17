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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Auto-configuration tests using {@link ApplicationContextRunner}.
 */
class KmsAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(KmsAutoConfiguration.class));

    @AfterEach
    void tearDown() {
        KmsPropertyResolver.reset();
    }

    @Test
    void registers_client_when_properties_are_present() {
        runner.withPropertyValues(
                        "bk.kms.base-url=http://localhost:23681",
                        "bk.kms.direct=true",
                        "bk.kms.app-code=app_code",
                        "bk.kms.access-key=ak",
                        "bk.kms.secret-key=sk")
                .run(context -> assertThat(context).hasSingleBean(Client.class));
    }

    @Test
    void does_not_register_when_disabled() {
        runner.withPropertyValues(
                        "bk.kms.enabled=false",
                        "bk.kms.base-url=http://localhost:23681")
                .run(context -> assertThat(context).doesNotHaveBean(Client.class));
    }

    @Test
    void backs_off_when_user_supplies_client_bean() {
        runner.withUserConfiguration(UserClientConfig.class)
                .withPropertyValues(
                        "bk.kms.base-url=http://localhost:23681",
                        "bk.kms.direct=true",
                        "bk.kms.app-code=app_code",
                        "bk.kms.access-key=ak",
                        "bk.kms.secret-key=sk")
                .run(context -> {
                    assertThat(context).hasSingleBean(Client.class);
                    assertThat(context.getBean(Client.class))
                            .isSameAs(context.getBean(UserClientConfig.class).userClient());
                });
    }

    @Test
    void fails_fast_when_base_url_is_missing() {
        runner.withPropertyValues(
                        "bk.kms.access-key=ak",
                        "bk.kms.secret-key=sk")
                .run(context -> assertThat(context).hasFailed());
    }

    @Configuration
    static class UserClientConfig {

        private final Client userClient = Mockito.mock(Client.class);

        @Bean
        Client userClient() {
            return userClient;
        }
    }
}
