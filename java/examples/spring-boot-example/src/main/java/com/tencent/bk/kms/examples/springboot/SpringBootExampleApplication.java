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

package com.tencent.bk.kms.examples.springboot;

import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Component;

/**
 * Spring Boot example that resolves every supported {@code KMS:xxx} placeholder
 * declared in {@code application.yml} into a plain-text credential value at
 * start-up and verifies the resolved value against the expected demo data.
 */
@SpringBootApplication
public class SpringBootExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootExampleApplication.class, args);
    }

    /** Prints every resolved KMS placeholder on start-up. */
    @Component
    public static class Runner implements CommandLineRunner {

        private static final Logger LOGGER = LoggerFactory.getLogger(Runner.class);

        // ---------- SINGLE_PASSWORD ----------
        @Value("${kms-demo.single-password.credential-name-2}")
        private String credentialName2Password;

        @Value("${kms-demo.single-password.test-2-sp}")
        private String test2SpPassword;

        // ---------- SINGLE_SECRET_KEY ----------
        @Value("${kms-demo.single-secret-key.test-2-sk}")
        private String test2SkSecretKey;

        // ---------- USERNAME_PASSWORD ----------
        @Value("${kms-demo.username-password.credential-name-1-username}")
        private String credentialName1Username;

        @Value("${kms-demo.username-password.credential-name-1-password}")
        private String credentialName1Password;

        @Value("${kms-demo.username-password.test-2-up-username}")
        private String test2UpUsername;

        @Value("${kms-demo.username-password.test-2-up-password}")
        private String test2UpPassword;

        // ---------- APP_ID_SECRET_KEY ----------
        @Value("${kms-demo.app-id-secret-key.test-2-app-app-id}")
        private String test2AppAppId;

        @Value("${kms-demo.app-id-secret-key.test-2-app-secret-key}")
        private String test2AppSecretKey;

        @Override
        public void run(String... args) {
            // Expected plain-text values based on the KMS demo data.
            Map<String, String[]> cases = new LinkedHashMap<>();
            // key -> [ actual, expected, description ]
            cases.put(
                "credential_name_2 (SINGLE_PASSWORD)",
                new String[] {credentialName2Password, "demo-pass-2", "password"});
            cases.put(
                "test-2-sp (SINGLE_PASSWORD)",
                new String[] {test2SpPassword, "test-2-pass", "password"});
            cases.put(
                "test-2-sk (SINGLE_SECRET_KEY)",
                new String[] {test2SkSecretKey, "test-2-secret", "secret_key"});
            cases.put(
                "credential_name_1#username (USERNAME_PASSWORD)",
                new String[] {credentialName1Username, "demo-user-1", "username"});
            cases.put(
                "credential_name_1#password (USERNAME_PASSWORD)",
                new String[] {credentialName1Password, "demo-pass-1", "password"});
            cases.put(
                "test-2-up#username (USERNAME_PASSWORD)",
                new String[] {test2UpUsername, "test-2-user", "username"});
            cases.put(
                "test-2-up#password (USERNAME_PASSWORD)",
                new String[] {test2UpPassword, "test-2-pass-2", "password"});
            cases.put(
                "test-2-app#app_id (APP_ID_SECRET_KEY)",
                new String[] {test2AppAppId, "test-2-appid", "app_id"});
            cases.put(
                "test-2-app#secret_key (APP_ID_SECRET_KEY)",
                new String[] {test2AppSecretKey, "test-2-secret", "secret_key"});

            int passed = 0;
            int failed = 0;
            LOGGER.info("========== BK-KMS placeholder resolution test ==========");
            for (Map.Entry<String, String[]> entry : cases.entrySet()) {
                String name = entry.getKey();
                String actual = entry.getValue()[0];
                String expected = entry.getValue()[1];
                boolean ok = expected.equals(actual);
                if (ok) {
                    passed++;
                    LOGGER.info("[PASS] {} -> {}", name, actual);
                } else {
                    failed++;
                    LOGGER.error("[FAIL] {} -> actual='{}', expected='{}'", name, actual, expected);
                }
            }
            LOGGER.info("========== summary: total={}, passed={}, failed={} ==========",
                cases.size(), passed, failed);
        }
    }
}
