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

package com.tencent.bk.kms.examples.envelope;

import com.tencent.bk.kms.consume.Client;
import com.tencent.bk.kms.consume.ClientOptions;
import com.tencent.bk.kms.consume.ConsumeOptions;
import com.tencent.bk.kms.types.ConsumeEnvelope;
import com.tencent.bk.kms.types.ConsumeResult;
import com.tencent.bk.kms.types.Credential;
import com.tencent.bk.kms.types.ErrorCodes;

import java.util.List;

/**
 * Two-phase example: fetch the encrypted envelope now, decrypt it later.
 * The URL / access key / secret key are loaded from environment variables:
 *   BK_KMS_BASE_URL, BK_KMS_ACCESS_KEY, BK_KMS_SECRET_KEY
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        // Read connection parameters from environment variables to avoid
        // leaking credentials in source code.
        String baseUrl = requireEnv("BK_KMS_BASE_URL");
        String accessKey = requireEnv("BK_KMS_ACCESS_KEY");
        String secretKey = requireEnv("BK_KMS_SECRET_KEY");

        // Direct mode requires app code, which is sent as X-Bk-AppCode for
        // caller identification. SaaS callers should drop .direct(true) and
        // provide .appCode(...) plus .appSecret(...) along with an API gateway URL.
        Client client = Client.create(ClientOptions.builder()
                .baseUrl(baseUrl)
                .direct(true)
                .appCode("your_app_code_xxxx")
                .build());

        // Phase 1: fetch the envelope. Keep {envelope, privateKey} safe together.
        ConsumeEnvelope envelope = client.consumeCredentialEnvelope(ConsumeOptions.builder()
                .accessKeySecret(accessKey, secretKey)
//                .credentialNameList("credential_name_1", "credential_name_2")
                .build());

        System.out.println("envelope: " + envelope.envelope());
        System.out.println("private key: " + envelope.privateKey());

        // Phase 2: locally decrypt. This does not need any HTTP access.
        List<ConsumeResult> results = Client.decryptEnvelope(envelope);
        for (ConsumeResult result : results) {
            if (!ErrorCodes.isOk(result.errCode())) {
                System.out.printf(
                        "consume credential %d failed: code=%d, msg=%s%n",
                        result.credentialId(), result.errCode(), result.errMsg());
                continue;
            }
            Credential cred = result.credential();
            System.out.printf("credential %d: name=%s type=%s annotation=%s%n",
                    result.credentialId(), cred.name(), cred.type(), cred.annotation());

            // Extract auth fields per CredentialType. Covers all four wire values:
            // single_password / username_password / single_secret_key / app_id_secret_key.
            switch (cred.type()) {
                case SINGLE_PASSWORD -> System.out.printf("  password=%s%n",
                        cred.authInfo().password());
                case USERNAME_PASSWORD -> System.out.printf("  username=%s password=%s%n",
                        cred.authInfo().username(), cred.authInfo().password());
                case SINGLE_SECRET_KEY -> System.out.printf("  secret_key=%s%n",
                        cred.authInfo().secretKey());
                case APP_ID_SECRET_KEY -> System.out.printf("  app_id=%s secret_key=%s%n",
                        cred.authInfo().appId(), cred.authInfo().secretKey());
            }
        }
    }

    private static String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            throw new IllegalStateException("Environment variable " + name + " is required but not set");
        }
        return value;
    }
}
