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
import com.tencent.bk.kms.types.KmsException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link KmsPropertyResolver}.
 */
class KmsPropertyResolverTest {

    private Client client;

    @BeforeEach
    void setUp() {
        client = Mockito.mock(Client.class);
        KmsPropertyResolver.reset();
        KmsPropertyResolver.registerClient(client);
    }

    @AfterEach
    void tearDown() {
        KmsPropertyResolver.reset();
    }

    @Test
    void non_kms_value_is_returned_unchanged() {
        assertEquals("plain-value", KmsPropertyResolver.resolve("plain-value"));
        assertEquals(null, KmsPropertyResolver.resolve(null));
    }

    @Test
    void single_password_credential_returns_password() {
        stubResult("db-password", new ConsumeResult(
                1L, 0, "",
                new Credential("db-password", CredentialType.SINGLE_PASSWORD,
                        new AuthInfo("s3cret", null, null, null), "")));

        assertEquals("s3cret", KmsPropertyResolver.resolve("KMS:db-password"));
    }

    @Test
    void single_secret_key_credential_returns_secret_key() {
        stubResult("api-key", new ConsumeResult(
                2L, 0, "",
                new Credential("api-key", CredentialType.SINGLE_SECRET_KEY,
                        new AuthInfo(null, null, "sk-xxx", null), "")));

        assertEquals("sk-xxx", KmsPropertyResolver.resolve("KMS:api-key"));
    }

    @Test
    void username_password_credential_requires_field() {
        stubResult("mysql-cred", new ConsumeResult(
                3L, 0, "",
                new Credential("mysql-cred", CredentialType.USERNAME_PASSWORD,
                        new AuthInfo("pw", "root", null, null), "")));

        KmsException ex = assertThrows(KmsException.class,
                () -> KmsPropertyResolver.resolve("KMS:mysql-cred"));
        assertTrue(ex.getMessage().contains("requires a '#field' suffix"),
                "unexpected message: " + ex.getMessage());

        assertEquals("pw", KmsPropertyResolver.resolve("KMS:mysql-cred#password"));
        assertEquals("root", KmsPropertyResolver.resolve("KMS:mysql-cred#username"));
    }

    @Test
    void app_id_secret_key_credential_supports_field_selectors() {
        stubResult("wework-app", new ConsumeResult(
                4L, 0, "",
                new Credential("wework-app", CredentialType.APP_ID_SECRET_KEY,
                        new AuthInfo(null, null, "sec", "app-123"), "")));

        assertEquals("app-123", KmsPropertyResolver.resolve("KMS:wework-app#app_id"));
        assertEquals("sec", KmsPropertyResolver.resolve("KMS:wework-app#secret_key"));
    }

    @Test
    void unknown_field_throws() {
        stubResult("mysql-cred", new ConsumeResult(
                5L, 0, "",
                new Credential("mysql-cred", CredentialType.USERNAME_PASSWORD,
                        new AuthInfo("pw", "root", null, null), "")));

        KmsException ex = assertThrows(KmsException.class,
                () -> KmsPropertyResolver.resolve("KMS:mysql-cred#nope"));
        assertTrue(ex.getMessage().contains("unknown KMS placeholder field"));
    }

    @Test
    void cache_ensures_only_one_remote_call_per_credential() {
        stubResult("db-password", new ConsumeResult(
                6L, 0, "",
                new Credential("db-password", CredentialType.SINGLE_PASSWORD,
                        new AuthInfo("s3cret", null, null, null), "")));

        KmsPropertyResolver.resolve("KMS:db-password");
        KmsPropertyResolver.resolve("KMS:db-password");
        KmsPropertyResolver.resolve("KMS:db-password");

        verify(client, times(1)).consumeCredential(ArgumentMatchers.any(ConsumeOptions.class));
    }

    @Test
    void non_zero_err_code_raises_exception() {
        stubResult("db-password", new ConsumeResult(
                7L, 1034003, "not found", null));

        KmsException ex = assertThrows(KmsException.class,
                () -> KmsPropertyResolver.resolve("KMS:db-password"));
        assertTrue(ex.getMessage().contains("db-password"));
        assertTrue(ex.getMessage().contains("1034003"));
        assertTrue(ex.getMessage().contains("not found"));
    }

    private void stubResult(String name, ConsumeResult result) {
        when(client.consumeCredential(ArgumentMatchers.any(ConsumeOptions.class)))
                .thenReturn(List.of(result));
        // Also configure a consume-options factory so the resolver has a template.
        KmsPropertyResolver.registerLazyClientFactory(
                () -> client,
                () -> ConsumeOptions.builder().accessKeySecret("ak", "sk"));
        // reference name to satisfy static analyzers that expect the parameter to be used
        assertTrue(name != null);
    }
}
