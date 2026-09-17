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

package com.tencent.bk.kms.types;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies JSON serialization contracts (field order, empty-list handling) for
 * request payload records.
 */
class SerializationTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void consume_credential_req_has_fixed_field_order() throws Exception {
        ConsumeCredentialReq req = new ConsumeCredentialReq(
                null, null,
                new CryptoInfo(CryptoType.RSA, CryptoType.AES, CryptoMode.CBC),
                "public-key");
        String json = mapper.writeValueAsString(req);
        int idx = json.indexOf("\"credential_id_list\"");
        int idx2 = json.indexOf("\"credential_name_list\"");
        int idx3 = json.indexOf("\"crypto\"");
        int idx4 = json.indexOf("\"public_key\"");
        assertTrue(idx >= 0 && idx < idx2 && idx2 < idx3 && idx3 < idx4,
                "field order incorrect: " + json);
    }

    @Test
    void empty_credential_lists_serialize_as_bracket_pairs() throws Exception {
        ConsumeCredentialReq req = new ConsumeCredentialReq(
                null, null,
                new CryptoInfo(CryptoType.RSA, CryptoType.AES, CryptoMode.CBC),
                "public-key");
        String json = mapper.writeValueAsString(req);
        assertTrue(json.contains("\"credential_id_list\":[]"), json);
        assertTrue(json.contains("\"credential_name_list\":[]"), json);
    }

    @Test
    void crypto_info_has_fixed_field_order() throws Exception {
        CryptoInfo crypto = new CryptoInfo(CryptoType.RSA, CryptoType.AES, CryptoMode.CBC);
        String json = mapper.writeValueAsString(crypto);
        assertEquals("{\"asymmetric_type\":\"RSA\",\"symmetric_type\":\"AES\",\"symmetric_mode\":\"CBC\"}", json);
    }

    @Test
    void non_empty_credential_name_list_round_trips() throws Exception {
        ConsumeCredentialReq req = new ConsumeCredentialReq(
                List.of(), List.of("a", "b"),
                new CryptoInfo(CryptoType.SM2, CryptoType.SM4, CryptoMode.CTR),
                "pk");
        String json = mapper.writeValueAsString(req);
        assertTrue(json.contains("\"credential_name_list\":[\"a\",\"b\"]"), json);
    }

    /**
     * Deserialization is a byte-exact string compare, so lower-case values
     * must be rejected.
     */
    @Test
    void crypto_type_deserialization_is_case_sensitive() throws Exception {
        assertEquals(CryptoType.AES, mapper.readValue("\"AES\"", CryptoType.class));
        assertThrows(Exception.class, () -> mapper.readValue("\"aes\"", CryptoType.class));
        assertThrows(Exception.class, () -> mapper.readValue("\"Aes\"", CryptoType.class));
    }

    /**
     * Same case-sensitivity contract for {@link CryptoMode}.
     */
    @Test
    void crypto_mode_deserialization_is_case_sensitive() throws Exception {
        assertEquals(CryptoMode.CBC, mapper.readValue("\"CBC\"", CryptoMode.class));
        assertThrows(Exception.class, () -> mapper.readValue("\"cbc\"", CryptoMode.class));
        assertThrows(Exception.class, () -> mapper.readValue("\"Cbc\"", CryptoMode.class));
    }

    /**
     * {@link CredentialType} is defined with lower-snake-case wire values
     * ({@code single_password}, ...); any other spelling is rejected.
     */
    @Test
    void credential_type_deserialization_is_case_sensitive() throws Exception {
        assertEquals(CredentialType.SINGLE_PASSWORD,
                mapper.readValue("\"single_password\"", CredentialType.class));
        assertThrows(Exception.class,
                () -> mapper.readValue("\"SINGLE_PASSWORD\"", CredentialType.class));
        assertThrows(Exception.class,
                () -> mapper.readValue("\"Single_Password\"", CredentialType.class));
    }
}
