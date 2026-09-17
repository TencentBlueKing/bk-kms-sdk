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

package com.tencent.bk.kms.internal.signature;

import com.tencent.bk.kms.internal.common.Hex;
import com.tencent.bk.kms.internal.common.HmacSha256;
import com.tencent.bk.kms.types.CryptoInfo;
import com.tencent.bk.kms.types.CryptoMode;
import com.tencent.bk.kms.types.CryptoType;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the consume signature algorithm.
 */
class SignatureTest {

    private static final String SECRET_KEY = "test-secret-key";
    private static final String NONCE = "testnonce0123456789abcdef0123456";
    private static final String TIMESTAMP = "1700000000";
    private static final String PUBLIC_KEY = "dummy-public-key";

    @Test
    void empty_lists_serialize_as_arrays_not_null() throws Exception {
        SignContent content = new SignContent(
                null, null,
                new CryptoInfo(CryptoType.RSA, CryptoType.AES, CryptoMode.CBC),
                PUBLIC_KEY);
        String json = ConsumeSignature.MAPPER.writeValueAsString(content);
        // Field order must be preserved.
        assertTrue(json.startsWith(
                "{\"credential_id_list\":[],\"credential_name_list\":[],\"crypto\":"),
                "unexpected field order or empty-list representation: " + json);
        assertTrue(json.contains("\"public_key\":\"" + PUBLIC_KEY + "\""));
    }

    @Test
    void signature_is_lowercase_hex_of_expected_length() {
        SignContent content = new SignContent(
                List.of(), List.of("credential_name_1"),
                new CryptoInfo(CryptoType.RSA, CryptoType.AES, CryptoMode.CBC),
                PUBLIC_KEY);
        String sig = new ConsumeSignature(SECRET_KEY, NONCE, TIMESTAMP, content).sign();

        assertNotNull(sig);
        assertEquals(64, sig.length(), "HMAC-SHA256 hex must be 64 characters");
        assertTrue(sig.matches("[0-9a-f]{64}"), "signature must be lowercase hex: " + sig);
    }

    @Test
    void signature_matches_reference_calculation() throws Exception {
        // Build a stable, known SignContent.
        SignContent content = new SignContent(
                List.of(), List.of("credential_name_1"),
                new CryptoInfo(CryptoType.RSA, CryptoType.AES, CryptoMode.CBC),
                PUBLIC_KEY);
        String actual = new ConsumeSignature(SECRET_KEY, NONCE, TIMESTAMP, content).sign();

        // Independently recompute using the same primitives. The reference
        // implementation must reuse the same HTML-escaping mapper so that HTML
        // escaping stays in lockstep with the signer.
        byte[] contentBytes = ConsumeSignature.MAPPER.writeValueAsBytes(content);
        String contentHash = Hex.encode(
                MessageDigest.getInstance("SHA-256").digest(contentBytes));
        String stringToSign = TIMESTAMP + "\n" + NONCE + "\n" + contentHash;
        byte[] signingKey = HmacSha256.hmac(
                SECRET_KEY.getBytes(StandardCharsets.UTF_8),
                NONCE.getBytes(StandardCharsets.UTF_8));
        String expected = Hex.encode(
                HmacSha256.hmac(signingKey, stringToSign.getBytes(StandardCharsets.UTF_8)));

        assertEquals(expected, actual);
    }

    /**
     * Guards against a regression that would drop HTML escaping from the
     * signer's Jackson mapper. {@code <}, {@code >} and {@code &} must be
     * emitted as their six-character escape sequences, and the SHA-256 hash
     * of the JSON bytes feeds the signature, so any drift here breaks the
     * signature the moment a credential name contains one of these characters.
     */
    @Test
    void sign_content_html_characters_are_escaped() throws Exception {
        SignContent content = new SignContent(
                List.of(), List.of("a<b", "c>d", "e&f"),
                new CryptoInfo(CryptoType.RSA, CryptoType.AES, CryptoMode.CBC),
                PUBLIC_KEY);
        String json = ConsumeSignature.MAPPER.writeValueAsString(content);

        // Six-character escape sequences must be present; raw characters must not.
        assertTrue(json.contains("a\\u003cb"), "'<' must be escaped: " + json);
        assertTrue(json.contains("c\\u003ed"), "'>' must be escaped: " + json);
        assertTrue(json.contains("e\\u0026f"), "'&' must be escaped: " + json);
        org.junit.jupiter.api.Assertions.assertFalse(
                json.contains("a<b") || json.contains("c>d") || json.contains("e&f"),
                "raw HTML characters leaked into signed JSON: " + json);
    }

    /**
     * Byte-for-byte reference vector for the same {@link SignContent}. Any
     * deviation here means the signer would produce a mismatching signature.
     */
    @Test
    void sign_content_bytes_match_reference_when_containing_html_chars() throws Exception {
        SignContent content = new SignContent(
                List.of(1L, 2L), List.of("name<1>", "a&b"),
                new CryptoInfo(CryptoType.RSA, CryptoType.AES, CryptoMode.CBC),
                "pk<xyz>");
        String json = ConsumeSignature.MAPPER.writeValueAsString(content);

        // Expected (whitespace-free, keys in declared order):
        //   {"credential_id_list":[1,2],"credential_name_list":["name\u003c1\u003e","a\u0026b"],
        //    "crypto":{"asymmetric_type":"RSA","symmetric_type":"AES","symmetric_mode":"CBC"},
        //    "public_key":"pk\u003cxyz\u003e"}
        String expected =
                "{\"credential_id_list\":[1,2],\"credential_name_list\":"
                + "[\"name\\u003c1\\u003e\",\"a\\u0026b\"],"
                + "\"crypto\":{\"asymmetric_type\":\"RSA\",\"symmetric_type\":\"AES\","
                + "\"symmetric_mode\":\"CBC\"},"
                + "\"public_key\":\"pk\\u003cxyz\\u003e\"}";
        assertEquals(expected, json);
    }

    @Test
    void signature_is_deterministic_for_the_same_input() {
        SignContent content = new SignContent(
                List.of(), List.of("credential_name_1"),
                new CryptoInfo(CryptoType.RSA, CryptoType.AES, CryptoMode.CBC),
                PUBLIC_KEY);
        String first = new ConsumeSignature(SECRET_KEY, NONCE, TIMESTAMP, content).sign();
        String second = new ConsumeSignature(SECRET_KEY, NONCE, TIMESTAMP, content).sign();
        assertEquals(first, second);
    }
}
