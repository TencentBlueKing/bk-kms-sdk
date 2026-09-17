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

import com.fasterxml.jackson.core.io.CharacterEscapes;
import com.fasterxml.jackson.core.io.SerializedString;
import com.fasterxml.jackson.core.SerializableString;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tencent.bk.kms.internal.common.Hex;
import com.tencent.bk.kms.internal.common.HmacSha256;
import com.tencent.bk.kms.types.KmsException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Computes the {@code X-BKKMS-Signature} header value:
 * <pre>{@code
 *   signingKey  = HMAC-SHA256(secretKey, nonce)
 *   contentHash = HEX(SHA256(bodyJsonBytes))
 *   stringToSign = timestamp + "\n" + nonce + "\n" + contentHash
 *   signature   = HEX(HMAC-SHA256(signingKey, stringToSign))
 * }</pre>
 *
 * <p>The JSON body is serialized with HTML escaping (the literal ASCII
 * characters {@code <}, {@code >} and {@code &} are emitted as their
 * six-character JSON escape sequences, in lower-case hex). This is essential:
 * the SHA-256 hash of the body bytes participates in the signature, so any
 * single-byte drift would produce a mismatching signature whenever the
 * payload contains these characters.
 *
 * <p><b>Internal API.</b> Do not depend on this class from outside the SDK.
 */
public final class ConsumeSignature {

    /**
     * Mapper preconfigured to escape the literal ASCII characters {@code <},
     * {@code >} and {@code &} as their six-character JSON escape sequences
     * (lower-case hex). Shared and thread-safe.
     *
     * <p>This mapper MUST be reused for serializing any HTTP request body
     * whose SHA-256 content hash participates in the signature. Using a
     * different (non-escaping) mapper for the wire payload would cause a
     * byte-level drift versus the signed content and produce mismatching
     * signatures whenever the payload contains {@code <}, {@code >} or
     * {@code &} (for example, a credential name such as {@code a&b}).
     *
     * <p><b>Internal API.</b> Exposed only for reuse inside the SDK.
     */
    public static final ObjectMapper MAPPER = createMapper();

    private static ObjectMapper createMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.getFactory().setCharacterEscapes(new HtmlEscapes());
        return mapper;
    }

    private final String secretKey;
    private final String nonce;
    private final String timestamp;
    private final SignContent signContent;

    public ConsumeSignature(String secretKey, String nonce, String timestamp, SignContent signContent) {
        this.secretKey = secretKey;
        this.nonce = nonce;
        this.timestamp = timestamp;
        this.signContent = signContent;
    }

    /**
     * Computes the signature as lower-case hex.
     */
    public String sign() {
        if (secretKey == null || secretKey.isEmpty()) {
            throw new KmsException("invalid secret key");
        }
        if (nonce == null || nonce.isEmpty()) {
            throw new KmsException("invalid nonce");
        }
        if (timestamp == null || timestamp.isEmpty()) {
            throw new KmsException("invalid timestamp");
        }
        Objects.requireNonNull(signContent, "signContent");

        byte[] contentBytes;
        try {
            contentBytes = MAPPER.writeValueAsBytes(signContent);
        } catch (Exception e) {
            throw new KmsException("marshal sign content error(" + e.getMessage() + ")", e);
        }

        String contentHash = Hex.encode(sha256(contentBytes));
        String stringToSign = timestamp + "\n" + nonce + "\n" + contentHash;

        byte[] signingKey = HmacSha256.hmac(
                secretKey.getBytes(StandardCharsets.UTF_8),
                nonce.getBytes(StandardCharsets.UTF_8));
        byte[] signature = HmacSha256.hmac(
                signingKey, stringToSign.getBytes(StandardCharsets.UTF_8));
        return Hex.encode(signature);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new KmsException("sha-256 error(" + e.getMessage() + ")", e);
        }
    }

    /**
     * Character escape strategy for HTML escaping: only {@code <}, {@code >}
     * and {@code &} are escaped, using the backslash-u lower-case hex form
     * (that is, {@code \\u003c}, {@code \\u003e}, {@code \\u0026}). All other
     * characters follow Jackson's standard escaping rules.
     */
    private static final class HtmlEscapes extends CharacterEscapes {

        private static final long serialVersionUID = 1L;

        private static final int[] ESCAPES;

        static {
            int[] esc = CharacterEscapes.standardAsciiEscapesForJSON();
            esc['<'] = CharacterEscapes.ESCAPE_CUSTOM;
            esc['>'] = CharacterEscapes.ESCAPE_CUSTOM;
            esc['&'] = CharacterEscapes.ESCAPE_CUSTOM;
            ESCAPES = esc;
        }

        private static final SerializableString LT = new SerializedString("\\u003c");
        private static final SerializableString GT = new SerializedString("\\u003e");
        private static final SerializableString AMP = new SerializedString("\\u0026");

        @Override
        public int[] getEscapeCodesForAscii() {
            return ESCAPES;
        }

        @Override
        public SerializableString getEscapeSequence(int ch) {
            return switch (ch) {
                case '<' -> LT;
                case '>' -> GT;
                case '&' -> AMP;
                default -> null;
            };
        }
    }
}
