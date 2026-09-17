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

package com.tencent.bk.kms.consume;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tencent.bk.kms.internal.common.Authorization;
import com.tencent.bk.kms.internal.common.Headers;
import com.tencent.bk.kms.internal.common.HttpDateParser;
import com.tencent.bk.kms.internal.common.Urls;
import com.tencent.bk.kms.internal.common.Uuids;
import com.tencent.bk.kms.internal.crypto.KeyPair;
import com.tencent.bk.kms.internal.crypto.KeyPairs;
import com.tencent.bk.kms.internal.retry.Retry;
import com.tencent.bk.kms.internal.retry.RetryResult;
import com.tencent.bk.kms.internal.signature.ConsumeSignature;
import com.tencent.bk.kms.internal.signature.Nonces;
import com.tencent.bk.kms.internal.signature.SignContent;
import com.tencent.bk.kms.types.ConsumeCredentialReq;
import com.tencent.bk.kms.types.ConsumeCredentialResp;
import com.tencent.bk.kms.types.ConsumeEnvelope;
import com.tencent.bk.kms.types.ConsumeResult;
import com.tencent.bk.kms.types.ErrorCodes;
import com.tencent.bk.kms.types.KmsException;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Default {@link Client} implementation, backed by the JDK 17
 * {@link java.net.http.HttpClient}.
 */
final class DefaultClient implements Client {

    /** Consume credential API-Gateway path (SaaS / gateway routing). */
    static final String CONSUME_CREDENTIAL_APIGW_PATH = "/api/v1/consume_credential";

    /** Consume credential direct-mode path (platform integration). */
    static final String CONSUME_CREDENTIAL_PATH = "/api/v1/consume/credential";

    /** Maximum attempts per consume call. */
    static final int CONSUME_MAX_ATTEMPTS = 2;

    /**
     * Mapper used to serialize the HTTP request body. Reuses the HTML-escaping
     * mapper from {@link ConsumeSignature} so that the bytes placed on the wire
     * are identical to the bytes hashed into the signature. Any drift here
     * would cause signature mismatch whenever the payload contains
     * {@code <}, {@code >} or {@code &} (for example, credential names such as
     * {@code a&b} or {@code x<y}).
     */
    private static final ObjectMapper MAPPER = ConsumeSignature.MAPPER;

    private final ClientOptions options;
    private final HttpClient httpClient;
    private final AtomicLong clockOffset = new AtomicLong(0L);

    DefaultClient(ClientOptions options) {
        if (options == null) {
            throw new IllegalArgumentException("client options cannot be null");
        }
        this.options = options;
        this.httpClient = options.getHttpClient() != null
                ? options.getHttpClient()
                : HttpClient.newBuilder().connectTimeout(options.getTimeout()).build();
    }

    @Override
    public List<ConsumeResult> consumeCredential(ConsumeOptions consumeOptions) {
        ConsumeEnvelope envelope;
        try {
            envelope = consumeCredentialEnvelope(consumeOptions);
        } catch (KmsException e) {
            throw new KmsException("consume credential envelope error(" + e.getMessage() + ")", e);
        }
        return Client.decryptEnvelope(envelope);
    }

    @Override
    public ConsumeEnvelope consumeCredentialEnvelope(ConsumeOptions consumeOptions) {
        if (consumeOptions == null) {
            throw new IllegalArgumentException("consume options cannot be null");
        }
        if (isBlank(consumeOptions.getAccessKey())) {
            throw new KmsException("access key can not be empty");
        }
        if (isBlank(consumeOptions.getSecretKey())) {
            throw new KmsException("secret key can not be empty");
        }
        consumeOptions.getCrypto().validateHybrid();

        AtomicReference<ConsumeEnvelope> holder = new AtomicReference<>();
        Retry.doWithRetry(CONSUME_MAX_ATTEMPTS, () -> consumeOnce(consumeOptions, holder));
        return holder.get();
    }

    private RetryResult consumeOnce(ConsumeOptions consumeOptions, AtomicReference<ConsumeEnvelope> holder) {
        KeyPair keyPair;
        try {
            keyPair = KeyPairs.newKeyPair(consumeOptions.getCrypto().asymmetricType());
        } catch (Exception e) {
            return RetryResult.failure(false,
                    new KmsException("generate asymmetric key pair error(" + e.getMessage() + ")", e));
        }

        String nonce = Nonces.newNonce();
        String timestamp = Long.toString(Instant.now().getEpochSecond() + clockOffset.get());

        ConsumeCredentialReq req = new ConsumeCredentialReq(
                List.of(),
                consumeOptions.getCredentialNameList(),
                consumeOptions.getCrypto(),
                keyPair.publicKey());

        String signature;
        try {
            signature = new ConsumeSignature(
                    consumeOptions.getSecretKey(),
                    nonce,
                    timestamp,
                    new SignContent(
                            req.credentialIdList(),
                            req.credentialNameList(),
                            req.crypto(),
                            req.publicKey())).sign();
        } catch (Exception e) {
            return RetryResult.failure(false,
                    new KmsException("sign error(" + e.getMessage() + ")", e));
        }

        byte[] body;
        try {
            body = MAPPER.writeValueAsBytes(req);
        } catch (Exception e) {
            return RetryResult.failure(false,
                    new KmsException("marshal request body error(" + e.getMessage() + ")", e));
        }

        HttpResponse<byte[]> response;
        try {
            response = sendHttp(consumeOptions, body, timestamp, nonce, signature);
        } catch (Exception e) {
            return RetryResult.failure(false,
                    new KmsException("send request error(" + e.getMessage() + ")", e));
        }

        int status = response.statusCode();
        ConsumeCredentialResp resp;
        try {
            resp = MAPPER.readValue(response.body(), ConsumeCredentialResp.class);
        } catch (Exception e) {
            return RetryResult.failure(false, new KmsException(
                    "unmarshal response error(" + e.getMessage() + "), http status(" + status + ")", e));
        }

        if (resp.code() == ErrorCodes.ERR_CODE_REQUEST_TIME_TOO_SKEWED) {
            Optional<String> dateHeader = response.headers().firstValue(Headers.DATE);
            if (dateHeader.isEmpty()) {
                return RetryResult.failure(false, new KmsException("empty date"));
            }
            try {
                long serverEpoch = HttpDateParser.parseEpochSecond(dateHeader.get());
                clockOffset.set(serverEpoch - Instant.now().getEpochSecond());
            } catch (KmsException e) {
                return RetryResult.failure(false, e);
            }
            return RetryResult.failure(true, new KmsException(
                    "request time too skewed, code(" + resp.code() + "), message(" + resp.message() + ")"));
        }

        if (status != 200 || !ErrorCodes.isOk(resp.code())) {
            return RetryResult.failure(false, new KmsException(
                    "consume credential error, http status(" + status + "), code(" + resp.code()
                            + "), message(" + resp.message() + ")"));
        }

        if (resp.data() == null || isBlank(resp.data().envelope())) {
            return RetryResult.failure(false, new KmsException("empty envelope"));
        }

        holder.set(new ConsumeEnvelope(resp.data().envelope(), keyPair.privateKey()));
        return RetryResult.success();
    }

    private HttpResponse<byte[]> sendHttp(
            ConsumeOptions consumeOptions,
            byte[] body,
            String timestamp,
            String nonce,
            String signature) throws Exception {

        String path = options.isDirect() ? CONSUME_CREDENTIAL_PATH : CONSUME_CREDENTIAL_APIGW_PATH;
        String url = Urls.joinUrl(options.getBaseUrl(), path);

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(options.getTimeout())
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));

        if (options.isDirect()) {
            builder.header(Headers.BK_APP_CODE, options.getAppCode());
        } else {
            builder.header(Headers.BK_API_AUTHORIZATION,
                    Authorization.genAuthorizationHeader(options.getAppCode(), options.getAppSecret()));
        }

        builder.header(Headers.CONTENT_TYPE, Headers.CONTENT_TYPE_JSON_UTF8);
        builder.header(Headers.BK_API_REQUEST_ID, Uuids.newUuidWithoutDashes());

        if (!isBlank(consumeOptions.getTenantId())) {
            builder.header(Headers.BK_TENANT_ID, consumeOptions.getTenantId());
        }

        builder.header(Headers.BK_KMS_AK, consumeOptions.getAccessKey());
        builder.header(Headers.BK_KMS_TIMESTAMP, timestamp);
        builder.header(Headers.BK_KMS_NONCE, nonce);
        builder.header(Headers.BK_KMS_SIGNATURE, signature);
        builder.header(Headers.BK_KMS_SDK_VERSION, Headers.VERSION);

        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
