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
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.tencent.bk.kms.internal.common.Headers;
import com.tencent.bk.kms.types.ConsumeCredentialData;
import com.tencent.bk.kms.types.ConsumeCredentialResp;
import com.tencent.bk.kms.types.ConsumeEnvelope;
import com.tencent.bk.kms.types.ErrorCodes;
import com.tencent.bk.kms.types.KmsException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for {@link DefaultClient} using an in-process HTTP server.
 */
class ClientTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private HttpServer server;
    private String baseUrl;
    private final List<String> observedPaths = Collections.synchronizedList(new ArrayList<>());
    private final AtomicReference<Handler> handler = new AtomicReference<>();

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            observedPaths.add(exchange.getRequestURI().getPath());
            Handler h = handler.get();
            if (h != null) {
                try {
                    h.handle(exchange);
                } catch (IOException e) {
                    throw e;
                } catch (Exception e) {
                    throw new IOException(e);
                }
            } else {
                exchange.sendResponseHeaders(500, -1);
                exchange.close();
            }
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void direct_mode_hits_backend_path_without_authorization() throws Exception {
        AtomicReference<String> authHeader = new AtomicReference<>();
        AtomicReference<String> appCodeHeader = new AtomicReference<>();
        handler.set(exchange -> {
            authHeader.set(exchange.getRequestHeaders().getFirst(Headers.BK_API_AUTHORIZATION));
            appCodeHeader.set(exchange.getRequestHeaders().getFirst(Headers.BK_APP_CODE));
            writeJson(exchange, 200, envelopeResponse("dummy-envelope"));
        });

        Client client = Client.create(ClientOptions.builder()
                .baseUrl(baseUrl)
                .direct(true)
                .appCode("app_code")
                .build());

        ConsumeEnvelope envelope = client.consumeCredentialEnvelope(ConsumeOptions.builder()
                .accessKeySecret("ak", "sk")
                .credentialNameList("demo")
                .build());

        assertNotNull(envelope);
        assertEquals("dummy-envelope", envelope.envelope());
        assertNull(authHeader.get(), "direct mode must not send X-Bkapi-Authorization");
        assertEquals("app_code", appCodeHeader.get(), "direct mode must send X-Bk-AppCode");
        assertTrue(observedPaths.contains(DefaultClient.CONSUME_CREDENTIAL_PATH),
                "expected direct path, saw: " + observedPaths);
    }

    @Test
    void apigw_mode_hits_gateway_path_with_authorization() throws Exception {
        AtomicReference<String> authHeader = new AtomicReference<>();
        handler.set(exchange -> {
            authHeader.set(exchange.getRequestHeaders().getFirst(Headers.BK_API_AUTHORIZATION));
            writeJson(exchange, 200, envelopeResponse("dummy-envelope"));
        });

        Client client = Client.create(ClientOptions.builder()
                .baseUrl(baseUrl)
                .direct(false)
                .appCode("app_code")
                .appSecret("app_secret")
                .build());

        client.consumeCredentialEnvelope(ConsumeOptions.builder()
                .accessKeySecret("ak", "sk")
                .build());

        assertNotNull(authHeader.get(), "APIGW mode must send X-Bkapi-Authorization");
        assertTrue(authHeader.get().contains("app_code"));
        assertTrue(authHeader.get().contains("app_secret"));
        assertTrue(observedPaths.contains(DefaultClient.CONSUME_CREDENTIAL_APIGW_PATH),
                "expected APIGW path, saw: " + observedPaths);
    }

    @Test
    void request_time_skew_triggers_clock_correction_and_retry() {
        AtomicInteger calls = new AtomicInteger();
        handler.set(exchange -> {
            int n = calls.incrementAndGet();
            if (n == 1) {
                exchange.getResponseHeaders().set(
                        Headers.DATE,
                        ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.RFC_1123_DATE_TIME));
                writeJson(exchange, 200, MAPPER.writeValueAsBytes(
                        new ConsumeCredentialResp(
                                ErrorCodes.ERR_CODE_REQUEST_TIME_TOO_SKEWED,
                                "skew", null)));
            } else {
                writeJson(exchange, 200, envelopeResponse("real-envelope"));
            }
        });

        Client client = Client.create(ClientOptions.builder().baseUrl(baseUrl).direct(true).appCode("app_code").build());
        ConsumeEnvelope envelope = client.consumeCredentialEnvelope(ConsumeOptions.builder()
                .accessKeySecret("ak", "sk")
                .build());

        assertEquals("real-envelope", envelope.envelope());
        assertEquals(2, calls.get(), "must have retried exactly once");
    }

    @Test
    void empty_envelope_response_is_reported() {
        handler.set(exchange -> writeJson(exchange, 200, MAPPER.writeValueAsBytes(
                new ConsumeCredentialResp(
                        ErrorCodes.ERR_CODE_OK, "ok",
                        new ConsumeCredentialData("")))));

        Client client = Client.create(ClientOptions.builder().baseUrl(baseUrl).direct(true).appCode("app_code").build());
        KmsException ex = assertThrows(KmsException.class,
                () -> client.consumeCredentialEnvelope(ConsumeOptions.builder()
                        .accessKeySecret("ak", "sk").build()));
        assertTrue(ex.getMessage().toLowerCase().contains("empty envelope"),
                "expected empty envelope message, got: " + ex.getMessage());
    }

    private static byte[] envelopeResponse(String envelope) throws Exception {
        return MAPPER.writeValueAsBytes(new ConsumeCredentialResp(
                ErrorCodes.ERR_CODE_OK, "ok",
                new ConsumeCredentialData(envelope)));
    }

    private static void writeJson(HttpExchange exchange, int status, byte[] body) throws IOException {
        exchange.getResponseHeaders().set(Headers.CONTENT_TYPE, Headers.CONTENT_TYPE_JSON_UTF8);
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    @FunctionalInterface
    private interface Handler {
        void handle(HttpExchange exchange) throws Exception;
    }
}
