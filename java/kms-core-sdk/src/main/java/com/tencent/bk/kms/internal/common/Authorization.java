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

package com.tencent.bk.kms.internal.common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tencent.bk.kms.types.KmsException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the {@code X-Bkapi-Authorization} header value used when routing
 * requests through the BlueKing API Gateway.
 *
 * <p><b>Internal API.</b> Do not depend on this class from outside the SDK.
 */
public final class Authorization {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Authorization() {
    }

    /**
     * Builds a JSON string {@code {"bk_app_code":"...","bk_app_secret":"..."}} for
     * the {@code X-Bkapi-Authorization} header.
     */
    public static String genAuthorizationHeader(String appCode, String appSecret) {
        Map<String, String> payload = new LinkedHashMap<>();
        payload.put("bk_app_code", appCode);
        payload.put("bk_app_secret", appSecret);
        try {
            return MAPPER.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            throw new KmsException("marshal authorization header error(" + e.getMessage() + ")", e);
        }
    }
}
