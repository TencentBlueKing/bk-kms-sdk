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

/**
 * HTTP header names and content types used by the BK-KMS SDK, along with the
 * SDK version identifier.
 *
 * <p><b>Internal API.</b> Do not depend on this class from outside the SDK.
 */
public final class Headers {

    /** BK-KMS Java SDK version, emitted as {@code X-BKKMS-SDK-Version}. */
    public static final String VERSION = "v1.0.0-alpha.1";

    // BK API Gateway headers.
    public static final String BK_API_AUTHORIZATION = "X-Bkapi-Authorization";
    public static final String BK_API_REQUEST_ID = "X-Bkapi-Request-Id";
    public static final String BK_TENANT_ID = "X-Bk-Tenant-Id";

    /** BlueKing app code header, sent in direct mode as caller identity. */
    public static final String BK_APP_CODE = "X-Bk-AppCode";

    // BK KMS custom headers.
    public static final String BK_KMS_AK = "X-BKKMS-AK";
    public static final String BK_KMS_TIMESTAMP = "X-BKKMS-Timestamp";
    public static final String BK_KMS_NONCE = "X-BKKMS-Nonce";
    public static final String BK_KMS_SIGNATURE = "X-BKKMS-Signature";
    public static final String BK_KMS_SDK_VERSION = "X-BKKMS-SDK-Version";

    // Generic HTTP headers.
    public static final String DATE = "Date";
    public static final String CONTENT_TYPE = "Content-Type";

    public static final String CONTENT_TYPE_JSON_UTF8 = "application/json; charset=utf-8";

    private Headers() {
    }
}
