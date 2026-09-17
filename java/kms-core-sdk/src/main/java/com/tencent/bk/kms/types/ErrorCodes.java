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

/**
 * Server-side error code constants returned by the KMS backend.
 */
public final class ErrorCodes {

    public static final int ERR_CODE_OK = 0;
    public static final int ERR_CODE_GENERIC_ERROR = 1034000;
    public static final int ERR_CODE_NOT_FOUND = 1034003;
    public static final int ERR_CODE_PERMISSION_DENIED = 1034008;
    public static final int ERR_CODE_ACCESS_KEY_DISABLED = 1034011;
    public static final int ERR_CODE_ACCESS_KEY_EXPIRED = 1034012;
    public static final int ERR_CODE_ACCESS_KEY_NOT_BOUND = 1034013;
    public static final int ERR_CODE_NONCE_ALREADY_USED = 1034014;
    public static final int ERR_CODE_SIGNATURE_MISMATCH = 1034015;
    public static final int ERR_CODE_REQUEST_TIME_TOO_SKEWED = 1034016;

    private ErrorCodes() {
    }

    /**
     * Returns {@code true} when the given error code indicates success.
     */
    public static boolean isOk(int code) {
        return code == ERR_CODE_OK;
    }
}
