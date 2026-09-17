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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link ErrorCodes}.
 */
class ErrorCodesTest {

    @Test
    void isOk_returns_true_for_zero() {
        assertTrue(ErrorCodes.isOk(0));
        assertTrue(ErrorCodes.isOk(ErrorCodes.ERR_CODE_OK));
    }

    @Test
    void isOk_returns_false_for_all_error_codes() {
        assertFalse(ErrorCodes.isOk(ErrorCodes.ERR_CODE_GENERIC_ERROR));
        assertFalse(ErrorCodes.isOk(ErrorCodes.ERR_CODE_NOT_FOUND));
        assertFalse(ErrorCodes.isOk(ErrorCodes.ERR_CODE_PERMISSION_DENIED));
        assertFalse(ErrorCodes.isOk(ErrorCodes.ERR_CODE_ACCESS_KEY_DISABLED));
        assertFalse(ErrorCodes.isOk(ErrorCodes.ERR_CODE_ACCESS_KEY_EXPIRED));
        assertFalse(ErrorCodes.isOk(ErrorCodes.ERR_CODE_ACCESS_KEY_NOT_BOUND));
        assertFalse(ErrorCodes.isOk(ErrorCodes.ERR_CODE_NONCE_ALREADY_USED));
        assertFalse(ErrorCodes.isOk(ErrorCodes.ERR_CODE_SIGNATURE_MISMATCH));
        assertFalse(ErrorCodes.isOk(ErrorCodes.ERR_CODE_REQUEST_TIME_TOO_SKEWED));
    }
}
