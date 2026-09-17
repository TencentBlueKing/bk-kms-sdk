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

import java.util.UUID;

/**
 * UUID helpers used by the BK-KMS SDK.
 *
 * <p><b>Internal API.</b> Do not depend on this class from outside the SDK.
 */
public final class Uuids {

    private Uuids() {
    }

    /**
     * Returns a random UUID v4 string with dashes stripped (32 hex characters).
     */
    public static String newUuidWithoutDashes() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
