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

package com.tencent.bk.kms.internal.retry;

import com.tencent.bk.kms.types.KmsException;

/**
 * Simple retry executor: invokes the task up to {@code maxAttempts} times.
 *
 * <p><b>Internal API.</b> Do not depend on this class from outside the SDK.
 */
public final class Retry {

    private Retry() {
    }

    /**
     * Runs {@code task} up to {@code maxAttempts} times. Stops as soon as the
     * task returns a success outcome or a non-retryable failure. If all
     * attempts fail, wraps the last error in a {@link KmsException}.
     */
    public static void doWithRetry(int maxAttempts, RetryableTask task) {
        Throwable lastError = null;
        int attempts = 0;

        while (attempts < maxAttempts) {
            attempts++;

            RetryResult result;
            try {
                result = task.run();
            } catch (Throwable t) {
                // Defensive: convert any accidental throw into a non-retryable failure.
                result = RetryResult.failure(false, t);
            }

            if (result.error() == null) {
                return;
            }

            lastError = result.error();

            if (!result.retryable()) {
                break;
            }
        }

        if (attempts > 1) {
            throw new KmsException(
                    "failed after " + attempts + " attempts, last error(" + describe(lastError) + ")",
                    lastError);
        }
        if (lastError instanceof RuntimeException re) {
            throw re;
        }
        throw new KmsException(describe(lastError), lastError);
    }

    private static String describe(Throwable t) {
        if (t == null) {
            return "";
        }
        return t.getMessage() == null ? t.toString() : t.getMessage();
    }
}
