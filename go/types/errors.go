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

package types

const (
	// ErrCodeOK means success.
	ErrCodeOK = 0

	// ErrCodeGenericError generic error.
	ErrCodeGenericError = 1034000

	// ErrCodeNotFound resource not found.
	ErrCodeNotFound = 1034003

	// ErrCodePermissionDenied permission denied.
	ErrCodePermissionDenied = 1034008

	// ErrCodeAccessKeyDisabled access key disabled.
	ErrCodeAccessKeyDisabled = 1034011

	// ErrCodeAccessKeyExpired access key expired.
	ErrCodeAccessKeyExpired = 1034012

	// ErrCodeAccessKeyNotBound access key not bound to credential group.
	ErrCodeAccessKeyNotBound = 1034013

	// ErrCodeNonceAlreadyUsed nonce already used.
	ErrCodeNonceAlreadyUsed = 1034014

	// ErrCodeSignatureMismatch signature mismatch.
	ErrCodeSignatureMismatch = 1034015

	// ErrCodeRequestTimeTooSkewed request time too skewed.
	ErrCodeRequestTimeTooSkewed = 1034016
)

// IsOK checks whether the error code means success.
func IsOK(errCode int32) bool {
	return errCode == ErrCodeOK
}
