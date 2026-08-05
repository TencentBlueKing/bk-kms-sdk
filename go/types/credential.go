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

// CredentialType is credential type.
type CredentialType string

const (
	// CredentialTypeSinglePassword single password credential type.
	CredentialTypeSinglePassword CredentialType = "single_password"

	// CredentialTypeUsernamePassword username password credential type.
	CredentialTypeUsernamePassword CredentialType = "username_password"

	// CredentialTypeSingleSecretKey single secret key credential type.
	CredentialTypeSingleSecretKey CredentialType = "single_secret_key"

	// CredentialTypeAppIDSecretKey app id secret key credential type.
	CredentialTypeAppIDSecretKey CredentialType = "app_id_secret_key"
)

// String returns the string representation of the credential type.
func (typ CredentialType) String() string {
	return string(typ)
}

// ConsumeCredentialReq consume credential request.
type ConsumeCredentialReq struct {
	CredentialIDList []int64    `json:"credential_id_list"`
	Crypto           CryptoInfo `json:"crypto"`
	PublicKey        string     `json:"public_key"`
}

// AuthInfo auth info.
type AuthInfo struct {
	Password  string `json:"password"`
	Username  string `json:"username"`
	SecretKey string `json:"secret_key"`
	AppID     string `json:"app_id"`
}

// Credential credential.
type Credential struct {
	Name     string         `json:"name"`
	Type     CredentialType `json:"type"`
	AuthInfo AuthInfo       `json:"auth_info"`
}

// ConsumeResult consume result.
type ConsumeResult struct {
	CredentialID int64       `json:"credential_id"`
	ErrCode      int32       `json:"err_code"`
	ErrMsg       string      `json:"err_msg"`
	Credential   *Credential `json:"credential,omitempty"`
}

// ConsumeCredentialData consume credential data.
type ConsumeCredentialData struct {
	Envelope string `json:"envelope"`
}

// ConsumeCredentialResp consume credential response.
type ConsumeCredentialResp struct {
	Code    int32                  `json:"code"`
	Message string                 `json:"message"`
	Data    *ConsumeCredentialData `json:"data,omitempty"`
}
