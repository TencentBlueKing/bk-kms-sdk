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

package consume

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/TencentBlueKing/bk-kms-sdk/go/types"
)

const (
	// defaultRequestTimeout is default request timeout.
	defaultRequestTimeout = 30 * time.Second
)

// clientOptions holds the internal state configured via ClientOption.
type clientOptions struct {
	baseURL    string
	direct     bool
	appCode    string
	appSecret  string
	timeout    time.Duration
	httpClient *http.Client
}

// newDefaultClientOptions returns clientOptions filled with defaults.
func newDefaultClientOptions() *clientOptions {
	return &clientOptions{
		timeout: defaultRequestTimeout,
	}
}

// validate validates the client options.
func (o *clientOptions) validate() error {
	if strings.TrimSpace(o.baseURL) == "" {
		return errors.New("invalid client options, base url cannot be empty")
	}

	if !o.direct {
		if strings.TrimSpace(o.appCode) == "" {
			return errors.New("invalid client options, app code cannot be empty")
		}

		if strings.TrimSpace(o.appSecret) == "" {
			return errors.New("invalid client options, app secret cannot be empty")
		}
	}

	if o.timeout <= 0 {
		return errors.New("invalid client options, timeout is invalid")
	}

	return nil
}

// ClientOption customizes options accepted by New.
type ClientOption func(*clientOptions)

// WithBaseURL sets the base URL of the KMS apigw or apiserver.
func WithBaseURL(url string) ClientOption {
	return func(o *clientOptions) {
		o.baseURL = strings.TrimRight(url, "/")
	}
}

// WithDirect sets the client to connect directly to the KMS backend service.
// In this mode, app code / secret are not required.
func WithDirect() ClientOption {
	return func(o *clientOptions) {
		o.direct = true
	}
}

// WithAppCodeSecret sets the app code and app secret.
func WithAppCodeSecret(appCode, appSecret string) ClientOption {
	return func(o *clientOptions) {
		o.appCode = appCode
		o.appSecret = appSecret
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(o *clientOptions) {
		o.timeout = timeout
	}
}

// WithClient sets a custom http client.
func WithClient(client *http.Client) ClientOption {
	return func(o *clientOptions) {
		o.httpClient = client
	}
}

// consumeOptions holds the internal state configured via ConsumeOption.
type consumeOptions struct {
	tenantID           string
	accessKey          string
	secretKey          string
	credentialNameList []string
	crypto             types.CryptoInfo
}

// newDefaultConsumeOptions returns consumeOptions filled with defaults.
func newDefaultConsumeOptions() *consumeOptions {
	return &consumeOptions{
		crypto: types.CryptoInfo{
			AsymmetricType: types.CryptoTypeRSA,
			SymmetricType:  types.CryptoTypeAES,
			SymmetricMode:  types.CryptoModeCBC,
		},
	}
}

// ConsumeOption customizes options accepted by ConsumeCredential.
type ConsumeOption func(*consumeOptions)

// WithTenantID sets the tenant id carried by the X-Bk-Tenant-Id header.
// When unset, the header is not sent.
func WithTenantID(tenantID string) ConsumeOption {
	return func(o *consumeOptions) {
		o.tenantID = tenantID
	}
}

// WithAccessKeySecret sets the access key and secret key.
func WithAccessKeySecret(accessKey, secretKey string) ConsumeOption {
	return func(o *consumeOptions) {
		o.accessKey = accessKey
		o.secretKey = secretKey
	}
}

// WithCredentialNameList sets the credential name list.
// When empty, the server returns all credentials in the AK's uniquely bound credential group.
func WithCredentialNameList(nameList ...string) ConsumeOption {
	return func(o *consumeOptions) {
		o.credentialNameList = nameList
	}
}

// WithCrypto sets the crypto info.
func WithCrypto(crypto types.CryptoInfo) ConsumeOption {
	return func(o *consumeOptions) {
		o.crypto = crypto
	}
}
