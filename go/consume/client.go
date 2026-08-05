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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/TencentBlueKing/bk-kms-sdk/go/internal/common"
	"github.com/TencentBlueKing/bk-kms-sdk/go/internal/crypto"
	"github.com/TencentBlueKing/bk-kms-sdk/go/internal/signature"
	"github.com/TencentBlueKing/bk-kms-sdk/go/types"
)

const (
	// consumeCredentialPath consume credential path.
	consumeCredentialPath = "/api/v1/consume/credential"
)

// Client provides credential consume methods.
type Client interface {
	// ConsumeCredential consume credential.
	ConsumeCredential(ctx context.Context, opts ...ConsumeOption) ([]types.ConsumeResult, error)
}

// New creates a new client.
func New(opts ...ClientOption) (Client, error) {
	defaultOptions := newDefaultClientOptions()

	for _, opt := range opts {
		opt(defaultOptions)
	}

	if err := defaultOptions.validate(); err != nil {
		return nil, err
	}

	if defaultOptions.httpClient == nil {
		defaultOptions.httpClient = &http.Client{Timeout: defaultOptions.timeout}
	}

	return &client{opts: defaultOptions}, nil
}

type client struct {
	opts *clientOptions
}

// ConsumeCredential consume credential.
func (c *client) ConsumeCredential(ctx context.Context, opts ...ConsumeOption) ([]types.ConsumeResult, error) {
	defaultOptions := newDefaultConsumeOptions()

	for _, opt := range opts {
		opt(defaultOptions)
	}

	if strings.TrimSpace(defaultOptions.accessKey) == "" {
		return nil, errors.New("access key can not be empty")
	}

	if strings.TrimSpace(defaultOptions.secretKey) == "" {
		return nil, errors.New("secret key can not be empty")
	}

	if err := defaultOptions.crypto.ValidateHybrid(); err != nil {
		return nil, err
	}

	// generate a temporary asymmetric key pair base on the target type.
	keyPair, err := crypto.NewKeyPair(defaultOptions.crypto.AsymmetricType)
	if err != nil {
		return nil, fmt.Errorf("generate asymmetric key pair error(%+v)", err)
	}

	// generate a unique nonce string.
	nonce, err := signature.NewNonce()
	if err != nil {
		return nil, err
	}

	req := types.ConsumeCredentialReq{
		CredentialIDList: defaultOptions.credentialIDList,
		Crypto:           defaultOptions.crypto,
		PublicKey:        keyPair.PublicKey(),
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	signature, err := (&signature.ConsumeSignature{
		SecretKey: defaultOptions.secretKey,
		Nonce:     nonce,
		Method:    http.MethodPost,
		URLPath:   signature.ConsumeCredentialSignaturePath,
		Timestamp: timestamp,
		SignContent: signature.SignContent{
			CredentialIDList: req.CredentialIDList,
			Crypto:           req.Crypto,
			PublicKey:        req.PublicKey,
		},
	}).Sign()

	if err != nil {
		return nil, fmt.Errorf("sign error(%+v)", err)
	}

	statusCode, respBody, err := c.sendRequest(ctx, req, defaultOptions.accessKey, timestamp, nonce, signature)
	if err != nil {
		return nil, err
	}

	return c.decryptResponse(statusCode, respBody, keyPair.PrivateKey())
}

func (c *client) sendRequest(ctx context.Context, req types.ConsumeCredentialReq,
	accessKey, timestamp, nonce, signature string) (int, []byte, error) {

	if req.CredentialIDList == nil {
		req.CredentialIDList = []int64{}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return 0, nil, fmt.Errorf("marshal request body error(%+v)", err)
	}

	consumeCredentialURL := common.JoinURL(c.opts.baseURL, consumeCredentialPath)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, consumeCredentialURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("new request error(%+v)", err)
	}

	request.Header.Set(common.BKKMSAKHeader, accessKey)
	request.Header.Set(common.BKKMSTimestampHeader, timestamp)
	request.Header.Set(common.BKKMSNonceHeader, nonce)
	request.Header.Set(common.BKKMSSignatureHeader, signature)
	request.Header.Set(common.ContentTypeHeader, common.ContentTypeJSONCharsetUTF8)
	request.Header.Set(common.BKAPIRequestIDHeader, common.GenReqID())

	response, err := c.opts.httpClient.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("send request error(%+v)", err)
	}
	defer response.Body.Close()

	respBody, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("read response body error(%+v)", err)
	}

	return response.StatusCode, respBody, nil
}

func (c *client) decryptResponse(statusCode int, body []byte, privateKey string) ([]types.ConsumeResult, error) {
	var resp types.ConsumeCredentialResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response error(%+v), http status(%d)", err, statusCode)
	}

	if statusCode != http.StatusOK || !types.IsOK(resp.Code) {
		return nil, fmt.Errorf("consume credential error, http status(%d), code(%d), message(%s)",
			statusCode, resp.Code, resp.Message)
	}

	if resp.Data == nil || resp.Data.Envelope == "" {
		return nil, errors.New("empty envelope")
	}

	plaintext, err := crypto.HybridDecrypt(resp.Data.Envelope, privateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt consume result error(%+v)", err)
	}

	var results []types.ConsumeResult
	if err := json.Unmarshal([]byte(plaintext), &results); err != nil {
		return nil, fmt.Errorf("unmarshal consume result error(%+v)", err)
	}

	return results, nil
}
