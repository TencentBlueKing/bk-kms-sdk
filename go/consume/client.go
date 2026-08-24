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
	"sync/atomic"
	"time"

	"github.com/TencentBlueKing/bk-kms-sdk/go/internal/common"
	"github.com/TencentBlueKing/bk-kms-sdk/go/internal/crypto"
	"github.com/TencentBlueKing/bk-kms-sdk/go/internal/retry"
	"github.com/TencentBlueKing/bk-kms-sdk/go/internal/signature"
	"github.com/TencentBlueKing/bk-kms-sdk/go/types"
)

const (
	// consumeCredentialAPIGWPath consume credential apigw path.
	consumeCredentialAPIGWPath = "/api/v1/consume_credential"

	// consumeCredentialPath consume credential apiservice path.
	consumeCredentialPath = "/api/v1/consume/credential"

	// consumeMaxAttempts max attempts of a consume credential request.
	consumeMaxAttempts = 2
)

// Client provides credential consume methods.
type Client interface {
	// ConsumeCredential consume credential.
	ConsumeCredential(ctx context.Context, opts ...ConsumeOption) ([]types.ConsumeResult, error)

	// ConsumeCredentialEnvelope consume credential envelope.
	ConsumeCredentialEnvelope(ctx context.Context, opts ...ConsumeOption) (*types.ConsumeEnvelope, error)
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

	clockOffset atomic.Int64
}

// ConsumeCredential consume credential.
func (c *client) ConsumeCredential(ctx context.Context, opts ...ConsumeOption) ([]types.ConsumeResult, error) {
	envelope, err := c.ConsumeCredentialEnvelope(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("consume credential envelope error(%+v)", err)
	}

	return DecryptEnvelope(envelope)
}

// ConsumeCredentialEnvelope consume credential envelope.
func (c *client) ConsumeCredentialEnvelope(ctx context.Context, opts ...ConsumeOption) (*types.ConsumeEnvelope, error) {
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

	var envelope *types.ConsumeEnvelope

	err := retry.Do(consumeMaxAttempts, func() (bool, error) {
		result, retryable, err := c.consumeOnce(ctx, defaultOptions)
		if err == nil {
			envelope = result
		}

		return retryable, err
	})

	if err != nil {
		return nil, err
	}

	return envelope, nil
}

func (c *client) consumeOnce(ctx context.Context, opts *consumeOptions) (*types.ConsumeEnvelope, bool, error) {
	// generate a temporary asymmetric key pair base on the target type.
	keyPair, err := crypto.NewKeyPair(opts.crypto.AsymmetricType)
	if err != nil {
		return nil, false, fmt.Errorf("generate asymmetric key pair error(%+v)", err)
	}

	// generate a unique nonce string.
	nonce, err := signature.NewNonce()
	if err != nil {
		return nil, false, err
	}

	req := types.ConsumeCredentialReq{
		CredentialIDList: opts.credentialIDList,
		Crypto:           opts.crypto,
		PublicKey:        keyPair.PublicKey(),
	}

	timestamp := strconv.FormatInt(time.Now().Unix()+c.clockOffset.Load(), 10)

	sign, err := (&signature.ConsumeSignature{
		SecretKey: opts.secretKey,
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
		return nil, false, fmt.Errorf("sign error(%+v)", err)
	}

	statusCode, respHeader, respBody, err := c.sendRequest(ctx, opts, req, timestamp, nonce, sign)
	if err != nil {
		return nil, false, err
	}

	var resp types.ConsumeCredentialResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, false, fmt.Errorf("unmarshal response error(%+v), http status(%d)", err, statusCode)
	}

	if resp.Code == types.ErrCodeRequestTimeTooSkewed {
		if skewErr := c.correctClockSkew(respHeader.Get(common.DateHeader)); skewErr != nil {
			return nil, false, skewErr
		}

		return nil, true, fmt.Errorf("request time too skewed, code(%d), message(%s)", resp.Code, resp.Message)
	}

	if statusCode != http.StatusOK || !types.IsOK(resp.Code) {
		return nil, false, fmt.Errorf("consume credential error, http status(%d), code(%d), message(%s)", statusCode, resp.Code, resp.Message)
	}

	if resp.Data == nil || resp.Data.Envelope == "" {
		return nil, false, errors.New("empty envelope")
	}

	return &types.ConsumeEnvelope{
		Envelope:   resp.Data.Envelope,
		PrivateKey: keyPair.PrivateKey(),
	}, false, nil
}

func (c *client) sendRequest(ctx context.Context, opts *consumeOptions,
	req types.ConsumeCredentialReq, timestamp, nonce, signature string) (int, http.Header, []byte, error) {

	if req.CredentialIDList == nil {
		req.CredentialIDList = []int64{}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("marshal request body error(%+v)", err)
	}

	path := consumeCredentialAPIGWPath
	if c.opts.direct {
		path = consumeCredentialPath
	}

	consumeCredentialURL := common.JoinURL(c.opts.baseURL, path)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, consumeCredentialURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("new request error(%+v)", err)
	}

	if !c.opts.direct {
		authorization, err := common.GenAuthorizationHeader(c.opts.appCode, c.opts.appSecret)
		if err != nil {
			return 0, nil, nil, err
		}

		request.Header.Set(common.BKAPIAuthorizationHeader, authorization)
	}

	request.Header.Set(common.ContentTypeHeader, common.ContentTypeJSONCharsetUTF8)
	request.Header.Set(common.BKAPIRequestIDHeader, common.GenReqID())
	request.Header.Set(common.BKTenantIDHeader, opts.tenantID)
	request.Header.Set(common.BKKMSAKHeader, opts.accessKey)
	request.Header.Set(common.BKKMSTimestampHeader, timestamp)
	request.Header.Set(common.BKKMSNonceHeader, nonce)
	request.Header.Set(common.BKKMSSignatureHeader, signature)
	request.Header.Set(common.BKKMSSDKVersionHeader, common.Version)

	response, err := c.opts.httpClient.Do(request)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("send request error(%+v)", err)
	}
	defer response.Body.Close()

	respBody, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read response body error(%+v)", err)
	}

	return response.StatusCode, response.Header.Clone(), respBody, nil
}

func (c *client) correctClockSkew(date string) error {
	date = strings.TrimSpace(date)
	if date == "" {
		return errors.New("empty date")
	}

	serverTime, err := http.ParseTime(date)
	if err != nil {
		return fmt.Errorf("parse date error(%+v)", err)
	}

	c.clockOffset.Store(serverTime.Unix() - time.Now().Unix())

	return nil
}
