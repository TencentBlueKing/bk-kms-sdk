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

#include "bk-kms/client.h"

#include <httplib.h>

#include <atomic>
#include <chrono>
#include <sstream>
#include <string>
#include <utility>

#include "internal/common/http.h"
#include "internal/common/id.h"
#include "internal/common/time.h"
#include "internal/common/url.h"
#include "internal/crypto/crypto.h"
#include "internal/crypto/key.h"
#include "internal/retry/retry.h"
#include "internal/signature/signature.h"
#include "types/credential.h"

namespace bkkms {

// max attempts of a consume credential request.
static constexpr int ConsumeMaxAttempts = 2;

class ClientImpl : public Client
{
public:
    explicit ClientImpl(ClientOptions opts) noexcept
        : m_opts(std::move(opts)), m_clockOffset(0) {}

public:
    std::vector<ConsumeResult> ConsumeCredential(const ConsumeOptions& opts, std::string& err) noexcept override;

    bool ConsumeCredentialEnvelope(const ConsumeOptions& opts, ConsumeEnvelope& out, std::string& err) noexcept override;

private:
    bool ConsumeOnce(const ConsumeOptions& opts, ConsumeEnvelope& out, bool& retryable, std::string& err) noexcept;

    bool SendRequest(const ConsumeOptions& opts,
                     const std::string& body, const std::string& timestamp,
                     const std::string& nonce, const std::string& signatureHex,
                     int& statusCode, std::string& respBody, std::string& dateHeader, std::string& err) noexcept;

    bool CorrectClockSkew(const std::string& date, std::string& err) noexcept;

private:
    ClientOptions m_opts;
    std::atomic<int64_t> m_clockOffset;
};

std::unique_ptr<Client> Client::New(const ClientOptions& opts, std::string& err) noexcept
{
    if (opts.baseUrl.empty())
    {
        err = "invalid client options, base url cannot be empty";
        return nullptr;
    }

    if (!opts.direct)
    {
        if (opts.appCode.empty())
        {
            err = "invalid client options, app code cannot be empty";
            return nullptr;
        }

        if (opts.appSecret.empty())
        {
            err = "invalid client options, app secret cannot be empty";
            return nullptr;
        }
    }

    if (opts.timeoutSeconds <= 0)
    {
        err = "invalid client options, timeout must be positive";
        return nullptr;
    }

    return std::unique_ptr<Client>(new ClientImpl(opts));
}

std::vector<ConsumeResult> ClientImpl::ConsumeCredential(const ConsumeOptions& opts, std::string& err) noexcept
{
    std::vector<ConsumeResult> empty;

    ConsumeEnvelope envelope;
    if (!ConsumeCredentialEnvelope(opts, envelope, err))
    {
        err = "consume credential envelope error(" + err + ")";
        return empty;
    }

    std::vector<ConsumeResult> results;
    if (!DecryptEnvelope(envelope, results, err))
    {
        return empty;
    }

    return results;
}

bool ClientImpl::ConsumeCredentialEnvelope(const ConsumeOptions& opts, ConsumeEnvelope& out, std::string& err) noexcept
{
    if (opts.accessKey.empty())
    {
        err = "access key can not be empty";
        return false;
    }

    if (opts.secretKey.empty())
    {
        err = "secret key can not be empty";
        return false;
    }

    if (!ValidateHybridCrypto(opts.crypto, err))
    {
        return false;
    }

    const RetryFunc consume = [this, &opts, &out](bool& retryable, std::string& onceErr) noexcept
    {
        return ConsumeOnce(opts, out, retryable, onceErr);
    };

    return RetryDo(ConsumeMaxAttempts, consume, err);
}

bool ClientImpl::ConsumeOnce(const ConsumeOptions& opts, ConsumeEnvelope& out, bool& retryable, std::string& err) noexcept
{
    retryable = false;

    // generate ephemeral asymmetric key pair.
    KeyPair kp;
    if (!GenerateKeyPair(opts.crypto.asymmetricType, kp, err))
    {
        return false;
    }

    // generate nonce (UUIDv4 without hyphens) and a Unix-second timestamp.
    const std::string nonce = GenReqID();
    if (nonce.empty())
    {
        err = "generate nonce failed";
        return false;
    }

    const auto nowSec = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();

    const std::string timestamp = std::to_string(nowSec + m_clockOffset.load());

    // canonically serialise the request body.
    std::string body;
    MarshalConsumeCredentialReq(opts.credentialIDList, opts.crypto, kp.publicKey, body);

    // two-stage HMAC-SHA256 signing. The URL path used for signing is always the
    // direct-mode path so that gateway and direct callers hash the same bytes.
    std::string signatureHex;
    if (!Sign(opts.secretKey, nonce, "POST", ConsumeCredentialSignaturePath, timestamp, body, signatureHex, err))
    {
        return false;
    }

    // send the HTTP request.
    int statusCode = 0;
    std::string respBody;
    std::string dateHeader;
    if (!SendRequest(opts, body, timestamp, nonce, signatureHex, statusCode, respBody, dateHeader, err))
    {
        return false;
    }

    ConsumeCredentialResp resp;
    if (!UnmarshalConsumeCredentialResp(respBody, resp))
    {
        std::ostringstream oss;
        oss << "unmarshal response error, http status(" << statusCode << ")";
        err = oss.str();
        return false;
    }

    if (resp.m_code == ErrCodeRequestTimeTooSkewed)
    {
        if (!CorrectClockSkew(dateHeader, err))
        {
            return false;
        }

        retryable = true;

        std::ostringstream oss;
        oss << "request time too skewed, code(" << resp.m_code << "), message(" << resp.m_message << ")";
        err = oss.str();
        return false;
    }

    if (statusCode != 200 || !IsOK(resp.m_code))
    {
        std::ostringstream oss;
        oss << "consume credential error, http status(" << statusCode << "), code(" << resp.m_code << "), message(" << resp.m_message << ")";
        err = oss.str();
        return false;
    }

    if (!resp.m_hasEnvelope || resp.m_envelope.empty())
    {
        err = "empty envelope";
        return false;
    }

    out.envelope = resp.m_envelope;
    out.privateKey = kp.privateKey;

    return true;
}

bool ClientImpl::SendRequest(const ConsumeOptions& opts,
                             const std::string& body, const std::string& timestamp,
                             const std::string& nonce, const std::string& signatureHex,
                             int& statusCode, std::string& respBody, std::string& dateHeader, std::string& err) noexcept
{
    std::string scheme;
    std::string host;
    uint16_t port = 0;
    std::string basePath;

    if (!SplitBaseURL(m_opts.baseUrl, scheme, host, port, basePath))
    {
        err = "invalid base url: " + m_opts.baseUrl;
        return false;
    }

    // APIGW and direct modes hit different API paths.
    const std::string path = basePath + (m_opts.direct ? ConsumeCredentialDirectPath : ConsumeCredentialAPIGWPath);

    // Feeding httplib the full "scheme://host:port" lets it pick the right
    // transport (HTTP or HTTPS) automatically when TLS support is compiled in.
    httplib::Client cli(scheme + "://" + host + ":" + std::to_string(port));

    cli.set_connection_timeout(m_opts.timeoutSeconds, 0);
    cli.set_read_timeout(m_opts.timeoutSeconds, 0);
    cli.set_write_timeout(m_opts.timeoutSeconds, 0);
    cli.set_keep_alive(true);

    httplib::Headers headers;

    if (!m_opts.direct)
    {
        std::string authHeader;
        GenAuthorizationHeader(m_opts.appCode, m_opts.appSecret, authHeader);
        headers.emplace(BKAPIAuthorizationHeader, authHeader);
    }

    headers.emplace(BKAPIRequestIDHeader, GenReqID());
    headers.emplace(BKTenantIDHeader, opts.tenantID.empty() ? DefaultTenantID : opts.tenantID);
    headers.emplace(BKKMSAKHeader, opts.accessKey);
    headers.emplace(BKKMSTimestampHeader, timestamp);
    headers.emplace(BKKMSNonceHeader, nonce);
    headers.emplace(BKKMSSignatureHeader, signatureHex);
    headers.emplace(BKKMSSDKVersionHeader, Version);

    auto res = cli.Post(path.c_str(), headers, body, ContentTypeJSONCharsetUTF8);
    if (!res)
    {
        std::ostringstream oss;
        oss << "send request error(" << httplib::to_string(res.error()) << ")";
        err = oss.str();
        return false;
    }

    statusCode = res->status;
    respBody = std::move(res->body);
    dateHeader = res->get_header_value(DateHeader);

    return true;
}

bool ClientImpl::CorrectClockSkew(const std::string& date, std::string& err) noexcept
{
    if (date.empty())
    {
        err = "empty date";
        return false;
    }

    std::time_t serverTime = 0;
    if (!ParseHTTPDate(date, serverTime))
    {
        err = "parse date error";
        return false;
    }

    const auto nowSec = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();

    m_clockOffset.store(serverTime - nowSec);

    return true;
}

} // namespace bkkms
