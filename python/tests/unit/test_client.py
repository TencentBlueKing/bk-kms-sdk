#
# TencentBlueKing is pleased to support the open source community by making
# 蓝鲸智云 - 凭证管理服务(BlueKing - Key Management Service) available.
# Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
# Licensed under the MIT License (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
# http://opensource.org/licenses/MIT
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.We undertake not
# to change the open source license (MIT license) applicable to the current version
# of the project delivered to anyone in the future.
#

import json
from datetime import UTC, datetime
from inspect import signature
from typing import Any

import httpx2
import pytest

from bk_kms import (
    Client,
    ClientClosedError,
    ClockSkewError,
    ConfigurationError,
    ConsumeEnvelope,
    ConsumeResult,
    CryptoInfo,
    KMSRequestError,
    ResponseDecodeError,
    TransportError,
    ValidationError,
)
from bk_kms.crypto.base import KeyPair


class RecordingHTTPClient:
    def __init__(self, responses: list[httpx2.Response]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []
        self.closed = False
        self.close_calls = 0

    def post(self, url: str, **kwargs: Any) -> httpx2.Response:
        self.calls.append({"url": url, **kwargs})
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True
        self.close_calls += 1


class FailingHTTPClient:
    def post(self, url: str, **kwargs: Any) -> httpx2.Response:
        request = httpx2.Request("POST", url)
        raise httpx2.ConnectError("connection refused", request=request)

    def close(self) -> None:
        pass


def make_response(
    *,
    status_code: int = 200,
    code: int = 0,
    message: str = "OK",
    envelope: str = "encrypted-envelope",
    date: str = "Tue, 14 Nov 2023 22:13:20 GMT",
) -> httpx2.Response:
    data = {"envelope": envelope} if envelope else None
    headers = {"Date": date} if date else None
    return httpx2.Response(
        status_code,
        content=json.dumps({"code": code, "message": message, "data": data}).encode(),
        headers=headers,
    )


def _client_with_http(
    monkeypatch: pytest.MonkeyPatch,
    http_client: RecordingHTTPClient | FailingHTTPClient,
    **kwargs: Any,
) -> Client:
    monkeypatch.setattr("bk_kms.client.httpx2.Client", lambda: http_client)
    kwargs.setdefault("tenant_id", "system")
    return Client(**kwargs)


def test_client_does_not_expose_http_client() -> None:
    assert "http_client" not in signature(Client).parameters


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"base_url": ""}, "base_url"),
        ({"base_url": "https://example.com"}, "app_code"),
        ({"base_url": "https://example.com", "app_code": "app", "direct": False}, "app_secret"),
        ({"base_url": "https://example.com", "direct": True, "app_code": "app", "timeout": 0}, "timeout"),
    ],
)
def test_client_validates_configuration(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigurationError, match=message):
        Client(tenant_id="system", **kwargs)


def test_gateway_request_matches_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    http_client = RecordingHTTPClient([make_response()])
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    monkeypatch.setattr("bk_kms.client.new_nonce", lambda: "nonce")
    monkeypatch.setattr("bk_kms.client.uuid.uuid4", lambda: type("UUID", (), {"hex": "request-id"})())
    monkeypatch.setattr("bk_kms.client.time.time", lambda: 1_700_000_000)
    client = _client_with_http(
        monkeypatch,
        http_client,
        base_url="https://example.com/api/bk-kms/prod/",
        app_code="app",
        app_secret="app-secret",
        tenant_id="tenant-a",
        direct=False,
    )

    result = client.consume_credential_envelope(
        access_key="access-key",
        secret_key="secret-key",
        credential_names=["database", "redis"],
    )

    assert result == ConsumeEnvelope("encrypted-envelope", "private-key")
    assert len(http_client.calls) == 1
    call = http_client.calls[0]
    assert call["url"] == "https://example.com/api/bk-kms/prod/api/v1/consume_credential"
    assert json.loads(call["content"]) == {
        "credential_id_list": [],
        "credential_name_list": ["database", "redis"],
        "crypto": {
            "asymmetric_type": "RSA",
            "symmetric_type": "AES",
            "symmetric_mode": "CBC",
        },
        "public_key": "public-key",
    }
    assert call["headers"]["X-Bkapi-Authorization"] == '{"bk_app_code":"app","bk_app_secret":"app-secret"}'
    assert call["headers"]["X-Bkapi-Request-Id"] == "request-id"
    assert call["headers"]["X-Bk-Tenant-Id"] == "tenant-a"
    assert call["headers"]["X-BKKMS-AK"] == "access-key"
    assert call["headers"]["X-BKKMS-Timestamp"] == "1700000000"
    assert call["headers"]["X-BKKMS-Nonce"] == "nonce"
    assert call["headers"]["X-BKKMS-Signature"] == ("150b382b58166dc71a67e5e49ba4390c16efbc88805b50ccee9d7bed7df2b3f7")
    assert call["headers"]["X-BKKMS-SDK-Version"] == "v1.0.0-alpha.1"
    assert call["timeout"] == 30.0
    assert call["follow_redirects"] is False


@pytest.mark.parametrize("tenant_id", ["   ", 123, False])
def test_client_rejects_invalid_tenant_id(tenant_id: Any) -> None:
    with pytest.raises(ConfigurationError, match="tenant_id"):
        Client(base_url="http://kms:23681", app_code="app", tenant_id=tenant_id)


@pytest.mark.parametrize("tenant_config", [{}, {"tenant_id": None}, {"tenant_id": ""}])
@pytest.mark.parametrize(
    ("paas_tenant", "app_tenant"),
    [
        (None, None),
        (None, "system"),
        ("saas-tenant", "system"),
        ("", "other"),
    ],
)
def test_client_sends_empty_tenant_without_reading_environment(
    monkeypatch: pytest.MonkeyPatch,
    tenant_config: dict[str, Any],
    paas_tenant: str | None,
    app_tenant: str | None,
) -> None:
    http_client = RecordingHTTPClient([make_response()])
    monkeypatch.setattr("bk_kms.client.httpx2.Client", lambda: http_client)
    monkeypatch.setattr("bk_kms.client.generate_key_pair", lambda _: KeyPair("public-key", "private-key"))
    for name, value in (("BKPAAS_APP_TENANT_ID", paas_tenant), ("BK_APP_TENANT_ID", app_tenant)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    with Client(base_url="http://kms:23681", app_code="app", **tenant_config) as client:
        monkeypatch.setenv("BKPAAS_APP_TENANT_ID", "changed-after-construction")
        client.consume_credential_envelope(access_key="ak", secret_key="sk")
    assert http_client.calls[0]["headers"]["X-Bk-Tenant-Id"] == ""


@pytest.mark.parametrize("direct", [True, False])
@pytest.mark.parametrize("tenant_id", ["tenant-a", "default"])
def test_client_keeps_configured_tenant_across_requests(
    monkeypatch: pytest.MonkeyPatch, direct: bool, tenant_id: str
) -> None:
    http_client = RecordingHTTPClient([make_response(), make_response()])
    monkeypatch.setattr("bk_kms.client.generate_key_pair", lambda _: KeyPair("public-key", "private-key"))
    with _client_with_http(
        monkeypatch,
        http_client,
        base_url="https://example.com",
        app_code="app",
        app_secret="secret",
        direct=direct,
        tenant_id=tenant_id,
    ) as client:
        client.consume_credential_envelope(access_key="ak", secret_key="sk")
        monkeypatch.setenv("BKPAAS_APP_TENANT_ID", "tenant-b")
        monkeypatch.setenv("BK_APP_TENANT_ID", "tenant-c")
        client.consume_credential_envelope(access_key="ak", secret_key="sk")
    assert [call["headers"]["X-Bk-Tenant-Id"] for call in http_client.calls] == [tenant_id, tenant_id]


@pytest.mark.parametrize("mode", [{}, {"direct": True}])
def test_direct_request_uses_backend_path_without_gateway_authorization(
    monkeypatch: pytest.MonkeyPatch,
    mode: dict[str, bool],
) -> None:
    http_client = RecordingHTTPClient([make_response()])
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    client = _client_with_http(monkeypatch, http_client, base_url="http://kms:23681", app_code="app", **mode)

    client.consume_credential_envelope(access_key="ak", secret_key="sk")

    call = http_client.calls[0]
    assert call["url"] == "http://kms:23681/api/v1/consume/credential"
    assert call["headers"]["X-Bk-AppCode"] == "app"
    assert "X-Bkapi-Authorization" not in call["headers"]
    assert json.loads(call["content"])["credential_id_list"] == []


def test_consume_credential_decrypts_returned_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    http_client = RecordingHTTPClient([make_response()])
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    expected = [ConsumeResult(1, 1034003, "not found", None)]
    monkeypatch.setattr("bk_kms.client.decrypt_envelope", lambda envelope: expected)
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    assert client.consume_credential(access_key="ak", secret_key="sk") is expected


def test_clock_skew_updates_offset_and_retries_once(monkeypatch: pytest.MonkeyPatch) -> None:
    server_timestamp = 1_700_000_100
    date = datetime.fromtimestamp(server_timestamp, UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")
    http_client = RecordingHTTPClient(
        [
            make_response(code=1034016, message="skewed", envelope="", date=date),
            make_response(),
        ]
    )
    key_pairs = iter([KeyPair("public-1", "private-1"), KeyPair("public-2", "private-2")])
    nonces = iter(["nonce-1", "nonce-2"])
    monkeypatch.setattr("bk_kms.client.generate_key_pair", lambda crypto_type: next(key_pairs))
    monkeypatch.setattr("bk_kms.client.new_nonce", lambda: next(nonces))
    monkeypatch.setattr("bk_kms.client.time.time", lambda: 1_700_000_000)
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    envelope = client.consume_credential_envelope(access_key="ak", secret_key="sk")

    assert envelope.private_key == "private-2"
    assert len(http_client.calls) == 2
    assert http_client.calls[0]["headers"]["X-BKKMS-Timestamp"] == "1700000000"
    assert http_client.calls[1]["headers"]["X-BKKMS-Timestamp"] == "1700000100"
    assert http_client.calls[0]["headers"]["X-BKKMS-Nonce"] == "nonce-1"
    assert http_client.calls[1]["headers"]["X-BKKMS-Nonce"] == "nonce-2"


def test_clock_skew_is_not_retried_more_than_once(monkeypatch: pytest.MonkeyPatch) -> None:
    http_client = RecordingHTTPClient(
        [
            make_response(code=1034016, message="skewed"),
            make_response(code=1034016, message="still skewed"),
        ]
    )
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    with pytest.raises(ClockSkewError) as exc_info:
        client.consume_credential_envelope(access_key="ak", secret_key="sk")

    assert exc_info.value.code == 1034016
    assert len(http_client.calls) == 2


def test_clock_skew_requires_valid_date_header(monkeypatch: pytest.MonkeyPatch) -> None:
    http_client = RecordingHTTPClient([make_response(code=1034016, message="skewed", date="")])
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    with pytest.raises(ClockSkewError, match="Date") as exc_info:
        client.consume_credential_envelope(access_key="ak", secret_key="sk")

    assert exc_info.value.status_code == 200
    assert exc_info.value.request_id is not None
    assert len(http_client.calls) == 1


def test_clock_skew_rejects_date_without_timezone(monkeypatch: pytest.MonkeyPatch) -> None:
    http_client = RecordingHTTPClient([make_response(code=1034016, message="skewed", date="Tue, 14 Nov 2023 22:13:20")])
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    with pytest.raises(ClockSkewError, match="invalid Date"):
        client.consume_credential_envelope(access_key="ak", secret_key="sk")


def test_non_success_response_raises_request_error_without_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http_client = RecordingHTTPClient([make_response(status_code=403, code=1034008, message="denied")])
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    with pytest.raises(KMSRequestError) as exc_info:
        client.consume_credential_envelope(access_key="access-key", secret_key="must-not-leak")

    assert exc_info.value.status_code == 403
    assert exc_info.value.code == 1034008
    assert "must-not-leak" not in str(exc_info.value)


def test_http_error_raises_transport_error_without_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    client = _client_with_http(
        monkeypatch,
        FailingHTTPClient(),
        base_url="http://kms:23681",
        direct=True,
        app_code="app",
    )

    with pytest.raises(TransportError, match="KMS request failed") as exc_info:
        client.consume_credential_envelope(access_key="access-key", secret_key="must-not-leak")

    assert "must-not-leak" not in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, httpx2.ConnectError)


def test_invalid_response_json_raises_decode_error(monkeypatch: pytest.MonkeyPatch) -> None:
    response = make_response()
    response._content = b"not-json"
    http_client = RecordingHTTPClient([response])
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    with pytest.raises(ResponseDecodeError):
        client.consume_credential_envelope(access_key="ak", secret_key="sk")


def test_response_message_rejects_wrong_type(monkeypatch: pytest.MonkeyPatch) -> None:
    response = make_response()
    response._content = b'{"code":0,"message":123,"data":{"envelope":"value"}}'
    http_client = RecordingHTTPClient([response])
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    with pytest.raises(ResponseDecodeError, match="message"):
        client.consume_credential_envelope(access_key="ak", secret_key="sk")


def test_response_rejects_non_standard_json_constants(monkeypatch: pytest.MonkeyPatch) -> None:
    response = make_response()
    response._content = b'{"code":NaN,"message":"","data":null}'
    http_client = RecordingHTTPClient([response])
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    with pytest.raises(ResponseDecodeError):
        client.consume_credential_envelope(access_key="ak", secret_key="sk")


def test_response_code_must_fit_go_int32(monkeypatch: pytest.MonkeyPatch) -> None:
    response = make_response(code=2**31)
    http_client = RecordingHTTPClient([response])
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    with pytest.raises(ResponseDecodeError, match="32-bit"):
        client.consume_credential_envelope(access_key="ak", secret_key="sk")


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ([], "JSON object"),
        ({"code": "0", "message": "OK", "data": {"envelope": "value"}}, "code must be an integer"),
        ({"code": 0, "message": "OK", "data": []}, "data must be an object"),
        ({"code": 0, "message": "OK", "data": {"envelope": ""}}, "empty envelope"),
    ],
)
def test_response_rejects_invalid_shapes(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
    message: str,
) -> None:
    response = make_response()
    response._content = json.dumps(payload).encode()
    http_client = RecordingHTTPClient([response])
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    with pytest.raises(ResponseDecodeError, match=message):
        client.consume_credential_envelope(access_key="ak", secret_key="sk")


def test_response_allows_missing_message(monkeypatch: pytest.MonkeyPatch) -> None:
    response = make_response()
    response._content = b'{"code":0,"data":{"envelope":"value"}}'
    http_client = RecordingHTTPClient([response])
    monkeypatch.setattr(
        "bk_kms.client.generate_key_pair",
        lambda crypto_type: KeyPair("public-key", "private-key"),
    )
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    assert client.consume_credential_envelope(access_key="ak", secret_key="sk") == ConsumeEnvelope(
        "value", "private-key"
    )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"access_key": "ak", "secret_key": ""}, "secret_key"),
    ],
)
def test_consume_envelope_validates_request_inputs(kwargs: dict[str, Any], message: str) -> None:
    client = Client(base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system")

    with pytest.raises(ValidationError, match=message):
        client.consume_credential_envelope(**kwargs)


def test_client_context_manager_closes_owned_http_client(monkeypatch: pytest.MonkeyPatch) -> None:
    http_client = RecordingHTTPClient([])
    monkeypatch.setattr("bk_kms.client.httpx2.Client", lambda: http_client)

    with Client(base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system") as client:
        assert client is not None

    assert http_client.closed


def test_client_close_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    http_client = RecordingHTTPClient([])
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )

    client.close()
    client.close()

    assert http_client.close_calls == 1


def test_closed_client_fails_before_generating_a_key_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    client = Client(base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system")
    client.close()

    def fail_if_called(crypto_type: object) -> KeyPair:
        raise AssertionError("key generation must not run after close")

    monkeypatch.setattr("bk_kms.client.generate_key_pair", fail_if_called)

    with pytest.raises(ClientClosedError):
        client.consume_credential_envelope(access_key="ak", secret_key="sk")


def test_validation_errors_do_not_include_secrets() -> None:
    client = Client(base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system")

    with pytest.raises(Exception) as exc_info:
        client.consume_credential_envelope(access_key="", secret_key="must-not-leak", crypto=CryptoInfo.rsa_aes_cbc())

    assert "must-not-leak" not in str(exc_info.value)


@pytest.mark.parametrize("code", [1034011, 1034012, 1034013, 1034014, 1034015])
def test_authentication_errors_are_not_retried(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    http_client = RecordingHTTPClient([make_response(code=code, envelope=""), make_response()])
    client = _client_with_http(
        monkeypatch, http_client, base_url="http://kms:23681", direct=True, app_code="app", tenant_id="system"
    )
    with pytest.raises(KMSRequestError) as exc_info:
        client.consume_credential_envelope(access_key="ak", secret_key="sk")
    assert type(exc_info.value) is KMSRequestError
    assert exc_info.value.code == code
    assert len(http_client.calls) == 1


@pytest.mark.parametrize("direct", [True, False])
@pytest.mark.parametrize("app_code", [None, "", "   ", 123])
def test_app_code_required_in_both_modes(direct: bool, app_code: Any) -> None:
    with pytest.raises(ConfigurationError, match="app_code"):
        Client(base_url="http://kms:23681", direct=direct, app_code=app_code, app_secret="secret", tenant_id="system")
