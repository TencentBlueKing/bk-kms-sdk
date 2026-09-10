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

"""Synchronous BK-KMS client and request orchestration."""

import time
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC
from email.utils import parsedate_to_datetime
from typing import Any, Optional, cast

import httpx2

from ._json import loads
from ._version import SDK_VERSION
from .crypto import generate_key_pair
from .envelope import decrypt_envelope
from .exceptions import (
    ClientClosedError,
    ClockSkewError,
    ConfigurationError,
    KMSRequestError,
    ResponseDecodeError,
    TransportError,
    ValidationError,
)
from .models import (
    ERR_CODE_REQUEST_TIME_TOO_SKEWED,
    ConsumeEnvelope,
    ConsumeResult,
    CryptoInfo,
)
from .signature import (
    build_authorization_header,
    build_consume_request,
    new_nonce,
    sign_request,
)

API_GATEWAY_PATH = "/api/v1/consume_credential"
DIRECT_PATH = "/api/v1/consume/credential"


class _RetryClockSkew(Exception):
    """Signal that clock correction succeeded and the request should be retried."""


class Client:
    """Consume credentials from BK-KMS in API Gateway or direct mode.

    The client owns its HTTP client. Use it as a context manager to close
    resources deterministically.

    :param base_url: Base URL of the API Gateway route or direct KMS service.
    :param direct: Send requests directly to KMS instead of through API Gateway. Defaults to ``True``.
    :param app_code: BlueKing application code required in both modes.
    :param tenant_id: Tenant ID sent in every KMS request. Defaults to an empty
        string; environment variables and framework settings are not read.
    :param app_secret: BlueKing application secret required in API Gateway mode.
    :param timeout: HTTP connect/read/write/pool timeout in seconds. Defaults to ``30.0``.
    :raises ConfigurationError: If the URL, application credentials, tenant ID, or timeout is invalid.
    """

    def __init__(
        self,
        *,
        base_url: str,
        tenant_id: Optional[str] = None,
        direct: bool = True,
        app_code: Optional[str] = None,
        app_secret: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ConfigurationError("base_url cannot be empty")
        if not isinstance(app_code, str) or not app_code.strip():
            raise ConfigurationError("app_code cannot be empty")
        if tenant_id is not None and not isinstance(tenant_id, str):
            raise ConfigurationError("tenant_id must be a string")
        tenant_id = tenant_id or ""
        if tenant_id and not tenant_id.strip():
            raise ConfigurationError("tenant_id cannot be whitespace")
        if not direct and (not isinstance(app_secret, str) or not app_secret.strip()):
            raise ConfigurationError("app_secret cannot be empty in gateway mode")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ConfigurationError("timeout must be greater than zero")

        self._base_url = base_url.rstrip("/")
        self._direct = direct
        self._app_code = app_code
        self._tenant_id = tenant_id
        self._app_secret = app_secret or ""
        self._timeout = float(timeout)
        self._http_client = httpx2.Client()
        self._closed = False
        self._clock_offset = 0

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close HTTP resources owned by this client.

        Calling this method more than once is safe.
        """

        if self._closed:
            return
        self._closed = True
        self._http_client.close()

    def consume_credential(
        self,
        *,
        access_key: str,
        secret_key: str,
        credential_names: Optional[Sequence[str]] = None,
        crypto: Optional[CryptoInfo] = None,
    ) -> list[ConsumeResult]:
        """Fetch credentials and decrypt the returned envelope locally.

        :param access_key: KMS access key used to authenticate the request.
        :param secret_key: KMS secret key used to sign the request.
        :param credential_names: Credential names to fetch. ``None`` and an empty
            sequence request all credentials in the Access Key's uniquely bound group.
        :param crypto: Hybrid-encryption algorithms. Defaults to RSA with AES-CBC.
        :return: One result for each credential returned by KMS.
        :rtype: list[ConsumeResult]
        :raises ValidationError: If a request argument or crypto selection is invalid.
        :raises ClientClosedError: If the client has already been closed.
        :raises TransportError: If the HTTP request cannot be completed.
        :raises ResponseDecodeError: If the KMS response cannot be decoded.
        :raises KMSRequestError: If KMS rejects the request, including an uncorrectable clock-skew error.
        :raises CryptoError: If key generation or local envelope decryption fails.
        """

        envelope = self.consume_credential_envelope(
            access_key=access_key,
            secret_key=secret_key,
            credential_names=credential_names,
            crypto=crypto,
        )
        return decrypt_envelope(envelope)

    def consume_credential_envelope(
        self,
        *,
        access_key: str,
        secret_key: str,
        credential_names: Optional[Sequence[str]] = None,
        crypto: Optional[CryptoInfo] = None,
    ) -> ConsumeEnvelope:
        """Fetch an encrypted credential envelope for deferred decryption.

        The returned envelope and private key must both be treated as secrets.

        :param access_key: KMS access key used to authenticate the request.
        :param secret_key: KMS secret key used to sign the request.
        :param credential_names: Credential names to fetch. ``None`` and an empty
            sequence request all credentials in the Access Key's uniquely bound group.
        :param crypto: Hybrid-encryption algorithms. Defaults to RSA with AES-CBC.
        :return: The encrypted response and request-scoped private key needed to decrypt it.
        :rtype: ConsumeEnvelope
        :raises ValidationError: If a request argument or crypto selection is invalid.
        :raises ClientClosedError: If the client has already been closed.
        :raises TransportError: If the HTTP request cannot be completed.
        :raises ResponseDecodeError: If the KMS response cannot be decoded.
        :raises KMSRequestError: If KMS rejects the request, including an uncorrectable clock-skew error.
        :raises CryptoError: If request key generation fails.
        """

        if self._closed:
            raise ClientClosedError("client is closed")
        if not isinstance(access_key, str) or not access_key.strip():
            raise ValidationError("access_key cannot be empty")
        if not isinstance(secret_key, str) or not secret_key.strip():
            raise ValidationError("secret_key cannot be empty")

        crypto_info = crypto or CryptoInfo.rsa_aes_cbc()

        try:
            return self._consume_once(
                access_key=access_key,
                secret_key=secret_key,
                credential_names=credential_names,
                crypto=crypto_info,
                allow_clock_retry=True,
            )
        except _RetryClockSkew:
            # The retry regenerates key material, nonce, timestamp, signature,
            # and request ID. No other error is retried.
            return self._consume_once(
                access_key=access_key,
                secret_key=secret_key,
                credential_names=credential_names,
                crypto=crypto_info,
                allow_clock_retry=False,
            )

    def _consume_once(
        self,
        *,
        access_key: str,
        secret_key: str,
        credential_names: Optional[Sequence[str]],
        crypto: CryptoInfo,
        allow_clock_retry: bool,
    ) -> ConsumeEnvelope:
        """Execute one fully signed request."""

        key_pair = generate_key_pair(crypto.asymmetric_type)
        nonce = new_nonce()
        timestamp = str(int(time.time()) + self._clock_offset)
        body = build_consume_request(
            credential_names=credential_names,
            crypto=crypto,
            public_key=key_pair.public_key,
        )
        signature = sign_request(
            secret_key=secret_key,
            nonce=nonce,
            timestamp=timestamp,
            content=body,
        )
        request_id = uuid.uuid4().hex
        headers = self._build_headers(
            access_key=access_key,
            timestamp=timestamp,
            nonce=nonce,
            signature=signature,
            request_id=request_id,
        )
        path = DIRECT_PATH if self._direct else API_GATEWAY_PATH
        try:
            response = self._http_client.post(
                f"{self._base_url}{path}",
                content=body,
                headers=headers,
                timeout=self._timeout,
                follow_redirects=False,
            )
        except httpx2.HTTPError as exc:
            raise TransportError("KMS request failed") from exc
        try:
            code, message, data = _parse_response(response.content, response.status_code)

            if code == ERR_CODE_REQUEST_TIME_TOO_SKEWED:
                if allow_clock_retry:
                    self._correct_clock_skew(
                        response.headers.get("Date"),
                        status_code=response.status_code,
                        request_id=request_id,
                    )
                    raise _RetryClockSkew
                raise ClockSkewError(
                    f"KMS rejected request: code={code}, message={message}",
                    status_code=response.status_code,
                    code=code,
                    request_id=request_id,
                )

            if response.status_code != httpx2.codes.OK or code != 0:
                raise KMSRequestError(
                    f"KMS rejected request: status={response.status_code}, code={code}, message={message}",
                    status_code=response.status_code,
                    code=code,
                    request_id=request_id,
                )

            envelope = cast(Mapping[str, Any], data).get("envelope")
            if not isinstance(envelope, str) or not envelope:
                raise ResponseDecodeError("KMS response contains an empty envelope")
            return ConsumeEnvelope(envelope=envelope, private_key=key_pair.private_key)
        finally:
            response.close()

    def _build_headers(
        self,
        *,
        access_key: str,
        timestamp: str,
        nonce: str,
        signature: str,
        request_id: str,
    ) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "X-Bkapi-Request-Id": request_id,
            "X-Bk-Tenant-Id": self._tenant_id,
            "X-BKKMS-AK": access_key,
            "X-BKKMS-Timestamp": timestamp,
            "X-BKKMS-Nonce": nonce,
            "X-BKKMS-Signature": signature,
            "X-BKKMS-SDK-Version": SDK_VERSION,
        }
        if self._direct:
            headers["X-Bk-AppCode"] = self._app_code
        else:
            headers["X-Bkapi-Authorization"] = build_authorization_header(self._app_code, self._app_secret)
        return headers

    def _correct_clock_skew(
        self,
        date_header: Optional[str],
        *,
        status_code: int,
        request_id: str,
    ) -> None:
        """Update the request timestamp offset from a valid HTTP Date header."""

        if not date_header:
            raise ClockSkewError(
                "KMS clock-skew response is missing the Date header",
                status_code=status_code,
                code=ERR_CODE_REQUEST_TIME_TOO_SKEWED,
                request_id=request_id,
            )
        try:
            server_time = parsedate_to_datetime(date_header)
            if server_time.tzinfo is None:
                raise ValueError("HTTP Date must include a timezone")
            server_time = server_time.astimezone(UTC)
            offset = int(server_time.timestamp()) - int(time.time())
        except (TypeError, ValueError, OverflowError) as exc:
            raise ClockSkewError(
                "KMS clock-skew response contains an invalid Date header",
                status_code=status_code,
                code=ERR_CODE_REQUEST_TIME_TOO_SKEWED,
                request_id=request_id,
            ) from exc
        self._clock_offset = offset


def _parse_response(content: bytes, status_code: int) -> tuple[int, str, Optional[Mapping[str, Any]]]:
    """Decode a KMS response into its code, normalized message, and data.

    Codes use the Go-compatible signed 32-bit range. Missing or null messages
    become empty strings, and data is required only for successful responses.
    """

    try:
        payload = loads(content)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ResponseDecodeError(f"KMS response is not valid JSON; status={status_code}") from exc
    if not isinstance(payload, Mapping):
        raise ResponseDecodeError(f"KMS response must be a JSON object; status={status_code}")

    code = payload.get("code")
    if isinstance(code, bool) or not isinstance(code, int):
        raise ResponseDecodeError("KMS response code must be an integer")
    if code < -(2**31) or code > 2**31 - 1:
        raise ResponseDecodeError("KMS response code must fit in a signed 32-bit integer")

    message = payload.get("message")
    if message is None:
        message = ""
    if not isinstance(message, str):
        raise ResponseDecodeError("KMS response message must be a string")

    data = payload.get("data")
    data_mapping = data if isinstance(data, Mapping) else None
    if status_code == httpx2.codes.OK and code == 0 and data_mapping is None:
        raise ResponseDecodeError("KMS response data must be an object")
    return code, message, data_mapping
