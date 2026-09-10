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

"""Stable exception hierarchy exposed by the BK-KMS SDK."""

from collections.abc import Sequence
from typing import Optional


class BKMSException(Exception):
    """Base exception for the BK-KMS SDK."""


class ConfigurationError(BKMSException):
    """Raised when client configuration is invalid."""


class ValidationError(BKMSException):
    """Raised when a request or model value is invalid."""


class ClientClosedError(BKMSException):
    """Raised when a closed client is used."""


class TransportError(BKMSException):
    """Raised when an HTTP request cannot be completed."""


class ResponseDecodeError(BKMSException):
    """Raised when an HTTP response cannot be decoded."""


class KMSRequestError(BKMSException):
    """Raised when KMS rejects a request.

    :param message: Human-readable failure description without request secrets.
    :param status_code: HTTP status code returned by KMS or API Gateway.
    :param code: Optional KMS application error code.
    :param request_id: Optional request identifier used for troubleshooting.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        code: Optional[int] = None,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.request_id = request_id


class ClockSkewError(KMSRequestError):
    """Raised when KMS reports clock skew and correction is not possible."""


class CryptoError(BKMSException):
    """Raised when cryptographic processing fails."""


class CryptoBackendUnavailableError(CryptoError):
    """Raised when an optional cryptographic backend cannot be loaded.

    :param backend: Name of the unavailable backend.
    :param algorithms: Algorithms that require the backend.
    :param platform: Current platform description included in the error message.
    """

    def __init__(
        self,
        *,
        backend: str,
        algorithms: Sequence[str],
        platform: str,
    ) -> None:
        algorithms_text = ", ".join(algorithms)
        super().__init__(
            f"{backend} backend is unavailable on {platform}; "
            f"required for {algorithms_text}. Install bk-kms-sdk[gm] if a compatible wheel exists."
        )
        self.backend = backend
        self.algorithms = tuple(algorithms)
        self.platform = platform


class EnvelopeDecodeError(CryptoError):
    """Raised when a credential envelope cannot be decoded."""
