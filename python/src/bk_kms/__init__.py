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

"""Public API for the BK-KMS Python SDK."""

from ._version import __version__
from .client import Client
from .envelope import decrypt_envelope
from .exceptions import (
    BKMSException,
    ClientClosedError,
    ClockSkewError,
    ConfigurationError,
    CryptoBackendUnavailableError,
    CryptoError,
    EnvelopeDecodeError,
    KMSRequestError,
    ResponseDecodeError,
    TransportError,
    ValidationError,
)
from .models import (
    ERR_CODE_ACCESS_KEY_DISABLED,
    ERR_CODE_ACCESS_KEY_EXPIRED,
    ERR_CODE_ACCESS_KEY_NOT_BOUND,
    ERR_CODE_GENERIC_ERROR,
    ERR_CODE_NONCE_ALREADY_USED,
    ERR_CODE_NOT_FOUND,
    ERR_CODE_OK,
    ERR_CODE_PERMISSION_DENIED,
    ERR_CODE_REQUEST_TIME_TOO_SKEWED,
    ERR_CODE_SIGNATURE_MISMATCH,
    AsymmetricType,
    AuthInfo,
    ConsumeEnvelope,
    ConsumeResult,
    Credential,
    CredentialType,
    CryptoInfo,
    CryptoMode,
    SymmetricType,
)

__all__ = [
    "ERR_CODE_ACCESS_KEY_DISABLED",
    "ERR_CODE_ACCESS_KEY_EXPIRED",
    "ERR_CODE_ACCESS_KEY_NOT_BOUND",
    "ERR_CODE_NONCE_ALREADY_USED",
    "ERR_CODE_SIGNATURE_MISMATCH",
    "ERR_CODE_GENERIC_ERROR",
    "ERR_CODE_NOT_FOUND",
    "ERR_CODE_OK",
    "ERR_CODE_PERMISSION_DENIED",
    "ERR_CODE_REQUEST_TIME_TOO_SKEWED",
    "AsymmetricType",
    "AuthInfo",
    "BKMSException",
    "ClientClosedError",
    "Client",
    "ClockSkewError",
    "ConfigurationError",
    "ConsumeEnvelope",
    "ConsumeResult",
    "Credential",
    "CredentialType",
    "CryptoBackendUnavailableError",
    "CryptoError",
    "CryptoInfo",
    "CryptoMode",
    "EnvelopeDecodeError",
    "KMSRequestError",
    "ResponseDecodeError",
    "SymmetricType",
    "TransportError",
    "ValidationError",
    "__version__",
    "decrypt_envelope",
]
