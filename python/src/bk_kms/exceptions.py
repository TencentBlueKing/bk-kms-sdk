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


class BKMSException(Exception):
    """Base exception for the BK-KMS SDK."""


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
