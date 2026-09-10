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

"""Dispatch cryptographic operations through the unified bkcrypto adapter."""

from typing import assert_never

from ..models import AsymmetricType, CryptoMode, SymmetricType
from .base import KeyPair
from .bkcrypto import (
    decrypt_aes,
    decrypt_rsa,
    decrypt_sm2,
    decrypt_sm4,
    generate_rsa_key_pair,
    generate_sm2_key_pair,
)


def generate_key_pair(crypto_type: AsymmetricType) -> KeyPair:
    """Generate a request-scoped key pair for the selected asymmetric algorithm."""

    if crypto_type is AsymmetricType.RSA:
        return generate_rsa_key_pair()
    if crypto_type is AsymmetricType.SM2:
        return generate_sm2_key_pair()
    assert_never(crypto_type)


def decrypt_asymmetric(ciphertext: str, crypto_type: AsymmetricType, private_key: str) -> bytes:
    """Decrypt an envelope data key with the selected asymmetric algorithm."""

    if crypto_type is AsymmetricType.RSA:
        return decrypt_rsa(ciphertext, private_key)
    if crypto_type is AsymmetricType.SM2:
        return decrypt_sm2(ciphertext, private_key)
    assert_never(crypto_type)


def decrypt_symmetric(
    ciphertext: str,
    crypto_type: SymmetricType,
    mode: CryptoMode,
    key: bytes,
) -> bytes:
    """Decrypt an envelope payload with the selected symmetric algorithm and mode."""

    if crypto_type is SymmetricType.AES:
        return decrypt_aes(ciphertext, key, mode)
    if crypto_type is SymmetricType.SM4:
        return decrypt_sm4(ciphertext, key, mode)
    assert_never(crypto_type)
