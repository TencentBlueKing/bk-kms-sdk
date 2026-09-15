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

"""Unified RSA/AES/SM2/SM4 providers implemented through ``bkcrypto``."""

import base64
import binascii
import sys
from enum import StrEnum
from typing import assert_never

from bkcrypto import constants as bkcrypto_constants
from bkcrypto.asymmetric.ciphers import RSAAsymmetricCipher
from bkcrypto.symmetric.ciphers import AESSymmetricCipher
from cryptography.hazmat.primitives import hashes

from .exceptions import CryptoBackendUnavailableError, CryptoError

BLOCK_SIZE_BYTES = 16


class AsymmetricType(StrEnum):
    """Supported asymmetric algorithms."""

    RSA = "RSA"
    SM2 = "SM2"


class SymmetricType(StrEnum):
    """Supported symmetric algorithms."""

    AES = "AES"
    SM4 = "SM4"


class CryptoMode(StrEnum):
    """Supported symmetric cipher modes."""

    CBC = "CBC"
    CTR = "CTR"


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


def decrypt_rsa(ciphertext: str, private_key: str) -> bytes:
    """Decrypt a data key with RSA-OAEP using SHA-256."""

    _decode_base64(ciphertext, "RSA ciphertext")
    private_key_string = _decode_pem(private_key, "RSA private key")
    try:
        cipher = RSAAsymmetricCipher(
            private_key_string=private_key_string,
            padding=bkcrypto_constants.RSACipherPadding.PKCS1_OAEP,
            oaep_hash=hashes.SHA256(),
            mgf1_hash=hashes.SHA256(),
            oaep_label=None,
            enable_segmented_encryption=False,
        )
    except (TypeError, ValueError) as exc:
        raise CryptoError("failed to decode RSA private key") from exc

    try:
        return cipher.decrypt_bytes(ciphertext)
    except Exception as exc:
        raise CryptoError("failed to decrypt RSA ciphertext") from exc


def decrypt_aes(ciphertext: str, key: bytes, mode: CryptoMode) -> bytes:
    """Decrypt Base64 ``IV || ciphertext`` with AES-CBC or AES-CTR."""

    _validate_key(key)
    _validate_symmetric_ciphertext(ciphertext, "AES", mode)
    if mode is CryptoMode.CBC:
        padding = bkcrypto_constants.SymmetricPadding.PKCS7
    elif mode is CryptoMode.CTR:
        padding = bkcrypto_constants.SymmetricPadding.NONE
    else:
        assert_never(mode)

    try:
        cipher = AESSymmetricCipher(
            key=key,
            mode=bkcrypto_constants.SymmetricMode(mode.value),
            padding=padding,
            enable_iv=True,
            iv_size=BLOCK_SIZE_BYTES,
            enable_aad=False,
            encryption_metadata_combination_mode=bkcrypto_constants.EncryptionMetadataCombinationMode.BYTES,
        )
        return cipher.decrypt_bytes(ciphertext)
    except ValueError as exc:
        if "padding" in str(exc).lower():
            raise CryptoError("invalid PKCS#7 padding") from exc
        raise CryptoError(f"failed to decrypt AES-{mode.value} ciphertext") from exc
    except Exception as exc:
        raise CryptoError(f"failed to decrypt AES-{mode.value} ciphertext") from exc


def decrypt_sm2(ciphertext: str, private_key: str) -> bytes:
    """Decrypt a data key with the optional SM2 backend."""

    _decode_base64(ciphertext, "SM2 ciphertext")
    private_key_string = _decode_pem(private_key, "SM2 private key")
    try:
        from bkcrypto.asymmetric.ciphers.sm2 import SM2AsymmetricCipher
    except (ImportError, OSError) as exc:
        raise CryptoBackendUnavailableError(
            backend="bkcrypto",
            algorithms=("SM2", "SM4"),
            platform=sys.platform,
        ) from exc
    try:
        return SM2AsymmetricCipher(private_key_string=private_key_string).decrypt_bytes(ciphertext)
    except Exception as exc:
        raise CryptoError("failed to decrypt SM2 ciphertext") from exc


def decrypt_sm4(ciphertext: str, key: bytes, mode: CryptoMode) -> bytes:
    """Decrypt Base64 ``IV || ciphertext`` with SM4-CBC or SM4-CTR."""

    _validate_key(key)
    _validate_symmetric_ciphertext(ciphertext, "SM4", mode)
    if mode is CryptoMode.CBC:
        unpad = True
    elif mode is CryptoMode.CTR:
        unpad = False
    else:
        assert_never(mode)
    try:
        from bkcrypto.symmetric.ciphers.sm4 import SM4SymmetricCipher
    except (ImportError, OSError) as exc:
        raise CryptoBackendUnavailableError(
            backend="bkcrypto",
            algorithms=("SM2", "SM4"),
            platform=sys.platform,
        ) from exc
    try:
        cipher = SM4SymmetricCipher(
            key=key,
            mode=bkcrypto_constants.SymmetricMode(mode.value),
            padding=bkcrypto_constants.SymmetricPadding.NONE,
            enable_iv=True,
            iv_size=BLOCK_SIZE_BYTES,
            enable_aad=False,
            encryption_metadata_combination_mode=bkcrypto_constants.EncryptionMetadataCombinationMode.BYTES,
        )
        plaintext = cipher.decrypt_bytes(ciphertext)
    except Exception as exc:
        raise CryptoError(f"failed to decrypt SM4-{mode.value} ciphertext") from exc
    return _pkcs7_unpad(plaintext) if unpad else plaintext


def _decode_base64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CryptoError(f"invalid base64 {label}") from exc


def _decode_pem(value: str, label: str) -> str:
    try:
        return _decode_base64(value, label).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CryptoError(f"invalid base64 {label}") from exc


def _validate_key(key: bytes) -> None:
    if len(key) != BLOCK_SIZE_BYTES:
        raise CryptoError(f"symmetric key must be exactly {BLOCK_SIZE_BYTES} bytes")


def _validate_symmetric_ciphertext(ciphertext: str, algorithm: str, mode: CryptoMode) -> None:
    """Validate Base64 ``IV || ciphertext`` framing and CBC block alignment."""

    encrypted = _decode_base64(ciphertext, f"{algorithm} ciphertext")
    if len(encrypted) < BLOCK_SIZE_BYTES + 1:
        raise CryptoError(f"{algorithm} ciphertext is too short")
    if mode is CryptoMode.CBC and len(encrypted[BLOCK_SIZE_BYTES:]) % BLOCK_SIZE_BYTES != 0:
        raise CryptoError(f"{algorithm}-CBC ciphertext is not block aligned")


def _pkcs7_unpad(value: bytes) -> bytes:
    """Remove strict PKCS#7 padding only when every padding byte matches."""

    if not value or len(value) % BLOCK_SIZE_BYTES != 0:
        raise CryptoError("invalid PKCS#7 padding")
    padding_size = value[-1]
    if padding_size < 1 or padding_size > BLOCK_SIZE_BYTES:
        raise CryptoError("invalid PKCS#7 padding")
    if value[-padding_size:] != bytes([padding_size]) * padding_size:
        raise CryptoError("invalid PKCS#7 padding")
    return value[:-padding_size]
