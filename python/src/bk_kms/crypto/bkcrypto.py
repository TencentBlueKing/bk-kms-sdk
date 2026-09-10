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
import importlib
import sys
from typing import Any, assert_never, cast

from bkcrypto import constants as bkcrypto_constants
from bkcrypto.asymmetric.ciphers import RSAAsymmetricCipher
from bkcrypto.symmetric.ciphers import AESSymmetricCipher
from cryptography.hazmat.primitives import hashes

from ..exceptions import CryptoBackendUnavailableError, CryptoError
from ..models import CryptoMode
from .base import KeyPair

BLOCK_SIZE_BYTES = 16


def _rsa_cipher(*, private_key_string: str | None = None) -> RSAAsymmetricCipher:
    return RSAAsymmetricCipher(
        private_key_string=private_key_string,
        padding=bkcrypto_constants.RSACipherPadding.PKCS1_OAEP,
        oaep_hash=hashes.SHA256(),
        mgf1_hash=hashes.SHA256(),
        oaep_label=None,
        enable_segmented_encryption=False,
    )


def generate_rsa_key_pair() -> KeyPair:
    """Generate the protocol's 2048-bit RSA key pair in Base64 PEM form."""

    try:
        cipher = _rsa_cipher()
        return KeyPair(
            public_key=_encode_pem(cipher.export_public_key()),
            private_key=_encode_pem(cipher.export_private_key()),
        )
    except Exception as exc:
        raise CryptoError("failed to generate RSA key pair") from exc


def decrypt_rsa(ciphertext: str, private_key: str) -> bytes:
    """Decrypt a data key with RSA-OAEP using SHA-256."""

    _decode_base64(ciphertext, "RSA ciphertext")
    private_key_string = _decode_pem(private_key, "RSA private key")
    try:
        cipher = _rsa_cipher(private_key_string=private_key_string)
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


def _load_gm_backend() -> tuple[type[Any], type[Any], Any, Any]:
    """Import the optional GM backend and preserve its import failure as the cause."""

    try:
        serialization = importlib.import_module("tongsuopy.crypto.serialization")
        asymmetric = importlib.import_module("bkcrypto.asymmetric.ciphers")
        symmetric = importlib.import_module("bkcrypto.symmetric.ciphers")
        constants = importlib.import_module("bkcrypto.constants")
        return asymmetric.SM2AsymmetricCipher, symmetric.SM4SymmetricCipher, constants, serialization
    except (ImportError, OSError) as exc:
        error = CryptoBackendUnavailableError(
            backend="bkcrypto",
            algorithms=("SM2", "SM4"),
            platform=sys.platform,
        )
        raise error from exc


def generate_sm2_key_pair() -> KeyPair:
    """Generate an SM2 key pair in the protocol's Base64 PEM form."""

    sm2_class, _, _, serialization = _load_gm_backend()
    try:
        cipher = sm2_class()
        private_key = serialization.load_pem_private_key(
            cipher.export_private_key().encode("utf-8"),
            password=None,
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return KeyPair(
            public_key=_encode_pem(cipher.export_public_key()),
            private_key=base64.b64encode(private_pem).decode("ascii"),
        )
    except Exception as exc:
        raise CryptoError("failed to generate SM2 key pair") from exc


def decrypt_sm2(ciphertext: str, private_key: str) -> bytes:
    """Decrypt a data key with the optional SM2 backend."""

    _decode_base64(ciphertext, "SM2 ciphertext")
    private_key_string = _decode_pem(private_key, "SM2 private key")
    sm2_class, _, _, _ = _load_gm_backend()
    try:
        return cast(bytes, sm2_class(private_key_string=private_key_string).decrypt_bytes(ciphertext))
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
    _, sm4_class, constants, _ = _load_gm_backend()
    try:
        cipher = sm4_class(
            key=key,
            mode=constants.SymmetricMode(mode.value),
            padding=constants.SymmetricPadding.NONE,
            enable_iv=True,
            iv_size=BLOCK_SIZE_BYTES,
            enable_aad=False,
            encryption_metadata_combination_mode=constants.EncryptionMetadataCombinationMode.BYTES,
        )
        plaintext = cast(bytes, cipher.decrypt_bytes(ciphertext))
    except Exception as exc:
        raise CryptoError(f"failed to decrypt SM4-{mode.value} ciphertext") from exc
    return _pkcs7_unpad(plaintext) if unpad else plaintext


def _decode_base64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CryptoError(f"invalid base64 {label}") from exc


def _encode_pem(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


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
