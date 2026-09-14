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

import base64
import json
from pathlib import Path

import pytest

from bk_kms import CryptoError
from bk_kms._crypto import AsymmetricType, CryptoMode, SymmetricType, decrypt_asymmetric, decrypt_symmetric

FIXTURE = json.loads((Path(__file__).parents[1] / "fixtures" / "interop_vectors.json").read_text(encoding="utf-8"))
PYTHON_KEY_FIXTURE = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "python_key_interop_vectors.json").read_text(encoding="utf-8")
)


def test_rsa_key_generated_by_python_is_accepted_by_go() -> None:
    vector = PYTHON_KEY_FIXTURE["vectors"]["rsa"]

    plaintext = decrypt_asymmetric(
        vector["ciphertext"],
        AsymmetricType.RSA,
        vector["private_key"],
    )

    assert plaintext == base64.b64decode(PYTHON_KEY_FIXTURE["plaintext_b64"])


@pytest.mark.parametrize("name", ["rsa_aes_cbc", "rsa_aes_ctr"])
def test_rsa_oaep_sha256_decrypts_go_data_key(name: str) -> None:
    vector = FIXTURE["vectors"][name]
    envelope = json.loads(base64.b64decode(vector["envelope"]))

    key = decrypt_asymmetric(
        envelope["encrypted_key"],
        AsymmetricType.RSA,
        vector["private_key"],
    )

    assert key == b"0123456789abcdef"


@pytest.mark.parametrize(
    ("name", "mode"),
    [
        ("rsa_aes_cbc", CryptoMode.CBC),
        ("rsa_aes_ctr", CryptoMode.CTR),
    ],
)
def test_aes_decrypts_go_ciphertext(name: str, mode: CryptoMode) -> None:
    envelope = json.loads(base64.b64decode(FIXTURE["vectors"][name]["envelope"]))

    plaintext = decrypt_symmetric(
        envelope["ciphertext"],
        SymmetricType.AES,
        mode,
        b"0123456789abcdef",
    )

    assert plaintext.decode() == FIXTURE["plaintext"]


def test_symmetric_decrypt_rejects_wrong_key_length() -> None:
    with pytest.raises(CryptoError, match="16 bytes"):
        decrypt_symmetric("YQ==", SymmetricType.AES, CryptoMode.CTR, b"short")


@pytest.mark.parametrize(
    ("ciphertext", "mode", "message"),
    [
        ("not-base64", CryptoMode.CTR, "base64"),
        (base64.b64encode(b"\x00" * 16).decode(), CryptoMode.CTR, "too short"),
        (base64.b64encode(b"\x00" * 17).decode(), CryptoMode.CBC, "block aligned"),
    ],
)
def test_aes_rejects_malformed_ciphertext(ciphertext: str, mode: CryptoMode, message: str) -> None:
    with pytest.raises(CryptoError, match=message):
        decrypt_symmetric(ciphertext, SymmetricType.AES, mode, b"0123456789abcdef")


def test_aes_cbc_rejects_invalid_padding() -> None:
    invalid_ciphertext = base64.b64encode(b"\x00" * 32).decode()

    with pytest.raises(CryptoError, match="padding"):
        decrypt_symmetric(invalid_ciphertext, SymmetricType.AES, CryptoMode.CBC, b"0123456789abcdef")


def test_rsa_rejects_invalid_private_key_pem() -> None:
    ciphertext = base64.b64encode(b"ciphertext").decode()
    private_key = base64.b64encode(b"not-a-private-key").decode()

    with pytest.raises(CryptoError, match="decode RSA private key"):
        decrypt_asymmetric(ciphertext, AsymmetricType.RSA, private_key)


def test_rsa_wraps_decryption_failure() -> None:
    private_key = FIXTURE["vectors"]["rsa_aes_cbc"]["private_key"]
    invalid_ciphertext = base64.b64encode(b"not-an-rsa-ciphertext").decode()

    with pytest.raises(CryptoError, match="decrypt RSA ciphertext"):
        decrypt_asymmetric(invalid_ciphertext, AsymmetricType.RSA, private_key)


def test_rsa_decrypt_passes_bk_kms_options_to_bkcrypto(monkeypatch: pytest.MonkeyPatch) -> None:
    from bkcrypto import constants

    from bk_kms import _crypto as backend

    captured: dict[str, object] = {}

    class FakeRSA:
        def __init__(self, **options: object) -> None:
            captured.update(options)

        def decrypt_bytes(self, ciphertext: str) -> bytes:
            captured["ciphertext"] = ciphertext
            return b"0123456789abcdef"

    monkeypatch.setattr(backend, "RSAAsymmetricCipher", FakeRSA)
    ciphertext = base64.b64encode(b"rsa ciphertext").decode("ascii")
    private_key = base64.b64encode(b"-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n").decode("ascii")

    assert backend.decrypt_rsa(ciphertext, private_key) == b"0123456789abcdef"
    assert captured["padding"] is constants.RSACipherPadding.PKCS1_OAEP
    assert captured["oaep_hash"].name == "sha256"
    assert captured["mgf1_hash"].name == "sha256"
    assert captured["oaep_label"] is None
    assert captured["enable_segmented_encryption"] is False
    assert captured["ciphertext"] == ciphertext


@pytest.mark.parametrize(
    ("mode", "expected_padding"),
    [
        (CryptoMode.CBC, "PKCS7"),
        (CryptoMode.CTR, "NONE"),
    ],
)
def test_aes_decrypt_passes_mode_and_padding_to_bkcrypto(
    monkeypatch: pytest.MonkeyPatch,
    mode: CryptoMode,
    expected_padding: str,
) -> None:
    from bk_kms import _crypto as backend

    captured: dict[str, object] = {}

    class FakeAES:
        def __init__(self, key: bytes, **options: object) -> None:
            captured["key"] = key
            captured.update(options)

        def decrypt_bytes(self, ciphertext: str) -> bytes:
            captured["ciphertext"] = ciphertext
            return b"plaintext"

    monkeypatch.setattr(backend, "AESSymmetricCipher", FakeAES)
    raw = b"\x00" * 16 + (b"\x00" * 16 if mode is CryptoMode.CBC else b"payload")
    ciphertext = base64.b64encode(raw).decode("ascii")

    assert backend.decrypt_aes(ciphertext, b"0123456789abcdef", mode) == b"plaintext"
    assert captured["mode"].value == mode.value
    assert captured["padding"].value == expected_padding
    assert captured["enable_iv"] is True
    assert captured["iv_size"] == 16
    assert captured["enable_aad"] is False
    assert captured["ciphertext"] == ciphertext


def test_aes_rejects_ignored_non_base64_character_before_bkcrypto() -> None:
    valid = base64.b64encode(b"\x00" * 16 + b"payload").decode("ascii")
    malformed = valid[:8] + "!" + valid[8:]

    with pytest.raises(CryptoError, match="base64"):
        decrypt_symmetric(malformed, SymmetricType.AES, CryptoMode.CTR, b"0123456789abcdef")
