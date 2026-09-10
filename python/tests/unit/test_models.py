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

import pytest

from bk_kms import (
    AsymmetricType,
    AuthInfo,
    ConsumeEnvelope,
    ConsumeResult,
    Credential,
    CredentialType,
    CryptoInfo,
    CryptoMode,
    SymmetricType,
    ValidationError,
)


def test_default_crypto_matches_go_sdk() -> None:
    assert CryptoInfo.rsa_aes_cbc() == CryptoInfo(
        asymmetric_type=AsymmetricType.RSA,
        symmetric_type=SymmetricType.AES,
        symmetric_mode=CryptoMode.CBC,
    )


def test_crypto_info_rejects_algorithm_in_wrong_role() -> None:
    with pytest.raises(ValidationError, match="asymmetric"):
        CryptoInfo(SymmetricType.AES, SymmetricType.AES, CryptoMode.CBC)  # type: ignore[arg-type]

    with pytest.raises(ValidationError, match="symmetric"):
        CryptoInfo(AsymmetricType.RSA, AsymmetricType.RSA, CryptoMode.CBC)  # type: ignore[arg-type]


def test_crypto_info_rejects_raw_strings_during_construction() -> None:
    with pytest.raises(ValidationError, match="asymmetric"):
        CryptoInfo("RSA", SymmetricType.AES, CryptoMode.CBC)  # type: ignore[arg-type]


def test_consume_result_exposes_per_credential_status() -> None:
    successful = ConsumeResult(
        credential_id=1,
        err_code=0,
        err_msg="",
        credential=Credential(
            name="demo",
            type=CredentialType.SINGLE_PASSWORD,
            auth_info=AuthInfo(password="secret"),
            annotation="test",
        ),
    )
    failed = ConsumeResult(credential_id=2, err_code=1034003, err_msg="not found", credential=None)

    assert successful.ok
    assert not failed.ok


def test_unknown_credential_type_is_preserved() -> None:
    credential = Credential.from_wire(
        {
            "name": "future",
            "type": "future_type",
            "auth_info": {},
            "annotation": "",
        }
    )

    assert credential.type == "future_type"


def test_string_enums_render_as_wire_values() -> None:
    assert str(AsymmetricType.RSA) == "RSA"
    assert str(SymmetricType.AES) == "AES"
    assert str(CryptoMode.CBC) == "CBC"
    assert str(CredentialType.SINGLE_PASSWORD) == "single_password"


def test_sensitive_model_fields_are_hidden_from_repr() -> None:
    auth_info = AuthInfo(
        password="password-value",
        username="username-value",
        secret_key="secret-value",
        app_id="app-id-value",
    )
    envelope = ConsumeEnvelope(envelope="envelope-value", private_key="private-value")

    assert "password-value" not in repr(auth_info)
    assert "username-value" not in repr(auth_info)
    assert "secret-value" not in repr(auth_info)
    assert "app-id-value" not in repr(auth_info)
    assert "envelope-value" not in repr(envelope)
    assert "private-value" not in repr(envelope)


def test_wire_models_reject_present_fields_with_wrong_types() -> None:
    with pytest.raises(ValidationError, match="err_code"):
        ConsumeResult.from_wire(
            {
                "credential_id": 1,
                "err_code": "0",
                "err_msg": "",
            }
        )

    with pytest.raises(ValidationError, match="auth_info"):
        Credential.from_wire(
            {
                "name": "demo",
                "type": "single_password",
                "auth_info": "not-an-object",
            }
        )

    with pytest.raises(ValidationError, match="32-bit"):
        ConsumeResult.from_wire(
            {
                "credential_id": 1,
                "err_code": 2**31,
                "err_msg": "",
            }
        )

    with pytest.raises(ValidationError, match="64-bit"):
        ConsumeResult.from_wire(
            {
                "credential_id": 2**63,
                "err_code": 0,
                "err_msg": "",
            }
        )


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({}, "credential_id"),
        ({"credential_id": 1}, "err_code"),
        ({"credential_id": 1, "err_code": None}, "err_code"),
    ],
)
def test_consume_result_requires_protocol_fields(payload: dict[str, object], field: str) -> None:
    with pytest.raises(ValidationError, match=field):
        ConsumeResult.from_wire(payload)


def test_successful_consume_result_requires_a_credential() -> None:
    with pytest.raises(ValidationError, match="credential"):
        ConsumeResult.from_wire({"credential_id": 1, "err_code": 0, "err_msg": ""})


@pytest.mark.parametrize("field", ["name", "type", "auth_info"])
def test_credential_requires_protocol_fields(field: str) -> None:
    payload: dict[str, object] = {
        "name": "demo",
        "type": "single_password",
        "auth_info": {"password": "secret"},
    }
    del payload[field]

    with pytest.raises(ValidationError, match=field):
        Credential.from_wire(payload)


def test_known_credential_type_requires_its_auth_fields() -> None:
    with pytest.raises(ValidationError, match="password"):
        Credential.from_wire(
            {
                "name": "demo",
                "type": "single_password",
                "auth_info": {},
            }
        )


def test_auth_info_uses_none_for_absent_fields() -> None:
    auth_info = AuthInfo.from_wire({"password": "secret"})

    assert auth_info.password == "secret"
    assert auth_info.username is None
    assert auth_info.secret_key is None
    assert auth_info.app_id is None


def test_known_credential_constructor_rejects_missing_auth_fields() -> None:
    with pytest.raises(ValidationError, match="password"):
        Credential(
            name="demo",
            type=CredentialType.SINGLE_PASSWORD,
            auth_info=AuthInfo(),
        )


def test_credential_constructor_normalizes_known_type_strings() -> None:
    credential = Credential(
        name="demo",
        type="single_password",
        auth_info=AuthInfo(password="secret"),
    )

    assert credential.type is CredentialType.SINGLE_PASSWORD


def test_known_credential_string_constructor_rejects_missing_auth_fields() -> None:
    with pytest.raises(ValidationError, match="username"):
        Credential(
            name="demo",
            type="username_password",
            auth_info=AuthInfo(),
        )


def test_known_credential_constructor_rejects_unexpected_auth_fields() -> None:
    with pytest.raises(ValidationError, match="secret_key"):
        Credential(
            name="demo",
            type=CredentialType.SINGLE_PASSWORD,
            auth_info=AuthInfo(password="secret", secret_key="unexpected"),
        )


def test_successful_consume_result_constructor_requires_a_credential() -> None:
    with pytest.raises(ValidationError, match="credential"):
        ConsumeResult(credential_id=1, err_code=0, err_msg="", credential=None)
