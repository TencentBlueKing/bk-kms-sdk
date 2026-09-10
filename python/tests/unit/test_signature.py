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
import uuid
from pathlib import Path

import pytest

from bk_kms import AsymmetricType, CryptoInfo, CryptoMode, SymmetricType
from bk_kms.exceptions import ValidationError
from bk_kms.signature import (
    build_authorization_header,
    build_consume_request,
    new_nonce,
    sign_request,
)

FIXTURE = json.loads((Path(__file__).parents[1] / "fixtures" / "protocol_vectors.json").read_text(encoding="utf-8"))[
    "consume_request"
]


def test_consume_request_matches_go_wire_bytes() -> None:
    body = build_consume_request(
        credential_names=FIXTURE["credential_names"],
        crypto=CryptoInfo(AsymmetricType.RSA, SymmetricType.AES, CryptoMode.CBC),
        public_key=FIXTURE["public_key"],
    )

    assert json.loads(body)["credential_id_list"] == []
    assert json.loads(body)["credential_name_list"] == FIXTURE["credential_names"]
    assert body == FIXTURE["body"].encode()


@pytest.mark.parametrize("names", [None, [], ()])
def test_empty_credential_names_are_encoded_as_empty_array(names: list[str] | tuple[str, ...] | None) -> None:
    body = build_consume_request(
        credential_names=names,
        crypto=CryptoInfo.rsa_aes_cbc(),
        public_key="public-key",
    )

    assert body.startswith(b'{"credential_id_list":[],"credential_name_list":[],"crypto":')


@pytest.mark.parametrize("credential_names", ["database", b"12", bytearray(b"12")])
def test_credential_names_reject_scalar_sequences(credential_names: object) -> None:
    with pytest.raises(ValidationError, match="sequence of strings"):
        build_consume_request(
            credential_names=credential_names,  # type: ignore[arg-type]
            crypto=CryptoInfo.rsa_aes_cbc(),
            public_key="public-key",
        )


@pytest.mark.parametrize("credential_names", [[1], [True], [None], ["database", 2]])
def test_credential_names_require_strings(credential_names: object) -> None:
    with pytest.raises(ValidationError, match="contain strings"):
        build_consume_request(
            credential_names=credential_names,  # type: ignore[arg-type]
            crypto=CryptoInfo.rsa_aes_cbc(),
            public_key="public-key",
        )


def test_signature_matches_cross_language_protocol_vector() -> None:
    body = build_consume_request(
        credential_names=FIXTURE["credential_names"],
        crypto=CryptoInfo.rsa_aes_cbc(),
        public_key=FIXTURE["public_key"],
    )

    assert (
        sign_request(
            secret_key=FIXTURE["secret_key"],
            nonce=FIXTURE["nonce"],
            timestamp=FIXTURE["timestamp"],
            content=body,
        )
        == FIXTURE["signature"]
    )


def test_authorization_header_uses_compact_json() -> None:
    assert build_authorization_header("app", "secret") == '{"bk_app_code":"app","bk_app_secret":"secret"}'


def test_authorization_header_matches_go_html_escaping() -> None:
    assert build_authorization_header("<应用>", "&secret\u2028") == (
        '{"bk_app_code":"\\u003c应用\\u003e","bk_app_secret":"\\u0026secret\\u2028"}'
    )


def test_nonce_is_uuid_v4_without_dashes() -> None:
    nonce = new_nonce()

    assert len(nonce) == 32
    assert str(uuid.UUID(nonce)).replace("-", "") == nonce


@pytest.mark.parametrize("name", ["\ud800", "\udc00"])
def test_credential_names_reject_invalid_unicode(name: str) -> None:
    with pytest.raises(ValidationError, match="valid Unicode"):
        build_consume_request(
            credential_names=[name],
            crypto=CryptoInfo.rsa_aes_cbc(),
            public_key="public-key",
        )
