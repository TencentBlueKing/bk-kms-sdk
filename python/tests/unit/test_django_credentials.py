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

from collections.abc import Mapping, Sequence
from typing import Any, Optional

import pytest
from django.core.exceptions import ImproperlyConfigured

from bk_kms import (
    AuthInfo,
    ConfigurationError,
    ConsumeResult,
    Credential,
    CredentialType,
    CryptoBackendUnavailableError,
    CryptoInfo,
    KMSRequestError,
)
from bk_kms.django import CredentialStore, load_credentials
from bk_kms.django import credentials as credentials_module


def _credential(
    credential_type: CredentialType,
    *,
    name: str = "service-credential",
    username: str = "",
    password: str = "",
    secret_key: str = "",
    app_id: str = "",
) -> Credential:
    return Credential(
        name=name,
        type=credential_type,
        auth_info=AuthInfo(
            username=username,
            password=password,
            secret_key=secret_key,
            app_id=app_id,
        ),
    )


def _result(credential_id: int, credential: Credential) -> ConsumeResult:
    return ConsumeResult(
        credential_id=credential_id,
        err_code=0,
        err_msg="",
        credential=credential,
    )


def _config(credentials: Mapping[str, Mapping[str, object]]) -> dict[str, object]:
    return {
        "BASE_URL": "https://example.com/api/bk-kms/prod",
        "APP_CODE": "app-code",
        "APP_SECRET": "app-secret",
        "ACCESS_KEY": "access-key",
        "SECRET_KEY": "secret-key",
        "TENANT_ID": "tenant-a",
        "TIMEOUT": 5,
        "CREDENTIALS": credentials,
    }


def _install_fake_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    results: Optional[Sequence[ConsumeResult]] = None,
    error: Optional[Exception] = None,
) -> dict[str, Any]:
    calls: dict[str, Any] = {}

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            calls["client"] = kwargs

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
            calls["closed"] = True

        def consume_credential(self, **kwargs: object) -> list[ConsumeResult]:
            calls["consume"] = kwargs
            if error is not None:
                raise error
            return list(results or ())

    monkeypatch.setattr(credentials_module, "Client", FakeClient)
    return calls


def test_load_credentials_batches_names_and_exposes_typed_projections(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _credential(CredentialType.USERNAME_PASSWORD, username="db-user", password="db-password")
    redis = _credential(name="redis", credential_type=CredentialType.SINGLE_PASSWORD, password="redis-password")
    rabbitmq = _credential(
        name="rabbitmq",
        credential_type=CredentialType.USERNAME_PASSWORD,
        username="rabbit-user",
        password="rabbit-password",
    )
    elasticsearch = _credential(
        name="elasticsearch",
        credential_type=CredentialType.USERNAME_PASSWORD,
        username="es-user",
        password="es-password",
    )
    api = _credential(name="api", credential_type=CredentialType.SINGLE_SECRET_KEY, secret_key="api-secret")
    calls = _install_fake_client(
        monkeypatch,
        results=[
            _result(104, elasticsearch),
            _result(102, redis),
            _result(105, api),
            _result(101, db),
            _result(103, rabbitmq),
        ],
    )

    store = load_credentials(
        _config(
            {
                "database": {"NAME": "service-credential", "TYPE": "username_password"},
                "redis": {"NAME": "redis", "TYPE": CredentialType.SINGLE_PASSWORD},
                "rabbitmq": {"NAME": "rabbitmq", "TYPE": "username_password"},
                "elasticsearch": {"NAME": "elasticsearch", "TYPE": "username_password"},
                "api": {"NAME": "api", "TYPE": "single_secret_key"},
                "database_replica": {"NAME": "service-credential", "TYPE": "username_password"},
            }
        )
    )

    assert isinstance(store, CredentialStore)
    assert len(store) == 6
    assert store["database"] is db
    assert store.database("database") == {"USER": "db-user", "PASSWORD": "db-password"}
    assert store.database("database_replica") == {"USER": "db-user", "PASSWORD": "db-password"}
    assert store.password("redis") == "redis-password"
    assert store.username_password("rabbitmq") == ("rabbit-user", "rabbit-password")
    assert store.username_password("elasticsearch") == ("es-user", "es-password")
    assert store.secret_key("api") == "api-secret"
    assert calls["client"] == {
        "base_url": "https://example.com/api/bk-kms/prod",
        "direct": True,
        "app_code": "app-code",
        "app_secret": "app-secret",
        "timeout": 5.0,
        "tenant_id": "tenant-a",
    }
    assert calls["consume"] == {
        "access_key": "access-key",
        "secret_key": "secret-key",
        "credential_names": ["service-credential", "redis", "rabbitmq", "elasticsearch", "api"],
        "crypto": None,
    }
    assert calls["closed"] is True
    assert "db-password" not in repr(store)
    assert "redis-password" not in repr(store)
    assert "database" in repr(store)


def test_store_exposes_app_id_secret_key_projection() -> None:
    store = CredentialStore(
        {
            "service": _credential(
                CredentialType.APP_ID_SECRET_KEY,
                app_id="app-id",
                secret_key="app-secret",
            )
        }
    )

    assert store.app_id_secret_key("service") == ("app-id", "app-secret")


def test_store_missing_alias_follows_mapping_contract() -> None:
    store = CredentialStore({"service": _credential(CredentialType.SINGLE_PASSWORD, password="secret")})

    assert "missing" not in store
    assert store.get("missing") is None
    with pytest.raises(KeyError, match="missing"):
        store["missing"]


def test_typed_projection_reports_missing_alias_as_configuration_error() -> None:
    store = CredentialStore({"service": _credential(CredentialType.SINGLE_PASSWORD, password="secret")})

    with pytest.raises(ImproperlyConfigured, match="Unknown.*missing"):
        store.password("missing")


def test_load_credentials_passes_crypto_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = _credential(CredentialType.SINGLE_PASSWORD, password="secret")
    calls = _install_fake_client(monkeypatch, results=[_result(101, credential)])
    config = _config({"service": {"NAME": "service-credential", "TYPE": "single_password"}})
    crypto = CryptoInfo.sm2_sm4_cbc()
    config["CRYPTO"] = crypto

    load_credentials(config)

    assert calls["consume"]["crypto"] is crypto


def test_load_credentials_uses_bootstrap_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = _credential(CredentialType.SINGLE_PASSWORD, password="secret")
    calls = _install_fake_client(monkeypatch, results=[_result(101, credential)])
    config = _config({"service": {"NAME": "service-credential", "TYPE": "single_password"}})
    del config["TIMEOUT"]
    del config["TENANT_ID"]

    load_credentials(config)

    assert calls["client"]["timeout"] == 5.0
    assert calls["client"]["tenant_id"] == ""


def test_load_credentials_defaults_to_direct_mode_without_app_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = _credential(CredentialType.SINGLE_PASSWORD, password="secret")
    calls = _install_fake_client(monkeypatch, results=[_result(101, credential)])
    config = _config({"service": {"NAME": "service-credential", "TYPE": "single_password"}})
    del config["APP_SECRET"]

    load_credentials(config)

    assert calls["client"]["direct"] is True
    assert calls["client"]["app_code"] == "app-code"
    assert calls["client"]["app_secret"] is None


def test_store_rejects_projection_for_wrong_credential_type() -> None:
    store = CredentialStore(
        {
            "database": _credential(CredentialType.SINGLE_PASSWORD, password="secret"),
        }
    )

    with pytest.raises(ImproperlyConfigured, match="database.*username_password"):
        store.database("database")


@pytest.mark.parametrize(
    ("results", "message"),
    [
        ([], "missing"),
        (
            [ConsumeResult(101, 1034008, "denied", None)],
            "err_code=1034008, err_msg='denied'",
        ),
        ([_result(101, _credential(CredentialType.SINGLE_PASSWORD, password="pass"))], "expected username_password"),
    ],
)
def test_load_credentials_rejects_invalid_kms_results(
    monkeypatch: pytest.MonkeyPatch,
    results: Sequence[ConsumeResult],
    message: str,
) -> None:
    _install_fake_client(monkeypatch, results=results)

    with pytest.raises(ImproperlyConfigured, match=message):
        load_credentials(_config({"database": {"NAME": "service-credential", "TYPE": "username_password"}}))


def test_load_credentials_wraps_kms_failures_without_repeating_service_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_client(
        monkeypatch,
        error=KMSRequestError(
            "service supplied detail",
            status_code=503,
            code=1034000,
            request_id="request-id",
        ),
    )

    with pytest.raises(ImproperlyConfigured) as exc_info:
        load_credentials(_config({"database": {"NAME": "service-credential", "TYPE": "username_password"}}))

    assert str(exc_info.value) == "Unable to load BK-KMS credentials"
    assert "service supplied detail" not in str(exc_info.value)


def test_load_credentials_preserves_actionable_missing_gm_error(monkeypatch: pytest.MonkeyPatch) -> None:
    error = CryptoBackendUnavailableError(
        backend="bkcrypto",
        algorithms=("SM2", "SM4"),
        platform="linux",
    )
    _install_fake_client(monkeypatch, error=error)

    with pytest.raises(ImproperlyConfigured, match=r"Install bk-kms-sdk\[gm\]") as exc_info:
        load_credentials(_config({"database": {"NAME": "service-credential", "TYPE": "username_password"}}))

    assert exc_info.value.__cause__ is error


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("APP_CODE", None, "app_code cannot be empty"),
        ("APP_SECRET", "", "app_secret cannot be empty in gateway mode"),
    ],
)
def test_load_credentials_preserves_client_configuration_error(key: str, value: object, message: str) -> None:
    config = _config({"service": {"NAME": "service-credential", "TYPE": "single_password"}})
    config["DIRECT"] = False
    if value is None:
        del config[key]
    else:
        config[key] = value

    with pytest.raises(ImproperlyConfigured) as exc_info:
        load_credentials(config)

    assert str(exc_info.value) == message
    assert isinstance(exc_info.value.__cause__, ConfigurationError)


@pytest.mark.parametrize(
    ("bindings", "message"),
    [
        ({}, "CREDENTIALS"),
        ({"database": {"NAME": True, "TYPE": "username_password"}}, "non-empty string"),
        ({"database": {"NAME": "service-credential", "TYPE": "future_type"}}, "TYPE"),
        (
            {
                "database": {"NAME": "service-credential", "TYPE": "username_password"},
                "redis": {"NAME": "service-credential", "TYPE": "single_password"},
            },
            "conflicting types",
        ),
    ],
)
def test_load_credentials_validates_binding_configuration(
    monkeypatch: pytest.MonkeyPatch,
    bindings: Mapping[str, Mapping[str, object]],
    message: str,
) -> None:
    calls = _install_fake_client(monkeypatch)

    with pytest.raises(ImproperlyConfigured, match=message):
        load_credentials(_config(bindings))

    assert "client" not in calls


@pytest.mark.parametrize(
    "names, message", [(["other"], "unexpected"), (["service-credential", "service-credential"], "duplicate")]
)
def test_load_credentials_rejects_ambiguous_names(
    monkeypatch: pytest.MonkeyPatch, names: list[str], message: str
) -> None:
    results = [
        _result(index, _credential(CredentialType.SINGLE_PASSWORD, name=name, password="secret"))
        for index, name in enumerate(names)
    ]
    _install_fake_client(monkeypatch, results=results)
    with pytest.raises(ImproperlyConfigured, match=message):
        load_credentials(_config({"service": {"NAME": "service-credential", "TYPE": "single_password"}}))


@pytest.mark.parametrize("name", ["\ud800", "\udc00"])
def test_load_credentials_rejects_invalid_unicode_names_before_request(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    calls = _install_fake_client(monkeypatch)
    with pytest.raises(ImproperlyConfigured, match="valid Unicode"):
        load_credentials(_config({"service": {"NAME": name, "TYPE": "single_password"}}))
    assert "client" not in calls


@pytest.mark.parametrize("app_code", [None, "", "   "])
def test_direct_mode_requires_app_code(app_code: str | None) -> None:
    config = _config({"service": {"NAME": "service-credential", "TYPE": "single_password"}})
    del config["APP_SECRET"]
    if app_code is None:
        del config["APP_CODE"]
    else:
        config["APP_CODE"] = app_code
    with pytest.raises(ImproperlyConfigured, match="app_code"):
        load_credentials(config)


def test_load_credentials_rejects_invalid_tenant_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _install_fake_client(monkeypatch)
    config = _config({"service": {"NAME": "service-credential", "TYPE": "single_password"}})
    config["TENANT_ID"] = 123
    with pytest.raises(ImproperlyConfigured, match="TENANT_ID"):
        load_credentials(config)
    assert calls == {}
