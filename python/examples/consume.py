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

"""Consume and decrypt credentials directly from an internal BK-KMS service."""

from bk_kms import Client


def main() -> None:
    """Fetch a batch and inspect each per-credential outcome."""

    with Client(
        base_url="http://kms.service:23681",
        app_code="your-app-code",
    ) as client:
        results = client.consume_credential(
            access_key="your-access-key",
            secret_key="your-secret-key",
            credential_names=["database", "redis"],
        )

    for result in results:
        if not result.ok:
            print(f"credential {result.credential_id}: code={result.err_code} message={result.err_msg}")
            continue

        # Authentication fields are intentionally not printed; treat them as secrets.
        credential = result.credential
        if credential is not None:
            print(f"credential {result.credential_id}: name={credential.name} type={credential.type}")


if __name__ == "__main__":
    main()
