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

"""Fetch an encrypted envelope now and decrypt it later in the same trust boundary."""

from bk_kms import Client, decrypt_envelope


def main() -> None:
    """Demonstrate the deferred-decryption API."""

    with Client(
        base_url="http://kms.service:23681",
        app_code="your-app-code",
    ) as client:
        envelope = client.consume_credential_envelope(
            access_key="your-access-key",
            secret_key="your-secret-key",
            credential_names=["database", "redis"],
        )

    # The envelope and private key together can recover plaintext credentials.
    results = decrypt_envelope(envelope)
    for result in results:
        print(result.credential_id, result.ok)


if __name__ == "__main__":
    main()
