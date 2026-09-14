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

"""Read an envelope from a file and its private key from the environment."""

import os
from pathlib import Path

from bk_kms import decrypt


def main() -> None:
    envelope = Path("envelope.txt").read_text(encoding="utf-8").strip()
    private_key = os.environ["BK_KMS_PRIVATE_KEY"].strip()
    plaintext = decrypt(envelope, private_key)
    # Pass plaintext to the application; do not log it.
    del plaintext


if __name__ == "__main__":
    main()
