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


@pytest.mark.parametrize(
    ("package_version", "expected"),
    [
        ("1.0.0", "v1.0.0"),
        ("1.0.0a1", "v1.0.0-alpha.1"),
        ("1.0.0b2", "v1.0.0-beta.2"),
        ("1.0.0rc3", "v1.0.0-rc.3"),
    ],
)
def test_format_sdk_version_supports_pep440_release_versions(package_version: str, expected: str) -> None:
    from bk_kms._version import _format_sdk_version

    assert _format_sdk_version(package_version) == expected
