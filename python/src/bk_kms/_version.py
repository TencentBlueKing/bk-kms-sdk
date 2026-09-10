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

"""Package version and its wire-header representation."""

import re

__version__ = "1.0.0a1"


def _format_sdk_version(package_version: str) -> str:
    """Translate a PEP 440 version into the Go/C++ SDK header spelling."""

    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:(a|b|rc)(\d+))?", package_version)
    if match is None:
        raise ValueError(f"unsupported package version: {package_version}")

    release, label, number = match.groups()
    if label is None:
        return f"v{release}"
    prerelease = {"a": "alpha", "b": "beta", "rc": "rc"}[label]
    return f"v{release}-{prerelease}.{number}"


SDK_VERSION = _format_sdk_version(__version__)
