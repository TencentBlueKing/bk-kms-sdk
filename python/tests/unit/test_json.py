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

from bk_kms._json import loads


def test_loads_rejects_utf8_bom_like_go_json() -> None:
    with pytest.raises(ValueError, match="BOM"):
        loads(b'\xef\xbb\xbf{"code":0}')


@pytest.mark.parametrize("raw", ['"\\ud800"', '"\\udc00"'])
def test_loads_replaces_lone_surrogates_like_go_json(raw: str) -> None:
    assert loads(raw) == "\ufffd"


def test_loads_preserves_valid_surrogate_pair() -> None:
    assert loads('"\\ud83d\\ude00"') == "😀"
