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

import ast
from pathlib import Path

PACKAGE_DIR = Path(__file__).parents[2] / "src" / "bk_kms"


def test_production_crypto_imports_no_cryptography_cipher_primitives() -> None:
    forbidden: list[str] = []
    for source_file in PACKAGE_DIR.rglob("*.py"):
        tree = ast.parse(source_file.read_text(encoding="utf-8"), filename=str(source_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("cryptography"):
                        forbidden.append(f"{source_file.name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("cryptography"):
                imported_names = {alias.name for alias in node.names}
                if node.module == "cryptography.hazmat.primitives" and imported_names == {"hashes"}:
                    continue
                forbidden.append(f"{source_file.name}: from {node.module} import {sorted(imported_names)}")

    assert forbidden == []
