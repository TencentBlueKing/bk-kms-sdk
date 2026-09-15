# BlueKing KMS Python SDK

提供信封的本地解密功能，支持 Python `>=3.11,<3.15`。

## 安装

```bash
pip install bk-kms-sdk
```

需要 SM2/SM4 国密算法时安装：

```bash
pip install "bk-kms-sdk[gm]"
```

国密依赖兼容平台的 Tongsuo 后端；RSA/AES 无需安装国密依赖。

## 解密

```python
import os
from pathlib import Path

from bk_kms import decrypt

plaintext = decrypt(
    envelope=Path("envelope.txt").read_text(encoding="utf-8").strip(),
    private_key=os.environ["BK_KMS_PRIVATE_KEY"].strip(),
)
```

`envelope.txt` 保存 Base64 编码的信封；环境变量 `BK_KMS_PRIVATE_KEY` 保存配套的 Base64 编码 PEM 私钥内容，不是私钥文件路径。

`decrypt(envelope, private_key)` 返回原始 UTF-8 明文字符串。信封中的算法字段决定使用 RSA/SM2、AES/SM4 和 CBC/CTR，无需额外配置。

如果录入的内容是 JSON，由应用解析并读取所需字段：

```python
import json

credentials = json.loads(plaintext)
```

应用负责获取信封和配套私钥、管理配置及使用明文。完整示例见 [examples/decrypt.py](examples/decrypt.py)。

## 错误处理

- `EnvelopeDecodeError`：参数为空或类型错误、信封格式或算法不支持、私钥不匹配、解密失败，或明文不是 UTF-8。
- `CryptoBackendUnavailableError`：国密后端不可用；安装兼容平台的 `bk-kms-sdk[gm]`。
- `CryptoError`：以上解密错误的公共基类。

请勿记录私钥、明文或完整信封。
