# BK-KMS-SDK Node.js 版本

运行时解密还原凭证明文，信封格式由 KMS 服务约定，调用方无需关心。

## 运行环境

- Node.js `>=20`
- RSA、AES、SM4 使用 `node:crypto`；SM2 使用 [sm-crypto-v2](https://github.com/Cubelrti/sm-crypto-v2)（基于 `@noble/curves`），不依赖 Node.js 所带 OpenSSL 的 SM2 实现
- SM4 依赖 Node.js 所带 OpenSSL；官方发行版均支持。若使用裁剪过国密算法的自定义构建，将抛出 `ALGORITHM_UNAVAILABLE`

## 安装

```bash
npm install @blueking/bk-kms-sdk
```

## 解密

```js
const fs = require('node:fs');
const { decrypt } = require('@blueking/bk-kms-sdk');

const plaintext = decrypt(
  fs.readFileSync('envelope.txt', 'utf8').trim(),
  process.env.BK_KMS_PRIVATE_KEY.trim(),
);
```

`envelope.txt` 保存 Base64 编码的信封；环境变量 `BK_KMS_PRIVATE_KEY` 保存配套的 Base64 编码 PEM 私钥内容，不是私钥文件路径。

`decrypt(envelope, privateKey)` 同步返回原始 UTF-8 明文字符串。信封中的算法字段决定使用 RSA/SM2、AES/SM4 和 CBC/CTR。如果录入的内容是 JSON，由应用自行 `JSON.parse(plaintext)`。

ESM 与 TypeScript 均可直接使用：`import { decrypt } from '@blueking/bk-kms-sdk'`（自带类型声明）。

完整示例见 [examples/decrypt.js](examples/decrypt.js)。

## 支持的格式

- RSA：OAEP SHA-256（MGF1-SHA-256，无 label），私钥为 PKCS#8 或 PKCS#1 PEM
- SM2：ASN.1 密文（C1C3C2），私钥为 PKCS#8 PEM
- AES-128 / SM4：密文为 Base64(`IV[16] || ciphertext`)；CBC 使用 PKCS#7 填充，CTR 无填充且至少 1 字节（与 Go 一致）

## 错误处理

所有错误均为 `KmsError`，通过 `err.code` 区分：

| code | 含义 |
| --- | --- |
| `INVALID_ARGUMENT` | 参数为空或不是字符串 |
| `INVALID_ENVELOPE` | 信封不是 Base64 JSON 对象，或缺少必填字段 |
| `UNSUPPORTED_ALGORITHM` | 信封中的算法/模式不支持 |
| `ALGORITHM_UNAVAILABLE` | 当前 Node.js 的 OpenSSL 不支持国密算法 |
| `INVALID_PRIVATE_KEY` | 私钥无法解析，或与信封的非对称算法不符 |
| `DECRYPT_FAILED` | 私钥不匹配、数据损坏或填充错误 |
| `INVALID_PLAINTEXT` | 明文不是合法 UTF-8 |

错误信息不会包含私钥、数据密钥、信封或明文。请勿记录私钥、明文或完整信封。

## 开发

```bash
npm test
```

测试覆盖 8 种 RSA/SM2 × AES/SM4 × CBC/CTR 向量、二进制数据密钥、RSA/AES/SM4 往返加解密及各类异常输入。`test/fixtures` 中的密钥仅用于测试，来源见 [fixtures 说明](test/fixtures/README.md)。

## License

项目基于 MIT 协议，详细请参考 [LICENSE](../LICENSE)。
