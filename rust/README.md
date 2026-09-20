# BK-KMS-SDK Rust 版本

运行时解密还原凭证明文，信封格式由 KMS 服务约定，调用方无需关心。

## 运行环境

- Rust `>=1.85`（国密依赖 `sm2` 的最低要求）
- 纯 Rust 实现，无原生依赖：`RSA`、`AES`、`SM2`、`SM4` 在任意平台开箱可用，无需安装国密后端

## 安装

从 Git 引入，建议用 `rev` 锁定提交以保证构建可复现：

```toml
[dependencies]
bk-kms-sdk = { git = "https://github.com/TencentBlueKing/bk-kms-sdk", rev = "8c6571bddd86225a2fef6bbe94452db04162475e" }
```

本地开发可改用路径依赖：

```toml
[dependencies]
bk-kms-sdk = { path = "../bk-kms-sdk/rust" }
```

发布到 crates.io 后可直接声明版本：

```toml
[dependencies]
bk-kms-sdk = "1.0"
```

## 快速开始

```rust
use std::env;
use std::fs;

use bk_kms::decrypt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 读取配置：信封从当前目录的 envelope.txt 读取（KMS 下发的 Base64 字符串），
    //    私钥从环境变量读取（Base64(PEM) 内容本身，不是私钥文件路径）。
    let envelope = fs::read_to_string("envelope.txt")?;
    let private_key = env::var("BK_KMS_PRIVATE_KEY")?;

    // 2. 调用核心接口：没有客户端对象，也没有初始化步骤。
    let plaintext = decrypt(envelope.trim(), private_key.trim())?;

    // 3. 处理返回结果：明文结构由应用定义。示例按 JSON 格式化输出，
    //    不是 JSON 时原样输出，避免对明文结构做强假设。
    match serde_json::from_str::<serde_json::Value>(&plaintext) {
        Ok(value) => println!("解密成功：{value}"),
        Err(_) => println!("解密成功：{plaintext}"),
    }
    Ok(())
}
```

`decrypt(envelope, private_key)` 返回原始 UTF-8 明文字符串。信封中的算法字段决定使用 RSA/SM2、AES/SM4 和 CBC/CTR，无需额外配置。如果录入的内容是 JSON，由应用自行解析：

```rust
let credentials: serde_json::Value = serde_json::from_str(&plaintext)?;
```

## 如何在项目中使用

完整流程如下，可直接参考可运行示例 [`examples/consumer`](examples/consumer)。

**第 1 步：添加依赖。** 在目标项目的 `Cargo.toml` 中声明：

```toml
[dependencies]
bk-kms-sdk = { git = "https://github.com/TencentBlueKing/bk-kms-sdk", rev = "8c6571bddd86225a2fef6bbe94452db04162475e" }
serde_json = "1.0"   # 仅当明文是 JSON 时需要
```

**第 2 步：初始化。** SDK **没有客户端对象，也没有初始化步骤**：没有 `Client`、没有配置项、不发网络请求、不持有全局状态。`use bk_kms::decrypt;` 之后即可调用。

**第 3 步：准备入参。** 信封是 KMS 下发的 Base64 字符串（示例存放在文件里）；私钥必须是 **Base64(PEM)** 形式的内容：

```rust
let envelope = std::fs::read_to_string("envelope.txt")?;
let private_key = std::env::var("BK_KMS_PRIVATE_KEY")?;
```

**第 4 步：调用核心接口。**

```rust
let plaintext = bk_kms::decrypt(envelope.trim(), &private_key)?;
```

**第 5 步：处理返回结果与错误。**

```rust
use bk_kms::Error;

match bk_kms::decrypt(envelope.trim(), &private_key) {
    Ok(plaintext) => {
        let credentials: serde_json::Value = serde_json::from_str(&plaintext)?;
        // 交给业务使用，不要打印或落盘
        let _ = credentials;
    }
    Err(Error::EmptyEnvelope | Error::EmptyPrivateKey) => {
        eprintln!("配置缺失：信封或私钥为空");
    }
    Err(err @ (Error::EnvelopeBase64(_)
    | Error::EnvelopeJson(_)
    | Error::EnvelopeField { .. }
    | Error::UnsupportedAlgorithm { .. })) => {
        eprintln!("信封不可用: {err}");
    }
    Err(Error::PrivateKey { .. } | Error::Ciphertext { .. }) => {
        eprintln!("解密失败：私钥与信封不匹配，或数据已损坏");
    }
    Err(Error::PlaintextUtf8(_)) => {
        eprintln!("明文不是合法 UTF-8 文本");
    }
    Err(other) => {
        eprintln!("未预期的失败: {other}");
    }
}
```

运行 `examples/consumer`（信封放在 `examples/consumer/envelope.txt`，私钥内容通过环境变量传入）：

```bash
cd examples/consumer
# 把 KMS 下发的 Base64 信封写入 envelope.txt
export BK_KMS_PRIVATE_KEY='<base64(PEM) 私钥内容>'
cargo run
```

Windows PowerShell 把 `export X='...'` 换成 `$env:X = '...'`。

## 信封格式

信封是标准 Base64 编码的 JSON 对象，字段值**大小写敏感**：

| 字段 | 取值 | 说明 |
| --- | --- | --- |
| `asymmetric_type` | `RSA` \| `SM2` | 用于包裹对称密钥 |
| `symmetric_type` | `AES` \| `SM4` | 用于加密业务数据 |
| `symmetric_mode` | `CBC` \| `CTR` | 对称加密模式 |
| `encrypted_key` | Base64 | 被非对称公钥加密后的 16 字节对称密钥 |
| `ciphertext` | Base64 | `IV[16] \|\| 密文`，CBC 带 PKCS#7 填充 |

私钥是标准 Base64 编码的 PEM 文本，RSA 支持 PKCS#8 与 PKCS#1，SM2 要求 PKCS#8。

## API

### `bk_kms::decrypt`

```rust
pub fn decrypt(envelope: &str, private_key: &str) -> Result<String, Error>
```

解密凭据信封，返回原始 UTF-8 明文。函数无 I/O、无状态，可安全地在多线程中并发调用。

### `bk_kms::Error`

| 变体 | 含义 |
| --- | --- |
| `EmptyEnvelope` / `EmptyPrivateKey` | 入参为空字符串 |
| `EnvelopeBase64` | 信封不是合法 Base64 |
| `EnvelopeJson` | 信封解码后不是 JSON 对象 |
| `EnvelopeField` | 信封字段缺失、非字符串或为空 |
| `UnsupportedAlgorithm` | 信封中的算法标识不受支持 |
| `PrivateKey` | 私钥无法解码 |
| `Ciphertext` | 解密失败：密钥不匹配、数据损坏、填充非法等 |
| `PlaintextUtf8` | 明文不是合法 UTF-8 |

错误类型实现了 `std::error::Error`，可用 `source()` 取得底层原因；`Error` 与 `Result` 均满足 `Send + Sync`，可跨线程传播。错误信息**不会**包含私钥、信封、数据密钥或明文。

### `bk_kms::Result`

`Result<T, E = Error>` 的便捷别名。

## 算法支持

| 角色 | 算法 | 实现细节 |
| --- | --- | --- |
| 非对称 | `RSA` | OAEP + SHA-256 / MGF1-SHA-256，无 label |
| 非对称 | `SM2` | ASN.1 密文（`SEQUENCE { x, y, c3, c2 }`） |
| 对称 | `AES` | 128 位密钥，CBC（PKCS#7）/ CTR |
| 对称 | `SM4` | 128 位密钥，CBC（PKCS#7）/ CTR |

八种组合（`RSA`/`SM2` × `AES`/`SM4` × `CBC`/`CTR`）全部支持，并与 Go、Python、C++ SDK 使用同一信封格式。

## 示例

- [`examples/decrypt.rs`](examples/decrypt.rs)：单文件端到端示例，`cargo run --example decrypt` 可直接运行（未配置环境变量时使用内置测试向量）。
- [`examples/consumer/`](examples/consumer)：独立 crate，演示在其他项目中引入依赖、从文件读取信封（私钥走环境变量）、调用接口与处理错误的完整流程。


## 安全注意事项

- 不要记录私钥、明文或完整信封。本 SDK 产生的错误信息不会包含它们。
- 解密得到的 `String` 无法可靠地擦除，请缩短其生命周期，避免复制到长期存活的结构中。
- SDK 不做缓存：每次调用都会重新解析私钥。同一凭据反复使用时，请在业务侧缓存明文。
- 应用负责获取信封与配套私钥、管理配置及使用明文。

## License

项目基于 MIT 协议，详细请参考 [LICENSE](../LICENSE)。
