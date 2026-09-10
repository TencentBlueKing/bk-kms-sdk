# BK-KMS Python SDK 设计与协议

本文面向 SDK 维护者，描述当前 Python 实现的模块职责、协议约束和验证边界。维护规则见 [AGENTS.md](../AGENTS.md)。普通开发者的安装与调用示例见 [Python SDK README](../README.md)，settings 配置见 [Django 集成](django.md)，固定向量来源见 [fixtures 说明](../tests/fixtures/README.md)。

## 范围与依赖

SDK 提供同步 `Client`，支持直连 KMS、API 网关、按名称消费凭证、获取密文信封及延迟本地解密。Django 集成在 settings 导入时批量加载凭据。当前没有异步客户端、凭证管理接口、本地缓存、后台刷新或通用网络重试。

[pyproject.toml](../pyproject.toml) 定义安装约束：

| 项目 | 当前配置 |
| --- | --- |
| Python | `>=3.11,<3.15` |
| 包名 / 导入名 | `bk-kms-sdk` / `bk_kms` |
| HTTP | `httpx2>=2.12,<3` |
| 密码后端 | `bk-crypto-python-sdk==4.1.1` |
| `gm` extra | `bk-crypto-python-sdk[gm]==4.1.1` |
| `django` extra | `Django>=4.2,<6` |
| 打包 | `setuptools.build_meta`，`src/` 布局，包含 `py.typed` |

RSA/AES 使用 bkcrypto 的基础后端；SM2/SM4 按需加载可选 Tongsuo 后端。缺少或无法加载国密后端时，RSA/AES 路径仍可使用；选择 SM2/SM4 会抛出 `CryptoBackendUnavailableError`，不会自动改用其他算法。

## 模块职责

| 模块 | 职责 |
| --- | --- |
| [client.py](../src/bk_kms/client.py) | 参数校验、HTTP 生命周期、请求编排、租户头、响应解析及校时重试 |
| [signature.py](../src/bk_kms/signature.py) | 有序请求体、nonce、授权头和两阶段 HMAC 签名 |
| [_json.py](../src/bk_kms/_json.py) | 统一的线协议 JSON 编解码 |
| [models.py](../src/bk_kms/models.py) | Enum、不可变 dataclass、线协议字段校验与错误码 |
| [exceptions.py](../src/bk_kms/exceptions.py) | 公开异常层次 |
| [envelope.py](../src/bk_kms/envelope.py) | 信封解析、解密编排及凭证结果反序列化 |
| [crypto/_dispatch.py](../src/bk_kms/crypto/_dispatch.py) | 按算法 Enum 分派到固定密码函数 |
| [crypto/base.py](../src/bk_kms/crypto/base.py) | 请求级 `KeyPair` 数据模型 |
| [crypto/bkcrypto.py](../src/bk_kms/crypto/bkcrypto.py) | bkcrypto 适配、严格格式校验、国密延迟加载及异常转换 |
| [django/credentials.py](../src/bk_kms/django/credentials.py) | settings 启动校验、批量加载及 `CredentialStore` 类型化取值 |
| [_version.py](../src/bk_kms/_version.py) | 包版本及派生的 SDK 请求头版本 |

密码原语统一通过 bkcrypto 公共 Cipher 类调用；KMS 层负责协议格式和参数。`cryptography.hazmat.primitives.hashes` 用于配置 RSA OAEP；SM2 私钥通过 Tongsuo serialization 转为 PKCS#8。内部使用固定函数分派，没有插件注册表或通用 Provider 框架。

## 客户端与 HTTP

`Client` 配置使用关键字参数。默认 `direct=True`；两种模式都要求非空 `app_code`，网关模式额外要求 `app_secret`。SDK 不根据 URL 自动切换模式。

| 模式 | 拼接到 `base_url.rstrip("/")` 的路径 | 额外请求头 |
| --- | --- | --- |
| 直连 | `/api/v1/consume/credential` | `X-Bk-AppCode` |
| 网关 | `/api/v1/consume_credential` | `X-Bkapi-Authorization` |

边界拼接保留 base URL 的路径前缀。网关授权头为包含 `bk_app_code`、`bk_app_secret` 的紧凑 JSON。

每次请求还发送：

- `Content-Type: application/json; charset=utf-8`；
- `X-Bkapi-Request-Id`：无连字符的 UUID v4；
- `X-Bk-Tenant-Id`：Client 配置的租户值，包括空字符串；
- `X-BKKMS-AK`、`X-BKKMS-Timestamp`、`X-BKKMS-Nonce`、`X-BKKMS-Signature`；
- `X-BKKMS-SDK-Version`：由包版本转换的协议版本字符串，例如 `1.0.0a1` 对应 `v1.0.0-alpha.1`。

`tenant_id` 只在构造 Client 时设置，消费方法不接收该参数。省略、`None` 或 `""` 均使用空字符串；非字符串和纯空白字符串被拒绝。SDK 不读取环境变量或框架配置，也不推导 `default` 或 `system`。实际目标租户由应用显式选择。

SDK 创建并关闭内部 `httpx2.Client`，不接收调用方提供的 HTTP client。推荐使用上下文管理器；`close()` 幂等，关闭后消费抛出 `ClientClosedError`。支持一个线程复用一个 Client，不承诺跨线程并发安全。

请求显式关闭重定向。核心 Client 的 `timeout` 默认 30 秒，传给 HTTPX2 的 connect/read/write/pool 超时；它不是整次消费的总耗时截止时间。公开 API 不提供自定义 transport、CA 或客户端证书参数。

## 请求体与签名

`consume_credential()` 与 `consume_credential_envelope()` 接收 `access_key`、`secret_key`、可选 `credential_names` 和 `crypto`。默认算法为 `CryptoInfo.rsa_aes_cbc()`。

`credential_names=None` 或空序列均请求 AK 唯一绑定凭证组内的全部凭证。名称必须是有效 Unicode 字符串，保留原始值；不能把单个字符串当名称列表传入。按名称请求仍保留空的 `credential_id_list` 线协议字段，返回结果仍包含 `credential_id`。

请求字段按以下顺序构造：

```text
credential_id_list: []
credential_name_list: [...]
crypto:
  asymmetric_type
  symmetric_type
  symmetric_mode
public_key
```

`_json.dumps_bytes()` 生成紧凑 UTF-8 JSON，拒绝 NaN/Infinity，并像 Go `encoding/json` 一样转义 `<`、`>`、`&`、U+2028、U+2029。签名和 `content=body` 使用同一份字节，不通过 HTTP client 的 `json=` 参数重新序列化。

```text
content_hash = HEX_LOWER(SHA256(body))
string_to_sign = timestamp + "\n" + nonce + "\n" + content_hash
signing_key = HMAC-SHA256(secret_key, nonce)
signature = HEX_LOWER(HMAC-SHA256(signing_key, string_to_sign))
```

其中 `signing_key` 是第一阶段 HMAC 的原始字节；timestamp 为十进制 Unix 秒，nonce 为无连字符 UUID v4。HTTP method 和 URL path 不参与签名。

Go 和 C++ 的参考实现在 [Go signature](../../go/internal/signature/signature.go) 与 [C++ signature](../../cpp/source/internal/signature/signature.cpp)。C++ RapidJSON 对上述特殊字符的转义与 Go/Python 不同；相同签名输入的算法一致，不代表各语言自行序列化的请求字节总是相同。

## 响应与校时重试

HTTP 响应通过 `_json.loads(response.content)` 解析，不直接调用标准 `json.loads()` 或 `Response.json()`。统一解码器拒绝 UTF-8 BOM 和非标准数值，并将孤立 surrogate 规范化为 U+FFFD。

处理顺序：

1. 校验顶层 JSON 对象、signed 32-bit `code` 和 `message` 类型；缺失或 `null` 的 message 变为空字符串。
2. 顶层 `code == 1034016` 时进入校时分支。
3. 其他情况下，HTTP 状态非 200 或 `code != 0` 抛出 `KMSRequestError`。
4. 成功响应要求 `data` 为对象且 `data.envelope` 为非空字符串，返回它与本次临时私钥组成的 `ConsumeEnvelope`。
5. 无论成功或失败，关闭已收到的 HTTP response。

只有 `1034016` 触发自动重试：读取带时区的有效 HTTP `Date`，计算服务端与本机的秒差，保存到当前 Client，并重新生成密钥对、nonce、request ID、timestamp、body 和 signature 后重试一次。缺失或非法 Date、第二次仍报时钟偏差均抛出 `ClockSkewError`。偏移属于 Client 实例，没有锁或全局时钟修改。

该分支先于一般 HTTP 状态判断，因此非 200 响应携带有效 `1034016` 也可能触发校时。HTTP 5xx 本身、transport 错误、超时、签名错误 `1034015`、其他业务错误及解密失败均不会触发重试。

## 密码与信封格式

| 项目 | 线协议格式与处理 |
| --- | --- |
| RSA | 2048 位、指数 65537；OAEP SHA-256、MGF1 SHA-256、空 label；公钥 SPKI PEM，私钥 PKCS#1 PEM，再 Base64 |
| SM2 | 公钥 SPKI PEM，私钥 PKCS#8 PEM，再 Base64；ASN.1 密文；数据密钥按 bytes 解密 |
| AES / SM4 | 16 字节密钥；Base64 编码的 `IV[16] || ciphertext` |
| CBC | 校验块对齐和 PKCS#7；AES 由 bkcrypto 去填充，SM4 由 SDK 严格去填充 |
| CTR | 不填充，使用完整 16 字节计数器初值 |

外层信封为 `Base64(JSON)`，JSON 必须包含非空字符串字段 `asymmetric_type`、`symmetric_type`、`symmetric_mode`、`encrypted_key`、`ciphertext`。算法标识严格匹配 Enum。

`decrypt_envelope()` 不依赖 Client：先解密数据密钥，再解密凭证 JSON 数组，最后转换为 `list[ConsumeResult]`。当前对称密文校验要求 IV 后至少有一个字节的密文。格式、算法、密钥、解密或结果字段错误统一表现为 `EnvelopeDecodeError`；国密后端不可用保留为 `CryptoBackendUnavailableError`。

客户端模型允许 RSA/SM2 × AES/SM4 × CBC/CTR 的八种组合，固定向量覆盖本地解密。此覆盖不证明部署的 KMS 服务接受全部组合。CBC/CTR 信封没有 AEAD 认证标签，格式与填充校验不能等同于密码学完整性验证。

## 数据模型与错误边界

公开模型使用 frozen dataclass，算法使用角色分离的 `StrEnum`；完整字段和导出见 [models.py](../src/bk_kms/models.py) 与 [顶层导出](../src/bk_kms/__init__.py)。

- 已知凭证类型转换为 `CredentialType`，未知字符串保留以兼容新类型。
- 已知类型校验必需认证字段，并拒绝不属于该类型的非空认证字段。线协议中缺失、`null` 或空的可选认证字段归一化为 `None`。
- 结果解析要求 `credential_id` 为 signed 64-bit 整数、`err_code` 为 signed 32-bit 整数，不接受 bool、缺失或 `null`；成功结果必须带凭证。
- 请求级失败抛异常；核心 Client 的单凭证 `err_code != 0` 保留为结果，由调用方检查 `result.ok`。Django 启动集成将此类失败升级为 `ImproperlyConfigured`。

```text
BKMSException
├── ConfigurationError
├── ValidationError
├── ClientClosedError
├── TransportError
├── ResponseDecodeError
├── KMSRequestError
│   └── ClockSkewError
└── CryptoError
    ├── CryptoBackendUnavailableError
    └── EnvelopeDecodeError
```

`KMSRequestError` 提供 `message`、`status_code`、`code`、`request_id`，不保存完整响应或请求。其消息可能包含服务端 `message`；单凭证 `err_msg` 也来自服务端，SDK 不对这些文本提供脱敏保证。

`AuthInfo`、`ConsumeEnvelope`、`KeyPair` 的敏感字段不参与 `repr`。这不等于任意日志或异常链都已脱敏；不要输出密钥、认证头或凭证明文。信封和配套私钥共同可恢复明文，二者均需保密。

## Django 启动边界

`load_credentials()` 在 settings 导入时同步运行，按 `NAME + TYPE` 声明校验非空别名映射，合并同名同类型绑定后消费，再检查失败、重复、未请求、缺失及类型不符的结果。同名不同类型配置直接失败。每次调用创建并关闭 Client，不缓存结果或维护连接刷新。

`CredentialStore` 提供只读 Mapping 接口，以及用户名/密码、App ID/Secret Key、单值和数据库 `USER`/`PASSWORD` 投影。完整 URI 与 Base64 TLS 材料作为 KMS 字符串凭据读取，由应用装配连接配置、解码和加载。配置默认值、取值方法及示例集中在 [Django 集成](django.md)。

## 验证来源与边界

[Makefile](../Makefile) 提供从 `python/` 运行的 `make lint`、`make test` 和 `make build`，分别执行 Ruff/格式检查/mypy、pytest、sdist/wheel 构建。

[Python CI](../../.github/workflows/python.yml) 配置如下；这里描述检查范围，不代表某次流水线已通过：

| 环境 | Python / 架构 | 配置检查 |
| --- | --- | --- |
| Ubuntu | Python 3.11–3.14 | 安装 `dev,django,gm`，lint/test/build |
| TencentOS 4 | `linux/amd64`、`linux/arm64`，镜像内 Python | 固定镜像 digest，安装 `dev,django,gm`，lint/test/build |
| macOS / Windows | Python 3.11、3.14 | 安装 `dev,django`，`pytest -m "not gm"` |

固定向量由 Python 单元测试消费，不在测试时执行 Go/C++；具体文件和覆盖见 [fixtures 说明](../tests/fixtures/README.md)。[HTTP 集成测试](../tests/integration/test_client_roundtrip.py) 使用本地 `http.server`，验证请求、签名和 RSA/AES-CBC 信封往返，不连接真实 KMS。

真实部署的权限、租户解析、nonce 防重放窗口及服务端算法支持需由受控环境另行验证。包元数据、CI 配置和离线向量不能替代生产或远程 CI 运行证据。
