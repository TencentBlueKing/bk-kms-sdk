# BK-KMS Python SDK

通过 Access Key / Secret Key 获取 KMS 中的凭证，可用于应用密钥、数据库密码等配置。支持普通 Python 应用和 Django 启动时加载。

## 运行环境

- Python `>=3.11,<3.15`
- 默认支持 RSA、AES，无需额外配置
- 使用 SM2、SM4 时安装国密依赖，支持 TencentOS/Linux 容器的 x86_64、aarch64 环境

## 安装

```bash
pip install bk-kms-sdk
```

需要使用 SM2、SM4 时安装国密依赖：

```bash
pip install "bk-kms-sdk[gm]"
```

## 接入准备

开始前，请向 KMS 管理员或运维确认以下信息：

- KMS 服务地址，以及访问 KMS 使用的应用编码（`app_code`）。
- 配套的 Access Key / Secret Key，且 Access Key 已启用、未过期并绑定所需凭证组。
- 需要读取的凭证名称和类型。将示例中的 `database`、`redis` 等名称替换为实际名称。

普通 Python 应用可直接查看[基础示例](#2-直接消费直连模式默认)，Django 应用查看 [Django 集成](docs/django.md)。

## 租户配置

SDK 在直连和网关模式下统一使用租户头 `X-Bk-Tenant-Id`。`tenant_id` 在创建 `Client` 时配置，后续消费方法无需传入；同一个 Client 使用固定的租户 ID。

| 部署环境 | 应用类型 | 创建 Client 时如何配置 |
| --- | --- | --- |
| 非多租户环境 | 所有应用 | 可省略 `tenant_id`，或显式传入 `"default"` |
| 多租户环境 | 单租户应用（绝大多数 SaaS） | 可省略 `tenant_id` |
| 多租户环境 | 全租户应用（已做多租户改造的蓝鲸官方系统等） | 显式传入目标租户 ID, 蓝鲸系统直接配置 `system`即可，非蓝鲸系统如果是开发者中心应用可以使用`BKPAAS_APP_TENANT_ID`环境变量 |

省略 `tenant_id`、传入 `None` 或空字符串时，SDK 发送的 `X-Bk-Tenant-Id` 值为空字符串，不自动填入 `default`，也不读取环境变量或框架配置。应用自行读取所需配置并传入；访问不同租户时分别创建不同的 Client。

```python
from bk_kms import Client

# 非多租户环境 或 多租户环境的单租户应用 => 无需设置 tenant_id
with Client(base_url="http://kms.service:23681", app_code="your-app-code") as client:
    ...

# 多租户环境的全租户应用，需要显式传入自己所属租户 ID
# 已做多租户改造的蓝鲸官方系统, tenant_id = system， 其他应用按照实际租户配置
BK_APP_TENANT_ID = "system"
with Client(
    base_url="http://kms.service:23681",
    app_code="your-app-code",
    tenant_id=BK_APP_TENANT_ID,
) as client:
    ...

```

## 使用

### 1. 框架集成

- [Django：settings 启动期凭据加载](docs/django.md)

### 2. 直接消费：直连模式（默认）

填写 KMS 服务地址和应用编码，使用 KMS 提供的 Access Key / Secret Key 消费凭据。

```python
from bk_kms import Client, CredentialType

# 已做多租户改造的蓝鲸官方系统, tenant_id = system， 其他应用按照实际租户配置
BK_APP_TENANT_ID = "system"

with Client(
    base_url="http://kms.service:23681",
    app_code="your-app-code",
    tenant_id=BK_APP_TENANT_ID,
) as client:
    results = client.consume_credential(
        access_key="your-access-key",
        secret_key="your-secret-key",
        credential_names=["database", "redis"],
    )

for result in results:
    if not result.ok:
        print(result.credential_id, result.err_code, result.err_msg)
        continue

    credential = result.credential
    assert credential is not None

    match credential.type:
        case CredentialType.SINGLE_PASSWORD:
            password = credential.auth_info.password
            # 使用 password
        case CredentialType.USERNAME_PASSWORD:
            username = credential.auth_info.username
            password = credential.auth_info.password
            # 使用 username 和 password
        case CredentialType.SINGLE_SECRET_KEY:
            secret_key = credential.auth_info.secret_key
            # 使用 secret_key
        case CredentialType.APP_ID_SECRET_KEY:
            app_id = credential.auth_info.app_id
            secret_key = credential.auth_info.secret_key
            # 使用 app_id 和 secret_key
```

**按名称消费凭证**

通过 `credential_names` 指定需要的凭证，如上例中的 `["database", "redis"]`。省略或传入 `[]` 时，返回该 Access Key 绑定凭证组内的全部凭证。

**处理失败**

调用失败时 SDK 会抛出异常；返回结果后，逐条检查 `result.ok`，失败原因见 `result.err_code` 和 `result.err_msg`，处理方式如上例。异常及错误码详见 [报错及排障](#5-报错及排障)。

### 3. 直接消费：高级用法

**Client 使用约定**

使用 `with Client(...)` 上下文管理器或显式调用 `Client.close()` 释放连接资源。

`Client` 默认 `timeout=30.0`。该数值分别约束 connect、read、write 和连接池等待，不是整个请求的总耗时截止时间。

多线程程序应为每个线程创建独立 Client，不应跨线程共享同一个 Client。

#### 3.1 获取密文信封

`consume_credential()` 会在本地自动解密。仅在需要延迟解密或跨边界传递密文时，才使用 `consume_credential_envelope()`：

```python
from bk_kms import Client, decrypt_envelope

# 已做多租户改造的蓝鲸官方系统, tenant_id = system， 其他应用按照实际租户配置
BK_APP_TENANT_ID = "system"

with Client(
    base_url="http://kms.service:23681",
    app_code="your-app-code",
    tenant_id=BK_APP_TENANT_ID,
) as client:
    envelope = client.consume_credential_envelope(
        access_key="your-access-key",
        secret_key="your-secret-key",
        credential_names=["database", "redis"],
    )

results = decrypt_envelope(envelope)
```

`envelope.envelope` 和 `envelope.private_key` 同时存在时可以恢复凭证明文，两者都必须作为敏感数据保护。

#### 3.2 国密算法

默认使用 RSA + AES-CBC。需要使用 SM2 + SM4-CBC 时，先安装 `bk-kms-sdk[gm]`，再按下面的示例设置 `crypto`。

```python
from bk_kms import Client, CryptoInfo

# 已做多租户改造的蓝鲸官方系统, tenant_id = system， 其他应用按照实际租户配置
BK_APP_TENANT_ID = "system"

with Client(
    base_url="http://kms.service:23681",
    app_code="your-app-code",
    tenant_id=BK_APP_TENANT_ID,
) as client:
    results = client.consume_credential(
        access_key="your-access-key",
        secret_key="your-secret-key",
        credential_names=["database", "redis"],
        crypto=CryptoInfo.sm2_sm4_cbc(),
    )
```

### 4. 直接消费：网关模式（可选）

通过 API 网关访问时，设置 `direct=False`，填写网关发布环境的 HTTPS 地址、应用编码和应用密钥。Access Key / Secret Key 仍使用 KMS 提供的值。

```python
from bk_kms import Client

# 已做多租户改造的蓝鲸官方系统, tenant_id = system， 其他应用按照实际租户配置
BK_APP_TENANT_ID = "system"

with Client(
    base_url="https://example.com/api/bk-kms/prod",
    direct=False,
    app_code="your-app-code",
    app_secret="your-app-secret",
    tenant_id=BK_APP_TENANT_ID,
) as client:
    results = client.consume_credential(
        access_key="your-access-key",
        secret_key="your-secret-key",
        credential_names=["database", "redis"],
    )

for result in results:
    if not result.ok:
        print(result.credential_id, result.err_code, result.err_msg)
        continue

    credential = result.credential
    assert credential is not None
    print(credential.name, credential.type)
```

### 5. 报错及排障

#### 5.1 SDK 异常

以下异常均可从 `bk_kms` 导入，统一基类为 `BKMSException`。

| 异常 | 含义及排查方向 |
| --- | --- |
| `ConfigurationError` | Client 配置无效，检查服务地址、应用编码、租户及超时配置；网关模式还需提供应用密钥。 |
| `ValidationError` | 参数无效，检查 Access Key / Secret Key、凭证名称及算法配置。凭证名称不能包含非法 Unicode 字符。 |
| `ClientClosedError` | Client 已关闭，重新创建 Client 后调用。 |
| `TransportError` | HTTP 请求失败，检查网络、服务地址、TLS 证书及超时设置。 |
| `ResponseDecodeError` | 服务响应格式异常，检查是否访问了正确的 KMS 或网关地址。 |
| `KMSRequestError` | 服务拒绝请求，可通过异常的 `status_code`、`code` 和 `request_id` 排查；后两项可能为 `None`。 |
| `ClockSkewError` | 请求时间偏差无法自动修正，检查客户端与服务端的系统时间同步。此异常继承自 `KMSRequestError`。 |
| `CryptoError` | 加解密处理失败，检查算法配置及运行环境。 |
| `CryptoBackendUnavailableError` | 国密后端不可用，确认已安装 `bk-kms-sdk[gm]` 且平台受支持。此异常继承自 `CryptoError`。 |
| `EnvelopeDecodeError` | 凭证信封解密或数据校验失败，检查信封、私钥是否匹配以及服务端返回的数据。此异常继承自 `CryptoError`。 |

`consume_credential()` 或 `decrypt_envelope()` 遇到结果字段缺失、类型错误，或凭证缺少必需认证字段时，会抛出 `EnvelopeDecodeError`，不会返回部分结果。

#### 5.2 单条凭证失败

调用正常返回后，仍需逐条检查 `result.ok`。为 `False` 时，通过 `result.credential_id`、`result.err_code` 和 `result.err_msg` 定位失败凭证及原因，不要读取其 `credential`；为 `True` 时才读取 `result.credential`。

#### 5.3 常见服务错误码

以下常量均可从 `bk_kms` 导入。请求被拒绝时，可与 `KMSRequestError.code` 比较。

| 常量 | 错误码 | 含义及排查方向 |
| --- | --- | --- |
| `ERR_CODE_ACCESS_KEY_DISABLED` | 1034011 | Access Key 已禁用，检查其启用状态。 |
| `ERR_CODE_ACCESS_KEY_EXPIRED` | 1034012 | Access Key 已过期，更新有效的访问密钥。 |
| `ERR_CODE_ACCESS_KEY_NOT_BOUND` | 1034013 | Access Key 未绑定凭证组，检查绑定关系。 |
| `ERR_CODE_NONCE_ALREADY_USED` | 1034014 | nonce 已使用，检查请求是否被重复发送或重放。 |
| `ERR_CODE_SIGNATURE_MISMATCH` | 1034015 | 签名不匹配，检查 Access Key / Secret Key 是否配套、配置是否正确。 |
| `ERR_CODE_REQUEST_TIME_TOO_SKEWED` | 1034016 | 请求时间偏差过大，检查系统时间同步。 |

遇到 `1034016` 时，SDK 会尝试根据响应的 `Date` 校时并重试一次；缺少有效的 `Date` 或重试后仍报时间偏差时，抛出 `ClockSkewError`。其他错误不自动重试。
