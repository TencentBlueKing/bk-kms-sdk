# Django 启动期凭据

在 Django 启动、加载 settings 时，通过直连 KMS 获取应用、MySQL 和 Redis 凭据；仅支持启动时加载，不支持运行期凭据轮转。

## 安装

支持 Django `>=4.2,<6`，Python 版本要求见 [README](../README.md#运行环境)。安装 Django 集成依赖：

```bash
pip install "bk-kms-sdk[django]"
```

## 配置与使用

`TENANT_ID` 由应用显式选择。省略或配置为 `""` 时，SDK 发送空的 `X-Bk-Tenant-Id`，不会读取环境变量，也不会自动推导 `default` 或 `system`。Django 配置要求该值是字符串（不接受 `None`），并拒绝纯空白字符串。服务端如何解释空租户头需按部署约定确认。

以下示例由应用读取环境变量：

- `BK_APP_TENANT_ID`：目标租户 ID；仅当目标确实为系统租户时使用 `system`。
- `BK_KMS_BASE_URL`：运维提供的 KMS 服务地址。
- `BK_APP_CODE`：访问 KMS 使用的应用标识。
- `BK_KMS_ACCESS_KEY`、`BK_KMS_SECRET_KEY`：KMS 提供的配套 Access Key / Secret Key。

请向 KMS 管理员或运维确认上述信息，并确认 Access Key 已启用、未过期且绑定了所需凭证组。准备好组内要读取的凭证名称和类型，替换下面的示例配置。

在 `settings.py` 中通过应用别名声明 `NAME`（KMS 凭证名称）和 `TYPE`（凭证类型），并批量获取凭据：

```python
import os

from bk_kms.django import load_credentials

BK_APP_TENANT_ID = os.environ["BK_APP_TENANT_ID"]

BK_KMS = {
    "TENANT_ID": BK_APP_TENANT_ID,
    "BASE_URL": os.environ["BK_KMS_BASE_URL"],
    "APP_CODE": os.environ["BK_APP_CODE"],
    "ACCESS_KEY": os.environ["BK_KMS_ACCESS_KEY"],
    "SECRET_KEY": os.environ["BK_KMS_SECRET_KEY"],
    "TIMEOUT": 5,
}

# 将 NAME 替换为 KMS 中的实际凭证名称。
credential_bindings = {
    "app_secret": {"NAME": "app_secret", "TYPE": "app_id_secret_key"},
    "mysql_password": {"NAME": "mysql_password", "TYPE": "username_password"},
    "redis_password": {"NAME": "redis_password", "TYPE": "single_password"},
}

BK_KMS["CREDENTIALS"] = credential_bindings
credentials = load_credentials(BK_KMS)

BK_APP_CODE, BK_APP_SECRET = credentials.app_id_secret_key("app_secret")
MYSQL_USERNAME, MYSQL_PASSWORD = credentials.username_password("mysql_password")
REDIS_PASSWORD = credentials.password("redis_password")
```

## 凭证校验与错误处理

每项凭证配置都需要填写 `NAME` 和 `TYPE`，分别对应 KMS 中的凭证名称和类型。加载失败时会抛出 `ImproperlyConfigured`，Django 启动失败，请根据异常提示检查配置或凭证状态。错误码含义见 README 的[报错及排障](../README.md#5-报错及排障)。

如果只看到 `Unable to load BK-KMS credentials`，请查看完整 traceback 中此前的原始异常。KMS 请求错误的 `code`、`request_id` 位于原始 `KMSRequestError` 上，不在外层 `ImproperlyConfigured` 上。

## 超时

`TIMEOUT` 默认 5 秒，可在 `BK_KMS` 中调整。它限制各阶段的网络等待时间，不是整个启动过程的总时限。

## 国密算法

需要选择国密算法时，用下面的代码替换前述 `credentials = load_credentials(BK_KMS)`：

```python
from bk_kms import CryptoInfo

BK_KMS["CRYPTO"] = CryptoInfo.sm2_sm4_cbc()
credentials = load_credentials(BK_KMS)
```

使用国密算法需要安装 `bk-kms-sdk[django,gm]`。默认算法为 RSA/AES-CBC；国密后端不可用时启动失败，不会自动切换算法。

## 读取凭证

通过 `credentials` 读取凭证。下面的 `alias` 是 `CREDENTIALS` 中的键名，例如 `"mysql_password"`，不是其中的 `NAME` 值。

| 方法 | 凭证类型 | 返回值 |
| --- | --- | --- |
| `username_password(alias)` | `username_password` | `(username, password)` |
| `database(alias)` | `username_password` | `{"USER": username, "PASSWORD": password}` |
| `password(alias)` | `single_password` / `username_password` | password 字符串 |
| `secret_key(alias)` | `single_secret_key` / `app_id_secret_key` | secret_key 字符串 |
| `app_id_secret_key(alias)` | `app_id_secret_key` | `(app_id, secret_key)` |

键名不存在或凭证类型不符时，会抛出 `ImproperlyConfigured`。连接地址、端口等由应用自行配置。

如果 KMS 保存的是完整连接 URI，在调用 `load_credentials()` 前添加配置，再读取使用：

```python
BK_KMS["CREDENTIALS"]["redis_uri"] = {
    "NAME": "redis_connection",  # 替换为 KMS 中保存完整 URI 的凭证名称
    "TYPE": "single_secret_key",
}
credentials = load_credentials(BK_KMS)
REDIS_URL = credentials.secret_key("redis_uri")
```

## 可选：加载 TLS 证书

需要从 KMS 获取 MySQL 或 Redis 的 TLS 证书时，用下面的代码替换基础示例中的 `credentials = load_credentials(BK_KMS)`。两个服务分别通过 `MYSQL_TLS_ENABLED`、`REDIS_TLS_ENABLED` 环境变量启用，值为 `true` 时加载，默认关闭。

在 KMS 中将 CA、客户端证书和客户端私钥分别保存为 `single_secret_key` 类型的凭证，值为完整文件内容的 Base64。将下面的 `NAME` 替换为实际凭证名称：

```python
import base64

MYSQL_TLS_ENABLED = os.environ.get("MYSQL_TLS_ENABLED", "false").lower() == "true"
REDIS_TLS_ENABLED = os.environ.get("REDIS_TLS_ENABLED", "false").lower() == "true"

tls_bindings = {}
if MYSQL_TLS_ENABLED:
    tls_bindings.update({
        "mysql_ca": {"NAME": "mysql_tls_ca_cert_base64", "TYPE": "single_secret_key"},
        "mysql_cert": {"NAME": "mysql_tls_client_cert_base64", "TYPE": "single_secret_key"},
        "mysql_key": {"NAME": "mysql_tls_client_private_key_base64", "TYPE": "single_secret_key"},
    })
if REDIS_TLS_ENABLED:
    tls_bindings.update({
        "redis_ca": {"NAME": "redis_tls_ca_cert_base64", "TYPE": "single_secret_key"},
        "redis_cert": {"NAME": "redis_tls_client_cert_base64", "TYPE": "single_secret_key"},
        "redis_key": {"NAME": "redis_tls_client_private_key_base64", "TYPE": "single_secret_key"},
    })

BK_KMS["CREDENTIALS"].update(tls_bindings)
credentials = load_credentials(BK_KMS)
TLS_MATERIALS = {
    alias: base64.b64decode(credentials.secret_key(alias), validate=True)
    for alias in tls_bindings
}
```

例如，启用 MySQL 后，通过 `TLS_MATERIALS["mysql_ca"]` 取得 CA 文件内容（`bytes`）。未启用的服务不会请求对应证书。

这一步只加载证书，还需在数据库或 Redis 连接配置中启用 TLS 并传入这些材料；若连接库要求文件路径，需先将材料安全写入文件。Base64 内容无效时会直接抛出解码异常，请检查 KMS 中保存的值。
