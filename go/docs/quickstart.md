# Go SDK 快速上手

## 1. 安装

```bash
go get github.com/TencentBlueKing/bk-kms-sdk/go
```

## 2. 创建 Client

```go
client, err := consume.New(
    consume.WithBaseURL("http://xxxx/api/bk-kms/prod"),
    consume.WithAppCodeSecret("your_app_code_xxxx", "your_app_secret_xxxx"),
)
```

`BaseURL` 需指定到 KMS 网关对应环境的地址, `AppCode` / `AppSecret` 为调用方的应用态认证参数。

| 选项                | 必填 | 默认值             | 说明                                                      |
| ------------------- | ---- | ------------------ | --------------------------------------------------------- |
| `WithBaseURL`       | 是   | 无                 | KMS 网关地址, 如 `http://xxxx/api/bk-kms/prod`            |
| `WithAppCodeSecret` | 是   | 无                 | 调用方应用态认证参数 App Code / App Secret                |
| `WithTimeout`       | 否   | `30s`              | 单次请求超时时间, 有更长/更短时延要求时可覆盖             |
| `WithClient`        | 否   | 内置 `http.Client` | 自定义 `http.Client`, 如有需要可设置更多维度参数的客户端  |
| `WithDirect`        | 否   | 关闭               | 不经过网关, 直连 KMS 后端服务, 该模式下无需应用态认证参数 |

特殊情况下需要不经过网关直连 KMS 后端时, 可通过 `WithDirect` 开启, `BaseURL` 需指定到 KMS 的 HTTP 端口 (`23680`), 常规情况下业务接入请走网关模式:

```go
client, err := consume.New(
    consume.WithBaseURL("http://xxxx:23680"),
    consume.WithDirect(),
)
```

## 3. 消费凭证

默认使用国际算法 `RSA + AES(CBC)`:

```go
results, err := client.ConsumeCredential(context.Background(),
    consume.WithAccessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx"),
    consume.WithCredentialIDList(1, 2),
)
```

特殊情况下选定直连模式时, 需要通过 `WithJWTToken` 传入 JWT token 完成直连请求认证, 常规情况下业务接入无需关心:

```go
results, err := client.ConsumeCredential(context.Background(),
    consume.WithAccessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx"),
    consume.WithCredentialIDList(1, 2),
    consume.WithJWTToken("your_jwt_token_xxxx"),
)
```

需要国密时通过 `WithCrypto` 覆盖:

```go
results, err := client.ConsumeCredential(context.Background(),
    consume.WithAccessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx"),
    consume.WithCredentialIDList(1, 2),
    consume.WithCrypto(types.CryptoInfo{
        AsymmetricType: types.CryptoTypeSM2,
        SymmetricType:  types.CryptoTypeSM4,
        SymmetricMode:  types.CryptoModeCBC,
    }),
)
```

多租户环境下, 可以通过 `WithTenantID` 指定目标租户, 未设置时 SDK 默认使用 `default` 租户, 非多租户环境无需关心:

```go
results, err := client.ConsumeCredential(context.Background(),
    consume.WithAccessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx"),
    consume.WithCredentialIDList(1, 2),
    consume.WithTenantID("tenant_name"),
)
```

| 选项                   | 必填 | 默认值           | 说明                                                       |
| ---------------------- | ---- | ---------------- | ---------------------------------------------------------- |
| `WithAccessKeySecret`  | 是   | 无               | 调用方的 Access Key / Secret Key                           |
| `WithCredentialIDList` | 否   | 空(返回全部凭证) | 要消费的凭证 ID 列表, 不指定则返回该 AK 授权范围内全部凭证 |
| `WithCrypto`           | 否   | `RSA + AES(CBC)` | 混合加密算法组合, 可选取值见下表                           |
| `WithTenantID`         | 否   | `default`        | 目标租户 ID, 仅限多租户场景使用, 默认为default租户         |
| `WithJWTToken`         | 否   | 无               | JWT token, 仅限直连模式使用                                |

当前版本支持的 `WithCrypto` 可选组合:

| 维度     | Go 常量                                          |
| -------- | ------------------------------------------------ |
| 非对称   | `types.CryptoTypeRSA` / `types.CryptoTypeSM2`    |
| 对称     | `types.CryptoTypeAES` / `types.CryptoTypeSM4`    |
| 分组模式 | `types.CryptoModeCBC` / `types.CryptoModeCTR`    |

常见的算法组合:

- 国际算法(默认): `RSA + AES(CBC)`
- 国密算法: `SM2 + SM4(CBC)`

## 4. 处理返回值

`ConsumeCredential` 返回 `([]types.ConsumeResult, error)`, 遵循请求级error + 单条err_code 的两级错误模型:

- `error != nil`: 请求失败, 无结果可处理;
- `error == nil`: 请求成功, 遍历 `results`, 单条是否成功看 `ErrCode`。

### 4.1 ConsumeResult

| 字段           | 类型                 | 说明                      |
| -------------- | -------------------- | ------------------------- |
| `CredentialID` | `int64`              | 凭证 ID                   |
| `ErrCode`      | `int32`              | `0` 成功; 非 `0` 该条失败 |
| `ErrMsg`       | `string`             | 失败原因                  |
| `Credential`   | `*types.Credential`  | 成功时返回, 失败为 `nil`  |

单条 `ErrCode` 常量位于 `types` 包, 可用 `types.IsOK(errCode)` 快速判断:

| 常量                            | 值        | 含义     |
| ------------------------------- | --------- | -------- |
| `types.ErrCodeOK`                     | `0`       | 成功             |
| `types.ErrCodeGenericError`           | `1034000` | 系统错误         |
| `types.ErrCodeNotFound`               | `1034003` | 未找到           |
| `types.ErrCodePermissionDenied`       | `1034008` | 无权限           |
| `types.ErrCodeRequestTimeTooSkewed`   | `1034015` | 请求时间偏差过大 |

其中 `ErrCodeRequestTimeTooSkewed` 表示本机与服务端时间偏差过大, 收到该错误, SDK 会依据响应 `Date` 自动校正时钟偏移并重试一次。

### 4.2 Credential

| 字段         | 类型                   | 说明                         |
| ------------ | ---------------------- | ---------------------------- |
| `Name`       | `string`               | 凭证名称                     |
| `Type`       | `types.CredentialType` | 凭证类型, 取值见下表         |
| `AuthInfo`   | `types.AuthInfo`       | 凭证明文, 字段随 `Type` 而异 |
| `Annotation` | `string`               | 凭证注解                     |

`Type` 可选值:

| Type                | Go 常量                                | 含义             |
| ------------------- | -------------------------------------- | ---------------- |
| `single_password`   | `types.CredentialTypeSinglePassword`   | 单密码           |
| `username_password` | `types.CredentialTypeUsernamePassword` | 用户名+ 密码     |
| `single_secret_key` | `types.CredentialTypeSingleSecretKey`  | 单密钥           |
| `app_id_secret_key` | `types.CredentialTypeAppIDSecretKey`   | 应用 ID + 密钥   |

### 4.3 AuthInfo

按 `Type` 取对应字段:

| Type                | 取值                         |
| ------------------- | ---------------------------- |
| `single_password`   | `AuthInfo.Password`          |
| `username_password` | `AuthInfo.Username/Password` |
| `single_secret_key` | `AuthInfo.SecretKey`         |
| `app_id_secret_key` | `AuthInfo.AppID/SecretKey`   |

## 5. 完整示例

见 [../examples/consume](../examples/consume)。
