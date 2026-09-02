# Go SDK 快速上手

## 1. 安装

```bash
go get github.com/TencentBlueKing/bk-kms-sdk/go
```

## 2. 创建 Client

SDK 提供直连与网关两种接入模式, 由调用方类型决定: 蓝鲸平台系统接入采用直连模式, SaaS场景构建的应用采用网关模式。

直连模式需开启 `WithDirect`, `BaseURL` 指向 KMS 的 HTTP 直连端口 (`23681`), 该端口不校验 JWT, 无需提供 App Code / App Secret:

```go
client, err := consume.New(
    consume.WithBaseURL("http://xxxx:23681"),
    consume.WithDirect(),
)
```

网关模式无需开启 `WithDirect`, `BaseURL` 指向蓝鲸网关 APIGW 地址, 该入口由 APIGW 注入并校验 JWT, 需通过 `WithAppCodeSecret` 提供 App Code / App Secret:

```go
client, err := consume.New(
    consume.WithBaseURL("http://xxxx/api/bk-kms/prod"),
    consume.WithAppCodeSecret("your_app_code_xxxx", "your_app_secret_xxxx"),
)
```

| 选项                | 必填 | 默认值             | 说明                                                                           |
| ------------------- | ---- | ------------------ | ------------------------------------------------------------------------------ |
| `WithBaseURL`       | 是   | 无                 | KMS 地址, 直连时如 `http://xxxx:23681`, 网关时如 `http://xxxx/api/bk-kms/prod` |
| `WithDirect`        | 否   | 关闭               | 开启直连调用, 不经过网关, 无需JWT                                              |
| `WithAppCodeSecret` | 否   | 无                 | 应用态认证 App Code / App Secret (直连不需要)                                  |
| `WithTimeout`       | 否   | `30s`              | 单次请求超时时间, 有更长/更短时延要求时可覆盖                                  |
| `WithClient`        | 否   | 内置 `http.Client` | 自定义 `http.Client`                                                           |

## 3. 消费凭证

### 3.1 明文消费

默认使用国际算法 `RSA + AES(CBC)`:

```go
results, err := client.ConsumeCredential(context.Background(),
    consume.WithAccessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx"),
    consume.WithCredentialNameList("credential_name_1", "credential_name_2"),
)
```

需要国密时通过 `WithCrypto` 覆盖:

```go
results, err := client.ConsumeCredential(context.Background(),
    consume.WithAccessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx"),
    consume.WithCredentialNameList("credential_name_1", "credential_name_2"),
    consume.WithCrypto(types.CryptoInfo{
        AsymmetricType: types.CryptoTypeSM2,
        SymmetricType:  types.CryptoTypeSM4,
        SymmetricMode:  types.CryptoModeCBC,
    }),
)
```

多租户环境下, 可以通过 `WithTenantID` 指定目标租户; 未设置时不携带该 header。非多租户环境无需关心:

```go
results, err := client.ConsumeCredential(context.Background(),
    consume.WithAccessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx"),
    consume.WithCredentialNameList("credential_name_1", "credential_name_2"),
    consume.WithTenantID("tenant_name"),
)
```

| 选项                     | 必填 | 默认值           | 说明                                                               |
| ------------------------ | ---- | ---------------- | ------------------------------------------------------------------ |
| `WithTenantID`           | 否   | 无               | 目标租户 ID, 仅限多租户场景使用                                    |
| `WithAccessKeySecret`    | 是   | 无               | 调用方的 Access Key / Secret Key                                   |
| `WithCredentialNameList` | 否   | 空(返回全部凭证) | 要消费的凭证名称列表, 不指定则返回该 AK 唯一绑定凭证组下的全部凭证 |
| `WithCrypto`             | 否   | `RSA + AES(CBC)` | 混合加密算法组合, 可选取值见下表                                   |

当前版本支持的 `WithCrypto` 可选组合:

| 维度     | Go 常量                                          |
| -------- | ------------------------------------------------ |
| 非对称   | `types.CryptoTypeRSA` / `types.CryptoTypeSM2`    |
| 对称     | `types.CryptoTypeAES` / `types.CryptoTypeSM4`    |
| 分组模式 | `types.CryptoModeCBC` / `types.CryptoModeCTR`    |

常见的算法组合:

- 国际算法(默认): `RSA + AES(CBC)`
- 国密算法: `SM2 + SM4(CBC)`

### 3.2 信封消费

需要密文信封而非明文时(如先落库或交由其他进程解密), 换用 `ConsumeCredentialEnvelope`, 选项与 3.1 完全一致, 网关与直连模式均适用, 返回 `(*types.ConsumeEnvelope, error)`:

```go
envelope, err := client.ConsumeCredentialEnvelope(context.Background(),
    consume.WithAccessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx"),
    consume.WithCredentialNameList("credential_name_1", "credential_name_2"),
)
```

| 字段         | 类型     | 说明                        |
| ------------ | -------- | --------------------------- |
| `Envelope`   | `string` | 信封式包裹的密文 (base64)   |
| `PrivateKey` | `string` | 本次临时生成的私钥 (base64) |

`Envelope` 与 `PrivateKey` 需自行保管, 需要明文时通过 `consume.DecryptEnvelope` 本地解密:

```go
results, err := consume.DecryptEnvelope(envelope)
```

## 4. 处理返回值

`ConsumeCredential` 与 `DecryptEnvelope` 均返回 `([]types.ConsumeResult, error)`, 遵循请求级error + 单条err_code 的两级错误模型:

- `error != nil`: 请求失败, 无结果可处理;
- `error == nil`: 请求成功, 遍历 `results`, 单条是否成功看 `ErrCode`。

### 4.1 ConsumeResult

| 字段           | 类型                 | 说明                      |
| -------------- | -------------------- | ------------------------- |
| `CredentialID` | `int64`              | 凭证 ID                   |
| `ErrCode`      | `int32`              | `0` 成功; 非 `0` 该条失败 |
| `ErrMsg`       | `string`             | 失败原因                  |
| `Credential`   | `*types.Credential`  | 成功时返回, 失败为 `nil`  |

单条 `ErrCode` 常量位于 `types` 包, 可用 `types.IsOK(errCode)` 快速判断。常用如下, 完整错误码见 [`types/errors.go`](../types/errors.go):

| 常量                                  | 值        | 含义             |
| ------------------------------------- | --------- | ---------------- |
| `types.ErrCodeOK`                     | `0`       | 成功             |
| `types.ErrCodeGenericError`           | `1034000` | 系统错误         |
| `types.ErrCodeNotFound`               | `1034003` | 未找到           |
| `types.ErrCodePermissionDenied`       | `1034008` | 无权限           |
| `types.ErrCodeRequestTimeTooSkewed`   | `1034016` | 请求时间偏差过大 |

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

明文消费见 [../examples/consume](../examples/consume);
信封消费见 [../examples/consume_envelope](../examples/consume_envelope);
