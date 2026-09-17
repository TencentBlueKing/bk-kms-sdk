# Java SDK 快速上手

## 1. 环境要求

- Java 17 及以上
- Maven 3.6+
- Spring Boot 3.x (仅当使用 `kms-spring-boot-starter` 时需要)

## 2. 引入依赖

只使用核心能力:

```xml
<dependency>
    <groupId>com.tencent.bk.kms</groupId>
    <artifactId>kms-core-sdk</artifactId>
    <version>1.0.0-alpha.1</version>
</dependency>
```

Spring Boot 3.x 应用推荐使用 Starter:

```xml
<dependency>
    <groupId>com.tencent.bk.kms</groupId>
    <artifactId>kms-spring-boot-starter</artifactId>
    <version>1.0.0-alpha.1</version>
</dependency>
```

## 3. 创建 Client

SDK 提供直连与网关两种接入模式, 由调用方类型决定: 蓝鲸平台系统接入采用直连模式, SaaS 场景构建的应用采用网关模式。

直连模式需要开启 `direct(true)`, `baseUrl` 指向 KMS 的 HTTP 直连端口 (`23681`), 该端口不校验 JWT, 无需 App Secret, 但须通过 `appCode` 提供 App Code, 作为身份标识写入 `X-Bk-AppCode`:

```java
Client client = Client.create(ClientOptions.builder()
        .baseUrl("http://xxxx:23681")
        .direct(true)
        .appCode("your_app_code_xxxx")
        .build());
```

网关模式无需开启 `direct`, `baseUrl` 指向蓝鲸网关 APIGW 地址, 该入口由 APIGW 注入并校验 JWT, 需通过 `appCode` / `appSecret` 提供 App Code / App Secret:

```java
Client client = Client.create(ClientOptions.builder()
        .baseUrl("http://xxxx/api/bk-kms/prod")
        .appCode("your_app_code_xxxx")
        .appSecret("your_app_secret_xxxx")
        .build());
```

| 选项              | 必填    | 默认值                | 说明                                                                             |
| ----------------- | ------- | --------------------- | -------------------------------------------------------------------------------- |
| `baseUrl`         | 是      | 无                    | KMS 地址, 直连模式如 `http://xxxx:23681`, 网关模式如 `http://xxxx/api/bk-kms/prod` |
| `direct`          | 否      | `false`               | 开启直连调用, 不经过网关, 无需 JWT                                               |
| `appCode`         | 是      | 无                    | 应用身份; 直连模式写入 `X-Bk-AppCode`, 网关模式随 `X-Bkapi-Authorization` 提供   |
| `appSecret`       | 网关是  | 无                    | 网关应用态认证 App Secret (直连不需要)                                           |
| `timeout`         | 否      | `30s`                 | 单次请求超时时间, 有更长/更短时延要求时可覆盖                                    |
| `httpClient`      | 否      | 内置 `HttpClient`     | 自定义 JDK `java.net.http.HttpClient`                                            |

## 4. 消费凭证

### 4.1 明文消费

默认使用国际算法 `RSA + AES(CBC)`:

```java
List<ConsumeResult> results = client.consumeCredential(ConsumeOptions.builder()
        .accessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx")
        .credentialNameList("credential_name_1", "credential_name_2")
        .build());
```

需要国密时通过 `crypto` 覆盖:

```java
List<ConsumeResult> results = client.consumeCredential(ConsumeOptions.builder()
        .accessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx")
        .credentialNameList("credential_name_1", "credential_name_2")
        .crypto(new CryptoInfo(CryptoType.SM2, CryptoType.SM4, CryptoMode.CBC))
        .build());
```

多租户环境下, 可通过 `tenantId` 指定目标租户; 未设置时不携带该 header:

```java
List<ConsumeResult> results = client.consumeCredential(ConsumeOptions.builder()
        .accessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx")
        .credentialNameList("credential_name_1")
        .tenantId("tenant_name")
        .build());
```

| 选项                 | 必填 | 默认值            | 说明                                                                 |
| -------------------- | ---- | ----------------- | -------------------------------------------------------------------- |
| `tenantId`           | 否   | 无                | 目标租户 ID, 仅限多租户场景使用                                      |
| `accessKeySecret`    | 是   | 无                | 调用方的 Access Key / Secret Key                                     |
| `credentialNameList` | 否   | 空 (返回全部凭证) | 要消费的凭证名称列表, 不指定则返回该 AK 唯一绑定凭证组下的全部凭证    |
| `crypto`             | 否   | `RSA + AES(CBC)`  | 混合加密算法组合                                                     |

当前支持的算法组合:

| 维度     | 常量                                                       |
| -------- | ---------------------------------------------------------- |
| 非对称   | `CryptoType.RSA` / `CryptoType.SM2`                        |
| 对称     | `CryptoType.AES` / `CryptoType.SM4`                        |
| 分组模式 | `CryptoMode.CBC` / `CryptoMode.CTR`                        |

### 4.2 信封消费

需要密文信封而非明文时 (如先落库或交由其他进程解密), 换用 `consumeCredentialEnvelope`:

```java
ConsumeEnvelope envelope = client.consumeCredentialEnvelope(ConsumeOptions.builder()
        .accessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx")
        .credentialNameList("credential_name_1")
        .build());

// envelope.envelope()  -> Base64 密文信封
// envelope.privateKey() -> 本次临时生成的私钥 (Base64)
```

需要明文时, 通过 `Client.decryptEnvelope` 本地解密:

```java
List<ConsumeResult> results = Client.decryptEnvelope(envelope);
```

## 5. 处理返回值

`consumeCredential` 与 `decryptEnvelope` 均返回 `List<ConsumeResult>`, 遵循请求级异常 + 单条 err_code 的两级错误模型:

- 抛出 `KmsException`: 请求失败, 无结果可处理;
- 未抛出: 请求成功, 遍历 `results`, 单条是否成功看 `errCode()`。

### 5.1 ConsumeResult

| 字段            | 类型          | 说明                       |
| --------------- | ------------- | -------------------------- |
| `credentialId`  | `long`        | 凭证 ID                    |
| `errCode`       | `int`         | `0` 成功; 非 `0` 该条失败  |
| `errMsg`        | `String`      | 失败原因                   |
| `credential`    | `Credential`  | 成功时返回, 失败为 `null`  |

单条 `errCode` 常量位于 `com.tencent.bk.kms.types.ErrorCodes`, 可用 `ErrorCodes.isOk(errCode)` 快速判断。常用如下:

| 常量                                    | 值        | 含义             |
| --------------------------------------- | --------- | ---------------- |
| `ERR_CODE_OK`                           | `0`       | 成功             |
| `ERR_CODE_GENERIC_ERROR`                | `1034000` | 系统错误         |
| `ERR_CODE_NOT_FOUND`                    | `1034003` | 未找到           |
| `ERR_CODE_PERMISSION_DENIED`            | `1034008` | 无权限           |
| `ERR_CODE_REQUEST_TIME_TOO_SKEWED`      | `1034016` | 请求时间偏差过大 |

其中 `ERR_CODE_REQUEST_TIME_TOO_SKEWED` 表示本机与服务端时间偏差过大, 收到该错误 SDK 会依据响应 `Date` 头自动校正时钟偏移并重试一次。

### 5.2 Credential

| 字段          | 类型              | 说明                        |
| ------------- | ----------------- | --------------------------- |
| `name`        | `String`          | 凭证名称                    |
| `type`        | `CredentialType`  | 凭证类型                    |
| `authInfo`    | `AuthInfo`        | 凭证明文, 字段随 `type` 而异 |
| `annotation`  | `String`          | 凭证注解                    |

### 5.3 AuthInfo

按 `type` 取对应字段:

| type                        | 取值                                     |
| --------------------------- | ---------------------------------------- |
| `SINGLE_PASSWORD`           | `authInfo.password()`                    |
| `USERNAME_PASSWORD`         | `authInfo.username() / authInfo.password()` |
| `SINGLE_SECRET_KEY`         | `authInfo.secretKey()`                   |
| `APP_ID_SECRET_KEY`         | `authInfo.appId() / authInfo.secretKey()` |

## 6. Spring Boot Starter

### 6.1 配置

在 `application.yml` 中声明:

```yaml
bk:
  kms:
    base-url: "http://xxxx:23681"
    direct: true
    access-key: "your_access_key_xxxx"
    secret-key: "your_secret_key_xxxx"
    timeout: 30s
    crypto:
      asymmetric-type: RSA
      symmetric-type: AES
      symmetric-mode: CBC
    placeholder:
      enabled: true
```

Starter 自动构建并注册 `com.tencent.bk.kms.consume.Client` Bean, 可直接 `@Autowired` 使用。若已提供自定义 `Client` Bean, 自动装配会自动后退。

### 6.2 `KMS:xxx` 配置占位符

在任意配置项中直接使用 `KMS:` 前缀, 值会被自动解密:

```yaml
spring:
  datasource:
    # 单字段凭证 (single_password / single_secret_key)
    password: "KMS:demo_credential"

    # 多字段凭证 (username_password / app_id_secret_key) 需要显式指定 #field
    username: "KMS:mysql_cred#username"
```

支持的 `#field` 取值: `password`、`username`、`secret_key`、`app_id`。同名凭证在同一 JVM 生命周期内只会请求一次 KMS。

要禁用占位符解析, 设置 `bk.kms.placeholder.enabled=false` 即可, `KMS:xxx` 会原样保留。

## 7. 完整示例

- 明文消费: [../examples/consume-example](../examples/consume-example)
- 信封消费: [../examples/consume-envelope-example](../examples/consume-envelope-example)
- Spring Boot 集成: [../examples/spring-boot-example](../examples/spring-boot-example)
