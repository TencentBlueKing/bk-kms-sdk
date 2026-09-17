# BK-KMS Java SDK

蓝鲸凭证管理服务 (BlueKing - Key Management Service) Java 版官方 SDK。

## 模块结构

| 模块 | 说明 |
| ---- | ---- |
| `kms-core-sdk` | 核心 SDK。不依赖 Spring, 提供 `Client` 接口用于消费凭证。 |
| `kms-spring-boot-starter` | Spring Boot 3.x Starter。提供自动装配以及 `KMS:xxx` 配置占位符解密。 |
| `examples/consume-example` | 直连模式一步式消费凭证示例。 |
| `examples/consume-envelope-example` | 两段式获取信封 + 本地解密示例。 |
| `examples/spring-boot-example` | 使用 Starter + `KMS:xxx` 占位符的最小 Spring Boot 应用。 |

## Maven 坐标

```xml
<!-- 仅使用核心能力 -->
<dependency>
    <groupId>com.tencent.bk.kms</groupId>
    <artifactId>kms-core-sdk</artifactId>
    <version>1.0.0-alpha.1</version>
</dependency>

<!-- Spring Boot 3.x 应用推荐直接使用 Starter -->
<dependency>
    <groupId>com.tencent.bk.kms</groupId>
    <artifactId>kms-spring-boot-starter</artifactId>
    <version>1.0.0-alpha.1</version>
</dependency>
```

## 环境要求

- Java 17+
- Spring Boot 3.x (仅使用 Starter 时需要)

## 快速开始

```java
Client client = Client.create(ClientOptions.builder()
        .baseUrl("http://xxxx:23681")
        .direct(true)
        .appCode("your_app_code_xxxx")
        .build());

List<ConsumeResult> results = client.consumeCredential(ConsumeOptions.builder()
        .accessKeySecret("your_access_key_xxxx", "your_secret_key_xxxx")
        .credentialNameList("credential_name_1", "credential_name_2")
        .build());
```

详细说明请参见 [docs/quickstart.md](docs/quickstart.md)。

## 构建

```bash
mvn -f java/pom.xml clean package
```

## 许可证

基于 MIT License 开源。
