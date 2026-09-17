# BK-KMS-SDK Java 版本

运行时解密还原凭证明文，信封格式由 KMS 服务约定，调用方无需关心。

## 运行环境

- Java `>=17`
- 默认支持 RSA、AES、SM2、SM4（基于 BouncyCastle），无需额外配置

## Maven 坐标

```xml
<dependency>
    <groupId>com.tencent.bk.kms</groupId>
    <artifactId>bk-kms-sdk</artifactId>
    <version>1.0.0-alpha.1</version>
</dependency>
```

## 快速开始

```java
import com.tencent.bk.kms.decrypt.Decrypt;

public class Demo {
    public static void main(String[] args) {
        String envelope = "your_envelope";       // Base64 hybrid envelope from KMS
        String privateKey = "your_private_key";  // Base64-of-PEM private key

        String plaintext = Decrypt.decrypt(envelope, privateKey);
        System.out.println(plaintext);
    }
}
```

## 示例

见 [examples/decrypt](examples/decrypt)。

## 构建

```bash
mvn -f java/pom.xml clean package
```

## License

项目基于 MIT 协议，详细请参考 [LICENSE](../LICENSE)。
