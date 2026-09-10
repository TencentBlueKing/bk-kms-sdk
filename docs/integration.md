# BK-KMS 凭证管理集成方案

蓝鲸智云凭证管理服务（BlueKing Key Management Service，简称 BK-KMS）提供一套控制面统一纳管凭证、数据面可信身份消费、全链路密文流转的凭证托管与集成方案, 本文档从集成角度对方案做详细介绍。

![凭证托管与消费全景](img/bk_kms_product.svg)

## 方案总览

集成方案按职责自上而下分为四层：控制面、凭证存储、注入层、业务消费层。凭证在录入后以密文形式流转，仅在业务应用运行时解密使用，业务侧无需持久化敏感数据。

### 控制面

- **系统运维/平台服务**：负责凭证录入与凭证管理;
- **凭证管理服务**：凭证存储的控制面，负责元数据管理，并将凭证写入底层存储;

### 凭证存储

- **OpenBao/Vault**：作为底层密钥存储，遵循行业密钥管理标准，支持多租户隔离与命名空间级凭证托管;

### 注入层

基于 K8S ServiceAccount 的可信身份从存储中消费凭证，并同步/轮转到业务侧，支持两种集成方式：

- **Agent Injector**：以 Sidecar 方式将密文挂载为文件;
- **ESO（External Secrets Operator）**：将密文同步为 K8S Secret;

### 消费层

业务 Pod 在应用运行时解密并使用凭证，对应两种消费形态：

- **Secret 消费(推荐)**：凭证注入 K8S Secret，应用运行时解密使用;
- **文件消费**：凭证以文件形式挂载，应用运行时解密使用;

## ESO（External Secrets Operator）凭证消费

**0. 业务 ServiceAccount —— 访问 OpenBao 的可信身份: **

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-prod-sa
  namespace: app-prod
```

**1. SecretStore —— 用 SA Token 认证连接 OpenBao: **

```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: openbao-store
  namespace: app-prod
spec:
  provider:
    vault:
      # 蓝鲸 KMS 托管的 OpenBAO 服务地址
      server: "https://openbao.bk-kms.svc:8200"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "app-prod-reader"
          serviceAccountRef:
            name: "app-prod-sa"
```

**2. ExternalSecret —— 同步指定凭证生成 K8S Secret: **

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-mysql-credential
  namespace: app-prod
spec:
  refreshInterval: "1h"
  secretStoreRef:
    name: openbao-store
    kind: SecretStore
  target:
    # 蓝鲸 KMS 凭证转为 Secret
    name: app-mysql-secret
    creationPolicy: Owner
  data:
    - secretKey: privateKey
      remoteRef:
        key: default/my-scope/mysql        # 蓝鲸 KMS 托管的 OpenBAO 凭证路径: {租户ID，非多租户为default}/{scope，业务名称}/{凭证名称}
        property: private_key              # 蓝鲸 KMS 托管的 OpenBAO 凭证私钥字段名, 约定为 'private_key'
    - secretKey: envelope
      remoteRef:
        key: default/my-scope/mysql        # 蓝鲸 KMS 托管的 OpenBAO 凭证路径: {租户ID，非多租户为default}/{scope，业务名称}/{凭证名称}
        property: envelope                 # 蓝鲸 KMS 托管的 OpenBAO 凭证信封字段名, 约定为 'envelope'
```

**3. Deployment —— Pod 以 SA 运行，凭证挂载为文件: **

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-server
  namespace: app-prod
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app-server
  template:
    metadata:
      labels:
        app: app-server
    spec:
      serviceAccountName: app-prod-sa
      containers:
        - name: app
          image: your-registry/app-server:v1.0.0
          env:
            - name: MYSQL_PRIVATE_KEY_ENV_NAME     # 业务 POD 内将 ESO 同步的 Secret 中的 'privateKey' 挂载为环境变量，变量名业务自定义
              valueFrom:
                secretKeyRef:
                  name: app-mysql-secret
                  key: privateKey
          volumeMounts:
            - name: mysql-cred
              mountPath: "/etc/secrets/mysql"      # 业务 POD 内将 ESO 同步的 Secret 中的 'envelope' 挂载为文件, 路径为/etc/secrets/mysql/envelope
              readOnly: true
      volumes:
        - name: mysql-cred
          secret:
            secretName: app-mysql-secret
            items:
              - key: envelope
                path: envelope
            defaultMode: 0400
```

如上所示，依据 K8S ServiceAccount 使用 ESO 方案实现业务凭证的注入, 业务 POD 内将会得到凭证对应的密文文件和私钥变量，使用 KMS SDK 中的解密函数即可得到明文。
