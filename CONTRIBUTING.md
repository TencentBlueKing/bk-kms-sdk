# 开发指南

开发前需先阅读了解项目的代码规范以及代码提交规范。

BK-KMS-SDK 按语言划分子目录, 每种语言的实现有各自的规范文件, 请结合本文一起阅读。

- [GOLANG CONTRIBUTING](go/CONTRIBUTING.md)

## 目录约定

- 每种语言 SDK 独立放在仓库根下的 `<language>/` 目录, 拥有独立的构建入口 (如 `go`);
- 仓库根下的 `docs/` 存放与具体语言无关的说明, 可以根据实际的场景需要灵活处理;
- 新增语言 SDK 时, 请同步在根`README.md` 的 Overview 和 Getting started 中登记入口;

## 代码提交规范

### 分支与Issue

请确保关键性的问题都关联其对应的 Issue, 并确保该 Issue 是否已经存在, 尽量将相同话题在一个 Issue 处理或进行关联, 不要冗余创建 Issue 话题。

- 关键特性需要关联 Issue;
- 代码提交需在单独的特性分支不要在 master 分支提交;

### Commit 信息格式

Each commit message should include a **type**, a **scope**, a **subject** and a **issue**:

Commit 信息需包含 **type**, **scope**(若需要), **subject**, **issue** (若有):

```
 <type>(<scope>): <subject>. issue #num
```

Commit 信息不要超过 100 个字符, 尽量保证内容的可读性, 比较好的提交示例如下,

```
 #8 feat(consume): add credential consume option. issue #202
 #7 fix(signature): fix nonce generation. issue #201
 #6 docs(project): update quickstart section. issue #200
```

#### Commit Type 类型说明

Commit Type 必须是下面类型中的一个:

- **feat**: 新特性
- **fix**: 修复问题
- **opt**: 逻辑优化
- **perf**: 性能优化
- **docs**: 仅仅文档更新
- **style**: 修改不影响代码逻辑的格式问题
- **refactor**: 既不是新特性也不是修复问题的重构
- **test**: 更新测试相关
- **chore**: 修改构建、部署等相关内容
- **release**: 版本发布单独使用的提交类型

#### Commit Scope 说明

Scope 为可选, 该信息需简短说明改动提交的关联内容, 如 `consume`, `signature`, `project` 等。

#### Commit Subject 说明

Subject 需简短准确描述改动内容:

- 准确适用时态语义: "change" not "changed" nor "changes"
- 首个字母不要大写
- 结尾不要使用中英文句号 (除非有关联的 issue 在后面), 多个简短描述可以使用 `;` 分隔, 但不建议单个 Commit 信息提交过多
