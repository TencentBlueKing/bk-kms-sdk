# 开发指南

Go SDK 的开发规范, 通用规范 (Commit 信息、分支模型等) 遵循仓库根 [CONTRIBUTING](../CONTRIBUTING.md)。

## 代码规范

[golang style guide](https://go.dev/doc/effective_go)

## 构建与验证

进入本目录 (`go/`) 后执行:

```bash
go build ./...
```

## 示例

新增能力时请同步在 `examples/<capability>/` 下补充一个可运行的最小示例, 并在本目录 `README.md` 中登记入口。
