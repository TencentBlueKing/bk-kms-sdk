# 开发指南

Python SDK 的开发规范, 通用规范 (Commit 信息、分支模型等) 遵循仓库根 [CONTRIBUTING](../CONTRIBUTING.md)。

## 代码规范

格式由本目录 `pyproject.toml` 约束。

## 构建与验证

需要 Python `>=3.11,<3.15`。进入本目录 (`python/`) 后执行:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev,gm]"
make lint
make test
make build
```

## 示例

新增能力时请同步在 `examples/` 下补充可运行示例, 并在本目录 `README.md` 中登记入口。
