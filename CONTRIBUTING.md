# 贡献指南（Contributing）

感谢你愿意为 TamperScan 做出贡献！本文说明本地开发、测试、代码风格与 PR 流程。

## 环境准备

- Windows 10 / 11（x64）；本项目仅支持 Windows。
- Python **3.10+**（推荐 3.10 / 3.11）。
- 建议使用虚拟环境：

```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements-build.txt
```

> `requirements.txt` 是运行依赖，`requirements-build.txt` 额外包含 PyInstaller 与测试/构建所需工具。
> 进程内存扫描依赖可选的 `skrapa`（未安装时相关检查按设计降级为 `SKIPPED`）。
> 外部工具 `tools/autorunsc64.exe` 属 Microsoft Sysinternals，**不在仓库中**；需要 Autoruns 模块时按
> [tools/README.txt](tools/README.txt) 从微软官方下载（缺失时 Autoruns 模块自动 `SKIPPED`）。

## 运行与验证

```bat
:: 快速冒烟（只跑一个模块，避免完整扫描耗时）
python main.py --scan --module network --quiet

:: 完整 CLI 扫描（约 30–60s）
python main.py --scan

:: GUI
python gui.py

:: 语法检查（不产生 __pycache__）
python -B -m compileall -q core modules main.py gui.py reporter.py
```

> CI 中**不会**运行真实扫描（依赖机器环境且耗时），只做静态检查与单元测试。

## 测试

- 测试脚本放在 `tests/` 目录，使用 `pytest`：

```bat
python -m pytest -q
```

- 新增/修复扫描规则时，请尽量添加**不依赖本机环境的纯函数测试**（例如规则匹配、去重排序、白名单命中、报告渲染）；
- 不要提交真实机器的扫描报告或个人路径；测试数据请使用脱敏后的样例。

## 代码风格

- 遵循 PEP 8；行宽 **120**；允许中文注释/日志（本项目面向中文用户）。
- 使用 [Ruff](https://docs.astral.sh/ruff/) 做静态检查：

```bat
python -m pip install ruff
python -m ruff check .
```

- 类型注解尽量完整（Python 3.10 语法，例如 `str | None`）。
- **不要修改 `core/` 与 `modules/` 中的扫描逻辑来"让结果好看"**；如需调整规则，优先改 `rules/` 下的 JSON/YARA 数据。
- 安全敏感改动（签名校验、内存扫描、HTML 转义、权限判断）请在 PR 描述中明确标注，并附测试。

## 提交 PR

1. Fork 仓库并从 `main` 创建分支：`git checkout -b feat/your-change`；
2. 保持改动聚焦（一个 PR 只做一件事），并更新 `CHANGELOG.md` 的 `[Unreleased]` 段；
3. 提交前本地执行：`python -m ruff check .` 与 `python -m pytest -q`（如有测试）；
4. PR 描述请包含：变更内容、关联 Issue、测试方式、**是否涉及安全敏感逻辑**；
5. 等待 CI 通过与维护者审查；合并后请删除分支。

## 不接受的改动

- 提交 `dist/`、`tools/autorunsc64.exe` 或其他二进制/构建产物；
- 提交包含个人隐私（用户名、设备名、真实路径、扫描报告）的截图或样例；
- 引入联网/遥测/上传数据的行为；
- 无测试、无说明地修改核心扫描判定。
