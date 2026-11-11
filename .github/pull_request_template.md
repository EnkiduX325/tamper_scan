## 变更描述

<!-- 这个 PR 做了什么？为什么需要它？ -->

## 关联 Issue

<!-- 例如：Closes #123 / Related to #45；无关联可写 N/A -->

## 测试情况

<!-- 在 Windows 10/11 + Python 3.10+ 上执行过的检查 -->

- [ ] `python -m compileall -q core modules main.py gui_qt.py reporter.py`
- [ ] `python -m ruff check .`
- [ ] `python -m pytest -q`（如有测试）
- [ ] 手动验证（说明命令/步骤）：

```text
（粘贴关键输出或说明）
```

## 是否涉及安全敏感逻辑

- [ ] 否
- [ ] 是 → 请说明涉及范围（签名校验 / 内存扫描 / HTML 转义 / 权限判断 / 白名单规则 / 其他），并说明测试方式：

## 检查清单

- [ ] 未提交 `dist/`、`tools/autorunsc64.exe`、`build/`、`*.spec` 等二进制或构建产物
- [ ] 未提交真实扫描报告、未脱敏截图或其他个人隐私信息
- [ ] 未修改 `core/` 与 `modules/` 的扫描逻辑（如确需修改，已在本 PR 说明理由并附测试）
- [ ] 已更新 `CHANGELOG.md` 的 `[Unreleased]` 段
- [ ] 文档/README 与行为变化保持一致
