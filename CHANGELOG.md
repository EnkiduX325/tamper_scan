# 更新日志（Changelog）

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 计划中

- 增加 `tests/` 下的纯函数单元测试与 GitHub Actions CI；
- 扩展 Web Store 哈希比对与权限变化（diff）能力。

## [1.0.0] - 2026-11-10

首个公开版本。

### Added

- **15 个扫描模块**：Autoruns 广度兜底、注册表 Run/RunOnce、浏览器策略/Defender 排除项、
  浏览器主页/搜索/代理、Startup LNK、计划任务、服务、WMI 永久订阅、Hosts/DNS、BITS 作业、
  PowerShell Profile、COM 劫持、LSA/AppInit/IFEO、浏览器扩展深度检测、LOLBin 进程与内存扫描。
- **四层判定漏斗**：广度采集 → 静态 Authenticode 信任链（嵌入签名 + 目录签名兜底）→
  内容/行为特征 → 进程内存 YARA。
- **统一 Finding 模型**：`severity/category/target/detail/evidence/rule_id`，按
  `target + 规则基名` 去重、按严重等级排序、支持白名单 `downgrade/filter/off`。
- **CLI**（`main.py`）：`--scan/--quiet/--format/--output/--module/--no-memory` 等参数，
  退出码 `2/1/0` 便于自动化调度。
- **GUI**（`gui.py`）：tkinter/ttk Fluent 风格界面，五色统计卡片、结果列表、详情面板、
  进度条、一键导出 HTML/JSON；后台线程扫描，界面不阻塞。
- **报告**（`reporter.py`）：JSON 与自包含 HTML（Jinja2 autoescape 强制开启），
  无外部资源、可离线转发。
- **配置外置**：`rules/whitelist.json`、`rules/extension_weights.json`、
  `rules/lolbin_rules.json`、`rules/yara/*.yar`，规则可直接维护而无需改代码。
- **打包**：`build.bat` 一次生成 CLI 与 GUI 两个 onefile exe；
  GUI 使用 `--windowed`，内部子进程统一隐藏窗口，运行时不闪控制台/黑框。
- **文档**：README（含权限降级说明、GUI 指南与打包指南）、SECURITY.md、
  CONTRIBUTING.md、脱敏后的演示报告与界面截图。

### Security

- 默认不强制提权；标准用户下内存扫描/BITS 全用户/Defender 排除项按设计降级为
  `SKIPPED`（明确“未检查”，不误判为安全）。
- HTML 报告全字段自动转义，外部输入不拼接原始 HTML。
- 仓库不包含用户个人数据；样例报告与截图已脱敏（主机名/用户名/路径均为示例值）。
