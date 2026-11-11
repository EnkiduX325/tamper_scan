# 更新日志（Changelog）

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 计划中

- 扩展 Web Store 哈希比对与权限变化（diff）能力；
- 模块 1 后续增强：只删改部分 `SD` 的结构校验（Tarrask 变体）；
- 模块 2 后续增强：IPv6 远端地址（`FWP_BYTE_ARRAY16` 指针）解析与 NDR 布局跨版本兼容；
- 模块 3 后续增强：RDP 配置类后门（`fDenyTSConnections` / 端口 / 影子会话等）。

## [1.3.0] - 2026-11-11

V1.3「基线对比（Baseline Diff）」：新增基线对比引擎，把静态扫描升级为动态判篡改——
按 `(target, rule_base)` 主键对比历史基线与当前扫描，输出 NEW / RESOLVED / ESCALATED /
DOWNGRADED / MODIFIED / UNCHANGED 六种状态；新增 4 个 CLI 参数与 GUI 基线交互；
不传新参数时扫描行为、JSON 结构与退出码与 V1.2 完全一致。模块总数仍为 **20**。

### Added

- **基线对比引擎**（`core/baseline.py`）：
  - 主键 `(target 归一化, rule_base)`：`rule_base` 剥离 `AUTORUNS_` / `SVC_` / `RDP_` 等采集层
    前缀，并兼容 `evidence.merged_rules`，避免规则合并导致同一事实被误判 `NEW`；
  - 六种状态：`NEW`（新增）、`RESOLVED`（消失）、`ESCALATED`（升级）、`DOWNGRADED`（降级）、
    `MODIFIED`（状态指纹 / 哈希变化）、`UNCHANGED`（一致）；
  - fingerprint：只提取 `signature.status` / `signature.signer` / `pe.CompanyName` / `actual` /
    `service.path_name` / `task.sd_present` / `task.index` 等稳定字段，剥离 `timestamp` / `pid`
    等易变字段后计算 SHA256；
  - `enrich_findings_with_hashes()`：为 HIGH/MEDIUM 本地文件 target 写入 `evidence.sha256`；
    “签名有效但文件哈希改变，高度疑似被篡改” → 判定 `MODIFIED` 并强制 `HIGH`。
- **CLI 基线参数**（`main.py`，向后兼容）：
  - `--save-baseline PATH`：扫描后保存完整 JSON 基线（不对比；与 `--baseline` 同时给出时保存优先）；
  - `--baseline PATH`：加载基线并对比，报告每条 Finding 带 `diff_status`；
  - `--fail-on-new`：存在 `NEW` 的 HIGH/MEDIUM 时强制退出码 `2`（NEW 的 LOW/INFO 不触发）；
  - `--hash-targets`：为 HIGH/MEDIUM 本地文件写入 `evidence.sha256`，可配合 `--save-baseline`。
- **报告基线展示**（`reporter.py`）：
  - 启用 `--baseline` 时 JSON 顶层新增 `baseline{path,generated_at}`，每条 Finding 新增
    `diff_status`，`summary` 新增 `diff_counts`；`RESOLVED` 条目保留在报告中但不计入
    `summary.counts` / 退出码；
  - HTML 新增「基线对比」统计（NEW / MODIFIED / ESCALATED 等）、状态徽章
    （NEW 红、MODIFIED 橙、ESCALATED 红底加粗、DOWNGRADED 黄、RESOLVED 灰底+删除线）与
    「⚠️ 此项目与基线相比发生变化」警告横幅；不启用基线时 HTML 与 V1.2 一致。
- **GUI 基线交互**（`gui.py`）：「对比基线」「保存为基线」按钮，结果列表新增「状态」列，
  显示「对比基线: <文件名>」与 X 取消对比；导出报告自动带基线 diff 信息。
- **测试与 CI**：新增基线对比测试（`tests/test_baseline*.py`，覆盖引擎 / CLI / 报告 / GUI
  纯函数），CI 与 `tools/verify_v13.ps1` 增加基线引擎六状态自检与 CLI 基线参数断言；
  单元测试总数 426 条（V1.3 起，含基线对比测试）。

### Changed

- 版本号升级为 `1.3.0`（`core/version.py` 唯一来源）；README 新增/更新基线使用章节、CLI 参数、
  JSON / HTML 结构、GUI 说明、目录树与本地校验脚本引用（`tools/verify_v13.ps1`）。
- 退出码：启用基线对比时按“当前扫描 Finding（排除 `RESOLVED`）”重算；`--fail-on-new`
  为额外强制条件。未启用新参数时退出码/报告结构与 V1.2 完全一致。
- 模块总数保持 **20**，任何扫描模块的规则与严重等级语义均未改变。

### Fixed

- 基线解析异常（文件缺失 / JSON 损坏 / 根节点非对象 / 缺 `findings` 列表）统一降级为
  `[WARN]` 并跳过对比，不再可能因基线输入中断扫描；
- 保证不启用基线参数时 JSON / HTML / 退出码与 V1.2 结构一致（无 `baseline` /
  `diff_status` / `diff_counts` / `sha256` 新增键的回归保护）。

### Security

- 基线文件视为**用户输入**：所有字段通过防御性解析（缺失/类型不符不抛异常），损坏的基线只
  输出 WARNING 并跳过对比，避免恶意/误改基线导致扫描器崩溃；
- 基线与当前主机名/版本不一致时只提示 WARNING，不静默忽略差异；
- 基线是完整报告的快照，包含主机名/用户名/路径等敏感信息，文档明确提示不要提交真实个人数据；
- `--hash-targets` 只读取本地文件计算哈希，不修改、不执行任何文件；基线对比全程只读，
  不触发任何处置动作。

## [1.2.0] - 2026-11-11

V1.2「冷门持久化与只读修复建议」：模块总数增至 **20**（新增 `persistence_ext`），扩展
`lsa_appinit` 的 Winlogon 检测与 `service` 的 ServiceDll 校验，新增只读修复建议机制；
协议由 MIT 变更为 **CC BY-NC 4.0**（严禁未授权商用）；单元测试 **312** 条。

### Added

- **新增模块 `persistence_ext`（阶段 8，第 20 个模块）**：覆盖 10 个冷门持久化扩展点 ——
  Netsh Helper DLL（`NETSH_HELPER_TAMPER`）、W32Time TimeProvider（`TIMEPROVIDER_DLL_TAMPER`）、
  Print Processor / Monitor（`PRINT_PROCESSOR_TAMPER` / `PRINT_MONITOR_TAMPER`）、
  Active Setup StubPath（`ACTIVE_SETUP_STUB`）、AppCompat 自定义 Shim（`APPCOMPAT_SHIM`）、
  SilentProcessExit MonitorProcess（`SILENTPROCESS_EXIT_TAMPER`）、
  WER LocalDumps（`WER_LOCALDUMPS_TAMPER`）、CMD AutoRun（`CMD_AUTORUN`）、
  屏幕保护程序（`SCRNSAVER_TAMPER`）；采集失败按统一契约降级为 `SKIPPED`。
- **`lsa_appinit` 增加 Winlogon / 自动登录检测（8 条规则）**：
  `WINLOGON_SHELL_TAMPER`、`WINLOGON_USERINIT_TAMPER`、`WINLOGON_GINADLL_TAMPER`、
  `WINLOGON_APPSETUP_TAMPER`、`WINLOGON_TASKMAN_TAMPER`、`WINLOGON_NOTIFY_TAMPER`、
  `AUTOADMINLOGON_PLAINTEXT`、`LSA_AUTH_PACKAGE_TAMPER`。
- **只读修复建议机制**：新增 `rules/remediation.json`（按 `rule_id` 索引的 `summary` / `expected` / `actual` / `command` / `risk` / `requires_admin`），
  `reporter` 为命中的 Finding 挂载 `remediation` 字段并在 HTML 报告渲染「建议处理」区块，
  GUI 详情面板展示建议并支持一键复制命令；**扫描器绝不执行任何命令**。
- `tools/verify_v12.ps1`（由 `tools/verify_v11.ps1` 更名）新增 LICENSE / README 协议断言。

### Changed

- 版本号升级为 `1.2.0`（`core/version.py` 唯一来源）；模块总数 19 → 20，`--list-modules`、
  JSON 报告 `modules_total` / `modules_available`、样例报告与 CI / verify 断言同步更新。
- `service` 泛化 `ServiceDll` 校验：文件缺失 → `SVC_SERVICEDLL_ABSENT`；
  系统目录外且签名非有效微软签名 → `SVC_SERVICEDLL_TAMPER`；
  与 `credential_rdp` 的 `RDP_SERVICEDLL_TAMPER` / `RDP_SERVICEDLL_ABSENT` 自动去重合并。
- README 更新 V1.2 说明、§9.2 规则清单（Winlogon 8 条 / persistence_ext 10 条 / ServiceDll 2 条）、
  第 20 个模块与 20 模块完整清单、修复建议（只读）机制说明；`--collect-submodules`、
  打包/测试局限、目录结构等处的模块数描述统一为 20。
- 单元测试扩展至 **312 条**（V1.2 起），CI 继续执行 `python -m pytest -q`。

### Removed

- 移除 README 顶部的 MIT 徽章与 MIT 授权声明，替换为 CC BY-NC 4.0 提示行与 §11 许可协议章节。
- 删除旧的 `tools/verify_v11.ps1`（内容并入 `tools/verify_v12.ps1`）。
- `service` 与 `credential_rdp` 对同一服务 `ServiceDll` 目标的重复上报改为自动去重合并。

### Security

- **协议变更（重要）**：本项目自 V1.2 起采用 **CC BY-NC 4.0**（知识共享 署名-非商业性使用
  4.0 国际许可协议），替代原 MIT 协议；**严禁未经授权的商业用途**，完整文本见 `LICENSE`，
  协议说明见 README §11 与 <https://creativecommons.org/licenses/by-nc/4.0/>。
- 只读修复建议全程仅展示 / 复制文本：扫描器、报告生成与 GUI 均不执行 `remediation.command`，
  也不做 shell 拼接执行，避免把“建议”变成自动处置风险。
- `persistence_ext` / Winlogon / ServiceDll 检测均遵循统一降级策略：权限不足或结构异常显式
  上报 `SKIPPED`，不误判为安全。

## [1.1.0] - 2026-11-10

V1.1「高级威胁检测」：在 1.0.0 的 15 个模块基础上新增 **4 个红队维度检测模块**（计划任务隐藏、
WFP 持久化过滤器 / EDR Silencer、凭证与 RDP 后门、未加引号服务路径），模块总数 **19**；
新增 **140 条单元测试**并接入 CI（`python -m pytest -q`）。

### Added

- **V1.1 高级威胁检测 · 模块 1：计划任务隐藏检测（Tarrask）**
  - 新增 `modules/scheduled_task_hidden.py`：递归遍历
    `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`，
    子键缺少 `SD` 值（或为空/非二进制）或 `Index` 为 `0x0` 时上报 **HIGH
    `TASK_HIDDEN_TARRASK`**；对可疑节点追加读取 `TaskCache\Tasks\<GUID>` 的
    `Actions` 命令行作为 evidence（T1053.005 / T1685）。
  - 采集失败按项目约定降级：`TASK_HIDDEN_ACCESS_DENIED`（标准用户读不到 TaskCache）、
    `TASK_HIDDEN_SKIPPED`、`TASK_HIDDEN_PARTIAL`（部分子键读取失败），不抛异常。
  - 降噪：`Index==0` 但无对应 `Tasks\<Id>` 定义的历史残留键默认降为 MEDIUM
    （模块常量 `STALE_INDEX_ZERO_SEVERITY`，可改回 `"HIGH"`），evidence 附
    `stale_candidate` 与 `Tasks` 动作命令行，便于人工确认。
  - `core/scanner.py` 注册第 16 个模块（阶段 7），CLI/GUI 自动纳入扫描与
    `--list-modules`。

- **V1.1 高级威胁检测 · 模块 2：WFP 持久化过滤器检测（EDR Silencer）**
  - 新增 `modules/wfp_filter.py`：读取
    `HKLM\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Filter`，
    按 BFE 持久化对象格式（16 字节头 + NDR 编码的 `BFE_PERSISTENT_OBJECT`）解析二进制，
    用 `FWPM_FILTER0` 字段偏移定位过滤器结构，并扫描 condition 记录还原远端 IP/端口/应用条件。
  - 规则：`WFP_EDR_SILENCER` HIGH（出站层 + BLOCK + ALE_APP_ID）、
    `WFP_BLOCK_PUBLIC_IP` HIGH（阻断公网 IPv4）、`WFP_BLOCK_REMOTE_PORT` HIGH
    （阻断出站远端端口）、`WFP_BLOCK_FILTER` MEDIUM（其它非系统阻断过滤器）。
  - 系统过滤器（`FWPM_SUBLAYER_MPSSVC_*` 子层或 `@...` 资源显示名）自动跳过；
    解析失败的二进制记 `SKIPPED / WFP_FILTER_UNPARSED`（未检查 ≠ 安全）。
  - 降级：`WFP_ACCESS_DENIED`（标准用户读不到 BFE Policy）、`WFP_SKIPPED`、`WFP_PARTIAL`。
  - `core/scanner.py` 注册第 17 个模块（阶段 7）。

- **V1.1 高级威胁检测 · 模块 3：凭证与 RDP 后门检测**
  - 新增 `modules/credential_rdp.py`：检测
    `HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order` 的 `ProviderOrder`
    是否被插入陌生/被替换的 Network Provider（对照微软基线
    `RDPNP/P9NP/LanmanWorkstation/webclient`，校验 `ProviderPath` 的基线 DLL、系统目录、
    用户可写目录、文件存在性与微软签名），并交叉校验 `Order` 与 `HwOrder`；
  - 检测 `Services\TermService\Parameters` 的 `ServiceDll`：系统目录外、用户可写目录、
    文件名不是 `termsrv.dll`、文件缺失、无签名/签名无效、非微软签名 → HIGH
    `RDP_SERVICEDLL_TAMPER`；值缺失 → MEDIUM `RDP_SERVICEDLL_ABSENT`；
  - 规则：`NP_PROVIDER_TAMPER` / `NP_UNKNOWN_PROVIDER`（LOW，系统目录 + 微软签名）/
    `NP_ORDER_MISMATCH` / `NP_ORDER_ABSENT`；网络提供者与 RDP 两部分**独立降级**
    （`NP_ACCESS_DENIED` / `RDP_ACCESS_DENIED`），实测标准用户通常可读这两处键；
  - `core/scanner.py` 注册第 18 个模块（阶段 7）。

- **V1.1 高级威胁检测 · 模块 4：未加引号的服务路径提权（Unquoted Service Path）**
  - 新增 `modules/unquoted_service_path.py`：**复用 `service` 模块的 CIM 采集结果**
    （`service.collect_services(max_age_seconds=180)` 短时缓存，同一次扫描只查询一次
    `Win32_Service`），不重复造采集轮子；
  - 规则：`ImagePath` 含空格且未以双引号完整包裹、且 `StartName` 为 SYSTEM 类账户
    （`LocalSystem` / `NT AUTHORITY\LocalSystem` / `NT AUTHORITY\SYSTEM`）→
    **MEDIUM `SVC_UNQUOTED_PATH`**（T1574.009）；
  - evidence 附带候选劫持路径（按空格拆分的 `*.exe`）与"当前用户可写的候选目录"，
    便于判断真实可利用性；畸形/只有开引号的路径按 MEDIUM 提示需人工确认；
  - 采集失败/结构异常/超限：`SVC_UNQUOTED_SKIPPED` / `SVC_UNQUOTED_PARSE_ERROR` /
    `SVC_UNQUOTED_PARTIAL`（SKIPPED，未检查 ≠ 安全）；
  - `service.py` 新增可复用的 `collect_services()` / `normalize_service_records()` /
    `clear_service_cache()`（`scan()` 行为保持不变，有回归测试）。

- **开发工具（V1.1）**：新增 `tools/verify_v11.ps1`（本地一键复现 CI：
  `compileall` + `pytest` + `ruff` + 版本/模块数/样例报告断言，退出码 0 表示全部通过）与
  `tools/regenerate_sample_report.py`（重新生成并脱敏演示报告：用户目录/主机名/用户名/域替换、
  按 `MODULE_REGISTRY` 归一 19 个模块状态、重渲染 HTML）；README §8.1 增加使用说明。

### Fixed

- **模块 1 加固补丁（V1.1 统一合并前）**：
  - 遍历达到深度/节点上限时不再静默漏报：`TASK_HIDDEN_PARTIAL` 显式上报截断数量；
  - 节点上限改为在 `append` 前检查，修复单层海量子键可一次突破 `_MAX_NODES` 的问题；
  - 新增 `Index` 值删除变体检测：任务节点（含 `Id`）缺少 `Index` → HIGH
    `TASK_HIDDEN_TARRASK`（`evidence.reasons` 含 `index_missing`）；
  - 模块 1 测试增至 34 条（模块 1/2/3/4 + 采集复用层共 140 条）。

### Tests

- 新增 `tests/` 纯函数单元测试 140 条，无需管理员权限、不依赖本机是否被入侵：
  `tests/test_scheduled_task_hidden.py`（34）、`tests/test_wfp_filter.py`（31）、
  `tests/test_credential_rdp.py`（35）、`tests/test_unquoted_service_path.py`（29）、
  `tests/test_service_collect.py`（11）；
- CI（`.github/workflows/ci.yml`）新增 `python -m pytest -q` 步骤，并在
  `compileall` 中纳入 `tests/`，同时校验样例报告版本号/模块数。

### Security

- 需要管理员权限才能读的持久化位置（`TaskCache\Tree`、BFE `Policy`）在标准用户下
  明确返回 `SKIPPED / TASK_HIDDEN_ACCESS_DENIED` / `WFP_ACCESS_DENIED`，不误判为安全；
- 模块 3 的 `NetworkProvider` / `TermService\Parameters` 在实测 Windows 11 上标准用户可读，
  因此普通用户也能得到真实检测结果；加固系统 ACL 收紧时按部分降级，两部分互不影响；
- 模块 4 复用 `service` 模块采集结果（180s 短时缓存），单次扫描只查询一次
  `Win32_Service`，避免重复调用 CIM 带来的开销与不一致。

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
