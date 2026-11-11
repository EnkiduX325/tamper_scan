# TamperScan

[![CI](https://github.com/EnkiduX325/tamper_scan/actions/workflows/ci.yml/badge.svg)](https://github.com/EnkiduX325/tamper_scan/actions/workflows/ci.yml)

> ⚠️ 本作品采用 CC BY-NC 4.0 协议，严禁商用。

开箱即用的 Windows 防篡改扫描器：直接运行即可扫描持久化位置与浏览器配置，输出按严重等级排序的可疑项报告。不依赖预先建立的基线，判定依据是启发式规则 + 数字签名信任链 + 内容特征 + 行为特征。

> ⚠️ 免责声明：本工具仅用于个人设备或已获得明确授权的安全评估。请勿用于未经授权的扫描。使用者应遵守当地法律法规，作者不对滥用行为承担责任。

![TamperScan 图形界面：扫描结果与详情面板](docs/screenshots/gui_results.png)

- 版本：`1.2.0`（唯一来源：[core/version.py](core/version.py)）
- **V1.2 更新（2026-11-11）**：
  - 许可证由 MIT 变更为 **CC BY-NC 4.0**（署名-非商业性使用），**严禁未经授权的商业用途**，详见 [§11](#11-许可协议)；
  - 新增第 20 个模块 `persistence_ext`「冷门持久化扩展点」（Netsh Helper / TimeProvider / Print 处理器与监视器 / Active Setup / AppCompat Shim / SilentProcessExit / WER LocalDumps / CMD Autorun / SCRNSaver 共 10 个检测点），模块总数 **20**，规则清单见 [§9.2](#92-v12-新增变更规则清单)；
  - `lsa_appinit` 增加 **Winlogon / AutoAdminLogon** 检测（8 条规则，覆盖 Shell / Userinit / GinaDll / AppSetup / TaskMan / Notify 篡改与明文自动登录）；
  - `service` 泛化 **ServiceDll** 校验（`SVC_SERVICEDLL_TAMPER` / `SVC_SERVICEDLL_ABSENT`，与 RDP 的 `ServiceDll` 检测自动去重合并）；
  - 新增**只读修复建议**（`rules/remediation.json`）：JSON / HTML / GUI 展示建议处理命令，**扫描器绝不执行任何命令**；
  - 单元测试扩展至 **312 条**（V1.2 起，`python -m pytest -q`）。
- **V1.1 新增 4 个高级威胁检测模块**（Tarrask 计划任务隐藏、WFP / EDR Silencer 持久化过滤器、
  凭证与 RDP 后门、未加引号服务路径）；详见 [§9.1](#91-v11-新增模块与规则清单)
- 支持：Windows 10 / 11（x64），Python 3.10+
- 单次扫描、无云端依赖；外部工具仅 Sysinternals `autorunsc64.exe`（缺失自动降级）

> 外部工具提示（重要）：本仓库不包含 Sysinternals 的 `autorunsc64.exe`（其许可不允许第三方再分发），请按 [tools/README.txt](tools/README.txt) 从微软官方下载后放入 `tools/`。若缺少该工具，Autoruns 模块会自动跳过（`SKIPPED`），扫描继续，其余模块不受影响（当前共 20 个模块）。

提供两种使用形态：

- GUI 版 `dist\tamper_scan_gui.exe`：双击即用、无控制台窗口，适合普通用户日常扫描与直观查看结果（图形界面详见 [§2](2-图形界面gui)）。
- CLI 版 `dist\tamper_scan.exe`：适合自动化、计划任务、脚本调度或 CI 流水线，通过退出码判断结果。

---

 1. 快速开始

 方式 A：图形界面（推荐普通用户）

```bat
dist\tamper_scan_gui.exe     :: 双击，或在命令行启动（无控制台窗口）
python gui.py                :: 源码方式启动
```

界面操作：点击「开始扫描」→ 查看左侧结果列表与右侧详情 → 点击「导出报告」保存 HTML/JSON。

 方式 B：命令行（适合自动化 / CI）

```bat
dist\tamper_scan.exe --scan
dist\tamper_scan.exe --scan --format both --output reports\scan
python main.py --scan --quiet --format both --output C:\reports\tamper
```

 方式 C：源码运行

```bat
python -m pip install -r requirements.txt
python main.py --scan        :: CLI
python gui.py                :: GUI
```

> `requirements.txt` 是运行依赖；打包 exe 另需 `python -m pip install -r requirements-build.txt`。
> GUI 无新增依赖：`gui.py` 仅使用 Python 标准库 `tkinter` / `ttk`，`requirements.txt` 保持原样即可。
> `skrapa` 为可选依赖（缺失时内存扫描返回 `SKIPPED / MEMORY_SKIPPED`），默认在 `requirements.txt` 中注释，需要内存扫描时自行 `pip install skrapa`。

 以管理员身份运行可得到完整结果

默认不强制提权（exe 无 UAC manifest，GUI 与 CLI 行为一致），标准用户可以正常使用大部分功能，但以下检查按设计降级为 `SKIPPED`（不是"没问题"）：

| 检查 | 标准用户行为 | 原因 |
|---|---|---|
| 进程内存 YARA（`MEMORY_`） | `SKIPPED / MEMORY_ACCESS_DENIED` | skrapa 读取进程内存前必须启用 `SeDebugPrivilege`，标准用户对任何进程（含自己）都会 `TokenPrivilegeError` |
| BITS 全用户作业（`BITS_`） | `SKIPPED / BITS_ACCESS_DENIED`，自动降级只查当前用户 | `Get-BitsTransfer -AllUsers` 需要管理员 |
| Defender 排除项（`POLICY_`） | `SKIPPED / POLICY_ACCESS_DENIED` | `Windows Defender\Exclusions` 键对标准用户拒绝访问 |
| 计划任务隐藏检测（`TASK_HIDDEN_`） | `SKIPPED / TASK_HIDDEN_ACCESS_DENIED` | `Schedule\TaskCache\Tree` 键对标准用户拒绝访问（Tarrask 检测需管理员） |
| WFP 持久化过滤器（`WFP_`） | `SKIPPED / WFP_ACCESS_DENIED` | `BFE\Parameters\Policy` 键对标准用户拒绝访问（EDR Silencer 检测需管理员） |

需要完整结果时：

- GUI：右键 `tamper_scan_gui.exe` → 以管理员身份运行；
- CLI：以管理员身份打开终端，再执行 `python main.py --scan` 或 `dist\tamper_scan.exe --scan`。

权限降级与界面提示详见 [§2.2](22-权限提醒与降级说明)。

---

 2. 图形界面（GUI）

`gui.py` 是 tkinter + ttk 实现的 Windows 11 Fluent 风格界面（浅灰背景、白色卡片、强调色 `0067C0`、Segoe UI），扫描核心与 CLI 完全复用 [core/scanner.py](core/scanner.py)，因此两种形态的模块顺序、白名单、去重排序、异常降级结果完全一致。

 2.1 两种形态对比

| 维度 | GUI 版 `tamper_scan_gui.exe` | CLI 版 `tamper_scan.exe` |
|---|---|---|
| 启动方式 | 双击即用（`--windowed`，无控制台窗口） | 终端 / 计划任务 / CI 脚本 |
| 结果展示 | 五色统计卡片 + 结果表格 + 详情面板 + 进度条 | 控制台逐条打印 + JSON/HTML 报告文件 |
| 自动化 | 不适合（交互式） | 适合：`--quiet` + 退出码 `2/1/0` |
| 报告导出 | 界面按钮导出 HTML/JSON（文件对话框） | `--format json\|html\|both --output PATH` |
| 典型用户 | 普通用户日常巡检、人工确认 | 运维/安全团队批量调度 |
| 权限完整度 | 取决于是否以管理员身份运行（见 2.2） | 同左 |

 2.2 权限提醒与降级说明

以管理员身份运行可获得最完整的结果：Defender 排除项、BITS 全用户作业、进程内存扫描（`MEMORY_`）、计划任务隐藏检测（`TASK_HIDDEN_`）、WFP 持久化过滤器检测（`WFP_`）都需要管理员权限。

标准用户（未提权）时，以下五类检查会降级为 `SKIPPED`：

| 降级项 | 典型 rule_id | 界面表现 | 说明 |
|---|---|---|---|
| 进程内存 YARA | `MEMORY_ACCESS_DENIED` / `MEMORY_SKIPPED` | 灰色 `SKIPPED` 行 + 灰色统计卡片计数 | skrapa 需 `SeDebugPrivilege` |
| BITS 全用户作业 | `BITS_ACCESS_DENIED` | 灰色 `SKIPPED` 行 | 自动降级只查当前用户 |
| Defender 排除项 | `POLICY_ACCESS_DENIED` | 灰色 `SKIPPED` 行 | 注册表排除项键需要管理员 |
| 计划任务隐藏检测 | `TASK_HIDDEN_ACCESS_DENIED` | 灰色 `SKIPPED` 行 | `Schedule\TaskCache\Tree` 键需要管理员 |
| WFP 持久化过滤器 | `WFP_ACCESS_DENIED` | 灰色 `SKIPPED` 行 | `BFE\Parameters\Policy` 键需要管理员 |

> 这不是报错，也不是“安全”：`SKIPPED` 是权限不足时的安全降级——扫描器明确告诉你“这一项没有检查”，而不是把未检查项当作干净。灰色统计卡片/灰色结果行就是为此设计的提示，导出报告时会原样保留（HTML 报告同样按灰色展示）。

 2.3 界面功能速览

- 五色统计卡片（顶部）：HIGH 红、MEDIUM 橙、LOW 黄、INFO 蓝、SKIPPED 灰，数字为本次扫描各等级结果数；SKIPPED 卡片 > 0 时提示存在未检查项。
- 左侧结果列表：按严重等级排序，行文字与等级同色；列为「等级 / 类别 / 目标 / 摘要」，点击任意行在右侧查看完整详情。
- 右侧详情面板：等级徽章、规则编号、类别、`target`、`detail`，以及可滚动的结构化 `evidence`（签名结果、PE 元数据、命中规则、攻击链等原始证据），便于人工确认。
- 工具栏：「开始扫描」在扫描期间禁用并显示实时进度与当前模块名；「导出报告」复用 [reporter.py](reporter.py) 生成自包含 HTML 或 JSON（原生保存对话框，取消不会报错）。
- 底部状态栏：当前状态、可用模块数、结果数、耗时；扫描在后台线程执行，界面全程可响应、不“未响应”。

![扫描进行中：进度条与模块提示](docs/screenshots/gui_scanning.png)

 2.4 打包指南

`build.bat` 一次生成两个 exe（先清理 `build/` 与 `dist/`）：

| 产物 | 子系统 | 说明 |
|---|---|---|
| `dist\tamper_scan.exe` | CONSOLE | CLI，保留控制台输出与退出码 |
| `dist\tamper_scan_gui.exe` | WINDOWS_GUI | GUI，基于 `gui.py`，双击不弹控制台 |

```bat
:: 1) 安装构建依赖（仅构建时需要 PyInstaller）
python -m pip install -r requirements-build.txt

:: 2) 一键打包两个 exe
build.bat
```

- 两个 exe 共享同一套打包参数：`--add-data "rules;rules" --add-data "tools;tools"`、`--collect-submodules modules`、`--collect-binaries yara`、`--hidden-import skrapa.windows / win32com.client / pythoncom / pywintypes`（漏掉任何一个都会让 GUI exe 在扫描时静默失败）；
- GUI 仅额外增加 `--windowed`（并改 `--name tamper_scan_gui`）：它让进程使用 Windows GUI 子系统，双击不闪控制台；
- GUI 内部调用 `autorunsc64.exe` / `powershell.exe` 时统一使用 `CREATE_NO_WINDOW` + `SW_HIDE`（`core/utils.py::hidden_process_options` 集中处理），扫描时不会闪黑框；
- 若存在 `icon.ico`，`build.bat` 会自动加 `--icon icon.ico` 嵌入盾牌图标；
- `tools/autorunsc64.exe` 不随仓库分发（[Sysinternals 许可说明](https://learn.microsoft.com/en-us/sysinternals/license-faq)）；本地构建前请按 [tools/README.txt](tools/README.txt) 从微软官方下载，或直接使用无 Autoruns 的降级模式；
- 打包细节（onefile/`_MEIPASS`/模块收集）与测试局限见 [§8](8-构建与打包)。

---

 3. 命令行参数

| 参数 | 说明 |
|---|---|
| `--scan` | 执行一次完整扫描（不带 `--scan` 只打印帮助） |
| `--output PATH` | 报告输出路径（基名；传目录时写入该目录下 `tamper_scan_report`；自动补 `.json/.html`） |
| `--format json\|html\|both` | 报告格式；不指定 `--output` 时写到当前目录 `tamper_scan_report.` |
| `--no-memory` | 跳过进程内存扫描（`lolbin_process` 内存部分 → `MEMORY_SKIPPED`） |
| `--max-memory-scan N` | 内存扫描最多进程数（默认 10；负数会被参数校验拒绝） |
| `--quiet` | 只输出统计摘要、退出码与报告路径，不逐条打印 Finding（适合计划任务/CI） |
| `--module NAME` | 只运行指定模块（可重复，调试/验收用） |
| `--verbose, -v` | 输出模块级明细（含跳过原因） |
| `--list-modules` | 列出 20 个扫描模块及接入状态 |
| `--version` | 打印版本（当前 `1.2.0`） |

示例：

```bat
:: 定时任务场景：安静模式 + 双格式报告
tamper_scan.exe --scan --quiet --format both --output C:\reports\tamper

:: 管理员完整扫描，并限制内存扫描进程数
tamper_scan.exe --scan --format both --output reports\admin_scan --max-memory-scan 5
```

退出码约定（与输出格式、`--quiet` 无关，供调度器使用）：

| 退出码 | 含义 |
|---|---|
| `2` | 存在 `HIGH` Finding |
| `1` | 无 HIGH，但存在 `MEDIUM` |
| `0` | 其余情况（仅 LOW/INFO/SKIPPED 或干净） |

---

 4. 报告格式

 JSON

```json
{
  "tool": "TamperScan",
  "version": "1.2.0",
  "generated_at": "2026-11-11T00:00:00+00:00",
  "host": {"name": "TEST-PC", "os": "Windows-11-...", "is_admin": true, "user": "User"},
  "scan": {
    "duration_seconds": 47.71,
    "modules_total": 20, "modules_available": 20,
    "modules": [{"name": "autoruns", "label": "...", "status": "ok", "count": 21, "error": null}]
  },
  "summary": {"total": 32, "counts": {"HIGH": 12, "MEDIUM": 0, "LOW": 2, "INFO": 17, "SKIPPED": 1}, "exit_code": 2},
  "findings": [
    {
      "severity": "HIGH | MEDIUM | LOW | INFO | SKIPPED",
      "category": "Autoruns",
      "target": "被检查对象（路径/键/任务名/进程）",
      "detail": "中文描述",
      "evidence": {"...": "结构化证据：签名结果、PE 元数据、命中的规则/攻击链等"},
      "rule_id": "SIG_UNSIGNED 等规则编号",
      "remediation": {
        "summary": "建议处理摘要（只读）",
        "expected": "建议值",
        "actual": "当前值",
        "command": "建议命令文本 / 多行（仅展示，绝不执行）",
        "risk": "LOW | MEDIUM | HIGH",
        "requires_admin": true
      }
    }
  ]
}
```

- 去重与排序复用 `core/finding.py`：`target + 规则基名`（如 `AUTORUNS_SIG_UNSIGNED` 与 `SIG_UNSIGNED` 同源合并，`evidence.merged_rules` 记录原始 rule_id），排序 HIGH → MEDIUM → LOW → INFO → SKIPPED。
- 白名单命中的条目会降为 INFO（默认 `mode: downgrade`），`evidence.whitelisted=true` 且 `whitelist_match` 记录命中原因。
- V1.2 起命中的 Finding 可带 `remediation` 字段（只读修复建议，来源 [rules/remediation.json](rules/remediation.json)）：`reporter.build_report()` 仅挂载建议文本，**扫描器与报告生成过程绝不执行其中任何命令**；没有建议的规则不写该字段。
- GUI 导出的 JSON 与 CLI 生成的 JSON 结构完全一致（同一 `reporter.build_report`）。

 HTML

单文件、自包含（CSS 内联在 `<style>`，无外部资源、无 JS），可直接转发/离线打开。按 severity 着色：

| 等级 | 颜色 | 含义 |
|---|---|---|
| HIGH | 红 | 需要立即处理 |
| MEDIUM | 橙 | 可疑，建议人工确认 |
| LOW | 黄 | 低风险提示/需了解 |
| INFO | 蓝 | 信息（含白名单降级后的记录） |
| SKIPPED | 灰 | 权限/依赖不足未检查（不代表干净） |

模板使用 Jinja2 且 autoescaping 强制开启（无关闭入口、无 `|safe`），攻击者可控字符串（扩展名、命令行、路径）均已转义。

> V1.2 起 HTML 报告为带修复建议的条目增加「建议处理」区块：只读展示 `remediation.summary` 与命令文本（同样经过 autoescape），命令仅供复制后人工复核执行，报告本身不包含任何自动执行逻辑。

> 本仓库附一份脱敏后的管理员演示报告（主机名/用户名/路径均为示例值）：[reports/sample_report.json](reports/sample_report.json) / [reports/sample_report.html](reports/sample_report.html)。

---

 5. 降噪策略与白名单

白名单文件：[rules/whitelist.json](rules/whitelist.json)；加载失败（JSON 损坏等）会降级为空名单并继续扫描，不会中断。

`mode` 可选：`downgrade`（默认，命中降 INFO）、`filter`（命中丢弃）、`off`（不过滤）。

已启用的降噪项：

1. 厂商伪装结构化豁免 `masquerade_allow`（6 条）：只对 `SIG_PATH_MASQUERADE` 生效，要求 签名者匹配 + 路径前缀匹配 + 签名状态为 `valid` 三个条件同时满足才降 INFO。当前覆盖 SteelSeries / Micro-Star International / NVIDIA，路径限定 `C:\Windows\System32\` 与 `C:\Windows\SysWOW64\`。签名 `invalid`（内容被篡改）、文件出现在 `%TEMP%`/`Downloads` 等路径时不会降级。
2. 扩展 ID 白名单 `extensions`：只按扩展 ID 精确匹配（不做名称子串，防 typosquatting）。`allowlist_by_id` 全放行；`allowlist_by_id_with_max_score` 内评分 ≤ 上限才放行，权限扩张导致评分超限会重新上报（更新劫持信号）。
3. 不降级的项（有意为之）：
   - 用户可写目录的自启动（如 `%APPDATA%` 下的更新器、Startup 目录脚本）：真实风险面，默认 HIGH；
   - 微软自带计划任务使用脚本解释器的 13 条 `TASK_INTERPRETER`：保留 LOW，不过滤（信息完整）；
   - 任何 `SKIPPED`：权限不足是"未检查"，不会因白名单变成 INFO。

---

 6. 已知局限

1. 目录签名兜底依赖本地 catalog 缓存：`verify()` 先验嵌入签名，失败/缺失时用 `CryptCATAdmin` 查本地目录签名（`WTD_CACHE_ONLY_URL_RETRIEVAL`）。完全离线且未缓存 catalog 的机器上，个别系统文件可能被判 `unsigned`。
2. Web Store 哈希比对未实现：不联网核对扩展文件哈希；`verified_contents.json` 只做 `item_id`/`item_version` 一致性，不当作签名来源。
3. 内存扫描需要管理员（见 [§1](以管理员身份运行可得到完整结果)）；且 `skrapa` 扫描耗时与进程内存大小相关，模块内置 60 秒总时间预算，超预算会记录未扫 PID，可用 `--max-memory-scan` 进一步限制。
4. 单次快照：无法捕捉时间维度变化（例如"昨天可信的扩展今天权限扩张"）。扩展模块已把完整权限集合写入 evidence，为后续版本做权限 diff 预留数据。
5. YARA 内存规则可能误报：内存规则要求多个特征组合出现（如 `Assembly.Load` + AMSI 符号），但正常进程内存仍可能命中；命中会以 HIGH `MEM_YARA_HIT` 上报并附进程/规则信息，需人工确认。若确认误报，收紧 `rules/yara/memory_.yar` 的 `condition` 或降低 `meta.confidence`。
6. `autorunsc64.exe` 采集省略 `-h`：哈希列不参与判定，且 `-h` 会把单次采集从约 16s 拉长到约 72s；需要哈希时自行用其他工具对 Finding 目标计算。
7. CRX2 不支持：仅解析 CRX3 头；CRX2 文件会被跳过（不产生误报）。
8. DNS 判定只覆盖 IPv4：IPv6 DNS（运营商地址无法枚举）统一跳过，避免大量误报；Hosts/DNS 指向私网不报。
9. 计划任务隐藏检测（`TASK_HIDDEN_TARRASK`）依赖 `HKLM\...\Schedule\TaskCache\Tree`，标准用户读不到该键（返回 `SKIPPED / TASK_HIDDEN_ACCESS_DENIED`）；且判定是状态型的：只能发现"当前处于隐藏状态"的任务，已删除的任务需要实时注册表事件（Sysmon 13/14）配合才能回溯。`Index==0` 在默认系统上可能存在历史残留键（无对应 `Tasks\<Id>` 定义，例如卸载残留/Edge 升级程序动态值），这类节点默认降为 MEDIUM（模块常量 `STALE_INDEX_ZERO_SEVERITY`，改成 `"HIGH"` 即恢复严格规则）；`Index` 值被删除的变体（会让 schtasks/任务计划程序整体枚举失败）已覆盖：任务节点（含 `Id`）缺少 `Index` 时 HIGH；遍历截断/部分读取失败会以 `TASK_HIDDEN_PARTIAL` 显式上报。只删改一部分 `SD` 的变体（`schtasks` 隐藏但 PowerShell 仍可枚举）暂不覆盖，需人工复核。
10. WFP 持久化过滤器检测（`WFP_`）解析的是 BFE 的 NDR 二进制存储（Quarkslab 逆向格式 + `FWPM_FILTER0` 字段顺序），NDR 指针布局跨 Windows 版本可能变化：无法定位结构的过滤器只会记 `SKIPPED / WFP_FILTER_UNPARSED`（不误报，但也不检查）；IPv6 远端地址以 `FWP_BYTE_ARRAY16` 指针形式存储，本版不解析；远端 IPv4 按 WFP 约定的网络字节序解释；系统过滤器按 `MPSSVC_*` 子层或 `@...` 资源显示名排除，攻击者可伪造显示名冒充系统规则，需结合进程/签名审计确认。
11. 凭证与 RDP 后门检测（`NP_` / `RDP_`）读取的 `Control\NetworkProvider` 与 `Services\TermService\Parameters` 在实测 Windows 11 上**标准用户可读**，因此标准用户也能得到真实结果；但加固系统/组策略可能收紧 ACL，此时按部分降级（`NP_ACCESS_DENIED` / `RDP_ACCESS_DENIED`，两部分互不影响）。Network Provider 基线为 `RDPNP→drprov.dll`、`P9NP→p9np.dll`、`LanmanWorkstation→ntlanman.dll`、`webclient→davclnt.dll`（Win11 起含 P9NP）；第三方 VPN/安全产品可能注册自己的 Provider，非微软签名的"未知提供者"按 HIGH 上报并附签名/路径证据，需人工确认是否为已知产品；RDP 侧只检测 `ServiceDll`，不覆盖 `termsrv.dll` 内存补丁/配置类后门。
12. 未加引号的服务路径检测（`SVC_UNQUOTED_PATH`）复用 `service` 模块的 CIM 采集结果（短时缓存 180s，避免同一次扫描重复查询）；只按"含空格 + 未加引号 + SYSTEM 运行"给 MEDIUM，evidence 中附带候选劫持路径与当前用户可写的候选目录供人工判断真实可利用性；非 SYSTEM 服务（NetworkService/LocalService/域用户）不参与提权判定；`PathName` 由 CIM 返回、可能被系统截断（极长路径），本模块对完整字符串判定、展示统一截断。
13. 只读修复建议（`remediation`）仅是参考文本：命令需人工复核后执行，扫描器不会自动执行、也不会校验命令结果；规则未提供建议时该字段缺省。`persistence_ext` 覆盖的冷门持久化位置在不同 Windows 版本/补丁级别下键名与默认值可能略有差异，异常结构按 `SKIPPED` 降级处理（未检查 ≠ 安全）。

---

 7. 规则更新（规则 / 白名单 / 权重数据维护）

```
rules/
├── lolbin_rules.json         进程名特征 / 命令行补充特征 / 父进程异常方向（含 T1047、T1204.002 参考）
├── extension_weights.json    扩展权限权重、可选权限半权重、攻击链 bonus、severity_floors、评分阈值
├── whitelist.json            白名单（masquerade_allow / extensions / paths / signers / ...）
├── remediation.json          V1.2 只读修复建议（按 rule_id 索引，仅供展示/复制，绝不执行）
└── yara/
    ├── memory_powershell.yar           内存专用（meta.scope = memory）
    ├── memory_dotnet_reflective.yar    内存专用
    └── file_known_persistence.yar      文件专用（meta.scope = file）
```

- 新增 YARA 规则：放进 `rules/yara/`，文件名以 `memory_` 开头的只用于进程内存扫描，其余用于文件扫描；必须写 `meta.scope` 与 `meta.confidence`。`YaraEngine` 逐文件编译，单条规则语法错误只影响该文件并记录到 `engine.errors`。
- 新增 LOLBin/父进程规则：编辑 `rules/lolbin_rules.json`（正则）。父进程异常是"父 → 子"单向规则，宁窄勿宽。
- 调整扩展评分：编辑 `rules/extension_weights.json`（权重/阈值/攻击链/`severity_floors`），无需改代码。
- 新增厂商伪装豁免：在 `whitelist.json` 的 `masquerade_allow` 追加 `{signer_contains, path_prefix, require_signature_status}`，不要用模糊签名或全局路径放行。
- 新增扩展白名单：`extensions.allowlist_by_id`（完全放行）或 `extensions.allowlist_by_id_with_max_score`（评分上限）。
- 新增/调整修复建议：编辑 `rules/remediation.json`（以 `rule_id` 为键，包含 `summary` / `expected` / `actual` / `command` / `risk` / `requires_admin` 字段；只读展示，扫描器不会执行）。

---

 8. 构建与打包

```bat
:: 1) 安装依赖（仅构建时需要 pyinstaller）
python -m pip install -r requirements-build.txt

:: 2) 打包（产物 dist\tamper_scan.exe 与 dist\tamper_scan_gui.exe，均为 onefile）
build.bat
```

`build.bat` 中的关键参数及原因：

| 参数 | 原因 |
|---|---|
| `--onefile` | 单文件分发；运行时解包到 `_MEIPASS`，代码用 `core/utils.get_base_dir()` 兼容 |
| `--add-data "rules;rules"` / `"tools;tools"` | Windows 分隔符是 `;`；规则与外部工具一起打包（CLI/GUI 必须完全一致）。`tools/` 可能仅有 README（本仓库不提交 autorunsc64.exe），打包仍成功，运行时 Autoruns 模块 SKIPPED |
| `--collect-submodules modules` | 20 个扫描模块是 `importlib` 动态导入，PyInstaller 静态分析发现不了 |
| `--collect-binaries yara` | 打包 `libyara.dll` |
| `--hidden-import skrapa.windows` | skrapa 的 Windows 子模块动态加载 |
| `--hidden-import win32com.client / pythoncom / pywintypes` | pywin32 的动态 COM 加载 |
| `--windowed`（仅 GUI） | 使用 Windows GUI 子系统，双击不弹控制台；子进程统一 `CREATE_NO_WINDOW` 隐藏 |
| `--icon icon.ico`（可选） | 存在时自动嵌入盾牌图标 |
| 不加 `--uac-admin` | 标准用户可运行；需要完整结果时由用户自行"以管理员身份运行" |

> `tools/autorunsc64.exe` 不随仓库分发（[Sysinternals 许可说明](https://learn.microsoft.com/en-us/sysinternals/license-faq)）；本地构建前请按 [tools/README.txt](tools/README.txt) 从微软官方下载，或直接使用无 Autoruns 的降级模式。

测试局限：打包后的 exe 在开发机（有 Python）上验证只能证明"exe 能运行且不依赖系统 Python 路径"（验证方法：清空 PATH 中的 Python 目录后运行 `--scan`，20 个模块仍可用）。完全无 Python 环境的验证建议在干净虚拟机或 Windows Sandbox 中复测。已在 Windows 11 + Python 3.10 上完成打包与运行验证（CLI 与 GUI 双 exe）。

 8.1 本地一键校验与样例报告重生成

V1.2 起在 `tools/` 提供两个开发脚本（不参与扫描逻辑；`build.bat` 会随 `--add-data tools;tools` 一起打包，体积很小）。V1.1 的本地校验脚本已更名为 `tools/verify_v12.ps1`：

| 脚本 | 用途 | 用法 |
|---|---|---|
| `tools/verify_v12.ps1` | 本地一键复现 GitHub Actions：`compileall`（含 `tests/`）→ `pytest` → `ruff` → 版本号 / 模块数（20）/ 样例报告 / LICENSE 与 README 协议断言；退出码 0 表示全部通过 | `powershell -ExecutionPolicy Bypass -File tools\verify_v12.ps1`（可加 `-SkipInstall` 跳过自动安装 pytest/ruff，`-RunFullScan` 额外跑一次真实扫描） |
| `tools/regenerate_sample_report.py` | 重新生成并脱敏 `reports/sample_report.json/.html`：用户目录 → `C:\Users\User`、主机名 → `TEST-PC`、用户名/域 → `User`/`DOMAIN`，按 `MODULE_REGISTRY` 归一 20 个模块状态并挂载只读 `remediation` 字段，再用 `reporter.render_html()` 重渲染 HTML | 先 `python main.py --scan --format both --output reports\sample_report`，再 `python tools\regenerate_sample_report.py` |

> 提交前建议固定执行一次 `powershell -ExecutionPolicy Bypass -File tools\verify_v12.ps1`，与 CI（Python 3.10 / 3.11 矩阵）完全一致。
> 样例报告包含主机名/用户名/路径，**重新生成后必须运行脱敏脚本并检查 `git diff reports/`**，禁止提交真实个人数据。

最小提交前工作流：

```bat
python -m pip install -r requirements.txt
python -m pip install ruff pytest
powershell -ExecutionPolicy Bypass -File tools\verify_v12.ps1
```

---

 9. 项目结构

```
tamper_scan/
├── main.py                   CLI 入口：参数解析、控制台输出、报告落盘、退出码
├── gui.py                    GUI 入口：tkinter/ttk Fluent 界面，复用 core/scanner.py
├── reporter.py               JSON / 自包含 HTML 报告（Jinja2 autoescape）
├── requirements.txt          运行依赖（GUI 无需新增依赖，tkinter 为标准库）
├── requirements-build.txt    打包依赖（含 -r requirements.txt + pyinstaller）
├── build.bat                 一键打包：CLI + GUI 两个 onefile exe
├── icon.ico                  exe 图标（存在时 build.bat 自动 --icon）
├── README.md
├── core/
│   ├── scanner.py            扫描调度核心（CLI/GUI 共用）：模块顺序、进度回调、白名单、去重排序
│   ├── finding.py            Finding 数据结构、去重（规则基名合并）、排序、退出码
│   ├── signature.py          WinVerifyTrust 嵌入签名 + 目录签名兜底、PE 元数据
│   ├── yara_engine.py        YARA 文件扫描 + skrapa 内存扫描封装（含权限降级）
│   ├── utils.py              路径/ACL/命令行/白名单/系统组件启发式/外部命令（隐藏子进程窗口）
│   └── version.py            版本号唯一来源
├── modules/                  20 个扫描模块，均暴露 scan() -> list[Finding]
│   ├── autoruns.py / registry_run.py / registry_policy.py / browser_settings.py / startup_lnk.py
│   ├── scheduled_task.py / scheduled_task_hidden.py / wfp_filter.py / credential_rdp.py
│   ├── service.py / unquoted_service_path.py / wmi_subscription.py / network.py / bits.py
│   ├── powershell_profile.py / com_hijack.py / lsa_appinit.py / persistence_ext.py
│   ├── browser_ext.py / lolbin_process.py
├── tests/                    纯函数单元测试（不依赖管理员权限；`python -m pytest -q`）
├── rules/                    规则与白名单（随 exe 打包，含 remediation.json 只读修复建议）
├── tools/                    外部工具目录（不含 autorunsc64.exe；下载说明见 tools/README.txt）
│   ├── verify_v12.ps1        本地复现 CI（compileall + pytest + ruff + 版本/模块数/样例报告/协议断言）
│   └── regenerate_sample_report.py  重新生成并脱敏演示报告（版本/20 模块归一 + remediation 挂载 + HTML 重渲染）
├── docs/screenshots/         界面截图（本 README 引用）
└── reports/
    └── sample_report.json / sample_report.html    脱敏后的管理员演示报告
```

 9.1 V1.1 新增模块与规则清单

V1.1 在 1.0.0 的 15 个模块基础上新增 **4 个高级威胁检测模块**（V1.1 时模块总数为 **19**）。
新增模块与既有模块遵循同一契约（`scan() -> list[Finding]`、`make_finding`、异常降级为
`SKIPPED`、白名单/去重/排序统一由调度核心处理）；V1.1 时单元测试 **140 条**（`python -m pytest -q`，
CI 中执行）：

| 模块 | 关键规则 | 默认等级 | 检测点与要点 |
|---|---|---|---|
| Tarrask 计划任务隐藏<br>`scheduled_task_hidden` | `TASK_HIDDEN_TARRASK` / `TASK_HIDDEN_PARTIAL` / `TASK_HIDDEN_ACCESS_DENIED` | HIGH / SKIPPED | `TaskCache\Tree` 子键 `SD` 缺失/为空/非二进制、`Index == 0`、任务节点 `Index` 被删除；`Index==0` 的历史残留键默认降 MEDIUM（常量 `STALE_INDEX_ZERO_SEVERITY` 可切 HIGH） |
| WFP 持久化过滤器<br>`wfp_filter` | `WFP_EDR_SILENCER` / `WFP_BLOCK_PUBLIC_IP` / `WFP_BLOCK_REMOTE_PORT` / `WFP_BLOCK_FILTER` / `WFP_FILTER_UNPARSED` | HIGH / MEDIUM / SKIPPED | 解析 BFE `Persistent\Filter` 的 NDR 二进制（GUID 命名值 + `FWPM_FILTER0` 字段偏移 + condition 记录），识别 EDR Silencer 式出站阻断与公网 IP/端口阻断；系统过滤器（`MPSSVC_*` 子层 / `@` 显示名）跳过 |
| 凭证与 RDP 后门<br>`credential_rdp` | `NP_PROVIDER_TAMPER` / `NP_UNKNOWN_PROVIDER` / `NP_ORDER_MISMATCH` / `RDP_SERVICEDLL_TAMPER` / `RDP_SERVICEDLL_ABSENT` / `NP_ACCESS_DENIED` / `RDP_ACCESS_DENIED` | HIGH / LOW / MEDIUM / SKIPPED | NetworkProvider `ProviderOrder` 陌生/被替换的提供者（对照微软基线 + `ProviderPath` 路径/签名校验，交叉校验 `Order` 与 `HwOrder`）；TermService `ServiceDll` 系统目录外/改名/非微软签名；两部分独立降级 |
| 未加引号服务路径<br>`unquoted_service_path` | `SVC_UNQUOTED_PATH` / `SVC_UNQUOTED_SKIPPED` / `SVC_UNQUOTED_PARTIAL` | MEDIUM / SKIPPED | 复用 `service` 模块 CIM 采集（180s 短时缓存，不重复查询）；`ImagePath` 含空格且未加引号 + SYSTEM 类账户运行；evidence 附候选劫持路径与当前用户可写目录（T1574.009） |

> 阶段 7 = V1.1 新增；阶段 2–6 = 1.0.0 既有模块。逐模块规则/局限见 [§6](6-已知局限) 与各模块 docstring。

20 个扫描模块完整清单（按 `core/scanner.py::MODULE_REGISTRY` 顺序）：

| # | 模块名 | 阶段 | 说明 |
|---|---|---|---|
| 1 | `autoruns` | 2 | Autoruns 广度兜底（autorunsc64.exe） |
| 2 | `registry_run` | 3 | 注册表 Run/RunOnce（64/32 位） |
| 3 | `registry_policy` | 3 | 浏览器策略键 / Defender 排除项 |
| 4 | `browser_settings` | 3 | IE/系统主页、搜索、代理 |
| 5 | `startup_lnk` | 3 | Startup 启动目录 LNK |
| 6 | `scheduled_task` | 4 | 计划任务 |
| 7 | `scheduled_task_hidden` | 7 | 计划任务隐藏（Tarrask/Index） |
| 8 | `wfp_filter` | 7 | WFP 持久化过滤器（EDR Silencer） |
| 9 | `credential_rdp` | 7 | 凭证与 RDP 后门（NetworkProvider） |
| 10 | `service` | 4 | 系统服务（V1.2 泛化 ServiceDll） |
| 11 | `unquoted_service_path` | 7 | 未加引号服务路径提权 |
| 12 | `wmi_subscription` | 4 | WMI 永久订阅 |
| 13 | `network` | 4 | Hosts / DNS |
| 14 | `bits` | 4 | BITS 作业 |
| 15 | `powershell_profile` | 4 | PowerShell Profile |
| 16 | `com_hijack` | 4 | COM 劫持（InprocServer32） |
| 17 | `lsa_appinit` | 4 | LSA / AppInit / IFEO / Winlogon（V1.2 新增 Winlogon 检测） |
| 18 | `persistence_ext` | 8 | 冷门持久化扩展点（Netsh / TimeProvider / Print / Active Setup / Shim / SilentProcessExit / WER / CMD Autorun / SCRNSaver） |
| 19 | `browser_ext` | 5 | 浏览器扩展深度检测 |
| 20 | `lolbin_process` | 6 | LOLBin 进程与内存扫描 |

> 阶段 8 = V1.2 新增；阶段 7 = V1.1 新增；阶段 2–6 = 1.0.0 既有模块。逐模块规则/局限见 [§6](6-已知局限) 与各模块 docstring。

 9.2 V1.2 新增/变更规则清单

V1.2 保持「20 个模块、统一模块契约」不变，重点新增/变更如下（严重等级以各模块实现为准，
均支持统一的白名单/去重/排序与异常降级）：

| 模块 | 变更 | 关键规则 |
|---|---|---|
| `persistence_ext`（新增，阶段 8） | 新增冷门持久化扩展点检测，共 10 个检测点 | `NETSH_HELPER_TAMPER` / `TIMEPROVIDER_DLL_TAMPER` / `PRINT_PROCESSOR_TAMPER` / `PRINT_MONITOR_TAMPER` / `ACTIVE_SETUP_STUB` / `APPCOMPAT_SHIM` / `SILENTPROCESS_EXIT_TAMPER` / `WER_LOCALDUMPS_TAMPER` / `CMD_AUTORUN` / `SCRNSAVER_TAMPER` |
| `lsa_appinit`（扩展） | 在 LSA / AppInit / IFEO 基础上增加 Winlogon 与自动登录检测，共 8 条规则 | `WINLOGON_SHELL_TAMPER` / `WINLOGON_USERINIT_TAMPER` / `WINLOGON_GINADLL_TAMPER` / `WINLOGON_APPSETUP_TAMPER` / `WINLOGON_TASKMAN_TAMPER` / `WINLOGON_NOTIFY_TAMPER` / `AUTOADMINLOGON_PLAINTEXT` / `LSA_AUTH_PACKAGE_TAMPER` |
| `service`（泛化） | 对服务 `ServiceDll` 做通用校验（文件缺失 / 系统目录外且签名非有效微软签名），与 `credential_rdp` 的 RDP `ServiceDll` 检测**自动去重合并** | `SVC_SERVICEDLL_TAMPER` / `SVC_SERVICEDLL_ABSENT`（与 RDP 侧 `RDP_SERVICEDLL_TAMPER` / `RDP_SERVICEDLL_ABSENT` 对应；严重等级以模块实现为准） |

`persistence_ext` 10 个检测点对应的持久化位置：

| 规则 ID | 检测位置 | 要点 |
|---|---|---|
| `NETSH_HELPER_TAMPER` | `SOFTWARE\Microsoft\NetSh`（Helper DLL） | Netsh helper 指向系统目录外/非微软签名 DLL |
| `TIMEPROVIDER_DLL_TAMPER` | `SYSTEM\...\Services\W32Time\TimeProviders\*` | `DllName` 非系统目录/非微软签名 |
| `PRINT_PROCESSOR_TAMPER` | `Control\Print\Environments\...\Print Processors\*` | `Driver` 指向非系统目录/非微软签名 DLL |
| `PRINT_MONITOR_TAMPER` | `Control\Print\Monitors\*` | `Driver` 指向非系统目录/非微软签名 DLL |
| `ACTIVE_SETUP_STUB` | `SOFTWARE\Microsoft\Active Setup\Installed Components\*` | `StubPath` 指向非微软/Edge/Office 签名程序（非路径遗留开关值视为系统基线，跳过） |
| `APPCOMPAT_SHIM` | `...\AppCompatFlags\Custom` / `InstalledSDB` | 自定义兼容性 shim 劫持应用启动 |
| `SILENTPROCESS_EXIT_TAMPER` | `...\SilentProcessExit\*` | `MonitorProcess` 指向非系统/用户可写路径 |
| `WER_LOCALDUMPS_TAMPER` | `...\Windows Error Reporting\LocalDumps` | 转储目录/类型被改写（可被用于凭证转储） |
| `CMD_AUTORUN` | `SOFTWARE\Microsoft\Command Processor\AutoRun` | 非空 AutoRun 命令被植入 |
| `SCRNSAVER_TAMPER` | `Control Panel\Desktop\SCRNSAVE.EXE` | 屏幕保护程序指向系统目录外/可疑可执行文件 |

`lsa_appinit` 新增的 Winlogon / 自动登录检测点：

| 规则 ID | 检测位置 | 要点 |
|---|---|---|
| `WINLOGON_SHELL_TAMPER` | `Winlogon\Shell` | shell 被替换为非 explorer.exe/异常命令 |
| `WINLOGON_USERINIT_TAMPER` | `Winlogon\Userinit` | 用户登录初始化程序被追加/替换为可疑路径 |
| `WINLOGON_GINADLL_TAMPER` | `Winlogon\GinaDll` | 自定义登录 DLL（凭证窃取常用位置） |
| `WINLOGON_APPSETUP_TAMPER` | `Winlogon\AppSetup` | 登录时额外执行程序 |
| `WINLOGON_TASKMAN_TAMPER` | `Winlogon\Taskman` | 任务管理器被替换 |
| `WINLOGON_NOTIFY_TAMPER` | `Winlogon\Notify` | 登录通知包被追加/替换 |
| `AUTOADMINLOGON_PLAINTEXT` | `Winlogon\AutoAdminLogon` / `DefaultPassword` | 自动登录开启且存在明文密码配置 |
| `LSA_AUTH_PACKAGE_TAMPER` | `Lsa\Authentication Packages` | 认证包列表被追加非系统 DLL |

**修复建议（只读）机制**：

- 建议数据外置在 [rules/remediation.json](rules/remediation.json)，以 `rule_id` 为键，包含 `summary` / `expected` / `actual` / `command` / `risk` / `requires_admin` 字段；
- `reporter` 在生成 JSON/HTML 时为命中的 Finding 挂载 `remediation` 字段；HTML 报告渲染「建议处理」区块（autoescape）；
- GUI 详情面板展示建议，并提供「一键复制命令」按钮（仅复制文本）；
- **只读边界**：扫描器、报告生成与 GUI 全程**绝不执行** `remediation.command` 中的任何命令，也不做 shell 拼接执行；命令必须由用户人工复核后自行执行。

---

 10. 免责声明

本工具为启发式扫描器，Finding 不等于恶意软件，`SKIPPED` 也表示"未检查"而非"安全"。在隔离/授权的环境中使用；对扫描结果中的文件做删除、隔离等处置前，请先人工确认。

---

 11. 许可协议（License）

本项目采用 **[知识共享 署名-非商业性使用 4.0 国际许可协议（CC BY-NC 4.0）](https://creativecommons.org/licenses/by-nc/4.0/)** 授权，完整协议文本见 [LICENSE](LICENSE)。

- **署名（BY）**：使用、复制、分发或修改本项目时，必须保留版权声明与协议声明，并注明是否做出修改；
- **非商业性使用（NC）**：**严禁未经授权的商业用途**——包括但不限于将本项目或其修改版用于商业产品、商业服务、对外收费交付、商业演示或商业再分发；
- 允许出于个人学习、研究、安全评估等非商业目的使用、复制、分发与修改；
- 需要商业授权或对协议适用范围有疑问时，请先联系作者取得书面许可；
- V1.2 起协议由 MIT 变更为 CC BY-NC 4.0（历史版本仍按其发布时的协议授权）。

使用本项目即表示你已阅读并同意上述许可条款与 [§10 免责声明](10-免责声明)。
