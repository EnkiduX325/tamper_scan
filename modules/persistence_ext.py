# -*- coding: utf-8 -*-
"""冷门持久化扩展点检测（V1.2 阶段 8）。

覆盖 10 个"不属于 Run/服务/计划任务，但同样能在开机、登录或特定操作时加载代码"的
注册表持久化位置。每个位置都由「独立采集函数（winreg）」+「独立纯分析函数」组成：

======================================================================  =============================  ======
检测位置（值路径）                                                        规则 ID                        等级
======================================================================  =============================  ======
``HKLM\\SOFTWARE\\Microsoft\\NetSh`` 的 ``NetshHelperDll``                  ``NETSH_HELPER_TAMPER``        HIGH
``...\\W32Time\\TimeProviders\\<n>`` 的 ``DllName``                        ``TIMEPROVIDER_DLL_TAMPER``    HIGH
``...\\Print\\Environments\\Windows x64\\Print Processors\\<n>`` 的 ``Driver``  ``PRINT_PROCESSOR_TAMPER``     HIGH
``...\\Print\\Monitors\\<n>`` 的 ``Driver``                                ``PRINT_MONITOR_TAMPER``       HIGH
``...\\Active Setup\\Installed Components\\<GUID>`` 的 ``StubPath``         ``ACTIVE_SETUP_STUB``          MEDIUM
``...\\AppCompatFlags\\InstalledSDB\\<id>`` / ``...\\Custom\\<name>`` 的路径值  ``APPCOMPAT_SHIM``             MEDIUM
``...\\Image File Execution Options\\<proc>\\SilentProcessExit`` 的 ``MonitorProcess`` ``SILENTPROCESS_EXIT_TAMPER`` HIGH
``...\\Windows Error Reporting\\LocalDumps\\<proc>`` 的 ``DumpFolder``      ``WER_LOCALDUMPS_TAMPER``      MEDIUM
``HKLM`` / ``HKCU\\Software\\Microsoft\\Command Processor`` 的 ``AutoRun``   ``CMD_AUTORUN``               MEDIUM
``HKCU\\Control Panel\\Desktop`` 的 ``SCRNSAVE.EXE``                        ``SCRNSAVER_TAMPER``           LOW
======================================================================  =============================  ======

判定基线
--------
这些位置默认**不存在**，或只指向**微软有效签名**的文件；出现非微软签名 / 无签名 /
签名无效 / 文件缺失即视为异常（``signature.verify`` 的 ``status`` 为
``valid`` / ``unsigned`` / ``invalid`` / ``missing``）：

- 1~4、7：非微软 / 无签名 / 无效 / 缺失 → HIGH；
- 5：微软 / Edge / Office 有效签名放行（用户登录时由系统刷新，属正常），其余 MEDIUM；
  但纯开关式/非路径遗留值（如 Win11 内置组件遗留的 ``/UserInstall``、``U``）并不指向
  任何可执行文件，判定前直接跳过、不产出 Finding；裸可执行名（``cmd.exe``、
  ``rundll32.exe``）与带路径/带扩展名的值仍照常检测；
- 6：非微软 / 无签名 / 无效 / 缺失 → MEDIUM；
- 8：``DumpFolder`` 不在系统目录或落在用户可写目录才报（默认 System32 目录不报）；
- 9：``AutoRun`` 非空即 MEDIUM（每次启动 ``cmd.exe`` 都会执行）；
- 10：``SCRNSAVE.EXE`` 非空且（不在 System32 或非微软签名）→ LOW。

证据结构
--------
每条 Finding 的 ``evidence`` 固定包含：

- ``registry_value_path``：展示路径（如 ``HKLM\\SOFTWARE\\Microsoft\\NetSh\\NetshHelperDll``），
  供 ``rules/whitelist.json`` 的 ``persistence_ext_allow`` 精确匹配；
- ``registry_key`` / ``value_name`` / ``raw_value`` / ``expanded_path``；
- ``signature``：``{"status": ..., "signer": ...}``（WER 的 DumpFolder 是目录，状态记 ``n/a``）；
- 各检测点的必要上下文（提供者名、进程名、``ReportingMode``、是否用户可写等）。

采集约定
--------
- 只读注册表与文件签名，不执行命令、不修改系统状态；
- 64/32 视图统一按原生 64 位视图读取（``KEY_WOW64_64KEY``，与 ``credential_rdp`` 一致），
  避免 WOW64 重定向造成的重复与歧义；键/值不存在直接跳过；
- 单个检测点读取失败只记入 ``errors``，``scan()`` 末尾汇总为一条 SKIPPED
  （``PERSISTENCE_EXT_ACCESS_DENIED`` / ``PERSISTENCE_EXT_SKIPPED``：未检查 ≠ 安全）；
- 末尾统一 ``utils.apply_whitelist(findings)``。
"""

from __future__ import annotations

import os
import re
import winreg
from typing import Any

from core import signature, utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "PersistenceExt"

# ---------------------------------------------------------------------------
# 规则编号
# ---------------------------------------------------------------------------

RULE_NETSH_HELPER = "NETSH_HELPER_TAMPER"
RULE_TIMEPROVIDER_DLL = "TIMEPROVIDER_DLL_TAMPER"
RULE_PRINT_PROCESSOR = "PRINT_PROCESSOR_TAMPER"
RULE_PRINT_MONITOR = "PRINT_MONITOR_TAMPER"
RULE_ACTIVE_SETUP_STUB = "ACTIVE_SETUP_STUB"
RULE_APPCOMPAT_SHIM = "APPCOMPAT_SHIM"
RULE_SILENTPROCESS_EXIT = "SILENTPROCESS_EXIT_TAMPER"
RULE_WER_LOCALDUMPS = "WER_LOCALDUMPS_TAMPER"
RULE_CMD_AUTORUN = "CMD_AUTORUN"
RULE_SCRNSAVER = "SCRNSAVER_TAMPER"
# scan() 内部降级规则（读取失败 / 权限不足）
RULE_ACCESS_DENIED = "PERSISTENCE_EXT_ACCESS_DENIED"
RULE_SKIPPED = "PERSISTENCE_EXT_SKIPPED"

# ---------------------------------------------------------------------------
# 注册表路径常量
# ---------------------------------------------------------------------------

_VIEW_FLAG = winreg.KEY_WOW64_64KEY

_NETSH_KEY = r"SOFTWARE\Microsoft\NetSh"
_TIMEPROVIDERS_KEY = r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders"
_PRINT_PROCESSORS_KEY = r"SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors"
_PRINT_MONITORS_KEY = r"SYSTEM\CurrentControlSet\Control\Print\Monitors"
_ACTIVE_SETUP_KEY = r"SOFTWARE\Microsoft\Active Setup\Installed Components"
_APPCOMPAT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
_IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
_WER_LOCALDUMPS_KEY = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
_COMMAND_PROCESSOR_KEY = r"Software\Microsoft\Command Processor"
_DESKTOP_KEY = r"Control Panel\Desktop"

# 展示用键（Finding 的 registry_key / registry_value_path 与白名单保持一致）
_NETSH_DISPLAY = rf"HKLM\{_NETSH_KEY}"
_TIMEPROVIDERS_DISPLAY = rf"HKLM\{_TIMEPROVIDERS_KEY}"
_PRINT_PROCESSORS_DISPLAY = rf"HKLM\{_PRINT_PROCESSORS_KEY}"
_PRINT_MONITORS_DISPLAY = rf"HKLM\{_PRINT_MONITORS_KEY}"
_ACTIVE_SETUP_DISPLAY = rf"HKLM\{_ACTIVE_SETUP_KEY}"
_APPCOMPAT_DISPLAY = rf"HKLM\{_APPCOMPAT_KEY}"
_IFEO_DISPLAY = rf"HKLM\{_IFEO_KEY}"
_WER_LOCALDUMPS_DISPLAY = rf"HKLM\{_WER_LOCALDUMPS_KEY}"
_COMMAND_PROCESSOR_DISPLAY = rf"HKLM\{_COMMAND_PROCESSOR_KEY}"
_DESKTOP_DISPLAY = rf"HKCU\{_DESKTOP_KEY}"

# Active Setup 中属于"正常刷新"的签名者关键字：微软 / Edge / Office 组件
_ACTIVE_SETUP_TRUSTED_SIGNERS = ("microsoft", "edge", "office")

# AppCompatFlags\InstalledSDB\<id> 下与实际加载数据库/shim 相关的值名
_INSTALLED_SDB_VALUE_NAMES = ("DatabasePath", "ShimPath", "SdbPath")

# 打印处理器 / 打印监视器的 Driver 值通常只写裸 DLL 文件名，由打印子系统在
# 这些目录中查找（实测 Win11 的 winprint.dll 位于 spool\prtprocs\x64）。
_PRINT_PROCESSOR_SEARCH_SUBDIRS = (
    r"System32\spool\prtprocs\x64",
    r"System32\spool\prtprocs\W32X86",
    r"System32\spool\prtprocs\x86",
)
_PRINT_MONITOR_SEARCH_SUBDIRS = (
    r"System32\spool\drivers\x64\3",
    r"System32\spool\drivers\x64\PCC",
    r"System32\spool\drivers\x64",
)

# 风险原因 -> 中文描述（写入 detail / evidence.reasons）
_DLL_REASON_DETAILS: dict[str, str] = {
    "invalid_path": "值无法解析为文件路径",
    "not_pe": "目标不是可执行 PE 文件（无法通过 Authenticode 验证来源）",
    "missing_file": "文件不存在（悬空引用）",
    "unsigned": "文件没有数字签名",
    "invalid_signature": "数字签名无效（内容可能被篡改）",
    "non_microsoft": "签名有效但不是微软签名",
    "signature_unknown": "无法确认签名状态",
    "untrusted_signer": "签名者不在微软/Edge/Office 基线内",
    "outside_system": "文件/目录不在 System32",
    "non_microsoft_signer": "非微软签名",
}

_ERROR_LABELS: dict[str, str] = {
    "access_denied": "拒绝访问（需要管理员权限）",
    "read_error": "读取失败",
}


# ---------------------------------------------------------------------------
# 基础工具（可打桩：测试可 mock 这些函数，不依赖真实 HKLM）
# ---------------------------------------------------------------------------


def _is_access_denied(exc: BaseException) -> bool:
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5


def _string_value(value: Any) -> str:
    """把注册表值转成字符串（兼容 REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ / bytes）。"""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-16-le", "ignore").strip()
    if isinstance(value, (list, tuple)):
        return ";".join(str(item).strip() for item in value if str(item).strip())
    return str(value).strip()


def _read_value(
    hive: int,
    subkey: str,
    name: str,
    view_flag: int = _VIEW_FLAG,
) -> tuple[Any, str | None]:
    """读取单个注册表值；返回 ``(值, 错误类型)``。

    错误类型：``None``（成功）/ ``value_missing`` / ``not_found`` /
    ``access_denied`` / ``read_error``。采集层只把后两者记入 errors。
    """
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | int(view_flag or 0)) as key:
            try:
                data, _value_type = winreg.QueryValueEx(key, name)
            except FileNotFoundError:
                return None, "value_missing"
            except OSError as exc:
                return None, "access_denied" if _is_access_denied(exc) else "read_error"
            return data, None
    except FileNotFoundError:
        return None, "not_found"
    except OSError as exc:
        return None, "access_denied" if _is_access_denied(exc) else "read_error"
    except Exception:  # noqa: BLE001 - 采集层任何异常都降级
        return None, "read_error"


def _enum_subkeys(
    hive: int,
    subkey: str,
    view_flag: int = _VIEW_FLAG,
) -> tuple[list[str], str | None]:
    """枚举子键名；键不存在时返回 ``([], "not_found")``。"""
    names: list[str] = []
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | int(view_flag or 0)) as key:
            try:
                count = int(winreg.QueryInfoKey(key)[0])
            except OSError:
                count = 0
            for index in range(count):
                try:
                    names.append(winreg.EnumKey(key, index))
                except OSError:
                    break
    except FileNotFoundError:
        return names, "not_found"
    except OSError as exc:
        return names, "access_denied" if _is_access_denied(exc) else "read_error"
    except Exception:  # noqa: BLE001
        return names, "read_error"
    return names, None


def _enum_values(
    hive: int,
    subkey: str,
    view_flag: int = _VIEW_FLAG,
) -> tuple[dict[str, Any], str | None]:
    """枚举键下的值（名称 -> 原始数据）；键不存在时返回 ``({}, "not_found")``。"""
    values: dict[str, Any] = {}
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | int(view_flag or 0)) as key:
            try:
                count = int(winreg.QueryInfoKey(key)[1])
            except OSError:
                count = 0
            for index in range(count):
                try:
                    name, data, _value_type = winreg.EnumValue(key, index)
                except OSError:
                    break
                values[str(name)] = data
    except FileNotFoundError:
        return values, "not_found"
    except OSError as exc:
        return values, "access_denied" if _is_access_denied(exc) else "read_error"
    except Exception:  # noqa: BLE001
        return values, "read_error"
    return values, None


def _record_read_error(errors: list[str], display: str, error: str | None) -> None:
    """把读取失败登记到 errors；键/值不存在属于正常情况，静默跳过。"""
    if not error or error in ("not_found", "value_missing"):
        return
    label = _ERROR_LABELS.get(error, error)
    entry = f"{display}: {label}"
    if entry not in errors:
        errors.append(entry)


def _hive_name(hive: int) -> str:
    return "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"


def _display_key(hive_name: str, subkey: str) -> str:
    return f"{hive_name}\\{subkey}"


# ---------------------------------------------------------------------------
# 路径 / 签名状态（采集层，可打桩）
# ---------------------------------------------------------------------------


def _system_windir() -> str:
    return os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"


def _spool_search_dirs(subdirs: tuple[str, ...]) -> tuple[str, ...]:
    windir = _system_windir()
    return tuple(os.path.join(windir, subdir) for subdir in subdirs)


def _resolve_bare_reference(executable: str, search_dirs: tuple[str, ...] | None = None) -> str:
    """把注册表里常见的裸文件名（如 ``winprint.dll``）解析到 System32。

    打印处理器 / 打印监视器的 ``Driver`` 值通常只写 DLL 文件名，由打印子系统在
    特定目录中查找（如 ``System32\\spool\\prtprocs\\x64``）；不补全会把
    "文件存在且微软签名"的正常组件误判为"文件缺失"。``search_dirs`` 为额外
    搜索目录，按顺序取第一个真实存在的候选；都不存在时返回 System32 候选。
    """
    text = str(executable or "").strip()
    if not text:
        return ""
    if os.path.isabs(text) or "\\" in text or "/" in text:
        return text
    candidates = [os.path.join(_system_windir(), "System32", text)]
    for directory in search_dirs or ():
        candidates.append(os.path.join(str(directory), text))
    for candidate in candidates:
        try:
            if os.path.isfile(candidate):
                return candidate
        except Exception:  # noqa: BLE001 - 路径异常按不存在处理
            continue
    return candidates[0]


def _collect_path_state(raw_value: Any, search_dirs: tuple[str, ...] | None = None) -> dict[str, Any]:
    """从注册表值解析可执行文件路径状态（纯采集，不做签名判定）。"""
    expanded = utils.expand_vars(raw_value).strip()
    executable = ""
    if expanded:
        executable = utils.extract_executable(expanded) or utils.normalize_path(expanded)
        executable = _resolve_bare_reference(executable, search_dirs)
    return {
        "expanded": expanded,
        "executable": executable,
        "is_pe": bool(executable) and utils.is_pe_executable(executable),
        "in_system_dir": bool(executable) and utils.is_in_system_dir(executable),
    }


def _collect_folder_state(raw_value: Any) -> dict[str, Any]:
    """解析目录型注册表值（WER DumpFolder）：是否系统目录、是否用户可写。"""
    expanded = utils.expand_vars(raw_value).strip()
    folder = utils.normalize_path(expanded) if expanded else ""
    in_system_dir = bool(folder) and utils.is_in_system_dir(folder)
    user_writable = False
    if folder:
        try:
            user_writable = bool(utils.is_user_writable(folder))
        except Exception:  # noqa: BLE001 - ACL 探测失败按不可写处理
            user_writable = False
    return {
        "expanded": expanded,
        "folder": folder,
        "in_system_dir": in_system_dir,
        "user_writable": user_writable,
    }


def _verify_signature(path: str) -> dict[str, Any]:
    """验签包装：失败返回 missing 状态而不是抛异常。"""
    if not path:
        return {"status": "missing", "signer": None, "error": "路径为空", "via": None}
    try:
        return signature.verify(path)
    except Exception as exc:  # noqa: BLE001 - 验签失败不能影响扫描
        return {"status": "missing", "signer": None, "error": f"{type(exc).__name__}: {exc}", "via": None}


def _path_state_and_signature(
    raw_value: Any,
    search_dirs: tuple[str, ...] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    path_state = _collect_path_state(raw_value, search_dirs)
    sig_result = _verify_signature(path_state.get("executable") or "")
    return path_state, sig_result


# ---------------------------------------------------------------------------
# 纯判定工具
# ---------------------------------------------------------------------------


def _looks_like_path(text: Any) -> bool:
    """判断字符串是否像文件/目录路径（AppCompatFlags\\Custom 的值筛选）。"""
    value = str(text or "").strip().strip('"').strip("'")
    if not value:
        return False
    if value.startswith("%"):
        return True
    if value.startswith("\\\\") or value.startswith("//"):
        return True
    if re.match(r"(?i)^[a-z]:[\\/]", value):
        return True
    return "\\" in value or "/" in value


# StubPath 中视为"可执行/脚本文件"的扩展名
_EXECUTABLE_EXT_RE = re.compile(
    r"(?i)\.(?:exe|dll|com|bat|cmd|ps1|vbs|js|msi|cpl|scr|sys|ocx)(?![a-z0-9])"
)


def _looks_like_executable_reference(value: Any) -> bool:
    """判断 StubPath 是否指向可执行/脚本文件（``False`` = 非可执行开关式遗留值）。

    Active Setup 的 ``StubPath`` 在部分 Win11 系统上存在历史遗留的非路径值
    （实测如 ``/UserInstall``、单字符 ``U``），它们不指向任何文件，不可能加载代码，
    不应按"签名无法验证"上报。判定规则：

    - 盘符前缀（``C:\\...``）、UNC（``\\\\server\\share\\...``）、``%VAR%`` 引用、
      含反斜杠/正斜杠的值，都按路径型照常检测；
    - 裸可执行名（``cmd.exe``、``rundll32.exe``、``evil.dll``）虽无路径分隔符，
      但有常见可执行扩展名，仍照常检测；
    - 以 ``/`` 或 ``-`` 开头的纯开关值（``/UserInstall``、``-install``，无扩展名、
      无其它路径特征）与无分隔符/无扩展名的遗留值（``U``）视为非可执行值，直接跳过。
    """
    text = _string_value(value).strip().strip('"').strip("'").strip()
    if not text:
        return False
    lowered = text.lower()
    has_extension = bool(_EXECUTABLE_EXT_RE.search(lowered))
    has_separator = "\\" in text or "/" in text
    has_drive = bool(re.match(r"(?i)^[a-z]:", text))
    has_env = "%" in text or lowered.startswith("$env:") or lowered.startswith("$(")
    is_unc = lowered.startswith("\\\\") or lowered.startswith("//")
    # 纯开关式遗留值（"/UserInstall"、"-install"）：不可能加载代码，按基线跳过
    if text.startswith(("/", "-")) and not has_extension and not has_env and "\\" not in text:
        return False
    return bool(has_separator or has_drive or has_env or is_unc or has_extension)


def _signer_matches_any(signer: Any, needles: tuple[str, ...]) -> bool:
    text = str(signer or "").strip().lower()
    return bool(text) and any(needle in text for needle in needles)


def _dll_risk_reasons(sig_result: dict[str, Any], path_state: dict[str, Any]) -> list[str]:
    """由签名结果 + 路径状态得出风险原因（空列表表示"微软有效签名"基线）。"""
    reasons: list[str] = []
    executable = str(path_state.get("executable") or "")
    if not executable:
        return ["invalid_path"]
    status = str(sig_result.get("status") or "")
    if status == "missing":
        reasons.append("missing_file")
    elif status == "unsigned":
        reasons.append("unsigned")
    elif status == "invalid":
        reasons.append("invalid_signature")
    elif status == "valid":
        if not signature.is_microsoft_signer(sig_result.get("signer")):
            reasons.append("non_microsoft")
    else:
        reasons.append("signature_unknown")
    # 非 PE 文件无法用 Authenticode 验签：只有确认签名有效（如目录签名）时才放行
    if not path_state.get("is_pe") and status != "valid":
        reasons.append("not_pe")
    return list(dict.fromkeys(reasons))


def _describe_reasons(reasons: list[str]) -> str:
    return "；".join(_DLL_REASON_DETAILS.get(reason, reason) for reason in reasons)


def _base_evidence(
    registry_key: str,
    value_name: str,
    raw_value: Any,
    path_state: dict[str, Any],
    sig_result: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """构造统一证据骨架（registry_value_path 供白名单精确匹配）。"""
    executable = str(path_state.get("executable") or "")
    evidence: dict[str, Any] = {
        "registry_value_path": f"{registry_key}\\{value_name}",
        "registry_key": registry_key,
        "value_name": value_name,
        "raw_value": truncate(_string_value(raw_value), 400),
        "expanded_path": str(path_state.get("expanded") or ""),
        # 顶层 path / image_path / signer 供 rules/whitelist.json 的通用白名单匹配
        "path": executable,
        "image_path": executable,
        "signer": sig_result.get("signer") or "",
        "signature": {
            "status": sig_result.get("status"),
            "signer": sig_result.get("signer"),
            "via": sig_result.get("via"),
        },
        "in_system_dir": bool(path_state.get("in_system_dir")),
    }
    if extra:
        evidence.update(extra)
    return evidence


def _injected_value_finding(
    subject: str,
    raw_value: Any,
    sig_result: dict[str, Any],
    path_state: dict[str, Any],
    registry_key: str,
    value_name: str,
    rule_id: str,
    severity: str,
    extra: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """通用判定：目标 DLL/EXE 非微软有效签名时产出一条 Finding。"""
    text = _string_value(raw_value)
    if not text:
        return []
    reasons = _dll_risk_reasons(sig_result, path_state)
    if not reasons:
        return []
    evidence = _base_evidence(
        registry_key,
        value_name,
        raw_value,
        path_state,
        sig_result,
        extra=dict(extra or {}, reasons=reasons),
    )
    target = str(path_state.get("executable") or f"{registry_key}\\{value_name}")
    detail = f"{subject} 指向可疑文件：{truncate(text, 200)}（{_describe_reasons(reasons)}）"
    return [make_finding(severity, CATEGORY, target, truncate(detail, 300), evidence, rule_id)]


def _reporting_mode_nonzero(value: Any) -> bool:
    """SilentProcessExit 的 ReportingMode 是否非 0（非 0 表示会真正上报，更可疑）。"""
    if value is None or isinstance(value, bool):
        return bool(value)
    try:
        return int(value) != 0
    except (TypeError, ValueError):
        text = str(value).strip().lower()
        return bool(text) and text not in ("0", "false", "no", "off")


# ---------------------------------------------------------------------------
# 1~4：DLL / Driver 注入型持久化（纯分析函数）
# ---------------------------------------------------------------------------


def _analyze_netsh_helper(
    raw_value: Any,
    sig_result: dict[str, Any],
    path_state: dict[str, Any],
    registry_key: str = _NETSH_DISPLAY,
) -> list[dict[str, Any]]:
    """NetshHelperDll 判定（纯函数）：非微软/无签名/无效/缺失 -> HIGH。"""
    return _injected_value_finding(
        "NetSh 的 NetshHelperDll",
        raw_value,
        sig_result,
        path_state,
        registry_key,
        "NetshHelperDll",
        RULE_NETSH_HELPER,
        "HIGH",
        {"mechanism": "netsh.exe 启动时加载 HELPER DLL"},
    )


def _analyze_time_provider(
    provider_name: str,
    raw_value: Any,
    sig_result: dict[str, Any],
    path_state: dict[str, Any],
    registry_key: str = _TIMEPROVIDERS_DISPLAY,
) -> list[dict[str, Any]]:
    """W32Time TimeProviders 的 DllName 判定（纯函数）：异常 -> HIGH。"""
    return _injected_value_finding(
        f"W32Time TimeProviders 项 {provider_name} 的 DllName",
        raw_value,
        sig_result,
        path_state,
        f"{registry_key}\\{provider_name}",
        "DllName",
        RULE_TIMEPROVIDER_DLL,
        "HIGH",
        {"time_provider": provider_name, "mechanism": "时间服务启动时加载 DLL"},
    )


def _analyze_print_processor(
    processor_name: str,
    raw_value: Any,
    sig_result: dict[str, Any],
    path_state: dict[str, Any],
    registry_key: str = _PRINT_PROCESSORS_DISPLAY,
) -> list[dict[str, Any]]:
    """打印处理器 Driver 判定（纯函数）：异常 -> HIGH。"""
    return _injected_value_finding(
        f"打印处理器 {processor_name} 的 Driver",
        raw_value,
        sig_result,
        path_state,
        f"{registry_key}\\{processor_name}",
        "Driver",
        RULE_PRINT_PROCESSOR,
        "HIGH",
        {"print_processor": processor_name, "mechanism": "打印时由 spoolsv 加载 DLL"},
    )


def _analyze_print_monitor(
    monitor_name: str,
    raw_value: Any,
    sig_result: dict[str, Any],
    path_state: dict[str, Any],
    registry_key: str = _PRINT_MONITORS_DISPLAY,
) -> list[dict[str, Any]]:
    """打印监视器 Driver 判定（纯函数）：异常 -> HIGH。"""
    return _injected_value_finding(
        f"打印监视器 {monitor_name} 的 Driver",
        raw_value,
        sig_result,
        path_state,
        f"{registry_key}\\{monitor_name}",
        "Driver",
        RULE_PRINT_MONITOR,
        "HIGH",
        {"print_monitor": monitor_name, "mechanism": "打印服务启动时加载 DLL"},
    )


# ---------------------------------------------------------------------------
# 5：Active Setup StubPath（纯分析函数）
# ---------------------------------------------------------------------------


def _analyze_active_setup(
    component_id: str,
    raw_value: Any,
    sig_result: dict[str, Any],
    path_state: dict[str, Any],
    registry_key: str | None = None,
) -> list[dict[str, Any]]:
    """Active Setup 的 StubPath 判定（纯函数）。

    - 非可执行/开关式遗留值（Win11 内置 ``/UserInstall``、``U`` 等）不指向任何
      可执行文件，按基线直接跳过，不产出 Finding（见 :func:`_looks_like_executable_reference`）；
    - 微软 / Edge / Office 的有效签名放行（这是系统正常的登录刷新行为）；
    - 其余（第三方签名 / 无签名 / 无效 / 缺失）-> MEDIUM（仍按签名规则检测，
      裸可执行名与路径型值都适用）。
    """
    text = _string_value(raw_value)
    if not text:
        return []
    if not _looks_like_executable_reference(utils.expand_vars(text)):
        return []
    status = str(sig_result.get("status") or "")
    signer = sig_result.get("signer")
    if status == "valid" and _signer_matches_any(signer, _ACTIVE_SETUP_TRUSTED_SIGNERS):
        return []
    reasons = _dll_risk_reasons(sig_result, path_state) or ["untrusted_signer"]
    key = registry_key or f"{_ACTIVE_SETUP_DISPLAY}\\{component_id}"
    evidence = _base_evidence(
        key,
        "StubPath",
        raw_value,
        path_state,
        sig_result,
        extra={
            "component_id": component_id,
            "stub_path": truncate(text, 400),
            "trusted_signers": list(_ACTIVE_SETUP_TRUSTED_SIGNERS),
            "reasons": reasons,
        },
    )
    target = str(path_state.get("executable") or f"{key}\\StubPath")
    detail = (
        f"Active Setup 组件 {component_id} 的 StubPath 指向非微软/Edge/Office 程序："
        f"{truncate(text, 200)}（{_describe_reasons(reasons)}；每个用户登录时都会执行）"
    )
    return [make_finding("MEDIUM", CATEGORY, target, truncate(detail, 300), evidence, RULE_ACTIVE_SETUP_STUB)]


# ---------------------------------------------------------------------------
# 6：AppCompatFlags shim / SDB（纯分析函数）
# ---------------------------------------------------------------------------


def _analyze_appcompat_shim(
    entry_kind: str,
    entry_name: str,
    value_name: str,
    raw_value: Any,
    sig_result: dict[str, Any],
    path_state: dict[str, Any],
    registry_key: str | None = None,
) -> list[dict[str, Any]]:
    """AppCompatFlags InstalledSDB / Custom 路径值判定（纯函数）：异常 -> MEDIUM。"""
    text = _string_value(raw_value)
    if not text:
        return []
    reasons = _dll_risk_reasons(sig_result, path_state)
    if not reasons:
        return []
    key = registry_key or f"{_APPCOMPAT_DISPLAY}\\{entry_kind}\\{entry_name}"
    evidence = _base_evidence(
        key,
        value_name,
        raw_value,
        path_state,
        sig_result,
        extra={
            "entry_kind": entry_kind,
            "entry_name": entry_name,
            "shim_value": truncate(text, 400),
            "reasons": reasons,
        },
    )
    target = str(path_state.get("executable") or f"{key}\\{value_name}")
    detail = (
        f"AppCompat {entry_kind} 项 {entry_name} 的 {value_name} 指向非微软可信 shim/数据库："
        f"{truncate(text, 200)}（{_describe_reasons(reasons)}；应用启动时可能被注入兼容层）"
    )
    return [make_finding("MEDIUM", CATEGORY, target, truncate(detail, 300), evidence, RULE_APPCOMPAT_SHIM)]


# ---------------------------------------------------------------------------
# 7：IFEO SilentProcessExit（纯分析函数）
# ---------------------------------------------------------------------------


def _analyze_silentprocess_exit(
    process_name: str,
    raw_value: Any,
    reporting_mode: Any,
    sig_result: dict[str, Any],
    path_state: dict[str, Any],
    registry_key: str | None = None,
) -> list[dict[str, Any]]:
    """SilentProcessExit 的 MonitorProcess 判定（纯函数）：非空即 HIGH。"""
    text = _string_value(raw_value)
    if not text:
        return []
    reasons = ["monitor_process_set"] + _dll_risk_reasons(sig_result, path_state)
    reasons = list(dict.fromkeys(reasons))
    reporting_nonzero = _reporting_mode_nonzero(reporting_mode)
    key = registry_key or f"{_IFEO_DISPLAY}\\{process_name}\\SilentProcessExit"
    evidence = _base_evidence(
        key,
        "MonitorProcess",
        raw_value,
        path_state,
        sig_result,
        extra={
            "process": process_name,
            "monitor_process": truncate(text, 400),
            "reporting_mode": reporting_mode,
            "reporting_mode_nonzero": reporting_nonzero,
            "reasons": reasons,
        },
    )
    target = str(path_state.get("executable") or f"{key}\\MonitorProcess")
    signature_note = _describe_reasons(_dll_risk_reasons(sig_result, path_state))
    detail = (
        f"IFEO SilentProcessExit 为 {process_name} 设置了 MonitorProcess={truncate(text, 200)}"
        f"（进程退出时执行任意程序；ReportingMode={reporting_mode!r}"
        f"{'，非 0 更可疑' if reporting_nonzero else ''}"
        f"{'；' + signature_note if signature_note else ''}）"
    )
    return [
        make_finding("HIGH", CATEGORY, target, truncate(detail, 300), evidence, RULE_SILENTPROCESS_EXIT)
    ]


# ---------------------------------------------------------------------------
# 8：WER LocalDumps（纯分析函数）
# ---------------------------------------------------------------------------


def _analyze_wer_localdumps(
    process_name: str,
    raw_value: Any,
    in_system_dir: bool,
    user_writable: bool,
    registry_key: str | None = None,
) -> list[dict[str, Any]]:
    """WER LocalDumps 的 DumpFolder 判定（纯函数）。

    只有 DumpFolder 不在系统目录（或落在用户可写目录）时才报 MEDIUM；
    默认的 System32 目录不报。DumpFolder 是目录，signature 记为 ``n/a``。
    """
    text = _string_value(raw_value)
    if not text:
        return []
    if in_system_dir and not user_writable:
        return []
    key = registry_key or f"{_WER_LOCALDUMPS_DISPLAY}\\{process_name}"
    expanded = utils.expand_vars(text).strip()
    folder = utils.normalize_path(expanded) if expanded else ""
    reasons: list[str] = []
    if not in_system_dir:
        reasons.append("outside_system")
    if user_writable:
        reasons.append("user_writable")
    evidence = _base_evidence(
        key,
        "DumpFolder",
        raw_value,
        {"expanded": expanded, "executable": ""},
        {"status": "n/a", "signer": None, "via": None},
        extra={
            "process": process_name,
            "folder_path": folder,
            "path": folder,
            "image_path": folder,
            "in_system_dir": bool(in_system_dir),
            "user_writable": bool(user_writable),
            "reasons": reasons,
        },
    )
    target = folder or f"{key}\\DumpFolder"
    detail = (
        f"WER LocalDumps 为 {process_name} 配置了 DumpFolder={truncate(text, 200)}"
        f"（{'；'.join('不在系统目录' if item == 'outside_system' else '用户可写目录' for item in reasons)}，"
        f"崩溃转储可能被用于窃取进程内存）"
    )
    return [make_finding("MEDIUM", CATEGORY, target, truncate(detail, 300), evidence, RULE_WER_LOCALDUMPS)]


# ---------------------------------------------------------------------------
# 9：Command Processor AutoRun（纯分析函数）
# ---------------------------------------------------------------------------


def _analyze_cmd_autorun(
    raw_value: Any,
    sig_result: dict[str, Any],
    path_state: dict[str, Any],
    registry_key: str = _COMMAND_PROCESSOR_DISPLAY,
) -> list[dict[str, Any]]:
    """cmd.exe AutoRun 判定（纯函数）：非空即 MEDIUM（每次启动 cmd 都执行）。"""
    text = _string_value(raw_value)
    if not text:
        return []
    reasons = ["autorun_configured"] + _dll_risk_reasons(sig_result, path_state)
    reasons = list(dict.fromkeys(reasons))
    evidence = _base_evidence(
        registry_key,
        "AutoRun",
        raw_value,
        path_state,
        sig_result,
        extra={"autorun_command": truncate(text, 400), "reasons": reasons},
    )
    target = str(path_state.get("executable") or f"{registry_key}\\AutoRun")
    detail = f"Command Processor 配置了 AutoRun 命令：{truncate(text, 200)}（每次启动 cmd.exe 时执行）"
    return [make_finding("MEDIUM", CATEGORY, target, truncate(detail, 300), evidence, RULE_CMD_AUTORUN)]


# ---------------------------------------------------------------------------
# 10：屏幕保护程序（纯分析函数）
# ---------------------------------------------------------------------------


def _analyze_screensaver(
    raw_value: Any,
    sig_result: dict[str, Any],
    path_state: dict[str, Any],
    registry_key: str = _DESKTOP_DISPLAY,
) -> list[dict[str, Any]]:
    """SCRNSAVE.EXE 判定（纯函数）：非空且（不在 System32 或非微软签名）-> LOW。"""
    text = _string_value(raw_value)
    if not text:
        return []
    in_system_dir = bool(path_state.get("in_system_dir"))
    status = str(sig_result.get("status") or "")
    microsoft_signed = status == "valid" and signature.is_microsoft_signer(sig_result.get("signer"))
    if in_system_dir and microsoft_signed:
        return []
    reasons: list[str] = []
    if not in_system_dir:
        reasons.append("outside_system")
    if not microsoft_signed:
        status_reason = {
            "valid": "non_microsoft",
            "unsigned": "unsigned",
            "invalid": "invalid_signature",
            "missing": "missing_file",
        }.get(status, "signature_unknown")
        reasons.append(status_reason)
    if not path_state.get("executable"):
        reasons.insert(0, "invalid_path")
    evidence = _base_evidence(
        registry_key,
        "SCRNSAVE.EXE",
        raw_value,
        path_state,
        sig_result,
        extra={"reasons": reasons},
    )
    target = str(path_state.get("executable") or f"{registry_key}\\SCRNSAVE.EXE")
    detail = (
        f"屏幕保护程序被设为 {truncate(text, 200)}"
        f"（{_describe_reasons(reasons)}；锁屏/闲置时可能执行任意代码）"
    )
    return [make_finding("LOW", CATEGORY, target, truncate(detail, 300), evidence, RULE_SCRNSAVER)]


# ---------------------------------------------------------------------------
# 采集层：每个检测点一个独立采集函数（可 mock _read_value/_enum_* 测试）
# ---------------------------------------------------------------------------


def _collect_netsh_helper(
    errors: list[str],
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """采集 ``HKLM\\SOFTWARE\\Microsoft\\NetSh\\NetshHelperDll``。"""
    findings: list[dict[str, Any]] = []
    display_key = _display_key(_hive_name(hive), _NETSH_KEY)
    raw, error = _read_value(hive, _NETSH_KEY, "NetshHelperDll", view_flag)
    if error:
        _record_read_error(errors, f"{display_key}\\NetshHelperDll", error)
        return findings
    path_state, sig_result = _path_state_and_signature(raw)
    findings.extend(_analyze_netsh_helper(raw, sig_result, path_state, registry_key=display_key))
    return findings


def _collect_time_providers(
    errors: list[str],
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """采集 W32Time TimeProviders 下每个提供者的 ``DllName``。"""
    findings: list[dict[str, Any]] = []
    display_root = _display_key(_hive_name(hive), _TIMEPROVIDERS_KEY)
    entries, error = _enum_subkeys(hive, _TIMEPROVIDERS_KEY, view_flag)
    _record_read_error(errors, display_root, error)
    for provider_name in entries:
        subkey = f"{_TIMEPROVIDERS_KEY}\\{provider_name}"
        raw, value_error = _read_value(hive, subkey, "DllName", view_flag)
        if value_error:
            _record_read_error(errors, f"{display_root}\\{provider_name}\\DllName", value_error)
            continue
        path_state, sig_result = _path_state_and_signature(raw)
        findings.extend(
            _analyze_time_provider(
                provider_name,
                raw,
                sig_result,
                path_state,
                registry_key=display_root,
            )
        )
    return findings


def _collect_print_processors(
    errors: list[str],
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """采集打印处理器（Windows x64）下每个处理器的 ``Driver``。"""
    findings: list[dict[str, Any]] = []
    display_root = _display_key(_hive_name(hive), _PRINT_PROCESSORS_KEY)
    entries, error = _enum_subkeys(hive, _PRINT_PROCESSORS_KEY, view_flag)
    _record_read_error(errors, display_root, error)
    for processor_name in entries:
        subkey = f"{_PRINT_PROCESSORS_KEY}\\{processor_name}"
        raw, value_error = _read_value(hive, subkey, "Driver", view_flag)
        if value_error:
            _record_read_error(errors, f"{display_root}\\{processor_name}\\Driver", value_error)
            continue
        path_state, sig_result = _path_state_and_signature(
            raw, search_dirs=_spool_search_dirs(_PRINT_PROCESSOR_SEARCH_SUBDIRS)
        )
        findings.extend(
            _analyze_print_processor(
                processor_name,
                raw,
                sig_result,
                path_state,
                registry_key=display_root,
            )
        )
    return findings


def _collect_print_monitors(
    errors: list[str],
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """采集打印监视器下每个监视器的 ``Driver``。"""
    findings: list[dict[str, Any]] = []
    display_root = _display_key(_hive_name(hive), _PRINT_MONITORS_KEY)
    entries, error = _enum_subkeys(hive, _PRINT_MONITORS_KEY, view_flag)
    _record_read_error(errors, display_root, error)
    for monitor_name in entries:
        subkey = f"{_PRINT_MONITORS_KEY}\\{monitor_name}"
        raw, value_error = _read_value(hive, subkey, "Driver", view_flag)
        if value_error:
            _record_read_error(errors, f"{display_root}\\{monitor_name}\\Driver", value_error)
            continue
        path_state, sig_result = _path_state_and_signature(
            raw, search_dirs=_spool_search_dirs(_PRINT_MONITOR_SEARCH_SUBDIRS)
        )
        findings.extend(
            _analyze_print_monitor(
                monitor_name,
                raw,
                sig_result,
                path_state,
                registry_key=display_root,
            )
        )
    return findings


def _collect_active_setup(
    errors: list[str],
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """采集 Active Setup Installed Components 下每个组件的 ``StubPath``。"""
    findings: list[dict[str, Any]] = []
    display_root = _display_key(_hive_name(hive), _ACTIVE_SETUP_KEY)
    entries, error = _enum_subkeys(hive, _ACTIVE_SETUP_KEY, view_flag)
    _record_read_error(errors, display_root, error)
    for component_id in entries:
        subkey = f"{_ACTIVE_SETUP_KEY}\\{component_id}"
        raw, value_error = _read_value(hive, subkey, "StubPath", view_flag)
        if value_error:
            _record_read_error(errors, f"{display_root}\\{component_id}\\StubPath", value_error)
            continue
        path_state, sig_result = _path_state_and_signature(raw)
        findings.extend(
            _analyze_active_setup(
                component_id,
                raw,
                sig_result,
                path_state,
                registry_key=f"{display_root}\\{component_id}",
            )
        )
    return findings


def _collect_appcompat_shims(
    errors: list[str],
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """采集 AppCompatFlags 的 InstalledSDB（DatabasePath 等）与 Custom（路径值）。"""
    findings: list[dict[str, Any]] = []
    hive_name = _hive_name(hive)

    # InstalledSDB\<id>：通常只有 DatabasePath 一个路径值
    sdb_root = f"{_APPCOMPAT_KEY}\\InstalledSDB"
    sdb_display = _display_key(hive_name, sdb_root)
    sdb_entries, error = _enum_subkeys(hive, sdb_root, view_flag)
    _record_read_error(errors, sdb_display, error)
    for entry_name in sdb_entries:
        entry_key = f"{sdb_root}\\{entry_name}"
        entry_display = f"{sdb_display}\\{entry_name}"
        for value_name in _INSTALLED_SDB_VALUE_NAMES:
            raw, value_error = _read_value(hive, entry_key, value_name, view_flag)
            if value_error:
                _record_read_error(errors, f"{entry_display}\\{value_name}", value_error)
                continue
            path_state, sig_result = _path_state_and_signature(raw)
            findings.extend(
                _analyze_appcompat_shim(
                    "InstalledSDB",
                    entry_name,
                    value_name,
                    raw,
                    sig_result,
                    path_state,
                    registry_key=entry_display,
                )
            )

    # Custom\<name>：值名不固定，只分析"看起来像路径"的字符串值
    custom_root = f"{_APPCOMPAT_KEY}\\Custom"
    custom_display = _display_key(hive_name, custom_root)
    custom_entries, error = _enum_subkeys(hive, custom_root, view_flag)
    _record_read_error(errors, custom_display, error)
    for entry_name in custom_entries:
        entry_key = f"{custom_root}\\{entry_name}"
        entry_display = f"{custom_display}\\{entry_name}"
        values, values_error = _enum_values(hive, entry_key, view_flag)
        if values_error:
            _record_read_error(errors, entry_display, values_error)
            continue
        for value_name, raw in values.items():
            if not _looks_like_path(_string_value(raw)):
                continue
            path_state, sig_result = _path_state_and_signature(raw)
            findings.extend(
                _analyze_appcompat_shim(
                    "Custom",
                    entry_name,
                    value_name,
                    raw,
                    sig_result,
                    path_state,
                    registry_key=entry_display,
                )
            )
    return findings


def _collect_silentprocess_exit(
    errors: list[str],
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """采集 IFEO ``<proc>\\SilentProcessExit`` 的 MonitorProcess + ReportingMode。"""
    findings: list[dict[str, Any]] = []
    display_root = _display_key(_hive_name(hive), _IFEO_KEY)
    entries, error = _enum_subkeys(hive, _IFEO_KEY, view_flag)
    _record_read_error(errors, display_root, error)
    for process_name in entries:
        subkey = f"{_IFEO_KEY}\\{process_name}\\SilentProcessExit"
        display_key = f"{display_root}\\{process_name}\\SilentProcessExit"
        raw, value_error = _read_value(hive, subkey, "MonitorProcess", view_flag)
        if value_error:
            _record_read_error(errors, f"{display_key}\\MonitorProcess", value_error)
            continue
        if not _string_value(raw):
            continue
        reporting_mode, _ = _read_value(hive, subkey, "ReportingMode", view_flag)
        path_state, sig_result = _path_state_and_signature(raw)
        findings.extend(
            _analyze_silentprocess_exit(
                process_name,
                raw,
                reporting_mode,
                sig_result,
                path_state,
                registry_key=display_key,
            )
        )
    return findings


def _collect_wer_localdumps(
    errors: list[str],
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """采集 WER LocalDumps 下每个进程的 ``DumpFolder``。"""
    findings: list[dict[str, Any]] = []
    display_root = _display_key(_hive_name(hive), _WER_LOCALDUMPS_KEY)
    entries, error = _enum_subkeys(hive, _WER_LOCALDUMPS_KEY, view_flag)
    _record_read_error(errors, display_root, error)
    for process_name in entries:
        subkey = f"{_WER_LOCALDUMPS_KEY}\\{process_name}"
        display_key = f"{display_root}\\{process_name}"
        raw, value_error = _read_value(hive, subkey, "DumpFolder", view_flag)
        if value_error:
            _record_read_error(errors, f"{display_key}\\DumpFolder", value_error)
            continue
        if not _string_value(raw):
            continue
        folder_state = _collect_folder_state(raw)
        findings.extend(
            _analyze_wer_localdumps(
                process_name,
                raw,
                in_system_dir=bool(folder_state.get("in_system_dir")),
                user_writable=bool(folder_state.get("user_writable")),
                registry_key=display_key,
            )
        )
    return findings


def _collect_cmd_autorun(
    errors: list[str],
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """采集 HKLM 与 HKCU 的 Command Processor ``AutoRun``。"""
    findings: list[dict[str, Any]] = []
    for hive, hive_name in (
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        (winreg.HKEY_CURRENT_USER, "HKCU"),
    ):
        display_key = _display_key(hive_name, _COMMAND_PROCESSOR_KEY)
        raw, error = _read_value(hive, _COMMAND_PROCESSOR_KEY, "AutoRun", view_flag)
        if error:
            _record_read_error(errors, f"{display_key}\\AutoRun", error)
            continue
        path_state, sig_result = _path_state_and_signature(raw)
        findings.extend(_analyze_cmd_autorun(raw, sig_result, path_state, registry_key=display_key))
    return findings


def _collect_screensaver(
    errors: list[str],
    hive: int = winreg.HKEY_CURRENT_USER,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """采集 ``HKCU\\Control Panel\\Desktop`` 的 ``SCRNSAVE.EXE``。"""
    display_key = _display_key(_hive_name(hive), _DESKTOP_KEY)
    raw, error = _read_value(hive, _DESKTOP_KEY, "SCRNSAVE.EXE", view_flag)
    if error:
        _record_read_error(errors, f"{display_key}\\SCRNSAVE.EXE", error)
        return []
    path_state, sig_result = _path_state_and_signature(raw)
    return _analyze_screensaver(raw, sig_result, path_state, registry_key=display_key)


_COLLECTORS = (
    _collect_netsh_helper,
    _collect_time_providers,
    _collect_print_processors,
    _collect_print_monitors,
    _collect_active_setup,
    _collect_appcompat_shims,
    _collect_silentprocess_exit,
    _collect_wer_localdumps,
    _collect_cmd_autorun,
    _collect_screensaver,
)


def _has_access_denied(errors: list[str]) -> bool:
    tokens = ("access_denied", "permissionerror", "拒绝访问")
    return any(token in str(error).lower() for error in errors for token in tokens)


def scan() -> list[dict[str, Any]]:
    """扫描全部冷门持久化扩展点，返回 ``list[Finding]``。

    单个检测点异常只降级为 errors 并汇总成一条 SKIPPED，绝不让整个扫描抛异常。
    """
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for collector in _COLLECTORS:
        try:
            findings.extend(collector(errors))
        except Exception as exc:  # noqa: BLE001 - 单检测点异常不中断整体扫描
            errors.append(f"{collector.__name__}: {type(exc).__name__}: {exc}")
    if errors:
        rule_id = RULE_ACCESS_DENIED if _has_access_denied(errors) else RULE_SKIPPED
        findings.append(
            make_skipped(
                CATEGORY,
                "PersistenceExt",
                "部分冷门持久化检测点无法读取（未检查 ≠ 安全）：" + "；".join(errors[:5]),
                {"errors": errors},
                rule_id,
            )
        )
    return utils.apply_whitelist(findings)
