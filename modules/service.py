# -*- coding: utf-8 -*-
"""系统服务持久化检测（阶段 4）。

用 ``Get-CimInstance Win32_Service`` 采集 ``Name/DisplayName/PathName/StartMode/
StartName/State``。

**关键：svchost 托管服务的 ServiceDll 检测**。``Win32_Service.PathName`` 对
svchost 服务只是 ``C:\\Windows\\system32\\svchost.exe -k netsvcs -p``，只验
svchost.exe 的签名会全部 valid，从而漏掉
``HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>\\Parameters\\ServiceDll``
被替换这一类经典持久化。因此对 svchost 服务额外读取 ServiceDll 并验签/判可写。

**V1.2：泛化 ServiceDll 校验**。除 svchost 专有规则外，还枚举
``HKLM\\SYSTEM\\CurrentControlSet\\Services`` 下**所有**服务子键的
``Parameters\\ServiceDll``（REG_SZ / REG_EXPAND_SZ，64 位视图），对系统目录外
或缺失的 DLL 独立上报 ``SVC_SERVICEDLL_TAMPER`` / ``SVC_SERVICEDLL_ABSENT``。
泛化规则的 target 是**展开后的 DLL 绝对路径**，与 ``credential_rdp`` 的
``RDP_SERVICEDLL_TAMPER`` 指向同一文件时 target 相同；报告层
``dedupe_findings(merge_rule_base=True)`` 按规则基名 ``SERVICEDLL_TAMPER``
自动合并为一条（``evidence["merged_rules"]`` 记录两边 rule_id）。

规则：
- ``SERVICE_USERWRITABLE``         HIGH 服务二进制位于用户可写目录
- ``SERVICE_SVCHOST_DLL``          HIGH svchost 服务的 ServiceDll 位于用户可写目录
- ``SERVICE_SVCHOST_DLL_OUTSIDE``  MEDIUM ServiceDll 不在系统目录且签名正常（需复核）
- ``SERVICE_NAME_MISMATCH``        MEDIUM 名称自称系统组件但二进制非微软签名
- ``SVC_SERVICEDLL_TAMPER``        HIGH 任意服务的 ServiceDll 位于系统目录外且签名不可信
- ``SVC_SERVICEDLL_ABSENT``        HIGH 任意服务的 ServiceDll 文件不存在（悬空引用）
- 另对 PE 目标调用 ``signature.signature_finding``（SIG_*）

采集失败 → SKIPPED；不抛异常。
"""

from __future__ import annotations

import os
import time
import winreg
from typing import Any

from core import signature, utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "Service"

# 泛化 ServiceDll 检查（V1.2）：枚举 Services 下所有子键，而不只是 svchost。
_SERVICES_ROOT = r"SYSTEM\CurrentControlSet\Services"
_SERVICEDLL_VALUE_NAME = "ServiceDll"
_VIEW_FLAG = winreg.KEY_WOW64_64KEY
RULE_SERVICEDLL_TAMPER = "SVC_SERVICEDLL_TAMPER"
RULE_SERVICEDLL_ABSENT = "SVC_SERVICEDLL_ABSENT"

_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
if ($null -eq $services) { Write-Output '[]'; exit 0 }
$services | Select-Object Name, DisplayName, PathName, StartMode, StartName, State | ConvertTo-Json -Depth 3
"""

# 服务名"自称系统组件"的强关键词（避免 Update/Driver 等泛词误报）
_SYSTEM_CLAIM_KEYWORDS = ("microsoft", "windows", "defender", "system32", "winlogon", "lsass", "svchost")

# 采集结果短时缓存：其它模块（如 unquoted_service_path）通过 collect_services(max_age_seconds>0)
# 直接复用本模块的采集结果，避免同一次扫描重复执行 CIM 查询。
_SERVICE_CACHE: dict[str, Any] = {"timestamp": 0.0, "data": None, "error": None}


def clear_service_cache() -> None:
    """清空服务采集缓存（测试或需要强制刷新时调用）。"""
    _SERVICE_CACHE.update(timestamp=0.0, data=None, error=None)


def collect_services(max_age_seconds: float = 0.0) -> tuple[Any, str | None]:
    """采集 ``Win32_Service`` 原始 JSON 数据（唯一采集入口）。

    Args:
        max_age_seconds: >0 时允许复用该时限内的缓存（供其它模块复用采集结果）；
            0 表示强制重新采集（``service.scan()`` 的默认行为）。

    Returns:
        ``(原始数据, 错误信息)``；失败时数据为 None，错误信息非空。
    """
    now = time.monotonic()
    cached = _SERVICE_CACHE
    if (
        max_age_seconds > 0
        and cached["data"] is not None
        and now - float(cached["timestamp"] or 0.0) <= max_age_seconds
    ):
        return cached["data"], None
    data, error = utils.run_powershell_json(_PS_SCRIPT, timeout=60)
    _SERVICE_CACHE.update(timestamp=time.monotonic(), data=data, error=error)
    return data, error


def normalize_service_records(data: Any) -> tuple[list[dict[str, Any]] | None, str | None]:
    """把 CIM JSON 结果规范化为 ``list[dict]``；结构异常返回 ``(None, 原因)``。"""
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return None, f"服务 JSON 结构异常：{type(data).__name__}"
    return [item for item in data if isinstance(item, dict)], None


def _claims_system(name: str, display_name: str) -> bool:
    """只看服务名（DisplayName 里的 "Windows SCM" 之类描述性文字不算自称系统组件）。"""
    text = str(name or "").lower()
    return any(keyword in text for keyword in _SYSTEM_CLAIM_KEYWORDS)


def _read_service_dll(service_name: str) -> str:
    """读取 svchost 服务的 Parameters\\ServiceDll（REG_EXPAND_SZ），失败返回空串。"""
    if not service_name:
        return ""
    subkey = rf"SYSTEM\CurrentControlSet\Services\{service_name}\Parameters"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            value = str(winreg.QueryValueEx(key, "ServiceDll")[0] or "").strip()
    except (FileNotFoundError, OSError):
        return ""
    return utils.expand_vars(value).strip()


# ---------------------------------------------------------------------------
# 泛化 ServiceDll 采集与判定（V1.2；纯函数化，便于 mock 测试）
# ---------------------------------------------------------------------------


def _is_access_denied(exc: BaseException) -> bool:
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5


def _hive_display(hive: int) -> str:
    if hive == winreg.HKEY_LOCAL_MACHINE:
        return "HKLM"
    if hive == winreg.HKEY_CURRENT_USER:
        return "HKCU"
    return "HIVE"


def _service_parameters_key(service_name: str, root: str = _SERVICES_ROOT) -> str:
    return rf"{root}\{service_name}\Parameters"


def _service_parameters_display(service_name: str, root: str, hive: int) -> str:
    return rf"{_hive_display(hive)}\{_service_parameters_key(service_name, root)}"


def _read_service_dll_entry(
    service_name: str,
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    root: str = _SERVICES_ROOT,
    view_flag: int = _VIEW_FLAG,
) -> dict[str, Any]:
    """读取单个服务的 ``Parameters\\ServiceDll``。

    Returns:
        ``{"service_name", "registry_key", "raw_value", "value_type", "error"}``；
        ``error`` 为 None 表示读取成功，否则为 ``not_found`` / ``value_missing`` /
        ``access_denied`` / ``read_error`` / ``unsupported_type``。
    """
    entry: dict[str, Any] = {
        "service_name": service_name,
        "registry_key": _service_parameters_display(service_name, root, hive),
        "raw_value": "",
        "value_type": None,
        "error": None,
    }
    subkey = _service_parameters_key(service_name, root)
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | int(view_flag or 0)) as key:
            try:
                data, value_type = winreg.QueryValueEx(key, _SERVICEDLL_VALUE_NAME)
            except FileNotFoundError:
                entry["error"] = "value_missing"
                return entry
            except OSError as exc:
                entry["error"] = "access_denied" if _is_access_denied(exc) else "read_error"
                return entry
    except FileNotFoundError:
        entry["error"] = "not_found"
        return entry
    except OSError as exc:
        entry["error"] = "access_denied" if _is_access_denied(exc) else "read_error"
        return entry
    except Exception:  # noqa: BLE001 - 采集层任何异常都降级
        entry["error"] = "read_error"
        return entry

    if value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
        entry["error"] = "unsupported_type"
        return entry
    entry["value_type"] = int(value_type)
    if isinstance(data, (bytes, bytearray)):
        entry["raw_value"] = bytes(data).decode("utf-16-le", "ignore").strip()
    else:
        entry["raw_value"] = str(data or "").strip()
    return entry


def _iter_service_dll_entries(
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    root: str = _SERVICES_ROOT,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """枚举 ``Services`` 下所有带 ``Parameters\\ServiceDll`` 的服务子键。

    只返回"确实存在 ServiceDll 值"或"读取该子键失败"的条目；单个子键读取失败
    记录在 ``error`` 字段后继续枚举，不影响其它服务，也不抛异常。
    根键都打不开时返回空列表（后续按"未检查"处理，不阻断 scan）。
    """
    entries: list[dict[str, Any]] = []
    try:
        root_key = winreg.OpenKey(hive, root, 0, winreg.KEY_READ | int(view_flag or 0))
    except (FileNotFoundError, OSError):
        return entries
    except Exception:  # noqa: BLE001
        return entries
    try:
        index = 0
        while True:
            try:
                service_name = winreg.EnumKey(root_key, index)
            except OSError:
                break
            except Exception:  # noqa: BLE001
                break
            index += 1
            try:
                entry = _read_service_dll_entry(service_name, hive, root, view_flag)
            except Exception:  # noqa: BLE001 - 单个子键异常不允许中断整体枚举
                entry = {
                    "service_name": str(service_name),
                    "registry_key": _service_parameters_display(service_name, root, hive),
                    "raw_value": "",
                    "value_type": None,
                    "error": "read_error",
                }
            # 找不到 Parameters 键/值属于正常现象（绝大多数服务没有 ServiceDll）；
            # 只有"存在但读不了"的失败才记录到结果里，供上层跳过并保留可追溯信息。
            if entry.get("error") in ("not_found", "value_missing", "unsupported_type"):
                continue
            entries.append(entry)
    finally:
        try:
            winreg.CloseKey(root_key)
        except Exception:  # noqa: BLE001
            pass
    return entries


def _collect_service_dll_state(dll: str) -> dict[str, Any]:
    """收集泛化 ServiceDll 的文件状态（存在性 / 是否系统目录），不抛异常。"""
    state: dict[str, Any] = {"exists": False, "in_system_dir": False}
    try:
        state["exists"] = bool(os.path.isfile(dll))
    except Exception:  # noqa: BLE001
        state["exists"] = False
    try:
        state["in_system_dir"] = bool(utils.is_in_system_dir(dll))
    except Exception:  # noqa: BLE001
        state["in_system_dir"] = False
    return state


def _verify_signature(dll_path: str) -> dict[str, Any]:
    """验签包装（独立函数便于测试打桩）；失败返回 missing 状态而不抛异常。"""
    if not dll_path:
        return {"status": "missing", "signer": None, "error": "路径为空", "via": None}
    try:
        return signature.verify(dll_path)
    except Exception as exc:  # noqa: BLE001 - 验签失败不能影响扫描
        return {"status": "missing", "signer": None, "error": f"{type(exc).__name__}: {exc}", "via": None}


def _service_dll_path(raw_value: str) -> tuple[str, str]:
    """把原始 ServiceDll 值转换为 ``(expanded_path, dll)``。

    ``expanded_path`` 与 credential_rdp 的 evidence 保持一致（expand_vars 后的原串）；
    ``dll`` 是可比较的 DLL 绝对路径（与 credential_rdp 的 target 规范化方式一致，
    这样两条规则的 target 才能在报告层合并）。
    """
    expanded = utils.expand_vars(raw_value).strip()
    dll = utils.extract_executable(expanded) or utils.normalize_path(expanded)
    return expanded, dll


def _analyze_service_dll(
    service_name: str,
    raw_value: str,
    registry_key: str = "",
    path_state: dict[str, Any] | None = None,
    sig_result: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """对单个服务（任意服务，不限 svchost）的 ServiceDll 做判定（纯函数）。

    判定（文件缺失优先，避免同时报 ABSENT 与 TAMPER）：
    - ServiceDll 为空 → 不报（交由专有规则处理 TermService 缺失等语义）；
    - 文件不存在 → ``SVC_SERVICEDLL_ABSENT`` HIGH；
    - 位于 System32/SysWOW64 → 不报（系统目录内由 SIG_* / svchost 专有规则覆盖）；
    - 系统目录外且（非 PE 或签名非"有效微软签名"）→ ``SVC_SERVICEDLL_TAMPER`` HIGH。

    target 一律为展开规范化后的 DLL 绝对路径，与 ``credential_rdp`` 的
    ``RDP_SERVICEDLL_TAMPER`` target 相同，便于跨模块按规则基名合并。
    """
    raw_text = str(raw_value or "").strip()
    if not raw_text:
        return []
    expanded, dll = _service_dll_path(raw_text)
    if not dll:
        return []
    state = path_state if isinstance(path_state, dict) else _collect_service_dll_state(dll)
    exists = bool(state.get("exists"))
    in_system_dir = bool(state.get("in_system_dir"))
    sig = sig_result if isinstance(sig_result, dict) else {"status": "missing", "signer": None, "via": None}
    evidence: dict[str, Any] = {
        "service_name": service_name,
        "registry_key": registry_key,
        "value_name": _SERVICEDLL_VALUE_NAME,
        "raw_value": truncate(raw_text, 400),
        "expanded_path": expanded,
        "service_dll": dll,
        # 与 credential_rdp evidence 对齐的字段，供白名单/报告复用
        "dll": dll,
        "path": dll,
        "image_path": dll,
        "signer": sig.get("signer") or "",
        "in_system_dir": in_system_dir,
        "exists": exists,
        "signature": {
            "status": sig.get("status"),
            "signer": sig.get("signer"),
            "via": sig.get("via"),
        },
    }

    if not exists:
        return [
            make_finding(
                "HIGH",
                CATEGORY,
                dll,
                truncate(
                    f"服务 {service_name} 的 ServiceDll 文件不存在（悬空引用，疑似被删除或从未落地）：{dll}",
                    300,
                ),
                evidence,
                RULE_SERVICEDLL_ABSENT,
            )
        ]

    if in_system_dir:
        return []

    if not utils.is_pe_executable(dll):
        return [
            make_finding(
                "HIGH",
                CATEGORY,
                dll,
                truncate(f"服务 {service_name} 的 ServiceDll 位于系统目录之外且不是可执行 PE 文件：{dll}", 300),
                evidence,
                RULE_SERVICEDLL_TAMPER,
            )
        ]

    signature_ok = sig.get("status") == "valid" and signature.is_microsoft_signer(sig.get("signer"))
    if not signature_ok:
        return [
            make_finding(
                "HIGH",
                CATEGORY,
                dll,
                truncate(
                    f"服务 {service_name} 的 ServiceDll 位于系统目录之外且签名不可信"
                    f"（签名者：{sig.get('signer') or '无签名'}）：{dll}",
                    300,
                ),
                evidence,
                RULE_SERVICEDLL_TAMPER,
            )
        ]
    return []


def _scan_all_service_dlls(
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    root: str = _SERVICES_ROOT,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """枚举所有服务的 ServiceDll 并判定（scan() 在 CIM 检查之后调用）。"""
    findings: list[dict[str, Any]] = []
    for entry in _iter_service_dll_entries(hive, root, view_flag):
        if entry.get("error"):
            # 单个子键读取失败：跳过该项（已记录），不影响其它服务
            continue
        raw_value = str(entry.get("raw_value") or "")
        if not raw_value.strip():
            continue
        _expanded, dll = _service_dll_path(raw_value)
        if not dll:
            continue
        state = _collect_service_dll_state(dll)
        sig_result: dict[str, Any] = {"status": "missing", "signer": None, "via": None}
        # 只有系统目录外且存在的文件才需要验签（系统目录内由 SIG_* 规则负责，
        # 避免对上百个系统 DLL 做无谓的 WinVerifyTrust 调用）。
        if state["exists"] and not state["in_system_dir"]:
            sig_result = _verify_signature(dll)
        findings.extend(
            _analyze_service_dll(
                str(entry.get("service_name") or ""),
                raw_value,
                str(entry.get("registry_key") or ""),
                state,
                sig_result,
            )
        )
    return findings


def _analyze_service(service: dict[str, Any]) -> list[dict[str, Any]]:
    """对单个服务做判定（纯函数，便于单元测试）。"""
    name = str(service.get("Name") or "").strip()
    display_name = str(service.get("DisplayName") or "").strip()
    path_name = str(service.get("PathName") or "").strip()
    if not path_name:
        return []
    executable = utils.extract_executable(path_name)
    evidence: dict[str, Any] = {
        "service_name": name,
        "display_name": display_name,
        "path_name": truncate(path_name, 400),
        "start_mode": service.get("StartMode"),
        "start_name": service.get("StartName"),
        "state": service.get("State"),
        "executable": executable,
    }
    findings: list[dict[str, Any]] = []
    if not executable:
        return findings

    # 服务二进制验签 + 用户可写
    sig_finding = signature.signature_finding(executable, category=CATEGORY)
    if sig_finding:
        sig_finding["evidence"].update({"service": evidence})
        findings.append(sig_finding)
    if utils.is_user_writable(executable):
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                executable,
                f"服务 {name} 的二进制位于用户可写目录：{truncate(executable, 200)}",
                dict(evidence),
                "SERVICE_USERWRITABLE",
            )
        )

    # svchost 托管服务：额外检查 ServiceDll
    basename = os.path.basename(utils.normalize_path(executable)).lower()
    if basename == "svchost.exe":
        service_dll = _read_service_dll(name)
        if service_dll:
            dll_evidence = {**evidence, "service_dll": truncate(service_dll, 400)}
            dll_sig = signature.signature_finding(service_dll, category=CATEGORY)
            if utils.is_user_writable(service_dll):
                findings.append(
                    make_finding(
                        "HIGH",
                        CATEGORY,
                        service_dll,
                        f"svchost 服务 {name} 的 ServiceDll 位于用户可写目录：{truncate(service_dll, 200)}",
                        dll_evidence,
                        "SERVICE_SVCHOST_DLL",
                    )
                )
            if dll_sig:
                dll_sig["evidence"].update({"service": dll_evidence})
                findings.append(dll_sig)
            if (
                utils.is_in_system_dir(executable)
                and not utils.is_in_system_dir(service_dll)
                and not utils.is_trusted_install_location(service_dll)
                and dll_sig is None
            ):
                findings.append(
                    make_finding(
                        "MEDIUM",
                        CATEGORY,
                        service_dll,
                        f"svchost 服务 {name} 的 ServiceDll 不在系统目录（签名有效，需复核）：{truncate(service_dll, 200)}",
                        dll_evidence,
                        "SERVICE_SVCHOST_DLL_OUTSIDE",
                    )
                )

    # 名称与签名者不符（自称系统组件但非微软签名）
    sig_result = signature.verify(executable)
    signer = sig_result.get("signer")
    if _claims_system(name, display_name) and (
        sig_finding is not None or (signer and not signature.is_microsoft_signer(signer))
    ):
        findings.append(
            make_finding(
                "MEDIUM",
                CATEGORY,
                executable,
                f"服务 {name}（{display_name}）疑似名不副实：签名者={signer or '无签名'}",
                dict(evidence),
                "SERVICE_NAME_MISMATCH",
            )
        )
    return findings


def scan() -> list[dict[str, Any]]:
    """采集并检查服务，返回 ``list[Finding]``。"""
    data, error = collect_services()
    if error:
        return [
            make_skipped(
                CATEGORY,
                "Win32_Service",
                f"服务采集失败：{error}",
                {"error": error},
                "SERVICE_SKIPPED",
            )
        ]
    records, parse_error = normalize_service_records(data)
    if parse_error or records is None:
        return [
            make_skipped(
                CATEGORY,
                "Win32_Service",
                parse_error or "服务 JSON 结构异常",
                {"sample": truncate(data, 400)},
                "SERVICE_PARSE_ERROR",
            )
        ]

    findings: list[dict[str, Any]] = []
    for service in records:
        findings.extend(_analyze_service(service))

    # V1.2 泛化 ServiceDll 检查：在现有 CIM 服务检查之后追加，覆盖所有服务
    # （含非 svchost）；svchost 专有 SERVICE_SVCHOST_DLL* 规则保留。
    # 枚举/读取失败已在内部降级，这里再兜一层异常，保证 scan() 永不抛出。
    try:
        findings.extend(_scan_all_service_dlls())
    except Exception:  # noqa: BLE001 - 采集层任何异常都不应中断整体扫描
        pass

    return utils.apply_whitelist(findings)
