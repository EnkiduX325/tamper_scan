# -*- coding: utf-8 -*-
"""凭证与 RDP 后门检测（NetworkProvider 劫持 + TermService ServiceDll 篡改）。

背景
----
两类经典的"凭证/远程访问后门"持久化点：

1. **Network Provider 劫持**（凭据捕获 / 网络栈持久化）
   ``HKLM\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order`` 的
   ``ProviderOrder`` 决定网络提供者顺序（正常如
   ``RDPNP,P9NP,LanmanWorkstation,webclient``）。攻击者把自己的 DLL 注册成
   Network Provider 并插入 ProviderOrder 最前（或替换某个已知 provider 的
   ``Services\\<Provider>\\NetworkProvider\\ProviderPath``），即可在 SMB/RDP/WebDAV
   的连接建立路径上加载恶意 DLL，捕获凭据或注入进程。Windows 只会把 Order 中的
   提供者加入多 UNC 提供者链（MUP），因此「陌生提供者」本身就是强信号。

2. **TermService（RDP 服务）ServiceDll 篡改**
   ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters`` 的
   ``ServiceDll`` 正常为 ``%SystemRoot%\\System32\\termsrv.dll``。攻击者把它改为
   系统目录外的 DLL、改为非微软签名 DLL，或换成同目录下改名/未签名的载荷，即可让
   RDP 服务在启动时加载后门（``svchost -k NetworkService`` 内运行，隐蔽性高）。

规则
----
- ``NP_PROVIDER_TAMPER`` HIGH：ProviderOrder 中的提供者存在异常——
  未知提供者 + 非系统目录/非微软签名、已知提供者的 ProviderPath 与基线不符、
  ProviderPath 位于用户可写目录、DLL 缺失、无签名/非微软签名、provider 键不可读；
- ``NP_UNKNOWN_PROVIDER`` LOW：未知提供者，但 DLL 位于系统目录且为微软有效签名
  （大概率是未来 Windows 版本新增的提供者，保留信息供人工确认）；
- ``NP_ORDER_MISMATCH`` MEDIUM：``Order`` 与 ``HwOrder`` 的提供者集合不一致；
- ``NP_ORDER_ABSENT`` MEDIUM：``ProviderOrder`` 值缺失/为空（网络提供者链被破坏）；
- ``RDP_SERVICEDLL_TAMPER`` HIGH：ServiceDll 指向系统目录外、用户可写目录、文件缺失、
  无签名/签名无效、非微软签名，或文件名不是 ``termsrv.dll``；
- ``RDP_SERVICEDLL_ABSENT`` MEDIUM：``ServiceDll`` 值缺失（RDP 服务无法加载，疑似被破坏）；
- ``NP_ACCESS_DENIED`` / ``RDP_ACCESS_DENIED`` / ``NP_SKIPPED`` / ``RDP_SKIPPED``：
  权限不足或异常降级（未检查 ≠ 安全）。

权限说明
--------
实测 Windows 11 上上述键**标准用户通常可读**（与 BFE TaskCache 不同），因此本模块在
标准用户下也能产出真实结果；但加固系统/组策略可能 ACL 收紧，此时按部分降级处理：
网络提供者部分失败不影响 RDP 部分，反之亦然。

本模块只读注册表与文件签名，不执行命令、不修改系统状态。
"""

from __future__ import annotations

import os
import winreg
from typing import Any

from core import signature, utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "CredentialBackdoor"

# 规则编号
RULE_NP_TAMPER = "NP_PROVIDER_TAMPER"
RULE_NP_UNKNOWN = "NP_UNKNOWN_PROVIDER"
RULE_NP_ORDER_MISMATCH = "NP_ORDER_MISMATCH"
RULE_NP_ORDER_ABSENT = "NP_ORDER_ABSENT"
RULE_NP_ACCESS_DENIED = "NP_ACCESS_DENIED"
RULE_NP_SKIPPED = "NP_SKIPPED"
RULE_RDP_TAMPER = "RDP_SERVICEDLL_TAMPER"
RULE_RDP_ABSENT = "RDP_SERVICEDLL_ABSENT"
RULE_RDP_ACCESS_DENIED = "RDP_ACCESS_DENIED"
RULE_RDP_SKIPPED = "RDP_SKIPPED"

_NETWORK_PROVIDER_ROOT = r"SYSTEM\CurrentControlSet\Control\NetworkProvider"
_SERVICES_ROOT = r"SYSTEM\CurrentControlSet\Services"
_TERMSERVICE_PARAMETERS = r"SYSTEM\CurrentControlSet\Services\TermService\Parameters"

_ORDER_KEY = rf"HKLM\{_NETWORK_PROVIDER_ROOT}\Order"
_HWORDER_KEY = rf"HKLM\{_NETWORK_PROVIDER_ROOT}\HwOrder"
_TERMSERVICE_KEY_DISPLAY = rf"HKLM\{_TERMSERVICE_PARAMETERS}"

_VIEW_FLAG = winreg.KEY_WOW64_64KEY

# 已知的微软 Network Provider 基线：名称（小写） -> 期望 DLL（小写）。
# 正常 Win10/11 顺序：RDPNP,P9NP,LanmanWorkstation,webclient（Win11 才含 P9NP/WSL）。
_KNOWN_PROVIDERS: dict[str, str] = {
    "rdpnp": "drprov.dll",
    "p9np": "p9np.dll",
    "lanmanworkstation": "ntlanman.dll",
    "webclient": "davclnt.dll",
}

# TermService ServiceDll 的正常文件名
_EXPECTED_TERMSRV_DLL = "termsrv.dll"

_REASON_DETAILS: dict[str, str] = {
    "unknown_provider": "提供者不在已知微软基线中",
    "path_mismatch": "ProviderPath 与基线 DLL 不符（疑似被替换）",
    "outside_system": "DLL 不在系统目录（System32/SysWOW64）",
    "user_writable": "DLL 位于用户可写目录",
    "missing_file": "DLL 文件不存在（悬空引用）",
    "unsigned": "DLL 无数字签名或签名无效",
    "non_microsoft": "DLL 签名有效但不是微软签名",
    "provider_path_absent": "provider 键缺少 ProviderPath 值",
    "provider_missing": "ProviderOrder 中的提供者没有对应注册表键",
    "provider_unreadable": "provider 注册表键读取失败（可能被 ACL 隐藏）",
    "invalid_path": "ProviderPath 无法解析为文件路径",
}

_RDP_REASON_DETAILS: dict[str, str] = {
    "unexpected_name": f"ServiceDll 文件名不是 {_EXPECTED_TERMSRV_DLL}",
    "outside_system": "ServiceDll 不在系统目录（System32/SysWOW64）",
    "user_writable": "ServiceDll 位于用户可写目录",
    "missing_file": "ServiceDll 文件不存在",
    "unsigned": "ServiceDll 无数字签名或签名无效",
    "non_microsoft": "ServiceDll 签名有效但不是微软签名",
    "invalid_path": "ServiceDll 无法解析为文件路径",
}


def _is_access_denied(exc: BaseException) -> bool:
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5


# ---------------------------------------------------------------------------
# 注册表读取（可注入 hive/root，便于测试）
# ---------------------------------------------------------------------------


def _read_string_value(
    subkey: str,
    value_name: str,
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    view_flag: int = _VIEW_FLAG,
) -> tuple[str, str | None]:
    """读取字符串注册表值；返回 ``(原始值, 错误类型)``，错误类型为 None 表示成功。"""
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | int(view_flag or 0)) as key:
            try:
                data, _value_type = winreg.QueryValueEx(key, value_name)
            except FileNotFoundError:
                return "", "value_missing"
            except OSError as exc:
                return "", "access_denied" if _is_access_denied(exc) else "read_error"
            if isinstance(data, (bytes, bytearray)):
                return bytes(data).decode("utf-16-le", "ignore").strip(), None
            return str(data or "").strip(), None
    except FileNotFoundError:
        return "", "not_found"
    except OSError as exc:
        return "", "access_denied" if _is_access_denied(exc) else "read_error"
    except Exception:  # noqa: BLE001 - 采集层任何异常都降级
        return "", "read_error"


def _read_provider_entry(
    provider_name: str,
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    services_root: str = _SERVICES_ROOT,
    view_flag: int = _VIEW_FLAG,
) -> tuple[dict[str, str], str | None]:
    """读取 ``Services\\<Provider>\\NetworkProvider`` 下的字符串值。"""
    subkey = f"{services_root}\\{provider_name}\\NetworkProvider"
    values: dict[str, str] = {}
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | int(view_flag or 0)) as key:
            try:
                value_count = int(winreg.QueryInfoKey(key)[1])
            except OSError:
                value_count = 0
            for index in range(value_count):
                try:
                    name, data, value_type = winreg.EnumValue(key, index)
                except OSError:
                    break
                if value_type in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                    values[str(name)] = str(data or "").strip()
    except FileNotFoundError:
        return values, "not_found"
    except OSError as exc:
        return values, "access_denied" if _is_access_denied(exc) else "read_error"
    except Exception:  # noqa: BLE001
        return values, "read_error"
    return values, None


def _parse_provider_order(raw: str) -> list[str]:
    """解析 ``ProviderOrder``（逗号分隔，容忍空格/空项），保序去重。"""
    names: list[str] = []
    seen: set[str] = set()
    for item in str(raw or "").split(","):
        name = item.strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        names.append(name)
    return names


# ---------------------------------------------------------------------------
# 文件/签名状态（可打桩，便于测试）
# ---------------------------------------------------------------------------


def _collect_path_state(raw_path: str) -> dict[str, Any]:
    """收集 DLL 路径状态：展开变量、规范化、存在性、系统目录、用户可写。"""
    expanded = utils.expand_vars(raw_path)
    dll = utils.extract_executable(expanded) or utils.normalize_path(expanded)
    escaped = bool(raw_path) and not dll
    state: dict[str, Any] = {
        "expanded": expanded.strip(),
        "dll": dll,
        "exists": False,
        "in_system_dir": False,
        "user_writable": False,
        "escape_suspicious": escaped,
    }
    if not dll:
        return state
    try:
        state["exists"] = os.path.isfile(dll)
    except Exception:  # noqa: BLE001
        state["exists"] = False
    try:
        state["in_system_dir"] = utils.is_in_system_dir(dll)
    except Exception:  # noqa: BLE001
        state["in_system_dir"] = False
    try:
        state["user_writable"] = utils.is_user_writable(dll)
    except Exception:  # noqa: BLE001
        state["user_writable"] = False
    return state


def _verify_signature(dll_path: str) -> dict[str, Any]:
    """验签包装（独立函数便于测试打桩）；失败返回 missing 状态而不是抛异常。"""
    if not dll_path:
        return {"status": "missing", "signer": None, "error": "路径为空", "via": None}
    try:
        return signature.verify(dll_path)
    except Exception as exc:  # noqa: BLE001 - 验签失败不能影响扫描
        return {"status": "missing", "signer": None, "error": f"{type(exc).__name__}: {exc}", "via": None}


def _signature_reason(dll_path: str, path_state: dict[str, Any], sig_result: dict[str, Any]) -> str:
    """由路径状态 + 验签结果得出签名类原因（无问题返回空串）。"""
    if not dll_path or not path_state.get("exists"):
        return ""
    status = str(sig_result.get("status") or "")
    signer = sig_result.get("signer")
    if status in ("invalid", "unsigned"):
        return "unsigned"
    if status == "valid" and not signature.is_microsoft_signer(signer):
        return "non_microsoft"
    return ""


# ---------------------------------------------------------------------------
# 判定（纯函数）
# ---------------------------------------------------------------------------


def _analyze_provider_entry(
    provider_name: str,
    info: dict[str, str],
    path_state: dict[str, Any],
    sig_result: dict[str, Any],
    read_error: str | None = None,
) -> list[dict[str, Any]]:
    """对单个 Network Provider 做判定（纯函数）。"""
    expected_dll = _KNOWN_PROVIDERS.get(str(provider_name or "").strip().lower())
    dll = str(path_state.get("dll") or "")
    reasons: list[str] = []

    if read_error == "access_denied":
        reasons.append("provider_unreadable")
    elif read_error == "not_found":
        reasons.append("provider_missing")
    elif read_error:
        reasons.append("provider_unreadable")
    elif not str(info.get("ProviderPath") or "").strip():
        reasons.append("provider_path_absent")

    if expected_dll is None:
        reasons.append("unknown_provider")
    elif dll and os.path.basename(dll).lower() != expected_dll:
        reasons.append("path_mismatch")

    if dll:
        if path_state.get("escape_suspicious"):
            reasons.append("outside_system")
        if not path_state.get("in_system_dir"):
            reasons.append("outside_system")
        if path_state.get("user_writable"):
            reasons.append("user_writable")
        if not path_state.get("exists"):
            reasons.append("missing_file")
        else:
            signature_reason = _signature_reason(dll, path_state, sig_result)
            if signature_reason:
                reasons.append(signature_reason)
    elif str(info.get("ProviderPath") or "").strip():
        reasons.append("invalid_path")

    # 去重同时保持稳定顺序
    reasons = list(dict.fromkeys(reasons))
    if not reasons:
        return []

    evidence: dict[str, Any] = {
        "provider_name": provider_name,
        "provider_path_raw": str(info.get("ProviderPath") or ""),
        "expanded_path": path_state.get("expanded", ""),
        "dll": dll,
        # 顶层 path/image_path/signer 供 rules/whitelist.json 的 paths/signers 白名单匹配
        "path": dll,
        "image_path": dll,
        "signer": sig_result.get("signer") or "",
        "expected_dll": expected_dll or "",
        "device_name": str(info.get("DeviceName") or ""),
        "display_name": truncate(str(info.get("DisplayName") or ""), 200),
        "name": truncate(str(info.get("Name") or ""), 200),
        "reasons": reasons,
        "signature": {
            "status": sig_result.get("status"),
            "signer": sig_result.get("signer"),
            "via": sig_result.get("via"),
        },
        "path_state": {
            "exists": bool(path_state.get("exists")),
            "in_system_dir": bool(path_state.get("in_system_dir")),
            "user_writable": bool(path_state.get("user_writable")),
        },
    }

    signature_ok = (
        sig_result.get("status") == "valid"
        and signature.is_microsoft_signer(sig_result.get("signer"))
        and path_state.get("in_system_dir")
    )
    # 仅"未知提供者"且其余一切正常：多半是未来 Windows 版本新增的微软提供者，降为 LOW
    if reasons == ["unknown_provider"] and signature_ok:
        return [
            make_finding(
                "LOW",
                CATEGORY,
                provider_name,
                (
                    f"Network Provider {provider_name} 不在已知微软基线中，"
                    f"但 DLL 位于系统目录且为微软有效签名（{truncate(dll, 200)}），供人工确认"
                ),
                evidence,
                RULE_NP_UNKNOWN,
            )
        ]

    descriptions = [_REASON_DETAILS.get(reason, reason) for reason in reasons]
    detail = f"Network Provider {provider_name} 异常：" + "；".join(descriptions)
    target = dll or provider_name
    return [make_finding("HIGH", CATEGORY, target, truncate(detail, 300), evidence, RULE_NP_TAMPER)]


def _analyze_term_service(
    raw_value: str,
    value_error: str | None,
    path_state: dict[str, Any],
    sig_result: dict[str, Any],
) -> list[dict[str, Any]]:
    """对 TermService 的 ServiceDll 做判定（纯函数）。"""
    if value_error == "access_denied":
        return [
            make_skipped(
                CATEGORY,
                _TERMSERVICE_KEY_DISPLAY,
                "RDP ServiceDll 检测无法执行：TermService\\Parameters 拒绝访问（需要管理员权限）",
                {"error": "access_denied"},
                RULE_RDP_ACCESS_DENIED,
            )
        ]
    if value_error and value_error not in ("not_found", "value_missing"):
        return [
            make_skipped(
                CATEGORY,
                _TERMSERVICE_KEY_DISPLAY,
                f"RDP ServiceDll 检测无法执行：读取 TermService\\Parameters 失败（{value_error}）",
                {"error": value_error},
                RULE_RDP_SKIPPED,
            )
        ]
    if value_error in ("not_found", "value_missing") or not str(raw_value or "").strip():
        return [
            make_finding(
                "MEDIUM",
                CATEGORY,
                _TERMSERVICE_KEY_DISPLAY,
                "TermService\\Parameters 缺少 ServiceDll 值（RDP 服务无法正常加载，疑似被破坏或篡改）",
                {
                    "service": "TermService",
                    "raw_value": truncate(raw_value, 400),
                    "error": value_error or "value_missing",
                },
                RULE_RDP_ABSENT,
            )
        ]

    dll = str(path_state.get("dll") or "")
    reasons: list[str] = []
    if dll and os.path.basename(dll).lower() != _EXPECTED_TERMSRV_DLL:
        reasons.append("unexpected_name")
    if dll:
        if path_state.get("escape_suspicious") or not path_state.get("in_system_dir"):
            reasons.append("outside_system")
        if path_state.get("user_writable"):
            reasons.append("user_writable")
        if not path_state.get("exists"):
            reasons.append("missing_file")
        else:
            signature_reason = _signature_reason(dll, path_state, sig_result)
            if signature_reason:
                reasons.append(signature_reason)
    reasons = list(dict.fromkeys(reasons))
    if not reasons:
        return []

    evidence: dict[str, Any] = {
        "service": "TermService",
        "registry_key": _TERMSERVICE_KEY_DISPLAY,
        "raw_value": truncate(raw_value, 400),
        "expanded_path": path_state.get("expanded", ""),
        "dll": dll,
        # 顶层 path/image_path/signer 供白名单匹配（同 Network Provider 部分）
        "path": dll,
        "image_path": dll,
        "signer": sig_result.get("signer") or "",
        "expected_dll": _EXPECTED_TERMSRV_DLL,
        "reasons": reasons,
        "signature": {
            "status": sig_result.get("status"),
            "signer": sig_result.get("signer"),
            "via": sig_result.get("via"),
        },
        "path_state": {
            "exists": bool(path_state.get("exists")),
            "in_system_dir": bool(path_state.get("in_system_dir")),
            "user_writable": bool(path_state.get("user_writable")),
        },
    }
    descriptions = [_RDP_REASON_DETAILS.get(reason, reason) for reason in reasons]
    detail = f"RDP 服务 TermService 的 ServiceDll 异常：{'；'.join(descriptions)}"
    return [
        make_finding(
            "HIGH",
            CATEGORY,
            dll or _TERMSERVICE_KEY_DISPLAY,
            truncate(detail, 300),
            evidence,
            RULE_RDP_TAMPER,
        )
    ]


# ---------------------------------------------------------------------------
# 采集编排
# ---------------------------------------------------------------------------


def _scan_network_providers(
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    root: str = _NETWORK_PROVIDER_ROOT,
    services_root: str = _SERVICES_ROOT,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """检测 Network Provider 链（Order/HwOrder + 每个提供者）。"""
    order_raw, order_error = _read_string_value(f"{root}\\Order", "ProviderOrder", hive, view_flag)
    if order_error == "access_denied":
        return [
            make_skipped(
                CATEGORY,
                _ORDER_KEY,
                "Network Provider 检测无法执行：NetworkProvider\\Order 拒绝访问（需要管理员权限）",
                {"error": "access_denied"},
                RULE_NP_ACCESS_DENIED,
            )
        ]
    if order_error:
        return [
            make_skipped(
                CATEGORY,
                _ORDER_KEY,
                f"Network Provider 检测无法执行：{_ORDER_KEY} 读取失败（{order_error}）",
                {"error": order_error},
                RULE_NP_SKIPPED,
            )
        ]

    names = _parse_provider_order(order_raw)
    findings: list[dict[str, Any]] = []
    if not names:
        findings.append(
            make_finding(
                "MEDIUM",
                CATEGORY,
                _ORDER_KEY,
                "ProviderOrder 值为空：网络提供者链被破坏（疑似被篡改）",
                {"registry_key": _ORDER_KEY, "provider_order": truncate(order_raw, 400)},
                RULE_NP_ORDER_ABSENT,
            )
        )
        return findings

    for name in names:
        info, read_error = _read_provider_entry(name, hive, services_root, view_flag)
        provider_path = str(info.get("ProviderPath") or "").strip()
        path_state = _collect_path_state(provider_path) if provider_path else _collect_path_state("")
        sig_result = _verify_signature(path_state.get("dll") or "")
        findings.extend(
            _analyze_provider_entry(name, info, path_state, sig_result, read_error=read_error)
        )

    # Order 与 HwOrder 交叉校验（正常系统两者一致；只改一个列表是典型篡改痕迹）
    hw_raw, hw_error = _read_string_value(f"{root}\\HwOrder", "ProviderOrder", hive, view_flag)
    if not hw_error:
        hw_names = {item.lower() for item in _parse_provider_order(hw_raw)}
        order_names = {item.lower() for item in names}
        if hw_names and hw_names != order_names:
            findings.append(
                make_finding(
                    "MEDIUM",
                    CATEGORY,
                    _ORDER_KEY,
                    "ProviderOrder 与 HwOrder 的提供者集合不一致（可能只篡改了其中一个列表）",
                    {
                        "order": truncate(order_raw, 400),
                        "hw_order": truncate(hw_raw, 400),
                        "only_in_order": sorted(order_names - hw_names),
                        "only_in_hw_order": sorted(hw_names - order_names),
                    },
                    RULE_NP_ORDER_MISMATCH,
                )
            )
    return findings


def _scan_term_service(
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    parameters_key: str = _TERMSERVICE_PARAMETERS,
    view_flag: int = _VIEW_FLAG,
) -> list[dict[str, Any]]:
    """检测 TermService 的 ServiceDll。"""
    raw_value, value_error = _read_string_value(parameters_key, "ServiceDll", hive, view_flag)
    path_state = _collect_path_state(raw_value) if raw_value else _collect_path_state("")
    sig_result = _verify_signature(path_state.get("dll") or "")
    return _analyze_term_service(raw_value, value_error, path_state, sig_result)


def scan() -> list[dict[str, Any]]:
    """扫描凭证与 RDP 后门持久化点，返回 ``list[Finding]``。"""
    findings: list[dict[str, Any]] = []
    # 两部分独立降级：网络提供者失败不影响 RDP 检测，反之亦然
    try:
        findings.extend(_scan_network_providers())
    except Exception as exc:  # noqa: BLE001 - 单部分异常不中断整体扫描
        findings.append(
            make_skipped(
                CATEGORY,
                _ORDER_KEY,
                f"Network Provider 检测异常：{type(exc).__name__}: {exc}",
                {"error": f"{type(exc).__name__}: {exc}"},
                RULE_NP_SKIPPED,
            )
        )
    try:
        findings.extend(_scan_term_service())
    except Exception as exc:  # noqa: BLE001
        findings.append(
            make_skipped(
                CATEGORY,
                _TERMSERVICE_KEY_DISPLAY,
                f"RDP ServiceDll 检测异常：{type(exc).__name__}: {exc}",
                {"error": f"{type(exc).__name__}: {exc}"},
                RULE_RDP_SKIPPED,
            )
        )
    return utils.apply_whitelist(findings)
