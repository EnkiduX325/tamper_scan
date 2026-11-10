# -*- coding: utf-8 -*-
"""系统服务持久化检测（阶段 4）。

用 ``Get-CimInstance Win32_Service`` 采集 ``Name/DisplayName/PathName/StartMode/
StartName/State``。

**关键：svchost 托管服务的 ServiceDll 检测**。``Win32_Service.PathName`` 对
svchost 服务只是 ``C:\\Windows\\system32\\svchost.exe -k netsvcs -p``，只验
svchost.exe 的签名会全部 valid，从而漏掉
``HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>\\Parameters\\ServiceDll``
被替换这一类经典持久化。因此对 svchost 服务额外读取 ServiceDll 并验签/判可写。

规则：
- ``SERVICE_USERWRITABLE``         HIGH 服务二进制位于用户可写目录
- ``SERVICE_SVCHOST_DLL``          HIGH svchost 服务的 ServiceDll 位于用户可写目录
- ``SERVICE_SVCHOST_DLL_OUTSIDE``  MEDIUM ServiceDll 不在系统目录且签名正常（需复核）
- ``SERVICE_NAME_MISMATCH``        MEDIUM 名称自称系统组件但二进制非微软签名
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
    return utils.apply_whitelist(findings)
