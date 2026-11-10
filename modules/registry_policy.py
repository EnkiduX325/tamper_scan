# -*- coding: utf-8 -*-
"""浏览器策略键 / Windows Defender 排除项检测（阶段 3，第一梯队）。

1. **Chrome / Edge 企业策略**（``HKLM/HKCU\\SOFTWARE\\Policies\\...``）：

   - ``ExtensionInstallForcelist``、``HomepageLocation``、``DefaultSearchProvider*``
   - 规则：**策略值存在且非空即 HIGH / POLICY_HIJACK**（正常个人电脑不应出现这些键）

2. **Defender 排除项**（``...\\Windows Defender\\Exclusions\\Paths|Processes``）：

   - 排除路径位于用户可写目录 → HIGH / ``DEFENDER_EXCLUSION``
   - 排除进程为 powershell/cmd/mshta 等解释器 → HIGH / ``DEFENDER_EXCLUSION``

读取失败（标准用户常见：Exclusions 键受保护）→ SKIPPED Finding，不中断扫描。
"""

from __future__ import annotations

import os
import winreg
from typing import Any, Iterator

from core import utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "RegistryPolicy"

_BROWSER_POLICY_ROOTS = (
    ("Google Chrome", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome"),
    ("Google Chrome", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Google\Chrome"),
    ("Microsoft Edge", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge"),
    ("Microsoft Edge", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Edge"),
)
# 规范点名的高危策略值（存在且非空即 HIGH）
_HIGH_RISK_POLICY_PREFIXES = (
    "ExtensionInstallForcelist",
    "HomepageLocation",
    "DefaultSearchProvider",
)

_DEFENDER_EXCLUSION_KEYS = (
    ("Paths", r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"),
    ("Processes", r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"),
)
_SUSPICIOUS_EXCLUDED_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msbuild.exe",
    "installutil.exe",
}

_VIEW_FLAGS = ((winreg.KEY_WOW64_64KEY, "64"), (winreg.KEY_WOW64_32KEY, "32"))


# ---------------------------------------------------------------------------
# 浏览器策略
# ---------------------------------------------------------------------------


def _iter_key_values(hive: int, subkey: str, view_flag: int) -> Iterator[tuple[str, Any, int]]:
    """枚举注册表键的第一层值（权不足时抛 PermissionError 交由调用方降级）。"""
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as key:
            value_count = winreg.QueryInfoKey(key)[1]
            for index in range(value_count):
                try:
                    yield winreg.EnumValue(key, index)
                except OSError:
                    continue
    except FileNotFoundError:
        return
    except OSError:
        raise


def _value_is_non_empty(data: Any) -> bool:
    if isinstance(data, str):
        return bool(data.strip())
    if isinstance(data, (list, tuple)):
        return any(str(item).strip() for item in data)
    if isinstance(data, bytes):
        return bool(data)
    return data is not None


def _browser_policy_finding(
    browser: str,
    key_path: str,
    value_name: str,
    data: Any,
    value_type: int,
) -> dict[str, Any] | None:
    """单条浏览器策略值判定（纯函数，便于单元测试）。"""
    if not value_name.startswith(_HIGH_RISK_POLICY_PREFIXES):
        return None
    if not _value_is_non_empty(data):
        return None
    return make_finding(
        "HIGH",
        CATEGORY,
        f"{key_path}\{value_name}",
        f"{browser} 策略键被设置为非空值（{value_name}）：{truncate(data, 200)}",
        {
            "browser": browser,
            "key": key_path,
            "value_name": value_name,
            "value": truncate(data, 400),
            "value_type": value_type,
        },
        "POLICY_HIJACK",
    )


def _check_browser_policies() -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for browser, hive, subkey in _BROWSER_POLICY_ROOTS:
        hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        views = _VIEW_FLAGS if hive == winreg.HKEY_LOCAL_MACHINE else ((0, "默认"),)
        for view_flag, view_name in views:
            key_path = f"{hive_name}\\{subkey}（{view_name}）"
            try:
                for name, data, value_type in _iter_key_values(hive, subkey, view_flag):
                    finding = _browser_policy_finding(browser, key_path, str(name), data, value_type)
                    if finding:
                        findings.append(finding)
            except PermissionError as exc:
                errors.append(f"{key_path}: 拒绝访问（{exc}）")
            except OSError as exc:
                errors.append(f"{key_path}: {exc}")
    return findings, errors


# ---------------------------------------------------------------------------
# Defender 排除项
# ---------------------------------------------------------------------------


def _defender_entry_finding(
    kind: str,
    entry: str,
    key_path: str,
    view_name: str,
) -> dict[str, Any] | None:
    """单条 Defender 排除项判定（纯函数，便于单元测试）。"""
    evidence = {"kind": kind, "key": key_path, "entry": entry, "view": view_name}
    if kind == "Paths":
        if utils.is_user_writable(entry):
            return make_finding(
                "HIGH",
                CATEGORY,
                entry,
                f"Defender 排除路径位于用户可写目录：{truncate(entry, 240)}",
                evidence,
                "DEFENDER_EXCLUSION",
            )
        return None
    basename = os.path.basename(utils.normalize_path(entry)).lower()
    if basename in _SUSPICIOUS_EXCLUDED_PROCESSES:
        return make_finding(
            "HIGH",
            CATEGORY,
            entry,
            f"Defender 排除了脚本解释器/常用 LOLBin：{basename}",
            evidence,
            "DEFENDER_EXCLUSION",
        )
    return None


def _check_defender_exclusions() -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for kind, subkey in _DEFENDER_EXCLUSION_KEYS:
        key_path = f"HKLM\\{subkey}"
        opened = False
        for view_flag, view_name in _VIEW_FLAGS:
            try:
                values = list(_iter_key_values(winreg.HKEY_LOCAL_MACHINE, subkey, view_flag))
            except PermissionError as exc:
                if not opened:
                    errors.append(f"{key_path}（{view_name}）: 拒绝访问（{exc}）")
                continue
            except OSError:
                continue
            opened = True
            for name, _data, _value_type in values:
                entry = str(name).strip()
                if not entry:
                    continue
                finding = _defender_entry_finding(kind, entry, key_path, view_name)
                if finding:
                    findings.append(finding)
    return findings, errors


# ---------------------------------------------------------------------------
# 模块入口
# ---------------------------------------------------------------------------


def scan() -> list[dict[str, Any]]:
    """扫描浏览器策略键与 Defender 排除项，返回 ``list[Finding]``。"""
    findings: list[dict[str, Any]] = []
    errors: list[str] = []

    policy_findings, policy_errors = _check_browser_policies()
    findings.extend(policy_findings)
    errors.extend(policy_errors)

    exclusion_findings, exclusion_errors = _check_defender_exclusions()
    findings.extend(exclusion_findings)
    errors.extend(exclusion_errors)

    if errors:
        findings.append(
            make_skipped(
                CATEGORY,
                "Policies/DefenderExclusions",
                "部分策略/排除项位置无法读取（权限不足）：" + "；".join(errors[:5]),
                {"errors": errors},
                "POLICY_ACCESS_DENIED",
            )
        )
    return utils.apply_whitelist(findings)
