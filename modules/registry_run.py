# -*- coding: utf-8 -*-
"""注册表 Run/RunOnce 自启动项（阶段 3，第一梯队）。

覆盖 HKLM/HKCU 的 ``Run`` / ``RunOnce``，且分别以 **64 位** 与 **32 位
（WOW6432Node）** 视图枚举，避免漏掉 32 位写法的启动项。

判定规则（遵守规范汇总表）：

- ``RUN_USERWRITABLE`` HIGH  启动项指向用户可写目录
- ``RUN_LOLBIN``       HIGH  启动项命令行命中 LOLBin / 下载 / 编码执行特征
- ``RUN_MASQUERADE``   HIGH  伪装系统组件：系统二进制名（svchost.exe 等）出现在
                            系统目录之外，或名称自称 Windows/微软组件但位于
                            非受信任位置且签名异常
- 同时调用 ``signature.signature_finding`` 做独立验签（SIG_UNSIGNED / SIG_INVALID / ...）

权限不足的键返回 SKIPPED Finding，不抛异常。
"""

from __future__ import annotations

import os
import winreg
from typing import Any, Iterator

from core import signature, utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "RegistryRun"

_RUN_SUBKEYS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
)
_VIEWS = (
    (winreg.KEY_WOW64_64KEY, "64"),
    (winreg.KEY_WOW64_32KEY, "32"),
)
_HIVES = (
    (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
    (winreg.HKEY_CURRENT_USER, "HKCU"),
)


def _iter_values() -> Iterator[dict[str, Any]]:
    """枚举四个注册表位置 × 两个 WOW64 视图的全部值。"""
    for hive, hive_name in _HIVES:
        # HKCU 不参与 WOW64 重定向，用默认视图即可；HKLM 才需要 64/32 两个视图
        views = _VIEWS if hive == winreg.HKEY_LOCAL_MACHINE else ((0, "默认视图"),)
        for subkey in _RUN_SUBKEYS:
            for view_flag, view_name in views:
                key_path = f"{hive_name}\\{subkey}（{view_name} 位视图）"
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as key:
                        value_count = winreg.QueryInfoKey(key)[1]
                        for index in range(value_count):
                            try:
                                name, data, value_type = winreg.EnumValue(key, index)
                            except OSError:
                                continue
                            if not isinstance(data, str) or not data.strip():
                                continue
                            yield {
                                "key_path": key_path,
                                "value_name": str(name),
                                "command": data.strip(),
                                "value_type": value_type,
                            }
                except FileNotFoundError:
                    continue
                except PermissionError as exc:
                    yield {"error": f"{key_path}: 拒绝访问（{exc}）"}
                except OSError as exc:
                    yield {"error": f"{key_path}: {exc}"}


def _is_masquerade(value_name: str, executable: str, sig_finding: dict[str, Any] | None) -> bool:
    """伪装系统组件判定（两条强信号）。"""
    if not executable:
        return False
    # 1) svchost.exe 这类系统二进制出现在系统目录之外
    if utils.is_system_binary_name(executable) and not utils.is_in_system_dir(executable):
        return True
    # 2) 值名自称 Windows/微软组件，但路径不在受信任位置且签名异常
    if (
        sig_finding is not None
        and utils.looks_like_system_component_name(value_name)
        and not utils.is_trusted_install_location(executable)
    ):
        return True
    return False


def _analyze(item: dict[str, Any]) -> list[dict[str, Any]]:
    """对单个 Run/RunOnce 值做判定。"""
    command = item["command"]
    value_name = item["value_name"]
    executable = utils.extract_executable(command)
    evidence: dict[str, Any] = {
        "key": item["key_path"],
        "value_name": value_name,
        "command": truncate(command, 400),
        "executable": executable,
        "value_type": item.get("value_type"),
    }
    findings: list[dict[str, Any]] = []
    target = executable or command

    # 独立验签
    sig_finding: dict[str, Any] | None = None
    if executable:
        sig_finding = signature.signature_finding(executable, category=CATEGORY)
        if sig_finding:
            sig_finding["evidence"].update({"registry": evidence})
            findings.append(sig_finding)

    # 用户可写目录
    if executable and utils.is_user_writable(executable):
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                target,
                f"Run 启动项指向用户可写目录：{truncate(executable, 200)}",
                dict(evidence),
                "RUN_USERWRITABLE",
            )
        )

    # 可疑命令行
    hit = utils.match_suspicious_cmdline(command)
    if hit:
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                target,
                f"Run 启动项命令行可疑（{hit['description']}）：{truncate(command, 180)}",
                {**evidence, "cmdline_hit": hit},
                "RUN_LOLBIN",
            )
        )

    # 伪装系统组件
    if _is_masquerade(value_name, executable, sig_finding):
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                target,
                f"疑似伪装系统组件：值名「{value_name}」指向 {truncate(executable, 200)}",
                dict(evidence),
                "RUN_MASQUERADE",
            )
        )

    return findings


def scan() -> list[dict[str, Any]]:
    """扫描 Run/RunOnce 自启动项，返回 ``list[Finding]``。"""
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for item in _iter_values():
        if "error" in item:
            errors.append(str(item["error"]))
            continue
        findings.extend(_analyze(item))

    if errors:
        findings.append(
            make_skipped(
                CATEGORY,
                "Run/RunOnce",
                "部分注册表启动项位置无法读取：" + "；".join(errors[:5]),
                {"errors": errors},
                "RUN_ACCESS_DENIED",
            )
        )
    return utils.apply_whitelist(findings)
