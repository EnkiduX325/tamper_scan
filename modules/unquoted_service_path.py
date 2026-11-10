# -*- coding: utf-8 -*-
"""未加引号的服务路径提权（Unquoted Service Path）检测。

背景
----
Windows 服务控制管理器（SCM）解析 ``ImagePath`` 时，如果可执行文件路径**含空格且
没有用双引号包裹**，CreateProcess 会按空格逐段尝试候选路径。攻击者在低权限可写的
上层目录中放入 ``Program.exe`` 之类的同名文件，就可能以服务的权限（通常 SYSTEM）
执行自己的代码，属于 MITRE ATT&CK T1574.009（Path Interception by Unquoted Path）。

示例（``C:\\Users\\Public\\My App\\svc.exe``）::

    C:\\Users.exe                  <- 攻击者可写 C:\\Users\\Public 时（此处仅为示例）
    C:\\Users\\Public\\My.exe      <- 攻击者可写该目录时
    C:\\Users\\Public\\My App\\svc.exe

检测规则
--------
- 复用 ``modules.service`` 的 ``Win32_Service`` 采集结果（**不重复查询 CIM/注册表**）：
  ``service.collect_services(max_age_seconds=180)`` 会优先复用 ``service.scan()``
  刚采集到的结果；单独运行本模块时才自行采集一次；
- ``ImagePath`` 含空格且**未以双引号完整包裹**，且服务 ``StartName`` 为 SYSTEM 类
  账户（``LocalSystem`` / ``NT AUTHORITY\\LocalSystem`` / ``NT AUTHORITY\\SYSTEM``）
  → **MEDIUM ``SVC_UNQUOTED_PATH``**；
- 证据：原始/展开后的 ImagePath、实际可执行文件、按空格拆分出的候选劫持路径、
  候选路径所在目录中**当前用户可写**的项（便于判断真实可利用性，不改变 MEDIUM 定级）；
- 字符串安全：判定使用完整字符串，展示统一 ``truncate``；超长/畸形路径不抛异常。

降级
----
- ``SVC_UNQUOTED_SKIPPED`` SKIPPED：服务采集失败（复用 service 模块的错误）；
- ``SVC_UNQUOTED_PARSE_ERROR`` SKIPPED：采集结果结构异常；
- ``SVC_UNQUOTED_PARTIAL`` SKIPPED：服务数量超过分析上限，部分未检查。

本模块只读分析，不执行命令、不修改系统状态。
"""

from __future__ import annotations

import os
from typing import Any

from core import utils
from core.finding import make_finding, make_skipped
from core.utils import truncate
from modules import service

CATEGORY = "UnquotedServicePath"

# 规则编号
RULE_UNQUOTED = "SVC_UNQUOTED_PATH"
RULE_SKIPPED = "SVC_UNQUOTED_SKIPPED"
RULE_PARSE_ERROR = "SVC_UNQUOTED_PARSE_ERROR"
RULE_PARTIAL = "SVC_UNQUOTED_PARTIAL"

# 复用 service 模块采集结果的时限（秒）：同一次扫描/两次 GUI 刷新内命中缓存
_SERVICE_CACHE_MAX_AGE = 180.0

_MAX_SERVICES = 5000
_MAX_CANDIDATES = 20

_EXEC_SUFFIXES = frozenset({".exe", ".com", ".scr", ".pif"})

# Win32_Service.StartName 中代表 SYSTEM 权限的写法
_SYSTEM_ACCOUNTS = frozenset(
    {
        "localsystem",
        "nt authority\\localsystem",
        "nt authority\\system",
        "system",
        ".\\localsystem",
        "local system",
    }
)


def _is_system_account(start_name: Any) -> bool:
    """判断服务运行账户是否为 SYSTEM 类账户（大小写/首尾空白容错）。"""
    text = " ".join(str(start_name or "").strip().lower().split())
    return bool(text) and text in _SYSTEM_ACCOUNTS


def _looks_like_executable(token: str) -> bool:
    try:
        return os.path.splitext(str(token or ""))[1].lower() in _EXEC_SUFFIXES
    except (TypeError, ValueError):
        return False


def _parse_unquoted_path(path_name: Any) -> dict[str, Any] | None:
    """解析 ImagePath，判断是否存在"含空格且未加引号"的路径歧义。

    Returns:
        None 表示安全/不适用（已正确加引号、无空格、路径为空）；否则返回解析结果 dict。
    """
    raw = str(path_name or "").strip()
    if not raw:
        return None
    try:
        expanded = str(utils.expand_vars(raw) or "").strip()
    except Exception:  # noqa: BLE001 - 变量展开失败按原值继续分析
        expanded = raw
    if not expanded:
        return None
    # 判定使用完整字符串（不提前截断，避免把超长路径中的空格截掉导致漏报）；
    # token 数与候选数都有上限，病态输入不会拖垮扫描。
    text = expanded

    result: dict[str, Any] = {
        "raw": raw,
        "expanded": expanded,
        "quoted": False,
        "unbalanced_quote": False,
        "actual_exe": "",
        "first_token": "",
        "candidates": [],
    }

    if text.startswith('"'):
        closing = text.find('"', 1)
        if closing < 0:
            # 只有开引号没有闭引号：SCM 解析同样存在歧义，按可疑处理
            result["unbalanced_quote"] = True
            result["actual_exe"] = utils.normalize_path(text[1:].strip())
            return result
        # 正确包裹的引号路径：SCM 可无歧义解析，安全
        result["quoted"] = True
        return None

    if " " not in text:
        # 路径本身不含空格：不存在歧义
        return None

    tokens = text.split(" ")
    result["first_token"] = tokens[0]

    # 逐段累加，找到真正的 exe 结尾（其后的空格属于命令行参数）
    actual = ""
    consumed = 0
    for index in range(min(len(tokens), 256)):
        prefix = " ".join(tokens[: index + 1])
        if _looks_like_executable(prefix):
            actual = prefix
            consumed = index + 1
            break

    if actual:
        # 只有"含空格的可执行文件路径"才存在路径歧义；exe 本身无空格 + 参数含空格是安全的
        if " " not in actual:
            return None
        result["actual_exe"] = utils.normalize_path(actual)
        exe_tokens = actual.split(" ")
    else:
        # 无法定位 exe 结尾的畸形路径：保守提示，候选按所有空格构造
        result["actual_exe"] = utils.normalize_path(text)
        consumed = len(tokens)
        exe_tokens = tokens[:consumed]

    candidates: list[str] = []
    running = ""
    for part in exe_tokens[:-1]:
        if len(candidates) >= _MAX_CANDIDATES:
            break
        running = part if not running else f"{running} {part}"
        candidates.append(f"{running}.exe")
    result["candidates"] = candidates
    return result


def _writable_candidates(candidates: list[str]) -> list[dict[str, str]]:
    """找出候选劫持路径中"所在目录可被当前用户写入"的项（仅证据，不改变定级）。"""
    writable: list[dict[str, str]] = []
    for candidate in candidates:
        try:
            directory = os.path.dirname(candidate)
            if directory and utils.is_user_writable(directory):
                writable.append(
                    {
                        "candidate": truncate(candidate, 260),
                        "directory": truncate(directory, 260),
                    }
                )
        except Exception:  # noqa: BLE001 - 权限探测失败不影响主判定
            continue
    return writable


def _analyze_service(record: dict[str, Any]) -> list[dict[str, Any]]:
    """对单个 ``Win32_Service`` 记录做判定（纯函数，便于单元测试）。"""
    name = str(record.get("Name") or "").strip()
    display_name = str(record.get("DisplayName") or "").strip()
    path_name = str(record.get("PathName") or "").strip()
    start_name = str(record.get("StartName") or "").strip()
    if not path_name:
        return []
    # 只关心以 SYSTEM 权限运行的服务（User/NetworkService/LocalService 不满足提权前提）
    if not _is_system_account(start_name):
        return []
    parsed = _parse_unquoted_path(path_name)
    if parsed is None:
        return []

    candidates = list(parsed.get("candidates") or [])
    writable = _writable_candidates(candidates)
    evidence: dict[str, Any] = {
        "service_name": name,
        "display_name": truncate(display_name, 200),
        "start_name": start_name,
        "start_mode": record.get("StartMode"),
        "state": record.get("State"),
        # 原始值可能很长：判定用完整值，展示统一截断
        "path_name": truncate(path_name, 400),
        "path_name_length": len(path_name),
        "expanded_path": truncate(parsed.get("expanded") or "", 400),
        "quoted": False,
        "unbalanced_quote": bool(parsed.get("unbalanced_quote")),
        "actual_exe": truncate(parsed.get("actual_exe") or "", 300),
        "first_token": truncate(parsed.get("first_token") or "", 200),
        "candidates": [truncate(candidate, 300) for candidate in candidates],
        "writable_candidates": writable,
    }
    if parsed.get("unbalanced_quote"):
        detail = (
            f"服务 {name}（{display_name}）的 ImagePath 以引号开头但缺少闭合引号，且以 {start_name} 运行："
            f"{truncate(path_name, 200)}；疑似手工篡改，需人工确认"
        )
    else:
        detail = (
            f"服务 {name}（{display_name}）的 ImagePath 含空格且未加引号，且以 {start_name} 运行："
            f"{truncate(path_name, 200)}；存在未加引号服务路径提权风险（T1574.009）"
        )
        if writable:
            detail += f"，且 {len(writable)} 个候选劫持目录对当前用户可写"
    return [
        make_finding(
            "MEDIUM",
            CATEGORY,
            truncate(path_name, 400),
            truncate(detail, 400),
            evidence,
            RULE_UNQUOTED,
        )
    ]


def scan() -> list[dict[str, Any]]:
    """复用 service 模块采集结果，检测未加引号的服务路径，返回 ``list[Finding]``。"""
    try:
        data, error = service.collect_services(max_age_seconds=_SERVICE_CACHE_MAX_AGE)
    except Exception as exc:  # noqa: BLE001 - 采集层异常降级
        return [
            make_skipped(
                CATEGORY,
                "Win32_Service",
                f"未加引号服务路径检测无法执行：服务采集异常 {type(exc).__name__}: {exc}",
                {"error": f"{type(exc).__name__}: {exc}"},
                RULE_SKIPPED,
            )
        ]
    if error:
        return [
            make_skipped(
                CATEGORY,
                "Win32_Service",
                f"未加引号服务路径检测无法执行：服务采集失败（复用 service 模块）：{error}",
                {"error": error},
                RULE_SKIPPED,
            )
        ]
    try:
        records, parse_error = service.normalize_service_records(data)
    except Exception as exc:  # noqa: BLE001
        records, parse_error = None, f"{type(exc).__name__}: {exc}"
    if parse_error or records is None:
        return [
            make_skipped(
                CATEGORY,
                "Win32_Service",
                f"未加引号服务路径检测无法执行：{parse_error or '服务数据结构异常'}",
                {"sample": truncate(data, 400)},
                RULE_PARSE_ERROR,
            )
        ]

    findings: list[dict[str, Any]] = []
    selected = records[:_MAX_SERVICES]
    for record in selected:
        try:
            findings.extend(_analyze_service(record))
        except Exception:  # noqa: BLE001 - 单条服务解析异常不影响其余服务
            continue
    if len(records) > len(selected):
        findings.append(
            make_skipped(
                CATEGORY,
                "Win32_Service",
                f"服务数量超过分析上限（{len(records)} > {_MAX_SERVICES}），{len(records) - len(selected)} 个服务未检查",
                {"total": len(records), "limit": _MAX_SERVICES},
                RULE_PARTIAL,
            )
        )
    return utils.apply_whitelist(findings)
