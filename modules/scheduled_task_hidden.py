# -*- coding: utf-8 -*-
"""计划任务隐藏检测（Tarrask / Index 篡改）。

背景
----
Windows 计划任务有两处注册表缓存：

- ``...\\Schedule\\TaskCache\\Tree\\<任务路径>``：任务名到任务 GUID 的索引，每个节点带
  ``Id``（GUID）、``Index``（DWORD）、``SD``（自相对安全描述符二进制）三个值；
  目录节点（如 ``\\Microsoft``）同样是可安全描述符对象，也会写 ``SD``。
- ``...\\Schedule\\TaskCache\\Tasks\\<GUID>``：任务定义（``Path`` / ``Actions`` /
  ``Triggers`` / ``SD`` 等）。

Tarrask（Microsoft 2022 披露）创建任务后删除 ``Tree\\<任务>`` 下的 ``SD`` 值：任务仍由
Task Scheduler 服务正常执行，但任务计划程序等工具读不到安全描述符，于是"看不见"该任务。
另一个变体把 ``Index`` 改成 0，使 ``schtasks /query`` 枚举时跳过该任务。两者均对应
SigmaHQ 规则：``registry_delete_schtasks_hide_task_via_sd_value_removal`` 与
``registry_set_hide_scheduled_task_via_index_tamper``。

规则
----
- ``TASK_HIDDEN_TARRASK``（默认 HIGH）：Tree 子键存在，但
  * ``SD`` 值缺失 / 为空 / 不是二进制安全描述符（Tarrask；目录节点同样有 ``SD``，
    删除目录的 ``SD`` 会把整个目录连同任务一起隐藏，因此任务/目录节点同等对待）；
  * ``Index`` 值为 0（DWORD 0x00000000，Qualys 2022 披露的枚举隐藏手法）；
  * 任务节点（有 ``Id``）的 ``Index`` 值被删除——Qualys 披露该手法会让
    ``schtasks /query`` 与任务计划程序整体枚举失败，从而隐藏全部任务。
  同一节点的多个证据合并为一条 Finding（``evidence.reasons`` 区分），并尽力从
  ``TaskCache\\Tasks\\<Id>`` 读出动作命令行，便于人工确认"隐藏任务到底执行了什么"。
- 降噪：``Index == 0`` 但节点没有对应 ``Tasks\\<Id>`` 定义（无 ``Id``，或 ``Tasks``
  键不存在）时，更可能是历史残留键/卸载残渣——Qualys 2022 与实战应急响应记录
  显示默认系统上此类节点并不罕见（例如 Edge 升级程序的 Index 会动态变化）。这类
  节点按 :data:`STALE_INDEX_ZERO_SEVERITY`（默认 MEDIUM）上报并标记
  ``evidence.stale_candidate=True``；把它改成 ``"HIGH"`` 即恢复严格规则。

降级（本模块不抛异常）
----------------------
- ``TASK_HIDDEN_ACCESS_DENIED`` SKIPPED：``TaskCache\\Tree`` 本身拒绝访问
  （标准用户必然如此：该键只有 Administrators / SYSTEM 可读）；
- ``TASK_HIDDEN_SKIPPED`` SKIPPED：注册表键缺失或未预期异常；
- ``TASK_HIDDEN_PARTIAL`` SKIPPED：部分子键读取失败，结果可能不完整。

性能与安全
----------
只读注册表，不执行命令、不修改系统状态；Tree 遍历带深度（32）与节点数（20000）上限，
正常情况全量遍历在毫秒级完成。遍历截断/子键读取失败会以 ``TASK_HIDDEN_PARTIAL``
（SKIPPED）显式上报，避免"看起来干净"的假阴性。
"""

from __future__ import annotations

import re
import winreg
from typing import Any

from core import utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "ScheduledTaskHidden"

# 规则编号
RULE_TARRASK = "TASK_HIDDEN_TARRASK"
RULE_ACCESS_DENIED = "TASK_HIDDEN_ACCESS_DENIED"
RULE_SKIPPED = "TASK_HIDDEN_SKIPPED"
RULE_PARTIAL = "TASK_HIDDEN_PARTIAL"

# Index==0 但 Tree 节点无对应 Tasks\<Id> 定义（历史残留键常见）时的严重等级。
# 需要严格按"Index==0 一律 HIGH"验收时，改成 "HIGH" 即可（规则编号不变）。
STALE_INDEX_ZERO_SEVERITY = "MEDIUM"

_TREE_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
_TASKS_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
_ROOT_DISPLAY = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"

# TaskCache 是 64 位共享键（不做 WOW64 重定向），显式 64 位视图避免 32 位进程读错。
_VIEW_FLAG = winreg.KEY_WOW64_64KEY

# 遍历上限：防御异常/恶意的超深路径或海量子键拖垮扫描
_MAX_DEPTH = 32
_MAX_NODES = 20000

_ID_VALUE = "Id"
_INDEX_VALUE = "Index"
_SD_VALUE = "SD"

_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# Tasks\<GUID>\Actions 是 UTF-16LE 的 XML 片段，下面两个正则只做"尽力提取"，失败不影响判定。
_COMMAND_RE = re.compile(r"(?is)<Command>(.*?)</Command>")
_ARGUMENTS_RE = re.compile(r"(?is)<Arguments>(.*?)</Arguments>")

_REASON_DESCRIPTIONS: dict[str, str] = {
    "sd_missing": "SD 值缺失（Tarrask 隐藏手法：任务仍会执行，但不会出现在任务计划程序中）",
    "sd_empty": "SD 值为空（安全描述符被清空，隐藏手法）",
    "sd_not_binary": "SD 值不是二进制安全描述符（疑似被篡改）",
    "index_zero": "Index 值为 0（会从 schtasks /query 等枚举结果中隐藏）",
    "index_missing": "Index 值被删除（会让 schtasks/任务计划程序整体枚举失败，隐藏全部任务）",
}


def _is_access_denied(exc: BaseException) -> bool:
    """区分"拒绝访问"与其它 OSError：winreg 抛 PermissionError（winerror=5）。"""
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5


def _registry_flags(view_flag: int) -> int:
    return winreg.KEY_READ | int(view_flag or 0)


# ---------------------------------------------------------------------------
# 注册表采集
# ---------------------------------------------------------------------------


def _iter_tree_node_paths(
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    root: str = _TREE_KEY,
    view_flag: int = _VIEW_FLAG,
) -> tuple[list[str], dict[str, Any], str | None]:
    """递归枚举 ``TaskCache\\Tree`` 下的所有节点（相对路径，用 ``\\`` 分隔）。

    Args:
        hive: 注册表根键（测试可注入 ``HKEY_CURRENT_USER``）。
        root: Tree 根键子路径（测试可注入临时键）。
        view_flag: WOW64 视图标志（测试可传 0）。

    Returns:
        ``(节点相对路径列表, 统计信息, 致命错误信息)``。
        致命错误指 Tree 根键本身打开失败（权限/不存在），此时列表为空；
        子键级失败只计入统计信息，不影响其余节点。
    """
    paths: list[str] = []
    stats: dict[str, Any] = {"nodes": 0, "denied": 0, "errors": 0, "truncated": 0, "fatal_kind": ""}
    flags = _registry_flags(view_flag)

    def walk(relative: str, depth: int) -> None:
        if len(paths) >= _MAX_NODES:
            stats["truncated"] += 1
            return
        full = root if not relative else f"{root}\\{relative}"
        children: list[str] = []
        try:
            with winreg.OpenKey(hive, full, 0, flags) as key:
                try:
                    child_count = int(winreg.QueryInfoKey(key)[0])
                except OSError:
                    child_count = 0
                for index in range(child_count):
                    try:
                        children.append(winreg.EnumKey(key, index))
                    except OSError:
                        stats["errors"] += 1
                        break
        except FileNotFoundError:
            if relative:
                stats["errors"] += 1
            else:
                stats["fatal_kind"] = "not_found"
            return
        except OSError as exc:
            if not relative:
                stats["fatal_kind"] = "access_denied" if _is_access_denied(exc) else "open_failed"
            elif _is_access_denied(exc):
                stats["denied"] += 1
            else:
                stats["errors"] += 1
            return

        for child in children:
            # 节点上限必须在 append 前检查：否则单层海量子键可一次突破 _MAX_NODES
            if len(paths) >= _MAX_NODES:
                stats["truncated"] += 1
                return
            child_path = child if not relative else f"{relative}\\{child}"
            paths.append(child_path)
            if depth + 1 >= _MAX_DEPTH:
                stats["truncated"] += 1
                continue
            walk(child_path, depth + 1)

    walk("", 0)
    stats["nodes"] = len(paths)
    paths.sort(key=str.lower)

    kind = stats["fatal_kind"]
    if kind == "access_denied":
        return [], stats, f"拒绝访问（需要管理员权限）：{_ROOT_DISPLAY}"
    if kind == "not_found":
        return [], stats, f"注册表键不存在：{_ROOT_DISPLAY}"
    if kind == "open_failed":
        return [], stats, f"打开注册表键失败：{_ROOT_DISPLAY}"
    return paths, stats, None


def _read_node_values(
    relative: str,
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    root: str = _TREE_KEY,
    view_flag: int = _VIEW_FLAG,
) -> tuple[dict[str, tuple[Any, int]], str | None]:
    """读取单个 Tree 节点的全部值：``{值名: (数据, 类型)}``；失败返回错误描述。"""
    full = root if not relative else f"{root}\\{relative}"
    values: dict[str, tuple[Any, int]] = {}
    try:
        with winreg.OpenKey(hive, full, 0, _registry_flags(view_flag)) as key:
            try:
                value_count = int(winreg.QueryInfoKey(key)[1])
            except OSError:
                value_count = 0
            for index in range(value_count):
                try:
                    name, data, value_type = winreg.EnumValue(key, index)
                except OSError:
                    return values, f"枚举值失败（第 {index} 个）"
                values[str(name)] = (data, value_type)
    except FileNotFoundError:
        return values, "子键已不存在"
    except OSError as exc:
        return values, "拒绝访问" if _is_access_denied(exc) else f"{type(exc).__name__}: {exc}"
    return values, None


# ---------------------------------------------------------------------------
# 值解析（纯函数，便于单元测试）
# ---------------------------------------------------------------------------


def _int_value(values: dict[str, tuple[Any, int]]) -> int | None:
    """把 ``Index`` 值转成整数；缺失或类型无法解析返回 None。"""
    entry = values.get(_INDEX_VALUE)
    if entry is None:
        return None
    data = entry[0]
    if isinstance(data, bool):
        return int(data)
    if isinstance(data, int):
        return data
    if isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
        if 1 <= len(raw) <= 8:
            return int.from_bytes(raw, "little")
        return None
    if isinstance(data, str):
        try:
            return int(data.strip(), 0)
        except (TypeError, ValueError):
            return None
    return None


def _sd_state(values: dict[str, tuple[Any, int]]) -> tuple[bool, int, str]:
    """判断 ``SD`` 值状态：``(是否存在, 字节长度, 异常原因)``，合理时原因为空串。"""
    entry = values.get(_SD_VALUE)
    if entry is None:
        return False, 0, "sd_missing"
    data = entry[0]
    if isinstance(data, (bytes, bytearray)):
        length = len(data)
        return True, length, "sd_empty" if length == 0 else ""
    if data is None or data == "":
        return True, 0, "sd_empty"
    return True, 0, "sd_not_binary"


def _task_id_text(values: dict[str, tuple[Any, int]]) -> str:
    """读取 ``Id`` 的 GUID 文本（正常为 REG_SZ，容错二进制）。"""
    entry = values.get(_ID_VALUE)
    if entry is None:
        return ""
    data = entry[0]
    if isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
        for encoding in ("utf-16-le", "latin-1"):
            text = raw.decode(encoding, "ignore").replace("\x00", "").strip()
            if text:
                return text
        return ""
    return str(data or "").strip()


def _parse_actions(raw: Any) -> tuple[str, str]:
    """从 ``Tasks\\<GUID>\\Actions`` 的二进制 XML 中尽力提取命令与参数。"""
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw).decode("utf-16-le", "ignore")
        if "<" not in text:
            text = bytes(raw).decode("latin-1", "ignore")
    else:
        text = str(raw or "")
    if not text.strip():
        return "", ""

    def _clean(items: list[str]) -> list[str]:
        return [truncate(" ".join(item.split()), 200) for item in items if str(item or "").strip()]

    commands = _clean(_COMMAND_RE.findall(text))
    arguments = _clean(_ARGUMENTS_RE.findall(text))
    return truncate(" ; ".join(commands), 400), truncate(" ; ".join(arguments), 400)


def _read_task_definition(task_id: str) -> dict[str, Any]:
    """尽力读取 ``Tasks\\<GUID>`` 的任务定义。

    返回值同时用于 evidence 和 "Index==0 是否属于活跃任务" 的降噪判断：
    ``definition_exists`` 表示 ``Tasks\\<Id>`` 键是否存在，``definition_error``
    记录读取失败原因（拒绝访问等异常时**不**据此降级，避免漏报）。
    """
    guid = str(task_id or "").strip().strip("{}").strip()
    if not _GUID_RE.match(guid):
        return {}
    evidence: dict[str, Any] = {}
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, f"{_TASKS_KEY}\\{{{guid}}}", 0, _registry_flags(_VIEW_FLAG)
        ) as key:
            evidence["definition_exists"] = True
            value_names: set[str] = set()
            try:
                value_count = int(winreg.QueryInfoKey(key)[1])
            except OSError:
                value_count = 0
            for index in range(value_count):
                try:
                    value_names.add(str(winreg.EnumValue(key, index)[0]))
                except OSError:
                    break
            evidence["definition_sd_present"] = _SD_VALUE in value_names
            evidence["definition_values"] = sorted(value_names)
            try:
                path_value = winreg.QueryValueEx(key, "Path")[0]
                evidence["definition_path"] = truncate(str(path_value or ""), 300)
            except OSError:
                pass
            try:
                actions_value = winreg.QueryValueEx(key, "Actions")[0]
            except OSError:
                actions_value = None
            if actions_value is not None:
                command, arguments = _parse_actions(actions_value)
                if command:
                    evidence["command"] = command
                if arguments:
                    evidence["arguments"] = arguments
    except FileNotFoundError:
        return {"definition_exists": False}
    except OSError as exc:
        message = "拒绝访问" if _is_access_denied(exc) else f"{type(exc).__name__}: {exc}"
        return {"definition_exists": False, "definition_error": message}
    except Exception:  # noqa: BLE001 - evidence 增强失败绝不能影响判定
        return {"definition_exists": False, "definition_error": "读取异常"}
    return evidence


def _analyze_node(relative: str, values: dict[str, tuple[Any, int]]) -> list[dict[str, Any]]:
    """对单个 Tree 节点做判定（纯函数，便于单元测试）。"""
    task_name = relative.rsplit("\\", 1)[-1] if relative else ""
    task_label = f"\\{relative}" if relative else "\\"
    sd_present, sd_length, sd_problem = _sd_state(values)
    index_value = _int_value(values)
    index_present = _INDEX_VALUE in values
    index_zero = index_value == 0

    reasons: list[str] = []
    if sd_problem:
        reasons.append(sd_problem)
    if index_zero:
        reasons.append("index_zero")
    # 任务节点（有 Id）的 Index 被删除：Qualys 披露会让 schtasks/任务计划程序整体枚举失败
    if not index_present and _ID_VALUE in values:
        reasons.append("index_missing")
    if not reasons:
        return []

    task_id = _task_id_text(values)
    node_kind = "task" if (_ID_VALUE in values or _INDEX_VALUE in values) else "folder"
    definitions: dict[str, Any] = _read_task_definition(task_id) if task_id else {}
    definition_exists = bool(definitions.get("definition_exists"))
    definition_error = str(definitions.get("definition_error") or "")
    # 降噪：只有 Index==0 且确认"没有对应 Tasks 定义"才视为历史残留（读取异常时不降级）
    stale_candidate = bool(index_zero and not sd_problem and not definition_exists and not definition_error)

    evidence: dict[str, Any] = {
        "task_name": task_name,
        "task_path": task_label,
        "registry_key": f"{_ROOT_DISPLAY}\\{relative}" if relative else _ROOT_DISPLAY,
        "node_kind": node_kind,
        "task_id": task_id,
        "index": index_value,
        "index_present": _INDEX_VALUE in values,
        "sd_present": sd_present,
        "sd_length": sd_length,
        "reasons": list(reasons),
        "value_names": sorted(str(name) for name in values),
        "task_definition_exists": definition_exists if definitions else None,
        "stale_candidate": stale_candidate,
    }
    if definitions:
        evidence["task_definition"] = definitions

    descriptions = [_REASON_DESCRIPTIONS.get(reason, reason) for reason in reasons]
    detail = f"计划任务缓存项 {truncate(task_label, 200)} 异常：" + "；".join(descriptions)
    severity = "HIGH"
    if stale_candidate:
        severity = STALE_INDEX_ZERO_SEVERITY
        detail += "；未找到对应 Tasks\\<Id> 定义（常见于历史残留键，请确认该任务是否仍会执行）"
    return [make_finding(severity, CATEGORY, task_label, detail, evidence, RULE_TARRASK)]


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------


def scan() -> list[dict[str, Any]]:
    """扫描 ``TaskCache\\Tree`` 的隐藏任务迹象，返回 ``list[Finding]``。"""
    try:
        paths, stats, fatal = _iter_tree_node_paths()
        if fatal:
            rule_id = RULE_ACCESS_DENIED if stats.get("fatal_kind") == "access_denied" else RULE_SKIPPED
            return [
                make_skipped(
                    CATEGORY,
                    _ROOT_DISPLAY,
                    f"计划任务隐藏检测无法执行：{fatal}",
                    {"error": stats.get("fatal_kind") or "open_failed", "stats": stats},
                    rule_id,
                )
            ]

        findings: list[dict[str, Any]] = []
        read_failures = 0
        for relative in paths:
            values, error = _read_node_values(relative)
            if error:
                read_failures += 1
                continue
            findings.extend(_analyze_node(relative, values))

        denied = int(stats.get("denied") or 0)
        errors = int(stats.get("errors") or 0) + read_failures
        truncated = int(stats.get("truncated") or 0)
        if denied or errors or truncated:
            parts: list[str] = []
            if denied or errors:
                parts.append(f"拒绝访问 {denied} 个子键 / 读取失败 {errors} 个子键")
            if truncated:
                parts.append(f"遍历达到上限，{truncated} 处子树/节点未检查（截断）")
            findings.append(
                make_skipped(
                    CATEGORY,
                    _ROOT_DISPLAY,
                    "计划任务缓存未完整检查，结果可能不完整：" + "；".join(parts),
                    {"stats": stats, "read_failures": read_failures, "truncated": truncated},
                    RULE_PARTIAL,
                )
            )
        return utils.apply_whitelist(findings)
    except Exception as exc:  # noqa: BLE001 - 采集层任何意外都降级为 SKIPPED，不中断整体扫描
        return [
            make_skipped(
                CATEGORY,
                _ROOT_DISPLAY,
                f"计划任务隐藏检测异常：{type(exc).__name__}: {exc}",
                {"error": f"{type(exc).__name__}: {exc}"},
                RULE_SKIPPED,
            )
        ]
