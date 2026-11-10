# -*- coding: utf-8 -*-
"""扫描调度核心（CLI 与 GUI 共用）。

把原先散落在 ``main.py`` 里的模块调度逻辑抽出来，供两个入口复用：

- CLI 入口：``main.py``
- GUI 入口：``gui.py``（阶段 1）

两者共用本模块后，模块顺序、异常降级、白名单、去重排序行为完全一致，
不会出现"GUI 和 CLI 结果对不上"的问题。
"""

from __future__ import annotations

import importlib
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

from .finding import dedupe_findings, make_skipped, sort_findings
from .utils import apply_whitelist, load_whitelist

# (模块名, 中文说明, 计划接入阶段) —— 与重构前 main.py 完全一致，保持 15 个模块顺序
MODULE_REGISTRY: tuple[tuple[str, str, int], ...] = (
    ("autoruns", "Autoruns 广度兜底（autorunsc64.exe）", 2),
    ("registry_run", "注册表 Run/RunOnce（64/32 位）", 3),
    ("registry_policy", "浏览器策略键 / Defender 排除项", 3),
    ("browser_settings", "IE/系统主页、搜索、代理", 3),
    ("startup_lnk", "Startup 启动目录 LNK", 3),
    ("scheduled_task", "计划任务", 4),
    ("service", "系统服务", 4),
    ("wmi_subscription", "WMI 永久订阅", 4),
    ("network", "Hosts / DNS", 4),
    ("bits", "BITS 作业", 4),
    ("powershell_profile", "PowerShell Profile", 4),
    ("com_hijack", "COM 劫持（InprocServer32）", 4),
    ("lsa_appinit", "LSA / AppInit / IFEO", 4),
    ("browser_ext", "浏览器扩展深度检测", 5),
    ("lolbin_process", "LOLBin 进程与内存扫描", 6),
)

ProgressCallback = Callable[[int, int, str], None]


@dataclass
class ScanResult:
    """一次扫描的完整结果。

    Attributes:
        findings: 已完成白名单降级、去重、排序的 Finding 列表。
        duration: 扫描耗时（秒）。
        modules_total: 本次实际调度的模块数（受 ``module_filter`` 影响）。
        modules_available: 成功执行 ``scan()`` 的模块数。
        module_status: 每个模块的状态
            ``{name, label, stage, status, count, error}``（status 为 ok/failed/unimplemented/error）。
        errors: 模块导入/执行失败的错误信息（供 CLI 警告与 GUI 展示）。
    """

    findings: list[dict[str, Any]]
    duration: float
    modules_total: int
    modules_available: int
    module_status: list[dict[str, Any]]
    errors: list[str] = field(default_factory=list)


def load_scanner(name: str) -> tuple[Any | None, str | None]:
    """导入 ``modules.<name>`` 并校验 ``scan()`` 接口。

    Returns:
        ``(module, error)``。error 为 ``"unimplemented"`` 表示模块尚未实现，
        其它字符串表示导入/依赖/接口错误。
    """
    module_name = f"modules.{name}"
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if getattr(exc, "name", "") == module_name:
            return None, "unimplemented"
        return None, f"依赖缺失: {exc}"
    except Exception as exc:  # noqa: BLE001 - 任何导入错误都降级为警告
        return None, f"导入失败: {type(exc).__name__}: {exc}"
    scanner = getattr(module, "scan", None)
    if not callable(scanner):
        return None, "模块未提供 scan() 接口"
    return module, None


def _configure_memory(module: Any, memory_scan: bool, max_memory_scan: int) -> None:
    """仅对进程模块透传内存扫描配置（不改其它模块，也不改扫描逻辑）。"""
    module_short_name = getattr(module, "__name__", "").rsplit(".", 1)[-1]
    if module_short_name != "lolbin_process":
        return
    try:
        module.ENABLE_MEMORY_SCAN = bool(memory_scan)
        module.MAX_MEMORY_SCAN = max(0, int(max_memory_scan))
    except (AttributeError, TypeError, ValueError):
        pass


def _emit_progress(
    callback: ProgressCallback | None,
    current: int,
    total: int,
    message: str,
) -> None:
    """安全地调用进度回调：回调自身异常不能影响扫描。"""
    if not callable(callback):
        return
    try:
        callback(int(current), int(total), str(message))
    except Exception:  # noqa: BLE001 - 进度 UI 的异常与扫描无关
        pass


def run_scan(
    progress_callback: ProgressCallback | None = None,
    memory_scan: bool = True,
    max_memory_scan: int = 10,
    module_filter: list[str] | None = None,
    whitelist: dict[str, Any] | None = None,
) -> ScanResult:
    """依次调度扫描模块，返回规整后的 ``ScanResult``。

    Args:
        progress_callback: ``callback(current, total, message)``；每完成一个模块回调一次。
        memory_scan: 是否启用进程内存扫描（透传给 ``lolbin_process``）。
        max_memory_scan: 内存扫描最多进程数（透传给 ``lolbin_process``）。
        module_filter: 只运行指定模块（CLI ``--module`` 调试用；GUI 不传）。
        whitelist: 白名单配置（缺省从 ``rules/whitelist.json`` 加载）。

    单个模块失败不影响其它模块：失败模块会变成一条 ``SKIPPED / MODULE_ERROR``
    Finding，并记录到 ``ScanResult.errors``。
    """
    config = whitelist if whitelist is not None else load_whitelist()
    started = time.perf_counter()
    findings: list[dict[str, Any]] = []
    module_status: list[dict[str, Any]] = []
    errors: list[str] = []

    selected = [
        item for item in MODULE_REGISTRY if not module_filter or item[0] in module_filter
    ]
    total = len(selected)

    for index, (name, label, stage) in enumerate(selected, start=1):
        _emit_progress(progress_callback, index - 1, total, f"正在扫描: {label}")
        module, error = load_scanner(name)
        if module is None:
            status = "unimplemented" if error == "unimplemented" else "failed"
            module_status.append(
                {"name": name, "label": label, "stage": stage, "status": status, "count": 0, "error": error}
            )
            if error != "unimplemented":
                errors.append(f"{name}: {error}")
            continue

        _configure_memory(module, memory_scan, max_memory_scan)
        try:
            produced = module.scan() or []
            if not isinstance(produced, list):
                raise TypeError(f"scan() 返回 {type(produced).__name__}，应为 list[Finding]")
        except Exception as exc:  # noqa: BLE001 - 单模块异常降级，不中断整体扫描
            detail = f"模块执行异常：{type(exc).__name__}: {exc}"
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
            module_status.append(
                {
                    "name": name,
                    "label": label,
                    "stage": stage,
                    "status": "error",
                    "count": 0,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            findings.append(
                make_skipped(
                    name,
                    f"模块:{name}",
                    detail,
                    {"traceback": traceback.format_exc()},
                    "MODULE_ERROR",
                )
            )
            _emit_progress(progress_callback, index, total, f"模块异常: {label}")
            continue

        findings.extend(produced)
        module_status.append(
            {"name": name, "label": label, "stage": stage, "status": "ok", "count": len(produced), "error": None}
        )
        _emit_progress(progress_callback, index, total, f"已完成: {label}")

    elapsed = time.perf_counter() - started

    # 白名单降级（默认 downgrade：保留 INFO 记录便于追溯；配置为 filter/off 时按配置）
    whitelist_mode = str(config.get("mode") or "downgrade").lower()
    if whitelist_mode not in ("downgrade", "filter", "off"):
        whitelist_mode = "downgrade"
    filtered = apply_whitelist(findings, config, mode=whitelist_mode)

    normalized = sort_findings(dedupe_findings(filtered, merge_rule_base=True))
    _emit_progress(progress_callback, total, total, "扫描完成")

    return ScanResult(
        findings=normalized,
        duration=elapsed,
        modules_total=len(module_status),
        modules_available=sum(1 for item in module_status if item["status"] == "ok"),
        module_status=module_status,
        errors=errors,
    )
