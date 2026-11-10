# -*- coding: utf-8 -*-
"""WMI 永久订阅检测（阶段 4）。

必须枚举三个命名空间：``root\\subscription``、``root\\default``、``root\\cimv2``。
``root\\default`` 是已知的绕过路径，常见工具只查 root\\subscription 会漏。

三种"空结果"必须区分（规范未细化，这里补齐）：
- 命名空间不存在（InvalidNamespace）→ 跳过，不报；
- 类不存在（InvalidClass）→ 正常情况，跳过；
- 权限不足（AccessDenied，标准用户读 root\\subscription 大概率如此）→
  ``SKIPPED / WMI_ACCESS_DENIED``，**绝不能当成"没有订阅"**。

规则：
- consumer 为 ``ActiveScriptEventConsumer`` / ``CommandLineEventConsumer`` → HIGH ``WMI_PERSIST``；
- 任意永久订阅（filter/consumer/binding）存在 → 至少 MEDIUM ``WMI_SUBSCRIPTION``。

每个命名空间的采集超时 10 秒；PowerShell 采集失败 → SKIPPED。
"""

from __future__ import annotations

from typing import Any

from core import utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "WMISubscription"

_NAMESPACES = ("root\\subscription", "root\\default", "root\\cimv2")
_DANGEROUS_CONSUMERS = {"ActiveScriptEventConsumer", "CommandLineEventConsumer"}

# Windows 自带的良性永久订阅（SCM 事件日志消费者），不能按"任意订阅"报 MEDIUM
_KNOWN_BENIGN_FILTERS = {"scm event log filter"}
_KNOWN_BENIGN_CONSUMERS = {"scm event log consumer"}
_KNOWN_BENIGN_CONSUMER_CLASSES = {"NTEventLogEventConsumer"}
_QUERY_TIMEOUT = 10  # 规范：每个查询 10 秒超时

_PS_TEMPLATE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$out = [pscustomobject]@{
  namespace = '@NAMESPACE@'
  filters = @()
  consumers = @()
  bindings = @()
  errors = @()
}
try {
  $out.filters = @(Get-CimInstance -Namespace '@NAMESPACE@' -ClassName __EventFilter -ErrorAction Stop | Select-Object Name, Query, EventNamespace)
} catch { $out.errors += ('filters: ' + $_.Exception.Message) }
try {
  $out.consumers = @(Get-CimInstance -Namespace '@NAMESPACE@' -ClassName __EventConsumer -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = $_.Name; ClassName = $_.CimClass.CimClassName; ScriptText = $_.ScriptText; ExecutablePath = $_.ExecutablePath; CommandLineTemplate = $_.CommandLineTemplate } })
} catch { $out.errors += ('consumers: ' + $_.Exception.Message) }
try {
  $out.bindings = @(Get-CimInstance -Namespace '@NAMESPACE@' -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Filter = [string]$_.Filter; Consumer = [string]$_.Consumer } })
} catch { $out.errors += ('bindings: ' + $_.Exception.Message) }
$out | ConvertTo-Json -Depth 5
"""


def _classify_error(message: str) -> str:
    """把 WMI 错误消息归类（中英文都覆盖）。"""
    text = str(message or "")
    lower = text.lower()
    if "access" in lower or "denied" in lower or "拒绝访问" in text or "权限" in text:
        return "access_denied"
    if (
        "invalidnamespace" in lower
        or "invalid namespace" in lower
        or "无效命名空间" in text
        or ("命名空间" in text and "无效" in text)
    ):
        return "missing_namespace"
    if "invalidclass" in lower or "invalid class" in lower or "无效类" in text:
        return "missing_class"
    if "not found" in lower or "找不到" in text or "不存在" in text:
        return "missing"
    return "other"


def _as_list(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _analyze_namespace(data: dict[str, Any]) -> list[dict[str, Any]]:
    """对单个命名空间的采集结果做判定（纯函数，便于单元测试）。"""
    namespace = str(data.get("namespace") or "")
    filters = _as_list(data.get("filters"))
    consumers = _as_list(data.get("consumers"))
    bindings = _as_list(data.get("bindings"))
    errors = [str(item) for item in (data.get("errors") or []) if str(item).strip()]

    error_kinds = {_classify_error(message) for message in errors}

    # 过滤 Windows 自带的良性订阅，避免把内置 SCM 事件日志消费者当成可疑
    benign_filter_names = {
        str(item.get("Name") or "").strip().lower() for item in filters
    } <= _KNOWN_BENIGN_FILTERS
    benign_consumer_names = {
        str(item.get("Name") or "").strip().lower() for item in consumers
    } <= _KNOWN_BENIGN_CONSUMERS
    benign_classes = {
        str(item.get("ClassName") or "").strip() for item in consumers
    } <= _KNOWN_BENIGN_CONSUMER_CLASSES
    if filters and consumers and benign_filter_names and benign_consumer_names and benign_classes:
        filters, consumers = [], []
        benign_binding = True
        filtered_bindings = []
        for binding in bindings:
            blob = f"{binding.get('Filter', '')} {binding.get('Consumer', '')}".lower()
            if any(name in blob for name in _KNOWN_BENIGN_FILTERS) or any(
                name in blob for name in _KNOWN_BENIGN_CONSUMERS
            ):
                continue
            filtered_bindings.append(binding)
        bindings = filtered_bindings

    has_data = bool(filters or consumers or bindings)
    if error_kinds == {"access_denied"} and not has_data:
        return [
            make_skipped(
                CATEGORY,
                namespace or "WMI",
                f"读取 {namespace} 命名空间被拒绝（AccessDenied），无法确认是否存在永久订阅",
                {"namespace": namespace, "errors": errors},
                "WMI_ACCESS_DENIED",
            )
        ]
    if not has_data:
        return []  # 命名空间/类不存在或确实没有订阅
    if "access_denied" in error_kinds:
        # 部分类不可读但已拿到数据：记录降级提示，继续分析已有数据
        findings: list[dict[str, Any]] = [
            make_skipped(
                CATEGORY,
                namespace or "WMI",
                f"{namespace} 部分 WMI 类无法读取（AccessDenied），结果可能不完整",
                {"namespace": namespace, "errors": errors},
                "WMI_ACCESS_DENIED_PARTIAL",
            )
        ]
    else:
        findings = []

    for consumer in consumers:
        class_name = str(consumer.get("ClassName") or "")
        name = str(consumer.get("Name") or "(未命名 consumer)")
        if class_name in _DANGEROUS_CONSUMERS:
            findings.append(
                make_finding(
                    "HIGH",
                    CATEGORY,
                    f"WMI:{namespace}:{name}",
                    f"发现高危 WMI 永久消费者 {class_name}（{name}）",
                    {
                        "namespace": namespace,
                        "consumer_name": name,
                        "consumer_class": class_name,
                        "script_text": truncate(consumer.get("ScriptText"), 500),
                        "executable_path": truncate(consumer.get("ExecutablePath"), 400),
                        "command_line_template": truncate(consumer.get("CommandLineTemplate"), 400),
                    },
                    "WMI_PERSIST",
                )
            )

    if bindings or (filters and consumers):
        findings.append(
            make_finding(
                "MEDIUM",
                CATEGORY,
                f"WMI:{namespace}",
                f"{namespace} 存在永久订阅（filter={len(filters)}, consumer={len(consumers)}, binding={len(bindings)}）",
                {
                    "namespace": namespace,
                    "filter_count": len(filters),
                    "consumer_count": len(consumers),
                    "binding_count": len(bindings),
                    "filters": filters,
                    "consumers": [{"Name": item.get("Name"), "ClassName": item.get("ClassName")} for item in consumers],
                    "bindings": bindings,
                },
                "WMI_SUBSCRIPTION",
            )
        )
    return findings


def _query_namespace(namespace: str) -> tuple[dict[str, Any] | None, str | None]:
    script = _PS_TEMPLATE.replace("@NAMESPACE@", namespace)
    data, error = utils.run_powershell_json(script, timeout=_QUERY_TIMEOUT)
    if error:
        return None, error
    if not isinstance(data, dict):
        return None, f"JSON 结构异常：{type(data).__name__}"
    return data, None


def scan() -> list[dict[str, Any]]:
    """枚举三个命名空间的永久订阅，返回 ``list[Finding]``。"""
    findings: list[dict[str, Any]] = []
    for namespace in _NAMESPACES:
        data, error = _query_namespace(namespace)
        if data is None:
            kind = _classify_error(error or "")
            if kind in ("missing_namespace", "missing_class", "missing"):
                continue  # 命名空间/类不存在属正常情况
            findings.append(
                make_skipped(
                    CATEGORY,
                    namespace,
                    f"WMI 查询失败（{kind}）：{truncate(error, 200)}",
                    {"namespace": namespace, "error": error},
                    "WMI_ACCESS_DENIED" if kind == "access_denied" else "WMI_SKIPPED",
                )
            )
            continue
        findings.extend(_analyze_namespace(data))
    return utils.apply_whitelist(findings)
