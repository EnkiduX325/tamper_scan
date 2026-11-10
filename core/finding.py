"""统一的 Finding 数据结构。

所有扫描模块对外只返回 ``list[dict]``，每个 dict 必须由 :func:`make_finding` 生成，
键固定为 ``severity`` / ``category`` / ``target`` / ``detail`` / ``evidence`` / ``rule_id``。

本模块同时提供去重、排序与统计工具，供 ``main.py`` 与 ``reporter.py`` 复用。
"""

from __future__ import annotations

from typing import Any, Iterable

# 严格按报告需要的顺序排列（HIGH 最严重）
SEVERITIES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW", "INFO", "SKIPPED")
SEVERITY_ORDER: dict[str, int] = {name: index for index, name in enumerate(SEVERITIES)}

# 退出码权重（阶段 7 使用）：存在 HIGH -> 2，仅 MEDIUM -> 1，其余 -> 0
SEVERITY_EXIT_WEIGHT: dict[str, int] = {
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
    "INFO": 0,
    "SKIPPED": 0,
}


def normalize_severity(severity: str) -> str:
    """把任意输入规范化为合法 severity；非法值直接抛错（暴露编程错误）。"""
    sev = str(severity or "").strip().upper()
    if sev not in SEVERITY_ORDER:
        raise ValueError(f"非法 severity: {severity!r}，允许值: {', '.join(SEVERITIES)}")
    return sev


def make_finding(
    severity: str,
    category: str,
    target: str,
    detail: str,
    evidence: dict[str, Any] | None = None,
    rule_id: str = "",
) -> dict[str, Any]:
    """Finding 工厂函数。

    Args:
        severity: HIGH / MEDIUM / LOW / INFO / SKIPPED。
        category: 检查类别，如 ``RegistryRun``、``BrowserExtension``。
        target: 被检查对象（路径、注册表键、任务名、进程名等）。
        detail: 面向用户的中文描述。
        evidence: 结构化证据（签名结果、命中规则、原始命令行等）。
        rule_id: 判定规则编号，如 ``SIG_UNSIGNED``。

    Returns:
        统一结构的 Finding dict。
    """
    sev = normalize_severity(severity)
    if evidence is None:
        ev: dict[str, Any] = {}
    elif isinstance(evidence, dict):
        ev = dict(evidence)
    else:
        ev = {"value": evidence}
    return {
        "severity": sev,
        "category": str(category or "General"),
        "target": "" if target is None else str(target),
        "detail": "" if detail is None else str(detail),
        "evidence": ev,
        "rule_id": str(rule_id or ""),
    }


def make_skipped(
    category: str,
    target: str,
    detail: str,
    evidence: dict[str, Any] | None = None,
    rule_id: str = "",
) -> dict[str, Any]:
    """权限不足 / 依赖缺失时的统一降级 Finding（不抛异常）。"""
    return make_finding("SKIPPED", category, target, detail, evidence, rule_id)


def dedupe_key(finding: dict[str, Any]) -> tuple[str, str]:
    """去重键：``target + rule_id``（target 规范化大小写与首尾空白）。"""
    return (str(finding.get("target", "")).strip().lower(), str(finding.get("rule_id", "")))


# 采集层前缀：同源事实可能被不同模块用不同 rule_id 上报（如 AUTORUNS_SIG_UNSIGNED 与
# SIG_UNSIGNED），去重时按"规则基名"合并，避免报告里同一文件重复计数。
_MODULE_RULE_PREFIXES: tuple[str, ...] = (
    "AUTORUNS_",
    "RUN_",
    "SCHTASK_",
    "TASK_",
    "SVC_",
    "SERVICE_",
    "WMI_",
    "BITS_",
    "PS_PROFILE_",
    "PROFILE_",
    "COM_",
    "LSA_",
    "IFEO_",
    "APPINIT_",
    "HOSTS_",
    "DNS_",
    "BROWSE_",
    "LNK_",
    "MEM_",
    "EXT_",
    "NETWORK_",
)

# 基名别名：不同模块对同一事实用了不同措辞时在此归一
_RULE_BASENAME_ALIASES: dict[str, str] = {
    "LOLBIN": "LOLBIN_CMDLINE",
}


def rule_basename(rule_id: str) -> str:
    """去掉采集层前缀后的"规则基名"，作为跨模块同源去重键（见 REPORT_DEDUPE_POLICY）。"""
    name = str(rule_id or "").strip().upper()
    for prefix in _MODULE_RULE_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return _RULE_BASENAME_ALIASES.get(name, name)


def dedupe_findings(
    findings: Iterable[dict[str, Any]],
    merge_rule_base: bool = True,
) -> list[dict[str, Any]]:
    """去重：``target + 规则基名``；重复项保留严重等级更高的一条，并合并证据。

    - ``merge_rule_base=True``（默认，阶段 4 起采用的策略）：``AUTORUNS_SIG_UNSIGNED``
      与 ``SIG_UNSIGNED`` 指向同一文件时合并为一条，``evidence["merged_rules"]``
      记录两边的原始 rule_id，evidence 其余字段做并集（主条目的同名字段优先）。
    - ``merge_rule_base=False``：退回规范里的严格 ``target + rule_id`` 去重。
    """
    order: list[tuple[str, str]] = []
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings or []:
        target_key = str(finding.get("target", "")).strip().lower()
        rule_id = str(finding.get("rule_id", ""))
        key = (target_key, rule_basename(rule_id) if merge_rule_base else rule_id)
        existing = best.get(key)
        if existing is None:
            entry = dict(finding)
            entry["evidence"] = dict(entry.get("evidence") or {})
            if merge_rule_base and rule_id:
                entry["evidence"]["merged_rules"] = [rule_id]
            order.append(key)
            best[key] = entry
            continue
        old_rank = SEVERITY_ORDER.get(str(existing.get("severity", "SKIPPED")), 99)
        new_rank = SEVERITY_ORDER.get(str(finding.get("severity", "SKIPPED")), 99)
        primary, secondary = (finding, existing) if new_rank < old_rank else (existing, finding)
        merged = dict(primary)
        merged_evidence = dict(secondary.get("evidence") or {})
        merged_evidence.update(primary.get("evidence") or {})
        merged_rules = list(merged_evidence.get("merged_rules") or [])
        for candidate in (existing.get("rule_id"), finding.get("rule_id")):
            if candidate and str(candidate) not in merged_rules:
                merged_rules.append(str(candidate))
        merged_evidence["merged_rules"] = merged_rules
        merged["evidence"] = merged_evidence
        best[key] = merged
    return [best[key] for key in order]


def sort_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """按 HIGH → MEDIUM → LOW → INFO → SKIPPED 排序（同级按 rule_id / target）。"""
    return sorted(
        findings or [],
        key=lambda f: (
            SEVERITY_ORDER.get(str(f.get("severity", "")), 99),
            str(f.get("rule_id", "")),
            str(f.get("target", "")).lower(),
        ),
    )


def severity_counts(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    """统计各严重等级数量，五个键始终存在。"""
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings or []:
        sev = str(finding.get("severity", "")).upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def exit_code_for(findings: Iterable[dict[str, Any]]) -> int:
    """按报告内容计算进程退出码：HIGH=2，仅 MEDIUM=1，否则 0。"""
    return max((SEVERITY_EXIT_WEIGHT.get(str(f.get("severity", "")), 0) for f in findings or []), default=0)
