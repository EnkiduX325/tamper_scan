# -*- coding: utf-8 -*-
"""基线对比（Baseline Diff）引擎（V1.3）。

设计目标
--------
把一个"静态扫描器"升级为"动态判篡改"工具：把本次扫描结果与用户此前保存的
基线报告（均由 :func:`reporter.build_report` 生成）按主键逐项对比，输出
``NEW`` / ``RESOLVED`` / ``ESCALATED`` / ``DOWNGRADED`` / ``MODIFIED`` /
``UNCHANGED`` 六种状态。

关键约束
--------
- **纯只读**：本模块只读取/比较报告 dict，绝不执行任何命令、不写注册表；
- **防御性解析**：基线文件是用户可能误改的输入。所有 evidence 字段都通过
  ``dict.get`` / 逐层 ``get`` 提取（:func:`_dig`），缺失字段不会触发
  ``KeyError``，也不会崩溃；
- **向后兼容**：不启用基线时本模块不参与报告生成，扫描行为/JSON 结构/退出码
  与 V1.2 完全一致；
- **主键**：``(target 归一化, rule_base)``。``rule_base`` 由
  :func:`core.finding.rule_basename` 剥离采集层前缀（``AUTORUNS_``/``SVC_``/
  ``RDP_`` 等）；若 Finding 的 ``evidence.merged_rules`` 存在，则把所有被合并
  规则的基名都作为匹配维度，避免"规则合并导致同一事实被误判为 NEW"。
- **Fingerprint**：只提取反映真实状态的稳定字段（见 :data:`FINGERPRINT_FIELDS`），
  显式剥离 ``timestamp``/``pid`` 等随时间变化的字段，再做 SHA256。
- **文件哈希增强**：``--hash-targets`` 为 HIGH/MEDIUM Finding 的本地文件 target
  计算 SHA256 写入 ``evidence["sha256"]``；若基线与本次的签名状态都是 ``valid``
  但 SHA256 不同（白利用式篡改），强制判定 ``MODIFIED`` 并提升为 HIGH。

典型用法::

    from core import baseline

    diff = baseline.diff_reports(baseline_report, current_report, baseline_path="base.json")
    print(diff.counts)              # {"NEW": 1, "RESOLVED": 0, ...}
    enriched = report  # 由 reporter.apply_baseline_diff 挂载 diff_status
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import utils
from .finding import SEVERITY_ORDER, rule_basename

# 基线报告结构标识（写入报告顶层 baseline 元信息，便于人工识别）
BASELINE_SCHEMA_VERSION = "1.3"

# 六种对比状态（顺序即报告展示顺序）
DIFF_NEW = "NEW"
DIFF_RESOLVED = "RESOLVED"
DIFF_ESCALATED = "ESCALATED"
DIFF_DOWNGRADED = "DOWNGRADED"
DIFF_MODIFIED = "MODIFIED"
DIFF_UNCHANGED = "UNCHANGED"
DIFF_STATUSES: tuple[str, ...] = (
    DIFF_NEW,
    DIFF_MODIFIED,
    DIFF_ESCALATED,
    DIFF_DOWNGRADED,
    DIFF_RESOLVED,
    DIFF_UNCHANGED,
)

# 值得写入 HTML/JSON 的"变化"状态（UNCHANGED 不强调）
CHANGED_STATUSES: frozenset[str] = frozenset({DIFF_NEW, DIFF_MODIFIED, DIFF_ESCALATED, DIFF_DOWNGRADED})

# 判定"哈希被篡改"时要求基线/当前签名状态都是 valid（白利用场景）
_HASH_TAMPER_SIGNATURE_STATUS = "valid"

# fingerprint 提取白名单：evidence 内的相对路径；缺失时回退到顶层同名字段
FINGERPRINT_FIELDS: tuple[tuple[str, ...], ...] = (
    ("signature", "status"),
    ("signature", "signer"),
    ("pe", "CompanyName"),
    ("actual",),
    ("service", "path_name"),
    ("task", "sd_present"),
    ("task", "index"),
)

# 容易随时间/进程变化的字段：fingerprint / 稳定化处理时一律剔除
VOLATILE_KEYS: frozenset[str] = frozenset(
    {
        "timestamp",
        "time",
        "ts",
        "pid",
        "process_id",
        "scan_time",
        "scanned_at",
        "last_write_time",
        "mtime",
        "ctime",
        "created_at",
        "updated_at",
    }
)

# 文件哈希时默认只处理这些严重等级（与任务要求一致）
HASH_SEVERITIES: tuple[str, ...] = ("HIGH", "MEDIUM")

_MISSING = object()


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass
class DiffEntry:
    """单条对比结果（一个 ``(target, rule_base)`` 主键）。"""

    target: str
    rule_base: str
    status: str
    baseline_severity: str | None = None
    current_severity: str | None = None
    baseline_fingerprint: str | None = None
    current_fingerprint: str | None = None
    baseline_sha256: str | None = None
    current_sha256: str | None = None
    hash_tamper: bool = False
    baseline_finding: dict[str, Any] | None = None
    current_finding: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """转成可 JSON 序列化的简要 dict（不含完整 Finding，供调试/测试）。"""
        return {
            "target": self.target,
            "rule_base": self.rule_base,
            "status": self.status,
            "baseline_severity": self.baseline_severity,
            "current_severity": self.current_severity,
            "baseline_fingerprint": self.baseline_fingerprint,
            "current_fingerprint": self.current_fingerprint,
            "baseline_sha256": self.baseline_sha256,
            "current_sha256": self.current_sha256,
            "hash_tamper": self.hash_tamper,
        }


@dataclass
class BaselineDiff:
    """一次基线对比的完整结果。"""

    entries: list[DiffEntry] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    baseline_meta: dict[str, Any] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.entries)

    def entries_with_status(self, *statuses: str) -> list[DiffEntry]:
        wanted = {str(item).upper() for item in statuses}
        return [entry for entry in self.entries if entry.status in wanted]

    def to_dict(self) -> dict[str, Any]:
        return {
            "counts": dict(self.counts),
            "baseline": dict(self.baseline_meta),
            "entries": [entry.to_dict() for entry in self.entries],
        }


# ---------------------------------------------------------------------------
# 防御性取值工具
# ---------------------------------------------------------------------------


def _dig(data: Any, path: tuple[str, ...]) -> Any:
    """按路径逐层取 dict 值；任意一层缺失/类型不符返回 :data:`_MISSING`。"""
    current = data
    for key in path:
        if not isinstance(current, dict):
            return _MISSING
        if key not in current:
            return _MISSING
        current = current[key]
    return current


def _stable(value: Any) -> Any:
    """把 evidence 值转换为稳定、可 JSON 序列化的形式（递归剔除易变字段）。"""
    if isinstance(value, dict):
        return {
            str(key): _stable(item)
            for key, item in value.items()
            if str(key).strip().lower() not in VOLATILE_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_stable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _severity_of(finding: dict[str, Any] | None) -> str | None:
    if not isinstance(finding, dict):
        return None
    severity = str(finding.get("severity") or "").strip().upper()
    return severity or None


def _severity_rank(severity: str | None) -> int:
    return SEVERITY_ORDER.get(str(severity or "").upper(), 99)


def _evidence_of(finding: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(finding, dict):
        return {}
    evidence = finding.get("evidence")
    return evidence if isinstance(evidence, dict) else {}


def _sha256_of(finding: dict[str, Any] | None) -> str | None:
    value = _evidence_of(finding).get("sha256")
    text = str(value or "").strip().lower()
    return text or None


def _signature_valid(finding: dict[str, Any] | None) -> bool:
    status = _dig(_evidence_of(finding), ("signature", "status"))
    return str(status if status is not _MISSING else "").strip().lower() == _HASH_TAMPER_SIGNATURE_STATUS


def target_key(target: Any) -> str:
    """主键中的 target 归一化：去空白 + 大小写不敏感（Windows 路径语义）。"""
    return str(target or "").strip().lower()


# ---------------------------------------------------------------------------
# 规则基名 / 索引
# ---------------------------------------------------------------------------


def rule_bases(finding: dict[str, Any]) -> list[str]:
    """返回 Finding 参与对比的全部规则基名（rule_id + merged_rules 去重保序）。

    ``merged_rules`` 是去重合并时写入 ``evidence`` 的原始规则列表；把它也作为
    对比维度，可避免"基线里两条规则合并成一条、本次只报其中一条"被误判 NEW。
    没有任何规则名的 Finding 归入空基名 ``""``（仍然参与对比，不会被丢弃）。
    """
    if not isinstance(finding, dict):
        return [""]
    raw_ids: list[str] = [str(finding.get("rule_id") or "")]
    merged = _evidence_of(finding).get("merged_rules")
    if isinstance(merged, (list, tuple)):
        raw_ids.extend(str(item or "") for item in merged)
    bases: list[str] = []
    for raw in raw_ids:
        base = rule_basename(raw)
        if base and base not in bases:
            bases.append(base)
    return bases or [""]


def index_findings(findings: Iterable[dict[str, Any]] | None) -> dict[tuple[str, str], dict[str, Any]]:
    """按 ``(target 归一化, rule_base)`` 建立索引；同一主键保留严重等级更高者。"""
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        key_target = target_key(finding.get("target"))
        for base in rule_bases(finding):
            key = (key_target, base)
            existing = index.get(key)
            if existing is None or _severity_rank(_severity_of(finding)) < _severity_rank(_severity_of(existing)):
                index[key] = finding
    return index


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


def extract_fingerprint_fields(evidence: Any) -> dict[str, Any]:
    """从 evidence 提取稳定状态字段（白名单 + 防御性回退，缺失字段直接跳过）。"""
    data = evidence if isinstance(evidence, dict) else {}
    fields: dict[str, Any] = {}
    for path in FINGERPRINT_FIELDS:
        value = _dig(data, path)
        if value is _MISSING and len(path) > 1:
            # 兼容旧基线/其它模块把字段平铺在 evidence 顶层的情况
            value = _dig(data, (path[-1],))
        if value is _MISSING:
            continue
        fields[".".join(path)] = _stable(value)
    return fields


def compute_fingerprint(evidence: Any) -> str:
    """把 evidence 的稳定字段序列化为 JSON 后计算 SHA256（十六进制小写）。"""
    fields = extract_fingerprint_fields(evidence)
    try:
        serialized = json.dumps(fields, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):  # pragma: no cover - _stable 已确保可序列化
        serialized = str(fields)
    return hashlib.sha256(serialized.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# 文件哈希增强
# ---------------------------------------------------------------------------


def compute_file_sha256(path: Any) -> str | None:
    """计算本地文件 SHA256；路径为空/不是文件/读取失败返回 ``None``（不抛异常）。"""
    normalized = utils.normalize_path(path)
    if not normalized or not os.path.isfile(normalized):
        return None
    digest = hashlib.sha256()
    try:
        with open(normalized, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def enrich_findings_with_hashes(
    findings: Iterable[dict[str, Any]] | None,
    severities: Iterable[str] = HASH_SEVERITIES,
) -> list[dict[str, Any]]:
    """为指定严重等级、target 为真实本地文件的 Finding 写入 ``evidence["sha256"]``。

    - 不修改入参：返回新列表，命中项做浅拷贝（evidence 也复制）；
    - 只处理 target 是已存在文件的情况（注册表键/任务名等自动跳过）；
    - 计算失败不中断扫描（该条不加 sha256）。
    """
    wanted = {str(item).strip().upper() for item in severities}
    enriched: list[dict[str, Any]] = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        severity = _severity_of(finding)
        if severity not in wanted:
            enriched.append(finding)
            continue
        digest = compute_file_sha256(finding.get("target"))
        if not digest:
            enriched.append(finding)
            continue
        entry = dict(finding)
        evidence = dict(_evidence_of(finding))
        evidence["sha256"] = digest
        entry["evidence"] = evidence
        enriched.append(entry)
    return enriched


# ---------------------------------------------------------------------------
# 对比
# ---------------------------------------------------------------------------


def _report_findings(report: Any) -> list[dict[str, Any]]:
    """从报告 dict（或 Finding 列表）中防御性提取 Finding 列表。"""
    items: Any
    if isinstance(report, dict):
        items = report.get("findings")
    elif isinstance(report, (list, tuple)):
        items = report
    else:
        return []
    if not isinstance(items, (list, tuple)):
        return []
    return [item for item in items if isinstance(item, dict)]


def _baseline_meta(baseline_report: Any, baseline_path: str) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "path": str(baseline_path or ""),
        "generated_at": "",
        "version": "",
        "host": "",
        "tool": "",
        "schema_version": BASELINE_SCHEMA_VERSION,
    }
    if not isinstance(baseline_report, dict):
        return meta
    meta["generated_at"] = str(baseline_report.get("generated_at") or "")
    meta["version"] = str(baseline_report.get("version") or "")
    meta["tool"] = str(baseline_report.get("tool") or "")
    host = baseline_report.get("host")
    if isinstance(host, dict):
        meta["host"] = str(host.get("name") or "")
    return meta


def validate_baseline_report(report: Any) -> tuple[bool, str | None]:
    """校验基线文件基本结构；返回 ``(是否可用, 不可用原因)``（不抛异常）。"""
    if not isinstance(report, dict):
        return False, f"基线文件根节点应为 JSON 对象，实际为 {type(report).__name__}"
    findings = report.get("findings")
    if not isinstance(findings, list):
        return False, "基线文件缺少 findings 列表（可能不是 TamperScan 报告或被误改）"
    return True, None


def baseline_warnings(
    baseline_report: Any,
    current_report: Any,
    expected_version: str = "",
) -> list[str]:
    """生成基线与当前环境/版本不一致的 WARNING 文本（只提示，不阻断对比）。"""
    warnings: list[str] = []
    if not isinstance(baseline_report, dict):
        return ["基线文件不是 JSON 对象，已跳过对比"]
    if not isinstance(baseline_report.get("findings"), list):
        warnings.append("基线文件缺少 findings 列表，已跳过对比")
        return warnings
    baseline_version = str(baseline_report.get("version") or "").strip()
    if expected_version and baseline_version and baseline_version != expected_version:
        warnings.append(f"基线版本 {baseline_version} 与当前工具版本 {expected_version} 不一致，对比结果仅供参考")
    baseline_host = ""
    current_host = ""
    if isinstance(baseline_report.get("host"), dict):
        baseline_host = str(baseline_report["host"].get("name") or "").strip()
    if isinstance(current_report, dict) and isinstance(current_report.get("host"), dict):
        current_host = str(current_report["host"].get("name") or "").strip()
    if baseline_host and current_host and baseline_host.lower() != current_host.lower():
        warnings.append(
            f"基线主机名 {baseline_host} 与当前主机 {current_host} 不一致，可能不是同一台机器的基线"
        )
    return warnings


def _hash_tamper_detected(
    baseline_finding: dict[str, Any] | None,
    current_finding: dict[str, Any] | None,
) -> bool:
    """签名都有效但文件 SHA256 变化 -> 白利用式篡改（仅当两侧都有哈希时判定）。"""
    baseline_sha = _sha256_of(baseline_finding)
    current_sha = _sha256_of(current_finding)
    if not baseline_sha or not current_sha or baseline_sha == current_sha:
        return False
    return _signature_valid(baseline_finding) and _signature_valid(current_finding)


def _make_entry(
    rule_base: str,
    baseline_finding: dict[str, Any] | None,
    current_finding: dict[str, Any] | None,
) -> DiffEntry:
    current_target = current_finding.get("target") if isinstance(current_finding, dict) else None
    baseline_target = baseline_finding.get("target") if isinstance(baseline_finding, dict) else None
    target = str(current_target or baseline_target or "")
    baseline_severity = _severity_of(baseline_finding)
    current_severity = _severity_of(current_finding)
    baseline_fingerprint = compute_fingerprint(_evidence_of(baseline_finding)) if baseline_finding else None
    current_fingerprint = compute_fingerprint(_evidence_of(current_finding)) if current_finding else None
    entry = DiffEntry(
        target=target,
        rule_base=rule_base,
        status=DIFF_UNCHANGED,
        baseline_severity=baseline_severity,
        current_severity=current_severity,
        baseline_fingerprint=baseline_fingerprint,
        current_fingerprint=current_fingerprint,
        baseline_sha256=_sha256_of(baseline_finding),
        current_sha256=_sha256_of(current_finding),
        baseline_finding=baseline_finding,
        current_finding=current_finding,
    )
    if baseline_finding is None:
        entry.status = DIFF_NEW
        return entry
    if current_finding is None:
        entry.status = DIFF_RESOLVED
        return entry
    entry.hash_tamper = _hash_tamper_detected(baseline_finding, current_finding)
    if entry.hash_tamper:
        # 哈希变化优先于严重等级变化：强制 MODIFIED + HIGH（见 annotate_findings）
        entry.status = DIFF_MODIFIED
        entry.current_severity = "HIGH"
        return entry
    baseline_rank = _severity_rank(baseline_severity)
    current_rank = _severity_rank(current_severity)
    if current_rank < baseline_rank:
        entry.status = DIFF_ESCALATED
    elif current_rank > baseline_rank:
        entry.status = DIFF_DOWNGRADED
    elif baseline_fingerprint != current_fingerprint:
        entry.status = DIFF_MODIFIED
    else:
        entry.status = DIFF_UNCHANGED
    return entry


def diff_reports(
    baseline_report: Any,
    current_report: Any,
    *,
    baseline_path: str = "",
) -> BaselineDiff:
    """对比两份 ``build_report()`` 结果，返回 :class:`BaselineDiff`。

    Args:
        baseline_report: 基线报告 dict（结构异常时按空基线处理，全部标记 NEW）。
        current_report: 本次报告 dict（或 Finding 列表）。
        baseline_path: 基线文件路径（写入报告元信息，仅用于展示）。

    主键匹配分两阶段：先配对"基线/当前都存在"的 Finding（多个规则基名任一命中
    即视为同一事实），再把未配对项标为 RESOLVED / NEW，避免 merged_rules 或
    规则基名变化导致同一事实被重复计数。
    """
    baseline_findings = _report_findings(baseline_report)
    current_findings = _report_findings(current_report)
    baseline_index = index_findings(baseline_findings)
    current_index = index_findings(current_findings)

    entries: list[DiffEntry] = []
    paired_baseline: set[int] = set()
    paired_current: set[int] = set()

    # 阶段 1：两侧都存在的按主键配对（id 去重，防止同一 Finding 在多个基名下重复）
    all_keys = sorted(set(baseline_index) | set(current_index))
    for key in all_keys:
        baseline_finding = baseline_index.get(key)
        current_finding = current_index.get(key)
        if baseline_finding is None or current_finding is None:
            continue
        if id(baseline_finding) in paired_baseline or id(current_finding) in paired_current:
            continue
        paired_baseline.add(id(baseline_finding))
        paired_current.add(id(current_finding))
        entries.append(_make_entry(key[1], baseline_finding, current_finding))

    # 阶段 2：未配对的基线项 -> RESOLVED；未配对的当前项 -> NEW
    for key in sorted(baseline_index):
        baseline_finding = baseline_index[key]
        if id(baseline_finding) in paired_baseline:
            continue
        paired_baseline.add(id(baseline_finding))
        entries.append(_make_entry(key[1], baseline_finding, None))
    for key in sorted(current_index):
        current_finding = current_index[key]
        if id(current_finding) in paired_current:
            continue
        paired_current.add(id(current_finding))
        entries.append(_make_entry(key[1], None, current_finding))

    counts = {status: 0 for status in DIFF_STATUSES}
    for entry in entries:
        if entry.status in counts:
            counts[entry.status] += 1
    return BaselineDiff(
        entries=entries,
        counts=counts,
        baseline_meta=_baseline_meta(baseline_report, baseline_path),
    )


def has_new_high_medium(diff: BaselineDiff | None) -> bool:
    """是否存在 NEW 状态、且严重等级为 HIGH/MEDIUM 的条目（``--fail-on-new`` 用）。"""
    if not isinstance(diff, BaselineDiff):
        return False
    for entry in diff.entries:
        if entry.status == DIFF_NEW and str(entry.current_severity or "").upper() in ("HIGH", "MEDIUM"):
            return True
    return False


def diff_counts(diff: BaselineDiff | None) -> dict[str, int]:
    """返回六种状态计数（缺失状态补 0，保证 UI 可直接取键）。"""
    counts = {status: 0 for status in DIFF_STATUSES}
    if isinstance(diff, BaselineDiff):
        for status, value in (diff.counts or {}).items():
            if status in counts:
                try:
                    counts[status] = int(value)
                except (TypeError, ValueError):
                    counts[status] = 0
    return counts


# ---------------------------------------------------------------------------
# 把对比结果挂到 Finding 列表（供 reporter / GUI 复用）
# ---------------------------------------------------------------------------


def _key_map(diff: BaselineDiff) -> dict[tuple[str, str], DiffEntry]:
    mapping: dict[tuple[str, str], DiffEntry] = {}
    for entry in diff.entries:
        mapping.setdefault((target_key(entry.target), entry.rule_base), entry)
    return mapping


def annotate_findings(
    findings: Iterable[dict[str, Any]] | None,
    diff: BaselineDiff | None,
) -> list[dict[str, Any]]:
    """给当前 Finding 列表挂载 ``diff_status``，并追加 RESOLVED 基线项。

    - 返回新列表，不修改入参 Finding；
    - ``hash_tamper`` 条目：期望 Finding 提升为 HIGH，并在 detail 追加篡改提示；
    - RESOLVED 条目以基线 Finding 的拷贝形式追加（``diff_status="RESOLVED"``）。
    """
    if not isinstance(diff, BaselineDiff):
        return [dict(item) if isinstance(item, dict) else item for item in findings or []]
    by_identity = {id(entry.current_finding): entry for entry in diff.entries if entry.current_finding is not None}
    fallback = _key_map(diff)
    resolved_entries = [entry for entry in diff.entries if entry.status == DIFF_RESOLVED and entry.baseline_finding]
    already_annotated = False
    annotated: list[dict[str, Any]] = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        entry = by_identity.get(id(finding))
        if entry is None:
            for base in rule_bases(finding):
                candidate = fallback.get((target_key(finding.get("target")), base))
                if candidate is not None and candidate.current_finding is not None:
                    entry = candidate
                    break
        if entry is None:
            annotated.append(dict(finding))
            continue
        if str(finding.get("diff_status") or "") == DIFF_RESOLVED:
            already_annotated = True
        item = dict(finding)
        evidence = dict(_evidence_of(finding))
        item["evidence"] = evidence
        item["diff_status"] = entry.status
        if entry.hash_tamper:
            item["severity"] = "HIGH"
            evidence["hash_tamper"] = True
            if entry.baseline_sha256:
                evidence["baseline_sha256"] = entry.baseline_sha256
            detail = str(item.get("detail") or "")
            message = "签名有效但文件哈希改变，高度疑似被篡改"
            if message not in detail:
                item["detail"] = f"{detail}；{message}" if detail else message
        annotated.append(item)
    if not already_annotated:
        for entry in resolved_entries:
            item = dict(entry.baseline_finding or {})
            evidence = dict(_evidence_of(item))
            evidence["resolved"] = True
            item["evidence"] = evidence
            item["diff_status"] = DIFF_RESOLVED
            annotated.append(item)
    return annotated
