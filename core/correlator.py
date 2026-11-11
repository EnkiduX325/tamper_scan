# -*- coding: utf-8 -*-
"""攻击链关联引擎（V1.4 阶段 C2）。

设计原则
--------
- **纯只读后处理**：输入现有 ``list[Finding]``，输出 campaign/suppressed 视图，
  默认不修改 Finding 本身、不影响严重等级与进程退出码；
- **绝无自由组合**：只有完整/接近完整匹配 ``rules/attack_chain.json`` 中固定
  ``chain_templates`` 的攻击序列才会成链；任意"看起来相关"的规则组合都不成链
  （宁可漏报，不误报）；
- **反模式优先抑制**：命中 ``anti_patterns``（企业更新器/托管策略等合法多阶段
  组合）的 campaign 直接移入 ``suppressed``，不进入 ``campaigns``；
- **数据驱动**：战术映射、剧本模板、反模式全部来自规则库，改规则不改代码。

公开 API
--------
``load_chain_rules(path=None) -> dict``
    加载并规范化攻击链规则库；文件缺失/损坏/结构异常时返回安全的空骨架
    （``_comment`` / ``tactic_mapping`` / ``chain_templates`` / ``anti_patterns``），
    绝不抛异常；结果按绝对路径缓存，``clear_chain_cache()`` 清空缓存。

``correlate(findings, *, rules=None, now=None, window_hours=24) -> dict``
    返回 ``{"campaigns": [...], "suppressed": [...], "stats": {...}}``。

    聚类：Finding 为节点，边 = 共享归一化 target（复用
    ``core.baseline.normalize_target``，不可用时回退 ``utils.normalize_path().lower()``）
    或父子进程边（``evidence.process.ppid/parent_pid/ppid`` 与另一 Finding 的
    ``pid/process.pid`` 关联，且两者时间差不超过 ``window_hours``；缺失时间戳视为
    无法证伪而保留）。连通分量即候选攻击子图，孤立 Finding 不成 campaign。

    模板比对：按 ``chain_templates`` 顺序严格匹配；每个 step 需至少
    ``min_findings`` 条命中 ``rule_ids``（支持结尾 ``*`` 通配）的 Finding，
    同一 Finding 不能重复用于多个 step；``rule_ids`` 为空的 step 按
    ``tactic_mapping`` 战术匹配。覆盖率 = 命中步数 / 模板步数：
    完整 -> ``high``、>= 2/3 -> ``medium``、>= 2 步但 < 2/3 -> ``low``、
    不足 2 步不成链。模板存在时间戳时再校验 ``max_gap_hours``。

    反模式：在子图（cluster）范围内检查 ``anti_patterns``；命中后把 campaign
    标记 ``suppressed=True``、``suppressed_by=<反模式 id>`` 并放入 ``suppressed``。

campaign 字段（固定 11 个键）::

    {"chain_id", "name", "description", "confidence", "tactics", "steps",
     "finding_count", "targets", "suppressed", "suppressed_by", "shadow"}

    steps: [{"tactic", "rule_ids", "findings": [{"rule_id", "target", "severity"}]}]
    shadow 恒为 False（本引擎不改变报告，仅提供关联视图）。

本模块不 import ``main`` / ``gui`` / ``reporter``，可安全被 CLI/GUI/测试复用。
"""

from __future__ import annotations

import copy
import os
from datetime import datetime, timezone
from typing import Any

from . import utils

_CHAIN_RULES_FILENAME = "attack_chain.json"
_DEFAULT_WINDOW_HOURS = 24.0
_CONFIDENCE_RANK: dict[str, int] = {"high": 0, "medium": 1, "low": 2}

# 缓存：绝对路径 -> 已规范化规则 dict（深拷贝对外返回，避免调用方污染缓存）
_CHAIN_CACHE: dict[str, dict[str, Any]] = {}


def _empty_rules() -> dict[str, Any]:
    return {"_comment": "", "tactic_mapping": {}, "chain_templates": [], "anti_patterns": []}


# ---------------------------------------------------------------------------
# 规则库加载（防御 / 规范化 / 缓存）
# ---------------------------------------------------------------------------


def _rules_path(path: str | os.PathLike[str] | None = None) -> str:
    if path:
        try:
            return os.path.abspath(os.fspath(path))
        except (TypeError, ValueError):
            return ""
    return os.path.abspath(os.fspath(utils.RULES_DIR / _CHAIN_RULES_FILENAME))


def _as_str_list(value: Any) -> list[str]:
    """把任意输入转成"去空白、丢弃空项与非标量"的字符串列表。"""
    if not isinstance(value, (list, tuple)):
        return []
    items: list[str] = []
    for entry in value:
        if isinstance(entry, (dict, list, tuple, set)):
            continue
        text = str(entry).strip()
        if text:
            items.append(text)
    return items


def _as_positive_int(value: Any, default: int = 1) -> int:
    if isinstance(value, bool):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number >= 1 else default


def _as_positive_float(value: Any, default: float = _DEFAULT_WINDOW_HOURS) -> float:
    if isinstance(value, bool):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def _normalize_step(raw_step: Any) -> dict[str, Any] | None:
    if not isinstance(raw_step, dict):
        return None
    tactic = str(raw_step.get("tactic") or "").strip()
    rule_ids = _as_str_list(raw_step.get("rule_ids"))
    if not tactic and not rule_ids:
        return None
    return {
        "tactic": tactic,
        "rule_ids": rule_ids,
        "min_findings": _as_positive_int(raw_step.get("min_findings"), 1),
    }


def _normalize_template(raw_template: Any, index: int) -> dict[str, Any] | None:
    if not isinstance(raw_template, dict):
        return None
    chain_id = str(raw_template.get("id") or "").strip()
    if not chain_id:
        return None
    raw_steps = raw_template.get("steps")
    if not isinstance(raw_steps, list):
        return None
    steps = [step for step in (_normalize_step(item) for item in raw_steps) if step is not None]
    if len(steps) < 2:
        # 固定剧本至少两步；单步"模板"无法体现攻击序列，直接丢弃
        return None
    return {
        "id": chain_id,
        "name": str(raw_template.get("name") or chain_id).strip(),
        "description": str(raw_template.get("description") or "").strip(),
        "confidence": str(raw_template.get("confidence") or "high").strip().lower(),
        "max_gap_hours": _as_positive_float(raw_template.get("max_gap_hours"), _DEFAULT_WINDOW_HOURS),
        "steps": steps,
        "_order": index,
    }


def _normalize_anti_pattern(raw_pattern: Any) -> dict[str, Any] | None:
    if not isinstance(raw_pattern, dict):
        return None
    pattern_id = str(raw_pattern.get("id") or "").strip()
    if not pattern_id:
        return None
    raw_match = raw_pattern.get("match")
    match = raw_match if isinstance(raw_match, dict) else {}
    rule_ids = _as_str_list(match.get("rule_ids"))
    tactics = [str(item).strip().upper() for item in _as_str_list(match.get("tactics"))]
    target_contains = [str(item).strip().lower() for item in _as_str_list(match.get("target_contains"))]
    if not rule_ids and not tactics and not target_contains:
        return None
    return {
        "id": pattern_id,
        "description": str(raw_pattern.get("description") or "").strip(),
        "match": {
            "rule_ids": rule_ids,
            "tactics": tactics,
            "require_all": bool(match.get("require_all")),
            "target_contains": target_contains,
        },
    }


def _normalize_rules(data: Any) -> dict[str, Any]:
    """把规则库原始 JSON 规范化为安全结构；任何异常输入都退化为空骨架。"""
    rules = _empty_rules()
    if not isinstance(data, dict):
        return rules
    rules["_comment"] = str(data.get("_comment") or "")

    raw_mapping = data.get("tactic_mapping")
    if isinstance(raw_mapping, dict):
        for key, value in raw_mapping.items():
            tactic_key = str(key or "").strip()
            if not tactic_key:
                continue
            rules["tactic_mapping"][tactic_key] = str(value or "").strip()

    raw_templates = data.get("chain_templates")
    if isinstance(raw_templates, list):
        for index, item in enumerate(raw_templates):
            template = _normalize_template(item, index)
            if template is not None:
                rules["chain_templates"].append(template)

    raw_patterns = data.get("anti_patterns")
    if isinstance(raw_patterns, list):
        for item in raw_patterns:
            pattern = _normalize_anti_pattern(item)
            if pattern is not None:
                rules["anti_patterns"].append(pattern)
    return rules


def load_chain_rules(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """加载攻击链规则库（缓存 + 防御）。

    Args:
        path: 规则库 JSON 路径；缺省为 ``rules/attack_chain.json``。

    Returns:
        规范化后的规则 dict（``_comment`` / ``tactic_mapping`` /
        ``chain_templates`` / ``anti_patterns``）。文件缺失、JSON 损坏或结构
        异常时返回安全的空骨架，绝不抛异常。
    """
    key = _rules_path(path)
    cached = _CHAIN_CACHE.get(key) if key else None
    if cached is not None:
        return copy.deepcopy(cached)
    try:
        data = utils.load_json(key, default=None) if key else None
    except Exception:  # noqa: BLE001 - 任何加载异常都降级为空骨架
        data = None
    rules = _normalize_rules(data)
    if key:
        _CHAIN_CACHE[key] = rules
    return copy.deepcopy(rules)


def clear_chain_cache() -> None:
    """清空规则库缓存（测试/长驻进程复读规则文件时使用）。"""
    _CHAIN_CACHE.clear()


# ---------------------------------------------------------------------------
# target / 时间 / 进程字段归一化
# ---------------------------------------------------------------------------


def _get_baseline_normalizer() -> Any:
    """取 ``core.baseline.normalize_target``（若该函数尚未提供则返回 None）。

    延迟到调用时解析：``core/baseline.py`` 与关联引擎并行开发，缺少该函数时
    回退 ``utils.normalize_path().lower()``，实现同时兼容两种环境。
    """
    try:
        from . import baseline  # 延迟导入：避免与并行开发的 baseline 模块硬耦合
    except Exception:  # noqa: BLE001
        return None
    normalizer = getattr(baseline, "normalize_target", None)
    return normalizer if callable(normalizer) else None


def _normalize_target(value: Any) -> str:
    """Finding target 归一化：优先 baseline.normalize_target，回退 utils.normalize_path。"""
    normalizer = _get_baseline_normalizer()
    if normalizer is not None:
        try:
            normalized = normalizer(value)
            if normalized:
                return str(normalized).strip().lower()
        except Exception:  # noqa: BLE001
            pass
    try:
        return utils.normalize_path(value).strip().lower()
    except Exception:  # noqa: BLE001
        return str(value or "").strip().lower()


def _evidence_of(finding: Any) -> dict[str, Any]:
    if not isinstance(finding, dict):
        return {}
    evidence = finding.get("evidence")
    return evidence if isinstance(evidence, dict) else {}


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _first_int(*values: Any) -> int | None:
    for value in values:
        number = _as_int(value)
        if number is not None:
            return number
    return None


def _process_fields(finding: dict[str, Any]) -> tuple[int | None, int | None]:
    """返回 ``(pid, ppid)``；兼容 evidence.pid/ppid/parent_pid 与 evidence.process.*。"""
    evidence = _evidence_of(finding)
    process = evidence.get("process")
    if not isinstance(process, dict):
        process = {}
    pid = _first_int(evidence.get("pid"), process.get("pid"))
    ppid = _first_int(
        evidence.get("ppid"),
        evidence.get("parent_pid"),
        process.get("ppid"),
        process.get("parent_pid"),
    )
    return pid, ppid


def _as_timestamp(value: Any) -> float | None:
    """把 epoch / ISO8601 / datetime 转成 epoch 秒；失败返回 None。"""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, datetime):
        try:
            moment = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
            return moment.timestamp()
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 1e12:  # 毫秒时间戳
            number /= 1000.0
        return number
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        return datetime.fromisoformat(iso_text).timestamp()
    except (OSError, OverflowError, ValueError):
        return None


def _finding_time(finding: dict[str, Any]) -> float | None:
    evidence = _evidence_of(finding)
    for key in ("timestamp", "created_at", "time", "first_seen"):
        if key in evidence:
            moment = _as_timestamp(evidence.get(key))
            if moment is not None:
                return moment
    return None


# ---------------------------------------------------------------------------
# 图聚类
# ---------------------------------------------------------------------------


class _DisjointSet:
    """并查集：连通分量 = 攻击候选子图。"""

    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, index: int) -> int:
        root = index
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[index] != root:
            self._parent[index], index = root, self._parent[index]
        return root

    def union(self, left: int, right: int) -> None:
        root_left, root_right = self.find(left), self.find(right)
        if root_left != root_right:
            self._parent[root_right] = root_left


def _window_seconds(window_hours: Any) -> float:
    return _as_positive_float(window_hours, _DEFAULT_WINDOW_HOURS) * 3600.0


def _within_window(left: float | None, right: float | None, window: float) -> bool:
    """ppid 边的时间窗过滤：两端时间戳都可用时才按窗口裁剪。"""
    if left is None or right is None:
        return True
    return abs(left - right) <= window


def _build_clusters(findings: list[dict[str, Any]], window: float) -> list[list[dict[str, Any]]]:
    """按共享 target / ppid 连边，返回连通分量（仅 >=2 个 Finding 的子图）。"""
    total = len(findings)
    if total < 2:
        return []
    disjoint = _DisjointSet(total)
    targets = [_normalize_target(finding.get("target")) for finding in findings]
    process_fields = [_process_fields(finding) for finding in findings]
    times = [_finding_time(finding) for finding in findings]

    first_by_target: dict[str, int] = {}
    for index, target in enumerate(targets):
        if not target:
            continue
        existing = first_by_target.get(target)
        if existing is None:
            first_by_target[target] = index
        else:
            disjoint.union(existing, index)

    for parent_index in range(total):
        parent_ppid = process_fields[parent_index][1]
        if parent_ppid is None:
            continue
        for child_index in range(total):
            if parent_index == child_index:
                continue
            child_pid = process_fields[child_index][0]
            if child_pid is None or child_pid != parent_ppid:
                continue
            if _within_window(times[parent_index], times[child_index], window):
                disjoint.union(parent_index, child_index)

    groups: dict[int, list[int]] = {}
    for index in range(total):
        groups.setdefault(disjoint.find(index), []).append(index)
    clusters = [
        ([findings[index] for index in members], members[0])
        for members in groups.values()
        if len(members) >= 2
    ]
    clusters.sort(key=lambda item: item[1])
    return [cluster for cluster, _first_index in clusters]


# ---------------------------------------------------------------------------
# 战术映射 / 模板匹配
# ---------------------------------------------------------------------------


def _tactic_index(tactic_mapping: Any) -> dict[str, str]:
    index: dict[str, str] = {}
    if not isinstance(tactic_mapping, dict):
        return index
    for key, value in tactic_mapping.items():
        rule_key = str(key or "").strip().upper()
        if not rule_key:
            continue
        index[rule_key] = str(value or "").strip()
    return index


def _map_tactic(rule_id: Any, tactic_index: dict[str, str]) -> str:
    """规则 -> ATT&CK 战术：精确键优先，其次最长前缀（支持 ``SIG_`` 或 ``SIG_*`` 写法）。"""
    rule = str(rule_id or "").strip().upper()
    if not rule or not tactic_index:
        return ""
    exact = tactic_index.get(rule)
    if exact is not None:
        return exact
    best_tactic = ""
    best_length = -1
    for key, tactic in tactic_index.items():
        prefix = key[:-1] if key.endswith("*") else key
        if not prefix:
            continue
        if rule.startswith(prefix) and len(prefix) > best_length:
            best_tactic = tactic
            best_length = len(prefix)
    return best_tactic


def _rule_matches(rule_id: Any, pattern: Any) -> bool:
    rule = str(rule_id or "").strip().upper()
    expected = str(pattern or "").strip().upper()
    if not rule or not expected:
        return False
    if expected.endswith("*"):
        return rule.startswith(expected[:-1])
    return rule == expected


def _finding_matches_step(finding: dict[str, Any], step: dict[str, Any], tactic_index: dict[str, str]) -> bool:
    rule_id = finding.get("rule_id")
    step_rules = step.get("rule_ids") or []
    if step_rules:
        return any(_rule_matches(rule_id, pattern) for pattern in step_rules)
    step_tactic = str(step.get("tactic") or "").strip()
    if step_tactic:
        return _map_tactic(rule_id, tactic_index) == step_tactic
    return False


def _match_template(
    cluster: list[dict[str, Any]],
    template: dict[str, Any],
    tactic_index: dict[str, str],
) -> list[tuple[dict[str, Any], list[dict[str, Any]]]] | None:
    """严格按模板 steps 顺序匹配；返回 ``[(step, matched_findings), ...]``。"""
    used: set[int] = set()
    matched: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    for step in template.get("steps") or []:
        needed = int(step.get("min_findings") or 1)
        candidates: list[int] = []
        for index, finding in enumerate(cluster):
            if index in used:
                continue
            if _finding_matches_step(finding, step, tactic_index):
                candidates.append(index)
                if len(candidates) >= needed:
                    break
        if len(candidates) < needed:
            continue
        used.update(candidates)
        matched.append((step, [cluster[index] for index in candidates]))
    return matched or None


def _coverage_confidence(matched_steps: int, total_steps: int) -> str | None:
    """覆盖完整 -> high；>= 2/3 -> medium；>= 2 步 -> low；否则不成链。"""
    if matched_steps <= 0 or total_steps <= 0:
        return None
    if matched_steps == total_steps:
        return "high"
    if matched_steps >= (2.0 * total_steps / 3.0):
        return "medium"
    if matched_steps >= 2:
        return "low"
    return None


def _template_within_gap(template: dict[str, Any], matched: list[tuple[dict[str, Any], list[dict[str, Any]]]]) -> bool:
    """模板内时间跨度校验：时间戳齐全时不得超过 max_gap_hours。"""
    times = [_finding_time(finding) for _, findings in matched for finding in findings]
    known = [moment for moment in times if moment is not None]
    if len(known) < 2:
        return True
    limit = _as_positive_float(template.get("max_gap_hours"), _DEFAULT_WINDOW_HOURS) * 3600.0
    return (max(known) - min(known)) <= limit


# ---------------------------------------------------------------------------
# campaign / 反模式
# ---------------------------------------------------------------------------


def _finding_summary(finding: dict[str, Any]) -> dict[str, str]:
    return {
        "rule_id": str(finding.get("rule_id") or ""),
        "target": str(finding.get("target") or ""),
        "severity": str(finding.get("severity") or ""),
    }


def _build_campaign(
    template: dict[str, Any],
    matched: list[tuple[dict[str, Any], list[dict[str, Any]]]],
    confidence: str,
) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    tactics: list[str] = []
    targets: list[str] = []
    finding_count = 0
    for step, findings in matched:
        tactic = str(step.get("tactic") or "")
        if tactic and tactic not in tactics:
            tactics.append(tactic)
        step_findings = [_finding_summary(finding) for finding in findings]
        steps.append(
            {
                "tactic": tactic,
                "rule_ids": list(step.get("rule_ids") or []),
                "findings": step_findings,
            }
        )
        finding_count += len(step_findings)
        for summary in step_findings:
            if summary["target"] and summary["target"] not in targets:
                targets.append(summary["target"])
    return {
        "chain_id": str(template.get("id") or ""),
        "name": str(template.get("name") or ""),
        "description": str(template.get("description") or ""),
        "confidence": confidence,
        "tactics": tactics,
        "steps": steps,
        "finding_count": finding_count,
        "targets": targets,
        "suppressed": False,
        "suppressed_by": None,
        "shadow": False,
    }


def _match_anti_pattern(
    pattern: dict[str, Any],
    cluster: list[dict[str, Any]],
    tactic_index: dict[str, str],
) -> bool:
    """反模式匹配：rule_ids / tactics / target_contains 三组约束按 AND 组合。"""
    match = pattern.get("match") if isinstance(pattern.get("match"), dict) else {}
    rule_patterns = match.get("rule_ids") or []
    tactics = [str(item).strip().upper() for item in (match.get("tactics") or []) if str(item).strip()]
    target_needles = [str(item).strip().lower() for item in (match.get("target_contains") or []) if str(item).strip()]
    if not rule_patterns and not tactics and not target_needles:
        return False
    require_all = bool(match.get("require_all"))

    finding_rules = [str(finding.get("rule_id") or "") for finding in cluster]
    finding_tactics = {_map_tactic(rule_id, tactic_index).upper() for rule_id in finding_rules}
    finding_tactics.discard("")

    if rule_patterns:
        rule_hits = [
            any(_rule_matches(rule_id, pattern_id) for rule_id in finding_rules)
            for pattern_id in rule_patterns
        ]
        if not (all(rule_hits) if require_all else any(rule_hits)):
            return False
    if tactics:
        tactic_hits = [tactic in finding_tactics for tactic in tactics]
        if not (all(tactic_hits) if require_all else any(tactic_hits)):
            return False
    if target_needles:
        raw_targets = [str(finding.get("target") or "").lower() for finding in cluster]
        if not any(needle in target for needle in target_needles for target in raw_targets):
            return False
    return True


# ---------------------------------------------------------------------------
# 公开入口
# ---------------------------------------------------------------------------


def _valid_findings(findings: Any) -> list[dict[str, Any]]:
    """只保留参与关联的合法 Finding：dict 且非 SKIPPED（未检查 ≠ 攻击证据）。"""
    if findings is None:
        return []
    if isinstance(findings, dict):
        candidates: list[Any] = [findings] if findings else []
    else:
        try:
            candidates = list(findings)
        except TypeError:
            return []
    valid: list[dict[str, Any]] = []
    for finding in candidates:
        if not isinstance(finding, dict):
            continue
        if str(finding.get("severity") or "").strip().upper() == "SKIPPED":
            continue
        valid.append(finding)
    return valid


def correlate(
    findings: Any,
    *,
    rules: dict[str, Any] | None = None,
    now: Any = None,
    window_hours: Any = _DEFAULT_WINDOW_HOURS,
) -> dict[str, Any]:
    """关联攻击链（纯只读后处理）。

    Args:
        findings: 现有 ``list[Finding]``（允许 None / 生成器 / 含非法项）。
        rules: 攻击链规则 dict；缺省时 ``load_chain_rules()``。传入非法类型时按空
            骨架处理（不抛异常）。
        now: 可选时间基准（datetime / epoch / ISO 字符串）。聚类窗口按 Finding
            之间的时间差计算，``now`` 仅用于调用方固定"当前时间"以保证可复现，
            不改变保守的关联结果。
        window_hours: ppid 父子进程边的时间窗口（小时）；非法/非正数回退 24。

    Returns:
        ``{"campaigns": [...], "suppressed": [...],
        "stats": {"findings", "clusters", "campaigns", "suppressed"}}``；
        ``findings`` 为参与关联的合法 Finding 数（排除非 dict 与 SKIPPED），
        ``clusters`` 为至少含 2 个 Finding 的连通分量数。
    """
    if rules is None:
        config = load_chain_rules()
    elif isinstance(rules, dict):
        config = _normalize_rules(rules)
    else:
        config = _empty_rules()
    # 校验时间基准参数（datetime / epoch / ISO 均可解析）；当前保守聚类按 Finding
    # 之间的时间差计算窗口，now 不参与判断，仅保证调用方传入非法值时不崩溃。
    _as_timestamp(now)

    valid_findings = _valid_findings(findings)
    tactic_index = _tactic_index(config.get("tactic_mapping"))
    templates = config.get("chain_templates") if isinstance(config.get("chain_templates"), list) else []
    anti_patterns = config.get("anti_patterns") if isinstance(config.get("anti_patterns"), list) else []
    window = _window_seconds(window_hours)

    clusters = _build_clusters(valid_findings, window)
    campaigns: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []

    for cluster in clusters:
        for template in templates:
            if not isinstance(template, dict):
                continue
            matched = _match_template(cluster, template, tactic_index)
            if not matched:
                continue
            confidence = _coverage_confidence(len(matched), len(template.get("steps") or []))
            if confidence is None:
                continue
            if not _template_within_gap(template, matched):
                continue
            campaign = _build_campaign(template, matched, confidence)
            pattern = None
            for candidate in anti_patterns:
                if not isinstance(candidate, dict):
                    continue
                if _match_anti_pattern(candidate, cluster, tactic_index):
                    pattern = candidate
                    break
            if pattern is not None:
                campaign["suppressed"] = True
                campaign["suppressed_by"] = str(pattern.get("id") or "")
                suppressed.append(campaign)
            else:
                campaigns.append(campaign)

    # 确定性排序：置信度（high -> medium -> low），同置信度保持"子图顺序 + 模板顺序"
    campaigns.sort(key=lambda campaign: _CONFIDENCE_RANK.get(str(campaign.get("confidence")), 9))
    suppressed.sort(key=lambda campaign: _CONFIDENCE_RANK.get(str(campaign.get("confidence")), 9))

    stats = {
        "findings": len(valid_findings),
        "clusters": len(clusters),
        "campaigns": len(campaigns),
        "suppressed": len(suppressed),
    }
    return {"campaigns": campaigns, "suppressed": suppressed, "stats": stats}
