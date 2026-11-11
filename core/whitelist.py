# -*- coding: utf-8 -*-
"""白名单加载 / 匹配 / 应用（V1.4 从 :mod:`core.utils` 拆出）。

依赖 :mod:`core.finding`（分级与规则基名）与 :mod:`core.paths`（路径归一化），
**不依赖** :mod:`core.utils`。``DEFAULT_WHITELIST`` 与 ``utils.DEFAULT_WHITELIST``
是同一个对象（兼容 shim 再导出）。
"""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any, Iterable

from .finding import SEVERITY_ORDER, rule_basename
from .paths import RULES_DIR, _norm_abs, load_json, normalize_path, path_under


DEFAULT_WHITELIST: dict[str, Any] = {
    "enabled": True,
    # downgrade：命中降为 INFO；filter：直接丢弃；off：不过滤
    "mode": "downgrade",
    "paths": [],
    "commandline_patterns": [],
    "signers": [],
    "domains": [],
    # 扩展白名单只按"扩展 ID 精确匹配"，不做名称子串（防 typosquatting 放行）
    "extensions": {
        "allowlist_by_id": [],
        "allowlist_by_id_with_max_score": {},
    },
    "services": [],
    "tasks": [],
    "masquerade_allow": [],
    # 冷门持久化扩展点结构化豁免（modules/persistence_ext.py）：
    # 每项 {"registry_value_path": "...", "signer_contains": "...", "note": "..."}
    "persistence_ext_allow": [],
}


_WHITELIST_LIST_KEYS = ("paths", "commandline_patterns", "signers", "domains", "services", "tasks")


_WHITELIST_MODES = ("downgrade", "filter", "off")


def load_whitelist(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """加载白名单配置；文件不存在时返回空骨架（阶段 0 即为空文件）。

    返回 dict 始终包含 enabled/mode 与六类列表键，便于调用方安全迭代。
    """
    target = Path(path) if path else RULES_DIR / "whitelist.json"
    data = load_json(target, default=None)
    merged: dict[str, Any] = copy.deepcopy(DEFAULT_WHITELIST)
    if isinstance(data, dict):
        for key, value in data.items():
            merged[key] = value
    if not isinstance(merged.get("enabled"), bool):
        merged["enabled"] = True
    if str(merged.get("mode", "")).lower() not in _WHITELIST_MODES:
        merged["mode"] = "downgrade"
    else:
        merged["mode"] = str(merged["mode"]).lower()
    for key in _WHITELIST_LIST_KEYS:
        value = merged.get(key)
        if not isinstance(value, list):
            merged[key] = []
        else:
            merged[key] = [str(item).strip() for item in value if str(item).strip()]
    merged["extensions"] = _normalize_extension_allowlist(merged.get("extensions"))
    raw_masquerade = merged.get("masquerade_allow")
    merged["masquerade_allow"] = (
        [item for item in raw_masquerade if isinstance(item, dict)]
        if isinstance(raw_masquerade, list)
        else []
    )
    # persistence_ext_allow 是 dict 列表（不是字符串列表），单独归一化：非 dict 项丢弃
    raw_persistence_ext = merged.get("persistence_ext_allow")
    merged["persistence_ext_allow"] = (
        [item for item in raw_persistence_ext if isinstance(item, dict)]
        if isinstance(raw_persistence_ext, list)
        else []
    )
    merged["_source"] = str(target)
    merged["_loaded"] = isinstance(data, dict)
    return merged


def _normalize_extension_allowlist(value: Any) -> dict[str, Any]:
    """扩展白名单归一化：兼容"纯 ID 列表"与"带 max_score 的字典"两种写法。"""
    if isinstance(value, list):
        ids = [str(item).strip().lower() for item in value if str(item).strip()]
        return {"allowlist_by_id": ids, "allowlist_by_id_with_max_score": {}}
    if isinstance(value, dict):
        raw_ids = value.get("allowlist_by_id") or []
        raw_max = value.get("allowlist_by_id_with_max_score") or {}
        ids = [str(item).strip().lower() for item in raw_ids if str(item).strip()]
        max_scores: dict[str, int] = {}
        if isinstance(raw_max, dict):
            for key, limit in raw_max.items():
                try:
                    max_scores[str(key).strip().lower()] = int(limit)
                except (TypeError, ValueError):
                    continue
        return {"allowlist_by_id": ids, "allowlist_by_id_with_max_score": max_scores}
    return {"allowlist_by_id": [], "allowlist_by_id_with_max_score": {}}


def _evidence_texts(finding: dict[str, Any]) -> list[str]:
    """收集 Finding 中可用于白名单匹配的文本字段。"""
    evidence = finding.get("evidence") or {}
    parts = [
        str(finding.get("target", "")),
        str(finding.get("detail", "")),
        str(finding.get("category", "")),
    ]
    for key in (
        "image_path",
        "launch",
        "commandline",
        "cmdline",
        "command",
        "path",
        "signer",
        "company",
        "service_name",
        "task_name",
        "extension_id",
        "extension_name",
        "name",
        "target_path",
    ):
        value = evidence.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
    return parts


def _norm_text(value: Any) -> str:
    return " ".join(str(value or "").lower().split())


def _match_masquerade_allow(finding: dict[str, Any], config: dict[str, Any]) -> dict[str, str] | None:
    """厂商伪装结构化豁免：签名者 + 路径前缀 + 签名状态 valid 三个条件同时满足才放行。

    只对 SIG_PATH_MASQUERADE 生效；签名 invalid（内容被篡改）或路径不在限定前缀下
    （如 %TEMP%）时不匹配，保持 HIGH。
    """
    entries = config.get("masquerade_allow")
    if not isinstance(entries, list) or not entries:
        return None
    rule_id = str(finding.get("rule_id") or "")
    if rule_basename(rule_id) != "SIG_PATH_MASQUERADE":
        return None
    evidence = finding.get("evidence") or {}
    signature = evidence.get("signature") if isinstance(evidence.get("signature"), dict) else {}
    status = str(signature.get("status") or "").strip().lower()
    signer = str(signature.get("signer") or "").strip()
    target = str(finding.get("target") or evidence.get("path") or "").strip()
    if not signer or not target:
        return None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        signer_needle = str(entry.get("signer_contains") or "").strip().lower()
        if not signer_needle or signer_needle not in signer.lower():
            continue
        required_status = str(entry.get("require_signature_status") or "valid").strip().lower()
        if required_status and status != required_status:
            continue
        path_prefix = str(entry.get("path_prefix") or "").strip()
        if path_prefix and not path_under(target, path_prefix):
            continue
        return {
            "type": "masquerade_allow",
            "value": f"signer={signer} path_prefix={path_prefix} status={status}",
        }
    return None


def _norm_registry_value_path(value: Any) -> str:
    """规范化注册表值展示路径：``normalize_path`` + 去首尾空白 + 小写。"""
    return str(normalize_path(value) or "").strip().lower()


def _match_persistence_ext_allow(finding: dict[str, Any], config: dict[str, Any]) -> dict[str, str] | None:
    """冷门持久化扩展点结构化豁免（modules/persistence_ext.py）。

    命中条件（必须同时满足）：

    1. ``finding.evidence["registry_value_path"]`` 归一化后与条目
       ``registry_value_path`` **精确相等**（大小写不敏感）；
    2. ``finding.evidence`` 的签名者（``signature.signer``，兼容顶层 ``signer``）
       非空，且条目 ``signer_contains`` 非空并为其大小写不敏感子串。

    路径不匹配或签名不匹配时不豁免（保持原等级，交给人工判断）。
    """
    entries = config.get("persistence_ext_allow")
    if not isinstance(entries, list) or not entries:
        return None
    evidence = finding.get("evidence") or {}
    value_path = _norm_registry_value_path(evidence.get("registry_value_path"))
    if not value_path:
        return None
    signature_info = evidence.get("signature") if isinstance(evidence.get("signature"), dict) else {}
    signer = str(signature_info.get("signer") or evidence.get("signer") or "").strip()
    if not signer:
        return None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_path = _norm_registry_value_path(entry.get("registry_value_path"))
        signer_needle = str(entry.get("signer_contains") or "").strip()
        if not entry_path or not signer_needle:
            continue
        if entry_path != value_path:
            continue
        if signer_needle.lower() not in signer.lower():
            continue
        return {
            "type": "persistence_ext_allow",
            "value": f"{value_path}（signer 含 {signer_needle}）",
        }
    return None


def match_whitelist(finding: dict[str, Any], whitelist: dict[str, Any] | None = None) -> dict[str, str] | None:
    """判断 Finding 是否命中白名单，返回命中详情（type/value）或 None。"""
    config = whitelist if whitelist is not None else load_whitelist()
    if not config.get("enabled", True) or config.get("mode") == "off":
        return None

    evidence = finding.get("evidence") or {}
    texts = _evidence_texts(finding)
    joined = _norm_text(" | ".join(texts))
    target_norm = _norm_abs(normalize_path(finding.get("target", "")))
    image_norm = _norm_abs(normalize_path(evidence.get("image_path", "")))

    # 1) 路径白名单：支持目录（包含关系）与完整文件路径
    for entry in config.get("paths", []):
        entry_norm = _norm_abs(normalize_path(entry))
        if not entry_norm:
            continue
        for candidate in (target_norm, image_norm):
            if candidate and path_under(candidate, entry_norm):
                return {"type": "paths", "value": str(entry)}

    # 1.5) 厂商伪装结构化豁免（签名者 + 路径 + valid 签名）
    masquerade_match = _match_masquerade_allow(finding, config)
    if masquerade_match:
        return masquerade_match

    # 1.6) 冷门持久化扩展点结构化豁免（注册表值路径精确 + 签名者子串）
    persistence_ext_match = _match_persistence_ext_allow(finding, config)
    if persistence_ext_match:
        return persistence_ext_match

    # 2) 签名者/公司白名单（大小写不敏感子串）
    for entry in config.get("signers", []):
        needle = _norm_text(entry)
        if not needle:
            continue
        for key in ("signer", "company"):
            value = _norm_text(evidence.get(key))
            if value and needle in value:
                return {"type": "signers", "value": str(entry)}

    # 3) 扩展白名单：只做扩展 ID 精确匹配（不做名称子串，防 typosquatting 放行）
    extension_config = _normalize_extension_allowlist(config.get("extensions"))
    extension_id = _norm_text(evidence.get("extension_id")).strip()
    if extension_id:
        if extension_id in extension_config["allowlist_by_id"]:
            return {"type": "extensions", "value": extension_id}
        max_score = extension_config["allowlist_by_id_with_max_score"].get(extension_id)
        if max_score is not None:
            try:
                score = int(float(evidence.get("score") or 0))
            except (TypeError, ValueError):
                score = 0
            if score <= max_score:
                return {
                    "type": "extensions",
                    "value": f"{extension_id}（评分 {score} ≤ 白名单上限 {max_score}）",
                }

    # 4) 服务名 / 计划任务名白名单
    for key, entries in (("service_name", config.get("services", [])), ("task_name", config.get("tasks", []))):
        value = _norm_text(evidence.get(key))
        for entry in entries:
            needle = _norm_text(entry)
            if not needle:
                continue
            if (value and needle == value) or (needle and needle in joined):
                return {"type": "services" if key == "service_name" else "tasks", "value": str(entry)}

    # 5) 命令行正则白名单
    for entry in config.get("commandline_patterns", []):
        try:
            regex = re.compile(str(entry), re.IGNORECASE)
        except re.error:
            continue
        for text in texts:
            if regex.search(str(text)):
                return {"type": "commandline_patterns", "value": str(entry)}

    return None


def apply_whitelist(
    findings: Iterable[dict[str, Any]] | None,
    whitelist: dict[str, Any] | None = None,
    mode: str | None = None,
) -> list[dict[str, Any]]:
    """对所有 Finding 应用白名单：downgrade 降为 INFO、filter 丢弃、off 不过滤。

    Args:
        findings: 待过滤的 Finding 列表。
        whitelist: 白名单配置；缺省时加载 ``rules/whitelist.json``。
        mode: 覆盖白名单文件里的 ``mode``（``downgrade``/``filter``/``off``）。
            缺省时沿用配置文件值。扫描调度核心显式传 ``downgrade`` 以保证
            GUI/CLI 默认保留"降级为 INFO"的可追溯记录。

    返回新列表，不修改入参对象（除被降级的项会生成浅拷贝）。
    """
    config = whitelist if whitelist is not None else load_whitelist()
    effective_mode = str(mode or config.get("mode", "downgrade")).lower()
    if effective_mode not in _WHITELIST_MODES:
        effective_mode = "downgrade"
    result: list[dict[str, Any]] = []
    for finding in findings or []:
        hit = match_whitelist(finding, config)
        if not hit:
            result.append(finding)
            continue
        if effective_mode == "filter":
            continue
        if effective_mode == "off":
            result.append(finding)
            continue
        downgraded = dict(finding)
        evidence = dict(downgraded.get("evidence") or {})
        evidence["whitelisted"] = True
        evidence["whitelist_match"] = hit
        downgraded["evidence"] = evidence
        if SEVERITY_ORDER.get(str(downgraded.get("severity", "")), 99) < SEVERITY_ORDER["INFO"]:
            downgraded["severity"] = "INFO"
        result.append(downgraded)
    return result


__all__ = ["DEFAULT_WHITELIST", "apply_whitelist", "load_whitelist", "match_whitelist"]
