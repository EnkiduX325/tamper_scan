# -*- coding: utf-8 -*-
"""白名单加载 / 匹配 / 应用（V1.4 拆分，V1.5 联合指纹增强）。

V1.5 在原有五类白名单（paths / signers / services / tasks / commandline_patterns）
基础上新增**联合指纹豁免**（``fingerprints``）：

- 匹配覆盖 ``rule_id`` + ``signer_contains`` + ``target_prefix`` 三个维度：
  ``target_prefix`` **必填**且必须是具体对象/目录（盘符根、注册表根等过宽前缀
  一律拒绝），因此单靠"目录白名单"放行整棵目录的做法不再成立（防黑客把恶意
  文件放进受信任目录"蹭目录"）；
- ``rule_id`` 为空/``*`` 表示不限制规则、``signer_contains`` 为空表示不限制
  签名者——这是为无签名 Finding 保留的语义；GUI 的"信任此项"始终写入真实
  ``rule_id`` 与完整 target，三个维度天然同时生效；
- 每条指纹支持 ``expire_days``：``created_at + expire_days`` 到期后**自动失效**，
  防止长期白名单滥用；声明了 ``expire_days`` 但缺少创建时间的条目按"立即失效"
  处理（fail closed）；
- GUI"信任此项"通过 :func:`build_trust_entry` 生成上述格式，持久化在用户级
  ``config.json``（:mod:`core.config`），由 :func:`load_whitelist` 合并进
  ``fingerprints``，**无需修改只读的程序目录规则文件**。

兼容性：``load_whitelist(path)`` 位置参数与原有五类白名单行为保持不变；新增参数
均为 keyword-only。依赖 :mod:`core.finding`、:mod:`core.paths`、:mod:`core.config`，
**不依赖** :mod:`core.utils`。``DEFAULT_WHITELIST`` 与
``utils.DEFAULT_WHITELIST`` 是同一个对象（兼容 shim 再导出）。
"""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any, Iterable

from . import config as _config
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
    # V1.5 联合指纹豁免（GUI 信任按钮写入 config.json 的 trust.entries，加载时合并）：
    # 每项 {"rule_id", "signer_contains", "target_prefix", "created_at",
    #       "expires_at", "expire_days", "source", "note"}
    "fingerprints": [],
}


#: 联合指纹命中的 whitelist_match.type 取值（GUI / 报告据此展示）
FINGERPRINT_MATCH_TYPE = "fingerprints"

#: GUI 信任按钮默认有效期（天），与 :mod:`core.config` 保持同一来源
DEFAULT_TRUST_EXPIRE_DAYS = _config.DEFAULT_TRUST_EXPIRE_DAYS


_WHITELIST_LIST_KEYS = ("paths", "commandline_patterns", "signers", "domains", "services", "tasks")


_WHITELIST_MODES = ("downgrade", "filter", "off")


def load_whitelist(
    path: str | os.PathLike[str] | None = None,
    *,
    include_user_trust: bool = True,
    trust_entries: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """加载白名单配置；文件不存在时返回空骨架（阶段 0 即为空文件）。

    Args:
        path: 白名单 JSON 路径；缺省为 ``rules/whitelist.json``。
        include_user_trust: 是否把用户级 ``config.json`` 的 ``trust.entries``
            合并进 ``fingerprints``（默认 True；GUI 信任按钮即依赖此机制）。
        trust_entries: 显式指定用户信任项（测试用；为 ``None`` 时从 config 读取，
            传空列表可关闭合并而不改默认行为）。

    返回 dict 始终包含 enabled/mode、六类列表键与 ``fingerprints``，便于调用方
    安全迭代。归一化后的 ``fingerprints`` 已去重（用户条目覆盖内置同键条目）。
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
    # V1.5：内置联合指纹 + 用户信任名单（config.json trust.entries）
    builtin_fingerprints = _normalize_fingerprint_list(merged.get("fingerprints"))
    if include_user_trust or trust_entries is not None:
        raw_user_entries = trust_entries if trust_entries is not None else _load_user_trust_entries()
        user_fingerprints = _normalize_fingerprint_list(raw_user_entries)
        builtin_fingerprints = _merge_fingerprint_lists(builtin_fingerprints, user_fingerprints)
    merged["fingerprints"] = builtin_fingerprints
    merged["_source"] = str(target)
    merged["_loaded"] = isinstance(data, dict)
    return merged


def _load_user_trust_entries() -> list[dict[str, Any]]:
    """从用户级 config.json 读取信任名单；任何异常都降级为空列表（不影响扫描）。"""
    try:
        entries = _config.load_trust_entries()
    except Exception:  # noqa: BLE001 - 用户配置损坏绝不能影响扫描主流程
        return []
    return [item for item in entries if isinstance(item, dict)]


def _normalize_fingerprint_list(value: Any) -> list[dict[str, Any]]:
    """归一化联合指纹列表：非 dict / 缺必要维度 / 非法条目丢弃，同键去重后保留最后一条。"""
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for raw in value:
        normalized = _config.normalize_trust_entry(raw)
        if normalized is None:
            continue
        merged[_config.trust_entry_key(normalized)] = normalized
    return list(merged.values())


def _merge_fingerprint_lists(
    builtin: list[dict[str, Any]],
    user: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """合并内置与用户指纹：同键时用户条目覆盖内置条目。"""
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in builtin:
        merged[_config.trust_entry_key(entry)] = entry
    for entry in user:
        merged[_config.trust_entry_key(entry)] = entry
    return list(merged.values())


def normalize_fingerprint_entry(
    entry: Any,
    now: Any = None,
) -> dict[str, Any] | None:
    """归一化单条联合指纹（GUI 生成 / 手写配置 / 匹配前校验共用）。

    委托给 :func:`core.config.normalize_trust_entry`，保证白名单存储与匹配对
    ``expire_days`` / ``expires_at`` 的语义完全一致。
    """
    return _config.normalize_trust_entry(entry, now=now)


def fingerprint_active(entry: Any, now: Any = None) -> bool:
    """联合指纹是否仍在有效期内（未声明有效期 = 永久有效）。"""
    return not _config.is_trust_entry_expired(entry, now=now)


def _finding_signer(finding: dict[str, Any]) -> str:
    """从 Finding 中提取签名者（兼容 evidence.signature.signer / evidence.signer / company）。"""
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    signature = evidence.get("signature") if isinstance(evidence.get("signature"), dict) else {}
    candidates = (
        signature.get("signer"),
        evidence.get("signer"),
        evidence.get("company"),
        finding.get("signer"),
    )
    for candidate in candidates:
        text = " ".join(str(candidate or "").split()).strip()
        if text:
            return text
    return ""


def build_trust_entry(
    finding: dict[str, Any],
    *,
    expire_days: int | None = DEFAULT_TRUST_EXPIRE_DAYS,
    source: str = "gui_trust",
    note: str = "",
    now: Any = None,
) -> dict[str, Any]:
    """由 Finding 生成符合联合指纹格式的信任项（GUI"信任此项"按钮使用）。

    提取 ``rule_id``、``signer``、``target`` 三个维度：

    - ``rule_id``：Finding 的规则编号（为空时用 ``*`` 表示任意规则）；
    - ``signer_contains``：签名者子串（无签名信息时为空 = 不限制签名者）；
    - ``target_prefix``：**完整 target 作为前缀**（而非父目录），把信任范围精确
      限定到该对象本身，避免"黑产把恶意文件放进被信任目录即豁免"。

    Args:
        finding: 扫描 Finding dict。
        expire_days: 有效期天数；``None`` 表示永久（默认 90 天，到期自动失效）。
        source: 来源标记，默认 ``gui_trust``。
        note: 备注（GUI 可填"用户信任原因"）。
        now: 测试注入的当前时间。

    Raises:
        ValueError: Finding 不是 dict，或缺少可用于限定的 target。
    """
    if not isinstance(finding, dict):
        raise ValueError("Finding 必须是 dict，无法生成联合指纹信任项")
    rule_id = " ".join(str(finding.get("rule_id") or "").split()).strip() or "*"
    target = str(finding.get("target") or "").strip()
    if not target:
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        target = str(evidence.get("image_path") or evidence.get("path") or "").strip()
    if not target:
        raise ValueError("Finding 缺少 target，无法生成联合指纹信任项")
    if _is_too_broad_prefix(target):
        raise ValueError("Finding target 过于宽泛（盘符根 / 注册表根），无法生成联合指纹信任项")
    entry = {
        "rule_id": rule_id,
        "signer_contains": _finding_signer(finding),
        "target_prefix": target,
        "expire_days": expire_days,
        "created_at": _config.now_iso(now),
        "source": source,
        "note": note,
    }
    normalized = _config.normalize_trust_entry(entry, now=now)
    if normalized is None:
        raise ValueError("生成的联合指纹信任项不合法")
    return normalized


_PATH_LIKE_RE = re.compile(r"(?i)^(?:[a-z]:(?:[\\/]|$)|\\\\|/)")


def _is_too_broad_prefix(prefix: Any) -> bool:
    """过宽前缀判断（整盘 / 注册表根 / 盘符相对路径），委托 :mod:`core.config`。

    与 :func:`core.config.add_trust_entry` 使用同一实现，保证"匹配 / GUI 生成 /
    配置写入"三处校验一致。
    """
    return _config.is_too_broad_prefix(prefix)


def _looks_like_path(value: str) -> bool:
    """粗判字符串是否文件系统路径（盘符 / UNC / 根路径），否则按注册表/名称前缀处理。"""
    return bool(_PATH_LIKE_RE.match(str(value or "").strip()))


def _target_prefix_match(target: Any, prefix: Any) -> bool:
    """``target_prefix`` 匹配：文件路径按目录包含，注册表/名称按分隔符边界前缀。"""
    if _is_too_broad_prefix(prefix):
        return False
    target_norm = normalize_path(target)
    prefix_norm = normalize_path(prefix)
    if not target_norm or not prefix_norm:
        return False
    if _looks_like_path(target_norm) or _looks_like_path(prefix_norm):
        return path_under(target_norm, prefix_norm)
    left = target_norm.strip().rstrip("\\/").casefold()
    right = prefix_norm.strip().rstrip("\\/").casefold()
    if not right:
        return False
    if left == right:
        return True
    return left.startswith(right + "\\") or left.startswith(right + "/")


def _rule_dimension_matches(entry_rule: str, finding_rule: str) -> bool:
    """联合指纹的规则维度匹配：精确相等或规则基名相同（兼容采集层前缀合并）。"""
    expected = str(entry_rule or "").strip().upper()
    actual = str(finding_rule or "").strip().upper()
    if not expected or expected == "*":
        return True
    if expected == actual:
        return True
    base = rule_basename(expected)
    return bool(base) and base == rule_basename(actual)


def _match_fingerprints(
    finding: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, str] | None:
    """联合指纹豁免：rule_id + signer_contains + target_prefix 三个维度同时命中才放行。"""
    raw_entries = config.get("fingerprints")
    if not isinstance(raw_entries, list) or not raw_entries:
        return None
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    target = str(finding.get("target") or "").strip()
    if not target:
        target = str(evidence.get("image_path") or evidence.get("path") or "").strip()
    if not target:
        return None
    finding_rule = str(finding.get("rule_id") or "")
    finding_signer = _finding_signer(finding)
    for raw in raw_entries:
        entry = normalize_fingerprint_entry(raw)
        if entry is None:
            continue
        if not fingerprint_active(entry):
            continue
        rule_id = entry["rule_id"]
        if not _rule_dimension_matches(rule_id, finding_rule):
            continue
        signer_needle = entry["signer_contains"]
        if signer_needle:
            if not finding_signer or signer_needle.casefold() not in finding_signer.casefold():
                continue
        if not _target_prefix_match(target, entry["target_prefix"]):
            continue
        return {
            "type": FINGERPRINT_MATCH_TYPE,
            "value": (
                f"rule_id={rule_id} signer={signer_needle or '*'} "
                f"target_prefix={entry['target_prefix']}"
            ),
        }
    return None


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

    # 1.7) V1.5 联合指纹豁免（rule_id + signer_contains + target_prefix + 有效期）
    fingerprint_match = _match_fingerprints(finding, config)
    if fingerprint_match:
        return fingerprint_match

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


__all__ = [
    "DEFAULT_TRUST_EXPIRE_DAYS",
    "DEFAULT_WHITELIST",
    "FINGERPRINT_MATCH_TYPE",
    "apply_whitelist",
    "build_trust_entry",
    "fingerprint_active",
    "load_whitelist",
    "match_whitelist",
    "normalize_fingerprint_entry",
]
