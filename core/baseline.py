# -*- coding: utf-8 -*-
"""基线对比（Baseline Diff）引擎（V1.3 起步，V1.4 增强）。

设计目标
--------
把一个"静态扫描器"升级为"动态判篡改"工具：把本次扫描结果与用户此前保存的
基线报告（均由 :func:`reporter.build_report` 生成）按主键逐项对比，输出
``NEW`` / ``RESOLVED`` / ``ESCALATED`` / ``DOWNGRADED`` / ``MODIFIED`` /
``BENIGN_UPDATE`` / ``UNCHANGED`` 七种状态。

V1.4 增强
---------
- **严格 target 归一化**（:func:`normalize_target`）：展开环境变量、剥离
  ``\\\\?\\`` / ``\\??\\`` 长路径前缀、Sysnative→System32、8.3 短名→长名
  （``GetLongPathNameW``）、normcase、去除尾部空白/分隔符；注册表 target 只做
  大小写/分隔符归一而不调用文件 API。index / 匹配 / annotate 统一使用该归一化，
  对比时把结果写入 ``normalized_key``（纯扫描路径不写，保持默认 JSON 与 V1.3 一致）。
- **良性版本前进豁免**：签名都 valid 但 SHA256 变化（白利用式篡改）时，若两侧
  签名者一致且 PE 版本（``pe.FileVersion`` 或 ``pe.TimeDateStamp``）单调前进，
  视为正常自动更新：``treat_version_bump_as_benign=True`` → ``BENIGN_UPDATE``
  （完全静默）；默认 → 仍为 ``MODIFIED`` 但降为 MEDIUM。签名者不同/版本倒退/
  无版本信息时保持原 MODIFIED + HIGH。

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

V1.5 C2 增强（系统更新时间窗容差）
--------------------------------
- **1 小时时间窗 + 系统更新目录**：哈希变化且"签名一致 + 版本未回退"时，若文件
  ``mtime`` 距基线生成时间不超过 3600 秒（且不早于基线），并且路径位于
  ``WinSxS`` / ``System32\\DriverStore`` / ``servicing`` / ``$WinREAgent`` /
  ``SoftwareDistribution``，则判定为 Windows 更新刚写入系统文件的正常行为，
  直接输出 ``BENIGN_UPDATE``（完全静默，不受 ``--treat-version-bump-as-benign``
  开关影响）。``mtime`` 优先取 ``evidence.mtime``，缺失时对本地文件 target 做
  ``os.stat`` 兜底；任一条件缺失都保持原有 ``MODIFIED`` 判定，不引入新的静默。

典型用法::

    from core import baseline

    diff = baseline.diff_reports(baseline_report, current_report, baseline_path="base.json")
    print(diff.counts)              # {"NEW": 1, "RESOLVED": 0, ...}
    enriched = report  # 由 reporter.apply_baseline_diff 挂载 diff_status
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from . import utils
from .finding import SEVERITY_ORDER, rule_basename

# 基线报告结构标识（写入报告顶层 baseline 元信息，便于人工识别）
BASELINE_SCHEMA_VERSION = "1.3"

# 七种对比状态（顺序即报告展示顺序；V1.4 增加 BENIGN_UPDATE，原顺序语义保留）
DIFF_NEW = "NEW"
DIFF_RESOLVED = "RESOLVED"
DIFF_ESCALATED = "ESCALATED"
DIFF_DOWNGRADED = "DOWNGRADED"
DIFF_MODIFIED = "MODIFIED"
DIFF_BENIGN_UPDATE = "BENIGN_UPDATE"
DIFF_UNCHANGED = "UNCHANGED"
DIFF_STATUSES: tuple[str, ...] = (
    DIFF_NEW,
    DIFF_MODIFIED,
    DIFF_ESCALATED,
    DIFF_DOWNGRADED,
    DIFF_RESOLVED,
    DIFF_BENIGN_UPDATE,
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

# V1.5 C2：系统更新目录时间窗容差（哈希变化但文件是刚被系统更新写入的）
#: 文件 mtime 晚于基线生成时间且相差不超过 1 小时，才视为"刚更新的系统文件"
SYSTEM_UPDATE_WINDOW_SECONDS = 3600

#: 相对系统根目录（%SystemRoot%）的系统更新/组件目录白名单
SYSTEM_UPDATE_SUBDIRS: tuple[str, ...] = (
    "WinSxS",
    os.path.join("System32", "DriverStore"),
    "servicing",
    "$WinREAgent",
    "SoftwareDistribution",
)

#: 读取 Finding 文件 mtime 时依次尝试的 evidence 路径（V1.5 新增，旧数据缺失即跳过）
_MTIME_EVIDENCE_PATHS: tuple[tuple[str, ...], ...] = (
    ("mtime",),
    ("last_write_time",),
    ("modified_time",),
    ("target_mtime",),
    ("file", "mtime"),
    ("file", "last_write_time"),
    ("file_info", "mtime"),
    ("file_info", "last_write_time"),
)

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
    # V1.4：良性版本前进豁免（哈希变化但版本单调前进）
    version_bump: bool = False
    benign_update: bool = False
    # V1.5 C2：系统更新时间窗豁免（mtime 距基线生成 1h 内 + 系统更新目录）
    recent_system_update: bool = False
    baseline_version: Any = None
    current_version: Any = None
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
            "version_bump": self.version_bump,
            "benign_update": self.benign_update,
            "recent_system_update": self.recent_system_update,
            "baseline_version": self.baseline_version,
            "current_version": self.current_version,
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


# ---------------------------------------------------------------------------
# 严格 target 归一化（V1.4）
# ---------------------------------------------------------------------------

_TARGET_TYPE_AUTO = "auto"
_TARGET_TYPE_PATH = "path"
_TARGET_TYPE_REGISTRY = "registry"
_TARGET_TYPES: tuple[str, ...] = (_TARGET_TYPE_AUTO, _TARGET_TYPE_PATH, _TARGET_TYPE_REGISTRY)

# 注册表根键简称/全称（auto 启发式；大小写不敏感）
_REGISTRY_HIVES: frozenset[str] = frozenset(
    {
        "HKLM",
        "HKEY_LOCAL_MACHINE",
        "HKCU",
        "HKEY_CURRENT_USER",
        "HKCR",
        "HKEY_CLASSES_ROOT",
        "HKU",
        "HKEY_USERS",
        "HKCC",
        "HKEY_CURRENT_CONFIG",
    }
)

# 长路径前缀：\\?\C:\... / \\?\UNC\server\share / \??\C:\...
_LONG_PATH_PREFIX = "\\\\?\\"
_NT_OBJECT_PREFIX = "\\??\\"

_LONG_PATH_BUFFER_SIZE = 32768
_SYSNATIVE_RE = re.compile(r"(?i)\\sysnative(?=\\|$)")

# 懒加载的 kernel32（只在需要解析 8.3 短名时初始化；测试可 mock _get_kernel32）
_KERNEL32: Any = None


def _get_kernel32() -> Any:
    """返回已声明 GetLongPathNameW 签名的 kernel32（仅在 Windows 上可用）。"""
    global _KERNEL32
    if _KERNEL32 is None:
        kernel32 = ctypes.WinDLL("kernel32.dll")  # type: ignore[attr-defined]
        kernel32.GetLongPathNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
        kernel32.GetLongPathNameW.restype = ctypes.c_ulong
        _KERNEL32 = kernel32
    return _KERNEL32


def _strip_long_path_prefix(text: str) -> str:
    """剥离 ``\\\\?\\`` / ``\\??\\`` 前缀；``\\\\?\\UNC\\server\\share`` 还原成 UNC。"""
    lowered = text.lower()
    if lowered.startswith(_LONG_PATH_PREFIX.lower()):
        stripped = text[len(_LONG_PATH_PREFIX) :]
        if stripped.lower().startswith("unc\\"):
            return "\\\\" + stripped[4:]
        return stripped
    if lowered.startswith(_NT_OBJECT_PREFIX.lower()):
        stripped = text[len(_NT_OBJECT_PREFIX) :]
        if stripped.lower().startswith("unc\\"):
            return "\\\\" + stripped[4:]
        return stripped
    return text


def _replace_sysnative(text: str) -> str:
    """把 ``\\Sysnative\\`` 重定向路径替换成 ``\\System32\\``（大小写不敏感）。"""
    if "sysnative" not in text.lower():
        return text
    return _SYSNATIVE_RE.sub(lambda _match: "\\System32", text)


def _long_path_from_kernel32(path: str) -> str:
    """用 ``GetLongPathNameW`` 把 8.3 短名解析为长名；失败/非 Windows 保留原值。"""
    if not path or os.name != "nt":
        return path
    try:
        kernel32 = _get_kernel32()
        buffer = ctypes.create_unicode_buffer(_LONG_PATH_BUFFER_SIZE)
        length = int(kernel32.GetLongPathNameW(path, buffer, _LONG_PATH_BUFFER_SIZE) or 0)
        if 0 < length < _LONG_PATH_BUFFER_SIZE:
            value = str(buffer.value or "").strip()
            if value:
                return value
    except Exception:  # noqa: BLE001 - 文件 API 失败一律保留原值，不抛异常
        return path
    return path


def _looks_like_registry_target(text: str) -> bool:
    first = text.split("\\", 1)[0].strip().upper()
    if not first:
        return False
    return first in _REGISTRY_HIVES or first.startswith("HKEY_")


def _looks_like_path_target(text: str) -> bool:
    """auto 启发式：盘符 / UNC / 含反斜杠且 basename 带扩展名的相对路径。"""
    if re.match(r"(?i)^[a-z]:", text):
        return True
    if text.startswith("\\\\"):
        return True
    if "\\" not in text:
        return False
    basename = text.rsplit("\\", 1)[-1]
    return "." in basename


def _resolve_target_type(text: str, target_type: str) -> str:
    requested = str(target_type or _TARGET_TYPE_AUTO).strip().lower()
    if requested not in _TARGET_TYPES:
        requested = _TARGET_TYPE_AUTO
    if requested != _TARGET_TYPE_AUTO:
        return requested
    if _looks_like_registry_target(text):
        return _TARGET_TYPE_REGISTRY
    if _looks_like_path_target(text):
        return _TARGET_TYPE_PATH
    return _TARGET_TYPE_REGISTRY


def _normalize_registry_target(text: str) -> str:
    """注册表/其它非文件 target：只做大小写、分隔符与空白归一，不调用文件 API。"""
    value = text.strip().rstrip(" ")
    value = value.replace("/", "\\")
    value = re.sub(r"\\{2,}", lambda _match: "\\", value)
    value = value.rstrip(" \\")
    return value.lower()


def _normalize_path_target(text: str) -> str:
    """文件路径 target：前缀/Sysnative/8.3/normpath/normcase/尾部归一。"""
    value = _strip_long_path_prefix(text.strip()).strip()
    value = _replace_sysnative(value)
    value = value.rstrip(" ")
    if os.name == "nt":
        try:
            value = os.path.normpath(value)
        except Exception:  # noqa: BLE001
            pass
    # 8.3 短名 -> 长名（GetLongPathNameW 对不存在的路径会失败，此时保留原值）
    value = _long_path_from_kernel32(value)
    value = _strip_long_path_prefix(value.strip()).strip().rstrip(" ")
    if os.name == "nt":
        try:
            value = os.path.normpath(value)
        except Exception:  # noqa: BLE001
            pass
    value = os.path.normcase(value)
    # normpath 已处理尾部分隔符（盘符根 C:\ 会保留），这里再兜一层纯尾随空格
    return value.rstrip(" ")


def normalize_target(target: Any, target_type: str = "auto") -> str:
    """把 Finding target 归一化为可比对的稳定字符串（V1.4 严格归一化）。

    规则（按顺序）：
    1. ``None`` / 非字符串防御性转成字符串（失败返回空串）；
    2. 环境变量展开（复用 :func:`core.utils.expand_vars`）；
    3. 剥离 ``\\\\?\\`` / ``\\??\\`` 长路径前缀（含 ``\\\\?\\UNC`` 还原）；
    4. ``\\Sysnative\\`` → ``\\System32\\``（大小写不敏感）；
    5. ``target_type="path"``（或 auto 判定为路径）时：8.3 短名 → 长名
       （``kernel32.GetLongPathNameW``，仅 Windows；失败/异常保留原值）、
       normpath + normcase、去尾部空白/分隔符（保留盘符根）；不存在的路径不会
       抛异常，退化为小写规范化路径；
    6. ``target_type="registry"`` 或 auto 判定为非文件路径：只做大小写、分隔符
       与空白归一，**不调用任何文件 API**（注册表键、进程名、任务名等）；
    7. ``target_type="auto"`` 启发式：盘符 / UNC / 含反斜杠且 basename 带扩展名 →
       路径，否则按注册表/其它处理。

    Returns:
        归一化后的字符串（永不为 None）。
    """
    if target is None:
        return ""
    if isinstance(target, str):
        text = target
    else:
        try:
            text = str(target)
        except Exception:  # noqa: BLE001
            return ""
    text = utils.expand_vars(text)
    if not isinstance(text, str):  # pragma: no cover - expand_vars 始终返回 str
        text = str(text)
    text = text.strip()
    if not text:
        return ""
    resolved_type = _resolve_target_type(text, target_type)
    if resolved_type == _TARGET_TYPE_REGISTRY:
        return _normalize_registry_target(text)
    return _normalize_path_target(text)


def target_key(target: Any) -> str:
    """主键中的 target 归一化（V1.4 起复用 :func:`normalize_target`）。"""
    return normalize_target(target, _TARGET_TYPE_AUTO)


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


# ---------------------------------------------------------------------------
# 良性版本前进判定（V1.4）
# ---------------------------------------------------------------------------


def _parse_file_version(value: Any) -> tuple[int, ...] | None:
    """把 ``pe.FileVersion``（"a.b.c.d" / "a,b,c,d" / 数字列表）解析为数值元组。"""
    if value is None or value is _MISSING or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return (value,)
    if isinstance(value, (list, tuple)):
        numbers: list[int] = []
        for item in value:
            if isinstance(item, bool):
                return None
            try:
                numbers.append(int(item))
            except (TypeError, ValueError):
                return None
        return tuple(numbers) if numbers else None
    text = str(value).strip()
    if not text:
        return None
    pieces = [piece for piece in re.split(r"[.,\s]+", text) if piece]
    if not pieces:
        return None
    numbers = []
    for piece in pieces:
        try:
            numbers.append(int(piece))
        except (TypeError, ValueError):
            return None
    return tuple(numbers)


def _parse_timestamp(value: Any) -> int | None:
    """把 ``pe.TimeDateStamp`` 防御性解析为整数；bool/非法值返回 None。"""
    if value is None or value is _MISSING or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 10)
    except (TypeError, ValueError):
        try:
            return int(text, 0)
        except (TypeError, ValueError):
            return None


def _pe_versions(finding: dict[str, Any] | None) -> tuple[tuple[int, ...] | None, int | None]:
    """提取 ``(pe.FileVersion 元组, pe.TimeDateStamp 整数)``；缺失/类型异常为 None。"""
    evidence = _evidence_of(finding)
    file_version = _dig(evidence, ("pe", "FileVersion"))
    if file_version is _MISSING:
        file_version = _dig(evidence, ("FileVersion",))
    timestamp = _dig(evidence, ("pe", "TimeDateStamp"))
    if timestamp is _MISSING:
        timestamp = _dig(evidence, ("TimeDateStamp",))
    return _parse_file_version(file_version), _parse_timestamp(timestamp)


def _compare_version_tuples(baseline: tuple[int, ...], current: tuple[int, ...]) -> int:
    """比较两个版本元组：1=前进、0=相同、-1=倒退（缺失位补 0）。"""
    length = max(len(baseline), len(current))
    left = baseline + (0,) * (length - len(baseline))
    right = current + (0,) * (length - len(current))
    if right > left:
        return 1
    if right < left:
        return -1
    return 0


def _signer_of(finding: dict[str, Any] | None) -> str:
    evidence = _evidence_of(finding)
    value = _dig(evidence, ("signature", "signer"))
    if value is _MISSING:
        value = _dig(evidence, ("signer",))
    if value is _MISSING or value is None:
        return ""
    return str(value).strip().lower()


def _same_nonempty_signer(
    baseline_finding: dict[str, Any] | None,
    current_finding: dict[str, Any] | None,
) -> bool:
    """两侧签名者是否一致且非空（大小写不敏感）。"""
    baseline_signer = _signer_of(baseline_finding)
    return bool(baseline_signer) and baseline_signer == _signer_of(current_finding)


def _version_progression(
    baseline_finding: dict[str, Any] | None,
    current_finding: dict[str, Any] | None,
) -> tuple[bool, Any, Any]:
    """判定版本是否单调前进，返回 ``(version_bump, baseline_version, current_version)``。

    判定顺序：优先 ``pe.FileVersion`` 数值元组（按位比较，缺失高位补 0）；
    FileVersion 相同或缺失时再比较 ``pe.TimeDateStamp`` 整数。任何字段缺失、
    类型异常、版本相同或倒退都视为"无版本前进"（version_bump=False，保持 HIGH）。
    """
    baseline_fv, baseline_ts = _pe_versions(baseline_finding)
    current_fv, current_ts = _pe_versions(current_finding)

    if baseline_fv is not None and current_fv is not None:
        comparison = _compare_version_tuples(baseline_fv, current_fv)
        if comparison > 0:
            return True, baseline_fv, current_fv
        if comparison < 0:
            return False, baseline_fv, current_fv
        # FileVersion 相同：允许 TimeDateStamp 前进（重新编译但未改版本号）
        if baseline_ts is not None and current_ts is not None and current_ts > baseline_ts:
            return True, baseline_ts, current_ts
        return False, baseline_fv, current_fv

    if baseline_ts is not None and current_ts is not None:
        if current_ts > baseline_ts:
            return True, baseline_ts, current_ts
        return False, baseline_ts, current_ts

    baseline_token = baseline_fv if baseline_fv is not None else baseline_ts
    current_token = current_fv if current_fv is not None else current_ts
    return False, baseline_token, current_token


# ---------------------------------------------------------------------------
# V1.5 C2：系统更新时间窗容差
# ---------------------------------------------------------------------------


def _to_epoch_seconds(value: Any) -> float | None:
    """把 epoch 秒 / 毫秒 / ISO8601 / datetime 防御性解析为 epoch 秒。

    容错规则：

    - 秒/毫秒数值以及**数字字符串**统一按 ``>1e12`` 视为毫秒并除以 1000；
    - 无时区的 ISO / 日期字符串按 **UTC** 解释（与无时区 datetime 对象一致，
      避免不同主机时区导致 1 小时窗口偏移）；
    - ``NaN`` / ``±inf`` / bool / 缺失 / 非法值 -> ``None``，绝不抛异常。
    """
    if value is None or value is _MISSING or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        try:
            moment = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
            return moment.timestamp()
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, (int, float)):
        number = float(value)
        if not math.isfinite(number):
            return None
        if abs(number) > 1e12:  # 毫秒时间戳
            number /= 1000.0
        return number
    text = str(value).strip()
    if not text:
        return None
    try:
        number = float(text)
    except (TypeError, ValueError):
        number = None
    if number is not None:
        if not math.isfinite(number):
            return None
        if abs(number) > 1e12:  # 数字字符串形态的毫秒时间戳
            number /= 1000.0
        return number
    iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        moment = datetime.fromisoformat(iso_text)
    except (OSError, OverflowError, ValueError):
        moment = None
    if moment is not None:
        try:
            return (moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)).timestamp()
        except (OSError, OverflowError, ValueError):
            return None
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(text, pattern).replace(tzinfo=timezone.utc).timestamp()
        except (TypeError, ValueError):
            continue
    return None


def _system_update_roots(roots: Iterable[str] | None = None) -> list[str]:
    """系统更新目录前缀列表（默认按 ``%SystemRoot%`` 拼装，可用参数覆盖/测试）。"""
    if roots is not None:
        return [str(item).strip() for item in roots if str(item or "").strip()]
    base = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    return [os.path.join(base, sub) for sub in SYSTEM_UPDATE_SUBDIRS]


def _is_system_update_path(path: Any, roots: Iterable[str] | None = None) -> bool:
    """路径是否位于系统更新/组件目录（WinSxS / DriverStore / servicing 等）。"""
    if not path:
        return False
    text = str(path).strip()
    if not text:
        return False
    return any(utils.path_under(text, root) for root in _system_update_roots(roots))


def _is_recent_system_update(
    file_mtime: Any,
    baseline_generated_at: Any,
    file_path: Any = _MISSING,
    *,
    roots: Iterable[str] | None = None,
) -> bool:
    """判断一次哈希变化是否属于"刚发生的系统更新"（V1.5 C2）。

    判定条件（必须同时满足）：

    1. ``file_mtime`` 与 ``baseline_generated_at`` 都可解析；
    2. ``0 <= file_mtime - baseline_generated_at <= 3600`` 秒（基线生成后 1 小时内）；
    3. ``file_path`` 位于系统更新目录白名单（``WinSxS`` /
       ``System32\\DriverStore`` / ``servicing`` / ``$WinREAgent`` /
       ``SoftwareDistribution``，均以 ``%SystemRoot%`` 为根）。

    兼容两种调用方式：**省略**第三个参数时仅判定时间窗（供单元测试/调用方自行
    判断目录）；显式传 ``file_path``（包括 ``None`` / 空串）时同时校验目录，空值
    返回 ``False``（fail closed），避免未来调用方漏传路径导致意外放行。

    该函数是纯函数（仅读取 ``SystemRoot`` 环境变量拼默认根目录，可用 ``roots``
    参数显式覆盖），不做任何 IO / 全局状态修改。缺少 mtime 或基线时间时一律
    返回 ``False``（保持原有判定，不引入新的静默）。
    """
    mtime = _to_epoch_seconds(file_mtime)
    baseline_time = _to_epoch_seconds(baseline_generated_at)
    if mtime is None or baseline_time is None:
        return False
    delta = mtime - baseline_time
    if not 0 <= delta <= SYSTEM_UPDATE_WINDOW_SECONDS:
        return False
    if file_path is _MISSING:
        return True
    if file_path is None or not str(file_path).strip():
        return False
    return _is_system_update_path(file_path, roots)


def _looks_like_local_drive(value: Any) -> bool:
    """是否本地盘符路径（``^[A-Za-z]:[\\/]``）；UNC 不算，避免触发网络 stat。"""
    return bool(re.match(r"(?i)^[a-z]:[\\/]", str(value or "").strip()))


def _looks_like_unc(value: Any) -> bool:
    """是否 UNC 网络路径（``\\\\server\\share``）。"""
    return str(value or "").strip().startswith("\\\\")


def _looks_like_local_path(value: Any) -> bool:
    """兼容旧名：仅本地盘符路径允许 stat（UNC 返回 False）。"""
    return _looks_like_local_drive(value)


def _finding_file_mtime(finding: dict[str, Any] | None) -> Any:
    """从 Finding 提取文件 mtime：优先 evidence，再对本地文件 target 做 os.stat 兜底。"""
    evidence = _evidence_of(finding)
    for path in _MTIME_EVIDENCE_PATHS:
        value = _dig(evidence, path)
        if value is not _MISSING and value is not None:
            return value
    target = _finding_target_path(finding)
    if target and _looks_like_local_drive(target):
        try:
            return os.path.getmtime(target)
        except OSError:
            return None
    return None


def _finding_target_path(finding: dict[str, Any] | None) -> str:
    """提取用于目录判定的目标路径（优先 target，其次 evidence 中的文件路径）。"""
    if not isinstance(finding, dict):
        return ""
    target = str(finding.get("target") or "").strip()
    if target:
        return target
    evidence = _evidence_of(finding)
    for key in ("image_path", "path", "file_path", "target_path"):
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _version_not_regressed(
    baseline_finding: dict[str, Any] | None,
    current_finding: dict[str, Any] | None,
) -> bool:
    """版本是否"未回退"：无版本信息视为未回退；任一可比较版本回退则 False。"""
    baseline_fv, baseline_ts = _pe_versions(baseline_finding)
    current_fv, current_ts = _pe_versions(current_finding)
    if baseline_fv is not None and current_fv is not None:
        if _compare_version_tuples(baseline_fv, current_fv) < 0:
            return False
        if baseline_ts is not None and current_ts is not None and current_ts < baseline_ts:
            return False
        return True
    if baseline_ts is not None and current_ts is not None and current_ts < baseline_ts:
        return False
    return True


def _make_entry(
    rule_base: str,
    baseline_finding: dict[str, Any] | None,
    current_finding: dict[str, Any] | None,
    *,
    treat_version_bump_as_benign: bool = False,
    baseline_generated_at: Any = None,
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
        # 哈希变化优先于严重等级变化；但"签名者一致 + 版本单调前进"视为正常自动更新（V1.4）。
        version_bump, baseline_version, current_version = _version_progression(
            baseline_finding, current_finding
        )
        same_signer = _same_nonempty_signer(baseline_finding, current_finding)
        # V1.5 C2：签名一致、版本未回退，且文件 mtime 在基线生成后 1 小时内、
        # 位于系统更新目录 -> 视为 Windows 更新刚写入，降级 BENIGN_UPDATE（完全静默）。
        if (
            same_signer
            and _version_not_regressed(baseline_finding, current_finding)
            and _is_recent_system_update(
                _finding_file_mtime(current_finding),
                baseline_generated_at,
                _finding_target_path(current_finding),
            )
        ):
            entry.status = DIFF_BENIGN_UPDATE
            entry.benign_update = True
            entry.recent_system_update = True
            entry.version_bump = version_bump
            entry.baseline_version = baseline_version
            entry.current_version = current_version
            return entry
        if version_bump and same_signer:
            entry.version_bump = True
            entry.baseline_version = baseline_version
            entry.current_version = current_version
            if treat_version_bump_as_benign:
                # 完全静默：不强制 HIGH、不写篡改 detail
                entry.status = DIFF_BENIGN_UPDATE
                entry.benign_update = True
            else:
                # 仍为 MODIFIED，但降为 MEDIUM（annotate 追加"版本正常前进"说明）
                entry.status = DIFF_MODIFIED
                entry.current_severity = "MEDIUM"
            return entry
        # 签名者不同 / 版本倒退 / 非系统更新目录 / 无 mtime：保持原逻辑 MODIFIED + HIGH
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
    treat_version_bump_as_benign: bool = False,
) -> BaselineDiff:
    """对比两份 ``build_report()`` 结果，返回 :class:`BaselineDiff`。

    Args:
        baseline_report: 基线报告 dict（结构异常时按空基线处理，全部标记 NEW）。
        current_report: 本次报告 dict（或 Finding 列表）。
        baseline_path: 基线文件路径（写入报告元信息，仅用于展示）。
        treat_version_bump_as_benign: 哈希变化且"签名者一致 + 版本单调前进"时，
            True 输出 ``BENIGN_UPDATE``（完全静默）；False（默认）仍输出
            ``MODIFIED`` 但降为 MEDIUM。

    V1.5 C2：哈希变化且"签名一致 + 版本未回退 + 文件 mtime 在基线生成后 1 小时内
    + 位于系统更新目录"时，无论 ``treat_version_bump_as_benign`` 取值如何都输出
    ``BENIGN_UPDATE``（对应 Windows 更新刚写入系统文件）。

    主键匹配分两阶段：先配对"基线/当前都存在"的 Finding（多个规则基名任一命中
    即视为同一事实），再把未配对项标为 RESOLVED / NEW，避免 merged_rules 或
    规则基名变化导致同一事实被重复计数。
    """
    baseline_findings = _report_findings(baseline_report)
    current_findings = _report_findings(current_report)
    baseline_index = index_findings(baseline_findings)
    current_index = index_findings(current_findings)
    baseline_generated_at = (
        str(baseline_report.get("generated_at") or "")
        if isinstance(baseline_report, dict)
        else ""
    )

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
        entries.append(
            _make_entry(
                key[1],
                baseline_finding,
                current_finding,
                treat_version_bump_as_benign=treat_version_bump_as_benign,
                baseline_generated_at=baseline_generated_at,
            )
        )

    # 阶段 2：未配对的基线项 -> RESOLVED；未配对的当前项 -> NEW
    for key in sorted(baseline_index):
        baseline_finding = baseline_index[key]
        if id(baseline_finding) in paired_baseline:
            continue
        paired_baseline.add(id(baseline_finding))
        entries.append(
            _make_entry(
                key[1],
                baseline_finding,
                None,
                treat_version_bump_as_benign=treat_version_bump_as_benign,
                baseline_generated_at=baseline_generated_at,
            )
        )
    for key in sorted(current_index):
        current_finding = current_index[key]
        if id(current_finding) in paired_current:
            continue
        paired_current.add(id(current_finding))
        entries.append(
            _make_entry(
                key[1],
                None,
                current_finding,
                treat_version_bump_as_benign=treat_version_bump_as_benign,
                baseline_generated_at=baseline_generated_at,
            )
        )

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
    """返回七种状态计数（缺失状态补 0，保证 UI 可直接取键）。"""
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


def _attach_version_evidence(evidence: dict[str, Any], entry: DiffEntry) -> None:
    """把版本前进信息写入 annotate 输出的 evidence（不修改 DiffEntry/入参）。"""
    evidence["version_bump"] = True
    if entry.baseline_version is not None:
        evidence["baseline_version"] = entry.baseline_version
    if entry.current_version is not None:
        evidence["current_version"] = entry.current_version


def annotate_findings(
    findings: Iterable[dict[str, Any]] | None,
    diff: BaselineDiff | None,
) -> list[dict[str, Any]]:
    """给当前 Finding 列表挂载 ``diff_status``，并追加 RESOLVED 基线项。

    - 返回新列表，不修改入参 Finding；
    - 有 diff 时每个返回项（含追加的 RESOLVED 项）写 ``normalized_key``（V1.4）；
      无 diff 的纯扫描路径不新增该键，保证默认 JSON 与 V1.3 一致；
    - ``BENIGN_UPDATE`` 条目完全静默：不提升严重等级、不追加篡改提示，仅写
      ``evidence.benign_update=True``；版本前进时追加版本信息，系统更新时间窗
      豁免时追加 ``evidence.recent_system_update=True``；
    - ``MODIFIED`` 且版本前进（``entry.version_bump``）：降为 MEDIUM，detail 追加
      "版本正常前进（自动更新），已降级为 MEDIUM"，不再写 HIGH 篡改措辞；
    - 其它 ``hash_tamper`` 条目：提升为 HIGH，并在 detail 追加篡改提示；
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
            item = dict(finding)
            item["normalized_key"] = normalize_target(item.get("target"))
            annotated.append(item)
            continue
        if str(finding.get("diff_status") or "") == DIFF_RESOLVED:
            already_annotated = True
        item = dict(finding)
        evidence = dict(_evidence_of(finding))
        item["evidence"] = evidence
        item["diff_status"] = entry.status
        item["normalized_key"] = normalize_target(item.get("target"))
        if entry.status == DIFF_BENIGN_UPDATE:
            # 完全静默：不提升严重等级、不写篡改 detail；reporter 负责中性样式
            evidence["benign_update"] = True
            if entry.recent_system_update:
                evidence["recent_system_update"] = True
            if entry.version_bump:
                _attach_version_evidence(evidence, entry)
        elif entry.hash_tamper and entry.version_bump:
            # 版本正常前进（自动更新）：降为 MEDIUM，不写"疑似被篡改"措辞
            item["severity"] = "MEDIUM"
            evidence["hash_tamper"] = True
            if entry.baseline_sha256:
                evidence["baseline_sha256"] = entry.baseline_sha256
            _attach_version_evidence(evidence, entry)
            detail = str(item.get("detail") or "")
            message = "版本正常前进（自动更新），已降级为 MEDIUM"
            if message not in detail:
                item["detail"] = f"{detail}；{message}" if detail else message
        elif entry.hash_tamper:
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
            item["normalized_key"] = normalize_target(item.get("target"))
            annotated.append(item)
    return annotated
