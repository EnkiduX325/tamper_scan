# -*- coding: utf-8 -*-
"""用户级配置 / 本地信任名单 / 暂存上报队列（V1.5 新增）。

职责边界
--------
- **只读内置规则**：``rules/whitelist.json`` 随程序分发，可能位于只读的
  Program Files / ``_MEIPASS``；本模块**不**修改它。
- **可写用户数据**：``config.json``（更新检查偏好、主题、联合指纹信任名单）与
  ``pending_report.json``（弱网时暂存的匿名上报）写到用户目录：
  ``%APPDATA%\\TamperScan``（测试/便携场景可用环境变量
  ``TAMPERSCAN_CONFIG_DIR`` 覆盖）。
- ``core.whitelist.load_whitelist()`` 会把 ``trust.entries`` 合并进
  ``fingerprints`` 联合指纹白名单，因此 GUI 点击"信任此项"后**无需修改程序目录**，
  下一次扫描即可生效。

健壮性约束（弱网 / 权限不足 / 文件损坏）
----------------------------------------
- 读取：文件缺失、JSON 损坏、类型不符 -> 回退默认值，**绝不抛异常**；
- 写入：同目录临时文件 + ``os.replace`` 原子替换，失败返回 ``False``；
- 并发：GUI 的 QThread 与主线程可能同时读写，所有"读取-修改-写回"都经
  模块级 ``RLock`` 串行化（可重入）。

配置结构（schema_version = 1）::

    {
      "schema_version": 1,
      "update": {
        "auto_check": true,
        "ignored_versions": [],          # 不再提示的版本（如 v1.5.1）
        "ignored_current_version": null, # "不再提示"：本次运行版本内不再提醒
        "snooze_until": null,            # "暂不更新"：24h 内不弹（ISO8601 UTC）
        "last_check_at": null,
        "last_result": null,
        "last_latest_version": null,
        "release_api": null              # 覆盖默认 GitHub latest release API
      },
      "trust": {
        "entries": [                     # 联合指纹白名单（GUI 信任按钮写入）
          {
            "rule_id": "SIG_UNSIGNED",
            "signer_contains": "Contoso Ltd",
            "target_prefix": "C:\\\\Program Files\\\\Contoso\\\\app.exe",
            "created_at": "2026-11-11T12:00:00+00:00",
            "expires_at": "2027-02-09T12:00:00+00:00",
            "expire_days": 90,
            "source": "gui_trust",
            "note": ""
          }
        ]
      },
      "reporting": {"endpoint": null, "pending_file": "pending_report.json"},
      "ui": {"theme": "light"}
    }
"""

from __future__ import annotations

import copy
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .paths import _norm_abs, normalize_path

APP_DIR_NAME = "TamperScan"
CONFIG_FILENAME = "config.json"
PENDING_REPORT_FILENAME = "pending_report.json"
ENV_CONFIG_DIR = "TAMPERSCAN_CONFIG_DIR"

#: config.json 结构版本；未来字段迁移时递增（当前加载器对未知字段宽容保留）
SCHEMA_VERSION = 1

#: GUI 信任按钮默认有效期（天）；到期自动失效，防长期白名单滥用
DEFAULT_TRUST_EXPIRE_DAYS = 90

#: 信任名单 / 暂存上报队列上限，防止长期使用后无限膨胀
MAX_TRUST_ENTRIES = 500
MAX_PENDING_REPORTS = 100
MAX_IGNORED_VERSIONS = 100

#: config.json 大小上限：配置文件是小型 JSON，超限视为异常输入直接回退默认值
MAX_CONFIG_BYTES = 2 * 1024 * 1024

#: 暂存上报队列文件大小上限（比配置宽松，且写入时同样拒绝超限）
MAX_PENDING_BYTES = 8 * 1024 * 1024

#: Windows 保留设备名不能作为文件名（pending_file 校验用）
_RESERVED_DOS_STEMS = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)

#: 盘符相对路径（如 ``C:...`` / ``C:foo``）：会被 Windows 规范化为盘符根，必须按过宽处理
_DRIVE_RELATIVE_RE = re.compile(r"(?i)^[a-z]:(?![\\/])")

#: 盘符根（``C:`` / ``C:\``）
_DRIVE_ROOT_RE = re.compile(r"(?i)^[a-z]:[\\/]?$")

#: 规范化后仍是盘符根（``ntpath.abspath("C:...") == "C:\\"``）
_CANONICAL_ROOT_RE = re.compile(r"(?i)^[a-z]:[\\/]?$")

#: 注册表根（整棵 hive 级别的过宽前缀）
_HIVE_ROOTS = frozenset(
    {
        "HKLM",
        "HKCU",
        "HKCR",
        "HKU",
        "HKCC",
        "HKEY_LOCAL_MACHINE",
        "HKEY_CURRENT_USER",
        "HKEY_CLASSES_ROOT",
        "HKEY_USERS",
        "HKEY_CURRENT_CONFIG",
    }
)

THEMES: tuple[str, ...] = ("light", "dark")

DEFAULT_CONFIG: dict[str, Any] = {
    "schema_version": SCHEMA_VERSION,
    "update": {
        "auto_check": True,
        "ignored_versions": [],
        "ignored_current_version": None,
        "snooze_until": None,
        "last_check_at": None,
        "last_result": None,
        "last_latest_version": None,
        "release_api": None,
    },
    "trust": {"entries": []},
    "reporting": {
        "endpoint": None,
        "pending_file": PENDING_REPORT_FILENAME,
    },
    "ui": {"theme": "light"},
}

_LOCK = threading.RLock()


# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------


def get_config_dir() -> Path:
    """返回可写的用户数据目录（不主动创建）。

    优先级：``TAMPERSCAN_CONFIG_DIR`` 环境变量 > Windows ``%APPDATA%`` >
    ``%LOCALAPPDATA%`` > ``~/.tamper_scan``；非 Windows 使用
    ``$XDG_CONFIG_HOME/tamper_scan`` 或 ``~/.config/tamper_scan``。
    """
    override = os.environ.get(ENV_CONFIG_DIR)
    if override:
        try:
            return Path(override).expanduser()
        except (OSError, ValueError):
            pass
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.environ.get("LOCALAPPDATA")
        if base:
            try:
                return Path(base) / APP_DIR_NAME
            except (OSError, ValueError):
                pass
        return Path.home() / ".tamper_scan"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        try:
            return Path(xdg) / "tamper_scan"
        except (OSError, ValueError):
            pass
    return Path.home() / ".config" / "tamper_scan"


def get_config_path() -> Path:
    """返回 ``config.json`` 的完整路径（不创建文件）。"""
    return get_config_dir() / CONFIG_FILENAME


def _safe_pending_filename(value: Any) -> str | None:
    """校验暂存上报文件名：纯 ``*.json`` 文件名、非 ``config.json``、非 Windows 保留名。"""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or not candidate.lower().endswith(".json"):
        return None
    try:
        name_path = Path(candidate)
    except (OSError, ValueError):
        return None
    if name_path.name != candidate or name_path.is_absolute():
        return None
    if candidate.casefold() == CONFIG_FILENAME.casefold():
        return None
    stem = candidate.split(".", 1)[0].strip().rstrip(" .").casefold()
    if stem in _RESERVED_DOS_STEMS:
        return None
    return candidate


def get_pending_report_path(config: dict[str, Any] | None = None) -> Path:
    """返回暂存上报文件的完整路径。

    ``config.reporting.pending_file`` 只允许纯 ``*.json`` 文件名（防路径穿越 /
    绝对路径 / 覆盖 config.json / Windows 保留设备名），非法值回退默认文件名。
    """
    name = PENDING_REPORT_FILENAME
    if isinstance(config, dict):
        reporting = config.get("reporting")
        if isinstance(reporting, dict):
            name = _safe_pending_filename(reporting.get("pending_file")) or PENDING_REPORT_FILENAME
    return get_config_dir() / name


def config_exists(path: str | os.PathLike[str] | None = None) -> bool:
    """配置文件是否存在（用于设置中心显示"首次使用"状态）。"""
    try:
        return (Path(path) if path else get_config_path()).is_file()
    except (OSError, ValueError):
        return False


# ---------------------------------------------------------------------------
# 时间 / JSON 基础工具
# ---------------------------------------------------------------------------


def _now_utc(now: datetime | float | int | None = None) -> datetime:
    """返回带时区的 UTC 时间；``now`` 可为 datetime / UNIX 时间戳（测试注入）。"""
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, datetime):
        return now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromtimestamp(float(now), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return datetime.now(timezone.utc)


def _parse_iso(value: Any) -> datetime | None:
    """容错解析 ISO8601 时间串；失败返回 ``None``（绝不抛异常）。"""
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        # 兼容 "2026-11-11 12:00:00" 这类空格分隔写法
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _clean_optional_str(value: Any, limit: int = 512) -> str | None:
    """把任意值归一为可选的去空白字符串（超长截断）。"""
    if value is None:
        return None
    text = " ".join(str(value).split())
    if not text:
        return None
    return text[:limit]


def _coerce_expire_days(value: Any) -> int | None:
    """把 ``expire_days`` 归一为 ``None``（永久）或正整数。

    ``0`` / 负数 / 非数字 -> ``None``（视为不启用自动失效，避免误伤）。
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        days = int(value)
    except (TypeError, ValueError):
        try:
            days = int(float(value))
        except (TypeError, ValueError):
            return None
    if days <= 0:
        return None
    return min(days, 3650)


def _deep_merge(base: Any, override: Any) -> Any:
    """递归合并：``override`` 覆盖 ``base``；保留 ``base`` 中的未知字段。"""
    if not isinstance(base, dict):
        return copy.deepcopy(override)
    result = copy.deepcopy(base)
    if not isinstance(override, dict):
        return result
    for key, value in override.items():
        existing = result.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            result[key] = _deep_merge(existing, value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def is_too_broad_prefix(prefix: Any) -> bool:
    """判断 target_prefix 是否"过宽"（整盘 / 整注册表根），过宽则拒绝信任。

    覆盖的绕过形态：

    - 字面根：``C:`` / ``C:\\`` / ``HKLM`` / ``HKCU`` / ``\\``；
    - 盘符相对路径：``C:...`` / ``C:..`` / ``C:foo``（Windows 会把它规范化为
      盘符根，若不拦截会放行整盘）；
    - 经 :func:`core.paths._norm_abs` 规范化后仍是盘符根的形式
      （如 ``C:/...`` / ``%SystemDrive%...``）；
    - ``.`` / ``..``。

    GUI 的 :func:`core.whitelist.build_trust_entry` 与用户配置写入
    :func:`add_trust_entry` 都复用本判断，保证"生成"和"存储"两侧一致。
    """
    text = normalize_path(prefix).strip()
    if not text:
        return True
    stripped = text.rstrip("\\/")
    if not stripped:
        return True
    if _DRIVE_RELATIVE_RE.match(stripped):
        return True
    if _DRIVE_ROOT_RE.match(stripped):
        return True
    if stripped.upper() in _HIVE_ROOTS:
        return True
    if stripped in (".", ".."):
        return True
    canonical = _norm_abs(stripped)
    if canonical and _CANONICAL_ROOT_RE.match(canonical):
        return True
    return False


def _write_json_atomic(payload: Any, target: Path, max_bytes: int | None = None) -> bool:
    """JSON 原子写入：同目录临时文件 + fsync + ``os.replace``。

    Args:
        payload: 可 JSON 序列化对象。
        target: 目标文件。
        max_bytes: 写入后文件大小上限；超限则放弃替换并返回 ``False``，避免
            "能保存但下次读取时因超限被忽略"的静默配置丢失。

    失败（权限不足 / 磁盘满 / 目标被占用 / 超限）返回 ``False``，绝不抛异常。
    """
    tmp_path: str | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
        )
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if max_bytes is not None and os.path.getsize(tmp_path) > max_bytes:
            raise ValueError(f"序列化后超过 {max_bytes} 字节上限")
        os.replace(tmp_path, target)
        return True
    except (OSError, TypeError, ValueError, OverflowError, RecursionError):
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return False


# ---------------------------------------------------------------------------
# 配置加载 / 保存
# ---------------------------------------------------------------------------


def _normalize_versions(value: Any) -> list[str]:
    """归一化"不再提示的版本号"列表：去 ``v`` 前缀、去重、限长。"""
    if not isinstance(value, (list, tuple)):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = str(item or "").strip()
        if not text:
            continue
        if text[:1] in ("v", "V"):
            text = text[1:].strip()
        if not text:
            continue
        token = text.casefold()
        if token in seen:
            continue
        seen.add(token)
        result.append(text)
        if len(result) >= MAX_IGNORED_VERSIONS:
            break
    return result


def normalize_trust_entry(
    entry: Any,
    now: datetime | float | int | None = None,
) -> dict[str, Any] | None:
    """归一化一条联合指纹信任项；结构非法时返回 ``None``。

    联合维度（三者共同限定，防止"黑客蹭目录"）：

    1. ``rule_id``：规则编号（大小写不敏感；``*`` 表示任意规则，兼容空规则）；
    2. ``signer_contains``：签名者子串（可为空 = 不限制签名者）；
    3. ``target_prefix``：目标前缀（**必填**，文件路径按目录包含，注册表/名称按
       分隔符边界前缀）。

    有效期：``expires_at`` 优先；否则 ``created_at + expire_days``。若声明了
    ``expire_days`` 却缺少可解析的 ``created_at``，按"立即失效"处理（fail closed，
    防止手写配置绕过有效期）。未声明 ``expire_days`` 的旧条目保持永久有效。
    """
    if not isinstance(entry, dict):
        return None
    rule_id = " ".join(str(entry.get("rule_id") or "").split()).upper() or "*"
    target_prefix = str(entry.get("target_prefix") or "").strip()
    if not target_prefix:
        # 兼容手写/早期格式：target 作为 target_prefix 的别名
        target_prefix = str(entry.get("target") or "").strip()
    if not target_prefix:
        return None
    signer = " ".join(str(entry.get("signer_contains") or "").split())[:256]
    expire_days = _coerce_expire_days(entry.get("expire_days"))

    created_at = _parse_iso(entry.get("created_at"))
    expires_at = _parse_iso(entry.get("expires_at"))
    current = _now_utc(now)
    if created_at is None:
        created_at = current
    if expires_at is None and expire_days is not None:
        raw_created = entry.get("created_at")
        if _parse_iso(raw_created) is not None:
            expires_at = created_at + timedelta(days=expire_days)
        else:
            # 无法证明创建时间：立即失效（fail closed）
            expires_at = current

    return {
        "rule_id": rule_id,
        "signer_contains": signer,
        "target_prefix": target_prefix[:1024],
        "created_at": _to_iso(created_at),
        "expires_at": _to_iso(expires_at),
        "expire_days": expire_days,
        "source": str(entry.get("source") or "").strip()[:64] or "unknown",
        "note": str(entry.get("note") or "").strip()[:512],
    }


def trust_entry_key(entry: Any) -> tuple[str, str, str]:
    """联合指纹去重键：``(rule_id, signer_contains, target_prefix)``，均大小写不敏感。"""
    if not isinstance(entry, dict):
        return ("", "", "")
    rule_id = " ".join(str(entry.get("rule_id") or "").split()).upper()
    signer = " ".join(str(entry.get("signer_contains") or "").split()).casefold()
    prefix = str(entry.get("target_prefix") or entry.get("target") or "").strip()
    prefix = prefix.rstrip("\\/").casefold()
    return (rule_id, signer, prefix)


def is_trust_entry_expired(
    entry: Any,
    now: datetime | float | int | None = None,
) -> bool:
    """联合指纹信任项是否已过期。

    - ``expires_at`` 可解析 -> 按它判断；
    - 否则 ``expire_days + created_at`` -> 按计算值判断；
    - 声明了 ``expire_days`` 但没有可解析的 ``created_at`` -> 失效（fail closed）；
    - 没有任何有效期信息 -> 不过期（兼容 V1.4 之前的无期限条目）。
    """
    if not isinstance(entry, dict):
        return True
    expires_at = _parse_iso(entry.get("expires_at"))
    if expires_at is None:
        expire_days = _coerce_expire_days(entry.get("expire_days"))
        if expire_days is None:
            return False
        created_at = _parse_iso(entry.get("created_at"))
        if created_at is None:
            return True
        expires_at = created_at + timedelta(days=expire_days)
    return _now_utc(now) >= expires_at


def _normalize_config(data: Any) -> dict[str, Any]:
    """默认值补齐 + 类型校验；未知字段原样保留（向前兼容）。"""
    source = data if isinstance(data, dict) else {}
    merged = _deep_merge(DEFAULT_CONFIG, source)

    schema = merged.get("schema_version")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema < 1:
        merged["schema_version"] = SCHEMA_VERSION

    update = merged.get("update")
    if not isinstance(update, dict):
        update = copy.deepcopy(DEFAULT_CONFIG["update"])
        merged["update"] = update
    if not isinstance(update.get("auto_check"), bool):
        update["auto_check"] = True
    update["ignored_versions"] = _normalize_versions(update.get("ignored_versions"))
    for key in (
        "ignored_current_version",
        "snooze_until",
        "last_check_at",
        "last_result",
        "last_latest_version",
        "release_api",
    ):
        update[key] = _clean_optional_str(update.get(key))

    trust = merged.get("trust")
    if not isinstance(trust, dict) or not isinstance(trust.get("entries"), list):
        trust = {"entries": []}
        merged["trust"] = trust
    normalized_entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in trust["entries"]:
        normalized = normalize_trust_entry(raw)
        if normalized is None:
            continue
        key = trust_entry_key(normalized)
        if key in seen:
            continue
        seen.add(key)
        normalized_entries.append(normalized)
    trust["entries"] = _prune_trust_entries(normalized_entries)

    reporting = merged.get("reporting")
    if not isinstance(reporting, dict):
        reporting = copy.deepcopy(DEFAULT_CONFIG["reporting"])
        merged["reporting"] = reporting
    # 严禁把暂存队列改名为 config.json / 非 .json / Windows 保留设备名，
    # 否则 append 会覆盖配置、clear 会删除配置。
    reporting["pending_file"] = (
        _safe_pending_filename(reporting.get("pending_file")) or PENDING_REPORT_FILENAME
    )
    reporting["endpoint"] = _clean_optional_str(reporting.get("endpoint"), 1024)

    ui = merged.get("ui")
    if not isinstance(ui, dict):
        ui = copy.deepcopy(DEFAULT_CONFIG["ui"])
        merged["ui"] = ui
    theme = str(ui.get("theme") or "light").strip().lower()
    ui["theme"] = theme if theme in THEMES else "light"

    return merged


def _prune_trust_entries(entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """去重 + 清理过期项 + 上限保护（仅在超过上限时优先清理过期/最旧项）。"""
    valid: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in entries:
        normalized = normalize_trust_entry(entry)
        if normalized is None:
            continue
        key = trust_entry_key(normalized)
        if key in seen:
            continue
        seen.add(key)
        valid.append(normalized)
    if len(valid) <= MAX_TRUST_ENTRIES:
        return valid
    active = [item for item in valid if not is_trust_entry_expired(item)]
    if len(active) > MAX_TRUST_ENTRIES:
        active = active[-MAX_TRUST_ENTRIES:]
    return active


def load_config(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """读取并归一化配置；任何读取/解析失败（含超深嵌套）都回退默认值，不抛异常。"""
    target = Path(path) if path else get_config_path()
    data: Any = None
    try:
        if target.is_file() and target.stat().st_size <= MAX_CONFIG_BYTES:
            # utf-8-sig：容忍记事本另存为带 BOM 的 UTF-8
            with open(target, "r", encoding="utf-8-sig", errors="ignore") as handle:
                data = json.load(handle)
    except (OSError, ValueError, TypeError, RecursionError):
        data = None
    try:
        return _normalize_config(data)
    except RecursionError:
        return _normalize_config(None)


def save_config(config: dict[str, Any], path: str | os.PathLike[str] | None = None) -> bool:
    """原子保存配置；返回是否成功（失败静默降级，不抛异常）。"""
    try:
        payload = _normalize_config(config)
    except RecursionError:
        return False
    except (TypeError, ValueError):
        return False
    target = Path(path) if path else get_config_path()
    with _LOCK:
        return _write_json_atomic(payload, target, max_bytes=MAX_CONFIG_BYTES)


def reset_config(path: str | os.PathLike[str] | None = None) -> bool:
    """把配置恢复为默认值（设置中心"恢复默认"预留）。"""
    return save_config(copy.deepcopy(DEFAULT_CONFIG), path)


def get_value(config: dict[str, Any] | None, key_path: str, default: Any = None) -> Any:
    """按点分隔路径读取配置值，如 ``get_value(cfg, "update.auto_check", True)``。"""
    if not isinstance(config, dict) or not key_path:
        return default
    current: Any = config
    for part in str(key_path).split("."):
        if not part:
            return default
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def set_value(
    key_path: str,
    value: Any,
    path: str | os.PathLike[str] | None = None,
) -> bool:
    """按点分隔路径写入配置并原子保存；返回是否成功。"""
    if not key_path:
        return False
    parts = [part for part in str(key_path).split(".") if part]
    if not parts:
        return False
    with _LOCK:
        config = load_config(path)
        current: dict[str, Any] = config
        for part in parts[:-1]:
            child = current.get(part)
            if not isinstance(child, dict):
                child = {}
                current[part] = child
            current = child
        current[parts[-1]] = value
        return save_config(config, path)


# ---------------------------------------------------------------------------
# 更新检查偏好（存储层；忽略/暂缓语义由 core.updater 负责）
# ---------------------------------------------------------------------------


def get_update_settings(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """返回 ``update`` 配置段的深拷贝（调用方可安全修改）。"""
    source = config if isinstance(config, dict) else load_config()
    update = source.get("update")
    return copy.deepcopy(update) if isinstance(update, dict) else copy.deepcopy(DEFAULT_CONFIG["update"])


def is_auto_check_enabled(config: dict[str, Any] | None = None) -> bool:
    """启动时是否自动检查更新（默认 True）。"""
    return bool(get_update_settings(config).get("auto_check", True))


def set_auto_check(enabled: Any, path: str | os.PathLike[str] | None = None) -> bool:
    """设置"启动时自动检查更新"。"""
    return set_value("update.auto_check", bool(enabled), path)


def get_theme(config: dict[str, Any] | None = None) -> str:
    """返回当前主题（``light`` / ``dark``）。"""
    source = config if isinstance(config, dict) else load_config()
    theme = str(get_value(source, "ui.theme", "light")).strip().lower()
    return theme if theme in THEMES else "light"


def set_theme(theme: Any, path: str | os.PathLike[str] | None = None) -> bool:
    """设置主题（非法值回退 light）。"""
    candidate = str(theme or "").strip().lower()
    return set_value("ui.theme", candidate if candidate in THEMES else "light", path)


# ---------------------------------------------------------------------------
# 本地信任名单（联合指纹）；core.whitelist 会合并这些条目
# ---------------------------------------------------------------------------


def load_trust_entries(
    config: dict[str, Any] | None = None,
    path: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """读取并归一化本地信任名单（联合指纹列表）。"""
    source = config if isinstance(config, dict) else load_config(path)
    trust = source.get("trust")
    raw_entries = trust.get("entries") if isinstance(trust, dict) else None
    if not isinstance(raw_entries, list):
        return []
    result: list[dict[str, Any]] = []
    for raw in raw_entries:
        normalized = normalize_trust_entry(raw)
        if normalized is not None:
            result.append(normalized)
    return result


def add_trust_entry(
    entry: Any,
    path: str | os.PathLike[str] | None = None,
    now: datetime | float | int | None = None,
) -> dict[str, Any] | None:
    """加入一条联合指纹信任项（同键则刷新有效期），保存成功返回归一化条目。

    联合指纹键为 ``(rule_id, signer_contains, target_prefix)``；重复点击"信任"
    不会产生重复条目，而是刷新 ``created_at`` / ``expires_at``。

    ``target_prefix`` 过宽（整盘 / 注册表根 / 盘符相对路径等，见
    :func:`is_too_broad_prefix`）时拒绝写入并返回 ``None``——与 GUI
    :func:`core.whitelist.build_trust_entry` 的校验保持一致。
    """
    normalized = normalize_trust_entry(entry, now=now)
    if normalized is None:
        return None
    if is_too_broad_prefix(normalized["target_prefix"]):
        return None
    with _LOCK:
        config = load_config(path)
        entries = config["trust"]["entries"]
        key = trust_entry_key(normalized)
        replaced = False
        for index, existing in enumerate(entries):
            existing_normalized = normalize_trust_entry(existing, now=now)
            if existing_normalized is not None and trust_entry_key(existing_normalized) == key:
                entries[index] = normalized
                replaced = True
                break
        if not replaced:
            entries.append(normalized)
        config["trust"]["entries"] = _prune_trust_entries(entries)
        if not save_config(config, path):
            return None
        return normalized


def remove_trust_entry(
    rule_id: Any,
    target_prefix: Any,
    signer_contains: Any = "",
    path: str | os.PathLike[str] | None = None,
) -> bool:
    """按联合指纹键删除一条信任项；成功（包括本来就不存在）返回 True。"""
    key = trust_entry_key(
        {
            "rule_id": rule_id,
            "signer_contains": signer_contains,
            "target_prefix": target_prefix,
        }
    )
    with _LOCK:
        config = load_config(path)
        entries = config["trust"]["entries"]
        remaining = [
            item
            for item in entries
            if trust_entry_key(item) != key and normalize_trust_entry(item) is not None
        ]
        if len(remaining) == len(entries):
            return True
        config["trust"]["entries"] = remaining
        return save_config(config, path)


def clear_trust_entries(path: str | os.PathLike[str] | None = None) -> bool:
    """清空本地信任名单；返回是否成功（本来为空/文件不存在也算成功）。"""
    with _LOCK:
        target = Path(path) if path else get_config_path()
        if not config_exists(target):
            return True
        config = load_config(target)
        if not config["trust"]["entries"]:
            return True
        config["trust"]["entries"] = []
        return save_config(config, target)


# ---------------------------------------------------------------------------
# 暂存匿名上报队列（弱网时本地落盘，恢复网络后再上报 / 导出）
# ---------------------------------------------------------------------------


def _load_pending_payload(report_path: Path) -> list[dict[str, Any]]:
    data: Any = None
    try:
        if report_path.is_file() and report_path.stat().st_size <= MAX_PENDING_BYTES:
            with open(report_path, "r", encoding="utf-8-sig", errors="ignore") as handle:
                data = json.load(handle)
    except (OSError, ValueError, TypeError, RecursionError):
        return []
    if isinstance(data, dict):
        data = data.get("reports")
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _pending_file(path: str | os.PathLike[str] | None) -> Path:
    """解析暂存上报文件路径：显式 path 优先；否则读取 config.reporting.pending_file。"""
    if path:
        return Path(path)
    try:
        return get_pending_report_path(load_config())
    except Exception:  # noqa: BLE001 - 配置读取异常回退默认文件名
        return get_pending_report_path()


def append_pending_report(
    report: Any,
    path: str | os.PathLike[str] | None = None,
) -> bool:
    """把一条匿名上报追加到本地暂存队列（弱网降级），返回是否写入成功。"""
    if not isinstance(report, dict):
        return False
    target = _pending_file(path)
    with _LOCK:
        reports = _load_pending_payload(target)
        try:
            reports.append(copy.deepcopy(report))
        except (TypeError, ValueError, RecursionError):
            return False
        if len(reports) > MAX_PENDING_REPORTS:
            reports = reports[-MAX_PENDING_REPORTS:]
        return _write_json_atomic(reports, target, max_bytes=MAX_PENDING_BYTES)


def load_pending_reports(path: str | os.PathLike[str] | None = None) -> list[dict[str, Any]]:
    """读取暂存上报队列（损坏 / 缺失返回空列表）。"""
    return _load_pending_payload(_pending_file(path))


def pending_report_count(path: str | os.PathLike[str] | None = None) -> int:
    """暂存上报条数。"""
    return len(load_pending_reports(path))


def clear_pending_reports(path: str | os.PathLike[str] | None = None) -> bool:
    """清空暂存上报队列（删除文件）；返回是否成功。"""
    with _LOCK:
        target = _pending_file(path)
        try:
            if target.exists():
                target.unlink()
            return True
        except OSError:
            return False


def export_pending_reports(
    destination: str | os.PathLike[str],
    path: str | os.PathLike[str] | None = None,
) -> str | None:
    """导出暂存上报队列为 JSON 文件。

    ``destination`` 为目录时自动生成文件名；否则视为文件路径。队列为空或写入
    失败返回 ``None``（GUI 提示"暂无暂存报告 / 导出失败"），不抛异常。
    """
    reports = load_pending_reports(path)
    if not reports:
        return None
    try:
        target = Path(destination)
        if target.is_dir():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            target = target / f"pending_report_export_{stamp}.json"
        payload = {
            "tool": "TamperScan",
            "exported_at": _to_iso(datetime.now(timezone.utc)),
            "count": len(reports),
            "reports": reports,
        }
        if not _write_json_atomic(payload, target):
            return None
        return str(target)
    except (OSError, ValueError):
        return None


def pending_export_path(directory: str | os.PathLike[str]) -> Path:
    """生成导出文件路径（供 GUI 文件对话框预填；不写文件）。"""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(directory) / f"pending_report_export_{stamp}.json"


def touch_timestamp() -> str:
    """当前 UTC 时间的 ISO 字符串（GUI / 测试展示用）。"""
    return _to_iso(_now_utc()) or ""


def now_iso(now: Any = None) -> str:
    """返回 ISO8601 UTC 时间串；``now`` 可注入固定时间（测试 / 指纹生成共用）。"""
    return _to_iso(_now_utc(now)) or ""


__all__ = [
    "APP_DIR_NAME",
    "CONFIG_FILENAME",
    "DEFAULT_CONFIG",
    "DEFAULT_TRUST_EXPIRE_DAYS",
    "ENV_CONFIG_DIR",
    "MAX_CONFIG_BYTES",
    "MAX_PENDING_BYTES",
    "MAX_PENDING_REPORTS",
    "MAX_TRUST_ENTRIES",
    "PENDING_REPORT_FILENAME",
    "SCHEMA_VERSION",
    "THEMES",
    "add_trust_entry",
    "append_pending_report",
    "clear_pending_reports",
    "clear_trust_entries",
    "config_exists",
    "export_pending_reports",
    "get_config_dir",
    "get_config_path",
    "get_pending_report_path",
    "get_theme",
    "get_update_settings",
    "get_value",
    "is_auto_check_enabled",
    "is_too_broad_prefix",
    "is_trust_entry_expired",
    "load_config",
    "load_pending_reports",
    "load_trust_entries",
    "normalize_trust_entry",
    "now_iso",
    "pending_export_path",
    "pending_report_count",
    "remove_trust_entry",
    "reset_config",
    "save_config",
    "set_auto_check",
    "set_theme",
    "set_value",
    "touch_timestamp",
    "trust_entry_key",
]
