# -*- coding: utf-8 -*-
"""浏览器扩展深度检测（阶段 5）。

定位 Chrome / Edge 各 Profile 的 ``Preferences``（含 ``Secure Preferences``）与
``Extensions`` 目录，读取每个扩展的 ``manifest.json``，做三件事：

1. **权限加权评分**（参数完全外置到 ``rules/extension_weights.json``）：
   ``score = Σ(required 权限权重) + Σ(optional 权限权重 × 0.5) + Σ(命中攻击链 bonus)``；
   ≥60 HIGH、40–59 MEDIUM、>0 LOW；``severity_floors`` 允许"单权限即高危"（debugger → HIGH）。
   MV2 的 host 权限在 ``permissions`` 里、MV3 在 ``host_permissions`` 里，两处都解析。

2. **签名/完整性一致性**：
   - 有 ``.crx``：解析 CRX3 头，取 ``signedcrx_id`` 与 manifest ``key`` 推导的 ID 交叉校验；
   - 无 ``.crx``（Store 安装常态）：降级为检查 ``_metadata/verified_contents.json``
     （可能是 gzip 压缩）里 ``item_id`` 与扩展目录名、``item_version`` 与 manifest 版本的一致性。
     **不把 verified_contents.json 当签名来源。**

3. **更新劫持的静态替代信号**：manifest 版本与 verified_contents 的 ``item_version``
   不一致（非开发者模式）→ MEDIUM ``EXT_VERSION_MISMATCH``；当前权限全集写入 evidence，
   供阶段 7/后续版本做权限扩张 diff。

其他约定：
- **不重复扫策略键**：``ExtensionInstallForcelist`` 已由 ``registry_policy`` 负责；这里只把
  扩展是否被策略强制安装标注到 ``evidence.force_installed``，不单独产出 Finding；
- 开发者模式（``location`` 为 UNPACKED/COMMAND_LINE）→ INFO ``EXT_UNPACKED``，不判 HIGH；
- 扩展白名单只按 **扩展 ID 精确匹配**（见 ``utils.match_whitelist``）。
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
import winreg
from typing import Any, Iterator

from core import utils
from core.finding import SEVERITY_ORDER, make_finding
from core.utils import truncate

CATEGORY = "BrowserExtension"

# 内置默认权重（rules/extension_weights.json 缺失/损坏时兜底）
DEFAULT_WEIGHTS: dict[str, Any] = {
    "permission_weights": {
        "debugger": 35,
        "nativeMessaging": 35,
        "userScripts": 25,
        "cookies": 20,
        "scripting": 20,
        "webRequestBlocking": 20,
        "proxy": 20,
    },
    "optional_weight_multiplier": 0.5,
    "attack_chain_bonuses": [
        {
            "id": "session_theft",
            "requires_all": ["cookies", "tabs", "storage"],
            "bonus": 20,
            "description": "会话令牌窃取组合（cookies+tabs+storage）",
        },
        {
            "id": "script_injection_broad",
            "requires_all": ["scripting"],
            "host_permissions_any": ["<all_urls>", "*://*/*"],
            "bonus": 25,
            "description": "全站脚本注入（scripting + 全站主机权限）",
        },
    ],
    "severity_floors": {"debugger": "HIGH"},
    "score_thresholds": {"high": 60, "medium": 40, "low": 1},
}

_LOCATION_NAMES = {
    0: "INVALID",
    1: "INTERNAL",
    2: "EXTERNAL_PREF",
    3: "EXTERNAL_REGISTRY",
    4: "UNPACKED",
    5: "EXTERNAL_PREF_DOWNLOAD",
    6: "EXTERNAL_POLICY_DOWNLOAD",
    7: "COMMAND_LINE",
    8: "EXTERNAL_POLICY",
    9: "EXTERNAL_COMPONENT",
}

_EXTENSION_ID_RE = re.compile(r"[a-p]{32}")


# ---------------------------------------------------------------------------
# 权重配置
# ---------------------------------------------------------------------------


def _load_weights() -> dict[str, Any]:
    """从 rules/extension_weights.json 加载评分参数（缺失/损坏时用内置默认值）。"""
    defaults = json.loads(json.dumps(DEFAULT_WEIGHTS))  # deep copy
    data = utils.load_json(utils.RULES_DIR / "extension_weights.json", default=None)
    if not isinstance(data, dict):
        return defaults
    weights = defaults

    raw_perm = data.get("permission_weights")
    if isinstance(raw_perm, dict):
        for key, value in raw_perm.items():
            try:
                weights["permission_weights"][str(key)] = float(value)
            except (TypeError, ValueError):
                continue
    try:
        weights["optional_weight_multiplier"] = float(data.get("optional_weight_multiplier", 0.5))
    except (TypeError, ValueError):
        pass
    raw_chains = data.get("attack_chain_bonuses")
    if isinstance(raw_chains, list):
        weights["attack_chain_bonuses"] = [item for item in raw_chains if isinstance(item, dict)]
    raw_floors = data.get("severity_floors")
    if isinstance(raw_floors, dict):
        weights["severity_floors"] = {
            str(key): str(value).upper() for key, value in raw_floors.items() if str(value).upper() in SEVERITY_ORDER
        }
    raw_thresholds = data.get("score_thresholds")
    if isinstance(raw_thresholds, dict):
        for key in ("high", "medium", "low"):
            try:
                weights["score_thresholds"][key] = int(raw_thresholds.get(key, weights["score_thresholds"][key]))
            except (TypeError, ValueError):
                continue
    return weights


# ---------------------------------------------------------------------------
# 浏览器 / Profile 发现
# ---------------------------------------------------------------------------


def _browser_user_data_dirs() -> list[tuple[str, str]]:
    """返回 ``[(browser, User Data 目录)]``（Chrome / Edge）。"""
    local_appdata = os.environ.get("LOCALAPPDATA") or ""
    if not local_appdata:
        return []
    return [
        ("Chrome", os.path.join(local_appdata, r"Google\Chrome\User Data")),
        ("Edge", os.path.join(local_appdata, r"Microsoft\Edge\User Data")),
    ]


def _iter_profiles() -> Iterator[tuple[str, str]]:
    """枚举两个浏览器的 Default / Profile N 目录。"""
    for browser, user_data in _browser_user_data_dirs():
        if not os.path.isdir(user_data):
            continue
        try:
            names = sorted(os.listdir(user_data))
        except OSError:
            continue
        for name in names:
            if name != "Default" and not name.startswith("Profile "):
                continue
            profile_dir = os.path.join(user_data, name)
            if not os.path.isdir(profile_dir):
                continue
            if os.path.isfile(os.path.join(profile_dir, "Preferences")) or os.path.isdir(
                os.path.join(profile_dir, "Extensions")
            ):
                yield browser, profile_dir


def _load_profile_settings(profile_dir: str) -> dict[str, dict[str, Any]]:
    """合并 ``Preferences`` 与 ``Secure Preferences`` 的 ``extensions.settings``。"""
    settings: dict[str, dict[str, Any]] = {}
    for filename in ("Preferences", "Secure Preferences"):
        data = utils.load_json(os.path.join(profile_dir, filename), default=None)
        if not isinstance(data, dict):
            continue
        extensions = data.get("extensions")
        if not isinstance(extensions, dict):
            continue
        ext_settings = extensions.get("settings")
        if not isinstance(ext_settings, dict):
            continue
        for extension_id, pref in ext_settings.items():
            if not isinstance(pref, dict):
                continue
            merged = dict(settings.get(extension_id) or {})
            merged.update(pref)
            merged["_source_file"] = filename
            settings[str(extension_id)] = merged
    return settings


def _version_sort_key(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.split(r"[^0-9]+", str(text)) if part)


def _resolve_extension_dir(profile_dir: str, extension_id: str, pref: dict[str, Any]) -> str:
    """优先级：Preferences 里的 path → profile\\Extensions\\<id>\\<最高版本>。"""
    path = pref.get("path")
    if isinstance(path, str) and path.strip():
        candidates: list[str] = []
        if os.path.isabs(path):
            candidates.append(path)
        else:
            candidates.append(os.path.join(profile_dir, path))
            candidates.append(os.path.join(profile_dir, "Extensions", path))
        for candidate in candidates:
            if os.path.isdir(candidate):
                return candidate
    base = os.path.join(profile_dir, "Extensions", extension_id)
    if os.path.isdir(base):
        try:
            versions = [name for name in os.listdir(base) if os.path.isdir(os.path.join(base, name))]
        except OSError:
            versions = []
        versions.sort(key=_version_sort_key, reverse=True)
        if versions:
            return os.path.join(base, versions[0])
    return ""


def _read_manifest(extension_dir: str) -> dict[str, Any]:
    if not extension_dir:
        return {}
    data = utils.load_json(os.path.join(extension_dir, "manifest.json"), default=None)
    return data if isinstance(data, dict) else {}


def _resolve_message(manifest: dict[str, Any], extension_dir: str, placeholder: str) -> str | None:
    """解析 manifest 中的 __MSG_xxx__ 占位符（读 _locales/<locale>/messages.json）。"""
    key = placeholder[6:-2]
    base = os.path.join(extension_dir, "_locales")
    locales: list[str] = []
    for locale in [manifest.get("default_locale") or "en", "en", "en_US", "en_GB"]:
        if locale and locale not in locales:
            locales.append(locale)
    if os.path.isdir(base):
        try:
            for locale in os.listdir(base):
                if locale not in locales:
                    locales.append(locale)
        except OSError:
            pass
    for locale in locales:
        messages = utils.load_json(os.path.join(base, locale, "messages.json"), default=None)
        if not isinstance(messages, dict):
            continue
        entry = messages.get(key) or messages.get(key.lower()) or messages.get(key.upper())
        if isinstance(entry, dict) and entry.get("message"):
            return str(entry["message"])
    return None


def _resolve_extension_name(manifest: dict[str, Any], extension_dir: str) -> str:
    raw = str(manifest.get("name") or "").strip()
    if raw.startswith("__MSG_") and raw.endswith("__") and len(raw) > 8 and extension_dir:
        resolved = _resolve_message(manifest, extension_dir, raw)
        if resolved:
            return resolved
    return raw


def _format_score(value: Any) -> int | float:
    number = float(value or 0)
    return int(number) if number.is_integer() else round(number, 1)


def _location_name(value: Any) -> str:
    if isinstance(value, str):
        return value.upper()
    try:
        return _LOCATION_NAMES.get(int(value), f"LOCATION_{int(value)}")
    except (TypeError, ValueError):
        return str(value)


def _is_unpacked(location_name: str, extension_dir: str, profile_dir: str) -> bool:
    """判断是否为开发者模式加载；EXTERNAL_* 属外部打包安装，不算解压加载。"""
    if location_name in ("UNPACKED", "COMMAND_LINE"):
        return True
    if location_name in ("INTERNAL", "EXTERNAL_PREF", "EXTERNAL_REGISTRY", "EXTERNAL_POLICY", "EXTERNAL_COMPONENT"):
        return False
    if location_name.startswith("EXTERNAL"):
        return False
    extensions_root = os.path.normcase(os.path.join(profile_dir, "Extensions"))
    if extension_dir and not os.path.normcase(extension_dir).startswith(extensions_root):
        return True
    return False


# ---------------------------------------------------------------------------
# 权限解析与评分（纯函数，便于单元测试）
# ---------------------------------------------------------------------------


def _is_host_permission(value: str) -> bool:
    text = str(value or "").strip().lower()
    return text == "<all_urls>" or "://" in text or text.startswith("*")


def _split_permissions(manifest: dict[str, Any]) -> tuple[list[str], list[str], list[str], list[str]]:
    """拆分为 (API 权限, 主机权限, 可选 API 权限, 可选主机权限)。"""
    api: list[str] = []
    hosts: list[str] = []
    for item in manifest.get("permissions") or []:
        text = str(item).strip()
        if not text:
            continue
        (hosts if _is_host_permission(text) else api).append(text)
    for item in manifest.get("host_permissions") or []:
        text = str(item).strip()
        if text:
            hosts.append(text)

    optional_api: list[str] = []
    optional_hosts: list[str] = []
    for item in manifest.get("optional_permissions") or []:
        text = str(item).strip()
        if not text:
            continue
        (optional_hosts if _is_host_permission(text) else optional_api).append(text)
    for item in manifest.get("optional_host_permissions") or []:
        text = str(item).strip()
        if text:
            optional_hosts.append(text)
    return api, hosts, optional_api, optional_hosts


def _score_extension(manifest: dict[str, Any], weights: dict[str, Any]) -> dict[str, Any]:
    """权限加权评分（纯函数）。"""
    api, hosts, optional_api, optional_hosts = _split_permissions(manifest)
    weight_map = {str(key).lower(): float(value) for key, value in weights["permission_weights"].items()}
    multiplier = float(weights.get("optional_weight_multiplier", 0.5))

    required = [
        {"name": name, "weight": weight_map.get(name.lower(), 0.0), "kind": "required"} for name in api
    ]
    optional = [
        {
            "name": name,
            "base_weight": weight_map.get(name.lower(), 0.0),
            "weight": round(weight_map.get(name.lower(), 0.0) * multiplier, 1),
            "kind": "optional",
        }
        for name in optional_api
    ]
    base_score = sum(item["weight"] for item in required) + sum(item["weight"] for item in optional)

    declared = {name.lower() for name in api}
    declared_hosts = {host.lower() for host in hosts}
    chains: list[dict[str, Any]] = []
    for chain in weights.get("attack_chain_bonuses") or []:
        requires = {str(item).lower() for item in chain.get("requires_all") or []}
        if not requires or not requires.issubset(declared):
            continue
        host_any = chain.get("host_permissions_any")
        if host_any:
            wanted = {str(item).lower() for item in host_any}
            if not (declared_hosts & wanted or "<all_urls>" in declared_hosts):
                continue
        chains.append(
            {
                "id": chain.get("id"),
                "bonus": int(chain.get("bonus") or 0),
                "description": chain.get("description"),
            }
        )
    score = base_score + sum(item["bonus"] for item in chains)

    floors = {str(key).lower(): str(value).upper() for key, value in (weights.get("severity_floors") or {}).items()}
    floor: str | None = None
    for permission, severity in floors.items():
        if permission in declared and severity in SEVERITY_ORDER:
            if floor is None or SEVERITY_ORDER[severity] < SEVERITY_ORDER[floor]:
                floor = severity

    thresholds = weights.get("score_thresholds") or {"high": 60, "medium": 40, "low": 1}
    severity: str | None = floor
    if severity is None:
        if score >= thresholds.get("high", 60):
            severity = "HIGH"
        elif score >= thresholds.get("medium", 40):
            severity = "MEDIUM"
        elif score >= thresholds.get("low", 1):
            severity = "LOW"
    return {
        "score": score,
        "base_score": base_score,
        "required_permissions": required,
        "optional_permissions": optional,
        "host_permissions": hosts,
        "optional_host_permissions": optional_hosts,
        "attack_chains": chains,
        "severity": severity,
        "severity_floor": floor,
        "thresholds": thresholds,
    }


# ---------------------------------------------------------------------------
# verified_contents.json（可能 gzip 压缩）
# ---------------------------------------------------------------------------


def _read_verified_contents(path: str) -> dict[str, Any] | None:
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        return None
    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
        except OSError:
            return None
    try:
        obj = json.loads(raw.decode("utf-8", "ignore"))
    except ValueError:
        return None
    if isinstance(obj, list):
        entries = [item for item in obj if isinstance(item, dict)]
        obj = entries[0] if entries else None
    if not isinstance(obj, dict):
        return None
    result: dict[str, Any] = {
        "item_id": obj.get("item_id"),
        "item_version": obj.get("item_version"),
        "has_signature": bool((obj.get("signed_content") or {}).get("signatures"))
        if isinstance(obj.get("signed_content"), dict)
        else False,
        "content_hash_count": len(obj.get("content_hashes") or []),
    }
    signed = obj.get("signed_content")
    payload = signed.get("payload") if isinstance(signed, dict) else None
    if isinstance(payload, str) and payload:
        try:
            padded = payload + "=" * (-len(payload) % 4)
            payload_obj = json.loads(base64.b64decode(padded).decode("utf-8", "ignore"))
            if isinstance(payload_obj, dict):
                result["item_id"] = result["item_id"] or payload_obj.get("item_id")
                result["item_version"] = result["item_version"] or payload_obj.get("item_version")
        except (ValueError, TypeError):
            pass
    return result


# ---------------------------------------------------------------------------
# CRX3 解析
# ---------------------------------------------------------------------------

_CRX_MAGIC = b"Cr24"


def _read_varint(data: bytes, index: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while index < len(data) and shift <= 63:
        byte = data[index]
        index += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, index
        shift += 7
    raise ValueError("bad varint")


def _iter_protobuf(data: bytes) -> Iterator[tuple[int, Any]]:
    """极简 protobuf wire-format 解析（只取我们需要的字段）。"""
    index = 0
    while index < len(data):
        key, index = _read_varint(data, index)
        field_number, wire_type = key >> 3, key & 7
        if wire_type == 0:
            value, index = _read_varint(data, index)
            yield field_number, value
        elif wire_type == 2:
            length, index = _read_varint(data, index)
            if index + length > len(data):
                raise ValueError("truncated")
            value = data[index : index + length]
            index += length
            yield field_number, value
        elif wire_type == 1:
            index += 8
        elif wire_type == 5:
            index += 4
        else:
            raise ValueError(f"unsupported wire type {wire_type}")


def _parse_crx3(path: str) -> dict[str, Any] | None:
    """解析 CRX3 头，返回 ``{version, crx_id, public_keys}``；CRX2/非法文件返回 None。"""
    try:
        with open(path, "rb") as handle:
            head = handle.read(12)
            if len(head) < 12 or head[:4] != _CRX_MAGIC:
                return None
            version = int.from_bytes(head[4:8], "little")
            if version != 3:
                return {"version": version, "crx_id": None, "public_keys": []}
            header_size = int.from_bytes(head[8:12], "little")
            if header_size <= 0 or header_size > 8 * 1024 * 1024:
                return None
            header = handle.read(header_size)
    except OSError:
        return None
    if len(header) != header_size:
        return None

    crx_id: bytes | None = None
    public_keys: list[bytes] = []
    try:
        for field_number, value in _iter_protobuf(header):
            if field_number == 10000 and isinstance(value, (bytes, bytearray)):
                for nested_field, nested_value in _iter_protobuf(bytes(value)):
                    if nested_field == 1 and isinstance(nested_value, (bytes, bytearray)):
                        crx_id = bytes(nested_value)
            elif field_number == 2 and isinstance(value, (bytes, bytearray)):
                for nested_field, nested_value in _iter_protobuf(bytes(value)):
                    if nested_field == 1 and isinstance(nested_value, (bytes, bytearray)):
                        public_keys.append(bytes(nested_value))
    except (ValueError, TypeError):
        return None
    return {"version": 3, "crx_id": crx_id, "public_keys": public_keys}


def _extension_id_from_bytes(data: bytes | None) -> str | None:
    """16 字节公钥哈希 → Chrome 扩展 ID（a-p 字母表）。"""
    if not data:
        return None
    raw = bytes(data)[:16]
    if len(raw) < 16:
        return None
    return "".join(
        chr(ord("a") + (byte >> 4)) + chr(ord("a") + (byte & 0x0F)) for byte in raw
    )


def _extension_id_from_public_key(der: bytes | None) -> str | None:
    if not der:
        return None
    return _extension_id_from_bytes(hashlib.sha256(der).digest()[:16])


def _extension_id_from_manifest_key(key_b64: str | None) -> str | None:
    if not key_b64:
        return None
    try:
        padded = str(key_b64).strip() + "=" * (-len(str(key_b64).strip()) % 4)
        der = base64.b64decode(padded)
    except (ValueError, TypeError):
        return None
    return _extension_id_from_public_key(der)


def _find_crx_files(extension_dir: str) -> list[str]:
    candidates: list[str] = []
    for directory in (extension_dir, os.path.dirname(extension_dir.rstrip("\\/"))):
        if not directory or not os.path.isdir(directory):
            continue
        try:
            entries = os.listdir(directory)
        except OSError:
            continue
        for name in entries:
            if name.lower().endswith(".crx"):
                candidates.append(os.path.join(directory, name))
    return candidates


# ---------------------------------------------------------------------------
# 策略强制安装的交叉引用（不产出 Finding）
# ---------------------------------------------------------------------------

_POLICY_KEYS = (
    r"SOFTWARE\Policies\Google\Chrome",
    r"SOFTWARE\Policies\Microsoft\Edge",
)


def _extract_force_installed_ids(values: list[str]) -> set[str]:
    """从 ExtensionInstallForcelist 的值（形如 ``<id>;<update_url>``）提取扩展 ID。"""
    ids: set[str] = set()
    for value in values:
        token = str(value or "").split(";", 1)[0].strip().lower()
        if _EXTENSION_ID_RE.fullmatch(token):
            ids.add(token)
    return ids


def _read_force_installed_ids() -> set[str]:
    """读取 Chrome/Edge 的 ExtensionInstallForcelist（只用于 evidence 标注）。"""
    values: list[str] = []
    for hive, hive_name in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
        views = ((winreg.KEY_WOW64_64KEY, 64), (winreg.KEY_WOW64_32KEY, 32)) if hive == winreg.HKEY_LOCAL_MACHINE else ((0, 0),)
        for subkey in _POLICY_KEYS:
            for view_flag, _view_name in views:
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as key:
                        count = winreg.QueryInfoKey(key)[1]
                        for index in range(count):
                            try:
                                _name, data, _type = winreg.EnumValue(key, index)
                            except OSError:
                                continue
                            if isinstance(data, str):
                                values.append(data)
                except (FileNotFoundError, OSError):
                    continue
    return _extract_force_installed_ids(values)


# ---------------------------------------------------------------------------
# 单个扩展判定
# ---------------------------------------------------------------------------


def _extension_target(browser: str, profile_dir: str, extension_id: str) -> str:
    return f"{browser}/{os.path.basename(profile_dir)}/{extension_id}"


def _analyze_extension(
    browser: str,
    profile_dir: str,
    extension_id: str,
    pref: dict[str, Any],
    weights: dict[str, Any],
    force_installed_ids: set[str],
) -> list[dict[str, Any]]:
    """对单个扩展做完整判定（纯函数，便于单元测试）。"""
    location_name = _location_name(pref.get("location"))
    if location_name in ("EXTERNAL_COMPONENT", "COMPONENT"):
        return []  # 浏览器自带组件扩展，跳过
    extension_dir = _resolve_extension_dir(profile_dir, extension_id, pref)
    manifest = _read_manifest(extension_dir)
    extension_name = _resolve_extension_name(manifest, extension_dir) or str(pref.get("name") or "").strip()
    version = str(manifest.get("version") or pref.get("version") or "").strip()
    unpacked = _is_unpacked(location_name, extension_dir, profile_dir)
    score_info = _score_extension(manifest, weights)
    target = _extension_target(browser, profile_dir, extension_id)

    evidence: dict[str, Any] = {
        "extension_id": extension_id.lower(),
        "extension_name": extension_name,
        "extension_name_raw": manifest.get("name"),
        "version": version,
        "browser": browser,
        "profile": os.path.basename(profile_dir),
        "location": location_name,
        "unpacked": unpacked,
        "extension_dir": extension_dir,
        "preferences_source": pref.get("_source_file"),
        "from_webstore": pref.get("from_webstore"),
        "force_installed": extension_id.lower() in force_installed_ids,
        "permissions": score_info["required_permissions"],
        "optional_permissions": score_info["optional_permissions"],
        "host_permissions": score_info["host_permissions"],
        "optional_host_permissions": score_info["optional_host_permissions"],
        "attack_chains": score_info["attack_chains"],
        "score": _format_score(score_info["score"]),
        "score_base": _format_score(score_info["base_score"]),
        "thresholds": score_info["thresholds"],
        "severity_floor": score_info["severity_floor"],
    }

    findings: list[dict[str, Any]] = []

    if not extension_dir and location_name == "INTERNAL":
        findings.append(
            make_finding(
                "INFO",
                CATEGORY,
                target,
                f"Preferences 记录了扩展 {extension_id}，但扩展目录不存在（可能为卸载残留或加载失败）",
                {
                    "extension_id": extension_id.lower(),
                    "browser": browser,
                    "profile": os.path.basename(profile_dir),
                    "location": location_name,
                    "preferences_source": pref.get("_source_file"),
                },
                "EXT_INCONSISTENT",
            )
        )
        return findings

    # 1) 完整性：CRX3 与 verified_contents
    if extension_dir:
        verified_path = os.path.join(extension_dir, "_metadata", "verified_contents.json")
        verified = _read_verified_contents(verified_path) if os.path.isfile(verified_path) else None
        if verified:
            evidence["verified_contents"] = {
                "path": verified_path,
                "item_id": verified.get("item_id"),
                "item_version": verified.get("item_version"),
                "has_signature": verified.get("has_signature"),
                "content_hash_count": verified.get("content_hash_count"),
            }
        crx_info = None
        for crx_path in _find_crx_files(extension_dir):
            parsed = _parse_crx3(crx_path)
            if parsed and parsed.get("version") == 3:
                crx_info = parsed
                crx_info["path"] = crx_path
                break
        mismatches: dict[str, Any] = {}
        if crx_info:
            evidence["crx"] = {"path": crx_info["path"], "crx_id": None}
            crx_id = _extension_id_from_bytes(crx_info.get("crx_id"))
            evidence["crx"]["crx_id"] = crx_id
            directory_id = extension_id.lower()
            if crx_id and crx_id != directory_id:
                mismatches["crx_id_vs_directory"] = {"crx_id": crx_id, "directory": directory_id}
            manifest_key_id = _extension_id_from_manifest_key(manifest.get("key"))
            if manifest_key_id:
                evidence["crx"]["manifest_key_id"] = manifest_key_id
                if crx_id and manifest_key_id != crx_id:
                    mismatches["manifest_key_vs_crx"] = {
                        "manifest_key_id": manifest_key_id,
                        "crx_id": crx_id,
                    }
            if not manifest_key_id and crx_info.get("public_keys"):
                crx_key_id = _extension_id_from_public_key(crx_info["public_keys"][0])
                evidence["crx"]["crx_public_key_id"] = crx_key_id
                if crx_id and crx_key_id and crx_key_id != crx_id:
                    mismatches["crx_public_key_vs_crx_id"] = {
                        "crx_public_key_id": crx_key_id,
                        "crx_id": crx_id,
                    }
        if verified:
            item_id = str(verified.get("item_id") or "").strip().lower()
            item_version = str(verified.get("item_version") or "").strip()
            if item_id and item_id != extension_id.lower():
                mismatches["verified_contents_item_id"] = {
                    "item_id": item_id,
                    "directory": extension_id.lower(),
                }
            if item_version and version and item_version != version and not unpacked:
                findings.append(
                    make_finding(
                        "MEDIUM",
                        CATEGORY,
                        target,
                        f"扩展 {extension_name or extension_id} 的 manifest 版本 {version} 与 Web Store 记录版本 {item_version} 不一致（更新劫持静态信号）",
                        {
                            **evidence,
                            "manifest_version": version,
                            "verified_item_version": item_version,
                        },
                        "EXT_VERSION_MISMATCH",
                    )
                )
        if mismatches:
            findings.append(
                make_finding(
                    "HIGH",
                    CATEGORY,
                    target,
                    f"扩展 {extension_name or extension_id} 的签名/完整性记录与扩展目录不一致",
                    {**evidence, "mismatches": mismatches},
                    "EXT_CRX_MISMATCH",
                )
            )

    # 2) 开发者模式加载
    if unpacked:
        findings.append(
            make_finding(
                "INFO",
                CATEGORY,
                target,
                f"扩展 {extension_name or extension_id} 为开发者模式加载（无 Web Store 签名，请确认来源可信）",
                dict(evidence),
                "EXT_UNPACKED",
            )
        )

    # 3) 权限评分
    severity = score_info["severity"]
    if severity:
        rule_id = {"HIGH": "EXT_PERM_HIGH", "MEDIUM": "EXT_PERM_MED"}.get(severity, "EXT_PERM_LOW")
        chain_text = (
            "；命中攻击链：" + "、".join(f"{item['id']}(+{item['bonus']})" for item in score_info["attack_chains"])
            if score_info["attack_chains"]
            else ""
        )
        findings.append(
            make_finding(
                severity,
                CATEGORY,
                target,
                f"扩展 {extension_name or extension_id} 权限风险评分 {_format_score(score_info['score'])}"
                f"（HIGH≥{score_info['thresholds'].get('high')}，MEDIUM≥{score_info['thresholds'].get('medium')}）{chain_text}",
                {**evidence, "score_details": score_info},
                rule_id,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# 模块入口
# ---------------------------------------------------------------------------


def scan() -> list[dict[str, Any]]:
    """扫描 Chrome/Edge 全部 Profile 的扩展，返回 ``list[Finding]``。"""
    weights = _load_weights()
    force_installed_ids = _read_force_installed_ids()
    findings: list[dict[str, Any]] = []

    for browser, profile_dir in _iter_profiles():
        try:
            settings = _load_profile_settings(profile_dir)
        except OSError:
            continue
        for extension_id, pref in settings.items():
            if not extension_id:
                continue
            try:
                findings.extend(
                    _analyze_extension(browser, profile_dir, extension_id, pref, weights, force_installed_ids)
                )
            except Exception:  # noqa: BLE001 - 单个扩展异常不中断整体扫描
                continue

        # Preferences 里没有但 Extensions 目录存在的扩展（残留/手工放置）
        extensions_dir = os.path.join(profile_dir, "Extensions")
        if os.path.isdir(extensions_dir):
            try:
                entries = os.listdir(extensions_dir)
            except OSError:
                entries = []
            for name in entries:
                if name.lower() in {key.lower() for key in settings}:
                    continue
                if not _EXTENSION_ID_RE.fullmatch(name.lower()):
                    continue
                if not os.path.isdir(os.path.join(extensions_dir, name)):
                    continue
                findings.append(
                    make_finding(
                        "INFO",
                        CATEGORY,
                        _extension_target(browser, profile_dir, name),
                        f"Extensions 目录存在扩展 {name}，但 Preferences 未记录（可能为卸载残留或手工放置）",
                        {
                            "extension_id": name.lower(),
                            "browser": browser,
                            "profile": os.path.basename(profile_dir),
                            "extension_dir": os.path.join(extensions_dir, name),
                        },
                        "EXT_INCONSISTENT",
                    )
                )

    return utils.apply_whitelist(findings)
