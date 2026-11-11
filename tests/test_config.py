# -*- coding: utf-8 -*-
"""``core/config.py`` 用户配置 / 信任名单 / 暂存上报队列测试（V1.5 任务组 B/C）。

覆盖：
- 默认配置结构、缺失/损坏/类型不符时的静默回退；
- 未知字段保留、嵌套默认值补齐、主题/更新开关归一化；
- 原子保存（目录创建、无临时文件残留、失败返回 False 而不抛异常）；
- 点分隔路径读写；
- 联合指纹信任项归一化、去重刷新、有效期（expire_days / expires_at / fail closed）、
  删除 / 清空 / 上限保护；
- 暂存上报队列追加 / 读取 / 清空 / 导出（文件与目录两种目标）。

所有测试都使用临时目录或 ``TAMPERSCAN_CONFIG_DIR``，不读写真实用户配置。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_config.py
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import config  # noqa: E402

NOW = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def cfg_path(tmp_path: Path) -> Path:
    return tmp_path / "config.json"


@pytest.fixture()
def entry() -> dict:
    return {
        "rule_id": "SIG_UNSIGNED",
        "signer_contains": "Contoso Ltd",
        "target_prefix": r"C:\Program Files\Contoso\app.exe",
        "expire_days": 90,
        "created_at": "2026-11-11T12:00:00+00:00",
        "source": "gui_trust",
        "note": "测试",
    }


# ---------------------------------------------------------------------------
# 默认值 / 加载
# ---------------------------------------------------------------------------


def test_default_config_shape() -> None:
    default = config.DEFAULT_CONFIG
    assert default["schema_version"] == config.SCHEMA_VERSION
    assert default["update"]["auto_check"] is True
    assert default["update"]["ignored_versions"] == []
    assert default["update"]["ignored_current_version"] is None
    assert default["trust"]["entries"] == []
    assert default["reporting"]["pending_file"] == config.PENDING_REPORT_FILENAME
    assert default["ui"]["theme"] == "light"
    assert config.DEFAULT_TRUST_EXPIRE_DAYS == 90


def test_load_missing_returns_defaults_and_does_not_create_file(cfg_path: Path) -> None:
    loaded = config.load_config(cfg_path)
    assert loaded["update"]["auto_check"] is True
    assert loaded["ui"]["theme"] == "light"
    assert not cfg_path.exists()


@pytest.mark.parametrize("payload", ["{not json", "[]", '"text"', "null"])
def test_load_invalid_json_falls_back_to_defaults(cfg_path: Path, payload: str) -> None:
    cfg_path.write_text(payload, encoding="utf-8")
    loaded = config.load_config(cfg_path)
    assert loaded["update"]["auto_check"] is True
    assert loaded["trust"]["entries"] == []


def test_load_fills_missing_nested_fields(cfg_path: Path) -> None:
    cfg_path.write_text(json.dumps({"update": {"auto_check": False}}), encoding="utf-8")
    loaded = config.load_config(cfg_path)
    assert loaded["update"]["auto_check"] is False
    assert loaded["update"]["ignored_versions"] == []
    assert loaded["ui"]["theme"] == "light"
    assert loaded["reporting"]["pending_file"] == config.PENDING_REPORT_FILENAME


def test_load_preserves_unknown_keys(cfg_path: Path) -> None:
    cfg_path.write_text(
        json.dumps({"custom_section": {"x": 1}, "update": {"future_flag": True}}),
        encoding="utf-8",
    )
    loaded = config.load_config(cfg_path)
    assert loaded["custom_section"] == {"x": 1}
    assert loaded["update"]["future_flag"] is True


def test_schema_version_bool_is_repaired(cfg_path: Path) -> None:
    cfg_path.write_text(json.dumps({"schema_version": True}), encoding="utf-8")
    assert config.load_config(cfg_path)["schema_version"] == config.SCHEMA_VERSION


def test_env_override_config_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(config.ENV_CONFIG_DIR, str(tmp_path / "data"))
    assert config.get_config_dir() == tmp_path / "data"
    assert config.get_config_path() == tmp_path / "data" / config.CONFIG_FILENAME
    assert config.get_pending_report_path() == tmp_path / "data" / config.PENDING_REPORT_FILENAME


@pytest.mark.skipif(os.name != "nt", reason="Windows %APPDATA% 路径语义")
def test_windows_appdata_default_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(config.ENV_CONFIG_DIR, raising=False)
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    assert config.get_config_dir() == tmp_path / "roaming" / config.APP_DIR_NAME


# ---------------------------------------------------------------------------
# 保存 / 读写
# ---------------------------------------------------------------------------


def test_save_and_load_roundtrip(cfg_path: Path) -> None:
    cfg = config.load_config(cfg_path)
    cfg["update"]["auto_check"] = False
    cfg["ui"]["theme"] = "dark"
    assert config.save_config(cfg, cfg_path) is True
    loaded = config.load_config(cfg_path)
    assert loaded["update"]["auto_check"] is False
    assert loaded["ui"]["theme"] == "dark"


def test_save_creates_parent_directories(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b" / "config.json"
    assert config.save_config(config.load_config(target), target) is True
    assert target.is_file()


def test_save_normalizes_illegal_values(cfg_path: Path) -> None:
    cfg = config.load_config(cfg_path)
    cfg["update"]["auto_check"] = "yes"  # 非 bool -> 默认 True
    cfg["ui"]["theme"] = "purple"  # 非法主题 -> light
    cfg["reporting"]["pending_file"] = "../evil.json"  # 路径穿越 -> 默认文件名
    assert config.save_config(cfg, cfg_path) is True
    loaded = config.load_config(cfg_path)
    assert loaded["update"]["auto_check"] is True
    assert loaded["ui"]["theme"] == "light"
    assert loaded["reporting"]["pending_file"] == config.PENDING_REPORT_FILENAME


def test_save_failure_returns_false(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    assert config.save_config(config.load_config(tmp_path / "x.json"), blocker / "config.json") is False


def test_save_leaves_no_temporary_files(cfg_path: Path) -> None:
    cfg = config.load_config(cfg_path)
    assert config.save_config(cfg, cfg_path) is True
    assert config.save_config(cfg, cfg_path) is True
    leftovers = [p.name for p in cfg_path.parent.iterdir() if p.name != cfg_path.name]
    assert leftovers == []


def test_get_and_set_value(cfg_path: Path) -> None:
    assert config.set_value("update.auto_check", False, cfg_path) is True
    loaded = config.load_config(cfg_path)
    assert config.get_value(loaded, "update.auto_check") is False
    assert config.get_value(loaded, "update.auto_check", True) is False
    assert config.get_value(loaded, "missing.path", "fallback") == "fallback"
    assert config.get_value(None, "update.auto_check", True) is True


def test_set_value_rejects_empty_key(cfg_path: Path) -> None:
    assert config.set_value("", 1, cfg_path) is False
    assert config.set_value("...", 1, cfg_path) is False


def test_update_helpers(cfg_path: Path) -> None:
    assert config.is_auto_check_enabled(config.load_config(cfg_path)) is True
    assert config.set_auto_check(False, cfg_path) is True
    assert config.is_auto_check_enabled(config.load_config(cfg_path)) is False
    assert config.is_auto_check_enabled({"update": {"auto_check": False}}) is False
    assert config.is_auto_check_enabled({}) is True

    assert config.get_theme(config.load_config(cfg_path)) == "light"
    assert config.set_theme("DARK", cfg_path) is True
    assert config.get_theme(config.load_config(cfg_path)) == "dark"
    assert config.set_theme("blue", cfg_path) is True
    assert config.get_theme(config.load_config(cfg_path)) == "light"


def test_reset_config(cfg_path: Path) -> None:
    cfg = config.load_config(cfg_path)
    cfg["ui"]["theme"] = "dark"
    config.save_config(cfg, cfg_path)
    assert config.reset_config(cfg_path) is True
    assert config.load_config(cfg_path)["ui"]["theme"] == "light"


def test_config_exists(cfg_path: Path) -> None:
    assert config.config_exists(cfg_path) is False
    config.save_config(config.load_config(cfg_path), cfg_path)
    assert config.config_exists(cfg_path) is True


# ---------------------------------------------------------------------------
# 联合指纹信任项
# ---------------------------------------------------------------------------


def test_normalize_trust_entry_requires_target_prefix() -> None:
    assert config.normalize_trust_entry(None) is None
    assert config.normalize_trust_entry({}) is None
    assert config.normalize_trust_entry({"rule_id": "X"}) is None
    # target 作为 target_prefix 的兼容别名
    normalized = config.normalize_trust_entry({"rule_id": "X", "target": r"C:\a.exe"})
    assert normalized is not None
    assert normalized["target_prefix"] == r"C:\a.exe"


def test_normalize_trust_entry_rule_and_signer_normalization(entry: dict) -> None:
    normalized = config.normalize_trust_entry(entry)
    assert normalized is not None
    assert normalized["rule_id"] == "SIG_UNSIGNED"
    assert normalized["signer_contains"] == "Contoso Ltd"
    assert normalized["source"] == "gui_trust"
    assert normalized["note"] == "测试"
    lowered = config.normalize_trust_entry({**entry, "rule_id": " sig_unsigned ", "signer_contains": "  Contoso   Ltd "})
    assert lowered is not None
    assert lowered["rule_id"] == "SIG_UNSIGNED"
    assert lowered["signer_contains"] == "Contoso Ltd"
    empty_rule = config.normalize_trust_entry({**entry, "rule_id": ""})
    assert empty_rule is not None and empty_rule["rule_id"] == "*"


def test_normalize_trust_entry_expiry_computed(entry: dict) -> None:
    normalized = config.normalize_trust_entry(entry, now=NOW)
    assert normalized is not None
    created = datetime.fromisoformat(normalized["created_at"])
    expires = datetime.fromisoformat(normalized["expires_at"])
    assert expires - created == timedelta(days=90)
    assert config.is_trust_entry_expired(normalized, now=NOW + timedelta(days=89)) is False
    assert config.is_trust_entry_expired(normalized, now=NOW + timedelta(days=91)) is True


def test_expire_days_without_created_at_fails_closed(entry: dict) -> None:
    raw = {key: value for key, value in entry.items() if key != "created_at"}
    normalized = config.normalize_trust_entry(raw, now=NOW)
    assert normalized is not None
    assert config.is_trust_entry_expired(normalized, now=NOW) is True


def test_legacy_entry_without_expiry_never_expires(entry: dict) -> None:
    raw = {key: value for key, value in entry.items() if key not in ("expire_days", "created_at")}
    normalized = config.normalize_trust_entry(raw, now=NOW)
    assert normalized is not None
    assert normalized["expires_at"] is None
    assert config.is_trust_entry_expired(normalized, now=NOW + timedelta(days=3650)) is False


def test_expires_at_overrides_expire_days(entry: dict) -> None:
    raw = {**entry, "expires_at": "2027-01-01T00:00:00+00:00"}
    normalized = config.normalize_trust_entry(raw, now=NOW)
    assert normalized is not None
    assert normalized["expires_at"].startswith("2027-01-01")
    assert config.is_trust_entry_expired(normalized, now=NOW + timedelta(days=30)) is False
    assert config.is_trust_entry_expired(normalized, now=datetime(2028, 1, 1, tzinfo=timezone.utc)) is True


def test_is_trust_entry_expired_defensive() -> None:
    assert config.is_trust_entry_expired(None) is True
    assert config.is_trust_entry_expired("bad") is True
    assert config.is_trust_entry_expired({"target_prefix": r"C:\a.exe"}) is False


def test_trust_entry_key_is_case_insensitive() -> None:
    left = {"rule_id": "sig_unsigned", "signer_contains": "CONTOSO", "target_prefix": r"C:\A\b.exe"}
    right = {"rule_id": "SIG_UNSIGNED", "signer_contains": "contoso", "target_prefix": r"c:\a\B.exe\\"}
    assert config.trust_entry_key(left) == config.trust_entry_key(right)
    assert config.trust_entry_key(None) == ("", "", "")


def test_add_and_load_trust_entry(cfg_path: Path, entry: dict) -> None:
    added = config.add_trust_entry(entry, cfg_path)
    assert added is not None
    assert added["rule_id"] == "SIG_UNSIGNED"
    entries = config.load_trust_entries(path=cfg_path)
    assert len(entries) == 1
    assert entries[0]["target_prefix"] == entry["target_prefix"]


def test_add_trust_entry_dedup_refreshes(cfg_path: Path, entry: dict) -> None:
    config.add_trust_entry({**entry, "note": "第一次"}, cfg_path)
    config.add_trust_entry({**entry, "note": "第二次"}, cfg_path)
    entries = config.load_trust_entries(path=cfg_path)
    assert len(entries) == 1
    assert entries[0]["note"] == "第二次"


def test_add_trust_entry_rejects_invalid(cfg_path: Path) -> None:
    assert config.add_trust_entry({"rule_id": "X"}, cfg_path) is None
    assert config.add_trust_entry("bad", cfg_path) is None
    assert not cfg_path.exists()


def test_load_trust_entries_skips_invalid(cfg_path: Path, entry: dict) -> None:
    cfg = config.load_config(cfg_path)
    cfg["trust"]["entries"] = [entry, "bad", {"rule_id": "X"}, 123]
    config.save_config(cfg, cfg_path)
    entries = config.load_trust_entries(path=cfg_path)
    assert len(entries) == 1


def test_remove_trust_entry(cfg_path: Path, entry: dict) -> None:
    config.add_trust_entry(entry, cfg_path)
    assert config.remove_trust_entry("SIG_UNSIGNED", entry["target_prefix"], "Contoso Ltd", cfg_path) is True
    assert config.load_trust_entries(path=cfg_path) == []
    # 不存在时也返回 True（幂等）
    assert config.remove_trust_entry("SIG_UNSIGNED", entry["target_prefix"], "", cfg_path) is True


def test_clear_trust_entries(cfg_path: Path, entry: dict) -> None:
    config.add_trust_entry(entry, cfg_path)
    config.add_trust_entry({**entry, "target_prefix": r"C:\Program Files\Contoso\b.exe"}, cfg_path)
    assert len(config.load_trust_entries(path=cfg_path)) == 2
    assert config.clear_trust_entries(cfg_path) is True
    assert config.load_trust_entries(path=cfg_path) == []
    assert config.clear_trust_entries(cfg_path) is True
    assert config.clear_trust_entries(cfg_path.parent / "missing.json") is True


def test_trust_entries_capped(cfg_path: Path, monkeypatch: pytest.MonkeyPatch, entry: dict) -> None:
    monkeypatch.setattr(config, "MAX_TRUST_ENTRIES", 3)
    for index in range(5):
        config.add_trust_entry({**entry, "target_prefix": rf"C:\Program Files\Contoso\app{index}.exe"}, cfg_path)
    entries = config.load_trust_entries(path=cfg_path)
    assert len(entries) == 3


def test_max_truncation_keeps_smaller_value() -> None:
    # 配置上界保护：expire_days 超过 10 年截断为 3650 天
    normalized = config.normalize_trust_entry(
        {"rule_id": "X", "target_prefix": r"C:\a.exe", "expire_days": 99999, "created_at": "2026-01-01T00:00:00+00:00"}
    )
    assert normalized is not None
    assert normalized["expire_days"] == 3650


# ---------------------------------------------------------------------------
# 暂存上报队列
# ---------------------------------------------------------------------------


@pytest.fixture()
def pending_path(tmp_path: Path) -> Path:
    return tmp_path / "pending_report.json"


def test_append_and_load_pending(pending_path: Path) -> None:
    assert config.append_pending_report({"rule_id": "R1"}, pending_path) is True
    assert config.append_pending_report({"rule_id": "R2"}, pending_path) is True
    reports = config.load_pending_reports(pending_path)
    assert [item["rule_id"] for item in reports] == ["R1", "R2"]
    assert config.pending_report_count(pending_path) == 2


def test_append_pending_rejects_non_dict(pending_path: Path) -> None:
    assert config.append_pending_report("bad", pending_path) is False
    assert config.load_pending_reports(pending_path) == []


def test_pending_queue_capped(pending_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "MAX_PENDING_REPORTS", 2)
    for index in range(3):
        config.append_pending_report({"index": index}, pending_path)
    reports = config.load_pending_reports(pending_path)
    assert [item["index"] for item in reports] == [1, 2]


def test_pending_corrupt_file_returns_empty(pending_path: Path) -> None:
    pending_path.write_text("{broken", encoding="utf-8")
    assert config.load_pending_reports(pending_path) == []
    assert config.pending_report_count(pending_path) == 0


def test_clear_pending_reports(pending_path: Path) -> None:
    config.append_pending_report({"a": 1}, pending_path)
    assert config.clear_pending_reports(pending_path) is True
    assert pending_path.exists() is False
    assert config.clear_pending_reports(pending_path) is True


def test_export_pending_reports_to_file(tmp_path: Path, pending_path: Path) -> None:
    config.append_pending_report({"rule_id": "R1"}, pending_path)
    destination = tmp_path / "export.json"
    written = config.export_pending_reports(destination, pending_path)
    assert written is not None
    payload = json.loads(Path(written).read_text(encoding="utf-8"))
    assert payload["tool"] == "TamperScan"
    assert payload["count"] == 1
    assert payload["reports"][0]["rule_id"] == "R1"


def test_export_pending_reports_to_directory(tmp_path: Path, pending_path: Path) -> None:
    config.append_pending_report({"rule_id": "R1"}, pending_path)
    written = config.export_pending_reports(tmp_path, pending_path)
    assert written is not None
    assert Path(written).parent == tmp_path
    assert Path(written).name.startswith("pending_report_export_")


def test_export_pending_reports_empty_returns_none(tmp_path: Path, pending_path: Path) -> None:
    assert config.export_pending_reports(tmp_path / "x.json", pending_path) is None


def test_pending_export_path(tmp_path: Path) -> None:
    candidate = config.pending_export_path(tmp_path)
    assert candidate.parent == tmp_path
    assert candidate.suffix == ".json"


def test_pending_custom_filename_is_honored(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """config.reporting.pending_file 自定义文件名必须被暂存队列读写采用。"""
    monkeypatch.setenv(config.ENV_CONFIG_DIR, str(tmp_path))
    cfg = config.load_config()
    cfg["reporting"]["pending_file"] = "custom_pending.json"
    assert config.save_config(cfg) is True
    assert config.append_pending_report({"x": 1}) is True
    assert (tmp_path / "custom_pending.json").is_file()
    assert config.load_pending_reports() == [{"x": 1}]


def test_timestamp_helpers() -> None:
    assert config.now_iso(NOW) == "2026-11-11T12:00:00+00:00"
    assert config.now_iso("bad") != ""
    assert config.touch_timestamp()


# ---------------------------------------------------------------------------
# 加固回归（独立验证反馈：损坏输入 / 文件名冲突 / 递归深度）
# ---------------------------------------------------------------------------


def test_load_utf8_bom_config(cfg_path: Path) -> None:
    cfg_path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"ui": {"theme": "dark"}}).encode("utf-8"))
    assert config.load_config(cfg_path)["ui"]["theme"] == "dark"


def test_load_oversized_config_falls_back(cfg_path: Path) -> None:
    cfg_path.write_bytes(b"{" + b'"x": "' + b"a" * (config.MAX_CONFIG_BYTES + 10) + b'"}')
    loaded = config.load_config(cfg_path)
    assert loaded["ui"]["theme"] == "light"
    assert loaded["update"]["auto_check"] is True


def test_load_directory_path_falls_back(tmp_path: Path) -> None:
    loaded = config.load_config(tmp_path)
    assert loaded["ui"]["theme"] == "light"


def test_load_deeply_nested_json_does_not_raise(cfg_path: Path) -> None:
    cfg_path.write_text('{"a":' * 700 + "1" + "}" * 700, encoding="utf-8")
    loaded = config.load_config(cfg_path)
    assert loaded["schema_version"] == config.SCHEMA_VERSION
    assert loaded["update"]["auto_check"] is True


def test_save_deeply_nested_config_returns_false(cfg_path: Path) -> None:
    deep: dict = {}
    current = deep
    for _ in range(5000):
        current["x"] = {}
        current = current["x"]
    assert config.save_config(deep, cfg_path) is False
    assert not cfg_path.exists()


@pytest.mark.parametrize("name", ["../evil.json", "config.json", "CONFIG.JSON", "evil.txt", "con.json", "nul.json"])
def test_pending_filename_rejects_unsafe_names(cfg_path: Path, name: str) -> None:
    cfg = config.load_config(cfg_path)
    cfg["reporting"]["pending_file"] = name
    config.save_config(cfg, cfg_path)
    assert config.load_config(cfg_path)["reporting"]["pending_file"] == config.PENDING_REPORT_FILENAME


def test_pending_file_cannot_alias_or_delete_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """M1 回归：pending_file=config.json 时不得覆盖 / 删除配置文件。"""
    monkeypatch.setenv(config.ENV_CONFIG_DIR, str(tmp_path))
    cfg = config.load_config()
    cfg["reporting"]["pending_file"] = "config.json"
    cfg["ui"]["theme"] = "dark"
    assert config.save_config(cfg) is True
    assert config.append_pending_report({"rule_id": "R1"}) is True
    reloaded = config.load_config()
    assert reloaded["ui"]["theme"] == "dark"
    assert reloaded["reporting"]["pending_file"] == config.PENDING_REPORT_FILENAME
    assert reloaded["trust"]["entries"] == []
    assert config.clear_pending_reports() is True
    assert config.load_config()["ui"]["theme"] == "dark"


def test_pending_payload_with_bom(cfg_path: Path, tmp_path: Path) -> None:
    pending = tmp_path / "pending_report.json"
    pending.write_bytes(b"\xef\xbb\xbf" + json.dumps([{"rule_id": "R1"}]).encode("utf-8"))
    assert config.load_pending_reports(pending) == [{"rule_id": "R1"}]


@pytest.mark.parametrize(
    "prefix",
    [
        "C:",
        "C:\\",
        "c:/",
        "HKLM",
        "HKCU",
        "HKLM\\",
        "\\",
        "C:...",
        "C:..",
        "C:....",
        "C:/...",
        r"C:\...",
        "C: ...",
        r"C:\....",
        "C:.../",
        "%SystemDrive%...",
        "%SystemDrive%",
        ".",
        "..",
        "",
    ],
)
def test_is_too_broad_prefix_rejects_root_equivalents(prefix: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SystemDrive", "C:")
    assert config.is_too_broad_prefix(prefix) is True


@pytest.mark.parametrize(
    "prefix",
    [r"C:\Program Files\Contoso\app.exe", r"HKLM\Software\Contoso\Value", r"C:\Program Files\Contoso"],
)
def test_is_too_broad_prefix_accepts_specific_prefixes(prefix: str) -> None:
    assert config.is_too_broad_prefix(prefix) is False


@pytest.mark.parametrize(
    "prefix",
    ["C:...", "C:..", "C:/...", r"C:\...", "%SystemDrive%...", "C:", "HKLM"],
)
def test_add_trust_entry_rejects_broad_prefix(
    cfg_path: Path, monkeypatch: pytest.MonkeyPatch, prefix: str
) -> None:
    monkeypatch.setenv("SystemDrive", "C:")
    entry = {
        "rule_id": "*",
        "signer_contains": "",
        "target_prefix": prefix,
        "expire_days": 90,
    }
    assert config.add_trust_entry(entry, cfg_path) is None
    assert config.load_trust_entries(path=cfg_path) == []


def test_save_oversized_config_returns_false(cfg_path: Path) -> None:
    """NIT 回归：超过 2MiB 的配置必须保存失败，而不是"保存成功但下次读回默认值"。"""
    cfg = config.load_config(cfg_path)
    cfg["huge_unknown_section"] = {"blob": "a" * (config.MAX_CONFIG_BYTES + 1024)}
    assert config.save_config(cfg, cfg_path) is False
    assert not cfg_path.exists()


@pytest.mark.parametrize("name", ["con .json", "aux .json", "nul .json", "com1 .json"])
def test_reserved_dos_stem_with_space_rejected(cfg_path: Path, name: str) -> None:
    cfg = config.load_config(cfg_path)
    cfg["reporting"]["pending_file"] = name
    config.save_config(cfg, cfg_path)
    assert config.load_config(cfg_path)["reporting"]["pending_file"] == config.PENDING_REPORT_FILENAME
