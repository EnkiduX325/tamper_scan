# -*- coding: utf-8 -*-
"""联合指纹白名单引擎测试（V1.5 任务组 C1 / C4）。

覆盖：
- GUI"信任此项"生成联合指纹 JSON 的三个维度（rule_id / signer_contains /
  target_prefix）与默认 90 天有效期；
- 三条件**同时**命中才豁免：签名者不符、规则不符、目标在受信任目录之外
  （"黑客蹭目录"）均不得放行；
- ``expire_days`` / ``expires_at`` 到期自动失效；声明有效期但没有创建时间时
  fail closed；旧的无期限条目保持永久有效；
- 用户级 ``config.json`` 的 ``trust.entries`` 合并进 ``load_whitelist()``，
  无需修改只读规则文件即可让下一次扫描生效；
- 原有五类白名单（paths / signers / services / tasks / commandline_patterns）
  行为不变（V1.4 700 条测试的兼容性回归）。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_whitelist_engine.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import config, whitelist  # noqa: E402
from core.finding import make_finding  # noqa: E402

NOW = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)

APP = r"C:\Program Files\Contoso\app.exe"
APP_DIR = r"C:\Program Files\Contoso"


def _finding(
    rule_id: str = "SIG_UNSIGNED",
    target: str = APP,
    *,
    severity: str = "HIGH",
    signer: str | None = "Contoso Ltd",
    evidence: dict | None = None,
) -> dict:
    merged = dict(evidence or {})
    if signer is not None and "signature" not in merged and "signer" not in merged:
        merged["signature"] = {"status": "valid", "signer": signer}
    return make_finding(severity, "Autoruns", target, "测试 Finding", merged, rule_id)


def _whitelist(entries: list[dict], **kwargs) -> dict:
    """仅使用显式指纹（不读取真实用户 config）的白名单配置。"""
    return whitelist.load_whitelist(include_user_trust=False, trust_entries=entries, **kwargs)


def _entry(finding: dict | None = None, **overrides) -> dict:
    entry = whitelist.build_trust_entry(finding or _finding())
    entry.update(overrides)
    return entry


# ---------------------------------------------------------------------------
# 联合指纹生成（GUI 信任按钮）
# ---------------------------------------------------------------------------


def test_build_trust_entry_extracts_three_dimensions() -> None:
    entry = whitelist.build_trust_entry(_finding())
    assert entry["rule_id"] == "SIG_UNSIGNED"
    assert entry["signer_contains"] == "Contoso Ltd"
    assert entry["target_prefix"] == APP
    assert entry["expire_days"] == 90
    assert entry["source"] == "gui_trust"
    assert entry["created_at"]
    assert entry["expires_at"]
    created = datetime.fromisoformat(entry["created_at"])
    expires = datetime.fromisoformat(entry["expires_at"])
    assert expires - created == timedelta(days=90)
    # GUI 直接 json.dumps 落盘 -> 必须可序列化且字段齐全
    payload = json.loads(json.dumps(entry, ensure_ascii=False))
    assert {"rule_id", "signer_contains", "target_prefix", "expire_days", "created_at"} <= set(payload)


def test_build_trust_entry_signer_fallback_chain() -> None:
    from_signature = whitelist.build_trust_entry(
        _finding(signer=None, evidence={"signature": {"status": "valid", "signer": "Fabrikam Inc"}})
    )
    assert from_signature["signer_contains"] == "Fabrikam Inc"
    from_top_level = whitelist.build_trust_entry(_finding(signer=None, evidence={"signer": "Contoso Ltd"}))
    assert from_top_level["signer_contains"] == "Contoso Ltd"
    from_company = whitelist.build_trust_entry(_finding(signer=None, evidence={"company": "Contoso"}))
    assert from_company["signer_contains"] == "Contoso"
    unsigned = whitelist.build_trust_entry(_finding(signer=None))
    assert unsigned["signer_contains"] == ""


def test_build_trust_entry_requires_target() -> None:
    with pytest.raises(ValueError):
        whitelist.build_trust_entry(_finding(target=""))
    with pytest.raises(ValueError):
        whitelist.build_trust_entry("not-a-finding")  # type: ignore[arg-type]


def test_build_trust_entry_uses_evidence_image_path_when_target_empty() -> None:
    finding = _finding(target="", signer=None, evidence={"image_path": APP})
    entry = whitelist.build_trust_entry(finding)
    assert entry["target_prefix"] == APP


def test_build_trust_entry_empty_rule_becomes_wildcard() -> None:
    entry = whitelist.build_trust_entry(_finding(rule_id=""))
    assert entry["rule_id"] == "*"


def test_build_trust_entry_expiry_options() -> None:
    entry = whitelist.build_trust_entry(_finding(), expire_days=30, now=NOW)
    assert entry["expire_days"] == 30
    assert datetime.fromisoformat(entry["expires_at"]) == NOW + timedelta(days=30)
    permanent = whitelist.build_trust_entry(_finding(), expire_days=None, now=NOW)
    assert permanent["expires_at"] is None
    assert whitelist.fingerprint_active(permanent, now=NOW + timedelta(days=36500)) is True


def test_fingerprint_active_helpers() -> None:
    entry = whitelist.build_trust_entry(_finding(), now=NOW)
    assert whitelist.fingerprint_active(entry, now=NOW + timedelta(days=1)) is True
    assert whitelist.fingerprint_active(entry, now=NOW + timedelta(days=91)) is False
    assert whitelist.fingerprint_active(None) is False
    assert whitelist.normalize_fingerprint_entry({"rule_id": "X"}) is None
    assert whitelist.normalize_fingerprint_entry(entry) is not None


# ---------------------------------------------------------------------------
# 联合维度匹配（防蹭目录）
# ---------------------------------------------------------------------------


def test_joint_fingerprint_requires_all_dimensions() -> None:
    config_dict = _whitelist([_entry()])
    assert whitelist.match_whitelist(_finding(), config_dict) is not None
    # 签名者不同 -> 不放行
    assert whitelist.match_whitelist(_finding(signer="Fabrikam Inc"), config_dict) is None
    # 规则不同 -> 不放行
    assert whitelist.match_whitelist(_finding(rule_id="SIG_INVALID"), config_dict) is None
    # 目标不同（同目录兄弟文件）-> 不放行，防"蹭目录"
    assert whitelist.match_whitelist(_finding(target=r"C:\Program Files\Contoso\evil.exe"), config_dict) is None
    # 完全不同目录 -> 不放行
    assert whitelist.match_whitelist(_finding(target=r"C:\Users\Public\app.exe"), config_dict) is None


def test_directory_prefix_still_matches_child_entries() -> None:
    """指纹的 target_prefix 是前缀语义：目录前缀可覆盖其子文件（内置条目用）。"""
    config_dict = _whitelist([_entry(target_prefix=APP_DIR)])
    assert whitelist.match_whitelist(_finding(target=APP), config_dict) is not None
    assert whitelist.match_whitelist(_finding(target=APP_DIR + r"\sub\tool.exe"), config_dict) is not None
    # 同名前缀但不是子目录（Contoso2）-> 不放行
    assert whitelist.match_whitelist(_finding(target=r"C:\Program Files\Contoso2\app.exe"), config_dict) is None


def test_rule_basename_matches_prefixed_finding_rule() -> None:
    """采集层前缀（AUTORUNS_）与基础规则号视为同一规则，避免去重合并后白名单失效。"""
    config_dict = _whitelist([_entry(rule_id="SIG_UNSIGNED")])
    finding = _finding(rule_id="AUTORUNS_SIG_UNSIGNED")
    assert whitelist.match_whitelist(finding, config_dict) is not None


def test_empty_signer_entry_matches_regardless_of_signer() -> None:
    entry = whitelist.build_trust_entry(_finding(signer=None))
    config_dict = _whitelist([entry])
    assert whitelist.match_whitelist(_finding(signer=None), config_dict) is not None
    assert whitelist.match_whitelist(_finding(signer="Anyone"), config_dict) is not None


def test_entry_requiring_signer_rejects_unsigned_finding() -> None:
    config_dict = _whitelist([_entry()])
    assert whitelist.match_whitelist(_finding(signer=None), config_dict) is None


def test_registry_target_prefix_boundary() -> None:
    prefix = r"HKLM\Software\Contoso\Value"
    config_dict = _whitelist([_entry(target_prefix=prefix)])
    assert whitelist.match_whitelist(_finding(target=prefix), config_dict) is not None
    assert whitelist.match_whitelist(_finding(target=prefix + r"\Sub"), config_dict) is not None
    # 边界：ValueBar 不是 Value 的子键
    assert whitelist.match_whitelist(_finding(target=prefix + "Bar"), config_dict) is None
    assert whitelist.match_whitelist(_finding(target=r"HKLM\Software\Fabrikam\Value"), config_dict) is None


def test_match_uses_raw_config_fingerprints_without_load() -> None:
    """调用方直接传入未归一化 config 字典也必须安全匹配。"""
    config_dict = whitelist.load_whitelist(include_user_trust=False)
    config_dict["fingerprints"] = [
        {"rule_id": "SIG_UNSIGNED", "signer_contains": "Contoso", "target_prefix": APP}
    ]
    assert whitelist.match_whitelist(_finding(), config_dict) is not None
    assert whitelist.match_whitelist(_finding(signer="Other"), config_dict) is None


# ---------------------------------------------------------------------------
# 有效期 / 到期自动失效
# ---------------------------------------------------------------------------


def test_expired_fingerprint_is_not_applied() -> None:
    expired = whitelist.build_trust_entry(_finding(), now=NOW - timedelta(days=100))
    config_dict = _whitelist([expired])
    assert whitelist.match_whitelist(_finding(), config_dict) is None
    result = whitelist.apply_whitelist([_finding()], config_dict)
    assert result[0]["severity"] == "HIGH"
    assert "whitelisted" not in result[0]["evidence"]


def test_active_fingerprint_downgrades_to_info() -> None:
    config_dict = _whitelist([whitelist.build_trust_entry(_finding(), now=NOW)])
    result = whitelist.apply_whitelist([_finding()], config_dict)
    assert result[0]["severity"] == "INFO"
    assert result[0]["evidence"]["whitelisted"] is True
    assert result[0]["evidence"]["whitelist_match"]["type"] == whitelist.FINGERPRINT_MATCH_TYPE


def test_expires_at_overrides_expire_days() -> None:
    active = _entry(created_at="2020-01-01T00:00:00+00:00", expire_days=1, expires_at="2027-01-01T00:00:00+00:00")
    assert whitelist.fingerprint_active(active, now=NOW) is True
    expired = _entry(created_at="2026-11-01T00:00:00+00:00", expire_days=90, expires_at="2026-11-05T00:00:00+00:00")
    assert whitelist.fingerprint_active(expired, now=NOW) is False


def test_expire_without_created_at_fails_closed() -> None:
    raw = {
        "rule_id": "SIG_UNSIGNED",
        "signer_contains": "Contoso Ltd",
        "target_prefix": APP,
        "expire_days": 90,
    }
    config_dict = _whitelist([raw])
    assert whitelist.match_whitelist(_finding(), config_dict) is None


def test_legacy_entry_without_expiry_stays_active() -> None:
    raw = {"rule_id": "SIG_UNSIGNED", "signer_contains": "Contoso Ltd", "target_prefix": APP}
    config_dict = _whitelist([raw])
    assert whitelist.match_whitelist(_finding(), config_dict) is not None


def test_malformed_fingerprint_entries_are_ignored(tmp_path: Path) -> None:
    target = _write_whitelist(
        tmp_path,
        {"fingerprints": ["bad", {}, {"rule_id": "X"}, {"rule_id": "X", "target_prefix": ""}]},
    )
    loaded = whitelist.load_whitelist(target, include_user_trust=False)
    assert loaded["fingerprints"] == []
    assert whitelist.match_whitelist(_finding(), loaded) is None


# ---------------------------------------------------------------------------
# 内置规则文件 + 用户 config.json 合并
# ---------------------------------------------------------------------------


def _write_whitelist(tmp_path: Path, payload: dict) -> Path:
    target = tmp_path / "whitelist.json"
    target.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return target


def test_builtin_fingerprints_from_rules_file(tmp_path: Path) -> None:
    entry = whitelist.build_trust_entry(_finding(), now=NOW)
    target = _write_whitelist(tmp_path, {"fingerprints": [entry]})
    config_dict = whitelist.load_whitelist(target, include_user_trust=False)
    assert len(config_dict["fingerprints"]) == 1
    assert whitelist.match_whitelist(_finding(), config_dict) is not None


def test_user_trust_entries_merged_from_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(config.ENV_CONFIG_DIR, str(tmp_path / "userdata"))
    entry = whitelist.build_trust_entry(_finding(), now=NOW)
    assert config.add_trust_entry(entry) is not None

    loaded = whitelist.load_whitelist()
    assert any(entry.get("source") == "gui_trust" for entry in loaded["fingerprints"])
    hit = whitelist.match_whitelist(_finding(), loaded)
    assert hit is not None and hit["type"] == whitelist.FINGERPRINT_MATCH_TYPE
    assert whitelist.apply_whitelist([_finding()], loaded)[0]["severity"] == "INFO"


def test_include_user_trust_false_ignores_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(config.ENV_CONFIG_DIR, str(tmp_path / "userdata"))
    config.add_trust_entry(whitelist.build_trust_entry(_finding(), now=NOW))
    loaded = whitelist.load_whitelist(include_user_trust=False)
    assert all(entry.get("source") != "gui_trust" for entry in loaded["fingerprints"])
    assert whitelist.match_whitelist(_finding(), loaded) is None


def test_clear_trust_entries_disables_user_fingerprint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(config.ENV_CONFIG_DIR, str(tmp_path / "userdata"))
    config.add_trust_entry(whitelist.build_trust_entry(_finding(), now=NOW))
    assert whitelist.match_whitelist(_finding(), whitelist.load_whitelist()) is not None

    assert config.clear_trust_entries() is True
    assert whitelist.match_whitelist(_finding(), whitelist.load_whitelist()) is None


def test_expired_user_trust_entry_is_not_applied(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(config.ENV_CONFIG_DIR, str(tmp_path / "userdata"))
    old_entry = whitelist.build_trust_entry(_finding(), now=NOW - timedelta(days=200))
    assert config.add_trust_entry(old_entry) is not None
    loaded = whitelist.load_whitelist()
    assert any(entry.get("source") == "gui_trust" for entry in loaded["fingerprints"])  # 条目保留，但匹配时失效
    assert whitelist.match_whitelist(_finding(), loaded) is None


def test_user_entry_overrides_builtin_entry_with_same_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(config.ENV_CONFIG_DIR, str(tmp_path / "userdata"))
    expired = whitelist.build_trust_entry(_finding(), now=NOW - timedelta(days=400))
    active = whitelist.build_trust_entry(_finding(), now=NOW)
    target = _write_whitelist(tmp_path, {"fingerprints": [expired]})
    assert config.add_trust_entry(active) is not None

    loaded = whitelist.load_whitelist(target)
    assert len(loaded["fingerprints"]) == 1
    assert whitelist.fingerprint_active(loaded["fingerprints"][0], now=NOW) is True
    assert whitelist.match_whitelist(_finding(), loaded) is not None


def test_default_whitelist_shape_and_real_file() -> None:
    assert whitelist.DEFAULT_WHITELIST["fingerprints"] == []
    assert whitelist.DEFAULT_TRUST_EXPIRE_DAYS == config.DEFAULT_TRUST_EXPIRE_DAYS
    loaded = whitelist.load_whitelist()
    assert isinstance(loaded["fingerprints"], list)
    assert loaded["mode"] in ("downgrade", "filter", "off")
    assert "extensions" in loaded and "persistence_ext_allow" in loaded


# ---------------------------------------------------------------------------
# 原有白名单行为不变（兼容性回归）
# ---------------------------------------------------------------------------


def test_legacy_signers_whitelist_still_works() -> None:
    config_dict = whitelist.load_whitelist(include_user_trust=False)
    config_dict["signers"] = ["Contoso"]
    finding = _finding(signer=None, evidence={"signer": "Contoso Ltd"})
    hit = whitelist.match_whitelist(finding, config_dict)
    assert hit is not None and hit["type"] == "signers"


def test_legacy_paths_whitelist_still_works() -> None:
    config_dict = whitelist.load_whitelist(include_user_trust=False)
    config_dict["paths"] = [APP_DIR]
    hit = whitelist.match_whitelist(_finding(), config_dict)
    assert hit is not None and hit["type"] == "paths"


def test_fingerprint_modes_filter_and_off() -> None:
    config_dict = _whitelist([whitelist.build_trust_entry(_finding(), now=NOW)])
    assert whitelist.apply_whitelist([_finding()], config_dict, mode="filter") == []
    passthrough = whitelist.apply_whitelist([_finding()], config_dict, mode="off")
    assert passthrough[0]["severity"] == "HIGH"


def test_apply_whitelist_does_not_mutate_input() -> None:
    config_dict = _whitelist([whitelist.build_trust_entry(_finding(), now=NOW)])
    finding = _finding()
    result = whitelist.apply_whitelist([finding], config_dict)
    assert result[0] is not finding
    assert finding["severity"] == "HIGH"
    assert "whitelisted" not in finding["evidence"]


def test_no_fingerprint_no_match() -> None:
    config_dict = whitelist.load_whitelist(include_user_trust=False)
    finding = _finding()
    assert whitelist.match_whitelist(finding, config_dict) is None
    assert whitelist.apply_whitelist([finding], config_dict)[0] is finding


def test_fingerprint_entry_is_json_safe_and_deterministic() -> None:
    first = whitelist.build_trust_entry(_finding(), now=NOW)
    second = whitelist.build_trust_entry(_finding(), now=NOW)
    assert first == second
    assert config.trust_entry_key(first) == config.trust_entry_key(second)


# ---------------------------------------------------------------------------
# 加固回归（独立验证反馈：过宽前缀 / 根路径信任）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("prefix", ["C:", "C:\\", "c:/", "HKLM", "HKCU", "HKLM\\", "\\"])
def test_too_broad_prefix_never_matches(prefix: str) -> None:
    config_dict = _whitelist([_entry(target_prefix=prefix)])
    for target in (r"C:\Windows\System32\evil.exe", r"HKLM\Software\X", r"HKCU\Software\Y"):
        assert whitelist.match_whitelist(_finding(target=target), config_dict) is None


def test_build_trust_entry_rejects_root_targets() -> None:
    for target in ("C:", "C:\\", "HKLM", "HKEY_CURRENT_USER"):
        with pytest.raises(ValueError):
            whitelist.build_trust_entry(_finding(target=target))


def test_specific_hive_key_still_matches() -> None:
    prefix = r"HKLM\Software\Contoso\Value"
    config_dict = _whitelist([_entry(target_prefix=prefix)])
    assert whitelist.match_whitelist(_finding(target=prefix + r"\Child"), config_dict) is not None


@pytest.mark.parametrize(
    "prefix",
    ["C:...", "C:..", "C:....", "C:/...", r"C:\...", "C: ...", r"C:\....", "C:.../", "%SystemDrive%..."],
)
def test_drive_relative_prefix_cannot_bypass_guard(prefix: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """MAJOR 回归：盘符相对路径会被 Windows 规范化为盘符根，不得放行整盘。"""
    monkeypatch.setenv("SystemDrive", "C:")
    config_dict = _whitelist(
        [{"rule_id": "*", "signer_contains": "", "target_prefix": prefix, "expire_days": 90}]
    )
    finding = _finding(target=r"C:\Windows\System32\malware.exe", signer=None)
    assert whitelist.match_whitelist(finding, config_dict) is None
    assert whitelist.apply_whitelist([finding], config_dict)[0]["severity"] == "HIGH"
    with pytest.raises(ValueError):
        whitelist.build_trust_entry(_finding(target=prefix, signer=None))


@pytest.mark.parametrize(
    "prefix", ["C:...", "C:..", "C:/...", "%SystemDrive%...", "C:", "HKLM"]
)
def test_add_trust_entry_rejects_broad_fingerprint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prefix: str
) -> None:
    monkeypatch.setenv("SystemDrive", "C:")
    monkeypatch.setenv(config.ENV_CONFIG_DIR, str(tmp_path / "userdata"))
    entry = {"rule_id": "*", "signer_contains": "", "target_prefix": prefix, "expire_days": 90}
    assert config.add_trust_entry(entry) is None
    assert config.load_trust_entries() == []
