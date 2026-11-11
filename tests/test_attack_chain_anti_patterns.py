# -*- coding: utf-8 -*-
"""``rules/attack_chain.json`` V1.5 C3 反模式库预埋测试。

覆盖：
- 真实规则库新增的 3 条反模式可被 ``core.correlator.load_chain_rules()`` 正确读取；
- 微软签名 svchost → cmd/powershell 的合法父子进程组合命中
  ``microsoft_svchost_shell_child``，campaign 进入 ``suppressed``；
- Edge / Chrome 自动更新器目录下的文件变更命中 ``browser_auto_updater_noise``；
- Windows 更新目录（WinSxS / servicing / SoftwareDistribution）噪声命中
  ``windows_servicing_update_noise``；
- ``require_all`` 语义：缺少 PARENT_ANOMALY / LOLBIN_CMDLINE 之一时不得抑制；
- 干净攻击链（目标不在合法目录、无合法组合）保持 campaign，不被误抑制。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_attack_chain_anti_patterns.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import correlator  # noqa: E402
from core.finding import make_finding  # noqa: E402

RULES_PATH = PROJECT_ROOT / "rules" / "attack_chain.json"

NEW_PATTERN_IDS = (
    "microsoft_svchost_shell_child",
    "browser_auto_updater_noise",
    "windows_servicing_update_noise",
)

#: 真实剧本 autostart_signature_service_hijack 的三步规则（TA0003 → TA0005 → TA0003）
TEMPLATE_RULES = ("RUN_USERWRITABLE", "SIG_UNSIGNED", "SVC_SERVICEDLL_TAMPER")


def _finding(rule_id: str, target: str) -> dict[str, Any]:
    return make_finding("HIGH", "TestCategory", target, "test detail", {}, rule_id)


def _template_cluster(target: str) -> list[dict[str, Any]]:
    return [_finding(rule_id, target) for rule_id in TEMPLATE_RULES]


def _result(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return correlator.correlate(findings)


# ---------------------------------------------------------------------------
# 规则库结构
# ---------------------------------------------------------------------------


def test_real_rules_contain_new_anti_patterns() -> None:
    rules = correlator.load_chain_rules()
    ids = [pattern["id"] for pattern in rules["anti_patterns"]]
    for pattern_id in NEW_PATTERN_IDS:
        assert pattern_id in ids
    assert len(rules["anti_patterns"]) >= 5


def test_new_pattern_schema_is_normalized() -> None:
    rules = correlator.load_chain_rules()
    by_id = {pattern["id"]: pattern for pattern in rules["anti_patterns"]}
    svchost = by_id["microsoft_svchost_shell_child"]
    assert svchost["match"]["require_all"] is True
    assert svchost["match"]["rule_ids"] == ["PARENT_ANOMALY", "LOLBIN_CMDLINE"]
    assert svchost["match"]["target_contains"] == ["svchost"]

    browser = by_id["browser_auto_updater_noise"]
    assert browser["match"]["require_all"] is False
    assert any("\\google\\update\\" in item for item in browser["match"]["target_contains"])
    assert any("\\microsoft\\edge\\update\\" in item for item in browser["match"]["target_contains"])

    servicing = by_id["windows_servicing_update_noise"]
    assert servicing["match"]["require_all"] is False
    assert any("\\winsxs\\" in item for item in servicing["match"]["target_contains"])
    for pattern_id in NEW_PATTERN_IDS:
        assert by_id[pattern_id]["description"].strip()


def test_raw_json_is_valid_and_keeps_existing_patterns() -> None:
    payload = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    ids = [item["id"] for item in payload["anti_patterns"]]
    assert ids[:2] == ["enterprise_updater_noise", "managed_it_policy_extension"]
    for pattern_id in NEW_PATTERN_IDS:
        assert pattern_id in ids


# ---------------------------------------------------------------------------
# 抑制行为
# ---------------------------------------------------------------------------


def test_svchost_shell_child_is_suppressed() -> None:
    target = r"C:\Windows\System32\svchost.exe"
    findings = _template_cluster(target) + [
        _finding("PARENT_ANOMALY", target),
        _finding("LOLBIN_CMDLINE", target),
    ]
    result = _result(findings)
    assert result["campaigns"] == []
    assert len(result["suppressed"]) == 1
    assert result["suppressed"][0]["suppressed_by"] == "microsoft_svchost_shell_child"
    assert result["suppressed"][0]["suppressed"] is True
    assert result["stats"]["campaigns"] == 0
    assert result["stats"]["suppressed"] == 1


def test_svchost_pattern_requires_both_rules() -> None:
    target = r"C:\Windows\System32\svchost.exe"
    findings = _template_cluster(target) + [_finding("PARENT_ANOMALY", target)]
    result = _result(findings)
    assert len(result["campaigns"]) == 1
    assert result["suppressed"] == []


def test_browser_auto_updater_noise_is_suppressed() -> None:
    target = r"C:\Program Files\Google\Update\1.3.36\setup.exe"
    result = _result(_template_cluster(target))
    assert result["campaigns"] == []
    assert len(result["suppressed"]) == 1
    assert result["suppressed"][0]["suppressed_by"] == "browser_auto_updater_noise"


def test_edge_updater_noise_is_suppressed() -> None:
    target = r"C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.195\MicrosoftEdgeUpdate.exe"
    result = _result(_template_cluster(target))
    assert len(result["suppressed"]) == 1
    assert result["suppressed"][0]["suppressed_by"] == "browser_auto_updater_noise"


def test_chrome_application_noise_is_suppressed() -> None:
    target = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    result = _result(_template_cluster(target))
    assert len(result["suppressed"]) == 1
    assert result["suppressed"][0]["suppressed_by"] == "browser_auto_updater_noise"


def test_windows_servicing_noise_is_suppressed() -> None:
    target = r"C:\Windows\WinSxS\amd64_microsoft-windows-foo\foo.dll"
    result = _result(_template_cluster(target))
    assert len(result["suppressed"]) == 1
    assert result["suppressed"][0]["suppressed_by"] == "windows_servicing_update_noise"


def test_clean_attack_chain_is_not_suppressed() -> None:
    target = r"C:\Users\Public\evil.exe"
    result = _result(_template_cluster(target))
    assert len(result["campaigns"]) == 1
    assert result["suppressed"] == []
    campaign = result["campaigns"][0]
    assert campaign["suppressed"] is False
    assert campaign["suppressed_by"] is None
    assert campaign["chain_id"] == "autostart_signature_service_hijack"


def test_anti_patterns_do_not_mutate_findings() -> None:
    target = r"C:\Windows\WinSxS\amd64_microsoft-windows-foo\foo.dll"
    findings = _template_cluster(target)
    snapshot = [dict(finding) for finding in findings]
    _result(findings)
    assert findings == snapshot
