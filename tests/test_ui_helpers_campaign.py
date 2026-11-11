# -*- coding: utf-8 -*-
"""``core.ui_helpers`` 攻击链纯函数测试（V1.5 rc2 自 V1.4 test_campaign_gui.py 迁移）。

覆盖：
- 置信度 tag / 中文标签 / 配色常量；
- campaign 摘要文本（含影子模式、缺失字段、从 steps 统计 finding）；
- campaign Finding 键提取/去重/容错；
- 列表行值与步骤时间线行；
- 与真实 ``core.correlator.correlate`` 输出的结构兼容性。

不包含任何 Tkinter 导入/窗口创建。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_ui_helpers_campaign.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import correlator, ui_helpers  # noqa: E402
from core.finding import make_finding  # noqa: E402

CAMPAIGN: dict[str, Any] = {
    "chain_id": "chain_demo",
    "name": "演示攻击链",
    "confidence": "high",
    "steps": [
        {
            "tactic": "TA0003",
            "rule_ids": ["PERSIST_A", "PERSIST_B"],
            "findings": [
                {"rule_id": "PERSIST_A", "target": r"C:\Users\Public\a.exe"},
                {"rule_id": "PERSIST_B", "target": r"C:\Users\Public\b.exe"},
            ],
        },
        {
            "tactic": "TA0005",
            "rule_ids": ["DEFENSE_C"],
            "findings": [{"rule_id": "DEFENSE_C", "target": r"C:\Users\Public\a.exe"}],
        },
    ],
    "finding_count": 3,
    "suppressed": False,
}


def _campaign(**overrides: Any) -> dict[str, Any]:
    data = {
        "chain_id": "chain_demo",
        "name": "演示攻击链",
        "confidence": "high",
        "steps": [
            {
                "tactic": "TA0003",
                "rule_ids": ["PERSIST_A"],
                "findings": [{"rule_id": "PERSIST_A", "target": r"C:\a.exe"}],
            }
        ],
        "finding_count": 1,
    }
    data.update(overrides)
    return data


class TestConfidenceMapping:
    def test_tag_known(self) -> None:
        assert ui_helpers.campaign_confidence_tag("high") == "campaign_high"
        assert ui_helpers.campaign_confidence_tag("medium") == "campaign_medium"
        assert ui_helpers.campaign_confidence_tag("low") == "campaign_low"

    def test_tag_case_insensitive(self) -> None:
        assert ui_helpers.campaign_confidence_tag(" HIGH ") == "campaign_high"
        assert ui_helpers.campaign_confidence_tag("Medium") == "campaign_medium"

    def test_tag_unknown_and_empty(self) -> None:
        for value in ("", None, "critical", 1):
            assert ui_helpers.campaign_confidence_tag(value) == ""

    def test_label_known(self) -> None:
        assert ui_helpers.campaign_confidence_label("high") == "高"
        assert ui_helpers.campaign_confidence_label("medium") == "中"
        assert ui_helpers.campaign_confidence_label("low") == "低"

    def test_label_unknown_and_empty(self) -> None:
        for value in ("", None, "critical"):
            assert ui_helpers.campaign_confidence_label(value) == "未知"

    def test_confidence_colors_mapping(self) -> None:
        assert ui_helpers.CAMPAIGN_CONFIDENCE_COLORS == {
            "high": "#C42B1C",
            "medium": "#F7630C",
            "low": "#C19C00",
        }


class TestCampaignSummary:
    def test_summary_text_full(self) -> None:
        text = ui_helpers.campaign_summary_text(CAMPAIGN)
        assert text == "演示攻击链（置信度 高，2 步 / 3 条 finding）"

    def test_summary_text_shadow(self) -> None:
        text = ui_helpers.campaign_summary_text({**CAMPAIGN, "shadow": True})
        assert text.endswith(" · 影子（仅观察））")

    def test_summary_text_missing_fields(self) -> None:
        text = ui_helpers.campaign_summary_text({"chain_id": "cid"})
        assert text == "cid（置信度 未知，0 步 / 0 条 finding）"

    def test_summary_text_computes_count_from_steps(self) -> None:
        campaign = _campaign()
        campaign.pop("finding_count")
        text = ui_helpers.campaign_summary_text(campaign)
        assert "1 条 finding" in text

    def test_summary_text_empty_or_invalid(self) -> None:
        for value in ({}, None, "bad", []):
            assert ui_helpers.campaign_summary_text(value) == ""


class TestCampaignFindingKeys:
    def test_extracts_nested_finding_keys(self) -> None:
        keys = ui_helpers.campaign_finding_keys(CAMPAIGN)
        assert keys == [
            ("PERSIST_A", r"C:\Users\Public\a.exe"),
            ("PERSIST_B", r"C:\Users\Public\b.exe"),
            ("DEFENSE_C", r"C:\Users\Public\a.exe"),
        ]

    def test_dedupes_same_key_ignoring_case(self) -> None:
        campaign = {
            "steps": [
                {"findings": [{"rule_id": "A", "target": "X"}]},
                {"findings": [{"rule_id": "a", "target": "x"}]},
            ]
        }
        assert ui_helpers.campaign_finding_keys(campaign) == [("A", "X")]

    def test_tolerates_broken_structures(self) -> None:
        campaign = {
            "steps": [
                "bad",
                {"findings": "bad"},
                {"findings": [None, 1, {"rule_id": "R"}]},
            ]
        }
        assert ui_helpers.campaign_finding_keys(campaign) == [("R", "")]

    def test_empty_or_invalid_campaign(self) -> None:
        for value in ({}, {"steps": []}, None, "bad"):
            assert ui_helpers.campaign_finding_keys(value) == []

    def test_row_values(self) -> None:
        assert ui_helpers.campaign_row_values(CAMPAIGN) == ("演示攻击链", "高", "2", "3")
        assert ui_helpers.campaign_row_values(None) == ("", "未知", "0", "0")

    def test_step_rows(self) -> None:
        rows = ui_helpers.campaign_step_rows(CAMPAIGN)
        assert rows[0] == ("1", "TA0003", "PERSIST_A, PERSIST_B", r"C:\Users\Public\a.exe; C:\Users\Public\b.exe")
        assert rows[1][0] == "2"
        assert rows[1][1] == "TA0005"
        assert ui_helpers.campaign_step_rows(None) == []


class TestConstants:
    def test_campaign_columns(self) -> None:
        assert ui_helpers.CAMPAIGN_COLUMNS == (
            ("name", "攻击链", 220),
            ("confidence", "置信度", 70),
            ("steps", "步骤", 56),
            ("findings", "Finding", 70),
        )

    def test_empty_text_constant(self) -> None:
        assert ui_helpers.CAMPAIGN_EMPTY_TEXT == "未发现满足固定剧本的攻击链（绝无自由组合）"


class TestCorrelatorIntegration:
    def test_correlate_empty_findings_structure(self) -> None:
        result = correlator.correlate([])
        assert result["campaigns"] == []
        assert result["stats"]["campaigns"] == 0
        assert ui_helpers.campaign_row_values(None) == ("", "未知", "0", "0")

    def test_real_campaign_consumed_by_ui_helpers(self) -> None:
        target = r"C:\Shared\Sample.dll"
        findings = [
            make_finding("HIGH", "Test", target, "d", {}, "TASK_HIDDEN_TARRASK"),
            make_finding("HIGH", "Test", target, "d", {}, "WFP_EDR_SILENCER"),
            make_finding("HIGH", "Test", target, "d", {}, "RDP_SERVICEDLL_TAMPER"),
        ]
        result = correlator.correlate(findings)
        assert result["campaigns"], result
        campaign = result["campaigns"][0]
        name, label, steps, count = ui_helpers.campaign_row_values(campaign)
        assert name
        assert label in ("高", "中", "低", "未知")
        assert int(steps) >= 2
        assert int(count) >= 1
        assert ui_helpers.campaign_finding_keys(campaign)
        assert ui_helpers.campaign_step_rows(campaign)

    def test_partial_campaign_confidence_is_consumable(self) -> None:
        campaign = _campaign(confidence="MEDIUM", steps=[])
        assert ui_helpers.campaign_confidence_label(campaign["confidence"]) == "中"
        assert ui_helpers.campaign_row_values(campaign)[1] == "中"
