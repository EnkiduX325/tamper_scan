# -*- coding: utf-8 -*-
"""V1.4 GUI 攻击链视图（campaign）的**纯函数级**单元测试（不创建 Tk 窗口）。

覆盖范围：

1. ``campaign_confidence_tag`` / ``campaign_confidence_label``：high/medium/low、
   大小写、未知、空值映射；
2. ``CAMPAIGN_CONFIDENCE_COLORS`` 配色映射与 ``CAMPAIGN_COLUMNS`` 列定义常量；
3. ``campaign_summary_text``：正常 campaign、shadow、缺失字段、空/非 dict；
4. ``campaign_finding_keys``：嵌套步骤提取、去重（忽略大小写）、缺字段容错；
5. ``campaign_row_values`` / ``campaign_step_rows``：列表与时间线显示值；
6. ``import gui`` 成功、不创建 Tk 根窗口、``--windowed`` 保护仍在最前；
7. 与真实 ``core.correlator.correlate`` 输出的结构兼容性（correlator 不可用则 skip）。

约束：绝不调用 ``tk.Tk()`` / 实例化 ``App`` / ``CampaignsWindow``；不需要管理员
权限、不启动扫描、不读写真实注册表。

运行方式（仓库根目录）：

    python -m pytest -q tests/test_campaign_gui.py
    python -m unittest tests.test_campaign_gui -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import tkinter

    TKINTER_AVAILABLE = True
except Exception:  # pragma: no cover - 环境相关
    tkinter = None  # type: ignore[assignment]
    TKINTER_AVAILABLE = False

try:
    from core import correlator

    CORRELATOR_AVAILABLE = True
except Exception:  # pragma: no cover - correlator 为 V1.4 并行模块
    correlator = None  # type: ignore[assignment]
    CORRELATOR_AVAILABLE = False

GUI_IMPORT_ERROR: str | None = None
try:
    import gui
except Exception as exc:  # pragma: no cover - 环境相关
    gui = None  # type: ignore[assignment]
    GUI_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

requires_gui = unittest.skipUnless(gui is not None, f"gui 不可导入：{GUI_IMPORT_ERROR}")


def _campaign() -> dict[str, Any]:
    """典型的 correlator campaign 结构（与 core.correlator 契约一致）。"""
    return {
        "chain_id": "CHAIN_TEST",
        "name": "测试攻击链",
        "confidence": "high",
        "steps": [
            {
                "tactic": "T1547.001",
                "rule_ids": ["RUN_REGISTRY", "SVC_SERVICEDLL_TAMPER"],
                "findings": [
                    {"rule_id": "RUN_REGISTRY", "target": "HKCU/.../Run", "severity": "HIGH"},
                    {"rule_id": "SVC_SERVICEDLL_TAMPER", "target": "C:/evil.dll", "severity": "HIGH"},
                ],
            },
            {
                "tactic": "T1055",
                "rule_ids": ["SIG_UNSIGNED"],
                "findings": [
                    {"rule_id": "SIG_UNSIGNED", "target": "C:/loader.exe", "severity": "MEDIUM"},
                ],
            },
        ],
        "finding_count": 3,
        "targets": ["C:/evil.dll", "C:/loader.exe"],
        "shadow": False,
    }


@requires_gui
class ConfidenceMappingTests(unittest.TestCase):
    """置信度 -> tag/中文/颜色 的纯函数映射。"""

    def test_tag_known(self) -> None:
        self.assertEqual(gui.campaign_confidence_tag("high"), "campaign_high")
        self.assertEqual(gui.campaign_confidence_tag("medium"), "campaign_medium")
        self.assertEqual(gui.campaign_confidence_tag("low"), "campaign_low")

    def test_tag_case_insensitive(self) -> None:
        self.assertEqual(gui.campaign_confidence_tag("HIGH"), "campaign_high")
        self.assertEqual(gui.campaign_confidence_tag(" Medium "), "campaign_medium")

    def test_tag_unknown_and_empty(self) -> None:
        for value in ("critical", "", None, "???", 123):
            self.assertEqual(gui.campaign_confidence_tag(value), "")

    def test_label_known(self) -> None:
        self.assertEqual(gui.campaign_confidence_label("high"), "高")
        self.assertEqual(gui.campaign_confidence_label("medium"), "中")
        self.assertEqual(gui.campaign_confidence_label("low"), "低")

    def test_label_unknown_and_empty(self) -> None:
        for value in ("critical", "", None, "???", 123):
            self.assertEqual(gui.campaign_confidence_label(value), "未知")

    def test_confidence_colors_mapping(self) -> None:
        colors = gui.CAMPAIGN_CONFIDENCE_COLORS
        self.assertEqual(set(colors), {"high", "medium", "low"})
        for value in colors.values():
            self.assertTrue(value.startswith("#") and len(value) == 7, f"非法颜色 {value!r}")


@requires_gui
class CampaignSummaryTests(unittest.TestCase):
    """``campaign_summary_text`` 摘要与容错。"""

    def test_summary_text_full(self) -> None:
        text = gui.campaign_summary_text(_campaign())
        self.assertIn("测试攻击链", text)
        self.assertIn("置信度 高", text)
        self.assertIn("2 步", text)
        self.assertIn("3 条 finding", text)

    def test_summary_text_shadow(self) -> None:
        campaign = _campaign()
        campaign["shadow"] = True
        self.assertIn("影子", gui.campaign_summary_text(campaign))

    def test_summary_text_missing_fields(self) -> None:
        campaign = {"chain_id": "CHAIN_ONLY", "steps": "not-a-list"}
        text = gui.campaign_summary_text(campaign)
        self.assertIn("CHAIN_ONLY", text)
        self.assertIn("0 步", text)
        self.assertIn("0 条 finding", text)

    def test_summary_text_computes_count_from_steps(self) -> None:
        campaign = {"name": "X", "steps": [{"findings": [{"rule_id": "A"}, {"rule_id": "B"}]}]}
        self.assertIn("2 条 finding", gui.campaign_summary_text(campaign))

    def test_summary_text_empty_or_invalid(self) -> None:
        for value in (None, {}, "not-a-dict", []):
            self.assertEqual(gui.campaign_summary_text(value), "")


@requires_gui
class CampaignFindingKeysTests(unittest.TestCase):
    """``campaign_finding_keys`` 提取/去重/容错。"""

    def test_extracts_nested_finding_keys(self) -> None:
        keys = gui.campaign_finding_keys(_campaign())
        self.assertEqual(
            keys,
            [
                ("RUN_REGISTRY", "HKCU/.../Run"),
                ("SVC_SERVICEDLL_TAMPER", "C:/evil.dll"),
                ("SIG_UNSIGNED", "C:/loader.exe"),
            ],
        )

    def test_dedupes_same_key_ignoring_case(self) -> None:
        campaign = {
            "steps": [
                {"findings": [{"rule_id": "RULE_A", "target": "C:/X.exe"}]},
                {"findings": [{"rule_id": "rule_a", "target": "c:/x.EXE"}]},
                {"findings": [{"rule_id": "RULE_B", "target": "C:/y.exe"}]},
            ]
        }
        keys = gui.campaign_finding_keys(campaign)
        self.assertEqual(len(keys), 2)
        self.assertEqual(keys[0], ("RULE_A", "C:/X.exe"))
        self.assertEqual(keys[1], ("RULE_B", "C:/y.exe"))

    def test_tolerates_broken_structures(self) -> None:
        campaign = {
            "steps": [
                "not-a-step",
                None,
                {"findings": "not-a-list"},
                {"findings": [None, "x", 42, {}, {"rule_id": "", "target": ""}]},
                {"findings": [{"rule_id": "ONLY_RULE"}, {"target": "C:/only-target"}]},
            ]
        }
        keys = gui.campaign_finding_keys(campaign)
        self.assertEqual(keys, [("ONLY_RULE", ""), ("", "C:/only-target")])

    def test_empty_or_invalid_campaign(self) -> None:
        for value in (None, {}, {"steps": []}, {"steps": None}, "x", []):
            self.assertEqual(gui.campaign_finding_keys(value), [])

    def test_row_values(self) -> None:
        values = gui.campaign_row_values(_campaign())
        self.assertEqual(values[0], "测试攻击链")
        self.assertEqual(values[1], "高")
        self.assertEqual(values[2], "2")
        self.assertEqual(values[3], "3")
        self.assertEqual(gui.campaign_row_values(None), ("", "未知", "0", "0"))

    def test_step_rows(self) -> None:
        rows = gui.campaign_step_rows(_campaign())
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "1")
        self.assertEqual(rows[0][1], "T1547.001")
        self.assertIn("RUN_REGISTRY", rows[0][2])
        self.assertIn("C:/evil.dll", rows[0][3])
        self.assertEqual(gui.campaign_step_rows(None), [])
        self.assertEqual(gui.campaign_step_rows({"steps": "bad"}), [])


@requires_gui
class CampaignConstantsAndImportTests(unittest.TestCase):
    """列定义常量 / import 行为（不创建窗口）。"""

    def test_campaign_columns(self) -> None:
        keys = [column[0] for column in gui.CAMPAIGN_COLUMNS]
        self.assertEqual(keys, ["name", "confidence", "steps", "findings"])
        headers = [column[1] for column in gui.CAMPAIGN_COLUMNS]
        for expected in ("攻击链", "置信度", "步骤", "Finding"):
            self.assertIn(expected, headers)

    def test_empty_text_constant(self) -> None:
        self.assertEqual(gui.CAMPAIGN_EMPTY_TEXT, "未发现满足固定剧本的攻击链（绝无自由组合）")

    def test_app_has_campaign_entrypoints(self) -> None:
        self.assertTrue(hasattr(gui.App, "_on_show_campaigns"))
        self.assertTrue(hasattr(gui.App, "_on_campaign_selected"))
        self.assertTrue(hasattr(gui.FindingTree, "select_by_keys"))
        self.assertTrue(hasattr(gui, "CampaignsWindow"))

    def test_import_does_not_create_tk_root(self) -> None:
        self.assertIsNone(getattr(tkinter, "_default_root", None), "导入 gui 不应创建 Tk 窗口")

    def test_windowed_guard_before_internal_imports(self) -> None:
        source = (PROJECT_ROOT / "gui.py").read_text(encoding="utf-8")
        guard = source.find("if sys.stdout is None")
        self.assertGreaterEqual(guard, 0)
        for marker in ("import reporter", "from core import baseline", "from core import correlator"):
            position = source.find(marker)
            if position >= 0:
                self.assertGreater(position, guard, f"{marker} 必须在 --windowed 保护之后")


@requires_gui
class CorrelatorIntegrationTests(unittest.TestCase):
    """真实 ``core.correlator`` 输出与 GUI 纯函数的兼容性。"""

    @unittest.skipUnless(CORRELATOR_AVAILABLE, "core.correlator 尚未提供（V1.4 并行模块）")
    def test_correlate_empty_findings_structure(self) -> None:
        data = correlator.correlate([])
        self.assertIsInstance(data, dict)
        self.assertIsInstance(data.get("campaigns"), list)
        self.assertIsInstance(data.get("stats"), dict)
        self.assertIsInstance(data.get("suppressed"), list)
        self.assertEqual(data.get("campaigns"), [])
        self.assertEqual(gui.campaign_summary_text({}), "")
        self.assertEqual(gui.campaign_finding_keys({"campaigns": []}), [])

    @unittest.skipUnless(CORRELATOR_AVAILABLE, "core.correlator 尚未提供（V1.4 并行模块）")
    def test_real_campaign_consumed_by_gui_helpers(self) -> None:
        """构造命中固定剧本的真实 findings，验证 campaign 结构与 GUI 纯函数兼容。"""
        target = "C:/fake/chain_target.exe"
        findings = [
            _real_finding("RUN_USERWRITABLE", target),
            _real_finding("SIG_UNSIGNED", target),
            _real_finding("SVC_SERVICEDLL_TAMPER", target),
        ]
        data = correlator.correlate(findings)
        campaigns = [
            campaign
            for campaign in data.get("campaigns") or []
            if campaign.get("chain_id") == "autostart_signature_service_hijack"
        ]
        self.assertTrue(campaigns, "固定剧本 autostart_signature_service_hijack 应命中")
        campaign = campaigns[0]
        self.assertEqual(campaign.get("confidence"), "high")
        self.assertGreaterEqual(int(campaign.get("finding_count") or 0), 3)

        # 1) 摘要/列表值/时间线可安全消费
        summary = gui.campaign_summary_text(campaign)
        self.assertNotEqual(summary, "")
        self.assertIn("置信度 高", summary)
        self.assertIn("3 步", summary)
        row = gui.campaign_row_values(campaign)
        self.assertEqual(row[1], "高")
        self.assertEqual(row[2], "3")
        self.assertEqual(len(gui.campaign_step_rows(campaign)), 3)
        self.assertIn(gui.campaign_confidence_tag(campaign.get("confidence")), CAMPAIGN_TAGS)

        # 2) campaign 关联键与原始 Finding 的 (rule_id, target) 一致（主窗口联动依据）
        keys = gui.campaign_finding_keys(campaign)
        self.assertEqual(len(keys), 3)
        expected = {gui.finding_match_key(finding) for finding in findings}
        actual = {gui.finding_match_key({"rule_id": rule, "target": item_target}) for rule, item_target in keys}
        self.assertEqual(actual, expected)

    @unittest.skipUnless(CORRELATOR_AVAILABLE, "core.correlator 尚未提供（V1.4 并行模块）")
    def test_partial_campaign_confidence_is_consumable(self) -> None:
        """只命中 2/3 步骤时应为 low/medium 置信度，GUI 映射同样安全。"""
        target = "C:/fake/partial_target.exe"
        findings = [
            _real_finding("RUN_USERWRITABLE", target),
            _real_finding("SIG_UNSIGNED", target),
        ]
        data = correlator.correlate(findings)
        for campaign in data.get("campaigns") or []:
            self.assertIn(gui.campaign_confidence_tag(campaign.get("confidence")), CAMPAIGN_TAGS)
            self.assertIsInstance(gui.campaign_finding_keys(campaign), list)
            self.assertNotEqual(gui.campaign_summary_text(campaign), "")


CAMPAIGN_TAGS = frozenset({"", "campaign_high", "campaign_medium", "campaign_low"})


def _real_finding(rule_id: str, target: str) -> dict[str, Any]:
    return {
        "severity": "HIGH",
        "category": "Test",
        "target": target,
        "rule_id": rule_id,
        "detail": "测试用 finding",
        "evidence": {},
    }


if __name__ == "__main__":
    unittest.main(verbosity=2)
