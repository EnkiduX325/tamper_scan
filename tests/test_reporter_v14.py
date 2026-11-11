# -*- coding: utf-8 -*-
"""``reporter.py`` V1.4 新增能力的单元测试：HTML 攻击链时间线 + BENIGN_UPDATE 展示。

覆盖范围：

1. B2（良性版本前进）：
   - ``diff_status == "BENIGN_UPDATE"`` -> 中性/绿色徽章 ``diff-badge-BENIGN_UPDATE``，
     **不出现**「⚠️ 此项目与基线相比发生变化」横幅，详情显示「版本正常前进（自动更新）」；
   - ``summary.diff_counts`` 的七状态（含 BENIGN_UPDATE）正常渲染；
   - ``diff_status == "MODIFIED"`` 且 ``evidence.version_bump`` -> 横幅改为
     「版本正常前进（已降级为 MEDIUM）」，不再出现红色告警措辞。
2. C3（攻击链 Campaigns）：
   - ``report["campaigns"]`` 非空 -> ``section.campaigns`` 纯 CSS 时间线渲染，
     且位于 ``section.findings`` 之前；卡片含 name/chain_id、confidence 徽章、
     steps（tactic/rule_ids/findings 的 rule_id+target）、finding_count/targets；
   - ``campaign_shadow`` 或 campaign.shadow -> ``campaign-shadow`` class +「影子模式（仅记录）」；
   - ``campaign_stats`` -> clusters/campaigns/suppressed 统计；
   - 无 campaigns / 无 baseline 时 HTML 与 V1.3 一致（无 campaign/diff 标记）。
3. 安全性：Jinja2 autoescape 与 ``_render_html_fallback`` 均对 campaign name/target
   等攻击者可控字符串做转义（<script> 被转义）。
4. JSON 可序列化（campaigns / diff_status 字段）。

约束：不创建 ``tk.Tk()`` 窗口、不需要管理员权限、不访问注册表/网络。

运行方式（仓库根目录）：

    python -m pytest -q tests\\\\test_reporter_v14.py
    python -m unittest tests.test_reporter_v14 -v
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import reporter  # noqa: E402
from core import baseline  # noqa: E402
from core.finding import make_finding  # noqa: E402

BASE_GENERATED_AT = "2026-02-02T00:00:00+00:00"
BASELINE_PATH = "C:/tmp/base_report.json"
WARNING_TEXT = "此项目与基线相比发生变化"


def _finding(
    rule_id: str = "SIG_UNSIGNED",
    target: str = "C:/x.exe",
    severity: str = "LOW",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return make_finding(severity, "Test", target, f"{rule_id} 描述", evidence or {}, rule_id)


def _report(*findings: dict[str, Any]) -> dict[str, Any]:
    return reporter.build_report(list(findings), version="1.4", generated_at=BASE_GENERATED_AT)


def _with_status(
    status: str,
    evidence: dict[str, Any] | None = None,
    severity: str = "LOW",
    rule_id: str = "SIG_UNSIGNED",
    target: str = "C:/x.exe",
) -> dict[str, Any]:
    """构造一条指定 diff_status 的报告（用真实 BaselineDiff 走 apply_baseline_diff）。

    说明：BENIGN_UPDATE 由 baseline-dev 在 core.baseline 并行增强；这里用
    ``DiffEntry(status="BENIGN_UPDATE")`` 构造真实 diff，并确保 summary.diff_counts
    含该键，使 reporter 的渲染逻辑可独立验证（baseline 合入后行为一致）。
    """
    report = _report(_finding(rule_id, target, severity, evidence))
    finding = report["findings"][0]
    entry = baseline.DiffEntry(
        target=finding["target"],
        rule_base=rule_id,
        status=status,
        current_severity=severity,
        current_finding=finding,
    )
    diff = baseline.BaselineDiff(
        entries=[entry],
        counts={status: 1},
        baseline_meta={"path": BASELINE_PATH, "generated_at": BASE_GENERATED_AT},
    )
    enriched = reporter.apply_baseline_diff(report, diff)
    enriched["summary"]["diff_counts"].setdefault(status, 1)
    return enriched


def _campaign(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": "横向移动攻击链",
        "chain_id": "CHAIN-001",
        "confidence": "high",
        "steps": [
            {
                "tactic": "初始访问",
                "rule_ids": ["SIG_UNSIGNED"],
                "findings": [{"rule_id": "SIG_UNSIGNED", "target": "C:/evil.exe"}],
            },
            {
                "tactic": "持久化",
                "rule_ids": ["RUN_REGISTRY"],
                "findings": [{"rule_id": "RUN_REGISTRY", "target": "HKCU/Run/Updater"}],
            },
        ],
        "finding_count": 2,
        "targets": ["C:/evil.exe", "HKCU/Run/Updater"],
    }
    payload.update(overrides)
    return payload


def _campaign_report(
    campaigns: list[dict[str, Any]] | None = None,
    stats: dict[str, Any] | None = None,
    shadow: bool | None = None,
) -> dict[str, Any]:
    report = _report(_finding())
    report["campaigns"] = [_campaign()] if campaigns is None else campaigns
    if stats is not None:
        report["campaign_stats"] = stats
    if shadow is not None:
        report["campaign_shadow"] = shadow
    return report


class BenignUpdateTests(unittest.TestCase):
    def test_benign_update_badge_without_warning_banner(self) -> None:
        html = reporter.render_html(_with_status("BENIGN_UPDATE"))
        self.assertIn("diff-badge-BENIGN_UPDATE", html)
        self.assertIn("diff-status-BENIGN_UPDATE", html)
        self.assertIn("BENIGN_UPDATE", html)
        self.assertNotIn(WARNING_TEXT, html)

    def test_benign_update_shows_version_note(self) -> None:
        # V1.5 rc2：BENIGN_UPDATE 的“版本正常前进”文案仅在 evidence.version_bump 时展示
        html = reporter.render_html(_with_status("BENIGN_UPDATE", {"version_bump": True}))
        self.assertIn("版本正常前进（自动更新）", html)

    def test_benign_update_diff_counts_renders_seven_statuses(self) -> None:
        html = reporter.render_html(_with_status("BENIGN_UPDATE"))
        for status in ("NEW", "MODIFIED", "ESCALATED", "DOWNGRADED", "RESOLVED", "BENIGN_UPDATE", "UNCHANGED"):
            self.assertIn(f"diff-count-{status}", html)
        self.assertIn('diff-count diff-count-BENIGN_UPDATE">1</td>', html)

    def test_modified_with_version_bump_uses_neutral_banner(self) -> None:
        html = reporter.render_html(_with_status("MODIFIED", {"version_bump": True}, severity="MEDIUM"))
        self.assertIn("diff-badge-MODIFIED", html)
        self.assertIn("版本正常前进（已降级为 MEDIUM）", html)
        self.assertNotIn(WARNING_TEXT, html)
        self.assertNotIn("⚠️ 此项目与基线相比发生变化", html)

    def test_modified_without_version_bump_keeps_warning(self) -> None:
        html = reporter.render_html(_with_status("MODIFIED", {}))
        self.assertIn("⚠️ 此项目与基线相比发生变化", html)
        self.assertNotIn("版本正常前进", html)

    def test_benign_update_fallback_rendering(self) -> None:
        with mock.patch.object(reporter, "JINJA2_AVAILABLE", False):
            html = reporter.render_html(_with_status("BENIGN_UPDATE", {"version_bump": True}))
        self.assertIn("diff-badge-BENIGN_UPDATE", html)
        self.assertIn("版本正常前进（自动更新）", html)
        self.assertNotIn(WARNING_TEXT, html)

    def test_version_bump_fallback_rendering(self) -> None:
        with mock.patch.object(reporter, "JINJA2_AVAILABLE", False):
            html = reporter.render_html(_with_status("MODIFIED", {"version_bump": True}))
        self.assertIn("版本正常前进（已降级为 MEDIUM）", html)
        self.assertNotIn(WARNING_TEXT, html)


class CampaignTests(unittest.TestCase):
    def test_campaigns_section_rendered_before_findings(self) -> None:
        html = reporter.render_html(_campaign_report())
        self.assertIn('<section class="campaigns">', html)
        self.assertIn("攻击链（Campaigns）", html)
        self.assertLess(
            html.index('<section class="campaigns">'),
            html.index('<section class="findings">'),
        )

    def test_campaign_steps_timeline_and_rules(self) -> None:
        html = reporter.render_html(_campaign_report())
        for token in (
            "campaign-timeline",
            "campaign-step",
            "campaign-step-tactic",
            "campaign-step-rules",
            "campaign-step-findings",
            "初始访问",
            "持久化",
            "SIG_UNSIGNED",
            "RUN_REGISTRY",
            "C:/evil.exe",
            "HKCU/Run/Updater",
        ):
            self.assertIn(token, html)

    def test_campaign_confidence_badges(self) -> None:
        campaigns = [
            _campaign(name="高置信", chain_id="C-HIGH", confidence="high"),
            _campaign(name="中置信", chain_id="C-MED", confidence="medium"),
            _campaign(name="低置信", chain_id="C-LOW", confidence="low"),
        ]
        html = reporter.render_html(_campaign_report(campaigns=campaigns))
        self.assertIn("campaign-confidence-high", html)
        self.assertIn("campaign-confidence-medium", html)
        self.assertIn("campaign-confidence-low", html)

    def test_campaign_summary_counts_and_targets(self) -> None:
        html = reporter.render_html(_campaign_report())
        self.assertIn("关联 Finding：2", html)
        self.assertIn("目标：", html)
        self.assertIn("C:/evil.exe", html)
        self.assertIn("HKCU/Run/Updater", html)

    def test_campaign_stats_rendered(self) -> None:
        html = reporter.render_html(_campaign_report(stats={"clusters": 3, "campaigns": 1, "suppressed": 2}))
        self.assertIn("campaign-stats", html)
        self.assertIn("clusters 3", html)
        self.assertIn("campaigns 1", html)
        self.assertIn("suppressed 2", html)

    def test_shadow_campaign_report_level(self) -> None:
        html = reporter.render_html(_campaign_report(shadow=True))
        self.assertIn("campaign-shadow", html)
        self.assertIn("影子模式（仅记录）", html)

    def test_shadow_campaign_per_campaign_flag(self) -> None:
        html = reporter.render_html(_campaign_report(campaigns=[_campaign(shadow=True)]))
        self.assertIn("campaign-card campaign-shadow", html)
        self.assertIn("影子模式（仅记录）", html)

    def test_campaigns_render_without_baseline(self) -> None:
        report = _campaign_report()
        html = reporter.render_html(report)
        self.assertNotIn("基线对比", html)
        self.assertIn('<section class="campaigns">', html)

    def test_campaign_structure_tolerance(self) -> None:
        campaign = {
            "chain_id": "CHAIN-X",
            "confidence": 0.8,
            "steps": [{"findings": [{"rule_id": "SIG_INVALID", "target": "C:/tol.exe"}]}],
            "targets": "C:/tol.exe",
        }
        html = reporter.render_html(_campaign_report(campaigns=[campaign]))
        self.assertIn("CHAIN-X", html)
        self.assertIn("campaign-confidence-high", html)
        self.assertIn("SIG_INVALID", html)
        self.assertIn("C:/tol.exe", html)

    def test_campaign_autoescape_in_jinja(self) -> None:
        campaign = _campaign(
            name="<script>alert(1)</script>",
            chain_id="CHAIN<script>",
            steps=[
                {
                    "tactic": "<b>tactic</b>",
                    "rule_ids": ["<script>rule</script>"],
                    "findings": [{"rule_id": "SIG_UNSIGNED", "target": "<script>alert(2)</script>"}],
                }
            ],
            targets=["<script>alert(3)</script>"],
        )
        html = reporter.render_html(_campaign_report(campaigns=[campaign]))
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<script>alert(2)</script>", html)
        self.assertNotIn("<script>alert(3)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)

    def test_campaign_autoescape_in_fallback(self) -> None:
        campaign = _campaign(
            name="<script>alert(1)</script>",
            steps=[{"tactic": "t", "findings": [{"rule_id": "R", "target": "<script>alert(2)</script>"}]}],
            targets=["<script>alert(3)</script>"],
        )
        with mock.patch.object(reporter, "JINJA2_AVAILABLE", False):
            html = reporter.render_html(_campaign_report(campaigns=[campaign]))
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<script>alert(2)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)

    def test_campaigns_fallback_rendering(self) -> None:
        with mock.patch.object(reporter, "JINJA2_AVAILABLE", False):
            html = reporter.render_html(_campaign_report(shadow=True, stats={"clusters": 1, "campaigns": 1}))
        self.assertIn('<section class="campaigns">', html)
        self.assertIn("攻击链（Campaigns）", html)
        self.assertIn("campaign-timeline", html)
        self.assertIn("campaign-shadow", html)
        self.assertIn("影子模式（仅记录）", html)
        self.assertIn("初始访问", html)
        self.assertIn("clusters 1", html)


class DefaultCompatibilityTests(unittest.TestCase):
    def test_default_html_has_no_v14_markers(self) -> None:
        html = reporter.render_html(_report(_finding()))
        for marker in ("diff-", "campaign", "BENIGN_UPDATE", "基线对比", "攻击链"):
            self.assertNotIn(marker, html)

    def test_default_fallback_html_has_no_v14_markers(self) -> None:
        with mock.patch.object(reporter, "JINJA2_AVAILABLE", False):
            html = reporter.render_html(_report(_finding()))
        for marker in ("diff-", "campaign", "BENIGN_UPDATE", "基线对比", "攻击链"):
            self.assertNotIn(marker, html)

    def test_json_serializable_with_campaigns_and_diff_status(self) -> None:
        report = _with_status("BENIGN_UPDATE")
        report["campaigns"] = [_campaign()]
        report["campaign_stats"] = {"clusters": 1, "campaigns": 1, "suppressed": 0}
        parsed = json.loads(reporter.render_json(report))
        self.assertEqual(len(parsed["campaigns"]), 1)
        self.assertEqual(parsed["campaigns"][0]["chain_id"], "CHAIN-001")
        self.assertEqual(parsed["findings"][0]["diff_status"], "BENIGN_UPDATE")
        self.assertEqual(parsed["summary"]["diff_counts"]["BENIGN_UPDATE"], 1)


if __name__ == "__main__":
    unittest.main()
