# -*- coding: utf-8 -*-
"""``reporter.apply_baseline_diff`` 与基线对比 HTML 渲染的单元测试（V1.3）。

覆盖范围：

1. ``apply_baseline_diff``：返回新 report 不修改入参、baseline 元信息恰好两个键
   且 path 回退/覆盖、各 Finding 的 diff_status、RESOLVED 条目追加、
   ``summary.diff_counts``、counts/exit_code/total 排除 RESOLVED、hash_tamper
   提升为 HIGH 且 detail 追加提示、其它键保留、未调用时报告结构与 V1.2 一致；
2. ``render_html``（Jinja2）：基线统计区块与数字、状态徽章 class、RESOLVED
   删除线 class、变化警告横幅、UNCHANGED 无横幅、无基线无 diff 标记、autoescape；
3. ``_render_html_fallback``（jinja2 缺失）：同步支持基线统计/徽章/横幅/转义；
4. JSON 可序列化。

约束：不创建 ``tk.Tk()`` 窗口、不需要管理员权限、不访问注册表/网络。

运行方式（仓库根目录）：

    python -m pytest -q tests\\\\test_baseline_report.py
    python -m unittest tests.test_baseline_report -v
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
from core.finding import exit_code_for, make_finding, severity_counts  # noqa: E402

BASE_GENERATED_AT = "2026-01-01T00:00:00+00:00"
BASELINE_PATH = "C:/tmp/baseline_report.json"
HASH_TAMPER_MESSAGE = "签名有效但文件哈希改变，高度疑似被篡改"


def _finding(
    rule_id: str,
    target: str,
    severity: str = "HIGH",
    evidence: dict[str, Any] | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    return make_finding(
        severity,
        "Test",
        target,
        detail or f"{rule_id} 描述",
        evidence or {},
        rule_id,
    )


def _report(*findings: dict[str, Any], generated_at: str = BASE_GENERATED_AT) -> dict[str, Any]:
    return reporter.build_report(list(findings), version="1.3", generated_at=generated_at)


def _diff_scenario() -> tuple[dict[str, Any], dict[str, Any], Any]:
    """构造覆盖 6 种状态的基线/当前报告 + 真实 BaselineDiff。"""
    baseline_findings = [
        _finding("SIG_UNSIGNED", "C:/a.exe", "HIGH", {"signature": {"status": "unsigned"}}),
        _finding("SIG_INVALID", "C:/b.exe", "HIGH", {"signature": {"status": "invalid", "signer": "X"}}),
        _finding("RUN_REGISTRY", "HKCU/run/x", "LOW"),
        _finding("CMD_AUTORUN", "HKCU/cmd", "MEDIUM"),
        _finding("SIG_UNSIGNED", "C:/resolved.exe", "HIGH", {"signature": {"status": "unsigned"}}),
    ]
    current_findings = [
        _finding("SIG_UNSIGNED", "C:/a.exe", "HIGH", {"signature": {"status": "unsigned"}}),
        _finding("SIG_INVALID", "C:/b.exe", "HIGH", {"signature": {"status": "invalid", "signer": "Y"}}),
        _finding("RUN_REGISTRY", "HKCU/run/x", "HIGH"),
        _finding("CMD_AUTORUN", "HKCU/cmd", "LOW"),
        _finding("SIG_INVALID", "C:/new.exe", "HIGH"),
    ]
    baseline_report = _report(*baseline_findings)
    current_report = _report(*current_findings)
    diff = baseline.diff_reports(baseline_report, current_report, baseline_path=BASELINE_PATH)
    return baseline_report, current_report, diff


def _status_map(findings: list[dict[str, Any]]) -> dict[tuple[str, str], str | None]:
    return {(item["rule_id"], item["target"]): item.get("diff_status") for item in findings}


class ApplyBaselineDiffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline_report, cls.current_report, cls.diff = _diff_scenario()
        cls.enriched = reporter.apply_baseline_diff(cls.current_report, cls.diff)

    # -- 不修改入参 / 返回新对象 -------------------------------------------
    def test_returns_new_report_without_mutating_input(self) -> None:
        snapshot = json.loads(json.dumps(self.current_report, ensure_ascii=False))
        enriched = reporter.apply_baseline_diff(self.current_report, self.diff)
        self.assertIsNot(enriched, self.current_report)
        self.assertEqual(json.loads(json.dumps(self.current_report, ensure_ascii=False)), snapshot)
        self.assertNotIn("baseline", self.current_report)
        self.assertNotIn("diff_counts", self.current_report["summary"])
        self.assertNotIn("diff_status", self.current_report["findings"][0])

    # -- baseline 元信息 --------------------------------------------------
    def test_baseline_metadata_has_exactly_two_keys(self) -> None:
        meta = self.enriched["baseline"]
        self.assertEqual(set(meta), {"path", "generated_at"})
        self.assertEqual(meta["path"], BASELINE_PATH)
        self.assertEqual(meta["generated_at"], BASE_GENERATED_AT)

    def test_baseline_path_falls_back_to_diff_meta(self) -> None:
        enriched = reporter.apply_baseline_diff(self.current_report, self.diff, baseline_path="")
        self.assertEqual(enriched["baseline"]["path"], BASELINE_PATH)

    def test_baseline_path_argument_overrides(self) -> None:
        enriched = reporter.apply_baseline_diff(self.current_report, self.diff, baseline_path="/override/base.json")
        self.assertEqual(enriched["baseline"]["path"], "/override/base.json")

    # -- 每种 diff_status -------------------------------------------------
    def test_each_finding_gets_expected_diff_status(self) -> None:
        statuses = _status_map(self.enriched["findings"])
        self.assertEqual(statuses[("SIG_UNSIGNED", "C:/a.exe")], "UNCHANGED")
        self.assertEqual(statuses[("SIG_INVALID", "C:/b.exe")], "MODIFIED")
        self.assertEqual(statuses[("RUN_REGISTRY", "HKCU/run/x")], "ESCALATED")
        self.assertEqual(statuses[("CMD_AUTORUN", "HKCU/cmd")], "DOWNGRADED")
        self.assertEqual(statuses[("SIG_INVALID", "C:/new.exe")], "NEW")
        self.assertEqual(statuses[("SIG_UNSIGNED", "C:/resolved.exe")], "RESOLVED")

    def test_resolved_baseline_entry_is_appended(self) -> None:
        resolved = [
            item
            for item in self.enriched["findings"]
            if item.get("diff_status") == baseline.DIFF_RESOLVED
        ]
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0]["target"], "C:/resolved.exe")
        self.assertEqual(resolved[0]["severity"], "HIGH")
        self.assertTrue(resolved[0]["evidence"].get("resolved"))

    # -- summary ----------------------------------------------------------
    def test_summary_diff_counts(self) -> None:
        counts = self.enriched["summary"]["diff_counts"]
        self.assertEqual(set(counts), set(baseline.DIFF_STATUSES))
        self.assertEqual(
            counts,
            {
                "NEW": 1,
                "MODIFIED": 1,
                "ESCALATED": 1,
                "DOWNGRADED": 1,
                "RESOLVED": 1,
                "UNCHANGED": 1,
            },
        )

    def test_summary_counts_and_exit_code_exclude_resolved(self) -> None:
        current = [
            item for item in self.enriched["findings"] if item.get("diff_status") != baseline.DIFF_RESOLVED
        ]
        summary = self.enriched["summary"]
        self.assertEqual(summary["total"], len(current))
        self.assertEqual(summary["counts"], severity_counts(current))
        self.assertEqual(summary["exit_code"], exit_code_for(current))
        # 当前扫描：4 条 HIGH + 1 条 LOW；RESOLVED 的 HIGH 不参与统计
        self.assertEqual(summary["total"], 5)
        self.assertEqual(summary["counts"]["HIGH"], 4)
        self.assertEqual(summary["counts"]["LOW"], 1)
        self.assertEqual(summary["exit_code"], 2)

    def test_resolved_only_scenario_does_not_raise_exit_code(self) -> None:
        baseline_report = _report(_finding("SIG_UNSIGNED", "C:/gone.exe", "HIGH"))
        current_report = _report()
        diff = baseline.diff_reports(baseline_report, current_report, baseline_path=BASELINE_PATH)
        enriched = reporter.apply_baseline_diff(current_report, diff)
        self.assertEqual(enriched["summary"]["diff_counts"]["RESOLVED"], 1)
        self.assertEqual(enriched["summary"]["counts"], severity_counts([]))
        self.assertEqual(enriched["summary"]["total"], 0)
        self.assertEqual(enriched["summary"]["exit_code"], 0)
        self.assertEqual(len(enriched["findings"]), 1)

    def test_other_summary_and_report_keys_are_preserved(self) -> None:
        report = dict(self.current_report)
        report["custom_top_key"] = {"keep": True}
        report["summary"] = dict(report["summary"])
        report["summary"]["custom_summary_key"] = "keep"
        enriched = reporter.apply_baseline_diff(report, self.diff)
        self.assertEqual(enriched["custom_top_key"], {"keep": True})
        self.assertEqual(enriched["summary"]["custom_summary_key"], "keep")
        self.assertEqual(enriched["summary"]["total"], 5)

    # -- hash_tamper ------------------------------------------------------
    def test_hash_tamper_escalates_to_high_and_appends_detail(self) -> None:
        old_sha = "a" * 64
        new_sha = "b" * 64
        signature = {"status": "valid", "signer": "Microsoft Windows"}
        baseline_report = _report(
            _finding("SIG_MODIFIED", "C:/hash.exe", "MEDIUM", {"signature": signature, "sha256": old_sha})
        )
        current_report = _report(
            _finding(
                "SIG_MODIFIED",
                "C:/hash.exe",
                "MEDIUM",
                {"signature": signature, "sha256": new_sha},
                detail="文件签名校验通过",
            )
        )
        diff = baseline.diff_reports(baseline_report, current_report, baseline_path=BASELINE_PATH)
        enriched = reporter.apply_baseline_diff(current_report, diff)
        finding = enriched["findings"][0]
        self.assertEqual(finding["diff_status"], baseline.DIFF_MODIFIED)
        self.assertEqual(finding["severity"], "HIGH")
        self.assertIn(HASH_TAMPER_MESSAGE, finding["detail"])
        self.assertTrue(finding["evidence"].get("hash_tamper"))
        self.assertEqual(finding["evidence"].get("baseline_sha256"), old_sha)

    # -- 兜底与序列化 -----------------------------------------------------
    def test_apply_with_non_diff_does_not_raise(self) -> None:
        enriched = reporter.apply_baseline_diff(self.current_report, None)
        self.assertIn("baseline", enriched)
        self.assertEqual(set(enriched["summary"]["diff_counts"]), set(baseline.DIFF_STATUSES))
        self.assertEqual(sum(enriched["summary"]["diff_counts"].values()), 0)
        self.assertNotIn("diff_status", enriched["findings"][0])

    def test_report_json_is_serializable(self) -> None:
        parsed = json.loads(reporter.render_json(self.enriched))
        self.assertEqual(parsed["baseline"]["path"], BASELINE_PATH)
        self.assertIn("diff_status", parsed["findings"][0])
        self.assertEqual(parsed["summary"]["diff_counts"]["NEW"], 1)

    def test_build_report_without_apply_has_no_diff_keys(self) -> None:
        report = _report(_finding("SIG_UNSIGNED", "C:/x.exe"))
        self.assertNotIn("baseline", report)
        self.assertNotIn("diff_counts", report["summary"])
        for finding in report["findings"]:
            self.assertNotIn("diff_status", finding)


class HtmlBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline_report, cls.current_report, cls.diff = _diff_scenario()
        cls.enriched = reporter.apply_baseline_diff(cls.current_report, cls.diff)
        cls.html = reporter.render_html(cls.enriched)

    def _one_status_report(self, status_findings: list[dict[str, Any]]) -> dict[str, Any]:
        baseline_report = _report(*status_findings)
        current_report = _report(*status_findings)
        diff = baseline.diff_reports(baseline_report, current_report, baseline_path=BASELINE_PATH)
        return reporter.apply_baseline_diff(current_report, diff)

    def test_html_has_baseline_stats_section(self) -> None:
        html = self.html
        self.assertIn("基线对比", html)
        self.assertIn("baseline_report.json", html)
        self.assertIn(BASE_GENERATED_AT, html)
        for status in ("NEW", "MODIFIED", "ESCALATED", "DOWNGRADED", "RESOLVED"):
            self.assertIn(f"diff-count diff-count-{status}\">1</td>", html)

    def test_html_has_diff_status_badges(self) -> None:
        for status in ("NEW", "MODIFIED", "ESCALATED", "DOWNGRADED", "RESOLVED"):
            self.assertIn(f'<span class="diff-badge diff-badge-{status} diff-status-{status}">{status}</span>', self.html)

    def test_html_resolved_has_strikethrough_class(self) -> None:
        self.assertIn('<details class="finding sev-border-HIGH is-resolved"', self.html)
        self.assertIn(".is-resolved .rule, .is-resolved .target, .is-resolved .detail", self.html)
        self.assertIn("text-decoration: line-through", self.html)

    def test_html_has_warning_banner_for_changed_items(self) -> None:
        changed = (
            self.enriched["summary"]["diff_counts"]["NEW"]
            + self.enriched["summary"]["diff_counts"]["MODIFIED"]
            + self.enriched["summary"]["diff_counts"]["ESCALATED"]
            + self.enriched["summary"]["diff_counts"]["DOWNGRADED"]
            + self.enriched["summary"]["diff_counts"]["RESOLVED"]
        )
        self.assertGreater(changed, 0)
        self.assertEqual(self.html.count("此项目与基线相比发生变化"), changed)
        self.assertIn("⚠️ 此项目与基线相比发生变化", self.html)

    def test_html_unchanged_has_no_badge_or_banner(self) -> None:
        report = self._one_status_report([_finding("SIG_UNSIGNED", "C:/same.exe", "HIGH")])
        html = reporter.render_html(report)
        self.assertIn("基线对比", html)
        self.assertNotIn('<span class="diff-badge', html)
        self.assertNotIn("此项目与基线相比发生变化", html)

    def test_html_without_baseline_has_no_diff_markers(self) -> None:
        html = reporter.render_html(self.current_report)
        self.assertNotIn("基线对比", html)
        self.assertNotIn('<span class="diff-badge', html)
        self.assertNotIn("此项目与基线相比发生变化", html)
        self.assertNotIn("diff-", html)

    def test_html_autoescapes_baseline_fields(self) -> None:
        baseline_report = _report(
            _finding("SIG_UNSIGNED", "C:/x.exe"),
            generated_at="<script>alert('at')</script>",
        )
        current_report = _report(_finding("SIG_UNSIGNED", "C:/x.exe"))
        diff = baseline.diff_reports(
            baseline_report,
            current_report,
            baseline_path="<script>alert('path')</script>.json",
        )
        enriched = reporter.apply_baseline_diff(current_report, diff)
        html = reporter.render_html(enriched)
        self.assertNotIn("<script>alert(", html)
        self.assertIn("&lt;script&gt;alert(", html)

    def test_fallback_html_supports_baseline(self) -> None:
        with mock.patch.object(reporter, "JINJA2_AVAILABLE", False):
            html = reporter.render_html(self.enriched)
        self.assertIn("基线对比", html)
        self.assertIn('diff-badge-NEW', html)
        self.assertIn("diff-status-RESOLVED", html)
        self.assertIn("is-resolved", html)
        self.assertIn("line-through", html)
        self.assertIn("⚠️ 此项目与基线相比发生变化", html)

    def test_fallback_html_without_baseline_has_no_diff_markers(self) -> None:
        with mock.patch.object(reporter, "JINJA2_AVAILABLE", False):
            html = reporter.render_html(self.current_report)
        self.assertNotIn("基线对比", html)
        self.assertNotIn("diff-", html)
        self.assertNotIn("此项目与基线相比发生变化", html)


if __name__ == "__main__":
    unittest.main()
