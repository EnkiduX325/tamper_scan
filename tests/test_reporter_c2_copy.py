# -*- coding: utf-8 -*-
"""HTML 报告 BENIGN_UPDATE / C2 中性文案测试（V1.5 rc2 任务 D）。

覆盖：
1. C2 命中（``evidence.recent_system_update=True``）→ 显示“系统更新时间窗内变更”，
   不出现“版本正常前进”；
2. ``evidence.version_bump=True`` → 保持“版本正常前进”；
3. 两者都不命中 → 中性“良性更新（BENIGN_UPDATE）”；
4. 非 BENIGN_UPDATE 的 HTML 与 rc1 快照逐字节一致。
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import reporter  # noqa: E402
from core.finding import make_finding  # noqa: E402

FIXTURES = PROJECT_ROOT / "tests" / "fixtures"
GENERATED_AT = "2026-11-11T00:00:00+00:00"


def _render(status: str, **evidence: object) -> str:
    finding = make_finding(
        "HIGH", "TestCategory", r"C:\Test\target.exe", "BENIGN 文案测试", dict(evidence), "TEST_RULE"
    )
    finding["diff_status"] = status
    report = reporter.build_report(
        [finding], version="1.5.0", duration_seconds=0.0, modules=[], generated_at=GENERATED_AT
    )
    return reporter.render_html(report)


def test_c2_recent_update_uses_system_update_copy() -> None:
    html = _render("BENIGN_UPDATE", recent_system_update=True)
    assert "系统更新时间窗内变更（BENIGN_UPDATE）" in html
    assert "版本正常前进" not in html


def test_version_bump_keeps_version_copy() -> None:
    html = _render("BENIGN_UPDATE", version_bump=True)
    assert "版本正常前进（自动更新）" in html
    assert "系统更新时间窗内变更" not in html


def test_benign_without_flags_uses_neutral_copy() -> None:
    html = _render("BENIGN_UPDATE")
    assert "良性更新（BENIGN_UPDATE）" in html
    assert "版本正常前进" not in html
    assert "系统更新时间窗内变更" not in html


def test_non_benign_html_is_byte_identical_to_rc1() -> None:
    fixture = FIXTURES / "reporter_non_benign_rc1.html"
    assert fixture.is_file(), "缺少 rc1 非 BENIGN HTML 快照 fixture"
    finding = make_finding(
        "HIGH", "TestCategory", r"C:\Test\target.exe", "非 BENIGN 文案回归样本", {"actual": "value"}, "TEST_RULE"
    )
    finding["diff_status"] = "MODIFIED"
    report = reporter.build_report(
        [finding], version="1.5.0", duration_seconds=0.0, modules=[], generated_at=GENERATED_AT
    )
    assert reporter.render_html(report) == fixture.read_text(encoding="utf-8")
