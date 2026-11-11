# -*- coding: utf-8 -*-
"""``core.ui_helpers`` 基线/diff 纯函数测试（V1.5 rc2 自 V1.4 test_baseline_gui.py 迁移）。

覆盖：
- ``load_baseline_file``：合法/缺失/坏 JSON/根节点非 dict/缺 findings/findings 非 list/
  空路径/BOM/真实 reporter 报告；
- ``diff_status_tag`` / ``finding_status_tag`` / ``baseline_label_text`` 映射与容错；
- ``STATUS_COLUMN`` / ``FINDING_COLUMNS`` 列定义；
- 与 ``core.baseline.annotate_findings`` 的集成。

不包含任何 Tkinter 导入/窗口创建。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_ui_helpers_baseline.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import reporter  # noqa: E402
from core import baseline, ui_helpers  # noqa: E402
from core.finding import make_finding  # noqa: E402


def _write(tmp_path: Path, payload: object, name: str = "baseline.json") -> Path:
    target = tmp_path / name
    target.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return target


class TestLoadBaselineFile:
    def test_load_valid_report(self, tmp_path: Path) -> None:
        path = _write(tmp_path, {"tool": "TamperScan", "version": "1.5.0", "findings": []})
        report, error = ui_helpers.load_baseline_file(path)
        assert error is None
        assert report is not None and report["tool"] == "TamperScan"

    def test_load_missing_file_returns_reason(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.json"
        report, error = ui_helpers.load_baseline_file(str(missing))
        assert report is None
        assert error == f"基线文件不存在：{missing}"

    def test_load_invalid_json_returns_reason(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{broken", encoding="utf-8")
        report, error = ui_helpers.load_baseline_file(path)
        assert report is None
        assert error is not None and error.startswith("基线文件不是合法 JSON（")

    def test_load_root_not_dict_returns_reason(self, tmp_path: Path) -> None:
        path = _write(tmp_path, [])
        report, error = ui_helpers.load_baseline_file(path)
        assert report is None
        assert error is not None and "根节点" in error

    def test_load_missing_findings_returns_reason(self, tmp_path: Path) -> None:
        path = _write(tmp_path, {"tool": "TamperScan"})
        report, error = ui_helpers.load_baseline_file(path)
        assert report is None
        assert error is not None and "findings" in error

    def test_load_findings_not_list_returns_reason(self, tmp_path: Path) -> None:
        path = _write(tmp_path, {"tool": "TamperScan", "findings": {}})
        report, error = ui_helpers.load_baseline_file(path)
        assert report is None
        assert error is not None and "findings" in error

    def test_load_empty_path_returns_reason(self) -> None:
        assert ui_helpers.load_baseline_file("") == (None, "未选择基线文件")
        assert ui_helpers.load_baseline_file(None) == (None, "未选择基线文件")

    def test_load_accepts_utf8_bom(self, tmp_path: Path) -> None:
        path = tmp_path / "bom.json"
        payload = {"tool": "TamperScan", "version": "1.5.0", "findings": []}
        path.write_bytes(b"\xef\xbb\xbf" + json.dumps(payload).encode("utf-8"))
        report, error = ui_helpers.load_baseline_file(path)
        assert error is None and report == payload

    def test_load_reporter_built_report(self, tmp_path: Path) -> None:
        finding = make_finding("LOW", "Test", r"C:\a.exe", "detail", {}, "TEST_RULE")
        report = reporter.build_report([finding], version="1.5.0", generated_at="2026-11-11T00:00:00+00:00")
        path = _write(tmp_path, report)
        loaded, error = ui_helpers.load_baseline_file(path)
        assert error is None and loaded is not None
        assert loaded["findings"][0]["rule_id"] == "TEST_RULE"


class TestDiffStatusMapping:
    def test_known_status_tags(self) -> None:
        assert ui_helpers.diff_status_tag("NEW") == "diff_new"
        assert ui_helpers.diff_status_tag("MODIFIED") == "diff_modified"
        assert ui_helpers.diff_status_tag("ESCALATED") == "diff_escalated"
        assert ui_helpers.diff_status_tag("DOWNGRADED") == "diff_downgraded"
        assert ui_helpers.diff_status_tag("RESOLVED") == "diff_resolved"

    def test_status_tag_is_case_insensitive_and_strips(self) -> None:
        assert ui_helpers.diff_status_tag(" new ") == "diff_new"
        assert ui_helpers.diff_status_tag("resolved") == "diff_resolved"

    def test_no_tag_for_unchanged_empty_and_unknown(self) -> None:
        for status in ("UNCHANGED", "", None, "???", 0):
            assert ui_helpers.diff_status_tag(status) is None

    def test_unchanged_not_in_tag_mapping(self) -> None:
        assert baseline.DIFF_UNCHANGED not in ui_helpers.DIFF_STATUS_TAGS
        assert set(ui_helpers.DIFF_STATUS_TAGS) == {
            baseline.DIFF_NEW,
            baseline.DIFF_MODIFIED,
            baseline.DIFF_ESCALATED,
            baseline.DIFF_DOWNGRADED,
            baseline.DIFF_RESOLVED,
        }

    def test_finding_status_tag_without_baseline(self) -> None:
        assert ui_helpers.finding_status_tag({"rule_id": "R"}) is None
        assert ui_helpers.finding_status_tag({"diff_status": ""}) is None

    def test_finding_status_tag_with_baseline(self) -> None:
        assert ui_helpers.finding_status_tag({"diff_status": "NEW"}) == "diff_new"
        assert ui_helpers.finding_status_tag({"diff_status": "resolved"}) == "diff_resolved"

    def test_finding_status_tag_non_dict(self) -> None:
        for value in (None, "NEW", 1, []):
            assert ui_helpers.finding_status_tag(value) is None

    def test_baseline_label_text(self) -> None:
        assert ui_helpers.baseline_label_text(r"C:\data\base.json") == "对比基线: base.json"
        assert ui_helpers.baseline_label_text("/tmp/reports/nightly.json") == "对比基线: nightly.json"

    def test_baseline_label_text_empty(self) -> None:
        for value in ("", None, "   "):
            assert ui_helpers.baseline_label_text(value) == "对比基线: （未加载）"


class TestStatusColumnDefinition:
    def test_status_column_constant(self) -> None:
        assert ui_helpers.STATUS_COLUMN == ("status", "状态", 76)

    def test_finding_columns_include_status(self) -> None:
        keys = [column[0] for column in ui_helpers.FINDING_COLUMNS]
        assert "status" in keys

    def test_status_column_after_severity(self) -> None:
        keys = [column[0] for column in ui_helpers.FINDING_COLUMNS]
        assert keys.index("status") == keys.index("severity") + 1

    def test_legacy_columns_preserved(self) -> None:
        keys = [column[0] for column in ui_helpers.FINDING_COLUMNS]
        assert keys == ["severity", "status", "category", "target", "summary"]


class TestAnnotatedStatusIntegration:
    def test_no_baseline_produces_no_status_tag(self) -> None:
        finding = make_finding("LOW", "Test", r"C:\a.exe", "detail", {}, "R")
        annotated = baseline.annotate_findings([finding], None)
        assert ui_helpers.finding_status_tag(annotated[0]) is None

    def test_annotated_findings_map_to_expected_tags(self) -> None:
        old = make_finding("LOW", "Test", r"C:\a.exe", "detail", {}, "R")
        new = make_finding("LOW", "Test", r"C:\b.exe", "detail", {}, "R")
        base_report = {"tool": "TamperScan", "version": "1.5.0", "findings": [old]}
        cur_report = {"tool": "TamperScan", "version": "1.5.0", "findings": [new]}
        diff = baseline.diff_reports(base_report, cur_report)
        annotated = baseline.annotate_findings([new], diff)
        tags = {ui_helpers.finding_status_tag(item) for item in annotated}
        assert "diff_new" in tags or "diff_resolved" in tags
        assert all(tag is not None for tag in tags if isinstance(tag, str))
