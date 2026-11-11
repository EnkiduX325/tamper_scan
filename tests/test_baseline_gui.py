# -*- coding: utf-8 -*-
"""V1.3 GUI 基线对比的**纯函数级**单元测试（不创建任何 Tk 窗口）。

覆盖范围：

1. ``load_baseline_file``：合法报告 / 文件不存在 / JSON 损坏 / 根节点非 dict /
   缺 findings / findings 非列表 / 空路径 / BOM 头 / 真实 reporter.build_report 产物；
2. ``diff_status_tag`` / ``finding_status_tag`` / ``DIFF_STATUS_TAGS`` 映射
   （含大小写、UNCHANGED/空/未知状态）；
3. ``baseline_label_text`` 文件名提取（空路径 -> 未加载）；
4. ``STATUS_COLUMN`` / ``FindingTree.COLUMNS`` 列定义包含 ``status``（模块常量，
   不实例化 Treeview / App / Tk）；
5. ``import gui`` 成功且导入本身不会创建 Tk 根窗口（tkinter 不可用时 skip）；
6. 纯函数级验证：无基线（diff=None）的 Finding 不产生状态 tag；有基线的
   annotate_findings 结果能映射出预期 tag。

约束：绝不调用 ``tk.Tk()`` / 实例化 ``App`` / ``FindingTree``；不需要管理员权限，
不读写真实注册表，不启动扫描。

运行方式（仓库根目录）：

    python -m pytest -q tests/test_baseline_gui.py
    python -m unittest tests.test_baseline_gui -v
"""

from __future__ import annotations

import json
import sys
import tempfile
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

GUI_IMPORT_ERROR: str | None = None
try:
    import gui
except Exception as exc:  # pragma: no cover - 环境相关
    gui = None  # type: ignore[assignment]
    GUI_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

requires_gui = unittest.skipUnless(gui is not None, f"gui 不可导入：{GUI_IMPORT_ERROR}")
requires_tkinter = unittest.skipUnless(TKINTER_AVAILABLE, "tkinter 不可用")


class _TempDirMixin(unittest.TestCase):
    """提供临时目录与写文件辅助（不进入文件系统敏感目录）。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp_path = Path(self._tmp.name)

    def _write_json(self, name: str, payload: Any, encoding: str = "utf-8") -> Path:
        path = self.tmp_path / name
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding=encoding)
        return path

    def _write_text(self, name: str, text: str, encoding: str = "utf-8") -> Path:
        path = self.tmp_path / name
        path.write_text(text, encoding=encoding)
        return path


@requires_gui
class LoadBaselineFileTests(_TempDirMixin):
    """``load_baseline_file`` 必须防御性解析，任何坏输入都不能抛异常。"""

    def test_load_valid_report(self) -> None:
        path = self._write_json(
            "base.json",
            {"version": "1.3.0", "findings": [{"rule_id": "TEST_RULE", "severity": "HIGH"}]},
        )
        report, error = gui.load_baseline_file(str(path))
        self.assertIsNone(error)
        self.assertIsInstance(report, dict)
        self.assertEqual(report["findings"][0]["rule_id"], "TEST_RULE")

    def test_load_missing_file_returns_reason(self) -> None:
        missing = self.tmp_path / "not_exists.json"
        report, error = gui.load_baseline_file(str(missing))
        self.assertIsNone(report)
        self.assertIsInstance(error, str)
        self.assertIn("不存在", error)

    def test_load_invalid_json_returns_reason(self) -> None:
        path = self._write_text("broken.json", "{ this is not json ")
        report, error = gui.load_baseline_file(str(path))
        self.assertIsNone(report)
        self.assertIsInstance(error, str)
        self.assertIn("JSON", error)

    def test_load_root_not_dict_returns_reason(self) -> None:
        path = self._write_json("list.json", [{"rule_id": "X"}])
        report, error = gui.load_baseline_file(str(path))
        self.assertIsNone(report)
        self.assertIsInstance(error, str)
        self.assertIn("JSON 对象", error)

    def test_load_missing_findings_returns_reason(self) -> None:
        path = self._write_json("no_findings.json", {"version": "1.3.0", "host": {"name": "PC"}})
        report, error = gui.load_baseline_file(str(path))
        self.assertIsNone(report)
        self.assertIsInstance(error, str)
        self.assertIn("findings", error)

    def test_load_findings_not_list_returns_reason(self) -> None:
        path = self._write_json("bad_findings.json", {"findings": {"rule_id": "X"}})
        report, error = gui.load_baseline_file(str(path))
        self.assertIsNone(report)
        self.assertIsInstance(error, str)
        self.assertIn("findings", error)

    def test_load_empty_path_returns_reason(self) -> None:
        for value in (None, "", "   "):
            report, error = gui.load_baseline_file(value)
            self.assertIsNone(report)
            self.assertIsInstance(error, str)
            self.assertIn("未选择", error)

    def test_load_accepts_utf8_bom(self) -> None:
        """Windows 记事本保存的 BOM 头不应导致 JSON 解析失败。"""
        path = self._write_json("bom.json", {"findings": []}, encoding="utf-8-sig")
        report, error = gui.load_baseline_file(str(path))
        self.assertIsNone(error)
        self.assertEqual(report, {"findings": []})

    def test_load_reporter_built_report(self) -> None:
        import reporter
        from core.finding import make_finding

        report = reporter.build_report(
            [make_finding("HIGH", "Test", "C:/tmp/sample.exe", "测试用 finding", {}, "TEST_RULE")],
            version="1.3.0",
        )
        path = self._write_json("real_report.json", report)
        loaded, error = gui.load_baseline_file(path)
        self.assertIsNone(error)
        self.assertIsInstance(loaded, dict)
        self.assertEqual(loaded["tool"], "TamperScan")
        self.assertEqual(len(loaded["findings"]), 1)


@requires_gui
class DiffStatusMappingTests(unittest.TestCase):
    """状态 -> tag / 标签文本的映射（纯函数，不依赖 Tk）。"""

    def test_known_status_tags(self) -> None:
        expected = {
            "NEW": "diff_new",
            "MODIFIED": "diff_modified",
            "ESCALATED": "diff_escalated",
            "DOWNGRADED": "diff_downgraded",
            "RESOLVED": "diff_resolved",
        }
        self.assertEqual(gui.DIFF_STATUS_TAGS, expected)
        for status, tag in expected.items():
            self.assertEqual(gui.diff_status_tag(status), tag)

    def test_status_tag_is_case_insensitive_and_strips(self) -> None:
        self.assertEqual(gui.diff_status_tag(" new "), "diff_new")
        self.assertEqual(gui.diff_status_tag("resolved"), "diff_resolved")

    def test_no_tag_for_unchanged_empty_and_unknown(self) -> None:
        for status in ("UNCHANGED", "unchanged", "", "   ", None, "FOO", 123):
            self.assertIsNone(gui.diff_status_tag(status), f"status={status!r} 不应有 tag")

    def test_unchanged_not_in_tag_mapping(self) -> None:
        from core import baseline

        self.assertNotIn(baseline.DIFF_UNCHANGED, gui.DIFF_STATUS_TAGS)
        self.assertEqual(len(set(gui.DIFF_STATUS_TAGS.values())), 5)

    def test_finding_status_tag_without_baseline(self) -> None:
        for finding in (
            {},
            {"severity": "HIGH"},
            {"diff_status": ""},
            {"diff_status": None},
            {"diff_status": "UNCHANGED"},
            {"diff_status": "???"},
        ):
            self.assertIsNone(gui.finding_status_tag(finding))

    def test_finding_status_tag_with_baseline(self) -> None:
        self.assertEqual(gui.finding_status_tag({"diff_status": "NEW"}), "diff_new")
        self.assertEqual(gui.finding_status_tag({"diff_status": "RESOLVED"}), "diff_resolved")

    def test_finding_status_tag_non_dict(self) -> None:
        self.assertIsNone(gui.finding_status_tag(None))
        self.assertIsNone(gui.finding_status_tag("NEW"))

    def test_baseline_label_text(self) -> None:
        self.assertEqual(gui.baseline_label_text(r"C:\data\base.json"), "对比基线: base.json")
        self.assertEqual(gui.baseline_label_text("/tmp/reports/nightly.json"), "对比基线: nightly.json")

    def test_baseline_label_text_empty(self) -> None:
        for value in (None, "", "   "):
            self.assertEqual(gui.baseline_label_text(value), "对比基线: （未加载）")


@requires_gui
class StatusColumnDefinitionTests(unittest.TestCase):
    """状态列定义必须是模块常量，测试无需创建 Treeview。"""

    def test_status_column_constant(self) -> None:
        self.assertEqual(gui.STATUS_COLUMN[0], "status")
        self.assertEqual(gui.STATUS_COLUMN[1], "状态")
        self.assertIsInstance(gui.STATUS_COLUMN[2], int)

    def test_finding_tree_columns_include_status(self) -> None:
        keys = [column[0] for column in gui.FindingTree.COLUMNS]
        self.assertIn("status", keys)
        self.assertEqual(keys.count("status"), 1)

    def test_status_column_after_severity(self) -> None:
        keys = [column[0] for column in gui.FindingTree.COLUMNS]
        self.assertEqual(keys.index("status"), keys.index("severity") + 1)

    def test_legacy_columns_preserved(self) -> None:
        keys = [column[0] for column in gui.FindingTree.COLUMNS]
        for key in ("severity", "category", "target", "summary"):
            self.assertIn(key, keys)
        headers = [column[1] for column in gui.FindingTree.COLUMNS]
        self.assertIn("等级", headers)
        self.assertIn("状态", headers)


@requires_gui
class GuiImportTests(unittest.TestCase):
    """``import gui`` 本身必须成功且不创建任何窗口。"""

    def test_gui_module_imported(self) -> None:
        self.assertIsNotNone(gui)
        for name in (
            "load_baseline_file",
            "diff_status_tag",
            "finding_status_tag",
            "baseline_label_text",
        ):
            self.assertTrue(callable(getattr(gui, name, None)), f"缺少纯函数 {name}")
        self.assertTrue(callable(getattr(gui, "App", None)))
        self.assertTrue(callable(getattr(gui, "FindingTree", None)))

    def test_import_does_not_create_tk_root(self) -> None:
        self.assertIsNone(getattr(tkinter, "_default_root", None), "导入 gui 不应创建 Tk 窗口")

    def test_windowed_stdout_guard_kept_at_top(self) -> None:
        """--windowed 保护必须在导入内部模块/任何 print 之前（源码顺序检查）。"""
        source = (PROJECT_ROOT / "gui.py").read_text(encoding="utf-8")
        guard = source.find("if sys.stdout is None")
        reporter_import = source.find("import reporter")
        self.assertGreaterEqual(guard, 0)
        self.assertGreater(reporter_import, guard)


@requires_gui
class AnnotatedStatusTagIntegrationTests(unittest.TestCase):
    """用 core.baseline 的纯函数模拟列表渲染，验证状态 tag 只在有基线时出现。"""

    @staticmethod
    def _finding(severity: str, target: str, rule_id: str) -> dict[str, Any]:
        return {
            "severity": severity,
            "target": target,
            "rule_id": rule_id,
            "category": "Test",
            "detail": "测试",
            "evidence": {"signature": {"status": "valid"}},
        }

    def test_no_baseline_produces_no_status_tag(self) -> None:
        from core import baseline

        findings = [self._finding("HIGH", "C:/a.exe", "RULE_A")]
        annotated = baseline.annotate_findings(findings, None)
        self.assertEqual(len(annotated), 1)
        for finding in annotated:
            self.assertNotIn("diff_status", finding)
            self.assertIsNone(gui.finding_status_tag(finding))

    def test_annotated_findings_map_to_expected_tags(self) -> None:
        from core import baseline

        baseline_report = {
            "findings": [
                self._finding("HIGH", "C:/same.exe", "RULE_SAME"),
                self._finding("MEDIUM", "C:/gone.exe", "RULE_GONE"),
            ]
        }
        current = [
            self._finding("HIGH", "C:/same.exe", "RULE_SAME"),
            self._finding("LOW", "C:/added.exe", "RULE_ADDED"),
        ]
        diff = baseline.diff_reports(baseline_report, current)
        annotated = baseline.annotate_findings(current, diff)
        by_status = {str(item.get("diff_status") or "") for item in annotated}

        self.assertIn("UNCHANGED", by_status)
        self.assertIn("NEW", by_status)
        self.assertIn("RESOLVED", by_status)
        tags = {gui.finding_status_tag(item) for item in annotated}
        # UNCHANGED 不产生 tag（None），NEW / RESOLVED 分别映射到对应样式
        self.assertEqual(tags - {None}, {"diff_new", "diff_resolved"})
        self.assertIn(None, tags)
        for item in annotated:
            self.assertEqual(gui.diff_status_tag(item.get("diff_status")), gui.finding_status_tag(item))


if __name__ == "__main__":
    unittest.main(verbosity=2)
