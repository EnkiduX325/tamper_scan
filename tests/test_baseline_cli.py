# -*- coding: utf-8 -*-
"""``main.py`` CLI 基线参数测试（V1.3）。

覆盖 ``--save-baseline`` / ``--baseline`` / ``--fail-on-new`` / ``--hash-targets``：

- 保存基线：JSON 内容、version=1.3.0、按严重等级的正常退出码、quiet 输出、
  与 ``--baseline`` 同时给出时保存优先、``--hash-targets`` 一起写入 SHA256；
- 对比基线：报告顶层 ``baseline`` 元信息（path/generated_at）、Finding
  ``diff_status``、``summary.diff_counts``、非 quiet 输出六种状态计数、
  调用 ``reporter.apply_baseline_diff`` 的契约参数；
- ``--fail-on-new``：NEW MEDIUM 默认退出码 1 -> 2；无 NEW HIGH/MEDIUM 不强制；
  NEW HIGH 默认已 2；NEW LOW 不强制；不与 --baseline 联用时无副作用；
- 无效基线（文件不存在/JSON 损坏/根节点非 dict/缺 findings 列表）：只输出 WARN、
  不崩溃、退出码与正常扫描一致、报告无 baseline 字段；
- ``--hash-targets``：HIGH/MEDIUM 真实本地文件写 ``evidence.sha256``、LOW 不写、
  文件不存在不写、保存基线 + 对比端到端识别"签名有效但哈希改变"的篡改；
- 向后兼容：不传新参数时报告 JSON 结构/V1.2 退出码语义/run_scan 调用参数不变，
  输出无 baseline / diff_status / sha256 / diff_counts 键。

所有测试均 ``mock.patch.object(main, "run_scan")``，不执行真实扫描；报告写临时目录。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_baseline_cli.py
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import main  # noqa: E402
import reporter  # noqa: E402
from core import baseline  # noqa: E402
from core.finding import make_finding  # noqa: E402
from core.scanner import ScanResult  # noqa: E402
from core.version import __version__  # noqa: E402

HOSTNAME = socket.gethostname()
BASELINE_GENERATED_AT = "2026-11-10T12:00:00+08:00"


# ---------------------------------------------------------------------------
# 测试数据构造
# ---------------------------------------------------------------------------


def _finding(severity: str, rule_id: str, target: str, detail: str = "", **evidence: object) -> dict:
    return make_finding(
        severity,
        "TestCategory",
        target,
        detail or f"测试 {rule_id}",
        evidence if evidence else None,
        rule_id,
    )


def _scan_result(findings: list[dict] | None = None, duration: float = 0.12) -> ScanResult:
    items = list(findings or [])
    module_status = [
        {
            "name": "autoruns",
            "label": "Autoruns 广度兜底",
            "stage": 2,
            "status": "ok",
            "count": len(items),
            "error": None,
        }
    ]
    return ScanResult(
        findings=items,
        duration=duration,
        modules_total=1,
        modules_available=1,
        module_status=module_status,
        errors=[],
    )


def _baseline_report(
    findings: list[dict],
    *,
    version: str = __version__,
    generated_at: str = BASELINE_GENERATED_AT,
    host: str = HOSTNAME,
) -> dict:
    return {
        "tool": "TamperScan",
        "version": version,
        "generated_at": generated_at,
        "host": {"name": host, "os": "Windows", "is_admin": False, "user": "tester"},
        "scan": {"duration_seconds": 1.0, "modules_total": 1, "modules_available": 1, "modules": []},
        "summary": {"total": len(findings), "counts": {}, "exit_code": 0},
        "findings": findings,
    }


class BaselineCliTestCase(unittest.TestCase):
    """公共脚手架：临时目录 + mock run_scan + stdout/stderr 捕获。"""

    def setUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self.tmp = Path(self._tempdir.name)

    def _run(self, argv: list[str], result: ScanResult) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(main, "run_scan", return_value=result) as run_mock:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main.main(["--scan", *argv])
        self.assertEqual(run_mock.call_count, 1)
        return code, stdout.getvalue(), stderr.getvalue()

    def _write_json(self, name: str, data: object) -> Path:
        path = self.tmp / name
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return path

    def _read_json(self, path: str | Path) -> dict:
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def _output_json(self, base: Path) -> dict:
        return self._read_json(str(base) + ".json")


# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------


class TestParser(BaselineCliTestCase):
    def test_new_options_registered(self) -> None:
        # V1.4：--save-baseline 与 --baseline 成为互斥参数，需分别解析
        save_args = main.build_parser().parse_args(
            ["--scan", "--save-baseline", "base.json", "--fail-on-new", "--hash-targets"]
        )
        self.assertEqual(save_args.save_baseline, "base.json")
        self.assertIsNone(save_args.baseline)
        self.assertTrue(save_args.fail_on_new)
        self.assertTrue(save_args.hash_targets)

        compare_args = main.build_parser().parse_args(["--scan", "--baseline", "old.json"])
        self.assertEqual(compare_args.baseline, "old.json")
        self.assertIsNone(compare_args.save_baseline)

    def test_defaults_keep_v12_semantics(self) -> None:
        args = main.build_parser().parse_args(["--scan"])
        self.assertIsNone(args.save_baseline)
        self.assertIsNone(args.baseline)
        self.assertFalse(args.fail_on_new)
        self.assertFalse(args.hash_targets)
        self.assertFalse(args.quiet)
        self.assertIsNone(args.output)
        self.assertIsNone(args.format)

    def test_help_lists_new_options_and_examples(self) -> None:
        text = main.build_parser().format_help()
        for option in ("--save-baseline", "--baseline", "--fail-on-new", "--hash-targets"):
            self.assertIn(option, text)
        self.assertIn("基线", text)


# ---------------------------------------------------------------------------
# --save-baseline
# ---------------------------------------------------------------------------


class TestSaveBaseline(BaselineCliTestCase):
    def test_save_baseline_writes_report_with_version(self) -> None:
        path = self.tmp / "baseline.json"
        result = _scan_result([_finding("HIGH", "SIG_UNSIGNED", r"C:\Temp\evil.exe")])
        code, stdout, _stderr = self._run(["--save-baseline", str(path)], result)

        self.assertEqual(code, 2)
        self.assertIn("基线已保存", stdout)
        self.assertTrue(path.is_file())
        data = self._read_json(path)
        self.assertEqual(data["version"], "1.5.0")
        self.assertEqual(data["version"], __version__)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["rule_id"], "SIG_UNSIGNED")
        self.assertEqual(data["summary"]["exit_code"], 2)
        # 保存的基线本身不含对比元信息（只有 --baseline 才写 baseline/diff_status）
        self.assertNotIn("baseline", data)
        self.assertNotIn("diff_status", data["findings"][0])

    def test_save_baseline_exit_code_follows_severity(self) -> None:
        for severity, expected in (("HIGH", 2), ("MEDIUM", 1), ("LOW", 0), ("INFO", 0)):
            with self.subTest(severity=severity):
                path = self.tmp / f"baseline_{severity}.json"
                result = _scan_result(
                    [_finding(severity, f"RULE_{severity}", rf"C:\Temp\{severity}.dat")]
                )
                code, _stdout, _stderr = self._run(
                    ["--save-baseline", str(path), "--quiet"], result
                )
                self.assertEqual(code, expected)
                self.assertEqual(self._read_json(path)["summary"]["exit_code"], expected)

    def test_save_baseline_quiet_still_prints_path(self) -> None:
        path = self.tmp / "quiet_baseline.json"
        code, stdout, _stderr = self._run(["--save-baseline", str(path), "--quiet"], _scan_result([]))
        self.assertEqual(code, 0)
        self.assertIn("基线已保存", stdout)
        self.assertIn(str(path), stdout)
        self.assertTrue(path.is_file())

    def test_save_baseline_and_baseline_are_mutually_exclusive(self) -> None:
        # V1.4：--save-baseline 与 --baseline 改为 argparse 互斥组，同时传入直接报错退出
        saved = self.tmp / "preferred.json"
        old = self._write_json("old.json", _baseline_report([]))
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(main, "run_scan") as run_mock:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    main.main(["--scan", "--save-baseline", str(saved), "--baseline", str(old)])
        self.assertEqual(caught.exception.code, 2)
        run_mock.assert_not_called()
        self.assertFalse(saved.exists())

    def test_hash_targets_are_written_into_saved_baseline(self) -> None:
        target = self.tmp / "evil.exe"
        target.write_bytes(b"payload")
        path = self.tmp / "hash_baseline.json"
        result = _scan_result([_finding("HIGH", "R", str(target))])

        code, _stdout, _stderr = self._run(
            ["--save-baseline", str(path), "--hash-targets", "--quiet"], result
        )

        self.assertEqual(code, 2)
        data = self._read_json(path)
        self.assertEqual(
            data["findings"][0]["evidence"]["sha256"],
            hashlib.sha256(b"payload").hexdigest(),
        )


# ---------------------------------------------------------------------------
# --baseline 对比
# ---------------------------------------------------------------------------


class TestBaselineCompare(BaselineCliTestCase):
    def test_compare_attaches_baseline_metadata_and_new_status(self) -> None:
        old = self._write_json("old.json", _baseline_report([]))
        out = self.tmp / "current"
        result = _scan_result([_finding("HIGH", "SIG_UNSIGNED", r"C:\Temp\evil.exe")])

        code, stdout, _stderr = self._run(
            ["--baseline", str(old), "--format", "json", "--output", str(out)], result
        )

        self.assertEqual(code, 2)
        self.assertIn("基线对比", stdout)
        data = self._output_json(out)
        self.assertEqual(data["baseline"]["path"], str(old))
        self.assertEqual(data["baseline"]["generated_at"], BASELINE_GENERATED_AT)
        self.assertEqual(sorted(data["baseline"]), ["generated_at", "path"])
        self.assertEqual(data["findings"][0]["diff_status"], "NEW")
        self.assertEqual(data["summary"]["diff_counts"]["NEW"], 1)
        self.assertEqual(data["summary"]["diff_counts"]["UNCHANGED"], 0)

    def test_compare_unchanged_finding_keeps_exit_code(self) -> None:
        finding = _finding("MEDIUM", "RUN_REGISTRY", r"HKLM\Software\Run\X")
        old = self._write_json("old.json", _baseline_report([copy.deepcopy(finding)]))
        out = self.tmp / "unchanged"

        code, _stdout, _stderr = self._run(
            ["--baseline", str(old), "--format", "json", "--output", str(out), "--quiet"],
            _scan_result([copy.deepcopy(finding)]),
        )

        self.assertEqual(code, 1)  # 无 NEW，默认退出码语义不变
        data = self._output_json(out)
        self.assertEqual(data["findings"][0]["diff_status"], "UNCHANGED")
        self.assertEqual(data["summary"]["diff_counts"]["UNCHANGED"], 1)
        self.assertEqual(data["summary"]["exit_code"], 1)

    def test_compare_prints_six_status_counts(self) -> None:
        old = self._write_json(
            "old.json", _baseline_report([_finding("LOW", "OLD_RULE", r"C:\Temp\gone.exe")])
        )
        result = _scan_result([_finding("HIGH", "NEW_RULE", r"C:\Temp\new.exe")])

        _code, stdout, _stderr = self._run(["--baseline", str(old)], result)

        for status in baseline.DIFF_STATUSES:
            self.assertIn(status, stdout)
        self.assertIn("NEW: 1", stdout)
        self.assertIn("RESOLVED: 1", stdout)
        self.assertIn("UNCHANGED: 0", stdout)

    def test_compare_calls_apply_baseline_diff_contract(self) -> None:
        old = self._write_json("old.json", _baseline_report([]))
        result = _scan_result([_finding("LOW", "R", r"C:\Temp\x.exe")])
        captured: dict = {}

        def fake_apply(report: dict, diff: object, baseline_path: str = "") -> dict:
            captured["baseline_path"] = baseline_path
            captured["diff"] = diff
            updated = copy.deepcopy(report)
            updated["baseline"] = {
                "path": baseline_path,
                "generated_at": getattr(diff, "baseline_meta", {}).get("generated_at", ""),
            }
            for item in updated["findings"]:
                item["diff_status"] = "NEW"
            return updated

        with mock.patch.object(reporter, "apply_baseline_diff", side_effect=fake_apply) as apply_mock:
            code, _stdout, _stderr = self._run(["--baseline", str(old)], result)

        apply_mock.assert_called_once()
        self.assertEqual(captured["baseline_path"], str(old))
        self.assertIsInstance(captured["diff"], baseline.BaselineDiff)
        self.assertEqual(code, 0)


# ---------------------------------------------------------------------------
# --fail-on-new 退出码矩阵
# ---------------------------------------------------------------------------


class TestFailOnNew(BaselineCliTestCase):
    def _run_new(self, severity: str, fail_on_new: bool) -> int:
        old = self._write_json(f"old_{severity}.json", _baseline_report([]))
        result = _scan_result([_finding(severity, f"RULE_{severity}", rf"C:\Temp\{severity}.exe")])
        argv = ["--baseline", str(old), "--quiet"]
        if fail_on_new:
            argv.append("--fail-on-new")
        code, _stdout, _stderr = self._run(argv, result)
        return code

    def test_new_medium_default_exit_1(self) -> None:
        self.assertEqual(self._run_new("MEDIUM", False), 1)

    def test_new_medium_fail_on_new_forces_2(self) -> None:
        self.assertEqual(self._run_new("MEDIUM", True), 2)

    def test_new_high_default_already_2(self) -> None:
        self.assertEqual(self._run_new("HIGH", False), 2)
        self.assertEqual(self._run_new("HIGH", True), 2)

    def test_new_low_is_not_forced(self) -> None:
        self.assertEqual(self._run_new("LOW", False), 0)
        self.assertEqual(self._run_new("LOW", True), 0)

    def test_no_new_high_medium_is_not_forced(self) -> None:
        finding = _finding("MEDIUM", "RUN_REGISTRY", r"HKLM\Software\Run\X")
        old = self._write_json("old.json", _baseline_report([copy.deepcopy(finding)]))
        result = _scan_result([copy.deepcopy(finding)])

        _code, _stdout, _stderr = self._run(["--baseline", str(old), "--fail-on-new", "--quiet"], result)

        self.assertEqual(_code, 1)  # UNCHANGED MEDIUM，不强制 2

    def test_fail_on_new_without_baseline_has_no_effect(self) -> None:
        result = _scan_result([_finding("MEDIUM", "R", r"C:\Temp\m.exe")])
        code, _stdout, _stderr = self._run(["--fail-on-new", "--quiet"], result)
        self.assertEqual(code, 1)


# ---------------------------------------------------------------------------
# 无效 / 缺失基线：只 WARN，不崩溃，不影响正常扫描
# ---------------------------------------------------------------------------


class TestInvalidBaseline(BaselineCliTestCase):
    def _assert_invalid_baseline(self, name: str, content: str | None) -> None:
        if content is None:
            baseline_path = self.tmp / name  # 不创建：文件不存在
        else:
            baseline_path = self.tmp / name
            baseline_path.write_text(content, encoding="utf-8")
        out = self.tmp / f"report_{name.replace('.', '_')}"
        result = _scan_result([_finding("MEDIUM", "R", r"C:\Temp\m.exe")])

        code, _stdout, stderr = self._run(
            ["--baseline", str(baseline_path), "--format", "json", "--output", str(out)], result
        )

        self.assertEqual(code, 1)  # 正常扫描退出码（MEDIUM=1），不受无效基线影响
        self.assertIn("[WARN]", stderr)
        data = self._output_json(out)
        self.assertNotIn("baseline", data)
        self.assertNotIn("diff_counts", data["summary"])
        self.assertNotIn("diff_status", data["findings"][0])
        self.assertNotIn("sha256", data["findings"][0].get("evidence") or {})

    def test_missing_baseline_file_warns_and_continues(self) -> None:
        self._assert_invalid_baseline("missing.json", None)

    def test_corrupt_baseline_json_warns_and_continues(self) -> None:
        self._assert_invalid_baseline("broken.json", "this is not json {")

    def test_root_not_dict_warns_and_continues(self) -> None:
        self._assert_invalid_baseline("list.json", json.dumps([1, 2, 3]))

    def test_missing_findings_list_warns_and_continues(self) -> None:
        self._assert_invalid_baseline("no_findings.json", json.dumps({"version": "1.3.0"}))


# ---------------------------------------------------------------------------
# --hash-targets
# ---------------------------------------------------------------------------


class TestHashTargets(BaselineCliTestCase):
    def test_high_and_medium_local_files_get_sha256(self) -> None:
        high_file = self.tmp / "high.exe"
        high_file.write_bytes(b"high-content")
        medium_file = self.tmp / "medium.dll"
        medium_file.write_bytes(b"medium-content")
        low_file = self.tmp / "low.txt"
        low_file.write_bytes(b"low-content")
        findings = [
            _finding("HIGH", "R_HIGH", str(high_file)),
            _finding("MEDIUM", "R_MEDIUM", str(medium_file)),
            _finding("LOW", "R_LOW", str(low_file)),
        ]
        out = self.tmp / "hash_report"

        self._run(["--hash-targets", "--format", "json", "--output", str(out)], _scan_result(findings))

        data = self._output_json(out)
        by_rule = {item["rule_id"]: item for item in data["findings"]}
        self.assertEqual(
            by_rule["R_HIGH"]["evidence"]["sha256"],
            hashlib.sha256(b"high-content").hexdigest(),
        )
        self.assertEqual(
            by_rule["R_MEDIUM"]["evidence"]["sha256"],
            hashlib.sha256(b"medium-content").hexdigest(),
        )
        self.assertNotIn("sha256", by_rule["R_LOW"]["evidence"])

    def test_missing_local_file_gets_no_sha256(self) -> None:
        missing = self.tmp / "not-there.exe"
        out = self.tmp / "missing_report"

        code, _stdout, _stderr = self._run(
            ["--hash-targets", "--format", "json", "--output", str(out)],
            _scan_result([_finding("HIGH", "R", str(missing))]),
        )

        self.assertEqual(code, 2)  # HIGH 正常退出码
        data = self._output_json(out)
        self.assertNotIn("sha256", data["findings"][0]["evidence"])

    def test_hash_tamper_end_to_end(self) -> None:
        target = self.tmp / "signed.dll"
        target.write_bytes(b"original-content")
        finding = _finding("MEDIUM", "SVC_SERVICEDLL_TAMPER", str(target), signature={"status": "valid"})
        base_path = self.tmp / "tamper_baseline.json"

        code1, _stdout1, _stderr1 = self._run(
            ["--save-baseline", str(base_path), "--hash-targets", "--quiet"],
            _scan_result([copy.deepcopy(finding)]),
        )
        self.assertEqual(code1, 1)

        target.write_bytes(b"tampered-content")
        out = self.tmp / "tamper_report"
        code2, _stdout2, _stderr2 = self._run(
            [
                "--baseline",
                str(base_path),
                "--hash-targets",
                "--format",
                "json",
                "--output",
                str(out),
                "--quiet",
            ],
            _scan_result([copy.deepcopy(finding)]),
        )

        data = self._output_json(out)
        item = data["findings"][0]
        self.assertEqual(item["diff_status"], "MODIFIED")
        self.assertTrue(item["evidence"]["hash_tamper"])
        self.assertEqual(item["severity"], "HIGH")
        self.assertEqual(code2, 2)  # 哈希篡改后提升为 HIGH


# ---------------------------------------------------------------------------
# 向后兼容（不传任何新参数）
# ---------------------------------------------------------------------------


class TestBackwardCompat(BaselineCliTestCase):
    def test_no_new_args_report_shape_unchanged(self) -> None:
        out = self.tmp / "v12_report"
        result = _scan_result([_finding("HIGH", "SIG_UNSIGNED", r"C:\Temp\evil.exe")])

        code, _stdout, _stderr = self._run(["--format", "json", "--output", str(out)], result)

        self.assertEqual(code, 2)
        data = self._output_json(out)
        self.assertEqual(
            set(data),
            {"tool", "version", "generated_at", "host", "scan", "summary", "findings"},
        )
        self.assertNotIn("baseline", data)
        self.assertNotIn("diff_counts", data["summary"])
        self.assertEqual(data["version"], "1.5.0")
        for item in data["findings"]:
            self.assertNotIn("diff_status", item)
            self.assertNotIn("sha256", item.get("evidence") or {})

    def test_no_new_args_exit_code_matrix(self) -> None:
        for severity, expected in (("HIGH", 2), ("MEDIUM", 1), ("LOW", 0), ("INFO", 0)):
            with self.subTest(severity=severity):
                result = _scan_result(
                    [_finding(severity, f"R_{severity}", rf"C:\Temp\{severity}.dat")]
                )
                code, _stdout, _stderr = self._run(["--quiet"], result)
                self.assertEqual(code, expected)

    def test_run_scan_call_args_unchanged(self) -> None:
        result = _scan_result([])
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(main, "run_scan", return_value=result) as run_mock:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                main.main(["--scan"])
        run_mock.assert_called_once_with(
            progress_callback=None,
            memory_scan=True,
            max_memory_scan=10,
            module_filter=None,
        )

    def test_hash_targets_off_does_not_add_sha256(self) -> None:
        real_file = self.tmp / "real.exe"
        real_file.write_bytes(b"real-content")
        out = self.tmp / "no_hash_report"

        self._run(
            ["--format", "json", "--output", str(out)],
            _scan_result([_finding("HIGH", "R", str(real_file))]),
        )

        data = self._output_json(out)
        self.assertNotIn("sha256", data["findings"][0]["evidence"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
