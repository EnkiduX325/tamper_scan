# -*- coding: utf-8 -*-
"""``main.py`` V1.4 CLI 测试：容错参数、攻击链参数与 build.bat。

覆盖任务 A3 + C3：

- 互斥参数（``--save-baseline``/``--baseline``、``--campaign``/``--campaign-shadow``）
  同时传入 -> argparse 报错退出（SystemExit 2）且不执行扫描；
- ``--save-baseline`` 未带 ``--hash-targets`` 的 SHA256 警告（相反情况不告警）；
- ``--quiet`` + SKIPPED 的 WARN（非 quiet 不打印）；
- ``--fail-on-skipped``：有 SKIPPED -> 退出码 3，且优先于 fail-on-new / high campaign；
- ``--campaign`` 写入 report["campaigns"]/["campaign_stats"]；``--campaign-shadow``
  额外给每条 campaign 加 shadow=True 且 report["campaign_shadow"]=True；
- ``--fail-on-campaign high``：high campaign -> 2，medium 不强制；
- ``--treat-version-bump-as-benign`` 透传给 ``core.baseline.diff_reports``（默认不传）；
- 默认（不传新参数）报告键集合/退出码与 V1.3 完全一致；
- build.bat 静态断言：pip show skrapa 探测、缺失时从 COMMON 移除 skrapa hidden-import。

所有测试均 ``mock.patch.object(main, "run_scan")``，不执行真实扫描；不依赖
``core/correlator.py`` 真实实现（通过 ``main._load_correlator`` 注入 fake）。
报告写临时目录。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_cli_v14.py
"""

from __future__ import annotations

import contextlib
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
from core import baseline  # noqa: E402
from core.finding import make_finding  # noqa: E402
from core.scanner import ScanResult  # noqa: E402
from core.version import __version__  # noqa: E402

HOSTNAME = socket.gethostname()
BASELINE_GENERATED_AT = "2026-11-10T12:00:00+08:00"

#: 默认（未启用 campaign）报告键集合（V1.3 结构）
V13_REPORT_KEYS = {"tool", "version", "generated_at", "host", "scan", "summary", "findings"}


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


def _baseline_report(findings: list[dict], *, host: str = HOSTNAME) -> dict:
    return {
        "tool": "TamperScan",
        "version": __version__,
        "generated_at": BASELINE_GENERATED_AT,
        "host": {"name": host, "os": "Windows", "is_admin": False, "user": "tester"},
        "scan": {"duration_seconds": 1.0, "modules_total": 1, "modules_available": 1, "modules": []},
        "summary": {"total": len(findings), "counts": {}, "exit_code": 0},
        "findings": findings,
    }


def _campaign(
    confidence: str = "high",
    name: str = "隐藏任务 -> WFP 阻断 -> 凭证后门",
    chain_id: str = "CHAIN-001",
    steps: int = 3,
    finding_count: int = 3,
) -> dict:
    step_list = [
        {
            "tactic": f"TA000{index + 3}",
            "rule_ids": ["TASK_HIDDEN_TARRASK"],
            "findings": [
                {"rule_id": "TASK_HIDDEN_TARRASK", "target": "Task: \\Evil", "severity": "HIGH"}
            ],
        }
        for index in range(steps)
    ]
    return {
        "chain_id": chain_id,
        "name": name,
        "description": "固定剧本",
        "confidence": confidence,
        "tactics": ["TA0003", "TA0005", "TA0006"],
        "steps": step_list,
        "finding_count": finding_count,
        "targets": ["Task: \\Evil"],
        "suppressed": False,
        "suppressed_by": None,
        "shadow": False,
    }


def _correlation(campaigns: list[dict] | None = None) -> dict:
    items = list(campaigns or [])
    return {
        "campaigns": items,
        "suppressed": [],
        "stats": {
            "findings": 3,
            "clusters": 1 if items else 0,
            "campaigns": len(items),
            "suppressed": 0,
        },
    }


class CliV14TestCase(unittest.TestCase):
    """公共脚手架：临时目录 + mock run_scan + correlator 注入 + stdout/stderr 捕获。"""

    def setUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self.tmp = Path(self._tempdir.name)

    def _run(
        self,
        argv: list[str],
        result: ScanResult,
        *,
        correlate_result: dict | None = None,
    ) -> tuple[int, str, str, mock.Mock]:
        """执行 main.main(argv)；返回 (退出码, stdout, stderr, fake_correlator)。"""
        stdout, stderr = io.StringIO(), io.StringIO()
        correlator = mock.Mock()
        correlator.correlate.return_value = correlate_result if correlate_result is not None else _correlation()
        with mock.patch.object(main, "run_scan", return_value=result) as run_mock:
            with mock.patch.object(main, "_load_correlator", return_value=correlator) as loader_mock:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = main.main(["--scan", *argv])
        self.assertEqual(run_mock.call_count, 1)
        self._loader_mock = loader_mock
        return code, stdout.getvalue(), stderr.getvalue(), correlator

    def _run_system_exit(self, argv: list[str]) -> tuple[int, mock.Mock]:
        """执行预期被 argparse 拒绝的 argv，返回 (SystemExit.code, run_scan mock)。"""
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(main, "run_scan") as run_mock:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    main.main(["--scan", *argv])
        return int(caught.exception.code or 0), run_mock

    def _write_json(self, name: str, data: object) -> Path:
        path = self.tmp / name
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return path

    def _output_json(self, base: Path) -> dict:
        return json.loads(Path(str(base) + ".json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# A3：互斥参数
# ---------------------------------------------------------------------------


class TestMutuallyExclusiveArguments(CliV14TestCase):
    def test_save_baseline_and_baseline_together_is_error(self) -> None:
        code, run_mock = self._run_system_exit(
            ["--save-baseline", str(self.tmp / "a.json"), "--baseline", str(self.tmp / "b.json")]
        )
        self.assertEqual(code, 2)
        run_mock.assert_not_called()

    def test_campaign_and_campaign_shadow_together_is_error(self) -> None:
        code, run_mock = self._run_system_exit(["--campaign", "--campaign-shadow"])
        self.assertEqual(code, 2)
        run_mock.assert_not_called()


# ---------------------------------------------------------------------------
# A3：--save-baseline 的 SHA256 警告
# ---------------------------------------------------------------------------


class TestSaveBaselineWarning(CliV14TestCase):
    def test_save_baseline_without_hash_targets_warns(self) -> None:
        saved = self.tmp / "baseline.json"
        code, stdout, stderr, _corr = self._run(
            ["--save-baseline", str(saved), "--quiet"], _scan_result([])
        )
        self.assertEqual(code, 0)
        self.assertTrue(saved.is_file())
        self.assertIn(
            "[WARN] 基线将不含文件 SHA256，后续哈希篡改检测可能失效；建议同时使用 --hash-targets",
            stderr,
        )
        self.assertIn("基线已保存", stdout)

    def test_save_baseline_with_hash_targets_has_no_warning(self) -> None:
        saved = self.tmp / "baseline.json"
        _code, _stdout, stderr, _corr = self._run(
            ["--save-baseline", str(saved), "--hash-targets", "--quiet"], _scan_result([])
        )
        self.assertNotIn("基线将不含文件 SHA256", stderr)


# ---------------------------------------------------------------------------
# A3：--quiet + SKIPPED 警告
# ---------------------------------------------------------------------------


class TestQuietSkippedWarning(CliV14TestCase):
    def test_quiet_with_skipped_warns(self) -> None:
        skipped = _finding("SKIPPED", "SERVICE_SKIPPED", "svc: Demo")
        code, _stdout, stderr, _corr = self._run(["--quiet"], _scan_result([skipped]))
        self.assertEqual(code, 0)
        self.assertIn("[WARN] 本次扫描存在 1 个 SKIPPED 项（未检查 ≠ 安全）", stderr)

    def test_quiet_without_skipped_has_no_warning(self) -> None:
        medium = _finding("MEDIUM", "R_MED", r"C:\Temp\m.exe")
        _code, _stdout, stderr, _corr = self._run(["--quiet"], _scan_result([medium]))
        self.assertNotIn("本次扫描存在", stderr)

    def test_non_quiet_with_skipped_has_no_extra_warning(self) -> None:
        skipped = _finding("SKIPPED", "SERVICE_SKIPPED", "svc: Demo")
        _code, _stdout, stderr, _corr = self._run([], _scan_result([skipped]))
        self.assertNotIn("本次扫描存在", stderr)


# ---------------------------------------------------------------------------
# A3：--fail-on-skipped（退出码 3，优先级最高）
# ---------------------------------------------------------------------------


class TestFailOnSkipped(CliV14TestCase):
    def test_skipped_forces_exit_code_3(self) -> None:
        skipped = _finding("SKIPPED", "SERVICE_SKIPPED", "svc: Demo")
        code, _stdout, _stderr, _corr = self._run(
            ["--fail-on-skipped", "--quiet"], _scan_result([skipped])
        )
        self.assertEqual(code, 3)

    def test_without_flag_skipped_keeps_v13_exit_code(self) -> None:
        skipped = _finding("SKIPPED", "SERVICE_SKIPPED", "svc: Demo")
        code, _stdout, _stderr, _corr = self._run(["--quiet"], _scan_result([skipped]))
        self.assertEqual(code, 0)

    def test_fail_on_skipped_overrides_fail_on_new(self) -> None:
        old = self._write_json("old.json", _baseline_report([]))
        medium = _finding("MEDIUM", "R_MED", r"C:\Temp\m.exe")
        skipped = _finding("SKIPPED", "SVC_SKIPPED", "svc: Demo")
        result = _scan_result([medium, skipped])

        code_new, _out, _err, _corr = self._run(
            ["--baseline", str(old), "--fail-on-new", "--quiet"], result
        )
        self.assertEqual(code_new, 2)

        code_skipped, _out, _err, _corr = self._run(
            ["--baseline", str(old), "--fail-on-new", "--fail-on-skipped", "--quiet"], result
        )
        self.assertEqual(code_skipped, 3)

    def test_fail_on_skipped_overrides_high_campaign(self) -> None:
        skipped = _finding("SKIPPED", "SVC_SKIPPED", "svc: Demo")
        result = _scan_result([skipped])
        payload = _correlation([_campaign(confidence="high")])

        code_new, _out, _err, _corr = self._run(
            ["--campaign", "--fail-on-campaign", "high", "--quiet"],
            result,
            correlate_result=payload,
        )
        self.assertEqual(code_new, 2)

        code_skipped, _out, _err, _corr = self._run(
            ["--campaign", "--fail-on-campaign", "high", "--fail-on-skipped", "--quiet"],
            result,
            correlate_result=payload,
        )
        self.assertEqual(code_skipped, 3)

    def test_fail_on_skipped_without_skipped_keeps_base_exit_code(self) -> None:
        medium = _finding("MEDIUM", "R_MED", r"C:\Temp\m.exe")
        code, _stdout, _stderr, _corr = self._run(
            ["--fail-on-skipped", "--quiet"], _scan_result([medium])
        )
        self.assertEqual(code, 1)


# ---------------------------------------------------------------------------
# C3：--campaign / --campaign-shadow
# ---------------------------------------------------------------------------


class TestCampaign(CliV14TestCase):
    def test_campaign_writes_campaigns_and_stats(self) -> None:
        out = self.tmp / "campaign_report"
        result = _scan_result([_finding("HIGH", "TASK_HIDDEN_TARRASK", "Task: \\Evil")])
        payload = _correlation([_campaign(confidence="high")])

        code, stdout, _stderr, correlator = self._run(
            ["--campaign", "--format", "json", "--output", str(out)],
            result,
            correlate_result=payload,
        )

        data = self._output_json(out)
        self.assertIn("campaigns", data)
        self.assertEqual(len(data["campaigns"]), 1)
        self.assertEqual(data["campaigns"][0]["chain_id"], "CHAIN-001")
        self.assertEqual(data["campaigns"][0]["confidence"], "high")
        self.assertEqual(data["campaign_stats"]["campaigns"], 1)
        self.assertNotIn("campaign_shadow", data)
        self.assertIn("攻击链", stdout)
        self.assertIn("CHAIN-001", stdout)
        self.assertIn("[high]", stdout)
        self.assertEqual(code, 2)
        correlator.correlate.assert_called_once()

    def test_campaign_shadow_marks_shadow(self) -> None:
        out = self.tmp / "shadow_report"
        result = _scan_result([_finding("HIGH", "TASK_HIDDEN_TARRASK", "Task: \\Evil")])
        payload = _correlation([_campaign(confidence="high"), _campaign(chain_id="CHAIN-002")])

        _code, stdout, _stderr, _corr = self._run(
            ["--campaign-shadow", "--format", "json", "--output", str(out)],
            result,
            correlate_result=payload,
        )

        data = self._output_json(out)
        self.assertIs(data["campaign_shadow"], True)
        self.assertEqual(len(data["campaigns"]), 2)
        for campaign in data["campaigns"]:
            self.assertIs(campaign["shadow"], True)
        self.assertIn("影子", stdout)
        self.assertIn("[影子模式]", stdout)
        self.assertIn("campaign_stats", data)

    def test_correlator_receives_current_findings(self) -> None:
        result = _scan_result([_finding("HIGH", "TASK_HIDDEN_TARRASK", "Task: \\Evil")])
        _code, _stdout, _stderr, correlator = self._run(
            ["--campaign", "--quiet"], result, correlate_result=_correlation([])
        )
        findings_arg = correlator.correlate.call_args[0][0]
        self.assertEqual([item["rule_id"] for item in findings_arg], ["TASK_HIDDEN_TARRASK"])

    def test_campaign_without_flag_is_not_loaded(self) -> None:
        out = self.tmp / "plain_report"
        _code, _stdout, _stderr, _corr = self._run(
            ["--format", "json", "--output", str(out)],
            _scan_result([_finding("HIGH", "TASK_HIDDEN_TARRASK", "Task: \\Evil")]),
        )
        data = self._output_json(out)
        for key in ("campaigns", "campaign_stats", "campaign_shadow"):
            self.assertNotIn(key, data)
        self._loader_mock.assert_not_called()

    def test_campaign_empty_result_prints_no_chain_hint(self) -> None:
        out = self.tmp / "empty_campaign_report"
        _code, stdout, _stderr, _corr = self._run(
            ["--campaign", "--format", "json", "--output", str(out)],
            _scan_result([]),
            correlate_result=_correlation([]),
        )
        self.assertIn("未发现满足固定剧本的攻击链", stdout)
        data = self._output_json(out)
        self.assertEqual(data["campaigns"], [])
        self.assertEqual(data["campaign_stats"]["campaigns"], 0)


# ---------------------------------------------------------------------------
# C3：--fail-on-campaign high
# ---------------------------------------------------------------------------


class TestFailOnCampaign(CliV14TestCase):
    def test_high_campaign_forces_exit_code_2(self) -> None:
        low = _finding("LOW", "R_LOW", r"C:\Temp\l.dat")
        code, _stdout, _stderr, _corr = self._run(
            ["--campaign", "--fail-on-campaign", "high", "--quiet"],
            _scan_result([low]),
            correlate_result=_correlation([_campaign(confidence="high")]),
        )
        self.assertEqual(code, 2)

    def test_medium_campaign_does_not_force(self) -> None:
        low = _finding("LOW", "R_LOW", r"C:\Temp\l.dat")
        code, _stdout, _stderr, _corr = self._run(
            ["--campaign", "--fail-on-campaign", "high", "--quiet"],
            _scan_result([low]),
            correlate_result=_correlation([_campaign(confidence="medium")]),
        )
        self.assertEqual(code, 0)

    def test_no_campaign_does_not_force(self) -> None:
        low = _finding("LOW", "R_LOW", r"C:\Temp\l.dat")
        code, _stdout, _stderr, _corr = self._run(
            ["--campaign", "--fail-on-campaign", "high", "--quiet"],
            _scan_result([low]),
            correlate_result=_correlation([]),
        )
        self.assertEqual(code, 0)

    def test_fail_on_campaign_without_campaign_flag_is_noop(self) -> None:
        low = _finding("LOW", "R_LOW", r"C:\Temp\l.dat")
        code, _stdout, _stderr, _corr = self._run(
            ["--fail-on-campaign", "high", "--quiet"], _scan_result([low])
        )
        self.assertEqual(code, 0)
        self._loader_mock.assert_not_called()


# ---------------------------------------------------------------------------
# 基线增强参数透传（--treat-version-bump-as-benign）
# ---------------------------------------------------------------------------


class TestTreatVersionBumpForwarding(CliV14TestCase):
    def _empty_diff(self, baseline_path: Path) -> baseline.BaselineDiff:
        return baseline.BaselineDiff(
            entries=[],
            counts={status: 0 for status in baseline.DIFF_STATUSES},
            baseline_meta={"path": str(baseline_path), "generated_at": BASELINE_GENERATED_AT},
        )

    def test_flag_forwards_kwarg_to_diff_reports(self) -> None:
        old = self._write_json("old.json", _baseline_report([]))
        captured: dict = {}

        def spy(*args: object, **kwargs: object) -> baseline.BaselineDiff:
            captured["args"] = args
            captured["kwargs"] = kwargs
            return self._empty_diff(old)

        result = _scan_result([_finding("LOW", "R", r"C:\Temp\x.dat")])
        with mock.patch.object(main.baseline, "diff_reports", side_effect=spy):
            _code, _stdout, _stderr, _corr = self._run(
                ["--baseline", str(old), "--treat-version-bump-as-benign"], result
            )

        self.assertIs(captured["kwargs"].get("treat_version_bump_as_benign"), True)
        self.assertEqual(captured["kwargs"].get("baseline_path"), str(old))

    def test_flag_absent_by_default(self) -> None:
        old = self._write_json("old.json", _baseline_report([]))
        captured: dict = {}

        def spy(*args: object, **kwargs: object) -> baseline.BaselineDiff:
            captured["kwargs"] = kwargs
            return self._empty_diff(old)

        result = _scan_result([_finding("LOW", "R", r"C:\Temp\x.dat")])
        with mock.patch.object(main.baseline, "diff_reports", side_effect=spy):
            _code, _stdout, _stderr, _corr = self._run(["--baseline", str(old)], result)

        self.assertNotIn("treat_version_bump_as_benign", captured["kwargs"])


# ---------------------------------------------------------------------------
# 默认路径：与 V1.3 完全一致
# ---------------------------------------------------------------------------


class TestBackwardCompat(CliV14TestCase):
    def test_default_report_has_no_v14_keys(self) -> None:
        out = self.tmp / "v13_report"
        result = _scan_result([_finding("HIGH", "SIG_UNSIGNED", r"C:\Temp\evil.exe")])

        code, _stdout, stderr, _corr = self._run(
            ["--format", "json", "--output", str(out)], result
        )

        data = self._output_json(out)
        self.assertEqual(set(data), V13_REPORT_KEYS)
        self.assertEqual(data["version"], "1.4.0")
        for key in ("campaigns", "campaign_stats", "campaign_shadow"):
            self.assertNotIn(key, data)
        self.assertNotIn("baseline", data)
        self.assertNotIn("diff_counts", data["summary"])
        self.assertNotIn("本次扫描存在", stderr)
        self.assertEqual(code, 2)
        self._loader_mock.assert_not_called()

    def test_default_exit_code_matrix_unchanged(self) -> None:
        for severity, expected in (("HIGH", 2), ("MEDIUM", 1), ("LOW", 0), ("SKIPPED", 0)):
            with self.subTest(severity=severity):
                finding = _finding(severity, f"R_{severity}", rf"C:\Temp\{severity}.dat")
                code, _stdout, _stderr, _corr = self._run(["--quiet"], _scan_result([finding]))
                self.assertEqual(code, expected)

    def test_help_contains_v14_options(self) -> None:
        text = main.build_parser().format_help()
        for option in (
            "--fail-on-skipped",
            "--treat-version-bump-as-benign",
            "--campaign",
            "--campaign-shadow",
            "--fail-on-campaign",
            "--save-baseline",
            "--baseline",
        ):
            self.assertIn(option, text)
        self.assertIn("互斥", text)


# ---------------------------------------------------------------------------
# build.bat 静态断言（不执行构建）
# ---------------------------------------------------------------------------


class TestBuildBat(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (PROJECT_ROOT / "build.bat").read_text(encoding="utf-8", errors="ignore")
        self.lines = self.text.splitlines()
        self.common_line = next(
            (line for line in self.lines if line.strip().startswith("set COMMON=")), ""
        )

    def test_build_bat_detects_optional_skrapa(self) -> None:
        self.assertIn("pip show skrapa", self.text)
        self.assertIn("skrapa.windows", self.text)
        self.assertIn("WARNING", self.text)

    def test_build_bat_removes_skrapa_hidden_imports_when_missing(self) -> None:
        # 缺失分支先清空 SKRAPA_HIDDEN，COMMON 再引用该变量（未安装时不带 skrapa）
        self.assertIn('set "SKRAPA_HIDDEN="', self.text)
        self.assertIn("%SKRAPA_HIDDEN%", self.common_line)
        self.assertNotIn("--hidden-import skrapa.windows", self.common_line)
        self.assertLess(
            self.text.index("pip show skrapa"),
            self.text.index("set COMMON="),
        )

    def test_build_bat_cli_and_gui_share_common(self) -> None:
        self.assertTrue(self.common_line)
        lowered = self.text.lower()
        self.assertEqual(lowered.count("python -m pyinstaller %common%"), 2)
        self.assertIn("--name tamper_scan main.py", self.text)
        self.assertIn("--name tamper_scan_gui gui.py", self.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
