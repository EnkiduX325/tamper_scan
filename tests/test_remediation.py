# -*- coding: utf-8 -*-
"""``rules/remediation.json`` 与 reporter 只读修复建议（remediation）的单元测试。

覆盖范围：

1. ``load_remediation``：正常加载 / 文件缺失 / JSON 损坏 / 两种结构 / 非 dict 丢弃 /
   字段标准化 / 进程内缓存与 ``clear_remediation_cache`` 刷新；
2. ``apply_remediation``：精确 rule_id 命中 / 未命中 / ``evidence.merged_rules`` 命中 /
   规则基名兜底 / 不修改入参 / 返回新列表；
3. 纯只读断言：mock ``subprocess`` 与 ``os.system`` 后调用 ``apply_remediation``，
   断言绝不执行任何命令；
4. 真实 ``rules/remediation.json`` 覆盖全部 V1.2 规则 ID 且字段齐全；
5. ``build_report`` 挂载 remediation、JSON 可序列化、``render_html`` 包含「建议处理」
   区块、无 remediation 时不渲染、remediation 文本被 HTML 自动转义、jinja2 缺失兜底。

约束：不创建 ``tk.Tk()`` 窗口、不需要管理员权限、不读写真实注册表。

运行方式（仓库根目录）：

    python -m pytest -q tests\\\\test_remediation.py
    python -m unittest tests.test_remediation -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import reporter  # noqa: E402
from core.finding import make_finding  # noqa: E402

#: V1.2 新增规则（需求要求 remediation.json 必须全部覆盖）
V12_RULE_IDS: tuple[str, ...] = (
    "WINLOGON_SHELL_TAMPER",
    "WINLOGON_USERINIT_TAMPER",
    "WINLOGON_GINADLL_TAMPER",
    "WINLOGON_APPSETUP_TAMPER",
    "WINLOGON_TASKMAN_TAMPER",
    "WINLOGON_NOTIFY_TAMPER",
    "AUTOADMINLOGON_PLAINTEXT",
    "LSA_AUTH_PACKAGE_TAMPER",
    "NETSH_HELPER_TAMPER",
    "TIMEPROVIDER_DLL_TAMPER",
    "PRINT_PROCESSOR_TAMPER",
    "PRINT_MONITOR_TAMPER",
    "ACTIVE_SETUP_STUB",
    "APPCOMPAT_SHIM",
    "SILENTPROCESS_EXIT_TAMPER",
    "WER_LOCALDUMPS_TAMPER",
    "CMD_AUTORUN",
    "SCRNSAVER_TAMPER",
    "SVC_SERVICEDLL_TAMPER",
    "SVC_SERVICEDLL_ABSENT",
    "RDP_SERVICEDLL_TAMPER",
)

#: 重要既有规则（含 Lead 补充的 sample_report 命中项）
EXISTING_RULE_IDS: tuple[str, ...] = (
    "SIG_UNSIGNED",
    "SIG_INVALID",
    "LSA_PACKAGE_HIJACK",
    "RUN_REGISTRY",
    "LSA_APPINIT",
    "SIG_PATH_MASQUERADE",
    "AUTORUNS_USERWRITABLE",
    "DEFENDER_EXCLUSION",
    "EXT_PERM_HIGH",
    "EXT_PERM_MED",
    "COM_HIJACK_LOW",
)

REMEDIATION_KEYS = {"summary", "expected", "actual", "command", "risk", "requires_admin"}


def _finding(rule_id: str = "", evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return make_finding(
        "HIGH",
        "Test",
        "C:/tmp/sample.exe",
        "测试用 finding",
        evidence or {},
        rule_id,
    )


def _sample_remediation(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "summary": "测试建议",
        "expected": "期望值",
        "actual": "当前值",
        "command": 'reg query "HKCU\\Software\\Test"',
        "risk": "MEDIUM",
        "requires_admin": False,
    }
    payload.update(overrides)
    return payload


class _TempJsonMixin(unittest.TestCase):
    """提供临时 JSON 文件的辅助方法。"""

    def setUp(self) -> None:
        reporter.clear_remediation_cache()
        self.addCleanup(reporter.clear_remediation_cache)
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.tmp_dir = Path(self._dir.name)

    def write_json(self, name: str, payload: Any) -> Path:
        path = self.tmp_dir / name
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path


# ---------------------------------------------------------------------------
# load_remediation
# ---------------------------------------------------------------------------


class LoadRemediationTests(_TempJsonMixin):
    def test_real_remediation_file_loads(self) -> None:
        rules = reporter.load_remediation()
        self.assertIsInstance(rules, dict)
        self.assertGreaterEqual(len(rules), len(V12_RULE_IDS))
        for item in rules.values():
            self.assertIsInstance(item, dict)
            self.assertEqual(set(item), REMEDIATION_KEYS)

    def test_missing_file_returns_empty_dict(self) -> None:
        self.assertEqual(reporter.load_remediation(self.tmp_dir / "does_not_exist.json"), {})

    def test_corrupt_json_returns_empty_dict(self) -> None:
        path = self.tmp_dir / "broken.json"
        path.write_text("{ this is not json ", encoding="utf-8")
        self.assertEqual(reporter.load_remediation(path), {})

    def test_non_dict_root_returns_empty_dict(self) -> None:
        path = self.write_json("list.json", [{"rule": "X"}])
        self.assertEqual(reporter.load_remediation(path), {})

    def test_supports_rules_wrapper_structure(self) -> None:
        path = self.write_json(
            "wrapped.json",
            {"_comment": "测试", "rules": {"RULE_A": _sample_remediation()}},
        )
        rules = reporter.load_remediation(path)
        self.assertEqual(set(rules), {"RULE_A"})
        self.assertEqual(rules["RULE_A"]["risk"], "MEDIUM")

    def test_supports_direct_structure(self) -> None:
        path = self.write_json("direct.json", {"RULE_B": _sample_remediation(risk="HIGH")})
        rules = reporter.load_remediation(path)
        self.assertEqual(set(rules), {"RULE_B"})
        self.assertEqual(rules["RULE_B"]["risk"], "HIGH")

    def test_non_dict_entries_are_dropped(self) -> None:
        path = self.write_json(
            "mixed.json",
            {
                "rules": {
                    "GOOD": _sample_remediation(),
                    "BAD_STRING": "oops",
                    "BAD_LIST": [1, 2, 3],
                    "BAD_NULL": None,
                }
            },
        )
        self.assertEqual(set(reporter.load_remediation(path)), {"GOOD"})

    def test_fields_are_normalized(self) -> None:
        path = self.write_json(
            "normalize.json",
            {
                "rules": {
                    "RULE": {
                        "summary": "  说明  ",
                        "risk": "severe",
                        "requires_admin": 1,
                        "command": "  whoami  ",
                    }
                }
            },
        )
        item = reporter.load_remediation(path)["RULE"]
        self.assertEqual(item["summary"], "说明")
        self.assertEqual(item["expected"], "")
        self.assertEqual(item["actual"], "")
        self.assertEqual(item["command"], "whoami")
        self.assertEqual(item["risk"], "MEDIUM")  # 非法 risk 回退为 MEDIUM
        self.assertIs(item["requires_admin"], True)

    def test_cache_reused_until_cleared(self) -> None:
        path = self.write_json("cache.json", {"rules": {"RULE_C": _sample_remediation()}})
        with mock.patch.object(reporter.utils, "load_json", wraps=reporter.utils.load_json) as mocked:
            first = reporter.load_remediation(path)
            second = reporter.load_remediation(path)
            self.assertEqual(mocked.call_count, 1)
            self.assertEqual(first, second)

            reporter.clear_remediation_cache()
            reporter.load_remediation(path)
            self.assertEqual(mocked.call_count, 2)

    def test_returned_copy_does_not_pollute_cache(self) -> None:
        path = self.write_json("copy.json", {"rules": {"RULE_D": _sample_remediation()}})
        first = reporter.load_remediation(path)
        first["RULE_D"]["summary"] = "被调用方篡改"
        second = reporter.load_remediation(path)
        self.assertEqual(second["RULE_D"]["summary"], "测试建议")

    def test_default_path_points_at_rules_dir(self) -> None:
        self.assertEqual(reporter.REMEDIATION_PATH.name, "remediation.json")
        self.assertEqual(reporter.REMEDIATION_PATH.parent, reporter.utils.RULES_DIR)


# ---------------------------------------------------------------------------
# apply_remediation
# ---------------------------------------------------------------------------


class ApplyRemediationTests(_TempJsonMixin):
    def test_exact_rule_id_match(self) -> None:
        remediations = {"SIG_UNSIGNED": _sample_remediation(summary="无签名建议")}
        annotated = reporter.apply_remediation([_finding("SIG_UNSIGNED")], remediations)
        self.assertIn("remediation", annotated[0])
        self.assertEqual(annotated[0]["remediation"]["summary"], "无签名建议")
        self.assertEqual(set(annotated[0]["remediation"]), REMEDIATION_KEYS)

    def test_no_match_does_not_attach_remediation(self) -> None:
        annotated = reporter.apply_remediation([_finding("SOME_UNKNOWN_RULE")], {"SIG_UNSIGNED": _sample_remediation()})
        self.assertNotIn("remediation", annotated[0])

    def test_merged_rules_match(self) -> None:
        finding = _finding("CUSTOM_RULE", {"merged_rules": ["SIG_INVALID", "SIG_UNSIGNED"]})
        remediations = {"SIG_INVALID": _sample_remediation(summary="签名无效建议")}
        annotated = reporter.apply_remediation([finding], remediations)
        self.assertEqual(annotated[0]["remediation"]["summary"], "签名无效建议")

    def test_basename_fallback_matches_prefixed_rule(self) -> None:
        finding = _finding("AUTORUNS_SIG_UNSIGNED")
        remediations = {"SIG_UNSIGNED": _sample_remediation(summary="基名兜底命中")}
        annotated = reporter.apply_remediation([finding], remediations)
        self.assertEqual(annotated[0]["remediation"]["summary"], "基名兜底命中")

    def test_basename_fallback_matches_merged_prefixed_rule(self) -> None:
        finding = _finding("SOME_OTHER", {"merged_rules": ["AUTORUNS_SIG_PATH_MASQUERADE"]})
        remediations = {"SIG_PATH_MASQUERADE": _sample_remediation(summary="merged 基名命中")}
        annotated = reporter.apply_remediation([finding], remediations)
        self.assertEqual(annotated[0]["remediation"]["summary"], "merged 基名命中")

    def test_exact_match_preferred_over_basename(self) -> None:
        finding = _finding("AUTORUNS_SIG_UNSIGNED", {"merged_rules": ["SIG_UNSIGNED"]})
        remediations = {
            "AUTORUNS_SIG_UNSIGNED": _sample_remediation(summary="精确命中"),
            "SIG_UNSIGNED": _sample_remediation(summary="基名命中"),
        }
        annotated = reporter.apply_remediation([finding], remediations)
        self.assertEqual(annotated[0]["remediation"]["summary"], "精确命中")

    def test_does_not_mutate_input_findings(self) -> None:
        finding = _finding("SIG_UNSIGNED", {"status": "unsigned"})
        snapshot = json.loads(json.dumps(finding))
        annotated = reporter.apply_remediation([finding], {"SIG_UNSIGNED": _sample_remediation()})
        self.assertIn("remediation", annotated[0])
        self.assertEqual(finding, snapshot)
        self.assertNotIn("remediation", finding)

    def test_returns_new_list_and_new_entries(self) -> None:
        findings = [_finding("SIG_UNSIGNED"), _finding("OTHER")]
        expected_inputs = list(findings)
        annotated = reporter.apply_remediation(findings, {"SIG_UNSIGNED": _sample_remediation()})
        self.assertIsNot(annotated, findings)
        self.assertEqual(len(annotated), 2)
        for index in range(2):
            self.assertIsNot(annotated[index], expected_inputs[index])

    def test_non_dict_remediation_entries_are_ignored(self) -> None:
        annotated = reporter.apply_remediation(
            [_finding("BROKEN")],
            {"BROKEN": "not-a-dict"},  # type: ignore[dict-item]
        )
        self.assertNotIn("remediation", annotated[0])

    def test_defaults_to_real_remediation_file(self) -> None:
        annotated = reporter.apply_remediation([_finding("WINLOGON_SHELL_TAMPER")])
        self.assertIn("remediation", annotated[0])
        self.assertEqual(annotated[0]["remediation"]["risk"], "HIGH")

    def test_empty_findings_returns_empty_list(self) -> None:
        self.assertEqual(reporter.apply_remediation([], {"SIG_UNSIGNED": _sample_remediation()}), [])

    def test_apply_is_read_only_no_process_execution(self) -> None:
        with mock.patch("subprocess.Popen") as popen, mock.patch("subprocess.run") as run, mock.patch(
            "subprocess.call"
        ) as call, mock.patch("subprocess.check_call") as check_call, mock.patch(
            "subprocess.check_output"
        ) as check_output, mock.patch("os.system") as system, mock.patch("os.popen") as popen_os:
            annotated = reporter.apply_remediation(
                [
                    _finding("WINLOGON_SHELL_TAMPER"),
                    _finding("SIG_UNSIGNED"),
                    _finding("CMD_AUTORUN"),
                    _finding("RDP_SERVICEDLL_TAMPER"),
                ]
            )
        self.assertEqual(len(annotated), 4)
        for mocked in (popen, run, call, check_call, check_output, system, popen_os):
            mocked.assert_not_called()
        # command 只是文本，原样挂载，不参与执行
        self.assertIn("reg query", annotated[0]["remediation"]["command"])


# ---------------------------------------------------------------------------
# 真实 rules/remediation.json 覆盖与字段
# ---------------------------------------------------------------------------


class RealRulesCoverageTests(_TempJsonMixin):
    def test_required_rule_ids_are_covered(self) -> None:
        rules = reporter.load_remediation()
        missing = [rule_id for rule_id in (*V12_RULE_IDS, *EXISTING_RULE_IDS) if rule_id not in rules]
        self.assertEqual(missing, [], f"remediation.json 缺少规则: {missing}")

    def test_all_fields_present_and_valid(self) -> None:
        rules = reporter.load_remediation()
        for rule_id, item in rules.items():
            with self.subTest(rule_id=rule_id):
                self.assertEqual(set(item), REMEDIATION_KEYS)
                self.assertIn(item["risk"], reporter.REMEDIATION_RISK_LEVELS)
                self.assertIsInstance(item["requires_admin"], bool)
                self.assertIsInstance(item["command"], str)
                self.assertTrue(item["summary"].strip())
                self.assertTrue(item["expected"].strip())
                self.assertTrue(item["actual"].strip())
                self.assertTrue(item["command"].strip())

    def test_command_is_manual_suggestion_not_executed(self) -> None:
        """规则库里的 command 只能是手动复制文本：不含自动执行/下载类危险动作。"""
        rules = reporter.load_remediation()
        forbidden = ("invoke-expression", "iex(", "downloadstring", "curl ", "wget ", "bitsadmin")
        for rule_id, item in rules.items():
            with self.subTest(rule_id=rule_id):
                lowered = item["command"].lower()
                for token in forbidden:
                    self.assertNotIn(token, lowered, f"{rule_id} 的命令包含危险动作: {token}")

    def test_all_v12_rules_have_remediation_when_applied(self) -> None:
        annotated = reporter.apply_remediation([_finding(rule_id) for rule_id in V12_RULE_IDS])
        for finding in annotated:
            with self.subTest(rule_id=finding["rule_id"]):
                self.assertIn("remediation", finding)
                self.assertEqual(set(finding["remediation"]), REMEDIATION_KEYS)


# ---------------------------------------------------------------------------
# build_report / HTML / JSON
# ---------------------------------------------------------------------------


class ReportRenderingTests(_TempJsonMixin):
    def _report(self, *rule_ids: str) -> dict[str, Any]:
        findings = [_finding(rule_id) for rule_id in rule_ids]
        return reporter.build_report(findings, version="1.2.0", duration_seconds=1.5)

    def test_build_report_attaches_remediation(self) -> None:
        report = self._report("WINLOGON_SHELL_TAMPER")
        self.assertEqual(len(report["findings"]), 1)
        self.assertIn("remediation", report["findings"][0])
        self.assertEqual(report["findings"][0]["remediation"]["risk"], "HIGH")

    def test_build_report_structure_unchanged(self) -> None:
        report = self._report("SIG_UNSIGNED")
        self.assertEqual(
            set(report),
            {"tool", "version", "generated_at", "host", "scan", "summary", "findings"},
        )
        self.assertEqual(report["tool"], "TamperScan")
        self.assertEqual(report["version"], "1.2.0")
        self.assertEqual(report["summary"]["total"], 1)
        self.assertIn("exit_code", report["summary"])
        self.assertEqual(report["scan"]["duration_seconds"], 1.5)

    def test_report_json_is_serializable(self) -> None:
        report = self._report("SIG_INVALID", "LSA_APPINIT")
        text = reporter.render_json(report)
        parsed = json.loads(text)
        self.assertEqual(len(parsed["findings"]), 2)
        self.assertIn("remediation", parsed["findings"][0])

    def test_render_html_contains_remediation_section(self) -> None:
        report = self._report("WINLOGON_SHELL_TAMPER")
        html = reporter.render_html(report)
        self.assertIn("建议处理", html)
        self.assertIn("remediation-meta", html)
        self.assertIn("remediation-command", html)
        self.assertIn("explorer.exe", html)  # command/expected 内容进入报告

    def test_render_html_without_remediation_omits_section(self) -> None:
        report = self._report("TOTALLY_UNKNOWN_RULE_XYZ")
        html = reporter.render_html(report)
        self.assertNotIn("建议处理", html)
        self.assertNotIn('<section class="remediation">', html)

    def test_render_html_escapes_remediation_content(self) -> None:
        report = self._report("SIG_UNSIGNED")
        report["findings"][0]["remediation"] = _sample_remediation(
            summary="<script>alert(1)</script>",
            expected='<img src=x onerror="alert(2)">',
            command="echo <script>alert(3)</script>",
        )
        html = reporter.render_html(report)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("<script>alert(3)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("&lt;img src=x onerror=", html)

    def test_fallback_html_supports_remediation_and_escaping(self) -> None:
        report = self._report("SIG_UNSIGNED")
        report["findings"][0]["remediation"] = _sample_remediation(
            summary="<b>兜底建议</b>",
            command="echo <script>alert(1)</script>",
        )
        with mock.patch.object(reporter, "JINJA2_AVAILABLE", False):
            html = reporter.render_html(report)
        self.assertIn("建议处理", html)
        self.assertIn("&lt;b&gt;兜底建议&lt;/b&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)

    def test_fallback_html_without_remediation_omits_section(self) -> None:
        report = self._report("TOTALLY_UNKNOWN_RULE_XYZ")
        with mock.patch.object(reporter, "JINJA2_AVAILABLE", False):
            html = reporter.render_html(report)
        self.assertNotIn("建议处理", html)
        self.assertNotIn('<section class="remediation">', html)


if __name__ == "__main__":
    unittest.main()
