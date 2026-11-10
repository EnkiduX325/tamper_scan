# -*- coding: utf-8 -*-
"""``modules/unquoted_service_path.py`` 的单元测试。

全部使用构造的假路径，不依赖本机真实服务列表（最后有一条真实冒烟）：

1. ``_parse_unquoted_path``：含空格未加引号 / 已加引号 / 仅参数含空格 / 畸形引号；
2. ``_analyze_service``：SYSTEM 权限 + 未加引号 → MEDIUM；User/NetworkService 不报；
   候选劫持路径与"当前用户可写目录"证据；%VAR% 展开；超长路径截断；
3. ``scan()``：复用 ``service.collect_services`` 的采集结果（打桩），采集失败/结构异常/
   超限降级。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_unquoted_service_path.py
    python -m unittest discover -s tests -p "test_*.py" -v
    python tests\\test_unquoted_service_path.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.finding import SEVERITIES  # noqa: E402
from modules import unquoted_service_path as m  # noqa: E402

_FINDING_KEYS = {"severity", "category", "target", "detail", "evidence", "rule_id"}


def _service(**overrides: str) -> dict[str, str]:
    record = {
        "Name": "VulnSvc",
        "DisplayName": "Vulnerable Service",
        "PathName": r"C:\Program Files\My App\svc.exe",
        "StartMode": "Auto",
        "StartName": "LocalSystem",
        "State": "Running",
    }
    record.update(overrides)
    return record


class TestIsSystemAccount(unittest.TestCase):
    def test_system_variants(self) -> None:
        for value in (
            "LocalSystem",
            "localsystem",
            "NT AUTHORITY\\LocalSystem",
            "NT AUTHORITY\\SYSTEM",
            " .\\LocalSystem ",
        ):
            self.assertTrue(m._is_system_account(value), value)

    def test_non_system_accounts(self) -> None:
        for value in (
            "NT AUTHORITY\\NetworkService",
            "NT AUTHORITY\\LocalService",
            "DOMAIN\\svcuser",
            "",
            None,
            "User",
        ):
            self.assertFalse(m._is_system_account(value), value)


class TestParseUnquotedPath(unittest.TestCase):
    def test_unquoted_path_with_spaces_is_vulnerable(self) -> None:
        parsed = m._parse_unquoted_path(r"C:\Program Files\My App\svc.exe")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["actual_exe"], r"C:\Program Files\My App\svc.exe")
        self.assertEqual(parsed["first_token"], r"C:\Program")
        self.assertEqual(
            parsed["candidates"],
            [r"C:\Program.exe", r"C:\Program Files\My.exe"],
        )

    def test_unquoted_path_with_args(self) -> None:
        parsed = m._parse_unquoted_path(r"C:\Program Files\My App\svc.exe -k run")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["actual_exe"], r"C:\Program Files\My App\svc.exe")
        self.assertEqual(parsed["candidates"], [r"C:\Program.exe", r"C:\Program Files\My.exe"])

    def test_quoted_path_is_safe(self) -> None:
        for value in (
            r'"C:\Program Files\My App\svc.exe"',
            r'"C:\Program Files\My App\svc.exe" -k run',
        ):
            self.assertIsNone(m._parse_unquoted_path(value), value)

    def test_space_only_in_arguments_is_safe(self) -> None:
        for value in (
            r"C:\Windows\system32\svchost.exe -k netsvcs -p",
            r"C:\svc.exe -arg1 -arg2",
        ):
            self.assertIsNone(m._parse_unquoted_path(value), value)

    def test_no_space_is_safe(self) -> None:
        self.assertIsNone(m._parse_unquoted_path(r"C:\Windows\System32\termsrv.dll"))

    def test_empty_and_none_are_safe(self) -> None:
        for value in ("", "   ", None):
            self.assertIsNone(m._parse_unquoted_path(value), value)

    def test_unbalanced_quote_is_flagged(self) -> None:
        parsed = m._parse_unquoted_path(r'"C:\Program Files\My App\svc.exe')
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed["unbalanced_quote"])
        self.assertEqual(parsed["actual_exe"], r"C:\Program Files\My App\svc.exe")

    def test_expands_environment_variables(self) -> None:
        with mock.patch.object(
            m.utils, "expand_vars", side_effect=lambda value: str(value).replace("%ProgramFiles%", r"C:\Program Files")
        ):
            parsed = m._parse_unquoted_path(r"%ProgramFiles%\My App\svc.exe")
        self.assertIsNotNone(parsed)
        self.assertIn(r"C:\Program Files\My App\svc.exe", parsed["expanded"])

    def test_pathological_long_path_is_bounded(self) -> None:
        long_path = "C:\\" + "A" * 5000 + " Files\\svc.exe"
        parsed = m._parse_unquoted_path(long_path)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["expanded"], long_path)
        self.assertLessEqual(len(parsed["candidates"]), m._MAX_CANDIDATES)


class TestAnalyzeService(unittest.TestCase):
    def test_unquoted_system_service_is_medium(self) -> None:
        findings = m._analyze_service(_service())
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(set(finding), _FINDING_KEYS)
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["rule_id"], "SVC_UNQUOTED_PATH")
        self.assertEqual(finding["category"], "UnquotedServicePath")
        self.assertEqual(finding["target"], r"C:\Program Files\My App\svc.exe")
        evidence = finding["evidence"]
        self.assertEqual(evidence["service_name"], "VulnSvc")
        self.assertEqual(evidence["start_name"], "LocalSystem")
        self.assertFalse(evidence["quoted"])
        self.assertEqual(evidence["candidates"], [r"C:\Program.exe", r"C:\Program Files\My.exe"])
        self.assertIn("T1574.009", finding["detail"])

    def test_quoted_system_service_is_safe(self) -> None:
        findings = m._analyze_service(_service(PathName=r'"C:\Program Files\My App\svc.exe"'))
        self.assertEqual(findings, [])

    def test_user_service_is_ignored(self) -> None:
        findings = m._analyze_service(
            _service(PathName=r"C:\Program Files\My App\svc.exe", StartName="NT AUTHORITY\\NetworkService")
        )
        self.assertEqual(findings, [])

    def test_domain_user_service_is_ignored(self) -> None:
        findings = m._analyze_service(
            _service(PathName=r"C:\Program Files\My App\svc.exe", StartName="CONTOSO\\svcuser")
        )
        self.assertEqual(findings, [])

    def test_missing_path_is_ignored(self) -> None:
        self.assertEqual(m._analyze_service(_service(PathName="")), [])
        self.assertEqual(m._analyze_service(_service(PathName="   ")), [])

    def test_unbalanced_quote_is_medium(self) -> None:
        findings = m._analyze_service(_service(PathName=r'"C:\Program Files\My App\svc.exe'))
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertTrue(findings[0]["evidence"]["unbalanced_quote"])
        self.assertIn("缺少闭合引号", findings[0]["detail"])

    def test_writable_candidate_dirs_are_evidence(self) -> None:
        record = _service(
            Name="UserDirSvc",
            PathName=r"C:\Users\Public\My App\svc.exe",
            StartName="LocalSystem",
        )

        def _fake_writable(path: str) -> bool:
            return str(path).lower() == r"c:\users\public"

        with mock.patch.object(m.utils, "is_user_writable", side_effect=_fake_writable):
            findings = m._analyze_service(record)
        writable = findings[0]["evidence"]["writable_candidates"]
        self.assertEqual(len(writable), 1)
        self.assertEqual(writable[0]["directory"], r"C:\Users\Public")
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_long_path_is_truncated_in_evidence(self) -> None:
        long_path = "C:\\Program Files\\" + "VeryLongDirectoryName\\" * 40 + "svc.exe"
        findings = m._analyze_service(_service(PathName=long_path))
        self.assertEqual(len(findings), 1)
        evidence = findings[0]["evidence"]
        self.assertLessEqual(len(evidence["path_name"]), 400)
        self.assertGreater(evidence["path_name_length"], 400)
        self.assertLessEqual(len(findings[0]["detail"]), 400)

    def test_skips_when_parse_raises(self) -> None:
        with mock.patch.object(m, "_parse_unquoted_path", side_effect=RuntimeError("boom")):
            # 单条分析异常由 scan 兜底；纯函数这里允许抛出，验证 scan 隔离
            with self.assertRaises(RuntimeError):
                m._analyze_service(_service())


class TestScan(unittest.TestCase):
    _OK_SERVICE = _service()

    def test_reuses_service_module_collection(self) -> None:
        with mock.patch.object(
            m.service, "collect_services", return_value=([self._OK_SERVICE], None)
        ) as mocked:
            findings = m.scan()
        mocked.assert_called_once()
        self.assertEqual(mocked.call_args.kwargs.get("max_age_seconds"), m._SERVICE_CACHE_MAX_AGE)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SVC_UNQUOTED_PATH")

    def test_single_dict_record_is_normalized(self) -> None:
        with mock.patch.object(m.service, "collect_services", return_value=(self._OK_SERVICE, None)):
            findings = m.scan()
        self.assertEqual(len(findings), 1)

    def test_collection_error_is_skipped(self) -> None:
        with mock.patch.object(m.service, "collect_services", return_value=(None, "PowerShell 执行失败")):
            findings = m.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "SVC_UNQUOTED_SKIPPED")
        self.assertIn("复用 service 模块", findings[0]["detail"])

    def test_collection_exception_is_skipped(self) -> None:
        with mock.patch.object(m.service, "collect_services", side_effect=RuntimeError("boom")):
            findings = m.scan()
        self.assertEqual(findings[0]["rule_id"], "SVC_UNQUOTED_SKIPPED")

    def test_parse_error_is_skipped(self) -> None:
        with mock.patch.object(m.service, "collect_services", return_value=("not-a-list", None)):
            findings = m.scan()
        self.assertEqual(findings[0]["rule_id"], "SVC_UNQUOTED_PARSE_ERROR")
        self.assertEqual(findings[0]["severity"], "SKIPPED")

    def test_empty_service_list_returns_empty(self) -> None:
        with mock.patch.object(m.service, "collect_services", return_value=([], None)):
            self.assertEqual(m.scan(), [])

    def test_service_limit_adds_partial_skipped(self) -> None:
        records = [self._OK_SERVICE, self._OK_SERVICE, self._OK_SERVICE]
        with (
            mock.patch.object(m.service, "collect_services", return_value=(records, None)),
            mock.patch.object(m, "_MAX_SERVICES", 2),
        ):
            findings = m.scan()
        rule_ids = [finding["rule_id"] for finding in findings]
        self.assertIn("SVC_UNQUOTED_PATH", rule_ids)
        self.assertIn("SVC_UNQUOTED_PARTIAL", rule_ids)

    def test_invalid_record_is_isolated(self) -> None:
        records = [None, self._OK_SERVICE]  # type: ignore[list-item]
        with mock.patch.object(m.service, "collect_services", return_value=(records, None)):
            findings = m.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SVC_UNQUOTED_PATH")


@unittest.skipUnless(sys.platform == "win32", "仅 Windows 支持 CIM 服务采集")
class TestRealScanSmoke(unittest.TestCase):
    """真实环境冒烟：复用 service 采集，不假设本机是否存在脆弱服务，只要求不崩、结构合法。"""

    def test_scan_never_raises_and_findings_are_well_formed(self) -> None:
        findings = m.scan()
        self.assertIsInstance(findings, list)
        for finding in findings:
            self.assertEqual(set(finding), _FINDING_KEYS)
            self.assertIn(finding["severity"], SEVERITIES)
            self.assertIsInstance(finding["evidence"], dict)
            self.assertTrue(str(finding["rule_id"]).startswith("SVC_UNQUOTED_"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
