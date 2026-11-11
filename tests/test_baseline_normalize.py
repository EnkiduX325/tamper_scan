# -*- coding: utf-8 -*-
"""``core/baseline.py`` V1.4 严格 target 归一化（``normalize_target``）测试。

覆盖：
- 环境变量展开、``\\\\?\\`` / ``\\??\\`` 长路径前缀、``\\\\?\\UNC`` 还原；
- Sysnative → System32（大小写不敏感）、normcase、尾随空格/分隔符、盘符根保留；
- auto 启发式（盘符/UNC/相对路径 → path；HKLM 等注册表 → registry，不调文件 API）；
- ``GetLongPathNameW`` mock：成功解析 8.3 短名、失败保留原值、异常不抛出、非 Windows 跳过；
- ``normalize_target`` 对 None/非字符串/``__str__`` 异常对象的防御；
- index / target_key 使用新归一化（更严格匹配、不误配对）；
- ``annotate_findings`` 写 ``normalized_key``（当前项 + RESOLVED 项），无 diff 路径不写。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_baseline_normalize.py
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import baseline  # noqa: E402

_ENV_ROOT = "TS_NORM_ROOT"


def _finding(rule_id: str, target: str, severity: str = "HIGH", **evidence: object) -> dict:
    return {
        "severity": severity,
        "rule_id": rule_id,
        "target": target,
        "detail": "",
        "evidence": dict(evidence),
    }


def _report(*findings: dict) -> dict:
    return {"tool": "TamperScan", "version": "1.5.0", "findings": list(findings)}


def _fake_kernel32(result_path: str):
    """构造 GetLongPathNameW mock：把 result_path 写入缓冲区并返回长度。"""

    def _get_long_path_name(_path: str, buffer: object, _size: int) -> int:
        if buffer is not None:
            buffer.value = result_path  # type: ignore[attr-defined]
        return len(result_path) + 1

    kernel32 = mock.Mock()
    kernel32.GetLongPathNameW.side_effect = _get_long_path_name
    return kernel32


class TestNormalizeDefensive(unittest.TestCase):
    def test_none_and_blank(self) -> None:
        self.assertEqual(baseline.normalize_target(None), "")
        self.assertEqual(baseline.normalize_target(""), "")
        self.assertEqual(baseline.normalize_target("   \t "), "")

    def test_non_string_values_do_not_crash(self) -> None:
        self.assertEqual(baseline.normalize_target(123), "123")
        self.assertEqual(baseline.normalize_target(True), "true")
        self.assertEqual(baseline.normalize_target(3.5), "3.5")

    def test_broken_str_returns_empty(self) -> None:
        class _Bad:
            def __str__(self) -> str:
                raise RuntimeError("boom")

        self.assertEqual(baseline.normalize_target(_Bad()), "")


class TestNormalizePathRules(unittest.TestCase):
    def test_env_vars_expanded(self) -> None:
        with mock.patch.dict(os.environ, {_ENV_ROOT: r"C:\Windows"}):
            value = baseline.normalize_target(rf"%{_ENV_ROOT}%\System32\tamper_probe_norm.dll")
        self.assertEqual(value, r"c:\windows\system32\tamper_probe_norm.dll")

    def test_long_path_prefix_stripped(self) -> None:
        self.assertEqual(
            baseline.normalize_target(r"\\?\C:\Windows\System32\tamper_probe_norm.dll"),
            r"c:\windows\system32\tamper_probe_norm.dll",
        )
        self.assertEqual(
            baseline.normalize_target(r"\??\C:\Windows\System32\tamper_probe_norm.dll"),
            r"c:\windows\system32\tamper_probe_norm.dll",
        )

    def test_unc_long_path_prefix_restored(self) -> None:
        self.assertEqual(
            baseline.normalize_target(r"\\?\UNC\server\share\tamper_probe_norm.dll"),
            r"\\server\share\tamper_probe_norm.dll",
        )

    def test_sysnative_converted_case_insensitively(self) -> None:
        expected = rf"c:\windows\system32\tamper_probe_norm.dll"
        self.assertEqual(
            baseline.normalize_target(r"C:\Windows\Sysnative\tamper_probe_norm.dll"), expected
        )
        self.assertEqual(
            baseline.normalize_target(r"C:\Windows\SYSNATIVE\tamper_probe_norm.dll"), expected
        )

    def test_normcase_and_forward_slashes(self) -> None:
        self.assertEqual(
            baseline.normalize_target("C:/WINDOWS/System32/A.DLL"),
            r"c:\windows\system32\a.dll",
        )

    def test_trailing_spaces_and_separators_removed(self) -> None:
        self.assertEqual(
            baseline.normalize_target("  C:\\Windows\\System32\\TamperProbe.DLL   "),
            r"c:\windows\system32\tamperprobe.dll",
        )
        self.assertEqual(
            baseline.normalize_target("C:\\Windows\\System32\\"), r"c:\windows\system32"
        )

    def test_drive_root_separator_is_preserved(self) -> None:
        self.assertEqual(baseline.normalize_target("C:\\"), "c:\\")
        self.assertEqual(baseline.normalize_target("c:/"), "c:\\")

    def test_idempotent(self) -> None:
        once = baseline.normalize_target(r"C:\Windows\Sysnative\A.DLL ")
        self.assertEqual(baseline.normalize_target(once), once)

    def test_relative_path_like_target_uses_path_rules(self) -> None:
        value = baseline.normalize_target(r"TamperScanNoSuchDir\Evil.DLL")
        self.assertEqual(value, r"tamperscannosuchdir\evil.dll")

    def test_registry_target_does_not_call_file_api(self) -> None:
        with mock.patch.object(baseline, "_long_path_from_kernel32") as resolver:
            value = baseline.normalize_target(r"HKLM\SOFTWARE\Microsoft\Windows\Run\Evil")
        resolver.assert_not_called()
        self.assertEqual(value, r"hklm\software\microsoft\windows\run\evil")

    def test_registry_explicit_type_normalizes_separators_and_whitespace(self) -> None:
        self.assertEqual(
            baseline.normalize_target("  HKLM/SOFTWARE/Run/Evil/  ", "registry"),
            r"hklm\software\run\evil",
        )

    def test_registry_hive_variants_detected_by_auto(self) -> None:
        for target in (
            r"HKEY_LOCAL_MACHINE\Software\Run\X",
            r"HKCU\Software\Run\X",
            r"HKEY_USERS\S-1-5-21\Software\X",
        ):
            self.assertFalse(baseline._looks_like_path_target(target), target)
            self.assertTrue(baseline._looks_like_registry_target(target), target)

    def test_target_type_unknown_falls_back_to_auto(self) -> None:
        target = r"C:\Windows\System32\TamperProbe.DLL"
        self.assertEqual(
            baseline.normalize_target(target, "bogus"),
            baseline.normalize_target(target, "auto"),
        )

    def test_forced_path_type_skips_registry_heuristic(self) -> None:
        with mock.patch.object(baseline, "_long_path_from_kernel32", side_effect=lambda value: value):
            value = baseline.normalize_target(r"HKLM\Software\Run\X", "path")
        self.assertEqual(value, r"hklm\software\run\x")


class TestGetLongPathNameMock(unittest.TestCase):
    def test_short_name_resolved_to_long_name(self) -> None:
        kernel32 = _fake_kernel32(r"C:\Program Files\Vendor\app.dll")
        with mock.patch.object(baseline, "_get_kernel32", return_value=kernel32):
            value = baseline.normalize_target(r"C:\PROGRA~1\VENDOR\APP.DLL")
        self.assertEqual(value, r"c:\program files\vendor\app.dll")
        called_path = kernel32.GetLongPathNameW.call_args.args[0]
        self.assertIn("progra~1", called_path.lower())

    def test_failure_keeps_original_value(self) -> None:
        kernel32 = mock.Mock()
        kernel32.GetLongPathNameW.return_value = 0
        with mock.patch.object(baseline, "_get_kernel32", return_value=kernel32):
            value = baseline.normalize_target(r"C:\PROGRA~1\VENDOR\APP.DLL")
        self.assertEqual(value, r"c:\progra~1\vendor\app.dll")

    def test_exception_keeps_original_value(self) -> None:
        kernel32 = mock.Mock()
        kernel32.GetLongPathNameW.side_effect = OSError("api boom")
        with mock.patch.object(baseline, "_get_kernel32", return_value=kernel32):
            value = baseline.normalize_target(r"C:\PROGRA~1\VENDOR\APP.DLL")
        self.assertEqual(value, r"c:\progra~1\vendor\app.dll")

    def test_non_windows_skips_file_api(self) -> None:
        with (
            mock.patch.object(baseline.os, "name", "posix"),
            mock.patch.object(baseline, "_get_kernel32") as getter,
        ):
            value = baseline.normalize_target(r"C:\PROGRA~1\VENDOR\APP.DLL")
        getter.assert_not_called()
        self.assertEqual(value, r"c:\progra~1\vendor\app.dll")


class TestIndexAndMatching(unittest.TestCase):
    def test_target_key_delegates_to_normalize_target(self) -> None:
        self.assertEqual(
            baseline.target_key("  C:\\Windows\\A.EXE "), r"c:\windows\a.exe"
        )
        self.assertEqual(baseline.target_key(None), "")

    def test_index_collapses_case_and_separator_variants(self) -> None:
        index = baseline.index_findings(
            [
                _finding("R", r"C:\Windows\A.DLL", "LOW"),
                _finding("R", "C:/WiNdOwS/a.dll", "HIGH"),
            ]
        )
        self.assertEqual(len(index), 1)
        (key, kept), = index.items()
        self.assertEqual(key[0], r"c:\windows\a.dll")
        self.assertEqual(kept["severity"], "HIGH")

    def test_registry_and_file_path_are_not_paired(self) -> None:
        diff = baseline.diff_reports(
            _report(_finding("R", r"HKLM\Run\X")),
            _report(_finding("R", r"C:\Run\X")),
        )
        self.assertEqual(diff.counts["NEW"], 1)
        self.assertEqual(diff.counts["RESOLVED"], 1)
        self.assertEqual(diff.counts["UNCHANGED"], 0)

    def test_trailing_separator_variants_match(self) -> None:
        diff = baseline.diff_reports(
            _report(_finding("R", "C:\\Windows\\System32\\")),
            _report(_finding("R", "C:\\Windows\\System32")),
        )
        self.assertEqual(diff.entries[0].status, baseline.DIFF_UNCHANGED)

    def test_env_var_variants_match(self) -> None:
        with mock.patch.dict(os.environ, {_ENV_ROOT: r"C:\Windows"}):
            diff = baseline.diff_reports(
                _report(_finding("R", rf"%{_ENV_ROOT}%\System32\tamper_probe_norm.dll")),
                _report(_finding("R", r"C:\Windows\System32\tamper_probe_norm.dll")),
            )
        self.assertEqual(diff.entries[0].status, baseline.DIFF_UNCHANGED)


class TestAnnotateNormalizedKey(unittest.TestCase):
    def test_current_and_resolved_items_get_normalized_key(self) -> None:
        diff = baseline.diff_reports(
            _report(_finding("R", "C:\\Gone.EXE")),
            _report(_finding("R", "C:\\New.EXE")),
        )
        annotated = baseline.annotate_findings([_finding("R", "C:\\New.EXE")], diff)
        by_status = {item["diff_status"]: item for item in annotated}
        self.assertEqual(by_status[baseline.DIFF_NEW]["normalized_key"], r"c:\new.exe")
        self.assertEqual(
            by_status[baseline.DIFF_RESOLVED]["normalized_key"], r"c:\gone.exe"
        )

    def test_no_diff_path_has_no_normalized_key(self) -> None:
        finding = _finding("R", "C:\\x.exe")
        annotated = baseline.annotate_findings([finding], None)
        self.assertNotIn("normalized_key", annotated[0])
        self.assertNotIn("normalized_key", finding)

    def test_annotate_does_not_mutate_input(self) -> None:
        finding = _finding("R", "C:\\x.exe")
        diff = baseline.diff_reports(_report(_finding("R", "C:\\x.exe")), _report(dict(finding)))
        snapshot = json.dumps(finding, sort_keys=True)
        baseline.annotate_findings([finding], diff)
        self.assertEqual(json.dumps(finding, sort_keys=True), snapshot)

    def test_unmatched_finding_also_gets_normalized_key(self) -> None:
        diff = baseline.diff_reports(_report([]), _report([_finding("R", "C:\\x.exe")]))
        annotated = baseline.annotate_findings(
            [_finding("R", "C:\\x.exe"), _finding("OTHER", "HKLM\\Run\\Y")], diff
        )
        self.assertEqual(len(annotated), 2)
        for item in annotated:
            self.assertIn("normalized_key", item)
        self.assertEqual(annotated[1]["normalized_key"], r"hklm\run\y")


if __name__ == "__main__":
    unittest.main(verbosity=2)
