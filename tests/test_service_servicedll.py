# -*- coding: utf-8 -*-
"""``modules/service.py`` V1.2 泛化 ServiceDll 校验 + 与 RDP 规则合并的单元测试。

不要求管理员权限、不写真实 HKLM：

1. 纯函数 ``_analyze_service_dll``：系统目录+微软签名不报、系统目录外第三方签名
   HIGH、文件缺失 ABSENT、空值跳过、非 PE TAMPER、%VAR% 展开、evidence 字段；
2. 枚举层 ``_iter_service_dll_entries``：HKCU 合成 Services 结构验证 REG_SZ /
   REG_EXPAND_SZ 读取、64 位视图标志、单子键读取失败不中断、根键不可读降级；
3. ``_scan_all_service_dlls``：多服务聚合、读取失败条目跳过；
4. ``service.scan()`` 集成：泛化检查追加在 CIM 检查之后、异常不抛出、64 位视图；
5. ``core.finding``：``RDP_SERVICEDLL_TAMPER`` 与 ``SVC_SERVICEDLL_TAMPER`` 同 target
   经 ``dedupe_findings(merge_rule_base=True)`` 合并为一条（merged_rules 记录两边）。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_service_servicedll.py
    python -m unittest discover -s tests -p "test_*.py" -v
    python tests\\test_service_servicedll.py
"""

from __future__ import annotations

import os
import sys
import unittest
import uuid
import winreg
from pathlib import Path
from typing import Any
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.finding import dedupe_findings, rule_basename  # noqa: E402
from modules import service  # noqa: E402

_FINDING_KEYS = {"severity", "category", "target", "detail", "evidence", "rule_id"}

_HKCU_TEST_PARENT = r"Software\TamperScanTests"
_HKCU_TEST_ROOT = rf"{_HKCU_TEST_PARENT}\ServiceDll\{uuid.uuid4().hex}"
_HKCU_SERVICES = rf"{_HKCU_TEST_ROOT}\Services"

SYSTEM32 = r"C:\Windows\System32"

MS_SIG: dict[str, Any] = {"status": "valid", "signer": "Microsoft Windows", "via": "embedded", "error": None}
THIRD_PARTY_SIG: dict[str, Any] = {"status": "valid", "signer": "Contoso Ltd", "via": "embedded", "error": None}
UNSIGNED_SIG: dict[str, Any] = {"status": "unsigned", "signer": None, "via": None, "error": None}
INVALID_SIG: dict[str, Any] = {"status": "invalid", "signer": None, "via": "embedded", "error": "TRUST_E_BAD_DIGEST"}
MISSING_SIG: dict[str, Any] = {"status": "missing", "signer": None, "via": None, "error": "文件不存在"}


def _path_state(
    *,
    exists: bool = True,
    in_system: bool = False,
) -> dict[str, Any]:
    return {"exists": exists, "in_system_dir": in_system}


class TestAnalyzeServiceDll(unittest.TestCase):
    """单个服务的 ServiceDll 判定（纯函数）。"""

    def test_system_dir_with_microsoft_signature_has_no_finding(self) -> None:
        dll = rf"{SYSTEM32}\termsrv.dll"
        findings = service._analyze_service_dll(
            "TermService",
            dll,
            r"HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters",
            _path_state(in_system=True),
            MS_SIG,
        )
        self.assertEqual(findings, [])

    def test_outside_system_with_third_party_signature_is_high(self) -> None:
        dll = r"C:\Users\Public\evilsvc.dll"
        findings = service._analyze_service_dll(
            "EvilSvc",
            dll,
            r"HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc\Parameters",
            _path_state(in_system=False),
            THIRD_PARTY_SIG,
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(set(finding), _FINDING_KEYS)
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["rule_id"], "SVC_SERVICEDLL_TAMPER")
        self.assertEqual(finding["target"], dll)
        self.assertIn("EvilSvc", finding["detail"])

    def test_unsigned_and_invalid_signatures_are_high(self) -> None:
        dll = r"C:\ProgramData\payload.dll"
        for sig in (UNSIGNED_SIG, INVALID_SIG):
            findings = service._analyze_service_dll("Svc", dll, "", _path_state(), sig)
            self.assertEqual(len(findings), 1, sig)
            self.assertEqual(findings[0]["rule_id"], "SVC_SERVICEDLL_TAMPER")

    def test_valid_microsoft_signature_outside_system_is_not_reported(self) -> None:
        """按 V1.2 规范：系统目录外但有有效微软签名的 DLL 不报。"""
        dll = r"C:\Program Files\Vendor\legit.dll"
        findings = service._analyze_service_dll("LegitSvc", dll, "", _path_state(), MS_SIG)
        self.assertEqual(findings, [])

    def test_missing_file_is_absent_high(self) -> None:
        dll = rf"{SYSTEM32}\ghost.dll"
        findings = service._analyze_service_dll(
            "GhostSvc",
            dll,
            r"HKLM\SYSTEM\CurrentControlSet\Services\GhostSvc\Parameters",
            _path_state(exists=False, in_system=True),
            MISSING_SIG,
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["rule_id"], "SVC_SERVICEDLL_ABSENT")
        self.assertEqual(finding["target"], dll)
        self.assertIn("不存在", finding["detail"])
        self.assertFalse(finding["evidence"]["exists"])

    def test_empty_service_dll_is_skipped(self) -> None:
        for raw in ("", "   ", "\t"):
            self.assertEqual(
                service._analyze_service_dll("Svc", raw, "", _path_state(), UNSIGNED_SIG),
                [],
                raw,
            )

    def test_non_pe_file_outside_system_is_tamper(self) -> None:
        dll = r"C:\ProgramData\payload.bin"
        findings = service._analyze_service_dll(
            "OddSvc",
            dll,
            "",
            _path_state(in_system=False),
            MS_SIG,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SVC_SERVICEDLL_TAMPER")
        self.assertIn("PE", findings[0]["detail"])

    def test_evidence_fields(self) -> None:
        dll = r"C:\Users\Public\evil.dll"
        registry_key = r"HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc\Parameters"
        findings = service._analyze_service_dll(
            "EvilSvc",
            dll,
            registry_key,
            _path_state(in_system=False),
            THIRD_PARTY_SIG,
        )
        evidence = findings[0]["evidence"]
        self.assertEqual(evidence["service_name"], "EvilSvc")
        self.assertEqual(evidence["registry_key"], registry_key)
        self.assertEqual(evidence["value_name"], "ServiceDll")
        self.assertEqual(evidence["raw_value"], dll)
        self.assertEqual(evidence["expanded_path"], dll)
        self.assertEqual(evidence["service_dll"], dll)
        self.assertEqual(evidence["dll"], dll)
        self.assertIs(evidence["in_system_dir"], False)
        self.assertIs(evidence["exists"], True)
        self.assertEqual(
            evidence["signature"],
            {"status": "valid", "signer": "Contoso Ltd", "via": "embedded"},
        )
        self.assertEqual(evidence["signer"], "Contoso Ltd")

    def test_env_vars_are_expanded_in_target_and_evidence(self) -> None:
        raw = r"%TS_TEST_ROOT%\Bad\evil.dll"
        with mock.patch.dict(os.environ, {"TS_TEST_ROOT": r"C:\Windows"}):
            findings = service._analyze_service_dll(
                "EvilSvc",
                raw,
                "",
                _path_state(in_system=False),
                UNSIGNED_SIG,
            )
        self.assertEqual(len(findings), 1)
        expanded = r"C:\Windows\Bad\evil.dll"
        self.assertEqual(findings[0]["target"], expanded)
        self.assertEqual(findings[0]["evidence"]["expanded_path"], expanded)
        self.assertEqual(findings[0]["evidence"]["raw_value"], raw)


class TestIterServiceDllEntries(unittest.TestCase):
    """真实 winreg：HKCU 下合成 Services 结构（不触碰真实 HKLM）。"""

    @classmethod
    def setUpClass(cls) -> None:
        _delete_key_tree(winreg.HKEY_CURRENT_USER, _HKCU_TEST_ROOT)
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _HKCU_SERVICES, 0, winreg.KEY_ALL_ACCESS) as services_key:
            with winreg.CreateKeyEx(services_key, r"SvcA\Parameters", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "ServiceDll", 0, winreg.REG_EXPAND_SZ, r"%SystemRoot%\System32\a.dll")
            # SvcB：没有 Parameters 子键
            with winreg.CreateKeyEx(services_key, r"SvcC\Parameters", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "Other", 0, winreg.REG_SZ, "x")
            with winreg.CreateKeyEx(services_key, r"SvcD\Parameters", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "ServiceDll", 0, winreg.REG_SZ, r"C:\ProgramData\d.dll")
            with winreg.CreateKeyEx(services_key, r"SvcE\Parameters", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "ServiceDll", 0, winreg.REG_DWORD, 1)

    @classmethod
    def tearDownClass(cls) -> None:
        _delete_key_tree(winreg.HKEY_CURRENT_USER, _HKCU_TEST_ROOT)
        for parent in (rf"{_HKCU_TEST_PARENT}\ServiceDll", _HKCU_TEST_PARENT):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, parent)
            except OSError:
                break

    def test_enumerates_only_services_with_string_servicedll(self) -> None:
        entries = service._iter_service_dll_entries(
            hive=winreg.HKEY_CURRENT_USER,
            root=_HKCU_SERVICES,
            view_flag=0,
        )
        by_name = {entry["service_name"]: entry for entry in entries}
        self.assertEqual(set(by_name), {"SvcA", "SvcD"})
        self.assertEqual(by_name["SvcA"]["raw_value"], r"%SystemRoot%\System32\a.dll")
        self.assertEqual(by_name["SvcA"]["registry_key"], rf"HKCU\{_HKCU_SERVICES}\SvcA\Parameters")
        self.assertEqual(by_name["SvcD"]["raw_value"], r"C:\ProgramData\d.dll")
        self.assertIsNone(by_name["SvcA"]["error"])
        self.assertEqual(by_name["SvcA"]["value_type"], winreg.REG_EXPAND_SZ)

    def test_single_subkey_read_failure_is_recorded_and_skipped(self) -> None:
        def _fake_read(service_name: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
            if service_name == "SvcA":
                return {
                    "service_name": service_name,
                    "registry_key": rf"HKCU\{_HKCU_SERVICES}\SvcA\Parameters",
                    "raw_value": "",
                    "value_type": None,
                    "error": "access_denied",
                }
            return {
                "service_name": service_name,
                "registry_key": rf"HKCU\{_HKCU_SERVICES}\{service_name}\Parameters",
                "raw_value": r"C:\ProgramData\d.dll",
                "value_type": winreg.REG_SZ,
                "error": None,
            }

        with mock.patch.object(service, "_read_service_dll_entry", side_effect=_fake_read):
            entries = service._iter_service_dll_entries(
                hive=winreg.HKEY_CURRENT_USER,
                root=_HKCU_SERVICES,
                view_flag=0,
            )
        by_name = {entry["service_name"]: entry for entry in entries}
        self.assertEqual(by_name["SvcA"]["error"], "access_denied")
        self.assertIsNone(by_name["SvcD"]["error"])
        self.assertEqual(len(entries), 4)

    def test_unreadable_root_returns_empty_list(self) -> None:
        with mock.patch.object(service.winreg, "OpenKey", side_effect=OSError("access denied")):
            entries = service._iter_service_dll_entries(
                hive=winreg.HKEY_CURRENT_USER,
                root=r"Software\NoSuchRootForTamperScan",
                view_flag=0,
            )
        self.assertEqual(entries, [])

    def test_root_open_uses_64bit_view_flag(self) -> None:
        with mock.patch.object(service.winreg, "OpenKey", side_effect=OSError("denied")) as opened:
            service._iter_service_dll_entries()
        self.assertEqual(opened.call_count, 1)
        args = opened.call_args.args
        self.assertEqual(args[0], winreg.HKEY_LOCAL_MACHINE)
        self.assertEqual(args[1], r"SYSTEM\CurrentControlSet\Services")
        self.assertEqual(args[3], winreg.KEY_READ | winreg.KEY_WOW64_64KEY)


class TestScanAllServiceDlls(unittest.TestCase):
    """泛化扫描编排：多服务聚合 + 读取失败条目跳过。"""

    @staticmethod
    def _entry(service_name: str, raw_value: str, error: str | None = None) -> dict[str, Any]:
        return {
            "service_name": service_name,
            "registry_key": rf"HKLM\SYSTEM\CurrentControlSet\Services\{service_name}\Parameters",
            "raw_value": raw_value,
            "value_type": winreg.REG_EXPAND_SZ,
            "error": error,
        }

    def test_aggregates_multiple_services_and_skips_read_errors(self) -> None:
        entries = [
            self._entry("EvilOne", r"C:\Users\Public\evil1.dll"),
            self._entry("Broken", "", error="access_denied"),
            self._entry("Empty", ""),
            self._entry("EvilTwo", r"C:\Temp\evil2.dll"),
            self._entry("GoodSvc", rf"{SYSTEM32}\good.dll"),
        ]

        def _fake_state(dll: str) -> dict[str, Any]:
            if "evil" in dll.lower():
                return _path_state(in_system=False)
            return _path_state(in_system=True)

        with (
            mock.patch.object(service, "_iter_service_dll_entries", return_value=entries),
            mock.patch.object(service, "_collect_service_dll_state", side_effect=_fake_state),
            mock.patch.object(service, "_verify_signature", return_value=UNSIGNED_SIG) as verifier,
        ):
            findings = service._scan_all_service_dlls()

        self.assertEqual(len(findings), 2)
        self.assertEqual({finding["evidence"]["service_name"] for finding in findings}, {"EvilOne", "EvilTwo"})
        self.assertTrue(all(finding["rule_id"] == "SVC_SERVICEDLL_TAMPER" for finding in findings))
        self.assertTrue(all(finding["severity"] == "HIGH" for finding in findings))
        # 系统目录内的 GoodSvc 不需要验签
        self.assertEqual([call.args[0] for call in verifier.call_args_list], [r"C:\Users\Public\evil1.dll", r"C:\Temp\evil2.dll"])

    def test_missing_file_goes_to_absent_without_signature_verification(self) -> None:
        entries = [self._entry("GhostSvc", r"C:\ProgramData\ghost.dll")]
        with (
            mock.patch.object(service, "_iter_service_dll_entries", return_value=entries),
            mock.patch.object(
                service,
                "_collect_service_dll_state",
                return_value=_path_state(exists=False, in_system=False),
            ),
            mock.patch.object(service, "_verify_signature") as verifier,
        ):
            findings = service._scan_all_service_dlls()
        verifier.assert_not_called()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SVC_SERVICEDLL_ABSENT")


class TestServiceScanIntegration(unittest.TestCase):
    """scan() 集成：泛化检查追加在 CIM 检查之后，且异常不抛出。"""

    def setUp(self) -> None:
        service.clear_service_cache()

    def tearDown(self) -> None:
        service.clear_service_cache()

    def test_generic_findings_are_appended_after_cim_findings(self) -> None:
        cim_finding = {
            "severity": "MEDIUM",
            "category": service.CATEGORY,
            "target": "cim",
            "detail": "d",
            "evidence": {},
            "rule_id": "SERVICE_NAME_MISMATCH",
        }
        generic_finding = {
            "severity": "HIGH",
            "category": service.CATEGORY,
            "target": r"C:\Users\Public\evil.dll",
            "detail": "d",
            "evidence": {"service_name": "EvilSvc"},
            "rule_id": "SVC_SERVICEDLL_TAMPER",
        }
        with (
            mock.patch.object(service, "collect_services", return_value=({"Name": "A"}, None)),
            mock.patch.object(service, "_analyze_service", return_value=[cim_finding]) as analyzer,
            mock.patch.object(service, "_scan_all_service_dlls", return_value=[generic_finding]) as generic,
        ):
            findings = service.scan()
        analyzer.assert_called_once_with({"Name": "A"})
        generic.assert_called_once_with()
        self.assertEqual([finding["rule_id"] for finding in findings], ["SERVICE_NAME_MISMATCH", "SVC_SERVICEDLL_TAMPER"])

    def test_generic_scan_exception_does_not_break_scan(self) -> None:
        cim_finding = {
            "severity": "MEDIUM",
            "category": service.CATEGORY,
            "target": "cim",
            "detail": "d",
            "evidence": {},
            "rule_id": "SERVICE_NAME_MISMATCH",
        }
        with (
            mock.patch.object(service, "collect_services", return_value=({"Name": "A"}, None)),
            mock.patch.object(service, "_analyze_service", return_value=[cim_finding]),
            mock.patch.object(service, "_scan_all_service_dlls", side_effect=RuntimeError("boom")),
        ):
            findings = service.scan()
        self.assertEqual([finding["rule_id"] for finding in findings], ["SERVICE_NAME_MISMATCH"])

    def test_scan_generic_enumeration_uses_64bit_view(self) -> None:
        with (
            mock.patch.object(service, "collect_services", return_value=({"Name": "A"}, None)),
            mock.patch.object(service, "_analyze_service", return_value=[]),
            mock.patch.object(service.winreg, "OpenKey", side_effect=OSError("denied")) as opened,
        ):
            self.assertEqual(service.scan(), [])
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(opened.call_args.args[3], winreg.KEY_READ | winreg.KEY_WOW64_64KEY)


class TestDedupeWithRdpRule(unittest.TestCase):
    """RDP_SERVICEDLL_TAMPER 与 SVC_SERVICEDLL_TAMPER 同 target 时按基名合并。"""

    def _svc_tamper(self) -> dict[str, Any]:
        dll = r"C:\Users\Public\termsrv.dll"
        findings = service._analyze_service_dll(
            "TermService",
            dll,
            r"HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters",
            _path_state(in_system=False),
            UNSIGNED_SIG,
        )
        return findings[0]

    def test_rule_basename_is_shared(self) -> None:
        self.assertEqual(rule_basename("RDP_SERVICEDLL_TAMPER"), "SERVICEDLL_TAMPER")
        self.assertEqual(rule_basename("SVC_SERVICEDLL_TAMPER"), "SERVICEDLL_TAMPER")
        self.assertEqual(rule_basename("SERVICE_SVCHOST_DLL"), "SVCHOST_DLL")

    def test_same_target_merges_into_one_finding(self) -> None:
        svc_finding = self._svc_tamper()
        dll = svc_finding["target"]
        rdp_finding = {
            "severity": "HIGH",
            "category": "CredentialBackdoor",
            "target": dll,
            "detail": "RDP TermService ServiceDll 异常",
            "evidence": {
                "service": "TermService",
                "dll": dll,
                "reasons": ["outside_system", "unsigned"],
                "signature": {"status": "unsigned", "signer": None, "via": None},
            },
            "rule_id": "RDP_SERVICEDLL_TAMPER",
        }
        merged = dedupe_findings([svc_finding, rdp_finding], merge_rule_base=True)
        self.assertEqual(len(merged), 1)
        finding = merged[0]
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["target"], dll)
        merged_rules = finding["evidence"]["merged_rules"]
        self.assertIn("SVC_SERVICEDLL_TAMPER", merged_rules)
        self.assertIn("RDP_SERVICEDLL_TAMPER", merged_rules)

    def test_different_targets_are_not_merged(self) -> None:
        """ABSENT 规则基名相同但 target 不同（RDP 是键路径，SVC 是 DLL 路径），不能误合并。"""
        svc_finding = {
            "severity": "HIGH",
            "category": service.CATEGORY,
            "target": rf"{SYSTEM32}\ghost.dll",
            "detail": "d",
            "evidence": {},
            "rule_id": "SVC_SERVICEDLL_ABSENT",
        }
        rdp_finding = {
            "severity": "MEDIUM",
            "category": "CredentialBackdoor",
            "target": r"HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters",
            "detail": "d",
            "evidence": {},
            "rule_id": "RDP_SERVICEDLL_ABSENT",
        }
        merged = dedupe_findings([svc_finding, rdp_finding], merge_rule_base=True)
        self.assertEqual(len(merged), 2)


def _delete_key_tree(hive: int, path: str) -> None:
    children: list[str] = []
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS) as key:
            try:
                child_count = int(winreg.QueryInfoKey(key)[0])
            except OSError:
                child_count = 0
            for index in range(child_count):
                try:
                    children.append(winreg.EnumKey(key, index))
                except OSError:
                    break
    except OSError:
        return
    for child in children:
        _delete_key_tree(hive, f"{path}\\{child}")
    try:
        winreg.DeleteKey(hive, path)
    except OSError:
        pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
