# -*- coding: utf-8 -*-
"""``modules/credential_rdp.py`` 的单元测试。

不依赖管理员权限、不依赖本机是否存在后门（实测这些键标准用户可读）：

1. 纯函数：ProviderOrder 解析、单个 Network Provider 判定、TermService ServiceDll 判定；
2. 真实 winreg：在 ``HKCU\\Software\\TamperScanTests`` 下造缩微的
   NetworkProvider + Services 结构，验证采集链路（签名/文件状态打桩，不依赖真实文件）；
3. ``scan()`` 集成：两部分独立降级、异常兜底、结果合并；最后真实冒烟。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_credential_rdp.py
    python -m unittest discover -s tests -p "test_*.py" -v
    python tests\\test_credential_rdp.py
"""

from __future__ import annotations

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

from core.finding import SEVERITIES  # noqa: E402
from modules import credential_rdp as m  # noqa: E402

_FINDING_KEYS = {"severity", "category", "target", "detail", "evidence", "rule_id"}

_HKCU_TEST_PARENT = r"Software\TamperScanTests"
_HKCU_TEST_ROOT = rf"{_HKCU_TEST_PARENT}\CredentialRDP\{uuid.uuid4().hex}"

SYSTEM32 = r"C:\Windows\System32"
MS_SIG: dict[str, Any] = {"status": "valid", "signer": "Microsoft Windows", "via": "embedded", "error": None}
THIRD_PARTY_SIG: dict[str, Any] = {"status": "valid", "signer": "Contoso Ltd", "via": "embedded", "error": None}
UNSIGNED_SIG: dict[str, Any] = {"status": "unsigned", "signer": None, "via": None, "error": None}
INVALID_SIG: dict[str, Any] = {"status": "invalid", "signer": None, "via": "embedded", "error": "TRUST_E_BAD_DIGEST"}
MISSING_SIG: dict[str, Any] = {"status": "missing", "signer": None, "via": None, "error": "文件不存在"}


def _path_state(
    dll: str,
    *,
    exists: bool = True,
    in_system: bool = True,
    user_writable: bool = False,
    escape: bool = False,
) -> dict[str, Any]:
    return {
        "expanded": dll,
        "dll": dll,
        "exists": exists,
        "in_system_dir": in_system,
        "user_writable": user_writable,
        "escape_suspicious": escape,
    }


def _provider(**values: str) -> dict[str, str]:
    base = {
        "ProviderPath": rf"{SYSTEM32}\drprov.dll",
        "DeviceName": r"\Device\RdpDr",
        "DisplayName": "@C:\\Windows\\system32\\drprov.dll,-100",
        "Name": "Microsoft Terminal Services",
    }
    base.update(values)
    return base


def _base_evidence() -> None:  # pragma: no cover - 仅用于可读性占位
    pass


class TestParseProviderOrder(unittest.TestCase):
    def test_parse_normal(self) -> None:
        self.assertEqual(
            m._parse_provider_order("RDPNP,P9NP,LanmanWorkstation,webclient"),
            ["RDPNP", "P9NP", "LanmanWorkstation", "webclient"],
        )

    def test_parse_tolerates_spaces_empty_and_duplicates(self) -> None:
        self.assertEqual(
            m._parse_provider_order(" RDPNP, ,P9NP,rdpnp, ,webclient "),
            ["RDPNP", "P9NP", "webclient"],
        )

    def test_parse_empty(self) -> None:
        for value in ("", "   ", ",", ", ,"):
            self.assertEqual(m._parse_provider_order(value), [])


class TestAnalyzeProvider(unittest.TestCase):
    """单个 Network Provider 判定（纯函数）。"""

    def test_known_good_provider_has_no_finding(self) -> None:
        dll = rf"{SYSTEM32}\drprov.dll"
        findings = m._analyze_provider_entry("RDPNP", _provider(), _path_state(dll), MS_SIG)
        self.assertEqual(findings, [])

    def test_unknown_provider_signed_system_dll_is_low(self) -> None:
        dll = rf"{SYSTEM32}\futurenp.dll"
        findings = m._analyze_provider_entry("FutureNP", _provider(ProviderPath=dll), _path_state(dll), MS_SIG)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "LOW")
        self.assertEqual(findings[0]["rule_id"], "NP_UNKNOWN_PROVIDER")

    def test_unknown_provider_temp_unsigned_is_high(self) -> None:
        dll = r"C:\Users\Public\evilnp.dll"
        findings = m._analyze_provider_entry(
            "EvilNet",
            _provider(ProviderPath=dll),
            _path_state(dll, exists=True, in_system=False, user_writable=True),
            UNSIGNED_SIG,
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(set(finding), _FINDING_KEYS)
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["rule_id"], "NP_PROVIDER_TAMPER")
        self.assertEqual(finding["target"], dll)
        self.assertIn("unknown_provider", finding["evidence"]["reasons"])
        self.assertIn("outside_system", finding["evidence"]["reasons"])
        self.assertIn("user_writable", finding["evidence"]["reasons"])
        self.assertIn("unsigned", finding["evidence"]["reasons"])
        self.assertIn("EvilNet", finding["detail"])

    def test_known_provider_path_mismatch_is_high(self) -> None:
        dll = rf"{SYSTEM32}\evil.dll"
        findings = m._analyze_provider_entry("RDPNP", _provider(ProviderPath=dll), _path_state(dll), MS_SIG)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("path_mismatch", findings[0]["evidence"]["reasons"])
        self.assertEqual(findings[0]["evidence"]["expected_dll"], "drprov.dll")

    def test_known_provider_third_party_signature_is_high(self) -> None:
        dll = rf"{SYSTEM32}\ntlanman.dll"
        findings = m._analyze_provider_entry(
            "LanmanWorkstation", _provider(ProviderPath=dll), _path_state(dll), THIRD_PARTY_SIG
        )
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("non_microsoft", findings[0]["evidence"]["reasons"])
        self.assertEqual(findings[0]["evidence"]["signature"]["signer"], "Contoso Ltd")

    def test_invalid_signature_is_high(self) -> None:
        dll = rf"{SYSTEM32}\drprov.dll"
        findings = m._analyze_provider_entry("RDPNP", _provider(), _path_state(dll), INVALID_SIG)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("unsigned", findings[0]["evidence"]["reasons"])

    def test_missing_provider_key_is_high(self) -> None:
        findings = m._analyze_provider_entry(
            "GhostNP", {}, _path_state(""), MISSING_SIG, read_error="not_found"
        )
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("provider_missing", findings[0]["evidence"]["reasons"])

    def test_unreadable_provider_key_is_high(self) -> None:
        findings = m._analyze_provider_entry(
            "HiddenNP", {}, _path_state(""), MISSING_SIG, read_error="access_denied"
        )
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("provider_unreadable", findings[0]["evidence"]["reasons"])

    def test_provider_path_absent_is_high(self) -> None:
        findings = m._analyze_provider_entry(
            "RDPNP", _provider(ProviderPath=""), _path_state(""), MISSING_SIG, read_error=None
        )
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("provider_path_absent", findings[0]["evidence"]["reasons"])

    def test_invalid_path_value_is_high(self) -> None:
        findings = m._analyze_provider_entry(
            "RDPNP", _provider(ProviderPath=":::"), _path_state("", escape=True), MISSING_SIG
        )
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("invalid_path", findings[0]["evidence"]["reasons"])

    def test_evidence_exposes_whitelist_fields(self) -> None:
        """顶层 path/image_path/signer 让 rules/whitelist.json 能对合法第三方 Provider 降噪。"""
        dll = r"C:\Users\Public\evilnp.dll"
        findings = m._analyze_provider_entry(
            "EvilNet",
            _provider(ProviderPath=dll),
            _path_state(dll, in_system=False, user_writable=True),
            THIRD_PARTY_SIG,
        )
        evidence = findings[0]["evidence"]
        self.assertEqual(evidence["path"], dll)
        self.assertEqual(evidence["image_path"], dll)
        self.assertEqual(evidence["signer"], "Contoso Ltd")

    def test_missing_dll_file_is_high(self) -> None:
        dll = rf"{SYSTEM32}\drprov.dll"
        findings = m._analyze_provider_entry(
            "RDPNP", _provider(), _path_state(dll, exists=False, in_system=True), MISSING_SIG
        )
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("missing_file", findings[0]["evidence"]["reasons"])


class TestAnalyzeTermService(unittest.TestCase):
    """TermService ServiceDll 判定（纯函数）。"""

    def test_legitimate_termsrv_has_no_finding(self) -> None:
        dll = rf"{SYSTEM32}\termsrv.dll"
        findings = m._analyze_term_service(dll, None, _path_state(dll), MS_SIG)
        self.assertEqual(findings, [])

    def test_outside_system_dir_is_high(self) -> None:
        dll = r"C:\Users\Public\termsrv.dll"
        findings = m._analyze_term_service(
            dll, None, _path_state(dll, in_system=False, user_writable=True), UNSIGNED_SIG
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(set(finding), _FINDING_KEYS)
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["rule_id"], "RDP_SERVICEDLL_TAMPER")
        self.assertEqual(finding["target"], dll)
        self.assertIn("outside_system", finding["evidence"]["reasons"])
        self.assertIn("user_writable", finding["evidence"]["reasons"])
        self.assertIn("unsigned", finding["evidence"]["reasons"])

    def test_unexpected_dll_name_is_high(self) -> None:
        dll = rf"{SYSTEM32}\evil.dll"
        findings = m._analyze_term_service(dll, None, _path_state(dll), MS_SIG)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("unexpected_name", findings[0]["evidence"]["reasons"])
        self.assertEqual(findings[0]["evidence"]["expected_dll"], "termsrv.dll")

    def test_third_party_signature_is_high(self) -> None:
        dll = rf"{SYSTEM32}\termsrv.dll"
        findings = m._analyze_term_service(dll, None, _path_state(dll), THIRD_PARTY_SIG)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("non_microsoft", findings[0]["evidence"]["reasons"])
        self.assertEqual(findings[0]["evidence"]["signer"], "Contoso Ltd")
        self.assertEqual(findings[0]["evidence"]["path"], dll)

    def test_missing_file_is_high(self) -> None:
        dll = rf"{SYSTEM32}\termsrv.dll"
        findings = m._analyze_term_service(dll, None, _path_state(dll, exists=False), MISSING_SIG)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("missing_file", findings[0]["evidence"]["reasons"])

    def test_absent_value_is_medium(self) -> None:
        findings = m._analyze_term_service("", "value_missing", _path_state(""), MISSING_SIG)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(findings[0]["rule_id"], "RDP_SERVICEDLL_ABSENT")

    def test_access_denied_is_skipped(self) -> None:
        findings = m._analyze_term_service("", "access_denied", _path_state(""), MISSING_SIG)
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "RDP_ACCESS_DENIED")

    def test_read_error_is_skipped(self) -> None:
        findings = m._analyze_term_service("", "read_error", _path_state(""), MISSING_SIG)
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "RDP_SKIPPED")


class TestRegistryReaders(unittest.TestCase):
    """真实 winreg：HKCU 合成 NetworkProvider + Services 结构。"""

    @classmethod
    def setUpClass(cls) -> None:
        _delete_key_tree(winreg.HKEY_CURRENT_USER, _HKCU_TEST_ROOT)
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _HKCU_TEST_ROOT, 0, winreg.KEY_ALL_ACCESS) as root:
            with winreg.CreateKeyEx(root, r"NetworkProvider\Order", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "ProviderOrder", 0, winreg.REG_SZ, "RDPNP,EvilNet")
            with winreg.CreateKeyEx(root, r"NetworkProvider\HwOrder", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "ProviderOrder", 0, winreg.REG_SZ, "RDPNP,EvilNet,ExtraNP")
            with winreg.CreateKeyEx(root, r"Services\RDPNP\NetworkProvider", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "ProviderPath", 0, winreg.REG_EXPAND_SZ, rf"{SYSTEM32}\drprov.dll")
                winreg.SetValueEx(key, "DeviceName", 0, winreg.REG_SZ, r"\Device\RdpDr")
                winreg.SetValueEx(key, "Name", 0, winreg.REG_SZ, "Microsoft Terminal Services")
            with winreg.CreateKeyEx(root, r"Services\EvilNet\NetworkProvider", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "ProviderPath", 0, winreg.REG_EXPAND_SZ, r"C:\Users\Public\evilnp.dll")
            with winreg.CreateKeyEx(root, r"Services\TermService\Parameters", 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.SetValueEx(key, "ServiceDll", 0, winreg.REG_EXPAND_SZ, rf"{SYSTEM32}\termsrv.dll")

    @classmethod
    def tearDownClass(cls) -> None:
        _delete_key_tree(winreg.HKEY_CURRENT_USER, _HKCU_TEST_ROOT)
        for parent in (rf"{_HKCU_TEST_PARENT}\CredentialRDP", _HKCU_TEST_PARENT):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, parent)
            except OSError:
                break

    def test_read_provider_order(self) -> None:
        value, error = m._read_string_value(
            rf"{_HKCU_TEST_ROOT}\NetworkProvider\Order", "ProviderOrder", winreg.HKEY_CURRENT_USER, 0
        )
        self.assertIsNone(error)
        self.assertEqual(value, "RDPNP,EvilNet")

    def test_read_provider_entry(self) -> None:
        info, error = m._read_provider_entry(
            "RDPNP", winreg.HKEY_CURRENT_USER, rf"{_HKCU_TEST_ROOT}\Services", 0
        )
        self.assertIsNone(error)
        self.assertEqual(info["ProviderPath"], rf"{SYSTEM32}\drprov.dll")
        self.assertEqual(info["DeviceName"], r"\Device\RdpDr")

    def test_read_missing_provider_entry(self) -> None:
        info, error = m._read_provider_entry(
            "GhostNP", winreg.HKEY_CURRENT_USER, rf"{_HKCU_TEST_ROOT}\Services", 0
        )
        self.assertEqual(info, {})
        self.assertEqual(error, "not_found")

    def test_read_term_service_dll(self) -> None:
        value, error = m._read_string_value(
            rf"{_HKCU_TEST_ROOT}\Services\TermService\Parameters",
            "ServiceDll",
            winreg.HKEY_CURRENT_USER,
            0,
        )
        self.assertIsNone(error)
        self.assertEqual(value, rf"{SYSTEM32}\termsrv.dll")

    def test_scan_network_providers_uses_stubbed_file_state(self) -> None:
        def _fake_path_state(raw: str) -> dict[str, Any]:
            path = str(raw or "")
            if "evilnp" in path.lower():
                return _path_state(path, exists=True, in_system=False, user_writable=True)
            return _path_state(path)

        def _fake_verify(path: str) -> dict[str, Any]:
            return UNSIGNED_SIG if "evilnp" in str(path).lower() else MS_SIG

        with (
            mock.patch.object(m, "_collect_path_state", side_effect=_fake_path_state),
            mock.patch.object(m, "_verify_signature", side_effect=_fake_verify),
        ):
            findings = m._scan_network_providers(
                hive=winreg.HKEY_CURRENT_USER,
                root=rf"{_HKCU_TEST_ROOT}\NetworkProvider",
                services_root=rf"{_HKCU_TEST_ROOT}\Services",
                view_flag=0,
            )
        rule_ids = {finding["rule_id"] for finding in findings}
        self.assertIn("NP_PROVIDER_TAMPER", rule_ids)
        self.assertIn("NP_ORDER_MISMATCH", rule_ids)
        tamper = next(finding for finding in findings if finding["rule_id"] == "NP_PROVIDER_TAMPER")
        self.assertIn("unknown_provider", tamper["evidence"]["reasons"])

    def test_scan_network_providers_missing_root_is_skipped(self) -> None:
        findings = m._scan_network_providers(
            hive=winreg.HKEY_CURRENT_USER,
            root=rf"{_HKCU_TEST_ROOT}\NoSuchRoot",
            services_root=rf"{_HKCU_TEST_ROOT}\Services",
            view_flag=0,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "NP_SKIPPED")

    def test_scan_term_service_uses_stubbed_file_state(self) -> None:
        with (
            mock.patch.object(m, "_collect_path_state", side_effect=lambda raw: _path_state(str(raw))),
            mock.patch.object(m, "_verify_signature", return_value=MS_SIG),
        ):
            findings = m._scan_term_service(
                hive=winreg.HKEY_CURRENT_USER,
                parameters_key=rf"{_HKCU_TEST_ROOT}\Services\TermService\Parameters",
                view_flag=0,
            )
        self.assertEqual(findings, [])


class TestScanIntegration(unittest.TestCase):
    """scan() 编排：两部分独立降级、异常兜底、结果合并。"""

    def test_both_parts_good_returns_empty(self) -> None:
        with (
            mock.patch.object(m, "_scan_network_providers", return_value=[]),
            mock.patch.object(m, "_scan_term_service", return_value=[]),
        ):
            self.assertEqual(m.scan(), [])

    def test_network_failure_does_not_block_rdp(self) -> None:
        rdp_finding = {
            "severity": "HIGH",
            "category": m.CATEGORY,
            "target": "x",
            "detail": "d",
            "evidence": {},
            "rule_id": "RDP_SERVICEDLL_TAMPER",
        }
        with (
            mock.patch.object(m, "_scan_network_providers", side_effect=RuntimeError("np boom")),
            mock.patch.object(m, "_scan_term_service", return_value=[rdp_finding]),
        ):
            findings = m.scan()
        rule_ids = [finding["rule_id"] for finding in findings]
        self.assertIn("NP_SKIPPED", rule_ids)
        self.assertIn("RDP_SERVICEDLL_TAMPER", rule_ids)

    def test_rdp_failure_does_not_block_network(self) -> None:
        np_finding = {
            "severity": "HIGH",
            "category": m.CATEGORY,
            "target": "y",
            "detail": "d",
            "evidence": {},
            "rule_id": "NP_PROVIDER_TAMPER",
        }
        with (
            mock.patch.object(m, "_scan_network_providers", return_value=[np_finding]),
            mock.patch.object(m, "_scan_term_service", side_effect=RuntimeError("rdp boom")),
        ):
            findings = m.scan()
        rule_ids = [finding["rule_id"] for finding in findings]
        self.assertIn("NP_PROVIDER_TAMPER", rule_ids)
        self.assertIn("RDP_SKIPPED", rule_ids)

    def test_both_fail_return_two_skipped(self) -> None:
        with (
            mock.patch.object(m, "_scan_network_providers", side_effect=RuntimeError("a")),
            mock.patch.object(m, "_scan_term_service", side_effect=RuntimeError("b")),
        ):
            findings = m.scan()
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(finding["severity"] == "SKIPPED" for finding in findings))


@unittest.skipUnless(sys.platform == "win32", "仅 Windows 支持 winreg")
class TestRealScanSmoke(unittest.TestCase):
    """真实环境冒烟：不假设是否管理员，只要求不崩、结构合法。"""

    def test_scan_never_raises_and_findings_are_well_formed(self) -> None:
        findings = m.scan()
        self.assertIsInstance(findings, list)
        for finding in findings:
            self.assertEqual(set(finding), _FINDING_KEYS)
            self.assertIn(finding["severity"], SEVERITIES)
            self.assertIsInstance(finding["evidence"], dict)
            self.assertTrue(
                str(finding["rule_id"]).startswith("NP_") or str(finding["rule_id"]).startswith("RDP_")
            )


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
