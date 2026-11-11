# -*- coding: utf-8 -*-
"""``modules/lsa_appinit.py`` 的 V1.2 Winlogon / AutoAdminLogon / LSA 扩展测试。

所有判定都在纯函数层完成：注册表数据由 mock 注入、签名结果由测试构造，
因此**不要求管理员权限、不写真实 HKLM、不依赖真实文件存在**。

覆盖：

1. Winlogon 默认基线（Shell/Userinit/GinaDLL/AppSetup/Taskman/Notify）不误报；
2. 判定阶梯：HIGH（文件不存在/非 PE/无签名/签名无效/不在系统目录）、
   MEDIUM（非微软签名）、LOW（微软签名且位于系统目录）；
3. Userinit 尾逗号等价、Shell 带参数、Notify 子键、非 PE 目标；
4. AutoAdminLogon 明文密码 LOW 且永不泄露密码明文；
5. LSA Authentication/Security Packages 未知项 HIGH，Notification 保持原规则；
6. 采集层 mock（64 位视图 + 默认视图）与读取失败降级 SKIPPED；
7. ``scan()`` 汇总不抛异常、包含 LSA/Winlogon 规则、末尾应用白名单。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_lsa_appinit_winlogon.py
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.finding import SEVERITIES  # noqa: E402
from modules import lsa_appinit as m  # noqa: E402

_FINDING_KEYS = {"severity", "category", "target", "detail", "evidence", "rule_id"}
SYSTEM32 = r"C:\Windows\System32"
USER_PUBLIC = r"C:\Users\Public"
WINLOGON_TARGET = "HKLM\\" + m._WINLOGON_KEY + "（64）"

MS_SIG: dict[str, Any] = {"status": "valid", "signer": "Microsoft Windows", "via": "embedded", "error": None}
THIRD_PARTY_SIG: dict[str, Any] = {"status": "valid", "signer": "Contoso Ltd", "via": "embedded", "error": None}
UNSIGNED_SIG: dict[str, Any] = {"status": "unsigned", "signer": None, "via": None, "error": None}
INVALID_SIG: dict[str, Any] = {"status": "invalid", "signer": None, "via": "embedded", "error": "TRUST_E_BAD_DIGEST"}
MISSING_SIG: dict[str, Any] = {"status": "missing", "signer": None, "via": None, "error": "文件不存在"}
NON_PE_SIG: dict[str, Any] = {"status": "n/a", "signer": None, "via": None, "error": "非 PE 文件"}


def _analyze(value_name: str, raw_value: Any, sig_result: dict[str, Any], rule_id: str = "") -> list[dict[str, Any]]:
    return m._analyze_winlogon_value(value_name, raw_value, f"{WINLOGON_TARGET}\\{value_name}", sig_result, rule_id)


def _only(test: unittest.TestCase, findings: list[dict[str, Any]]) -> dict[str, Any]:
    test.assertEqual(len(findings), 1, msg=f"期望 1 条 Finding，实际 {len(findings)}: {findings}")
    return findings[0]


class TestWinlogonBaseline(unittest.TestCase):
    """默认基线（正常系统）不应产生任何 Finding。"""

    def test_absent_values_not_reported(self) -> None:
        for value_name in m._WINLOGON_VALUE_NAMES:
            with self.subTest(value_name=value_name):
                self.assertEqual(_analyze(value_name, None, MISSING_SIG), [])

    def test_default_shell_not_reported(self) -> None:
        values = (
            "explorer.exe",
            "  EXPLORER.EXE  ",
            "explorer.exe /e,shell:::{}",
            os.path.join(m._windows_dir(), "explorer.exe"),
        )
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(_analyze("Shell", value, MS_SIG), [])

    def test_default_userinit_trailing_comma_not_reported(self) -> None:
        default = m._default_userinit()
        values = (default + ",", default.upper() + ",", default + ",,", "  " + default + ",  ")
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(_analyze("Userinit", value, MS_SIG), [])

    def test_gina_dll_absent_not_reported(self) -> None:
        self.assertEqual(_analyze("GinaDLL", None, MISSING_SIG), [])

    def test_blank_value_not_reported(self) -> None:
        # 空白值无法构成可执行劫持，不上报（避免噪声）
        self.assertEqual(_analyze("GinaDLL", "   ", MISSING_SIG), [])
        self.assertEqual(_analyze("Shell", "", MISSING_SIG), [])

    def test_extra_userinit_executable_is_not_default(self) -> None:
        self.assertFalse(m._is_default_userinit(m._default_userinit() + rf",{USER_PUBLIC}\evil.exe"))


class TestWinlogonSeverityLadder(unittest.TestCase):
    """判定阶梯与各严重等级分支。"""

    def test_severity_ladder_combinations(self) -> None:
        cases = [
            ((False, "valid", True, "Microsoft Windows"), ("HIGH", "non_pe_target")),
            ((True, "missing", True, None), ("HIGH", "missing_file")),
            ((True, "unsigned", True, None), ("HIGH", "unsigned")),
            ((True, "invalid", True, None), ("HIGH", "invalid_signature")),
            ((True, "valid", False, "Microsoft Windows"), ("HIGH", "outside_system_dir")),
            ((True, "valid", True, "Contoso Ltd"), ("MEDIUM", "non_microsoft_signer")),
            ((True, "valid", True, "Microsoft Windows"), ("LOW", "baseline_deviation")),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(m._winlogon_severity(*args), expected)

    def test_shell_outside_system_unsigned_is_high(self) -> None:
        finding = _only(self, _analyze("Shell", rf"{USER_PUBLIC}\evil.exe", UNSIGNED_SIG))
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["rule_id"], "WINLOGON_SHELL_TAMPER")
        self.assertIn("unsigned", finding["evidence"]["reasons"])
        self.assertFalse(finding["evidence"]["in_system_dir"])

    def test_shell_outside_system_third_party_still_high(self) -> None:
        finding = _only(self, _analyze("Shell", rf"{USER_PUBLIC}\vendor.exe", THIRD_PARTY_SIG))
        self.assertEqual(finding["severity"], "HIGH")
        self.assertIn("outside_system_dir", finding["evidence"]["reasons"])

    def test_shell_valid_non_microsoft_signature_is_medium(self) -> None:
        finding = _only(self, _analyze("Shell", rf"{SYSTEM32}\ContosoApp.exe", THIRD_PARTY_SIG))
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["rule_id"], "WINLOGON_SHELL_TAMPER")
        self.assertEqual(finding["evidence"]["signer"], "Contoso Ltd")
        self.assertIn("non_microsoft_signer", finding["evidence"]["reasons"])

    def test_shell_microsoft_signed_in_system32_is_low(self) -> None:
        finding = _only(self, _analyze("Shell", rf"{SYSTEM32}\cmd.exe", MS_SIG))
        self.assertEqual(finding["severity"], "LOW")
        self.assertEqual(finding["rule_id"], "WINLOGON_SHELL_TAMPER")
        self.assertIn("baseline_deviation", finding["evidence"]["reasons"])

    def test_shell_missing_file_is_high(self) -> None:
        finding = _only(self, _analyze("Shell", rf"{SYSTEM32}\ghost.exe", MISSING_SIG))
        self.assertEqual(finding["severity"], "HIGH")
        self.assertIn("missing_file", finding["evidence"]["reasons"])

    def test_shell_invalid_signature_is_high(self) -> None:
        finding = _only(self, _analyze("Shell", rf"{SYSTEM32}\tampered.exe", INVALID_SIG))
        self.assertEqual(finding["severity"], "HIGH")
        self.assertIn("invalid_signature", finding["evidence"]["reasons"])

    def test_shell_non_pe_target_is_high(self) -> None:
        finding = _only(self, _analyze("Shell", rf"{SYSTEM32}\evil.ps1", NON_PE_SIG))
        self.assertEqual(finding["severity"], "HIGH")
        self.assertIn("non_pe_target", finding["evidence"]["reasons"])

    def test_gina_dll_added_is_high(self) -> None:
        finding = _only(self, _analyze("GinaDLL", rf"{USER_PUBLIC}\gina.dll", UNSIGNED_SIG))
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["rule_id"], "WINLOGON_GINADLL_TAMPER")
        self.assertEqual(finding["target"], f"{WINLOGON_TARGET}\\GinaDLL")

    def test_appsetup_added_is_medium(self) -> None:
        finding = _only(self, _analyze("AppSetup", rf"{SYSTEM32}\vendor.exe", THIRD_PARTY_SIG))
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["rule_id"], "WINLOGON_APPSETUP_TAMPER")

    def test_taskman_added_is_low(self) -> None:
        finding = _only(self, _analyze("Taskman", rf"{SYSTEM32}\taskmgr.exe", MS_SIG))
        self.assertEqual(finding["severity"], "LOW")
        self.assertEqual(finding["rule_id"], "WINLOGON_TASKMAN_TAMPER")

    def test_notify_subkey_high(self) -> None:
        finding = _only(
            self,
            _analyze("Notify\\Evil\\DllName", rf"{USER_PUBLIC}\evil.dll", UNSIGNED_SIG, "WINLOGON_NOTIFY_TAMPER"),
        )
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["rule_id"], "WINLOGON_NOTIFY_TAMPER")
        self.assertEqual(finding["evidence"]["value_name"], "Notify\\Evil\\DllName")

    def test_notify_subkey_microsoft_signed_is_low(self) -> None:
        finding = _only(
            self,
            _analyze("Notify\\Vendor\\DllName", rf"{SYSTEM32}\vendor.dll", MS_SIG, "WINLOGON_NOTIFY_TAMPER"),
        )
        self.assertEqual(finding["severity"], "LOW")
        self.assertEqual(finding["rule_id"], "WINLOGON_NOTIFY_TAMPER")

    def test_userinit_extra_executable_is_high(self) -> None:
        raw = m._default_userinit() + rf",{USER_PUBLIC}\evil.exe"
        finding = _only(self, _analyze("Userinit", raw, UNSIGNED_SIG))
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["rule_id"], "WINLOGON_USERINIT_TAMPER")
        # 默认 userinit.exe 被忽略，检查目标是新增项
        self.assertEqual(finding["evidence"]["executable"], rf"{USER_PUBLIC}\evil.exe")
        self.assertIn("userinit.exe", finding["evidence"]["raw_value"])

    def test_finding_shape_and_evidence(self) -> None:
        finding = _only(self, _analyze("Shell", rf"{USER_PUBLIC}\evil.exe", UNSIGNED_SIG))
        self.assertEqual(set(finding), _FINDING_KEYS)
        self.assertEqual(finding["category"], m.CATEGORY)
        evidence = finding["evidence"]
        self.assertEqual(evidence["value_name"], "Shell")
        self.assertEqual(evidence["executable"], rf"{USER_PUBLIC}\evil.exe")
        self.assertFalse(evidence["in_system_dir"])
        self.assertEqual(evidence["signature_status"], "unsigned")
        self.assertIsNone(evidence["signer"])
        self.assertFalse(evidence["default_baseline"])
        self.assertEqual(evidence["expected_baseline"], "explorer.exe")
        self.assertIsInstance(evidence["signature"], dict)
        # 便于 white list / reporter 按文件路径与签名者降噪
        self.assertEqual(evidence["path"], rf"{USER_PUBLIC}\evil.exe")
        self.assertEqual(evidence["image_path"], rf"{USER_PUBLIC}\evil.exe")


class TestAutoAdminLogon(unittest.TestCase):
    """AutoAdminLogon 明文密码判定。"""

    def test_enabled_plaintext_password_is_low_and_redacted(self) -> None:
        password = "P@ssw0rd-SuperSecret!"
        finding = _only(
            self,
            m._analyze_autoadminlogon("1", password, f"{WINLOGON_TARGET}\\AutoAdminLogon"),
        )
        self.assertEqual(finding["severity"], "LOW")
        self.assertEqual(finding["rule_id"], "AUTOADMINLOGON_PLAINTEXT")
        self.assertTrue(finding["evidence"]["password_present"])
        self.assertEqual(finding["evidence"]["password_length"], len(password))
        serialized = json.dumps(finding, ensure_ascii=False)
        self.assertNotIn(password, serialized)
        self.assertNotIn(password, finding["detail"])
        self.assertNotIn(password, str(finding["evidence"]))

    def test_int_one_also_reported(self) -> None:
        findings = m._analyze_autoadminlogon(1, "secret", f"{WINLOGON_TARGET}\\AutoAdminLogon")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "AUTOADMINLOGON_PLAINTEXT")

    def test_disabled_or_missing_password_not_reported(self) -> None:
        cases = (("0", "password"), (None, "password"), ("1", None), ("1", ""), ("1", "   "))
        for auto_value, password_value in cases:
            with self.subTest(auto_value=auto_value, password_value=password_value):
                self.assertEqual(
                    m._analyze_autoadminlogon(auto_value, password_value, f"{WINLOGON_TARGET}\\AutoAdminLogon"),
                    [],
                )


class TestLsaPackageRules(unittest.TestCase):
    """LSA Authentication/Security Packages 使用新规则，Notification 保持旧行为。"""

    def test_known_authentication_packages_not_reported(self) -> None:
        findings = m._analyze_lsa_packages(
            "Authentication Packages",
            ["msv1_0", "kerberos"],
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages",
            m._KNOWN_AUTH_PACKAGES,
            "LSA_AUTH_PACKAGE_TAMPER",
        )
        self.assertEqual(findings, [])

    def test_unknown_authentication_and_security_packages_high(self) -> None:
        for kind in ("Authentication Packages", "Security Packages"):
            with self.subTest(kind=kind):
                findings = m._analyze_lsa_packages(
                    kind,
                    ["msv1_0", "evilfilter"],
                    rf"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\{kind}",
                    m._KNOWN_AUTH_PACKAGES,
                    "LSA_AUTH_PACKAGE_TAMPER",
                )
                finding = _only(self, findings)
                self.assertEqual(finding["severity"], "HIGH")
                self.assertEqual(finding["rule_id"], "LSA_AUTH_PACKAGE_TAMPER")
                self.assertEqual(finding["evidence"]["unknown"], ["evilfilter"])

    def test_notification_packages_keep_legacy_rule(self) -> None:
        findings = m._analyze_lsa_packages(
            "Notification Packages",
            ["evilpkg"],
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages",
            m._KNOWN_NOTIFICATION_PACKAGES,
        )
        finding = _only(self, findings)
        self.assertEqual(finding["rule_id"], "LSA_PACKAGE_HIJACK")

    def test_quoted_empty_security_package_ignored(self) -> None:
        # 实测 Windows 的 Security Packages 可能存 "" 占位，不应报未知包
        findings = m._analyze_lsa_packages(
            "Security Packages",
            ['""'],
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages",
            m._KNOWN_AUTH_PACKAGES,
            "LSA_AUTH_PACKAGE_TAMPER",
        )
        self.assertEqual(findings, [])


class TestWinlogonCollection(unittest.TestCase):
    """采集层：mock ``_collect_winlogon`` / ``_verify_winlogon_target``，不触碰真实 HKLM。"""

    def test_scan_winlogon_uses_injected_data_and_dedupes_views(self) -> None:
        collected = {
            "values": {
                "Shell": rf"{USER_PUBLIC}\evil.exe",
                "Userinit": m._default_userinit() + ",",
                "AppSetup": rf"{SYSTEM32}\vendor.exe",
                "AutoAdminLogon": "1",
                "DefaultPassword": "P@ssw0rd",
            },
            "notify": [{"name": "Evil", "dll": rf"{SYSTEM32}\notify_evil.dll"}],
        }

        def _fake_verify(executable: str) -> dict[str, Any]:
            name = str(executable).lower()
            if "vendor" in name:
                return THIRD_PARTY_SIG
            if "evil" in name or "notify" in name:
                return UNSIGNED_SIG
            return MS_SIG

        with (
            mock.patch.object(m, "_collect_winlogon", return_value=collected) as collect,
            mock.patch.object(m, "_verify_winlogon_target", side_effect=_fake_verify),
        ):
            findings = m._scan_winlogon()

        # 64 位视图 + 默认视图各采集一次；相同数据只上报一次
        self.assertEqual(collect.call_count, 2)
        self.assertEqual(len(findings), 4)
        by_rule = {finding["rule_id"]: finding for finding in findings}
        self.assertEqual(
            set(by_rule),
            {
                "WINLOGON_SHELL_TAMPER",
                "WINLOGON_APPSETUP_TAMPER",
                "WINLOGON_NOTIFY_TAMPER",
                "AUTOADMINLOGON_PLAINTEXT",
            },
        )
        self.assertEqual(by_rule["WINLOGON_SHELL_TAMPER"]["severity"], "HIGH")
        self.assertEqual(by_rule["WINLOGON_APPSETUP_TAMPER"]["severity"], "MEDIUM")
        self.assertEqual(by_rule["WINLOGON_NOTIFY_TAMPER"]["severity"], "HIGH")
        self.assertEqual(by_rule["AUTOADMINLOGON_PLAINTEXT"]["severity"], "LOW")

    def test_scan_winlogon_access_denied_is_skipped(self) -> None:
        with mock.patch.object(m, "_collect_winlogon", side_effect=PermissionError("拒绝访问")):
            findings = m._scan_winlogon()
        self.assertEqual(len(findings), len(m._WINLOGON_VIEWS))
        for finding in findings:
            self.assertEqual(finding["severity"], "SKIPPED")
            self.assertEqual(finding["rule_id"], "WINLOGON_ACCESS_DENIED")

    def test_scan_winlogon_missing_key_is_skipped(self) -> None:
        with mock.patch.object(m, "_collect_winlogon", side_effect=FileNotFoundError("键不存在")):
            findings = m._scan_winlogon()
        self.assertTrue(findings)
        self.assertTrue(all(finding["rule_id"] == "WINLOGON_ACCESS_DENIED" for finding in findings))

    def test_scan_winlogon_default_config_returns_empty(self) -> None:
        collected = {
            "values": {"Shell": "explorer.exe", "Userinit": m._default_userinit() + ","},
            "notify": [],
        }
        with (
            mock.patch.object(m, "_collect_winlogon", return_value=collected),
            mock.patch.object(m, "_verify_winlogon_target", return_value=MS_SIG) as verify,
        ):
            findings = m._scan_winlogon()
        self.assertEqual(findings, [])
        verify.assert_not_called()  # 默认值不应触发验签（性能与噪声考虑）

    def test_verify_winlogon_target_skips_non_pe(self) -> None:
        with mock.patch.object(m.signature, "verify") as verify:
            result = m._verify_winlogon_target(rf"{SYSTEM32}\evil.ps1")
        verify.assert_not_called()
        self.assertEqual(result["status"], "n/a")

    def test_verify_winlogon_target_empty_path_is_missing(self) -> None:
        self.assertEqual(m._verify_winlogon_target("")["status"], "missing")


class TestScanIntegration(unittest.TestCase):
    """``scan()`` 编排：Winlogon 失败降级、LSA 新规则合并、末尾应用白名单。"""

    def test_scan_never_raises_when_winlogon_errors(self) -> None:
        with (
            mock.patch.object(m, "_scan_winlogon", side_effect=RuntimeError("winlogon boom")),
            mock.patch.object(m, "_read_multi_sz", return_value=[]),
            mock.patch.object(m, "_read_value", return_value=None),
            mock.patch.object(m, "_iter_ifeo_entries", return_value=iter(())),
            mock.patch.object(m.utils, "apply_whitelist", side_effect=lambda items: list(items)) as whitelist,
        ):
            findings = m.scan()
        whitelist.assert_called_once()
        self.assertTrue(all(finding["severity"] in SEVERITIES for finding in findings))
        self.assertIn("WINLOGON_ACCESS_DENIED", [finding["rule_id"] for finding in findings])

    def test_scan_combines_lsa_and_winlogon_rules(self) -> None:
        def _fake_multi(hive: int, subkey: str, name: str, view_flag: int = 0) -> list[str]:
            if name == "Authentication Packages":
                return ["msv1_0", "evil_auth"]
            if name == "Security Packages":
                return ["evil_security"]
            return ["scecli"]

        winlogon_finding = {
            "severity": "HIGH",
            "category": m.CATEGORY,
            "target": f"{WINLOGON_TARGET}\\Shell",
            "detail": "d",
            "evidence": {},
            "rule_id": "WINLOGON_SHELL_TAMPER",
        }
        with (
            mock.patch.object(m, "_read_multi_sz", side_effect=_fake_multi),
            mock.patch.object(m, "_read_value", return_value=None),
            mock.patch.object(m, "_iter_ifeo_entries", return_value=iter(())),
            mock.patch.object(m, "_scan_winlogon", return_value=[winlogon_finding]),
            mock.patch.object(m.utils, "apply_whitelist", side_effect=lambda items: list(items)),
        ):
            findings = m.scan()
        rule_ids = [finding["rule_id"] for finding in findings]
        self.assertEqual(rule_ids.count("LSA_AUTH_PACKAGE_TAMPER"), 2)
        self.assertIn("WINLOGON_SHELL_TAMPER", rule_ids)
        self.assertNotIn("LSA_PACKAGE_HIJACK", rule_ids)

    def test_scan_calls_apply_whitelist(self) -> None:
        with (
            mock.patch.object(m, "_scan_winlogon", return_value=[]),
            mock.patch.object(m, "_read_multi_sz", return_value=[]),
            mock.patch.object(m, "_read_value", return_value=None),
            mock.patch.object(m, "_iter_ifeo_entries", return_value=iter(())),
            mock.patch.object(m.utils, "apply_whitelist", return_value=[]) as whitelist,
        ):
            self.assertEqual(m.scan(), [])
        whitelist.assert_called_once()


@unittest.skipUnless(sys.platform == "win32", "仅 Windows 支持 winreg")
class TestRealScanSmoke(unittest.TestCase):
    """真实环境冒烟：只读注册表，不假设是否管理员，只要求不崩且结构合法。"""

    def test_scan_never_raises_and_findings_well_formed(self) -> None:
        findings = m.scan()
        self.assertIsInstance(findings, list)
        for finding in findings:
            self.assertEqual(set(finding), _FINDING_KEYS)
            self.assertIn(finding["severity"], SEVERITIES)
            self.assertIsInstance(finding["evidence"], dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
