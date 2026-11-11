# -*- coding: utf-8 -*-
"""``modules/persistence_ext.py`` 的单元测试。

覆盖范围（不要求管理员权限、不依赖真实 HKLM/真实文件）：

1. 10 个检测点的纯分析函数：第三方有效签名 / 微软签名放行 / 无签名 / 无效签名 /
   文件缺失等正反例；
2. 采集层：mock ``_read_value`` / ``_enum_subkeys`` / ``_enum_values`` /
   ``_collect_path_state`` / ``_verify_signature``，验证权限失败降级与上下文证据；
3. ``scan()``：读取失败汇总 SKIPPED、单检测点异常不中断、白名单调用；
4. 白名单：``persistence_ext_allow`` 段加载归一化、路径+签名者精确匹配、
   路径不匹配/签名不匹配不豁免、命中降 INFO、不影响既有 signers 行为；
5. 真实环境冒烟（签名打桩）：scan() 不抛异常、Finding 结构合法。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_persistence_ext.py
    python -m unittest discover -s tests -p "test_*.py" -v
    python tests\\test_persistence_ext.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import utils  # noqa: E402
from core.finding import SEVERITIES  # noqa: E402
from modules import persistence_ext as m  # noqa: E402

_FINDING_KEYS = {"severity", "category", "target", "detail", "evidence", "rule_id"}
_REQUIRED_EVIDENCE_KEYS = {
    "registry_value_path",
    "registry_key",
    "value_name",
    "raw_value",
    "expanded_path",
    "signature",
}

SYSTEM32 = r"C:\Windows\System32"

MS_SIG: dict[str, Any] = {"status": "valid", "signer": "Microsoft Windows", "via": "catalog", "error": None}
EDGE_SIG: dict[str, Any] = {"status": "valid", "signer": "Microsoft Edge", "via": "embedded", "error": None}
OFFICE_SIG: dict[str, Any] = {"status": "valid", "signer": "Microsoft Office", "via": "embedded", "error": None}
THIRD_PARTY_SIG: dict[str, Any] = {"status": "valid", "signer": "Contoso Ltd", "via": "embedded", "error": None}
UNSIGNED_SIG: dict[str, Any] = {"status": "unsigned", "signer": None, "via": None, "error": None}
INVALID_SIG: dict[str, Any] = {
    "status": "invalid",
    "signer": None,
    "via": "embedded",
    "error": "TRUST_E_BAD_DIGEST",
}
MISSING_SIG: dict[str, Any] = {"status": "missing", "signer": None, "via": None, "error": "文件不存在"}


def _path_state(
    executable: str,
    *,
    is_pe: bool = True,
    in_system: bool = True,
    expanded: str | None = None,
) -> dict[str, Any]:
    return {
        "expanded": expanded if expanded is not None else executable,
        "executable": executable,
        "is_pe": is_pe,
        "in_system_dir": in_system,
    }


def _assert_finding(
    case: unittest.TestCase,
    finding: dict[str, Any],
    *,
    rule_id: str,
    severity: str,
    registry_value_path: str,
) -> None:
    """统一断言 Finding 结构与 evidence 关键字段。"""
    case.assertEqual(set(finding), _FINDING_KEYS)
    case.assertEqual(finding["category"], m.CATEGORY)
    case.assertEqual(finding["rule_id"], rule_id)
    case.assertEqual(finding["severity"], severity)
    evidence = finding["evidence"]
    case.assertIsInstance(evidence, dict)
    case.assertTrue(_REQUIRED_EVIDENCE_KEYS.issubset(set(evidence)), sorted(set(evidence)))
    case.assertEqual(evidence["registry_value_path"], registry_value_path)
    case.assertIsInstance(evidence["signature"], dict)
    case.assertIn("status", evidence["signature"])
    case.assertIn("signer", evidence["signature"])


def _whitelist_config(persistence_ext_allow: list[Any]) -> dict[str, Any]:
    return {
        "enabled": True,
        "mode": "downgrade",
        "paths": [],
        "commandline_patterns": [],
        "signers": [],
        "domains": [],
        "extensions": {"allowlist_by_id": [], "allowlist_by_id_with_max_score": {}},
        "services": [],
        "tasks": [],
        "masquerade_allow": [],
        "persistence_ext_allow": persistence_ext_allow,
    }


# ---------------------------------------------------------------------------
# 1. NetSh NetshHelperDll
# ---------------------------------------------------------------------------


class TestNetshHelper(unittest.TestCase):
    def test_third_party_signed_is_high(self) -> None:
        dll = r"C:\Users\Public\evilhelper.dll"
        findings = m._analyze_netsh_helper(dll, THIRD_PARTY_SIG, _path_state(dll, in_system=False))
        self.assertEqual(len(findings), 1)
        _assert_finding(
            self,
            findings[0],
            rule_id=m.RULE_NETSH_HELPER,
            severity="HIGH",
            registry_value_path=r"HKLM\SOFTWARE\Microsoft\NetSh\NetshHelperDll",
        )
        self.assertIn("non_microsoft", findings[0]["evidence"]["reasons"])
        self.assertEqual(findings[0]["evidence"]["signature"]["signer"], "Contoso Ltd")
        self.assertEqual(findings[0]["evidence"]["value_name"], "NetshHelperDll")

    def test_microsoft_signed_is_allowed(self) -> None:
        dll = rf"{SYSTEM32}\netsh.exe"
        self.assertEqual(m._analyze_netsh_helper(dll, MS_SIG, _path_state(dll)), [])

    def test_unsigned_is_high(self) -> None:
        dll = r"C:\Users\Public\unsigned.dll"
        findings = m._analyze_netsh_helper(dll, UNSIGNED_SIG, _path_state(dll, in_system=False))
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("unsigned", findings[0]["evidence"]["reasons"])

    def test_invalid_signature_is_high(self) -> None:
        dll = r"C:\Users\Public\bad.dll"
        findings = m._analyze_netsh_helper(dll, INVALID_SIG, _path_state(dll, in_system=False))
        self.assertIn("invalid_signature", findings[0]["evidence"]["reasons"])

    def test_missing_file_is_high(self) -> None:
        dll = r"C:\Users\Public\ghost.dll"
        findings = m._analyze_netsh_helper(dll, MISSING_SIG, _path_state(dll, in_system=False))
        self.assertEqual(len(findings), 1)
        self.assertIn("missing_file", findings[0]["evidence"]["reasons"])

    def test_empty_value_is_skipped(self) -> None:
        self.assertEqual(m._analyze_netsh_helper("", MS_SIG, _path_state("")), [])
        self.assertEqual(m._analyze_netsh_helper(None, MS_SIG, _path_state("")), [])


# ---------------------------------------------------------------------------
# 2. W32Time TimeProviders
# ---------------------------------------------------------------------------


class TestTimeProvider(unittest.TestCase):
    def test_third_party_dll_is_high(self) -> None:
        dll = r"C:\Users\Public\eviltime.dll"
        findings = m._analyze_time_provider("EvilProvider", dll, THIRD_PARTY_SIG, _path_state(dll, in_system=False))
        self.assertEqual(len(findings), 1)
        _assert_finding(
            self,
            findings[0],
            rule_id=m.RULE_TIMEPROVIDER_DLL,
            severity="HIGH",
            registry_value_path=(
                r"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\EvilProvider\DllName"
            ),
        )
        self.assertEqual(findings[0]["evidence"]["time_provider"], "EvilProvider")

    def test_microsoft_dll_is_allowed(self) -> None:
        dll = rf"{SYSTEM32}\w32time.dll"
        self.assertEqual(m._analyze_time_provider("NtpClient", dll, MS_SIG, _path_state(dll)), [])


# ---------------------------------------------------------------------------
# 3~4. 打印处理器 / 打印监视器
# ---------------------------------------------------------------------------


class TestPrintPersistence(unittest.TestCase):
    def test_print_processor_third_party_is_high(self) -> None:
        dll = r"C:\Users\Public\evilpp.dll"
        findings = m._analyze_print_processor("EvilPP", dll, THIRD_PARTY_SIG, _path_state(dll, in_system=False))
        self.assertEqual(len(findings), 1)
        _assert_finding(
            self,
            findings[0],
            rule_id=m.RULE_PRINT_PROCESSOR,
            severity="HIGH",
            registry_value_path=(
                r"HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments"
                r"\Windows x64\Print Processors\EvilPP\Driver"
            ),
        )
        self.assertEqual(findings[0]["evidence"]["print_processor"], "EvilPP")

    def test_print_processor_microsoft_is_allowed(self) -> None:
        dll = rf"{SYSTEM32}\winprint.dll"
        self.assertEqual(m._analyze_print_processor("winprint", dll, MS_SIG, _path_state(dll)), [])

    def test_print_monitor_third_party_is_high(self) -> None:
        dll = r"C:\Users\Public\evilmon.dll"
        findings = m._analyze_print_monitor("EvilMon", dll, THIRD_PARTY_SIG, _path_state(dll, in_system=False))
        self.assertEqual(len(findings), 1)
        _assert_finding(
            self,
            findings[0],
            rule_id=m.RULE_PRINT_MONITOR,
            severity="HIGH",
            registry_value_path=r"HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\EvilMon\Driver",
        )

    def test_print_monitor_microsoft_is_allowed(self) -> None:
        dll = rf"{SYSTEM32}\localspl.dll"
        self.assertEqual(m._analyze_print_monitor("LocalMon", dll, MS_SIG, _path_state(dll)), [])


# ---------------------------------------------------------------------------
# 5. Active Setup StubPath
# ---------------------------------------------------------------------------


class TestActiveSetup(unittest.TestCase):
    def test_third_party_stub_is_medium(self) -> None:
        stub = r"C:\Users\Public\evil.exe /quiet"
        findings = m._analyze_active_setup(
            "{11111111-2222-3333-4444-555555555555}",
            stub,
            THIRD_PARTY_SIG,
            _path_state(r"C:\Users\Public\evil.exe", in_system=False),
        )
        self.assertEqual(len(findings), 1)
        _assert_finding(
            self,
            findings[0],
            rule_id=m.RULE_ACTIVE_SETUP_STUB,
            severity="MEDIUM",
            registry_value_path=(
                r"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components"
                r"\{11111111-2222-3333-4444-555555555555}\StubPath"
            ),
        )
        self.assertEqual(findings[0]["evidence"]["component_id"], "{11111111-2222-3333-4444-555555555555}")
        self.assertIn("每个用户登录时都会执行", findings[0]["detail"])
        self.assertIn("non_microsoft", findings[0]["evidence"]["reasons"])

    def test_microsoft_signed_stub_is_allowed(self) -> None:
        stub = rf"{SYSTEM32}\ie4uinit.exe -UserConfig"
        findings = m._analyze_active_setup(
            "{89B4C3A0-0000-0000-0000-000000000000}",
            stub,
            MS_SIG,
            _path_state(rf"{SYSTEM32}\ie4uinit.exe"),
        )
        self.assertEqual(findings, [])

    def test_edge_and_office_signers_are_allowed(self) -> None:
        for signer_result in (EDGE_SIG, OFFICE_SIG):
            with self.subTest(signer=signer_result["signer"]):
                stub = r"C:\Program Files (x86)\Microsoft\Edge\Application\setup.exe --configure-user-settings"
                finding = m._analyze_active_setup(
                    "{22222222-3333-4444-5555-666666666666}",
                    stub,
                    signer_result,
                    _path_state(r"C:\Program Files (x86)\Microsoft\Edge\Application\setup.exe", in_system=False),
                )
                self.assertEqual(finding, [])

    def test_unsigned_stub_is_medium(self) -> None:
        stub = r"C:\Users\Public\unsigned.exe"
        findings = m._analyze_active_setup(
            "{33333333-4444-5555-6666-777777777777}",
            stub,
            UNSIGNED_SIG,
            _path_state(stub, in_system=False),
        )
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertIn("unsigned", findings[0]["evidence"]["reasons"])

    def test_missing_stub_target_is_medium(self) -> None:
        stub = r"C:\Users\Public\ghost.exe"
        findings = m._analyze_active_setup(
            "{44444444-5555-6666-7777-888888888888}",
            stub,
            MISSING_SIG,
            _path_state(stub, in_system=False),
        )
        self.assertIn("missing_file", findings[0]["evidence"]["reasons"])

    def test_empty_stub_is_skipped(self) -> None:
        self.assertEqual(
            m._analyze_active_setup("{55555555-6666-7777-8888-999999999999}", "", MS_SIG, _path_state("")),
            [],
        )


class TestActiveSetupLegacyFilter(unittest.TestCase):
    """回归：系统内置非路径 StubPath 不误报，且不放宽真实检测。

    Win11 的 Active Setup 中存在历史遗留的非路径值：
    ``/UserInstall``（开关式）与单字符 ``U``（归一化后甚至会变成
    ``C:\\Windows\\System32\\U``）。它们不指向任何可执行文件，必须跳过；
    而裸可执行名、DLL 路径、路径型第三方签名仍按签名规则判 MEDIUM。
    """

    def test_switch_style_legacy_values_are_skipped(self) -> None:
        for raw in ("/UserInstall", "-UserInstall", "/install", "/ConfigureUserSettings"):
            with self.subTest(raw=raw):
                self.assertEqual(
                    m._analyze_active_setup("{LEGACY-GUID}", raw, MISSING_SIG, _path_state("")),
                    [],
                )

    def test_single_char_and_plain_legacy_values_are_skipped(self) -> None:
        for raw in ("U", "  U  ", "undefined"):
            with self.subTest(raw=raw):
                self.assertEqual(
                    m._analyze_active_setup("{LEGACY-GUID}", raw, MISSING_SIG, _path_state("")),
                    [],
                )

    def test_executable_reference_classification_table(self) -> None:
        expected = {
            "": False,
            "/UserInstall": False,
            "-install": False,
            "U": False,
            "undefined": False,
            "cmd.exe": True,
            "EVIL.DLL": True,
            "rundll32.exe,Install": True,
            r"C:\Windows\System32\evil.dll": True,
            r"%LOCALAPPDATA%\evil.exe": True,
            r"\\server\share\evil.exe": True,
            "/evil.exe": True,
        }
        for raw, expected_result in expected.items():
            with self.subTest(raw=raw):
                self.assertEqual(m._looks_like_executable_reference(raw), expected_result)

    def test_bare_executable_names_are_still_detected(self) -> None:
        for name in ("cmd.exe", "rundll32.exe", "evil.dll"):
            with self.subTest(name=name):
                findings = m._analyze_active_setup(
                    "{GUID}",
                    name,
                    THIRD_PARTY_SIG,
                    _path_state(rf"{SYSTEM32}\{name}"),
                )
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["rule_id"], m.RULE_ACTIVE_SETUP_STUB)
                self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_bare_microsoft_signed_name_is_still_allowed(self) -> None:
        findings = m._analyze_active_setup(
            "{GUID}", "cmd.exe", MS_SIG, _path_state(rf"{SYSTEM32}\cmd.exe")
        )
        self.assertEqual(findings, [])

    def test_path_style_third_party_still_medium(self) -> None:
        chrome = r"C:\Program Files\Google\Chrome\Application\chrmstp.exe"
        stub = f'"{chrome}" --configure-user-settings --system-level'
        findings = m._analyze_active_setup(
            "{GUID}", stub, THIRD_PARTY_SIG, _path_state(chrome, in_system=False)
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertIn("non_microsoft", findings[0]["evidence"]["reasons"])

    def test_dll_path_with_untrusted_signature_is_still_medium(self) -> None:
        dll = rf"{SYSTEM32}\evil.dll"
        findings = m._analyze_active_setup("{GUID}", dll, THIRD_PARTY_SIG, _path_state(dll))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_switch_style_value_with_extension_is_still_judged(self) -> None:
        """"/evil.exe" 虽以 / 开头，但带可执行扩展名，不能按遗留开关跳过。"""
        findings = m._analyze_active_setup("{GUID}", "/evil.exe", MISSING_SIG, _path_state("/evil.exe"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertIn("missing_file", findings[0]["evidence"]["reasons"])

    def test_edge_office_path_values_are_still_allowed(self) -> None:
        edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\setup.exe"
        office = r"C:\Program Files\Microsoft Office\root\Integration\Integrator.exe"
        for signer_result, path in ((EDGE_SIG, edge), (OFFICE_SIG, office)):
            with self.subTest(signer=signer_result["signer"]):
                self.assertEqual(
                    m._analyze_active_setup(
                        "{GUID}",
                        f'"{path}" --configure-user-settings',
                        signer_result,
                        _path_state(path, in_system=False),
                    ),
                    [],
                )


# ---------------------------------------------------------------------------
# 6. AppCompatFlags shim / SDB
# ---------------------------------------------------------------------------


class TestAppCompatShim(unittest.TestCase):
    def test_installed_sdb_third_party_is_medium(self) -> None:
        db = r"C:\Users\Public\evil.sdb"
        findings = m._analyze_appcompat_shim(
            "InstalledSDB",
            "{AABBCCDD-1122-3344-5566-778899AABBCC}",
            "DatabasePath",
            db,
            THIRD_PARTY_SIG,
            _path_state(db, is_pe=False, in_system=False),
        )
        self.assertEqual(len(findings), 1)
        _assert_finding(
            self,
            findings[0],
            rule_id=m.RULE_APPCOMPAT_SHIM,
            severity="MEDIUM",
            registry_value_path=(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
                r"\InstalledSDB\{AABBCCDD-1122-3344-5566-778899AABBCC}\DatabasePath"
            ),
        )
        self.assertEqual(findings[0]["evidence"]["entry_kind"], "InstalledSDB")

    def test_microsoft_signed_sdb_is_allowed(self) -> None:
        db = r"C:\Windows\AppCompat\Programs\DrvMain.sdb"
        self.assertEqual(
            m._analyze_appcompat_shim(
                "InstalledSDB",
                "{00000000-0000-0000-0000-000000000001}",
                "DatabasePath",
                db,
                MS_SIG,
                _path_state(db, is_pe=False, in_system=False),
            ),
            [],
        )

    def test_custom_shim_third_party_is_medium(self) -> None:
        shim = r"C:\Users\Public\evilshim.dll"
        findings = m._analyze_appcompat_shim(
            "Custom",
            "evil.exe",
            "ShimPath",
            shim,
            THIRD_PARTY_SIG,
            _path_state(shim, in_system=False),
        )
        self.assertEqual(len(findings), 1)
        _assert_finding(
            self,
            findings[0],
            rule_id=m.RULE_APPCOMPAT_SHIM,
            severity="MEDIUM",
            registry_value_path=(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
                r"\Custom\evil.exe\ShimPath"
            ),
        )


# ---------------------------------------------------------------------------
# 7. IFEO SilentProcessExit
# ---------------------------------------------------------------------------


class TestSilentProcessExit(unittest.TestCase):
    def test_monitor_process_is_high(self) -> None:
        exe = r"C:\Users\Public\evil.exe"
        findings = m._analyze_silentprocess_exit(
            "notepad.exe", exe, 1, THIRD_PARTY_SIG, _path_state(exe, in_system=False)
        )
        self.assertEqual(len(findings), 1)
        _assert_finding(
            self,
            findings[0],
            rule_id=m.RULE_SILENTPROCESS_EXIT,
            severity="HIGH",
            registry_value_path=(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
                r"\notepad.exe\SilentProcessExit\MonitorProcess"
            ),
        )
        evidence = findings[0]["evidence"]
        self.assertEqual(evidence["process"], "notepad.exe")
        self.assertEqual(evidence["reporting_mode"], 1)
        self.assertTrue(evidence["reporting_mode_nonzero"])
        self.assertIn("monitor_process_set", evidence["reasons"])

    def test_reporting_mode_zero_is_recorded(self) -> None:
        exe = r"C:\Users\Public\evil.exe"
        findings = m._analyze_silentprocess_exit(
            "notepad.exe", exe, 0, THIRD_PARTY_SIG, _path_state(exe, in_system=False)
        )
        self.assertFalse(findings[0]["evidence"]["reporting_mode_nonzero"])

    def test_microsoft_signed_monitor_still_reported(self) -> None:
        """SilentProcessExit 本身是强可疑持久化点：微软签名也不降低等级。"""
        exe = rf"{SYSTEM32}\cmd.exe"
        findings = m._analyze_silentprocess_exit(
            "notepad.exe", exe, 1, MS_SIG, _path_state(exe)
        )
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["evidence"]["signature"]["signer"], "Microsoft Windows")

    def test_empty_monitor_process_is_skipped(self) -> None:
        self.assertEqual(
            m._analyze_silentprocess_exit("notepad.exe", "", 1, MS_SIG, _path_state("")), []
        )


# ---------------------------------------------------------------------------
# 8. WER LocalDumps
# ---------------------------------------------------------------------------


class TestWerLocalDumps(unittest.TestCase):
    def test_user_writable_folder_is_medium(self) -> None:
        findings = m._analyze_wer_localdumps("evil.exe", r"C:\Users\Public\Dumps", False, True)
        self.assertEqual(len(findings), 1)
        _assert_finding(
            self,
            findings[0],
            rule_id=m.RULE_WER_LOCALDUMPS,
            severity="MEDIUM",
            registry_value_path=(
                r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\evil.exe\DumpFolder"
            ),
        )
        evidence = findings[0]["evidence"]
        self.assertEqual(evidence["signature"]["status"], "n/a")
        self.assertTrue(evidence["user_writable"])
        self.assertIn("user_writable", evidence["reasons"])

    def test_system32_default_folder_is_allowed(self) -> None:
        self.assertEqual(
            m._analyze_wer_localdumps("evil.exe", r"C:\Windows\System32\dumps", True, False), []
        )

    def test_non_system_folder_is_medium(self) -> None:
        findings = m._analyze_wer_localdumps("evil.exe", r"C:\ProgramData\Dumps", False, False)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertIn("outside_system", findings[0]["evidence"]["reasons"])

    def test_empty_dump_folder_is_skipped(self) -> None:
        self.assertEqual(m._analyze_wer_localdumps("evil.exe", "", False, True), [])


# ---------------------------------------------------------------------------
# 9. Command Processor AutoRun
# ---------------------------------------------------------------------------


class TestCmdAutoRun(unittest.TestCase):
    def test_autorun_is_medium(self) -> None:
        command = r'C:\Users\Public\evil.cmd'
        findings = m._analyze_cmd_autorun(command, THIRD_PARTY_SIG, _path_state(command, is_pe=False))
        self.assertEqual(len(findings), 1)
        _assert_finding(
            self,
            findings[0],
            rule_id=m.RULE_CMD_AUTORUN,
            severity="MEDIUM",
            registry_value_path=r"HKLM\Software\Microsoft\Command Processor\AutoRun",
        )
        self.assertIn("autorun_configured", findings[0]["evidence"]["reasons"])

    def test_empty_autorun_is_skipped(self) -> None:
        self.assertEqual(m._analyze_cmd_autorun("", MS_SIG, _path_state("")), [])

    def test_collector_reads_both_hives(self) -> None:
        def fake_read(hive: int, subkey: str, name: str, view_flag: int) -> tuple[Any, str | None]:
            del subkey, name, view_flag
            if hive == m.winreg.HKEY_LOCAL_MACHINE:
                return r"C:\Users\Public\hklm.cmd", None
            return r"C:\Users\Public\hkcu.cmd", None

        with (
            mock.patch.object(m, "_read_value", side_effect=fake_read),
            mock.patch.object(m, "_path_state_and_signature", return_value=(_path_state(""), THIRD_PARTY_SIG)),
        ):
            errors: list[str] = []
            findings = m._collect_cmd_autorun(errors)
        self.assertEqual(errors, [])
        self.assertEqual(len(findings), 2)
        paths = {finding["evidence"]["registry_value_path"] for finding in findings}
        self.assertEqual(
            paths,
            {
                r"HKLM\Software\Microsoft\Command Processor\AutoRun",
                r"HKCU\Software\Microsoft\Command Processor\AutoRun",
            },
        )


# ---------------------------------------------------------------------------
# 10. 屏幕保护程序
# ---------------------------------------------------------------------------


class TestScreensaver(unittest.TestCase):
    def test_system32_microsoft_signed_is_allowed(self) -> None:
        scr = rf"{SYSTEM32}\Bubbles.scr"
        self.assertEqual(m._analyze_screensaver(scr, MS_SIG, _path_state(scr)), [])

    def test_third_party_outside_system32_is_low(self) -> None:
        scr = r"C:\Users\Public\evil.scr"
        findings = m._analyze_screensaver(scr, THIRD_PARTY_SIG, _path_state(scr, in_system=False))
        self.assertEqual(len(findings), 1)
        _assert_finding(
            self,
            findings[0],
            rule_id=m.RULE_SCRNSAVER,
            severity="LOW",
            registry_value_path=r"HKCU\Control Panel\Desktop\SCRNSAVE.EXE",
        )
        self.assertIn("outside_system", findings[0]["evidence"]["reasons"])
        self.assertIn("non_microsoft", findings[0]["evidence"]["reasons"])

    def test_unsigned_scr_in_system32_is_low(self) -> None:
        scr = rf"{SYSTEM32}\unsigned.scr"
        findings = m._analyze_screensaver(scr, UNSIGNED_SIG, _path_state(scr))
        self.assertEqual(findings[0]["severity"], "LOW")
        self.assertIn("unsigned", findings[0]["evidence"]["reasons"])

    def test_empty_screensaver_is_skipped(self) -> None:
        self.assertEqual(m._analyze_screensaver("", MS_SIG, _path_state("")), [])


# ---------------------------------------------------------------------------
# 采集辅助：路径解析
# ---------------------------------------------------------------------------


class TestCollectPathState(unittest.TestCase):
    def test_bare_dll_resolves_to_system32(self) -> None:
        with mock.patch.dict(os.environ, {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows"}):
            state = m._collect_path_state("winprint.dll")
        self.assertEqual(state["executable"], rf"{SYSTEM32}\winprint.dll")
        self.assertTrue(state["is_pe"])
        self.assertTrue(state["in_system_dir"])

    def test_quoted_command_with_arguments_extracts_executable(self) -> None:
        raw = '"C:\\Windows\\System32\\regsvr32.exe" /s "C:\\Program Files\\x\\a.dll"'
        with mock.patch.dict(os.environ, {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows"}):
            state = m._collect_path_state(raw)
        self.assertEqual(state["executable"], rf"{SYSTEM32}\regsvr32.exe")
        self.assertTrue(state["is_pe"])

    def test_expands_environment_variables(self) -> None:
        with mock.patch.dict(os.environ, {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows"}):
            state = m._collect_path_state(r"%SystemRoot%\System32\w32time.dll")
        self.assertEqual(state["executable"], rf"{SYSTEM32}\w32time.dll")

    def test_bare_dll_prefers_existing_search_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "winprint.dll")
            with open(target, "wb"):
                pass
            with mock.patch.dict(os.environ, {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows"}):
                state = m._collect_path_state("winprint.dll", search_dirs=(tmpdir,))
        self.assertEqual(state["executable"], target)


# ---------------------------------------------------------------------------
# 采集层（mock winreg 读取函数，不触碰真实 HKLM）
# ---------------------------------------------------------------------------


class TestCollectors(unittest.TestCase):
    def test_netsh_collector_reports_third_party(self) -> None:
        dll = r"C:\Users\Public\evilhelper.dll"

        def fake_read(hive: int, subkey: str, name: str, view_flag: int) -> tuple[Any, str | None]:
            del hive, subkey, view_flag
            if name == "NetshHelperDll":
                return dll, None
            return None, "not_found"

        with (
            mock.patch.object(m, "_read_value", side_effect=fake_read),
            mock.patch.object(
                m,
                "_path_state_and_signature",
                return_value=(_path_state(dll, in_system=False), THIRD_PARTY_SIG),
            ),
        ):
            errors: list[str] = []
            findings = m._collect_netsh_helper(errors)
        self.assertEqual(errors, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], m.RULE_NETSH_HELPER)

    def test_netsh_collector_access_denied_records_error(self) -> None:
        with mock.patch.object(m, "_read_value", return_value=(None, "access_denied")):
            errors: list[str] = []
            findings = m._collect_netsh_helper(errors)
        self.assertEqual(findings, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("拒绝访问", errors[0])

    def test_time_provider_collector(self) -> None:
        dll = r"C:\Users\Public\eviltime.dll"

        def fake_read(hive: int, subkey: str, name: str, view_flag: int) -> tuple[Any, str | None]:
            del hive, subkey, view_flag
            if name == "DllName":
                return dll, None
            return None, "not_found"

        with (
            mock.patch.object(m, "_enum_subkeys", return_value=(["EvilProvider"], None)),
            mock.patch.object(m, "_read_value", side_effect=fake_read),
            mock.patch.object(
                m,
                "_path_state_and_signature",
                return_value=(_path_state(dll, in_system=False), THIRD_PARTY_SIG),
            ),
        ):
            findings = m._collect_time_providers([])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], m.RULE_TIMEPROVIDER_DLL)
        self.assertEqual(findings[0]["evidence"]["time_provider"], "EvilProvider")

    def test_active_setup_collector_filters_trusted_signer(self) -> None:
        trusted_stub = rf"{SYSTEM32}\ie4uinit.exe -UserConfig"
        evil_stub = r"C:\Users\Public\evil.exe"
        trusted_guid = "{AAAAAAAA-0000-0000-0000-000000000001}"
        evil_guid = "{BBBBBBBB-0000-0000-0000-000000000002}"

        def fake_read(hive: int, subkey: str, name: str, view_flag: int) -> tuple[Any, str | None]:
            del hive, view_flag
            self.assertEqual(name, "StubPath")
            if trusted_guid in subkey:
                return trusted_stub, None
            if evil_guid in subkey:
                return evil_stub, None
            return None, "not_found"

        def fake_path_state(raw: Any) -> tuple[dict[str, Any], dict[str, Any]]:
            text = str(raw)
            if "evil" in text:
                return _path_state(r"C:\Users\Public\evil.exe", in_system=False), THIRD_PARTY_SIG
            return _path_state(rf"{SYSTEM32}\ie4uinit.exe"), MS_SIG

        with (
            mock.patch.object(m, "_enum_subkeys", return_value=([trusted_guid, evil_guid], None)),
            mock.patch.object(m, "_read_value", side_effect=fake_read),
            mock.patch.object(m, "_path_state_and_signature", side_effect=fake_path_state),
        ):
            findings = m._collect_active_setup([])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], m.RULE_ACTIVE_SETUP_STUB)
        self.assertEqual(findings[0]["evidence"]["component_id"], evil_guid)

    def test_active_setup_collector_skips_legacy_non_path_values(self) -> None:
        """采集链路：/UserInstall、U 不产出 Finding，只有真实路径型条目被判定。"""
        chrome = r"C:\Program Files\Google\Chrome\Application\chrmstp.exe"
        stubs = {
            "{AAAAAAAA-0000-0000-0000-000000000001}": "/UserInstall",
            "{BBBBBBBB-0000-0000-0000-000000000002}": "U",
            "{CCCCCCCC-0000-0000-0000-000000000003}": f'"{chrome}" --configure-user-settings',
        }

        def fake_read(hive: int, subkey: str, name: str, view_flag: int) -> tuple[Any, str | None]:
            del hive, view_flag
            self.assertEqual(name, "StubPath")
            for guid, stub in stubs.items():
                if guid in subkey:
                    return stub, None
            return None, "not_found"

        def fake_path_state(raw: Any) -> tuple[dict[str, Any], dict[str, Any]]:
            del raw
            return _path_state(chrome, in_system=False), THIRD_PARTY_SIG

        with (
            mock.patch.object(m, "_enum_subkeys", return_value=(list(stubs), None)),
            mock.patch.object(m, "_read_value", side_effect=fake_read),
            mock.patch.object(m, "_path_state_and_signature", side_effect=fake_path_state),
        ):
            findings = m._collect_active_setup([])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"]["component_id"], "{CCCCCCCC-0000-0000-0000-000000000003}")
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_appcompat_collector_analyses_only_path_like_custom_values(self) -> None:
        shim = r"C:\Users\Public\evilshim.dll"

        def fake_enum(hive: int, subkey: str, view_flag: int) -> tuple[list[str], str | None]:
            del hive, view_flag
            if subkey.endswith("InstalledSDB"):
                return [], None
            return ["evil.exe"], None

        def fake_values(hive: int, subkey: str, view_flag: int) -> tuple[dict[str, Any], str | None]:
            del hive, subkey, view_flag
            return {"ShimPath": shim, "Note": "not a path"}, None

        with (
            mock.patch.object(m, "_enum_subkeys", side_effect=fake_enum),
            mock.patch.object(m, "_enum_values", side_effect=fake_values),
            mock.patch.object(
                m,
                "_path_state_and_signature",
                return_value=(_path_state(shim, in_system=False), THIRD_PARTY_SIG),
            ),
        ):
            findings = m._collect_appcompat_shims([])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], m.RULE_APPCOMPAT_SHIM)
        self.assertEqual(findings[0]["evidence"]["entry_kind"], "Custom")
        self.assertEqual(findings[0]["evidence"]["shim_value"], shim)

    def test_silentprocess_collector(self) -> None:
        exe = r"C:\Users\Public\evil.exe"

        def fake_read(hive: int, subkey: str, name: str, view_flag: int) -> tuple[Any, str | None]:
            del hive, subkey, view_flag
            if name == "MonitorProcess":
                return exe, None
            if name == "ReportingMode":
                return 1, None
            return None, "value_missing"

        with (
            mock.patch.object(m, "_enum_subkeys", return_value=(["notepad.exe"], None)),
            mock.patch.object(m, "_read_value", side_effect=fake_read),
            mock.patch.object(
                m,
                "_path_state_and_signature",
                return_value=(_path_state(exe, in_system=False), THIRD_PARTY_SIG),
            ),
        ):
            findings = m._collect_silentprocess_exit([])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], m.RULE_SILENTPROCESS_EXIT)
        self.assertEqual(findings[0]["evidence"]["reporting_mode"], 1)

    def test_wer_collector_reports_user_writable_folder(self) -> None:
        with (
            mock.patch.object(m, "_enum_subkeys", return_value=(["evil.exe"], None)),
            mock.patch.object(m, "_read_value", return_value=(r"C:\Users\Public\Dumps", None)),
            mock.patch.object(
                m,
                "_collect_folder_state",
                return_value={
                    "expanded": r"C:\Users\Public\Dumps",
                    "folder": r"C:\Users\Public\Dumps",
                    "in_system_dir": False,
                    "user_writable": True,
                },
            ),
        ):
            findings = m._collect_wer_localdumps([])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], m.RULE_WER_LOCALDUMPS)

    def test_screensaver_collector(self) -> None:
        scr = r"C:\Users\Public\evil.scr"
        with (
            mock.patch.object(m, "_read_value", return_value=(scr, None)),
            mock.patch.object(
                m,
                "_path_state_and_signature",
                return_value=(_path_state(scr, in_system=False), THIRD_PARTY_SIG),
            ),
        ):
            findings = m._collect_screensaver([])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], m.RULE_SCRNSAVER)
        self.assertEqual(findings[0]["evidence"]["value_name"], "SCRNSAVE.EXE")

    def test_print_processor_collector_uses_spool_search_dirs(self) -> None:
        """打印处理器 Driver 是裸 DLL 名，采集层必须把 spool\\prtprocs 纳入搜索。"""
        dll = rf"{SYSTEM32}\spool\prtprocs\x64\winprint.dll"
        with (
            mock.patch.object(m, "_enum_subkeys", return_value=(["winprint"], None)),
            mock.patch.object(m, "_read_value", return_value=("winprint.dll", None)),
            mock.patch.object(
                m,
                "_path_state_and_signature",
                return_value=(_path_state(dll), MS_SIG),
            ) as patched,
        ):
            findings = m._collect_print_processors([])
        self.assertEqual(findings, [])
        search_dirs = patched.call_args.kwargs.get("search_dirs")
        self.assertIsNotNone(search_dirs)
        self.assertTrue(any("prtprocs" in str(directory).lower() for directory in search_dirs))


# ---------------------------------------------------------------------------
# scan() 编排
# ---------------------------------------------------------------------------


class TestScan(unittest.TestCase):
    def _sample_finding(self) -> dict[str, Any]:
        return m.make_finding(
            "HIGH",
            m.CATEGORY,
            r"C:\Users\Public\evil.dll",
            "sample",
            {"registry_value_path": r"HKLM\SOFTWARE\Microsoft\NetSh\NetshHelperDll"},
            m.RULE_NETSH_HELPER,
        )

    def test_access_denied_collector_yields_skipped(self) -> None:
        def denied(errors: list[str]) -> list[dict[str, Any]]:
            raise PermissionError("access denied")

        with mock.patch.object(m, "_COLLECTORS", (denied, lambda errors: [])):
            findings = m.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], m.RULE_ACCESS_DENIED)
        self.assertIn("PersistenceExt", findings[0]["target"])

    def test_generic_collector_error_yields_skipped_and_keeps_findings(self) -> None:
        sample = self._sample_finding()

        def boom(errors: list[str]) -> list[dict[str, Any]]:
            raise RuntimeError("boom")

        with mock.patch.object(m, "_COLLECTORS", (lambda errors: [dict(sample)], boom)):
            findings = m.scan()
        rule_ids = [finding["rule_id"] for finding in findings]
        self.assertIn(m.RULE_NETSH_HELPER, rule_ids)
        self.assertIn(m.RULE_SKIPPED, rule_ids)
        skipped = next(finding for finding in findings if finding["severity"] == "SKIPPED")
        self.assertIn("RuntimeError", skipped["detail"])

    def test_scan_invokes_apply_whitelist(self) -> None:
        sample = self._sample_finding()

        def fake_apply(findings: list[dict[str, Any]], *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            del args, kwargs
            return list(findings)

        with (
            mock.patch.object(m, "_COLLECTORS", (lambda errors: [dict(sample)],)),
            mock.patch.object(m.utils, "apply_whitelist", side_effect=fake_apply) as patched,
        ):
            findings = m.scan()
        patched.assert_called_once()
        self.assertEqual(findings, [sample])

    def test_scan_without_collector_errors_has_no_skipped(self) -> None:
        with mock.patch.object(m, "_COLLECTORS", (lambda errors: [], lambda errors: [])):
            self.assertEqual(m.scan(), [])


# ---------------------------------------------------------------------------
# 白名单 persistence_ext_allow
# ---------------------------------------------------------------------------


class TestPersistenceExtWhitelist(unittest.TestCase):
    _ENTRY = {
        "registry_value_path": r"HKLM\SOFTWARE\Microsoft\NetSh\NetshHelperDll",
        "signer_contains": "Contoso",
        "note": "企业内网合法 Netsh helper",
    }

    def _finding(self, value_path: str, signer: str | None) -> dict[str, Any]:
        return m.make_finding(
            "HIGH",
            m.CATEGORY,
            r"C:\Program Files\Contoso\helper.dll",
            "sample",
            {
                "registry_value_path": value_path,
                "registry_key": r"HKLM\SOFTWARE\Microsoft\NetSh",
                "value_name": "NetshHelperDll",
                "signer": signer or "",
                "signature": {"status": "valid", "signer": signer},
            },
            m.RULE_NETSH_HELPER,
        )

    def test_default_whitelist_has_section(self) -> None:
        self.assertIn("persistence_ext_allow", utils.DEFAULT_WHITELIST)
        self.assertIsInstance(utils.DEFAULT_WHITELIST["persistence_ext_allow"], list)

    def test_real_whitelist_file_has_empty_section(self) -> None:
        config = utils.load_whitelist()
        self.assertIn("persistence_ext_allow", config)
        self.assertEqual(config["persistence_ext_allow"], [])

    def test_load_whitelist_keeps_only_dict_entries(self) -> None:
        payload = {"persistence_ext_allow": [dict(self._ENTRY), "bad", 3, None]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            json.dump(payload, handle)
            path = handle.name
        try:
            config = utils.load_whitelist(path)
        finally:
            os.unlink(path)
        self.assertEqual(config["persistence_ext_allow"], [dict(self._ENTRY)])

    def test_exact_path_and_signer_hit(self) -> None:
        config = _whitelist_config([dict(self._ENTRY)])
        hit = utils.match_whitelist(
            self._finding(r"HKLM\SOFTWARE\Microsoft\NetSh\NetshHelperDll", "Contoso Ltd"),
            config,
        )
        self.assertIsNotNone(hit)
        self.assertEqual(hit["type"], "persistence_ext_allow")
        self.assertIn("netshhelperdll", hit["value"].lower())

    def test_match_is_case_insensitive(self) -> None:
        config = _whitelist_config([dict(self._ENTRY)])
        hit = utils.match_whitelist(
            self._finding(r"hklm\software\microsoft\netsh\netshhelperdll", "CONTOSO LTD"),
            config,
        )
        self.assertIsNotNone(hit)
        self.assertEqual(hit["type"], "persistence_ext_allow")

    def test_path_mismatch_is_not_exempt(self) -> None:
        config = _whitelist_config([dict(self._ENTRY)])
        hit = utils.match_whitelist(
            self._finding(r"HKLM\SOFTWARE\Microsoft\NetSh\OtherValue", "Contoso Ltd"),
            config,
        )
        self.assertIsNone(hit)

    def test_signer_mismatch_is_not_exempt(self) -> None:
        config = _whitelist_config([dict(self._ENTRY)])
        hit = utils.match_whitelist(
            self._finding(r"HKLM\SOFTWARE\Microsoft\NetSh\NetshHelperDll", "Fabrikam Inc"),
            config,
        )
        self.assertIsNone(hit)

    def test_empty_signer_is_not_exempt(self) -> None:
        config = _whitelist_config([dict(self._ENTRY)])
        for signer in (None, ""):
            with self.subTest(signer=signer):
                hit = utils.match_whitelist(
                    self._finding(r"HKLM\SOFTWARE\Microsoft\NetSh\NetshHelperDll", signer),
                    config,
                )
                self.assertIsNone(hit)

    def test_empty_entry_fields_do_not_match(self) -> None:
        config = _whitelist_config(
            [
                {"registry_value_path": "", "signer_contains": "Contoso"},
                {"registry_value_path": "x", "signer_contains": ""},
            ]
        )
        self.assertIsNone(
            utils.match_whitelist(
                self._finding(r"HKLM\SOFTWARE\Microsoft\NetSh\NetshHelperDll", "Contoso Ltd"),
                config,
            )
        )

    def test_apply_whitelist_downgrades_to_info(self) -> None:
        config = _whitelist_config([dict(self._ENTRY)])
        finding = self._finding(r"HKLM\SOFTWARE\Microsoft\NetSh\NetshHelperDll", "Contoso Ltd")
        result = utils.apply_whitelist([finding], config, mode="downgrade")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "INFO")
        self.assertTrue(result[0]["evidence"]["whitelisted"])
        self.assertEqual(
            result[0]["evidence"]["whitelist_match"]["type"], "persistence_ext_allow"
        )

    def test_apply_whitelist_filter_mode_drops(self) -> None:
        config = _whitelist_config([dict(self._ENTRY)])
        finding = self._finding(r"HKLM\SOFTWARE\Microsoft\NetSh\NetshHelperDll", "Contoso Ltd")
        self.assertEqual(utils.apply_whitelist([finding], config, mode="filter"), [])

    def test_existing_signers_whitelist_still_works(self) -> None:
        config = _whitelist_config([])
        config["signers"] = ["Contoso"]
        finding = self._finding(r"HKLM\SOFTWARE\Microsoft\NetSh\NetshHelperDll", "Contoso Ltd")
        hit = utils.match_whitelist(finding, config)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["type"], "signers")

    def test_finding_without_registry_value_path_is_not_exempt(self) -> None:
        config = _whitelist_config([dict(self._ENTRY)])
        finding = m.make_finding(
            "HIGH",
            m.CATEGORY,
            r"C:\Users\Public\evil.dll",
            "sample",
            {"signature": {"status": "valid", "signer": "Contoso Ltd"}},
            m.RULE_NETSH_HELPER,
        )
        self.assertIsNone(utils.match_whitelist(finding, config))


# ---------------------------------------------------------------------------
# 全部 10 个检测点的 evidence 字段表驱动校验
# ---------------------------------------------------------------------------


class TestEvidenceFields(unittest.TestCase):
    def test_all_rules_expose_required_evidence(self) -> None:
        third = THIRD_PARTY_SIG
        cases: list[tuple[str, str, str, Any]] = [
            (
                "netsh",
                m.RULE_NETSH_HELPER,
                "HIGH",
                lambda: m._analyze_netsh_helper(
                    r"C:\Users\Public\a.dll", third, _path_state(r"C:\Users\Public\a.dll", in_system=False)
                ),
            ),
            (
                "timeprovider",
                m.RULE_TIMEPROVIDER_DLL,
                "HIGH",
                lambda: m._analyze_time_provider(
                    "EvilProvider",
                    r"C:\Users\Public\a.dll",
                    third,
                    _path_state(r"C:\Users\Public\a.dll", in_system=False),
                ),
            ),
            (
                "printprocessor",
                m.RULE_PRINT_PROCESSOR,
                "HIGH",
                lambda: m._analyze_print_processor(
                    "EvilPP",
                    r"C:\Users\Public\a.dll",
                    third,
                    _path_state(r"C:\Users\Public\a.dll", in_system=False),
                ),
            ),
            (
                "printmonitor",
                m.RULE_PRINT_MONITOR,
                "HIGH",
                lambda: m._analyze_print_monitor(
                    "EvilMon",
                    r"C:\Users\Public\a.dll",
                    third,
                    _path_state(r"C:\Users\Public\a.dll", in_system=False),
                ),
            ),
            (
                "activesetup",
                m.RULE_ACTIVE_SETUP_STUB,
                "MEDIUM",
                lambda: m._analyze_active_setup(
                    "{GUID}",
                    r"C:\Users\Public\a.exe",
                    third,
                    _path_state(r"C:\Users\Public\a.exe", in_system=False),
                ),
            ),
            (
                "appcompat",
                m.RULE_APPCOMPAT_SHIM,
                "MEDIUM",
                lambda: m._analyze_appcompat_shim(
                    "InstalledSDB",
                    "{ID}",
                    "DatabasePath",
                    r"C:\Users\Public\a.sdb",
                    third,
                    _path_state(r"C:\Users\Public\a.sdb", is_pe=False, in_system=False),
                ),
            ),
            (
                "silentprocessexit",
                m.RULE_SILENTPROCESS_EXIT,
                "HIGH",
                lambda: m._analyze_silentprocess_exit(
                    "notepad.exe",
                    r"C:\Users\Public\a.exe",
                    1,
                    third,
                    _path_state(r"C:\Users\Public\a.exe", in_system=False),
                ),
            ),
            (
                "wer",
                m.RULE_WER_LOCALDUMPS,
                "MEDIUM",
                lambda: m._analyze_wer_localdumps("a.exe", r"C:\Users\Public\Dumps", False, True),
            ),
            (
                "cmdautorun",
                m.RULE_CMD_AUTORUN,
                "MEDIUM",
                lambda: m._analyze_cmd_autorun(
                    r"C:\Users\Public\a.cmd", third, _path_state(r"C:\Users\Public\a.cmd", is_pe=False)
                ),
            ),
            (
                "screensaver",
                m.RULE_SCRNSAVER,
                "LOW",
                lambda: m._analyze_screensaver(
                    r"C:\Users\Public\a.scr", third, _path_state(r"C:\Users\Public\a.scr", in_system=False)
                ),
            ),
        ]
        expected_path_parts = {
            "netsh": r"\NetshHelperDll",
            "timeprovider": r"\TimeProviders\EvilProvider\DllName",
            "printprocessor": r"\Print Processors\EvilPP\Driver",
            "printmonitor": r"\Control\Print\Monitors\EvilMon\Driver",
            "activesetup": r"\Installed Components\{GUID}\StubPath",
            "appcompat": r"\InstalledSDB\{ID}\DatabasePath",
            "silentprocessexit": r"\Image File Execution Options\notepad.exe\SilentProcessExit\MonitorProcess",
            "wer": r"\LocalDumps\a.exe\DumpFolder",
            "cmdautorun": r"\Command Processor\AutoRun",
            "screensaver": r"\Control Panel\Desktop\SCRNSAVE.EXE",
        }
        for label, rule_id, severity, factory in cases:
            with self.subTest(label=label):
                findings = factory()
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                _assert_finding(
                    self,
                    finding,
                    rule_id=rule_id,
                    severity=severity,
                    registry_value_path=finding["evidence"]["registry_value_path"],
                )
                self.assertIn(expected_path_parts[label], finding["evidence"]["registry_value_path"])
                if label == "wer":
                    self.assertEqual(finding["evidence"]["signature"]["status"], "n/a")


# ---------------------------------------------------------------------------
# 真实环境冒烟（签名打桩，只读注册表）
# ---------------------------------------------------------------------------


@unittest.skipUnless(sys.platform == "win32", "仅 Windows 支持 winreg")
class TestRealScanSmoke(unittest.TestCase):
    def test_scan_never_raises_and_findings_are_well_formed(self) -> None:
        with mock.patch.object(m.signature, "verify", return_value=MS_SIG):
            findings = m.scan()
        self.assertIsInstance(findings, list)
        allowed_rules = {
            m.RULE_NETSH_HELPER,
            m.RULE_TIMEPROVIDER_DLL,
            m.RULE_PRINT_PROCESSOR,
            m.RULE_PRINT_MONITOR,
            m.RULE_ACTIVE_SETUP_STUB,
            m.RULE_APPCOMPAT_SHIM,
            m.RULE_SILENTPROCESS_EXIT,
            m.RULE_WER_LOCALDUMPS,
            m.RULE_CMD_AUTORUN,
            m.RULE_SCRNSAVER,
            m.RULE_ACCESS_DENIED,
            m.RULE_SKIPPED,
        }
        for finding in findings:
            self.assertEqual(set(finding), _FINDING_KEYS)
            self.assertEqual(finding["category"], m.CATEGORY)
            self.assertIn(finding["severity"], SEVERITIES)
            self.assertIsInstance(finding["evidence"], dict)
            self.assertIn(finding["rule_id"], allowed_rules)


if __name__ == "__main__":
    unittest.main(verbosity=2)
