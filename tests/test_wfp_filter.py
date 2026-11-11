# -*- coding: utf-8 -*-
"""``modules/wfp_filter.py`` 的单元测试。

不依赖管理员权限、不依赖真实机器上是否存在 EDR Silencer：

1. 纯函数：用按 ``FWPM_FILTER0`` 字段偏移构造的合成 blob 验证结构定位、condition 解析、
   公网 IP/端口/应用条件判定、系统过滤器降噪；
2. 真实 winreg：在 ``HKCU\\Software\\TamperScanTests`` 下造一个缩微的
   ``Persistent\\Filter``（GUID 命名值 + 子键 FilterData 两种布局），验证采集链路；
3. ``scan()`` 集成：打桩采集层，验证阈值降级、未解析统计、异常兜底；最后真实冒烟。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_wfp_filter.py
    python -m unittest discover -s tests -p "test_*.py" -v
    python tests\\test_wfp_filter.py
"""

from __future__ import annotations

import ipaddress
import struct
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
from modules import wfp_filter as m  # noqa: E402

# 权威 GUID（与 fwpmu.h / Win32 元数据一致）
LAYER_CONNECT_V4 = "c38d57d1-05a7-4c33-904f-7fbceee60e82"
LAYER_CONNECT_V6 = "4a72393b-319f-44bc-84c3-ba54dcb3b6b4"
LAYER_RECV_ACCEPT_V4 = "e1cd9fe7-f4b5-4273-96c0-592e487b8650"
SUBLAYER_MPSSVC_WF = "b3cdd441-af90-41ba-a745-7c6008ff2301"
SUBLAYER_UNIVERSAL = "eebecc03-ced4-4380-819a-2734397b2b74"
COND_APP_ID = "d78e1e87-8644-4ea5-9437-d809ecefc971"
COND_REMOTE_ADDRESS = "b235ae9a-1d64-49b8-a44c-5ff3d9095045"
COND_REMOTE_PORT = "c35a604d-d22b-4e1a-91b4-68f674ee674b"
COND_LOCAL_PORT = "0c1ba1af-5765-453f-af22-a8f791ac775b"
COND_PROTOCOL = "3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"

FILTER_KEY = "11111111-2222-3333-4444-555555555555"
FILTER_KEY_2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

_FINDING_KEYS = {"severity", "category", "target", "detail", "evidence", "rule_id"}

_HKCU_TEST_PARENT = r"Software\TamperScanTests"
_HKCU_TEST_ROOT = rf"{_HKCU_TEST_PARENT}\WFPFilter\{uuid.uuid4().hex}"


# ---------------------------------------------------------------------------
# 合成 blob 构造（FWPM_FILTER0 字段偏移 + condition 记录）
# ---------------------------------------------------------------------------


def _guid_bytes(text: str) -> bytes:
    return uuid.UUID(text).bytes_le


def _put_u32(buffer: bytearray, offset: int, value: int) -> None:
    buffer[offset : offset + 4] = struct.pack("<I", value)


def _put_u64(buffer: bytearray, offset: int, value: int) -> None:
    buffer[offset : offset + 8] = struct.pack("<Q", value)


def _condition(field_guid: str, match_type: int, value_type: int, value_bytes: bytes = b"") -> tuple:
    return (field_guid, match_type, value_type, bytes(value_bytes))


def _build_blob(
    *,
    layer: str = LAYER_CONNECT_V4,
    sublayer: str = SUBLAYER_UNIVERSAL,
    action: int = m.FWP_ACTION_BLOCK,
    conditions: tuple = (),
    display: str = "EDRSilencer",
    flags: int = 1,
    base: int = 0x20,
    filter_key: str = FILTER_KEY,
) -> bytes:
    """按 FWPM_FILTER0 布局造一个持久化过滤器 blob（含 16 字节对象头）。"""
    header = b"\x01\x10\x08\x00" + b"\xcc" * 4 + b"\x00" * 8
    struct_size = 0xA8
    condition_offset = base + struct_size
    if condition_offset % 8:
        condition_offset += 8 - condition_offset % 8
    tail = 512 + (len(display) + 1) * 2
    blob = bytearray(len(header) + base + struct_size + 32 * len(conditions) + tail)
    blob[0:16] = header

    blob[base : base + 16] = _guid_bytes(filter_key)
    _put_u32(blob, base + 0x10, 0x20000)  # displayData.name 指针
    _put_u32(blob, base + 0x14, 0x00000)  # displayData.description 指针
    _put_u32(blob, base + 0x18, flags)
    _put_u32(blob, base + 0x1C, 0x20004)  # providerKey 指针
    _put_u32(blob, base + 0x20, 0)  # providerData.size
    _put_u32(blob, base + 0x24, 0)  # providerData.data 指针
    blob[base + 0x28 : base + 0x38] = _guid_bytes(layer)
    blob[base + 0x38 : base + 0x48] = _guid_bytes(sublayer)
    _put_u32(blob, base + 0x48, 0)  # weight.type = FWP_EMPTY
    _put_u32(blob, base + 0x50, len(conditions))
    _put_u32(blob, base + 0x54, 0x20010)  # filterCondition 指针
    _put_u32(blob, base + 0x58, action)
    _put_u64(blob, base + 0x88, 0x1010A)  # filterId

    for index, (field_guid, match_type, value_type, value_bytes) in enumerate(conditions):
        record = condition_offset + index * 32
        blob[record : record + 16] = _guid_bytes(field_guid)
        _put_u32(blob, record + 16, match_type)
        _put_u32(blob, record + 20, value_type)
        if value_bytes:
            blob[record + 24 : record + 24 + len(value_bytes)] = value_bytes

    display_bytes = display.encode("utf-16-le") + b"\x00\x00"
    blob[-len(display_bytes) :] = display_bytes
    return bytes(blob)


def _ipv4_bytes(text: str) -> bytes:
    return ipaddress.IPv4Address(text).packed


def _port_bytes(port: int) -> bytes:
    return struct.pack("<H", port)


APP_ID_CONDITION = _condition(COND_APP_ID, 0, m.FWP_BYTE_BLOB_TYPE, b"\x00\x02\x00\x00")
REMOTE_IP_CONDITION = _condition(COND_REMOTE_ADDRESS, 0, m.FWP_UINT32, _ipv4_bytes("8.8.8.8"))
PRIVATE_IP_CONDITION = _condition(COND_REMOTE_ADDRESS, 0, m.FWP_UINT32, _ipv4_bytes("192.168.1.10"))
REMOTE_PORT_CONDITION = _condition(COND_REMOTE_PORT, 0, m.FWP_UINT16, _port_bytes(443))
LOCAL_PORT_CONDITION = _condition(COND_LOCAL_PORT, 0, m.FWP_UINT16, _port_bytes(8080))
PROTOCOL_CONDITION = _condition(COND_PROTOCOL, 0, m.FWP_UINT8, b"\x06")


def _entry(blob: bytes, name: str = FILTER_KEY) -> dict[str, Any]:
    return {"name": name, "layout": "value", "data": blob}


class TestParseFilterBlob(unittest.TestCase):
    """结构定位 + condition 解析（纯函数）。"""

    def test_parses_struct_and_conditions(self) -> None:
        blob = _build_blob(conditions=(APP_ID_CONDITION, REMOTE_IP_CONDITION, REMOTE_PORT_CONDITION))
        parsed = m._parse_filter_blob(blob)
        self.assertTrue(parsed["struct_found"])
        self.assertTrue(parsed["header_valid"])
        self.assertEqual(parsed["struct_base"], 0x20)
        self.assertEqual(parsed["filter_key"], FILTER_KEY)
        self.assertEqual(parsed["layer_name"], "FWPM_LAYER_ALE_AUTH_CONNECT_V4")
        self.assertEqual(parsed["layer_direction"], "outbound")
        self.assertEqual(parsed["sub_layer_name"], "FWPM_SUBLAYER_UNIVERSAL")
        self.assertEqual(parsed["action"], m.FWP_ACTION_BLOCK)
        self.assertEqual(parsed["action_name"], "FWP_ACTION_BLOCK")
        self.assertTrue(parsed["persistent"])
        self.assertEqual(parsed["num_conditions"], 3)
        self.assertEqual(parsed["filter_id"], 0x1010A)
        self.assertIn("EDRSilencer", parsed["strings"])

        by_name = {condition["field_name"]: condition for condition in parsed["conditions"]}
        self.assertEqual(by_name["FWPM_CONDITION_IP_REMOTE_ADDRESS"]["ipv4"], "8.8.8.8")
        self.assertEqual(by_name["FWPM_CONDITION_IP_REMOTE_PORT"]["port"], 443)
        self.assertEqual(by_name["FWPM_CONDITION_ALE_APP_ID"]["value_name"], "FWP_BYTE_BLOB")
        self.assertEqual(by_name["FWPM_CONDITION_IP_REMOTE_ADDRESS"]["value_name"], "FWP_UINT32")

    def test_tolerates_different_struct_base(self) -> None:
        for base in (0x10, 0x18, 0x30, 0x40):
            blob = _build_blob(base=base, conditions=(APP_ID_CONDITION,))
            parsed = m._parse_filter_blob(blob)
            self.assertTrue(parsed["struct_found"], f"base={base}")
            self.assertEqual(parsed["struct_base"], base)
            self.assertEqual(parsed["layer_name"], "FWPM_LAYER_ALE_AUTH_CONNECT_V4")

    def test_inbound_layer_is_classified(self) -> None:
        parsed = m._parse_filter_blob(_build_blob(layer=LAYER_RECV_ACCEPT_V4))
        self.assertEqual(parsed["layer_direction"], "inbound")

    def test_ipv6_layer_is_known(self) -> None:
        parsed = m._parse_filter_blob(_build_blob(layer=LAYER_CONNECT_V6))
        self.assertEqual(parsed["layer_name"], "FWPM_LAYER_ALE_AUTH_CONNECT_V6")

    def test_short_or_garbage_blob_is_not_parsed(self) -> None:
        for blob in (b"", b"\x00" * 10, b"\x01\x10\x08\x00" + b"\x00" * 60, bytes(range(256))):
            parsed = m._parse_filter_blob(blob)
            self.assertFalse(parsed["struct_found"])
            self.assertEqual(parsed["conditions"], [])

    def test_header_missing_but_struct_valid_is_still_parsed(self) -> None:
        blob = bytearray(_build_blob())
        blob[0:4] = b"\xde\xad\xbe\xef"
        parsed = m._parse_filter_blob(bytes(blob))
        self.assertFalse(parsed["header_valid"])
        self.assertTrue(parsed["struct_found"])
        self.assertEqual(parsed["layer_name"], "FWPM_LAYER_ALE_AUTH_CONNECT_V4")

    def test_non_bytes_input_is_not_parsed(self) -> None:
        for value in (None, 123, "abc", []):
            parsed = m._parse_filter_blob(value)  # type: ignore[arg-type]
            self.assertFalse(parsed["struct_found"])

    def test_condition_value_alignment_shift_is_handled(self) -> None:
        """condition 记录起点非 8 字节对齐时，union 仍有 4 字节对齐补偿。"""
        blob = bytearray(_build_blob(conditions=(REMOTE_PORT_CONDITION,)))
        parsed = m._parse_filter_blob(bytes(blob))
        condition = next(c for c in parsed["conditions"] if c["field_name"] == "FWPM_CONDITION_IP_REMOTE_PORT")
        self.assertEqual(condition["port"], 443)


class TestAnalyzeFilter(unittest.TestCase):
    """规则判定（纯函数）。"""

    def _findings(self, blob: bytes, name: str = FILTER_KEY) -> list[dict[str, Any]]:
        parsed = m._parse_filter_blob(blob)
        self.assertTrue(parsed["struct_found"])
        return m._analyze_filter(_entry(blob, name), parsed)

    def test_edr_silencer_signature_is_high(self) -> None:
        findings = self._findings(_build_blob(conditions=(APP_ID_CONDITION,)))
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(set(finding), _FINDING_KEYS)
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["rule_id"], "WFP_EDR_SILENCER")
        self.assertEqual(finding["category"], "WFPFilter")
        self.assertIn("ALE_APP_ID", finding["detail"])
        self.assertTrue(finding["target"].endswith(FILTER_KEY))
        evidence = finding["evidence"]
        self.assertEqual(evidence["layer_name"], "FWPM_LAYER_ALE_AUTH_CONNECT_V4")
        self.assertEqual(evidence["action"], "FWP_ACTION_BLOCK")
        self.assertEqual(evidence["filter_key"], FILTER_KEY)
        self.assertTrue(evidence["persistent_flag"])
        self.assertIn("conditions", evidence)

    def test_block_public_ip_is_high(self) -> None:
        findings = self._findings(_build_blob(conditions=(REMOTE_IP_CONDITION,), display="custom-rule"))
        rule_ids = {finding["rule_id"] for finding in findings}
        self.assertIn("WFP_BLOCK_PUBLIC_IP", rule_ids)
        public = next(finding for finding in findings if finding["rule_id"] == "WFP_BLOCK_PUBLIC_IP")
        self.assertEqual(public["severity"], "HIGH")
        self.assertIn("8.8.8.8", public["detail"])

    def test_block_private_ip_is_not_public_high(self) -> None:
        findings = self._findings(_build_blob(conditions=(PRIVATE_IP_CONDITION,), display="custom-rule"))
        self.assertNotIn("WFP_BLOCK_PUBLIC_IP", {finding["rule_id"] for finding in findings})
        self.assertEqual(findings[0]["rule_id"], "WFP_BLOCK_FILTER")
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_block_remote_port_is_high(self) -> None:
        findings = self._findings(_build_blob(conditions=(REMOTE_PORT_CONDITION,), display="custom-rule"))
        port_findings = [finding for finding in findings if finding["rule_id"] == "WFP_BLOCK_REMOTE_PORT"]
        self.assertEqual(len(port_findings), 1)
        self.assertEqual(port_findings[0]["severity"], "HIGH")
        self.assertIn("443", port_findings[0]["detail"])

    def test_permit_action_has_no_finding(self) -> None:
        self.assertEqual(
            self._findings(_build_blob(action=m.FWP_ACTION_PERMIT, conditions=(APP_ID_CONDITION,))), []
        )

    def test_callout_action_has_no_finding(self) -> None:
        self.assertEqual(
            self._findings(
                _build_blob(action=m.FWP_ACTION_CALLOUT_TERMINATING, conditions=(APP_ID_CONDITION,))
            ),
            [],
        )

    def test_system_sublayer_is_skipped(self) -> None:
        findings = self._findings(
            _build_blob(sublayer=SUBLAYER_MPSSVC_WF, conditions=(APP_ID_CONDITION,), display="Windows Firewall")
        )
        self.assertEqual(findings, [])

    def test_system_display_name_is_skipped(self) -> None:
        findings = self._findings(
            _build_blob(conditions=(APP_ID_CONDITION,), display="@FirewallAPI.dll,-28502")
        )
        self.assertEqual(findings, [])

    def test_block_all_outbound_is_medium(self) -> None:
        findings = self._findings(_build_blob(conditions=(), display="custom-rule"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(findings[0]["rule_id"], "WFP_BLOCK_FILTER")
        self.assertIn("阻断全部流量", findings[0]["detail"])

    def test_inbound_app_id_is_not_silencer(self) -> None:
        findings = self._findings(
            _build_blob(layer=LAYER_RECV_ACCEPT_V4, conditions=(APP_ID_CONDITION,), display="custom-rule")
        )
        self.assertNotIn("WFP_EDR_SILENCER", {finding["rule_id"] for finding in findings})
        self.assertEqual(findings[0]["rule_id"], "WFP_BLOCK_FILTER")

    def test_local_port_and_protocol_evidence(self) -> None:
        findings = self._findings(
            _build_blob(conditions=(LOCAL_PORT_CONDITION, PROTOCOL_CONDITION), display="custom-rule")
        )
        self.assertEqual(findings[0]["rule_id"], "WFP_BLOCK_FILTER")
        names = {condition["field_name"] for condition in findings[0]["evidence"]["conditions"]}
        self.assertIn("FWPM_CONDITION_IP_LOCAL_PORT", names)
        self.assertIn("FWPM_CONDITION_IP_PROTOCOL", names)


class TestHelpers(unittest.TestCase):
    def test_public_ipv4_ranges(self) -> None:
        for text in ("8.8.8.8", "1.1.1.1", "93.184.216.34", "20.1.2.3"):
            self.assertTrue(m._is_public_ipv4(text), text)
        for text in ("192.168.1.1", "10.0.0.1", "172.16.5.5", "127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1"):
            self.assertFalse(m._is_public_ipv4(text), text)
        # 文档/保留网段（RFC 5737）不是可路由公网地址
        for text in ("203.0.113.5", "198.51.100.7", "192.0.2.1"):
            self.assertFalse(m._is_public_ipv4(text), text)
        for text in ("not-an-ip", "", "999.1.1.1"):
            self.assertFalse(m._is_public_ipv4(text), text)

    def test_looks_system(self) -> None:
        self.assertTrue(m._looks_system({"sub_layer_name": "FWPM_SUBLAYER_MPSSVC_WF"}))
        self.assertTrue(m._looks_system({"strings": ["@FirewallAPI.dll,-1"]}))
        self.assertFalse(m._looks_system({"sub_layer_name": "FWPM_SUBLAYER_UNIVERSAL", "strings": ["EDRSilencer"]}))


class TestRegistryReader(unittest.TestCase):
    """真实 winreg：GUID 命名值布局 + 子键 FilterData 布局。"""

    @classmethod
    def setUpClass(cls) -> None:
        _delete_key_tree(winreg.HKEY_CURRENT_USER, _HKCU_TEST_ROOT)
        blob = _build_blob(conditions=(APP_ID_CONDITION,))
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _HKCU_TEST_ROOT, 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, FILTER_KEY, 0, winreg.REG_BINARY, blob)
            winreg.SetValueEx(key, FILTER_KEY_2, 0, winreg.REG_BINARY, blob)
            winreg.SetValueEx(key, "NotBinary", 0, winreg.REG_SZ, "ignore-me")
            with winreg.CreateKeyEx(key, "SubkeyLayout", 0, winreg.KEY_ALL_ACCESS) as sub:
                winreg.SetValueEx(sub, "FilterData", 0, winreg.REG_BINARY, blob)

    @classmethod
    def tearDownClass(cls) -> None:
        _delete_key_tree(winreg.HKEY_CURRENT_USER, _HKCU_TEST_ROOT)
        for parent in (rf"{_HKCU_TEST_PARENT}\WFPFilter", _HKCU_TEST_PARENT):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, parent)
            except OSError:
                break

    def test_reads_value_and_subkey_layouts(self) -> None:
        entries, stats, fatal = m._read_persistent_filter_entries(
            hive=winreg.HKEY_CURRENT_USER, root=_HKCU_TEST_ROOT, view_flag=0
        )
        self.assertIsNone(fatal)
        self.assertEqual(stats["values"], 2)
        self.assertEqual(stats["subkeys"], 1)
        layouts = {(entry["name"], entry["layout"]) for entry in entries}
        self.assertIn((FILTER_KEY, "value"), layouts)
        self.assertIn((FILTER_KEY_2, "value"), layouts)
        self.assertIn(("SubkeyLayout", "subkey"), layouts)
        for entry in entries:
            parsed = m._parse_filter_blob(entry["data"])
            self.assertTrue(parsed["struct_found"])
            findings = m._analyze_filter(entry, parsed)
            self.assertIn("WFP_EDR_SILENCER", {finding["rule_id"] for finding in findings})

    def test_missing_root_is_not_found(self) -> None:
        entries, stats, fatal = m._read_persistent_filter_entries(
            hive=winreg.HKEY_CURRENT_USER, root=rf"{_HKCU_TEST_PARENT}\nope-{uuid.uuid4().hex}", view_flag=0
        )
        self.assertEqual(entries, [])
        self.assertEqual(stats["fatal_kind"], "not_found")
        self.assertIn("不存在", fatal or "")


class TestScanDegrade(unittest.TestCase):
    """``scan()`` 集成：打桩采集层，验证降级/统计/异常兜底。"""

    _OK_STATS = {"values": 0, "subkeys": 0, "skipped": 0, "errors": 0, "truncated": 0, "fatal_kind": ""}

    def test_access_denied_returns_skipped(self) -> None:
        stats = dict(self._OK_STATS, fatal_kind="access_denied")
        with mock.patch.object(m, "_read_persistent_filter_entries", return_value=([], stats, "拒绝访问")):
            findings = m.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "WFP_ACCESS_DENIED")

    def test_not_found_returns_skipped(self) -> None:
        stats = dict(self._OK_STATS, fatal_kind="not_found")
        with mock.patch.object(m, "_read_persistent_filter_entries", return_value=([], stats, "键不存在")):
            findings = m.scan()
        self.assertEqual(findings[0]["rule_id"], "WFP_SKIPPED")
        self.assertEqual(findings[0]["severity"], "SKIPPED")

    def test_unexpected_exception_is_degraded(self) -> None:
        with mock.patch.object(m, "_read_persistent_filter_entries", side_effect=RuntimeError("boom")):
            findings = m.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "WFP_SKIPPED")
        self.assertIn("boom", findings[0]["detail"])

    def test_empty_store_returns_empty_list(self) -> None:
        with mock.patch.object(m, "_read_persistent_filter_entries", return_value=([], dict(self._OK_STATS), None)):
            self.assertEqual(m.scan(), [])

    def test_silencer_detected_and_unparsed_reported(self) -> None:
        good = _build_blob(conditions=(APP_ID_CONDITION,))
        entries = [_entry(good), _entry(b"garbage" * 8, "bad-filter")]
        with mock.patch.object(
            m, "_read_persistent_filter_entries", return_value=(entries, dict(self._OK_STATS), None)
        ):
            findings = m.scan()
        rule_ids = [finding["rule_id"] for finding in findings]
        self.assertIn("WFP_EDR_SILENCER", rule_ids)
        self.assertIn("WFP_FILTER_UNPARSED", rule_ids)
        unparsed = next(finding for finding in findings if finding["rule_id"] == "WFP_FILTER_UNPARSED")
        self.assertEqual(unparsed["severity"], "SKIPPED")
        self.assertIn("1 个", unparsed["detail"])

    def test_partial_stats_add_skipped_note(self) -> None:
        stats = dict(self._OK_STATS, errors=2, truncated=1)
        with mock.patch.object(m, "_read_persistent_filter_entries", return_value=([], stats, None)):
            findings = m.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "WFP_PARTIAL")

    def test_analyze_exception_isolated_per_entry(self) -> None:
        good = _build_blob(conditions=(APP_ID_CONDITION,))
        with (
            mock.patch.object(
                m, "_read_persistent_filter_entries", return_value=([_entry(good)], dict(self._OK_STATS), None)
            ),
            mock.patch.object(m, "_parse_filter_blob", side_effect=RuntimeError("parse boom")),
        ):
            findings = m.scan()
        self.assertEqual(findings[0]["rule_id"], "WFP_FILTER_UNPARSED")


@unittest.skipUnless(sys.platform == "win32", "仅 Windows 支持 winreg")
class TestRealScanSmoke(unittest.TestCase):
    """真实环境冒烟：不假设是否管理员，只要求不崩、结构合法、权限不足必须 SKIPPED。"""

    def test_scan_never_raises_and_findings_are_well_formed(self) -> None:
        findings = m.scan()
        self.assertIsInstance(findings, list)
        for finding in findings:
            self.assertEqual(set(finding), _FINDING_KEYS)
            self.assertIn(finding["severity"], SEVERITIES)
            self.assertIsInstance(finding["evidence"], dict)
            self.assertTrue(str(finding["rule_id"]).startswith("WFP_"))

        from core import utils

        if not utils.is_admin():
            rule_ids = [finding["rule_id"] for finding in findings]
            self.assertIn("WFP_ACCESS_DENIED", rule_ids)
            self.assertNotIn("HIGH", [finding["severity"] for finding in findings])


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
