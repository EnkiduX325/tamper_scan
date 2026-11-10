# -*- coding: utf-8 -*-
"""``modules/scheduled_task_hidden.py`` 的单元测试。

设计目标：**不依赖本机是否管理员、不依赖真实机器上是否存在隐藏任务**，任何 Windows
机器上都能通过；同时不触碰 HKLM 的 TaskCache（标准用户读不到）。

覆盖三层：
1. 纯函数判定：``_sd_state`` / ``_int_value`` / ``_parse_actions`` / ``_analyze_node``；
2. 真实 winreg 递归：在 ``HKCU\\Software\\TamperScanTests\\...`` 下临时造一棵
   TaskCache\\Tree 结构，验证枚举/取值/判定链路（用完删除，不留痕迹）；
3. ``scan()`` 集成：monkeypatch 采集层，验证白名单/降级/异常兜底；最后用真实
   ``scan()`` 做冒烟（标准用户应得到 SKIPPED，管理员应得到合法 Finding 列表）。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_scheduled_task_hidden.py
    python -m unittest discover -s tests -p "test_*.py" -v
    python tests\\test_scheduled_task_hidden.py
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

from core.finding import SEVERITIES  # noqa: E402  必须在 sys.path 之后导入
from modules import scheduled_task_hidden as m  # noqa: E402

TASK_GUID = "{11111111-2222-3333-4444-555555555555}"
# 任意非空二进制：判定只看"存在且非空"，不解析安全描述符内容
VALID_SD = b"\x01\x00\x04\x80" + b"\x00" * 12

_FINDING_KEYS = {"severity", "category", "target", "detail", "evidence", "rule_id"}

_HKCU_TEST_PARENT = r"Software\TamperScanTests"
_HKCU_TREE_PARENT = rf"{_HKCU_TEST_PARENT}\TaskCacheTree"
_HKCU_TEST_ROOT = rf"{_HKCU_TREE_PARENT}\{uuid.uuid4().hex}"


def _values(**entries: Any) -> dict[str, tuple[Any, int]]:
    """构造 ``{值名: (数据, 类型)}``，模拟 ``_read_node_values`` 的返回值。"""
    return dict(entries)


def _delete_key_tree(hive: int, path: str) -> None:
    """递归删除测试用注册表键（失败忽略，不影响测试结果）。"""
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


def _create_test_tree() -> None:
    """在 HKCU 下造一棵模拟 TaskCache\\Tree（folders + 正常/异常任务节点）。"""
    nodes: dict[str, dict[str, tuple[Any, int]]] = {
        "": {},
        r"Microsoft": {"SD": (VALID_SD, winreg.REG_BINARY)},
        r"Microsoft\Windows": {"SD": (VALID_SD, winreg.REG_BINARY)},
        r"Microsoft\Windows\GoodTask": {
            "Id": (TASK_GUID, winreg.REG_SZ),
            "Index": (42, winreg.REG_DWORD),
            "SD": (VALID_SD, winreg.REG_BINARY),
        },
        r"Microsoft\Windows\EvilTask": {  # Tarrask：Id/Index 都在，SD 被删
            "Id": (TASK_GUID, winreg.REG_SZ),
            "Index": (7, winreg.REG_DWORD),
        },
        r"Microsoft\Windows\IndexZeroTask": {  # Index 篡改为 0，SD 正常
            "Id": (TASK_GUID, winreg.REG_SZ),
            "Index": (0, winreg.REG_DWORD),
            "SD": (VALID_SD, winreg.REG_BINARY),
        },
        r"Microsoft\Windows\StaleZeroTask": {  # Index==0 且无 Id（历史残留，应降为 MEDIUM）
            "Index": (0, winreg.REG_DWORD),
            "SD": (VALID_SD, winreg.REG_BINARY),
        },
    }
    for relative, values in nodes.items():
        path = _HKCU_TEST_ROOT if not relative else f"{_HKCU_TEST_ROOT}\\{relative}"
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as key:
            for name, (data, value_type) in values.items():
                winreg.SetValueEx(key, name, 0, value_type, data)


class _PatchedDefinitionTest(unittest.TestCase):
    """默认把 Tasks\\<GUID> 定义读取打桩为"定义存在"，保证纯函数测试不访问真实注册表。"""

    def setUp(self) -> None:
        patcher = mock.patch.object(m, "_read_task_definition", return_value={"definition_exists": True})
        patcher.start()
        self.addCleanup(patcher.stop)


class TestAnalyzeNode(_PatchedDefinitionTest):
    """``_analyze_node`` 判定规则与 Finding 结构。"""

    def test_missing_sd_is_high_tarrask(self) -> None:
        findings = m._analyze_node(
            r"Evil\Task",
            _values(Id=(TASK_GUID, winreg.REG_SZ), Index=(7, winreg.REG_DWORD)),
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(set(finding), _FINDING_KEYS)
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["category"], "ScheduledTaskHidden")
        self.assertEqual(finding["rule_id"], "TASK_HIDDEN_TARRASK")
        self.assertEqual(finding["target"], r"\Evil\Task")
        self.assertEqual(finding["evidence"]["reasons"], ["sd_missing"])
        self.assertTrue(finding["evidence"]["registry_key"].endswith(r"\Evil\Task"))

    def test_index_zero_is_high_tarrask(self) -> None:
        findings = m._analyze_node(
            r"Microsoft\Windows\IndexZeroTask",
            _values(
                Id=(TASK_GUID, winreg.REG_SZ),
                Index=(0, winreg.REG_DWORD),
                SD=(VALID_SD, winreg.REG_BINARY),
            ),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["rule_id"], "TASK_HIDDEN_TARRASK")
        self.assertEqual(findings[0]["evidence"]["reasons"], ["index_zero"])
        self.assertEqual(findings[0]["evidence"]["index"], 0)

    def test_empty_sd_is_high(self) -> None:
        findings = m._analyze_node(
            r"EmptySd",
            _values(
                Id=(TASK_GUID, winreg.REG_SZ),
                Index=(3, winreg.REG_DWORD),
                SD=(b"", winreg.REG_BINARY),
            ),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["evidence"]["reasons"], ["sd_empty"])
        self.assertFalse(findings[0]["evidence"]["sd_length"])

    def test_non_binary_sd_is_high(self) -> None:
        findings = m._analyze_node(
            r"TextSd",
            _values(Id=(TASK_GUID, winreg.REG_SZ), Index=(3, winreg.REG_DWORD), SD=("x", winreg.REG_SZ)),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"]["reasons"], ["sd_not_binary"])

    def test_missing_sd_and_zero_index_merge_into_one_finding(self) -> None:
        findings = m._analyze_node(r"Both", _values(Id=(TASK_GUID, winreg.REG_SZ), Index=(0, winreg.REG_DWORD)))
        self.assertEqual(len(findings), 1, "同一节点的两个证据应合并为一条 Finding，避免重复上报")
        self.assertEqual(findings[0]["evidence"]["reasons"], ["sd_missing", "index_zero"])

    def test_index_zero_without_definition_is_downgraded(self) -> None:
        """Index==0 但无对应 Tasks 定义（历史残留键）→ 默认降为 MEDIUM，仍上报。"""
        with mock.patch.object(m, "_read_task_definition", return_value={"definition_exists": False}):
            findings = m._analyze_node(
                r"Residue\OldTask",
                _values(
                    Id=(TASK_GUID, winreg.REG_SZ),
                    Index=(0, winreg.REG_DWORD),
                    SD=(VALID_SD, winreg.REG_BINARY),
                ),
            )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(findings[0]["rule_id"], "TASK_HIDDEN_TARRASK")
        self.assertTrue(findings[0]["evidence"]["stale_candidate"])
        self.assertIn("历史残留", findings[0]["detail"])

    def test_index_zero_with_definition_error_stays_high(self) -> None:
        """Tasks 定义读取被拒绝时不能当作"不存在"，保持 HIGH 避免漏报。"""
        with mock.patch.object(
            m,
            "_read_task_definition",
            return_value={"definition_exists": False, "definition_error": "拒绝访问"},
        ):
            findings = m._analyze_node(
                r"Evil\Task",
                _values(
                    Id=(TASK_GUID, winreg.REG_SZ),
                    Index=(0, winreg.REG_DWORD),
                    SD=(VALID_SD, winreg.REG_BINARY),
                ),
            )
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertFalse(findings[0]["evidence"]["stale_candidate"])

    def test_index_missing_on_task_node_is_high(self) -> None:
        """Index 值被删除（Qualys 隐藏全部任务的手法）：有 Id 的任务节点 → HIGH。"""
        findings = m._analyze_node(
            r"Microsoft\Windows\NoIndexTask",
            _values(Id=(TASK_GUID, winreg.REG_SZ), SD=(VALID_SD, winreg.REG_BINARY)),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["rule_id"], "TASK_HIDDEN_TARRASK")
        self.assertEqual(findings[0]["evidence"]["reasons"], ["index_missing"])

    def test_folder_without_index_is_not_flagged(self) -> None:
        """目录节点（无 Id/Index）只有 SD，属正常结构，不能报 index_missing。"""
        findings = m._analyze_node(r"Microsoft\Windows", _values(SD=(VALID_SD, winreg.REG_BINARY)))
        self.assertEqual(findings, [])

    def test_healthy_task_has_no_finding(self) -> None:
        findings = m._analyze_node(
            r"Microsoft\Windows\GoodTask",
            _values(
                Id=(TASK_GUID, winreg.REG_SZ),
                Index=(42, winreg.REG_DWORD),
                SD=(VALID_SD, winreg.REG_BINARY),
            ),
        )
        self.assertEqual(findings, [])

    def test_folder_node_with_sd_has_no_finding(self) -> None:
        findings = m._analyze_node(r"Microsoft\Windows", _values(SD=(VALID_SD, winreg.REG_BINARY)))
        self.assertEqual(findings, [])

    def test_binary_index_zero_is_detected(self) -> None:
        findings = m._analyze_node(
            r"BinaryIndex",
            _values(
                Id=(TASK_GUID, winreg.REG_SZ),
                Index=(b"\x00\x00\x00\x00", winreg.REG_BINARY),
                SD=(VALID_SD, winreg.REG_BINARY),
            ),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"]["reasons"], ["index_zero"])

    def test_binary_index_nonzero_is_not_detected(self) -> None:
        findings = m._analyze_node(
            r"BinaryIndexOk",
            _values(
                Id=(TASK_GUID, winreg.REG_SZ),
                Index=(b"\x2a\x00\x00\x00", winreg.REG_BINARY),
                SD=(VALID_SD, winreg.REG_BINARY),
            ),
        )
        self.assertEqual(findings, [])

    def test_evidence_and_detail_are_analyst_friendly(self) -> None:
        findings = m._analyze_node(
            r"Microsoft\Windows\EvilTask",
            _values(Id=(TASK_GUID, winreg.REG_SZ), Index=(9, winreg.REG_DWORD)),
        )
        evidence = findings[0]["evidence"]
        self.assertEqual(evidence["task_name"], "EvilTask")
        self.assertEqual(evidence["task_path"], r"\Microsoft\Windows\EvilTask")
        self.assertEqual(evidence["node_kind"], "task")
        self.assertEqual(evidence["task_id"], TASK_GUID)
        self.assertEqual(evidence["index"], 9)
        self.assertTrue(evidence["index_present"])
        self.assertFalse(evidence["sd_present"])
        self.assertEqual(evidence["value_names"], ["Id", "Index"])
        self.assertIn("SD 值缺失", findings[0]["detail"])

    def test_folder_node_kind_without_id_or_index(self) -> None:
        findings = m._analyze_node(r"LonelyFolder", _values())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"]["node_kind"], "folder")
        self.assertEqual(findings[0]["evidence"]["reasons"], ["sd_missing"])


class TestValueHelpers(unittest.TestCase):
    """值解析辅助函数。"""

    def test_int_value_variants(self) -> None:
        self.assertEqual(m._int_value({"Index": (0, winreg.REG_DWORD)}), 0)
        self.assertEqual(m._int_value({"Index": (b"\x07\x00\x00\x00", winreg.REG_BINARY)}), 7)
        self.assertEqual(m._int_value({"Index": ("0x10", winreg.REG_SZ)}), 16)
        self.assertIsNone(m._int_value({}))
        self.assertIsNone(m._int_value({"Index": (b"\x00" * 9, winreg.REG_BINARY)}))

    def test_sd_state_variants(self) -> None:
        self.assertEqual(m._sd_state({}), (False, 0, "sd_missing"))
        self.assertEqual(m._sd_state({"SD": (b"", winreg.REG_BINARY)}), (True, 0, "sd_empty"))
        self.assertEqual(m._sd_state({"SD": (VALID_SD, winreg.REG_BINARY)}), (True, len(VALID_SD), ""))
        self.assertEqual(m._sd_state({"SD": ("", winreg.REG_SZ)}), (True, 0, "sd_empty"))
        self.assertEqual(m._sd_state({"SD": ("oops", winreg.REG_SZ)}), (True, 0, "sd_not_binary"))

    def test_parse_actions_utf16_xml(self) -> None:
        xml = (
            '<?xml version="1.0" encoding="UTF-16"?><Task><Actions Context="Author">'
            "<Exec><Command>C:\\Windows\\System32\\cmd.exe</Command>"
            "<Arguments>/c calc.exe</Arguments></Exec></Actions></Task>"
        )
        command, arguments = m._parse_actions(xml.encode("utf-16-le"))
        self.assertIn("cmd.exe", command)
        self.assertIn("/c calc.exe", arguments)

    def test_parse_actions_ascii_xml_and_garbage(self) -> None:
        xml = "<Task><Actions><Exec><Command>C:\\evil.exe</Command></Exec></Actions></Task>"
        command, _arguments = m._parse_actions(xml.encode("latin-1"))
        self.assertIn("evil.exe", command)
        self.assertEqual(m._parse_actions(b"\x00\x01\x02"), ("", ""))
        self.assertEqual(m._parse_actions(None), ("", ""))

    def test_task_id_text_variants(self) -> None:
        self.assertEqual(m._task_id_text({"Id": (TASK_GUID, winreg.REG_SZ)}), TASK_GUID)
        self.assertEqual(m._task_id_text({"Id": (TASK_GUID.encode("utf-16-le"), winreg.REG_BINARY)}), TASK_GUID)
        self.assertEqual(m._task_id_text({}), "")


@unittest.skipUnless(sys.platform == "win32", "仅 Windows 有 winreg")
class TestRealRegistryWalk(unittest.TestCase):
    """在 HKCU 下用真实 winreg 验证递归枚举 + 取值 + 判定链路（不需管理员）。"""

    @classmethod
    def setUpClass(cls) -> None:
        _delete_key_tree(winreg.HKEY_CURRENT_USER, _HKCU_TEST_ROOT)
        _create_test_tree()

    @classmethod
    def tearDownClass(cls) -> None:
        _delete_key_tree(winreg.HKEY_CURRENT_USER, _HKCU_TEST_ROOT)
        # 顺带清理空父键，避免测试机残留 HKCU\Software\TamperScanTests（非空则保留）
        for parent in (_HKCU_TREE_PARENT, _HKCU_TEST_PARENT):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, parent)
            except OSError:
                break

    def setUp(self) -> None:
        patcher = mock.patch.object(m, "_read_task_definition", return_value={"definition_exists": True})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_walk_enumerates_all_nodes(self) -> None:
        paths, stats, fatal = m._iter_tree_node_paths(
            hive=winreg.HKEY_CURRENT_USER, root=_HKCU_TEST_ROOT, view_flag=0
        )
        self.assertIsNone(fatal)
        self.assertEqual(stats["nodes"], 6)
        self.assertEqual(stats["denied"], 0)
        self.assertEqual(stats["errors"], 0)
        self.assertIn(r"Microsoft\Windows\EvilTask", paths)
        self.assertEqual(paths, sorted(paths, key=str.lower))

    def test_node_limit_truncates_without_overflow(self) -> None:
        """单层大量子键也不能突破 _MAX_NODES；越过上限的节点必须计入 truncated。"""
        with mock.patch.object(m, "_MAX_NODES", 3):
            paths, stats, fatal = m._iter_tree_node_paths(
                hive=winreg.HKEY_CURRENT_USER, root=_HKCU_TEST_ROOT, view_flag=0
            )
        self.assertIsNone(fatal)
        self.assertEqual(len(paths), 3)
        self.assertGreaterEqual(stats["truncated"], 1)

    def test_walk_and_analyze_detect_only_anomalies(self) -> None:
        paths, _stats, _fatal = m._iter_tree_node_paths(
            hive=winreg.HKEY_CURRENT_USER, root=_HKCU_TEST_ROOT, view_flag=0
        )
        findings: list[dict[str, Any]] = []
        for relative in paths:
            values, error = m._read_node_values(
                relative, hive=winreg.HKEY_CURRENT_USER, root=_HKCU_TEST_ROOT, view_flag=0
            )
            self.assertIsNone(error)
            findings.extend(m._analyze_node(relative, values))
        by_target = {finding["target"]: finding for finding in findings}
        self.assertEqual(
            set(by_target),
            {
                r"\Microsoft\Windows\EvilTask",
                r"\Microsoft\Windows\IndexZeroTask",
                r"\Microsoft\Windows\StaleZeroTask",
            },
        )
        self.assertEqual(by_target[r"\Microsoft\Windows\EvilTask"]["evidence"]["reasons"], ["sd_missing"])
        self.assertEqual(by_target[r"\Microsoft\Windows\IndexZeroTask"]["evidence"]["reasons"], ["index_zero"])
        self.assertEqual(by_target[r"\Microsoft\Windows\EvilTask"]["severity"], "HIGH")
        self.assertEqual(by_target[r"\Microsoft\Windows\IndexZeroTask"]["severity"], "HIGH")
        # Index==0 且无 Id/无 Tasks 定义的历史残留键：仍上报，但默认降为 MEDIUM
        self.assertEqual(by_target[r"\Microsoft\Windows\StaleZeroTask"]["severity"], "MEDIUM")
        self.assertTrue(by_target[r"\Microsoft\Windows\StaleZeroTask"]["evidence"]["stale_candidate"])

    def test_scan_end_to_end_against_synthetic_tree(self) -> None:
        """完整走一遍 scan()：真实 winreg 递归 + 判定 + 白名单，不需要管理员。"""
        original_walk = m._iter_tree_node_paths
        original_read = m._read_node_values

        with (
            mock.patch.object(
                m,
                "_iter_tree_node_paths",
                lambda: original_walk(hive=winreg.HKEY_CURRENT_USER, root=_HKCU_TEST_ROOT, view_flag=0),
            ),
            mock.patch.object(
                m,
                "_read_node_values",
                lambda relative: original_read(
                    relative, hive=winreg.HKEY_CURRENT_USER, root=_HKCU_TEST_ROOT, view_flag=0
                ),
            ),
        ):
            findings = m.scan()

        self.assertEqual(
            sorted(finding["target"] for finding in findings),
            [
                r"\Microsoft\Windows\EvilTask",
                r"\Microsoft\Windows\IndexZeroTask",
                r"\Microsoft\Windows\StaleZeroTask",
            ],
        )
        severities = {finding["target"]: finding["severity"] for finding in findings}
        self.assertEqual(severities[r"\Microsoft\Windows\EvilTask"], "HIGH")
        self.assertEqual(severities[r"\Microsoft\Windows\IndexZeroTask"], "HIGH")
        self.assertEqual(severities[r"\Microsoft\Windows\StaleZeroTask"], "MEDIUM")
        self.assertTrue(all(finding["rule_id"] == "TASK_HIDDEN_TARRASK" for finding in findings))

    def test_missing_root_reports_not_found_without_raising(self) -> None:
        missing = rf"Software\TamperScanTests\nope-{uuid.uuid4().hex}"
        paths, stats, fatal = m._iter_tree_node_paths(hive=winreg.HKEY_CURRENT_USER, root=missing, view_flag=0)
        self.assertEqual(paths, [])
        self.assertEqual(stats["fatal_kind"], "not_found")
        self.assertIn("不存在", fatal or "")

    def test_read_node_values_missing_subkey_returns_error(self) -> None:
        values, error = m._read_node_values(
            r"Microsoft\Windows\DefinitelyMissing",
            hive=winreg.HKEY_CURRENT_USER,
            root=_HKCU_TEST_ROOT,
            view_flag=0,
        )
        self.assertEqual(values, {})
        self.assertIsNotNone(error)


class TestScanDegrade(_PatchedDefinitionTest):
    """``scan()`` 集成：降级路径与白名单/合并逻辑（采集层打桩，不依赖权限）。"""

    _OK_STATS: dict[str, Any] = {"nodes": 0, "denied": 0, "errors": 0, "truncated": 0, "fatal_kind": ""}

    def test_empty_tree_returns_empty_list(self) -> None:
        with mock.patch.object(m, "_iter_tree_node_paths", return_value=([], dict(self._OK_STATS), None)):
            self.assertEqual(m.scan(), [])

    def test_access_denied_returns_skipped(self) -> None:
        stats = dict(self._OK_STATS, fatal_kind="access_denied")
        with mock.patch.object(
            m, "_iter_tree_node_paths", return_value=([], stats, "拒绝访问（需要管理员权限）：TaskCache\\Tree")
        ):
            findings = m.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "TASK_HIDDEN_ACCESS_DENIED")

    def test_not_found_returns_skipped(self) -> None:
        stats = dict(self._OK_STATS, fatal_kind="not_found")
        with mock.patch.object(m, "_iter_tree_node_paths", return_value=([], stats, "注册表键不存在")):
            findings = m.scan()
        self.assertEqual(findings[0]["rule_id"], "TASK_HIDDEN_SKIPPED")
        self.assertEqual(findings[0]["severity"], "SKIPPED")

    def test_unexpected_collector_exception_is_degraded(self) -> None:
        with mock.patch.object(m, "_iter_tree_node_paths", side_effect=RuntimeError("boom")):
            findings = m.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "TASK_HIDDEN_SKIPPED")
        self.assertIn("boom", findings[0]["detail"])

    def test_hidden_tasks_are_reported_with_definition_evidence(self) -> None:
        values = _values(Id=(TASK_GUID, winreg.REG_SZ), Index=(0, winreg.REG_DWORD))
        definition = {
            "definition_exists": True,
            "command": r"C:\Windows\System32\cmd.exe",
            "arguments": "/c calc.exe",
        }
        with (
            mock.patch.object(m, "_iter_tree_node_paths", return_value=([r"Evil\Task"], dict(self._OK_STATS), None)),
            mock.patch.object(m, "_read_node_values", return_value=(values, None)),
            mock.patch.object(m, "_read_task_definition", return_value=definition),
        ):
            findings = m.scan()
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["rule_id"], "TASK_HIDDEN_TARRASK")
        self.assertEqual(finding["target"], r"\Evil\Task")
        self.assertEqual(finding["evidence"]["task_definition"]["command"], r"C:\Windows\System32\cmd.exe")

    def test_truncated_walk_adds_partial_note(self) -> None:
        """遍历达到上限（截断）必须显式上报 PARTIAL，不能静默漏报。"""
        stats = dict(self._OK_STATS, truncated=2)
        with (
            mock.patch.object(m, "_iter_tree_node_paths", return_value=(["A"], stats, None)),
            mock.patch.object(m, "_read_node_values", return_value=({}, "拒绝访问")),
        ):
            findings = m.scan()
        partial = [finding for finding in findings if finding["rule_id"] == "TASK_HIDDEN_PARTIAL"]
        self.assertEqual(len(partial), 1)
        self.assertEqual(partial[0]["severity"], "SKIPPED")
        self.assertIn("截断", partial[0]["detail"])
        self.assertEqual(partial[0]["evidence"]["truncated"], 2)

    def test_partial_read_failures_add_skipped_note(self) -> None:
        stats = dict(self._OK_STATS, denied=2, errors=1)
        with (
            mock.patch.object(m, "_iter_tree_node_paths", return_value=(["A"], stats, None)),
            mock.patch.object(m, "_read_node_values", return_value=({}, "拒绝访问")),
        ):
            findings = m.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "TASK_HIDDEN_PARTIAL")


@unittest.skipUnless(sys.platform == "win32", "仅 Windows 支持 winreg")
class TestRealScanSmoke(unittest.TestCase):
    """真实环境冒烟：不假设是否管理员，只要求"不崩、结构合法、权限不足必须 SKIPPED"。"""

    def test_scan_never_raises_and_findings_are_well_formed(self) -> None:
        findings = m.scan()
        self.assertIsInstance(findings, list)
        for finding in findings:
            self.assertEqual(set(finding), _FINDING_KEYS)
            self.assertIn(finding["severity"], SEVERITIES)
            self.assertIsInstance(finding["evidence"], dict)
            self.assertTrue(str(finding["rule_id"]).startswith("TASK_HIDDEN_"))

        from core import utils

        if not utils.is_admin():
            rule_ids = [finding["rule_id"] for finding in findings]
            self.assertIn("TASK_HIDDEN_ACCESS_DENIED", rule_ids)
            self.assertNotIn("HIGH", [finding["severity"] for finding in findings])


if __name__ == "__main__":
    unittest.main(verbosity=2)
