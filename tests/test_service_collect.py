# -*- coding: utf-8 -*-
"""``modules/service.py`` 采集复用层测试（模块 4 依赖的 collect_services / 规范化）。

覆盖：
- ``collect_services`` 的"强制刷新"与"短时缓存复用"语义（unquoted_service_path 靠它复用采集结果）；
- 采集错误不进入可复用缓存（下次仍会重新采集）；
- ``normalize_service_records`` 对 dict / list / 异常结构的处理；
- ``service.scan()`` 仍保持原有降级行为。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_service_collect.py
    python -m unittest discover -s tests -p "test_*.py" -v
    python tests\\test_service_collect.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules import service  # noqa: E402


class TestNormalizeServiceRecords(unittest.TestCase):
    def test_single_dict_becomes_list(self) -> None:
        records, error = service.normalize_service_records({"Name": "A"})
        self.assertIsNone(error)
        self.assertEqual(records, [{"Name": "A"}])

    def test_list_filters_non_dict_items(self) -> None:
        records, error = service.normalize_service_records([{"Name": "A"}, None, "junk", 3])
        self.assertIsNone(error)
        self.assertEqual(records, [{"Name": "A"}])

    def test_invalid_structure_returns_error(self) -> None:
        for value in ("text", 42, None):
            records, error = service.normalize_service_records(value)
            self.assertIsNone(records, value)
            self.assertIsNotNone(error, value)
            self.assertIn("结构异常", error or "")


class TestCollectServices(unittest.TestCase):
    def setUp(self) -> None:
        service.clear_service_cache()

    def tearDown(self) -> None:
        service.clear_service_cache()

    def test_force_refresh_calls_powershell_every_time(self) -> None:
        with mock.patch.object(service.utils, "run_powershell_json", return_value=([{"Name": "A"}], None)) as mocked:
            first = service.collect_services()
            second = service.collect_services()
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(first, ([{"Name": "A"}], None))
        self.assertEqual(second, ([{"Name": "A"}], None))

    def test_short_ttl_reuses_cache(self) -> None:
        with mock.patch.object(service.utils, "run_powershell_json", return_value=([{"Name": "A"}], None)) as mocked:
            service.collect_services()  # service.scan() 会先采集并写入缓存
            data, error = service.collect_services(max_age_seconds=180)
        self.assertEqual(mocked.call_count, 1)
        self.assertIsNone(error)
        self.assertEqual(data, [{"Name": "A"}])

    def test_expired_cache_recollects(self) -> None:
        timestamps = [100.0, 101.0, 500.0, 501.0]  # now, cache-update, now(过期), cache-update
        with (
            mock.patch.object(service.utils, "run_powershell_json", return_value=([{"Name": "A"}], None)) as mocked,
            mock.patch.object(service.time, "monotonic", side_effect=timestamps),
        ):
            service.collect_services()
            data, _error = service.collect_services(max_age_seconds=180)
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(data, [{"Name": "A"}])

    def test_errors_are_not_reused_and_are_reported(self) -> None:
        with mock.patch.object(
            service.utils, "run_powershell_json", return_value=(None, "PowerShell 执行超时")
        ) as mocked:
            service.collect_services()
            data, error = service.collect_services(max_age_seconds=180)
        self.assertEqual(mocked.call_count, 2)
        self.assertIsNone(data)
        self.assertEqual(error, "PowerShell 执行超时")

    def test_clear_cache_forces_recollection(self) -> None:
        with mock.patch.object(service.utils, "run_powershell_json", return_value=([{"Name": "A"}], None)) as mocked:
            service.collect_services()
            service.clear_service_cache()
            service.collect_services(max_age_seconds=180)
        self.assertEqual(mocked.call_count, 2)


class TestServiceScanRegression(unittest.TestCase):
    """重构后 service.scan() 行为不变：成功返回分析结果，失败降级 SKIPPED。"""

    def setUp(self) -> None:
        service.clear_service_cache()

    def tearDown(self) -> None:
        service.clear_service_cache()

    def test_scan_uses_collect_services_and_normalizes(self) -> None:
        with (
            mock.patch.object(service, "collect_services", return_value=({"Name": "A"}, None)) as mocked,
            mock.patch.object(service, "_analyze_service", return_value=[]) as analyzer,
        ):
            self.assertEqual(service.scan(), [])
        mocked.assert_called_once()
        analyzer.assert_called_once_with({"Name": "A"})

    def test_scan_collection_error_is_skipped(self) -> None:
        with mock.patch.object(service, "collect_services", return_value=(None, "采集失败")):
            findings = service.scan()
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "SERVICE_SKIPPED")
        self.assertIn("采集失败", findings[0]["detail"])

    def test_scan_parse_error_is_skipped(self) -> None:
        with mock.patch.object(service, "collect_services", return_value=("bad-structure", None)):
            findings = service.scan()
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "SERVICE_PARSE_ERROR")


if __name__ == "__main__":
    unittest.main(verbosity=2)
