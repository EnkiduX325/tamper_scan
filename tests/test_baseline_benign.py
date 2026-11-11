# -*- coding: utf-8 -*-
"""``core/baseline.py`` V1.4 良性版本前进豁免（BENIGN_UPDATE）测试。

覆盖：
- DiffEntry 新字段默认值 / to_dict；DIFF_STATUSES 七状态；
- 签名者一致 + FileVersion 前进：flag 关 -> MODIFIED + MEDIUM；flag 开 -> BENIGN_UPDATE 且不强制 HIGH；
- TimeDateStamp 前进、FileVersion 相同+时间戳前进、版本相同/倒退/缺失 -> MODIFIED HIGH；
- 签名者不同/为空、版本字段类型异常 -> MODIFIED HIGH（不抛异常）；
- 签名无效时不触发哈希篡改分支；SHA 相同 -> UNCHANGED；
- BENIGN_UPDATE 计数（七状态）；
- annotate：BENIGN_UPDATE 静默（不写篡改 detail、不强制 HIGH），MODIFIED 版本前进降 MEDIUM 并追加说明；
- 不修改入参；旧 V1.3 hash tamper 行为回归。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_baseline_benign.py
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import baseline  # noqa: E402

TARGET = r"C:\Program Files\Vendor\app.dll"
BASE_SHA = "a" * 64
CUR_SHA = "b" * 64
BASE_FV = "1.2.3.4"
CUR_FV = "1.2.3.5"
BASE_TS = 1700000000
CUR_TS = 1700000100


def _finding(
    rule_id: str = "SIG_UNSIGNED",
    target: str = TARGET,
    severity: str = "MEDIUM",
    *,
    signer: Any = "Contoso Ltd",
    status: str = "valid",
    sha256: str | None = BASE_SHA,
    file_version: Any = None,
    timestamp: Any = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {"signature": {"status": status, "signer": signer}}
    if sha256 is not None:
        evidence["sha256"] = sha256
    pe: dict[str, Any] = {}
    if file_version is not None:
        pe["FileVersion"] = file_version
    if timestamp is not None:
        pe["TimeDateStamp"] = timestamp
    if pe:
        evidence["pe"] = pe
    return {
        "severity": severity,
        "rule_id": rule_id,
        "target": target,
        "detail": "原始描述",
        "evidence": evidence,
    }


def _report(*findings: dict[str, Any]) -> dict[str, Any]:
    return {"tool": "TamperScan", "version": "1.5.0", "findings": list(findings)}


def _diff(
    baseline_finding: dict[str, Any],
    current_finding: dict[str, Any],
    *,
    treat: bool = False,
) -> tuple[baseline.BaselineDiff, dict[str, Any], dict[str, Any]]:
    baseline_report = _report(baseline_finding)
    current_report = _report(current_finding)
    diff = baseline.diff_reports(
        baseline_report,
        current_report,
        treat_version_bump_as_benign=treat,
    )
    return diff, baseline_report, current_report


def _bump_pair(**overrides: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    base_kwargs: dict[str, Any] = {
        "sha256": BASE_SHA,
        "file_version": BASE_FV,
        "signer": "Contoso Ltd",
    }
    cur_kwargs: dict[str, Any] = {
        "sha256": CUR_SHA,
        "file_version": CUR_FV,
        "signer": "Contoso Ltd",
    }
    base_kwargs.update(overrides.get("baseline", {}))
    cur_kwargs.update(overrides.get("current", {}))
    return _finding(**base_kwargs), _finding(**cur_kwargs)


class TestDiffEntryDefaults(unittest.TestCase):
    def test_new_fields_defaults_and_to_dict(self) -> None:
        entry = baseline.DiffEntry(target="x", rule_base="R", status=baseline.DIFF_UNCHANGED)
        self.assertFalse(entry.version_bump)
        self.assertFalse(entry.benign_update)
        self.assertIsNone(entry.baseline_version)
        self.assertIsNone(entry.current_version)
        payload = entry.to_dict()
        self.assertFalse(payload["version_bump"])
        self.assertFalse(payload["benign_update"])
        self.assertIn("baseline_version", payload)
        self.assertIn("current_version", payload)
        json.dumps(payload)

    def test_seven_statuses(self) -> None:
        self.assertEqual(len(baseline.DIFF_STATUSES), 7)
        self.assertIn("BENIGN_UPDATE", baseline.DIFF_STATUSES)
        self.assertEqual(baseline.DIFF_BENIGN_UPDATE, "BENIGN_UPDATE")
        self.assertNotIn(baseline.DIFF_BENIGN_UPDATE, baseline.CHANGED_STATUSES)


class TestFileVersionBump(unittest.TestCase):
    def test_flag_off_is_modified_medium(self) -> None:
        baseline_finding, current_finding = _bump_pair()
        diff, _, _ = _diff(baseline_finding, current_finding, treat=False)
        entry = diff.entries[0]
        self.assertTrue(entry.hash_tamper)
        self.assertEqual(entry.status, baseline.DIFF_MODIFIED)
        self.assertEqual(entry.current_severity, "MEDIUM")
        self.assertTrue(entry.version_bump)
        self.assertFalse(entry.benign_update)
        self.assertEqual(entry.baseline_version, (1, 2, 3, 4))
        self.assertEqual(entry.current_version, (1, 2, 3, 5))

    def test_flag_on_is_benign_update(self) -> None:
        baseline_finding, current_finding = _bump_pair()
        diff, _, _ = _diff(baseline_finding, current_finding, treat=True)
        entry = diff.entries[0]
        self.assertEqual(entry.status, baseline.DIFF_BENIGN_UPDATE)
        self.assertTrue(entry.benign_update)
        self.assertTrue(entry.version_bump)
        self.assertTrue(entry.hash_tamper)
        # 不强制 HIGH：current_severity 保持当前 Finding 的 MEDIUM
        self.assertEqual(entry.current_severity, "MEDIUM")

    def test_version_fields_accept_comma_and_list(self) -> None:
        baseline_finding, current_finding = _bump_pair()
        baseline_finding["evidence"]["pe"]["FileVersion"] = "1,2,3,4"
        current_finding["evidence"]["pe"]["FileVersion"] = [1, 2, 3, 5]
        diff, _, _ = _diff(baseline_finding, current_finding)
        self.assertTrue(diff.entries[0].version_bump)

    def test_padded_version_comparison(self) -> None:
        baseline_finding, current_finding = _bump_pair()
        baseline_finding["evidence"]["pe"]["FileVersion"] = "1.2"
        current_finding["evidence"]["pe"]["FileVersion"] = "1.2.0.1"
        diff, _, _ = _diff(baseline_finding, current_finding)
        self.assertTrue(diff.entries[0].version_bump)


class TestTimeStampBump(unittest.TestCase):
    def test_timestamp_forward_without_file_version(self) -> None:
        baseline_finding = _finding(sha256=BASE_SHA, timestamp=BASE_TS)
        current_finding = _finding(sha256=CUR_SHA, timestamp=CUR_TS)
        diff, _, _ = _diff(baseline_finding, current_finding, treat=False)
        entry = diff.entries[0]
        self.assertTrue(entry.version_bump)
        self.assertEqual(entry.status, baseline.DIFF_MODIFIED)
        self.assertEqual(entry.current_severity, "MEDIUM")
        self.assertEqual(entry.baseline_version, BASE_TS)
        self.assertEqual(entry.current_version, CUR_TS)
        benign, _, _ = _diff(baseline_finding, current_finding, treat=True)
        self.assertEqual(benign.entries[0].status, baseline.DIFF_BENIGN_UPDATE)

    def test_equal_file_version_but_newer_timestamp_is_bump(self) -> None:
        baseline_finding = _finding(sha256=BASE_SHA, file_version=BASE_FV, timestamp=BASE_TS)
        current_finding = _finding(sha256=CUR_SHA, file_version=BASE_FV, timestamp=CUR_TS)
        diff, _, _ = _diff(baseline_finding, current_finding, treat=True)
        entry = diff.entries[0]
        self.assertTrue(entry.version_bump)
        self.assertEqual(entry.status, baseline.DIFF_BENIGN_UPDATE)
        self.assertEqual(entry.baseline_version, BASE_TS)
        self.assertEqual(entry.current_version, CUR_TS)


class TestNoVersionBump(unittest.TestCase):
    def test_same_version_stays_modified_high(self) -> None:
        baseline_finding, current_finding = _bump_pair()
        current_finding["evidence"]["pe"]["FileVersion"] = BASE_FV
        diff, _, _ = _diff(baseline_finding, current_finding)
        entry = diff.entries[0]
        self.assertFalse(entry.version_bump)
        self.assertEqual(entry.status, baseline.DIFF_MODIFIED)
        self.assertEqual(entry.current_severity, "HIGH")

    def test_backward_version_stays_modified_high(self) -> None:
        baseline_finding = _finding(sha256=BASE_SHA, file_version="2.0.0.0")
        current_finding = _finding(sha256=CUR_SHA, file_version="1.9.9.9")
        diff, _, _ = _diff(baseline_finding, current_finding, treat=True)
        entry = diff.entries[0]
        self.assertFalse(entry.version_bump)
        self.assertFalse(entry.benign_update)
        self.assertEqual(entry.status, baseline.DIFF_MODIFIED)
        self.assertEqual(entry.current_severity, "HIGH")
        self.assertIsNone(entry.baseline_version)

    def test_missing_version_info_stays_modified_high(self) -> None:
        baseline_finding = _finding(sha256=BASE_SHA)
        current_finding = _finding(sha256=CUR_SHA)
        diff, _, _ = _diff(baseline_finding, current_finding, treat=True)
        entry = diff.entries[0]
        self.assertFalse(entry.version_bump)
        self.assertEqual(entry.status, baseline.DIFF_MODIFIED)
        self.assertEqual(entry.current_severity, "HIGH")

    def test_invalid_version_types_do_not_raise(self) -> None:
        for bad_base, bad_cur in (("abc", "abd"), ("1.x.3", "1.x.4"), (object(), object())):
            baseline_finding = _finding(sha256=BASE_SHA, file_version=bad_base)
            current_finding = _finding(sha256=CUR_SHA, file_version=bad_cur)
            diff, _, _ = _diff(baseline_finding, current_finding)
            entry = diff.entries[0]
            self.assertFalse(entry.version_bump, bad_base)
            self.assertEqual(entry.current_severity, "HIGH", bad_base)


class TestSignerChecks(unittest.TestCase):
    def test_different_signer_stays_modified_high(self) -> None:
        baseline_finding, current_finding = _bump_pair()
        current_finding["evidence"]["signature"]["signer"] = "Evil Corp"
        diff, _, _ = _diff(baseline_finding, current_finding, treat=True)
        entry = diff.entries[0]
        self.assertFalse(entry.version_bump)
        self.assertEqual(entry.status, baseline.DIFF_MODIFIED)
        self.assertEqual(entry.current_severity, "HIGH")

    def test_empty_signer_stays_modified_high(self) -> None:
        for value in (None, ""):
            baseline_finding = _finding(sha256=BASE_SHA, file_version=BASE_FV, signer=value)
            current_finding = _finding(sha256=CUR_SHA, file_version=CUR_FV, signer=value)
            diff, _, _ = _diff(baseline_finding, current_finding, treat=True)
            entry = diff.entries[0]
            self.assertFalse(entry.version_bump)
            self.assertEqual(entry.current_severity, "HIGH")

    def test_signer_comparison_is_case_insensitive(self) -> None:
        baseline_finding = _finding(sha256=BASE_SHA, file_version=BASE_FV, signer="Contoso Ltd")
        current_finding = _finding(sha256=CUR_SHA, file_version=CUR_FV, signer="CONTOSO LTD")
        diff, _, _ = _diff(baseline_finding, current_finding, treat=True)
        self.assertEqual(diff.entries[0].status, baseline.DIFF_BENIGN_UPDATE)


class TestNonTamperCases(unittest.TestCase):
    def test_same_hash_is_unchanged(self) -> None:
        baseline_finding, current_finding = _bump_pair()
        current_finding["evidence"]["sha256"] = BASE_SHA
        diff, _, _ = _diff(baseline_finding, current_finding, treat=True)
        entry = diff.entries[0]
        self.assertFalse(entry.hash_tamper)
        self.assertEqual(entry.status, baseline.DIFF_UNCHANGED)

    def test_invalid_signature_does_not_trigger_benign(self) -> None:
        for status in ("unsigned", "invalid", "missing"):
            baseline_finding = _finding(sha256=BASE_SHA, file_version=BASE_FV, status=status)
            current_finding = _finding(sha256=CUR_SHA, file_version=CUR_FV, status=status)
            diff, _, _ = _diff(baseline_finding, current_finding, treat=True)
            entry = diff.entries[0]
            self.assertFalse(entry.hash_tamper, status)
            self.assertNotEqual(entry.status, baseline.DIFF_BENIGN_UPDATE, status)

    def test_counts_include_benign_update(self) -> None:
        baseline_finding, current_finding = _bump_pair()
        diff, _, _ = _diff(baseline_finding, current_finding, treat=True)
        self.assertEqual(diff.counts["BENIGN_UPDATE"], 1)
        self.assertEqual(set(diff.counts), set(baseline.DIFF_STATUSES))
        counts = baseline.diff_counts(diff)
        self.assertEqual(len(counts), 7)
        self.assertEqual(counts["BENIGN_UPDATE"], 1)
        self.assertEqual(sum(counts.values()), diff.total)

    def test_flag_does_not_change_new_or_resolved(self) -> None:
        diff = baseline.diff_reports(
            _report(_finding(rule_id="A", target=r"C:\gone.exe", severity="LOW")),
            _report(_finding(rule_id="B", target=r"C:\new.exe", severity="LOW")),
            treat_version_bump_as_benign=True,
        )
        self.assertEqual(diff.counts["NEW"], 1)
        self.assertEqual(diff.counts["RESOLVED"], 1)
        self.assertFalse(baseline.has_new_high_medium(diff))


class TestAnnotateBenign(unittest.TestCase):
    def test_benign_update_is_silent(self) -> None:
        baseline_finding, current_finding = _bump_pair()
        diff, _, current_report = _diff(baseline_finding, current_finding, treat=True)
        annotated = baseline.annotate_findings(current_report["findings"], diff)
        item = annotated[0]
        self.assertEqual(item["diff_status"], baseline.DIFF_BENIGN_UPDATE)
        self.assertEqual(item["severity"], "MEDIUM")
        self.assertNotIn("疑似被篡改", item["detail"])
        self.assertNotIn("签名有效但文件哈希改变", item["detail"])
        evidence = item["evidence"]
        self.assertTrue(evidence["benign_update"])
        self.assertTrue(evidence["version_bump"])
        self.assertEqual(evidence["baseline_version"], (1, 2, 3, 4))
        self.assertEqual(evidence["current_version"], (1, 2, 3, 5))
        self.assertIn("normalized_key", item)

    def test_flag_off_bump_downgraded_to_medium_with_note(self) -> None:
        baseline_finding, current_finding = _bump_pair()
        diff, _, current_report = _diff(baseline_finding, current_finding, treat=False)
        annotated = baseline.annotate_findings(current_report["findings"], diff)
        item = annotated[0]
        self.assertEqual(item["diff_status"], baseline.DIFF_MODIFIED)
        self.assertEqual(item["severity"], "MEDIUM")
        self.assertIn("版本正常前进（自动更新），已降级为 MEDIUM", item["detail"])
        self.assertNotIn("疑似被篡改", item["detail"])
        evidence = item["evidence"]
        self.assertTrue(evidence["version_bump"])
        self.assertEqual(evidence["baseline_version"], (1, 2, 3, 4))
        self.assertEqual(evidence["current_version"], (1, 2, 3, 5))

    def test_old_hash_tamper_regression(self) -> None:
        """V1.3 行为回归：无签名者/无版本信息 -> MODIFIED HIGH + 篡改提示。"""
        baseline_finding = _finding(sha256=BASE_SHA, signer=None)
        current_finding = _finding(sha256=CUR_SHA, signer=None)
        diff, _, current_report = _diff(baseline_finding, current_finding, treat=True)
        entry = diff.entries[0]
        self.assertTrue(entry.hash_tamper)
        self.assertFalse(entry.version_bump)
        self.assertEqual(entry.status, baseline.DIFF_MODIFIED)
        self.assertEqual(entry.current_severity, "HIGH")
        annotated = baseline.annotate_findings(current_report["findings"], diff)
        self.assertEqual(annotated[0]["severity"], "HIGH")
        self.assertIn("签名有效但文件哈希改变，高度疑似被篡改", annotated[0]["detail"])

    def test_annotate_does_not_mutate_input(self) -> None:
        baseline_finding, current_finding = _bump_pair()
        diff, _, current_report = _diff(baseline_finding, current_finding, treat=True)
        snapshot = json.dumps(current_finding, sort_keys=True, default=str)
        baseline.annotate_findings(current_report["findings"], diff)
        self.assertEqual(json.dumps(current_finding, sort_keys=True, default=str), snapshot)

    def test_benign_annotate_with_high_input_keeps_severity_untouched(self) -> None:
        """BENIGN_UPDATE 不额外强改 severity（原扫描等级原样保留，diff 状态负责静默）。"""
        baseline_finding, current_finding = _bump_pair()
        current_finding["severity"] = "HIGH"
        diff, _, current_report = _diff(baseline_finding, current_finding, treat=True)
        annotated = baseline.annotate_findings(current_report["findings"], diff)
        self.assertEqual(annotated[0]["diff_status"], baseline.DIFF_BENIGN_UPDATE)
        self.assertNotIn("疑似被篡改", annotated[0]["detail"])

    def test_annotate_without_diff_has_no_version_keys(self) -> None:
        finding = _finding()
        annotated = baseline.annotate_findings([finding], None)
        self.assertNotIn("benign_update", annotated[0]["evidence"])
        self.assertNotIn("version_bump", annotated[0]["evidence"])
        self.assertNotIn("normalized_key", annotated[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
