# -*- coding: utf-8 -*-
"""``core/baseline.py`` 基线对比（Baseline Diff）引擎测试（V1.3）。

覆盖：
- 6 种 diff_status（NEW / RESOLVED / ESCALATED / DOWNGRADED / MODIFIED / UNCHANGED）；
- fingerprint 稳定性（忽略 timestamp/pid）与 actual 变化触发 MODIFIED；
- merged_rules / 采集层前缀剥离，避免规则合并导致误判 NEW；
- 文件 SHA256 增强与"签名有效但哈希改变"的强制 MODIFIED + HIGH；
- 防御性解析（缺字段、非法基线、版本/主机不一致 WARNING）；
- annotate_findings 挂载 diff_status 与 RESOLVED 追加。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_baseline.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import baseline  # noqa: E402


def _finding(
    rule_id: str,
    target: str,
    severity: str,
    detail: str = "",
    **evidence: object,
) -> dict:
    return {
        "severity": severity,
        "rule_id": rule_id,
        "target": target,
        "detail": detail,
        "evidence": dict(evidence),
    }


def _report(findings: list[dict], version: str = "1.3.0", host: str = "TEST-PC") -> dict:
    return {
        "tool": "TamperScan",
        "version": version,
        "generated_at": "2026-11-11T00:00:00+00:00",
        "host": {"name": host, "os": "Windows", "is_admin": True, "user": "User"},
        "findings": findings,
    }


class TestRuleBases(unittest.TestCase):
    def test_strips_collection_prefixes(self) -> None:
        self.assertEqual(baseline.rule_bases(_finding("AUTORUNS_SIG_UNSIGNED", "x", "HIGH")), ["SIG_UNSIGNED"])
        self.assertEqual(baseline.rule_bases(_finding("SVC_SERVICEDLL_TAMPER", "x", "HIGH")), ["SERVICEDLL_TAMPER"])
        self.assertEqual(baseline.rule_bases(_finding("RDP_SERVICEDLL_TAMPER", "x", "HIGH")), ["SERVICEDLL_TAMPER"])

    def test_merged_rules_added_and_deduped(self) -> None:
        finding = _finding(
            "SVC_SERVICEDLL_TAMPER",
            "x",
            "HIGH",
            merged_rules=["RDP_SERVICEDLL_TAMPER", "SVC_SERVICEDLL_TAMPER", "SIG_UNSIGNED"],
        )
        self.assertEqual(
            baseline.rule_bases(finding),
            ["SERVICEDLL_TAMPER", "SIG_UNSIGNED"],
        )

    def test_empty_rule_id_falls_back_to_empty_base(self) -> None:
        self.assertEqual(baseline.rule_bases(_finding("", "x", "LOW")), [""])
        self.assertEqual(baseline.rule_bases({}), [""])


class TestTargetKey(unittest.TestCase):
    def test_case_insensitive_and_stripped(self) -> None:
        self.assertEqual(baseline.target_key("  C:\\Windows\\A.EXE "), "c:\\windows\\a.exe")
        self.assertEqual(baseline.target_key(None), "")


class TestFingerprint(unittest.TestCase):
    def test_extracts_whitelisted_fields(self) -> None:
        evidence = {
            "signature": {"status": "valid", "signer": "Microsoft Windows", "via": "embedded"},
            "pe": {"CompanyName": "Microsoft Corporation", "FileVersion": "1.0"},
            "actual": "explorer.exe",
            "service": {"path_name": "C:\\Windows\\System32\\svchost.exe"},
            "task": {"sd_present": True, "index": 0},
            "irrelevant": "ignored",
        }
        fields = baseline.extract_fingerprint_fields(evidence)
        self.assertEqual(fields["signature.status"], "valid")
        self.assertEqual(fields["signature.signer"], "Microsoft Windows")
        self.assertEqual(fields["pe.CompanyName"], "Microsoft Corporation")
        self.assertEqual(fields["actual"], "explorer.exe")
        self.assertEqual(fields["service.path_name"], "C:\\Windows\\System32\\svchost.exe")
        self.assertIs(fields["task.sd_present"], True)
        self.assertEqual(fields["task.index"], 0)
        self.assertNotIn("irrelevant", fields)

    def test_flat_evidence_fallback(self) -> None:
        fields = baseline.extract_fingerprint_fields({"path_name": "C:\\a.dll", "sd_present": False})
        self.assertEqual(fields["service.path_name"], "C:\\a.dll")
        self.assertIs(fields["task.sd_present"], False)

    def test_missing_or_invalid_evidence_never_raises(self) -> None:
        self.assertEqual(baseline.extract_fingerprint_fields(None), {})
        self.assertEqual(baseline.extract_fingerprint_fields("junk"), {})
        self.assertEqual(baseline.extract_fingerprint_fields({"signature": "not-a-dict"}), {})

    def test_volatile_fields_are_stripped(self) -> None:
        base = {"actual": "cmd", "signature": {"status": "unsigned"}}
        noisy = {
            "actual": "cmd",
            "signature": {"status": "unsigned"},
            "timestamp": "2026-11-11T00:00:00",
            "pid": 4242,
        }
        self.assertEqual(baseline.compute_fingerprint(base), baseline.compute_fingerprint(noisy))

    def test_actual_change_changes_fingerprint(self) -> None:
        first = baseline.compute_fingerprint({"actual": "explorer.exe"})
        second = baseline.compute_fingerprint({"actual": "evil.exe"})
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), 64)


class TestFileHash(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "sample.bin"
        self.path.write_bytes(b"tamper-scan-v1.3")

    def test_compute_file_sha256(self) -> None:
        import hashlib

        expected = hashlib.sha256(b"tamper-scan-v1.3").hexdigest()
        self.assertEqual(baseline.compute_file_sha256(str(self.path)), expected)

    def test_compute_file_sha256_missing_and_directory(self) -> None:
        self.assertIsNone(baseline.compute_file_sha256(str(Path(self.tempdir.name) / "missing.bin")))
        self.assertIsNone(baseline.compute_file_sha256(self.tempdir.name))
        self.assertIsNone(baseline.compute_file_sha256(""))

    def test_enrich_only_high_medium_existing_files(self) -> None:
        findings = [
            _finding("R1", str(self.path), "HIGH"),
            _finding("R2", str(self.path), "MEDIUM"),
            _finding("R3", str(self.path), "LOW"),
            _finding("R4", "HKLM\\Software\\Run\\X", "HIGH"),
        ]
        enriched = baseline.enrich_findings_with_hashes(findings)
        self.assertIn("sha256", enriched[0]["evidence"])
        self.assertIn("sha256", enriched[1]["evidence"])
        self.assertNotIn("sha256", enriched[2]["evidence"])
        self.assertNotIn("sha256", enriched[3]["evidence"])
        # 不修改入参
        self.assertNotIn("sha256", findings[0]["evidence"])

    def test_enrich_custom_severities(self) -> None:
        findings = [_finding("R1", str(self.path), "LOW")]
        enriched = baseline.enrich_findings_with_hashes(findings, severities=("LOW",))
        self.assertIn("sha256", enriched[0]["evidence"])


class TestDiffStatuses(unittest.TestCase):
    def test_six_statuses_are_classified(self) -> None:
        baseline_report = _report(
            [
                _finding("AUTORUNS_SIG_UNSIGNED", "C:\\same.exe", "HIGH", signature={"status": "unsigned"}),
                _finding("RUN_REGISTRY", "HKLM\\Run\\X", "MEDIUM", actual="cmd /c evil"),
                _finding("SVC_SERVICEDLL_TAMPER", "C:\\b.dll", "LOW", signature={"status": "valid"}),
                _finding("TASK_INTERPRETER", "C:\\unchanged.exe", "LOW", actual="same"),
                _finding("RESOLVED_ONLY", "C:\\gone.exe", "MEDIUM"),
            ]
        )
        current_report = _report(
            [
                _finding("SIG_UNSIGNED", "C:\\same.exe", "HIGH", signature={"status": "unsigned"}),
                _finding("RUN_REGISTRY", "HKLM\\Run\\X", "HIGH", actual="cmd /c evil"),
                _finding("SVC_SERVICEDLL_TAMPER", "C:\\b.dll", "LOW", signature={"status": "valid", "signer": "X"}),
                _finding("TASK_INTERPRETER", "C:\\unchanged.exe", "LOW", actual="same"),
                _finding("NEW_ONLY", "C:\\new.exe", "MEDIUM"),
            ]
        )
        diff = baseline.diff_reports(baseline_report, current_report, baseline_path="base.json")
        status_by_rule = {entry.rule_base: entry.status for entry in diff.entries}
        self.assertEqual(status_by_rule["SIG_UNSIGNED"], baseline.DIFF_UNCHANGED)
        self.assertEqual(status_by_rule["REGISTRY"], baseline.DIFF_ESCALATED)
        self.assertEqual(status_by_rule["SERVICEDLL_TAMPER"], baseline.DIFF_MODIFIED)
        self.assertEqual(status_by_rule["INTERPRETER"], baseline.DIFF_UNCHANGED)
        self.assertEqual(status_by_rule["RESOLVED_ONLY"], baseline.DIFF_RESOLVED)
        self.assertEqual(status_by_rule["NEW_ONLY"], baseline.DIFF_NEW)
        self.assertEqual(diff.counts["NEW"], 1)
        self.assertEqual(diff.counts["MODIFIED"], 1)
        self.assertEqual(diff.counts["ESCALATED"], 1)
        self.assertEqual(diff.counts["DOWNGRADED"], 0)
        self.assertEqual(diff.counts["RESOLVED"], 1)
        self.assertEqual(diff.counts["UNCHANGED"], 2)
        self.assertEqual(set(diff.counts), set(baseline.DIFF_STATUSES))

    def test_downgraded(self) -> None:
        diff = baseline.diff_reports(
            _report([_finding("R", "C:\\x.exe", "HIGH")]),
            _report([_finding("R", "C:\\x.exe", "LOW")]),
        )
        self.assertEqual(diff.entries[0].status, baseline.DIFF_DOWNGRADED)

    def test_case_insensitive_target_matching(self) -> None:
        diff = baseline.diff_reports(
            _report([_finding("R", "C:\\Windows\\A.EXE", "LOW")]),
            _report([_finding("R", "c:\\windows\\a.exe", "LOW")]),
        )
        self.assertEqual(diff.entries[0].status, baseline.DIFF_UNCHANGED)

    def test_identical_finding_is_unchanged(self) -> None:
        finding = _finding("R", "C:\\x.exe", "LOW", signature={"status": "unsigned"})
        diff = baseline.diff_reports(_report([dict(finding)]), _report([dict(finding)]))
        self.assertEqual(diff.entries[0].status, baseline.DIFF_UNCHANGED)
        self.assertEqual(diff.counts["UNCHANGED"], 1)


class TestMergedRules(unittest.TestCase):
    def test_prefixed_rule_does_not_become_new(self) -> None:
        baseline_report = _report([_finding("AUTORUNS_SIG_UNSIGNED", "C:\\a.exe", "HIGH")])
        current_report = _report(
            [_finding("SIG_UNSIGNED", "C:\\a.exe", "HIGH", merged_rules=["AUTORUNS_SIG_UNSIGNED"])]
        )
        diff = baseline.diff_reports(baseline_report, current_report)
        self.assertEqual(diff.counts["NEW"], 0)
        self.assertEqual(diff.entries[0].status, baseline.DIFF_UNCHANGED)

    def test_merged_rules_match_across_base_names(self) -> None:
        baseline_report = _report(
            [
                _finding(
                    "SVC_SERVICEDLL_TAMPER",
                    "C:\\evil.dll",
                    "HIGH",
                    merged_rules=["SVC_SERVICEDLL_TAMPER", "RDP_SERVICEDLL_TAMPER"],
                )
            ]
        )
        current_report = _report([_finding("RDP_SERVICEDLL_TAMPER", "C:\\evil.dll", "HIGH")])
        diff = baseline.diff_reports(baseline_report, current_report)
        self.assertEqual(diff.counts["NEW"], 0)
        self.assertEqual(diff.counts["RESOLVED"], 0)
        self.assertEqual(diff.entries[0].status, baseline.DIFF_UNCHANGED)

    def test_same_target_different_rule_is_new(self) -> None:
        diff = baseline.diff_reports(
            _report([_finding("RUN_REGISTRY", "C:\\a.exe", "HIGH")]),
            _report([_finding("COM_HIJACK", "C:\\a.exe", "HIGH")]),
        )
        self.assertEqual(diff.counts["NEW"], 1)
        self.assertEqual(diff.counts["RESOLVED"], 1)


class TestHashTamper(unittest.TestCase):
    def test_signature_valid_but_hash_changed_forced_modified_high(self) -> None:
        baseline_report = _report(
            [_finding("R", "C:\\signed.dll", "MEDIUM", signature={"status": "valid"}, sha256="a" * 64)]
        )
        current_finding = _finding("R", "C:\\signed.dll", "MEDIUM", signature={"status": "valid"}, sha256="b" * 64)
        current_report = _report([current_finding])
        diff = baseline.diff_reports(baseline_report, current_report)
        entry = diff.entries[0]
        self.assertTrue(entry.hash_tamper)
        self.assertEqual(entry.status, baseline.DIFF_MODIFIED)
        annotated = baseline.annotate_findings(current_report["findings"], diff)
        self.assertEqual(annotated[0]["severity"], "HIGH")
        self.assertEqual(annotated[0]["diff_status"], baseline.DIFF_MODIFIED)
        self.assertIn("签名有效但文件哈希改变", annotated[0]["detail"])
        self.assertTrue(annotated[0]["evidence"]["hash_tamper"])
        self.assertEqual(annotated[0]["evidence"]["baseline_sha256"], "a" * 64)

    def test_hash_change_without_valid_signature_is_not_forced(self) -> None:
        for status in ("unsigned", "invalid", "missing"):
            baseline_report = _report(
                [_finding("R", "C:\\x.dll", "MEDIUM", signature={"status": status}, sha256="a" * 64)]
            )
            current_report = _report(
                [_finding("R", "C:\\x.dll", "MEDIUM", signature={"status": status}, sha256="b" * 64)]
            )
            diff = baseline.diff_reports(baseline_report, current_report)
            self.assertFalse(diff.entries[0].hash_tamper, status)
            self.assertEqual(diff.entries[0].status, baseline.DIFF_UNCHANGED, status)

    def test_same_hash_stays_unchanged(self) -> None:
        report = _report([_finding("R", "C:\\x.dll", "MEDIUM", signature={"status": "valid"}, sha256="a" * 64)])
        diff = baseline.diff_reports(report, _report([dict(report["findings"][0])]))
        self.assertEqual(diff.entries[0].status, baseline.DIFF_UNCHANGED)

    def test_end_to_end_hash_enrichment_detects_file_change(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "signed.dll"
            path.write_bytes(b"original-content")
            baseline_finding = _finding("R", str(path), "MEDIUM", signature={"status": "valid"})
            baseline_report = _report(baseline.enrich_findings_with_hashes([baseline_finding]))
            path.write_bytes(b"tampered-content")
            current_finding = _finding("R", str(path), "MEDIUM", signature={"status": "valid"})
            current_report = _report(baseline.enrich_findings_with_hashes([current_finding]))
            diff = baseline.diff_reports(baseline_report, current_report)
            self.assertIn("sha256", baseline_report["findings"][0]["evidence"])
            self.assertNotEqual(
                baseline_report["findings"][0]["evidence"]["sha256"],
                current_report["findings"][0]["evidence"]["sha256"],
            )
            self.assertTrue(diff.entries[0].hash_tamper)
            annotated = baseline.annotate_findings(current_report["findings"], diff)
            self.assertEqual(annotated[0]["severity"], "HIGH")


class TestAnnotateFindings(unittest.TestCase):
    def test_adds_diff_status_without_mutating_input(self) -> None:
        current_finding = _finding("R", "C:\\x.exe", "LOW")
        diff = baseline.diff_reports(_report([]), _report([dict(current_finding)]))
        annotated = baseline.annotate_findings([current_finding], diff)
        self.assertEqual(annotated[0]["diff_status"], baseline.DIFF_NEW)
        self.assertNotIn("diff_status", current_finding)

    def test_appends_resolved_baseline_finding(self) -> None:
        resolved = _finding("R", "C:\\gone.exe", "HIGH")
        diff = baseline.diff_reports(_report([dict(resolved)]), _report([]))
        annotated = baseline.annotate_findings([], diff)
        self.assertEqual(len(annotated), 1)
        self.assertEqual(annotated[0]["diff_status"], baseline.DIFF_RESOLVED)
        self.assertTrue(annotated[0]["evidence"]["resolved"])

    def test_no_diff_returns_copies(self) -> None:
        finding = _finding("R", "C:\\x.exe", "LOW")
        annotated = baseline.annotate_findings([finding], None)
        self.assertEqual(annotated[0], finding)
        self.assertIsNot(annotated[0], finding)


class TestFailOnNewHelper(unittest.TestCase):
    def test_new_high_or_medium(self) -> None:
        for severity in ("HIGH", "MEDIUM"):
            diff = baseline.diff_reports(_report([]), _report([_finding("R", "C:\\x.exe", severity)]))
            self.assertTrue(baseline.has_new_high_medium(diff), severity)

    def test_new_low_or_non_new_does_not_trigger(self) -> None:
        low = baseline.diff_reports(_report([]), _report([_finding("R", "C:\\x.exe", "LOW")]))
        self.assertFalse(baseline.has_new_high_medium(low))
        escalated = baseline.diff_reports(
            _report([_finding("R", "C:\\x.exe", "LOW")]),
            _report([_finding("R", "C:\\x.exe", "HIGH")]),
        )
        self.assertFalse(baseline.has_new_high_medium(escalated))
        self.assertFalse(baseline.has_new_high_medium(None))


class TestDefensiveParsing(unittest.TestCase):
    def test_invalid_baseline_treated_as_empty(self) -> None:
        current = _report([_finding("R", "C:\\x.exe", "MEDIUM")])
        diff = baseline.diff_reports(None, current)
        self.assertEqual(diff.counts["NEW"], 1)
        self.assertEqual(baseline.diff_reports("junk", current).counts["NEW"], 1)
        self.assertEqual(baseline.diff_reports({"findings": "bad"}, current).counts["NEW"], 1)

    def test_findings_with_missing_fields_do_not_crash(self) -> None:
        baseline_report = {"findings": [{"target": "C:\\a.exe", "severity": "HIGH"}]}
        current_report = {"findings": [{"target": "C:\\a.exe", "severity": "HIGH"}]}
        diff = baseline.diff_reports(baseline_report, current_report)
        self.assertEqual(diff.entries[0].status, baseline.DIFF_UNCHANGED)

    def test_validate_baseline_report(self) -> None:
        ok, reason = baseline.validate_baseline_report({"findings": []})
        self.assertTrue(ok)
        self.assertIsNone(reason)
        for value in (None, "junk", [], {"findings": "x"}):
            ok, reason = baseline.validate_baseline_report(value)
            self.assertFalse(ok, value)
            self.assertTrue(reason)

    def test_baseline_warnings(self) -> None:
        old = _report([], version="1.2.0", host="OLD-PC")
        current = _report([], version="1.3.0", host="NEW-PC")
        warnings = baseline.baseline_warnings(old, current, expected_version="1.3.0")
        self.assertEqual(len(warnings), 2)
        self.assertTrue(any("版本" in item for item in warnings))
        self.assertTrue(any("主机" in item for item in warnings))
        same_host = _report([], version="1.3.0", host="NEW-PC")
        self.assertEqual(baseline.baseline_warnings(same_host, current), [])
        same = baseline.diff_reports(same_host, current)
        self.assertEqual(same.baseline_meta["host"], "NEW-PC")

    def test_baseline_meta(self) -> None:
        report = _report([], version="1.2.0", host="PC-1")
        diff = baseline.diff_reports(report, _report([]), baseline_path="C:\\base.json")
        self.assertEqual(diff.baseline_meta["path"], "C:\\base.json")
        self.assertEqual(diff.baseline_meta["version"], "1.2.0")
        self.assertEqual(diff.baseline_meta["host"], "PC-1")
        self.assertEqual(diff.baseline_meta["generated_at"], report["generated_at"])

    def test_diff_entry_to_dict_serializable(self) -> None:
        diff = baseline.diff_reports(
            _report([_finding("R", "C:\\x.exe", "LOW")]),
            _report([_finding("R", "C:\\x.exe", "HIGH")]),
        )
        payload = diff.to_dict()
        json.dumps(payload, ensure_ascii=False)
        self.assertEqual(payload["entries"][0]["status"], baseline.DIFF_ESCALATED)
        self.assertEqual(payload["counts"]["ESCALATED"], 1)


if __name__ == "__main__":
    unittest.main()
