# -*- coding: utf-8 -*-
"""非 C2 场景 baseline diff/annotate 输出字节级快照（V1.5 rc2 任务 P1）。

fixture 由 rc1 行为生成并人工 review：不包含 ``recent_system_update`` /
``benign_update`` 等 V1.5 C2 键，证明非 C2 路径输出未漂移。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_baseline_snapshot.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import baseline  # noqa: E402

FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "baseline_non_c2_snapshot.json"


def _finding(rule: str, target: str, severity: str, **evidence: object) -> dict:
    return {
        "severity": severity,
        "rule_id": rule,
        "target": target,
        "detail": f"detail-{rule}",
        "evidence": dict(evidence),
    }


def _reports() -> tuple[dict, dict]:
    baseline_report = {
        "tool": "TamperScan",
        "version": "1.5.0",
        "generated_at": "2026-11-11T00:00:00+00:00",
        "findings": [
            _finding("R_MOD", r"C:\Test\modified.exe", "MEDIUM", actual="v1"),
            _finding("R_RES", r"C:\Test\resolved.exe", "HIGH"),
            _finding("R_SAME", r"C:\Test\same.exe", "LOW", actual="same"),
            _finding("R_ESC", r"C:\Test\esc.exe", "LOW"),
            _finding("R_DOWN", r"C:\Test\down.exe", "HIGH"),
        ],
    }
    current_report = {
        "tool": "TamperScan",
        "version": "1.5.0",
        "generated_at": "2026-11-11T01:00:00+00:00",
        "findings": [
            _finding("R_MOD", r"C:\Test\modified.exe", "MEDIUM", actual="v2"),
            _finding("R_SAME", r"C:\Test\same.exe", "LOW", actual="same"),
            _finding("R_ESC", r"C:\Test\esc.exe", "HIGH"),
            _finding("R_DOWN", r"C:\Test\down.exe", "LOW"),
            _finding("R_NEW", r"C:\Test\new.exe", "MEDIUM"),
        ],
    }
    return baseline_report, current_report


def test_non_c2_annotated_output_matches_fixture_byte_for_byte() -> None:
    assert FIXTURE.is_file(), "缺少 tests/fixtures/baseline_non_c2_snapshot.json"
    baseline_report, current_report = _reports()
    diff = baseline.diff_reports(baseline_report, current_report)
    annotated = baseline.annotate_findings(current_report["findings"], diff)
    rendered = json.dumps(annotated, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    assert rendered == FIXTURE.read_text(encoding="utf-8")


def test_non_c2_fixture_contains_no_c2_keys() -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    assert "recent_system_update" not in text
    assert "benign_update" not in text
    assert "version_bump" not in text
