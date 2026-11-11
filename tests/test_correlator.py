# -*- coding: utf-8 -*-
"""``core/correlator.py`` 的单元测试（V1.4 攻击链关联引擎）。

覆盖：
1. ``load_chain_rules``：真实规则库、缺文件、坏 JSON、非 dict JSON、非法条目
   规范化、缓存与 ``clear_chain_cache()``、缓存隔离；
2. 图聚类：共享归一化 target（大小写/环境变量差异）、父子进程 ppid 连边、
   ppid 时间窗过滤、无关联不聚合、孤立 Finding 不成 campaign、SKIPPED/非法项忽略；
3. 固定剧本模板匹配：完整 -> high、2/3 -> medium、4 步模板命中 2 步 -> low、
   不足 2 步不成链、min_findings、同 Finding 不复用、tactic 步/wildcard；
4. 反模式抑制：require_all 语义、tactics / target_contains 条件、suppressed 字段；
5. 自由组合不成链（绝无自由组合）；stats/campaign 字段；空/异常输入；
6. 与真实 ``rules/attack_chain.json`` 集成：3 条对应规则成 high campaign，
   反模式命中后进入 suppressed。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_correlator.py
    python -m unittest discover -s tests -p "test_*.py" -v
    python tests\\test_correlator.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import correlator  # noqa: E402
from core.finding import make_finding  # noqa: E402

TARGET = r"C:\Users\Public\evil.exe"

_CAMPAIGN_FIELDS = {
    "chain_id",
    "name",
    "description",
    "confidence",
    "tactics",
    "steps",
    "finding_count",
    "targets",
    "suppressed",
    "suppressed_by",
    "shadow",
}
_STEP_FIELDS = {"tactic", "rule_ids", "findings"}
_STEP_FINDING_FIELDS = {"rule_id", "target", "severity"}

_DEFAULT_MAPPING = {
    "PERSIST_A": "TA0003",
    "DEFENSE_B": "TA0005",
    "CRED_C": "TA0006",
    "EXTRA_D": "TA0007",
    "OTHER_X": "TA0002",
}


# ---------------------------------------------------------------------------
# 构造工具
# ---------------------------------------------------------------------------


def _finding(
    rule_id: str,
    target: str = TARGET,
    severity: str = "HIGH",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return make_finding(severity, "TestCategory", target, "test detail", evidence or {}, rule_id)


def _step(rule_ids: list[str] | None = None, tactic: str = "", min_findings: int = 1) -> dict[str, Any]:
    return {"tactic": tactic, "rule_ids": list(rule_ids or []), "min_findings": min_findings}


def _template(
    template_id: str,
    steps: list[dict[str, Any]],
    *,
    max_gap_hours: float = 24,
    confidence: str = "high",
) -> dict[str, Any]:
    return {
        "id": template_id,
        "name": f"剧本 {template_id}",
        "description": f"描述 {template_id}",
        "confidence": confidence,
        "max_gap_hours": max_gap_hours,
        "steps": steps,
    }


def _rules(
    templates: list[dict[str, Any]] | None = None,
    anti_patterns: list[dict[str, Any]] | None = None,
    tactic_mapping: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "_comment": "test rules",
        "tactic_mapping": dict(_DEFAULT_MAPPING if tactic_mapping is None else tactic_mapping),
        "chain_templates": list(templates or []),
        "anti_patterns": list(anti_patterns or []),
    }


def _abc_template(template_id: str = "chain_abc", **kwargs: Any) -> dict[str, Any]:
    return _template(
        template_id,
        [
            _step(["PERSIST_A"], "TA0003"),
            _step(["DEFENSE_B"], "TA0005"),
            _step(["CRED_C"], "TA0006"),
        ],
        **kwargs,
    )


def _abcd_template(template_id: str = "chain_abcd", **kwargs: Any) -> dict[str, Any]:
    return _template(
        template_id,
        [
            _step(["PERSIST_A"], "TA0003"),
            _step(["DEFENSE_B"], "TA0005"),
            _step(["CRED_C"], "TA0006"),
            _step(["EXTRA_D"], "TA0007"),
        ],
        **kwargs,
    )


def _anti(
    pattern_id: str = "legit_pattern",
    *,
    rule_ids: list[str] | None = None,
    tactics: list[str] | None = None,
    require_all: bool = False,
    target_contains: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": pattern_id,
        "description": "合法多阶段组合",
        "match": {
            "rule_ids": list(rule_ids or []),
            "tactics": list(tactics or []),
            "require_all": require_all,
            "target_contains": list(target_contains or []),
        },
    }


class _Case(unittest.TestCase):
    """公共 setUp/tearDown：清空规则缓存，避免临时文件互相污染。"""

    def setUp(self) -> None:
        correlator.clear_chain_cache()

    def tearDown(self) -> None:
        correlator.clear_chain_cache()


# ---------------------------------------------------------------------------
# 规则库加载
# ---------------------------------------------------------------------------


class TestLoadChainRules(_Case):
    def test_real_rules_file_is_complete(self) -> None:
        rules = correlator.load_chain_rules()
        self.assertEqual(
            set(rules), {"_comment", "tactic_mapping", "chain_templates", "anti_patterns"}
        )
        self.assertGreaterEqual(len(rules["chain_templates"]), 3)
        self.assertGreaterEqual(len(rules["anti_patterns"]), 2)
        self.assertGreaterEqual(len(rules["tactic_mapping"]), 20)
        for template in rules["chain_templates"]:
            self.assertTrue(template["id"])
            self.assertGreaterEqual(len(template["steps"]), 2)
            self.assertGreater(template["max_gap_hours"], 0)
            for step in template["steps"]:
                self.assertTrue(step["tactic"] or step["rule_ids"])
                self.assertGreaterEqual(step["min_findings"], 1)
        for pattern in rules["anti_patterns"]:
            self.assertIn("match", pattern)
            self.assertIn("require_all", pattern["match"])

    def test_real_tactic_mapping_covers_common_rules(self) -> None:
        mapping = correlator.load_chain_rules()["tactic_mapping"]
        self.assertEqual(mapping.get("TASK_HIDDEN_TARRASK"), "TA0003")
        self.assertEqual(mapping.get("WFP_EDR_SILENCER"), "TA0005")
        self.assertEqual(mapping.get("RDP_SERVICEDLL_TAMPER"), "TA0003")
        self.assertEqual(mapping.get("NP_PROVIDER_TAMPER"), "TA0003")
        self.assertEqual(mapping.get("LSA_AUTH_PACKAGE_TAMPER"), "TA0003")
        self.assertEqual(mapping.get("WINLOGON_NOTIFY_TAMPER"), "TA0004")
        self.assertEqual(mapping.get("WINLOGON_SHELL_TAMPER"), "TA0003")
        self.assertEqual(mapping.get("SILENTPROCESS_EXIT_TAMPER"), "TA0003")
        self.assertEqual(mapping.get("CMD_AUTORUN"), "TA0003")
        self.assertEqual(mapping.get("SIG_"), "TA0005")

    def test_missing_file_returns_empty_skeleton(self) -> None:
        missing = os.path.join(tempfile.gettempdir(), "tamper_scan_no_such_attack_chain.json")
        rules = correlator.load_chain_rules(missing)
        self.assertEqual(rules["chain_templates"], [])
        self.assertEqual(rules["anti_patterns"], [])
        self.assertEqual(rules["tactic_mapping"], {})

    def test_corrupt_json_returns_empty_skeleton(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            handle.write('{"chain_templates": [broken')
            path = handle.name
        try:
            rules = correlator.load_chain_rules(path)
        finally:
            os.unlink(path)
        self.assertEqual(rules["chain_templates"], [])
        self.assertEqual(rules["anti_patterns"], [])

    def test_non_dict_json_returns_empty_skeleton(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            json.dump([1, 2, 3], handle)
            path = handle.name
        try:
            rules = correlator.load_chain_rules(path)
        finally:
            os.unlink(path)
        self.assertEqual(rules["chain_templates"], [])
        self.assertEqual(rules["tactic_mapping"], {})

    def test_invalid_entries_are_sanitized(self) -> None:
        payload = {
            "_comment": 123,
            "tactic_mapping": {"PERSIST_A": "TA0003", "": "X", "BAD": None, 5: "TA0005"},
            "chain_templates": [
                None,
                "junk",
                {},
                {"id": "only_one_step", "steps": [{"rule_ids": ["PERSIST_A"]}]},
                {"id": "no_steps", "steps": "bad"},
                {
                    "id": "valid_chain",
                    "steps": [
                        {"tactic": "TA0003"},
                        {"tactic": "TA0005", "min_findings": "bad"},
                    ],
                },
            ],
            "anti_patterns": [None, {}, {"id": "", "match": {"rule_ids": ["X"]}}, {"id": "p", "match": {}}],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            json.dump(payload, handle)
            path = handle.name
        try:
            rules = correlator.load_chain_rules(path)
        finally:
            os.unlink(path)
        self.assertEqual([template["id"] for template in rules["chain_templates"]], ["valid_chain"])
        self.assertEqual(rules["chain_templates"][0]["steps"][1]["min_findings"], 1)
        self.assertEqual(rules["anti_patterns"], [])
        self.assertEqual(rules["tactic_mapping"]["PERSIST_A"], "TA0003")
        self.assertIn("5", rules["tactic_mapping"])

    def test_cache_avoids_rereading_file(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            json.dump(_rules([_abc_template()]), handle)
            path = handle.name
        try:
            first = correlator.load_chain_rules(path)
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(_rules([_abc_template("changed")]), handle)
            second = correlator.load_chain_rules(path)
            self.assertEqual([item["id"] for item in second["chain_templates"]], ["chain_abc"])
            correlator.clear_chain_cache()
            third = correlator.load_chain_rules(path)
            self.assertEqual([item["id"] for item in third["chain_templates"]], ["changed"])
            self.assertEqual(first["chain_templates"], second["chain_templates"])
        finally:
            os.unlink(path)

    def test_cache_result_is_isolated_copy(self) -> None:
        rules = correlator.load_chain_rules()
        template_count = len(rules["chain_templates"])
        rules["chain_templates"].append({"id": "injected", "steps": []})
        reloaded = correlator.load_chain_rules()
        self.assertEqual(len(reloaded["chain_templates"]), template_count)


# ---------------------------------------------------------------------------
# target 归一化
# ---------------------------------------------------------------------------


class TestNormalizeTarget(_Case):
    def test_prefers_baseline_normalizer_when_available(self) -> None:
        with mock.patch.object(correlator, "_get_baseline_normalizer", return_value=lambda value: f"BASELINE:{value}"):
            self.assertEqual(correlator._normalize_target("X"), "baseline:x")

    def test_fallback_uses_utils_normalize_path(self) -> None:
        with (
            mock.patch.object(correlator, "_get_baseline_normalizer", return_value=None),
            mock.patch.dict(os.environ, {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows"}),
        ):
            normalized = correlator._normalize_target(r"%SystemRoot%\System32\EVIL.EXE")
        self.assertEqual(normalized, r"c:\windows\system32\evil.exe")

    def test_baseline_normalizer_exception_falls_back(self) -> None:
        def _boom(value: Any) -> str:
            raise RuntimeError("boom")

        with (
            mock.patch.object(correlator, "_get_baseline_normalizer", return_value=_boom),
            mock.patch.dict(os.environ, {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows"}),
        ):
            normalized = correlator._normalize_target(r"%SystemRoot%\System32\EVIL.EXE")
        self.assertEqual(normalized, r"c:\windows\system32\evil.exe")

    def test_empty_and_invalid_targets(self) -> None:
        with mock.patch.object(correlator, "_get_baseline_normalizer", return_value=None):
            self.assertEqual(correlator._normalize_target(""), "")
            self.assertEqual(correlator._normalize_target(None), "")


# ---------------------------------------------------------------------------
# 图聚类
# ---------------------------------------------------------------------------


class TestClustering(_Case):
    def test_shared_target_links_findings(self) -> None:
        rules = _rules([_abc_template()])
        result = correlator.correlate(
            [_finding("PERSIST_A"), _finding("DEFENSE_B"), _finding("CRED_C")], rules=rules
        )
        self.assertEqual(result["stats"]["clusters"], 1)
        self.assertEqual(len(result["campaigns"]), 1)
        self.assertEqual(result["campaigns"][0]["confidence"], "high")

    def test_target_normalization_links_case_and_env_variants(self) -> None:
        rules = _rules(
            [
                _template(
                    "normalized",
                    [_step(["PERSIST_A"], "TA0003"), _step(["DEFENSE_B"], "TA0005")],
                )
            ]
        )
        left = _finding("PERSIST_A", target=r"%SystemRoot%\System32\EVIL.EXE")
        right = _finding("DEFENSE_B", target=r"c:\windows\system32\evil.exe")
        with mock.patch.dict(os.environ, {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows"}):
            result = correlator.correlate([left, right], rules=rules)
        self.assertEqual(result["stats"]["clusters"], 1)
        self.assertEqual(len(result["campaigns"]), 1)

    def test_ppid_relation_links_findings(self) -> None:
        rules = _rules(
            [
                _template(
                    "ppid_chain",
                    [_step(["PERSIST_A"], "TA0003"), _step(["DEFENSE_B"], "TA0005")],
                )
            ]
        )
        parent = _finding("PERSIST_A", target=r"C:\a.exe", evidence={"pid": 4242})
        child = _finding("DEFENSE_B", target=r"C:\b.exe", evidence={"process": {"ppid": 4242}})
        result = correlator.correlate([parent, child], rules=rules)
        self.assertEqual(result["stats"]["clusters"], 1)
        self.assertEqual(len(result["campaigns"]), 1)

    def test_ppid_relation_outside_window_does_not_link(self) -> None:
        rules = _rules(
            [
                _template(
                    "ppid_chain",
                    [_step(["PERSIST_A"], "TA0003"), _step(["DEFENSE_B"], "TA0005")],
                )
            ]
        )
        parent = _finding(
            "PERSIST_A",
            target=r"C:\a.exe",
            evidence={"pid": 4242, "timestamp": "2026-01-01T00:00:00Z"},
        )
        child = _finding(
            "DEFENSE_B",
            target=r"C:\b.exe",
            evidence={"process": {"ppid": 4242}, "timestamp": "2026-01-03T00:00:00Z"},
        )
        outside = correlator.correlate([parent, child], rules=rules)
        self.assertEqual(outside["stats"]["clusters"], 0)
        self.assertEqual(outside["campaigns"], [])
        widened = correlator.correlate([parent, child], rules=rules, window_hours=72)
        self.assertEqual(widened["stats"]["clusters"], 1)

    def test_unrelated_findings_do_not_cluster(self) -> None:
        rules = _rules([_abc_template()])
        result = correlator.correlate(
            [
                _finding("PERSIST_A", target=r"C:\a.exe"),
                _finding("DEFENSE_B", target=r"C:\b.exe"),
                _finding("OTHER_X", target=r"C:\c.exe"),
            ],
            rules=rules,
        )
        self.assertEqual(result["stats"]["clusters"], 0)
        self.assertEqual(result["campaigns"], [])

    def test_skipped_and_invalid_findings_are_ignored(self) -> None:
        rules = _rules([_abc_template()])
        result = correlator.correlate(
            [
                _finding("PERSIST_A", severity="SKIPPED"),
                None,
                "junk",
                42,
                {"severity": "SKIPPED", "rule_id": "DEFENSE_B"},
            ],
            rules=rules,
        )
        self.assertEqual(result["stats"]["findings"], 0)
        self.assertEqual(result["stats"]["clusters"], 0)

    def test_generator_input_is_supported(self) -> None:
        rules = _rules([_abc_template()])
        findings = (_finding(rule) for rule in ("PERSIST_A", "DEFENSE_B", "CRED_C"))
        result = correlator.correlate(findings, rules=rules)
        self.assertEqual(result["stats"]["findings"], 3)
        self.assertEqual(len(result["campaigns"]), 1)

    def test_single_dict_finding_is_supported(self) -> None:
        result = correlator.correlate(_finding("PERSIST_A"), rules=_rules())
        self.assertEqual(result["stats"]["findings"], 1)
        self.assertEqual(result["campaigns"], [])


# ---------------------------------------------------------------------------
# 模板匹配（固定剧本，绝无自由组合）
# ---------------------------------------------------------------------------


class TestTemplateMatching(_Case):
    def test_full_coverage_is_high(self) -> None:
        rules = _rules([_abc_template()])
        result = correlator.correlate(
            [_finding("PERSIST_A"), _finding("DEFENSE_B"), _finding("CRED_C")], rules=rules
        )
        campaign = result["campaigns"][0]
        self.assertEqual(set(campaign), _CAMPAIGN_FIELDS)
        self.assertEqual(campaign["chain_id"], "chain_abc")
        self.assertEqual(campaign["name"], "剧本 chain_abc")
        self.assertEqual(campaign["confidence"], "high")
        self.assertEqual(campaign["tactics"], ["TA0003", "TA0005", "TA0006"])
        self.assertEqual(campaign["finding_count"], 3)
        self.assertEqual(campaign["targets"], [TARGET])
        self.assertFalse(campaign["suppressed"])
        self.assertIsNone(campaign["suppressed_by"])
        self.assertFalse(campaign["shadow"])
        for step in campaign["steps"]:
            self.assertEqual(set(step), _STEP_FIELDS)
            for summary in step["findings"]:
                self.assertEqual(set(summary), _STEP_FINDING_FIELDS)

    def test_two_of_three_steps_is_medium(self) -> None:
        rules = _rules([_abc_template()])
        result = correlator.correlate([_finding("PERSIST_A"), _finding("DEFENSE_B")], rules=rules)
        self.assertEqual(len(result["campaigns"]), 1)
        self.assertEqual(result["campaigns"][0]["confidence"], "medium")
        self.assertEqual(len(result["campaigns"][0]["steps"]), 2)

    def test_two_of_four_steps_is_low(self) -> None:
        rules = _rules([_abcd_template()])
        result = correlator.correlate(
            [_finding("PERSIST_A"), _finding("DEFENSE_B"), _finding("OTHER_X")], rules=rules
        )
        self.assertEqual(len(result["campaigns"]), 1)
        self.assertEqual(result["campaigns"][0]["confidence"], "low")

    def test_less_than_two_steps_is_not_a_chain(self) -> None:
        rules = _rules([_abc_template()])
        result = correlator.correlate([_finding("PERSIST_A"), _finding("OTHER_X")], rules=rules)
        self.assertEqual(result["campaigns"], [])
        self.assertEqual(result["suppressed"], [])

    def test_free_combination_is_not_a_chain(self) -> None:
        """两条不同模板各命中一步：不在同一固定剧本中的组合不成链。"""
        rules = _rules(
            [
                _abc_template("chain_abc"),
                _template(
                    "chain_def",
                    [_step(["EXTRA_D"], "TA0007"), _step(["OTHER_X"], "TA0002")],
                ),
            ]
        )
        result = correlator.correlate([_finding("PERSIST_A"), _finding("EXTRA_D")], rules=rules)
        self.assertEqual(result["campaigns"], [])

    def test_min_findings_required_per_step(self) -> None:
        template = _template(
            "min_two",
            [
                _step(["PERSIST_A"], "TA0003", min_findings=2),
                _step(["DEFENSE_B"], "TA0005"),
            ],
        )
        rules = _rules([template])
        one = correlator.correlate([_finding("PERSIST_A"), _finding("DEFENSE_B")], rules=rules)
        self.assertEqual(one["campaigns"], [])
        two = correlator.correlate(
            [_finding("PERSIST_A"), _finding("PERSIST_A"), _finding("DEFENSE_B")], rules=rules
        )
        self.assertEqual(len(two["campaigns"]), 1)
        self.assertEqual(two["campaigns"][0]["confidence"], "high")

    def test_same_finding_is_not_reused_across_steps(self) -> None:
        template = _template(
            "reuse",
            [_step(["PERSIST_A"], "TA0003"), _step(["PERSIST_A"], "TA0003")],
        )
        rules = _rules([template])
        result = correlator.correlate([_finding("PERSIST_A"), _finding("OTHER_X")], rules=rules)
        self.assertEqual(result["campaigns"], [])

    def test_tactic_only_step_matches_via_mapping(self) -> None:
        template = _template(
            "tactic_steps",
            [_step([], "TA0003"), _step([], "TA0005")],
        )
        rules = _rules([template])
        result = correlator.correlate([_finding("PERSIST_A"), _finding("DEFENSE_B")], rules=rules)
        self.assertEqual(len(result["campaigns"]), 1)
        self.assertEqual(result["campaigns"][0]["confidence"], "high")

    def test_wildcard_rule_ids_match_prefix(self) -> None:
        template = _template(
            "wildcard",
            [_step(["SIG_*"], "TA0005"), _step(["DEFENSE_B"], "TA0005")],
        )
        rules = _rules([template])
        result = correlator.correlate([_finding("SIG_UNSIGNED"), _finding("DEFENSE_B")], rules=rules)
        self.assertEqual(len(result["campaigns"]), 1)

    def test_rule_id_matching_is_case_insensitive(self) -> None:
        rules = _rules([_abc_template()])
        result = correlator.correlate(
            [_finding("persist_a"), _finding("defense_b"), _finding("cred_c")], rules=rules
        )
        self.assertEqual(len(result["campaigns"]), 1)

    def test_template_max_gap_hours_is_enforced(self) -> None:
        template = _template(
            "gap_limited",
            [_step(["PERSIST_A"], "TA0003"), _step(["DEFENSE_B"], "TA0005")],
            max_gap_hours=1,
        )
        rules = _rules([template])
        early = _finding("PERSIST_A", evidence={"timestamp": "2026-01-01T00:00:00Z"})
        late = _finding("DEFENSE_B", evidence={"timestamp": "2026-01-01T05:00:00Z"})
        self.assertEqual(correlator.correlate([early, late], rules=rules)["campaigns"], [])
        wide = _template(
            "gap_wide",
            [_step(["PERSIST_A"], "TA0003"), _step(["DEFENSE_B"], "TA0005")],
            max_gap_hours=24,
        )
        result = correlator.correlate([early, late], rules=_rules([wide]))
        self.assertEqual(len(result["campaigns"]), 1)

    def test_multiple_templates_produce_deterministic_order(self) -> None:
        low_first = _abcd_template("template_medium_cover")  # 3/4 -> medium
        high_second = _abc_template("template_full_cover")  # 3/3 -> high
        rules = _rules([low_first, high_second])
        result = correlator.correlate(
            [_finding("PERSIST_A"), _finding("DEFENSE_B"), _finding("CRED_C")], rules=rules
        )
        self.assertEqual(
            [campaign["chain_id"] for campaign in result["campaigns"]],
            ["template_full_cover", "template_medium_cover"],
        )
        self.assertEqual(
            [campaign["confidence"] for campaign in result["campaigns"]], ["high", "medium"]
        )


# ---------------------------------------------------------------------------
# 反模式抑制
# ---------------------------------------------------------------------------


class TestAntiPatterns(_Case):
    def _base_findings(self) -> list[dict[str, Any]]:
        return [
            _finding("PERSIST_A"),
            _finding("DEFENSE_B"),
            _finding("CRED_C"),
        ]

    def test_anti_pattern_suppresses_matching_campaign(self) -> None:
        rules = _rules(
            [_abc_template()],
            [_anti("legit_updater", rule_ids=["SIG_UNSIGNED"], require_all=False)],
        )
        result = correlator.correlate(
            self._base_findings() + [_finding("SIG_UNSIGNED")], rules=rules
        )
        self.assertEqual(result["campaigns"], [])
        self.assertEqual(len(result["suppressed"]), 1)
        campaign = result["suppressed"][0]
        self.assertTrue(campaign["suppressed"])
        self.assertEqual(campaign["suppressed_by"], "legit_updater")
        self.assertEqual(campaign["confidence"], "high")
        self.assertEqual(result["stats"]["suppressed"], 1)

    def test_anti_pattern_require_all_blocks_partial_match(self) -> None:
        rules = _rules(
            [_abc_template()],
            [
                _anti(
                    "needs_two",
                    rule_ids=["SIG_UNSIGNED", "WER_LOCALDUMPS_TAMPER"],
                    require_all=True,
                )
            ],
        )
        result = correlator.correlate(
            self._base_findings() + [_finding("SIG_UNSIGNED")], rules=rules
        )
        self.assertEqual(len(result["campaigns"]), 1)
        self.assertEqual(result["suppressed"], [])

    def test_anti_pattern_any_match_when_not_require_all(self) -> None:
        rules = _rules(
            [_abc_template()],
            [
                _anti(
                    "any_two",
                    rule_ids=["SIG_UNSIGNED", "WER_LOCALDUMPS_TAMPER"],
                    require_all=False,
                )
            ],
        )
        result = correlator.correlate(
            self._base_findings() + [_finding("WER_LOCALDUMPS_TAMPER")], rules=rules
        )
        self.assertEqual(result["campaigns"], [])
        self.assertEqual(len(result["suppressed"]), 1)

    def test_anti_pattern_tactics_condition(self) -> None:
        rules = _rules(
            [_abc_template()],
            [_anti("by_tactic", tactics=["TA0005"], require_all=False)],
        )
        result = correlator.correlate(self._base_findings(), rules=rules)
        self.assertEqual(result["campaigns"], [])
        self.assertEqual(len(result["suppressed"]), 1)

    def test_anti_pattern_target_contains_condition(self) -> None:
        hit_rules = _rules(
            [_abc_template()],
            [_anti("by_target", target_contains=[r"users\public"], require_all=False)],
        )
        self.assertEqual(correlator.correlate(self._base_findings(), rules=hit_rules)["campaigns"], [])

        miss_rules = _rules(
            [_abc_template()],
            [_anti("by_target", target_contains=[r"windows\system32"], require_all=False)],
        )
        result = correlator.correlate(self._base_findings(), rules=miss_rules)
        self.assertEqual(len(result["campaigns"]), 1)

    def test_anti_pattern_is_evaluated_per_cluster(self) -> None:
        rules = _rules(
            [_abc_template()],
            [_anti("legit", rule_ids=["SIG_UNSIGNED"], require_all=False)],
        )
        clean = [_finding("PERSIST_A", target=r"C:\clean.exe")]
        clean += [
            _finding("DEFENSE_B", target=r"C:\clean.exe"),
            _finding("CRED_C", target=r"C:\clean.exe"),
        ]
        dirty = [
            _finding("PERSIST_A", target=r"C:\dirty.exe"),
            _finding("DEFENSE_B", target=r"C:\dirty.exe"),
            _finding("CRED_C", target=r"C:\dirty.exe"),
            _finding("SIG_UNSIGNED", target=r"C:\dirty.exe"),
        ]
        result = correlator.correlate(clean + dirty, rules=rules)
        self.assertEqual(len(result["campaigns"]), 1)
        self.assertEqual(result["campaigns"][0]["targets"], [r"C:\clean.exe"])
        self.assertEqual(len(result["suppressed"]), 1)
        self.assertEqual(result["suppressed"][0]["targets"], [r"C:\dirty.exe"])


# ---------------------------------------------------------------------------
# stats / 防御 / 真实规则集成
# ---------------------------------------------------------------------------


class TestCorrelateApi(_Case):
    def test_empty_findings_returns_empty_result(self) -> None:
        for value in ([], None, (), {}):
            with self.subTest(value=value):
                result = correlator.correlate(value, rules=_rules())
                self.assertEqual(result["campaigns"], [])
                self.assertEqual(result["suppressed"], [])
                self.assertEqual(
                    result["stats"],
                    {"findings": 0, "clusters": 0, "campaigns": 0, "suppressed": 0},
                )

    def test_invalid_rules_do_not_raise(self) -> None:
        for value in (None, [], "junk", 42):
            with self.subTest(value=value):
                result = correlator.correlate([_finding("PERSIST_A"), _finding("DEFENSE_B")], rules=value)
                self.assertEqual(result["campaigns"], [])

    def test_now_parameter_is_defensive(self) -> None:
        rules = _rules([_abc_template()])
        findings = [_finding("PERSIST_A"), _finding("DEFENSE_B"), _finding("CRED_C")]
        for now in (None, 1700000000, "2026-01-01T00:00:00Z", datetime(2026, 1, 1, tzinfo=timezone.utc), "junk"):
            with self.subTest(now=now):
                result = correlator.correlate(findings, rules=rules, now=now)
                self.assertEqual(len(result["campaigns"]), 1)

    def test_invalid_window_hours_falls_back_to_default(self) -> None:
        rules = _rules([_abc_template()])
        findings = [_finding("PERSIST_A"), _finding("DEFENSE_B"), _finding("CRED_C")]
        for window in (0, -5, "bad", None):
            with self.subTest(window=window):
                result = correlator.correlate(findings, rules=rules, window_hours=window)
                self.assertEqual(len(result["campaigns"]), 1)

    def test_stats_count_clusters_campaigns_and_suppressed(self) -> None:
        rules = _rules(
            [_abc_template()],
            [_anti("legit", rule_ids=["SIG_UNSIGNED"], require_all=False)],
        )
        clean = [
            _finding("PERSIST_A", target=r"C:\clean.exe"),
            _finding("DEFENSE_B", target=r"C:\clean.exe"),
            _finding("CRED_C", target=r"C:\clean.exe"),
        ]
        dirty = [
            _finding("PERSIST_A", target=r"C:\dirty.exe"),
            _finding("DEFENSE_B", target=r"C:\dirty.exe"),
            _finding("CRED_C", target=r"C:\dirty.exe"),
            _finding("SIG_UNSIGNED", target=r"C:\dirty.exe"),
        ]
        result = correlator.correlate(clean + dirty, rules=rules)
        self.assertEqual(
            result["stats"],
            {"findings": 7, "clusters": 2, "campaigns": 1, "suppressed": 1},
        )

    def test_correlate_does_not_mutate_findings(self) -> None:
        rules = _rules([_abc_template()])
        findings = [_finding("PERSIST_A"), _finding("DEFENSE_B"), _finding("CRED_C")]
        snapshot = [dict(finding) for finding in findings]
        correlator.correlate(findings, rules=rules)
        self.assertEqual(findings, snapshot)
        for finding in findings:
            self.assertNotIn("campaign", finding)
            self.assertNotIn("chain_id", finding)

    def test_real_rules_full_attack_sequence_is_high(self) -> None:
        findings = [
            _finding("TASK_HIDDEN_TARRASK"),
            _finding("WFP_EDR_SILENCER"),
            _finding("RDP_SERVICEDLL_TAMPER"),
        ]
        result = correlator.correlate(findings)
        self.assertEqual(len(result["campaigns"]), 1)
        campaign = result["campaigns"][0]
        self.assertEqual(campaign["chain_id"], "hidden_task_wfp_credential_backdoor")
        self.assertEqual(campaign["confidence"], "high")
        self.assertEqual(campaign["tactics"], ["TA0003", "TA0005", "TA0006"])
        self.assertEqual(campaign["finding_count"], 3)

    def test_real_rules_partial_sequence_is_medium(self) -> None:
        findings = [_finding("TASK_HIDDEN_TARRASK"), _finding("WFP_EDR_SILENCER")]
        result = correlator.correlate(findings)
        self.assertEqual(len(result["campaigns"]), 1)
        self.assertEqual(result["campaigns"][0]["confidence"], "medium")

    def test_real_rules_free_combination_is_not_a_chain(self) -> None:
        """TASK_HIDDEN_TARRASK + SIG_UNSIGNED + CMD_AUTORUN 不在任何固定剧本中 -> 不成链。"""
        findings = [
            _finding("TASK_HIDDEN_TARRASK"),
            _finding("SIG_UNSIGNED"),
            _finding("CMD_AUTORUN"),
        ]
        result = correlator.correlate(findings)
        self.assertEqual(result["campaigns"], [])
        self.assertEqual(result["suppressed"], [])

    def test_real_rules_anti_pattern_suppresses(self) -> None:
        findings = [
            _finding("TASK_HIDDEN_TARRASK"),
            _finding("WFP_EDR_SILENCER"),
            _finding("RDP_SERVICEDLL_TAMPER"),
            _finding("SIG_UNSIGNED"),
            _finding("WER_LOCALDUMPS_TAMPER"),
            _finding("ACTIVE_SETUP_STUB"),
        ]
        result = correlator.correlate(findings)
        self.assertEqual(result["campaigns"], [])
        self.assertEqual(len(result["suppressed"]), 1)
        self.assertEqual(result["suppressed"][0]["suppressed_by"], "enterprise_updater_noise")


if __name__ == "__main__":
    unittest.main(verbosity=2)
