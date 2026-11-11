# -*- coding: utf-8 -*-
"""GUI 纯函数与展示常量（V1.5 rc2，自 V1.4 ``gui.py`` 迁移）。

本模块**不依赖 Tkinter / PyQt6**，只包含可从 GUI 单测的纯函数与常量，供
``gui_qt.py`` 与回归测试复用。迁移来源为 V1.4 ``gui.py``（rc1 删除 Tkinter 时
误删了其中的纯函数），函数实现与旧版本保持一致（仅补充类型注解与
``from __future__``）。
"""

from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Any

from . import baseline

# ---------------------------------------------------------------------------
# 常量（与 V1.4 gui.py 的模块级定义保持一致）
# ---------------------------------------------------------------------------

DIFF_STATUS_TAGS: dict[str, str] = {
    "NEW": "diff_new",
    "MODIFIED": "diff_modified",
    "ESCALATED": "diff_escalated",
    "DOWNGRADED": "diff_downgraded",
    "RESOLVED": "diff_resolved",
}

DIFF_TAG_STYLES: dict[str, dict[str, Any]] = {
    "diff_new": {"background": "#C42B1C", "foreground": "#FFFFFF"},
    "diff_modified": {"background": "#F7630C", "foreground": "#FFFFFF"},
    "diff_escalated": {"background": "#A4262C", "foreground": "#FFFFFF", "bold": True},
    "diff_downgraded": {"background": "#F2D64B", "foreground": "#1F2328"},
    "diff_resolved": {"foreground": "#8A8886", "overstrike": True},
}

CAMPAIGN_COLUMNS: tuple[tuple[str, str, int], ...] = (
    ("name", "攻击链", 220),
    ("confidence", "置信度", 70),
    ("steps", "步骤", 56),
    ("findings", "Finding", 70),
)

CAMPAIGN_CONFIDENCE_COLORS: dict[str, str] = {
    "high": "#C42B1C",
    "medium": "#F7630C",
    "low": "#C19C00",
}

CAMPAIGN_CONFIDENCE_LABELS: dict[str, str] = {
    "high": "高",
    "medium": "中",
    "low": "低",
}

CAMPAIGN_CONFIDENCE_TAGS: dict[str, str] = {
    "high": "campaign_high",
    "medium": "campaign_medium",
    "low": "campaign_low",
}

CAMPAIGN_EMPTY_TEXT = "未发现满足固定剧本的攻击链（绝无自由组合）"

CAMPAIGN_STEP_COLUMNS: tuple[tuple[str, str, int], ...] = (
    ("step", "#", 44),
    ("tactic", "战术", 100),
    ("rules", "规则", 200),
    ("targets", "目标", 320),
)

STATUS_COLUMN: tuple[str, str, int] = ("status", "状态", 76)

#: V1.4 FindingTree 的列定义（迁移常量，供纯函数测试使用；V1.5 Qt 列表不再使用）
FINDING_COLUMNS: tuple[tuple[str, str, int], ...] = (
    ("severity", "等级", 64),
    ("status", "状态", 76),
    ("category", "类别", 100),
    ("target", "目标", 258),
    ("summary", "摘要", 196),
)


# ---------------------------------------------------------------------------
# 基线 / diff 展示
# ---------------------------------------------------------------------------


def load_baseline_file(path: str | Path | None) -> tuple[dict[str, Any] | None, str | None]:
    """安全读取基线 JSON 文件，返回 ``(报告 dict, 失败原因)``；绝不抛异常。"""
    raw = str(path or "").strip()
    if not raw:
        return None, "未选择基线文件"
    try:
        with open(raw, "r", encoding="utf-8-sig") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        return None, f"基线文件不存在：{raw}"
    except json.JSONDecodeError as exc:
        return None, f"基线文件不是合法 JSON（{exc.msg}，第 {exc.lineno} 行）"
    except OSError as exc:
        return None, f"无法读取基线文件：{exc}"
    ok, reason = baseline.validate_baseline_report(payload)
    if not ok:
        return None, str(reason or "基线文件结构无效")
    return payload, None


def _normalize_diff_status(status: Any) -> str:
    return str(status or "").strip().upper()


def diff_status_tag(status: Any) -> str | None:
    """diff_status -> Treeview tag；UNCHANGED/空/未知状态返回 ``None``。"""
    return DIFF_STATUS_TAGS.get(_normalize_diff_status(status))


def finding_status_tag(finding: Any) -> str | None:
    """取单个 Finding 的基线状态 tag；非 dict 返回 ``None``。"""
    if not isinstance(finding, dict):
        return None
    return diff_status_tag(finding.get("diff_status"))


def baseline_label_text(path: Any) -> str:
    """生成对比基线标签：“对比基线: <文件名>”；空路径显示未加载。"""
    raw = str(path or "").strip()
    if not raw:
        return "对比基线: （未加载）"
    name = Path(raw).name
    return f"对比基线: {name or raw}"


# ---------------------------------------------------------------------------
# campaign 展示
# ---------------------------------------------------------------------------


def _clean_match_value(value: Any) -> str:
    return str(value or "").strip()


def _normalize_confidence(confidence: Any) -> str:
    return str(confidence or "").strip().lower()


def campaign_confidence_tag(confidence: Any) -> str:
    """置信度 -> Treeview tag；未知/空值返回空字符串。"""
    return CAMPAIGN_CONFIDENCE_TAGS.get(_normalize_confidence(confidence), "")


def campaign_confidence_label(confidence: Any) -> str:
    """置信度 -> 中文标签；未知/空值返回“未知”。"""
    return CAMPAIGN_CONFIDENCE_LABELS.get(_normalize_confidence(confidence), "未知")


def campaign_finding_count(campaign: Any) -> int:
    """campaign 的 finding 数：优先 finding_count，缺失时按 findings 统计。"""
    if not isinstance(campaign, dict):
        return 0
    count = campaign.get("finding_count")
    if isinstance(count, bool):
        count = None
    if isinstance(count, int):
        return max(0, count)
    return len(campaign_finding_keys(campaign))


def campaign_summary_text(campaign: Any) -> str:
    """campaign 一句话摘要：“名称（置信度 高，2 步 / 3 条 finding）”。"""
    if not isinstance(campaign, dict) or not campaign:
        return ""
    name = str(campaign.get("name") or campaign.get("chain_id") or "未命名攻击链")
    label = campaign_confidence_label(campaign.get("confidence"))
    steps = campaign.get("steps")
    step_count = len(steps) if isinstance(steps, (list, tuple)) else 0
    count = campaign_finding_count(campaign)
    shadow = " · 影子（仅观察）" if campaign.get("shadow") else ""
    return f"{name}（置信度 {label}，{step_count} 步 / {count} 条 finding{shadow}）"


def campaign_finding_keys(campaign: Any) -> list[tuple[str, str]]:
    """获取 campaign 全部 Finding 的 ``(rule_id, target)``，去重（忽略大小写）。"""
    if not isinstance(campaign, dict):
        return []
    steps = campaign.get("steps")
    if not isinstance(steps, (list, tuple)):
        return []
    keys: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for step in steps:
        if not isinstance(step, dict):
            continue
        findings = step.get("findings")
        if not isinstance(findings, (list, tuple)):
            continue
        for item in findings:
            if not isinstance(item, dict):
                continue
            rule = _clean_match_value(item.get("rule_id"))
            target = _clean_match_value(item.get("target"))
            if not rule and not target:
                continue
            normalized = (rule.casefold(), target.casefold())
            if normalized in seen:
                continue
            seen.add(normalized)
            keys.append((rule, target))
    return keys


def finding_match_key(finding: Any) -> tuple[str, str] | None:
    """Finding 与 campaign 关联用的归一化匹配 ``(rule_id, target)``；空返回 None。"""
    if not isinstance(finding, dict):
        return None
    rule = _clean_match_value(finding.get("rule_id"))
    target = _clean_match_value(finding.get("target"))
    if not rule and not target:
        return None
    return (rule.casefold(), target.casefold())


def campaign_row_values(campaign: Any) -> tuple[str, str, str, str]:
    """攻击链列表一行的显示值：名称/置信度/步骤数/finding 数量。"""
    if not isinstance(campaign, dict):
        return ("", "未知", "0", "0")
    name = str(campaign.get("name") or campaign.get("chain_id") or "未命名攻击链")
    label = campaign_confidence_label(campaign.get("confidence"))
    steps = campaign.get("steps")
    step_count = len(steps) if isinstance(steps, (list, tuple)) else 0
    return (name, label, str(step_count), str(campaign_finding_count(campaign)))


def campaign_step_rows(campaign: Any) -> list[tuple[str, str, str, str]]:
    """把 campaign.steps 转成时间线行（# / 战术 / 规则 / 目标摘要）。"""
    if not isinstance(campaign, dict):
        return []
    steps = campaign.get("steps")
    if not isinstance(steps, (list, tuple)):
        return []
    rows: list[tuple[str, str, str, str]] = []
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            continue
        tactic = str(step.get("tactic") or "")
        rule_ids = step.get("rule_ids")
        if isinstance(rule_ids, (list, tuple)):
            rules = ", ".join(str(item) for item in rule_ids if _clean_match_value(item))
        else:
            rules = str(rule_ids or "")
        targets: list[str] = []
        findings = step.get("findings")
        if isinstance(findings, (list, tuple)):
            for item in findings:
                if not isinstance(item, dict):
                    continue
                target = _clean_match_value(item.get("target"))
                if target and target not in targets:
                    targets.append(target)
        rows.append(
            (
                str(index),
                _truncate_display(tactic, 18),
                _truncate_display(rules, 46),
                _truncate_display("; ".join(targets), 64),
            )
        )
    return rows


# ---------------------------------------------------------------------------
# 终端/表格宽度工具（V1.4 gui.py 同名实现）
# ---------------------------------------------------------------------------


def _display_width(text: str) -> int:
    width = 0
    for char in str(text):
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def _truncate_display(text: str, width: int) -> str:
    """按显示宽度截断（CJK 按 2 列），超出时追加省略号。"""
    value = " ".join(str(text or "").split())
    if _display_width(value) <= width:
        return value
    out = ""
    used = 0
    for char in value:
        char_width = 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        if used + char_width > width - 1:
            return out + "…"
        out += char
        used += char_width
    return out + "…"


__all__ = [
    "CAMPAIGN_COLUMNS",
    "CAMPAIGN_CONFIDENCE_COLORS",
    "CAMPAIGN_CONFIDENCE_LABELS",
    "CAMPAIGN_CONFIDENCE_TAGS",
    "CAMPAIGN_EMPTY_TEXT",
    "CAMPAIGN_STEP_COLUMNS",
    "DIFF_STATUS_TAGS",
    "DIFF_TAG_STYLES",
    "FINDING_COLUMNS",
    "STATUS_COLUMN",
    "_display_width",
    "_truncate_display",
    "baseline_label_text",
    "campaign_confidence_label",
    "campaign_confidence_tag",
    "campaign_finding_count",
    "campaign_finding_keys",
    "campaign_row_values",
    "campaign_step_rows",
    "campaign_summary_text",
    "diff_status_tag",
    "finding_match_key",
    "finding_status_tag",
    "load_baseline_file",
]
