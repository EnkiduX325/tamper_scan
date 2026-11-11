# -*- coding: utf-8 -*-
"""TamperScan 图形界面（tkinter + ttk，Windows 11 Fluent 扁平风格）。

启动：``python gui.py`` / 打包后双击 ``tamper_scan_gui.exe``。

设计要点：
- **窗口化打包保护**：``--windowed`` 打包后 stdout/stderr 为 ``None``，任何
  ``print()`` 都会 ``AttributeError`` 闪退，因此在导入内部模块**之前**先兜底；
- 扫描在后台线程执行，通过 ``queue`` + ``after(100)`` 轮询更新进度，UI 不阻塞；
- 扫描核心复用 ``core.scanner.run_scan()``，导出复用 ``reporter.py``；
- 所有 tkinter 回调都经 ``_safe`` 包装，异常弹 ``messagebox`` 而不是崩溃。
"""

import sys
import os

# ---------------------------------------------------------------------------
# 窗口化打包（--windowed）保护：必须在导入内部模块/任何 print 之前执行
# ---------------------------------------------------------------------------
if sys.stdout is None:  # pragma: no cover - 由 --windowed 打包触发
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:  # pragma: no cover - 由 --windowed 打包触发
    sys.stderr = open(os.devnull, "w")

from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import json
import queue
import threading
import traceback
import unicodedata
from datetime import datetime
from typing import Any, Callable, Iterable

import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox, ttk

import reporter
from core import baseline
from core.finding import SEVERITIES, severity_counts
from core.scanner import ScanResult, run_scan
from core.utils import is_admin, truncate
from core.version import __version__

# ---------------------------------------------------------------------------
# Fluent 调色板 / 字体
# ---------------------------------------------------------------------------

COLORS = {
    "bg": "#F3F3F3",
    "card": "#FFFFFF",
    "border": "#E1E1E1",
    "text": "#1F2328",
    "muted": "#5F6368",
    "accent": "#0067C0",
    "accent_active": "#005BA1",
    "accent_soft": "#E5F1FB",
    "header_bg": "#FFFFFF",
}

SEVERITY_COLORS = {
    "HIGH": "#D13438",
    "MEDIUM": "#F7630C",
    "LOW": "#C19C00",
    "INFO": "#0078D4",
    "SKIPPED": "#8A8886",
}

SEVERITY_LABELS = {
    "HIGH": "高危",
    "MEDIUM": "中危",
    "LOW": "低危",
    "INFO": "信息",
    "SKIPPED": "跳过",
}

#: 修复建议风险等级配色（与严重等级同色系）
REMEDIATION_RISK_COLORS = {
    "HIGH": SEVERITY_COLORS["HIGH"],
    "MEDIUM": SEVERITY_COLORS["MEDIUM"],
    "LOW": SEVERITY_COLORS["LOW"],
}

FONT_FAMILY = "Segoe UI"
FONT_MONO = "Consolas"


# ---------------------------------------------------------------------------
# 基线对比（V1.3）
# ---------------------------------------------------------------------------

#: 结果表格「状态」列定义：(key, 表头, 默认宽度)
STATUS_COLUMN: tuple[str, str, int] = ("status", "状态", 76)

#: diff_status -> Treeview 整行 tag 名；UNCHANGED / 空状态不加额外 tag
DIFF_STATUS_TAGS: dict[str, str] = {
    baseline.DIFF_NEW: "diff_new",
    baseline.DIFF_MODIFIED: "diff_modified",
    baseline.DIFF_ESCALATED: "diff_escalated",
    baseline.DIFF_DOWNGRADED: "diff_downgraded",
    baseline.DIFF_RESOLVED: "diff_resolved",
}

#: 状态 tag 样式：NEW 红底白字 / MODIFIED 橙底 / ESCALATED 红底加粗 /
#: DOWNGRADED 黄底 / RESOLVED 灰字删除线（字体对象在 FindingTree 内用 tkfont 构建）。
#: 状态 tag 在 severity tag 之后配置，因此叠加时以状态样式为准。
DIFF_TAG_STYLES: dict[str, dict[str, Any]] = {
    "diff_new": {"background": "#C42B1C", "foreground": "#FFFFFF"},
    "diff_modified": {"background": "#F7630C", "foreground": "#FFFFFF"},
    "diff_escalated": {"background": "#A4262C", "foreground": "#FFFFFF", "bold": True},
    "diff_downgraded": {"background": "#F2D64B", "foreground": "#1F2328"},
    "diff_resolved": {"foreground": "#8A8886", "overstrike": True},
}


def load_baseline_file(path: str | os.PathLike[str] | None) -> tuple[dict[str, Any] | None, str | None]:
    """安全读取基线 JSON 报告，返回 ``(报告 dict, 错误原因)``；任何异常都不抛出。

    - 文件不存在 / 无权限 / JSON 损坏 -> ``(None, 可读原因)``；
    - 根节点不是 JSON 对象或缺少 findings 列表 -> 复用
      :func:`core.baseline.validate_baseline_report` 校验后返回原因；
    - 使用 ``utf-8-sig`` 读取，兼容 Windows 记事本保存的 BOM 头。
    """
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
    """把 diff_status 归一化为大写字符串（空值返回空串）。"""
    return str(status or "").strip().upper()


def diff_status_tag(status: Any) -> str | None:
    """diff_status -> Treeview tag 名；UNCHANGED/空/未知状态返回 ``None``。"""
    return DIFF_STATUS_TAGS.get(_normalize_diff_status(status))


def finding_status_tag(finding: Any) -> str | None:
    """取一条 Finding 的基线状态 tag（无 diff_status / 非 dict 时返回 ``None``）。"""
    if not isinstance(finding, dict):
        return None
    return diff_status_tag(finding.get("diff_status"))


def baseline_label_text(path: Any) -> str:
    """工具栏基线标签文本：``对比基线: <文件名>``（空路径显示未加载）。"""
    raw = str(path or "").strip()
    if not raw:
        return "对比基线: （未加载）"
    name = Path(raw).name
    return f"对比基线: {name or raw}"


# ---------------------------------------------------------------------------
# 攻击链视图（V1.4）
# ---------------------------------------------------------------------------

#: 攻击链列表列定义：(key, 表头, 默认宽度)
CAMPAIGN_COLUMNS: tuple[tuple[str, str, int], ...] = (
    ("name", "攻击链", 220),
    ("confidence", "置信度", 70),
    ("steps", "步骤", 56),
    ("findings", "Finding", 70),
)

#: 置信度 -> 列表行颜色（high 红 / medium 橙 / low 黄）
CAMPAIGN_CONFIDENCE_COLORS: dict[str, str] = {
    "high": "#C42B1C",
    "medium": "#F7630C",
    "low": "#C19C00",
}

#: 置信度 -> 中文标签
CAMPAIGN_CONFIDENCE_LABELS: dict[str, str] = {
    "high": "高",
    "medium": "中",
    "low": "低",
}

#: 置信度 -> Treeview tag 名
CAMPAIGN_CONFIDENCE_TAGS: dict[str, str] = {
    "high": "campaign_high",
    "medium": "campaign_medium",
    "low": "campaign_low",
}

#: 无 campaign 时的提示文案（固定剧本，不做自由组合）
CAMPAIGN_EMPTY_TEXT = "未发现满足固定剧本的攻击链（绝无自由组合）"

#: 右侧步骤时间线列定义
CAMPAIGN_STEP_COLUMNS: tuple[tuple[str, str, int], ...] = (
    ("step", "#", 44),
    ("tactic", "战术", 100),
    ("rules", "规则", 200),
    ("targets", "目标", 320),
)


def _clean_match_value(value: Any) -> str:
    return str(value or "").strip()


def _normalize_confidence(confidence: Any) -> str:
    return str(confidence or "").strip().lower()


def campaign_confidence_tag(confidence: Any) -> str:
    """置信度 -> Treeview 行 tag；未知/空值返回空串（不加 tag）。"""
    return CAMPAIGN_CONFIDENCE_TAGS.get(_normalize_confidence(confidence), "")


def campaign_confidence_label(confidence: Any) -> str:
    """置信度 -> 中文标签；未知/空值返回「未知」。"""
    return CAMPAIGN_CONFIDENCE_LABELS.get(_normalize_confidence(confidence), "未知")


def campaign_finding_count(campaign: Any) -> int:
    """campaign 的 finding 数（优先 finding_count，缺失时按步骤 findings 统计）。"""
    if not isinstance(campaign, dict):
        return 0
    count = campaign.get("finding_count")
    if isinstance(count, bool):
        count = None
    if isinstance(count, int):
        return max(0, count)
    return len(campaign_finding_keys(campaign))


def campaign_summary_text(campaign: Any) -> str:
    """campaign 一句话摘要：``名称（置信度 高，2 步 / 3 条 finding）``。"""
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
    """提取 campaign 全部步骤内 ``(rule_id, target)``，去重（忽略大小写）且容错缺字段。"""
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
    """Finding 与 campaign 联动用的归一化匹配键 ``(rule_id, target)``；空返回 None。"""
    if not isinstance(finding, dict):
        return None
    rule = _clean_match_value(finding.get("rule_id"))
    target = _clean_match_value(finding.get("target"))
    if not rule and not target:
        return None
    return (rule.casefold(), target.casefold())


def campaign_row_values(campaign: Any) -> tuple[str, str, str, str]:
    """攻击链列表一行的显示值（名称/置信度/步骤数/finding 数）。"""
    if not isinstance(campaign, dict):
        return ("", "未知", "0", "0")
    name = str(campaign.get("name") or campaign.get("chain_id") or "未命名攻击链")
    label = campaign_confidence_label(campaign.get("confidence"))
    steps = campaign.get("steps")
    step_count = len(steps) if isinstance(steps, (list, tuple)) else 0
    return (name, label, str(step_count), str(campaign_finding_count(campaign)))


def campaign_step_rows(campaign: Any) -> list[tuple[str, str, str, str]]:
    """把 campaign.steps 转成时间线行（# / 战术 / 规则 / 目标摘要），防御性解析。"""
    if not isinstance(campaign, dict):
        return []
    steps = campaign.get("steps")
    if not isinstance(steps, (list, tuple)):
        return []
    rows: list[tuple[str, str, str, str]] = []
    for index, step in enumerate(steps, 1):
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


def _import_correlator() -> Any:
    """延迟导入 ``core.correlator``（V1.4 并行模块）；不可用时返回 ``None``。"""
    try:
        from core import correlator
    except Exception:  # noqa: BLE001 - 模块缺失/导入失败时 GUI 仍需可用
        return None
    return correlator


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------


def _display_width(text: str) -> int:
    width = 0
    for char in str(text):
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def _truncate_display(text: str, width: int) -> str:
    """按显示宽度截断（CJK 算 2 列），用于 Treeview 单元格。"""
    value = " ".join(str(text or "").split())
    if _display_width(value) <= width:
        return value
    out = ""
    used = 0
    for char in value:
        char_width = 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        if used + char_width > width - 1:
            break
        out += char
        used += char_width
    return out + "…"


def _enable_dpi_awareness() -> None:
    """让窗口在高 DPI 屏幕上保持清晰（失败无关紧要）。"""
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


def _round_rect_points(x1: float, y1: float, x2: float, y2: float, radius: float) -> list[float]:
    """生成圆角矩形顶点（Canvas polygon + smooth 使用）。"""
    points: list[float] = []
    for x, y in ((x1 + radius, y1), (x2 - radius, y1)):
        points.extend((x, y))
    for x, y in ((x2, y1 + radius), (x2, y2 - radius)):
        points.extend((x, y))
    for x, y in ((x2 - radius, y2), (x1 + radius, y2)):
        points.extend((x, y))
    for x, y in ((x1, y2 - radius), (x1, y1 + radius)):
        points.extend((x, y))
    return points


# ---------------------------------------------------------------------------
# 统计卡片
# ---------------------------------------------------------------------------


class StatCard(tk.Frame):
    """单个严重等级统计卡片：顶部强调条 + 大数字 + 等级名称。"""

    def __init__(self, master: tk.Misc, severity: str, label: str, color: str) -> None:
        super().__init__(
            master,
            bg=COLORS["card"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            bd=0,
        )
        self._color = color
        self._severity = severity

        accent = tk.Frame(self, bg=color, height=3)
        accent.pack(fill="x", side="top")

        body = tk.Frame(self, bg=COLORS["card"])
        body.pack(fill="both", expand=True, padx=14, pady=(10, 10))

        title = tk.Frame(body, bg=COLORS["card"])
        title.pack(fill="x")
        tk.Label(
            title,
            text=severity,
            bg=COLORS["card"],
            fg=color,
            font=(FONT_FAMILY, 9, "bold"),
            anchor="w",
        ).pack(side="left")
        tk.Label(
            title,
            text=f" {label}",
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9),
            anchor="w",
        ).pack(side="left")

        self._value_var = tk.StringVar(value="0")
        tk.Label(
            body,
            textvariable=self._value_var,
            bg=COLORS["card"],
            fg=color,
            font=(FONT_FAMILY, 26, "bold"),
            anchor="w",
        ).pack(fill="x", pady=(2, 0))

    def set_value(self, value: int) -> None:
        self._value_var.set(str(int(value)))

    def reset(self) -> None:
        self.set_value(0)


# ---------------------------------------------------------------------------
# 结果表格
# ---------------------------------------------------------------------------


class FindingTree(tk.Frame):
    """左侧结果表格：按 severity 着色，维护 iid → Finding 映射。"""

    COLUMNS = (
        ("severity", "等级", 64),
        STATUS_COLUMN,
        ("category", "类别", 100),
        ("target", "目标", 258),
        ("summary", "摘要", 196),
    )

    def __init__(self, master: tk.Misc, on_select: Callable[[dict[str, Any] | None], None] | None = None) -> None:
        super().__init__(
            master,
            bg=COLORS["card"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            bd=0,
        )
        self._on_select = on_select
        self._findings: dict[str, dict[str, Any]] = {}

        header = tk.Frame(self, bg=COLORS["card"])
        header.pack(fill="x", padx=14, pady=(12, 6))
        tk.Label(
            header,
            text="扫描结果",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT_FAMILY, 12, "bold"),
            anchor="w",
        ).pack(side="left")
        self._count_var = tk.StringVar(value="0 条")
        tk.Label(
            header,
            textvariable=self._count_var,
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9),
            anchor="e",
        ).pack(side="right")

        table_wrap = tk.Frame(self, bg=COLORS["card"])
        table_wrap.pack(fill="both", expand=True, padx=(10, 4), pady=(0, 10))
        table_wrap.grid_rowconfigure(0, weight=1)
        table_wrap.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            table_wrap,
            columns=[column[0] for column in self.COLUMNS],
            show="headings",
            selectmode="browse",
        )
        for key, title, width in self.COLUMNS:
            self.tree.heading(key, text=title, anchor="w")
            self.tree.column(key, width=width, minwidth=48, stretch=(key in ("target", "summary")), anchor="w")
        for severity, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(severity, foreground=color)
        # 状态 tag 叠加在 severity tag 之上（配置顺序靠后者优先）
        self._diff_fonts: list[tkfont.Font] = []
        self._configure_diff_tags()

        vertical = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(table_wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        self.tree.bind("<<TreeviewSelect>>", self._handle_select_event)

    # -- 样式 --------------------------------------------------------------
    def _configure_diff_tags(self) -> None:
        """配置基线对比的整行 tag（RESOLVED 删除线用 tkfont.Font(overstrike=1)）。"""
        bold_font = tkfont.Font(self, family=FONT_FAMILY, size=9, weight="bold")
        overstrike_font = tkfont.Font(self, family=FONT_FAMILY, size=9, overstrike=1)
        self._diff_fonts = [bold_font, overstrike_font]
        for tag, style in DIFF_TAG_STYLES.items():
            options: dict[str, Any] = {
                key: style[key] for key in ("background", "foreground") if key in style
            }
            if style.get("bold"):
                options["font"] = bold_font
            if style.get("overstrike"):
                options["font"] = overstrike_font
            self.tree.tag_configure(tag, **options)

    # -- 数据 --------------------------------------------------------------
    def load(self, findings: list[dict[str, Any]]) -> None:
        self.clear()
        for index, finding in enumerate(findings):
            iid = str(index)
            severity = str(finding.get("severity") or "")
            status = _normalize_diff_status(finding.get("diff_status"))
            status_tag = finding_status_tag(finding)
            tags: tuple[str, ...] = (severity, status_tag) if status_tag else (severity,)
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    severity,
                    status,
                    truncate(finding.get("category"), 22),
                    _truncate_display(finding.get("target"), 62),
                    _truncate_display(finding.get("detail"), 70),
                ),
                tags=tags,
            )
            self._findings[iid] = finding
        self._count_var.set(f"{len(findings)} 条")

    def clear(self) -> None:
        for child in self.tree.get_children():
            self.tree.delete(child)
        self._findings.clear()
        self._count_var.set("0 条")

    def selected_finding(self) -> dict[str, Any] | None:
        selection = self.tree.selection()
        if not selection:
            return None
        return self._findings.get(selection[0])

    def finding_for_iid(self, iid: str) -> dict[str, Any] | None:
        return self._findings.get(iid)

    def select_first(self) -> None:
        children = self.tree.get_children()
        if not children:
            return
        first = children[0]
        self.tree.selection_set(first)
        self.tree.focus(first)
        self.tree.see(first)

    def select_by_keys(self, keys: Iterable[tuple[str, str]]) -> list[str]:
        """按 ``(rule_id, target)`` 多选匹配行并滚动到第一条；返回选中 iid 列表。

        供攻击链视图联动使用：找不到匹配行时返回空列表，不改变当前选择。
        """
        wanted: set[tuple[str, str]] = set()
        for rule, target in keys or []:
            normalized = finding_match_key({"rule_id": rule, "target": target})
            if normalized is not None:
                wanted.add(normalized)
        if not wanted:
            return []
        matched = [
            iid
            for iid, finding in self._findings.items()
            if finding_match_key(finding) in wanted
        ]
        if not matched:
            return []
        self.tree.selection_set(matched)
        first = matched[0]
        self.tree.focus(first)
        self.tree.see(first)
        return matched

    def select_by_findings(self, findings: Iterable[dict[str, Any]]) -> list[str]:
        """按 finding 身份（对象 id）多选匹配行；供攻击链联动优先使用。"""
        wanted_ids: set[int] = set()
        for finding in findings or []:
            if isinstance(finding, dict):
                wanted_ids.add(id(finding))
        if not wanted_ids:
            return []
        matched = [iid for iid, finding in self._findings.items() if id(finding) in wanted_ids]
        if not matched:
            return []
        self.tree.selection_set(matched)
        first = matched[0]
        self.tree.focus(first)
        self.tree.see(first)
        return matched

    def _handle_select_event(self, _event: tk.Event) -> None:
        if self._on_select is not None:
            self._on_select(self.selected_finding())


# ---------------------------------------------------------------------------
# 详情面板
# ---------------------------------------------------------------------------


class DetailPanel(tk.Frame):
    """右侧详情面板：等级徽章 + target / detail / rule_id / category / evidence / 建议处理。"""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(
            master,
            bg=COLORS["card"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            bd=0,
        )
        header = tk.Frame(self, bg=COLORS["card"])
        header.pack(fill="x", padx=16, pady=(14, 8))
        tk.Label(
            header,
            text="详情",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT_FAMILY, 12, "bold"),
            anchor="w",
        ).pack(side="left")

        self._badge = tk.Label(
            header,
            text="",
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9, "bold"),
            padx=10,
            pady=2,
        )
        self._badge.pack(side="right")

        # 空状态
        self._placeholder = tk.Label(
            self,
            text="在左侧选择一条结果查看完整详情",
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 10),
            justify="center",
        )

        # 内容区（默认隐藏）：放进 Canvas 里，详情较多时可滚动，避免小窗口下被裁掉
        self._content = tk.Frame(self, bg=COLORS["card"])
        self._canvas = tk.Canvas(self._content, bg=COLORS["card"], highlightthickness=0, bd=0)
        self._content_scrollbar = ttk.Scrollbar(self._content, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self._content_scrollbar.set)
        self._content_scrollbar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)
        self._body = tk.Frame(self._canvas, bg=COLORS["card"])
        self._body_window = self._canvas.create_window((0, 0), window=self._body, anchor="nw")
        self._body.bind("<Configure>", self._on_body_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)
        self._canvas.bind("<MouseWheel>", self._on_mousewheel)
        self._body.bind("<MouseWheel>", self._on_mousewheel)

        self._meta_wrap = tk.Frame(self._body, bg=COLORS["card"])
        self._meta_wrap.pack(fill="x", padx=16, pady=(0, 8))
        self._rule_var = tk.StringVar(value="")
        self._category_var = tk.StringVar(value="")
        self._meta_wrap.columnconfigure(1, weight=1)
        for row, (name, var) in enumerate((("规则编号", self._rule_var), ("类别", self._category_var))):
            tk.Label(
                self._meta_wrap,
                text=name,
                bg=COLORS["card"],
                fg=COLORS["muted"],
                font=(FONT_FAMILY, 9),
                anchor="w",
            ).grid(row=row, column=0, sticky="w", padx=(0, 10), pady=1)
            tk.Label(
                self._meta_wrap,
                textvariable=var,
                bg=COLORS["card"],
                fg=COLORS["text"],
                font=(FONT_MONO, 9),
                anchor="w",
                justify="left",
            ).grid(row=row, column=1, sticky="w", pady=1)

        self._target_text = self._make_section("目标（target）", height=2)
        self._detail_text = self._make_section("描述（detail）", height=2)
        self._evidence_text = self._make_section("证据（evidence）", height=5, mono=True)
        self._build_remediation_section()

        self.show_placeholder()

    # -- 构建 --------------------------------------------------------------
    def _make_section(self, title: str, height: int, mono: bool = False) -> tk.Text:
        wrap = tk.Frame(self._body, bg=COLORS["card"])
        wrap.pack(fill="both", expand=(height >= 8), padx=16, pady=(0, 6))
        tk.Label(
            wrap,
            text=title,
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9),
            anchor="w",
        ).pack(fill="x", pady=(0, 3))

        body = tk.Frame(wrap, bg="#FAFAFA", highlightbackground=COLORS["border"], highlightthickness=1)
        body.pack(fill="both", expand=True)
        text = tk.Text(
            body,
            height=height,
            wrap="word",
            bg="#FAFAFA",
            fg=COLORS["text"],
            font=(FONT_MONO, 9) if mono else (FONT_FAMILY, 9),
            relief="flat",
            borderwidth=0,
            padx=8,
            pady=4,
            highlightthickness=0,
        )
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        if height >= 8:
            scrollbar.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        text.configure(state="disabled")
        return text

    # -- 滚动 --------------------------------------------------------------
    def _on_body_configure(self, _event: tk.Event) -> None:
        try:
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        except tk.TclError:
            pass

    def _on_canvas_configure(self, event: tk.Event) -> None:
        try:
            self._canvas.itemconfigure(self._body_window, width=event.width)
        except tk.TclError:
            pass

    def _on_mousewheel(self, event: tk.Event) -> None:
        """鼠标滚轮滚动详情内容（内容未超出可视区域时不拦截）。"""
        try:
            first, last = self._canvas.yview()
            if first <= 0.0 and last >= 1.0:
                return
            delta = int(-event.delta / 120) if getattr(event, "delta", 0) else 0
            if delta:
                self._canvas.yview_scroll(delta, "units")
        except tk.TclError:
            pass

    # -- 建议处理 ----------------------------------------------------------
    def _build_remediation_section(self) -> None:
        """构建「建议处理」区块；默认不显示，命中 remediation 时由 show_finding 显示。"""
        self._command = ""
        self._copy_after: str | None = None
        self._remediation = tk.Frame(self._body, bg=COLORS["card"])

        head = tk.Frame(self._remediation, bg=COLORS["card"])
        head.pack(fill="x", pady=(0, 4))
        tk.Label(
            head,
            text="建议处理",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT_FAMILY, 10, "bold"),
            anchor="w",
        ).pack(side="left")
        self._risk_label = tk.Label(
            head,
            text="",
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9, "bold"),
        )
        self._risk_label.pack(side="right")

        self._rem_summary_var = tk.StringVar(value="")
        self._rem_expected_var = tk.StringVar(value="")
        self._rem_actual_var = tk.StringVar(value="")
        self._rem_admin_var = tk.StringVar(value="")

        tk.Label(
            self._remediation,
            textvariable=self._rem_summary_var,
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT_FAMILY, 9),
            anchor="w",
            justify="left",
            wraplength=300,
        ).pack(fill="x", pady=(0, 4))

        grid = tk.Frame(self._remediation, bg=COLORS["card"])
        grid.pack(fill="x")
        grid.columnconfigure(1, weight=1)
        for row, (name, var) in enumerate(
            (
                ("建议值", self._rem_expected_var),
                ("当前值", self._rem_actual_var),
                ("需要管理员", self._rem_admin_var),
            )
        ):
            tk.Label(
                grid,
                text=name,
                bg=COLORS["card"],
                fg=COLORS["muted"],
                font=(FONT_FAMILY, 9),
                anchor="nw",
            ).grid(row=row, column=0, sticky="nw", padx=(0, 10), pady=1)
            tk.Label(
                grid,
                textvariable=var,
                bg=COLORS["card"],
                fg=COLORS["text"],
                font=(FONT_FAMILY, 9),
                anchor="w",
                justify="left",
                wraplength=230,
            ).grid(row=row, column=1, sticky="w", pady=1)

        self._command_wrap = tk.Frame(self._remediation, bg=COLORS["card"])
        self._command_wrap.pack(fill="x", pady=(6, 0))
        tk.Label(
            self._command_wrap,
            text="命令（只读；扫描器不会执行，仅供手动复制）",
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9),
            anchor="w",
        ).pack(fill="x", pady=(0, 3))
        command_body = tk.Frame(
            self._command_wrap,
            bg="#FAFAFA",
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        command_body.pack(fill="x")
        self._command_text = tk.Text(
            command_body,
            height=4,
            wrap="word",
            bg="#FAFAFA",
            fg=COLORS["text"],
            font=(FONT_MONO, 9),
            relief="flat",
            borderwidth=0,
            padx=8,
            pady=4,
            highlightthickness=0,
        )
        self._command_text.pack(fill="x")
        self._command_text.configure(state="disabled")
        self._copy_button = ttk.Button(
            self._command_wrap,
            text="复制命令",
            style="Secondary.TButton",
            command=self._on_copy_command,
        )
        self._copy_button.pack(anchor="w", pady=(6, 0))

    def _apply_remediation_view(self, remediation: dict[str, Any]) -> None:
        """把 remediation dict 填入「建议处理」区块并显示（含复制按钮状态）。"""
        self._rem_summary_var.set(str(remediation.get("summary") or ""))
        self._rem_expected_var.set(str(remediation.get("expected") or ""))
        self._rem_actual_var.set(str(remediation.get("actual") or ""))
        requires_admin = bool(remediation.get("requires_admin"))
        self._rem_admin_var.set("是（命令需以管理员身份运行）" if requires_admin else "否")
        risk = str(remediation.get("risk") or "").upper()
        self._risk_label.configure(
            text=f"风险 {risk}" if risk else "",
            fg=REMEDIATION_RISK_COLORS.get(risk, COLORS["muted"]),
        )
        self._command = str(remediation.get("command") or "")
        self._set_text(self._command_text, self._command)
        self._copy_button.configure(text="复制命令")
        if self._command:
            self._command_wrap.pack(fill="x", pady=(6, 0))
            self._copy_button.configure(state="normal")
        else:
            self._command_wrap.pack_forget()
            self._copy_button.configure(state="disabled")
        self._remediation.pack(fill="x", padx=16, pady=(0, 10))

    def _hide_remediation_view(self) -> None:
        """隐藏「建议处理」区块并清空复制状态（无 remediation 的 finding）。"""
        self._remediation.pack_forget()
        self._command = ""
        self._set_text(self._command_text, "")
        try:
            self._copy_button.configure(text="复制命令", state="disabled")
        except tk.TclError:
            pass

    def _on_copy_command(self) -> None:
        """把只读命令复制到剪贴板，并短暂显示「已复制」反馈。"""
        command = self._command
        if not command:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(command)
        except tk.TclError:
            return
        try:
            self._copy_button.configure(text="已复制")
        except tk.TclError:
            return
        if self._copy_after is not None:
            try:
                self.after_cancel(self._copy_after)
            except tk.TclError:
                pass
        try:
            self._copy_after = self.after(1500, self._reset_copy_button)
        except tk.TclError:
            self._copy_after = None

    def _reset_copy_button(self) -> None:
        self._copy_after = None
        try:
            if self.winfo_exists():
                self._copy_button.configure(text="复制命令")
        except tk.TclError:
            pass

    # -- 数据 --------------------------------------------------------------
    @staticmethod
    def _set_text(widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def show_placeholder(self) -> None:
        self._content.pack_forget()
        self._badge.configure(text="", bg=COLORS["card"], fg=COLORS["muted"])
        self._placeholder.pack(fill="both", expand=True)
        self._hide_remediation_view()

    def show_finding(self, finding: dict[str, Any] | None) -> None:
        if not finding:
            self.show_placeholder()
            return
        severity = str(finding.get("severity") or "")
        color = SEVERITY_COLORS.get(severity, COLORS["muted"])
        self._placeholder.pack_forget()
        self._content.pack(fill="both", expand=True)
        self._badge.configure(
            text=severity,
            bg=color,
            fg="#FFFFFF",
            font=(FONT_FAMILY, 9, "bold"),
        )
        self._rule_var.set(str(finding.get("rule_id") or ""))
        self._category_var.set(str(finding.get("category") or ""))
        self._set_text(self._target_text, str(finding.get("target") or ""))
        self._set_text(self._detail_text, str(finding.get("detail") or ""))
        try:
            evidence = json.dumps(finding.get("evidence") or {}, ensure_ascii=False, indent=2, default=str)
        except (TypeError, ValueError):
            evidence = str(finding.get("evidence") or "")
        self._set_text(self._evidence_text, evidence)
        remediation = finding.get("remediation")
        if isinstance(remediation, dict) and remediation:
            self._apply_remediation_view(remediation)
        else:
            self._hide_remediation_view()
        try:
            self._canvas.yview_moveto(0)
        except tk.TclError:
            pass


# ---------------------------------------------------------------------------
# 攻击链视图（V1.4）
# ---------------------------------------------------------------------------


class CampaignsWindow(tk.Toplevel):
    """攻击链独立窗口：左侧 campaign 列表，右侧选中 campaign 的步骤时间线。

    纯只读展示；选择/双击 campaign 时通过 ``on_select`` 回调让主窗口结果列表联动。
    无 campaign 时显示固定剧本提示文案，不做任何自由组合。
    """

    def __init__(
        self,
        master: tk.Misc,
        campaigns: list[dict[str, Any]] | None = None,
        on_select: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        super().__init__(master)
        self._on_select = on_select
        self._campaigns: list[dict[str, Any]] = []
        self._by_iid: dict[str, dict[str, Any]] = {}

        self.title("攻击链")
        self.configure(bg=COLORS["bg"])
        self.geometry("1000x620")
        self.minsize(780, 480)
        try:
            self.transient(master)
        except tk.TclError:
            pass
        self.protocol("WM_DELETE_WINDOW", self._on_close_pressed)
        self.bind("<Escape>", lambda _event: self._on_close_pressed())
        self._build_ui()
        self._center_on_parent(master)
        self.refresh(campaigns)

    # -- 布局 --------------------------------------------------------------
    def _build_ui(self) -> None:
        outer = tk.Frame(self, bg=COLORS["bg"])
        outer.pack(fill="both", expand=True, padx=16, pady=14)
        self._outer = outer

        header = tk.Frame(outer, bg=COLORS["bg"])
        header.pack(fill="x", pady=(0, 8))
        tk.Label(
            header,
            text="攻击链",
            bg=COLORS["bg"],
            fg=COLORS["text"],
            font=(FONT_FAMILY, 14, "bold"),
            anchor="w",
        ).pack(side="left")
        self._count_var = tk.StringVar(value="0 条攻击链")
        tk.Label(
            header,
            textvariable=self._count_var,
            bg=COLORS["bg"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9),
            anchor="e",
        ).pack(side="right")

        self._hint_var = tk.StringVar(value="")
        tk.Label(
            outer,
            textvariable=self._hint_var,
            bg=COLORS["bg"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9),
            anchor="w",
            justify="left",
        ).pack(fill="x", pady=(0, 8))

        self._paned = tk.PanedWindow(
            outer,
            orient="horizontal",
            bg=COLORS["bg"],
            bd=0,
            sashwidth=6,
            sashrelief="flat",
            handlesize=0,
            showhandle=False,
        )

        left = tk.Frame(
            self._paned,
            bg=COLORS["card"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            bd=0,
        )
        tk.Label(
            left,
            text="攻击链列表",
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9, "bold"),
            anchor="w",
        ).pack(fill="x", padx=12, pady=(10, 4))
        campaign_wrap = tk.Frame(left, bg=COLORS["card"])
        campaign_wrap.pack(fill="both", expand=True, padx=(10, 4), pady=(0, 10))
        campaign_wrap.grid_rowconfigure(0, weight=1)
        campaign_wrap.grid_columnconfigure(0, weight=1)
        self._campaign_tree = ttk.Treeview(
            campaign_wrap,
            columns=[column[0] for column in CAMPAIGN_COLUMNS],
            show="headings",
            selectmode="browse",
        )
        for key, title, width in CAMPAIGN_COLUMNS:
            self._campaign_tree.heading(key, text=title, anchor="w")
            self._campaign_tree.column(
                key, width=width, minwidth=44, stretch=(key == "name"), anchor="w"
            )
        for confidence, color in CAMPAIGN_CONFIDENCE_COLORS.items():
            tag = CAMPAIGN_CONFIDENCE_TAGS.get(confidence)
            if tag:
                self._campaign_tree.tag_configure(tag, foreground=color)
        campaign_scroll = ttk.Scrollbar(
            campaign_wrap, orient="vertical", command=self._campaign_tree.yview
        )
        self._campaign_tree.configure(yscrollcommand=campaign_scroll.set)
        self._campaign_tree.grid(row=0, column=0, sticky="nsew")
        campaign_scroll.grid(row=0, column=1, sticky="ns")
        self._campaign_tree.bind("<<TreeviewSelect>>", self._handle_campaign_select)
        self._campaign_tree.bind("<Double-1>", self._handle_campaign_select)

        right = tk.Frame(
            self._paned,
            bg=COLORS["card"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            bd=0,
        )
        tk.Label(
            right,
            text="步骤时间线",
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9, "bold"),
            anchor="w",
        ).pack(fill="x", padx=12, pady=(10, 4))
        self._detail_var = tk.StringVar(value="选择左侧攻击链查看步骤时间线")
        tk.Label(
            right,
            textvariable=self._detail_var,
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=(FONT_FAMILY, 10, "bold"),
            anchor="w",
            justify="left",
            wraplength=520,
        ).pack(fill="x", padx=12, pady=(0, 6))

        steps_wrap = tk.Frame(right, bg=COLORS["card"])
        steps_wrap.pack(fill="both", expand=True, padx=(10, 4), pady=(0, 10))
        steps_wrap.grid_rowconfigure(0, weight=1)
        steps_wrap.grid_columnconfigure(0, weight=1)
        self._steps_tree = ttk.Treeview(
            steps_wrap,
            columns=[column[0] for column in CAMPAIGN_STEP_COLUMNS],
            show="headings",
            selectmode="none",
        )
        for key, title, width in CAMPAIGN_STEP_COLUMNS:
            self._steps_tree.heading(key, text=title, anchor="w")
            self._steps_tree.column(
                key, width=width, minwidth=40, stretch=(key in ("rules", "targets")), anchor="w"
            )
        steps_scroll = ttk.Scrollbar(steps_wrap, orient="vertical", command=self._steps_tree.yview)
        self._steps_tree.configure(yscrollcommand=steps_scroll.set)
        self._steps_tree.grid(row=0, column=0, sticky="nsew")
        steps_scroll.grid(row=0, column=1, sticky="ns")

        self._paned.add(left, minsize=420, stretch="always")
        self._paned.add(right, minsize=360, stretch="always")

        self._empty_label = tk.Label(
            outer,
            text=CAMPAIGN_EMPTY_TEXT,
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 11),
            justify="center",
            padx=20,
            pady=40,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )

    def _center_on_parent(self, master: tk.Misc) -> None:
        try:
            self.update_idletasks()
            width, height = 1000, 620
            x = master.winfo_rootx() + max(0, (master.winfo_width() - width) // 2)
            y = master.winfo_rooty() + max(0, (master.winfo_height() - height) // 2)
            self.geometry(f"{width}x{height}+{x}+{y}")
        except tk.TclError:
            pass

    # -- 数据 --------------------------------------------------------------
    def refresh(self, campaigns: list[dict[str, Any]] | None) -> None:
        """用最新 campaign 列表刷新窗口内容（重复打开窗口时复用）。"""
        items = [item for item in (campaigns or []) if isinstance(item, dict)]
        self._campaigns = items
        self._by_iid.clear()
        for iid in self._campaign_tree.get_children():
            self._campaign_tree.delete(iid)
        self._clear_steps()
        for index, campaign in enumerate(items):
            iid = str(index)
            self._by_iid[iid] = campaign
            tag = campaign_confidence_tag(campaign.get("confidence"))
            tags: tuple[str, ...] = (tag,) if tag else ()
            self._campaign_tree.insert(
                "", "end", iid=iid, values=campaign_row_values(campaign), tags=tags
            )
        self._count_var.set(f"{len(items)} 条攻击链")
        if not items:
            self._detail_var.set(CAMPAIGN_EMPTY_TEXT)
            self._hint_var.set("固定剧本匹配：本次扫描未命中任何攻击链")
            self._paned.pack_forget()
            self._empty_label.pack(fill="both", expand=True)
            return
        self._empty_label.pack_forget()
        self._paned.pack(fill="both", expand=True)
        self._hint_var.set("固定剧本匹配结果 · 选中/双击攻击链可在主窗口联动高亮关联 findings")
        first = "0"
        self._campaign_tree.selection_set(first)
        self._campaign_tree.focus(first)
        self._campaign_tree.see(first)
        self._show_campaign(items[0])
        self._emit_select(items[0])

    def selected_campaign(self) -> dict[str, Any] | None:
        selection = self._campaign_tree.selection()
        if not selection:
            return None
        return self._by_iid.get(str(selection[0]))

    def _clear_steps(self) -> None:
        for iid in self._steps_tree.get_children():
            self._steps_tree.delete(iid)

    def _show_campaign(self, campaign: dict[str, Any]) -> None:
        self._detail_var.set(campaign_summary_text(campaign))
        self._clear_steps()
        for row in campaign_step_rows(campaign):
            self._steps_tree.insert("", "end", values=row)

    def _handle_campaign_select(self, _event: Any = None) -> None:
        campaign = self.selected_campaign()
        if campaign is None:
            return
        self._show_campaign(campaign)
        self._emit_select(campaign)

    def _emit_select(self, campaign: dict[str, Any]) -> None:
        if self._on_select is None:
            return
        try:
            self._on_select(campaign)
        except Exception:  # noqa: BLE001 - 联动回调异常不能拖垮攻击链窗口
            pass

    def _on_close_pressed(self) -> None:
        self.destroy()


# ---------------------------------------------------------------------------
# 主应用
# ---------------------------------------------------------------------------


class App(tk.Tk):
    """TamperScan 主窗口。"""

    POLL_INTERVAL_MS = 100

    def __init__(self) -> None:
        _enable_dpi_awareness()
        super().__init__()

        self.title("TamperScan —— Windows 防篡改扫描器")
        self.configure(bg=COLORS["bg"])
        self.geometry("1240x860")
        # 允许缩到 1100x720：详情面板内容区可滚动，小窗口下不会裁掉「建议处理」区块
        self.minsize(1060, 720)

        self._queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._scanning = False
        self._result: ScanResult | None = None
        self._poll_job: str | None = None
        # 基线对比状态（V1.3）：未加载基线时全部为空，UI 行为与 V1.2 一致
        self._baseline_report: dict[str, Any] | None = None
        self._baseline_path = ""
        self._baseline_diff: baseline.BaselineDiff | None = None
        self._baseline_warnings: list[str] = []
        # 攻击链（V1.4）：按需分析；不点击「攻击链」时不影响 V1.3 的任何行为
        self._campaigns: list[dict[str, Any]] = []
        self._campaign_data: dict[str, Any] = {}
        self._campaign_stats: dict[str, Any] = {}
        self._campaign_window: CampaignsWindow | None = None

        self._build_styles()
        self._build_ui()
        self._center_window(1240, 860)
        self.after(80, self._set_initial_sash)

        self.protocol("WM_DELETE_WINDOW", self._safe(self._on_close))
        self._poll_job = self.after(self.POLL_INTERVAL_MS, self._poll_queue)

    # -- 样式 --------------------------------------------------------------
    def _build_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Treeview",
            background=COLORS["card"],
            fieldbackground=COLORS["card"],
            foreground=COLORS["text"],
            rowheight=28,
            font=(FONT_FAMILY, 9),
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#FAFAFA",
            foreground=COLORS["muted"],
            font=(FONT_FAMILY, 9, "bold"),
            relief="flat",
            borderwidth=0,
            padding=(8, 6),
        )
        style.map(
            "Treeview",
            background=[("selected", COLORS["accent_soft"])],
            foreground=[("selected", COLORS["accent"])],
        )
        style.map("Treeview.Heading", background=[("active", "#F0F0F0")])
        style.configure(
            "Accent.TButton",
            background=COLORS["accent"],
            foreground="#FFFFFF",
            font=(FONT_FAMILY, 10, "bold"),
            padding=(18, 8),
            borderwidth=0,
            focusthickness=0,
            relief="flat",
        )
        style.map(
            "Accent.TButton",
            background=[("active", COLORS["accent_active"]), ("disabled", "#C7C7C7")],
            foreground=[("disabled", "#FFFFFF")],
        )
        style.configure(
            "Secondary.TButton",
            background=COLORS["card"],
            foreground=COLORS["text"],
            font=(FONT_FAMILY, 10),
            padding=(14, 8),
            borderwidth=1,
            relief="flat",
        )
        style.map(
            "Secondary.TButton",
            background=[("active", "#F3F3F3"), ("disabled", "#F7F7F7")],
            foreground=[("disabled", "#B1B1B1")],
        )
        style.configure(
            "Accent.Horizontal.TProgressbar",
            troughcolor="#E5E5E5",
            background=COLORS["accent"],
            bordercolor="#E5E5E5",
            lightcolor=COLORS["accent"],
            darkcolor=COLORS["accent"],
            thickness=6,
        )

    # -- 布局 --------------------------------------------------------------
    def _build_ui(self) -> None:
        self._build_topbar()

        content = tk.Frame(self, bg=COLORS["bg"])
        content.pack(fill="both", expand=True, padx=16, pady=(12, 0))

        self._build_stats(content)
        self._build_toolbar(content)
        self._build_main_area(content)
        self._build_statusbar()

    def _build_topbar(self) -> None:
        topbar = tk.Frame(self, bg=COLORS["header_bg"], height=90)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        inner = tk.Frame(topbar, bg=COLORS["header_bg"])
        inner.pack(fill="both", expand=True, padx=20)

        shield = tk.Canvas(inner, width=30, height=34, bg=COLORS["header_bg"], highlightthickness=0, bd=0)
        shield.pack(side="left", padx=(0, 12))
        self._draw_shield(shield, 3, 2, 24, COLORS["accent"])

        title_wrap = tk.Frame(inner, bg=COLORS["header_bg"])
        title_wrap.pack(side="left", fill="y", pady=12)
        tk.Label(
            title_wrap,
            text="TamperScan",
            bg=COLORS["header_bg"],
            fg=COLORS["text"],
            font=(FONT_FAMILY, 16, "bold"),
            anchor="w",
        ).pack(anchor="w")
        tk.Label(
            title_wrap,
            text=f"Windows 防篡改扫描器 · v{__version__}",
            bg=COLORS["header_bg"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 8),
            anchor="w",
        ).pack(anchor="w")

        badge = tk.Canvas(inner, width=96, height=28, bg=COLORS["header_bg"], highlightthickness=0, bd=0)
        badge.pack(side="right", pady=30)
        self._draw_permission_badge(badge, is_admin())

        separator = tk.Frame(self, bg=COLORS["border"], height=1)
        separator.pack(fill="x", side="top")

    @staticmethod
    def _draw_shield(canvas: tk.Canvas, x: float, y: float, size: float, color: str) -> None:
        points = [
            x, y + size * 0.08,
            x + size * 0.5, y,
            x + size, y + size * 0.08,
            x + size, y + size * 0.55,
            x + size * 0.5, y + size,
            x, y + size * 0.55,
        ]
        canvas.create_polygon(points, fill=color, outline="", smooth=False)
        canvas.create_line(
            x + size * 0.28, y + size * 0.48,
            x + size * 0.45, y + size * 0.66,
            x + size * 0.74, y + size * 0.30,
            fill="#FFFFFF", width=max(2, int(size * 0.11)),
            capstyle="round", joinstyle="round",
        )

    @staticmethod
    def _draw_permission_badge(canvas: tk.Canvas, admin: bool) -> None:
        background = COLORS["accent"] if admin else "#EFF0F2"
        foreground = "#FFFFFF" if admin else COLORS["muted"]
        text = "管理员" if admin else "标准用户"
        canvas.create_polygon(
            _round_rect_points(1, 2, 95, 26, 12),
            fill=background,
            outline="",
            smooth=True,
        )
        canvas.create_text(48, 14, text=text, fill=foreground, font=(FONT_FAMILY, 9, "bold"))

    def _build_stats(self, parent: tk.Frame) -> None:
        row = tk.Frame(parent, bg=COLORS["bg"])
        row.pack(fill="x", pady=(0, 12))
        self.stats: dict[str, StatCard] = {}
        for index, severity in enumerate(SEVERITIES):
            row.columnconfigure(index, weight=1, uniform="stat")
            card = StatCard(row, severity, SEVERITY_LABELS[severity], SEVERITY_COLORS[severity])
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 8, 0))
            self.stats[severity] = card

    def _build_toolbar(self, parent: tk.Frame) -> None:
        toolbar = tk.Frame(parent, bg=COLORS["card"], highlightbackground=COLORS["border"], highlightthickness=1)
        toolbar.pack(fill="x", pady=(0, 12))
        inner = tk.Frame(toolbar, bg=COLORS["card"])
        inner.pack(fill="x", padx=16, pady=12)

        self.start_button = ttk.Button(
            inner,
            text="开始扫描",
            style="Accent.TButton",
            command=self._safe(self._on_start_scan),
        )
        self.start_button.pack(side="left")

        self.compare_baseline_button = ttk.Button(
            inner,
            text="对比基线",
            style="Secondary.TButton",
            command=self._safe(self._on_load_baseline),
        )
        self.compare_baseline_button.pack(side="left", padx=(10, 0))

        self.save_baseline_button = ttk.Button(
            inner,
            text="保存为基线",
            style="Secondary.TButton",
            command=self._safe(self._on_save_baseline),
        )
        self.save_baseline_button.pack(side="left", padx=(10, 0))

        self.campaign_button = ttk.Button(
            inner,
            text="攻击链",
            style="Secondary.TButton",
            command=self._safe(self._on_show_campaigns),
        )
        self.campaign_button.pack(side="left", padx=(10, 0))

        self.export_button = ttk.Button(
            inner,
            text="导出报告",
            style="Secondary.TButton",
            command=self._safe(self._on_export),
            state="disabled",
        )
        self.export_button.pack(side="left", padx=(10, 0))

        self._build_baseline_badge(inner)

        progress_wrap = tk.Frame(inner, bg=COLORS["card"])
        progress_wrap.pack(side="left", fill="x", expand=True, padx=(20, 0))

        self.progress_text_var = tk.StringVar(value="就绪 · 点击「开始扫描」")
        tk.Label(
            progress_wrap,
            textvariable=self.progress_text_var,
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9),
            anchor="w",
        ).pack(fill="x")

        self.progress = ttk.Progressbar(
            progress_wrap,
            style="Accent.Horizontal.TProgressbar",
            mode="determinate",
            maximum=100,
            value=0,
        )
        self.progress.pack(fill="x", pady=(6, 0))

    def _build_baseline_badge(self, parent: tk.Frame) -> None:
        """构建「对比基线: <文件名>」标签 + 小 X 取消按钮；未加载基线时隐藏。"""
        self._baseline_badge = tk.Frame(parent, bg=COLORS["card"])
        pill = tk.Frame(
            self._baseline_badge,
            bg=COLORS["accent_soft"],
            highlightbackground=COLORS["accent_soft"],
            highlightthickness=1,
            bd=0,
        )
        pill.pack(side="left")
        self._baseline_label_var = tk.StringVar(value="")
        tk.Label(
            pill,
            textvariable=self._baseline_label_var,
            bg=COLORS["accent_soft"],
            fg=COLORS["accent"],
            font=(FONT_FAMILY, 9),
            padx=8,
            pady=2,
        ).pack(side="left")
        self._cancel_baseline_button = tk.Button(
            pill,
            text="X",
            command=self._safe(self._on_cancel_baseline),
            bg=COLORS["accent_soft"],
            fg=COLORS["accent"],
            activebackground="#D6E8F8",
            activeforeground=COLORS["accent"],
            bd=0,
            relief="flat",
            highlightthickness=0,
            font=(FONT_FAMILY, 8, "bold"),
            padx=6,
            cursor="hand2",
        )
        self._cancel_baseline_button.pack(side="left")
        # 先 pack 到右侧再 pack progress_wrap，避免被 expand 的进度区挤掉
        self._baseline_badge.pack(side="right", padx=(10, 0))
        self._baseline_badge.pack_forget()

    def _show_baseline_badge(self) -> None:
        """显示基线标签；存在版本/主机不一致警告时追加 ⚠ 标记。"""
        label = baseline_label_text(self._baseline_path)
        if self._baseline_warnings:
            label += " ⚠"
        self._baseline_label_var.set(label)
        self._baseline_badge.pack(side="right", padx=(10, 0))

    def _hide_baseline_badge(self) -> None:
        self._baseline_label_var.set("")
        self._baseline_badge.pack_forget()

    def _build_main_area(self, parent: tk.Frame) -> None:
        paned = tk.PanedWindow(
            parent,
            orient="horizontal",
            bg=COLORS["bg"],
            bd=0,
            sashwidth=6,
            sashrelief="flat",
            handlesize=0,
            showhandle=False,
        )
        paned.pack(fill="both", expand=True, pady=(0, 12))

        self.results_tree = FindingTree(paned, on_select=self._safe(self._on_select_finding))
        self.detail_panel = DetailPanel(paned)
        paned.add(self.results_tree, minsize=560, stretch="always")
        paned.add(self.detail_panel, minsize=360, stretch="always")
        self._paned = paned

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self, bg=COLORS["card"], height=38)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        tk.Frame(bar, bg=COLORS["border"], height=1).pack(fill="x", side="top")

        inner = tk.Frame(bar, bg=COLORS["card"])
        inner.pack(fill="both", expand=True, padx=16)
        self.status_var = tk.StringVar(value="就绪")
        tk.Label(
            inner,
            textvariable=self.status_var,
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9),
            anchor="w",
        ).pack(side="left", fill="y")

        self.info_var = tk.StringVar(value="模块 --/-- · 结果 -- · 耗时 --")
        tk.Label(
            inner,
            textvariable=self.info_var,
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=(FONT_FAMILY, 9),
            anchor="e",
        ).pack(side="right", fill="y")

    # -- 窗口辅助 ----------------------------------------------------------
    def _set_initial_sash(self) -> None:
        """让左侧结果表格占约 62% 宽度，右侧详情面板约 38%。"""
        try:
            width = self._paned.winfo_width()
            if width > 900:
                self._paned.sash_place(0, int(width * 0.62), 0)
        except tk.TclError:
            pass

    def _center_window(self, width: int, height: int) -> None:
        try:
            screen_width = self.winfo_screenwidth()
            screen_height = self.winfo_screenheight()
            x = max(0, (screen_width - width) // 2)
            y = max(0, (screen_height - height) // 2)
            self.geometry(f"{width}x{height}+{x}+{y}")
        except tk.TclError:
            pass

    def _safe(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """包装 tkinter 回调：异常弹窗提示，绝不让 GUI 崩溃。"""

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception:  # noqa: BLE001 - UI 回调兜底
                try:
                    messagebox.showerror("界面错误", traceback.format_exc(limit=5), parent=self)
                except tk.TclError:
                    pass
                return None

        return wrapper

    # -- 扫描流程 ----------------------------------------------------------
    def _on_start_scan(self) -> None:
        if self._scanning:
            return
        self._scanning = True
        self._result = None
        # 新扫描开始时旧攻击链结果即失效：关闭视图并清空缓存（不点击攻击链时无影响）
        self._close_campaign_window()
        self._campaigns = []
        self._campaign_data = {}
        self._campaign_stats = {}
        self._reset_view()
        self._set_controls(scanning=True)
        self.status_var.set("正在扫描…")
        self.progress_text_var.set("准备扫描…")
        threading.Thread(target=self._scan_worker, name="tamper-scan", daemon=True).start()

    def _scan_worker(self) -> None:
        def progress_callback(current: int, total: int, message: str) -> None:
            self._queue.put(("progress", (current, total, message)))

        try:
            result = run_scan(progress_callback=progress_callback, memory_scan=True, max_memory_scan=10)
            self._queue.put(("done", result))
        except Exception:  # noqa: BLE001 - 后台线程异常交给主线程提示
            self._queue.put(("error", traceback.format_exc()))

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "progress":
                    self._on_progress(*payload)
                elif kind == "done":
                    self._on_scan_finished(payload)
                elif kind == "error":
                    self._on_scan_failed(str(payload))
        except queue.Empty:
            pass
        finally:
            self._poll_job = self.after(self.POLL_INTERVAL_MS, self._poll_queue)

    def _on_progress(self, current: int, total: int, message: str) -> None:
        ratio = (current / total) if total else 0.0
        self.progress.configure(value=max(0.0, min(1.0, ratio)) * 100)
        self.progress_text_var.set(message)
        self.status_var.set(message)

    def _on_scan_finished(self, result: ScanResult) -> None:
        self._scanning = False
        self._result = result
        self._set_controls(scanning=False)
        self.export_button.configure(state="normal")

        # 只读修复建议：在加载结果表之前挂载 remediation，详情面板才能显示「建议处理」与复制按钮
        try:
            result.findings = reporter.apply_remediation(result.findings)
        except Exception:  # noqa: BLE001 - 建议加载失败不能中断扫描结果展示
            pass

        # 有基线时这里完成 diff + annotate，统计卡片按非 RESOLVED 项重算；无基线走原逻辑
        self._refresh_results_view()

        total = len(result.findings)
        self.progress.configure(value=100)
        self.progress_text_var.set(f"扫描完成 · 共 {total} 条结果")

        issues = f"，{len(result.errors)} 个模块异常" if result.errors else ""
        if self._baseline_report is not None:
            counts = baseline.diff_counts(self._baseline_diff)
            self.status_var.set(
                f"扫描完成 · 基线对比 NEW {counts['NEW']} / MODIFIED {counts['MODIFIED']} / "
                f"ESCALATED {counts['ESCALATED']} / DOWNGRADED {counts['DOWNGRADED']} / "
                f"RESOLVED {counts['RESOLVED']}，耗时 {result.duration:.2f}s{issues}"
            )
        else:
            self.status_var.set(f"扫描完成 · 共 {total} 条结果，耗时 {result.duration:.2f}s{issues}")
        self.info_var.set(
            f"模块 {result.modules_available}/{result.modules_total} · "
            f"结果 {total} · 耗时 {result.duration:.2f}s"
        )
        self.detail_panel.show_placeholder()
        if self.results_tree.tree.get_children():
            self.results_tree.select_first()

    def _on_scan_failed(self, message: str) -> None:
        self._scanning = False
        self._result = None
        self._set_controls(scanning=False)
        self.progress.configure(value=0)
        self.progress_text_var.set("扫描失败")
        self.status_var.set("扫描失败")
        messagebox.showerror("扫描失败", message[-2000:], parent=self)

    def _reset_view(self) -> None:
        for card in self.stats.values():
            card.reset()
        self.results_tree.clear()
        self.detail_panel.show_placeholder()
        self.progress.configure(value=0)
        self.info_var.set("模块 --/-- · 结果 -- · 耗时 --")

    def _set_controls(self, scanning: bool) -> None:
        self.start_button.configure(state="disabled" if scanning else "normal", text="扫描中…" if scanning else "开始扫描")
        if scanning:
            self.export_button.configure(state="disabled")

    # -- 基线对比 ----------------------------------------------------------
    def _current_report(self) -> dict[str, Any]:
        """构造当前结果对应的报告结构（供 host/version 警告使用）。"""
        findings = list(self._result.findings) if self._result is not None else []
        try:
            return reporter.build_report(
                findings,
                version=__version__,
                duration_seconds=(self._result.duration if self._result is not None else 0.0),
                modules=(self._result.module_status if self._result is not None else None),
            )
        except Exception:  # noqa: BLE001 - 环境信息收集失败时退化为最小结构
            return {"findings": findings, "version": __version__}

    def _compute_annotated(self) -> list[dict[str, Any]]:
        """对当前结果计算基线 diff，返回带 diff_status 的列表；无基线时原样返回。"""
        findings = list(self._result.findings) if self._result is not None else []
        if self._baseline_report is None or self._result is None:
            self._baseline_diff = None
            return findings
        # 用原始 findings 列表做 diff，annotate_findings 才能按对象身份匹配、避免错行
        self._baseline_diff = baseline.diff_reports(
            self._baseline_report, findings, baseline_path=self._baseline_path
        )
        self._baseline_warnings = baseline.baseline_warnings(
            self._baseline_report, self._current_report(), expected_version=__version__
        )
        self._show_baseline_badge()
        return baseline.annotate_findings(findings, self._baseline_diff)

    def _refresh_results_view(self) -> None:
        """按当前结果 + 基线状态刷新统计卡片与结果表（无基线时与 V1.2 一致）。"""
        if self._result is None:
            return
        if self._baseline_report is not None:
            annotated = self._compute_annotated()
            # 统计卡片排除 RESOLVED（已消失项不再计入当前风险）
            active = [
                finding
                for finding in annotated
                if _normalize_diff_status(finding.get("diff_status")) != baseline.DIFF_RESOLVED
            ]
            counts = severity_counts(active)
            self.results_tree.load(annotated)
        else:
            self._baseline_diff = None
            counts = severity_counts(self._result.findings)
            self.results_tree.load(self._result.findings)
        for severity, card in self.stats.items():
            card.set_value(counts.get(severity, 0))

    def _ensure_baseline_diff(self) -> baseline.BaselineDiff | None:
        """导出时确保 diff 已计算（加载基线后未重新扫描的兜底）。"""
        if self._baseline_report is None:
            return None
        if self._baseline_diff is None:
            findings = list(self._result.findings) if self._result is not None else []
            self._baseline_diff = baseline.diff_reports(
                self._baseline_report, findings, baseline_path=self._baseline_path
            )
        return self._baseline_diff

    def _baseline_status_text(self) -> str:
        name = Path(self._baseline_path).name if self._baseline_path else ""
        text = f"已加载基线：{name}" if name else "已加载基线"
        if self._baseline_warnings:
            text += " · WARNING：" + "；".join(self._baseline_warnings)
        if self._result is not None:
            counts = baseline.diff_counts(self._baseline_diff)
            text += (
                f" · NEW {counts['NEW']} / MODIFIED {counts['MODIFIED']} / "
                f"ESCALATED {counts['ESCALATED']}"
            )
        return text

    def _on_load_baseline(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="选择基线报告",
            filetypes=[("JSON 报告", "*.json"), ("所有文件", "*.*")],
        )
        if not path:  # 用户取消
            self.status_var.set("已取消选择基线")
            return
        report, error = load_baseline_file(path)
        if report is None:
            self.status_var.set(f"基线加载失败：{error or '未知原因'}")
            messagebox.showwarning("无法加载基线", error or "未知原因", parent=self)
            return
        self._baseline_report = report
        self._baseline_path = str(path)
        self._baseline_diff = None
        if self._result is not None:
            self._refresh_results_view()  # 内部重算 warnings / 更新标签
        else:
            self._baseline_warnings = baseline.baseline_warnings(
                report, self._current_report(), expected_version=__version__
            )
            self._show_baseline_badge()
        self.status_var.set(self._baseline_status_text())

    def _on_cancel_baseline(self) -> None:
        if self._baseline_report is None and not self._baseline_path:
            return
        self._baseline_report = None
        self._baseline_path = ""
        self._baseline_diff = None
        self._baseline_warnings = []
        self._hide_baseline_badge()
        if self._result is not None:
            self._refresh_results_view()  # 用原始 result.findings 重新 load，去掉 diff_status
            total = len(self._result.findings)
            self.status_var.set(f"已取消基线对比 · 共 {total} 条结果")
            self.progress_text_var.set(f"共 {total} 条结果")
        else:
            self.status_var.set("已取消基线对比")

    def _on_save_baseline(self) -> None:
        if self._result is None:
            self.status_var.set("尚未扫描，无法保存基线")
            messagebox.showinfo("保存基线", "请先完成一次扫描，再保存为基线。", parent=self)
            return
        default_name = datetime.now().strftime("tamper_scan_baseline_%Y%m%d_%H%M%S.json")
        path = filedialog.asksaveasfilename(
            parent=self,
            title="保存为基线",
            defaultextension=".json",
            initialfile=default_name,
            filetypes=[("JSON 报告", "*.json")],
        )
        if not path:  # 用户取消
            self.status_var.set("已取消保存基线")
            return
        try:
            written = self._save_baseline_to_path(path)
        except Exception as exc:  # noqa: BLE001 - 保存失败只弹窗，不崩溃
            self.status_var.set("基线保存失败")
            messagebox.showerror("基线保存失败", f"{type(exc).__name__}: {exc}", parent=self)
            return
        self.status_var.set(f"基线已保存：{written}")
        messagebox.showinfo("基线已保存", f"基线文件已保存到：\n{written}", parent=self)

    def _save_baseline_to_path(self, path: str) -> str:
        """把当前结果写成基线 JSON（含 HIGH/MEDIUM 文件 SHA256，供哈希篡改检测）。"""
        if self._result is None:
            raise RuntimeError("当前没有可保存的扫描结果")
        report = reporter.build_report(
            self._result.findings,
            version=__version__,
            duration_seconds=self._result.duration,
            modules=self._result.module_status,
        )
        report["findings"] = baseline.enrich_findings_with_hashes(report["findings"])
        return reporter.write_json(report, path)

    # -- 攻击链（V1.4） ----------------------------------------------------
    def _close_campaign_window(self) -> None:
        window = self._campaign_window
        self._campaign_window = None
        if window is None:
            return
        try:
            if window.winfo_exists():
                window.destroy()
        except tk.TclError:
            pass

    def _correlate_findings(self, findings: list[dict[str, Any]]) -> dict[str, Any] | None:
        """只读调用 ``core.correlator.correlate``；模块缺失/异常时弹 warning 返回 None。"""
        correlator = _import_correlator()
        if correlator is None:
            self.status_var.set("攻击链分析不可用")
            messagebox.showwarning(
                "攻击链分析不可用",
                "当前版本缺少 core.correlator 模块，无法进行攻击链分析。",
                parent=self,
            )
            return None
        try:
            data = correlator.correlate(findings)
        except Exception as exc:  # noqa: BLE001 - 攻击链分析失败只弹窗，不崩溃
            self.status_var.set("攻击链分析失败")
            messagebox.showwarning(
                "攻击链分析失败", f"{type(exc).__name__}: {exc}", parent=self
            )
            return None
        if not isinstance(data, dict):
            data = {}
        if not isinstance(data.get("campaigns"), list):
            data["campaigns"] = []
        if not isinstance(data.get("stats"), dict):
            data["stats"] = {}
        if not isinstance(data.get("suppressed"), list):
            data["suppressed"] = []
        return data

    def _on_show_campaigns(self) -> None:
        """「攻击链」按钮：无结果提示先扫描；有结果分析并打开/刷新攻击链视图。"""
        if self._result is None:
            messagebox.showinfo("攻击链", "请先完成一次扫描，再查看攻击链。", parent=self)
            return
        data = self._correlate_findings(self._result.findings)
        if data is None:
            return
        self._campaign_data = data
        self._campaigns = [item for item in data.get("campaigns") or [] if isinstance(item, dict)]
        self._campaign_stats = data.get("stats") or {}
        self._open_campaign_window()
        if not self._campaigns:
            self.status_var.set(f"攻击链: {CAMPAIGN_EMPTY_TEXT}")

    def _open_campaign_window(self) -> None:
        """打开攻击链窗口；已打开时刷新并前置（复用同一 Toplevel）。"""
        if self._campaign_window is not None:
            try:
                exists = bool(self._campaign_window.winfo_exists())
            except tk.TclError:
                exists = False
            if exists:
                self._campaign_window.refresh(self._campaigns)
                try:
                    self._campaign_window.deiconify()
                    self._campaign_window.lift()
                    self._campaign_window.focus_set()
                except tk.TclError:
                    pass
                return
            self._campaign_window = None
        try:
            self._campaign_window = CampaignsWindow(
                self,
                self._campaigns,
                on_select=self._safe(self._on_campaign_selected),
            )
        except Exception as exc:  # noqa: BLE001 - 视图创建失败只弹窗，不崩溃
            self._campaign_window = None
            self.status_var.set("攻击链视图打开失败")
            messagebox.showwarning(
                "攻击链视图", f"无法打开攻击链视图：{type(exc).__name__}: {exc}", parent=self
            )

    def _on_campaign_selected(self, campaign: dict[str, Any]) -> None:
        """攻击链视图选中 campaign：主结果列表多选关联 findings + 状态栏摘要。"""
        if not isinstance(campaign, dict):
            return
        identity_findings: list[dict[str, Any]] = []
        steps = campaign.get("steps")
        if isinstance(steps, (list, tuple)):
            for step in steps:
                if not isinstance(step, dict):
                    continue
                item_findings = step.get("findings")
                if isinstance(item_findings, (list, tuple)):
                    identity_findings.extend(
                        item for item in item_findings if isinstance(item, dict)
                    )
        selected = self.results_tree.select_by_findings(identity_findings)
        if not selected:
            selected = self.results_tree.select_by_keys(campaign_finding_keys(campaign))
        if selected:
            finding = self.results_tree.finding_for_iid(selected[0])
            if finding is not None:
                self.detail_panel.show_finding(finding)
        name = str(campaign.get("name") or campaign.get("chain_id") or "未命名攻击链")
        label = campaign_confidence_label(campaign.get("confidence"))
        count = campaign_finding_count(campaign)
        self.status_var.set(f"攻击链: {name}（{label}，{count} 条 finding）")

    # -- 交互 --------------------------------------------------------------
    def _on_select_finding(self, finding: dict[str, Any] | None) -> None:
        self.detail_panel.show_finding(finding)

    def _on_export(self) -> None:
        if self._result is None:
            return
        default_name = datetime.now().strftime("tamper_scan_%Y%m%d_%H%M%S.html")
        path = filedialog.asksaveasfilename(
            parent=self,
            title="导出扫描报告",
            defaultextension=".html",
            initialfile=default_name,
            filetypes=[("HTML 报告", "*.html"), ("JSON 报告", "*.json")],
        )
        if not path:  # 用户取消
            self.status_var.set("已取消导出")
            return
        fmt = "html" if path.lower().endswith(".html") else "json"
        try:
            written = self._export_to_path(path, fmt)
        except Exception as exc:  # noqa: BLE001 - 导出失败只弹窗，不崩溃
            self.status_var.set("导出失败")
            messagebox.showerror("导出失败", f"{type(exc).__name__}: {exc}", parent=self)
            return
        self.status_var.set(f"报告已导出：{written}")
        messagebox.showinfo("导出成功", f"报告已保存到：\n{written}", parent=self)

    def _export_to_path(self, path: str, fmt: str) -> str:
        """把当前扫描结果写成 HTML/JSON（供 GUI 与自动化测试复用）。"""
        if self._result is None:
            raise RuntimeError("当前没有可导出的扫描结果")
        report = reporter.build_report(
            self._result.findings,
            version=__version__,
            duration_seconds=self._result.duration,
            modules=self._result.module_status,
        )
        if self._baseline_report is not None:
            # 有基线时把对比结果（含 baseline 元信息 / diff_status）写进报告；
            # apply_baseline_diff 由 reporter 模块提供（V1.3），缺失时保持原报告不崩溃。
            diff = self._ensure_baseline_diff()
            apply_baseline_diff = getattr(reporter, "apply_baseline_diff", None)
            if callable(apply_baseline_diff) and diff is not None:
                report = apply_baseline_diff(report, diff, baseline_path=self._baseline_path)
        if str(fmt).lower() == "json":
            return reporter.write_json(report, path)
        return reporter.write_html(report, path)

    def _on_close(self) -> None:
        if self._scanning:
            if not messagebox.askyesno("退出 TamperScan", "扫描仍在进行，确定要退出吗？", parent=self):
                return
        self._close_campaign_window()
        if self._poll_job is not None:
            try:
                self.after_cancel(self._poll_job)
            except tk.TclError:
                pass
            self._poll_job = None
        self.destroy()

    def run(self) -> None:
        self.mainloop()


def main() -> int:
    app = App()
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
