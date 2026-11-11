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
from typing import Any, Callable

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import reporter
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
        ("category", "类别", 110),
        ("target", "目标", 280),
        ("summary", "摘要", 210),
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

        vertical = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(table_wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        self.tree.bind("<<TreeviewSelect>>", self._handle_select_event)

    # -- 数据 --------------------------------------------------------------
    def load(self, findings: list[dict[str, Any]]) -> None:
        self.clear()
        for index, finding in enumerate(findings):
            iid = str(index)
            severity = str(finding.get("severity") or "")
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    severity,
                    truncate(finding.get("category"), 22),
                    _truncate_display(finding.get("target"), 62),
                    _truncate_display(finding.get("detail"), 70),
                ),
                tags=(severity,),
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

        self.export_button = ttk.Button(
            inner,
            text="导出报告",
            style="Secondary.TButton",
            command=self._safe(self._on_export),
            state="disabled",
        )
        self.export_button.pack(side="left", padx=(10, 0))

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

        counts = severity_counts(result.findings)
        for severity, card in self.stats.items():
            card.set_value(counts.get(severity, 0))

        # 只读修复建议：在加载结果表之前挂载 remediation，详情面板才能显示「建议处理」与复制按钮
        try:
            result.findings = reporter.apply_remediation(result.findings)
        except Exception:  # noqa: BLE001 - 建议加载失败不能中断扫描结果展示
            pass

        self.results_tree.load(result.findings)
        self.progress.configure(value=100)
        self.progress_text_var.set(f"扫描完成 · 共 {len(result.findings)} 条结果")

        issues = f"，{len(result.errors)} 个模块异常" if result.errors else ""
        self.status_var.set(f"扫描完成 · 共 {len(result.findings)} 条结果，耗时 {result.duration:.2f}s{issues}")
        self.info_var.set(
            f"模块 {result.modules_available}/{result.modules_total} · "
            f"结果 {len(result.findings)} · 耗时 {result.duration:.2f}s"
        )
        self.detail_panel.show_placeholder()
        if result.findings:
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
        if str(fmt).lower() == "json":
            return reporter.write_json(report, path)
        return reporter.write_html(report, path)

    def _on_close(self) -> None:
        if self._scanning:
            if not messagebox.askyesno("退出 TamperScan", "扫描仍在进行，确定要退出吗？", parent=self):
                return
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
