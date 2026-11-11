# -*- coding: utf-8 -*-
"""TamperScan V1.5 PyQt6 图形界面（唯一 GUI 入口）。

设计目标
--------
- **彻底替换 Tkinter**：V1.5 已物理删除旧 ``gui.py``，主入口为
  ``python main.py --gui`` / ``python gui_qt.py``；本文件是唯一 GUI 入口。
- **绝不阻塞 UI**：扫描（``core.scanner.run_scan``）与更新检查
  （``core.updater.check_for_update``）全部在 :class:`QThread` 中执行，通过
  ``pyqtSignal`` / ``pyqtSlot`` 把进度与结果送回主线程。
- **商业级视觉**：无边框窗口 + 自定义标题栏拖拽 + 四周 QGraphicsDropShadowEffect；
  浅色/暗黑两套 QSS；5 张圆角统计卡；QPainter 自绘平滑环形进度条；结果列表为
  自定义横幅 Widget（等级色块 + NEW/MODIFIED 状态 + 摘要）；右侧详情面板展示
  evidence JSON。
- **业务闭环**：启动 5 秒后静默检查更新（可被"暂不更新/不再提示"抑制）；
  "信任此项"生成联合指纹写入用户 ``config.json`` 并可选暂存匿名上报；
  设置中心支持自动更新开关、主题切换、清空信任名单、查看待上报队列。
- **异常兜底**：扫描线程任何异常都会转成 ``scan_failed`` 信号并弹窗，绝不闪退；
  顶层 ``sys.excepthook`` 也会兜底提示。

启动方式::

    python gui_qt.py
    python main.py --gui
"""

from __future__ import annotations

import json
import os
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 窗口化打包（--windowed）保护：必须在导入内部模块/任何 print 之前执行
# ---------------------------------------------------------------------------
if sys.stdout is None:  # pragma: no cover - 由 --windowed 打包触发
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:  # pragma: no cover - 由 --windowed 打包触发
    sys.stderr = open(os.devnull, "w")

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from PyQt6.QtCore import (  # noqa: E402
    QEasingCurve,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
    QThread,
    QTimer,
    QUrl,
    pyqtProperty,
    pyqtSignal,
    pyqtSlot,
)
from PyQt6.QtGui import (  # noqa: E402
    QColor,
    QDesktopServices,
    QFont,
    QIcon,
    QPainter,
    QPen,
)
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPushButton,
    QSizeGrip,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

import reporter  # noqa: E402
from core import baseline, config, ui_helpers, updater, whitelist  # noqa: E402
from core.finding import SEVERITIES, severity_counts  # noqa: E402
from core.paths import BASE_DIR  # noqa: E402
from core.scanner import run_scan  # noqa: E402
from core.utils import is_admin, truncate  # noqa: E402
from core.version import __version__  # noqa: E402

APP_NAME = "TamperScan"

SEVERITY_COLORS: dict[str, str] = {
    "HIGH": "#D13438",
    "MEDIUM": "#F7630C",
    "LOW": "#C19C00",
    "INFO": "#0078D4",
    "SKIPPED": "#8A8886",
}

SEVERITY_LABELS: dict[str, str] = {
    "HIGH": "高危",
    "MEDIUM": "中危",
    "LOW": "低危",
    "INFO": "信息",
    "SKIPPED": "跳过",
}

DIFF_STATUS_COLORS: dict[str, str] = {
    "NEW": "#DC2626",
    "MODIFIED": "#EA580C",
    "ESCALATED": "#DC2626",
    "DOWNGRADED": "#CA8A04",
    "BENIGN_UPDATE": "#059669",
    "RESOLVED": "#6B7280",
}

#: 浅色 / 暗黑两套全局 QSS（默认浅色；设置中心可切换）
LIGHT_QSS = """
QWidget {
    color: #1F2328;
    font-family: "Microsoft YaHei UI", "Segoe UI", "PingFang SC", sans-serif;
    font-size: 13px;
}
QMainWindow, QDialog { background: transparent; }
QDialog { background: #F6F8FC; }
QDialog#FramelessDialog { background: transparent; }
#DialogCard {
    background: #F6F8FC;
    border: 1px solid #E2E8F0;
    border-radius: 16px;
}
#DialogTitleBar { background: transparent; }
#DialogTitle { font-size: 14px; font-weight: 700; color: #0F172A; }
#DialogCloseButton {
    background: transparent;
    border: none;
    border-radius: 7px;
    color: #475569;
    font-size: 14px;
    padding: 3px 9px;
}
#DialogCloseButton:hover { background: #DC2626; color: #FFFFFF; }
QTableWidget {
    background: #FFFFFF;
    alternate-background-color: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 8px;
    gridline-color: #E2E8F0;
    color: #1F2328;
    selection-background-color: #E0E7FF;
    selection-color: #1F2328;
}
QHeaderView::section {
    background: #F1F5F9;
    color: #475569;
    border: none;
    border-bottom: 1px solid #E2E8F0;
    padding: 5px 8px;
    font-weight: 600;
}
QTableCornerButton::section { background: #F1F5F9; border: none; }
#RootCard {
    background: #F6F8FC;
    border: 1px solid #E2E8F0;
    border-radius: 18px;
}
#TitleBar { background: transparent; }
#AppTitle { font-size: 17px; font-weight: 700; color: #0F172A; }
#VersionLabel { color: #64748B; font-size: 12px; }
#PermissionBadge {
    background: rgba(37, 99, 235, 0.10);
    color: #1D4ED8;
    border-radius: 10px;
    padding: 4px 10px;
    font-size: 12px;
    font-weight: 600;
}
#IconButton {
    background: transparent;
    border: none;
    border-radius: 8px;
    font-size: 17px;
    color: #475569;
    padding: 4px 8px;
}
#IconButton:hover { background: #E2E8F0; }
#WindowButton {
    background: transparent;
    border: none;
    border-radius: 8px;
    font-size: 15px;
    color: #475569;
    padding: 4px 10px;
}
#WindowButton:hover { background: #E2E8F0; }
#WindowButtonClose:hover { background: #DC2626; color: #FFFFFF; }
#StatCard {
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 14px;
}
#StatLabel { color: #64748B; font-size: 12px; }
#ControlBar {
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 16px;
}
#ScanButton {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563EB, stop:1 #4F46E5);
    color: #FFFFFF;
    border: none;
    border-radius: 12px;
    font-size: 15px;
    font-weight: 700;
    padding: 12px 26px;
}
#ScanButton:hover { background: #1D4ED8; }
#ScanButton:disabled { background: #94A3B8; color: #F8FAFC; }
#ScanButton[busy="true"] {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #DC2626, stop:1 #EA580C);
}
#SecondaryButton {
    background: #EEF2FF;
    color: #3730A3;
    border: 1px solid #C7D2FE;
    border-radius: 10px;
    padding: 9px 16px;
    font-weight: 600;
}
#SecondaryButton:hover { background: #E0E7FF; }
#SecondaryButton:disabled { color: #94A3B8; border-color: #E2E8F0; background: #F8FAFC; }
#TrustButton {
    background: #059669;
    color: #FFFFFF;
    border: none;
    border-radius: 10px;
    padding: 9px 16px;
    font-weight: 700;
}
#TrustButton:hover { background: #047857; }
#TrustButton:disabled { background: #CBD5E1; color: #F8FAFC; }
#StatusLabel { color: #64748B; font-size: 12px; }
#ResultsCard, #DetailCard {
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 16px;
}
#CardTitle { font-size: 14px; font-weight: 700; color: #0F172A; }
#CardBadge { color: #64748B; font-size: 12px; }
QListWidget#ResultsList {
    background: transparent;
    border: none;
    outline: none;
}
QListWidget#ResultsList::item { background: transparent; border: none; }
#ResultItem {
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 10px;
}
#ResultItem:hover { background: #EEF2FF; border-color: #C7D2FE; }
#ResultTitle { font-size: 13px; font-weight: 600; color: #0F172A; }
#ResultDetail { color: #64748B; font-size: 12px; }
#ResultMeta { color: #94A3B8; font-size: 11px; }
#DetailTarget { font-size: 15px; font-weight: 700; color: #0F172A; }
#DetailHint { color: #94A3B8; font-size: 12px; }
#EvidenceView {
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 10px;
    color: #334155;
    padding: 8px;
}
QTextBrowser { selection-background-color: #BFDBFE; }
QLabel#EmptyHint { color: #94A3B8; font-size: 13px; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #CBD5E1; border-radius: 5px; min-height: 24px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QCheckBox { color: #1F2328; spacing: 8px; }
QComboBox {
    background: #FFFFFF; border: 1px solid #CBD5E1; border-radius: 8px;
    padding: 5px 10px; min-width: 100px;
}
QComboBox QAbstractItemView { background: #FFFFFF; selection-background-color: #E0E7FF; }
QDialog QPushButton {
    background: #EEF2FF; color: #3730A3; border: 1px solid #C7D2FE;
    border-radius: 8px; padding: 7px 14px;
}
QDialog QPushButton:hover { background: #E0E7FF; }
QDialog QPushButton#PrimaryButton {
    background: #2563EB; color: #FFFFFF; border: none; font-weight: 700;
}
"""

DARK_QSS = """
QWidget {
    color: #E5E7EB;
    font-family: "Microsoft YaHei UI", "Segoe UI", "PingFang SC", sans-serif;
    font-size: 13px;
}
QMainWindow, QDialog { background: transparent; }
QDialog { background: #0F172A; }
QDialog#FramelessDialog { background: transparent; }
#DialogCard {
    background: #0F172A;
    border: 1px solid #243044;
    border-radius: 16px;
}
#DialogTitleBar { background: transparent; }
#DialogTitle { font-size: 14px; font-weight: 700; color: #F8FAFC; }
#DialogCloseButton {
    background: transparent;
    border: none;
    border-radius: 7px;
    color: #CBD5E1;
    font-size: 14px;
    padding: 3px 9px;
}
#DialogCloseButton:hover { background: #DC2626; color: #FFFFFF; }
QTableWidget {
    background: #111A2B;
    alternate-background-color: #172033;
    border: 1px solid #2A3648;
    border-radius: 8px;
    gridline-color: #2A3648;
    color: #E5E7EB;
    selection-background-color: #1E3A8A;
    selection-color: #F8FAFC;
}
QHeaderView::section {
    background: #172033;
    color: #94A3B8;
    border: none;
    border-bottom: 1px solid #2A3648;
    padding: 5px 8px;
    font-weight: 600;
}
QTableCornerButton::section { background: #172033; border: none; }
#RootCard {
    background: #0F172A;
    border: 1px solid #243044;
    border-radius: 18px;
}
#TitleBar { background: transparent; }
#AppTitle { font-size: 17px; font-weight: 700; color: #F8FAFC; }
#VersionLabel { color: #94A3B8; font-size: 12px; }
#PermissionBadge {
    background: rgba(96, 165, 250, 0.16);
    color: #93C5FD;
    border-radius: 10px;
    padding: 4px 10px;
    font-size: 12px;
    font-weight: 600;
}
#IconButton {
    background: transparent;
    border: none;
    border-radius: 8px;
    font-size: 17px;
    color: #CBD5E1;
    padding: 4px 8px;
}
#IconButton:hover { background: #1E293B; }
#WindowButton {
    background: transparent;
    border: none;
    border-radius: 8px;
    font-size: 15px;
    color: #CBD5E1;
    padding: 4px 10px;
}
#WindowButton:hover { background: #1E293B; }
#WindowButtonClose:hover { background: #DC2626; color: #FFFFFF; }
#StatCard {
    background: #1B2433;
    border: 1px solid #2A3648;
    border-radius: 14px;
}
#StatLabel { color: #94A3B8; font-size: 12px; }
#ControlBar {
    background: #1B2433;
    border: 1px solid #2A3648;
    border-radius: 16px;
}
#ScanButton {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563EB, stop:1 #4F46E5);
    color: #FFFFFF;
    border: none;
    border-radius: 12px;
    font-size: 15px;
    font-weight: 700;
    padding: 12px 26px;
}
#ScanButton:hover { background: #1D4ED8; }
#ScanButton:disabled { background: #475569; color: #E2E8F0; }
#ScanButton[busy="true"] {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #DC2626, stop:1 #EA580C);
}
#SecondaryButton {
    background: #1E293B;
    color: #C7D2FE;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 9px 16px;
    font-weight: 600;
}
#SecondaryButton:hover { background: #273449; }
#SecondaryButton:disabled { color: #64748B; border-color: #273449; background: #172033; }
#TrustButton {
    background: #059669;
    color: #FFFFFF;
    border: none;
    border-radius: 10px;
    padding: 9px 16px;
    font-weight: 700;
}
#TrustButton:hover { background: #047857; }
#TrustButton:disabled { background: #334155; color: #94A3B8; }
#StatusLabel { color: #94A3B8; font-size: 12px; }
#ResultsCard, #DetailCard {
    background: #1B2433;
    border: 1px solid #2A3648;
    border-radius: 16px;
}
#CardTitle { font-size: 14px; font-weight: 700; color: #F8FAFC; }
#CardBadge { color: #94A3B8; font-size: 12px; }
QListWidget#ResultsList {
    background: transparent;
    border: none;
    outline: none;
}
QListWidget#ResultsList::item { background: transparent; border: none; }
#ResultItem {
    background: #172033;
    border: 1px solid #2A3648;
    border-radius: 10px;
}
#ResultItem:hover { background: #1E2A3D; border-color: #3B4B63; }
#ResultTitle { font-size: 13px; font-weight: 600; color: #F1F5F9; }
#ResultDetail { color: #94A3B8; font-size: 12px; }
#ResultMeta { color: #64748B; font-size: 11px; }
#DetailTarget { font-size: 15px; font-weight: 700; color: #F8FAFC; }
#DetailHint { color: #64748B; font-size: 12px; }
#EvidenceView {
    background: #111A2B;
    border: 1px solid #2A3648;
    border-radius: 10px;
    color: #CBD5E1;
    padding: 8px;
}
QTextBrowser { selection-background-color: #1E3A8A; }
QLabel#EmptyHint { color: #64748B; font-size: 13px; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #334155; border-radius: 5px; min-height: 24px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QCheckBox { color: #E5E7EB; spacing: 8px; }
QComboBox {
    background: #1B2433; border: 1px solid #334155; border-radius: 8px;
    padding: 5px 10px; min-width: 100px; color: #E5E7EB;
}
QComboBox QAbstractItemView { background: #1B2433; selection-background-color: #1E3A8A; }
QDialog QPushButton {
    background: #1E293B; color: #C7D2FE; border: 1px solid #334155;
    border-radius: 8px; padding: 7px 14px;
}
QDialog QPushButton:hover { background: #273449; }
QDialog QPushButton#PrimaryButton {
    background: #2563EB; color: #FFFFFF; border: none; font-weight: 700;
}
"""

THEME_QSS: dict[str, str] = {"light": LIGHT_QSS, "dark": DARK_QSS}

RING_COLORS: dict[str, tuple[str, str, str]] = {
    "light": ("#E2E8F0", "#2563EB", "#0F172A"),
    "dark": ("#273449", "#60A5FA", "#F8FAFC"),
}


# ---------------------------------------------------------------------------
# 自绘环形进度条
# ---------------------------------------------------------------------------


class RingProgress(QWidget):
    """QPainter 自绘的平滑环形进度条（0-100，带百分比文字与属性动画）。"""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._value = 0.0
        self._track_color = QColor(RING_COLORS["light"][0])
        self._arc_color = QColor(RING_COLORS["light"][1])
        self._text_color = QColor(RING_COLORS["light"][2])
        self._animation: QPropertyAnimation | None = None
        self.setFixedSize(QSize(60, 60))

    # -- Qt property（供 QPropertyAnimation 平滑驱动） --------------------
    def _get_value(self) -> float:
        return self._value

    def _set_value(self, value: float) -> None:
        self._value = max(0.0, min(100.0, float(value)))
        self.update()

    value = pyqtProperty(float, fget=_get_value, fset=_set_value)

    def set_colors(self, track: str, arc: str, text: str) -> None:
        self._track_color = QColor(track)
        self._arc_color = QColor(arc)
        self._text_color = QColor(text)
        self.update()

    def setValue(self, value: float, animate: bool = True) -> None:  # noqa: N802 - Qt 风格 API
        target = max(0.0, min(100.0, float(value)))
        if not animate:
            if self._animation is not None:
                self._animation.stop()
            self._set_value(target)
            return
        if self._animation is not None:
            self._animation.stop()
        animation = QPropertyAnimation(self, b"value", self)
        animation.setDuration(320)
        animation.setStartValue(self._value)
        animation.setEndValue(target)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        animation.start()
        self._animation = animation

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(6, 6, self.width() - 12, self.height() - 12)
        pen = QPen(self._track_color, 6)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, 0, 360 * 16)
        if self._value > 0:
            pen = QPen(self._arc_color, 6)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            span = int(-360 * 16 * (self._value / 100.0))
            painter.drawArc(rect, 90 * 16, span)
        painter.setPen(self._text_color)
        font = QFont(self.font())
        font.setPointSizeF(9.0)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{int(round(self._value))}%")
        painter.end()


# ---------------------------------------------------------------------------
# 统计卡片
# ---------------------------------------------------------------------------


class StatCard(QFrame):
    """5 个圆角统计卡之一：大号彩色数字 + 等级中文名。"""

    def __init__(self, severity: str, label: str, color: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.severity = severity
        self.setObjectName("StatCard")
        self.setMinimumHeight(86)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(2)
        self.number_label = QLabel("0")
        font = self.number_label.font()
        font.setPointSizeF(26.0)
        font.setBold(True)
        self.number_label.setFont(font)
        # 应用级 QSS 的 font-size 优先级高于 setFont，这里用控件内联样式确保"大号数字"
        self.number_label.setStyleSheet(
            f"color: {color}; background: transparent; font-size: 30px; font-weight: 800;"
        )
        self.name_label = QLabel(f"{label}  {severity}")
        self.name_label.setObjectName("StatLabel")
        layout.addWidget(self.number_label)
        layout.addWidget(self.name_label)

    def set_count(self, count: int) -> None:
        self.number_label.setText(str(max(0, int(count))))


# ---------------------------------------------------------------------------
# 结果列表项（自定义横幅 Widget）
# ---------------------------------------------------------------------------


class ResultItemWidget(QFrame):
    """结果列表的一行：4px 等级色块 + 状态 + 等级 + 摘要。"""

    def __init__(self, finding: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.finding = finding
        self.setObjectName("ResultItem")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 12, 8)
        layout.setSpacing(10)

        severity = str(finding.get("severity") or "").upper()
        color = SEVERITY_COLORS.get(severity, "#8A8886")
        bar = QFrame(self)
        bar.setFixedWidth(4)
        bar.setStyleSheet(f"background: {color}; border-radius: 2px;")
        layout.addWidget(bar)

        body = QVBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(2)
        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(8)

        severity_chip = QLabel(f"{SEVERITY_LABELS.get(severity, severity)} {severity}", self)
        severity_chip.setStyleSheet(
            f"background: {color}; color: #FFFFFF; border-radius: 6px;"
            "padding: 1px 8px; font-size: 11px; font-weight: 700;"
        )
        top.addWidget(severity_chip)

        diff_status = str(finding.get("diff_status") or "").upper()
        if diff_status and diff_status != "UNCHANGED":
            status_label = QLabel(diff_status, self)
            tag = ui_helpers.diff_status_tag(diff_status)
            style = ui_helpers.DIFF_TAG_STYLES.get(tag or "", {})
            css = ["font-size: 11px", "font-weight: 700", "padding: 1px 8px", "border-radius: 6px"]
            background = style.get("background")
            foreground = style.get("foreground")
            if diff_status == "BENIGN_UPDATE" and not style:
                background = "#059669"
                foreground = "#FFFFFF"
            if background:
                css.append(f"background: {background}")
            else:
                css.append("background: transparent")
            if foreground:
                css.append(f"color: {foreground}")
            if style.get("bold"):
                css[1] = "font-weight: 800"
            status_label.setStyleSheet("; ".join(css) + ";")
            if style.get("overstrike"):
                font = status_label.font()
                font.setStrikeOut(True)
                status_label.setFont(font)
            top.addWidget(status_label)

        rule_label = QLabel(str(finding.get("rule_id") or ""), self)
        rule_label.setObjectName("ResultMeta")
        top.addWidget(rule_label)
        top.addStretch(1)

        title = QLabel(truncate(finding.get("target", "") or "(无 target)", 92), self)
        title.setObjectName("ResultTitle")
        detail = QLabel(truncate(finding.get("detail", ""), 120), self)
        detail.setObjectName("ResultDetail")
        body.addLayout(top)
        body.addWidget(title)
        body.addWidget(detail)
        layout.addLayout(body, 1)


# ---------------------------------------------------------------------------
# 详情面板
# ---------------------------------------------------------------------------


class DetailPanel(QFrame):
    """右侧详情卡：target + evidence JSON + 复制/信任/修复建议按钮。"""

    copy_requested = pyqtSignal()
    trust_requested = pyqtSignal()
    remediation_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("DetailCard")
        self.setMinimumWidth(380)
        self._finding: dict[str, Any] | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        title = QLabel("详情", self)
        title.setObjectName("CardTitle")
        layout.addWidget(title)

        self.target_label = QLabel("尚未选择结果", self)
        self.target_label.setObjectName("DetailTarget")
        self.target_label.setWordWrap(True)
        self.target_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.target_label)

        meta_row = QHBoxLayout()
        meta_row.setContentsMargins(0, 0, 0, 0)
        meta_row.setSpacing(8)
        self.severity_label = QLabel("", self)
        self.status_label = QLabel("", self)
        self.rule_label = QLabel("", self)
        self.rule_label.setObjectName("DetailHint")
        meta_row.addWidget(self.severity_label)
        meta_row.addWidget(self.status_label)
        meta_row.addWidget(self.rule_label)
        meta_row.addStretch(1)
        layout.addLayout(meta_row)

        hint = QLabel("evidence", self)
        hint.setObjectName("DetailHint")
        layout.addWidget(hint)

        self.evidence_view = QTextBrowser(self)
        self.evidence_view.setObjectName("EvidenceView")
        self.evidence_view.setOpenExternalLinks(False)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setPointSizeF(9.5)
        self.evidence_view.setFont(mono)
        layout.addWidget(self.evidence_view, 1)

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.setSpacing(10)
        self.copy_button = QPushButton("复制详情", self)
        self.copy_button.setObjectName("SecondaryButton")
        self.copy_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.trust_button = QPushButton("信任此项", self)
        self.trust_button.setObjectName("TrustButton")
        self.trust_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.remediation_button = QPushButton("修复建议", self)
        self.remediation_button.setObjectName("SecondaryButton")
        self.remediation_button.setCursor(Qt.CursorShape.PointingHandCursor)
        buttons.addWidget(self.remediation_button)
        buttons.addWidget(self.copy_button)
        buttons.addWidget(self.trust_button)
        layout.addLayout(buttons)

        self.copy_button.clicked.connect(self.copy_requested.emit)
        self.trust_button.clicked.connect(self.trust_requested.emit)
        self.remediation_button.clicked.connect(self.remediation_requested.emit)
        self.set_finding(None)

    def set_finding(self, finding: dict[str, Any] | None) -> None:
        self._finding = finding if isinstance(finding, dict) else None
        if self._finding is None:
            self.target_label.setText("尚未选择结果")
            self.severity_label.clear()
            self.status_label.clear()
            self.rule_label.clear()
            self.evidence_view.setPlainText("")
            self.copy_button.setEnabled(False)
            self.trust_button.setEnabled(False)
            self.remediation_button.setEnabled(False)
            return
        finding = self._finding
        self.target_label.setText(_wrap_path_for_display(str(finding.get("target") or "(无 target)")))
        severity = str(finding.get("severity") or "").upper()
        color = SEVERITY_COLORS.get(severity, "#8A8886")
        self.severity_label.setText(f"{SEVERITY_LABELS.get(severity, severity)} {severity}")
        self.severity_label.setStyleSheet(
            f"background: {color}; color: #FFFFFF; border-radius: 6px;"
            "padding: 1px 8px; font-size: 11px; font-weight: 700;"
        )
        diff_status = str(finding.get("diff_status") or "").upper()
        if diff_status:
            self.status_label.setText(diff_status)
            self.status_label.setStyleSheet(
                f"color: {DIFF_STATUS_COLORS.get(diff_status, '#6B7280')};"
                "font-weight: 700; font-size: 12px;"
            )
        else:
            self.status_label.clear()
        self.rule_label.setText(str(finding.get("rule_id") or ""))
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        try:
            payload = json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True, default=str)
        except (TypeError, ValueError):
            payload = str(evidence)
        self.evidence_view.setPlainText(payload)
        self.copy_button.setEnabled(True)
        # RESOLVED 项不在当前机器上，禁用"信任"
        self.trust_button.setEnabled(diff_status != "RESOLVED")
        remediation = finding.get("remediation")
        self.remediation_button.setEnabled(isinstance(remediation, dict) and bool(remediation))

    @property
    def finding(self) -> dict[str, Any] | None:
        return self._finding

    def formatted_text(self) -> str:
        """用于剪贴板的完整详情文本。"""
        finding = self._finding
        if not finding:
            return ""
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        try:
            payload = json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True, default=str)
        except (TypeError, ValueError):
            payload = str(evidence)
        return (
            f"TamperScan {__version__}\n"
            f"Severity: {finding.get('severity')}\n"
            f"Rule: {finding.get('rule_id')}\n"
            f"Target: {finding.get('target')}\n"
            f"Detail: {finding.get('detail')}\n"
            f"Diff: {finding.get('diff_status') or '-'}\n"
            f"Evidence:\n{payload}"
        )


# ---------------------------------------------------------------------------
# 顶部标题栏（无边框拖拽 + 权限徽章 + 设置/最小化/关闭）
# ---------------------------------------------------------------------------


class TitleBar(QWidget):
    settings_requested = pyqtSignal()
    minimize_requested = pyqtSignal()
    close_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("TitleBar")
        self.setFixedHeight(62)
        self._drag_offset = None
        layout = QHBoxLayout(self)
        layout.setContentsMargins(22, 8, 16, 8)
        layout.setSpacing(10)

        logo = QLabel("🛡", self)
        logo.setStyleSheet("font-size: 20px; background: transparent;")
        layout.addWidget(logo)

        title = QLabel(APP_NAME, self)
        title.setObjectName("AppTitle")
        layout.addWidget(title)

        version = QLabel(f"v{__version__}", self)
        version.setObjectName("VersionLabel")
        layout.addWidget(version)
        layout.addStretch(1)

        role = "管理员" if is_admin() else "标准用户"
        self.role_badge = QLabel(role, self)
        self.role_badge.setObjectName("PermissionBadge")
        layout.addWidget(self.role_badge)

        self.settings_button = QToolButton(self)
        self.settings_button.setObjectName("IconButton")
        self.settings_button.setText("⚙")
        self.settings_button.setToolTip("设置")
        self.settings_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.settings_button.clicked.connect(self.settings_requested.emit)
        layout.addWidget(self.settings_button)

        self.minimize_button = QToolButton(self)
        self.minimize_button.setObjectName("WindowButton")
        self.minimize_button.setText("—")
        self.minimize_button.setToolTip("最小化")
        self.minimize_button.clicked.connect(self.minimize_requested.emit)
        layout.addWidget(self.minimize_button)

        self.close_button = QToolButton(self)
        self.close_button.setObjectName("WindowButton")
        self.close_button.setProperty("class", "close")
        self.close_button.setText("✕")
        self.close_button.setToolTip("关闭")
        self.close_button.clicked.connect(self.close_requested.emit)
        layout.addWidget(self.close_button)

    # -- 无边框拖拽 -------------------------------------------------------
    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_offset = event.globalPosition().toPoint() - self.window().frameGeometry().topLeft()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if self._drag_offset is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self.window().move(event.globalPosition().toPoint() - self._drag_offset)
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        self._drag_offset = None
        super().mouseReleaseEvent(event)


# ---------------------------------------------------------------------------
# 线程：扫描 / 更新检查
# ---------------------------------------------------------------------------


class ScanWorker(QThread):
    """在后台线程执行 ``core.scanner.run_scan``，进度/结果通过信号回主线程。"""

    progress = pyqtSignal(int, int, str)
    scan_finished = pyqtSignal(object)
    scan_failed = pyqtSignal(str)
    scan_cancelled = pyqtSignal()

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        memory_scan: bool = True,
        max_memory_scan: int = 10,
    ) -> None:
        super().__init__(parent)
        self.memory_scan = bool(memory_scan)
        self.max_memory_scan = int(max_memory_scan)
        self._cancel_seen = False

    def _on_progress(self, current: int, total: int, message: str) -> None:
        if self.isInterruptionRequested():
            self._cancel_seen = True
        self.progress.emit(int(current), int(total), str(message))

    def run(self) -> None:  # noqa: D401 - QThread 入口
        try:
            result = run_scan(
                progress_callback=self._on_progress,
                memory_scan=self.memory_scan,
                max_memory_scan=self.max_memory_scan,
            )
        except BaseException:  # noqa: BLE001 - 线程内任何异常都必须回报 UI
            self.scan_failed.emit(traceback.format_exc())
            return
        if self._cancel_seen or self.isInterruptionRequested():
            self.scan_cancelled.emit()
            return
        self.scan_finished.emit(result)


class UpdateWorker(QThread):
    """后台执行更新检查；``updater.check_for_update`` 本身不抛异常，这里再兜底一次。"""

    checked = pyqtSignal(object)

    def run(self) -> None:  # noqa: D401 - QThread 入口
        try:
            result = updater.check_for_update(__version__, config.load_config())
        except BaseException:  # noqa: BLE001 - 线程内异常降级为 error 结果
            result = updater.UpdateCheckResult(
                updater.STATUS_ERROR,
                __version__,
                error=f"更新检查失败：{traceback.format_exc().splitlines()[-1]}",
                error_kind="unknown",
            )
        self.checked.emit(result)


class CampaignWorker(QThread):
    """后台执行 ``core.correlator.correlate``，结果/异常通过信号回主线程。"""

    signal_finished = pyqtSignal(object)
    signal_failed = pyqtSignal(str)

    def __init__(self, findings: list[dict[str, Any]], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._findings = [item for item in findings if isinstance(item, dict)]

    def run(self) -> None:  # noqa: D401 - QThread 入口
        try:
            from core import correlator

            result = correlator.correlate(self._findings)
        except BaseException:  # noqa: BLE001 - 线程异常必须回报 UI
            self.signal_failed.emit(traceback.format_exc())
            return
        self.signal_finished.emit(result)


# ---------------------------------------------------------------------------
# 设置中心 / 更新提示 / 攻击链对话框
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 无边框 Fluent 子窗口（攻击链 / 修复建议）
# ---------------------------------------------------------------------------


def _app_icon() -> QIcon:
    """加载项目自带 icon.ico；缺失时返回空图标（不抛异常）。"""
    icon_path = BASE_DIR / "icon.ico"
    if icon_path.is_file():
        return QIcon(str(icon_path))
    return QIcon()


class DialogTitleBar(QWidget):
    """子窗口自定义标题栏：标题 + 关闭按钮 + 拖拽移动。"""

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("DialogTitleBar")
        self.setFixedHeight(46)
        self._drag_offset = None
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 8, 0)
        layout.setSpacing(8)
        self.title_label = QLabel(title, self)
        self.title_label.setObjectName("DialogTitle")
        layout.addWidget(self.title_label)
        layout.addStretch(1)
        self.close_button = QToolButton(self)
        self.close_button.setObjectName("DialogCloseButton")
        self.close_button.setText("✕")
        self.close_button.setToolTip("关闭")
        self.close_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.close_button.clicked.connect(self.window().close)
        layout.addWidget(self.close_button)

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_offset = event.globalPosition().toPoint() - self.window().frameGeometry().topLeft()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if self._drag_offset is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self.window().move(event.globalPosition().toPoint() - self._drag_offset)
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        self._drag_offset = None
        super().mouseReleaseEvent(event)


class FramelessDialog(QDialog):
    """Fluent 风格无边框子窗口基类：圆角卡片 + 阴影 + 自定义标题栏。"""

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("FramelessDialog")
        self.setWindowTitle(title)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setWindowIcon(_app_icon())

        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(0)
        self.root_card = QFrame(self)
        self.root_card.setObjectName("DialogCard")
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(36)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(0, 0, 0, 90))
        self.root_card.setGraphicsEffect(shadow)
        outer.addWidget(self.root_card)

        root_layout = QVBoxLayout(self.root_card)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.title_bar = DialogTitleBar(title, self.root_card)
        root_layout.addWidget(self.title_bar)

        body = QWidget(self.root_card)
        self.content_layout = QVBoxLayout(body)
        self.content_layout.setContentsMargins(18, 10, 18, 14)
        self.content_layout.setSpacing(10)
        root_layout.addWidget(body, 1)


class FluentMessageBox(FramelessDialog):
    """Fluent 风格消息框，替代原生 information/warning/critical/question 弹窗。"""

    _ICON_STYLES = {
        "information": ("i", "#2563EB", "#EFF6FF"),
        "warning": ("!", "#F7630C", "#FFF7ED"),
        "critical": ("×", "#D13438", "#FEF2F2"),
        "question": ("?", "#7C3AED", "#F5F3FF"),
    }

    def __init__(
        self,
        parent: QWidget | None = None,
        title: str = "提示",
        text: str = "",
        kind: str = "information",
    ) -> None:
        super().__init__(title, parent)
        self.kind = kind if kind in self._ICON_STYLES else "information"
        self.result_value = False
        self.resize(560, 260)
        layout = self.content_layout
        layout.setContentsMargins(22, 14, 22, 18)
        layout.setSpacing(14)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(14)
        symbol, color, background = self._ICON_STYLES[self.kind]
        icon_label = QLabel(symbol, self)
        icon_label.setFixedSize(42, 42)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet(
            f"background: {background}; color: {color}; border-radius: 21px;"
            "font-size: 22px; font-weight: 800;"
        )
        body.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)
        self.message_label = QLabel(text, self)
        self.message_label.setWordWrap(True)
        self.message_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.message_label.setObjectName("DialogMessage")
        body.addWidget(self.message_label, 1)
        layout.addLayout(body, 1)

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.setSpacing(9)
        buttons.addStretch(1)
        if self.kind == "question":
            self.no_button = QPushButton("否", self)
            self.no_button.setObjectName("SecondaryButton")
            self.no_button.clicked.connect(self._choose_no)
            buttons.addWidget(self.no_button)
            self.yes_button = QPushButton("是", self)
            self.yes_button.setObjectName("PrimaryButton")
            self.yes_button.clicked.connect(self._choose_yes)
            buttons.addWidget(self.yes_button)
        else:
            self.ok_button = QPushButton("确定", self)
            self.ok_button.setObjectName("PrimaryButton")
            self.ok_button.clicked.connect(self.accept)
            buttons.addWidget(self.ok_button)
        layout.addLayout(buttons)

    def _choose_yes(self) -> None:
        self.result_value = True
        self.accept()

    def _choose_no(self) -> None:
        self.result_value = False
        self.reject()

    @classmethod
    def information(cls, parent: QWidget | None, title: str, text: str) -> None:
        cls(parent, title, text, "information").exec()

    @classmethod
    def warning(cls, parent: QWidget | None, title: str, text: str) -> None:
        cls(parent, title, text, "warning").exec()

    @classmethod
    def critical(cls, parent: QWidget | None, title: str, text: str) -> None:
        cls(parent, title, text, "critical").exec()

    @classmethod
    def question(
        cls,
        parent: QWidget | None,
        title: str,
        text: str,
        *,
        default_yes: bool = False,
    ) -> bool:
        box = cls(parent, title, text, "question")
        box.no_button.setDefault(not default_yes)
        box.yes_button.setDefault(default_yes)
        box.exec()
        return box.result_value


class RemediationDialog(FramelessDialog):
    """只读修复建议子窗口（非模态）。"""

    def __init__(self, remediation: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__("修复建议", parent)
        self.resize(720, 480)
        layout = self.content_layout

        summary = QLabel(str(remediation.get("summary") or "无建议摘要"), self)
        summary.setObjectName("DetailTarget")
        summary.setWordWrap(True)
        layout.addWidget(summary)

        meta = QLabel(
            f"期望值：{remediation.get('expected') or '-'}\n当前值：{remediation.get('actual') or '-'}",
            self,
        )
        meta.setObjectName("DetailHint")
        meta.setWordWrap(True)
        layout.addWidget(meta)

        risk = str(remediation.get("risk") or "UNKNOWN").upper()
        risk_colors = {"HIGH": "#D13438", "MEDIUM": "#F7630C", "LOW": "#C19C00", "INFO": "#0078D4"}
        risk_label = QLabel(
            f"风险等级：{risk} ｜ 需要管理员：{'是' if remediation.get('requires_admin') else '否'}",
            self,
        )
        risk_label.setStyleSheet(
            f"color: {risk_colors.get(risk, '#8A8886')}; font-weight: 700; background: transparent;"
        )
        layout.addWidget(risk_label)

        hint = QLabel("以下命令仅供手动复制执行，TamperScan 不会自动运行：", self)
        hint.setObjectName("DetailHint")
        layout.addWidget(hint)
        self.command_view = QTextBrowser(self)
        self.command_view.setObjectName("EvidenceView")
        self.command_view.setPlainText(str(remediation.get("command") or "（本规则未提供命令）"))
        layout.addWidget(self.command_view, 1)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        close_button = QPushButton("关闭", self)
        close_button.setObjectName("SecondaryButton")
        close_button.clicked.connect(self.close)
        buttons.addWidget(close_button)
        layout.addLayout(buttons)


class CampaignDialog(FramelessDialog):
    """攻击链视图：campaign 列表 + 选中行步骤时间线。"""

    def __init__(
        self,
        campaigns: list[dict[str, Any]],
        stats: dict[str, Any] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__("攻击链", parent)
        self.setWindowTitle("攻击链")
        self.resize(900, 600)
        self.campaigns = [item for item in campaigns if isinstance(item, dict)]
        self.stats = dict(stats) if isinstance(stats, dict) else {}
        self._details_dialog: FramelessDialog | None = None

        layout = self.content_layout
        layout.setContentsMargins(18, 10, 18, 14)

        self.title_label = QLabel("攻击链（固定剧本关联，绝无自由组合）", self)
        self.title_label.setObjectName("CardTitle")
        layout.addWidget(self.title_label)

        self.campaign_table = QTableWidget(0, 5, self)
        self.campaign_table.setHorizontalHeaderLabels(["攻击链名称", "置信度", "步骤数", "Finding 数", "状态"])
        self.campaign_table.verticalHeader().setVisible(False)
        self.campaign_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.campaign_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.campaign_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.campaign_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.campaign_table, 3)

        self.empty_label = QLabel(ui_helpers.CAMPAIGN_EMPTY_TEXT, self)
        self.empty_label.setObjectName("EmptyHint")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setWordWrap(True)
        self.empty_label.hide()
        layout.addWidget(self.empty_label, 3)

        steps_title = QLabel("步骤时间线", self)
        steps_title.setObjectName("CardTitle")
        layout.addWidget(steps_title)
        self.steps_table = QTableWidget(0, 4, self)
        self.steps_table.setHorizontalHeaderLabels(["#", "战术", "规则", "目标"])
        self.steps_table.verticalHeader().setVisible(False)
        self.steps_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.steps_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.steps_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.steps_table, 2)

        bottom = QHBoxLayout()
        bottom.setContentsMargins(0, 0, 0, 0)
        bottom.setSpacing(10)
        self.stats_label = QLabel(self._stats_text(), self)
        self.stats_label.setObjectName("DetailHint")
        bottom.addWidget(self.stats_label)
        bottom.addStretch(1)
        close_button = QPushButton("关闭", self)
        close_button.setObjectName("SecondaryButton")
        close_button.clicked.connect(self.accept)
        bottom.addWidget(close_button)
        layout.addLayout(bottom)

        self._populate_campaigns()
        self.campaign_table.currentCellChanged.connect(self._on_current_campaign_changed)
        self.campaign_table.cellDoubleClicked.connect(self._on_campaign_double_clicked)
        if self.campaigns:
            self.campaign_table.setCurrentCell(0, 0)

    def _stats_text(self) -> str:
        if not self.stats:
            return ""
        return (
            f"Finding {self.stats.get('findings', '-')} ｜ 聚类 {self.stats.get('clusters', '-')}"
            f" ｜ 攻击链 {self.stats.get('campaigns', '-')} ｜ 抑制 {self.stats.get('suppressed', '-')}"
        )

    def _populate_campaigns(self) -> None:
        self.campaign_table.setRowCount(0)
        if not self.campaigns:
            self.campaign_table.hide()
            self.empty_label.show()
            return
        self.empty_label.hide()
        self.campaign_table.show()
        self.campaign_table.setRowCount(len(self.campaigns))
        for row, campaign in enumerate(self.campaigns):
            name, label, steps, findings = ui_helpers.campaign_row_values(campaign)
            status = "影子模式" if campaign.get("shadow") else "正常"
            values = (name, label, steps, findings, status)
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 1:
                    color = ui_helpers.CAMPAIGN_CONFIDENCE_COLORS.get(
                        str(campaign.get("confidence") or "").strip().lower()
                    )
                    if color:
                        item.setForeground(QColor(color))
                self.campaign_table.setItem(row, column, item)

    def _on_current_campaign_changed(self, current_row: int, *args: Any) -> None:
        if 0 <= current_row < len(self.campaigns):
            self._populate_steps(self.campaigns[current_row])

    def _populate_steps(self, campaign: dict[str, Any]) -> None:
        rows = ui_helpers.campaign_step_rows(campaign)
        self.steps_table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                self.steps_table.setItem(row, column, QTableWidgetItem(str(value)))

    def _on_campaign_double_clicked(self, row: int, column: int) -> None:
        if not (0 <= row < len(self.campaigns)):
            return
        campaign = self.campaigns[row]
        if self._details_dialog is not None:
            self._details_dialog.close()
        detail = FramelessDialog("攻击链详情", self)
        detail.resize(720, 480)
        detail_layout = detail.content_layout
        browser = QTextBrowser(detail)
        browser.setObjectName("EvidenceView")
        lines = [ui_helpers.campaign_summary_text(campaign), ""]
        for index, (step_no, tactic, rules, targets) in enumerate(ui_helpers.campaign_step_rows(campaign), start=1):
            lines.append(f"{step_no}. 战术 {tactic or '-'} ｜ 规则 {rules or '-'}")
            if targets:
                lines.append(f"   目标：{targets}")
        browser.setPlainText("\n".join(lines))
        detail_layout.addWidget(browser, 1)
        close_button = QPushButton("关闭", detail)
        close_button.setObjectName("SecondaryButton")
        close_button.clicked.connect(detail.close)
        detail_layout.addWidget(close_button)
        self._details_dialog = detail
        detail.finished.connect(lambda *_: setattr(self, "_details_dialog", None))
        detail.show()


class SettingsDialog(FramelessDialog):
    """设置中心：自动检查更新、主题、清空信任名单、导出暂存上报队列。"""

    theme_changed = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("TamperScan 设置", parent)
        self.setModal(True)
        self.setMinimumWidth(460)
        self._config = config.load_config()
        layout = self.content_layout
        layout.setContentsMargins(22, 8, 22, 20)
        layout.setSpacing(14)

        title = QLabel("设置", self)
        title.setObjectName("CardTitle")
        layout.addWidget(title)

        self.auto_check = QCheckBox("启动时自动检查更新", self)
        self.auto_check.setChecked(config.is_auto_check_enabled(self._config))
        self.auto_check.toggled.connect(self._on_auto_check_toggled)
        layout.addWidget(self.auto_check)

        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("界面主题", self))
        self.theme_combo = QComboBox(self)
        self.theme_combo.addItem("浅色", "light")
        self.theme_combo.addItem("暗黑", "dark")
        current_theme = config.get_theme(self._config)
        self.theme_combo.setCurrentIndex(1 if current_theme == "dark" else 0)
        self.theme_combo.currentIndexChanged.connect(self._on_theme_changed)
        theme_row.addWidget(self.theme_combo, 1)
        layout.addLayout(theme_row)

        self.trust_count_label = QLabel(self)
        self.trust_count_label.setObjectName("DetailHint")
        layout.addWidget(self.trust_count_label)
        self._refresh_trust_count()

        trust_row = QHBoxLayout()
        self.clear_trust_button = QPushButton("清空本地信任名单", self)
        self.clear_trust_button.setObjectName("SecondaryButton")
        self.clear_trust_button.clicked.connect(self._on_clear_trust)
        trust_row.addWidget(self.clear_trust_button)

        self.pending_button = QPushButton("导出暂存的上报报告", self)
        self.pending_button.setObjectName("SecondaryButton")
        self.pending_button.clicked.connect(self._on_export_pending)
        trust_row.addWidget(self.pending_button)
        trust_row.addStretch(1)
        layout.addLayout(trust_row)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        close_button = QPushButton("关闭", self)
        close_button.setObjectName("PrimaryButton")
        close_button.clicked.connect(self.accept)
        buttons.addWidget(close_button)
        layout.addLayout(buttons)

    # -- 槽 ---------------------------------------------------------------
    def _on_auto_check_toggled(self, checked: bool) -> None:
        config.set_auto_check(bool(checked))

    def _on_theme_changed(self, index: int) -> None:
        theme = str(self.theme_combo.itemData(index) or "light")
        if config.set_theme(theme):
            self.theme_changed.emit(theme)

    def _refresh_trust_count(self) -> None:
        count = len(config.load_trust_entries(self._config))
        self.trust_count_label.setText(f"本地信任名单：{count} 条（联合指纹，默认 90 天过期）")

    def _on_clear_trust(self) -> None:
        if not FluentMessageBox.question(
            self,
            "清空信任名单",
            "确定清空全部本地信任名单吗？此操作不可撤销。",
            default_yes=False,
        ):
            return
        if config.clear_trust_entries():
            self._config = config.load_config()
            self._refresh_trust_count()
            FluentMessageBox.information(self, "已清空", "本地信任名单已清空。")
        else:
            FluentMessageBox.warning(self, "操作失败", "清空信任名单失败（配置文件可能被占用）。")

    def _on_export_pending(self) -> None:
        reports = config.load_pending_reports()
        if not reports:
            FluentMessageBox.information(self, "导出暂存上报", "暂无暂存的上报报告。")
            return
        default_path = Path.home() / f"tamper_scan_pending_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(
            self, "导出暂存的上报报告", str(default_path), "JSON (*.json)"
        )
        if not path:
            return
        written = config.export_pending_reports(path)
        if not written:
            FluentMessageBox.warning(self, "导出失败", "暂存报告导出失败（队列为空或目标不可写）。")
            return
        FluentMessageBox.information(self, "导出完成", f"暂存上报已导出：\n{written}")


class UpdateDialog(FramelessDialog):
    """发现新版本提示（前往下载 / 暂不更新 / 不再提示）。"""

    ACTION_DOWNLOAD = "download"
    ACTION_LATER = "later"
    ACTION_NEVER = "never"

    def __init__(self, result: updater.UpdateCheckResult, parent: QWidget | None = None) -> None:
        super().__init__("发现新版本", parent)
        self.setModal(True)
        self.setMinimumWidth(520)
        self.action = self.ACTION_LATER
        self.release_url = result.release_url or updater.RELEASES_PAGE
        self.download_url = result.download_url or self.release_url

        layout = self.content_layout
        layout.setContentsMargins(22, 8, 22, 20)
        layout.setSpacing(12)

        title = QLabel(f"发现新版本 {result.latest_version}（当前 {result.current_version}）", self)
        title.setObjectName("CardTitle")
        title.setWordWrap(True)
        layout.addWidget(title)

        notes = QTextBrowser(self)
        notes.setObjectName("EvidenceView")
        notes.setMinimumHeight(180)
        notes.setPlainText(result.notes or "本次更新暂无详细说明。")
        layout.addWidget(notes, 1)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        later = QPushButton("暂不更新", self)
        later.setObjectName("SecondaryButton")
        later.clicked.connect(self._choose_later)
        never = QPushButton("不再提示", self)
        never.setObjectName("SecondaryButton")
        never.clicked.connect(self._choose_never)
        download = QPushButton("前往下载", self)
        download.setObjectName("PrimaryButton")
        download.clicked.connect(self._choose_download)
        buttons.addWidget(later)
        buttons.addWidget(never)
        buttons.addWidget(download)
        layout.addLayout(buttons)

    def _choose_download(self) -> None:
        self.action = self.ACTION_DOWNLOAD
        self.accept()

    def _choose_later(self) -> None:
        self.action = self.ACTION_LATER
        self.accept()

    def _choose_never(self) -> None:
        self.action = self.ACTION_NEVER
        self.accept()


# ---------------------------------------------------------------------------
# 主窗口
# ---------------------------------------------------------------------------


class MainWindow(QMainWindow):
    """TamperScan 主窗口（无边框 + 卡片式布局）。"""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        start_update_check: bool = True,
        memory_scan: bool = True,
        max_memory_scan: int = 10,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{APP_NAME} {__version__}")
        self.setWindowIcon(_app_icon())
        self.setWindowFlags(self.windowFlags() | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setMinimumSize(1180, 760)

        self.memory_scan = memory_scan
        self.max_memory_scan = max_memory_scan
        self._findings: list[dict[str, Any]] = []
        self._current_duration = 0.0
        self._result: Any = None
        self._scan_worker: ScanWorker | None = None
        self._update_worker: UpdateWorker | None = None
        self._campaign_worker: CampaignWorker | None = None
        self._campaign_dialog: CampaignDialog | None = None
        self._remediation_dialog: RemediationDialog | None = None
        self._cancel_requested = False
        self._has_scanned = False
        self._baseline_path = ""
        self._theme = config.get_theme()
        self._baseline_diff: baseline.BaselineDiff | None = None

        self._build_ui()
        self.apply_theme(self._theme)

        if start_update_check and config.is_auto_check_enabled():
            QTimer.singleShot(int(updater.STARTUP_CHECK_DELAY_MS), self._start_update_check)

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        container = QWidget(self)
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(18, 18, 18, 18)
        container_layout.setSpacing(0)

        self.root_card = QFrame(container)
        self.root_card.setObjectName("RootCard")
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(42)
        shadow.setOffset(0, 10)
        shadow.setColor(QColor(0, 0, 0, 90))
        self.root_card.setGraphicsEffect(shadow)

        root_layout = QVBoxLayout(self.root_card)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        self.title_bar = TitleBar(self.root_card)
        self.title_bar.settings_requested.connect(self._open_settings)
        self.title_bar.minimize_requested.connect(self.showMinimized)
        self.title_bar.close_requested.connect(self.close)
        root_layout.addWidget(self.title_bar)

        content = QWidget(self.root_card)
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(20, 6, 20, 10)
        content_layout.setSpacing(18)

        left_column = QVBoxLayout()
        left_column.setContentsMargins(0, 0, 0, 0)
        left_column.setSpacing(14)

        # 统计卡片区
        stats_row = QHBoxLayout()
        stats_row.setContentsMargins(0, 0, 0, 0)
        stats_row.setSpacing(12)
        self.stat_cards: dict[str, StatCard] = {}
        for severity in SEVERITIES:
            card = StatCard(
                severity,
                SEVERITY_LABELS[severity],
                SEVERITY_COLORS[severity],
                content,
            )
            self.stat_cards[severity] = card
            stats_row.addWidget(card, 1)
        left_column.addLayout(stats_row)

        # 控制栏：第一行（扫描 + 环 + 状态），第二行（基线 / 导出 / 攻击链）
        control = QFrame(content)
        control.setObjectName("ControlBar")
        control_layout = QVBoxLayout(control)
        control_layout.setContentsMargins(18, 14, 18, 14)
        control_layout.setSpacing(9)

        primary_row = QHBoxLayout()
        primary_row.setContentsMargins(0, 0, 0, 0)
        primary_row.setSpacing(18)

        self.scan_button = QPushButton("开始扫描", control)
        self.scan_button.setObjectName("ScanButton")
        self.scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_button.setMinimumWidth(160)
        self.scan_button.clicked.connect(self._on_scan_clicked)
        primary_row.addWidget(self.scan_button)

        self.ring = RingProgress(control)
        primary_row.addWidget(self.ring)

        status_column = QVBoxLayout()
        status_column.setContentsMargins(0, 0, 0, 0)
        status_column.setSpacing(2)
        self.status_label = QLabel("就绪 · 点击开始扫描", control)
        self.status_label.setObjectName("StatusLabel")
        self.status_label.setMinimumWidth(160)
        self.progress_hint = QLabel("", control)
        self.progress_hint.setObjectName("DetailHint")
        status_column.addStretch(1)
        status_column.addWidget(self.status_label)
        status_column.addWidget(self.progress_hint)
        status_column.addStretch(1)
        primary_row.addLayout(status_column, 1)
        control_layout.addLayout(primary_row)

        secondary_row = QHBoxLayout()
        secondary_row.setContentsMargins(0, 0, 0, 0)
        secondary_row.setSpacing(9)
        secondary_row.addStretch(1)
        self.baseline_button = QPushButton("对比基线", control)
        self.baseline_button.setObjectName("SecondaryButton")
        self.baseline_button.clicked.connect(self._on_compare_baseline)
        secondary_row.addWidget(self.baseline_button)

        self.save_baseline_button = QPushButton("保存为基线", control)
        self.save_baseline_button.setObjectName("SecondaryButton")
        self.save_baseline_button.clicked.connect(self._on_save_baseline)
        secondary_row.addWidget(self.save_baseline_button)

        self.export_button = QPushButton("导出报告", control)
        self.export_button.setObjectName("SecondaryButton")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._on_export_report)
        secondary_row.addWidget(self.export_button)

        self.campaign_button = QPushButton("攻击链", control)
        self.campaign_button.setObjectName("SecondaryButton")
        self.campaign_button.clicked.connect(self._on_show_campaigns)
        secondary_row.addWidget(self.campaign_button)
        control_layout.addLayout(secondary_row)
        left_column.addWidget(control)

        # 结果列表
        results_card = QFrame(content)
        results_card.setObjectName("ResultsCard")
        results_layout = QVBoxLayout(results_card)
        results_layout.setContentsMargins(18, 14, 18, 14)
        results_layout.setSpacing(8)
        results_header = QHBoxLayout()
        results_header.setContentsMargins(0, 0, 0, 0)
        results_title = QLabel("扫描结果", results_card)
        results_title.setObjectName("CardTitle")
        self.results_badge = QLabel("0 项", results_card)
        self.results_badge.setObjectName("CardBadge")
        results_header.addWidget(results_title)
        results_header.addWidget(self.results_badge)
        results_header.addStretch(1)
        results_layout.addLayout(results_header)

        self.results_list = QListWidget(results_card)
        self.results_list.setObjectName("ResultsList")
        self.results_list.setSpacing(7)
        self.results_list.setVerticalScrollMode(QListWidget.ScrollMode.ScrollPerPixel)
        self.results_list.currentRowChanged.connect(self._on_current_row_changed)
        results_layout.addWidget(self.results_list, 1)
        left_column.addWidget(results_card, 1)

        content_layout.addLayout(left_column, 3)

        self.detail_panel = DetailPanel(content)
        self.detail_panel.copy_requested.connect(self._on_copy_detail)
        self.detail_panel.trust_requested.connect(self._on_trust_finding)
        self.detail_panel.remediation_requested.connect(self._on_show_remediation)
        content_layout.addWidget(self.detail_panel, 2)
        root_layout.addWidget(content, 1)

        bottom = QWidget(self.root_card)
        bottom_layout = QHBoxLayout(bottom)
        bottom_layout.setContentsMargins(24, 2, 8, 4)
        bottom_layout.setSpacing(6)
        self.footer_label = QLabel(f"TamperScan v{__version__} · 只读扫描 · 不上传原始文件", bottom)
        self.footer_label.setObjectName("DetailHint")
        bottom_layout.addWidget(self.footer_label)
        bottom_layout.addStretch(1)
        self.size_grip = QSizeGrip(bottom)
        bottom_layout.addWidget(self.size_grip)
        root_layout.addWidget(bottom)

        container_layout.addWidget(self.root_card)
        self.setCentralWidget(container)

    # ------------------------------------------------------------------
    # 主题
    # ------------------------------------------------------------------
    def apply_theme(self, theme: str) -> None:
        """应用浅色/暗黑主题（同时刷新自绘控件颜色）。"""
        normalized = theme if theme in THEME_QSS else "light"
        self._theme = normalized
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(THEME_QSS[normalized])
        self.ring.set_colors(*RING_COLORS[normalized])

    @property
    def theme(self) -> str:
        return self._theme

    # ------------------------------------------------------------------
    # 扫描
    # ------------------------------------------------------------------
    def _on_scan_clicked(self) -> None:
        worker = self._scan_worker
        if worker is not None and worker.isRunning():
            self._cancel_requested = True
            worker.requestInterruption()
            self.status_label.setText("正在取消扫描（等待当前模块结束）…")
            self.scan_button.setEnabled(False)
            return
        self.start_scan()

    def start_scan(self) -> None:
        """启动后台扫描（QThread）。"""
        self._cancel_requested = False
        self._baseline_diff = None
        self._set_busy(True)
        self.ring.setValue(0, animate=False)
        self.progress_hint.setText("")
        self.status_label.setText("正在扫描…")
        worker = ScanWorker(
            self,
            memory_scan=self.memory_scan,
            max_memory_scan=self.max_memory_scan,
        )
        worker.progress.connect(self._on_scan_progress)
        worker.scan_finished.connect(self._on_scan_finished)
        worker.scan_failed.connect(self._on_scan_failed)
        worker.scan_cancelled.connect(self._on_scan_cancelled)
        self._scan_worker = worker
        worker.start()

    def _set_busy(self, busy: bool) -> None:
        self.scan_button.setProperty("busy", "true" if busy else "false")
        self.scan_button.style().unpolish(self.scan_button)
        self.scan_button.style().polish(self.scan_button)
        self.scan_button.setText("取消扫描" if busy else "开始扫描")
        self.scan_button.setEnabled(True)
        self.baseline_button.setEnabled(not busy)
        self.save_baseline_button.setEnabled(not busy)
        self.export_button.setEnabled((not busy) and self._has_scanned)
        self.campaign_button.setEnabled(not busy)

    @pyqtSlot(int, int, str)
    def _on_scan_progress(self, current: int, total: int, message: str) -> None:
        percent = (float(current) / float(total) * 100.0) if total else 0.0
        self.ring.setValue(percent)
        self.progress_hint.setText(f"{current}/{total}")
        if message:
            self.status_label.setText(message)

    @pyqtSlot(object)
    def _on_scan_finished(self, result: Any) -> None:
        self._set_busy(False)
        self.ring.setValue(100)
        if self._cancel_requested:
            self._on_scan_cancelled()
            return
        findings = getattr(result, "findings", None)
        if not isinstance(findings, list):
            self._on_scan_failed("扫描结果结构异常：缺少 findings 列表")
            return
        self._result = result
        self._has_scanned = True
        duration = float(getattr(result, "duration", 0.0) or 0.0)
        self._display_findings(findings, duration)
        self.export_button.setEnabled(True)
        if self._scan_worker is not None:
            self._scan_worker.deleteLater()
        self._scan_worker = None

    @pyqtSlot()
    def _on_scan_cancelled(self) -> None:
        self._set_busy(False)
        self.ring.setValue(0)
        self.status_label.setText("已取消本次扫描")
        self.progress_hint.setText("")
        if self._scan_worker is not None:
            self._scan_worker.deleteLater()
        self._scan_worker = None

    @pyqtSlot(str)
    def _on_scan_failed(self, error: str) -> None:
        self._set_busy(False)
        self.ring.setValue(0)
        self.status_label.setText("扫描失败（本地扫描核心仍可用）")
        self.progress_hint.setText("")
        FluentMessageBox.critical(self, "扫描失败", f"扫描过程中出现异常：\n\n{error[-1800:]}")
        if self._scan_worker is not None:
            self._scan_worker.deleteLater()
        self._scan_worker = None

    # ------------------------------------------------------------------
    # 攻击链（QThread + QDialog）
    # ------------------------------------------------------------------
    @pyqtSlot()
    def _on_show_campaigns(self) -> None:
        if self._result is None:
            FluentMessageBox.information(self, "攻击链", "请先完成一次扫描")
            return
        findings = getattr(self._result, "findings", None)
        if not isinstance(findings, list):
            findings = list(self._findings)
        self.campaign_button.setEnabled(False)
        worker = CampaignWorker(findings, self)
        worker.signal_finished.connect(self._on_campaign_finished)
        worker.signal_failed.connect(self._on_campaign_failed)
        self._campaign_worker = worker
        worker.start()

    @pyqtSlot(object)
    def _on_campaign_finished(self, result: Any) -> None:
        self.campaign_button.setEnabled(True)
        if self._campaign_worker is not None:
            self._campaign_worker.deleteLater()
        self._campaign_worker = None
        if not isinstance(result, dict):
            FluentMessageBox.warning(self, "攻击链分析失败", "关联引擎返回结构异常（应为 dict）。")
            return
        campaigns = result.get("campaigns") if isinstance(result.get("campaigns"), list) else []
        stats = result.get("stats") if isinstance(result.get("stats"), dict) else {}
        if self._campaign_dialog is not None:
            self._campaign_dialog.close()
        dialog = CampaignDialog(campaigns, stats, self)
        self._campaign_dialog = dialog
        dialog.finished.connect(self._on_campaign_dialog_closed)
        dialog.setModal(False)
        dialog.show()

    @pyqtSlot(int)
    def _on_campaign_dialog_closed(self, _result: int = 0) -> None:
        self._campaign_dialog = None

    @pyqtSlot(str)
    def _on_campaign_failed(self, error: str) -> None:
        self.campaign_button.setEnabled(True)
        if self._campaign_worker is not None:
            self._campaign_worker.deleteLater()
        self._campaign_worker = None
        FluentMessageBox.warning(self, "攻击链分析失败", str(error)[:2000])

    # ------------------------------------------------------------------
    # 结果渲染 / 详情
    # ------------------------------------------------------------------
    def _display_findings(self, findings: list[dict[str, Any]], duration: float = 0.0) -> None:
        """把 Finding 列表渲染到统计卡 + 结果列表（主线程调用）。"""
        findings = reporter.apply_remediation([item for item in findings if isinstance(item, dict)])
        self._findings = list(findings)
        self._current_duration = float(duration)
        counts = severity_counts(self._findings)
        for severity, card in self.stat_cards.items():
            card.set_count(counts.get(severity, 0))
        self.results_list.clear()
        for finding in self._findings:
            item = QListWidgetItem(self.results_list)
            widget = ResultItemWidget(finding, self.results_list)
            item.setSizeHint(QSize(0, 64))
            item.setData(Qt.ItemDataRole.UserRole, finding)
            self.results_list.addItem(item)
            self.results_list.setItemWidget(item, widget)
        self.results_badge.setText(f"{len(self._findings)} 项")
        if self._findings:
            self.results_list.setCurrentRow(0)
            self.status_label.setText(
                f"扫描完成：{len(self._findings)} 个 Finding，耗时 {self._current_duration:.2f}s"
            )
        else:
            self.detail_panel.set_finding(None)
            self.status_label.setText("扫描完成：未发现可疑项")
        self.ring.setValue(100, animate=False)

    def _selected_finding(self) -> dict[str, Any] | None:
        item = self.results_list.currentItem()
        if item is None:
            return None
        finding = item.data(Qt.ItemDataRole.UserRole)
        return finding if isinstance(finding, dict) else None

    @pyqtSlot(int)
    def _on_current_row_changed(self, row: int) -> None:
        self.detail_panel.set_finding(self._selected_finding())

    @pyqtSlot()
    def _on_copy_detail(self) -> None:
        text = self.detail_panel.formatted_text()
        if not text:
            return
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)
        self.status_label.setText("详情已复制到剪贴板")

    @pyqtSlot()
    def _on_trust_finding(self) -> None:
        finding = self.detail_panel.finding
        if not finding:
            return
        try:
            entry = whitelist.build_trust_entry(finding, expire_days=config.DEFAULT_TRUST_EXPIRE_DAYS)
        except ValueError as exc:
            FluentMessageBox.warning(self, "无法信任此项", str(exc))
            return
        saved = config.add_trust_entry(entry)
        if saved is None:
            FluentMessageBox.warning(self, "保存失败", "信任名单写入失败（配置文件可能被占用）。")
            return
        if self._ask_anonymous_report():
            if config.append_pending_report(self._build_anonymous_report(finding)):
                self.status_label.setText("已加入白名单；匿名上报已暂存本地，稍后发送")
            else:
                self.status_label.setText("已加入白名单；匿名上报暂存失败（网络不佳，已跳过）")
        else:
            self.status_label.setText("已加入本地白名单")
        self.detail_panel.set_finding(finding)

    def _ask_anonymous_report(self) -> bool:
        """询问是否匿名上报（独立方法便于 GUI 测试注入）。"""
        message = (
            "已加入本地白名单（联合指纹：规则 + 签名者 + 精确路径，默认 90 天过期）。\n\n"
            "是否匿名上报至社区帮助改进？（不会上传原始文件或完整路径）"
        )
        return FluentMessageBox.question(
            self,
            "信任此项",
            message,
            default_yes=False,
        )

    @pyqtSlot()
    def _on_show_remediation(self) -> None:
        finding = self.detail_panel.finding
        if not isinstance(finding, dict):
            return
        remediation = finding.get("remediation")
        if not isinstance(remediation, dict) or not remediation:
            return
        if self._remediation_dialog is not None:
            self._remediation_dialog.close()
        dialog = self._make_remediation_dialog(remediation)
        self._remediation_dialog = dialog
        dialog.finished.connect(self._on_remediation_dialog_closed)
        dialog.setModal(False)
        dialog.show()

    @pyqtSlot(int)
    def _on_remediation_dialog_closed(self, _result: int = 0) -> None:
        self._remediation_dialog = None

    def _make_remediation_dialog(self, remediation: dict[str, Any]) -> RemediationDialog:
        """构造只读修复建议子窗口（便于测试直接检查内容）。"""
        return RemediationDialog(remediation, self)

    @staticmethod
    def _build_anonymous_report(finding: dict[str, Any]) -> dict[str, Any]:
        """构造已脱敏的匿名上报载荷（无用户名、无完整路径、无原始文件）。"""
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        signature = evidence.get("signature") if isinstance(evidence.get("signature"), dict) else {}
        target = str(finding.get("target") or "")
        target_name = os.path.basename(target.replace("/", os.sep)) if target else ""
        return {
            "tool": APP_NAME,
            "version": __version__,
            "reported_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "rule_id": finding.get("rule_id") or "",
            "severity": finding.get("severity") or "",
            "category": finding.get("category") or "",
            "target_name": target_name[:120],
            "signer": str(signature.get("signer") or evidence.get("signer") or "")[:200],
            "detail": _anonymize_text(str(finding.get("detail") or ""))[:500],
            "evidence_keys": sorted(str(key) for key in evidence),
        }

    # ------------------------------------------------------------------
    # 基线对比 / 保存
    # ------------------------------------------------------------------
    def _current_report(self) -> dict[str, Any]:
        modules = getattr(self._result, "module_status", []) if self._result is not None else []
        return reporter.build_report(
            self._findings,
            version=__version__,
            duration_seconds=self._current_duration,
            modules=modules if isinstance(modules, list) else [],
        )

    @pyqtSlot()
    def _on_compare_baseline(self) -> None:
        if not self._findings:
            FluentMessageBox.information(self, "对比基线", "请先执行一次扫描，再选择基线文件。")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "选择基线报告", str(Path.home()), "JSON 报告 (*.json);;所有文件 (*)"
        )
        if not path:
            return
        baseline_report, error = _load_baseline_report(path)
        if error:
            FluentMessageBox.warning(self, "基线无效", error)
            return
        current_report = self._current_report()
        assert baseline_report is not None
        diff = baseline.diff_reports(baseline_report, current_report, baseline_path=path)
        annotated = baseline.annotate_findings(self._findings, diff)
        self._baseline_diff = diff
        counts = baseline.diff_counts(diff)
        self._display_findings(annotated, self._current_duration)
        self._baseline_path = path
        changed = "  ".join(f"{status}: {counts[status]}" for status in baseline.DIFF_STATUSES)
        self.status_label.setText(f"基线对比完成（{Path(path).name}）：{changed}")

    @pyqtSlot()
    def _on_save_baseline(self) -> None:
        if not self._findings:
            FluentMessageBox.information(self, "保存基线", "请先执行一次扫描，再保存为基线。")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "保存为基线",
            str(Path.home() / "tamper_scan_baseline.json"),
            "JSON (*.json)",
        )
        if not path:
            return
        try:
            written = reporter.write_json(self._current_report(), path)
        except Exception as exc:  # noqa: BLE001 - 保存失败不能影响主界面
            FluentMessageBox.warning(self, "保存失败", f"{type(exc).__name__}: {exc}")
            return
        self.status_label.setText(f"基线已保存：{written}")

    @pyqtSlot()
    def _on_export_report(self) -> None:
        """导出当前结果为 HTML/JSON（未扫描时按钮禁用）。"""
        if not self._has_scanned:
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path, selected = QFileDialog.getSaveFileName(
            self,
            "导出报告",
            str(Path.home() / f"tamper_scan_report_{stamp}.html"),
            "HTML 报告 (*.html);;JSON 报告 (*.json)",
        )
        if not path:
            return
        suffix = Path(path).suffix.lower()
        if suffix in (".html", ".htm"):
            output_format = "html"
        elif suffix == ".json":
            output_format = "json"
        else:
            output_format = "json" if "JSON" in str(selected) else "html"
            path += ".json" if output_format == "json" else ".html"
        report = self._current_report()
        if self._baseline_diff is not None:
            report = reporter.apply_baseline_diff(
                report, self._baseline_diff, baseline_path=self._baseline_path
            )
        try:
            if output_format == "json":
                written = reporter.write_json(report, path)
            else:
                written = reporter.write_html(report, path)
        except Exception as exc:  # noqa: BLE001 - 导出失败不影响扫描结果
            FluentMessageBox.warning(self, "导出失败", f"{type(exc).__name__}: {exc}")
            return
        self.status_label.setText(f"报告已导出：{written}")
        FluentMessageBox.information(self, "导出完成", f"报告已保存：\n{written}")

    # ------------------------------------------------------------------
    # 更新检查
    # ------------------------------------------------------------------
    def _start_update_check(self) -> None:
        if self._update_worker is not None and self._update_worker.isRunning():
            return
        worker = UpdateWorker(self)
        worker.checked.connect(self._on_update_checked)
        self._update_worker = worker
        worker.start()

    @pyqtSlot(object)
    def _on_update_checked(self, result: Any) -> None:
        if self._update_worker is not None:
            self._update_worker.deleteLater()
        self._update_worker = None
        if not isinstance(result, updater.UpdateCheckResult):
            return
        if result.status == updater.STATUS_UPDATE_AVAILABLE:
            dialog = UpdateDialog(result, self)
            dialog.exec()
            current = config.load_config()
            if dialog.action == UpdateDialog.ACTION_DOWNLOAD:
                QDesktopServices.openUrl(QUrl(dialog.download_url))
                self.status_label.setText(f"已在浏览器打开下载页：{result.latest_version}")
            elif dialog.action == UpdateDialog.ACTION_LATER:
                config.save_config(updater.snooze_updates(current))
                self.status_label.setText("已暂不更新，24 小时内不再提醒")
            elif dialog.action == UpdateDialog.ACTION_NEVER:
                config.save_config(updater.ignore_current_version(current, __version__))
                self.status_label.setText("已忽略该版本提示")
            return
        if result.status == updater.STATUS_ERROR:
            # 弱网静默降级：只在状态栏提示，不弹窗、不影响本地扫描
            self.status_label.setText("网络不佳，已跳过更新检查")
        elif result.status == updater.STATUS_UP_TO_DATE:
            self.status_label.setText("已是最新版本")

    # ------------------------------------------------------------------
    # 设置
    # ------------------------------------------------------------------
    @pyqtSlot()
    def _open_settings(self) -> None:
        dialog = SettingsDialog(self)
        dialog.theme_changed.connect(self.apply_theme)
        dialog.exec()

    # ------------------------------------------------------------------
    # 关闭
    # ------------------------------------------------------------------
    def closeEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        worker = self._scan_worker
        if worker is not None and worker.isRunning():
            if not FluentMessageBox.question(
                self,
                "扫描进行中",
                "扫描仍在进行，确定要退出吗？",
                default_yes=False,
            ):
                event.ignore()
                return
            self._cancel_requested = True
            worker.requestInterruption()
            if not worker.wait(8000):
                FluentMessageBox.information(self, "请稍候", "扫描线程仍在收尾，请稍后再试。")
                event.ignore()
                return
        update_worker = self._update_worker
        if update_worker is not None and update_worker.isRunning():
            update_worker.requestInterruption()
            update_worker.wait(2000)
        campaign_worker = self._campaign_worker
        if campaign_worker is not None and campaign_worker.isRunning():
            campaign_worker.requestInterruption()
            campaign_worker.wait(2000)
        event.accept()


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def _wrap_path_for_display(text: str) -> str:
    """给长路径插入零宽空格，便于 QLabel 在面板宽度内换行（不影响原数据）。"""
    if not isinstance(text, str) or not text:
        return ""
    return re.sub(r"([\\/:._-])", lambda match: match.group(1) + "\u200b", text)


def _anonymize_text(text: str) -> str:
    """清除文本中的用户名 / 用户目录（匿名上报用）。"""
    if not isinstance(text, str) or not text:
        return ""
    result = text
    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    username = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    if home:
        result = result.replace(home, "<USER_HOME>")
        result = result.replace(home.replace("\\", "/"), "<USER_HOME>")
    if username:
        result = result.replace(username, "<USER>")
    result = re.sub(r"(?i)([a-z]:[\\/]+Users[\\/]+)[^\\/\s\"']+", r"\1<USER>", result)
    return result


def _load_baseline_report(path: str) -> tuple[dict[str, Any] | None, str | None]:
    """薄包装 ``core.ui_helpers.load_baseline_file``，保留 GUI 侧原有提示语义。"""
    data, error = ui_helpers.load_baseline_file(path)
    if error:
        return None, error
    return data, None


def _install_exception_hook() -> None:
    """顶层异常兜底：写 stderr 并弹窗，避免窗口化程序直接闪退。"""

    def hook(exc_type, exc_value, exc_tb) -> None:
        text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        try:
            sys.stderr.write(text)
        except Exception:  # noqa: BLE001 - stderr 不可用时忽略
            pass
        try:
            FluentMessageBox.critical(
                None,
                "TamperScan 未处理异常",
                f"程序遇到未处理异常：\n\n{exc_type.__name__}: {exc_value}",
            )
        except Exception:  # noqa: BLE001 - 弹窗失败时不再递归
            pass

    sys.excepthook = hook


def _center_window(window: QMainWindow) -> None:
    screen = QApplication.primaryScreen()
    if screen is None:
        return
    geometry = screen.availableGeometry()
    frame = window.frameGeometry()
    frame.moveCenter(geometry.center())
    window.move(frame.topLeft())


def main(argv: list[str] | None = None) -> int:
    """GUI 入口：创建 QApplication 并进入事件循环。"""
    app = QApplication.instance() or QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    icon_path = BASE_DIR / "icon.ico"
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    _install_exception_hook()
    theme = config.get_theme()
    app.setStyleSheet(THEME_QSS.get(theme, LIGHT_QSS))
    window = MainWindow(start_update_check=True)
    window.apply_theme(theme)
    window.show()
    _center_window(window)
    return int(app.exec())


__all__ = [
    "DARK_QSS",
    "CampaignDialog",
    "CampaignWorker",
    "DetailPanel",
    "FluentMessageBox",
    "FramelessDialog",
    "LIGHT_QSS",
    "MainWindow",
    "ResultItemWidget",
    "RingProgress",
    "ScanWorker",
    "SettingsDialog",
    "StatCard",
    "THEME_QSS",
    "TitleBar",
    "UpdateDialog",
    "UpdateWorker",
    "main",
]


if __name__ == "__main__":  # pragma: no cover - 手动启动
    sys.exit(main())
