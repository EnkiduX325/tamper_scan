# -*- coding: utf-8 -*-
"""``gui_qt.py`` PyQt6 界面测试（V1.5 第二阶段）。

覆盖：
- 无边框主窗口可正常实例化，5 张统计卡 / 结果列表 / 详情面板 / 设置按钮齐全；
- 结果渲染：统计卡数字、列表行数、状态徽章、详情面板联动；
- 浅色/暗黑 QSS 切换；
- "信任此项"闭环：联合指纹写入 config.json + 匿名上报可选暂存（隐私脱敏）；
- 设置中心 / 更新提示对话框构造；
- ScanWorker / UpdateWorker 的 ``pyqtSignal`` 成功与失败路径（线程入口直接调用，
  不执行真实扫描/网络）；
- ``main.py --gui`` 路由到 gui_qt。

测试使用 Qt **offscreen** 平台，不弹出真实窗口、不访问网络；无 ``pytest-qt``
依赖，直接管理 QApplication 生命周期（第三阶段接入 pytest-qt 后可平滑迁移）。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_gui_qt.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

# 必须在创建 QApplication 之前设置；CI/无桌面环境也可运行。
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

pytest.importorskip("PyQt6")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

import gui_qt  # noqa: E402
import main as cli_main  # noqa: E402
from core import config, updater  # noqa: E402
from core.finding import make_finding  # noqa: E402

_APP_REF: QApplication | None = None


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    global _APP_REF
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    _APP_REF = app
    yield app


@pytest.fixture()
def window(qapp: QApplication) -> gui_qt.MainWindow:
    config.clear_trust_entries()
    config.clear_pending_reports()
    win = gui_qt.MainWindow(start_update_check=False)
    win.show()
    qapp.processEvents()
    yield win
    win.close()
    qapp.processEvents()


def _finding(
    severity: str = "HIGH",
    target: str = r"C:\Program Files\Contoso\app.exe",
    rule_id: str = "SIG_UNSIGNED",
    **evidence: Any,
) -> dict[str, Any]:
    payload = {"signature": {"status": "valid", "signer": "Contoso Ltd"}}
    payload.update(evidence)
    return make_finding(severity, "Autoruns", target, "测试 Finding 详情", payload, rule_id)


def _select_first(window: gui_qt.MainWindow, qapp: QApplication) -> None:
    window.results_list.setCurrentRow(0)
    qapp.processEvents()


class _MsgBoxStub:
    """替换 FluentMessageBox，避免测试弹出模态框。"""

    calls: list[tuple[str, tuple[Any, ...]]] = []

    @classmethod
    def question(cls, *args: Any, **kwargs: Any) -> bool:
        cls.calls.append(("question", args))
        return False

    @classmethod
    def information(cls, *args: Any, **kwargs: Any) -> None:
        cls.calls.append(("information", args))

    @classmethod
    def warning(cls, *args: Any, **kwargs: Any) -> None:
        cls.calls.append(("warning", args))

    @classmethod
    def critical(cls, *args: Any, **kwargs: Any) -> None:
        cls.calls.append(("critical", args))


# ---------------------------------------------------------------------------
# 窗口 / 组件
# ---------------------------------------------------------------------------


def test_main_window_is_frameless_with_required_components(window: gui_qt.MainWindow) -> None:
    assert window.windowFlags() & Qt.WindowType.FramelessWindowHint
    assert window.windowTitle().startswith("TamperScan")
    assert window.title_bar is not None
    assert window.title_bar.settings_button.toolTip() == "设置"
    assert len(window.stat_cards) == 5
    assert set(window.stat_cards) == {"HIGH", "MEDIUM", "LOW", "INFO", "SKIPPED"}
    assert window.scan_button.text() == "开始扫描"
    assert window.ring.value == 0
    assert window.results_list.count() == 0
    assert window.detail_panel.finding is None
    assert window.baseline_button.text() == "对比基线"
    assert window.save_baseline_button.text() == "保存为基线"


def test_stat_cards_and_result_list_render(qapp: QApplication, window: gui_qt.MainWindow) -> None:
    findings = [
        _finding("HIGH", r"C:\Program Files\Contoso\a.exe"),
        _finding("LOW", r"C:\Program Files\Contoso\b.exe"),
        _finding("SKIPPED", r"C:\Program Files\Contoso\c.exe"),
    ]
    window._display_findings(findings, duration=1.23)
    qapp.processEvents()
    assert window.stat_cards["HIGH"].number_label.text() == "1"
    assert window.stat_cards["LOW"].number_label.text() == "1"
    assert window.stat_cards["SKIPPED"].number_label.text() == "1"
    assert window.stat_cards["MEDIUM"].number_label.text() == "0"
    assert window.results_list.count() == 3
    assert window.results_badge.text() == "3 项"
    assert "3 个 Finding" in window.status_label.text()


def test_selection_populates_detail_panel(qapp: QApplication, window: gui_qt.MainWindow) -> None:
    finding = _finding("MEDIUM", r"C:\Program Files\Contoso\detail.exe", rule_id="SIG_INVALID")
    window._display_findings([finding])
    _select_first(window, qapp)
    panel = window.detail_panel
    assert panel.finding is not None
    assert "detail.exe" in panel.target_label.text().replace("\u200b", "")
    assert "\u200b" in panel.target_label.text()  # 长路径可换行
    assert "SIG_INVALID" in panel.rule_label.text()
    assert "signature" in panel.evidence_view.toPlainText()
    assert panel.copy_button.isEnabled() is True
    assert panel.trust_button.isEnabled() is True


def test_theme_switch_applies_qss(qapp: QApplication, window: gui_qt.MainWindow) -> None:
    window.apply_theme("dark")
    assert window.theme == "dark"
    assert qapp.styleSheet() == gui_qt.DARK_QSS
    window.apply_theme("light")
    assert window.theme == "light"
    assert qapp.styleSheet() == gui_qt.LIGHT_QSS


def test_ring_progress_sets_value_without_animation() -> None:
    ring = gui_qt.RingProgress()
    ring.setValue(42, animate=False)
    assert ring.value == pytest.approx(42.0)
    ring.setValue(150, animate=False)
    assert ring.value == pytest.approx(100.0)


def test_copy_detail_updates_clipboard(qapp: QApplication, window: gui_qt.MainWindow) -> None:
    window._display_findings([_finding()])
    _select_first(window, qapp)
    window._on_copy_detail()
    qapp.processEvents()
    clipboard = QApplication.clipboard()
    assert clipboard is not None
    assert "SIG_UNSIGNED" in clipboard.text()
    assert "Evidence" in clipboard.text()


# ---------------------------------------------------------------------------
# 信任闭环 / 匿名上报
# ---------------------------------------------------------------------------


def test_trust_flow_persists_joint_fingerprint(
    qapp: QApplication, window: gui_qt.MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _finding()
    window._display_findings([finding])
    _select_first(window, qapp)
    monkeypatch.setattr(window, "_ask_anonymous_report", lambda: False)

    window._on_trust_finding()

    entries = config.load_trust_entries()
    assert len(entries) == 1
    assert entries[0]["rule_id"] == "SIG_UNSIGNED"
    assert entries[0]["signer_contains"] == "Contoso Ltd"
    assert entries[0]["target_prefix"] == finding["target"]
    assert entries[0]["expire_days"] == config.DEFAULT_TRUST_EXPIRE_DAYS
    assert config.load_pending_reports() == []
    assert "已加入本地白名单" in window.status_label.text()


def test_trust_flow_can_queue_anonymous_report(
    qapp: QApplication, window: gui_qt.MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _finding(target=r"C:\Users\VerySecretUser\AppData\Local\Temp\evil.exe")
    window._display_findings([finding])
    _select_first(window, qapp)
    monkeypatch.setenv("USERNAME", "VerySecretUser")
    monkeypatch.setattr(window, "_ask_anonymous_report", lambda: True)

    window._on_trust_finding()

    pending = config.load_pending_reports()
    assert len(pending) == 1
    payload = pending[0]
    assert "target" not in payload
    assert payload["target_name"] == "evil.exe"
    assert payload["rule_id"] == "SIG_UNSIGNED"
    assert "VerySecretUser" not in json.dumps(payload, ensure_ascii=False)


def test_trust_rejects_broad_target(
    qapp: QApplication, window: gui_qt.MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _finding(target="C:\\", rule_id="SIG_UNSIGNED")
    window._display_findings([finding])
    _select_first(window, qapp)
    monkeypatch.setattr(gui_qt, "FluentMessageBox", _MsgBoxStub)

    window._on_trust_finding()

    assert config.load_trust_entries() == []
    assert any(name == "warning" for name, _ in _MsgBoxStub.calls)


def test_anonymous_report_is_privacy_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USERNAME", "SecretUser")
    monkeypatch.setenv("USERPROFILE", r"C:\Users\SecretUser")
    finding = _finding(
        target=r"C:\Users\SecretUser\AppData\Local\Temp\payload.exe",
        evidence={"signature": {"status": "valid", "signer": "Contoso Ltd"}},
    )
    report = gui_qt.MainWindow._build_anonymous_report(finding)
    text = json.dumps(report, ensure_ascii=False)
    assert "SecretUser" not in text
    assert "target" not in report
    assert report["target_name"] == "payload.exe"
    assert report["tool"] == "TamperScan"


# ---------------------------------------------------------------------------
# 设置 / 更新对话框
# ---------------------------------------------------------------------------


def test_settings_dialog_components(qapp: QApplication, window: gui_qt.MainWindow) -> None:
    dialog = gui_qt.SettingsDialog(window)
    assert dialog.auto_check.isChecked() is True
    assert dialog.theme_combo.count() == 2
    assert dialog.clear_trust_button.text() == "清空本地信任名单"
    assert dialog.pending_button.text() == "导出暂存的上报报告"
    dialog.close()


def test_settings_theme_switch_updates_config(qapp: QApplication, window: gui_qt.MainWindow) -> None:
    dialog = gui_qt.SettingsDialog(window)
    changed: list[str] = []
    dialog.theme_changed.connect(changed.append)
    dialog.theme_combo.setCurrentIndex(1)  # dark
    qapp.processEvents()
    assert config.get_theme() == "dark"
    assert changed == ["dark"]
    dialog.theme_combo.setCurrentIndex(0)  # restore light
    dialog.close()


def test_update_dialog_actions(qapp: QApplication) -> None:
    result = updater.UpdateCheckResult(
        updater.STATUS_UPDATE_AVAILABLE,
        "1.5.0",
        latest_version="v1.6.0",
        release_url="https://example.test/release",
        download_url="https://example.test/setup.exe",
        notes="更新说明",
    )
    dialog = gui_qt.UpdateDialog(result)
    assert "新版本" in dialog.windowTitle()
    dialog._choose_download()
    assert dialog.action == gui_qt.UpdateDialog.ACTION_DOWNLOAD
    assert dialog.download_url == "https://example.test/setup.exe"
    dialog.close()


# ---------------------------------------------------------------------------
# 线程 / 信号
# ---------------------------------------------------------------------------


def test_scan_worker_success_emits_result(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_result = SimpleNamespace(findings=[_finding()], duration=0.5, module_status=[])
    monkeypatch.setattr(gui_qt, "run_scan", lambda **kwargs: fake_result)
    worker = gui_qt.ScanWorker()
    finished: list[Any] = []
    worker.scan_finished.connect(finished.append)
    worker.run()
    assert finished == [fake_result]


def test_scan_worker_failure_emits_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(**kwargs: Any) -> None:
        raise RuntimeError("scan exploded")

    monkeypatch.setattr(gui_qt, "run_scan", _boom)
    worker = gui_qt.ScanWorker()
    errors: list[str] = []
    worker.scan_failed.connect(errors.append)
    worker.run()
    assert errors and "RuntimeError" in errors[0]


def test_update_worker_emits_result(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = updater.UpdateCheckResult(updater.STATUS_UP_TO_DATE, "1.5.0")
    monkeypatch.setattr(gui_qt.updater, "check_for_update", lambda *a, **k: expected)
    worker = gui_qt.UpdateWorker()
    seen: list[Any] = []
    worker.checked.connect(seen.append)
    worker.run()
    assert seen == [expected]


def test_update_worker_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("network down")

    monkeypatch.setattr(gui_qt.updater, "check_for_update", _boom)
    worker = gui_qt.UpdateWorker()
    seen: list[Any] = []
    worker.checked.connect(seen.append)
    worker.run()
    assert len(seen) == 1
    assert seen[0].status == updater.STATUS_ERROR


def test_update_checked_handles_error_silently(qapp: QApplication, window: gui_qt.MainWindow) -> None:
    result = updater.UpdateCheckResult(
        updater.STATUS_ERROR, "1.5.0", error="更新检查超时（3 秒）", error_kind="timeout"
    )
    window._on_update_checked(result)
    assert "网络不佳" in window.status_label.text()


# ---------------------------------------------------------------------------
# CLI 路由
# ---------------------------------------------------------------------------


def test_main_gui_routes_to_gui_qt(monkeypatch: pytest.MonkeyPatch) -> None:
    parser = cli_main.build_parser()
    assert parser.parse_args(["--gui"]).gui is True
    monkeypatch.setattr(gui_qt, "main", lambda: 7)
    assert cli_main.main(["--gui"]) == 7


def test_load_baseline_report_invalid(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    data, error = gui_qt._load_baseline_report(str(missing))
    assert data is None and error
    bad = tmp_path / "bad.json"
    bad.write_text("{broken", encoding="utf-8")
    data, error = gui_qt._load_baseline_report(str(bad))
    assert data is None and "JSON" in (error or "")


def test_gui_entry_point_returns_zero(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    """``gui_qt.main()`` 能创建窗口并正常进入/退出事件循环（不弹真实窗口）。"""
    from PyQt6.QtCore import QTimer

    monkeypatch.setattr(gui_qt, "_install_exception_hook", lambda: None)
    QTimer.singleShot(80, qapp.quit)
    assert gui_qt.main([]) == 0
    qapp.setStyleSheet(gui_qt.LIGHT_QSS)


# ---------------------------------------------------------------------------
# V1.5 收尾补充：设置清空/队列查看、更新对话框其余动作、异常/取消/空结果
# ---------------------------------------------------------------------------


class _YesMsgBox(_MsgBoxStub):
    @classmethod
    def question(cls, *args: Any, **kwargs: Any) -> bool:
        cls.calls.append(("question", args))
        return True


def test_settings_clear_trust_and_export_pending(
    qapp: QApplication, window: gui_qt.MainWindow, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from core import whitelist

    config.add_trust_entry(whitelist.build_trust_entry(_finding()))
    config.append_pending_report({"rule_id": "SIG_UNSIGNED", "target_name": "app.exe"})
    dialog = gui_qt.SettingsDialog(window)
    _MsgBoxStub.calls.clear()
    monkeypatch.setattr(gui_qt, "FluentMessageBox", _YesMsgBox)

    dialog._on_clear_trust()
    assert config.load_trust_entries() == []
    assert "0 条" in dialog.trust_count_label.text()

    export_path = tmp_path / "pending_export.json"
    monkeypatch.setattr(
        gui_qt.QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *args, **kwargs: (str(export_path), "JSON (*.json)")),
    )
    dialog._on_export_pending()
    assert export_path.is_file()
    assert any(name == "information" for name, _ in _YesMsgBox.calls)
    dialog.close()


def test_settings_auto_check_toggle_persists(
    qapp: QApplication, window: gui_qt.MainWindow
) -> None:
    dialog = gui_qt.SettingsDialog(window)
    dialog.auto_check.setChecked(False)
    assert config.is_auto_check_enabled() is False
    dialog.auto_check.setChecked(True)
    assert config.is_auto_check_enabled() is True
    dialog.close()


def test_update_dialog_later_and_never(qapp: QApplication) -> None:
    result = updater.UpdateCheckResult(
        updater.STATUS_UPDATE_AVAILABLE,
        "1.5.0",
        latest_version="v1.6.0",
        release_url="https://example.test/release",
        notes="notes",
    )
    later = gui_qt.UpdateDialog(result)
    later._choose_later()
    assert later.action == gui_qt.UpdateDialog.ACTION_LATER
    never = gui_qt.UpdateDialog(result)
    never._choose_never()
    assert never.action == gui_qt.UpdateDialog.ACTION_NEVER


def test_display_empty_findings(qapp: QApplication, window: gui_qt.MainWindow) -> None:
    window._display_findings([], duration=0.0)
    qapp.processEvents()
    assert window.results_list.count() == 0
    assert window.detail_panel.finding is None
    assert "未发现可疑项" in window.status_label.text()
    assert all(card.number_label.text() == "0" for card in window.stat_cards.values())


def test_resolved_finding_disables_trust(qapp: QApplication, window: gui_qt.MainWindow) -> None:
    finding = _finding()
    finding["diff_status"] = "RESOLVED"
    window._display_findings([finding])
    _select_first(window, qapp)
    assert window.detail_panel.trust_button.isEnabled() is False
    assert window.detail_panel.copy_button.isEnabled() is True


def test_scan_progress_and_busy_state(qapp: QApplication, window: gui_qt.MainWindow) -> None:
    window._set_busy(True)
    assert window.scan_button.text() == "取消扫描"
    assert window.baseline_button.isEnabled() is False
    window._on_scan_progress(5, 10, "正在扫描: 模块")
    assert window.progress_hint.text() == "5/10"
    assert "模块" in window.status_label.text()
    window._on_scan_cancelled()
    assert window.scan_button.text() == "开始扫描"
    assert "已取消" in window.status_label.text()


def test_scan_finished_with_malformed_result_falls_back_to_error(
    qapp: QApplication, window: gui_qt.MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    _MsgBoxStub.calls.clear()
    monkeypatch.setattr(gui_qt, "FluentMessageBox", _MsgBoxStub)
    window._on_scan_finished(SimpleNamespace())  # 缺少 findings
    assert "扫描失败" in window.status_label.text()
    assert any(name == "critical" for name, _ in _MsgBoxStub.calls)


def test_baseline_actions_require_scan(
    qapp: QApplication, window: gui_qt.MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    _MsgBoxStub.calls.clear()
    monkeypatch.setattr(gui_qt, "FluentMessageBox", _MsgBoxStub)
    window._on_compare_baseline()
    window._on_save_baseline()
    assert sum(1 for name, _ in _MsgBoxStub.calls if name == "information") == 2


def test_load_valid_baseline_report(tmp_path: Path) -> None:
    target = tmp_path / "baseline.json"
    target.write_text(
        json.dumps({"tool": "TamperScan", "version": "1.5.0", "findings": []}),
        encoding="utf-8",
    )
    data, error = gui_qt._load_baseline_report(str(target))
    assert error is None and isinstance(data, dict)


def test_anonymize_text_removes_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USERNAME", "TopSecretUser")
    monkeypatch.setenv("USERPROFILE", r"C:\Users\TopSecretUser")
    text = r"C:\Users\TopSecretUser\Downloads\a.exe by TopSecretUser"
    cleaned = gui_qt._anonymize_text(text)
    assert "TopSecretUser" not in cleaned
    assert "<USER" in cleaned


# ---------------------------------------------------------------------------
# V1.5 rc2：攻击链按钮 / CampaignWorker / CampaignDialog
# ---------------------------------------------------------------------------


def _campaign(
    name: str = "演示攻击链",
    confidence: str = "high",
    *,
    shadow: bool = False,
    steps: int = 2,
) -> dict[str, Any]:
    return {
        "chain_id": f"chain_{name}",
        "name": name,
        "confidence": confidence,
        "shadow": shadow,
        "finding_count": steps,
        "steps": [
            {
                "tactic": f"TA000{index}",
                "rule_ids": [f"RULE_{index}"],
                "findings": [{"rule_id": f"RULE_{index}", "target": rf"C:\Test\sample{index}.dll"}],
            }
            for index in range(1, steps + 1)
        ],
    }


def test_campaign_button_without_scan_shows_information(
    qapp: QApplication, window: gui_qt.MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    _MsgBoxStub.calls.clear()
    monkeypatch.setattr(gui_qt, "FluentMessageBox", _MsgBoxStub)
    window._on_show_campaigns()
    assert any(name == "information" for name, _ in _MsgBoxStub.calls)


def test_campaign_worker_success_emits_result(monkeypatch: pytest.MonkeyPatch) -> None:
    from core import correlator

    expected = {"campaigns": [_campaign()], "stats": {"campaigns": 1}}
    monkeypatch.setattr(correlator, "correlate", lambda findings: expected)
    worker = gui_qt.CampaignWorker([_finding()])
    seen: list[Any] = []
    worker.signal_finished.connect(seen.append)
    worker.run()
    assert seen == [expected]


def test_campaign_worker_failure_emits_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from core import correlator

    def _boom(findings: Any) -> None:
        raise RuntimeError("correlate exploded")

    monkeypatch.setattr(correlator, "correlate", _boom)
    worker = gui_qt.CampaignWorker([_finding()])
    errors: list[str] = []
    worker.signal_failed.connect(errors.append)
    worker.run()
    assert errors and "RuntimeError" in errors[0]


def test_campaign_dialog_rows(qapp: QApplication) -> None:
    dialog = gui_qt.CampaignDialog([_campaign("A"), _campaign("B")], {"campaigns": 2})
    assert dialog.campaign_table.rowCount() == 2
    assert dialog.campaign_table.item(0, 0).text() == "A"
    assert dialog.steps_table.rowCount() == 2
    dialog.close()


def test_campaign_dialog_empty_state(qapp: QApplication) -> None:
    dialog = gui_qt.CampaignDialog([], {})
    assert dialog.campaign_table.isHidden() is True
    assert dialog.empty_label.isHidden() is False
    assert dialog.empty_label.text() == gui_qt.ui_helpers.CAMPAIGN_EMPTY_TEXT
    dialog.close()


def test_campaign_dialog_selection_updates_steps(qapp: QApplication) -> None:
    dialog = gui_qt.CampaignDialog(
        [_campaign("A", steps=1), _campaign("B", steps=3)], {"campaigns": 2}
    )
    dialog.campaign_table.setCurrentCell(1, 0)
    qapp.processEvents()
    assert dialog.steps_table.rowCount() == 3
    dialog.close()


def test_campaign_dialog_confidence_labels(qapp: QApplication) -> None:
    dialog = gui_qt.CampaignDialog(
        [
            _campaign("H", "high"),
            _campaign("M", "medium"),
            _campaign("L", "low"),
            _campaign("U", "unknown"),
        ],
        {},
    )
    labels = [dialog.campaign_table.item(row, 1).text() for row in range(4)]
    assert labels == ["高", "中", "低", "未知"]
    dialog.close()


def test_campaign_dialog_shadow_status(qapp: QApplication) -> None:
    dialog = gui_qt.CampaignDialog([_campaign("S", shadow=True)], {})
    assert dialog.campaign_table.item(0, 4).text() == "影子模式"
    dialog.close()


def test_campaign_finished_opens_dialog(
    qapp: QApplication, window: gui_qt.MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[Any] = []

    class _FakeDialog(gui_qt.QDialog):
        def __init__(self, campaigns: Any, stats: Any, parent: Any = None) -> None:
            super().__init__(parent)
            opened.append((campaigns, stats))

    monkeypatch.setattr(gui_qt, "CampaignDialog", _FakeDialog)
    window._on_campaign_finished({"campaigns": [_campaign()], "stats": {"campaigns": 1}})
    assert len(opened) == 1
    assert opened[0][1] == {"campaigns": 1}
    assert window._campaign_dialog is not None
    window._campaign_dialog.close()


def test_campaign_failed_shows_warning(
    qapp: QApplication, window: gui_qt.MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    _MsgBoxStub.calls.clear()
    monkeypatch.setattr(gui_qt, "FluentMessageBox", _MsgBoxStub)
    window._on_campaign_failed("Traceback: boom")
    assert any(name == "warning" for name, _ in _MsgBoxStub.calls)


def test_baseline_diff_perf_1000_findings(qapp: QApplication) -> None:
    """追问 2：1000 Finding 的基线对比/annotate 在主线程是否可接受（<500ms）。"""
    import time

    from core import baseline

    def _report(offset: int) -> dict[str, Any]:
        findings = []
        for index in range(1000):
            findings.append(
                make_finding(
                    "LOW" if index % 3 else "MEDIUM",
                    "PerfCategory",
                    rf"C:\Perf\target{index}.exe",
                    "性能样本",
                    {"actual": f"v{offset}"},
                    f"PERF_RULE_{index % 10}",
                )
            )
        return {"tool": "TamperScan", "version": "1.5.0", "findings": findings}

    baseline_report = _report(1)
    current_report = _report(2)
    started = time.monotonic()
    diff = baseline.diff_reports(baseline_report, current_report)
    baseline.annotate_findings(current_report["findings"], diff)
    elapsed = time.monotonic() - started
    assert diff.total == 1000
    assert elapsed < 0.5, f"1000 Finding diff+annotate 耗时 {elapsed:.3f}s > 500ms"


# ---------------------------------------------------------------------------
# V1.5 视觉验收修复：导出报告 / 修复建议 / 控制栏布局 / 状态徽章
# ---------------------------------------------------------------------------


def test_export_button_disabled_until_scan(
    qapp: QApplication, window: gui_qt.MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert window.export_button.isEnabled() is False
    _MsgBoxStub.calls.clear()
    monkeypatch.setattr(gui_qt, "FluentMessageBox", _MsgBoxStub)
    window._on_scan_finished(SimpleNamespace(findings=[_finding()], duration=0.1, module_status=[]))
    qapp.processEvents()
    assert window.export_button.isEnabled() is True


def test_export_report_writes_html_and_json(
    qapp: QApplication, window: gui_qt.MainWindow, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _MsgBoxStub.calls.clear()
    monkeypatch.setattr(gui_qt, "FluentMessageBox", _MsgBoxStub)
    window._on_scan_finished(SimpleNamespace(findings=[_finding()], duration=0.1, module_status=[]))
    qapp.processEvents()

    html_path = tmp_path / "report.html"
    monkeypatch.setattr(
        gui_qt.QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *a, **k: (str(html_path), "HTML 报告 (*.html)")),
    )
    window._on_export_report()
    assert html_path.is_file()
    assert "TamperScan" in html_path.read_text(encoding="utf-8")

    json_path = tmp_path / "report.json"
    monkeypatch.setattr(
        gui_qt.QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *a, **k: (str(json_path), "JSON 报告 (*.json)")),
    )
    window._on_export_report()
    assert json_path.is_file()
    assert json.loads(json_path.read_text(encoding="utf-8"))["version"] == "1.5.0"


def test_export_report_ignored_before_scan(
    qapp: QApplication, window: gui_qt.MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: list[bool] = []
    monkeypatch.setattr(
        gui_qt.QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *a, **k: called.append(True)),
    )
    window._on_export_report()
    assert called == []


def test_remediation_button_enabled_and_dialog_shows_command(
    qapp: QApplication, window: gui_qt.MainWindow
) -> None:
    remediation = {
        "summary": "建议重新签名或移除",
        "expected": "有效签名",
        "actual": "unsigned",
        "command": "Get-AuthenticodeSignature -LiteralPath 'x'",
        "risk": "HIGH",
        "requires_admin": False,
    }
    finding = _finding(rule_id="NO_REMEDIATION_RULE")
    finding["remediation"] = remediation
    window._display_findings([finding])
    _select_first(window, qapp)
    assert window.detail_panel.remediation_button.isEnabled() is True

    dialog = window._make_remediation_dialog(remediation)
    texts = [browser.toPlainText() for browser in dialog.findChildren(gui_qt.QTextBrowser)]
    assert any("Get-AuthenticodeSignature" in text for text in texts)
    dialog.close()


def test_remediation_button_disabled_without_field(qapp: QApplication, window: gui_qt.MainWindow) -> None:
    window._display_findings([_finding(rule_id="NO_REMEDIATION_RULE")])
    _select_first(window, qapp)
    assert window.detail_panel.remediation_button.isEnabled() is False


def test_control_layout_ring_does_not_overlap_scan_button(
    qapp: QApplication, window: gui_qt.MainWindow
) -> None:
    window.resize(1180, 760)
    qapp.processEvents()
    assert window.ring.width() == 60 and window.ring.height() == 60
    assert window.ring.geometry().intersects(window.scan_button.geometry()) is False
    assert window.ring.geometry().right() < window.status_label.geometry().left()


def test_result_item_renders_diff_status_badges(qapp: QApplication) -> None:
    from PyQt6.QtWidgets import QLabel

    def _labels(status: str) -> tuple[gui_qt.ResultItemWidget, dict[str, QLabel]]:
        finding = _finding()
        finding["diff_status"] = status
        widget = gui_qt.ResultItemWidget(finding)
        return widget, {label.text(): label for label in widget.findChildren(QLabel)}

    widget, labels = _labels("NEW")
    new_label = labels["NEW"]
    assert "background: #C42B1C" in new_label.styleSheet()
    widget2, labels2 = _labels("MODIFIED")
    modified_label = labels2["MODIFIED"]
    assert "background: #F7630C" in modified_label.styleSheet()
    widget3, labels3 = _labels("RESOLVED")
    resolved_label = labels3["RESOLVED"]
    assert resolved_label.font().strikeOut() is True
    assert widget is not None and widget2 is not None and widget3 is not None


# ---------------------------------------------------------------------------
# V1.5 子窗口风格 / 非模态 / 图标
# ---------------------------------------------------------------------------


def test_campaign_dialog_is_frameless_fluent(qapp: QApplication) -> None:
    dialog = gui_qt.CampaignDialog([_campaign()], {"campaigns": 1})
    flags = dialog.windowFlags()
    assert flags & Qt.WindowType.FramelessWindowHint
    assert dialog.testAttribute(Qt.WidgetAttribute.WA_TranslucentBackground) is True
    assert dialog.root_card.objectName() == "DialogCard"
    assert dialog.title_bar.title_label.text() == "攻击链"
    assert dialog.windowIcon().isNull() is False
    assert dialog.isModal() is False
    dialog.close()


def test_remediation_dialog_is_frameless_fluent(qapp: QApplication) -> None:
    remediation = {
        "summary": "建议处理",
        "command": "Get-AuthenticodeSignature -LiteralPath 'x'",
        "risk": "HIGH",
    }
    dialog = gui_qt.RemediationDialog(remediation)
    assert dialog.windowFlags() & Qt.WindowType.FramelessWindowHint
    assert dialog.testAttribute(Qt.WidgetAttribute.WA_TranslucentBackground) is True
    assert dialog.root_card.objectName() == "DialogCard"
    assert dialog.title_bar.title_label.text() == "修复建议"
    assert dialog.windowIcon().isNull() is False
    assert "Get-AuthenticodeSignature" in dialog.command_view.toPlainText()
    dialog.close()


def test_campaign_dialog_opened_non_modal(
    qapp: QApplication, window: gui_qt.MainWindow
) -> None:
    window._on_campaign_finished({"campaigns": [_campaign()], "stats": {"campaigns": 1}})
    qapp.processEvents()
    assert window._campaign_dialog is not None
    assert window._campaign_dialog.isModal() is False
    assert window._campaign_dialog.isVisible() is True
    window._campaign_dialog.close()
    qapp.processEvents()
    assert window._campaign_dialog is None


def test_remediation_dialog_opened_non_modal(
    qapp: QApplication, window: gui_qt.MainWindow
) -> None:
    remediation = {
        "summary": "建议处理",
        "command": "Get-AuthenticodeSignature -LiteralPath 'x'",
        "risk": "HIGH",
    }
    finding = _finding(rule_id="NO_REMEDIATION_RULE")
    finding["remediation"] = remediation
    window._display_findings([finding])
    _select_first(window, qapp)
    window._on_show_remediation()
    qapp.processEvents()
    assert window._remediation_dialog is not None
    assert window._remediation_dialog.isModal() is False
    assert window._remediation_dialog.isVisible() is True
    window._remediation_dialog.close()
    qapp.processEvents()
    assert window._remediation_dialog is None


def test_main_window_has_app_icon(qapp: QApplication, window: gui_qt.MainWindow) -> None:
    assert window.windowIcon().isNull() is False


def test_campaign_dialog_open_allows_main_list_interaction(
    qapp: QApplication, window: gui_qt.MainWindow
) -> None:
    findings = [
        _finding(target=r"C:\Test\first.exe"),
        _finding(target=r"C:\Test\second.exe"),
    ]
    window._display_findings(findings)
    window._on_campaign_finished({"campaigns": [_campaign()], "stats": {"campaigns": 1}})
    qapp.processEvents()
    assert window._campaign_dialog is not None
    window.results_list.setCurrentRow(1)
    qapp.processEvents()
    assert window.results_list.currentRow() == 1
    assert "second.exe" in window.detail_panel.target_label.text().replace("\u200b", "")
    window._campaign_dialog.close()
    qapp.processEvents()


def test_all_dialogs_are_frameless(qapp: QApplication) -> None:
    """遍历 gui_qt 下所有 QDialog 子类，防止再新增原生标题栏弹窗。"""
    import inspect

    factories = {
        gui_qt.FramelessDialog: lambda: gui_qt.FramelessDialog("测试子窗口"),
        gui_qt.FluentMessageBox: lambda: gui_qt.FluentMessageBox(None, "提示", "测试消息", "information"),
        gui_qt.SettingsDialog: lambda: gui_qt.SettingsDialog(),
        gui_qt.UpdateDialog: lambda: gui_qt.UpdateDialog(
            gui_qt.updater.UpdateCheckResult(status="up_to_date", current_version="1.5.0")
        ),
        gui_qt.CampaignDialog: lambda: gui_qt.CampaignDialog([], {}),
        gui_qt.RemediationDialog: lambda: gui_qt.RemediationDialog({"summary": "测试"}),
    }
    discovered = {
        cls
        for _, cls in inspect.getmembers(gui_qt, inspect.isclass)
        if issubclass(cls, gui_qt.QDialog) and cls.__module__ == gui_qt.__name__
    }
    assert discovered == set(factories), f"新增 QDialog 子类未加入无边框测试: {discovered - set(factories)}"
    for cls, factory in factories.items():
        dialog = factory()
        flags = dialog.windowFlags()
        assert flags & Qt.WindowType.FramelessWindowHint, cls.__name__
        assert dialog.testAttribute(Qt.WidgetAttribute.WA_TranslucentBackground), cls.__name__
        assert dialog.root_card.objectName() == "DialogCard", cls.__name__
        dialog.close()


def test_fluent_message_box_question_buttons(qapp: QApplication) -> None:
    box = gui_qt.FluentMessageBox(None, "确认", "是否继续？", "question")
    assert box.message_label.text() == "是否继续？"
    assert box.yes_button.text() == "是"
    assert box.no_button.text() == "否"
    assert box.windowFlags() & Qt.WindowType.FramelessWindowHint
    box.close()


def test_gui_module_has_no_qmessagebox_reference() -> None:
    source = (Path(gui_qt.__file__)).read_text(encoding="utf-8")
    assert "QMessageBox" not in source
