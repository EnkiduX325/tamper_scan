# -*- coding: utf-8 -*-
"""V1.5 收尾一致性测试：版本 / 依赖 / 打包 / CI / 文档 / 样例报告 / GUI 清理。

这些测试不执行真实扫描、不联网、不构建 exe；只做静态文件与 JSON 断言，
保证发布 v1.5.0 时"代码、CI、文档、样例报告、打包脚本"五处不漂移。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_v15_release.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.version import __version__  # noqa: E402

CI_PATH = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
README_PATH = PROJECT_ROOT / "README.md"
CHANGELOG_PATH = PROJECT_ROOT / "CHANGELOG.md"
BUILD_PATH = PROJECT_ROOT / "build.bat"
REQUIREMENTS_PATH = PROJECT_ROOT / "requirements.txt"
SAMPLE_JSON = PROJECT_ROOT / "reports" / "sample_report.json"
SAMPLE_HTML = PROJECT_ROOT / "reports" / "sample_report.html"
SCREENSHOT_DIR = PROJECT_ROOT / "docs" / "screenshots"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# 版本 / 依赖
# ---------------------------------------------------------------------------


def test_version_is_1_5_0() -> None:
    assert __version__ == "1.5.0"


def test_version_source_single_value() -> None:
    text = _read(PROJECT_ROOT / "core" / "version.py")
    assert '__version__ = "1.5.0"' in text
    assert '1.4.0' not in text


def test_requirements_include_pyqt6_and_pytest_qt() -> None:
    text = _read(REQUIREMENTS_PATH)
    assert re.search(r"(?m)^PyQt6\s*[><=]", text)
    assert re.search(r"(?m)^pytest-qt\s*[><=]", text)


def test_requirements_build_inherits_runtime_requirements() -> None:
    text = _read(PROJECT_ROOT / "requirements-build.txt")
    assert "-r requirements.txt" in text
    assert "pyinstaller" in text.lower()


# ---------------------------------------------------------------------------
# 打包脚本
# ---------------------------------------------------------------------------


def test_build_bat_uses_gui_qt_entry() -> None:
    text = _read(BUILD_PATH)
    assert "--name tamper_scan_gui gui_qt.py" in text
    assert "--name tamper_scan_gui gui.py" not in text
    assert "python -m PyInstaller %COMMON% %QT_COLLECT%" in text


def test_build_bat_collects_pyqt6_for_gui_only() -> None:
    text = _read(BUILD_PATH)
    assert "--collect-all PyQt6" in text
    assert "--collect-all PyQt6.Qt6" in text
    for module in ("PyQt6.QtCore", "PyQt6.QtGui", "PyQt6.QtWidgets"):
        assert f"--hidden-import {module}" in text
    cli_line = next(line for line in text.splitlines() if "--name tamper_scan main.py" in line)
    assert "QT_COLLECT" not in cli_line
    assert "--windowed" in text


def test_build_bat_checks_pyqt6_availability() -> None:
    text = _read(BUILD_PATH)
    assert 'python -c "import PyQt6"' in text
    assert "pip install -r requirements.txt" in text


def test_gui_py_and_legacy_tests_removed() -> None:
    assert not (PROJECT_ROOT / "gui.py").exists()
    assert not (PROJECT_ROOT / "tests" / "test_baseline_gui.py").exists()
    assert not (PROJECT_ROOT / "tests" / "test_campaign_gui.py").exists()
    assert (PROJECT_ROOT / "gui_qt.py").is_file()


def test_no_active_module_imports_removed_gui() -> None:
    offenders: list[str] = []
    for path in list(PROJECT_ROOT.glob("*.py")) + list((PROJECT_ROOT / "tests").glob("*.py")):
        if path.name in {"test_v15_release.py"}:
            continue
        text = _read(path)
        if re.search(r"(?m)^\s*(?:import\s+gui\b|from\s+gui\s+import)", text):
            offenders.append(path.name)
    assert offenders == []


# ---------------------------------------------------------------------------
# CI / 本地校验脚本
# ---------------------------------------------------------------------------


def test_ci_updated_for_v15() -> None:
    text = _read(CI_PATH)
    assert "__version__ == '1.5.0'" in text
    assert "d['version'] == '1.5.0'" in text
    assert "gui_qt.py" in text
    assert "gui.py" not in text.replace("gui_qt.py", "")
    assert "PyQt6 GUI smoke" in text


def test_ci_yaml_basic_structure() -> None:
    """不引入 PyYAML 依赖：仅校验关键结构（真正 YAML 解析由 GitHub Actions 完成）。"""
    text = _read(CI_PATH)
    assert text.lstrip().startswith("name: CI")
    assert "jobs:" in text
    assert "runs-on: windows-latest" in text
    assert "Unit tests" in text


def test_local_verify_script_renamed_and_updated() -> None:
    new_script = PROJECT_ROOT / "tools" / "verify_v15.ps1"
    assert new_script.is_file()
    assert not (PROJECT_ROOT / "tools" / "verify_v14.ps1").exists()
    text = _read(new_script)
    assert "1.5.0" in text
    assert "gui_qt.py" in text
    assert "PyQt6 GUI smoke" in text
    assert "1.4.0" not in text


# ---------------------------------------------------------------------------
# 文档
# ---------------------------------------------------------------------------


def test_readme_highlights_and_version() -> None:
    text = _read(README_PATH)
    assert "`1.5.0`" in text
    assert "V1.5 更新" in text
    assert "PyQt6" in text
    assert "gui_qt.py" in text
    assert "python main.py --gui" in text
    assert "1102 条" in text


def test_readme_agpl_dual_license_remains_prominent() -> None:
    text = _read(README_PATH)
    top = text[:1500]
    assert "AGPL-3.0" in top
    assert "双轨" in top
    assert "LICENSE-COMMERCIAL.md" in top
    assert "img.shields.io/badge/License-AGPL" in text
    assert "img.shields.io/badge/version-1.5.0" in text


def test_readme_uses_new_pyqt6_screenshots_only() -> None:
    text = _read(README_PATH)
    assert "docs/screenshots/gui_qt_light.png" in text
    assert "docs/screenshots/gui_qt_dark.png" in text
    for legacy in ("gui_results.png", "gui_scanning.png", "gui_initial.png"):
        assert legacy not in text
    assert (SCREENSHOT_DIR / "gui_qt_light.png").is_file()
    assert (SCREENSHOT_DIR / "gui_qt_dark.png").is_file()


def test_no_legacy_screenshots_left() -> None:
    files = sorted(path.name for path in SCREENSHOT_DIR.glob("*.png"))
    assert files == [
        "gui_qt_campaign.png",
        "gui_qt_dark.png",
        "gui_qt_light.png",
        "gui_qt_messagebox.png",
        "gui_qt_remediation.png",
        "gui_qt_settings.png",
        "gui_qt_update.png",
    ]


def test_changelog_has_v15_entry() -> None:
    text = _read(CHANGELOG_PATH)
    assert "## [1.5.0] - 2026-11-11" in text
    assert text.index("## [1.5.0]") < text.index("## [1.4.0]")
    for keyword in ("PyQt6", "联合指纹", "时间窗", "pending_report", "gui.py"):
        assert keyword in text


def test_legal_docs_reference_v15() -> None:
    for name in ("CLA.md", "LICENSE-COMMERCIAL.md"):
        text = _read(PROJECT_ROOT / name)
        assert "v1.5.0" in text
        assert "v1.4.0" not in text


# ---------------------------------------------------------------------------
# 样例报告
# ---------------------------------------------------------------------------


def test_sample_report_json_is_v15_and_complete() -> None:
    report = json.loads(_read(SAMPLE_JSON))
    assert report["tool"] == "TamperScan"
    assert report["version"] == "1.5.0"
    assert report["scan"]["modules_total"] == 20
    assert report["scan"]["modules_available"] == 20
    assert len(report["scan"]["modules"]) == 20
    assert isinstance(report["findings"], list)


def test_sample_report_is_desensitized() -> None:
    report = json.loads(_read(SAMPLE_JSON))
    assert report["host"]["name"] == "TEST-PC"
    assert report["host"]["user"] == "User"
    text = json.dumps(report, ensure_ascii=False)
    import os

    username = os.environ.get("USERNAME") or ""
    profile = os.environ.get("USERPROFILE") or ""
    assert not (username and username in text)
    assert not (profile and profile in text)


def test_sample_report_html_is_v15() -> None:
    text = _read(SAMPLE_HTML)
    assert "TamperScan 1.5.0" in text
    assert "1.4.0" not in text


def test_main_version_output(capsys: pytest.CaptureFixture[str]) -> None:
    import main as cli_main

    with pytest.raises(SystemExit) as exc_info:
        cli_main.main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "1.5.0" in captured.out


def test_main_parser_exposes_gui_flag() -> None:
    import main as cli_main

    parser = cli_main.build_parser()
    assert parser.parse_args(["--gui"]).gui is True
    assert parser.parse_args(["--scan"]).gui is False
