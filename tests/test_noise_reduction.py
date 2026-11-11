# -*- coding: utf-8 -*-
"""V1.5 降噪规则回归：Tarrask / 无签名常见软件 / Quark / Chrome-Edge Active Setup。

目标：在 mock 环境下断言这些已知官方路径不再产生 HIGH/MEDIUM；同时保留反例，
避免白名单过宽（未知无签名程序、伪造签名者、系统任务 SD 异常仍应告警）。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_noise_reduction.py
"""

from __future__ import annotations

import os
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import winreg  # noqa: E402

from core.whitelist import apply_whitelist, load_whitelist  # noqa: E402
from modules import persistence_ext, scheduled_task_hidden  # noqa: E402

TASK_GUID = "{11111111-2222-3333-4444-555555555555}"
VALID_SD = b"\x01\x00\x04\x80" + b"\x00" * 12
WHITELIST = load_whitelist(include_user_trust=False)


def _values(**entries: object) -> dict[str, tuple[object, int]]:
    return dict(entries)


def _apply(rule_id: str, target: str, *, signer: str = "", status: str | None = None) -> dict:
    evidence: dict = {}
    if signer or status:
        evidence["signature"] = {
            "status": status or ("valid" if signer else "unsigned"),
            "signer": signer or None,
        }
    finding = {
        "severity": "HIGH",
        "rule_id": rule_id,
        "category": "Test",
        "target": target,
        "detail": "noise reduction test",
        "evidence": evidence,
    }
    return apply_whitelist([finding], WHITELIST)[0]


# ---------------------------------------------------------------------------
# 1. Tarrask：Microsoft\Windows 系统任务 Index=0 历史残留
# ---------------------------------------------------------------------------


def test_system_task_stale_index_zero_downgraded_to_info() -> None:
    with mock.patch.object(
        scheduled_task_hidden, "_read_task_definition", return_value={"definition_exists": False}
    ):
        findings = scheduled_task_hidden._analyze_node(
            r"Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
            _values(
                Id=(TASK_GUID, winreg.REG_SZ),
                Index=(0, winreg.REG_DWORD),
                SD=(VALID_SD, winreg.REG_BINARY),
            ),
        )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "TASK_HIDDEN_TARRASK"
    assert finding["severity"] == "INFO"
    assert finding["evidence"]["stale_candidate"] is True
    assert finding["evidence"]["reasons"] == ["index_zero"]


def test_system_task_with_sd_anomaly_stays_high() -> None:
    with mock.patch.object(
        scheduled_task_hidden, "_read_task_definition", return_value={"definition_exists": False}
    ):
        findings = scheduled_task_hidden._analyze_node(
            r"Microsoft\Windows\UpdateOrchestrator\BrokenTask",
            _values(
                Id=(TASK_GUID, winreg.REG_SZ),
                Index=(0, winreg.REG_DWORD),
                SD=(b"", winreg.REG_BINARY),
            ),
        )
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["evidence"]["stale_candidate"] is False


def test_non_system_stale_task_keeps_medium() -> None:
    with mock.patch.object(
        scheduled_task_hidden, "_read_task_definition", return_value={"definition_exists": False}
    ):
        findings = scheduled_task_hidden._analyze_node(
            r"Contoso\Residue",
            _values(
                Id=(TASK_GUID, winreg.REG_SZ),
                Index=(0, winreg.REG_DWORD),
                SD=(VALID_SD, winreg.REG_BINARY),
            ),
        )
    assert findings[0]["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# 2. 无签名但属于知名开源/大厂安装目录
# ---------------------------------------------------------------------------


def test_known_unsigned_apps_are_info() -> None:
    program_files = os.environ.get("PROGRAMFILES", r"C:\Program Files")
    program_files_x86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
    local_appdata = os.environ.get("LOCALAPPDATA", r"C:\Users\Test\AppData\Local")
    cases = [
        (str(Path(program_files) / "7-Zip" / "7-zip.dll")),
        (str(Path(program_files_x86) / "NeatDM" / "NeatDM.exe")),
        (str(Path(local_appdata) / "Programs" / "LinkedIn" / "LinkedIn.exe")),
    ]
    for target in cases:
        finding = _apply("AUTORUNS_SIG_UNSIGNED", target)
        assert finding["severity"] == "INFO", target
        assert finding["evidence"]["whitelist_match"]["type"] == "fingerprints"


def test_unknown_unsigned_app_stays_high() -> None:
    finding = _apply("AUTORUNS_SIG_UNSIGNED", r"C:\Users\Public\Download\evil.exe")
    assert finding["severity"] == "HIGH"
    assert "whitelist_match" not in finding["evidence"]


# ---------------------------------------------------------------------------
# 3. Quark：用户可写目录 + 有效 Alibaba 签名
# ---------------------------------------------------------------------------


def test_signed_quark_in_user_programs_is_info() -> None:
    local_appdata = os.environ.get("LOCALAPPDATA", r"C:\Users\Test\AppData\Local")
    target = str(Path(local_appdata) / "Programs" / "Common" / "Quark" / "Quark.exe")
    finding = _apply(
        "AUTORUNS_USERWRITABLE",
        target,
        signer="Alibaba (China) Technology Co., Ltd.",
    )
    assert finding["severity"] == "INFO"


def test_unsigned_quark_path_stays_high() -> None:
    local_appdata = os.environ.get("LOCALAPPDATA", r"C:\Users\Test\AppData\Local")
    target = str(Path(local_appdata) / "Programs" / "Common" / "Quark" / "Quark.exe")
    finding = _apply("AUTORUNS_USERWRITABLE", target)
    assert finding["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# 4. Chrome / Edge Active Setup
# ---------------------------------------------------------------------------


def _active_setup_finding(executable: str, signature: dict) -> dict:
    path_state = {
        "expanded": executable,
        "executable": executable,
        "is_pe": True,
        "in_system_dir": False,
    }
    findings = persistence_ext._analyze_active_setup(
        "{CHROME-GUID}", executable, signature, path_state
    )
    assert len(findings) == 1
    return findings[0]


def test_chrome_active_setup_with_google_signature_downgraded_to_info() -> None:
    program_files = os.environ.get("PROGRAMFILES", r"C:\Program Files")
    stub = str(Path(program_files) / "Google" / "Chrome" / "Application" / "131" / "Installer" / "chrmstp.exe")
    signature = {"status": "valid", "signer": "Google LLC", "via": "embedded", "error": None}
    raw_finding = _active_setup_finding(stub, signature)
    assert raw_finding["severity"] == "INFO"
    assert raw_finding["evidence"]["official_browser_stub"] is True
    finding = apply_whitelist([raw_finding], WHITELIST)[0]
    assert finding["severity"] == "INFO"


def test_chrome_active_setup_unsigned_stays_medium() -> None:
    program_files = os.environ.get("PROGRAMFILES", r"C:\Program Files")
    stub = str(Path(program_files) / "Google" / "Chrome" / "Application" / "131" / "Installer" / "chrmstp.exe")
    signature = {"status": "unsigned", "signer": None, "via": None, "error": None}
    finding = _active_setup_finding(stub, signature)
    assert finding["severity"] == "MEDIUM"
    assert apply_whitelist([finding], WHITELIST)[0]["severity"] == "MEDIUM"


def test_edge_active_setup_with_microsoft_signature_is_silent() -> None:
    program_files_x86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
    stub = str(Path(program_files_x86) / "Microsoft" / "Edge" / "Application" / "setup.exe")
    signature = {"status": "valid", "signer": "Microsoft Edge", "via": "embedded", "error": None}
    path_state = {"expanded": stub, "executable": stub, "is_pe": True, "in_system_dir": False}
    findings = persistence_ext._analyze_active_setup("{EDGE-GUID}", stub, signature, path_state)
    assert findings == []
