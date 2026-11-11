# -*- coding: utf-8 -*-
"""``core/baseline.py`` V1.5 C2 系统更新时间窗容差测试。

覆盖：
- 纯函数 ``_is_recent_system_update(file_mtime, baseline_generated_at, file_path)``：
  1 小时内 + 系统更新目录 -> True；超窗 / 负向 / 非白名单目录 / 缺失输入 -> False；
- 五个白名单目录（WinSxS / System32\\DriverStore / servicing / $WinREAgent /
  SoftwareDistribution）逐一命中；
- ``diff_reports`` 集成：签名一致、版本未回退、哈希变化且命中时间窗 ->
  ``BENIGN_UPDATE``（完全静默）；超窗 / 非系统目录 / 版本回退 / 签名不一致 ->
  保持 ``MODIFIED + HIGH``；
- ``annotate_findings`` 对时间窗豁免写 ``evidence.recent_system_update`` 且不写
  "疑似被篡改"措辞；
- 原有 V1.4 版本前进豁免 / V1.3 哈希篡改行为不回归。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_baseline_recent_update.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import baseline  # noqa: E402

SYSTEM_ROOT = r"C:\Windows"
BASELINE_AT = "2026-11-11T00:00:00+00:00"

BASE_SHA = "a" * 64
CUR_SHA = "b" * 64

WINSXS = rf"{SYSTEM_ROOT}\WinSxS\amd64_microsoft-windows-foo\foo.dll"
DRIVERSTORE = rf"{SYSTEM_ROOT}\System32\DriverStore\FileRepository\nv\nv.dll"
SERVICING = rf"{SYSTEM_ROOT}\servicing\Packages\package.mum"
WINRE = rf"{SYSTEM_ROOT}\$WinREAgent\staging\setup.exe"
SOFTWARE_DIST = rf"{SYSTEM_ROOT}\SoftwareDistribution\Download\update.exe"
NORMAL_APP = r"C:\Program Files\Vendor\app.dll"

SYSTEM_UPDATE_PATHS = (WINSXS, DRIVERSTORE, SERVICING, WINRE, SOFTWARE_DIST)


def _finding(
    *,
    target: str = WINSXS,
    rule_id: str = "SIG_UNSIGNED",
    severity: str = "HIGH",
    signer: Any = "Microsoft Windows",
    status: str = "valid",
    sha256: str | None = BASE_SHA,
    mtime: Any = None,
    file_version: Any = None,
    pe_timestamp: Any = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {"signature": {"status": status, "signer": signer}}
    if sha256 is not None:
        evidence["sha256"] = sha256
    if mtime is not None:
        evidence["mtime"] = mtime
    pe: dict[str, Any] = {}
    if file_version is not None:
        pe["FileVersion"] = file_version
    if pe_timestamp is not None:
        pe["TimeDateStamp"] = pe_timestamp
    if pe:
        evidence["pe"] = pe
    return {
        "severity": severity,
        "rule_id": rule_id,
        "target": target,
        "detail": "原始描述",
        "evidence": evidence,
    }


def _report(findings: list[dict[str, Any]], generated_at: Any = BASELINE_AT) -> dict[str, Any]:
    return {
        "tool": "TamperScan",
        "version": "1.5.0",
        "generated_at": generated_at,
        "findings": findings,
    }


def _diff(
    baseline_finding: dict[str, Any],
    current_finding: dict[str, Any],
    *,
    baseline_generated_at: Any = BASELINE_AT,
    treat_version_bump_as_benign: bool = False,
) -> baseline.BaselineDiff:
    return baseline.diff_reports(
        _report([baseline_finding], generated_at=baseline_generated_at),
        _report([current_finding]),
        treat_version_bump_as_benign=treat_version_bump_as_benign,
    )


@pytest.fixture(autouse=True)
def _fixed_system_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SystemRoot", SYSTEM_ROOT)
    monkeypatch.delenv("WINDIR", raising=False)


# ---------------------------------------------------------------------------
# 纯函数
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", SYSTEM_UPDATE_PATHS)
def test_recent_system_update_paths(path: str) -> None:
    assert baseline._is_recent_system_update("2026-11-11T00:30:00+00:00", BASELINE_AT, path) is True


def test_recent_system_update_accepts_epoch_and_datetime() -> None:
    from datetime import datetime, timezone

    baseline_moment = datetime(2026, 11, 11, tzinfo=timezone.utc)
    assert (
        baseline._is_recent_system_update(
            baseline_moment.timestamp() + 1800, baseline_moment, WINSXS
        )
        is True
    )
    assert baseline._is_recent_system_update(1800, 0, WINSXS) is True


@pytest.mark.parametrize("delta", [0, 1, 3599, 3600])
def test_recent_system_update_window_inclusive(delta: int) -> None:
    mtime = 1762819200 + delta  # 2026-11-11T00:00:00Z
    assert baseline._is_recent_system_update(mtime, 1762819200, WINSXS) is True


@pytest.mark.parametrize("delta", [-1, 3601, 7200])
def test_recent_system_update_window_exceeded(delta: int) -> None:
    mtime = 1762819200 + delta
    assert baseline._is_recent_system_update(mtime, 1762819200, WINSXS) is False


@pytest.mark.parametrize("path", [NORMAL_APP, r"C:\Users\Public\WinSxS\evil.dll", ""])
def test_recent_system_update_outside_whitelist(path: str) -> None:
    assert baseline._is_recent_system_update("2026-11-11T00:30:00+00:00", BASELINE_AT, path) is False


@pytest.mark.parametrize(
    ("mtime", "generated"),
    [
        (None, BASELINE_AT),
        ("", BASELINE_AT),
        ("not-a-time", BASELINE_AT),
        ("2026-11-11T00:30:00+00:00", None),
        ("2026-11-11T00:30:00+00:00", ""),
        ("2026-11-11T00:30:00+00:00", "bad"),
        (True, BASELINE_AT),
    ],
)
def test_recent_system_update_invalid_inputs(mtime: Any, generated: Any) -> None:
    assert baseline._is_recent_system_update(mtime, generated, WINSXS) is False


def test_recent_system_update_custom_roots() -> None:
    assert (
        baseline._is_recent_system_update(
            "2026-11-11T00:30:00+00:00", BASELINE_AT, r"D:\Custom\WinSxS\x.dll", roots=[r"D:\Custom"]
        )
        is True
    )
    assert (
        baseline._is_recent_system_update(
            "2026-11-11T00:30:00+00:00", BASELINE_AT, WINSXS, roots=[r"D:\Custom"]
        )
        is False
    )


def test_system_update_path_accepts_env_vars() -> None:
    assert baseline._is_system_update_path(r"%SystemRoot%\WinSxS\x.dll") is True


def test_version_not_regressed_semantics() -> None:
    same = _finding(file_version="1.2.3.4", sha256=BASE_SHA)
    forward = _finding(file_version="1.2.3.5", sha256=CUR_SHA)
    backward = _finding(file_version="1.2.3.3", sha256=CUR_SHA)
    assert baseline._version_not_regressed(same, forward) is True
    assert baseline._version_not_regressed(same, same) is True
    assert baseline._version_not_regressed(same, backward) is False
    # 无版本信息 -> 不视为回退
    assert baseline._version_not_regressed(_finding(sha256=BASE_SHA), _finding(sha256=CUR_SHA)) is True


# ---------------------------------------------------------------------------
# diff_reports 集成
# ---------------------------------------------------------------------------


def _pair(**current_overrides: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    target = current_overrides.pop("target", WINSXS)
    base = _finding(sha256=BASE_SHA, target=target)
    current = _finding(sha256=CUR_SHA, target=target, **current_overrides)
    return base, current


def test_recent_update_in_system_dir_is_benign() -> None:
    base, current = _pair(mtime="2026-11-11T00:30:00+00:00")
    diff = _diff(base, current)
    entry = diff.entries[0]
    assert entry.hash_tamper is True
    assert entry.status == baseline.DIFF_BENIGN_UPDATE
    assert entry.benign_update is True
    assert entry.recent_system_update is True
    assert diff.counts["BENIGN_UPDATE"] == 1
    assert diff.counts["MODIFIED"] == 0


def test_recent_update_benign_regardless_of_version_flag() -> None:
    base, current = _pair(mtime="2026-11-11T00:30:00+00:00")
    diff = _diff(base, current, treat_version_bump_as_benign=False)
    assert diff.entries[0].status == baseline.DIFF_BENIGN_UPDATE


def test_recent_update_benign_with_version_progression() -> None:
    base = _finding(sha256=BASE_SHA, file_version="1.2.3.4")
    current = _finding(
        sha256=CUR_SHA, file_version="1.2.3.5", mtime="2026-11-11T00:30:00+00:00"
    )
    diff = _diff(base, current)
    entry = diff.entries[0]
    assert entry.status == baseline.DIFF_BENIGN_UPDATE
    assert entry.recent_system_update is True
    assert entry.version_bump is True


def test_outside_window_stays_modified_high() -> None:
    for mtime in ("2026-11-11T01:00:01+00:00", "2026-11-11T03:00:00+00:00"):
        base, current = _pair(mtime=mtime)
        entry = _diff(base, current).entries[0]
        assert entry.status == baseline.DIFF_MODIFIED
        assert entry.current_severity == "HIGH"
        assert entry.recent_system_update is False


def test_before_baseline_mtime_stays_modified_high() -> None:
    base, current = _pair(mtime="2026-11-10T23:59:00+00:00")
    entry = _diff(base, current).entries[0]
    assert entry.status == baseline.DIFF_MODIFIED
    assert entry.current_severity == "HIGH"


def test_outside_system_dir_stays_modified_high() -> None:
    base, current = _pair(target=NORMAL_APP, mtime="2026-11-11T00:30:00+00:00")
    entry = _diff(base, current).entries[0]
    assert entry.status == baseline.DIFF_MODIFIED
    assert entry.current_severity == "HIGH"


@pytest.mark.parametrize("path", SYSTEM_UPDATE_PATHS)
def test_all_system_update_dirs_downgrade(path: str) -> None:
    base, current = _pair(target=path, mtime="2026-11-11T00:30:00+00:00")
    assert _diff(base, current).entries[0].status == baseline.DIFF_BENIGN_UPDATE


def test_missing_mtime_stays_modified_high() -> None:
    base, current = _pair()
    entry = _diff(base, current).entries[0]
    assert entry.status == baseline.DIFF_MODIFIED
    assert entry.current_severity == "HIGH"


def test_missing_baseline_generated_at_stays_modified_high() -> None:
    base, current = _pair(mtime="2026-11-11T00:30:00+00:00")
    entry = _diff(base, current, baseline_generated_at="").entries[0]
    assert entry.status == baseline.DIFF_MODIFIED


def test_signer_mismatch_stays_modified_high() -> None:
    base = _finding(sha256=BASE_SHA, signer="Contoso Ltd")
    current = _finding(
        sha256=CUR_SHA, signer="Fabrikam Inc", mtime="2026-11-11T00:30:00+00:00"
    )
    entry = _diff(base, current).entries[0]
    assert entry.status == baseline.DIFF_MODIFIED
    assert entry.current_severity == "HIGH"


def test_empty_signer_stays_modified_high() -> None:
    base = _finding(sha256=BASE_SHA, signer=None)
    current = _finding(sha256=CUR_SHA, signer=None, mtime="2026-11-11T00:30:00+00:00")
    entry = _diff(base, current).entries[0]
    assert entry.status == baseline.DIFF_MODIFIED


def test_version_regression_stays_modified_high() -> None:
    base = _finding(sha256=BASE_SHA, file_version="1.2.3.5")
    current = _finding(
        sha256=CUR_SHA, file_version="1.2.3.4", mtime="2026-11-11T00:30:00+00:00"
    )
    entry = _diff(base, current).entries[0]
    assert entry.status == baseline.DIFF_MODIFIED
    assert entry.current_severity == "HIGH"


def test_unchanged_hash_is_not_time_window_benign() -> None:
    base = _finding(sha256=BASE_SHA)
    current = _finding(sha256=BASE_SHA, mtime="2026-11-11T00:30:00+00:00")
    entry = _diff(base, current).entries[0]
    assert entry.status == baseline.DIFF_UNCHANGED
    assert entry.recent_system_update is False


def test_target_env_var_path_downgrades() -> None:
    base = _finding(sha256=BASE_SHA, target=r"%SystemRoot%\WinSxS\foo.dll")
    current = _finding(
        sha256=CUR_SHA, target=r"%SystemRoot%\WinSxS\foo.dll", mtime="2026-11-11T00:30:00+00:00"
    )
    assert _diff(base, current).entries[0].status == baseline.DIFF_BENIGN_UPDATE


def test_entry_to_dict_contains_recent_system_update() -> None:
    base, current = _pair(mtime="2026-11-11T00:30:00+00:00")
    entry = _diff(base, current).entries[0]
    payload = entry.to_dict()
    assert payload["recent_system_update"] is True
    assert payload["benign_update"] is True


# ---------------------------------------------------------------------------
# annotate_findings：完全静默 + 标记
# ---------------------------------------------------------------------------


def test_annotate_recent_system_update_is_silent() -> None:
    base, current = _pair(mtime="2026-11-11T00:30:00+00:00")
    current_report = _report([current])
    diff = baseline.diff_reports(_report([base]), current_report)
    annotated = baseline.annotate_findings(current_report["findings"], diff)
    item = annotated[0]
    assert item["diff_status"] == baseline.DIFF_BENIGN_UPDATE
    assert item["severity"] == "HIGH"  # 不强制改变扫描等级，diff 状态负责静默
    assert "疑似被篡改" not in item["detail"]
    assert "签名有效但文件哈希改变" not in item["detail"]
    assert item["evidence"]["benign_update"] is True
    assert item["evidence"]["recent_system_update"] is True
    assert "version_bump" not in item["evidence"]
    assert "normalized_key" in item


def test_annotate_modified_keeps_tamper_warning() -> None:
    base, current = _pair(mtime="2026-11-11T05:00:00+00:00")
    current_report = _report([current])
    diff = baseline.diff_reports(_report([base]), current_report)
    item = baseline.annotate_findings(current_report["findings"], diff)[0]
    assert item["diff_status"] == baseline.DIFF_MODIFIED
    assert item["severity"] == "HIGH"
    assert "签名有效但文件哈希改变，高度疑似被篡改" in item["detail"]
    assert "recent_system_update" not in item["evidence"]


def test_two_arg_call_is_time_window_only() -> None:
    """兼容任务要求的二元签名：只传时间时仅判定 1 小时时间窗。"""
    assert baseline._is_recent_system_update("2026-11-11T00:30:00+00:00", BASELINE_AT) is True
    assert baseline._is_recent_system_update("2026-11-11T02:00:00+00:00", BASELINE_AT) is False


def test_finding_mtime_falls_back_to_os_stat(tmp_path: Path) -> None:
    target = tmp_path / "recent.dll"
    target.write_bytes(b"MZ")
    import os

    stamp = 1762819200 + 600  # 基线后 10 分钟
    os.utime(target, (stamp, stamp))
    finding = _finding(target=str(target), mtime=None)
    mtime = baseline._finding_file_mtime(finding)
    assert mtime is not None
    assert abs(float(mtime) - stamp) < 2


def test_finding_mtime_missing_file_returns_none() -> None:
    finding = _finding(target=r"C:\Windows\WinSxS\does-not-exist-xyz.dll", mtime=None)
    assert baseline._finding_file_mtime(finding) is None


# ---------------------------------------------------------------------------
# 格式容错 / 路径锚定 / 显式 None（独立验证反馈加固）
# ---------------------------------------------------------------------------

BASE_EPOCH = 1794355200  # 2026-11-11T00:00:00Z


@pytest.mark.parametrize(
    "value",
    [BASE_EPOCH * 1000, float(BASE_EPOCH * 1000), str(BASE_EPOCH * 1000), str(float(BASE_EPOCH * 1000))],
)
def test_to_epoch_seconds_treats_millisecond_values(value: Any) -> None:
    assert baseline._to_epoch_seconds(value) == pytest.approx(BASE_EPOCH)


@pytest.mark.parametrize(
    "value",
    ["2026-11-11T00:00:00", "2026-11-11 00:00:00", "2026-11-11", "2026/11/11"],
)
def test_naive_datetime_strings_are_utc(value: str) -> None:
    """无时区的 ISO/日期字符串必须按 UTC 解释（不随本机时区偏移）。"""
    assert baseline._to_epoch_seconds(value) == pytest.approx(BASE_EPOCH)


def test_naive_datetime_object_is_utc() -> None:
    from datetime import datetime

    assert baseline._to_epoch_seconds(datetime(2026, 11, 11)) == pytest.approx(BASE_EPOCH)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), "nan", "inf", "-inf"])
def test_to_epoch_seconds_rejects_nan_and_infinity(value: Any) -> None:
    assert baseline._to_epoch_seconds(value) is None


def test_explicit_none_or_empty_path_is_false() -> None:
    assert baseline._is_recent_system_update("2026-11-11T00:30:00+00:00", BASELINE_AT, None) is False
    assert baseline._is_recent_system_update("2026-11-11T00:30:00+00:00", BASELINE_AT, "") is False
    # 省略第三个参数 = 仅时间窗（兼容二元签名）
    assert baseline._is_recent_system_update("2026-11-11T00:30:00+00:00", BASELINE_AT) is True


def test_millisecond_string_mtime_downgrades() -> None:
    base = _finding(sha256=BASE_SHA)
    current = _finding(sha256=CUR_SHA, mtime=str((BASE_EPOCH + 1800) * 1000))
    assert _diff(base, current).entries[0].status == baseline.DIFF_BENIGN_UPDATE


def test_epoch_millisecond_generated_at_downgrades() -> None:
    base = _finding(sha256=BASE_SHA)
    current = _finding(sha256=CUR_SHA, mtime=BASE_EPOCH + 1800)
    diff = baseline.diff_reports(
        _report([base], generated_at=BASE_EPOCH * 1000),
        _report([current]),
    )
    assert diff.entries[0].status == baseline.DIFF_BENIGN_UPDATE


@pytest.mark.parametrize(
    "path",
    [
        rf"{SYSTEM_ROOT}\WinSxS2\x.dll",
        rf"{SYSTEM_ROOT}\servicing2\x.mum",
        rf"{SYSTEM_ROOT}\WinSxS\..\..\evil.exe",
        rf"{SYSTEM_ROOT}\WinSxS\..\WinSxS2\evil.exe",
        r"D:\Windows\WinSxS\x.dll",
        r"\server\share\Windows\WinSxS\x.dll",
        r"C:\Users\Public\WinSxS\evil.dll",
    ],
)
def test_path_anchoring_rejects_lookalikes(path: str) -> None:
    assert baseline._is_system_update_path(path) is False


@pytest.mark.parametrize(
    "path",
    [
        rf"{SYSTEM_ROOT}\WinSxS\x.dll",
        "C:/Windows/WinSxS/x.dll",
        r"\\?\C:\Windows\WinSxS\x.dll",
        r"%SystemRoot%\WinSxS\x.dll",
    ],
)
def test_path_anchoring_accepts_legit_forms(path: str) -> None:
    assert baseline._is_system_update_path(path) is True


# ---------------------------------------------------------------------------
# P2：UNC 路径不得触发 os.stat（避免网络阻塞）
# ---------------------------------------------------------------------------


def test_unc_target_never_calls_os_stat(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def _fake_getmtime(path):  # noqa: ANN001
        calls.append(str(path))
        raise OSError("should not be called")

    monkeypatch.setattr(baseline.os.path, "getmtime", _fake_getmtime)
    finding = _finding(target=r"\server\share\Windows\WinSxS\evil.dll")
    assert baseline._finding_file_mtime(finding) is None
    assert calls == []


def test_unc_nonexistent_target_is_fast() -> None:
    import time

    finding = _finding(target=r"\server\share\does-not-exist\evil.dll")
    started = time.monotonic()
    assert baseline._finding_file_mtime(finding) is None
    assert time.monotonic() - started < 0.01


def test_local_drive_target_still_calls_os_stat(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def _fake_getmtime(path):  # noqa: ANN001
        calls.append(str(path))
        return 1234567890.0

    monkeypatch.setattr(baseline.os.path, "getmtime", _fake_getmtime)
    finding = _finding(target=r"C:\Windows\WinSxS\foo.dll")
    assert baseline._finding_file_mtime(finding) == 1234567890.0
    assert calls == [r"C:\Windows\WinSxS\foo.dll"]
