# -*- coding: utf-8 -*-
"""``core/updater.py`` 静默更新检查测试（V1.5 任务组 B1）。

覆盖：
- 版本号解析/比较（``v`` 前缀、预发布后缀、位数不等、垃圾数据不误报）；
- 超时强制 ≤3 秒（``effective_timeout`` 与真实请求参数）；
- GitHub release JSON 字段提取（缺版本号、非法 URL、超长 notes、下载地址）；
- 网络层错误静默降级：超时 / HTTP 错误 / URLError / 非法 JSON / 超大响应；
- 状态机：update_available / up_to_date / ignored / snoozed / disabled / error；
- "不再提示（当前版本）/ 不再提示该版本 / 24h 暂不更新"配置变更均为纯函数；
- ``check_for_update`` 绝不抛异常、不修改入参、不触发真实网络。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_updater.py
"""

from __future__ import annotations

import json
import socket
import sys
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import updater  # noqa: E402
from core.version import __version__  # noqa: E402

NOW = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)


def _payload(tag: str = "v1.6.0", **overrides: object) -> dict:
    payload = {
        "tag_name": tag,
        "name": "TamperScan 1.6.0",
        "html_url": "https://github.com/EnkiduX325/tamper_scan/releases/tag/v1.5.0",
        "body": "## 更新内容\n- PyQt6 UI\n",
        "published_at": "2026-11-20T00:00:00Z",
        "assets": [
            {"name": "tamper_scan_gui.exe", "browser_download_url": "https://example.test/gui.exe"},
        ],
    }
    payload.update(overrides)
    return payload


class _Fetcher:
    def __init__(self, payload: dict | None = None, error: Exception | None = None) -> None:
        self.payload = payload if payload is not None else _payload()
        self.error = error
        self.calls: list[tuple[str, float]] = []

    def __call__(self, endpoint: str, timeout: float) -> dict:
        self.calls.append((endpoint, timeout))
        if self.error is not None:
            raise self.error
        return self.payload


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self._offset = 0
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            chunk = self._body[self._offset :]
            self._offset = len(self._body)
            return chunk
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


class _FakeUrlOpen:
    def __init__(self, response: _FakeResponse | None = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.calls: list[tuple[object, float]] = []

    def __call__(self, request, timeout: float = 0):  # noqa: ANN001
        self.calls.append((request, timeout))
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response


# ---------------------------------------------------------------------------
# 版本号
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1.5.0", (1, 5, 0)),
        ("v1.6.0", (1, 6, 0)),
        ("  V1.5.0  ", (1, 5, 0)),
        ("1.5", (1, 5)),
        ("1.5.0.4", (1, 5, 0, 4)),
        ("1.5.0-beta.1", (1, 5, 0)),
        ("release-1.5.0", (1, 5, 0)),
        (None, None),
        ("", None),
        ("abc", None),
        (True, None),
    ],
)
def test_parse_version(text, expected) -> None:
    assert updater.parse_version(text) == expected


def test_compare_versions_and_is_newer() -> None:
    assert updater.compare_versions("1.4.1", "1.5.0") == -1
    assert updater.compare_versions("1.5.0", "1.4.1") == 1
    assert updater.compare_versions("1.5", "1.5.0") == 0
    assert updater.compare_versions("v1.5.0", "1.5.0") == 0
    assert updater.compare_versions("bad", "1.5.0") == 0
    assert updater.is_newer("1.5.0", "1.4.9") is True
    assert updater.is_newer("1.5.0", "1.5.0") is False
    assert updater.is_newer("1.4.9", "1.5.0") is False
    assert updater.is_newer("bad", "1.5.0") is False


def test_effective_timeout_is_capped_at_three_seconds() -> None:
    assert updater.effective_timeout(30) == 3.0
    assert updater.effective_timeout(3) == 3.0
    assert updater.effective_timeout(1.5) == 1.5
    assert updater.effective_timeout(0) == 3.0
    assert updater.effective_timeout(-5) == 3.0
    assert updater.effective_timeout("bad") == 3.0
    assert updater.MAX_TIMEOUT_SECONDS == 3.0
    assert updater.STARTUP_CHECK_DELAY_MS == 5000
    assert updater.SNOOZE_HOURS == 24


# ---------------------------------------------------------------------------
# release JSON 提取
# ---------------------------------------------------------------------------


def test_extract_release_info_full_payload() -> None:
    info = updater.extract_release_info(_payload())
    assert info["latest_version"] == "v1.6.0"
    assert info["release_url"].startswith("https://github.com/")
    assert info["release_name"] == "TamperScan 1.6.0"
    assert info["published_at"] == "2026-11-20T00:00:00Z"
    assert info["notes"].startswith("## 更新内容")
    assert info["download_url"] == "https://example.test/gui.exe"


def test_extract_release_info_falls_back_to_name() -> None:
    info = updater.extract_release_info({"name": "TamperScan 1.6.0"})
    assert info["latest_version"] == "TamperScan 1.6.0"
    assert info["release_url"] == updater.RELEASES_PAGE


def test_extract_release_info_invalid_url_falls_back() -> None:
    info = updater.extract_release_info(_payload(html_url="javascript:alert(1)"))
    assert info["release_url"] == updater.RELEASES_PAGE


def test_extract_release_info_truncates_long_notes() -> None:
    info = updater.extract_release_info(_payload(body="x" * (updater.MAX_NOTES_CHARS + 100)))
    assert info["notes"] is not None
    assert len(info["notes"]) == updater.MAX_NOTES_CHARS
    assert info["notes"].endswith("…")


@pytest.mark.parametrize("payload", [{}, {"body": "x"}, {"tag_name": "not-a-version"}, [], "text", None])
def test_extract_release_info_invalid_payload(payload) -> None:
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.extract_release_info(payload)
    assert exc_info.value.kind == "parse"


# ---------------------------------------------------------------------------
# 网络请求（mock urlopen）
# ---------------------------------------------------------------------------


def test_fetch_latest_release_passes_headers_and_three_second_timeout() -> None:
    body = json.dumps(_payload()).encode("utf-8")
    fake = _FakeUrlOpen(_FakeResponse(body))
    payload = updater.fetch_latest_release(updater.DEFAULT_RELEASE_API, timeout=30, urlopen=fake)
    assert payload["tag_name"] == "v1.6.0"
    request, timeout = fake.calls[0]
    assert timeout == 3.0
    assert request.full_url == updater.DEFAULT_RELEASE_API
    assert request.get_header("User-agent") == updater.USER_AGENT
    assert "github" in request.get_header("Accept")
    assert fake.response is not None and fake.response.closed is True


def test_fetch_latest_release_timeout_error() -> None:
    fake = _FakeUrlOpen(error=socket.timeout("timed out"))
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.fetch_latest_release(urlopen=fake)
    assert exc_info.value.kind == "timeout"
    assert "超时" in exc_info.value.message


def test_fetch_latest_release_url_timeout_error() -> None:
    fake = _FakeUrlOpen(error=urllib.error.URLError(socket.timeout("timed out")))
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.fetch_latest_release(urlopen=fake)
    assert exc_info.value.kind == "timeout"


def test_fetch_latest_release_url_error() -> None:
    fake = _FakeUrlOpen(error=urllib.error.URLError("name resolution failed"))
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.fetch_latest_release(urlopen=fake)
    assert exc_info.value.kind == "network"
    assert "网络不可用" in exc_info.value.message


def test_fetch_latest_release_http_error() -> None:
    error = urllib.error.HTTPError(
        updater.DEFAULT_RELEASE_API, 403, "rate limited", hdrs=None, fp=None
    )
    fake = _FakeUrlOpen(error=error)
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.fetch_latest_release(urlopen=fake)
    assert exc_info.value.kind == "http"
    assert "403" in exc_info.value.message


def test_fetch_latest_release_invalid_json() -> None:
    fake = _FakeUrlOpen(_FakeResponse(b"{not json"))
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.fetch_latest_release(urlopen=fake)
    assert exc_info.value.kind == "parse"


def test_fetch_latest_release_non_object_json() -> None:
    fake = _FakeUrlOpen(_FakeResponse(b"[]"))
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.fetch_latest_release(urlopen=fake)
    assert exc_info.value.kind == "parse"


def test_fetch_latest_release_oversized_response() -> None:
    fake = _FakeUrlOpen(_FakeResponse(b"a" * (updater.MAX_RESPONSE_BYTES + 1)))
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.fetch_latest_release(urlopen=fake)
    assert exc_info.value.kind == "parse"


def test_fetch_latest_release_invalid_endpoint() -> None:
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.fetch_latest_release("file:///etc/passwd")
    assert exc_info.value.kind == "config"


def test_fetch_latest_release_os_error() -> None:
    fake = _FakeUrlOpen(error=OSError("network down"))
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.fetch_latest_release(urlopen=fake)
    assert exc_info.value.kind == "network"


def test_fetch_latest_release_unexpected_exception_wrapped() -> None:
    """fetch 对外只抛 UpdateError（不把任意异常泄漏给调用方）。"""
    fake = _FakeUrlOpen(error=RuntimeError("boom"))
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.fetch_latest_release(urlopen=fake)
    assert exc_info.value.kind == "unknown"
    assert "RuntimeError" in exc_info.value.message


# ---------------------------------------------------------------------------
# check_for_update 状态机
# ---------------------------------------------------------------------------


def test_check_for_update_available() -> None:
    fetcher = _Fetcher()
    result = updater.check_for_update("1.5.0", {}, fetcher=fetcher, now=NOW)
    assert result.status == updater.STATUS_UPDATE_AVAILABLE
    assert result.available is True
    assert result.current_version == "1.5.0"
    assert result.latest_version == "v1.6.0"
    assert result.release_url and result.release_url.startswith("https://")
    assert result.download_url == "https://example.test/gui.exe"
    assert result.checked_at == "2026-11-11T12:00:00+00:00"
    assert result.error is None
    assert fetcher.calls and fetcher.calls[0][1] == 3.0


def test_check_for_update_same_and_older_are_up_to_date() -> None:
    fetcher = _Fetcher(_payload(tag="v1.5.0"))
    assert updater.check_for_update("1.5.0", {}, fetcher=fetcher).status == updater.STATUS_UP_TO_DATE
    fetcher = _Fetcher(_payload(tag="v1.3.9"))
    assert updater.check_for_update("1.5.0", {}, fetcher=fetcher).status == updater.STATUS_UP_TO_DATE


def test_check_for_update_disabled_skips_network() -> None:
    fetcher = _Fetcher()
    result = updater.check_for_update("1.5.0", {"update": {"auto_check": False}}, fetcher=fetcher)
    assert result.status == updater.STATUS_DISABLED
    assert fetcher.calls == []


def test_is_auto_check_enabled_tolerates_dirty_values() -> None:
    assert updater.is_auto_check_enabled({"update": {"auto_check": False}}) is False
    assert updater.is_auto_check_enabled({"update": {"auto_check": "no"}}) is True
    assert updater.is_auto_check_enabled({"update": {"auto_check": 0}}) is True
    assert updater.is_auto_check_enabled({}) is True
    assert updater.is_auto_check_enabled(None) is True


def test_check_for_update_ignore_current_version_skips_network() -> None:
    fetcher = _Fetcher()
    config = {"update": {"ignored_current_version": "1.5.0"}}
    result = updater.check_for_update("1.5.0", config, fetcher=fetcher)
    assert result.status == updater.STATUS_IGNORED
    assert fetcher.calls == []


def test_check_for_update_ignored_specific_version() -> None:
    fetcher = _Fetcher()
    config = {"update": {"ignored_versions": ["1.6.0"]}}
    result = updater.check_for_update("1.5.0", config, fetcher=fetcher)
    assert result.status == updater.STATUS_IGNORED
    assert result.latest_version == "v1.6.0"
    assert fetcher.calls


def test_check_for_update_snoozed_skips_network() -> None:
    fetcher = _Fetcher()
    config = {"update": {"snooze_until": "2026-11-12T00:00:00+00:00"}}
    result = updater.check_for_update("1.5.0", config, fetcher=fetcher, now=NOW)
    assert result.status == updater.STATUS_SNOOZED
    assert fetcher.calls == []


def test_check_for_update_expired_snooze_checks_again() -> None:
    fetcher = _Fetcher()
    config = {"update": {"snooze_until": "2026-11-10T00:00:00+00:00"}}
    result = updater.check_for_update("1.5.0", config, fetcher=fetcher, now=NOW)
    assert result.status == updater.STATUS_UPDATE_AVAILABLE
    assert fetcher.calls


def test_check_for_update_endpoint_priority() -> None:
    fetcher = _Fetcher()
    updater.check_for_update("1.5.0", {"update": {"release_api": "https://config.test/latest"}}, fetcher=fetcher)
    assert fetcher.calls[-1][0] == "https://config.test/latest"
    updater.check_for_update(
        "1.5.0",
        {"update": {"release_api": "https://config.test/latest"}},
        endpoint="https://explicit.test/latest",
        fetcher=fetcher,
    )
    assert fetcher.calls[-1][0] == "https://explicit.test/latest"


def test_check_for_update_forced_timeout_passed_to_fetcher() -> None:
    fetcher = _Fetcher()
    updater.check_for_update("1.5.0", {}, timeout=60, fetcher=fetcher)
    assert fetcher.calls[0][1] == 3.0


def test_check_for_update_network_error_is_silent() -> None:
    fetcher = _Fetcher(error=updater.UpdateError("更新检查超时（3 秒）", kind="timeout"))
    result = updater.check_for_update("1.5.0", {}, fetcher=fetcher)
    assert result.status == updater.STATUS_ERROR
    assert result.error_kind == "timeout"
    assert "超时" in (result.error or "")
    assert result.available is False


def test_check_for_update_unexpected_exception_is_silent() -> None:
    fetcher = _Fetcher(error=RuntimeError("boom"))
    result = updater.check_for_update("1.5.0", {}, fetcher=fetcher)
    assert result.status == updater.STATUS_ERROR
    assert result.error_kind == "unknown"
    assert "RuntimeError" in (result.error or "")


def test_check_for_update_classifies_timeout_and_os_error_from_fetcher() -> None:
    timeout_result = updater.check_for_update("1.5.0", {}, fetcher=_Fetcher(error=socket.timeout("t")))
    assert timeout_result.status == updater.STATUS_ERROR
    assert timeout_result.error_kind == "timeout"
    assert "超时" in (timeout_result.error or "")
    os_result = updater.check_for_update("1.5.0", {}, fetcher=_Fetcher(error=OSError("down")))
    assert os_result.status == updater.STATUS_ERROR
    assert os_result.error_kind == "network"
    assert "网络不可用" in (os_result.error or "")


def test_check_for_update_does_not_mutate_config() -> None:
    config = {"update": {"ignored_versions": ["1.0.0"], "auto_check": True}}
    snapshot = json.loads(json.dumps(config))
    updater.check_for_update("1.5.0", config, fetcher=_Fetcher())
    assert config == snapshot


def test_check_for_update_defaults_to_package_version(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TAMPERSCAN_CONFIG_DIR", str(tmp_path / "none"))
    result = updater.check_for_update(fetcher=_Fetcher())
    assert result.current_version == __version__


def test_check_for_update_without_config_file_uses_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TAMPERSCAN_CONFIG_DIR", str(tmp_path / "missing"))
    result = updater.check_for_update("1.5.0", None, fetcher=_Fetcher())
    assert result.status == updater.STATUS_UPDATE_AVAILABLE


# ---------------------------------------------------------------------------
# 配置变更纯函数
# ---------------------------------------------------------------------------


def test_ignore_version_is_pure_and_dedupes() -> None:
    original = {"update": {"ignored_versions": []}}
    updated = updater.ignore_version(original, "v1.5.1")
    updated = updater.ignore_version(updated, "1.5.1")
    assert original["update"]["ignored_versions"] == []
    assert updated["update"]["ignored_versions"] == ["1.5.1"]
    assert updater.is_version_ignored(updated, "v1.5.1") is True
    assert updater.is_version_ignored(updated, "1.5.2") is False
    assert updater.is_version_ignored(updated, None) is False


def test_ignore_current_version() -> None:
    updated = updater.ignore_current_version({"update": {}}, "v1.5.0")
    assert updated["update"]["ignored_current_version"] == "1.5.0"
    assert updater.is_current_version_ignored(updated, "1.5.0") is True
    assert updater.is_current_version_ignored(updated, "1.6.0") is False
    assert updater.is_current_version_ignored({}, "1.5.0") is False


def test_snooze_updates_sets_24_hours() -> None:
    original = {"update": {}}
    updated = updater.snooze_updates(original, now=NOW)
    until = updater.snooze_until(updated)
    assert until == NOW + timedelta(hours=24)
    assert updater.is_snoozed(updated, now=NOW + timedelta(hours=1)) is True
    assert updater.is_snoozed(updated, now=NOW + timedelta(hours=25)) is False
    assert original["update"] == {}
    custom = updater.snooze_updates({}, hours=2, now=NOW)
    assert updater.snooze_until(custom) == NOW + timedelta(hours=2)


def test_clear_update_ignores() -> None:
    config = {
        "update": {
            "ignored_versions": ["1.5.0"],
            "ignored_current_version": "1.5.0",
            "snooze_until": "2026-11-12T00:00:00+00:00",
        }
    }
    cleared = updater.clear_update_ignores(config)
    assert cleared["update"]["ignored_versions"] == []
    assert cleared["update"]["ignored_current_version"] is None
    assert cleared["update"]["snooze_until"] is None
    assert updater.is_snoozed(cleared, now=NOW) is False


def test_record_check_updates_state() -> None:
    result = updater.check_for_update("1.5.0", {}, fetcher=_Fetcher(), now=NOW)
    original = {"update": {}}
    updated = updater.record_check(original, result, now=NOW)
    assert updated["update"]["last_check_at"] == "2026-11-11T12:00:00+00:00"
    assert updated["update"]["last_result"] == updater.STATUS_UPDATE_AVAILABLE
    assert updated["update"]["last_latest_version"] == "1.6.0"
    assert original["update"] == {}


def test_describe_result() -> None:
    available = updater.check_for_update("1.5.0", {}, fetcher=_Fetcher(), now=NOW)
    assert "新版本" in updater.describe_result(available)
    assert "已是最新" in updater.describe_result(
        updater.check_for_update("1.6.0", {}, fetcher=_Fetcher(), now=NOW)
    )
    assert "已忽略" in updater.describe_result(updater.UpdateCheckResult(updater.STATUS_IGNORED, "1.5.0"))
    assert "24 小时" in updater.describe_result(updater.UpdateCheckResult(updater.STATUS_SNOOZED, "1.5.0"))
    assert "已关闭" in updater.describe_result(updater.UpdateCheckResult(updater.STATUS_DISABLED, "1.5.0"))
    assert "网络不佳" in updater.describe_result(
        updater.UpdateCheckResult(updater.STATUS_ERROR, "1.5.0", error="断网")
    )


def test_result_to_dict_roundtrip() -> None:
    result = updater.check_for_update("1.5.0", {}, fetcher=_Fetcher(), now=NOW)
    payload = result.to_dict()
    assert payload["status"] == updater.STATUS_UPDATE_AVAILABLE
    assert payload["latest_version"] == "v1.6.0"
    assert set(payload) == {
        "status",
        "current_version",
        "latest_version",
        "release_url",
        "release_name",
        "published_at",
        "notes",
        "download_url",
        "error_kind",
        "error",
        "checked_at",
    }


def test_statuses_cover_state_machine() -> None:
    assert set(updater.STATUSES) == {
        updater.STATUS_UPDATE_AVAILABLE,
        updater.STATUS_UP_TO_DATE,
        updater.STATUS_IGNORED,
        updater.STATUS_SNOOZED,
        updater.STATUS_DISABLED,
        updater.STATUS_ERROR,
    }


# ---------------------------------------------------------------------------
# 加固回归（独立验证反馈：HTTPS / 单调时钟 / 非法超时）
# ---------------------------------------------------------------------------


def test_effective_timeout_rejects_nan_and_inf() -> None:
    assert updater.effective_timeout(float("nan")) == 3.0
    assert updater.effective_timeout(float("inf")) == 3.0
    assert updater.effective_timeout(float("-inf")) == 3.0


def test_fetch_rejects_http_endpoint() -> None:
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.fetch_latest_release("http://example.test/latest")
    assert exc_info.value.kind == "config"
    assert "HTTPS" in exc_info.value.message


def test_configured_http_endpoint_is_ignored() -> None:
    fetcher = _Fetcher()
    updater.check_for_update(
        "1.5.0",
        {"update": {"release_api": "http://example.test/latest"}},
        fetcher=fetcher,
    )
    assert fetcher.calls[0][0] == updater.DEFAULT_RELEASE_API


def test_fetch_wall_clock_deadline_stops_slow_drip(monkeypatch: pytest.MonkeyPatch) -> None:
    """M5 回归：服务端慢速滴流时，单调时钟截止时间必须中止读取。"""

    class _Clock:
        value = 0.0

        def __call__(self) -> float:
            return self.value

    clock = _Clock()

    class _SlowResponse:
        def read(self, size: int = -1) -> bytes:
            clock.value += 4.0  # 单次读取跨过 3 秒预算
            return b'{"tag_name": "v1.6.0"}'

        def close(self) -> None:
            pass

    monkeypatch.setattr(updater, "_monotonic", clock)
    with pytest.raises(updater.UpdateError) as exc_info:
        updater.fetch_latest_release(urlopen=_FakeUrlOpen(_SlowResponse()))
    assert exc_info.value.kind == "timeout"


def test_release_urls_require_https() -> None:
    info = updater.extract_release_info(
        _payload(
            html_url="http://evil.test/release",
            assets=[{"browser_download_url": "http://evil.test/gui.exe"}],
        )
    )
    assert info["release_url"] == updater.RELEASES_PAGE
    assert info["download_url"] is None


def test_effective_timeout_rejects_bool() -> None:
    assert updater.effective_timeout(True) == 3.0
    assert updater.effective_timeout(False) == 3.0
