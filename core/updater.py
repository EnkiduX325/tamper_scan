# -*- coding: utf-8 -*-
"""静默更新检查（V1.5 新增，弱网容忍）。

设计约束（对应 V1.5 任务组 B1）
------------------------------
- **非阻塞**：本模块只提供纯同步函数，绝不创建线程 / 触碰 UI；GUI 侧在
  :class:`QThread` 中调用 :func:`check_for_update`，通过信号回主线程。
- **强制 3 秒超时**：HTTP 请求的 socket ``timeout`` 经 :func:`effective_timeout`
  夹到 ``(0, 3.0]`` 秒，且响应体读取带单调时钟截止时间（防慢速滴流）；DNS 解析
  受操作系统控制，GUI 侧仍在后台线程执行，不阻塞主线程。
- **仅 HTTPS**：默认与自定义更新源、release 下载链接都必须是 HTTPS，防止公共
  Wi-Fi / 弱网环境下被劫持伪造更新提示。
- **静默降级**：任何网络 / HTTP / JSON / 意外异常都转换为 ``STATUS_ERROR``
  结果（含中文 ``error`` 文案），**绝不抛异常**，绝不影响本地扫描。
- **无隐藏副作用**：传入 ``config`` 时完全纯函数；仅在 ``config=None`` 时
  惰性读取用户配置（只读）。

状态机::

    disabled  --auto_check=False
    ignored   --当前运行版本被"不再提示"，或 latest 在 ignored_versions 中
    snoozed   --"暂不更新"未满 24h（直接跳过网络请求）
    error     --超时/断网/HTTP 错误/响应非法（静默）
    up_to_date
    update_available
"""

from __future__ import annotations

import copy
import json
import math
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .version import __version__

#: 单调时钟（模块级别名便于测试注入"慢速滴流"响应）
_monotonic = time.monotonic

#: 默认 GitHub latest release API（仓库地址见 README / CI badge）
DEFAULT_RELEASE_API = "https://api.github.com/repos/EnkiduX325/tamper_scan/releases/latest"

#: 无 API 信息时的下载页兜底
RELEASES_PAGE = "https://github.com/EnkiduX325/tamper_scan/releases"

#: 弱网强制超时（秒）
DEFAULT_TIMEOUT_SECONDS = 3.0
MAX_TIMEOUT_SECONDS = 3.0

#: "暂不更新"静默窗口
SNOOZE_HOURS = 24

#: GUI 启动后延迟检查更新（毫秒）
STARTUP_CHECK_DELAY_MS = 5000

#: 响应体上限（GitHub release JSON 通常 < 100KB，超限视为异常响应）
MAX_RESPONSE_BYTES = 512 * 1024

#: release notes 展示上限，避免 Dialog 被超长 Markdown 撑爆
MAX_NOTES_CHARS = 4000

USER_AGENT = f"TamperScan/{__version__}"

STATUS_UPDATE_AVAILABLE = "update_available"
STATUS_UP_TO_DATE = "up_to_date"
STATUS_IGNORED = "ignored"
STATUS_SNOOZED = "snoozed"
STATUS_DISABLED = "disabled"
STATUS_ERROR = "error"

STATUSES: tuple[str, ...] = (
    STATUS_UPDATE_AVAILABLE,
    STATUS_UP_TO_DATE,
    STATUS_IGNORED,
    STATUS_SNOOZED,
    STATUS_DISABLED,
    STATUS_ERROR,
)

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,3})")

#: 更新检查只允许 HTTPS（防止弱网 / 公共 Wi-Fi 下被劫持伪造更新提示）
_HTTPS_RE = re.compile(r"(?i)^https://")

#: 单次 read 的分块大小（配合单调时钟截止时间做总时长约束）
READ_CHUNK_BYTES = 64 * 1024


class UpdateError(Exception):
    """更新检查内部错误（由 ``check_for_update`` 捕获并转成 STATUS_ERROR）。"""

    def __init__(self, message: str, kind: str = "network") -> None:
        super().__init__(str(message))
        self.message: str = str(message)
        self.kind: str = str(kind or "unknown")


@dataclass
class UpdateCheckResult:
    """一次更新检查的结果（不可变语义：调用方只读，GUI 直接渲染）。"""

    status: str
    current_version: str
    latest_version: str | None = None
    release_url: str | None = None
    release_name: str | None = None
    published_at: str | None = None
    notes: str | None = None
    download_url: str | None = None
    error_kind: str | None = None
    error: str | None = None
    checked_at: str | None = None

    @property
    def available(self) -> bool:
        """是否存在可提示的新版本。"""
        return self.status == STATUS_UPDATE_AVAILABLE

    @property
    def is_error(self) -> bool:
        return self.status == STATUS_ERROR

    def to_dict(self) -> dict[str, Any]:
        """转纯 dict（日志 / 测试 / 未来上报用）。"""
        return {
            "status": self.status,
            "current_version": self.current_version,
            "latest_version": self.latest_version,
            "release_url": self.release_url,
            "release_name": self.release_name,
            "published_at": self.published_at,
            "notes": self.notes,
            "download_url": self.download_url,
            "error_kind": self.error_kind,
            "error": self.error,
            "checked_at": self.checked_at,
        }


# ---------------------------------------------------------------------------
# 时间 / 版本号
# ---------------------------------------------------------------------------


def _now(now: datetime | float | int | None = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, datetime):
        return now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromtimestamp(float(now), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return datetime.now(timezone.utc)


def _to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _parse_iso(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def parse_version(text: Any) -> tuple[int, ...] | None:
    """解析版本号（容忍 ``v`` 前缀 / 预发布后缀 / 前后空白）；失败返回 ``None``。"""
    if text is None or isinstance(text, bool):
        return None
    match = _VERSION_RE.search(str(text))
    if not match:
        return None
    parts = match.group(1).split(".")
    try:
        return tuple(int(part) for part in parts)
    except (TypeError, ValueError):
        return None


def compare_versions(left: Any, right: Any) -> int:
    """比较两个版本号：``left < right`` 返回 -1，相等 0，``left > right`` 返回 1。

    任一侧无法解析时返回 0（视为相同，不提示更新，避免垃圾数据误报）。
    """
    left_parts = parse_version(left)
    right_parts = parse_version(right)
    if left_parts is None or right_parts is None:
        return 0
    width = max(len(left_parts), len(right_parts))
    left_padded = left_parts + (0,) * (width - len(left_parts))
    right_padded = right_parts + (0,) * (width - len(right_parts))
    if left_padded == right_padded:
        return 0
    return 1 if left_padded > right_padded else -1


def is_newer(latest: Any, current: Any) -> bool:
    """``latest`` 是否比 ``current`` 新。"""
    return compare_versions(latest, current) > 0


def _versions_equal(left: Any, right: Any) -> bool:
    """版本等价判断（``1.5`` == ``1.5.0``；都可解析时按数值比较）。"""
    left_parsed = parse_version(left)
    right_parsed = parse_version(right)
    if left_parsed is not None and right_parsed is not None:
        return compare_versions(left, right) == 0
    return str(left or "").strip().casefold() == str(right or "").strip().casefold()


def _clean_version(value: Any) -> str:
    """存配置用的版本展示串：去空白、去 ``v`` 前缀。"""
    text = str(value or "").strip()
    if text[:1] in ("v", "V"):
        text = text[1:].strip()
    return text[:64]


def effective_timeout(timeout: Any = DEFAULT_TIMEOUT_SECONDS) -> float:
    """把调用方超时夹到 ``(0, 3.0]`` 秒：弱网下网络请求最多占用 3 秒。

    ``NaN`` / ``inf`` / 非数字 / 非正数等脏输入统一回退 3 秒，避免把非法超时
    抛给 ``urlopen``。
    """
    try:
        value = 3.0 if isinstance(timeout, bool) else float(timeout)
    except (TypeError, ValueError):
        value = DEFAULT_TIMEOUT_SECONDS
    if not math.isfinite(value) or value <= 0:
        value = DEFAULT_TIMEOUT_SECONDS
    return min(value, MAX_TIMEOUT_SECONDS)


# ---------------------------------------------------------------------------
# 配置读写（纯函数：返回新 dict，不修改入参，便于 GUI 先弹窗再落盘）
# ---------------------------------------------------------------------------


def _update_section(config: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(config, dict):
        return {}
    section = config.get("update")
    return section if isinstance(section, dict) else {}


def _copy_config(config: dict[str, Any] | None) -> dict[str, Any]:
    return copy.deepcopy(config) if isinstance(config, dict) else {}


def _ensure_update_section(config: dict[str, Any]) -> dict[str, Any]:
    section = config.get("update")
    if not isinstance(section, dict):
        section = {}
        config["update"] = section
    return section


def is_auto_check_enabled(config: dict[str, Any] | None) -> bool:
    """启动时是否自动检查更新（缺省 True；非 bool 的脏数据按 True 处理）。"""
    value = _update_section(config).get("auto_check", True)
    return value if isinstance(value, bool) else True


def ignored_versions(config: dict[str, Any] | None) -> list[str]:
    """已"不再提示"的版本列表（返回副本）。"""
    raw = _update_section(config).get("ignored_versions")
    if not isinstance(raw, (list, tuple)):
        return []
    return [str(item) for item in raw if str(item or "").strip()]


def is_version_ignored(config: dict[str, Any] | None, version: Any) -> bool:
    """指定最新版本是否被用户加入"不再提示"。"""
    target = _clean_version(version)
    if not target:
        return False
    return any(_versions_equal(item, target) for item in ignored_versions(config))


def is_current_version_ignored(config: dict[str, Any] | None, current_version: Any) -> bool:
    """当前运行版本是否被"不再提示"（用户选择后，本次安装内不再提醒）。"""
    raw = _update_section(config).get("ignored_current_version")
    if not isinstance(raw, str) or not raw.strip():
        return False
    return _versions_equal(raw, current_version)


def snooze_until(config: dict[str, Any] | None) -> datetime | None:
    """"暂不更新"截止时间；未设置或非法返回 ``None``。"""
    return _parse_iso(_update_section(config).get("snooze_until"))


def is_snoozed(config: dict[str, Any] | None, now: datetime | float | int | None = None) -> bool:
    """是否仍处于"暂不更新"静默窗口内。"""
    until = snooze_until(config)
    return until is not None and _now(now) < until


def ignore_version(config: dict[str, Any] | None, version: Any) -> dict[str, Any]:
    """把指定版本加入"不再提示"，返回新配置 dict。"""
    updated = _copy_config(config)
    clean = _clean_version(version)
    if not clean:
        return updated
    section = _ensure_update_section(updated)
    existing = section.get("ignored_versions")
    versions = list(existing) if isinstance(existing, (list, tuple)) else []
    if not any(_versions_equal(item, clean) for item in versions):
        versions.append(clean)
    section["ignored_versions"] = [str(item) for item in versions][-100:]
    return updated


def ignore_current_version(config: dict[str, Any] | None, current_version: Any = None) -> dict[str, Any]:
    """记录"不再提示"（记入 config 当前版本），返回新配置 dict。"""
    updated = _copy_config(config)
    clean = _clean_version(current_version or __version__)
    _ensure_update_section(updated)["ignored_current_version"] = clean or __version__
    return updated


def snooze_updates(
    config: dict[str, Any] | None,
    hours: int = SNOOZE_HOURS,
    now: datetime | float | int | None = None,
) -> dict[str, Any]:
    """记录"暂不更新"，返回新配置 dict（默认 24 小时内不再弹窗）。"""
    updated = _copy_config(config)
    try:
        span = max(1, min(int(hours), 24 * 30))
    except (TypeError, ValueError):
        span = SNOOZE_HOURS
    until = _now(now) + timedelta(hours=span)
    _ensure_update_section(updated)["snooze_until"] = _to_iso(until)
    return updated


def clear_update_ignores(config: dict[str, Any] | None) -> dict[str, Any]:
    """清除"不再提示 / 暂不更新"状态，返回新配置 dict（设置中心"重新启用提醒"）。"""
    updated = _copy_config(config)
    section = _ensure_update_section(updated)
    section["ignored_versions"] = []
    section["ignored_current_version"] = None
    section["snooze_until"] = None
    return updated


def record_check(
    config: dict[str, Any] | None,
    result: "UpdateCheckResult",
    now: datetime | float | int | None = None,
) -> dict[str, Any]:
    """把最近一次检查结果写回配置（返回新 dict；GUI 负责 ``config.save_config``）。"""
    updated = _copy_config(config)
    section = _ensure_update_section(updated)
    section["last_check_at"] = _to_iso(_now(now))
    section["last_result"] = str(getattr(result, "status", "") or "") or None
    last_latest = getattr(result, "latest_version", None)
    section["last_latest_version"] = _clean_version(last_latest) or None
    return updated


# ---------------------------------------------------------------------------
# 网络请求（GET GitHub latest release，3 秒硬超时）
# ---------------------------------------------------------------------------


def fetch_latest_release(
    endpoint: str = DEFAULT_RELEASE_API,
    timeout: Any = DEFAULT_TIMEOUT_SECONDS,
    *,
    urlopen: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """GET 最新 release JSON；失败抛 :class:`UpdateError`（由上层静默降级）。

    超时双重约束：

    1. ``urlopen(..., timeout=seconds)``：单个 socket 操作的超时（≤3 秒）；
    2. 单调时钟截止时间：响应体按 :data:`READ_CHUNK_BYTES` 分块读取，总读取
       时长超过 3 秒立即中止——防止服务端"慢速滴流"绕过单次读超时。

    仍无法中断的是 DNS 解析（受操作系统解析器控制）；GUI 侧在 QThread 中调用，
    不会阻塞主线程。

    Args:
        endpoint: release API 地址（**必须 HTTPS**）。
        timeout: 期望超时；实际值经 :func:`effective_timeout` 限制到 ≤3 秒。
        urlopen: 可注入的 ``urllib.request.urlopen`` 兼容函数（测试 mock）。
    """
    api = str(endpoint or DEFAULT_RELEASE_API).strip() or DEFAULT_RELEASE_API
    if not _HTTPS_RE.match(api):
        raise UpdateError("更新源地址必须使用 HTTPS", kind="config")
    seconds = effective_timeout(timeout)
    deadline = _monotonic() + seconds
    request = urllib.request.Request(
        api,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    opener = urlopen or urllib.request.urlopen
    response: Any = None
    chunks: list[bytes] = []
    total = 0
    try:
        response = opener(request, timeout=seconds)
        while True:
            if _monotonic() >= deadline:
                raise UpdateError("更新检查超时（3 秒）", kind="timeout")
            chunk = response.read(READ_CHUNK_BYTES)
            if not chunk:
                break
            if not isinstance(chunk, (bytes, bytearray)):
                raise UpdateError("更新源响应类型无效", kind="parse")
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise UpdateError("更新源响应过大", kind="parse")
            chunks.append(bytes(chunk))
        raw = b"".join(chunks)
    except UpdateError:
        raise
    except urllib.error.HTTPError as exc:
        raise UpdateError(f"更新服务返回 HTTP {getattr(exc, 'code', '?')}", kind="http") from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, (TimeoutError, socket.timeout)) or "timed out" in str(reason).lower():
            raise UpdateError("更新检查超时（3 秒）", kind="timeout") from exc
        raise UpdateError(f"网络不可用：{reason}", kind="network") from exc
    except (TimeoutError, socket.timeout) as exc:  # noqa: UP041 - 兼容 3.10 别名
        raise UpdateError("更新检查超时（3 秒）", kind="timeout") from exc
    except OSError as exc:
        raise UpdateError(f"网络不可用：{exc}", kind="network") from exc
    except Exception as exc:  # noqa: BLE001 - 保持 fetch 的"只抛 UpdateError"契约
        raise UpdateError(f"更新检查失败：{type(exc).__name__}", kind="unknown") from exc
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # noqa: BLE001 - 关闭失败与更新检查无关
                pass

    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise UpdateError("更新源响应不是合法 JSON", kind="parse") from exc
    if not isinstance(payload, dict):
        raise UpdateError("更新源返回格式无效（应为 JSON 对象）", kind="parse")
    return payload


def extract_release_info(payload: Any) -> dict[str, Any]:
    """从 GitHub release JSON 提取展示字段；版本号缺失/非法时抛 ``UpdateError``。"""
    if not isinstance(payload, dict):
        raise UpdateError("更新源返回格式无效", kind="parse")
    tag = payload.get("tag_name") or payload.get("name") or payload.get("version")
    if not isinstance(tag, str) or parse_version(tag) is None:
        raise UpdateError("更新源返回格式无效（缺少可用版本号）", kind="parse")
    latest_version = tag.strip()
    html_url = payload.get("html_url")
    release_url = (
        html_url.strip()
        if isinstance(html_url, str) and _HTTPS_RE.match(html_url.strip())
        else RELEASES_PAGE
    )
    notes = payload.get("body") if isinstance(payload.get("body"), str) else ""
    notes = notes.strip()
    if len(notes) > MAX_NOTES_CHARS:
        notes = notes[: MAX_NOTES_CHARS - 1] + "…"
    download_url = None
    assets = payload.get("assets")
    if isinstance(assets, list):
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            candidate = asset.get("browser_download_url")
            if isinstance(candidate, str) and _HTTPS_RE.match(candidate.strip()):
                download_url = candidate.strip()
                break
    release_name = payload.get("name") if isinstance(payload.get("name"), str) else ""
    published_at = payload.get("published_at") if isinstance(payload.get("published_at"), str) else ""
    return {
        "latest_version": latest_version,
        "release_url": release_url,
        "release_name": release_name.strip() or None,
        "published_at": published_at.strip() or None,
        "notes": notes or None,
        "download_url": download_url,
    }


def _configured_endpoint(config: dict[str, Any] | None) -> str | None:
    raw = _update_section(config).get("release_api")
    if isinstance(raw, str) and _HTTPS_RE.match(raw.strip()):
        return raw.strip()
    return None


def _load_default_config() -> dict[str, Any]:
    """延迟加载用户配置（避免与 :mod:`core.config` 形成导入环）。"""
    try:
        from . import config as config_module

        return config_module.load_config()
    except Exception:  # noqa: BLE001 - 配置读取失败按默认配置继续
        return {}


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------


def check_for_update(
    current_version: str | None = None,
    config: dict[str, Any] | None = None,
    *,
    endpoint: str | None = None,
    timeout: Any = DEFAULT_TIMEOUT_SECONDS,
    fetcher: Callable[[str, float], dict[str, Any]] | None = None,
    now: datetime | float | int | None = None,
) -> UpdateCheckResult:
    """检查是否有新版本；**任何异常都不会抛出**，最差返回 ``STATUS_ERROR``。

    Args:
        current_version: 当前版本，缺省读 :data:`core.version.__version__`。
        config: 用户配置 dict（缺省从 :mod:`core.config` 读取）。
        endpoint: 显式指定 release API（优先于 config）。
        timeout: 期望超时（强制 ≤3 秒）。
        fetcher: 可注入的 ``fetcher(endpoint, timeout) -> payload``（测试 mock）。
        now: 测试注入的当前时间。

    Returns:
        :class:`UpdateCheckResult`；网络失败时 ``status == "error"`` 且带
        中文 ``error`` 文案，调用方静默忽略即可。
    """
    current = str(current_version or __version__).strip() or __version__
    settings = config if isinstance(config, dict) else _load_default_config()
    checked_at = _to_iso(_now(now))

    if not is_auto_check_enabled(settings):
        return UpdateCheckResult(STATUS_DISABLED, current, checked_at=checked_at)
    if is_current_version_ignored(settings, current):
        return UpdateCheckResult(STATUS_IGNORED, current, checked_at=checked_at)
    if is_snoozed(settings, now):
        return UpdateCheckResult(STATUS_SNOOZED, current, checked_at=checked_at)

    api = endpoint or _configured_endpoint(settings) or DEFAULT_RELEASE_API
    try:
        if callable(fetcher):
            payload = fetcher(api, effective_timeout(timeout))
        else:
            payload = fetch_latest_release(api, timeout=timeout)
        info = extract_release_info(payload)
    except UpdateError as exc:
        return UpdateCheckResult(
            STATUS_ERROR,
            current,
            error=exc.message,
            error_kind=exc.kind,
            checked_at=checked_at,
        )
    except (TimeoutError, socket.timeout):
        return UpdateCheckResult(
            STATUS_ERROR,
            current,
            error="更新检查超时（3 秒）",
            error_kind="timeout",
            checked_at=checked_at,
        )
    except OSError as exc:
        return UpdateCheckResult(
            STATUS_ERROR,
            current,
            error=f"网络不可用：{exc}",
            error_kind="network",
            checked_at=checked_at,
        )
    except Exception as exc:  # noqa: BLE001 - 更新检查绝不影响主流程
        return UpdateCheckResult(
            STATUS_ERROR,
            current,
            error=f"更新检查失败：{type(exc).__name__}",
            error_kind="unknown",
            checked_at=checked_at,
        )

    result = UpdateCheckResult(
        STATUS_UP_TO_DATE,
        current,
        latest_version=info["latest_version"],
        release_url=info["release_url"],
        release_name=info["release_name"],
        published_at=info["published_at"],
        notes=info["notes"],
        download_url=info["download_url"],
        checked_at=checked_at,
    )
    if is_newer(info["latest_version"], current):
        result.status = (
            STATUS_IGNORED if is_version_ignored(settings, info["latest_version"]) else STATUS_UPDATE_AVAILABLE
        )
    return result


def describe_result(result: UpdateCheckResult) -> str:
    """把检查结果转成一句中文提示（GUI 状态栏 / 测试断言共用）。"""
    status = str(getattr(result, "status", "") or "")
    if status == STATUS_UPDATE_AVAILABLE:
        return f"发现新版本 {result.latest_version}（当前 {result.current_version}）"
    if status == STATUS_UP_TO_DATE:
        return "已是最新版本"
    if status == STATUS_IGNORED:
        return "已忽略该版本提示"
    if status == STATUS_SNOOZED:
        return "24 小时内不再提醒更新"
    if status == STATUS_DISABLED:
        return "已关闭启动时自动检查更新"
    return f"网络不佳，更新检查已跳过（{result.error or '未知错误'}）"


__all__ = [
    "DEFAULT_RELEASE_API",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_NOTES_CHARS",
    "MAX_RESPONSE_BYTES",
    "MAX_TIMEOUT_SECONDS",
    "RELEASES_PAGE",
    "SNOOZE_HOURS",
    "STARTUP_CHECK_DELAY_MS",
    "STATUSES",
    "STATUS_DISABLED",
    "STATUS_ERROR",
    "STATUS_IGNORED",
    "STATUS_SNOOZED",
    "STATUS_UPDATE_AVAILABLE",
    "STATUS_UP_TO_DATE",
    "UpdateCheckResult",
    "UpdateError",
    "USER_AGENT",
    "check_for_update",
    "clear_update_ignores",
    "compare_versions",
    "describe_result",
    "effective_timeout",
    "extract_release_info",
    "fetch_latest_release",
    "ignore_current_version",
    "ignore_version",
    "ignored_versions",
    "is_auto_check_enabled",
    "is_current_version_ignored",
    "is_newer",
    "is_snoozed",
    "is_version_ignored",
    "parse_version",
    "record_check",
    "snooze_updates",
    "snooze_until",
]
