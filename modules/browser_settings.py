# -*- coding: utf-8 -*-
"""浏览器/系统 URL 设置检测（阶段 3，第一梯队）。

覆盖：

1. **IE 主页**：``HKCU/HKLM\\...\\Internet Explorer\\Main\\Start Page``
   —— 域名不在白名单 → MEDIUM；IP 字面量 / punycode / file:/javascript: 等 → HIGH。
2. **IE 搜索提供者**：``HKCU/HKLM\\...\\Internet Explorer\\SearchScopes\\{GUID}\\URL``
   —— 搜索 URL 不是主流搜索引擎 → MEDIUM（IP/异体域名 → HIGH）。
3. **系统 http 协议处理器**：``HKCR/HKCU/HKLM\\...\\http\\shell\\open\\command``
   —— 被改成可疑命令/用户可写路径 → HIGH；不是已知浏览器 → MEDIUM。
4. **系统代理**：``HKCU\\...\\Internet Settings`` 的 ``ProxyEnable/ProxyServer/AutoConfigURL``
   —— 开启陌生代理或 PAC → MEDIUM（``PROXY_HIJACK``）。

域名白名单 = 内置主流域名 + ``rules/whitelist.json`` 的 ``domains`` 列表（阶段 7 填充）。
"""

from __future__ import annotations

import ipaddress
import os
import urllib.parse
import winreg
from typing import Any

from core import utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "BrowserSettings"

# 主流搜索引擎域名（搜索提供者检测用）
_MAINSTREAM_SEARCH_DOMAINS = frozenset(
    {
        "google.com",
        "google.com.hk",
        "google.co.jp",
        "bing.com",
        "baidu.com",
        "yahoo.com",
        "yandex.com",
        "yandex.ru",
        "duckduckgo.com",
        "so.com",
        "sogou.com",
        "ecosia.org",
        "startpage.com",
        "brave.com",
        "qwant.com",
        "ask.com",
        "naver.com",
        "seznam.cz",
        "mail.ru",
        "msn.com",
    }
)

# 受信任主页域名 = 主流搜索 + 常用门户/厂商站点
_TRUSTED_HOMEPAGE_DOMAINS = _MAINSTREAM_SEARCH_DOMAINS | frozenset(
    {
        "microsoft.com",
        "live.com",
        "office.com",
        "microsoft365.com",
        "apple.com",
        "icloud.com",
        "mozilla.org",
        "firefox.com",
        "about.gitlab.com",
        "github.com",
        "baidu.com.cn",
        "qq.com",
        "163.com",
        "sina.com.cn",
        "sohu.com",
        "taobao.com",
        "jd.com",
        "bilibili.com",
        "zhihu.com",
    }
)

# 已知浏览器可执行文件名（http 协议处理器检测用）
_KNOWN_BROWSER_EXES = frozenset(
    {
        "iexplore.exe",
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "brave.exe",
        "opera.exe",
        "vivaldi.exe",
        "chromium.exe",
        "360se.exe",
        "360chrome.exe",
        "360chromex.exe",
        "qqbrowser.exe",
        "sogouexplorer.exe",
        "maxthon.exe",
        "waterfox.exe",
        "librewolf.exe",
        "thorium.exe",
    }
)

_IE_MAIN_LOCATIONS = (
    ("HKCU", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Internet Explorer\Main", 0),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Internet Explorer\Main", winreg.KEY_WOW64_64KEY),
)
_IE_SEARCH_SCOPES_LOCATIONS = (
    ("HKCU", winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Internet Explorer\SearchScopes", 0),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Internet Explorer\SearchScopes", winreg.KEY_WOW64_64KEY),
)
_HTTP_SHELL_LOCATIONS = (
    ("HKCR", winreg.HKEY_CLASSES_ROOT, r"http\shell\open\command", 0),
    ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Classes\http\shell\open\command", 0),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\http\shell\open\command", 0),
)
_INTERNET_SETTINGS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"

_INTERNAL_SCHEMES = {"about", "chrome", "edge", "res", "ms-appx", "ms-settings", "view-source"}
_DANGEROUS_SCHEMES = {"file", "javascript", "data", "vbscript", "ftp"}


# ---------------------------------------------------------------------------
# URL 分析
# ---------------------------------------------------------------------------


def _load_extra_domains() -> set[str]:
    """读取白名单里自定义的域名（阶段 7 填充；缺失时为空）。"""
    whitelist = utils.load_whitelist()
    domains = whitelist.get("domains")
    if not isinstance(domains, list):
        return set()
    return {str(item).strip().lower().lstrip(".") for item in domains if str(item).strip()}


def _domain_allowed(host: str, allowed: set[str] | frozenset[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    return any(host == domain or host.endswith("." + domain) for domain in allowed)


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _analyze_url(url: str, allowed_domains: set[str] | frozenset[str]) -> tuple[str | None, str]:
    """分析主页/搜索 URL，返回 ``(severity, reason)``；``severity=None`` 表示可信。"""
    text = str(url or "").strip().strip('"')
    if not text:
        return None, ""
    try:
        parsed = urllib.parse.urlparse(text)
    except Exception:
        return "MEDIUM", f"URL 无法解析：{truncate(text, 120)}"
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if scheme in _INTERNAL_SCHEMES:
        return None, ""
    if scheme in _DANGEROUS_SCHEMES:
        return "HIGH", f"使用危险协议 {scheme}: 的 URL：{truncate(text, 160)}"
    if scheme not in ("http", "https"):
        return "MEDIUM", f"使用非常规协议 {scheme or '(无)'} 的 URL：{truncate(text, 160)}"
    if not host:
        return "HIGH", f"URL 缺少域名：{truncate(text, 160)}"
    if _domain_allowed(host, allowed_domains):
        return None, ""
    if _is_ip_host(host) or "xn--" in host:
        return "HIGH", f"指向 IP/异体域名 {host}：{truncate(text, 160)}"
    return "MEDIUM", f"域名不在白名单：{host}"


# 导航站/聚合页：既是常见正常设置、也是典型主页劫持落点，单独归为 MEDIUM 让用户判断
_NAVIGATION_PORTAL_DOMAINS = frozenset({"hao123.com", "2345.com", "265.com", "sogou.com"})


def _url_host(url: str) -> str:
    try:
        return (urllib.parse.urlparse(str(url or "").strip()).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def _is_navigation_portal(host: str) -> bool:
    return bool(host) and _domain_allowed(host, _NAVIGATION_PORTAL_DOMAINS)


def _classify_browse_url(
    url: str,
    allowed_domains: set[str] | frozenset[str],
    default_rule_id: str,
    check_navigation: bool = True,
) -> tuple[str, str, str] | None:
    """返回 ``(severity, reason, rule_id)``；可信/内部协议返回 None。"""
    host = _url_host(url)
    if check_navigation and _is_navigation_portal(host):
        return (
            "MEDIUM",
            f"疑似导航站（可能是正常设置或主页劫持，需人工确认）：{host}",
            "BROWSE_NAVIGATION_PORTAL",
        )
    severity, reason = _analyze_url(url, allowed_domains)
    if not severity:
        return None
    return severity, reason, default_rule_id

# ---------------------------------------------------------------------------
# 注册表读取工具
# ---------------------------------------------------------------------------


def _read_value(hive: int, subkey: str, name: str, view_flag: int = 0) -> Any:
    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as key:
        return winreg.QueryValueEx(key, name)[0]


# ---------------------------------------------------------------------------
# 各检查项
# ---------------------------------------------------------------------------


def _check_ie_homepage(allowed: set[str] | frozenset[str]) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for hive_name, hive, subkey, view_flag in _IE_MAIN_LOCATIONS:
        key_path = f"{hive_name}\\{subkey}"
        try:
            url = _read_value(hive, subkey, "Start Page", view_flag)
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            errors.append(f"{key_path}: 拒绝访问（{exc}）")
            continue
        except OSError:
            continue
        classification = _classify_browse_url(str(url or ""), allowed, "BROWSE_HOMEPAGE_HIJACK")
        if classification:
            severity, reason, rule_id = classification
            findings.append(
                make_finding(
                    severity,
                    CATEGORY,
                    key_path,
                    f"IE 主页异常（{reason}）",
                    {"key": key_path, "value_name": "Start Page", "value": truncate(url, 400)},
                    rule_id,
                )
            )
    return findings, errors


def _check_ie_search_scopes(
    allowed_search: set[str] | frozenset[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for hive_name, hive, subkey, view_flag in _IE_SEARCH_SCOPES_LOCATIONS:
        key_path = f"{hive_name}\\{subkey}"
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as scopes_key:
                subkey_count = winreg.QueryInfoKey(scopes_key)[0]
                scope_names = []
                for index in range(subkey_count):
                    try:
                        scope_names.append(winreg.EnumKey(scopes_key, index))
                    except OSError:
                        continue
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            errors.append(f"{key_path}: 拒绝访问（{exc}）")
            continue
        except OSError:
            continue
        for scope_name in scope_names:
            scope_path = f"{key_path}\\{scope_name}"
            try:
                url = _read_value(hive, f"{subkey}\\{scope_name}", "URL", view_flag)
            except (FileNotFoundError, OSError):
                continue
            if not str(url or "").strip():
                continue
            classification = _classify_browse_url(
                str(url), allowed_search, "BROWSE_SEARCH_HIJACK", check_navigation=False
            )
            if classification:
                severity, reason, rule_id = classification
                findings.append(
                    make_finding(
                        severity,
                        CATEGORY,
                        scope_path,
                        f"IE 搜索提供者异常（{reason}）",
                        {
                            "key": scope_path,
                            "scope": scope_name,
                            "value": truncate(url, 400),
                        },
                        rule_id,
                    )
                )
    return findings, errors


def _template_host(url_template: str) -> str:
    """把 ``{searchTerms}`` 等占位符替换后取 host。"""
    text = str(url_template or "")
    for placeholder in ("{searchTerms}", "{searchTerms?}", "{inputEncoding}", "{language}", "{startIndex}", "{startPage}"):
        text = text.replace(placeholder, "test")
    try:
        return (urllib.parse.urlparse(text).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def _check_http_shell() -> tuple[list[dict[str, Any]], list[str]]:
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    seen_commands: set[str] = set()
    for hive_name, hive, subkey, view_flag in _HTTP_SHELL_LOCATIONS:
        key_path = f"{hive_name}\\{subkey}"
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as key:
                command, _value_type = winreg.QueryValueEx(key, "")
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            errors.append(f"{key_path}: 拒绝访问（{exc}）")
            continue
        except OSError:
            continue
        command = str(command or "").strip()
        if not command or command in seen_commands:
            continue
        seen_commands.add(command)
        hit = utils.match_suspicious_cmdline(command)
        executable = utils.extract_executable(command)
        basename = os.path.basename(utils.normalize_path(executable)).lower()
        if hit:
            severity, reason = "HIGH", f"http 协议处理器被改为可疑命令（{hit['description']}）"
        elif executable and utils.is_user_writable(executable):
            severity, reason = "HIGH", f"http 协议处理器指向用户可写目录：{executable}"
        elif executable and basename not in _KNOWN_BROWSER_EXES:
            severity, reason = "MEDIUM", f"http 协议处理器不是已知浏览器：{basename or command}"
        else:
            continue
        findings.append(
            make_finding(
                severity,
                CATEGORY,
                key_path,
                reason,
                {"key": key_path, "command": truncate(command, 400), "cmdline_hit": hit},
                "BROWSE_HTTP_SHELL_HIJACK",
            )
        )
    return findings, errors


def _analyze_proxy_values(
    pac_url: str,
    proxy_enable: Any,
    proxy_server: str,
    key_path: str,
) -> list[dict[str, Any]]:
    """根据读取到的代理值生成 Finding（纯函数，便于单元测试）。"""
    findings: list[dict[str, Any]] = []
    if pac_url:
        findings.append(
            make_finding(
                "MEDIUM",
                CATEGORY,
                key_path,
                f"系统代理启用了 PAC 自动配置脚本：{truncate(pac_url, 220)}",
                {"key": key_path, "value_name": "AutoConfigURL", "value": truncate(pac_url, 400)},
                "PROXY_HIJACK",
            )
        )
    try:
        enabled = int(proxy_enable or 0) == 1
    except (TypeError, ValueError):
        enabled = False
    if enabled and proxy_server:
        findings.append(
            make_finding(
                "MEDIUM",
                CATEGORY,
                key_path,
                f"系统代理已启用且指向：{truncate(proxy_server, 220)}",
                {
                    "key": key_path,
                    "value_name": "ProxyServer",
                    "value": truncate(proxy_server, 400),
                },
                "PROXY_HIJACK",
            )
        )
    return findings


def _check_proxy() -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    key_path = f"HKCU\{_INTERNET_SETTINGS}"
    try:
        pac_url = str(_read_value(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS, "AutoConfigURL") or "").strip()
    except (FileNotFoundError, OSError):
        pac_url = ""
    try:
        proxy_enable = _read_value(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS, "ProxyEnable")
        proxy_server = str(_read_value(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS, "ProxyServer") or "").strip()
    except (FileNotFoundError, OSError):
        proxy_enable, proxy_server = 0, ""
    return _analyze_proxy_values(pac_url, proxy_enable, proxy_server, key_path), errors


# ---------------------------------------------------------------------------
# 模块入口
# ---------------------------------------------------------------------------


def scan() -> list[dict[str, Any]]:
    """扫描主页/搜索/协议处理器/代理设置，返回 ``list[Finding]``。"""
    homepages = _TRUSTED_HOMEPAGE_DOMAINS | _load_extra_domains()
    searches = _MAINSTREAM_SEARCH_DOMAINS | _load_extra_domains()

    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for collector in (
        lambda: _check_ie_homepage(homepages),
        lambda: _check_ie_search_scopes(searches),
        _check_http_shell,
        _check_proxy,
    ):
        section_findings, section_errors = collector()
        findings.extend(section_findings)
        errors.extend(section_errors)

    if errors:
        findings.append(
            make_skipped(
                CATEGORY,
                "BrowserSettings",
                "部分浏览器/系统设置无法读取（权限不足）：" + "；".join(errors[:5]),
                {"errors": errors},
                "BROWSE_ACCESS_DENIED",
            )
        )
    return utils.apply_whitelist(findings)
