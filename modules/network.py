# -*- coding: utf-8 -*-
"""Hosts / DNS 劫持检测（阶段 4）。

- **Hosts**（``%SystemRoot%\\System32\\drivers\\etc\\hosts``）：
  - 屏蔽安全/更新域名（微软更新、Defender、主流杀软更新域名）→ HIGH ``HOSTS_HIJACK``；
  - 非注释行把域名指向**公网 IP** → HIGH ``HOSTS_HIJACK``；
  - 指向回环/0.0.0.0/私网（常见广告屏蔽写法）不报。
- **DNS**（注册表 ``Tcpip/Tcpip6 Parameters\\Interfaces\\*\\NameServer``）：
  - 只报「公网 IPv4 且不在已知公共 DNS 列表」→ MEDIUM ``DNS_ANOMALY``；
  - 私网/回环/链路本地（路由器、公司内网 DNS）不报；
  - IPv6 DNS 无法枚举运营商名单，统一跳过（避免大量误报，见模块说明）。

权限不足 → SKIPPED，不抛异常。
"""

from __future__ import annotations

import ipaddress
import os
import winreg
from typing import Any, Iterator

from core import utils
from core.finding import make_finding, make_skipped

CATEGORY = "Network"

HOSTS_PATH = os.path.join(
    os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows",
    r"System32\drivers\etc\hosts",
)

# 被 Hosts 屏蔽即代表安全/更新能力受损的域名后缀
_SECURITY_DOMAIN_SUFFIXES = (
    "microsoft.com",
    "windowsupdate.com",
    "windows.com",
    "windowsdefender.com",
    "defender.microsoft.com",
    "kaspersky.com",
    "kaspersky.ru",
    "kaspersky-labs.com",
    "norton.com",
    "symantec.com",
    "mcafee.com",
    "bitdefender.com",
    "bitdefender.net",
    "avast.com",
    "avg.com",
    "eset.com",
    "eset.sk",
    "trendmicro.com",
    "drweb.com",
    "drweb.ru",
    "huorong.cn",
    "360.cn",
    "qihoo.com",
    "f-secure.com",
    "gdata.com",
    "clamav.net",
    "avira.com",
    "emsisoft.com",
    "sophos.com",
)

# 已知公共 DNS（公网 IP 且在此列表内不报）
_KNOWN_PUBLIC_DNS = {
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "114.114.114.114",
    "114.114.115.115",
    "223.5.5.5",
    "223.6.6.6",
    "119.29.29.29",
    "180.76.76.76",
    "1.12.12.12",
    "120.53.53.53",
    "101.226.4.6",
}

_DNS_INTERFACE_KEYS = (
    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
    r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces",
)


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------


def _parse_hosts(content: str) -> list[dict[str, Any]]:
    """解析 hosts 内容，返回有效映射行（纯函数）。"""
    entries: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(str(content or "").splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        entries.append(
            {
                "line_number": line_number,
                "ip": parts[0],
                "hostnames": parts[1:],
                "raw": raw_line.strip(),
            }
        )
    return entries


def _matches_security_domain(hostname: str) -> bool:
    hostname = hostname.lower().rstrip(".")
    return any(hostname == suffix or hostname.endswith("." + suffix) for suffix in _SECURITY_DOMAIN_SUFFIXES)


def _analyze_hosts(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Hosts 条目判定（纯函数）。"""
    findings: list[dict[str, Any]] = []
    for entry in entries:
        try:
            ip = ipaddress.ip_address(entry["ip"])
        except ValueError:
            continue
        hostnames = " ".join(entry["hostnames"])
        blocked_security = [name for name in entry["hostnames"] if _matches_security_domain(name)]
        if blocked_security:
            findings.append(
                make_finding(
                    "HIGH",
                    CATEGORY,
                    HOSTS_PATH,
                    f"Hosts 屏蔽了安全/更新域名 {', '.join(blocked_security)}（→ {entry['ip']}，第 {entry['line_number']} 行）",
                    {"entry": entry, "blocked_security_domains": blocked_security},
                    "HOSTS_HIJACK",
                )
            )
            continue
        if ip.is_loopback or ip.is_unspecified or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            continue
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                HOSTS_PATH,
                f"Hosts 将 {hostnames} 指向公网 IP {entry['ip']}（第 {entry['line_number']} 行）",
                {"entry": entry},
                "HOSTS_HIJACK",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def _iter_dns_servers() -> Iterator[dict[str, str]]:
    """从注册表枚举各网卡的静态 DNS（DHCP 下 NameServer 为空，跳过）。"""
    for base_key in _DNS_INTERFACE_KEYS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key, 0, winreg.KEY_READ) as interfaces:
                count = winreg.QueryInfoKey(interfaces)[0]
                interface_guids = []
                for index in range(count):
                    try:
                        interface_guids.append(winreg.EnumKey(interfaces, index))
                    except OSError:
                        continue
        except (FileNotFoundError, OSError):
            continue
        for guid in interface_guids:
            interface_key = f"{base_key}\\{guid}"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, interface_key, 0, winreg.KEY_READ) as interface:
                    try:
                        name_server = str(winreg.QueryValueEx(interface, "NameServer")[0] or "")
                    except (FileNotFoundError, OSError):
                        name_server = ""
                    try:
                        dhcp_name_server = str(winreg.QueryValueEx(interface, "DhcpNameServer")[0] or "")
                    except (FileNotFoundError, OSError):
                        dhcp_name_server = ""
            except (FileNotFoundError, OSError):
                continue
            for value, source in ((name_server, "static"), (dhcp_name_server, "dhcp")):
                for server in value.replace(",", " ").split():
                    if server:
                        yield {"interface": guid, "server": server.strip(), "source": source}


def _analyze_dns(servers: list[dict[str, str]]) -> list[dict[str, Any]]:
    """DNS 判定（纯函数）：只报公网 IPv4 且不在已知公共 DNS 列表。"""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in servers:
        server = item["server"].strip()
        if server.lower() in _KNOWN_PUBLIC_DNS:
            continue
        try:
            address = ipaddress.ip_address(server)
        except ValueError:
            continue
        if address.version != 4:
            continue  # IPv6 DNS 无法枚举运营商名单，跳过避免误报
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            continue
        key = (item.get("interface", ""), server)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            make_finding(
                "MEDIUM",
                CATEGORY,
                f"DNS:{server}",
                f"网卡 {item.get('interface')} 的 DNS 被设置为陌生公网 IP {server}（来源：{item.get('source')}）",
                {"interface": item.get("interface"), "server": server, "source": item.get("source")},
                "DNS_ANOMALY",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 模块入口
# ---------------------------------------------------------------------------


def scan() -> list[dict[str, Any]]:
    """扫描 Hosts 与 DNS 配置，返回 ``list[Finding]``。"""
    findings: list[dict[str, Any]] = []
    errors: list[str] = []

    # 1) Hosts
    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as handle:
            host_content = handle.read()
        findings.extend(_analyze_hosts(_parse_hosts(host_content)))
    except FileNotFoundError:
        findings.append(
            make_skipped(CATEGORY, HOSTS_PATH, "未找到 hosts 文件", {"path": HOSTS_PATH}, "NETWORK_SKIPPED")
        )
    except PermissionError as exc:
        errors.append(f"{HOSTS_PATH}: 拒绝访问（{exc}）")
    except OSError as exc:
        errors.append(f"{HOSTS_PATH}: {exc}")

    # 2) DNS
    try:
        findings.extend(_analyze_dns(list(_iter_dns_servers())))
    except PermissionError as exc:
        errors.append(f"DNS 注册表: 拒绝访问（{exc}）")
    except OSError as exc:
        errors.append(f"DNS 注册表: {exc}")

    if errors:
        findings.append(
            make_skipped(
                CATEGORY,
                "Hosts/DNS",
                "部分网络配置无法读取：" + "；".join(errors[:5]),
                {"errors": errors},
                "NETWORK_ACCESS_DENIED",
            )
        )
    return utils.apply_whitelist(findings)
