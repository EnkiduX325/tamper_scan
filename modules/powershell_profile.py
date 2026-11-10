# -*- coding: utf-8 -*-
"""PowerShell Profile 持久化检测（阶段 4）。

覆盖规范要求的四类 Profile（PS5.1 与 PS7 各一套，共 8 个实际路径）：

- ``CurrentUserCurrentHost`` / ``CurrentUserAllHosts``（用户目录，读写无阻）
- ``AllUsersCurrentHost`` / ``AllUsersAllHosts``（系统/Program Files，标准用户只读）

内容规则：命中 ``IEX/Invoke-Expression``、``DownloadString``、
``Invoke-WebRequest``、``-EncodedCommand``、``FromBase64String``、远程 URL
→ HIGH / ``PS_PROFILE_SUSPICIOUS``。注释行（``#`` 开头）不参与匹配；
``IEX`` 别名 ``iex`` 大小写不敏感。

读不到（权限不足）→ SKIPPED；不抛异常。
"""

from __future__ import annotations

import os
import re
import winreg
from typing import Any

from core import utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "PowerShellProfile"

# (pattern_id, 正则, 中文描述)
_SUSPICIOUS_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("iex", re.compile(r"(?i)\b(?:IEX|Invoke-Expression)\b"), "IEX / Invoke-Expression 动态执行"),
    (
        "download",
        re.compile(
            r"(?i)\b(?:DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|Start-BitsTransfer|iwr|irm)\b"
        ),
        "下载载荷（DownloadString/IWR 等）",
    ),
    ("encoded", re.compile(r"(?i)(?:^|\s)-(?:enc|encodedcommand|ec)\b"), "编码命令（-EncodedCommand）"),
    ("frombase64", re.compile(r"(?i)\bFromBase64String\b"), "Base64 解码执行"),
    ("remote_url", re.compile(r"(?i)\bhttps?://[^\s'\"<>]+"), "远程 URL"),
)


def _documents_dir() -> str:
    """优先用 Shell 已知文件夹（可能被 OneDrive 重定向），失败退回 %USERPROFILE%\\Documents。"""
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        ) as key:
            value = str(winreg.QueryValueEx(key, "Personal")[0])
            path = os.path.expandvars(value)
            if os.path.isdir(path):
                return path
    except (FileNotFoundError, OSError):
        pass
    return os.path.join(os.environ.get("USERPROFILE", ""), "Documents")


def _profile_paths() -> list[dict[str, str]]:
    """返回 8 个 Profile 路径（含 Profile 类型与 PowerShell 版本）。"""
    documents = _documents_dir()
    windir = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    program_files = os.environ.get("ProgramFiles") or r"C:\Program Files"
    return [
        {"type": "CurrentUserCurrentHost", "version": "PS5", "path": os.path.join(documents, r"WindowsPowerShell\Microsoft.PowerShell_profile.ps1")},
        {"type": "CurrentUserAllHosts", "version": "PS5", "path": os.path.join(documents, r"WindowsPowerShell\profile.ps1")},
        {"type": "CurrentUserCurrentHost", "version": "PS7", "path": os.path.join(documents, r"PowerShell\Microsoft.PowerShell_profile.ps1")},
        {"type": "CurrentUserAllHosts", "version": "PS7", "path": os.path.join(documents, r"PowerShell\profile.ps1")},
        {"type": "AllUsersCurrentHost", "version": "PS5", "path": os.path.join(windir, r"System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1")},
        {"type": "AllUsersAllHosts", "version": "PS5", "path": os.path.join(windir, r"System32\WindowsPowerShell\v1.0\profile.ps1")},
        {"type": "AllUsersCurrentHost", "version": "PS7", "path": os.path.join(program_files, r"PowerShell\7\Microsoft.PowerShell_profile.ps1")},
        {"type": "AllUsersAllHosts", "version": "PS7", "path": os.path.join(program_files, r"PowerShell\7\profile.ps1")},
    ]


def _analyze_profile(profile: dict[str, str], content: str) -> list[dict[str, Any]]:
    """对单个 Profile 内容做判定（纯函数，便于单元测试）。"""
    hits: list[dict[str, str]] = []
    for line_number, raw_line in enumerate(str(content or "").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for pattern_id, regex, description in _SUSPICIOUS_PATTERNS:
            match = regex.search(line)
            if match:
                hits.append(
                    {
                        "pattern_id": pattern_id,
                        "description": description,
                        "line": line_number,
                        "fragment": truncate(match.group(0), 160),
                    }
                )
    if not hits:
        return []
    path = profile.get("path", "")
    return [
        make_finding(
            "HIGH",
            CATEGORY,
            path,
            f"PowerShell Profile（{profile.get('type')}/{profile.get('version')}）含可疑内容："
            + "；".join(sorted({hit["description"] for hit in hits})),
            {
                "profile_type": profile.get("type"),
                "powershell_version": profile.get("version"),
                "path": path,
                "hits": hits,
            },
            "PS_PROFILE_SUSPICIOUS",
        )
    ]


def scan() -> list[dict[str, Any]]:
    """检查所有 PowerShell Profile 文件，返回 ``list[Finding]``。"""
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for profile in _profile_paths():
        path = profile["path"]
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read()
        except PermissionError as exc:
            errors.append(f"{path}: 拒绝访问（{exc}）")
            continue
        except OSError as exc:
            errors.append(f"{path}: {exc}")
            continue
        findings.extend(_analyze_profile(profile, content))

    if errors:
        findings.append(
            make_skipped(
                CATEGORY,
                "PowerShellProfile",
                "部分 PowerShell Profile 无法读取：" + "；".join(errors[:5]),
                {"errors": errors},
                "PS_PROFILE_ACCESS_DENIED",
            )
        )
    return utils.apply_whitelist(findings)
