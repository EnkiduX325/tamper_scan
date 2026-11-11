# -*- coding: utf-8 -*-
"""通用工具兼容层（V1.4 拆分后的向后兼容 shim）。

V1.4 起 ``core/utils.py`` 按职责拆分为 4 个模块：

- :mod:`core.paths`：路径 / 平台 / 文件类型判定（``normalize_path`` / ``RULES_DIR`` 等）
- :mod:`core.acl`：管理员权限与用户可写目录判定（``is_admin`` / ``is_user_writable``）
- :mod:`core.subprocess_util`：外部命令封装（``run_cmd`` / PowerShell / 隐藏窗口）
- :mod:`core.whitelist`：白名单加载 / 匹配 / 应用（``apply_whitelist`` 等）

本模块保持历史导入路径 ``from core import utils`` / ``core.utils.X`` 完全可用：
上面的公共 API 通过 ``from .xxx import *`` 原样再导出（与拆分模块中的是**同一对象**，
可用 ``is`` 比较），并显式保留 ``RULES_DIR`` / ``TOOLS_DIR`` / ``IS_WINDOWS`` 等历史上
被外部直接引用的名称。未拆分的内容（控制台初始化、可疑命令行特征识别）仍定义在本模块。

设计原则（沿用拆分前）：

- 不做隐式全局缓存（除 :mod:`core.acl` 的 ACL 探测缓存外），函数可独立调用、单独测试；
- 输入一律容错，路径/命令行解析失败退化为"不可判定"而不是抛异常。
"""

from __future__ import annotations

import re
import sys
from typing import Any

# --- 兼容再导出：paths -----------------------------------------------------
from .paths import *  # noqa: F401,F403
from .paths import BASE_DIR as BASE_DIR
from .paths import IS_WINDOWS as IS_WINDOWS
from .paths import RULES_DIR as RULES_DIR
from .paths import SYSTEM_BINARY_NAMES as SYSTEM_BINARY_NAMES
from .paths import SYSTEM_COMPONENT_NAME_KEYWORDS as SYSTEM_COMPONENT_NAME_KEYWORDS
from .paths import TOOLS_DIR as TOOLS_DIR
from .paths import YARA_RULES_DIR as YARA_RULES_DIR
from .paths import extract_executable as extract_executable
from .paths import is_in_system_dir as is_in_system_dir
from .paths import is_pe_executable as is_pe_executable
from .paths import load_json as load_json
from .paths import normalize_path as normalize_path
from .paths import truncate as truncate

# --- 兼容再导出：acl -------------------------------------------------------
from .acl import *  # noqa: F401,F403
from .acl import is_admin as is_admin
from .acl import is_user_writable as is_user_writable
from .acl import user_writable_roots as user_writable_roots

# --- 兼容再导出：subprocess_util -------------------------------------------
from .subprocess_util import *  # noqa: F401,F403
from .subprocess_util import hidden_process_options as hidden_process_options
from .subprocess_util import run_cmd as run_cmd
from .subprocess_util import run_powershell as run_powershell
from .subprocess_util import run_powershell_json as run_powershell_json

# --- 兼容再导出：whitelist -------------------------------------------------
from .whitelist import *  # noqa: F401,F403
from .whitelist import DEFAULT_WHITELIST as DEFAULT_WHITELIST
from .whitelist import apply_whitelist as apply_whitelist
from .whitelist import load_whitelist as load_whitelist
from .whitelist import match_whitelist as match_whitelist


def setup_console() -> None:
    """统一把 stdout/stderr 切到 UTF-8，避免 Windows 控制台中文乱码。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


_SUSPICIOUS_CMDLINE_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "powershell_encoded",
        re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*(?:-enc(?:odedcommand)?|-ec|-e)\s+[A-Za-z0-9+/=]{20,}"),
        "PowerShell 编码/Base64 命令",
    ),
    (
        "powershell_hidden",
        re.compile(r"(?i)(?:-w(?:indowstyle)?|--windowstyle)\s+hidden\b"),
        "隐藏窗口执行（WindowStyle Hidden）",
    ),
    (
        "powershell_nop",
        re.compile(r"(?i)\b(?:-nop\b|-noprofile\b|-noprofil\b)"),
        "PowerShell 无配置/无 Profile 启动",
    ),
    (
        "powershell_download",
        re.compile(
            r"(?i)\b(?:DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|Start-BitsTransfer|iwr\b|irm\b)"
        ),
        "PowerShell 下载载荷（DownloadString/IWR 等）",
    ),
    (
        "powershell_iex",
        re.compile(r"(?i)\b(?:IEX|Invoke-Expression)\b"),
        "PowerShell 动态执行（IEX/Invoke-Expression）",
    ),
    (
        "powershell_frombase64",
        re.compile(r"(?i)\bFromBase64String\b"),
        "PowerShell Base64 解码执行",
    ),
    (
        "mshta_remote",
        re.compile(r"(?i)\bmshta(?:\.exe)?\b[^\r\n]*(?:https?://|javascript:|vbscript:|\babouts?:)"),
        "mshta 执行远程/内联脚本",
    ),
    (
        "rundll32_javascript",
        re.compile(r"(?i)\brundll32(?:\.exe)?\b[^\r\n]*(?:javascript:|vbscript:)"),
        "rundll32 执行 javascript:/vbscript:",
    ),
    (
        "regsvr32_scrobj",
        re.compile(r"(?i)\bregsvr32(?:\.exe)?\b[^\r\n]*(?:/i:https?:|scrobj\.dll|comscriptlet)"),
        "regsvr32 远程 COM 脚本（Squiblydoo）",
    ),
    (
        "certutil_urlcache",
        re.compile(r"(?i)\bcertutil(?:\.exe)?\b[^\r\n]*(?:-urlcache|-verifyctl)\b"),
        "certutil 远程下载（-urlcache）",
    ),
    (
        "certutil_decode",
        re.compile(r"(?i)\bcertutil(?:\.exe)?\b[^\r\n]*-decode(?:hex)?\b"),
        "certutil 本地解码载荷",
    ),
    (
        "bitsadmin_transfer",
        re.compile(r"(?i)\bbitsadmin(?:\.exe)?\b[^\r\n]*(?:/transfer|/addfile)\b"),
        "bitsadmin 传输作业（BITS 持久化/下载）",
    ),
    (
        "wmic_process_create",
        re.compile(r"(?i)\bwmic(?:\.exe)?\b[^\r\n]*\bprocess\b[^\r\n]*\bcall\b[^\r\n]*\bcreate\b"),
        "WMIC 创建进程",
    ),
    (
        "msiexec_remote",
        re.compile(r"(?i)\bmsiexec(?:\.exe)?\b[^\r\n]*https?://"),
        "msiexec 安装远程 MSI",
    ),
    (
        "cmd_download_pipe",
        re.compile(r"(?i)\bcmd(?:\.exe)?\b[^\r\n]*(?:\bcertutil\b|\bcurl\b|\bwget\b)[^\r\n]*\|\s*(?:powershell|cmd|more)"),
        "cmd 管道下载执行",
    ),
    (
        "curl_pipe_shell",
        re.compile(r"(?i)\b(?:curl|wget)(?:\.exe)?\b[^\r\n]*\|\s*(?:powershell|cmd|sh)\b"),
        "curl/wget 管道到解释器",
    ),
)


def match_suspicious_cmdline(cmd: Any) -> dict[str, str] | None:
    """返回首个命中的可疑命令行特征；未命中返回 None。

    Returns:
        ``{"pattern_id": ..., "description": ..., "fragment": ...}``
    """
    text = str(cmd or "")
    if not text.strip():
        return None
    for pattern_id, regex, description in _SUSPICIOUS_CMDLINE_RULES:
        match = regex.search(text)
        if match:
            return {
                "pattern_id": pattern_id,
                "description": description,
                "fragment": truncate(match.group(0), 160),
            }
    return None


def is_suspicious_cmdline(cmd: Any) -> bool:
    """命令行是否命中任意可疑特征（LOLBin/下载/编码执行等）。"""
    return match_suspicious_cmdline(cmd) is not None
