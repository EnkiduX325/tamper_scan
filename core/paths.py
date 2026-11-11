# -*- coding: utf-8 -*-
"""路径 / 平台 / 文件类型相关工具（V1.4 从 :mod:`core.utils` 拆出）。

包含程序目录常量（``RULES_DIR`` / ``TOOLS_DIR`` 等）、路径规范化与命令行可执行文件
提取、系统目录判定、系统组件名判定与 PE 扩展名判定。本模块**不依赖**
:mod:`core.utils`（避免循环导入）；``core.utils`` 作为兼容 shim 再导出公共 API。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any


IS_WINDOWS = os.name == "nt"


def get_base_dir() -> Path:
    """返回程序根目录：源码运行时为项目根，PyInstaller 打包后为 _MEIPASS。"""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parent.parent


BASE_DIR: Path = get_base_dir()


RULES_DIR: Path = BASE_DIR / "rules"


TOOLS_DIR: Path = BASE_DIR / "tools"


YARA_RULES_DIR: Path = RULES_DIR / "yara"


def truncate(text: Any, limit: int = 300) -> str:
    """把任意对象转成单行字符串并截断，用于 detail/evidence 展示。"""
    value = " ".join(str(text or "").split())
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def expand_vars(value: Any) -> str:
    """展开 ``%VAR%`` 环境变量，失败时原样返回。"""
    try:
        return os.path.expandvars(str(value or ""))
    except Exception:
        return str(value or "")


def load_json(path: str | os.PathLike[str] | None, default: Any = None) -> Any:
    """读取 JSON 文件；文件缺失或格式错误时返回 default。"""
    if not path:
        return default
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return json.load(handle)
    except (OSError, ValueError, TypeError):
        return default


_EXEC_SUFFIX_RE = re.compile(
    r"(?i)\.(?:exe|dll|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|scr|sys|ocx|cpl|msi|jar|py|hta|lnk|pif)\b"
)


def _strip_long_path_prefix(value: str) -> str:
    if value.lower().startswith("\\\\?\\"):
        return value[4:]
    return value


def normalize_path(raw: Any) -> str:
    """把路径字符串规范化为可比较的形式（展开变量、去引号、normpath）。

    不做存在性假设，也不强制转绝对路径（注册表目标等非路径字符串原样返回）。
    """
    text = expand_vars(raw).strip()
    if not text:
        return ""
    if text[0] in "\"'":
        quote = text[0]
        end = text.find(quote, 1)
        text = text[1:end] if end != -1 else text[1:]
    text = _strip_long_path_prefix(text).strip()
    try:
        return os.path.normpath(text)
    except Exception:
        return text


def _clean_path(value: Any) -> str:
    text = expand_vars(value).strip().strip('"').strip("'").strip()
    text = _strip_long_path_prefix(text)
    try:
        text = os.path.normpath(text)
    except Exception:
        pass
    return text


def resolve_executable(name: str) -> str:
    """在 PATH 中解析可执行文件名（仅用于补全签名校验的目标路径）。"""
    if not name:
        return ""
    try:
        found = shutil.which(name)
        if found:
            return found
    except Exception:
        pass
    return ""


def extract_executable(command: Any) -> str:
    """从命令行/启动字符串中提取首个可执行文件路径。

    支持：带引号路径、含空格且真实存在的路径、PATH 中可解析的命令名、
    以及 ``powershell -enc xxx`` 这类无扩展名命令（返回命令名本身，交给后续解析）。
    """
    text = expand_vars(command).strip()
    if not text:
        return ""
    if text[0] in "\"'":
        quote = text[0]
        end = text.find(quote, 1)
        inner = text[1:end] if end != -1 else text[1:]
        return _clean_path(inner)
    if os.path.exists(text):
        return _clean_path(text)
    first_suffix_match = None
    for match in _EXEC_SUFFIX_RE.finditer(text):
        piece = text[: match.end()].strip()
        if first_suffix_match is None:
            first_suffix_match = piece
        if os.path.exists(expand_vars(piece)):
            return _clean_path(piece)
    # 文件不存在但形如路径：返回带扩展名的前缀（支持含空格的路径），否则取第一段命令名
    if first_suffix_match:
        return _clean_path(first_suffix_match)
    token = text.split()[0]
    return _clean_path(resolve_executable(token) or token)


def _norm_abs(path: str) -> str:
    """绝对化 + normcase，用于包含关系比较；失败返回空串。"""
    if not path:
        return ""
    try:
        return os.path.normcase(os.path.abspath(normalize_path(path)))
    except Exception:
        return ""


def path_under(path: str, root: str) -> bool:
    """判断 path 是否等于 root 或位于 root 目录之内（大小写不敏感）。"""
    p = _norm_abs(path)
    r = _norm_abs(root)
    if not p or not r:
        return False
    if p == r:
        return True
    root_prefix = r if r.endswith(os.sep) else r + os.sep
    return p.startswith(root_prefix)


def system_roots() -> list[str]:
    """系统目录集合：System32 / SysWOW64 / System。"""
    windir = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    return [
        os.path.join(windir, "System32"),
        os.path.join(windir, "SysWOW64"),
        os.path.join(windir, "System"),
    ]


def is_in_system_dir(path: Any) -> bool:
    """路径是否位于 System32 / SysWOW64（用于伪装系统组件判定）。"""
    if not path:
        return False
    candidate = extract_executable(path) or normalize_path(path)
    return any(path_under(candidate, root) for root in system_roots())


SYSTEM_BINARY_NAMES = frozenset(
    {
        "svchost.exe",
        "lsass.exe",
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "userinit.exe",
        "explorer.exe",
        "taskhostw.exe",
        "dllhost.exe",
        "conhost.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
        "schtasks.exe",
        "wuauclt.exe",
        "spoolsv.exe",
        "audiodg.exe",
        "dwm.exe",
        "fontdrvhost.exe",
        "sihost.exe",
        "ctfmon.exe",
        "runtimebroker.exe",
        "searchindexer.exe",
        "msmpeng.exe",
        "smartscreen.exe",
        "securityhealthservice.exe",
        "lsm.exe",
        "ntoskrnl.exe",
        "winlogon.exe",
    }
)


SYSTEM_COMPONENT_NAME_KEYWORDS = (
    "windows",
    "microsoft",
    "system32",
    "winlogon",
    "lsass",
    "svchost",
    "defender",
    "antivirus",
    "security",
    "update",
    "telemetry",
    "runtime",
    "driver",
)


def is_system_binary_name(path: Any) -> bool:
    """文件名是否为常见 Windows 系统二进制名。"""
    basename = os.path.basename(normalize_path(path or "")).lower()
    return basename in SYSTEM_BINARY_NAMES


def is_trusted_install_location(path: Any) -> bool:
    """路径是否位于 Windows 目录 / Program Files / Program Files (x86) 等受信任位置。"""
    if not path:
        return False
    candidate = extract_executable(path) or normalize_path(path)
    if not candidate:
        return False
    roots = [
        os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows",
        os.environ.get("ProgramFiles") or r"C:\Program Files",
        os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)",
        os.environ.get("ProgramW6432"),
    ]
    return any(path_under(candidate, root) for root in roots if root)


def looks_like_system_component_name(name: Any) -> bool:
    """名称（注册表值名/任务名/服务名）是否自称系统组件。"""
    text = str(name or "").lower()
    return bool(text) and any(keyword in text for keyword in SYSTEM_COMPONENT_NAME_KEYWORDS)


_PE_EXTENSIONS = frozenset({".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".msi", ".com"})


def is_pe_executable(path: Any) -> bool:
    """按扩展名粗判是否为 PE/安装包文件（脚本类文件不参与签名判定）。"""
    if not path:
        return False
    candidate = extract_executable(path) or normalize_path(path)
    if not candidate:
        return False
    return os.path.splitext(candidate)[1].lower() in _PE_EXTENSIONS


__all__ = [
    "BASE_DIR",
    "IS_WINDOWS",
    "RULES_DIR",
    "SYSTEM_BINARY_NAMES",
    "SYSTEM_COMPONENT_NAME_KEYWORDS",
    "TOOLS_DIR",
    "YARA_RULES_DIR",
    "expand_vars",
    "extract_executable",
    "get_base_dir",
    "is_in_system_dir",
    "is_pe_executable",
    "is_system_binary_name",
    "is_trusted_install_location",
    "load_json",
    "looks_like_system_component_name",
    "normalize_path",
    "path_under",
    "resolve_executable",
    "system_roots",
    "truncate",
]
