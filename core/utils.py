"""通用工具：权限判断、路径判定、命令行特征、白名单加载/过滤、外部命令封装。

设计原则：
- 不做隐式全局缓存，所有函数可独立调用、单独测试；
- 输入一律容错，路径/命令行解析失败退化为"不可判定"而不是抛异常；
- 白名单（``rules/whitelist.json``）从阶段 0 起就被所有模块调用，阶段 7 只填充内容。
"""

from __future__ import annotations

import copy
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

from .finding import SEVERITY_ORDER, rule_basename

IS_WINDOWS = os.name == "nt"

# ---------------------------------------------------------------------------
# 路径常量（兼容 PyInstaller --onefile 解包目录）
# ---------------------------------------------------------------------------


def get_base_dir() -> Path:
    """返回程序根目录：源码运行时为项目根，PyInstaller 打包后为 _MEIPASS。"""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parent.parent


BASE_DIR: Path = get_base_dir()
RULES_DIR: Path = BASE_DIR / "rules"
TOOLS_DIR: Path = BASE_DIR / "tools"
YARA_RULES_DIR: Path = RULES_DIR / "yara"


# ---------------------------------------------------------------------------
# 控制台 / 基础工具
# ---------------------------------------------------------------------------


def setup_console() -> None:
    """统一把 stdout/stderr 切到 UTF-8，避免 Windows 控制台中文乱码。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


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


# ---------------------------------------------------------------------------
# 权限
# ---------------------------------------------------------------------------


def is_admin() -> bool:
    """当前进程是否具备管理员权限。"""
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 路径规范化与判定
# ---------------------------------------------------------------------------

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


def user_writable_roots() -> list[str]:
    """用户可写目录集合：%TEMP% %APPDATA% %LOCALAPPDATA% %PROGRAMDATA% C:\\Users\\Public。"""
    values = [
        os.environ.get("TEMP"),
        os.environ.get("TMP"),
        os.environ.get("APPDATA"),
        os.environ.get("LOCALAPPDATA"),
        os.environ.get("PROGRAMDATA"),
        os.environ.get("PUBLIC"),
        r"C:\Users\Public",
        r"C:\ProgramData",
    ]
    roots: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value:
            continue
        try:
            absolute = os.path.abspath(expand_vars(value))
        except Exception:
            continue
        key = os.path.normcase(absolute)
        if key and key not in seen:
            seen.add(key)
            roots.append(absolute)
    return roots


def is_user_writable(path: Any) -> bool:
    """路径（或启动命令行）是否可被普通用户写入。

    判定 = 路径粗筛（落在 user_writable_roots 内）+ 真实 ACL 复核：
    路径存在时用 ``CreateFileW(FILE_ADD_FILE)`` 实测当前用户能否在该目录创建文件。
    这样可以避免把 ``%PROGRAMDATA%`` 下由 TrustedInstaller/SYSTEM 保护的目录
    （如 Windows Defender Platform）误判为"用户可写"。路径不存在时退回纯路径判定。
    """
    if not path:
        return False
    candidate = extract_executable(path) or normalize_path(path)
    if not candidate:
        return False
    absolute = _norm_abs(candidate)
    if not absolute:
        return False
    if not any(path_under(absolute, root) for root in user_writable_roots()):
        return False
    if _path_exists(absolute):
        probe = _probe_user_write(absolute)
        if probe is False:
            return False
    return True


# ---------------------------------------------------------------------------
# 真实写权限探测（只用于对已存在的路径复核 ACL，避免误判受保护目录）
# ---------------------------------------------------------------------------

_KERNEL32 = None
_WRITABLE_DIR_CACHE: dict[str, bool] = {}

_FILE_ADD_FILE = 0x0002  # 目录下创建文件（FILE_WRITE_DATA for files）
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_SHARE_ALL = 0x00000007
_OPEN_EXISTING = 3
_INVALID_HANDLE_VALUE = (1 << (8 * ctypes.sizeof(ctypes.c_void_p))) - 1


def _path_exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except Exception:
        return False


def _get_kernel32():
    global _KERNEL32
    if _KERNEL32 is None:
        kernel32 = ctypes.WinDLL("kernel32.dll")  # type: ignore[attr-defined]
        kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        _KERNEL32 = kernel32
    return _KERNEL32


def _probe_directory_write(directory: str) -> bool | None:
    """实测当前用户能否在目录内创建文件；None 表示无法判定。"""
    if not IS_WINDOWS:
        return None
    key = os.path.normcase(os.path.abspath(directory))
    if key in _WRITABLE_DIR_CACHE:
        return _WRITABLE_DIR_CACHE[key]
    writable: bool | None = None
    try:
        kernel32 = _get_kernel32()
        handle = kernel32.CreateFileW(
            directory,
            _FILE_ADD_FILE,
            _FILE_SHARE_ALL,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if handle in (None, 0, _INVALID_HANDLE_VALUE):
            writable = False
        else:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
            writable = True
    except Exception:
        writable = None
    if writable is not None:
        _WRITABLE_DIR_CACHE[key] = writable
    return writable


def _probe_user_write(path: str) -> bool | None:
    """对路径的父目录（或最近的已存在祖先目录）做写权限探测。"""
    try:
        candidate = os.path.dirname(path) if os.path.isfile(path) else path
        while candidate and not os.path.isdir(candidate):
            parent = os.path.dirname(candidate.rstrip("\\/"))
            if parent == candidate or not parent:
                return None
            candidate = parent
        if not candidate or not os.path.isdir(candidate):
            return None
        return _probe_directory_write(candidate)
    except Exception:
        return None


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


# 常见 Windows 系统二进制文件名：出现在系统目录之外即为强伪装信号
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

# 启动项/服务/任务名中出现这些词，说明"声称"自己是系统组件
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


# 可携带 Authenticode 签名的 PE/安装包扩展名
_PE_EXTENSIONS = frozenset({".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".msi", ".com"})


def is_pe_executable(path: Any) -> bool:
    """按扩展名粗判是否为 PE/安装包文件（脚本类文件不参与签名判定）。"""
    if not path:
        return False
    candidate = extract_executable(path) or normalize_path(path)
    if not candidate:
        return False
    return os.path.splitext(candidate)[1].lower() in _PE_EXTENSIONS


# ---------------------------------------------------------------------------
# 可疑命令行特征
# ---------------------------------------------------------------------------

# (pattern_id, 正则, 中文描述)。正则均忽略大小写；命中任意一条即视为可疑。
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


# ---------------------------------------------------------------------------
# 白名单
# ---------------------------------------------------------------------------

DEFAULT_WHITELIST: dict[str, Any] = {
    "enabled": True,
    # downgrade：命中降为 INFO；filter：直接丢弃；off：不过滤
    "mode": "downgrade",
    "paths": [],
    "commandline_patterns": [],
    "signers": [],
    "domains": [],
    # 扩展白名单只按"扩展 ID 精确匹配"，不做名称子串（防 typosquatting 放行）
    "extensions": {
        "allowlist_by_id": [],
        "allowlist_by_id_with_max_score": {},
    },
    "services": [],
    "tasks": [],
    "masquerade_allow": [],
    # 冷门持久化扩展点结构化豁免（modules/persistence_ext.py）：
    # 每项 {"registry_value_path": "...", "signer_contains": "...", "note": "..."}
    "persistence_ext_allow": [],
}

_WHITELIST_LIST_KEYS = ("paths", "commandline_patterns", "signers", "domains", "services", "tasks")
_WHITELIST_MODES = ("downgrade", "filter", "off")


def load_whitelist(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """加载白名单配置；文件不存在时返回空骨架（阶段 0 即为空文件）。

    返回 dict 始终包含 enabled/mode 与六类列表键，便于调用方安全迭代。
    """
    target = Path(path) if path else RULES_DIR / "whitelist.json"
    data = load_json(target, default=None)
    merged: dict[str, Any] = copy.deepcopy(DEFAULT_WHITELIST)
    if isinstance(data, dict):
        for key, value in data.items():
            merged[key] = value
    if not isinstance(merged.get("enabled"), bool):
        merged["enabled"] = True
    if str(merged.get("mode", "")).lower() not in _WHITELIST_MODES:
        merged["mode"] = "downgrade"
    else:
        merged["mode"] = str(merged["mode"]).lower()
    for key in _WHITELIST_LIST_KEYS:
        value = merged.get(key)
        if not isinstance(value, list):
            merged[key] = []
        else:
            merged[key] = [str(item).strip() for item in value if str(item).strip()]
    merged["extensions"] = _normalize_extension_allowlist(merged.get("extensions"))
    raw_masquerade = merged.get("masquerade_allow")
    merged["masquerade_allow"] = (
        [item for item in raw_masquerade if isinstance(item, dict)]
        if isinstance(raw_masquerade, list)
        else []
    )
    # persistence_ext_allow 是 dict 列表（不是字符串列表），单独归一化：非 dict 项丢弃
    raw_persistence_ext = merged.get("persistence_ext_allow")
    merged["persistence_ext_allow"] = (
        [item for item in raw_persistence_ext if isinstance(item, dict)]
        if isinstance(raw_persistence_ext, list)
        else []
    )
    merged["_source"] = str(target)
    merged["_loaded"] = isinstance(data, dict)
    return merged


def _normalize_extension_allowlist(value: Any) -> dict[str, Any]:
    """扩展白名单归一化：兼容"纯 ID 列表"与"带 max_score 的字典"两种写法。"""
    if isinstance(value, list):
        ids = [str(item).strip().lower() for item in value if str(item).strip()]
        return {"allowlist_by_id": ids, "allowlist_by_id_with_max_score": {}}
    if isinstance(value, dict):
        raw_ids = value.get("allowlist_by_id") or []
        raw_max = value.get("allowlist_by_id_with_max_score") or {}
        ids = [str(item).strip().lower() for item in raw_ids if str(item).strip()]
        max_scores: dict[str, int] = {}
        if isinstance(raw_max, dict):
            for key, limit in raw_max.items():
                try:
                    max_scores[str(key).strip().lower()] = int(limit)
                except (TypeError, ValueError):
                    continue
        return {"allowlist_by_id": ids, "allowlist_by_id_with_max_score": max_scores}
    return {"allowlist_by_id": [], "allowlist_by_id_with_max_score": {}}


def _evidence_texts(finding: dict[str, Any]) -> list[str]:
    """收集 Finding 中可用于白名单匹配的文本字段。"""
    evidence = finding.get("evidence") or {}
    parts = [
        str(finding.get("target", "")),
        str(finding.get("detail", "")),
        str(finding.get("category", "")),
    ]
    for key in (
        "image_path",
        "launch",
        "commandline",
        "cmdline",
        "command",
        "path",
        "signer",
        "company",
        "service_name",
        "task_name",
        "extension_id",
        "extension_name",
        "name",
        "target_path",
    ):
        value = evidence.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
    return parts


def _norm_text(value: Any) -> str:
    return " ".join(str(value or "").lower().split())


def _match_masquerade_allow(finding: dict[str, Any], config: dict[str, Any]) -> dict[str, str] | None:
    """厂商伪装结构化豁免：签名者 + 路径前缀 + 签名状态 valid 三个条件同时满足才放行。

    只对 SIG_PATH_MASQUERADE 生效；签名 invalid（内容被篡改）或路径不在限定前缀下
    （如 %TEMP%）时不匹配，保持 HIGH。
    """
    entries = config.get("masquerade_allow")
    if not isinstance(entries, list) or not entries:
        return None
    rule_id = str(finding.get("rule_id") or "")
    if rule_basename(rule_id) != "SIG_PATH_MASQUERADE":
        return None
    evidence = finding.get("evidence") or {}
    signature = evidence.get("signature") if isinstance(evidence.get("signature"), dict) else {}
    status = str(signature.get("status") or "").strip().lower()
    signer = str(signature.get("signer") or "").strip()
    target = str(finding.get("target") or evidence.get("path") or "").strip()
    if not signer or not target:
        return None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        signer_needle = str(entry.get("signer_contains") or "").strip().lower()
        if not signer_needle or signer_needle not in signer.lower():
            continue
        required_status = str(entry.get("require_signature_status") or "valid").strip().lower()
        if required_status and status != required_status:
            continue
        path_prefix = str(entry.get("path_prefix") or "").strip()
        if path_prefix and not path_under(target, path_prefix):
            continue
        return {
            "type": "masquerade_allow",
            "value": f"signer={signer} path_prefix={path_prefix} status={status}",
        }
    return None


def _norm_registry_value_path(value: Any) -> str:
    """规范化注册表值展示路径：``normalize_path`` + 去首尾空白 + 小写。"""
    return str(normalize_path(value) or "").strip().lower()


def _match_persistence_ext_allow(finding: dict[str, Any], config: dict[str, Any]) -> dict[str, str] | None:
    """冷门持久化扩展点结构化豁免（modules/persistence_ext.py）。

    命中条件（必须同时满足）：

    1. ``finding.evidence["registry_value_path"]`` 归一化后与条目
       ``registry_value_path`` **精确相等**（大小写不敏感）；
    2. ``finding.evidence`` 的签名者（``signature.signer``，兼容顶层 ``signer``）
       非空，且条目 ``signer_contains`` 非空并为其大小写不敏感子串。

    路径不匹配或签名不匹配时不豁免（保持原等级，交给人工判断）。
    """
    entries = config.get("persistence_ext_allow")
    if not isinstance(entries, list) or not entries:
        return None
    evidence = finding.get("evidence") or {}
    value_path = _norm_registry_value_path(evidence.get("registry_value_path"))
    if not value_path:
        return None
    signature_info = evidence.get("signature") if isinstance(evidence.get("signature"), dict) else {}
    signer = str(signature_info.get("signer") or evidence.get("signer") or "").strip()
    if not signer:
        return None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_path = _norm_registry_value_path(entry.get("registry_value_path"))
        signer_needle = str(entry.get("signer_contains") or "").strip()
        if not entry_path or not signer_needle:
            continue
        if entry_path != value_path:
            continue
        if signer_needle.lower() not in signer.lower():
            continue
        return {
            "type": "persistence_ext_allow",
            "value": f"{value_path}（signer 含 {signer_needle}）",
        }
    return None


def match_whitelist(finding: dict[str, Any], whitelist: dict[str, Any] | None = None) -> dict[str, str] | None:
    """判断 Finding 是否命中白名单，返回命中详情（type/value）或 None。"""
    config = whitelist if whitelist is not None else load_whitelist()
    if not config.get("enabled", True) or config.get("mode") == "off":
        return None

    evidence = finding.get("evidence") or {}
    texts = _evidence_texts(finding)
    joined = _norm_text(" | ".join(texts))
    target_norm = _norm_abs(normalize_path(finding.get("target", "")))
    image_norm = _norm_abs(normalize_path(evidence.get("image_path", "")))

    # 1) 路径白名单：支持目录（包含关系）与完整文件路径
    for entry in config.get("paths", []):
        entry_norm = _norm_abs(normalize_path(entry))
        if not entry_norm:
            continue
        for candidate in (target_norm, image_norm):
            if candidate and path_under(candidate, entry_norm):
                return {"type": "paths", "value": str(entry)}

    # 1.5) 厂商伪装结构化豁免（签名者 + 路径 + valid 签名）
    masquerade_match = _match_masquerade_allow(finding, config)
    if masquerade_match:
        return masquerade_match

    # 1.6) 冷门持久化扩展点结构化豁免（注册表值路径精确 + 签名者子串）
    persistence_ext_match = _match_persistence_ext_allow(finding, config)
    if persistence_ext_match:
        return persistence_ext_match

    # 2) 签名者/公司白名单（大小写不敏感子串）
    for entry in config.get("signers", []):
        needle = _norm_text(entry)
        if not needle:
            continue
        for key in ("signer", "company"):
            value = _norm_text(evidence.get(key))
            if value and needle in value:
                return {"type": "signers", "value": str(entry)}

    # 3) 扩展白名单：只做扩展 ID 精确匹配（不做名称子串，防 typosquatting 放行）
    extension_config = _normalize_extension_allowlist(config.get("extensions"))
    extension_id = _norm_text(evidence.get("extension_id")).strip()
    if extension_id:
        if extension_id in extension_config["allowlist_by_id"]:
            return {"type": "extensions", "value": extension_id}
        max_score = extension_config["allowlist_by_id_with_max_score"].get(extension_id)
        if max_score is not None:
            try:
                score = int(float(evidence.get("score") or 0))
            except (TypeError, ValueError):
                score = 0
            if score <= max_score:
                return {
                    "type": "extensions",
                    "value": f"{extension_id}（评分 {score} ≤ 白名单上限 {max_score}）",
                }

    # 4) 服务名 / 计划任务名白名单
    for key, entries in (("service_name", config.get("services", [])), ("task_name", config.get("tasks", []))):
        value = _norm_text(evidence.get(key))
        for entry in entries:
            needle = _norm_text(entry)
            if not needle:
                continue
            if (value and needle == value) or (needle and needle in joined):
                return {"type": "services" if key == "service_name" else "tasks", "value": str(entry)}

    # 5) 命令行正则白名单
    for entry in config.get("commandline_patterns", []):
        try:
            regex = re.compile(str(entry), re.IGNORECASE)
        except re.error:
            continue
        for text in texts:
            if regex.search(str(text)):
                return {"type": "commandline_patterns", "value": str(entry)}

    return None


def apply_whitelist(
    findings: Iterable[dict[str, Any]] | None,
    whitelist: dict[str, Any] | None = None,
    mode: str | None = None,
) -> list[dict[str, Any]]:
    """对所有 Finding 应用白名单：downgrade 降为 INFO、filter 丢弃、off 不过滤。

    Args:
        findings: 待过滤的 Finding 列表。
        whitelist: 白名单配置；缺省时加载 ``rules/whitelist.json``。
        mode: 覆盖白名单文件里的 ``mode``（``downgrade``/``filter``/``off``）。
            缺省时沿用配置文件值。扫描调度核心显式传 ``downgrade`` 以保证
            GUI/CLI 默认保留"降级为 INFO"的可追溯记录。

    返回新列表，不修改入参对象（除被降级的项会生成浅拷贝）。
    """
    config = whitelist if whitelist is not None else load_whitelist()
    effective_mode = str(mode or config.get("mode", "downgrade")).lower()
    if effective_mode not in _WHITELIST_MODES:
        effective_mode = "downgrade"
    result: list[dict[str, Any]] = []
    for finding in findings or []:
        hit = match_whitelist(finding, config)
        if not hit:
            result.append(finding)
            continue
        if effective_mode == "filter":
            continue
        if effective_mode == "off":
            result.append(finding)
            continue
        downgraded = dict(finding)
        evidence = dict(downgraded.get("evidence") or {})
        evidence["whitelisted"] = True
        evidence["whitelist_match"] = hit
        downgraded["evidence"] = evidence
        if SEVERITY_ORDER.get(str(downgraded.get("severity", "")), 99) < SEVERITY_ORDER["INFO"]:
            downgraded["severity"] = "INFO"
        result.append(downgraded)
    return result


# ---------------------------------------------------------------------------
# 外部命令封装（统一 timeout / 不抛异常 / 失败信息可上报）
# ---------------------------------------------------------------------------

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if IS_WINDOWS else 0


def hidden_process_options() -> dict[str, Any]:
    """返回隐藏子进程窗口的 subprocess 参数（仅 Windows 生效）。

    ``--windowed`` 打包的 GUI 进程本身没有控制台，若子进程不隐藏，会为
    powershell.exe / autorunsc64.exe 各弹出一个黑色 CMD 窗口（扫描过程中闪烁）。
    CREATE_NO_WINDOW 阻止创建控制台；STARTF_USESHOWWINDOW + SW_HIDE 再兜底隐藏窗口。
    """
    if not IS_WINDOWS:
        return {}
    options: dict[str, Any] = {"creationflags": _CREATE_NO_WINDOW}
    try:
        startupinfo = subprocess.STARTUPINFO()  # type: ignore[attr-defined]
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # type: ignore[attr-defined]
        startupinfo.wShowWindow = subprocess.SW_HIDE  # type: ignore[attr-defined]
        options["startupinfo"] = startupinfo
    except (AttributeError, OSError):
        pass
    return options


def run_cmd(
    args: list[str] | tuple[str, ...] | str,
    timeout: int = 60,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> dict[str, Any]:
    """执行外部命令并捕获输出；任何异常都转换为结果 dict，不向上抛出。

    Returns:
        ``{"ok", "returncode", "stdout", "stderr", "error", "args"}``
    """
    result: dict[str, Any] = {
        "ok": False,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "error": None,
        "args": list(args) if not isinstance(args, str) else [args],
    }
    kwargs = hidden_process_options()
    # GUI（--windowed）进程没有 stdin：显式给 DEVNULL，避免子进程继承无效句柄
    stdin_target = subprocess.PIPE if input_text is not None else subprocess.DEVNULL
    try:
        completed = subprocess.run(
            args,
            timeout=timeout,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            cwd=cwd,
            env=env,
            stdin=stdin_target,
            input=input_text,
            **kwargs,
        )
    except FileNotFoundError as exc:
        result["error"] = f"程序不存在: {exc}"
        return result
    except subprocess.TimeoutExpired:
        result["error"] = f"执行超时（{timeout}s）"
        return result
    except Exception as exc:  # noqa: BLE001 - 统一降级
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    result["ok"] = completed.returncode == 0
    result["returncode"] = completed.returncode
    result["stdout"] = completed.stdout or ""
    result["stderr"] = completed.stderr or ""
    return result


def run_powershell(script: str, timeout: int = 60) -> dict[str, Any]:
    """以 UTF-8 输出执行 PowerShell 脚本片段（供计划任务/服务/WMI 采集使用）。"""
    prelude = "$OutputEncoding=[Console]::OutputEncoding=[Text.Encoding]::UTF8;\n"
    args = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        prelude + script,
    ]
    return run_cmd(args, timeout=timeout)


def run_powershell_json(script: str, timeout: int = 60) -> tuple[Any, str | None]:
    """执行 PowerShell 并解析 JSON 输出；返回 ``(数据, 错误信息)``，失败时数据为 None。"""
    result = run_powershell(script, timeout=timeout)
    if not result["ok"]:
        return None, result.get("error") or (result.get("stderr") or "").strip() or "PowerShell 执行失败"
    text = (result.get("stdout") or "").strip()
    if not text:
        return None, "PowerShell 输出为空"
    try:
        return json.loads(text), None
    except ValueError as exc:
        return None, f"JSON 解析失败: {exc}"
