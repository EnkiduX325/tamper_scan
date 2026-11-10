# -*- coding: utf-8 -*-
"""LSA / AppInit_DLLs / IFEO 持久化检测（阶段 4）。

1. **LSA 包**：``HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa`` 的
   ``Authentication Packages`` / ``Notification Packages``。
   只有**不在已知合法列表**里的项才报 HIGH（企业环境合法追加 rassfm/pku2u 等，
   不能一看到非默认值就报）。
2. **AppInit_DLLs**：非空且 ``LoadAppInit_DLLs=1`` 才实际生效 → HIGH；
   ``LoadAppInit_DLLs=0`` 时**实际不生效** → 降为 INFO。
3. **IFEO Debugger**：``Image File Execution Options\\<exe>\\Debugger``。
   常见调试器（vsjitdebugger/windbg/cdb 等）作为合法目标 → LOW；
   其余 Debugger 劫持 → HIGH。

标准用户读取 HKLM 一般可读；权限不足时返回 SKIPPED。
"""

from __future__ import annotations

import os
import re
import winreg
from typing import Any, Iterator

from core import signature, utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "LsaAppInit"

_LSA_KEY = r"SYSTEM\CurrentControlSet\Control\Lsa"
_APPINIT_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
_IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

# 已知合法的 LSA 包（默认值 + 企业环境常见合法追加项）
_KNOWN_AUTH_PACKAGES = {
    "msv1_0",
    "pku2u",
    "rassfm",
    "scecli",
    "kerberos",
    "negoexts",
    "wdigest",
    "tspkg",
    "cloudap",
    "cng",
}
_KNOWN_NOTIFICATION_PACKAGES = {"scecli", "rassfm", "pku2u", "msv1_0"}

# 已知合法调试器（Application Verifier / 常见调试工具链）
_KNOWN_DEBUGGERS = {
    "vsjitdebugger.exe",
    "windbg.exe",
    "windbgx.exe",
    "cdb.exe",
    "ntsd.exe",
    "kd.exe",
    "dbgview.exe",
    "devenv.exe",
    "gflags.exe",
    "appverif.exe",
    "verifier.exe",
    "procmon.exe",
    "procexp.exe",
}

_VIEWS = ((winreg.KEY_WOW64_64KEY, "64"), (winreg.KEY_WOW64_32KEY, "32"))


def _read_multi_sz(hive: int, subkey: str, name: str, view_flag: int = 0) -> list[str]:
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as key:
            value = winreg.QueryValueEx(key, name)[0]
    except (FileNotFoundError, OSError):
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _read_value(hive: int, subkey: str, name: str, view_flag: int = 0) -> Any:
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as key:
            return winreg.QueryValueEx(key, name)[0]
    except (FileNotFoundError, OSError):
        return None


# ---------------------------------------------------------------------------
# LSA 包
# ---------------------------------------------------------------------------


def _analyze_lsa_packages(
    kind: str,
    packages: list[str],
    key_path: str,
    known: set[str],
) -> list[dict[str, Any]]:
    """LSA 包判定（纯函数）：未知包 → HIGH。"""
    unknown = [pkg for pkg in packages if pkg.lower() not in known]
    if not unknown:
        return []
    return [
        make_finding(
            "HIGH",
            CATEGORY,
            key_path,
            f"LSA {kind} 含未知项：{', '.join(unknown)}（默认值之外的包可能是密码过滤器/后门）",
            {
                "kind": kind,
                "key": key_path,
                "packages": packages,
                "unknown": unknown,
                "known_allowlist": sorted(known),
            },
            "LSA_PACKAGE_HIJACK",
        )
    ]


# ---------------------------------------------------------------------------
# AppInit_DLLs
# ---------------------------------------------------------------------------


def _split_dlls(value: Any) -> list[str]:
    return [part for part in re.split(r"[;,\s]+", str(value or "")) if part.strip()]


def _analyze_appinit(
    dlls_value: Any,
    load_flag: Any,
    require_signed: Any,
    key_path: str,
) -> list[dict[str, Any]]:
    """AppInit_DLLs 判定（纯函数）：生效时 HIGH，不生效时 INFO。"""
    entries = _split_dlls(dlls_value)
    if not entries:
        return []
    try:
        active = int(load_flag or 0) == 1
    except (TypeError, ValueError):
        active = False
    details = []
    for entry in entries:
        dll = utils.normalize_path(entry)
        sig = signature.verify(dll) if utils.is_pe_executable(dll) else {"status": "n/a", "signer": None}
        details.append(
            {
                "dll": dll,
                "user_writable": utils.is_user_writable(dll),
                "in_system_dir": utils.is_in_system_dir(dll),
                "signature_status": sig.get("status"),
                "signer": sig.get("signer"),
            }
        )
    severity = "HIGH" if active else "INFO"
    rule_id = "LSA_APPINIT" if active else "LSA_APPINIT_INACTIVE"
    suffix = "且 LoadAppInit_DLLs=1，已生效" if active else "但 LoadAppInit_DLLs=0，当前不生效"
    return [
        make_finding(
            severity,
            CATEGORY,
            key_path,
            f"AppInit_DLLs 非空（{', '.join(entries)}）{suffix}",
            {
                "key": key_path,
                "appinit_dlls": str(dlls_value or ""),
                "load_appinit_dlls": load_flag,
                "require_signed_appinit_dlls": require_signed,
                "entries": details,
            },
            rule_id,
        )
    ]


# ---------------------------------------------------------------------------
# IFEO
# ---------------------------------------------------------------------------


def _analyze_ifeo(image_name: str, debugger_value: str, key_path: str) -> list[dict[str, Any]]:
    """IFEO Debugger 判定（纯函数）：常见调试器 → LOW，其余 → HIGH。"""
    debugger = str(debugger_value or "").strip()
    if not debugger:
        return []
    executable = utils.extract_executable(debugger) or debugger
    basename = os.path.basename(utils.normalize_path(executable)).lower()
    legit = basename in _KNOWN_DEBUGGERS
    return [
        make_finding(
            "LOW" if legit else "HIGH",
            CATEGORY,
            key_path,
            (
                f"IFEO 为 {image_name or '(未知程序)'} 设置了 Debugger：{truncate(debugger, 200)}"
                + ("（常见调试器，可能为合法调试配置）" if legit else "（非已知调试器，疑似劫持）")
            ),
            {
                "key": key_path,
                "image": image_name,
                "debugger": truncate(debugger, 400),
                "debugger_basename": basename,
                "known_debugger": legit,
            },
            "IFEO_DEBUGGER_LEGIT" if legit else "IFEO_DEBUGGER",
        )
    ]


# ---------------------------------------------------------------------------
# 采集
# ---------------------------------------------------------------------------


def _iter_ifeo_entries() -> Iterator[tuple[str, str, str]]:
    for view_flag, view_name in _VIEWS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _IFEO_KEY, 0, winreg.KEY_READ | view_flag) as ifeo_key:
                count = winreg.QueryInfoKey(ifeo_key)[0]
                names = []
                for index in range(count):
                    try:
                        names.append(winreg.EnumKey(ifeo_key, index))
                    except OSError:
                        continue
        except (FileNotFoundError, OSError):
            continue
        for name in names:
            key_path = f"HKLM\\{_IFEO_KEY}\\{name}（{view_name}）"
            debugger = _read_value(winreg.HKEY_LOCAL_MACHINE, f"{_IFEO_KEY}\\{name}", "Debugger", view_flag)
            if debugger is None:
                continue
            yield name, str(debugger), key_path


def scan() -> list[dict[str, Any]]:
    """扫描 LSA / AppInit / IFEO，返回 ``list[Finding]``。"""
    findings: list[dict[str, Any]] = []
    errors: list[str] = []

    # 1) LSA 包
    try:
        auth_packages = _read_multi_sz(winreg.HKEY_LOCAL_MACHINE, _LSA_KEY, "Authentication Packages")
        notification_packages = _read_multi_sz(winreg.HKEY_LOCAL_MACHINE, _LSA_KEY, "Notification Packages")
        lsa_findings = _analyze_lsa_packages(
            "Authentication Packages",
            auth_packages,
            f"HKLM\\{_LSA_KEY}\\Authentication Packages",
            _KNOWN_AUTH_PACKAGES,
        )
        lsa_findings += _analyze_lsa_packages(
            "Notification Packages",
            notification_packages,
            f"HKLM\\{_LSA_KEY}\\Notification Packages",
            _KNOWN_NOTIFICATION_PACKAGES,
        )
        findings.extend(lsa_findings)
    except PermissionError as exc:
        errors.append(f"HKLM\\{_LSA_KEY}: 拒绝访问（{exc}）")
    except OSError as exc:
        errors.append(f"HKLM\\{_LSA_KEY}: {exc}")

    # 2) AppInit_DLLs（64/32 两个视图都看）
    for view_flag, view_name in _VIEWS:
        key_path = f"HKLM\\{_APPINIT_KEY}（{view_name}）"
        dlls = _read_value(winreg.HKEY_LOCAL_MACHINE, _APPINIT_KEY, "AppInit_DLLs", view_flag)
        if dlls is None:
            continue
        load_flag = _read_value(winreg.HKEY_LOCAL_MACHINE, _APPINIT_KEY, "LoadAppInit_DLLs", view_flag)
        require_signed = _read_value(winreg.HKEY_LOCAL_MACHINE, _APPINIT_KEY, "RequireSignedAppInit_DLLs", view_flag)
        findings.extend(_analyze_appinit(dlls, load_flag, require_signed, key_path))

    # 3) IFEO Debugger
    for image_name, debugger, key_path in _iter_ifeo_entries():
        findings.extend(_analyze_ifeo(image_name, debugger, key_path))

    if errors:
        findings.append(
            make_skipped(
                CATEGORY,
                "LSA/LSA API",
                "部分 LSA/启动相关注册表位置无法读取：" + "；".join(errors[:5]),
                {"errors": errors},
                "LSA_ACCESS_DENIED",
            )
        )
    return utils.apply_whitelist(findings)
