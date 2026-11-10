# -*- coding: utf-8 -*-
"""COM 劫持检测（阶段 4）：HKCU ``CLSID\\{...}\\InprocServer32``。

误报控制（重要）：用户级安装的 Electron/输入法等注册 COM 组件很常见，
"用户可写目录 → HIGH" 会大量误报。因此按以下加权判定：

1. **覆盖系统 CLSID**：该 CLSID 在 HKLM 下也存在（HKCU 覆盖系统注册项）→ HIGH；
2. **DLL 无签名/签名无效**：用户可写目录的 DLL 且 WinVerifyTrust 判定不可信 → HIGH；
3. 以上两条都不满足（用户可写但已签名，且非覆盖）→ **LOW**（需人工确认）；
4. DLL 不在用户可写目录 → 不报（系统/Program Files 注册的组件属正常）。

仅检查 ``InprocServer32`` 默认值指向的 DLL；缺失/空值跳过。
"""

from __future__ import annotations

import winreg
from typing import Any, Iterator

from core import signature, utils
from core.finding import make_finding
from core.utils import truncate

CATEGORY = "COMHijack"

_HKCU_CLSID = r"Software\Classes\CLSID"
_HKLM_CLSID = r"SOFTWARE\Classes\CLSID"
_INPROC = "InprocServer32"


def _key_exists(hive: int, subkey: str, view_flag: int = 0) -> bool:
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag):
            return True
    except OSError:
        return False


def _read_default_value(hive: int, subkey: str, view_flag: int = 0) -> str:
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as key:
            return str(winreg.QueryValueEx(key, "")[0] or "").strip()
    except (FileNotFoundError, OSError):
        return ""


def _iter_hkcu_inproc_servers() -> Iterator[tuple[str, str]]:
    """枚举 HKCU 下所有注册了 InprocServer32 的 CLSID → (clsid, dll_path)。"""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _HKCU_CLSID, 0, winreg.KEY_READ) as clsid_key:
            subkey_count = winreg.QueryInfoKey(clsid_key)[0]
            clsid_names = []
            for index in range(subkey_count):
                try:
                    clsid_names.append(winreg.EnumKey(clsid_key, index))
                except OSError:
                    continue
    except (FileNotFoundError, OSError):
        return
    for clsid in clsid_names:
        subkey = f"{_HKCU_CLSID}\\{clsid}\\{_INPROC}"
        dll_path = _read_default_value(winreg.HKEY_CURRENT_USER, subkey)
        if not dll_path:
            continue
        yield clsid, dll_path


def _analyze(clsid: str, dll_path: str) -> list[dict[str, Any]]:
    """对单个 HKCU COM 注册做判定（纯函数，便于单元测试）。"""
    if not dll_path:
        return []
    executable = utils.extract_executable(dll_path) or utils.normalize_path(dll_path)
    if not utils.is_user_writable(executable):
        return []

    clsid_key = f"HKCU\\{_HKCU_CLSID}\\{clsid}\\{_INPROC}"
    overrides_hklm = _key_exists(winreg.HKEY_LOCAL_MACHINE, f"{_HKLM_CLSID}\\{clsid}\\{_INPROC}")
    sig_finding = signature.signature_finding(executable, category=CATEGORY)
    signature_status = ""
    signature_signer = None
    if sig_finding:
        signature_status = str(sig_finding.get("rule_id", ""))
        signature_signer = (sig_finding.get("evidence", {}).get("signature") or {}).get("signer")

    evidence = {
        "clsid": clsid,
        "key": clsid_key,
        "inprocserver32": truncate(dll_path, 400),
        "dll_path": executable,
        "overrides_hklm": overrides_hklm,
        "signature_rule": signature_status,
        "signature_signer": signature_signer,
    }

    if overrides_hklm:
        return [
            make_finding(
                "HIGH",
                CATEGORY,
                executable,
                f"HKCU 覆盖了系统已注册的 CLSID {clsid}，InprocServer32 → {truncate(dll_path, 200)}",
                evidence,
                "COM_HIJACK",
            )
        ]
    if sig_finding is not None:
        return [
            make_finding(
                "HIGH",
                CATEGORY,
                executable,
                f"用户可写目录注册的 COM 组件签名异常（{signature_status}）：{truncate(dll_path, 200)}",
                evidence,
                "COM_HIJACK",
            )
        ]
    return [
        make_finding(
            "LOW",
            CATEGORY,
            executable,
            f"用户可写目录注册的 COM 组件（已签名，非系统 CLSID 覆盖，需人工确认）：{truncate(dll_path, 200)}",
            evidence,
            "COM_HIJACK_LOW",
        )
    ]


def scan() -> list[dict[str, Any]]:
    """扫描 HKCU CLSID 劫持，返回 ``list[Finding]``。"""
    findings: list[dict[str, Any]] = []
    try:
        for clsid, dll_path in _iter_hkcu_inproc_servers():
            findings.extend(_analyze(clsid, dll_path))
    except OSError:
        pass
    return utils.apply_whitelist(findings)
