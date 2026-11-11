# -*- coding: utf-8 -*-
"""LSA / AppInit_DLLs / IFEO / Winlogon 持久化检测（阶段 4，V1.2 扩展 Winlogon）。

1. **LSA 包**：``HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa`` 的
   ``Authentication Packages`` / ``Notification Packages``。
   只有**不在已知合法列表**里的项才报 HIGH（企业环境合法追加 rassfm/pku2u 等，
   不能一看到非默认值就报）。
2. **AppInit_DLLs**：非空且 ``LoadAppInit_DLLs=1`` 才实际生效 → HIGH；
   ``LoadAppInit_DLLs=0`` 时**实际不生效** → 降为 INFO。
3. **IFEO Debugger**：``Image File Execution Options\\<exe>\\Debugger``。
   常见调试器（vsjitdebugger/windbg/cdb 等）作为合法目标 → LOW；
   其余 Debugger 劫持 → HIGH。

4. **Winlogon**：``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon``
   的 ``Shell`` / ``Userinit`` / ``GinaDLL`` / ``AppSetup`` / ``Taskman`` 值，
   以及 ``Notify`` 子键下每个子键的 ``DllName``。默认基线：Shell=explorer.exe；
   Userinit=<SystemRoot>\\system32\\userinit.exe,；GinaDLL/AppSetup/Taskman/Notify 默认不存在。
   判定阶梯（值存在且与默认基线不符才判定）：

   - 文件不存在 / 非 PE / 签名 status != valid / 不在 System32 => HIGH；
   - 签名 valid 但签名者非微软 => MEDIUM；
   - 签名 valid、微软签名且位于系统目录 => LOW（仅基线偏移提示）。

   规则 ID：WINLOGON_SHELL_TAMPER / WINLOGON_USERINIT_TAMPER /
   WINLOGON_GINADLL_TAMPER / WINLOGON_APPSETUP_TAMPER /
   WINLOGON_TASKMAN_TAMPER / WINLOGON_NOTIFY_TAMPER。
   AutoAdminLogon=1 且 DefaultPassword 非空 -> LOW AUTOADMINLOGON_PLAINTEXT
   （evidence 只记 password_present/password_length，绝不写入明文密码）。
   Winlogon 键读取失败 -> SKIPPED WINLOGON_ACCESS_DENIED。

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

_WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
_WINLOGON_VALUE_NAMES = ("Shell", "Userinit", "GinaDLL", "AppSetup", "Taskman")
_WINLOGON_RULES = {
    "Shell": "WINLOGON_SHELL_TAMPER",
    "Userinit": "WINLOGON_USERINIT_TAMPER",
    "GinaDLL": "WINLOGON_GINADLL_TAMPER",
    "AppSetup": "WINLOGON_APPSETUP_TAMPER",
    "Taskman": "WINLOGON_TASKMAN_TAMPER",
}
_WINLOGON_NOTIFY_RULE = "WINLOGON_NOTIFY_TAMPER"
_WINLOGON_ACCESS_DENIED_RULE = "WINLOGON_ACCESS_DENIED"
# Winlogon 键不做 WOW64 重定向，两视图内容通常一致；仍按"64 位视图 + 默认视图"各读一次，
# 读不到的项跳过，判定结果按 (rule_id, value_name) 去重，避免重复上报。
_WINLOGON_VIEWS = ((winreg.KEY_WOW64_64KEY, "64"), (0, "默认"))


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


def _normalize_package(package: Any) -> str:
    """规范化 LSA 包名：去引号/空白。实测 Windows Security Packages 可能存 ``""`` 占位。"""
    return str(package or "").strip().strip('"').strip("'").strip()


def _analyze_lsa_packages(
    kind: str,
    packages: list[str],
    key_path: str,
    known: set[str],
    rule_id: str = "LSA_PACKAGE_HIJACK",
) -> list[dict[str, Any]]:
    """LSA 包判定（纯函数）：未知包 → HIGH。

    ``rule_id`` 缺省保持 Notification Packages 的历史行为（``LSA_PACKAGE_HIJACK``）；
    V1.2 起 Authentication/Security Packages 传入 ``LSA_AUTH_PACKAGE_TAMPER``。
    """
    packages = [_normalize_package(pkg) for pkg in packages]
    packages = [pkg for pkg in packages if pkg]
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
            rule_id,
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
# Winlogon（Shell / Userinit / GinaDLL / AppSetup / Taskman / Notify）
# ---------------------------------------------------------------------------


def _windows_dir() -> str:
    """Windows 安装目录（默认 ``C:\\Windows``），用于推导默认基线路径。"""
    return os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"


def _default_userinit() -> str:
    """Winlogon Userinit 的默认基线路径（随系统盘/安装目录变化）。"""
    return os.path.join(_windows_dir(), "system32", "userinit.exe")


def _is_default_shell(raw_value: Any) -> bool:
    """Shell 是否等价于默认值 explorer.exe（容忍大小写、空白、参数与 %SystemRoot% 路径）。"""
    text = str(raw_value or "").strip()
    if not text:
        return False
    executable = utils.normalize_path(utils.extract_executable(text) or text)
    if os.path.basename(executable).lower() != "explorer.exe":
        return False
    directory = os.path.dirname(executable)
    if not directory:
        return True  # 裸文件名 explorer.exe：由系统目录解析，视为默认值
    # 显式路径只接受 Windows 目录下的 explorer.exe（C:\Temp\explorer.exe 属伪装，需上报）
    return utils.path_under(executable, _windows_dir())


def _userinit_parts(raw_value: Any) -> list[str]:
    """把 Userinit 值拆成非空项（忽略尾逗号、多余逗号与空白）。"""
    return [part.strip() for part in str(raw_value or "").split(",") if part.strip()]


def _is_baseline_userinit(executable: str) -> bool:
    candidate = os.path.normcase(utils.normalize_path(executable))
    if not candidate:
        return False
    if candidate == os.path.normcase(utils.normalize_path(_default_userinit())):
        return True
    return os.path.basename(candidate).lower() == "userinit.exe" and utils.is_in_system_dir(candidate)


def _is_default_userinit(raw_value: Any) -> bool:
    """Userinit 是否等价于默认基线（忽略尾逗号、大小写与空白）。"""
    parts = _userinit_parts(raw_value)
    return len(parts) == 1 and _is_baseline_userinit(parts[0])


def _is_default_winlogon_value(value_name: str, raw_value: Any) -> bool:
    """值是否等于默认基线（Shell/Userinit 有基线，其余默认不存在）。"""
    if value_name == "Shell":
        return _is_default_shell(raw_value)
    if value_name == "Userinit":
        return _is_default_userinit(raw_value)
    return False


def _winlogon_executable(value_name: str, raw_value: Any) -> str:
    """从 Winlogon 原始值解析需要检查的可执行文件（纯字符串处理，不访问文件系统）。"""
    text = str(raw_value or "").strip()
    if not text:
        return ""
    if value_name == "Userinit":
        # Userinit 是逗号分隔的启动列表：跳过默认 userinit.exe，只看新增项
        for part in _userinit_parts(text):
            executable = utils.normalize_path(utils.extract_executable(part) or part)
            if executable and not _is_baseline_userinit(executable):
                return executable
        return ""
    executable = utils.extract_executable(text)
    return utils.normalize_path(executable or text)


def _expected_baseline(value_name: str) -> str | None:
    """返回该值的默认基线（用于 evidence 展示）；None 表示默认不存在。"""
    if value_name == "Shell":
        return "explorer.exe"
    if value_name == "Userinit":
        return _default_userinit() + ","
    return None


def _winlogon_severity(
    is_pe: bool,
    status: str,
    in_system_dir: bool,
    signer: str | None,
) -> tuple[str, str]:
    """Winlogon 判定阶梯（纯函数）：返回 ``(severity, reason)``。

    1. 文件不存在 / 非 PE / 签名 status != valid / 不在系统目录 => HIGH；
    2. 签名 valid 但签名者非微软 => MEDIUM；
    3. 签名 valid、微软签名且位于系统目录 => LOW（仅基线偏移）。
    """
    if not is_pe:
        return "HIGH", "non_pe_target"
    if status == "missing":
        return "HIGH", "missing_file"
    if status == "unsigned":
        return "HIGH", "unsigned"
    if status != "valid":
        return "HIGH", "invalid_signature"
    if not in_system_dir:
        return "HIGH", "outside_system_dir"
    if not signature.is_microsoft_signer(signer):
        return "MEDIUM", "non_microsoft_signer"
    return "LOW", "baseline_deviation"


def _winlogon_detail(value_name: str, reason: str, executable: str, signer: str | None, raw_text: str) -> str:
    """按判定阶梯生成中文 detail（不包含敏感信息）。"""
    target = executable or truncate(raw_text, 200)
    if reason == "non_pe_target":
        return f"Winlogon {value_name} 指向非 PE 目标：{target}（偏离默认基线，无法通过 Authenticode 验证）"
    if reason == "missing_file":
        return f"Winlogon {value_name} 指向的文件不存在：{target}（偏离默认基线，疑似残留或劫持配置）"
    if reason == "unsigned":
        return f"Winlogon {value_name} 指向的文件没有数字签名：{target}（偏离默认基线，无法验证来源）"
    if reason == "invalid_signature":
        return f"Winlogon {value_name} 指向的文件签名无效或缺失：{target}（偏离默认基线）"
    if reason == "outside_system_dir":
        return f"Winlogon {value_name} 指向 System32/SysWOW64 之外的文件：{target}（偏离默认基线）"
    if reason == "non_microsoft_signer":
        return f"Winlogon {value_name} 指向非微软签名的文件（签名者：{signer}）：{target}（偏离默认基线）"
    return f"Winlogon {value_name} 偏离默认基线，但目标为微软签名且位于系统目录：{target}（仅基线偏移提示）"


def _analyze_winlogon_value(
    value_name: str,
    raw_value: Any,
    key_path: str,
    sig_result: dict[str, Any],
    rule_id: str = "",
) -> list[dict[str, Any]]:
    """单个 Winlogon 值判定（纯函数：注册表数据与签名结果均由调用方注入）。

    Args:
        value_name: 值名；Notify 子键用 ``Notify\\<name>\\DllName`` 形式。
        raw_value: 注册表原始值（None 表示值不存在）。
        key_path: 写入 Finding.target 的可读注册表路径。
        sig_result: ``signature.verify()`` 结果（可注入；非 PE/空路径可为 missing/n-a）。
        rule_id: 规则 ID；缺省按值名映射到 ``WINLOGON_<VALUE>_TAMPER``。

    Returns:
        ``list[Finding]``；默认基线与空白值不产生 Finding。

    判定阶梯（值存在且与默认基线不符才判定）：

    1. 文件不存在 / 非 PE / 签名 status != valid / 不在 System32 => HIGH；
    2. 签名 valid 但签名者非微软 => MEDIUM；
    3. 签名 valid、微软签名且位于系统目录 => LOW（仅基线偏移提示）。
    """
    if raw_value is None:
        return []
    if _is_default_winlogon_value(value_name, raw_value):
        return []
    raw_text = str(raw_value).strip()
    if not raw_text:
        return []  # 空白值不构成可执行劫持，避免噪声
    executable = _winlogon_executable(value_name, raw_text)
    if not executable:
        return []
    resolved_rule = rule_id or _WINLOGON_RULES.get(value_name, "WINLOGON_TAMPER")
    sig = sig_result if isinstance(sig_result, dict) else {}
    status = str(sig.get("status") or "missing").strip().lower()
    signer = sig.get("signer")
    in_system_dir = utils.is_in_system_dir(executable)
    is_pe = utils.is_pe_executable(executable)
    severity, reason = _winlogon_severity(is_pe, status, in_system_dir, signer)
    return [
        make_finding(
            severity,
            CATEGORY,
            key_path,
            _winlogon_detail(value_name, reason, executable, signer, raw_text),
            {
                "value_name": value_name,
                "key": key_path,
                "raw_value": truncate(raw_text, 400),
                "executable": executable,
                "path": executable,
                "image_path": executable,
                "in_system_dir": in_system_dir,
                "is_pe": is_pe,
                "default_baseline": False,
                "expected_baseline": _expected_baseline(value_name),
                "signature_status": status,
                "signer": signer,
                "signature": dict(sig),
                "reasons": [reason],
            },
            resolved_rule,
        )
    ]


def _analyze_autoadminlogon(
    auto_value: Any,
    password_value: Any,
    key_path: str,
) -> list[dict[str, Any]]:
    """AutoAdminLogon + DefaultPassword 明文自动登录判定（纯函数）。

    仅当 ``AutoAdminLogon=1`` 且 DefaultPassword 存在且非空时上报 LOW；
    evidence 只记录 ``password_present`` / ``password_length``，绝不写入密码明文。
    """
    if str(auto_value if auto_value is not None else "").strip() != "1":
        return []
    if password_value is None:
        return []
    password = str(password_value)
    if not password.strip():
        return []
    return [
        make_finding(
            "LOW",
            CATEGORY,
            key_path,
            "Winlogon 启用了 AutoAdminLogon 且 DefaultPassword 以明文保存（密码内容不写入报告）",
            {
                "value_name": "DefaultPassword",
                "key": key_path,
                "auto_admin_logon": str(auto_value).strip(),
                "password_present": True,
                "password_length": len(password),
            },
            "AUTOADMINLOGON_PLAINTEXT",
        )
    ]


def _verify_winlogon_target(executable: str) -> dict[str, Any]:
    """对 Winlogon 目标验签（采集层调用，测试可 mock）；非 PE/空路径不调用 WinVerifyTrust。"""
    if not executable:
        return {"status": "missing", "signer": None, "error": "无法从注册表值解析可执行文件", "via": None}
    if not utils.is_pe_executable(executable):
        return {"status": "n/a", "signer": None, "error": "非 PE 文件，不适用 Authenticode 验签", "via": None}
    return signature.verify(executable)


def _collect_winlogon(view_flag: int) -> dict[str, Any]:
    """用 winreg 采集 Winlogon 值与 Notify 子键（只读；键/值缺失时跳过）。

    Returns:
        ``{"values": {值名: 原始值}, "notify": [{"name": 子键名, "dll": DllName 原始值}]}``。
        权限不足（PermissionError）等 OSError 向上抛出，由 :func:`_scan_winlogon` 降级为 SKIPPED。
    """
    values: dict[str, Any] = {}
    notify: list[dict[str, Any]] = []
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _WINLOGON_KEY, 0, winreg.KEY_READ | view_flag) as key:
        for name in _WINLOGON_VALUE_NAMES + ("AutoAdminLogon", "DefaultPassword"):
            try:
                values[name] = winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                continue
        try:
            with winreg.OpenKey(key, "Notify", 0, winreg.KEY_READ) as notify_key:
                sub_count = winreg.QueryInfoKey(notify_key)[0]
                for index in range(sub_count):
                    try:
                        sub_name = winreg.EnumKey(notify_key, index)
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(notify_key, sub_name, 0, winreg.KEY_READ) as sub_key:
                            dll_value = winreg.QueryValueEx(sub_key, "DllName")[0]
                    except FileNotFoundError:
                        continue
                    notify.append({"name": sub_name, "dll": dll_value})
        except FileNotFoundError:
            pass
    return {"values": values, "notify": notify}


def _analyze_winlogon_collected(collected: dict[str, Any] | None, key_path: str) -> list[dict[str, Any]]:
    """对已采集的 Winlogon 数据做判定（验签走 ``_verify_winlogon_target``，便于 mock）。"""
    data = collected if isinstance(collected, dict) else {}
    values = data.get("values") if isinstance(data.get("values"), dict) else {}
    findings: list[dict[str, Any]] = []
    for value_name in _WINLOGON_VALUE_NAMES:
        if value_name not in values:
            continue
        raw_value = values[value_name]
        if _is_default_winlogon_value(value_name, raw_value):
            continue
        executable = _winlogon_executable(value_name, raw_value)
        if not executable:
            continue
        findings.extend(
            _analyze_winlogon_value(
                value_name,
                raw_value,
                f"{key_path}\\{value_name}",
                _verify_winlogon_target(executable),
            )
        )
    notify_entries = data.get("notify") or []
    if isinstance(notify_entries, list):
        for entry in notify_entries:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            dll_value = entry.get("dll")
            if not name or dll_value is None:
                continue
            value_name = f"Notify\\{name}\\DllName"
            executable = _winlogon_executable(value_name, dll_value)
            if not executable:
                continue
            findings.extend(
                _analyze_winlogon_value(
                    value_name,
                    dll_value,
                    f"{key_path}\\Notify\\{name}\\DllName",
                    _verify_winlogon_target(executable),
                    _WINLOGON_NOTIFY_RULE,
                )
            )
    findings.extend(
        _analyze_autoadminlogon(
            values.get("AutoAdminLogon"),
            values.get("DefaultPassword"),
            f"{key_path}\\AutoAdminLogon",
        )
    )
    return findings


def _scan_winlogon() -> list[dict[str, Any]]:
    """采集并判定 Winlogon（64 位视图 + 默认视图）；读取失败的视图降级为 SKIPPED。"""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for view_flag, view_name in _WINLOGON_VIEWS:
        key_path = f"HKLM\\{_WINLOGON_KEY}（{view_name}）"
        try:
            collected = _collect_winlogon(view_flag)
        except PermissionError as exc:
            findings.append(
                make_skipped(
                    CATEGORY,
                    key_path,
                    f"Winlogon 注册表键拒绝访问（{exc}）",
                    {"key": key_path, "view": view_name, "error": str(exc)},
                    _WINLOGON_ACCESS_DENIED_RULE,
                )
            )
            continue
        except OSError as exc:
            findings.append(
                make_skipped(
                    CATEGORY,
                    key_path,
                    f"Winlogon 注册表键无法读取（{exc}）",
                    {"key": key_path, "view": view_name, "error": str(exc)},
                    _WINLOGON_ACCESS_DENIED_RULE,
                )
            )
            continue
        for finding in _analyze_winlogon_collected(collected, key_path):
            evidence = finding.get("evidence") or {}
            dedupe_key = (str(finding.get("rule_id") or ""), str(evidence.get("value_name") or ""))
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            findings.append(finding)
    return findings


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
    """扫描 LSA / AppInit / IFEO / Winlogon，返回 ``list[Finding]``（不抛异常）。"""
    findings: list[dict[str, Any]] = []
    errors: list[str] = []

    # 1) LSA 包
    try:
        auth_packages = _read_multi_sz(winreg.HKEY_LOCAL_MACHINE, _LSA_KEY, "Authentication Packages")
        notification_packages = _read_multi_sz(winreg.HKEY_LOCAL_MACHINE, _LSA_KEY, "Notification Packages")
        security_packages = _read_multi_sz(winreg.HKEY_LOCAL_MACHINE, _LSA_KEY, "Security Packages")
        lsa_findings = _analyze_lsa_packages(
            "Authentication Packages",
            auth_packages,
            f"HKLM\\{_LSA_KEY}\\Authentication Packages",
            _KNOWN_AUTH_PACKAGES,
            "LSA_AUTH_PACKAGE_TAMPER",
        )
        lsa_findings += _analyze_lsa_packages(
            "Security Packages",
            security_packages,
            f"HKLM\\{_LSA_KEY}\\Security Packages",
            _KNOWN_AUTH_PACKAGES,
            "LSA_AUTH_PACKAGE_TAMPER",
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

    # 4) Winlogon（Shell/Userinit/GinaDLL/AppSetup/Taskman/Notify + AutoAdminLogon）
    try:
        findings.extend(_scan_winlogon())
    except Exception as exc:  # noqa: BLE001 - scan() 不能抛异常，任何意外都降级为 SKIPPED
        findings.append(
            make_skipped(
                CATEGORY,
                f"HKLM\\{_WINLOGON_KEY}",
                f"Winlogon 检测异常，已降级：{exc}",
                {"error": f"{type(exc).__name__}: {exc}"},
                _WINLOGON_ACCESS_DENIED_RULE,
            )
        )

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
