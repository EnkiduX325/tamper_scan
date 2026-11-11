# -*- coding: utf-8 -*-
"""管理员权限 / 用户可写目录判定（V1.4 从 :mod:`core.utils` 拆出）。

依赖 :mod:`core.paths`，**不依赖** :mod:`core.utils`。``is_user_writable`` 先用路径
粗筛再用 ``CreateFileW(FILE_ADD_FILE)`` 实测 ACL，避免把受保护目录误判为用户可写。
"""

from __future__ import annotations

import ctypes
import os
from typing import Any

from .paths import IS_WINDOWS, _norm_abs, expand_vars, extract_executable, normalize_path, path_under


def is_admin() -> bool:
    """当前进程是否具备管理员权限。"""
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


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


_KERNEL32 = None


_WRITABLE_DIR_CACHE: dict[str, bool] = {}


_FILE_ADD_FILE = 0x0002


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


__all__ = ["is_admin", "is_user_writable", "user_writable_roots"]
