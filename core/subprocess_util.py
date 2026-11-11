# -*- coding: utf-8 -*-
"""外部命令封装（V1.4 从 :mod:`core.utils` 拆出）。

统一 timeout、任何异常都降级为结果 dict、不向上抛出；Windows 下端隐藏子进程窗口。
**不依赖** :mod:`core.utils`（仅从 :mod:`core.paths` 取平台常量）。
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

from .paths import IS_WINDOWS


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


__all__ = ["hidden_process_options", "run_cmd", "run_powershell", "run_powershell_json"]
