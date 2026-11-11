# -*- coding: utf-8 -*-
"""Startup 启动目录 LNK 检测（阶段 3，第一梯队）。

解析 ``%APPDATA%`` 与 ``%PROGRAMDATA%`` 下
``Microsoft\\Windows\\Start Menu\\Programs\\Startup`` 里的 ``.lnk``：

- 用 ``win32com.client`` 读取 ``TargetPath`` / ``Arguments`` / ``WorkingDirectory``；
- ``LNK_HIJACK`` HIGH：目标在用户可写目录、参数命中 LOLBin/下载/编码执行特征、
  或文件名与目标明显不符（名字自称系统组件却指向非受信任位置）；
- 对 PE 目标调用 ``signature.signature_finding`` 独立验签（SIG_* 规则）。

缺少 pywin32 → SKIPPED；单个 LNK 损坏/无权限 → 跳过该项，不中断。
"""

from __future__ import annotations

import os
import re
from typing import Any

from core import signature, utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "StartupLNK"

_GENERIC_TOKENS = {
    "exe",
    "lnk",
    "app",
    "application",
    "launcher",
    "launch",
    "start",
    "startup",
    "shortcut",
    "the",
    "and",
    "for",
    "run",
}


def _startup_dirs() -> list[str]:
    """返回用户级/机器级 Startup 目录（存在才返回）。"""
    directories: list[str] = []
    for env_name in ("APPDATA", "PROGRAMDATA"):
        base = os.environ.get(env_name)
        if not base:
            continue
        path = os.path.join(base, r"Microsoft\Windows\Start Menu\Programs\Startup")
        if os.path.isdir(path) and path not in directories:
            directories.append(path)
    return directories


_MAX_LNK_CHAIN_DEPTH = 2


def _resolve_shortcut(shell, lnk_path: str, depth: int = 0) -> tuple[str, str, str, list[str]]:
    """解析 LNK；目标若仍是 .lnk 则最多再跟 2 层，返回 ``(target, args, workdir, chain)``。"""
    shortcut = shell.CreateShortcut(lnk_path)
    target = str(getattr(shortcut, "TargetPath", "") or "")
    arguments = str(getattr(shortcut, "Arguments", "") or "")
    working_directory = str(getattr(shortcut, "WorkingDirectory", "") or "")
    chain = [lnk_path]
    while depth < _MAX_LNK_CHAIN_DEPTH and target.lower().endswith(".lnk") and os.path.isfile(target):
        depth += 1
        chain.append(target)
        try:
            nested = shell.CreateShortcut(target)
        except Exception:  # noqa: BLE001 - 链断裂时停止解析
            break
        nested_target = str(getattr(nested, "TargetPath", "") or "")
        nested_args = str(getattr(nested, "Arguments", "") or "").strip()
        nested_dir = str(getattr(nested, "WorkingDirectory", "") or "")
        if nested_args:
            arguments = (arguments + " " + nested_args).strip() if arguments else nested_args
        if nested_dir:
            working_directory = nested_dir
        target = nested_target
    return target, arguments, working_directory, chain

def _tokens(text: str) -> set[str]:
    raw = re.sub(r"[^0-9a-z\u4e00-\u9fff]+", " ", str(text or "").lower())
    return {token for token in raw.split() if token and token not in _GENERIC_TOKENS}


def _name_mismatch(lnk_stem: str, executable: str) -> bool:
    """LNK 文件名与目标文件是否"明显不符"（保守判定，避免误报）。"""
    if not executable:
        return False
    target_stem = os.path.splitext(os.path.basename(executable))[0]
    # 1) 名字自称系统组件，但目标不在受信任位置
    if utils.looks_like_system_component_name(lnk_stem) and not utils.is_trusted_install_location(executable):
        return True
    # 2) 目标在用户可写目录，且文件名与目标文件名完全没有词元交集
    if utils.is_user_writable(executable):
        lnk_tokens = _tokens(lnk_stem)
        target_tokens = _tokens(target_stem)
        if lnk_tokens and target_tokens and not (lnk_tokens & target_tokens):
            return True
    return False


def _analyze(
    lnk_path: str,
    lnk_name: str,
    target: str,
    arguments: str,
    working_directory: str,
    chain: list[str] | None = None,
) -> list[dict[str, Any]]:
    """对单个 LNK 做判定。"""
    lnk_stem = os.path.splitext(lnk_name)[0]
    command = f'"{target}" {arguments}'.strip() if target else str(arguments or "").strip()
    executable = target if target else utils.extract_executable(arguments)
    evidence: dict[str, Any] = {
        "lnk_path": lnk_path,
        "lnk_name": lnk_name,
        "target_path": target,
        "arguments": truncate(arguments, 400),
        "working_directory": working_directory,
        "command": truncate(command, 500),
        "target_path_empty": not bool(target),
        "lnk_chain": list(chain or [lnk_path]),
    }

    findings: list[dict[str, Any]] = []

    # 独立验签（signature_finding 内部只对 PE 目标验签）
    if executable:
        sig_finding = signature.signature_finding(executable, category=CATEGORY)
        if sig_finding:
            sig_finding["evidence"].update({"lnk": evidence})
            findings.append(sig_finding)

    reasons: list[str] = []
    if executable and utils.is_user_writable(executable):
        reasons.append(f"目标位于用户可写目录：{truncate(executable, 200)}")
    hit = utils.match_suspicious_cmdline(command)
    if hit:
        if not target:
            reasons.append(f"TargetPath 为空但 Arguments 可执行命令，且命中可疑特征（{hit['description']}）")
        else:
            reasons.append(f"参数命中可疑命令行（{hit['description']}）")
    if _name_mismatch(lnk_stem, executable):
        reasons.append(
            f"LNK 文件名「{lnk_stem}」与目标「{os.path.basename(executable) or executable}」不符"
        )

    if reasons:
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                lnk_path,
                "；".join(reasons),
                {**evidence, "reasons": reasons},
                "LNK_HIJACK",
            )
        )
    return findings


def scan() -> list[dict[str, Any]]:
    """扫描 Startup 目录内的 LNK，返回 ``list[Finding]``。"""
    directories = _startup_dirs()
    if not directories:
        return [
            make_skipped(
                CATEGORY,
                "Startup",
                "未找到 Startup 启动目录",
                {},
                "LNK_SKIPPED",
            )
        ]

    try:
        import win32com.client  # 延迟导入：缺少 pywin32 时降级
    except ImportError as exc:
        return [
            make_skipped(
                CATEGORY,
                "pywin32",
                f"缺少 pywin32，无法解析 LNK：{exc}",
                {"error": str(exc)},
                "LNK_SKIPPED",
            )
        ]

    try:
        shell = win32com.client.Dispatch("WScript.Shell")
    except Exception as exc:  # noqa: BLE001 - COM 创建失败降级
        return [
            make_skipped(
                CATEGORY,
                "WScript.Shell",
                f"无法创建 WScript.Shell COM 对象：{exc}",
                {"error": str(exc)},
                "LNK_SKIPPED",
            )
        ]

    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for directory in directories:
        try:
            names = os.listdir(directory)
        except OSError as exc:
            errors.append(f"{directory}: {exc}")
            continue
        for name in names:
            if not name.lower().endswith(".lnk"):
                continue
            lnk_path = os.path.join(directory, name)
            try:
                target, arguments, working_directory, chain = _resolve_shortcut(shell, lnk_path)
            except Exception:  # noqa: BLE001 - 单个损坏 LNK 跳过
                continue
            findings.extend(_analyze(lnk_path, name, target, arguments, working_directory, chain))

    if errors:
        findings.append(
            make_skipped(
                CATEGORY,
                "Startup",
                "部分 Startup 目录无法读取：" + "；".join(errors[:5]),
                {"errors": errors},
                "LNK_ACCESS_DENIED",
            )
        )
    return utils.apply_whitelist(findings)
