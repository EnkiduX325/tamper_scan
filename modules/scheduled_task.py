# -*- coding: utf-8 -*-
"""计划任务持久化检测（阶段 4）。

**禁止使用 ``schtasks /fo CSV``**（输出受系统语言影响）。改用 PowerShell
``Get-ScheduledTask`` 并把 ``Actions``/``Principal`` 显式投影为扁平对象后
``ConvertTo-Json``，避免 CIM 集合直接序列化输出嵌套引用。

规则：
- ``TASK_USERWRITABLE`` HIGH  Execute 位于用户可写目录
- ``TASK_SUSPICIOUS``   HIGH  Arguments 命中 LOLBin/下载/编码执行特征；
                              「脚本解释器」执行也视为可疑（微软自带任务降 LOW）
- ``TASK_MASQUERADE``   HIGH  任务名自称系统组件但 Execute 不在受信任位置
- ``TASK_INTERPRETER``  LOW   微软自带任务使用脚本解释器（需人工复核）
- 另对 PE 目标调用 ``signature.signature_finding``（SIG_*）

采集失败 → SKIPPED，不抛异常。
"""

from __future__ import annotations

import os
from typing import Any

from core import signature, utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "ScheduledTask"

_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
if ($null -eq $tasks) { Write-Output '[]'; exit 0 }
$tasks | ForEach-Object {
    [pscustomobject]@{
        TaskName  = $_.TaskName
        TaskPath  = $_.TaskPath
        UserId    = $_.Principal.UserId
        LogonType = $_.Principal.LogonType
        RunLevel  = $_.Principal.RunLevel
        Execute   = ($_.Actions.Execute -join ';')
        Arguments = ($_.Actions.Arguments -join ';')
        State     = $_.State
    }
} | ConvertTo-Json -Depth 3
"""

_SCRIPT_INTERPRETERS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msbuild.exe",
    "installutil.exe",
}

# 任务名"自称系统组件"的强关键词（比通用列表更严格，避免 update/driver 之类误报）
_SYSTEM_CLAIM_KEYWORDS = ("microsoft", "windows", "defender", "system32", "winlogon", "lsass", "svchost")

_TRUSTED_TASK_PATH_PREFIXES = ("\\microsoft\\windows\\", "\\microsoft\\office\\")


def _claims_system(task_name: str) -> bool:
    text = str(task_name or "").lower()
    return any(keyword in text for keyword in _SYSTEM_CLAIM_KEYWORDS)


def _is_trusted_microsoft_task(task_path: str) -> bool:
    return str(task_path or "").lower().startswith(_TRUSTED_TASK_PATH_PREFIXES)


def _analyze(task: dict[str, Any]) -> list[dict[str, Any]]:
    """对单个计划任务做判定（纯函数，便于单元测试）。"""
    task_name = str(task.get("TaskName") or "").strip()
    task_path = str(task.get("TaskPath") or "").strip() or "\\"
    execute_raw = str(task.get("Execute") or "").strip()
    arguments_raw = str(task.get("Arguments") or "").strip()
    if not execute_raw:
        return []
    if not task_path.endswith("\\"):
        task_path += "\\"
    task_label = f"{task_path}{task_name}"
    executes = [item.strip() for item in execute_raw.split(";") if item.strip()]
    argument_list = [item.strip() for item in arguments_raw.split(";")] if arguments_raw else []

    findings: list[dict[str, Any]] = []
    for index, execute in enumerate(executes):
        if index < len(argument_list):
            arguments = argument_list[index]
        elif len(argument_list) == 1:
            arguments = argument_list[0]
        else:
            arguments = ""
        executable = utils.extract_executable(execute)
        command = f'"{execute}" {arguments}'.strip()
        evidence: dict[str, Any] = {
            "task_name": task_name,
            "task_path": task_path,
            "task_label": task_label,
            "user_id": task.get("UserId"),
            "logon_type": task.get("LogonType"),
            "run_level": task.get("RunLevel"),
            "state": task.get("State"),
            "action_index": index,
            "execute": truncate(execute, 300),
            "arguments": truncate(arguments, 300),
            "executable": executable,
        }

        # 独立验签（PE 目标）
        sig_finding = None
        if executable:
            sig_finding = signature.signature_finding(executable, category=CATEGORY)
            if sig_finding:
                sig_finding["evidence"].update({"task": evidence})
                findings.append(sig_finding)

        if not executable:
            continue

        # 用户可写目录
        if utils.is_user_writable(executable):
            findings.append(
                make_finding(
                    "HIGH",
                    CATEGORY,
                    executable,
                    f"计划任务 {task_label} 的执行文件位于用户可写目录：{truncate(executable, 200)}",
                    dict(evidence),
                    "TASK_USERWRITABLE",
                )
            )

        # 可疑命令行 / 脚本解释器
        hit = utils.match_suspicious_cmdline(command)
        basename = os.path.basename(utils.normalize_path(executable)).lower()
        interpreter = basename in _SCRIPT_INTERPRETERS
        if hit:
            findings.append(
                make_finding(
                    "HIGH",
                    CATEGORY,
                    task_label,
                    f"计划任务 {task_label} 命令行可疑（{hit['description']}）：{truncate(command, 200)}",
                    {**evidence, "cmdline_hit": hit},
                    "TASK_SUSPICIOUS",
                )
            )
        elif interpreter:
            trusted_ms = _is_trusted_microsoft_task(task_path) and utils.is_trusted_install_location(executable)
            findings.append(
                make_finding(
                    "LOW" if trusted_ms else "HIGH",
                    CATEGORY,
                    task_label,
                    (
                        f"计划任务 {task_label} 使用脚本解释器执行：{basename}"
                        + ("（微软自带任务，降为 LOW 供人工复核）" if trusted_ms else "")
                    ),
                    {**evidence, "interpreter": basename},
                    "TASK_INTERPRETER" if trusted_ms else "TASK_SUSPICIOUS",
                )
            )

        # 伪装系统组件（系统二进制名必须出现在受信任位置之外才算伪装，explorer.exe@C:\Windows 属正常）
        if (
            utils.is_system_binary_name(executable)
            and not utils.is_in_system_dir(executable)
            and not utils.is_trusted_install_location(executable)
        ) or (
            _claims_system(task_name)
            and not utils.is_trusted_install_location(executable)
            and sig_finding is not None
        ):
            findings.append(
                make_finding(
                    "HIGH",
                    CATEGORY,
                    task_label,
                    f"计划任务疑似伪装系统组件：{task_label} → {truncate(executable, 200)}",
                    dict(evidence),
                    "TASK_MASQUERADE",
                )
            )

    return findings


def scan() -> list[dict[str, Any]]:
    """采集并检查计划任务，返回 ``list[Finding]``。"""
    data, error = utils.run_powershell_json(_PS_SCRIPT, timeout=60)
    if error:
        return [
            make_skipped(
                CATEGORY,
                "ScheduledTasks",
                f"计划任务采集失败：{error}",
                {"error": error},
                "TASK_SKIPPED",
            )
        ]
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return [
            make_skipped(
                CATEGORY,
                "ScheduledTasks",
                f"计划任务 JSON 结构异常：{type(data).__name__}",
                {"sample": truncate(data, 400)},
                "TASK_PARSE_ERROR",
            )
        ]

    findings: list[dict[str, Any]] = []
    for task in data:
        if not isinstance(task, dict):
            continue
        findings.extend(_analyze(task))
    return utils.apply_whitelist(findings)
