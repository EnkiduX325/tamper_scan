# -*- coding: utf-8 -*-
"""BITS 持久化检测（阶段 4）。

带 ``NotifyCmdLine`` 的 BITS 作业会在传输完成/出错时执行命令，是常见持久化手法
→ HIGH ``BITS_PERSIST``。

实现要点（规范未写、按实际权限补齐）：
- 优先用 PowerShell ``Get-BitsTransfer``（``bitsadmin`` 在新系统已弃用）；
- 标准用户执行 ``Get-BitsTransfer -AllUsers`` 会 AccessDenied →
  ``SKIPPED / BITS_ACCESS_DENIED``，并自动降级为只检查**当前用户**的作业；
- 两路都失败 → ``SKIPPED / BITS_SKIPPED``。
"""

from __future__ import annotations

from typing import Any

from core import utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "BITS"


def _collect_jobs(all_users: bool) -> tuple[list[dict[str, Any]] | None, str | None]:
    """采集 BITS 作业；返回 ``(jobs, error)``。"""
    scope = " -AllUsers" if all_users else ""
    script = (
        "$ErrorActionPreference = 'Stop';"
        f"$jobs = Get-BitsTransfer{scope} -ErrorAction Stop;"
        "if ($null -eq $jobs) { Write-Output '[]' } else {"
        " $jobs | Select-Object DisplayName, JobState, OwnerAccount, NotifyCmdLine, NotifyFlags,"
        " TransferType, Description | ConvertTo-Json -Depth 3 }"
    )
    data, error = utils.run_powershell_json(script, timeout=30)
    if error:
        return None, error
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return None, f"JSON 结构异常：{type(data).__name__}"
    return data, None


def _analyze_jobs(jobs: list[dict[str, Any]], all_users: bool) -> list[dict[str, Any]]:
    """BITS 作业判定（纯函数）。"""
    findings: list[dict[str, Any]] = []
    for job in jobs:
        if not isinstance(job, dict):
            continue
        notify_cmdline = str(job.get("NotifyCmdLine") or "").strip()
        if not notify_cmdline:
            continue
        display_name = str(job.get("DisplayName") or "").strip() or "(未命名作业)"
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                f"BITS:{display_name}",
                f"BITS 作业「{display_name}」设置了 NotifyCmdLine：{truncate(notify_cmdline, 220)}",
                {
                    "display_name": display_name,
                    "job_state": job.get("JobState"),
                    "owner_account": job.get("OwnerAccount"),
                    "notify_cmdline": truncate(notify_cmdline, 500),
                    "notify_flags": job.get("NotifyFlags"),
                    "transfer_type": job.get("TransferType"),
                    "all_users": all_users,
                },
                "BITS_PERSIST",
            )
        )
    return findings


def scan() -> list[dict[str, Any]]:
    """检查 BITS 作业，返回 ``list[Finding]``。"""
    findings: list[dict[str, Any]] = []

    jobs, error = _collect_jobs(all_users=True)
    if jobs is None:
        findings.append(
            make_skipped(
                CATEGORY,
                "BITS",
                f"Get-BitsTransfer -AllUsers 失败（权限不足），已降级为仅检查当前用户作业：{truncate(error, 160)}",
                {"error": error},
                "BITS_ACCESS_DENIED",
            )
        )
        jobs, fallback_error = _collect_jobs(all_users=False)
        if jobs is None:
            findings.append(
                make_skipped(
                    CATEGORY,
                    "BITS",
                    f"当前用户 BITS 作业采集也失败：{truncate(fallback_error, 160)}",
                    {"error": fallback_error},
                    "BITS_SKIPPED",
                )
            )
            return utils.apply_whitelist(findings)
        findings.extend(_analyze_jobs(jobs, all_users=False))
    else:
        findings.extend(_analyze_jobs(jobs, all_users=True))

    return utils.apply_whitelist(findings)
