# -*- coding: utf-8 -*-
"""进程行为层 + 内存层（阶段 6）。

1. **进程快照**：psutil ``process_iter`` 一次性取 ``pid/name/exe/cmdline/ppid``，
   父进程单独查询并缓存；进程/父进程随时可能退出，全部捕获
   ``NoSuchProcess/AccessDenied/ZombieProcess`` 后跳过。

2. **行为规则**（``rules/lolbin_rules.json`` + ``core.utils`` 内置命令行表）：
   - ``LOLBIN_CMDLINE``  HIGH 进程命令行命中 LOLBin/下载/编码执行特征
   - ``PARENT_ANOMALY``  HIGH 异常父进程派生：WmiPrvSE.exe → shell/解释器（T1047）；
                             Office → cmd/powershell/mshta/certutil 等（T1204.002）
   - ``PROCESS_LOLBIN_NAME`` 命中工具名特征（凭据窃取/横向移动等）
   - ``PROCESS_MASQUERADE`` HIGH 磁盘文件名与 PE 元数据 OriginalFilename 矛盾
     （空值/大小写/包装器排除，宁窄勿宽）

3. **文件 YARA**：对"高风险进程"的可执行文件做 ``file_*.yar`` 扫描
   （跳过系统/Program Files 受信任位置，避免把正常二进制里的字符串当恶意特征）。

4. **内存扫描**（默认最多 10 个进程）：
   候选进程按可解释评分排序——无签名 +30、用户可写启动 +25、父进程异常 +25、
   命令行含 LOLBin +20；取前 ``MAX_MEMORY_SCAN`` 个。
   - skrapa 缺失 → SKIPPED；
   - **标准用户无法启用 SeDebugPrivilege（实测对任何 PID 都失败）** →
     SKIPPED / ``MEMORY_ACCESS_DENIED``，evidence 记录"候选进程/已扫描/因权限跳过"，
     绝不把"没扫"当成"干净"；
   - 命中 → HIGH ``MEM_YARA_HIT``。
"""

from __future__ import annotations

import os
import re
import time
from typing import Any

import psutil

from core import signature, utils, yara_engine
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "LOLBinProcess"

# 可由 main.py 参数覆盖（阶段 7 的 --max-memory-scan / --no-memory）
MAX_MEMORY_SCAN = 10
ENABLE_MEMORY_SCAN = True
ENABLE_FILE_YARA = True
# 内存扫描总时间预算（秒）。管理员下若单个进程很慢，到预算即停止并记录未扫 PID，
# 避免 skrapa 拖垮整次扫描；<=0 表示不限制。
MEMORY_SCAN_TIME_BUDGET_SECONDS = 60

_WRAPPER_EXCLUSIONS = {
    "t64.exe",
    "t64-arm.exe",
    "python.exe",
    "pythonw.exe",
    "pip.exe",
    "pip3.exe",
    "easy_install.exe",
    "wheel.exe",
    "py.exe",
    "pyw.exe",
}


# ---------------------------------------------------------------------------
# 规则加载
# ---------------------------------------------------------------------------


def _load_rules() -> dict[str, list[dict[str, Any]]]:
    """加载 ``rules/lolbin_rules.json`` 并预编译正则（坏规则跳过）。"""
    data = utils.load_json(utils.RULES_DIR / "lolbin_rules.json", default=None)
    if not isinstance(data, dict):
        data = {}
    compiled: dict[str, list[dict[str, Any]]] = {
        "process_name_patterns": [],
        "cmdline_patterns": [],
        "parent_anomalies": [],
    }
    for key in ("process_name_patterns", "cmdline_patterns"):
        for item in data.get(key) or []:
            if not isinstance(item, dict):
                continue
            try:
                regex = re.compile(str(item.get("regex") or ""))
            except re.error:
                continue
            compiled[key].append({**item, "compiled": regex})
    for item in data.get("parent_anomalies") or []:
        if isinstance(item, dict):
            compiled["parent_anomalies"].append(
                {
                    "id": str(item.get("id") or ""),
                    "parent_names": {str(name).lower() for name in item.get("parent_names") or []},
                    "child_names": {str(name).lower() for name in item.get("child_names") or []},
                    "description": str(item.get("description") or ""),
                    "reference": str(item.get("reference") or ""),
                }
            )
    return compiled


def _basename(value: Any) -> str:
    return os.path.basename(str(value or "").strip()).lower()


# ---------------------------------------------------------------------------
# 进程快照
# ---------------------------------------------------------------------------


def _safe(callable_obj: Any) -> str:
    try:
        return str(callable_obj() or "")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return ""


def _parent_info(ppid: Any) -> dict[str, str]:
    try:
        pid = int(ppid)
    except (TypeError, ValueError):
        return {"name": "", "exe": ""}
    if pid <= 0:
        return {"name": "", "exe": ""}
    try:
        parent = psutil.Process(pid)
        return {"name": _safe(parent.name), "exe": _safe(parent.exe)}
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return {"name": "", "exe": ""}


def _snapshot_processes() -> list[dict[str, Any]]:
    """进程快照（含父进程信息），遍历中退出/无权限的进程直接跳过。"""
    snapshot: list[dict[str, Any]] = []
    parent_cache: dict[Any, dict[str, str]] = {}
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        pid = info.get("pid")
        if pid is None:
            continue
        raw_cmdline = info.get("cmdline") or []
        if isinstance(raw_cmdline, (list, tuple)):
            cmdline = " ".join(str(part) for part in raw_cmdline)
        else:
            cmdline = str(raw_cmdline or "")
        ppid = info.get("ppid")
        if ppid not in parent_cache:
            parent_cache[ppid] = _parent_info(ppid)
        parent = parent_cache[ppid]
        snapshot.append(
            {
                "pid": int(pid),
                "name": str(info.get("name") or ""),
                "exe": str(info.get("exe") or ""),
                "cmdline": cmdline,
                "ppid": ppid,
                "parent_name": parent["name"],
                "parent_exe": parent["exe"],
            }
        )
    return snapshot


# ---------------------------------------------------------------------------
# 单进程判定（纯函数，便于单元测试）
# ---------------------------------------------------------------------------


def _parent_anomaly(item: dict[str, Any], rules: dict[str, list[dict[str, Any]]]) -> dict[str, Any] | None:
    parent = _basename(item.get("parent_name"))
    child = _basename(item.get("name"))
    if not parent or not child:
        return None
    for anomaly in rules.get("parent_anomalies") or []:
        if parent in anomaly["parent_names"] and child in anomaly["child_names"]:
            return anomaly
    return None


def _pe_masquerade(executable: str) -> dict[str, Any] | None:
    """PE 元数据 OriginalFilename 与磁盘文件名矛盾（保守判定）。"""
    if not executable or not utils.is_pe_executable(executable):
        return None
    metadata = signature.pe_metadata(executable)
    if not metadata:
        return None
    original = _basename(metadata.get("OriginalFilename"))
    current = _basename(executable)
    if not original or not current or original == current:
        return None
    if current in _WRAPPER_EXCLUSIONS:
        return None  # 安装器/包装器的文件名差异属设计如此
    if utils.is_trusted_install_location(executable):
        # 系统目录/Program Files 里的微软签名文件常有历史遗留的拼写差异
        # （实测 audiodg.exe 的 OriginalFilename 是 audioadg.exe），不算伪装
        return None
    claims_system = (
        current in utils.SYSTEM_BINARY_NAMES
        or original in utils.SYSTEM_BINARY_NAMES
        or utils.looks_like_system_component_name(current)
        or utils.looks_like_system_component_name(original)
    )
    if not claims_system:
        return None
    return {
        "original_filename": original,
        "current_filename": current,
        "metadata": metadata,
    }


def _cmdline_hit(item: dict[str, Any], rules: dict[str, list[dict[str, Any]]]) -> dict[str, Any] | None:
    """命令行特征：内置表 ∪ lolbin_rules.json。"""
    cmdline = str(item.get("cmdline") or "")
    if not cmdline:
        return None
    hit = utils.match_suspicious_cmdline(cmdline)
    if hit:
        return {"id": hit.get("pattern_id"), "description": hit.get("description"), "source": "core.utils"}
    for pattern in rules.get("cmdline_patterns") or []:
        if pattern["compiled"].search(cmdline):
            return {
                "id": pattern.get("id"),
                "description": pattern.get("description"),
                "source": "lolbin_rules.json",
            }
    return None


def _analyze_process(item: dict[str, Any], rules: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """对单个进程快照做判定。"""
    name = str(item.get("name") or "")
    executable = str(item.get("exe") or "")
    cmdline = str(item.get("cmdline") or "")
    pid = item.get("pid")
    evidence = {
        "pid": pid,
        "name": name,
        "exe": executable,
        "cmdline": truncate(cmdline, 500),
        "ppid": item.get("ppid"),
        "parent_name": item.get("parent_name"),
    }
    target = f"pid:{pid}:{executable or name}"
    findings: list[dict[str, Any]] = []

    # 1) 工具名特征
    for pattern in rules.get("process_name_patterns") or []:
        if name and pattern["compiled"].search(name):
            findings.append(
                make_finding(
                    "HIGH",
                    CATEGORY,
                    target,
                    f"进程名命中工具特征（{pattern.get('description')}）：{name}",
                    {**evidence, "pattern_id": pattern.get("id")},
                    "PROCESS_LOLBIN_NAME",
                )
            )
            break

    # 2) 命令行特征
    hit = _cmdline_hit(item, rules)
    if hit:
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                target,
                f"进程命令行可疑（{hit.get('description')}）：{truncate(cmdline, 200)}",
                {**evidence, "cmdline_hit": hit},
                "LOLBIN_CMDLINE",
            )
        )

    # 3) 异常父进程
    anomaly = _parent_anomaly(item, rules)
    if anomaly:
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                target,
                f"异常父进程派生：{item.get('parent_name')} → {name}（{anomaly['description']}）",
                {**evidence, "anomaly_id": anomaly["id"], "reference": anomaly["reference"]},
                "PARENT_ANOMALY",
            )
        )

    # 4) PE 元数据伪装
    masquerade = _pe_masquerade(executable)
    if masquerade:
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                target,
                f"PE 元数据原始文件名（{masquerade['original_filename']}）与磁盘文件名（{masquerade['current_filename']}）不符",
                {**evidence, "masquerade": masquerade},
                "PROCESS_MASQUERADE",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 内存扫描候选评分（可解释）
# ---------------------------------------------------------------------------


def _process_risk_score(item: dict[str, Any], rules: dict[str, list[dict[str, Any]]]) -> tuple[int, list[str]]:
    """内存扫描候选评分：无签名 +30、用户可写 +25、父进程异常 +25、命令行 LOLBin +20。"""
    score = 0
    reasons: list[str] = []
    executable = str(item.get("exe") or "")
    if executable and utils.is_pe_executable(executable):
        status = signature.verify(executable).get("status")
        if status in ("unsigned", "invalid"):
            score += 30
            reasons.append(f"签名状态 {status}（+30）")
    if executable and utils.is_user_writable(executable):
        score += 25
        reasons.append("用户可写目录启动（+25）")
    if _parent_anomaly(item, rules):
        score += 25
        reasons.append("父进程异常（+25）")
    if _cmdline_hit(item, rules):
        score += 20
        reasons.append("命令行含 LOLBin 特征（+20）")
    return score, reasons


def _build_candidates(
    snapshot: list[dict[str, Any]], rules: dict[str, list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    own_pid = os.getpid()
    candidates: list[dict[str, Any]] = []
    for item in snapshot:
        if item.get("pid") in (0, 4, own_pid):
            continue
        if not item.get("exe"):
            continue
        try:
            score, reasons = _process_risk_score(item, rules)
        except Exception:  # noqa: BLE001 - 单个进程评分失败跳过
            continue
        if score > 0:
            candidates.append({"pid": item["pid"], "score": score, "reasons": reasons, "item": item})
    candidates.sort(key=lambda candidate: candidate["score"], reverse=True)
    return candidates


# ---------------------------------------------------------------------------
# 文件 YARA / 内存扫描
# ---------------------------------------------------------------------------


def _file_yara_findings(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not ENABLE_FILE_YARA:
        return []
    status = yara_engine.engine_status()
    if not status["yara_available"]:
        return [
            make_skipped(
                CATEGORY,
                "YARA",
                "yara-python 未安装，文件 YARA 扫描已跳过",
                {"engine": status},
                "YARA_SKIPPED",
            )
        ]
    engine = yara_engine.get_engine()
    if not engine.file_scan_rules() and not engine.rule_sets:
        return [
            make_skipped(
                CATEGORY,
                "YARA",
                "没有可用的 YARA 规则（或全部编译失败）",
                {"engine": status},
                "YARA_SKIPPED",
            )
        ]
    scanned_paths: set[str] = set()
    for candidate in candidates:
        item = candidate["item"]
        executable = str(item.get("exe") or "")
        if not executable or executable in scanned_paths:
            continue
        if not os.path.isfile(executable) or not utils.is_pe_executable(executable):
            continue
        if utils.is_trusted_install_location(executable):
            continue  # 受信任位置不扫文件 YARA，避免正常系统二进制字符串误报
        scanned_paths.add(executable)
        matches = engine.scan_file(executable)
        if not matches:
            continue
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                f"pid:{candidate['pid']}:{executable}",
                f"进程可执行文件命中 YARA 规则：{', '.join(match['rule'] for match in matches)}",
                {
                    "pid": candidate["pid"],
                    "name": item.get("name"),
                    "exe": executable,
                    "matches": matches,
                    "process_score": candidate["score"],
                    "process_reasons": candidate["reasons"],
                },
                "YARA_FILE_HIT",
            )
        )
    return findings


def _memory_scan_findings(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not ENABLE_MEMORY_SCAN:
        return [
            make_skipped(
                CATEGORY,
                "memory",
                "内存扫描已关闭（--no-memory）",
                {"enabled": False},
                "MEMORY_SKIPPED",
            )
        ]
    status = yara_engine.engine_status()
    if not status["skrapa_available"]:
        return [
            make_skipped(
                CATEGORY,
                "memory",
                "skrapa 未安装，进程内存扫描已跳过",
                {"engine": status},
                "MEMORY_SKIPPED",
            )
        ]
    try:
        limit = max(0, int(MAX_MEMORY_SCAN))
    except (TypeError, ValueError):
        limit = 10
    selected = candidates[:limit]
    candidate_evidence = [
        {"pid": item["pid"], "score": item["score"], "reasons": item["reasons"], "name": item["item"].get("name")}
        for item in selected
    ]
    if not selected:
        return [
            make_skipped(
                CATEGORY,
                "memory",
                "没有评分 >0 的高优先级进程可供内存扫描",
                {"candidates": [], "engine": status},
                "MEMORY_SKIPPED",
            )
        ]

    # skrapa 的 @se_debug 在 open_process 前就要求 SeDebugPrivilege：标准用户必失败，
    # 提前报 SKIPPED，避免"尝试了但没命中"的误导。
    if not utils.is_admin():
        return [
            make_skipped(
                CATEGORY,
                "memory",
                "内存扫描需要管理员权限（skrapa 需启用 SeDebugPrivilege，标准用户对所有进程都会失败）；"
                "已跳过，未扫描不等于无命中",
                {"candidates": candidate_evidence, "engine": status, "reason": "se_debug_privilege_required"},
                "MEMORY_ACCESS_DENIED",
            )
        ]

    findings: list[dict[str, Any]] = []
    scanned: list[int] = []
    denied: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    timed_out: list[int] = []
    started = time.monotonic()
    for index, candidate in enumerate(selected):
        if (
            MEMORY_SCAN_TIME_BUDGET_SECONDS > 0
            and (time.monotonic() - started) > MEMORY_SCAN_TIME_BUDGET_SECONDS
        ):
            timed_out = [item["pid"] for item in selected[index:]]
            break
        result = yara_engine.scan_process_memory(candidate["pid"])
        if result.get("status") == "ok":
            scanned.append(candidate["pid"])
            for hit in result.get("hits", []):
                findings.append(
                    make_finding(
                        "HIGH",
                        CATEGORY,
                        f"pid:{candidate['pid']}:{candidate['item'].get('exe') or candidate['item'].get('name')}",
                        f"进程内存命中 YARA 规则：{hit.get('rule')}",
                        {
                            "pid": candidate["pid"],
                            "name": candidate["item"].get("name"),
                            "exe": candidate["item"].get("exe"),
                            "hit": hit,
                            "process_score": candidate["score"],
                            "process_reasons": candidate["reasons"],
                        },
                        "MEM_YARA_HIT",
                    )
                )
        elif result.get("status") in ("access_denied", "no_privilege"):
            denied.append({"pid": candidate["pid"], "name": candidate["item"].get("name"), "error": result.get("error")})
        elif result.get("status") == "no_rules":
            errors.append({"pid": candidate["pid"], "error": result.get("error")})
            break
        else:
            errors.append({"pid": candidate["pid"], "error": result.get("error")})

    if scanned or denied or errors or timed_out:
        parts = [f"已扫描 {len(scanned)} 个进程"]
        if denied:
            parts.append(f"因权限跳过 {len(denied)} 个")
        if errors:
            parts.append(f"其它错误 {len(errors)} 个")
        if timed_out:
            parts.append(f"超出 {MEMORY_SCAN_TIME_BUDGET_SECONDS}s 时间预算未扫 {len(timed_out)} 个")
        if denied:
            rule_id = "MEMORY_ACCESS_DENIED"
        elif timed_out:
            rule_id = "MEMORY_TIME_BUDGET"
        else:
            rule_id = "MEMORY_SCAN_ERROR"
        findings.append(
            make_skipped(
                CATEGORY,
                "memory",
                "内存扫描部分完成：" + "，".join(parts),
                {
                    "scanned_pids": scanned,
                    "denied": denied,
                    "errors": errors,
                    "timed_out_pids": timed_out,
                    "time_budget_seconds": MEMORY_SCAN_TIME_BUDGET_SECONDS,
                    "candidates": candidate_evidence,
                    "engine": status,
                },
                rule_id,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# 模块入口
# ---------------------------------------------------------------------------


def scan() -> list[dict[str, Any]]:
    """进程行为 + 文件 YARA + 内存扫描，返回 ``list[Finding]``。"""
    rules = _load_rules()
    snapshot = _snapshot_processes()
    findings: list[dict[str, Any]] = []
    for item in snapshot:
        try:
            findings.extend(_analyze_process(item, rules))
        except Exception:  # noqa: BLE001 - 单个进程异常不中断扫描
            continue
    candidates = _build_candidates(snapshot, rules)
    findings.extend(_file_yara_findings(candidates))
    findings.extend(_memory_scan_findings(candidates))
    return utils.apply_whitelist(findings)
