# -*- coding: utf-8 -*-
"""Autoruns 广度兜底（阶段 2）。

调用 Sysinternals ``autorunsc64.exe`` 导出 ASEP（自动启动扩展点）CSV，作为
"四层漏斗"中广度采集的兜底，再对每一行做三重复核：

1. **静态信任**：``core.signature.signature_finding`` 独立验签（WinVerifyTrust 嵌入/目录签名）；
2. **用户可写目录**：``core.utils.is_user_writable``；
3. **命令行特征**：``core.utils.match_suspicious_cmdline``。

命中任一即产出 Finding，``rule_id`` 统一加 ``AUTORUNS_`` 前缀。

与规范命令的差异（均有实测依据，见 README/阶段说明）：
- 省略 ``-h``：哈希列（MD5/SHA-1/SHA-256）不参与任何判定，而 ``-h`` 会把单次采集
  从约 16s 拉长到约 72s（对每个文件算 SHA-256），默认关闭；
- 增加 ``-accepteula``：避免首次运行弹 EULA 对话框导致扫描卡死；
- ``-s`` 保留以拿到辅助用的 ``Signer`` 列；若 60s 超时（慢机器），自动降级为
  不带 ``-s`` 的快速采集（约 2s）。**签名判定始终以独立的 WinVerifyTrust 为准**，
  CSV 的 ``Signer`` 列只记录到 evidence，不参与判定。
- CSV 输出直接捕获（等价于临时 CSV，避免磁盘残留）；UTF-16/UTF-8 自动识别。

``autorunsc64.exe`` 缺失 → SKIPPED；采集/解析失败 → SKIPPED，绝不中断整体扫描。

信任边界（V1.4 起强制，T1553/T1574 防御）：
    ``tools/autorunsc64.exe`` 是外部下载的 Sysinternals 二进制，**不能默认信任**：
    若它被替换或篡改（T1553 破坏信任控制、T1574 劫持执行流），攻击者可以伪造一份
    "干净"的 ASEP 列表，或借由被劫持的进程污染整轮扫描结论。因此定位到二进制后、
    执行前必须先经 :func:`verify_autoruns_binary` 强制校验：

    1. Authenticode 状态必须为 ``valid``（独立 WinVerifyTrust，不采信任何外部元数据）；
    2. 签名者必须为微软（除非 ``rules/autoruns_trust.json`` 显式放宽且同时锁定哈希）；
    3. 若配置了 ``trusted_sha256`` 白名单，实际 SHA256 必须命中（流式计算，失败不抛异常）。

    任一条件不满足即视为不可信：只产出一条 ``AUTORUNS_UNTRUSTED_BINARY`` SKIPPED
    Finding（evidence 记录路径、原因、签名状态/签名者、SHA256 与白名单），
    **绝不调用 subprocess 执行该二进制**，扫描其余模块不受影响。
"""

from __future__ import annotations

import csv
import hashlib
import io
import locale
import os
import re
import subprocess
from typing import Any

from core import signature, utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "Autoruns"
AUTORUNS_EXE_NAME = "autorunsc64.exe"
COLLECT_TIMEOUT = 60  # 外部命令统一超时（代码质量要求）
INCLUDE_HASHES = False  # 打开后会在命令里追加 -h（采集时间约 +55s，默认关闭）

# 信任边界：autorunsc64.exe 执行前的强制校验（详见模块 docstring）
TRUST_CONFIG_PATH = utils.RULES_DIR / "autoruns_trust.json"
TRUST_RULE_ID = "AUTORUNS_UNTRUSTED_BINARY"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA256_CHUNK = 1024 * 1024

# autoruns 14.x 在 -s 模式下会给 Signer/Company 值加 "(Verified) " 前缀；
# 未验证时会出现 "(Not verified) (Not Verified) Igor Pavlov" 这种叠加形式。
_VERIFICATION_MARKERS = ("(not verified)", "(verified)", "not verified", "verified")


def _split_verification(value: str) -> tuple[str, bool]:
    """去掉 autoruns 的验证前缀，返回 ``(干净的值, 是否被标记为已验证)``。"""
    text = str(value or "").strip()
    verified = False
    changed = True
    while changed:
        changed = False
        lowered = text.lower()
        for marker in _VERIFICATION_MARKERS:
            if lowered.startswith(marker):
                if marker in ("(verified)", "verified"):
                    verified = True
                text = text[len(marker) :].strip()
                changed = True
                break
    return text, verified


# ---------------------------------------------------------------------------
# 工具定位 / 采集 / 解析
# ---------------------------------------------------------------------------


def _find_autorunsc() -> str | None:
    """定位 tools/autorunsc64.exe（PyInstaller 打包后同样适用）。"""
    candidate = utils.TOOLS_DIR / AUTORUNS_EXE_NAME
    if candidate.is_file():
        return str(candidate)
    return None


# ---------------------------------------------------------------------------
# 信任边界：执行前强制校验 autorunsc64.exe
# ---------------------------------------------------------------------------


def _sha256_file(path: str) -> str | None:
    """流式计算文件 SHA256（1 MiB 分块）；任何 I/O 失败返回 None，不抛异常。"""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(_SHA256_CHUNK), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, ValueError):
        return None


def _normalize_sha256_values(value: Any) -> list[str]:
    """把字符串/列表归一为小写 64 位十六进制摘要列表（非法项丢弃，不抛异常）。"""
    if value is None:
        return []
    if isinstance(value, str):
        candidates: list[Any] = [value]
    elif isinstance(value, (list, tuple, set, frozenset)):
        candidates = list(value)
    else:
        return []
    normalized: list[str] = []
    for item in candidates:
        text = "".join(str(item or "").split()).lower()
        if _SHA256_RE.match(text) and text not in normalized:
            normalized.append(text)
    return normalized


def load_trust_config() -> dict[str, Any]:
    """读取 ``rules/autoruns_trust.json``（缺失/损坏时安全回退）。

    默认策略（回退值）：``require_microsoft_signer=True`` 且 ``trusted_sha256`` 为空，
    即"只要求 Authenticode 有效 + 微软签名"，不按哈希锁定具体发布版本。
    """
    config: dict[str, Any] = {"trusted_sha256": [], "require_microsoft_signer": True}
    try:
        data = utils.load_json(TRUST_CONFIG_PATH, default=None)
    except Exception:  # noqa: BLE001 - 配置读取失败必须安全回退，不能阻断扫描
        data = None
    if not isinstance(data, dict):
        return config
    config["trusted_sha256"] = _normalize_sha256_values(data.get("trusted_sha256"))
    require_microsoft = data.get("require_microsoft_signer", True)
    config["require_microsoft_signer"] = require_microsoft if isinstance(require_microsoft, bool) else True
    return config


def verify_autoruns_binary(path: Any, *, expected_sha256: Any = None) -> dict[str, Any]:
    """执行前的信任校验（纯函数、不抛异常、可 mock ``signature.verify``）。

    判定规则（全部满足才可信）:

    1. 路径存在且可读；
    2. ``core.signature.verify`` 返回 ``status == "valid"``；
    3. 签名者为微软（``signature.is_microsoft_signer``）；若配置显式关闭该要求，
       则必须有 ``trusted_sha256`` 锁定且命中；
    4. 若配置/入参给出了 SHA256 白名单，实际 SHA256 必须命中。

    Args:
        path: 待校验的二进制路径。
        expected_sha256: 可选的期望 SHA256（字符串或列表）；与配置里的
            ``trusted_sha256`` 合并使用，便于调用方/测试注入。

    Returns:
        ``{"trusted", "reason", "path", "signature", "signer", "sha256",
           "sha256_match", "trusted_sha256", "expected_sha256", "error"}``，
        其中 ``reason`` 取值：``trusted`` / ``empty_path`` / ``missing_file`` /
        ``unsigned`` / ``invalid_signature`` / ``missing_signer`` /
        ``non_microsoft_signer`` / ``sha256_mismatch`` / ``verification_error``。
    """
    text = str(path or "").strip().strip('"').strip("'")
    result: dict[str, Any] = {
        "trusted": False,
        "reason": "empty_path",
        "path": text,
        "signature": {},
        "signer": None,
        "sha256": None,
        "sha256_match": None,
        "trusted_sha256": [],
        "expected_sha256": [],
        "error": None,
    }
    if not text:
        return result
    try:
        if not os.path.isfile(text):
            result["reason"] = "missing_file"
            return result

        config = load_trust_config()
        configured_pins = list(config.get("trusted_sha256") or [])
        pins = list(configured_pins)
        for value in _normalize_sha256_values(expected_sha256):
            if value not in pins:
                pins.append(value)
        result["trusted_sha256"] = configured_pins
        result["expected_sha256"] = pins

        result["sha256"] = _sha256_file(text)
        if pins:
            result["sha256_match"] = bool(result["sha256"]) and result["sha256"] in pins

        try:
            raw_signature = signature.verify(text)
        except Exception as exc:  # noqa: BLE001 - 验签失败一律降级为不可信
            raw_signature = {"status": "invalid", "signer": None, "error": f"{type(exc).__name__}: {exc}"}
        signature_info = dict(raw_signature) if isinstance(raw_signature, dict) else {"status": "missing"}
        status = str(signature_info.get("status") or "missing").strip().lower()
        signature_info["status"] = status
        result["signature"] = signature_info
        signer = str(signature_info.get("signer") or "").strip() or None
        result["signer"] = signer

        if status == "missing":
            result["reason"] = "missing_file"
            return result
        if status == "unsigned":
            result["reason"] = "unsigned"
            return result
        if status != "valid":
            result["reason"] = "invalid_signature"
            return result

        microsoft_signed = signature.is_microsoft_signer(signer)
        require_microsoft = bool(config.get("require_microsoft_signer", True))
        if require_microsoft and not microsoft_signed:
            result["reason"] = "missing_signer" if signer is None else "non_microsoft_signer"
            return result
        # 关闭微软签名要求时，必须同时有哈希锁定，否则仍不接受非微软签名
        if not require_microsoft and not microsoft_signed and not pins:
            result["reason"] = "non_microsoft_signer"
            return result
        if pins and not result["sha256_match"]:
            result["reason"] = "sha256_mismatch"
            return result
    except Exception as exc:  # noqa: BLE001 - 信任校验自身失败也必须安全拒绝执行
        result["trusted"] = False
        result["reason"] = "verification_error"
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    result["trusted"] = True
    result["reason"] = "trusted"
    return result


def _build_trust_evidence(binary_path: str, trust: dict[str, Any]) -> dict[str, Any]:
    """构造 ``AUTORUNS_UNTRUSTED_BINARY`` 的结构化证据（摘要字段可截断展示）。"""
    signature_info = trust.get("signature") or {}
    pins = list(trust.get("trusted_sha256") or [])
    actual = trust.get("sha256")
    evidence: dict[str, Any] = {
        "binary_path": binary_path,
        "reason": trust.get("reason"),
        "signature_status": signature_info.get("status"),
        "signature": dict(signature_info) if isinstance(signature_info, dict) else {},
        "signer": trust.get("signer"),
        "sha256": actual,
        "sha256_match": trust.get("sha256_match"),
        "trusted_sha256": pins,
        "expected_sha256": [truncate(value, 16) for value in pins],
        "actual_sha256": truncate(actual, 16) if actual else None,
    }
    error = signature_info.get("error") if isinstance(signature_info, dict) else None
    if error or trust.get("error"):
        evidence["error"] = error or trust.get("error")
    return evidence


def _build_args(exe_path: str, verify_signatures: bool) -> list[str]:
    args = [exe_path, "-accepteula", "-a", "*", "-c"]
    if INCLUDE_HASHES:
        args.append("-h")
    if verify_signatures:
        args.append("-s")
    args += ["-nobanner", "*"]
    return args


def _run_autorunsc(
    exe_path: str,
    verify_signatures: bool = True,
    timeout: int = COLLECT_TIMEOUT,
) -> tuple[bytes | None, str | None]:
    """执行 autorunsc64，返回 ``(stdout_bytes, error)``；任何失败都降级为 error。"""
    try:
        completed = subprocess.run(
            _build_args(exe_path, verify_signatures),
            timeout=timeout,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            **utils.hidden_process_options(),
        )
    except subprocess.TimeoutExpired:
        return None, f"执行超时（{timeout}s）"
    except FileNotFoundError:
        return None, "autorunsc64.exe 不存在"
    except Exception as exc:  # noqa: BLE001 - 外部工具失败一律降级
        return None, f"{type(exc).__name__}: {exc}"
    if completed.stdout:
        return completed.stdout, None
    stderr = (completed.stderr or b"").decode("utf-8", "ignore").strip()
    return None, stderr or f"退出码 {completed.returncode} 且无输出"


def _decode_csv(data: bytes) -> str:
    """解码 autorunsc CSV：优先识别 BOM（14.x 默认 UTF-16LE），再退回本地编码。"""
    if not data:
        return ""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="ignore")
    for encoding in ("utf-8-sig", locale.getpreferredencoding(False) or "utf-8", "mbcs"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="ignore")


def _parse_rows(data: bytes) -> tuple[list[dict[str, str]] | None, str | None]:
    """按表头名解析 CSV（不依赖列顺序/系统语言），返回 ``(rows, error)``。"""
    text = _decode_csv(data)
    if not text.strip():
        return None, "CSV 输出为空"
    # 无 BOM 但含大量 NUL 时，按 UTF-16LE 再试一次
    if "\x00" in text[:400]:
        text = data.decode("utf-16-le", errors="ignore")
    reader = csv.reader(io.StringIO(text))
    try:
        header = [cell.strip().lstrip("\ufeff") for cell in next(reader)]
    except StopIteration:
        return None, "CSV 缺少表头"
    index = {name: position for position, name in enumerate(header)}
    if "Entry Location" not in index or "Entry" not in index:
        return None, f"CSV 表头不符合 autorunsc 格式：{header}"
    rows: list[dict[str, str]] = []
    for raw in reader:
        if not raw or not any(cell.strip() for cell in raw):
            continue
        rows.append(
            {
                name: (raw[position].strip() if position < len(raw) else "")
                for name, position in index.items()
            }
        )
    return rows, None


# ---------------------------------------------------------------------------
# 单行判定
# ---------------------------------------------------------------------------


def _strip_verification_prefix(value: str) -> str:
    """兼容旧调用：只返回值部分。"""
    return _split_verification(value)[0]


def _analyze_row(row: dict[str, str]) -> list[dict[str, Any]]:
    """对单个 ASEP 行做三重复核，返回 Finding 列表。"""
    location = row.get("Entry Location", "")
    entry = row.get("Entry", "")
    enabled = row.get("Enabled", "")
    autoruns_category = row.get("Category", "")
    description = row.get("Description", "")
    version = row.get("Version", "")
    image_path = _strip_verification_prefix(row.get("Image Path", ""))
    launch = row.get("Launch String", "")
    raw_company = row.get("Company", "")
    raw_signer = row.get("Signer", "")
    company = _strip_verification_prefix(raw_company)
    signer_column, signer_verified_by_autoruns = _split_verification(raw_signer)

    if not (image_path or launch or entry):
        return []

    target = image_path or launch or f"{location}\\{entry}"
    executable = (
        utils.extract_executable(image_path)
        or utils.extract_executable(launch)
        or utils.extract_executable(target)
    )

    evidence: dict[str, Any] = {
        "entry_location": location,
        "entry": entry,
        "autoruns_category": autoruns_category,
        "enabled": enabled or "unknown",
        "description": description,
        "image_path": image_path,
        "launch_string": launch,
        "version": version,
        "company": company,
        "signer_column": signer_column,
        "signer_column_verified": signer_verified_by_autoruns,
        "signer_column_raw": raw_signer,
    }

    findings: list[dict[str, Any]] = []

    # 1) 静态信任：始终独立验签，不采信 CSV 的 Signer 列
    sig_finding = signature.signature_finding(
        executable or target,
        claimed_company=company or None,
        category=CATEGORY,
    )
    if sig_finding:
        sig_finding["rule_id"] = "AUTORUNS_" + str(sig_finding.get("rule_id", ""))
        merged = dict(evidence)
        merged.update(sig_finding.get("evidence") or {})
        # Signer 列只作辅助信号：仅当 autoruns 明确标为"已验证"却与独立校验矛盾时记录
        verified_signature = merged.get("signature") or {}
        if signer_verified_by_autoruns and verified_signature.get("status") in ("unsigned", "invalid"):
            merged["autoruns_signer_conflict"] = raw_signer
            sig_finding["detail"] = (
                f"{sig_finding.get('detail', '')}"
                f"（autorunsc 标记 Signer 已验证为「{signer_column}」，与独立验签结果矛盾，"
                "以 WinVerifyTrust 为准）"
            )
        sig_finding["evidence"] = merged
        findings.append(sig_finding)

    # 2) 用户可写目录
    if executable and utils.is_user_writable(executable):
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                target,
                f"自动启动项指向用户可写目录：{truncate(executable, 200)}",
                dict(evidence),
                "AUTORUNS_USERWRITABLE",
            )
        )

    # 3) 命令行特征（Launch String 优先，其次 Image Path）
    for candidate in (launch, image_path):
        hit = utils.match_suspicious_cmdline(candidate)
        if hit:
            findings.append(
                make_finding(
                    "HIGH",
                    CATEGORY,
                    target,
                    f"自动启动项命令行可疑（{hit['description']}）：{truncate(candidate, 180)}",
                    {**evidence, "cmdline_hit": hit},
                    "AUTORUNS_LOLBIN_CMDLINE",
                )
            )
            break

    return findings


# ---------------------------------------------------------------------------
# 模块入口
# ---------------------------------------------------------------------------


def scan() -> list[dict[str, Any]]:
    """执行 Autoruns 兜底扫描，返回 ``list[Finding]``（缺失/失败时返回 SKIPPED）。"""
    exe_path = _find_autorunsc()
    if exe_path is None:
        return [
            make_skipped(
                CATEGORY,
                f"tools/{AUTORUNS_EXE_NAME}",
                "缺少 Sysinternals autorunsc64.exe，Autoruns 兜底已跳过",
                {"expected_path": str(utils.TOOLS_DIR / AUTORUNS_EXE_NAME)},
                "AUTORUNS_SKIPPED",
            )
        ]

    # 信任边界（T1553/T1574）：执行前强制校验，不可信则绝不调用 subprocess
    trust = verify_autoruns_binary(exe_path)
    if not trust.get("trusted"):
        reason = trust.get("reason") or "unknown"
        return [
            make_skipped(
                CATEGORY,
                AUTORUNS_EXE_NAME,
                f"autorunsc64.exe 未通过信任校验（{reason}），已拒绝执行，"
                "以避免被替换/篡改的外部工具污染扫描结论",
                _build_trust_evidence(exe_path, trust),
                TRUST_RULE_ID,
            )
        ]

    data, error = _run_autorunsc(exe_path, verify_signatures=True)
    degraded = False
    if data is None:
        # 慢机器上带 -s 的采集可能超时：降级为快速采集（签名判定不受影响）
        data, fallback_error = _run_autorunsc(exe_path, verify_signatures=False)
        degraded = True
        if data is None:
            return [
                make_skipped(
                    CATEGORY,
                    exe_path,
                    f"autorunsc64 采集失败：{fallback_error or error}",
                    {"error": fallback_error or error, "args": _build_args(exe_path, True)},
                    "AUTORUNS_FAILED",
                )
            ]

    rows, parse_error = _parse_rows(data)
    if rows is None:
        return [
            make_skipped(
                CATEGORY,
                exe_path,
                f"无法解析 autorunsc64 CSV 输出：{parse_error}",
                {"error": parse_error, "bytes": len(data)},
                "AUTORUNS_PARSE_ERROR",
            )
        ]

    findings: list[dict[str, Any]] = []
    if degraded:
        findings.append(
            make_skipped(
                CATEGORY,
                exe_path,
                "autorunsc64 带签名校验采集超时，已降级为快速采集（Signer 列不可用，独立验签不受影响）",
                {"first_error": error},
                "AUTORUNS_DEGRADED",
            )
        )
    for row in rows:
        findings.extend(_analyze_row(row))

    return utils.apply_whitelist(findings)
