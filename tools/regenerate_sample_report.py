# -*- coding: utf-8 -*-
"""重新生成并脱敏「脱敏后的管理员演示报告」（reports/sample_report.{json,html}）。

用途
----
1. 在授权的测试机上以管理员身份生成原始报告：
       python main.py --scan --format both --output reports\\sample_report
2. 用本脚本脱敏并归一化（版本号 / 19 个模块状态 / HTML 重渲染）：
       python tools\\regenerate_sample_report.py
3. 本地校验（与 CI 一致）：
       powershell -ExecutionPolicy Bypass -File tools\\verify_v11.ps1

脱敏范围
--------
- 当前用户目录（``%USERPROFILE%``）→ ``C:\\Users\\User``
- 当前主机名（``%COMPUTERNAME%``）→ ``TEST-PC``
- 当前用户名（``%USERNAME%``）/ 域（``%USERDOMAIN%``）→ ``User`` / ``DOMAIN``（按单词边界替换）
- 报告主机信息块固定为脱敏演示值；生成时间使用当前 UTC 时间

安全约定
--------
脚本只读取环境变量做替换，不联网、不上传任何数据；处理完请务必检查
``git diff reports/``，确认没有残留真实主机名/用户名后再提交。
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import reporter  # noqa: E402  必须在 sys.path 之后导入
from core.scanner import MODULE_REGISTRY  # noqa: E402
from core.version import __version__  # noqa: E402

JSON_PATH = ROOT / "reports" / "sample_report.json"
HTML_PATH = ROOT / "reports" / "sample_report.html"


def _env(name: str) -> str:
    return str(os.environ.get(name) or "").strip()


def _scrub_text(text: str, tokens: list[tuple[str, str]]) -> str:
    """按顺序替换敏感字符串；对主机名/用户名/域使用单词边界避免误伤普通单词。"""
    for needle, replacement in tokens:
        if not needle:
            continue
        if needle in {r"C:\Users", "C:\\Users"}:
            continue
        # 路径类字符串直接替换；短标识符用单词边界，避免破坏 unrelated 文本
        if "\\" in needle or "/" in needle or len(needle) > 40:
            text = text.replace(needle, replacement)
        else:
            pattern = rf"(?<![A-Za-z0-9]){re.escape(needle)}(?![A-Za-z0-9])"
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


def _scrub(value, tokens: list[tuple[str, str]]) -> object:
    if isinstance(value, str):
        return _scrub_text(value, tokens)
    if isinstance(value, list):
        return [_scrub(item, tokens) for item in value]
    if isinstance(value, dict):
        return {_scrub_text(str(key), tokens): _scrub(item, tokens) for key, item in value.items()}
    return value


def _normalize_modules(report: dict) -> None:
    """按 core.scanner.MODULE_REGISTRY 归一化模块状态列表（保证 19 个模块与顺序一致）。"""
    old_entries = {str(item.get("name")): item for item in report.get("scan", {}).get("modules", [])}
    modules: list[dict] = []
    for name, label, stage in MODULE_REGISTRY:
        entry = dict(old_entries.get(name) or {"status": "ok", "count": 0, "error": None})
        entry.update({"name": name, "label": label, "stage": stage})
        modules.append(entry)
    report.setdefault("scan", {})["modules"] = modules
    report["scan"]["modules_total"] = len(modules)
    report["scan"]["modules_available"] = sum(1 for item in modules if item.get("status") == "ok")


def main() -> int:
    if not JSON_PATH.exists():
        print(f"ERROR: {JSON_PATH} not found; run a scan first:", file=sys.stderr)
        print(r"  python main.py --scan --format both --output reports\sample_report", file=sys.stderr)
        return 1

    try:
        report = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read {JSON_PATH}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(report, dict):
        print("ERROR: sample report root is not a JSON object", file=sys.stderr)
        return 1

    profile = _env("USERPROFILE")
    host = _env("COMPUTERNAME")
    user = _env("USERNAME")
    domain = _env("USERDOMAIN")
    tokens: list[tuple[str, str]] = [
        (profile, r"C:\Users\User"),
        (profile.replace("\\", "\\\\") if profile else "", r"C:\\Users\\User"),
        (host, "TEST-PC"),
        (user, "User"),
        (domain if domain and domain.lower() not in {user.lower(), host.lower()} else "", "DOMAIN"),
    ]

    report = _scrub(report, tokens)
    report["tool"] = "TamperScan"
    report["version"] = __version__
    report["generated_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    report["host"] = {
        "name": "TEST-PC",
        "os": "Windows-11-10.0.22631-SP0",
        "is_admin": True,
        "user": "User",
    }
    _normalize_modules(report)

    JSON_PATH.write_text(reporter.render_json(report) + "\n", encoding="utf-8")
    HTML_PATH.write_text(reporter.render_html(report), encoding="utf-8")

    print(f"reports/sample_report.json : version={report['version']}, "
          f"findings={len(report.get('findings') or [])}, modules={report['scan']['modules_total']}")
    print(f"reports/sample_report.html : {HTML_PATH.stat().st_size} bytes")

    # 简单残留自检：用户目录/UNC 路径中的主机名残留时提示人工复核。
    # 注意不能对主机名做"裸词"检查：例如主机名是 MSI 时，报告里的厂商名 "Micro-Star/MSI"
    # 会被误报；只检查用户目录与网络路径（\\HOST\... / //host/... / host.domain）上下文。
    raw = JSON_PATH.read_text(encoding="utf-8")
    leftovers: list[str] = []
    if profile and profile.lower() in raw.lower():
        leftovers.append(profile)
    if host:
        host_pattern = rf"(?i)(?:\\\\|//|\.){re.escape(host)}(?:\\|/|\.|$)"
        if re.search(host_pattern, raw):
            leftovers.append(f"{host} (network path context)")
    if leftovers:
        print("WARNING: possible personal data remains, please review before commit:", file=sys.stderr)
        for item in leftovers:
            print(f"  - {item}", file=sys.stderr)
        return 2
    print("sanitization check OK (no host name / user profile remaining)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
