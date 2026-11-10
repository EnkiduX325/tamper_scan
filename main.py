#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TamperScan —— 开箱即用的 Windows 防篡改扫描器（命令行入口）。

扫描调度（模块顺序、异常降级、白名单、去重排序）已抽到 ``core/scanner.py``，
CLI 与 GUI 共用同一套核心；本文件只负责：参数解析、控制台输出、报告落盘、退出码。

用法::

    python main.py --scan
    python main.py --scan --format both --output reports/scan1
    python main.py --scan --quiet --no-memory
    python main.py --list-modules
"""

from __future__ import annotations

import argparse
import platform
import sys
import unicodedata
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.finding import SEVERITIES, severity_counts  # noqa: E402
from core.scanner import MODULE_REGISTRY, load_scanner, run_scan  # noqa: E402
from core.utils import is_admin, truncate  # noqa: E402
from core.version import __version__  # noqa: E402
from reporter import build_report, write_report  # noqa: E402

BANNER_LINE = "=" * 78


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------


def _display_width(text: str) -> int:
    """终端显示宽度（CJK 全角字符按 2 列计）。"""
    width = 0
    for char in str(text):
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def _pad(text: str, width: int) -> str:
    return str(text) + " " * max(0, width - _display_width(str(text)))


def _os_display() -> str:
    """Windows 11 的 platform.release() 仍然返回 "10"，这里按内部版本号修正显示。"""
    try:
        if platform.system() == "Windows":
            build = int(platform.version().split(".")[2])
            return "Windows 11" if build >= 22000 else "Windows 10"
    except Exception:
        pass
    return f"{platform.system()} {platform.release()}".strip()


def _print_header() -> None:
    print(BANNER_LINE)
    role = "管理员" if is_admin() else "标准用户"
    print(f" TamperScan {__version__}   |   {_os_display()}   |   {role}")
    print(BANNER_LINE)


def _print_module_results(results: list[dict[str, Any]], verbose: bool) -> None:
    total = len(results)
    enabled = sum(1 for item in results if item["status"] == "ok")
    print(f"扫描模块：可用 {enabled}/{total}")
    if verbose:
        for item in results:
            if item["status"] == "ok":
                print(f"  [ OK ] {_pad(item['name'], 20)}{_pad(item['label'], 36)}产出 {item['count']} 条")
    problems = [item for item in results if item["status"] != "ok"]
    if not problems:
        return
    if verbose:
        for item in problems:
            if item["status"] == "unimplemented":
                reason = f"尚未实现（计划阶段 {item['stage']}）"
            else:
                reason = str(item.get("error") or "未知错误")
            print(f"  [WARN] {_pad(item['name'], 20)}{_pad(item['label'], 36)}{reason}")
    else:
        names = ", ".join(item["name"] for item in problems)
        print(f"  [WARN] {len(problems)} 个模块不可用已跳过：{names}（加 --verbose 查看原因）")


def _print_findings(findings: list[dict[str, Any]]) -> None:
    if not findings:
        return
    print("-" * 78)
    rule_width = min(max([len(str(item["rule_id"])) for item in findings] + [16]), 32)
    print(f"发现 {len(findings)} 个可疑项（按严重等级排序）：")
    for finding in findings:
        print(
            f"  [{_pad(finding['severity'], 7)}] "
            f"{_pad(finding['rule_id'], rule_width + 1)}{truncate(finding['target'], 70)}"
        )
        print(f"             {truncate(finding['detail'], 96)}")
    print("-" * 78)


def _print_summary(findings: list[dict[str, Any]], elapsed: float) -> None:
    counts = severity_counts(findings)
    print(f"扫描完成：{len(findings)} 个 Finding，耗时 {elapsed:.2f}s")
    print("  " + "  ".join(f"{name}: {counts[name]}" for name in SEVERITIES))


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------


def cmd_list_modules() -> int:
    print(BANNER_LINE)
    print(f" TamperScan {__version__} 模块清单")
    print(BANNER_LINE)
    print(f"  {_pad('模块名', 20)}{_pad('说明', 40)}{_pad('计划阶段', 10)}状态")
    for name, label, stage in MODULE_REGISTRY:
        module, error = load_scanner(name)
        if module is not None:
            status = "可用"
        elif error == "unimplemented":
            status = "未实现"
        else:
            status = f"异常（{error}）"
        print(f"  {_pad(name, 20)}{_pad(label, 40)}{_pad('阶段 ' + str(stage), 10)}{status}")
    return 0


def _write_reports(report: dict[str, Any], args: argparse.Namespace) -> tuple[list[str], str | None]:
    """按 --output/--format 写报告；未指定时不写文件（仅控制台）。"""
    if not args.output and args.format is None:
        return [], None
    fmt = (args.format or "json").lower()
    base = args.output or "tamper_scan_report"
    try:
        written = write_report(report, base, fmt)
    except Exception as exc:  # noqa: BLE001 - 报告写失败不影响扫描/退出码
        return [], f"报告写入失败：{type(exc).__name__}: {exc}"
    return written, None


def cmd_scan(args: argparse.Namespace) -> int:
    if not args.quiet:
        _print_header()

    max_memory_scan = args.max_memory_scan if args.max_memory_scan is not None else 10
    result = run_scan(
        progress_callback=None,
        memory_scan=not args.no_memory,
        max_memory_scan=max_memory_scan,
        module_filter=args.module,
    )

    if not args.quiet:
        _print_module_results(result.module_status, args.verbose)
        _print_findings(result.findings)

    report = build_report(
        result.findings,
        version=__version__,
        duration_seconds=result.duration,
        modules=result.module_status,
    )
    written, report_error = _write_reports(report, args)

    if args.quiet:
        counts = report["summary"]["counts"]
        summary = "  ".join(f"{name}: {counts[name]}" for name in SEVERITIES)
        print(
            f"扫描完成：{report['summary']['total']} 个 Finding，耗时 {result.duration:.2f}s，"
            f"退出码 {report['summary']['exit_code']} | {summary}"
        )
    else:
        _print_summary(result.findings, result.duration)

    for report_path in written:
        print(f"报告已写入：{report_path}")
    if report_error:
        print(f"[WARN] {report_error}（扫描结果与退出码不受影响）", file=sys.stderr)
    return int(report["summary"]["exit_code"])


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tamper_scan",
        description="TamperScan —— 开箱即用的 Windows 防篡改扫描器（无基线启发式扫描）",
        epilog=(
            "示例：tamper_scan.exe --scan\n"
            "      tamper_scan.exe --scan --format both --output reports/scan1\n"
            "      tamper_scan.exe --scan --quiet --no-memory"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--scan", action="store_true", help="执行一次完整扫描")
    parser.add_argument(
        "--module",
        action="append",
        metavar="NAME",
        help="只运行指定模块（可重复，用于单模块验收/调试）",
    )
    parser.add_argument("--list-modules", action="store_true", help="列出扫描模块及接入状态")
    parser.add_argument("--verbose", "-v", action="store_true", help="输出模块级明细")
    parser.add_argument(
        "--output",
        metavar="PATH",
        help="报告输出路径（基名；已存在目录时写入该目录下的 tamper_scan_report）",
    )
    parser.add_argument(
        "--format",
        choices=("json", "html", "both"),
        metavar="FORMAT",
        help="报告格式 json|html|both（未给 --output 时写到当前目录 tamper_scan_report）",
    )
    parser.add_argument("--no-memory", action="store_true", help="跳过进程内存扫描（skrapa）")
    parser.add_argument(
        "--max-memory-scan",
        type=int,
        metavar="N",
        default=None,
        help="内存扫描最多进程数（默认 10）",
    )
    parser.add_argument("--quiet", action="store_true", help="只输出统计摘要与退出码，不逐条打印 Finding")
    parser.add_argument("--version", action="version", version=f"TamperScan {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    from core.utils import setup_console

    setup_console()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_modules:
        return cmd_list_modules()
    if not args.scan:
        parser.print_help()
        print("\n提示：使用 --scan 执行扫描。")
        return 0
    if args.max_memory_scan is not None and args.max_memory_scan < 0:
        parser.error("--max-memory-scan 必须 >= 0")
    return cmd_scan(args)


if __name__ == "__main__":
    sys.exit(main())
