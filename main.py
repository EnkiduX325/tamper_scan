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
import json
import platform
import sys
import unicodedata
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import reporter  # noqa: E402
from core import baseline  # noqa: E402
from core.finding import SEVERITIES, severity_counts  # noqa: E402
from core.scanner import MODULE_REGISTRY, load_scanner, run_scan  # noqa: E402
from core.utils import is_admin, truncate  # noqa: E402
from core.version import __version__  # noqa: E402
from reporter import build_report, write_json, write_report  # noqa: E402

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
                print(f"  [ OK ] {_pad(item['name'], 22)}{_pad(item['label'], 36)}产出 {item['count']} 条")
    problems = [item for item in results if item["status"] != "ok"]
    if not problems:
        return
    if verbose:
        for item in problems:
            if item["status"] == "unimplemented":
                reason = f"尚未实现（计划阶段 {item['stage']}）"
            else:
                reason = str(item.get("error") or "未知错误")
            print(f"  [WARN] {_pad(item['name'], 22)}{_pad(item['label'], 36)}{reason}")
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
    print(f"  {_pad('模块名', 22)}{_pad('说明', 40)}{_pad('计划阶段', 10)}状态")
    for name, label, stage in MODULE_REGISTRY:
        module, error = load_scanner(name)
        if module is not None:
            status = "可用"
        elif error == "unimplemented":
            status = "未实现"
        else:
            status = f"异常（{error}）"
        print(f"  {_pad(name, 22)}{_pad(label, 40)}{_pad('阶段 ' + str(stage), 10)}{status}")
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


def _load_baseline_file(path: str) -> tuple[dict[str, Any] | None, str | None]:
    """安全读取基线 JSON；任何问题只返回 ``(None, 原因)``，绝不抛异常。

    ``--baseline`` 的基线文件属于用户输入（可能被误删/误改）：文件不存在、
    JSON 损坏、根节点不是 dict、缺 findings 列表都只告警并跳过对比，不能影响
    本次正常扫描与退出码。
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return None, f"基线文件不存在：{path}"
    except OSError as exc:
        return None, f"基线文件读取失败：{type(exc).__name__}: {exc}"
    except ValueError as exc:  # JSONDecodeError / UnicodeDecodeError 均继承 ValueError
        return None, f"基线文件不是合法 JSON：{exc}"
    ok, reason = baseline.validate_baseline_report(data)
    if not ok:
        return None, f"基线文件无效：{reason}"
    return (data if isinstance(data, dict) else None), None


def _print_diff_summary(diff: baseline.BaselineDiff) -> None:
    """打印基线对比的多种状态计数（非 quiet 模式）。"""
    counts = baseline.diff_counts(diff)
    print("-" * 78)
    print(f"基线对比：共 {diff.total} 项")
    print("  " + "  ".join(f"{status}: {counts[status]}" for status in baseline.DIFF_STATUSES))
    changed = [
        f"{status} {counts[status]}"
        for status in baseline.DIFF_STATUSES
        if status != baseline.DIFF_UNCHANGED and counts[status]
    ]
    if changed:
        print("  变化：" + "，".join(changed))
    print("-" * 78)


def _load_correlator() -> Any:
    """延迟导入 ``core.correlator``（攻击链关联引擎，V1.4）。

    延迟到运行时导入：V1.4 并行开发期间 correlator 可能尚未落地，保证 CLI
    其它功能仍可导入/测试；同时为测试提供单点注入位置。
    """
    from core import correlator

    return correlator


def _count_skipped(findings: list[dict[str, Any]]) -> int:
    """统计 SKIPPED Finding 数量（排除基线对比追加的 RESOLVED 项）。"""
    count = 0
    for item in findings or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("severity") or "").upper() != "SKIPPED":
            continue
        if str(item.get("diff_status") or "") == baseline.DIFF_RESOLVED:
            continue
        count += 1
    return count


def _has_high_campaign(campaigns: list[dict[str, Any]]) -> bool:
    """是否存在 confidence == "high" 的攻击链。"""
    return any(
        isinstance(item, dict) and str(item.get("confidence") or "").lower() == "high"
        for item in campaigns or []
    )


def _print_campaign_summary(campaigns: list[dict[str, Any]], shadow: bool) -> None:
    """非 quiet 模式下打印攻击链摘要（名称/置信度/步骤数，shadow 标注）。"""
    title = "攻击链（影子模式：仅记录，不告警）" if shadow else "攻击链"
    print("-" * 78)
    print(f"{title}：{len(campaigns)} 条")
    if not campaigns:
        print("  未发现满足固定剧本的攻击链")
    for campaign in campaigns:
        if not isinstance(campaign, dict):
            continue
        name = str(campaign.get("name") or campaign.get("chain_id") or "(未命名)")
        chain_id = str(campaign.get("chain_id") or "")
        confidence = str(campaign.get("confidence") or "low").lower()
        steps = campaign.get("steps") if isinstance(campaign.get("steps"), list) else []
        suffix = "  [影子模式]" if shadow else ""
        print(
            f"  [{confidence}] {name}（{chain_id}） 步骤 {len(steps)}，"
            f"Finding {campaign.get('finding_count')}{suffix}"
        )
    print("-" * 78)


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

    # SKIPPED 统计：--quiet 警告与 --fail-on-skipped 共用（排除基线 RESOLVED 项）
    skipped_count = _count_skipped(report["findings"])
    if args.quiet and skipped_count:
        print(
            f"[WARN] 本次扫描存在 {skipped_count} 个 SKIPPED 项（未检查 ≠ 安全）",
            file=sys.stderr,
        )

    # --hash-targets：在保存/对比之前为 HIGH/MEDIUM 的本地文件 target 计算 SHA256
    hash_targets = bool(getattr(args, "hash_targets", False))
    if hash_targets:
        report["findings"] = baseline.enrich_findings_with_hashes(report["findings"])

    # --save-baseline：保存后直接退出（与 --baseline 由 argparse 互斥保证）
    save_baseline = getattr(args, "save_baseline", None)
    if save_baseline:
        if not hash_targets:
            print(
                "[WARN] 基线将不含文件 SHA256，后续哈希篡改检测可能失效；建议同时使用 --hash-targets",
                file=sys.stderr,
            )
        try:
            saved_path = write_json(report, save_baseline)
        except Exception as exc:  # noqa: BLE001 - 基线写失败不影响扫描退出码语义
            print(f"[WARN] 基线保存失败：{type(exc).__name__}: {exc}", file=sys.stderr)
            return int(report["summary"]["exit_code"])
        print(f"基线已保存：{saved_path}")
        return int(report["summary"]["exit_code"])

    # --baseline：安全加载并对比；任何基线解析问题只告警，跳过对比继续正常输出
    diff = None
    baseline_path = getattr(args, "baseline", None)
    if baseline_path:
        baseline_report, load_error = _load_baseline_file(baseline_path)
        if load_error:
            print(f"[WARN] {load_error}，已跳过基线对比", file=sys.stderr)
        else:
            for warning in baseline.baseline_warnings(baseline_report, report, __version__):
                print(f"[WARN] {warning}", file=sys.stderr)
            diff_kwargs: dict[str, Any] = {}
            if getattr(args, "treat_version_bump_as_benign", False):
                diff_kwargs["treat_version_bump_as_benign"] = True
            diff = baseline.diff_reports(
                baseline_report,
                report,
                baseline_path=baseline_path,
                **diff_kwargs,
            )
            report = reporter.apply_baseline_diff(report, diff, baseline_path=baseline_path)
            if not args.quiet:
                _print_diff_summary(diff)

    # --campaign / --campaign-shadow：攻击链后处理（在写报告之前）
    campaigns: list[dict[str, Any]] = []
    campaign_shadow = bool(getattr(args, "campaign_shadow", False))
    if getattr(args, "campaign", False) or campaign_shadow:
        correlation = _load_correlator().correlate(report["findings"])
        correlation = correlation if isinstance(correlation, dict) else {}
        raw_campaigns = correlation.get("campaigns")
        campaigns = (
            [item for item in raw_campaigns if isinstance(item, dict)]
            if isinstance(raw_campaigns, list)
            else []
        )
        stats = correlation.get("stats")
        report["campaigns"] = campaigns
        report["campaign_stats"] = stats if isinstance(stats, dict) else {}
        if campaign_shadow:
            for campaign in campaigns:
                campaign["shadow"] = True
            report["campaign_shadow"] = True
        if not args.quiet:
            _print_campaign_summary(campaigns, campaign_shadow)

    # 退出码优先级：fail-on-skipped(3) > fail-on-new / fail-on-campaign high / base HIGH(2) > base
    exit_code = int(report["summary"]["exit_code"])
    if diff is not None and getattr(args, "fail_on_new", False) and baseline.has_new_high_medium(diff):
        exit_code = 2
    if getattr(args, "fail_on_campaign", None) == "high" and _has_high_campaign(campaigns):
        exit_code = 2
    if getattr(args, "fail_on_skipped", False) and skipped_count:
        exit_code = 3

    written, report_error = _write_reports(report, args)

    if args.quiet:
        counts = report["summary"]["counts"]
        summary = "  ".join(f"{name}: {counts[name]}" for name in SEVERITIES)
        print(
            f"扫描完成：{report['summary']['total']} 个 Finding，耗时 {result.duration:.2f}s，"
            f"退出码 {exit_code} | {summary}"
        )
    else:
        _print_summary(result.findings, result.duration)

    for report_path in written:
        print(f"报告已写入：{report_path}")
    if report_error:
        print(f"[WARN] {report_error}（扫描结果与退出码不受影响）", file=sys.stderr)
    return exit_code


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tamper_scan",
        description="TamperScan —— 开箱即用的 Windows 防篡改扫描器（基线对比 + 攻击链关联）",
        epilog=(
            "示例：tamper_scan.exe --scan\n"
            "      tamper_scan.exe --scan --format both --output reports/scan1\n"
            "      tamper_scan.exe --scan --save-baseline baseline.json --hash-targets\n"
            "      tamper_scan.exe --scan --baseline baseline.json --fail-on-new\n"
            "      tamper_scan.exe --scan --campaign --fail-on-campaign high\n"
            "      tamper_scan.exe --scan --campaign-shadow --format both --output reports/scan2\n"
            "退出码：3（--fail-on-skipped 命中）> 2（--fail-on-new / --fail-on-campaign high / HIGH）"
            " > 1（仅 MEDIUM）> 0"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--scan", action="store_true", help="执行一次完整扫描")
    parser.add_argument(
        "--gui",
        action="store_true",
        help="启动 PyQt6 图形界面（V1.5 新 GUI 入口；与 --scan 同时传时 GUI 优先）",
    )
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
    baseline_group = parser.add_mutually_exclusive_group()
    baseline_group.add_argument(
        "--save-baseline",
        metavar="PATH",
        help="扫描后把本次报告保存为基线 JSON 并退出（与 --baseline 互斥；建议同时使用 --hash-targets）",
    )
    baseline_group.add_argument(
        "--baseline",
        metavar="PATH",
        help="加载基线 JSON 并在扫描后对比（与 --save-baseline 互斥；基线文件无效时仅告警并跳过对比）",
    )
    parser.add_argument(
        "--fail-on-new",
        action="store_true",
        help="存在 NEW 状态的 HIGH/MEDIUM Finding 时强制退出码 2（需与 --baseline 一起使用）",
    )
    parser.add_argument(
        "--hash-targets",
        action="store_true",
        help="为 HIGH/MEDIUM Finding 的本地文件 target 计算 SHA256（保存基线时写入，便于检测白利用式篡改）",
    )
    parser.add_argument(
        "--fail-on-skipped",
        action="store_true",
        help="存在 SKIPPED 项时退出码强制为 3（优先级最高：高于 --fail-on-new/--fail-on-campaign）",
    )
    parser.add_argument(
        "--treat-version-bump-as-benign",
        action="store_true",
        help="基线对比时把“签名者相同且版本号前进”的哈希变化视为良性自动更新（BENIGN_UPDATE）",
    )
    campaign_group = parser.add_mutually_exclusive_group()
    campaign_group.add_argument(
        "--campaign",
        action="store_true",
        help="扫描后按 rules/attack_chain.json 的固定剧本关联攻击链，写入报告 campaigns",
    )
    campaign_group.add_argument(
        "--campaign-shadow",
        action="store_true",
        help="攻击链影子模式：仍计算并记录 campaigns，但不展示告警样式（与 --campaign 互斥）",
    )
    parser.add_argument(
        "--fail-on-campaign",
        choices=("high",),
        metavar="LEVEL",
        default=None,
        help="存在指定置信度的攻击链时强制退出码 2（目前仅支持 high）",
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
    if args.gui:
        # 延迟导入：CLI 路径（导入/测试/打包）不加载 PyQt6；只有 --gui 才进入 GUI。
        from gui_qt import main as gui_main

        return int(gui_main())
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
