# -*- coding: utf-8 -*-
"""报告生成（阶段 7）：JSON + 自包含 HTML。

关键约束：
- **HTML 必须单文件自包含**：CSS 全部内联在 ``<style>`` 里，不引用任何外部资源
  （无 ``<link>``/``<script src>``/外部字体），离线机器/转发给别人都能正常显示；
- **Jinja2 autoescaping 必须开启**：报告里会出现扩展名称、命令行、文件路径等
  攻击者可控字符串，若关闭自动转义，恶意扩展名里嵌入 ``<script>`` 就能在打开报告
  时执行。这里 ``Environment(autoescape=True)`` 且不提供关闭入口，模板中也不使用
  ``|safe``；
- 去重/排序直接复用 ``core.finding`` 的 ``dedupe_findings(..., merge_rule_base=True)``
  与 ``sort_findings``，不在 reporter 里另写一套逻辑；
- 退出码 = ``core.finding.exit_code_for``（HIGH=2，仅 MEDIUM=1，其余 0），与输出
  格式/quiet 无关。
"""

from __future__ import annotations

import datetime
import getpass
import html as html_module
import json
import os
import platform
import socket
from pathlib import Path
from typing import Any, Iterable

from core import utils
from core.finding import (
    SEVERITIES,
    dedupe_findings,
    exit_code_for,
    rule_basename,
    severity_counts,
    sort_findings,
)

try:  # jinja2 为必装依赖；缺失时退化为内置转义渲染，保证扫描不中断
    from jinja2 import Environment

    JINJA2_AVAILABLE = True
except ImportError:  # pragma: no cover - 环境相关
    Environment = None  # type: ignore
    JINJA2_AVAILABLE = False

SEVERITY_LABELS = {
    "HIGH": "高危",
    "MEDIUM": "中危",
    "LOW": "低危",
    "INFO": "信息",
    "SKIPPED": "跳过",
}

# ---------------------------------------------------------------------------
# 只读修复建议（remediation）
# ---------------------------------------------------------------------------
# 设计约束：``rules/remediation.json`` 里的 ``command`` 只是「给用户手动复制执行」
# 的建议文本，本模块只负责加载/匹配/渲染，**绝不执行任何命令**（无 subprocess /
# os.system / os.popen）。所有 finding 均原样保留，仅追加 ``remediation`` 字段。

REMEDIATION_FIELDS: tuple[str, ...] = (
    "summary",
    "expected",
    "actual",
    "command",
    "risk",
    "requires_admin",
)
REMEDIATION_RISK_LEVELS: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH")

#: 修复建议规则库路径（与 rules/whitelist.json 同目录，兼容 PyInstaller 解包目录）
REMEDIATION_PATH: Path = utils.RULES_DIR / "remediation.json"

# 进程内缓存：{路径字符串: {rule_id: 标准化 remediation dict}}
_REMEDIATION_CACHE: dict[str, dict[str, dict[str, Any]]] = {}

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TamperScan 扫描报告 - {{ report.generated_at }}</title>
<style>
  :root {
    --bg: #f6f7f9; --panel: #ffffff; --text: #1f2328; --muted: #57606a;
    --border: #d0d7de;
    --high: #b42318; --high-bg: #fde8e8;
    --medium: #b54708; --medium-bg: #fdf0e1;
    --low: #8a6d00; --low-bg: #fdf7d8;
    --info: #0b5cad; --info-bg: #e7f0fa;
    --skipped: #57606a; --skipped-bg: #eef0f2;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px; background: var(--bg); color: var(--text);
    font-family: "Segoe UI", "Microsoft YaHei", "PingFang SC", Arial, sans-serif;
    line-height: 1.55;
  }
  .page { max-width: 1100px; margin: 0 auto; }
  .page-header, section {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 18px 22px; margin-bottom: 16px;
  }
  h1 { margin: 0 0 12px; font-size: 22px; }
  h2 { margin: 0 0 12px; font-size: 17px; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 8px 18px; margin: 0; }
  .meta div { margin: 0; }
  .meta dt { color: var(--muted); font-size: 12px; }
  .meta dd { margin: 0; word-break: break-all; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid var(--border); padding: 6px 10px; text-align: left; font-size: 13px; }
  th { background: #f0f3f6; }
  .counts td, .counts th { text-align: center; font-weight: 600; }
  .cell-HIGH { color: var(--high); background: var(--high-bg); }
  .cell-MEDIUM { color: var(--medium); background: var(--medium-bg); }
  .cell-LOW { color: var(--low); background: var(--low-bg); }
  .cell-INFO { color: var(--info); background: var(--info-bg); }
  .cell-SKIPPED { color: var(--skipped); background: var(--skipped-bg); }
  .finding { border: 1px solid var(--border); border-left-width: 5px; border-radius: 8px; margin: 10px 0; background: #fff; }
  .finding summary { cursor: pointer; padding: 10px 12px; display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
  .severity-border-HIGH, .sev-border-HIGH { border-left-color: var(--high); }
  .severity-border-MEDIUM, .sev-border-MEDIUM { border-left-color: var(--medium); }
  .severity-border-LOW, .sev-border-LOW { border-left-color: var(--low); }
  .severity-border-INFO, .sev-border-INFO { border-left-color: var(--info); }
  .severity-border-SKIPPED, .sev-border-SKIPPED { border-left-color: var(--skipped); }
  .badge { display: inline-block; padding: 1px 9px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .badge-HIGH { color: var(--high); background: var(--high-bg); }
  .badge-MEDIUM { color: var(--medium); background: var(--medium-bg); }
  .badge-LOW { color: var(--low); background: var(--low-bg); }
  .badge-INFO { color: var(--info); background: var(--info-bg); }
  .badge-SKIPPED { color: var(--skipped); background: var(--skipped-bg); }
  .rule { font-weight: 600; }
  .target { color: var(--muted); word-break: break-all; }
  .detail { margin: 4px 14px 0; }
  .evidence { margin: 8px 14px 12px; padding: 10px; background: #f6f8fa; border: 1px solid var(--border); border-radius: 6px; }
  pre { white-space: pre-wrap; word-break: break-all; font-size: 12px; margin: 0; }
  .remediation { margin: 0 14px 12px; padding: 10px 12px; background: #f0f7ff; border: 1px solid #b6d4f0; border-left: 4px solid var(--info); border-radius: 6px; }
  .remediation-title { margin: 0 0 6px; font-size: 13px; color: var(--info); }
  .remediation-meta { margin: 0; display: grid; grid-template-columns: max-content 1fr; gap: 3px 12px; font-size: 13px; }
  .remediation-meta div { display: contents; }
  .remediation-meta dt { color: var(--muted); }
  .remediation-meta dd { margin: 0; word-break: break-all; }
  .remediation-risk { font-weight: 600; }
  .remediation-risk.risk-HIGH { color: var(--high); }
  .remediation-risk.risk-MEDIUM { color: var(--medium); }
  .remediation-risk.risk-LOW { color: var(--low); }
  .remediation-hint { color: var(--muted); font-size: 11px; margin: 8px 0 4px; }
  .remediation-command { background: #ffffff; border: 1px solid var(--border); border-radius: 4px; padding: 8px; }
  .empty { color: var(--muted); }
  footer { color: var(--muted); font-size: 12px; text-align: center; padding: 8px 0 24px; }
</style>
</head>
<body>
<div class="page">
  <header class="page-header">
    <h1>TamperScan 扫描报告</h1>
    <dl class="meta">
      <div><dt>生成时间</dt><dd>{{ report.generated_at }}</dd></div>
      <div><dt>主机</dt><dd>{{ report.host.name }}（{{ report.host.os }}，{{ "管理员" if report.host.is_admin else "标准用户" }}）</dd></div>
      <div><dt>工具版本</dt><dd>TamperScan {{ report.version }}</dd></div>
      <div><dt>扫描耗时</dt><dd>{{ "%.2f"|format(report.scan.duration_seconds) }} 秒</dd></div>
      <div><dt>扫描模块</dt><dd>{{ report.scan.modules_available }}/{{ report.scan.modules_total }} 可用</dd></div>
      <div><dt>退出码</dt><dd>{{ report.summary.exit_code }}（HIGH=2，MEDIUM=1，其余 0）</dd></div>
    </dl>
  </header>

  <section class="summary">
    <h2>严重等级统计</h2>
    <table class="counts">
      <thead>
        <tr>
          {% for severity in severity_order %}<th class="cell-{{ severity }}">{{ severity_labels[severity] }}</th>{% endfor %}
          <th>合计</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          {% for severity in severity_order %}<td class="cell-{{ severity }}">{{ counts[severity] }}</td>{% endfor %}
          <td>{{ report.summary.total }}</td>
        </tr>
      </tbody>
    </table>
  </section>

  {% if report.scan.modules %}
  <section class="modules">
    <h2>模块状态</h2>
    <table>
      <thead><tr><th>模块</th><th>说明</th><th>状态</th><th>产出</th><th>错误</th></tr></thead>
      <tbody>
        {% for module in report.scan.modules %}
        <tr>
          <td>{{ module.name }}</td>
          <td>{{ module.label }}</td>
          <td>{{ module.status }}</td>
          <td>{{ module.count }}</td>
          <td>{{ module.error or "" }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </section>
  {% endif %}

  <section class="findings">
    <h2>Finding 明细（{{ report.findings|length }}）</h2>
    {% if not report.findings %}
    <p class="empty">未发现可疑项。</p>
    {% endif %}
    {% for finding in view_findings %}
    <details class="finding sev-border-{{ finding.severity }}"{% if finding.severity == "HIGH" %} open{% endif %}>
      <summary>
        <span class="badge badge-{{ finding.severity }}">{{ finding.severity }}</span>
        <span class="rule">{{ finding.rule_id }}</span>
        <span class="target">{{ finding.target }}</span>
      </summary>
      <p class="detail">{{ finding.detail }}</p>
      <pre class="evidence">{{ finding.evidence_json }}</pre>
      {% if finding.remediation %}
      <section class="remediation">
        <h3 class="remediation-title">建议处理</h3>
        <dl class="remediation-meta">
          {% if finding.remediation.summary %}<div><dt>建议</dt><dd>{{ finding.remediation.summary }}</dd></div>{% endif %}
          {% if finding.remediation.expected %}<div><dt>建议值</dt><dd>{{ finding.remediation.expected }}</dd></div>{% endif %}
          {% if finding.remediation.actual %}<div><dt>当前值</dt><dd>{{ finding.remediation.actual }}</dd></div>{% endif %}
          <div><dt>风险等级</dt><dd class="remediation-risk risk-{{ finding.remediation.risk }}">{{ finding.remediation.risk }}</dd></div>
          <div><dt>需要管理员</dt><dd>{{ "是" if finding.remediation.requires_admin else "否" }}</dd></div>
        </dl>
        {% if finding.remediation.command %}
        <p class="remediation-hint">以下命令仅供手动复制执行，TamperScan 不会自动运行：</p>
        <pre class="remediation-command">{{ finding.remediation.command }}</pre>
        {% endif %}
      </section>
      {% endif %}
    </details>
    {% endfor %}
  </section>

  <footer>
    <p>本报告为单文件自包含 HTML（内联 CSS、无外部资源）。Finding 内容可能包含攻击者可控字符串，已由模板自动做 HTML 转义。</p>
  </footer>
</div>
</body>
</html>
"""


def _host_info() -> dict[str, Any]:
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = "unknown"
    return {
        "name": hostname,
        "os": platform.platform(),
        "is_admin": utils.is_admin(),
        "user": user,
    }


def _normalize_remediation(raw: Any) -> dict[str, Any] | None:
    """把单条 remediation 规范化为固定字段 dict；非 dict 返回 ``None``（丢弃）。"""
    if not isinstance(raw, dict):
        return None
    risk = str(raw.get("risk") or "").strip().upper()
    if risk not in REMEDIATION_RISK_LEVELS:
        risk = "MEDIUM"
    return {
        "summary": str(raw.get("summary") or "").strip(),
        "expected": str(raw.get("expected") or "").strip(),
        "actual": str(raw.get("actual") or "").strip(),
        "command": str(raw.get("command") or "").strip(),
        "risk": risk,
        "requires_admin": bool(raw.get("requires_admin", False)),
    }


def _extract_remediation_rules(data: Any) -> dict[str, dict[str, Any]]:
    """兼容 ``{"rules": {...}}`` 与 ``{rule_id: {...}}`` 两种结构，丢弃非 dict 项。"""
    if not isinstance(data, dict):
        return {}
    wrapped = data.get("rules")
    if isinstance(wrapped, dict):
        source: dict[Any, Any] = wrapped
    else:
        source = {key: value for key, value in data.items() if not str(key).startswith("_")}
    rules: dict[str, dict[str, Any]] = {}
    for rule_id, raw in source.items():
        key = str(rule_id or "").strip()
        item = _normalize_remediation(raw)
        if not key or item is None:
            continue
        rules[key] = item
    return rules


def clear_remediation_cache() -> None:
    """清空 remediation 进程内缓存（测试或热更新 ``rules/remediation.json`` 后使用）。"""
    _REMEDIATION_CACHE.clear()


def load_remediation(path: str | os.PathLike[str] | None = None) -> dict[str, dict[str, Any]]:
    """读取修复建议规则库，返回 ``{rule_id: remediation}``。

    - ``path`` 为 ``None`` 时读取 :data:`REMEDIATION_PATH`；
    - 文件缺失 / JSON 损坏 / 结构非法时返回空 dict，**不抛异常**；
    - 带进程内缓存（按路径区分），:func:`clear_remediation_cache` 可刷新；
    - 返回的是缓存条目的浅拷贝，调用方修改返回值不会污染缓存。
    """
    try:
        target = Path(path) if path is not None else REMEDIATION_PATH
    except (TypeError, ValueError):  # pragma: no cover - 非法 path 类型兜底
        return {}
    cache_key = str(target)
    cached = _REMEDIATION_CACHE.get(cache_key)
    if cached is None:
        cached = _extract_remediation_rules(utils.load_json(target, default=None))
        _REMEDIATION_CACHE[cache_key] = cached
    return {rule_id: dict(item) for rule_id, item in cached.items()}


def _finding_rule_candidates(finding: dict[str, Any]) -> tuple[str, list[str]]:
    """返回 ``(rule_id, merged_rules)``，merged_rules 已转成去空字符串列表。"""
    rule_id = str(finding.get("rule_id") or "").strip()
    evidence = finding.get("evidence")
    merged = evidence.get("merged_rules") if isinstance(evidence, dict) else None
    if isinstance(merged, (list, tuple)):
        merged_rules = [str(item).strip() for item in merged if str(item or "").strip()]
    else:
        merged_rules = []
    return rule_id, merged_rules


def _match_remediation(
    finding: dict[str, Any],
    exact_index: dict[str, dict[str, Any]],
    basename_index: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """按「精确 rule_id > merged_rules 精确 > 规则基名」的优先级匹配 remediation。"""
    rule_id, merged_rules = _finding_rule_candidates(finding)
    if rule_id and rule_id in exact_index:
        return exact_index[rule_id]
    for candidate in merged_rules:
        if candidate in exact_index:
            return exact_index[candidate]
    for candidate in [rule_id, *merged_rules]:
        if not candidate:
            continue
        hit = basename_index.get(rule_basename(candidate))
        if hit is not None:
            return hit
    return None


def apply_remediation(
    findings: Iterable[dict[str, Any]],
    remediations: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """给命中规则的 Finding 追加 ``remediation`` 字段，返回新列表。

    - 匹配顺序：``finding["rule_id"]`` 精确 → ``evidence["merged_rules"]`` 精确 →
      ``core.finding.rule_basename`` 基名兜底（如 ``AUTORUNS_SIG_UNSIGNED`` → ``SIG_UNSIGNED``）；
    - 命中后写入标准化 ``remediation`` dict（summary/expected/actual/command/risk/requires_admin）；
    - **不修改入参**（每条 finding / remediation 都做浅拷贝）；
    - ``remediations=None`` 时自动加载真实 ``rules/remediation.json``；
    - 纯只读：不执行、不写回任何命令。
    """
    if remediations is None:
        remediations = load_remediation()
    exact_index: dict[str, dict[str, Any]] = {}
    for rule_id, raw in (remediations or {}).items():
        key = str(rule_id or "").strip()
        item = _normalize_remediation(raw)
        if not key or item is None:
            continue
        exact_index[key] = item
    # 基名索引：优先使用「本身就是基名」的 key（如 SIG_UNSIGNED 优先于 AUTORUNS_SIG_UNSIGNED）
    basename_index: dict[str, dict[str, Any]] = {}
    for rule_id, item in exact_index.items():
        base = rule_basename(rule_id)
        if not base:
            continue
        if base not in basename_index or rule_id == base:
            basename_index[base] = item

    annotated: list[dict[str, Any]] = []
    for finding in findings or []:
        entry = dict(finding)
        match = _match_remediation(entry, exact_index, basename_index)
        if match is not None:
            entry["remediation"] = dict(match)
        annotated.append(entry)
    return annotated


def build_report(
    findings: Iterable[dict[str, Any]],
    *,
    version: str = "",
    duration_seconds: float = 0.0,
    modules: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """规范化 Findings 并组装报告 dict（去重/排序复用 core.finding）。"""
    normalized = sort_findings(dedupe_findings(findings, merge_rule_base=True))
    # 去重排序后挂载只读修复建议（幂等；纯数据操作，不执行任何命令）
    normalized = apply_remediation(normalized)
    counts = severity_counts(normalized)
    module_list = modules or []
    available = sum(1 for item in module_list if item.get("status") == "ok")
    return {
        "tool": "TamperScan",
        "version": version,
        "generated_at": generated_at
        or datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "host": _host_info(),
        "scan": {
            "duration_seconds": round(float(duration_seconds or 0.0), 2),
            "modules_total": len(module_list),
            "modules_available": available,
            "modules": module_list,
        },
        "summary": {
            "total": len(normalized),
            "counts": counts,
            "exit_code": exit_code_for(normalized),
        },
        "findings": normalized,
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, default=str)


def _view_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    views = []
    for finding in report.get("findings") or []:
        view = dict(finding)
        try:
            view["evidence_json"] = json.dumps(finding.get("evidence") or {}, ensure_ascii=False, indent=2, default=str)
        except (TypeError, ValueError):
            view["evidence_json"] = str(finding.get("evidence") or {})
        views.append(view)
    return views


def render_html(report: dict[str, Any]) -> str:
    """渲染单文件自包含 HTML；Jinja2 autoescape 强制开启，缺失 jinja2 时用转义回退。"""
    context = {
        "report": report,
        "findings": report.get("findings") or [],
        "view_findings": _view_findings(report),
        "counts": report.get("summary", {}).get("counts") or {},
        "severity_order": list(SEVERITIES),
        "severity_labels": SEVERITY_LABELS,
    }
    if JINJA2_AVAILABLE:
        # autoescape=True 是硬约束：不提供关闭开关，模板中也不使用 |safe
        environment = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)
        template = environment.from_string(_HTML_TEMPLATE)
        return template.render(**context)
    return _render_html_fallback(report)


def _fallback_remediation_html(finding: dict[str, Any]) -> str:
    """兜底渲染里的「建议处理」区块；所有动态字段一律 html.escape。"""
    escape = html_module.escape
    remediation = finding.get("remediation")
    if not isinstance(remediation, dict) or not remediation:
        return ""
    rows: list[str] = []
    for label, key in (("建议", "summary"), ("建议值", "expected"), ("当前值", "actual")):
        value = remediation.get(key)
        if value:
            rows.append(f"<div><dt>{escape(label)}</dt><dd>{escape(str(value))}</dd></div>")
    risk = str(remediation.get("risk") or "")
    rows.append(
        f"<div><dt>风险等级</dt><dd class=\"remediation-risk risk-{escape(risk)}\">{escape(risk)}</dd></div>"
    )
    rows.append(
        f"<div><dt>需要管理员</dt><dd>{'是' if remediation.get('requires_admin') else '否'}</dd></div>"
    )
    command = remediation.get("command")
    command_html = ""
    if command:
        command_html = (
            '<p class="remediation-hint">以下命令仅供手动复制执行，TamperScan 不会自动运行：</p>'
            f'<pre class="remediation-command">{escape(str(command))}</pre>'
        )
    return (
        '<section class="remediation"><h3 class="remediation-title">建议处理</h3>'
        f"<dl class=\"remediation-meta\">{''.join(rows)}</dl>{command_html}</section>"
    )


def _render_html_fallback(report: dict[str, Any]) -> str:
    """jinja2 缺失时的最小兜底渲染：所有动态内容一律 html.escape。"""
    escape = html_module.escape
    counts = report.get("summary", {}).get("counts") or {}
    rows = []
    for finding in report.get("findings") or []:
        evidence = json.dumps(finding.get("evidence") or {}, ensure_ascii=False, indent=2, default=str)
        rows.append(
            "<details class=\"finding\">"
            f"<summary><b>{escape(str(finding.get('severity')))}</b> "
            f"{escape(str(finding.get('rule_id')))} — {escape(str(finding.get('target')))}</summary>"
            f"<p>{escape(str(finding.get('detail')))}</p>"
            f"<pre>{escape(evidence)}</pre>{_fallback_remediation_html(finding)}</details>"
        )
    counts_html = " ".join(f"<b>{escape(name)}</b>: {counts.get(name, 0)}" for name in SEVERITIES)
    return (
        "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        f"<title>TamperScan {escape(str(report.get('generated_at')))}</title>"
        "<style>body{font-family:'Segoe UI','Microsoft YaHei',Arial,sans-serif;padding:20px;}"
        "pre{white-space:pre-wrap;font-size:12px;background:#f6f8fa;padding:8px;}"
        "details{margin:8px 0;border:1px solid #d0d7de;border-radius:6px;padding:6px;}"
        ".remediation{margin:8px 0;padding:8px;background:#f0f7ff;border:1px solid #b6d4f0;border-radius:6px;}"
        ".remediation-meta{display:grid;grid-template-columns:max-content 1fr;gap:2px 10px;margin:0;}"
        ".remediation-meta div{display:contents;}"
        ".remediation-command{background:#fff;border:1px solid #d0d7de;}"
        ".remediation-hint{color:#57606a;font-size:11px;margin:6px 0 4px;}</style>"
        "</head><body><h1>TamperScan 扫描报告</h1>"
        f"<p>生成时间：{escape(str(report.get('generated_at')))}｜主机：{escape(str(report.get('host', {}).get('name')))}｜版本：{escape(str(report.get('version')))}</p>"
        f"<p>统计：{counts_html}｜合计：{counts and report.get('summary', {}).get('total')}｜退出码：{report.get('summary', {}).get('exit_code')}</p>"
        f"<h2>Finding 明细（{len(report.get('findings') or [])}）</h2>{''.join(rows)}"
        "</body></html>"
    )


def _prepare_path(path: str | os.PathLike[str]) -> Path:
    target = Path(path)
    if target.is_dir() or str(path).endswith(("/", "\\")):
        target = target / "tamper_scan_report"
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    return target


def write_json(report: dict[str, Any], path: str | os.PathLike[str]) -> str:
    target = _prepare_path(path)
    text = str(target)
    if not text.lower().endswith(".json"):
        target = Path(text + ".json")
    target.write_text(render_json(report), encoding="utf-8")
    return str(target)


def write_html(report: dict[str, Any], path: str | os.PathLike[str]) -> str:
    target = _prepare_path(path)
    text = str(target)
    if not text.lower().endswith(".html"):
        target = Path(text + ".html")
    target.write_text(render_html(report), encoding="utf-8")
    return str(target)


def write_report(report: dict[str, Any], base_path: str | os.PathLike[str], fmt: str = "json") -> list[str]:
    """按格式写报告，返回实际写入的文件路径列表；``fmt`` 支持 json/html/both。"""
    fmt = str(fmt or "json").lower()
    written: list[str] = []
    if fmt in ("json", "both"):
        written.append(write_json(report, base_path))
    if fmt in ("html", "both"):
        written.append(write_html(report, base_path))
    return written
