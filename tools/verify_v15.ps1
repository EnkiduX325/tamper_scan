#requires -Version 5.1
<#
.SYNOPSIS
    Local CI reproduction for TamperScan V1.5 (compile / pytest / ruff / baseline / correlator / report / license).

.DESCRIPTION
    Run from the repository root (or any directory):

        powershell -ExecutionPolicy Bypass -File tools\verify_v15.ps1

    Exit code 0 means every check passed (mirrors .github/workflows/ci.yml).
    Use -SkipInstall to avoid installing pytest/ruff automatically.
    Use -RunFullScan to additionally run a real scan (informational only).

    V1.5 assertions: version == 1.5.0, modules_total == 20, len(MODULE_REGISTRY) == 20,
    LICENSE is AGPL-3.0 (old non-commercial license removed) with LICENSE-COMMERCIAL.md / CLA.md present,
    README carries the AGPL dual-license + campaign usage, core.baseline reports the
    7 diff statuses (incl. BENIGN_UPDATE / normalize_target), and core.correlator
    turns a fixed attack-chain template into a campaign.

.PARAMETER SkipInstall
    Do not install pytest/ruff even if they are missing.

.PARAMETER RunFullScan
    Also run "python main.py --scan --no-memory --quiet" and print the summary.
    Scan exit codes 0/1/2 are all accepted (2 = HIGH findings exist).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\verify_v15.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipInstall,
    [switch]$RunFullScan
)

$script:Failures = 0

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Label)
    Write-Host ""
    Write-Host "==> $Label" -ForegroundColor Cyan
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [int[]]$AllowedExitCodes = @(0)
    )
    Write-Step $Label
    & $Action
    $code = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
    if ($AllowedExitCodes -contains $code) {
        Write-Host "  [ OK ] $Label" -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] $Label (exit code $code)" -ForegroundColor Red
        $script:Failures++
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not (Test-Path (Join-Path $repoRoot "main.py"))) {
    Write-Host "ERROR: repository root not found (expected main.py in $repoRoot)" -ForegroundColor Red
    exit 1
}
Set-Location $repoRoot
Write-Host "TamperScan V1.5 local CI verification" -ForegroundColor Yellow
Write-Host "Repository: $repoRoot"

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "ERROR: python not found in PATH (Python 3.10+ required)" -ForegroundColor Red
    exit 1
}

Write-Step "Python version"
python --version
if ($LASTEXITCODE -ne 0) { Write-Host "  [FAIL] python --version" -ForegroundColor Red; exit 1 }

if (-not $SkipInstall) {
    $needInstall = $false
    python -c "import pytest" *> $null
    if ($LASTEXITCODE -ne 0) { $needInstall = $true }
    python -m ruff --version *> $null
    if ($LASTEXITCODE -ne 0) { $needInstall = $true }
    if ($needInstall) {
        Invoke-Checked "Install pytest and ruff" { python -m pip install --quiet pytest ruff }
    }
}

$sampleCheck = @'
import json
import pathlib

report = json.loads(pathlib.Path("reports/sample_report.json").read_text(encoding="utf-8"))
assert report["tool"] == "TamperScan", report.get("tool")
assert report["version"] == "1.5.0", report.get("version")
assert report["scan"]["modules_total"] == 20, report["scan"]["modules_total"]
assert report["scan"]["modules_available"] == 20, report["scan"]["modules_available"]
assert len(report["scan"]["modules"]) == 20, len(report["scan"]["modules"])
print("sample report OK:", len(report["findings"]), "findings,", report["scan"]["modules_total"], "modules")
'@

$versionCheck = @'
import sys

sys.path.insert(0, ".")
from core.version import __version__

assert __version__ == "1.5.0", __version__
print("core version OK:", __version__)
'@

$registryCheck = @'
import sys

sys.path.insert(0, ".")
from core.scanner import MODULE_REGISTRY

assert len(MODULE_REGISTRY) == 20, len(MODULE_REGISTRY)
print("module registry OK:", len(MODULE_REGISTRY), "modules")
'@

$licenseCheck = @'
import pathlib

license_text = pathlib.Path("LICENSE").read_text(encoding="utf-8")
assert "GNU AFFERO GENERAL PUBLIC LICENSE" in license_text, "LICENSE missing AGPL title"
assert "Version 3, 19 November 2007" in license_text, "LICENSE missing AGPL version line"
assert ("CC" + " BY-NC") not in license_text, "LICENSE still mentions the old non-commercial license"
commercial = pathlib.Path("LICENSE-COMMERCIAL.md")
assert commercial.is_file(), "LICENSE-COMMERCIAL.md missing"
assert "commercial" in commercial.read_text(encoding="utf-8").lower(), "LICENSE-COMMERCIAL.md content looks wrong"
cla = pathlib.Path("CLA.md")
assert cla.is_file(), "CLA.md missing"
assert "CLA-TEMPLATE" in cla.read_text(encoding="utf-8"), "CLA.md missing CLA-TEMPLATE marker"
print("license OK: AGPL-3.0 + commercial dual-license docs")
'@

$readmeCheck = @'
import pathlib

dual = "\u53cc\u8f68"  # dual-license marker
license_text = pathlib.Path("README.md").read_text(encoding="utf-8")
assert "AGPL-3.0" in license_text, "README missing AGPL-3.0"
assert dual in license_text, "README missing dual-license notice"
assert "img.shields.io/badge/License-AGPL" in license_text, "README missing AGPL badge"
assert "LICENSE-COMMERCIAL.md" in license_text, "README missing LICENSE-COMMERCIAL.md link"
assert "CLA.md" in license_text, "README missing CLA.md link"
assert "1.5.0" in license_text, "README missing version 1.5.0"
assert "--campaign" in license_text, "README missing --campaign usage"
assert "--campaign-shadow" in license_text, "README missing --campaign-shadow usage"
assert "--fail-on-campaign" in license_text, "README missing --fail-on-campaign usage"
assert "--fail-on-skipped" in license_text, "README missing --fail-on-skipped usage"
assert "--treat-version-bump-as-benign" in license_text, "README missing --treat-version-bump-as-benign usage"
assert "--gui" in license_text, "README missing --gui usage"
assert "PyQt6" in license_text, "README missing PyQt6 UI description"
assert "gui_qt.py" in license_text, "README missing gui_qt.py link"
print("README license/version/PyQt6 OK: AGPL-3.0 dual-license, 1.5.0")
'@

$baselineCheck = @'
import sys

sys.path.insert(0, ".")
from core import baseline as b


def finding(severity, target, rule_id, **evidence):
    return {"severity": severity, "target": target, "rule_id": rule_id, "evidence": evidence}


baseline_report = {
    "version": "1.5.0",
    "findings": [
        finding("HIGH", r"C:\u.exe", "SIG_UNSIGNED", actual="v1"),      # actual changed -> MODIFIED
        finding("LOW", r"C:\e.exe", "RUN_REGISTRY"),                    # LOW -> HIGH -> ESCALATED
        finding("HIGH", r"C:\r.exe", "SIG_INVALID"),                    # missing now -> RESOLVED
        finding("MEDIUM", r"C:\d.exe", "RUN_REGISTRY"),                 # MEDIUM -> LOW -> DOWNGRADED
        finding("HIGH", r"C:\s.exe", "SIG_UNSIGNED", actual="same"),    # identical -> UNCHANGED
    ],
}
current_report = {
    "version": "1.5.0",
    "findings": [
        finding("HIGH", r"C:\u.exe", "SIG_UNSIGNED", actual="v2"),
        finding("HIGH", r"C:\e.exe", "RUN_REGISTRY"),
        finding("MEDIUM", r"C:\n.exe", "SIG_UNSIGNED"),
        finding("LOW", r"C:\d.exe", "RUN_REGISTRY"),
        finding("HIGH", r"C:\s.exe", "SIG_UNSIGNED", actual="same"),
    ],
}

diff = b.diff_reports(baseline_report, current_report, baseline_path=r"C:\base.json")
expected = {
    "NEW": 1,
    "MODIFIED": 1,
    "ESCALATED": 1,
    "DOWNGRADED": 1,
    "BENIGN_UPDATE": 0,
    "RESOLVED": 1,
    "UNCHANGED": 1,
}
assert diff.counts == expected, (diff.counts, expected)
assert diff.baseline_meta["path"] == r"C:\base.json", diff.baseline_meta
assert b.has_new_high_medium(diff) is True, "NEW HIGH/MEDIUM should trigger --fail-on-new"
low_only = b.diff_reports(baseline_report, {"findings": [finding("LOW", r"C:\n.exe", "SIG_UNSIGNED")]})
assert b.has_new_high_medium(low_only) is False, "NEW LOW must not trigger --fail-on-new"
assert b.validate_baseline_report({"findings": []})[0] is True
assert b.validate_baseline_report({"no_findings": []})[0] is False
annotated = b.annotate_findings(current_report["findings"], diff)
statuses = [item.get("diff_status") for item in annotated]
for status in ("NEW", "MODIFIED", "ESCALATED", "DOWNGRADED", "RESOLVED", "UNCHANGED"):
    assert status in statuses, (status, statuses)
assert all("normalized_key" in item for item in annotated if item.get("diff_status")), "annotate missing normalized_key"

# V1.4 normalisation self-check (env var / Sysnative / case differences)
assert callable(getattr(b, "normalize_target", None)), "normalize_target missing"
normalized = b.normalize_target(r"%SystemRoot%\Sysnative\CMD.EXE  ")
assert normalized.lower().endswith(r"\system32\cmd.exe"), normalized
assert b.normalize_target(r"C:\Windows\System32\cmd.exe") == b.normalize_target(r"c:\windows\system32\CMD.EXE"), "path normalisation case-insensitive"

# V1.4 benign version-bump self-check
def versioned(version, sha):
    return {
        "severity": "HIGH",
        "target": r"C:\App\app.exe",
        "rule_id": "SIG_UNSIGNED",
        "evidence": {
            "signature": {"status": "valid", "signer": "Contoso Ltd."},
            "pe": {"FileVersion": version},
            "sha256": sha,
        },
    }


vb_base = {"version": "1.5.0", "findings": [versioned("1.0.0.0", "a" * 64)]}
vb_cur = {"version": "1.5.0", "findings": [versioned("2.0.0.0", "b" * 64)]}
vb = b.diff_reports(vb_base, vb_cur)
assert vb.counts.get("MODIFIED") == 1, vb.counts
entry = vb.entries[0]
assert getattr(entry, "version_bump", False) is True, "version_bump should be detected"
assert entry.current_severity == "MEDIUM", entry.current_severity
vb_benign = b.diff_reports(vb_base, vb_cur, treat_version_bump_as_benign=True)
assert vb_benign.counts.get("BENIGN_UPDATE") == 1, vb_benign.counts
assert vb_benign.entries[0].status == "BENIGN_UPDATE", vb_benign.entries[0].status
reversed_vb = b.diff_reports({"findings": [versioned("2.0.0.0", "b" * 64)]}, {"findings": [versioned("1.0.0.0", "a" * 64)]})
assert reversed_vb.entries[0].status == "MODIFIED", reversed_vb.entries[0].status
assert reversed_vb.entries[0].current_severity == "HIGH", reversed_vb.entries[0].current_severity
print("baseline engine OK:", diff.counts, "| normalize/BENIGN_UPDATE OK")
'@

$cliCheck = @'
import sys

sys.path.insert(0, ".")
import main

help_text = main.build_parser().format_help()
options = (
    "--save-baseline",
    "--baseline",
    "--fail-on-new",
    "--hash-targets",
    "--treat-version-bump-as-benign",
    "--fail-on-skipped",
    "--campaign",
    "--campaign-shadow",
    "--fail-on-campaign",
)
for option in options:
    assert option in help_text, "CLI help missing %s" % option
print("CLI options OK:", " ".join(options))
'@

$correlatorCheck = @'
import sys

sys.path.insert(0, ".")
from core import correlator as c

rules = c.load_chain_rules()
templates = rules.get("chain_templates") or []
assert templates, "attack_chain.json has no chain_templates"
assert "anti_patterns" in rules, "attack_chain.json missing anti_patterns"
assert isinstance(rules["anti_patterns"], list), rules["anti_patterns"]
assert "tactic_mapping" in rules, "attack_chain.json missing tactic_mapping"

campaigns = []
for template in templates:
    findings = []
    for step in template.get("steps", []):
        rule_ids = step.get("rule_ids") or []
        assert rule_ids, "template step without rule_ids"
        findings.append(
            {"severity": "HIGH", "rule_id": str(rule_ids[0]), "target": r"C:\Shared\Sample.dll", "evidence": {}}
        )
    result = c.correlate(findings, rules=rules)
    assert isinstance(result, dict), result
    for key in ("campaigns", "suppressed", "stats"):
        assert key in result, (key, result)
    for campaign in result.get("campaigns") or []:
        for key in ("chain_id", "name", "confidence", "steps", "finding_count", "targets"):
            assert key in campaign, (key, campaign)
        assert campaign["confidence"] in ("high", "medium", "low"), campaign["confidence"]
        campaigns.append(campaign)

assert campaigns, "no campaign produced for any fixed template"
empty = c.correlate([], rules=rules)
assert empty["campaigns"] == [], empty["campaigns"]
assert empty["stats"]["campaigns"] == 0, empty["stats"]
print("correlator OK:", len(templates), "templates,", len(campaigns), "campaigns")
'@

$guiCheck = @'
import os
import sys

os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.path.insert(0, ".")
from PyQt6.QtWidgets import QApplication

app = QApplication([])
import gui_qt

window = gui_qt.MainWindow(start_update_check=False)
assert len(window.stat_cards) == 5, "GUI stat cards missing"
assert window.results_list.count() == 0, "GUI result list should start empty"
window.close()
print("PyQt6 GUI smoke OK")
'@

Invoke-Checked "Syntax check (compileall, including tests)" {
    python -m compileall -q core modules main.py gui_qt.py reporter.py tests
}
Invoke-Checked "PyQt6 GUI smoke (offscreen)" { $guiCheck | python - }
Invoke-Checked "Unit tests (pytest)" { python -m pytest -q }
Invoke-Checked "Static analysis (ruff)" { python -m ruff check . }
Invoke-Checked "Version check" { $versionCheck | python - }
Invoke-Checked "Module registry check" { $registryCheck | python - }
Invoke-Checked "License check (AGPL-3.0 + commercial docs, old license removed)" { $licenseCheck | python - }
Invoke-Checked "README license/version/campaign check" { $readmeCheck | python - }
Invoke-Checked "Baseline engine check (7 statuses + normalize + BENIGN_UPDATE)" { $baselineCheck | python - }
Invoke-Checked "CLI options check (baseline + campaign + v15 flags)" { $cliCheck | python - }
Invoke-Checked "Correlator check (fixed template -> campaign)" { $correlatorCheck | python - }
Invoke-Checked "Sample report check" { $sampleCheck | python - }

if ($RunFullScan) {
    Write-Step "Full scan (informational; exit 0/1/2 accepted)"
    python main.py --scan --no-memory --quiet
    $scanCode = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
    if ($scanCode -in @(0, 1, 2)) {
        Write-Host "  [ OK ] full scan finished (exit code $scanCode)" -ForegroundColor Green
    }
    else {
        Write-Host "  [WARN] full scan exited with $scanCode" -ForegroundColor Yellow
    }
}

Write-Host ""
if ($script:Failures -eq 0) {
    Write-Host "ALL CHECKS PASSED" -ForegroundColor Green
    exit 0
}
Write-Host "$($script:Failures) CHECK(S) FAILED" -ForegroundColor Red
exit 1
