#requires -Version 5.1
<#
.SYNOPSIS
    Local CI reproduction for TamperScan V1.3 (compile / pytest / ruff / baseline / report / license).

.DESCRIPTION
    Run from the repository root (or any directory):

        powershell -ExecutionPolicy Bypass -File tools\verify_v13.ps1

    Exit code 0 means every check passed (mirrors .github/workflows/ci.yml).
    Use -SkipInstall to avoid installing pytest/ruff automatically.
    Use -RunFullScan to additionally run a real scan (informational only).

    V1.3 assertions: version == 1.3.0, modules_total == 20, len(MODULE_REGISTRY) == 20,
    LICENSE uses CC BY-NC 4.0 (not MIT), README carries the non-commercial notice,
    core.baseline diff engine reports the 6 diff statuses, CLI exposes the 4 baseline flags.

.PARAMETER SkipInstall
    Do not install pytest/ruff even if they are missing.

.PARAMETER RunFullScan
    Also run "python main.py --scan --no-memory --quiet" and print the summary.
    Scan exit codes 0/1/2 are all accepted (2 = HIGH findings exist).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\verify_v13.ps1
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
Write-Host "TamperScan V1.3 local CI verification" -ForegroundColor Yellow
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
assert report["version"] == "1.3.0", report.get("version")
assert report["scan"]["modules_total"] == 20, report["scan"]["modules_total"]
assert report["scan"]["modules_available"] == 20, report["scan"]["modules_available"]
assert len(report["scan"]["modules"]) == 20, len(report["scan"]["modules"])
print("sample report OK:", len(report["findings"]), "findings,", report["scan"]["modules_total"], "modules")
'@

$versionCheck = @'
import sys

sys.path.insert(0, ".")
from core.version import __version__

assert __version__ == "1.3.0", __version__
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
assert ("CC BY-NC 4.0" in license_text) or ("Attribution-NonCommercial" in license_text), (
    "LICENSE missing CC BY-NC 4.0 / Attribution-NonCommercial"
)
assert "MIT License" not in license_text, "LICENSE still contains MIT License"
print("license OK: CC BY-NC 4.0 (non-commercial)")
'@

$readmeCheck = @'
import pathlib

notice = "\u672c\u4f5c\u54c1\u91c7\u7528 CC BY-NC 4.0 \u534f\u8bae\uff0c\u4e25\u7981\u5546\u7528"
readme_text = pathlib.Path("README.md").read_text(encoding="utf-8")
assert notice in readme_text, "README missing CC BY-NC 4.0 non-commercial notice"
assert "img.shields.io/badge/License-MIT" not in readme_text, "README still has the MIT badge"
assert "1.3.0" in readme_text, "README missing version 1.3.0"
assert "--save-baseline" in readme_text, "README missing --save-baseline usage"
assert "--baseline" in readme_text, "README missing --baseline usage"
print("README license/version/baseline OK: CC BY-NC 4.0, 1.3.0")
'@

$baselineCheck = @'
import sys

sys.path.insert(0, ".")
from core import baseline as b


def finding(severity, target, rule_id, **evidence):
    return {"severity": severity, "target": target, "rule_id": rule_id, "evidence": evidence}


baseline_report = {
    "version": "1.3.0",
    "findings": [
        finding("HIGH", r"C:\u.exe", "SIG_UNSIGNED", actual="v1"),      # actual changed -> MODIFIED
        finding("LOW", r"C:\e.exe", "RUN_REGISTRY"),                    # LOW -> HIGH -> ESCALATED
        finding("HIGH", r"C:\r.exe", "SIG_INVALID"),                    # missing now -> RESOLVED
        finding("MEDIUM", r"C:\d.exe", "RUN_REGISTRY"),                 # MEDIUM -> LOW -> DOWNGRADED
        finding("HIGH", r"C:\s.exe", "SIG_UNSIGNED", actual="same"),    # identical -> UNCHANGED
    ],
}
current_report = {
    "version": "1.3.0",
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
    "RESOLVED": 1,
    "UNCHANGED": 1,
}
assert diff.counts == expected, diff.counts
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
print("baseline engine OK:", diff.counts)
'@

$cliCheck = @'
import sys

sys.path.insert(0, ".")
import main

help_text = main.build_parser().format_help()
for option in ("--save-baseline", "--baseline", "--fail-on-new", "--hash-targets"):
    assert option in help_text, "CLI help missing %s" % option
print("CLI baseline options OK: --save-baseline / --baseline / --fail-on-new / --hash-targets")
'@

Invoke-Checked "Syntax check (compileall, including tests)" {
    python -m compileall -q core modules main.py gui.py reporter.py tests
}
Invoke-Checked "Unit tests (pytest)" { python -m pytest -q }
Invoke-Checked "Static analysis (ruff)" { python -m ruff check . }
Invoke-Checked "Version check" { $versionCheck | python - }
Invoke-Checked "Module registry check" { $registryCheck | python - }
Invoke-Checked "License check (CC BY-NC 4.0, no MIT)" { $licenseCheck | python - }
Invoke-Checked "README protocol/baseline check" { $readmeCheck | python - }
Invoke-Checked "Baseline engine check (6 diff statuses)" { $baselineCheck | python - }
Invoke-Checked "CLI baseline options check" { $cliCheck | python - }
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
