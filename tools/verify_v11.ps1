#requires -Version 5.1
<#
.SYNOPSIS
    Local CI reproduction for TamperScan (compile / pytest / ruff / sample report).

.DESCRIPTION
    Run from the repository root (or any directory):

        powershell -ExecutionPolicy Bypass -File tools\verify_v11.ps1

    Exit code 0 means every check passed (mirrors .github/workflows/ci.yml).
    Use -SkipInstall to avoid installing pytest/ruff automatically.
    Use -RunFullScan to additionally run a real scan (informational only).

.PARAMETER SkipInstall
    Do not install pytest/ruff even if they are missing.

.PARAMETER RunFullScan
    Also run "python main.py --scan --no-memory --quiet" and print the summary.
    Scan exit codes 0/1/2 are all accepted (2 = HIGH findings exist).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\verify_v11.ps1
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
Write-Host "TamperScan local CI verification" -ForegroundColor Yellow
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
assert report["version"] == "1.1.0", report.get("version")
assert report["scan"]["modules_total"] == 19, report["scan"]["modules_total"]
assert len(report["scan"]["modules"]) == 19, len(report["scan"]["modules"])
print("sample report OK:", len(report["findings"]), "findings,", report["scan"]["modules_total"], "modules")
'@

$versionCheck = @'
import sys

sys.path.insert(0, ".")
from core.version import __version__

assert __version__ == "1.1.0", __version__
print("core version OK:", __version__)
'@

$registryCheck = @'
import sys

sys.path.insert(0, ".")
from core.scanner import MODULE_REGISTRY

assert len(MODULE_REGISTRY) == 19, len(MODULE_REGISTRY)
print("module registry OK:", len(MODULE_REGISTRY), "modules")
'@

Invoke-Checked "Syntax check (compileall, including tests)" {
    python -m compileall -q core modules main.py gui.py reporter.py tests
}
Invoke-Checked "Unit tests (pytest)" { python -m pytest -q }
Invoke-Checked "Static analysis (ruff)" { python -m ruff check . }
Invoke-Checked "Version check" { $versionCheck | python - }
Invoke-Checked "Module registry check" { $registryCheck | python - }
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

