@echo off
setlocal
REM ============================================================
REM TamperScan build script (Windows + PyInstaller onefile)
REM Produces:
REM   dist\tamper_scan.exe      - CLI (console)
REM   dist\tamper_scan_gui.exe  - GUI  (windowed, no console)
REM Usage: run build.bat in the project root
REM ============================================================

cd /d "%~dp0"

echo [1/4] Clean old build artifacts...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [2/4] Checking PyInstaller...
python -c "import PyInstaller" >nul 2>nul
if errorlevel 1 (
    echo PyInstaller is missing. Run: python -m pip install -r requirements-build.txt
    exit /b 1
)

set "ICON_ARG="
if exist icon.ico set "ICON_ARG=--icon icon.ico"

REM skrapa (memory scan dependency) is optional. PyInstaller fails if a
REM --hidden-import target cannot be resolved, so only add the skrapa hidden
REM imports when the package is actually installed; otherwise drop them from
REM COMMON and warn (the built exe simply loses memory-scan capability).
echo [3/4] Checking optional skrapa dependency...
set "SKRAPA_HIDDEN="
python -m pip show skrapa >nul 2>nul
if errorlevel 1 (
    echo WARNING: skrapa is not installed, removing skrapa hidden imports from COMMON.
    echo          Memory scan will be degraded in the built exes.
    echo          Install it with: python -m pip install skrapa
    set "SKRAPA_HIDDEN="
) else (
    set "SKRAPA_HIDDEN=--hidden-import skrapa.windows --hidden-import skrapa.windows.attributes"
)

REM Common flags shared by CLI and GUI; keep them identical so the GUI exe
REM bundles the same rules/tools/hidden imports as the CLI.
set COMMON=--onefile --noconfirm --clean --distpath dist --workpath build --add-data rules;rules --add-data tools;tools --collect-submodules modules --collect-binaries yara %SKRAPA_HIDDEN% --hidden-import win32com.client --hidden-import pythoncom --hidden-import pywintypes

echo [4/4] Building CLI exe...
python -m PyInstaller %COMMON% %ICON_ARG% --name tamper_scan main.py
if errorlevel 1 (
    echo CLI build failed.
    exit /b 1
)

echo [4/4] Building GUI exe (windowed)...
python -m PyInstaller %COMMON% %ICON_ARG% --windowed --name tamper_scan_gui gui.py
if errorlevel 1 (
    echo GUI build failed.
    exit /b 1
)

echo.
echo Build finished:
echo   dist\tamper_scan.exe      (CLI)
echo   dist\tamper_scan_gui.exe  (GUI, no console)
echo Example:
echo   dist\tamper_scan.exe --scan --format both --output reports\scan
endlocal
