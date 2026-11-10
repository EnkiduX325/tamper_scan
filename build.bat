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

echo [1/3] Clean old build artifacts...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [2/3] Checking PyInstaller...
python -c "import PyInstaller" >nul 2>nul
if errorlevel 1 (
    echo PyInstaller is missing. Run: python -m pip install -r requirements-build.txt
    exit /b 1
)

set "ICON_ARG="
if exist icon.ico set "ICON_ARG=--icon icon.ico"

REM Common flags shared by CLI and GUI; keep them identical so the GUI exe
REM bundles the same rules/tools/hidden imports as the CLI.
set COMMON=--onefile --noconfirm --clean --distpath dist --workpath build --add-data rules;rules --add-data tools;tools --collect-submodules modules --collect-binaries yara --hidden-import skrapa.windows --hidden-import skrapa.windows.attributes --hidden-import win32com.client --hidden-import pythoncom --hidden-import pywintypes

echo [3/3] Building CLI exe...
python -m PyInstaller %COMMON% %ICON_ARG% --name tamper_scan main.py
if errorlevel 1 (
    echo CLI build failed.
    exit /b 1
)

echo [3/3] Building GUI exe (windowed)...
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
