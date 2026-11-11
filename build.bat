@echo off
setlocal
REM ============================================================
REM TamperScan V1.5 build script (Windows + PyInstaller onefile)
REM Produces:
REM   dist\tamper_scan.exe      - CLI (console, independent of PyQt6)
REM   dist\tamper_scan_gui.exe  - PyQt6 GUI (windowed, no console)
REM Usage: run build.bat in the project root
REM ============================================================

cd /d "%~dp0"

echo [1/5] Clean old build artifacts...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [2/5] Checking PyInstaller / PyQt6...
python -c "import PyInstaller" >nul 2>nul
if errorlevel 1 (
    echo PyInstaller is missing. Run: python -m pip install -r requirements-build.txt
    exit /b 1
)
python -c "import PyQt6" >nul 2>nul
if errorlevel 1 (
    echo PyQt6 is missing. Run: python -m pip install -r requirements.txt
    exit /b 1
)

set "ICON_ARG="
if exist icon.ico set "ICON_ARG=--icon icon.ico"

REM skrapa (memory scan dependency) is optional. PyInstaller fails if a
REM --hidden-import target cannot be resolved, so only add the skrapa hidden
REM imports when the package is actually installed; otherwise drop them from
REM COMMON and warn (the built exe simply loses memory-scan capability).
echo [3/5] Checking optional skrapa dependency...
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
set COMMON=--onefile --noconfirm --clean --distpath dist --workpath build --add-data rules;rules --add-data tools;tools --add-data icon.ico;. --collect-submodules modules --collect-binaries yara %SKRAPA_HIDDEN% --hidden-import win32com.client --hidden-import pythoncom --hidden-import pywintypes

REM --- PyQt6 packaging (V1.5) -------------------------------------------
REM CLI build does NOT add QT_COLLECT. Because main.py references gui_qt for
REM --gui, PyInstaller still bundles a minimal PyQt6 runtime in
REM tamper_scan.exe (~40MB), so both --scan and --gui work without system
REM Python. The GUI exe additionally collects the whole PyQt6 package plus
REM Qt6 plugins/platforms/qwindows.dll, styles, imageformats, translations
REM (~90-100MB). PyQt6.Qt6 is a namespace directory in some wheels, so only
REM collect it when importable.
set "QT_COLLECT=--collect-all PyQt6 --collect-submodules PyQt6 --hidden-import PyQt6.QtCore --hidden-import PyQt6.QtGui --hidden-import PyQt6.QtWidgets"
python -c "import PyQt6.Qt6" >nul 2>nul
if not errorlevel 1 set "QT_COLLECT=%QT_COLLECT% --collect-all PyQt6.Qt6"

echo [4/5] Building CLI exe...
python -m PyInstaller %COMMON% %ICON_ARG% --name tamper_scan main.py
if errorlevel 1 (
    echo CLI build failed.
    exit /b 1
)

echo [5/5] Building PyQt6 GUI exe (windowed)...
python -m PyInstaller %COMMON% %QT_COLLECT% %ICON_ARG% --windowed --name tamper_scan_gui gui_qt.py
if errorlevel 1 (
    echo GUI build failed.
    exit /b 1
)

echo.
echo Build finished:
echo   dist\tamper_scan.exe      (CLI, independent of PyQt6)
echo   dist\tamper_scan_gui.exe  (PyQt6 GUI, no console)
echo Example:
echo   dist\tamper_scan.exe --scan --format both --output reports\scan
echo   dist\tamper_scan_gui.exe  (or: dist\tamper_scan.exe --gui)
endlocal
