@echo off
echo Building QR-AES-256 for Windows...

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Install required packages
echo Installing dependencies...
pip install pyinstaller pycryptodome pywin32 winshell qrcode[pil] Pillow

REM Check if icon file exists
if not exist "..\atom.png" (
    echo Warning: Icon file atom.png not found
)

REM Build the executable
echo Building executable...
pyinstaller build_windows.spec

if errorlevel 0 (
    echo Build completed successfully!
    echo Executable can be found in: dist\QR-AES-256.exe
) else (
    echo Build failed!
)

pause
