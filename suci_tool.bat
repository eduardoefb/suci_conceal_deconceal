@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "ROOT=%CD%"
set "ENVPY=%ROOT%\env\Scripts\python.exe"

set "NEEDSETUP=0"
if not exist "%ENVPY%" set "NEEDSETUP=1"
if "%NEEDSETUP%"=="0" (
  "%ENVPY%" -c "import customtkinter, pycrate_mobile, CryptoMobile" 2>nul
  if errorlevel 1 set "NEEDSETUP=1"
)

if "%NEEDSETUP%"=="1" (
  where python >nul 2>&1
  if not errorlevel 1 (
    python "%ROOT%\suci_tool.py" --setup-env
    if errorlevel 1 exit /b 1
    goto :run
  )
  where py >nul 2>&1
  if not errorlevel 1 (
    py -3 "%ROOT%\suci_tool.py" --setup-env
    if errorlevel 1 exit /b 1
    goto :run
  )
  echo suci_tool.bat: Python not found on PATH. Install Python 3.10+ or use the py launcher. 1>&2
  exit /b 1
)

:run
if not exist "%ENVPY%" (
  echo suci_tool.bat: Missing "%ENVPY%" after setup. Run: python suci_tool.py --setup-env 1>&2
  exit /b 1
)

"%ENVPY%" "%ROOT%\suci_tool.py" %*
