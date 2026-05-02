@echo off
REM Same as suci_tool.bat (GUI is the default when no args).
cd /d "%~dp0"
call "%~dp0suci_tool.bat" %*
