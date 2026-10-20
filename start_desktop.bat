@echo off
rem Tkinter native desktop GUI launcher for the packet analysis tool.
setlocal
cd /d "%~dp0"
set "PYTHON=%~dp0backend\.venv\Scripts\python.exe"
if not exist "%PYTHON%" (
  echo [PcapCheck] Missing backend\.venv\Scripts\python.exe
  echo [PcapCheck] Run start.bat once to create the backend environment.
  pause
  exit /b 1
)
echo [PcapCheck] Starting Tkinter native desktop GUI...
set "PYTHONPATH=%~dp0desktop_gui;%~dp0backend"
"%PYTHON%" "%~dp0desktop_gui\main.py"
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
  echo.
  echo [PcapCheck] Desktop GUI exited with code %EXIT_CODE%.
  pause
)
endlocal & exit /b %EXIT_CODE%
