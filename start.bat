@echo off
rem PcapCheck launcher: reuse or create venv, then start uvicorn.
rem Default port is 8123. Override with PCAPCHECK_PORT if needed.
setlocal
cd /d "%~dp0backend"
if not defined PCAPCHECK_PORT set PCAPCHECK_PORT=8123

if not exist ".venv\Scripts\python.exe" (
  echo [PcapCheck] First run: creating virtual environment and installing dependencies...
  python -m venv .venv
  if errorlevel 1 goto :failed
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  if errorlevel 1 goto :failed
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 goto :failed
)

echo [PcapCheck] Starting backend: http://127.0.0.1:%PCAPCHECK_PORT%/
start "" http://127.0.0.1:%PCAPCHECK_PORT%/
".venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port %PCAPCHECK_PORT%

endlocal
exit /b

:failed
echo [PcapCheck] Dependency setup failed. Check Python and network configuration.
endlocal
exit /b 1
