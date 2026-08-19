@echo off
REM Cross-platform Python launcher for AI log hooks (Windows cmd.exe).
REM Tries working interpreters, not just PATH entries. A stale Windows py/python
REM launcher may exist even when its target interpreter has been removed.
REM Exits 0 silently if no Python is found - hooks must never block the AI tool.

REM Prefer a uv-managed interpreter stored in this repository. This keeps hooks
REM independent from Windows Store aliases and per-user Python installations.
for /r "%~dp0..\.uv-python" %%P in (python.exe) do (
  "%%~fP" -c "import sys" >nul 2>nul
  if not errorlevel 1 (
    "%%~fP" %*
    exit /b %ERRORLEVEL%
  )
)

py -3 -c "import sys" >nul 2>nul
if not errorlevel 1 (
  py -3 %*
  exit /b %ERRORLEVEL%
)

python -c "import sys" >nul 2>nul
if not errorlevel 1 (
  python %*
  exit /b %ERRORLEVEL%
)

python3 -c "import sys" >nul 2>nul
if not errorlevel 1 (
  python3 %*
  exit /b %ERRORLEVEL%
)

exit /b 0
