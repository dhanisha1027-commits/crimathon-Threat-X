@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %ERRORLEVEL%==0 (
  set "PY=py -3"
) else (
  set "PY=python"
)
if not exist "data\threatx.sqlite" (
  %PY% seed_demo.py
)
echo.
echo Open http://127.0.0.1:8765 in a browser.
echo Login and token are in .demo-credentials.txt
%PY% app.py
pause
