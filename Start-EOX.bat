@echo off
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 goto usepython
py -3 eox.py
goto done
:usepython
python eox.py
:done
pause
