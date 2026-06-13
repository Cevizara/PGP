@echo off
REM Launch the PGP app with the project virtual environment.
cd /d "%~dp0"
".venv\Scripts\python.exe" main.py
pause
