@echo off
REM Demo instance "Alice" — uses its own keystore so it is a separate user.
cd /d "%~dp0"
".venv\Scripts\python.exe" main.py "keystore_alice"
pause
