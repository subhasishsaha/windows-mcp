@echo off
cd /d "%~dp0"
REM In stdio mode, stdout must remain completely clean for JSON-RPC messages.
".venv\Scripts\python.exe" server.py --transport stdio
