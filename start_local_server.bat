@echo off
cd /d "%~dp0"
echo =======================================================
echo   Starting Windows Control Center Local MCP Server
echo   Endpoint: http://127.0.0.1:8000/mcp (Localhost Only)
echo =======================================================
".venv\Scripts\python.exe" server.py --transport http --host 127.0.0.1 --port 8000
pause
