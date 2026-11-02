@echo off
chcp 65001 >nul
echo === FSTEC Service (dev) ===
echo.
echo [1/2] Services (gateway :8666 + ingest/llm/security/reporting)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0services\run_local.ps1"
echo.
echo [2/2] Frontend...
start "FSTEC Frontend" /D "%~dp0frontend" cmd /k npm run dev
echo.
echo Gateway: http://127.0.0.1:8666 (docs /api/docs)
echo Frontend: http://localhost:5173
echo.
pause