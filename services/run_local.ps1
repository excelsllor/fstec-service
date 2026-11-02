# Локальный запуск микросервисов (dev, без Kafka/Redis/Postgres):
# SQLite-шина (FSTEC_EVENT_BUS=sqlite) + SQLite БД + мок CMDB + heuristic LLM.
# Запуск:  .\run_local.ps1   (из services/)
# Останов:  Get-Process python | Where-Object { $_.Path -like "*python*" } — закрыть окна,
#           либо:  taskkill /F /IM python.exe  (закроет ВСЕ python!)
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

# --- окружение dev ---
$env:FSTEC_EVENT_BUS = "sqlite"
$env:FSTEC_BUS_POLL_S = "0.25"
$env:FSTEC_DATA_DIR = Join-Path $Root "data"
$env:DATABASE_URL = "sqlite:///" + (Join-Path $Root "data\fstec_services.db")
$env:FSTEC_OCR_ENABLED = "false"
$env:FSTEC_LLM_PROVIDER = "heuristic"
$env:FSTEC_SECURITY_MODE = "mock"
$env:CMDB_PROVIDER = "mock"
$env:FSTEC_GATEWAY_PORT = "8666"

New-Item -ItemType Directory -Force -Path (Join-Path $Root "data\logs") | Out-Null

$services = @(
    @{ Name = "api-gateway";   Module = "api_gateway.main";   Port = "8666" }
    @{ Name = "ingest";        Module = "ingest_service.worker" }
    @{ Name = "llm";           Module = "llm_service.worker" }
    @{ Name = "security";      Module = "security_service.worker" }
    @{ Name = "reporting";     Module = "reporting_service.worker" }
)

foreach ($svc in $services) {
    $args = @("-m", $svc.Module)
    $out = Join-Path $Root "data\logs\$($svc.Name).log"
    $err = Join-Path $Root "data\logs\$($svc.Name).err.log"
    $p = Start-Process -FilePath "python" -ArgumentList $args -WorkingDirectory $Root `
        -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Minimized -PassThru
    Write-Host ("[{0}] PID {1} -> {2}" -f $svc.Name, $p.Id, $out)
}

Write-Host ""
Write-Host "Gateway: http://127.0.0.1:8666 (docs /api/docs)"
Write-Host "Логи:    services\data\logs\*.log"
Write-Host "Смоук:   python tools\services_smoke.py  (из services/)"