# Спавн llama-server (llama.cpp из LM Studio backends) для локального теста моделей.
# Примеры:
#   .\start_llm_server.ps1                      # Qwen3-8B на порту 8001
#   .\start_llm_server.ps1 -Model "..\Qwen_Qwen3-14B-IQ3_XXS.gguf" -Port 8000
param(
    [string]$Model = "",
    [int]$Port = 8001,
    [int]$Context = 16384,
    [int]$NGP = 999
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$server = "$env:USERPROFILE\.lmstudio\extensions\backends\llama.cpp-win-x86_64-vulkan-avx2-2.33.0\llama-server.exe"
if (-not (Test-Path $server)) {
    $server = (Get-Command llama-server.exe -ErrorAction SilentlyContinue).Source
    if (-not $server) { throw "llama-server.exe не найден (LM Studio backend или PATH)" }
}
if (-not $Model) { $Model = Join-Path $root "Qwen3-8B-Q4_K_M.gguf" }
if (-not (Test-Path -LiteralPath $Model)) { throw "Модель не найдена: $Model" }
# Короткий 8.3-путь без пробелов (Start-Process сам не квотит аргументы с пробелами)
$fso = New-Object -ComObject Scripting.FileSystemObject
$Model = $fso.GetFile((Resolve-Path -LiteralPath $Model).Path).ShortPath

$args = @(
    "-m", $Model,
    "--host", "127.0.0.1",
    "--port", $Port,
    "-ngl", $NGP,
    "-c", $Context,
    "--no-webui"
)
$logDir = Join-Path $root "logs"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$stdout = Join-Path $logDir "llama_$Port.out.log"
$stderr = Join-Path $logDir "llama_$Port.err.log"
Remove-Item $stdout, $stderr -ErrorAction SilentlyContinue

$proc = Start-Process -FilePath $server -ArgumentList $args -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
Write-Output "llama-server PID=$($proc.Id) model=$Model port=$Port log=$logDir"

$deadline = (Get-Date).AddSeconds(120)
do {
    Start-Sleep -Seconds 2
    $ok = $false
    try { $null = Invoke-RestMethod "http://127.0.0.1:$Port/props" -TimeoutSec 2; $ok = $true } catch {}
} while (-not $ok -and (Get-Date) -lt $deadline)
if ($ok) { Write-Output "READY on http://127.0.0.1:$Port/v1" } else {
    Write-Output "NOT READY - хвост лога:"
    Get-Content $stderr -Tail 15 -ErrorAction SilentlyContinue
    if ($proc.HasExited) { Write-Output "процесс завершился с кодом $($proc.ExitCode)" }
}