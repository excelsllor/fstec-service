@echo off
setlocal
set FSTEC_E2E_RUN=9b
set VLLM_BASE_URL=http://127.0.0.1:8001/v1
set VLLM_MODEL=Qwen3.5-9B
set FSTEC_SECURITY_MODE=live
if "%FSTEC_LLM_ENABLE_THINKING%"=="" set FSTEC_LLM_ENABLE_THINKING=0
cd /d "C:\Users\artyom\Desktop\лгту хуйня\fstec-service\services\tools"
python -X utf8 e2e_generation.py %* > "..\..\logs\e2e_9b_run_full.out.log" 2> "..\..\logs\e2e_9b_run_full.err.log"
endlocal