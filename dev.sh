#!/bin/bash
echo "=== Запуск ФСТЭК Сервис (dev режим) ==="

DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[1/2] Запуск микросервисов (gateway :8666 + workers)..."
bash "$DIR/services/run_local.sh" &

echo "[2/2] Запуск frontend (Vite)..."
gnome-terminal -- bash -c "cd '$DIR/frontend' && npm run dev; read" &

echo ""
echo "Gateway: http://127.0.0.1:8666"
echo "Frontend: http://localhost:5173"
echo ""