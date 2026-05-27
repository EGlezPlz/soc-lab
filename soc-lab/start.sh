#!/bin/bash
# start.sh — Levanta todo el stack de SOC Lab en el orden correcto
# Uso: ./start.sh [--build]

set -e

BUILD_FLAG=""
if [[ "$1" == "--build" ]]; then
  BUILD_FLAG="--build"
  echo "🔨 Modo build activado — se reconstruirán las imágenes"
fi

echo ""
echo "╔══════════════════════════════════════╗"
echo "║          SOC Lab — Arranque          ║"
echo "╚══════════════════════════════════════╝"
echo ""

# 1. MISP
echo "▶ [1/3] Levantando MISP..."
cd ~/misp-lab/misp-docker
docker compose up -d
echo "   ✓ MISP iniciado (puede tardar 2-3 min en estar healthy)"

# 2. Wazuh + agente
echo ""
echo "▶ [2/3] Levantando Wazuh..."
cd ~/wazuh-lab
docker compose up -d
echo "   ✓ Wazuh iniciado"

# 3. Suricata
echo ""
echo "▶ [3/3] Levantando Suricata..."
cd ~/suricata-lab
docker compose up -d
echo "   ✓ Suricata iniciado"

# 4. SOC Lab (backend + frontend)
echo ""
echo "▶ Levantando SOC Lab (backend + frontend)..."
cd ~/soc-lab
docker compose up -d $BUILD_FLAG
echo "   ✓ SOC Lab iniciado"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Todo levantado. Esperando que los servicios estén   ║"
echo "║  listos (puede tardar hasta 3 min por MISP)...       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  SOC Lab:   http://localhost:8080"
echo "  MISP:      https://localhost"
echo "  Wazuh:     https://localhost:8443"
echo "  API docs:  http://localhost:8000/docs  (modo dev)"
echo ""

# Esperar a que el backend esté healthy
echo "⏳ Esperando al backend..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:8000/api/health > /dev/null 2>&1; then
    echo "   ✓ Backend listo"
    break
  fi
  sleep 5
  echo "   ... intento $i/30"
done

echo ""
echo "✅ SOC Lab disponible en http://localhost:8080"
