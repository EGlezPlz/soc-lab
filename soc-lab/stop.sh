#!/bin/bash
# stop.sh — Para todo el stack de SOC Lab

echo "⏹ Parando SOC Lab..."
cd ~/soc-lab && docker compose down

echo "⏹ Parando Suricata..."
cd ~/suricata-lab && docker compose down

echo "⏹ Parando Wazuh..."
cd ~/wazuh-lab && docker compose down

echo "⏹ Parando MISP..."
cd ~/misp-lab/misp-docker && docker compose down

echo "✅ Todo parado."
