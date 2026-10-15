#!/usr/bin/env bash
# VÉRTICE — lançador de dois cliques (Linux/macOS): sobe a bancada web local.
set -e
cd "$(dirname "$0")/.."
WS="${1:-demo-vertice}"
if [ ! -d "$WS" ]; then python3 -m vertice demo "$WS"; fi
echo "Bancada em http://127.0.0.1:8713 — Ctrl+C para sair"
python3 -m vertice bench "$WS"
