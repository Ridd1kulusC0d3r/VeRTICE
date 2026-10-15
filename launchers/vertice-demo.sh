#!/usr/bin/env bash
# VÉRTICE — lançador de dois cliques (Linux/macOS): monta a demo e abre o dossiê.
set -e
cd "$(dirname "$0")/.."
echo "== VÉRTICE :: demonstração offline =="
python3 -m vertice demo demo-vertice
python3 -m vertice report demo-vertice -o demo-vertice/dossie.html
echo "Abrindo o dossiê no navegador..."
if command -v xdg-open >/dev/null; then xdg-open demo-vertice/dossie.html
elif command -v open >/dev/null; then open demo-vertice/dossie.html
else echo "Abra manualmente: demo-vertice/dossie.html"; fi
