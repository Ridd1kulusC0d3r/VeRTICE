#!/usr/bin/env bash
# VÉRTICE — duplo-clique no macOS (Finder). Monta a demo e abre o dossiê.
cd "$(dirname "$0")/.."
python3 -m vertice demo demo-vertice
python3 -m vertice report demo-vertice -o demo-vertice/dossie.html
open demo-vertice/dossie.html
