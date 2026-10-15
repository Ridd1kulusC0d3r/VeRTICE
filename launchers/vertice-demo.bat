@echo off
REM VERTICE - lancador de dois cliques (Windows): monta a demo e abre o dossie.
cd /d "%~dp0\.."
echo == VERTICE :: demonstracao offline ==
python -m vertice demo demo-vertice
python -m vertice report demo-vertice -o demo-vertice\dossie.html
echo Abrindo o dossie no navegador...
start "" "demo-vertice\dossie.html"
pause
