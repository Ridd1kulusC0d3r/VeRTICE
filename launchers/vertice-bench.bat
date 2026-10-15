@echo off
REM VERTICE - lancador de dois cliques (Windows): sobe a bancada web local.
cd /d "%~dp0\.."
set WS=%1
if "%WS%"=="" set WS=demo-vertice
if not exist "%WS%" python -m vertice demo "%WS%"
echo Bancada em http://127.0.0.1:8713 - feche a janela para sair
python -m vertice bench "%WS%"
pause
