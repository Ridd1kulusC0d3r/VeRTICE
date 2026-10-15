# Validação VÉRTICE 1.1

Data: 2026-10-15. Ambiente local: Python 3.12, Linux.

## Executado

- `python -m unittest discover -s tests -v`: **28 testes aprovados**.
- `python -m compileall -q vertice`: sem erro de sintaxe.
- `python -m pip install --no-deps --no-build-isolation .`: wheel 1.1.0 construída e instalada.
- Notebook: compilação de todas as células e execução local das células offline,
  comparação sintética, servidor HTTP, `/`, `/graph.json`, `/verify` e ZIP sem credenciais.
- `git diff --check`: sem erro de whitespace.

## Regressões cobertas

Escopo vazio em modo ativo; sufixos enganosos; IP/CIDR/IPv6/URL; seed fora de escopo;
terceiro descoberto não expandido; fingerprint excluído do modo passivo; redirects
não seguidos; orçamento de tarefas; falha de rede distinta de vazio; redação de
credencial na URL; exceção sem vazamento do conteúdo; evidência ligada ao vínculo;
comparação sem apagar itens não reobservados; 80 escritas concorrentes no ledger;
imports Subfinder/Nmap; porta fechada não importada; DTD externo rejeitado; DOCTYPE
simples do Nmap aceito; CNAME não classificado como IP; credencial ausente visível.

Os 12 testes anteriores foram preservados, com a demo migrada para `.example`.

## Não validado neste ambiente

- Sessão Google Colab autenticada e renderização visual pelo proxy do navegador.
- Consultas ao vivo das APIs comerciais e compatibilidade dos planos/endpoints.
- Python 3.9 localmente: incluído na matriz de CI, sem afirmar resultado antes de rodar.
- Pentest ativo contra infraestrutura real.

O notebook usa `serve_kernel_port_as_iframe`, conforme o código oficial do Colab:
https://github.com/googlecolab/colabtools/blob/main/google/colab/output/_util.py

O ZIP com HTML é a alternativa quando o navegador bloqueia o iframe.
