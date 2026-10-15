<div align="center">

# 🔺 VÉRTICE

**Attack Surface Mapping & Intelligence Gathering**

Plataforma OSINT passiva, modular e auditável — da família **DEIVOSINT**.
Python **stdlib-only** (zero dependências). Coleta OSINT · histórico de
evidências com custódia SHA-256 · preparação de pentest.

</div>

---

## Por que o VÉRTICE existe

Fizemos a **engenharia reversa de 13 referências** — Mitaka, Maltego, Sublist3r,
OWASP Amass, BuiltWith, Subfinder, Recon-ng, ZoomEye, DNSDumpster, FOFA e Censys —
extraímos o padrão essencial de cada uma e os reunimos num só produto, passivo
por padrão e sem licença. O detalhe completo está em
[`docs/ENGENHARIA-REVERSA.md`](docs/ENGENHARIA-REVERSA.md).

| Padrão herdado | De onde | Onde vive no VÉRTICE |
|---|---|---|
| Pivô (tipo → N consultas) | Mitaka, FOFA | `pivots/registry.py` |
| Grafo de entidades tipadas | Maltego, Amass | `core/graph.py` |
| Agregação multi-fonte com proveniência | Sublist3r, Subfinder | `core/engine.py` |
| Engine + fronteira passivo/ativo | Amass | `core/engine.py` |
| Fingerprint passivo de tecnologia | BuiltWith | `collectors/web_fingerprint.py` |
| Workspace + banco por engajamento | Recon-ng | `core/workspace.py` |
| Índice de ciberespaço (cert/favicon/serviço) | ZoomEye, FOFA, Censys | `collectors/crtsh.py`, `collectors/cyberspace.py` |
| **Custódia criptográfica de evidência** (inovação) | — | `core/evidence.py` |

## Arquitetura

```
sementes → ENGINE (BFS, passivo por padrão)
             ├─ collectors (interface única):
             │    crtsh · dns(DoH) · rdap · fingerprint · wayback · pivot
             │    + conectores opcionais: censys · shodan · zoomeye · fofa (com chave)
             ├─ GRAFO (nós tipados + arestas, com proveniência)   → graph.json
             └─ LEDGER de evidências (SHA-256 encadeado)          → evidence.db
                                   │
                                   ▼
          RELATÓRIO: dossiê HTML + grafo SVG + alvos priorizados (pentest prep)
```

## Instalação

Nenhuma. Requer apenas **Python 3.9+**. Clone e rode.

```bash
git clone https://github.com/Ridd1kulusC0d3r/vertice
cd vertice
python3 -m vertice demo demo-vertice        # demonstração offline
python3 -m vertice report demo-vertice -o demo-vertice/dossie.html
```

## Uso

```bash
# 1. criar engajamento (com escopo autorizado)
python3 -m vertice init caso --scope alvo.com --by "Contrato 2026"

# 2. coleta passiva (profundidade 2)
python3 -m vertice run caso --seed alvo.com --depth 2

# 3. dossiê HTML
python3 -m vertice report caso -o caso/dossie.html

# 4. integridade das evidências
python3 -m vertice verify caso

# extras
python3 -m vertice stats caso            # resumo grafo/ledger
python3 -m vertice pivot alvo.com        # menu de pivô (Mitaka) no terminal
python3 -m vertice bench caso            # bancada web local
python3 -m vertice creds caso --set censys_token=ID:SECRET   # conector opcional
```

Modo **ativo** (coleta que toca o alvo) só roda com `--active` **e** respeitando o
escopo autorizado:

```bash
python3 -m vertice run caso --seed alvo.com --active
```

## Conectores opcionais (com chave)

Desligados por padrão. Ative colando a chave na config do workspace:

| Conector | Credencial (`credentials.json`) |
|---|---|
| Censys | `censys_token` = `API_ID:API_SECRET` |
| Shodan | `shodan_key` |
| ZoomEye | `zoomeye_key` |
| FOFA | `fofa_key` = `email:key` |

Nenhuma chave fica no código — só no workspace local (permissão `600`).

## Ética e escopo

O VÉRTICE é **passivo por padrão** e foi feito para investigação autorizada
(red team com contrato, defesa da própria superfície, pesquisa). Coleta ativa
exige flag explícita e escopo. Use apenas sobre ativos que você está autorizado
a investigar.

## Testes

```bash
python3 -m unittest discover -s tests -v
```

## Licença

Uso interno / pesquisa DEIVOSINT. Defina a licença antes de distribuir.

---

<div align="center">
<sub>🔺 VÉRTICE · DEIVOSINT · "três vértices: fonte, identificador e vínculo"</sub>
</div>
