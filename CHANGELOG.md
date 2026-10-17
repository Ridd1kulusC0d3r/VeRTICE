# Changelog — VÉRTICE

## v2.0.0 — 2026-10-17

Ampliação grande, mantendo compatibilidade total com workspaces v1.

### Núcleo (elevado, compatível)
- **Confiança por corroboração**: toda entidade ganha `confidence` 0..1 que
  cresce com o nº de fontes distintas (`seed` = 1.0). Visível no dossiê e no CSV.
- **Temporalidade**: `first_seen`/`last_seen` em nós e arestas — base do diff.
- **Snapshots**: `run` e importações congelam o grafo; `snapshot`/`diff` na CLI.
- **Config de collectors** por workspace: `disabled`, `rate_limit_s`, `weights`.
- **Engine**: `--only` para rodar collectors específicos; rate-limit por fonte;
  honra a config; snapshot automático ao fim do run.
- Novos tipos de entidade: `port`, `cpe`, `vulnerability`, `endpoint`,
  `parameter`, `form`, `secret`, `finding`.

### Novos collectors OSINT passivos (sem chave)
- **internetdb** — Shodan InternetDB: portas, CPEs e **CVEs** de um IP, de graça.
- **asn** — RIPEstat: ASN, prefixo anunciado e holder (de IP ou ASN).
- **emailsec** — postura SPF/DMARC (achados de severidade) via DoH TXT.
- **tlscert** — SANs/issuer/validade do certificado TLS direto do alvo.
- **dorks** — gera dorks Google/Bing/GitHub (offline) para o domínio.

### Integração FAROL + irmãs
- **importers/farol** — importa o JSONL do FAROL (endpoints, params, forms,
  e-mails, scripts) para dentro do grafo, ligando ao host. **Segredos são
  redigidos**: guarda-se só o rótulo e o tipo, nunca o valor.
- **importers/generic_jsonl** — importa JSONL de F.I.O./GARIMPO/PRISMA e afins.
- CLI: `import --farol` e `import --jsonl --source`.

### Inteligência de dados
- **core/intel**: `surface_diff` (detecção de mudança entre snapshots),
  `correlate` (clusters por IP/netblock/ASN/favicon — pivô FOFA sobre o grafo),
  `risk_signals` (vulns/portas/postura por host).
- **Scoring v2**: incorpora CVEs (peso alto), portas e postura alta.

### Saídas e produto
- **exporters**: `jsonl`, `csv`, **`stix`** (STIX 2.1 bundle), `targets`,
  `nmap` (-iL), `httpx` (-l). CLI: `export --format`.
- **Dossiê v2**: seções de vulnerabilidades/postura, correlação, dorks, coluna
  de confiança e de vulns.
- **Bancada web** agora com endpoints `/correlate`, `/diff`, `/snapshots`,
  `/export/<fmt>`, servidor com threads.

### Testes
- 23 testes (eram 12), cobrindo confiança, diff, correlação, exporters, STIX,
  redação de segredo do FAROL e snapshots.

## v1.0.0 — 2026-10-15
- Primeira versão. Engenharia reversa de 13 ferramentas; núcleo (entidades,
  grafo, evidência SHA-256, workspace, engine); collectors crt.sh, DNS/DoH,
  RDAP, fingerprint, Wayback, pivot + conectores Censys/Shodan/ZoomEye/FOFA;
  dossiê HTML + grafo SVG + preparação de pentest; entrega padrão F.I.O. Lab 2.1.
