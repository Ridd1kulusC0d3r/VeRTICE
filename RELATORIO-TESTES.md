# Relatório de Testes — VÉRTICE v2.0

**Data:** 2026-10-17 · **Ambiente:** container Linux (Python 3.13) ·
**Rede:** proxy com allowlist (apenas registries de pacote liberados).

Este relatório consolida a validação da v2.0, que **une** a linha v1.1
(runs/history, captura de requests, importação Subfinder/Nmap, notebook Colab)
com a ampliação v2 (novos collectors, integração FAROL, inteligência e exporters).

## 1. Resumo executivo

| Dimensão | Resultado |
|---|---|
| Testes automatizados (unittest) | **39/39 PASS** |
| Compatibilidade com workspace v1 | **mantida** |
| Collectors registrados | **15** (11 passivos + 4 conectores c/ chave) |
| Subcomandos da CLI | **17** (inclui import/export/snapshot/diff/runs/rundiff/ingest/collectors) |
| Bancada web (`/ /graph.json /verify /correlate /diff /snapshots /export/*`) | **200 OK** |
| Dossiê HTML v2 | **~90 KB** (vulns, postura, correlação, dorks, confiança) |
| Cadeia de custódia (61 registros na demo) | **íntegra** + **adulteração detectada** |
| Redação de segredo (import FAROL) | **valor nunca persiste** (grafo e ledger) |
| STIX 2.1 | **bundle válido** (identity/indicator/vulnerability) |
| Coleta OSINT online real | **N/D no ambiente** (bloqueio de rede — ver §4) |

## 2. Testes automatizados (`python -m unittest discover -s tests`)

```
Ran 39 tests
OK
```

Cobertura (destaques da v2 em **negrito**):

- **Classificação/normalização**: 9 tipos, refang, domínio registrável.
- **Grafo**: deduplicação, proveniência, ida-e-volta JSON.
- **Pivôs**: menu por tipo (domínio, CVE).
- **Cadeia de custódia**: íntegra; **adulteração detectada** no elo 3.
- **Superfície/pentest**: priorização; só-histórico não é "vivo"; render do dossiê.
- Regressões v1.1: escopo vazio em modo ativo; sufixos enganosos; IP/CIDR/IPv6/URL;
  seed fora de escopo; terceiro descoberto não expandido; fingerprint fora do passivo;
  redirects não seguidos; orçamento de tarefas; falha de rede ≠ vazio; redação de
  credencial na URL; evidência ligada ao vínculo; comparação sem apagar não
  reobservados; escritas concorrentes no ledger; import Subfinder/Nmap; porta fechada
  não importada; DTD externo rejeitado; CNAME não classificado como IP.
- **V2 collectors**: internetdb/asn/emailsec/tlscert/dorks registrados; tipos novos.
- **Confiança**: corroboração (2 fontes → 0.75; seed → 1.0).
- **Inteligência**: surface_diff (+1); cluster de favicon; risk_signals acha CVE.
- **Exporters**: todos os formatos; STIX 2.1 válido; escaping anti-injeção.
- **Import FAROL**: importa JSONL e **redige segredo** (valor fora de grafo e ledger).
- **Snapshots**: salvar + diff entre snapshots.

## 3. Validação funcional (demo v2)

```
nós: 52 | arestas: 63 | evidências: 61
  host 12 | ip 8 | technology 8 | service 5 | port 5 | url 3 |
  vulnerability 3 | email 2 | finding 2 | domain 1 | organization 1 |
  netblock 1 | favicon 1
```

- **verify** → `cadeia íntegra — 61 registros`.
- **diff** → adicionar subdomínio e comparar snapshots: `adicionados: 1 {'host': 1}`.
- **correlação** → favicon compartilhado por 2 hosts vira cluster.
- **export** → jsonl/csv/stix/targets/nmap/httpx; STIX `identity + indicator + vulnerability`.
- **CLI** → 17 subcomandos; `compileall` sem erro de sintaxe.

## 4. Coleta online — por que ficou N/D na nuvem

O proxy do ambiente rejeita por política as fontes OSINT:

```
connect_rejected  403 to CONNECT  host: dns.google:443
connect_rejected  403 to CONNECT  host: crt.sh:443
```

Só passam registries de pacote. **Restrição do ambiente, não do VÉRTICE.** Os
collectors usam só `urllib`/`ssl`/`socket`, são tolerantes a falha (devolvem `[]`
em erro, nunca derrubam o engine) e foram exercitados com payloads sintéticos.
Para a coleta real, rode na sua máquina/rede.

## 5. Não validado neste ambiente

- Sessão Google Colab autenticada e renderização do iframe pelo proxy do navegador.
- Consultas ao vivo das APIs (InternetDB, RIPEstat, crt.sh, DoH) e das comerciais
  (Shodan/Censys/ZoomEye/FOFA), incluindo compatibilidade de planos/endpoints.
- `tlscert` contra alvo real (faz handshake TLS no 443 — respeita escopo).
- Python 3.9 local (fica na matriz de CI).

## 6. Limitações conhecidas

- **Favicon hash** `vfav:` = SHA-256 do base64, não o MurmurHash3 do FOFA.
- **Domínio registrável**: heurística de TLDs compostos (sem Public Suffix List).
- IP/cert/favicon compartilhado **não comprova** propriedade.

## 7. Reprodutibilidade

```bash
python -m unittest discover -s tests -v
python -m vertice demo demo-vertice
python -m vertice report demo-vertice -o demo-vertice/dossie.html
python -m vertice verify demo-vertice
python -m vertice export demo-vertice --format stix -o demo.stix.json
```
