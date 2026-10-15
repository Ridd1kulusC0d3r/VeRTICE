# Relatório de Testes em Nuvem — VÉRTICE v1.0

**Data:** 2026-10-15 · **Ambiente:** container Linux (Python 3.13.16) ·
**Rede:** proxy com allowlist (apenas registries de pacote liberados).

## 1. Resumo executivo

| Dimensão | Resultado |
|---|---|
| Testes automatizados (unittest) | **12/12 PASS** |
| Importação de todos os módulos | **15/15 OK** |
| CLI (`demo`, `report`, `verify`, `pivot`, `stats`) | **PASS** |
| Bancada web (`/`, `/graph.json`, `/verify`) | **200 OK** |
| Dossiê HTML gerado | **60 KB**, com grafo, custódia e alvos |
| Cadeia de custódia (51 registros) | **íntegra** + **adulteração detectada** |
| Coleta OSINT online real | **N/D no ambiente** (bloqueio de rede — ver §4) |

Conclusão: todo o núcleo (classificação, grafo, engine, evidência, relatório,
bancada) está **validado offline com dados sintéticos rotulados**. A coleta
online depende de acesso à internet do operador — o ambiente de nuvem usado para
construir o projeto bloqueia as fontes OSINT por política de rede.

## 2. Testes automatizados (`python3 -m unittest discover -s tests`)

```
Ran 12 tests in 0.23s
OK
```

| Suite | Caso | Verifica |
|---|---|---|
| TestClassify | test_types | 9 tipos de entidade classificados corretamente |
| TestClassify | test_refang | `hxxps://evil[.]com` → URL; `ns1[.]exemplo[.]com` → domínio |
| TestClassify | test_registered_domain | `www.loja.exemplo.com.br` → `exemplo.com.br` |
| TestClassify | test_normalize | normalização (lowercase, ponto final) |
| TestGraph | test_dedup_and_provenance | nó único; fontes acumuladas (`{crtsh, dns}`) |
| TestGraph | test_edges_and_roundtrip | serialização JSON ida-e-volta preserva grafo |
| TestPivots | test_domain_pivots | menu inclui crt.sh, VirusTotal |
| TestPivots | test_cve_pivots | menu inclui NVD |
| TestEvidenceChain | test_chain_intact | 51 registros, cadeia OK |
| TestEvidenceChain | **test_tamper_detected** | alterar o registro #3 no SQLite → `verify` acusa `broken_at=3` |
| TestAttackSurface | test_surface | admin/api/vpn no topo; `old.*` (só histórico) não é "vivo" |
| TestAttackSurface | test_report_renders | HTML contém "Cadeia de custódia" e o alvo; >10 KB |

## 3. Validação funcional (CLI + bancada)

**Demo + stats** (ground truth sintético — alvo `exemplo-alvo.com.br`, RFC 2606/5737):

```
nós: 42 | arestas: 51 | evidências: 51
  host 12 | ip 8 | technology 8 | service 5 | url 3 | email 2
  domain 1 | organization 1 | netblock 1 | favicon 1
evidências por collector: fingerprint 16 | dns 11 | crtsh 9 | censys 5 |
                          wayback 5 | rdap 4 | seed 1
```

**Verify:**
```
[ok] cadeia íntegra — 51 registros
     head: bf39310fa452b6425daf83690a103c2b7d3cc495fa31d5fff0e971e7a512fc3f
```

**Bancada web** (loopback):
```
/            200  60216 bytes
/graph.json  200  17738 bytes
/verify      200    103 bytes
```

## 4. Coleta online — por que ficou N/D na nuvem

O ambiente de construção roteia todo tráfego de saída por um proxy com
*allowlist*. Consultas às fontes OSINT foram **rejeitadas por política**:

```
connect_rejected  gateway answered 403 to CONNECT  host: dns.google:443
connect_rejected  gateway answered 403 to CONNECT  host: crt.sh:443
```

Só são liberados `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`,
`proxy.golang.org`, `crates.io` e hosts internos. **Isto é uma restrição do
ambiente de nuvem, não do VÉRTICE.** O código de rede:

- usa apenas `urllib`/`ssl`/`socket` (stdlib), sem dependências;
- é **tolerante a falha** — todo collector devolve `[]` em erro de rede, nunca
  derruba o engine (coberto pelo tratamento em `util.http_get` e `Engine._run_collector`);
- foi exercitado contra os parsers com payloads sintéticos equivalentes aos das
  fontes reais (crt.sh JSON, DoH JSON, RDAP vcard).

**Como validar a coleta real:** na sua máquina/rede, rode
`python3 -m vertice run CASO --seed SEU-DOMINIO-AUTORIZADO --depth 2` e depois
`report`. As fontes passivas (crt.sh, DoH, RDAP, Wayback) funcionam sem chave.

## 5. Limitações conhecidas (honestas)

- **Favicon hash** usa SHA-256 do base64 (prefixo `vfav:`), não o MurmurHash3 do
  FOFA/Shodan (não está na stdlib). Mantém a função de *pivô por favicon* dentro
  do VÉRTICE, mas o valor **não** é comparável ao `icon_hash` do FOFA. Documentado
  em `util.favicon_mmh3_like`.
- **Domínio registrável** usa heurística de TLDs compostos (sem Public Suffix
  List, para manter stdlib-only). Cobre `.com.br`, `.gov.br`, `.co.uk` etc.;
  TLDs compostos exóticos podem escapar.
- **Layout do grafo SVG** é radial determinístico (sem física de força); ótimo
  até ~220 nós, depois prioriza tipos estruturais e limita a exibição.
- **Conectores ZoomEye/FOFA** seguem a interface e os endpoints documentados,
  mas não puderam ser exercitados contra a API real (sem chave e sem rede aqui).

## 6. Reprodutibilidade

```bash
python3 -m unittest discover -s tests -v     # testes
python3 -m vertice demo demo-vertice          # dados sintéticos
python3 -m vertice report demo-vertice -o demo-vertice/dossie.html
python3 -m vertice verify demo-vertice        # integridade
```
