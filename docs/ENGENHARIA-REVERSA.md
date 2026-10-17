# Engenharia Reversa — As 13 ferramentas que originaram o VÉRTICE

> Documento de fundamentação técnica. Dissecamos a arquitetura de cada ferramenta
> de referência (projetos open-source e serviços SaaS), extraímos o **padrão
> essencial** de cada uma e mostramos como ele reaparece, unificado, dentro do
> VÉRTICE. O objetivo não é copiar código — é entender *por que* cada ferramenta
> funciona e reimplementar o conceito em Python stdlib-only, passivo por padrão.

Posicionamento do VÉRTICE: **Attack Surface Mapping & Intelligence Gathering**
(mapeamento de superfície de ataque e coleta de inteligência).

---

## Método

Para cada alvo respondemos quatro perguntas:

1. **O que faz** (função observável).
2. **Como está construído** (arquitetura — modelo de dados, fluxo, abstrações).
3. **Qual é o padrão essencial** (a ideia que vale a pena herdar).
4. **Lacuna** (o que falta, e que o VÉRTICE resolve).

As afirmações sobre serviços fechados (Maltego, BuiltWith, ZoomEye, FOFA, Censys,
DNSDumpster) são **inferências de arquitetura** a partir de documentação pública,
de APIs e do comportamento observável — não de código-fonte. As afirmações sobre
os projetos open-source (Mitaka, Sublist3r, Amass, Subfinder, Recon-ng, o wrapper
nmmapper/dnsdumpster) partem da estrutura pública dos repositórios. Onde é
inferência, está marcado como tal.

---

## 1. Mitaka — `ninoseki/mitaka`

**O que faz.** Extensão de navegador. O analista seleciona um texto; a extensão
detecta o tipo de IOC (IP, domínio, URL, hash, e-mail, CVE, ASN, cartão, etc.) e
oferece um menu de ~70 "searchers" — mecanismos OSINT — cada um abrindo o IOC já
montado na URL de busca do serviço.

**Como está construído (TypeScript).**
- Um conjunto de *refangs* e **expressões regulares** por tipo de IOC
  (`Scanner` → detecta o tipo).
- Um registro de `Searcher`: cada searcher declara `baseURL`, os tipos que
  suporta (`supportedTypes`) e um método `buildURL(query)` que monta o link.
- O menu de contexto é a composição `tipo detectado × searchers que suportam o tipo`.

**Padrão essencial — PIVÔ.** *Detectar o tipo de um identificador e, a partir
dele, gerar automaticamente consultas em N serviços.* Zero requisição de rede na
detecção; tudo é passivo (só monta links). Esse é o coração do "pivoting" em OSINT.

**Lacuna.** Mitaka só gera links — não coleta, não persiste, não correlaciona.
É um trampolim, não um repositório de evidências.

**No VÉRTICE.** `vertice/pivots/registry.py` reimplementa o conceito: detector de
tipo de entidade (`core/entities.py::classify`) + registro de pivôs com template
de URL por serviço. O relatório HTML embute, para cada entidade, o leque de pivôs
— o analista tem o "menu Mitaka" dentro do próprio dossiê.

---

## 2. Maltego

**O que faz.** Plataforma comercial de *link analysis*. O analista arrasta uma
entidade (domínio, pessoa, e-mail…) para um grafo e roda **Transforms**: cada
transform recebe uma entidade e devolve entidades relacionadas, que viram novos
nós ligados por arestas. O resultado é um grafo navegável da investigação.

**Como está construído (inferência de arquitetura).**
- **Modelo entidade-transform-entidade.** Entidades tipadas; transforms são
  funções remotas (Transform Server / TDS) `entidade → [entidades]`.
- **Grafo** como estrutura central: nós + arestas rotuladas, com propriedades.
- **Hub de transforms** (local e de terceiros) — extensibilidade por catálogo.

**Padrão essencial — GRAFO.** *Toda a investigação é um grafo de entidades
tipadas conectadas por relações rotuladas e versionadas.* A visualização de
vínculos é o produto.

**Lacuna.** Caro, pesado, desktop-first, e a coleta depende de transforms de
terceiros (muitos pagos). Não há cadeia de custódia criptográfica embutida.

**No VÉRTICE.** `core/graph.py` é um grafo nó/aresta tipado; cada collector age
como um "transform" (`entidade → novas entidades + arestas`). O grafo é
serializado em JSON e desenhado em SVG no relatório — a visão Maltego, sem
licença e sem desktop.

---

## 3. Sublist3r — `aboul3la/sublist3r`

**O que faz.** Enumera subdomínios de um domínio consultando **motores de busca**
(Google, Bing, Yahoo, Baidu, Ask) e **fontes passivas** (VirusTotal, ThreatCrowd,
DNSdumpster, Netcraft, crt.sh/SSL). Opcionalmente faz bruteforce com `subbrute`.

**Como está construído (Python).**
- Uma classe base `enumratorBase` e subclasses por fonte, cada uma com
  `enumerate()` próprio e um parser de resultados (regex sobre o HTML/JSON).
- **Threads**: uma por motor, rodando em paralelo; resultados agregados num set.
- Saída: lista deduplicada de subdomínios.

**Padrão essencial — AGREGAÇÃO MULTI-FONTE.** *Um mesmo fato (subdomínio) é
buscado em várias fontes independentes e unido num conjunto deduplicado.* A
confiança vem da corroboração entre fontes.

**Lacuna.** Só subdomínios; parsers de SERP quebram quando os motores mudam o
HTML; sem persistência, sem proveniência por fonte (não se sabe *qual* fonte
trouxe cada subdomínio).

**No VÉRTICE.** A abstração `collectors/base.py::Collector` é a `enumratorBase`
generalizada. Deduplicação acontece no grafo (nó único por entidade), mas **a
proveniência é preservada**: cada nó guarda o conjunto de fontes que o
afirmaram — resolvendo a lacuna do Sublist3r.

---

## 4. OWASP Amass — `owasp-amass/amass`

**O que faz.** A referência de mapeamento de superfície de ataque. Enumeração de
DNS passiva *e* ativa, dezenas de fontes de dados, resolução de DNS, mapeamento
de ASN/netblock, e persistência em **banco de grafo** para correlação.

**Como está construído (Go — inferência a partir do repo público).**
- **Abstração de data source**: cada fonte implementa uma interface comum e é
  orquestrada por um *engine* assíncrono.
- **Grafo persistente** (histórico) para relacionar domínios ↔ IPs ↔ ASNs ↔
  certificados ao longo do tempo.
- Separação explícita entre **passivo** (OSINT, sem tocar o alvo) e **ativo**
  (resolução, brute, varredura).

**Padrão essencial — ENGINE + GRAFO PERSISTENTE + PASSIVO/ATIVO.** *A superfície
de ataque é um grafo que cresce no tempo, alimentado por muitas fontes sob uma
interface única, com fronteira clara entre o que é observação passiva e o que
toca o alvo.*

**Lacuna.** Curva de aprendizado alta; a saída é técnica demais para virar
dossiê/relatório executivo; sem custódia de evidência pensada para uso
investigativo/forense.

**No VÉRTICE.** É a espinha dorsal: `core/engine.py` (orquestrador de collectors),
`core/graph.py` (grafo persistente), e a **marcação `passive`/`active` por
collector**. O VÉRTICE nasce passivo; qualquer coleta ativa é explícita e
exige flag.

---

## 5. BuiltWith

**O que faz.** Perfilador de tecnologia. Dado um site, identifica o stack: CMS,
frameworks, analytics, CDN, hospedagem, e-commerce, tag managers, etc.

**Como está construído (inferência).**
- **Fingerprints**: assinaturas (strings em HTML, headers HTTP, caminhos de JS,
  cookies, meta tags) → tecnologia. É um dicionário assinatura → produto.
- Histórico de tecnologias por domínio (quando entrou/saiu cada tech).

**Padrão essencial — FINGERPRINTING PASSIVO.** *Tecnologia se revela por
assinaturas observáveis na resposta HTTP; casar assinatura → produto classifica o
alvo sem interação intrusiva.*

**Lacuna.** Fechado; a base de assinaturas não é inspecionável; sem integração
com o grafo de superfície.

**No VÉRTICE.** `collectors/web_fingerprint.py` traz um dicionário de assinaturas
(estilo Wappalyzer/BuiltWith, extensível por JSON) que casa contra headers e HTML
da página inicial. Cada tecnologia detectada vira **nó `technology`** ligado ao
`host` — a superfície de ataque passa a enxergar "o que roda ali".

---

## 6. Subfinder — `projectdiscovery/subfinder`

**O que faz.** Descoberta passiva de subdomínios, rápida, a partir de muitas
fontes online — focado em **APIs** (não em scraping de SERP), com chaves.

**Como está construído (Go).**
- Interface `Source` com `Run(domain) -> results` por fonte.
- **Config central de chaves de API** (`provider-config.yaml`).
- Alta concorrência; saída limpa (só a lista).

**Padrão essencial — SOURCE ABSTRACTION + CONFIG DE CREDENCIAIS.** *Fontes são
plugáveis sob uma interface única e as credenciais ficam numa configuração
central, separada do código.* É o Sublist3r "feito direito": API-first, sem
depender de HTML frágil.

**Lacuna.** Só subdomínios (de novo); a saída é um insumo, não um dossiê.

**No VÉRTICE.** `collectors/base.py` define a interface única; `core/workspace.py`
guarda a config de credenciais por workspace (JSON local, fora do código). Todo
collector que precise de chave lê dali — nenhuma chave no código.

---

## 7. Recon-ng — `lanmaster53/recon-ng`

**O que faz.** Framework de reconhecimento em formato de console (estilo
Metasploit). Módulos plugáveis, **workspaces**, banco de dados por workspace,
marketplace de módulos, e um esquema de tabelas (hosts, contacts, domains,
credentials…) que todos os módulos compartilham.

**Como está construído (Python).**
- **Workspace** = um diretório + um SQLite com esquema fixo de recon.
- **Módulos** herdam de uma base, declaram `options` e um `module_run()` que
  lê/escreve no banco compartilhado.
- Console interativo + marketplace.

**Padrão essencial — WORKSPACE + BANCO COMPARTILHADO + MÓDULOS.** *Cada
engajamento é um workspace isolado com um banco onde todos os módulos despejam
e de onde todos leem — o estado da investigação é o banco.*

**Lacuna.** Muitos módulos quebrados por mudança de fontes; o esquema é fixo e
tabular (não-grafo); sem custódia nem relatório pronto.

**No VÉRTICE.** `core/workspace.py` (diretório + SQLite por engajamento) e
`core/engine.py` (collectors como "módulos" que leem/escrevem no mesmo
workspace). Diferença: o estado é **grafo + evidência com custódia**, não um
esquema tabular rígido.

---

## 8. ZoomEye — `zoomeye.ai`

**O que faz.** Motor de busca de ciberespaço (hosts e aplicações web). Indexa
serviços expostos na internet: banners, portas, produtos, geolocalização. Busca
por linguagem de query (`app:`, `port:`, `country:`…).

**Como está construído (inferência).**
- Varredura contínua da internet → índice invertido de banners/serviços.
- API REST com DSL de busca; resultados paginados em JSON.

**Padrão essencial — ÍNDICE DE CIBERESPAÇO CONSULTÁVEL.** *Alguém já varreu a
internet; você consulta o índice em vez de varrer você mesmo (passivo do ponto
de vista do alvo).*

**Lacuna.** Exige conta/chave; termos de uso e cota; dado chinês-cêntrico; sem
integração com o resto da investigação.

**No VÉRTICE.** `collectors/cyberspace.py` traz um **conector opcional** para
motores de ciberespaço (ZoomEye/FOFA/Censys) sob a mesma interface `Collector`:
desligado por padrão, ativado só com chave na config do workspace, resultados
viram nós `service`/`host` no grafo.

---

## 9. DNSDumpster + `nmmapper/dnsdumpster`

**O que faz.** Serviço web de recon de DNS: subdomínios, registros (A, MX, NS,
TXT), e um mapa de hospedagem. O pacote `nmmapper/dnsdumpster` (Python) é um
**wrapper** que faz o fluxo do site (pega o CSRF token, posta o domínio, faz o
parse da tabela de resultados) e devolve estruturado.

**Como está construído.**
- Site: coleta DNS + agrega passivamente subdomínios; renderiza tabela + imagem.
- Wrapper: `requests.Session` para CSRF → POST → parser de HTML → dict.

**Padrão essencial — RECON DE DNS CONSOLIDADO.** *Juntar, num lugar só, todos os
registros DNS e a topologia de hospedagem de um domínio.*

**Lacuna.** Dependente de scraping de um serviço (frágil, com rate-limit);
resultado efêmero.

**No VÉRTICE.** `collectors/dns_recon.py` faz recon de DNS **direto**, via
DNS-over-HTTPS (stdlib `urllib` + JSON) e resolução por `socket` — sem depender
de scrape de terceiros. Registros viram nós/arestas no grafo e ficam persistidos
no workspace.

---

## 10. FOFA — `fofa.info`

**O que faz.** Motor de busca de ciberespaço (análogo ao ZoomEye/Shodan), com DSL
poderosa (`domain=`, `cert=`, `body=`, `icon_hash=`…) muito usada para achar
ativos correlatos por certificado e por favicon hash.

**Padrão essencial — PIVÔ POR ARTEFATO.** *Além de host/porta, pivotar por
**certificado** e por **hash de favicon** encontra ativos do mesmo dono que o DNS
não liga.* Essa é a grande sacada do FOFA.

**Lacuna.** Fechado, chave, cota, dado chinês-cêntrico.

**No VÉRTICE.** Dois reflexos: (a) o conector de ciberespaço (item 8) cobre a
consulta; (b) **o favicon hash e o fingerprint de certificado viram entidades de
primeira classe** no grafo (`core/entities.py`), de modo que o pivô "mesmo cert /
mesmo favicon" existe no modelo mesmo offline, pronto para alimentar qualquer
motor quando houver chave.

---

## 11. Censys — `search.censys.io`

**O que faz.** Busca sobre dados de varredura internet-wide: **hosts** e,
sobretudo, **certificados** (Certificate Transparency + varredura). DSL rica;
referência para descobrir ativos por SAN de certificado e por serviço exposto.

**Padrão essencial — CERTIFICADO COMO EIXO DE DESCOBERTA.** *Os SANs e o
`issuer`/`fingerprint` de certificados ligam domínios aparentemente
independentes; Certificate Transparency é uma fonte passiva riquíssima.*

**Lacuna.** Chave e cota; a modelagem é de busca, não de investigação acumulada.

**No VÉRTICE.** `collectors/crtsh.py` usa **Certificate Transparency (crt.sh)** —
fonte passiva, sem chave — para extrair subdomínios a partir de SANs de
certificados. É o mesmo eixo de descoberta do Censys, acessível sem conta. O
conector Censys (com chave) entra pelo `collectors/cyberspace.py` quando
disponível.

---

## 12–13. (DNSDumpster e Subfinder aparecem duplicados na lista de origem)

A lista do pedido repete `subfinder` e `dnsdumpster`; tratados uma vez cada
(itens 6 e 9). A repetição reforça o peso que subdomínio-via-API e recon-de-DNS
têm no conjunto — e ambos são collectors de primeira linha no VÉRTICE.

---

## Síntese — os 7 padrões herdados

| # | Padrão | Origem principal | Onde vive no VÉRTICE |
|---|--------|------------------|----------------------|
| 1 | **Pivô** (tipo → N consultas) | Mitaka, FOFA | `pivots/registry.py`, `entities.classify` |
| 2 | **Grafo** de entidades tipadas | Maltego, Amass | `core/graph.py` |
| 3 | **Agregação multi-fonte** com proveniência | Sublist3r, Subfinder | `core/engine.py`, nós com `sources` |
| 4 | **Engine + passivo/ativo** | Amass | `core/engine.py`, flag `passive` |
| 5 | **Fingerprint passivo** | BuiltWith | `collectors/web_fingerprint.py` |
| 6 | **Workspace + banco por engajamento** | Recon-ng | `core/workspace.py` (SQLite) |
| 7 | **Índice de ciberespaço** (cert/favicon/serviço) | ZoomEye, FOFA, Censys | `collectors/crtsh.py`, `collectors/cyberspace.py` |

E um **oitavo padrão, que é a inovação do VÉRTICE** e não vem de nenhuma das 13:

> **8. Custódia criptográfica de evidência.** Cada fato coletado é registrado com
> timestamp, fonte e **hash SHA-256 encadeado** (cada evidência referencia o hash
> da anterior — um *ledger* append-only). Isso transforma a coleta OSINT num
> histórico de evidências auditável, requisito de uso investigativo/forense e de
> preparação de pentest com rastreabilidade. É a marca da família DEIVOSINT
> (herdada de F.I.O. Lab, GARIMPO e PRISMA) aplicada à superfície de ataque.

---

## Da engenharia reversa ao produto

O VÉRTICE **não é** mais um enumerador de subdomínio. É a convergência:

```
            ┌───────────────── VÉRTICE ─────────────────┐
  PIVÔ ─────┤  entidades tipadas → grafo → evidência      ├───── relatório
 (Mitaka)   │       ▲              (Maltego/Amass)         │   (dossiê HTML + SVG)
            │       │                                      │
 multi-fonte│   collectors (interface única)              │  preparação de
(Sublist3r/ │   crt.sh · DNS/DoH · RDAP · fingerprint ·   │   pentest (escopo,
 Subfinder) │   pivô · archive · ciberespaço opcional     │   superfície, risco)
            │       │              ▲                       │
 workspace  │   workspace + SQLite (Recon-ng)             │  custódia SHA-256
(Recon-ng)  │                       cert/favicon (Censys/FOFA)   (inovação DEIVOSINT)
            └─────────────────────────────────────────────┘
```

Passivo por padrão, stdlib-only, com dossiê pronto para entregar e um ledger de
evidências que aguenta escrutínio. É isso que o código a seguir implementa.

---

# Apêndice v2 — novas engenharias reversas e integrações

A v2 amplia o conjunto com mais três referências reimplementadas e a costura
com a ferramenta irmã FAROL.

## 14. Shodan InternetDB

**O que faz.** `https://internetdb.shodan.io/{ip}` devolve, **sem chave e de
graça**, as portas abertas, CPEs (produtos), hostnames, tags e **CVEs
conhecidas** de um IP — tudo a partir da varredura que o Shodan já fez.

**Padrão essencial — VULNERABILIDADE PASSIVA.** *Dá para saber o que está aberto
e quais CVEs batem, sem tocar o alvo e sem conta.* É o "serviço+vulnerabilidade"
do ZoomEye/Censys, democratizado.

**No VÉRTICE.** `collectors/internetdb.py`: semente IP → nós `port`, `cpe`,
`vulnerability`, `host`. Alimenta diretamente o scoring v2 (CVE tem peso alto).

## 15. RIPEstat (RIPE NCC)

**O que faz.** API de dados aberta (`stat.ripe.net`) com roteamento global: de um
IP → prefixo e ASN; de um ASN → holder e prefixos anunciados.

**Padrão essencial — ASN/NETBLOCK SEM CHAVE.** Reimplementa o eixo de
roteamento do Amass/BGP.he.net via fonte pública e estável.

**No VÉRTICE.** `collectors/asn_bgp.py`: semente IP/ASN → `netblock`, `asn`,
`organization`. Base da correlação por netblock/ASN em `intel.correlate`.

## 16. Photon (s0md3v) → FAROL

**O que faz (Photon).** Crawler OSINT que, a partir de uma URL, extrai endpoints,
parâmetros, e-mails, arquivos, chaves e segredos "dentro" do site.

**Padrão essencial — SUPERFÍCIE INTERNA.** Enquanto o VÉRTICE descobre *quais*
hosts existem, o Photon descreve *o que há dentro* de cada um.

**No VÉRTICE.** O usuário reescreveu o Photon como **FAROL** (Go, moderno, estilo
katana/ProjectDiscovery, SHA-256 por resposta, saída JSONL). O VÉRTICE não
recria o FAROL — ele **o integra**: `importers/farol.py` lê o JSONL e costura
`endpoint`/`parameter`/`form`/`email`/`secret` ao host no grafo. **Decisão de
projeto responsável:** o valor de um segredo nunca é persistido — guarda-se só o
rótulo (`segredo:<tipo>@<host>`) e `redacted: true`. O VÉRTICE descobre os
hosts; o FAROL descreve o que há dentro; o grafo une os dois.

## Padrão 9 — INTELIGÊNCIA SOBRE O GRAFO

A v2 acrescenta um nono padrão, que não é coleta e sim **análise** do que já foi
coletado, e que nenhuma das 16 ferramentas entrega junto:

> **Confiança por corroboração + diff de superfície + correlação.** Cada fato
> ganha uma confiança que cresce com o número de fontes independentes; dois
> snapshots viram um *diff* (o que surgiu/sumiu na superfície — detecção de
> mudança); e o grafo é varrido em busca de ativos do mesmo dono por pista
> compartilhada (co-hospedagem, ASN, favicon). É o que transforma uma lista de
> achados em inteligência acionável — e fecha o ciclo com o scoring de pentest.
