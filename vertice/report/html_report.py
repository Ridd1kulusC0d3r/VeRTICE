"""Dossiê HTML do VÉRTICE — relatório autocontido (single-file).

Monta um HTML com CSS embutido (tema claro/escuro), contendo:
  - cabeçalho do engajamento (escopo, autorização, datas)
  - KPIs da superfície de ataque
  - grafo SVG (visão Maltego)
  - tabela de alvos priorizados (preparação de pentest)
  - menu de pivô por entidade (estilo Mitaka)
  - verificação da cadeia de custódia (SHA-256)

Stdlib-only. Sem CDN, sem JS externo; um pouco de JS inline para filtro/tabs.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Dict

from .graph_svg import render_graph_svg
from .pentest_prep import build_attack_surface
from ..pivots.registry import pivots_for

_CSS = """
:root{--bg:#f8fafc;--card:#ffffff;--fg:#0f172a;--muted:#64748b;
--line:#e2e8f0;--brand:#2563eb;--brand2:#0891b2;--warn:#dc2626;
--ok:#16a34a;--chip:#eff6ff}
@media(prefers-color-scheme:dark){:root{--bg:#0b1220;--card:#111a2e;
--fg:#e2e8f0;--muted:#94a3b8;--line:#1e293b;--brand:#60a5fa;--brand2:#22d3ee;
--chip:#15223b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5}
.wrap{max-width:1180px;margin:0 auto;padding:24px 18px}
header.top{display:flex;align-items:center;gap:14px;flex-wrap:wrap;
border-bottom:2px solid var(--brand);padding-bottom:16px;margin-bottom:8px}
.logo{width:46px;height:46px;flex:0 0 auto}
h1{font-size:24px;margin:0}h2{font-size:18px;margin:28px 0 10px;
border-left:4px solid var(--brand);padding-left:10px}
.sub{color:var(--muted);font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
gap:12px;margin:16px 0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:14px}
.kpi .n{font-size:28px;font-weight:700;color:var(--brand)}
.kpi .l{font-size:12px;color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:16px;margin:12px 0}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--muted);font-weight:600;position:sticky;top:0;background:var(--card)}
.chip{display:inline-block;background:var(--chip);color:var(--brand);
border-radius:999px;padding:1px 9px;font-size:11px;margin:1px 2px}
.chip.tech{background:#fff7ed;color:#c2410c}
.score{font-weight:700}.score.hi{color:var(--warn)}.score.md{color:#d97706}
.score.lo{color:var(--muted)}
a{color:var(--brand);text-decoration:none}a:hover{text-decoration:underline}
.pill{font-size:11px;padding:2px 8px;border-radius:6px;border:1px solid var(--line)}
.ok{color:var(--ok)}.bad{color:var(--warn)}
details{margin:6px 0}summary{cursor:pointer;font-weight:600}
.pivots a{display:inline-block;margin:2px 6px 2px 0;font-size:12px}
input.filter{width:100%;padding:8px 10px;border:1px solid var(--line);
border-radius:8px;background:var(--bg);color:var(--fg);margin-bottom:8px}
footer{color:var(--muted);font-size:12px;margin-top:30px;text-align:center}
code{background:var(--chip);padding:1px 5px;border-radius:5px;font-size:12px}
"""

_LOGO = (
    '<svg class="logo" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">'
    '<circle cx="50" cy="50" r="46" fill="#2563eb"/>'
    '<path d="M50 18 L78 70 L22 70 Z" fill="none" stroke="#fff" '
    'stroke-width="5" stroke-linejoin="round"/>'
    '<circle cx="50" cy="18" r="6" fill="#fde047"/>'
    '<circle cx="78" cy="70" r="6" fill="#22d3ee"/>'
    '<circle cx="22" cy="70" r="6" fill="#22d3ee"/>'
    '</svg>'
)

_JS = """
function vfilter(id,inp){var q=inp.value.toLowerCase();
var rows=document.querySelectorAll('#'+id+' tbody tr');
rows.forEach(function(r){r.style.display=
r.innerText.toLowerCase().indexOf(q)>-1?'':'none';});}
"""


def _score_class(s: float) -> str:
    return "hi" if s >= 5 else ("md" if s >= 2 else "lo")


def render_report(workspace) -> str:
    g = workspace.graph
    surface = build_attack_surface(g)
    meta = workspace.meta
    stats = g.count_by_type()
    chain = workspace.evidence.verify_chain()
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    e = html.escape
    out = ["<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>VÉRTICE — {e(meta.get('name',''))}</title>",
           f"<style>{_CSS}</style></head><body><div class='wrap'>"]

    # header
    out.append("<header class='top'>" + _LOGO +
               f"<div><h1>VÉRTICE — Dossiê de Superfície de Ataque</h1>"
               f"<div class='sub'>Engajamento: <b>{e(meta.get('name',''))}</b> · "
               f"gerado em {gen}</div></div></header>")

    # meta / autorização
    scope = ", ".join(meta.get("scope", [])) or "—"
    out.append("<div class='card'><table><tr><th>Escopo autorizado</th>"
               f"<td><code>{e(scope)}</code></td></tr>"
               f"<tr><th>Autorizado por</th><td>{e(meta.get('authorized_by','—') or '—')}</td></tr>"
               f"<tr><th>Criado</th><td>{e(meta.get('created','—'))}</td></tr>"
               f"<tr><th>Notas</th><td>{e(meta.get('notes','') or '—')}</td></tr>"
               "</table></div>")

    # KPIs
    s = surface["summary"]
    kpis = [("Hosts/domínios", s["hosts"]), ("Vivos (resolvem)", s["live"]),
            ("Com serviços", s["with_services"]),
            ("Alta prioridade", s["high_priority"]),
            ("Nós no grafo", len(g.nodes)), ("Arestas", len(g.edges)),
            ("Evidências", workspace.evidence.count())]
    out.append("<div class='kpis'>")
    for label, n in kpis:
        out.append(f"<div class='kpi'><div class='n'>{n}</div>"
                   f"<div class='l'>{e(label)}</div></div>")
    out.append("</div>")

    # cadeia de custódia
    if chain.get("ok"):
        badge = (f"<span class='pill ok'>✓ íntegra — {chain['records']} "
                 f"registros</span> <code>head: {e(chain['head'][:16])}…</code>")
    else:
        badge = (f"<span class='pill bad'>✗ quebrada no registro "
                 f"{chain.get('broken_at')} — {e(chain.get('reason',''))}</span>")
    out.append(f"<h2>Cadeia de custódia (SHA-256)</h2><div class='card'>{badge}"
               "<div class='sub'>Cada evidência referencia o hash da anterior; "
               "qualquer alteração ou remoção quebra a cadeia.</div></div>")

    # grafo
    out.append("<h2>Grafo de superfície (visão de vínculos)</h2>")
    out.append("<div class='card'>" + render_graph_svg(g) + "</div>")

    # alvos priorizados
    out.append("<h2>Alvos priorizados — preparação de pentest</h2>")
    out.append("<div class='sub'>Pontuação é auxílio de triagem, explicável e "
               "ajustável — não é veredito nem autorização para testar.</div>")
    out.append("<div class='card'>")
    out.append("<input class='filter' placeholder='filtrar alvos…' "
               "oninput=\"vfilter('tgt',this)\">")
    out.append("<div style='max-height:520px;overflow:auto'>"
               "<table id='tgt'><thead><tr><th>Score</th><th>Host</th>"
               "<th>IPs</th><th>Tecnologias</th><th>Serviços</th>"
               "<th>Fontes</th></tr></thead><tbody>")
    for t in surface["targets"]:
        sc = t["score"]
        techs = "".join(f"<span class='chip tech'>{e(x)}</span>"
                        for x in t["technologies"])
        svcs = "".join(f"<span class='chip'>{e(x)}</span>"
                       for x in t["services"]) or "—"
        ips = "<br>".join(e(i) for i in t["ips"]) or "—"
        srcs = "".join(f"<span class='chip'>{e(x)}</span>" for x in t["sources"])
        why = "; ".join(e(w) for w in t["rationale"])
        out.append(
            f"<tr><td class='score {_score_class(sc)}'>{sc}"
            f"<br><span class='sub' style='font-weight:400'>{why}</span></td>"
            f"<td><b>{e(t['host'])}</b></td><td>{ips}</td>"
            f"<td>{techs or '—'}</td><td>{svcs}</td><td>{srcs}</td></tr>")
    out.append("</tbody></table></div></div>")

    # por tecnologia
    if surface["by_technology"]:
        out.append("<h2>Por tecnologia</h2><div class='card'><table>"
                   "<thead><tr><th>Tecnologia</th><th>Hosts</th></tr></thead><tbody>")
        for tech, hosts in sorted(surface["by_technology"].items(),
                                  key=lambda kv: -len(kv[1])):
            out.append(f"<tr><td><b>{e(tech)}</b></td>"
                       f"<td>{len(hosts)} — {e(', '.join(hosts[:12]))}"
                       f"{'…' if len(hosts) > 12 else ''}</td></tr>")
        out.append("</tbody></table></div>")

    # menu de pivô por entidade (Mitaka)
    out.append("<h2>Menu de pivô por entidade (estilo Mitaka)</h2>")
    out.append("<div class='card'>")
    pivotable = [n for n in g.nodes.values()
                 if pivots_for(n)][:60]
    for node in pivotable:
        links = pivots_for(node)
        chips = " ".join(f"<a href='{e(p['url'])}' target='_blank' "
                         f"rel='noopener'>{e(p['service'])}</a>"
                         for p in links)
        out.append(f"<details><summary>{e(node.etype)}: {e(node.value)} "
                   f"<span class='sub'>({len(links)} pivôs)</span></summary>"
                   f"<div class='pivots'>{chips}</div></details>")
    if len(pivotable) == 0:
        out.append("<div class='sub'>Sem entidades pivotáveis.</div>")
    out.append("</div>")

    # e-mails / netblocks
    if surface["emails"] or surface["netblocks"]:
        out.append("<h2>Outros ativos</h2><div class='card'>")
        if surface["emails"]:
            out.append("<b>E-mails:</b> " +
                       " ".join(f"<span class='chip'>{e(x)}</span>"
                                for x in surface["emails"]) + "<br>")
        if surface["netblocks"]:
            out.append("<b>Netblocks:</b> " +
                       " ".join(f"<span class='chip'>{e(x)}</span>"
                                for x in surface["netblocks"]))
        out.append("</div>")

    out.append(f"<footer>VÉRTICE v1.0 · família DEIVOSINT · "
               f"Attack Surface Mapping &amp; Intelligence Gathering<br>"
               f"Coleta passiva por padrão. Use apenas sobre ativos que você "
               f"está autorizado a investigar.</footer>")
    out.append(f"<script>{_JS}</script>")
    out.append("</div></body></html>")
    return "\n".join(out)
