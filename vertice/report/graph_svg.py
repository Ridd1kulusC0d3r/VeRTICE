"""Renderizador de grafo em SVG puro (visão Maltego, stdlib-only).

Layout radial determinístico: entidades agrupadas por tipo em anéis
concêntricos, arestas desenhadas como linhas. Sem bibliotecas — SVG gerado por
string. Legível em tema claro e escuro (usa cores próprias com bom contraste).
"""
from __future__ import annotations

import html
import math
from typing import Dict, List

from ..core.entities import (T_DOMAIN, T_HOST, T_IP, T_ASN, T_NETBLOCK,
                             T_EMAIL, T_URL, T_CERT, T_FAVICON, T_TECH,
                             T_SERVICE, T_ORG, T_PERSON)

# Paleta por tipo (DEIVOSINT azul + apoio). Contraste alto.
_COLORS = {
    T_DOMAIN: "#2563eb", T_HOST: "#0891b2", T_IP: "#16a34a",
    T_ASN: "#9333ea", T_NETBLOCK: "#7c3aed", T_EMAIL: "#db2777",
    T_URL: "#0d9488", T_CERT: "#ca8a04", T_FAVICON: "#c2410c",
    T_TECH: "#ea580c", T_SERVICE: "#dc2626", T_ORG: "#4f46e5",
    T_PERSON: "#be123c",
}
_DEFAULT_COLOR = "#64748b"

# Ordem dos anéis (centro -> fora)
_RING_ORDER = [T_DOMAIN, T_HOST, T_IP, T_SERVICE, T_TECH, T_NETBLOCK, T_ASN,
               T_ORG, T_EMAIL, T_URL, T_FAVICON, T_CERT, T_PERSON]


def render_graph_svg(graph, width: int = 1100, height: int = 820,
                     max_nodes: int = 220) -> str:
    nodes = list(graph.nodes.values())
    # limita para legibilidade: prioriza tipos estruturais
    if len(nodes) > max_nodes:
        prio = {t: i for i, t in enumerate(_RING_ORDER)}
        nodes.sort(key=lambda n: prio.get(n.etype, 99))
        nodes = nodes[:max_nodes]
    keep = {n.key for n in nodes}

    cx, cy = width / 2, height / 2
    by_type: Dict[str, List] = {}
    for n in nodes:
        by_type.setdefault(n.etype, []).append(n)

    pos: Dict[str, tuple] = {}
    rings = [t for t in _RING_ORDER if t in by_type]
    rings += [t for t in by_type if t not in _RING_ORDER]
    max_r = min(width, height) / 2 - 60

    for ri, etype in enumerate(rings):
        group = by_type[etype]
        r = 0 if (ri == 0 and len(group) == 1) else \
            max_r * (ri + 1) / (len(rings) + 0.5)
        count = len(group)
        for i, node in enumerate(group):
            if r == 0:
                pos[node.key] = (cx, cy)
            else:
                ang = 2 * math.pi * i / max(count, 1) + ri * 0.4
                pos[node.key] = (cx + r * math.cos(ang),
                                 cy + r * math.sin(ang))

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" style="max-width:{width}px;font-family:system-ui,'
        f'sans-serif;background:transparent">',
        '<rect width="100%" height="100%" fill="none"/>',
    ]

    # arestas
    for e in graph.edges.values():
        if e.src not in keep or e.dst not in keep:
            continue
        if e.src not in pos or e.dst not in pos:
            continue
        x1, y1 = pos[e.src]
        x2, y2 = pos[e.dst]
        parts.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="#94a3b8" stroke-width="0.7" stroke-opacity="0.45"/>')

    # nós
    for node in nodes:
        if node.key not in pos:
            continue
        x, y = pos[node.key]
        color = _COLORS.get(node.etype, _DEFAULT_COLOR)
        rad = 7 if node.etype in (T_DOMAIN,) else 5
        label = node.value if len(node.value) <= 28 else node.value[:26] + "…"
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{rad}" fill="{color}" '
            f'stroke="#ffffff" stroke-width="1"><title>'
            f'{html.escape(node.etype)}: {html.escape(node.value)}</title>'
            f'</circle>')
        parts.append(
            f'<text x="{x + rad + 2:.1f}" y="{y + 3:.1f}" font-size="9" '
            f'fill="#334155">{html.escape(label)}</text>')

    # legenda
    ly = 20
    parts.append(f'<g transform="translate(16,16)">')
    for etype in rings:
        c = _COLORS.get(etype, _DEFAULT_COLOR)
        parts.append(
            f'<circle cx="6" cy="{ly - 4}" r="5" fill="{c}"/>'
            f'<text x="18" y="{ly}" font-size="11" fill="#334155">'
            f'{html.escape(etype)} ({len(by_type[etype])})</text>')
        ly += 18
    parts.append('</g>')

    parts.append('</svg>')
    return "\n".join(parts)
