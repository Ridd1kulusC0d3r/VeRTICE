"""Camada de inteligência de dados do VÉRTICE (v2).

Três capacidades que elevam a coleta a inteligência:

  1. surface_diff(old, new)  — o que mudou na superfície entre dois snapshots
     (entidades/arestas adicionadas, removidas, e nós reafirmados). É a base da
     detecção de mudança: subdomínio novo, serviço que sumiu, tech trocada.

  2. correlate(graph)        — clusters de ativos que pertencem ao mesmo dono
     por pistas compartilhadas: mesmo IP, mesmo ASN/netblock, mesmo favicon,
     mesma organização de certificado. Ideia do pivô FOFA/Censys, aplicada
     sobre o grafo já coletado.

  3. risk_signals(graph, host_key) — sinais de risco de um host (vulns, portas,
     postura, tech), usados pelo scoring v2 do pentest_prep.

Tudo determinístico e explicável; nada aqui "adivinha".
Stdlib-only.
"""
from __future__ import annotations

from typing import Dict, List

from .entities import (T_HOST, T_DOMAIN, T_IP, T_ASN, T_NETBLOCK, T_TECH,
                       T_SERVICE, T_PORT, T_VULN, T_FAVICON, T_CERT, T_FINDING,
                       T_CPE)


# --------------------------------------------------------------------------- #
# 1. Diff de superfície
# --------------------------------------------------------------------------- #
def surface_diff(old_graph, new_graph) -> Dict:
    """Compara dois grafos (snapshots) e devolve as diferenças."""
    old_nodes = set(old_graph.nodes)
    new_nodes = set(new_graph.nodes)
    old_edges = set(old_graph.edges)
    new_edges = set(new_graph.edges)

    added = sorted(new_nodes - old_nodes)
    removed = sorted(old_nodes - new_nodes)
    kept = new_nodes & old_nodes

    # nós reafirmados cujos atributos relevantes mudaram
    changed = []
    for key in sorted(kept):
        o, n = old_graph.nodes[key], new_graph.nodes[key]
        if o.sources != n.sources or o.attrs != n.attrs:
            changed.append({
                "key": key,
                "sources_added": sorted(n.sources - o.sources),
                "attrs_changed": {k: n.attrs[k] for k in n.attrs
                                  if o.attrs.get(k) != n.attrs[k]},
            })

    def _by_type(keys):
        out: Dict[str, int] = {}
        for k in keys:
            t = k.split(":", 1)[0]
            out[t] = out.get(t, 0) + 1
        return out

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "added_edges": [list(e) for e in sorted(new_edges - old_edges)],
        "removed_edges": [list(e) for e in sorted(old_edges - new_edges)],
        "summary": {
            "added": len(added), "removed": len(removed),
            "changed": len(changed),
            "added_by_type": _by_type(added),
            "removed_by_type": _by_type(removed),
        },
    }


# --------------------------------------------------------------------------- #
# 2. Correlação / clusters
# --------------------------------------------------------------------------- #
def correlate(graph) -> Dict[str, List[Dict]]:
    """Agrupa hosts por pistas compartilhadas (co-hospedagem, ASN, favicon, cert)."""
    def hosts_linked_to(pivot_key: str) -> List[str]:
        hs = []
        for src, _ in graph.neighbors_in(pivot_key):
            node = graph.nodes.get(src)
            if node and node.etype in (T_HOST, T_DOMAIN):
                hs.append(node.value)
        for dst, _ in graph.neighbors(pivot_key):
            node = graph.nodes.get(dst)
            if node and node.etype in (T_HOST, T_DOMAIN):
                hs.append(node.value)
        return sorted(set(hs))

    clusters = {"by_ip": [], "by_netblock": [], "by_asn": [],
                "by_favicon": [], "by_cert_org": []}
    mapping = {"by_ip": T_IP, "by_netblock": T_NETBLOCK, "by_asn": T_ASN,
               "by_favicon": T_FAVICON}
    for bucket, etype in mapping.items():
        for piv in graph.entities(etype):
            hs = hosts_linked_to(piv.key)
            if len(hs) >= 2:
                clusters[bucket].append({"pivot": piv.value, "hosts": hs,
                                         "count": len(hs)})
        clusters[bucket].sort(key=lambda c: -c["count"])
    return clusters


# --------------------------------------------------------------------------- #
# 3. Sinais de risco por host (para o scoring v2)
# --------------------------------------------------------------------------- #
def risk_signals(graph, host_key: str) -> Dict:
    sig = {"vulns": [], "ports": [], "cpes": [], "posture": [],
           "resolves": False, "has_service": False}
    # vulns/ports podem estar no host ou nos IPs que ele resolve
    related = [host_key]
    for dst, label in graph.neighbors(host_key):
        node = graph.nodes.get(dst)
        if not node:
            continue
        if node.etype == T_IP and label == "resolves-to":
            sig["resolves"] = True
            related.append(dst)
    for rk in related:
        for dst, _ in graph.neighbors(rk):
            node = graph.nodes.get(dst)
            if not node:
                continue
            if node.etype == T_VULN:
                sig["vulns"].append(node.value)
            elif node.etype in (T_PORT, T_SERVICE):
                sig["ports"].append(node.value)
                sig["has_service"] = True
            elif node.etype == T_CPE:
                sig["cpes"].append(node.value)
            elif node.etype == T_FINDING:
                sev = node.attrs.get("severity", "")
                sig["posture"].append({"finding": node.value, "severity": sev})
    for k in ("vulns", "ports", "cpes"):
        sig[k] = sorted(set(sig[k]))
    return sig
