"""Exportadores do VÉRTICE (v2) — leva a superfície para outros formatos/ferramentas.

Formatos:
  - jsonl   : uma entidade por linha (consumo por pipelines de dados)
  - csv     : entidades tabulares (tipo, valor, fontes, confiança, first/last seen)
  - stix    : STIX 2.1 bundle (observed-data/indicator básicos) p/ plataformas CTI
  - targets : hosts vivos, um por linha
  - nmap    : arquivo -iL com hosts vivos (pronto para `nmap -iL`)
  - httpx   : URLs http/https dos hosts vivos (pronto para `httpx -l`)

Nenhuma dependência externa. STIX é montado como JSON conforme a spec 2.1
(tipos `bundle`, `observed-data`, `indicator`), suficiente para ingestão.
"""
from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List

from ..core.entities import (T_HOST, T_DOMAIN, T_IP, T_EMAIL, T_URL, T_VULN)
from .pentest_prep import build_attack_surface


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def to_jsonl(graph) -> str:
    out = []
    for e in graph.nodes.values():
        out.append(json.dumps(e.to_dict(), ensure_ascii=False))
    return "\n".join(out) + ("\n" if out else "")


def to_csv(graph) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["etype", "value", "sources", "confidence",
                "first_seen", "last_seen"])
    for e in sorted(graph.nodes.values(), key=lambda n: (n.etype, n.value)):
        w.writerow([e.etype, e.value, "|".join(sorted(e.sources)),
                    e.confidence, e.first_seen, e.last_seen])
    return buf.getvalue()


# mapeia tipo VÉRTICE -> padrão de valor STIX Indicator
_STIX_PATTERN = {
    T_DOMAIN: lambda v: f"[domain-name:value = '{v}']",
    T_HOST: lambda v: f"[domain-name:value = '{v}']",
    T_IP: lambda v: f"[ipv4-addr:value = '{v}']",
    T_EMAIL: lambda v: f"[email-addr:value = '{v}']",
    T_URL: lambda v: f"[url:value = '{v}']",
}


def to_stix(graph, name: str = "VÉRTICE") -> str:
    """STIX 2.1 bundle com indicators para as entidades mapeáveis."""
    now = _utc()
    objects: List[Dict] = [{
        "type": "identity", "spec_version": "2.1",
        "id": f"identity--{uuid.uuid4()}", "created": now, "modified": now,
        "name": name, "identity_class": "system",
    }]
    ident_id = objects[0]["id"]
    for e in graph.nodes.values():
        patt = _STIX_PATTERN.get(e.etype)
        if not patt:
            continue
        val = e.value.replace("'", "\\'")
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now, "modified": now,
            "created_by_ref": ident_id,
            "name": f"{e.etype}: {e.value}",
            "pattern": patt(val), "pattern_type": "stix",
            "valid_from": e.first_seen or now,
            "labels": sorted(e.sources) or ["osint"],
            "confidence": int(round(e.confidence * 100)),
        })
    # vulnerabilidades como objetos 'vulnerability'
    for e in graph.entities(T_VULN):
        objects.append({
            "type": "vulnerability", "spec_version": "2.1",
            "id": f"vulnerability--{uuid.uuid4()}",
            "created": now, "modified": now, "created_by_ref": ident_id,
            "name": e.value,
            "external_references": [{"source_name": "cve", "external_id": e.value}],
        })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
              "objects": objects}
    return json.dumps(bundle, indent=2, ensure_ascii=False)


def to_targets(graph) -> str:
    surface = build_attack_surface(graph)
    return "\n".join(surface["live_hosts"]) + ("\n" if surface["live_hosts"] else "")


def to_nmap_list(graph) -> str:
    """Hosts vivos + IPs, deduplicados, para `nmap -iL`."""
    surface = build_attack_surface(graph)
    items = set(surface["live_hosts"])
    for t in surface["targets"]:
        items.update(t["ips"])
    return "\n".join(sorted(items)) + ("\n" if items else "")


def to_httpx_list(graph) -> str:
    """URLs http/https dos hosts vivos, para `httpx -l`."""
    surface = build_attack_surface(graph)
    lines = []
    for h in surface["live_hosts"]:
        lines.append(f"https://{h}")
        lines.append(f"http://{h}")
    return "\n".join(lines) + ("\n" if lines else "")


EXPORTERS = {
    "jsonl": to_jsonl, "csv": to_csv, "stix": to_stix,
    "targets": to_targets, "nmap": to_nmap_list, "httpx": to_httpx_list,
}


def export(graph, fmt: str) -> str:
    fn = EXPORTERS.get(fmt)
    if not fn:
        raise ValueError(f"formato desconhecido: {fmt} "
                         f"(use: {', '.join(EXPORTERS)})")
    return fn(graph)
