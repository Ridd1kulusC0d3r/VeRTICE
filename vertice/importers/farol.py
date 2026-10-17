"""Importador do FAROL (JSONL) — "dentro do host" para dentro do grafo.

O FAROL (irmão em Go do VÉRTICE, recriação modernizada do Photon) varre um host
e emite JSONL, uma linha por achado, com SHA-256 por resposta. O VÉRTICE lê esse
JSONL e costura cada achado ao host correspondente no grafo:

  endpoint/url     -> T_ENDPOINT ligado ao host (rel: has-endpoint)
  param            -> T_PARAM    ligado ao endpoint/host (rel: has-parameter)
  form             -> T_FORM     ligado ao host (rel: has-form)
  email            -> T_EMAIL    ligado ao host (rel: mentions-email)
  secret           -> T_SECRET   ligado ao host (rel: possible-secret) — rótulo,
                                  nunca o valor do segredo
  js/script        -> T_ENDPOINT (rel: loads-script)

Formato aceito (tolerante): cada linha é um objeto JSON com ao menos:
  {"type": "...", "host": "...", "value": "...", ...}
Campos alternativos comuns também são aceitos (url, endpoint, param, email...).

Cada achado vira uma evidência selada no ledger (collector="farol").
Stdlib-only.
"""
from __future__ import annotations

import json
from typing import Dict

from ..core.entities import (make, T_HOST, T_ENDPOINT, T_PARAM, T_FORM,
                             T_EMAIL, T_SECRET, T_URL, classify)

# mapeia o "type" do FAROL -> (etype no VÉRTICE, rótulo da aresta)
_MAP = {
    "endpoint": (T_ENDPOINT, "has-endpoint"),
    "url": (T_ENDPOINT, "has-endpoint"),
    "link": (T_ENDPOINT, "has-endpoint"),
    "js": (T_ENDPOINT, "loads-script"),
    "script": (T_ENDPOINT, "loads-script"),
    "param": (T_PARAM, "has-parameter"),
    "parameter": (T_PARAM, "has-parameter"),
    "form": (T_FORM, "has-form"),
    "email": (T_EMAIL, "mentions-email"),
    "secret": (T_SECRET, "possible-secret"),
    "key": (T_SECRET, "possible-secret"),
}


def _value(rec: Dict) -> str:
    for k in ("value", "url", "endpoint", "param", "parameter", "email",
              "name", "secret", "data"):
        if rec.get(k):
            return str(rec[k])
    return ""


def _host(rec: Dict) -> str:
    for k in ("host", "source", "domain", "target", "page"):
        if rec.get(k):
            return str(rec[k])
    return ""


def import_farol_jsonl(workspace, path: str) -> Dict[str, int]:
    """Importa um arquivo JSONL do FAROL para o workspace. Devolve contadores."""
    g = workspace.graph
    stats = {"lines": 0, "imported": 0, "skipped": 0, "secrets_label_only": 0}

    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            stats["lines"] += 1
            try:
                rec = json.loads(line)
            except ValueError:
                stats["skipped"] += 1
                continue

            rtype = str(rec.get("type", "")).lower()
            etype, rel = _MAP.get(rtype, (None, None))
            value = _value(rec)
            host = _host(rec)
            if not value and rtype != "secret":
                stats["skipped"] += 1
                continue

            # host-âncora: liga o achado ao host que o FAROL varreu
            host_ent = None
            if host and classify(host) in (T_HOST, None):
                host_ent = g.add(host, T_HOST, source="farol")

            # SEGREDO: nunca guardamos o valor — só um rótulo redigido e o tipo.
            if etype == T_SECRET:
                kind = rec.get("kind") or rec.get("rule") or "secret"
                label = f"segredo:{kind}@{host or 'host'}"
                sec = g.add(label, T_SECRET, source="farol",
                            kind=str(kind), redacted=True)
                if host_ent and sec:
                    g.link(host_ent, sec, rel, source="farol")
                workspace.evidence.record(
                    "farol", "entity", sec.key if sec else label,
                    {"from": host, "kind": str(kind), "note": "valor redigido"})
                stats["secrets_label_only"] += 1
                stats["imported"] += 1
                continue

            if etype is None:
                # tipo desconhecido: tenta classificar o valor sozinho
                ent = g.add(value, source="farol")
            else:
                ent = g.add(value, etype, source="farol")
            if ent is None:
                stats["skipped"] += 1
                continue

            if host_ent and ent and host_ent.key != ent.key:
                g.link(host_ent, ent, rel or "related-to", source="farol")
            workspace.evidence.record(
                "farol", "entity", ent.key,
                {"from": host, "type": rtype, "raw": rec.get("meta", {})})
            stats["imported"] += 1

    workspace.save()
    workspace.save_snapshot(label="farol-import")
    return stats
