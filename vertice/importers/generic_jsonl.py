"""Importador JSONL genérico — F.I.O. / GARIMPO / PRISMA e afins.

As ferramentas irmãs da família DEIVOSINT já emitem achados estruturados. Este
importador aceita um JSONL simples e plugável onde cada linha descreve uma
entidade e, opcionalmente, um vínculo:

  {"value": "...", "type": "domain|ip|email|...",      # type opcional (auto)
   "link_to": "...", "rel": "resolves-to",             # vínculo opcional
   "attrs": {...}}                                      # atributos opcionais

Se `type` faltar, o valor é classificado automaticamente. Se `link_to` existir,
cria a aresta (classificando o destino também). Cada linha vira evidência
selada (collector = o nome passado, ex.: "fio", "garimpo", "prisma").

Stdlib-only.
"""
from __future__ import annotations

import json
from typing import Dict, Optional

from ..core.entities import make, classify


def import_generic_jsonl(workspace, path: str,
                         source: str = "import") -> Dict[str, int]:
    g = workspace.graph
    stats = {"lines": 0, "imported": 0, "edges": 0, "skipped": 0}

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

            value = rec.get("value") or rec.get("v")
            if not value:
                stats["skipped"] += 1
                continue
            etype = rec.get("type") or rec.get("etype")
            attrs = rec.get("attrs", {}) if isinstance(rec.get("attrs"), dict) else {}
            ent = g.add(str(value), etype, source=source, **attrs)
            if ent is None:
                stats["skipped"] += 1
                continue
            workspace.evidence.record(source, "entity", ent.key,
                                      {"raw": rec})
            stats["imported"] += 1

            link_to = rec.get("link_to") or rec.get("to")
            if link_to:
                dst = g.add(str(link_to), source=source)
                if dst and dst.key != ent.key:
                    g.link(ent, dst, rec.get("rel", "related-to"),
                           source=source)
                    stats["edges"] += 1

    workspace.save()
    workspace.save_snapshot(label=f"{source}-import")
    return stats
