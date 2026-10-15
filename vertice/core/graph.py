"""Grafo de investigação do VÉRTICE (padrão Maltego/Amass).

Grafo dirigido de entidades tipadas conectadas por arestas rotuladas. É o
estado central da investigação: collectors agem como "transforms" que
adicionam nós e arestas.

Stdlib-only; serializa/deserializa em JSON.
"""
from __future__ import annotations

import json
from typing import Dict, Iterable, List, Optional, Tuple

from .entities import Entity, make, normalize, classify


class Edge:
    __slots__ = ("src", "dst", "label", "sources", "attrs")

    def __init__(self, src: str, dst: str, label: str,
                 source: Optional[str] = None, **attrs):
        self.src = src
        self.dst = dst
        self.label = label
        self.sources = set()
        if source:
            self.sources.add(source)
        self.attrs = dict(attrs)

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.src, self.dst, self.label)

    def to_dict(self) -> dict:
        return {
            "src": self.src, "dst": self.dst, "label": self.label,
            "sources": sorted(self.sources), "attrs": self.attrs,
        }


class Graph:
    """Nós (entidades, por `key`) + arestas rotuladas, com proveniência."""

    def __init__(self):
        self.nodes: Dict[str, Entity] = {}
        self.edges: Dict[Tuple[str, str, str], Edge] = {}

    # --- nós ------------------------------------------------------------- #
    def add_entity(self, entity: Optional[Entity]) -> Optional[Entity]:
        if entity is None:
            return None
        existing = self.nodes.get(entity.key)
        if existing:
            existing.sources |= entity.sources
            for k, v in entity.attrs.items():
                existing.attrs.setdefault(k, v)
            return existing
        self.nodes[entity.key] = entity
        return entity

    def add(self, value: str, etype: Optional[str] = None,
            source: Optional[str] = None, **attrs) -> Optional[Entity]:
        return self.add_entity(make(value, etype, source, **attrs))

    def get(self, value: str, etype: Optional[str] = None) -> Optional[Entity]:
        etype = etype or classify(value)
        if etype is None:
            return None
        return self.nodes.get(f"{etype}:{normalize(value, etype)}")

    # --- arestas --------------------------------------------------------- #
    def link(self, src: Entity, dst: Entity, label: str,
             source: Optional[str] = None, **attrs) -> Optional[Edge]:
        if src is None or dst is None:
            return None
        e = Edge(src.key, dst.key, label, source, **attrs)
        existing = self.edges.get(e.key)
        if existing:
            existing.sources |= e.sources
            return existing
        self.edges[e.key] = e
        return e

    # --- consultas ------------------------------------------------------- #
    def entities(self, etype: Optional[str] = None) -> List[Entity]:
        if etype is None:
            return list(self.nodes.values())
        return [e for e in self.nodes.values() if e.etype == etype]

    def neighbors(self, key: str) -> List[Tuple[str, str]]:
        """Devolve (key_vizinho, rótulo) para arestas que saem de `key`."""
        return [(e.dst, e.label) for e in self.edges.values() if e.src == key]

    def count_by_type(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for e in self.nodes.values():
            out[e.etype] = out.get(e.etype, 0) + 1
        return out

    # --- serialização ---------------------------------------------------- #
    def to_dict(self) -> dict:
        return {
            "nodes": [e.to_dict() for e in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
            "stats": self.count_by_type(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> "Graph":
        g = cls()
        for nd in data.get("nodes", []):
            ent = Entity(value=nd["value"], etype=nd["etype"],
                         attrs=nd.get("attrs", {}),
                         sources=set(nd.get("sources", [])))
            g.nodes[ent.key] = ent
        for ed in data.get("edges", []):
            edge = Edge(ed["src"], ed["dst"], ed["label"])
            edge.sources = set(ed.get("sources", []))
            edge.attrs = ed.get("attrs", {})
            g.edges[edge.key] = edge
        return g
