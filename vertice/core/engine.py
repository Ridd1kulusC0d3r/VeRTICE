"""Engine de orquestração (síntese de Amass engine + Recon-ng runner).

O engine:
  1. Percorre uma fila de entidades-semente (BFS até uma profundidade).
  2. Para cada semente, roda os collectors que a aceitam.
  3. Aplica cada Finding ao grafo (nó + aresta, com proveniência) e grava a
     evidência no ledger com custódia SHA-256.
  4. Enfileira os novos nós (respeitando escopo e profundidade).

Regras de segurança/ética embutidas:
  - PASSIVO por padrão: collectors ativos (passive=False) só rodam com
    `allow_active=True` E se a semente estiver no escopo autorizado.
  - Collectors que exigem credencial ausente são pulados silenciosamente.
  - Concorrência leve com threads (stdlib), com teto configurável.
"""
from __future__ import annotations

import concurrent.futures as cf
from typing import Callable, Dict, List, Optional

from ..collectors.base import Collector, Finding, REGISTRY
from .entities import Entity, make
from .workspace import Workspace


class Engine:
    def __init__(self, workspace: Workspace, allow_active: bool = False,
                 max_workers: int = 8,
                 log: Optional[Callable[[str], None]] = None):
        self.ws = workspace
        self.allow_active = allow_active
        self.max_workers = max_workers
        self.log = log or (lambda m: None)
        self.collectors: List[Collector] = self._load_collectors()

    def _load_collectors(self) -> List[Collector]:
        out = []
        for name, cls in sorted(REGISTRY.items()):
            # pula ativos se não autorizado
            if not cls.passive and not self.allow_active:
                continue
            inst = cls(workspace=self.ws)
            # pula se exige credencial ausente
            if cls.needs_cred and not inst.cred():
                self.log(f"[skip] {name}: credencial '{cls.needs_cred}' ausente")
                continue
            out.append(inst)
        return out

    def enabled_collectors(self) -> List[str]:
        return [c.name for c in self.collectors]

    # ------------------------------------------------------------------ #
    def _apply(self, seed: Entity, collector: Collector,
               findings: List[Finding]) -> List[Entity]:
        new_entities: List[Entity] = []
        for f in findings:
            ent = make(f.value, f.etype, source=collector.name, **f.attrs)
            if ent is None:
                continue
            added = self.ws.graph.add_entity(ent)
            if added.key == seed.key:
                # achado sobre a própria semente (ex.: registro TXT): guarda
                # atributo e evidência, sem criar auto-aresta nem reenfileirar.
                for k, v in f.attrs.items():
                    seed.attrs.setdefault(k, v)
                self.ws.evidence.record(
                    collector=collector.name, kind="note", subject=seed.key,
                    data={"rel": f.rel, "attrs": f.attrs, "raw": f.raw})
                continue
            self.ws.graph.link(seed, added, f.rel, source=collector.name)
            # evidência com custódia
            self.ws.evidence.record(
                collector=collector.name, kind="entity",
                subject=added.key,
                data={"from": seed.key, "rel": f.rel,
                      "attrs": f.attrs, "raw": f.raw},
            )
            new_entities.append(added)
        return new_entities

    def _run_collector(self, collector: Collector, seed: Entity):
        try:
            return collector, collector.collect(seed)
        except Exception as exc:  # collectors nunca derrubam o engine
            self.log(f"[erro] {collector.name} em {seed.key}: {exc}")
            return collector, []

    # ------------------------------------------------------------------ #
    def run(self, seeds: List[str], depth: int = 1) -> Dict[str, int]:
        """Executa a investigação a partir das sementes, em BFS até `depth`."""
        # normaliza sementes em entidades
        frontier: List[Entity] = []
        for s in seeds:
            ent = make(s, source="seed")
            if ent:
                self.ws.graph.add_entity(ent)
                self.ws.evidence.record("seed", "entity", ent.key,
                                        {"note": "semente inicial"})
                frontier.append(ent)
            else:
                self.log(f"[aviso] semente não classificada: {s}")

        visited = set()
        stats = {"seeds": len(frontier), "collectors_run": 0, "findings": 0}

        for level in range(depth):
            if not frontier:
                break
            self.log(f"--- nível {level + 1}/{depth} "
                     f"({len(frontier)} entidade(s)) ---")
            next_frontier: List[Entity] = []

            for seed in frontier:
                if seed.key in visited:
                    continue
                visited.add(seed.key)

                applicable = [c for c in self.collectors if c.accepts(seed)]
                # collector ativo só com escopo autorizado
                applicable = [
                    c for c in applicable
                    if c.passive or self.ws.in_scope(seed.value)
                ]
                if not applicable:
                    continue

                with cf.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                    futures = [ex.submit(self._run_collector, c, seed)
                               for c in applicable]
                    for fut in cf.as_completed(futures):
                        collector, findings = fut.result()
                        stats["collectors_run"] += 1
                        if findings:
                            new = self._apply(seed, collector, findings)
                            stats["findings"] += len(new)
                            next_frontier.extend(new)
                            self.log(f"[{collector.name}] {seed.value} "
                                     f"-> {len(new)} achado(s)")

                self.ws.save_graph()  # checkpoint incremental

            frontier = next_frontier

        self.ws.save()
        stats["nodes"] = len(self.ws.graph.nodes)
        stats["edges"] = len(self.ws.graph.edges)
        stats["evidence"] = self.ws.evidence.count()
        return stats
