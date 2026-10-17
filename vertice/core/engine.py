"""Bounded collector orchestration with evidence-linked observations and runs.

v2: além do runner instrumentado (runs/history, captura de requests, max_tasks,
escopo por semente), o engine honra a config do workspace (collectors
`disabled`, `rate_limit_s` por fonte) e grava um snapshot automático ao fim de
cada run — base do diff de superfície.
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import threading
import time
from time import monotonic

from ..collectors.base import REGISTRY
from .. import util
from .entities import make
from .history import start_run, utc


class Engine:
    def __init__(self, workspace, allow_active=False, max_workers=8, log=None,
                 selected=None, max_tasks=200):
        if not 1 <= max_workers <= 32 or max_tasks < 1:
            raise ValueError("workers deve estar entre 1 e 32; "
                             "max_tasks deve ser positivo")
        if allow_active and not workspace.meta.get("scope"):
            raise ValueError("Coleta ativa exige escopo explícito não vazio")
        if selected and set(selected) - REGISTRY.keys():
            raise ValueError("Collector desconhecido: "
                             + ", ".join(set(selected) - REGISTRY.keys()))
        self.ws = workspace
        self.allow_active = allow_active
        self.max_workers = max_workers
        self.max_tasks = max_tasks
        self.selected = set(selected) if selected else None
        self.log = log or (lambda m: None)
        self.skipped = []
        self.run_id = None
        self._cfg = workspace.config()
        self._rate_last = {}
        self._rate_lock = threading.Lock()
        self.collectors = self._load_collectors()

    def _load_collectors(self):
        disabled = set(self._cfg.get("disabled", []))
        out = []
        for name, cls in sorted(REGISTRY.items()):
            if self.selected is not None and name not in self.selected:
                continue
            if name in disabled:
                self.skipped.append({"collector": name, "reason": "disabled_config"})
                self.log(f"[skip] {name}: desabilitado na config")
                continue
            reason = None
            inst = cls(workspace=self.ws)
            if not cls.passive and not self.allow_active:
                reason = "active_disabled"
            elif cls.needs_cred and not inst.cred():
                reason = "missing_credential"
            if reason:
                self.skipped.append({"collector": name, "reason": reason})
                self.log(f"[skip] {name}: {reason}")
            else:
                out.append(inst)
        return out

    def enabled_collectors(self):
        return [c.name for c in self.collectors]

    def _respect_rate(self, name):
        """Intervalo mínimo entre chamadas de um mesmo collector (config)."""
        wait = self._cfg.get("rate_limit_s", {}).get(name, 0)
        if not wait:
            return
        with self._rate_lock:
            delta = time.monotonic() - self._rate_last.get(name, 0.0)
            if delta < wait:
                time.sleep(wait - delta)
            self._rate_last[name] = time.monotonic()

    def _apply(self, seed, collector, findings):
        new_entities = []
        seen = set()
        for f in findings:
            ent = make(f.value, f.etype, source=collector.name, **f.attrs)
            if ent is None:
                continue
            signature = (ent.key, f.rel, json.dumps(f.attrs, sort_keys=True),
                         json.dumps(f.raw, sort_keys=True))
            if signature in seen:
                continue
            seen.add(signature)
            added = self.ws.graph.add_entity(ent)
            collected_at = utc()
            data = {"run_id": self.run_id, "from": seed.key, "rel": f.rel,
                    "attrs": f.attrs, "raw": f.raw,
                    "collected_at": collected_at, "observed_at": f.observed_at}
            evidence_hash = self.ws.evidence.record(
                collector.name, "note" if added.key == seed.key else "entity",
                added.key, data)
            added.attrs.setdefault("first_seen", collected_at)
            added.attrs["last_seen"] = collected_at
            added.attrs["latest_evidence"] = evidence_hash
            if added.key != seed.key:
                edge = self.ws.graph.link(seed, added, f.rel,
                                          source=collector.name)
                edge.attrs.setdefault("first_seen", collected_at)
                edge.attrs["last_seen"] = collected_at
                edge.attrs["latest_evidence"] = evidence_hash
                new_entities.append(added)
        return new_entities

    def _run_collector(self, collector, seed):
        started = monotonic()
        error = None
        self._respect_rate(collector.name)
        with util.capture_requests() as requests:
            try:
                findings = collector.collect(seed)
            except Exception as exc:
                error = type(exc).__name__
                findings = []
        failures = any(r["error"] or r["truncated"] for r in requests)
        status = ("partial" if findings else "error") if error or failures else (
            "success" if findings else "empty")
        return collector, findings, {
            "status": status, "error": error,
            "duration_ms": round((monotonic() - started) * 1000),
            "requests": requests}

    def run(self, seeds, depth=1):
        if not 1 <= depth <= 5:
            raise ValueError("depth deve estar entre 1 e 5")
        self.run_id = start_run(self.ws, seeds, self.enabled_collectors(),
                                depth, self.allow_active)
        stats = {"run_id": self.run_id, "seed_count": 0, "collectors_run": 0,
                 "findings": 0, "errors": 0, "partial": 0,
                 "skipped_scope": 0, "limited": False}
        self.ws.evidence.record("engine", "run-config", self.run_id,
                                {"run_id": self.run_id, "skipped": self.skipped,
                                 "max_tasks": self.max_tasks})
        frontier = []
        for value in seeds:
            ent = make(value, source="seed")
            if ent is None:
                raise ValueError("Semente não classificada: " + value)
            if self.ws.meta.get("scope") and not self.ws.in_scope(ent.value):
                stats["skipped_scope"] += 1
                continue
            self.ws.graph.add_entity(ent)
            self.ws.evidence.record("seed", "entity", ent.key,
                                    {"run_id": self.run_id,
                                     "note": "semente inicial"})
            frontier.append(ent)
        stats["seed_count"] = len(frontier)
        visited = set()
        for _ in range(depth):
            next_frontier = []
            for seed in frontier:
                if seed.key in visited:
                    continue
                visited.add(seed.key)
                if self.ws.meta.get("scope") and not self.ws.in_scope(seed.value):
                    stats["skipped_scope"] += 1
                    continue
                applicable = [c for c in self.collectors if c.accepts(seed)
                              and (c.passive or self.ws.in_scope(seed.value))]
                remaining = self.max_tasks - stats["collectors_run"]
                if len(applicable) > remaining:
                    stats["limited"] = True
                    applicable = applicable[:remaining]
                with cf.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                    futures = [pool.submit(self._run_collector, c, seed)
                               for c in applicable]
                    for future in cf.as_completed(futures):
                        collector, findings, result = future.result()
                        stats["collectors_run"] += 1
                        for request in result.pop("requests"):
                            self.ws.evidence.record(
                                collector.name, "raw", seed.key,
                                {"run_id": self.run_id, "collected_at": utc(),
                                 **request})
                        stats["errors"] += result["status"] == "error"
                        stats["partial"] += result["status"] == "partial"
                        self.ws.evidence.record(
                            collector.name, "collection", seed.key,
                            {"run_id": self.run_id,
                             "finding_count": len(findings), **result})
                        new = self._apply(seed, collector, findings)
                        stats["findings"] += len(new)
                        next_frontier.extend(new)
                        self.log(f"[{collector.name}] {seed.value}: "
                                 f"{result['status']} ({len(new)})")
                self.ws.save_graph()
            frontier = next_frontier
            if not frontier or stats["limited"]:
                break
        stats.update(nodes=len(self.ws.graph.nodes),
                     edges=len(self.ws.graph.edges))
        status = "partial" if (stats["errors"] or stats["partial"]
                               or stats["limited"] or stats["skipped_scope"]
                               or (self.selected and self.skipped)) else "completed"
        self.ws.evidence.record("engine", "run-end", self.run_id,
                                {**stats, "status": status,
                                 "finished_at": utc()})
        self.ws.save()
        # snapshot automático: permite diff de superfície entre execuções
        stats["snapshot"] = self.ws.save_snapshot(label="run")
        stats["evidence"] = self.ws.evidence.count()
        return stats
