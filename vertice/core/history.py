"""Per-run observations and conservative comparisons (stdlib SQLite)."""
import json
import uuid
from datetime import datetime, timezone


def utc():
    return datetime.now(timezone.utc).isoformat()


def start_run(ws, seeds, collectors, depth, active):
    run_id = uuid.uuid4().hex
    ws.evidence.record("engine", "run-start", run_id, {
        "run_id": run_id, "seeds": sorted(seeds), "collectors": sorted(collectors),
        "depth": depth, "active": active, "collected_at": utc(),
    })
    return run_id


def runs(ws):
    result = {}
    for row in ws.evidence.all():
        if row["kind"] not in ("run-start", "run-end"):
            continue
        data = json.loads(row["data"])
        rid = data["run_id"]
        result.setdefault(rid, {"run_id": rid, "status": "interrupted"}).update(data)
    return list(result.values())


def observations(ws, run_id):
    result = {}
    for row in ws.evidence.all():
        if row["kind"] not in ("entity", "note"):
            continue
        data = json.loads(row["data"])
        if data.get("run_id") != run_id:
            continue
        key = (data.get("from", row["subject"]), row["subject"],
               data.get("rel", "seed"), row["collector"])
        signature = json.dumps(data.get("attrs", {}), sort_keys=True)
        result.setdefault(key, set()).add(signature)
    return result


def compare(ws, before, after):
    history = {r["run_id"]: r for r in runs(ws)}
    if before not in history or after not in history:
        raise ValueError("Execução não encontrada; consulte 'vertice runs'.")
    a, b = observations(ws, before), observations(ws, after)
    fields = ("seeds", "collectors", "depth", "active")
    comparable = all(history[before].get(f) == history[after].get(f) for f in fields)
    comparable = comparable and all(history[r].get("status") == "completed"
                                    for r in (before, after))
    def rows(keys):
        return [{"from": k[0], "subject": k[1], "relation": k[2], "source": k[3]}
                for k in sorted(keys)]
    return {"before": before, "after": after, "comparable": comparable,
            "new_observations": rows(b.keys() - a.keys()),
            "not_reobserved": rows(a.keys() - b.keys()),
            "changed": rows(k for k in a.keys() & b.keys() if a[k] != b[k]),
            "note": "Não reobservado não significa removido. Compare cobertura, "
                    "falhas e datas das fontes; o grafo mantém o histórico."}
