"""Workspace de engajamento (padrão Recon-ng).

Cada investigação é um diretório isolado com:
  - graph.json        : o grafo da investigação (persistido)
  - evidence.db       : o ledger de evidências (custódia SHA-256)
  - credentials.json  : chaves de API dos conectores opcionais (fora do código)
  - meta.json         : metadados do engajamento (escopo, autorização, datas)

Stdlib-only. Nenhuma credencial fica no código: tudo vem daqui.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .graph import Graph
from .evidence import EvidenceLedger


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


class Workspace:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        os.makedirs(self.path, exist_ok=True)
        self.graph_path = os.path.join(self.path, "graph.json")
        self.evidence_path = os.path.join(self.path, "evidence.db")
        self.cred_path = os.path.join(self.path, "credentials.json")
        self.meta_path = os.path.join(self.path, "meta.json")
        self.config_path = os.path.join(self.path, "config.json")
        self.snapshots_dir = os.path.join(self.path, "snapshots")
        os.makedirs(self.snapshots_dir, exist_ok=True)
        self.graph = self._load_graph()
        self.evidence = EvidenceLedger(self.evidence_path)
        self.meta = self._load_meta()

    # ------------------------------------------------------------------ #
    @classmethod
    def create(cls, path: str, name: str, scope: List[str],
               authorized_by: str = "", notes: str = "") -> "Workspace":
        ws = cls(path)
        ws.meta.update({
            "name": name,
            "scope": scope,              # domínios/IPs no escopo autorizado
            "authorized_by": authorized_by,
            "notes": notes,
            "created": _utc(),
        })
        ws.save_meta()
        return ws

    # ------------------------------------------------------------------ #
    def _load_graph(self) -> Graph:
        if os.path.exists(self.graph_path):
            with open(self.graph_path, encoding="utf-8") as fh:
                return Graph.from_dict(json.load(fh))
        return Graph()

    def save_graph(self):
        self._atomic_write(self.graph_path, self.graph.to_json())

    @staticmethod
    def _atomic_write(path, content):
        fd, temporary = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".vertice-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _load_meta(self) -> Dict:
        if os.path.exists(self.meta_path):
            with open(self.meta_path, encoding="utf-8") as fh:
                return json.load(fh)
        return {"name": os.path.basename(self.path), "scope": [],
                "created": _utc()}

    def save_meta(self):
        with open(self.meta_path, "w", encoding="utf-8") as fh:
            json.dump(self.meta, fh, indent=2, ensure_ascii=False)

    # --- credenciais dos conectores opcionais -------------------------- #
    def credentials(self) -> Dict[str, str]:
        if os.path.exists(self.cred_path):
            with open(self.cred_path, encoding="utf-8") as fh:
                return json.load(fh)
        return {}

    def get_credential(self, name: str) -> Optional[str]:
        return self.credentials().get(name)

    def set_credential(self, name: str, value: str):
        creds = self.credentials()
        creds[name] = value
        with open(self.cred_path, "w", encoding="utf-8") as fh:
            json.dump(creds, fh, indent=2, ensure_ascii=False)
        try:
            os.chmod(self.cred_path, 0o600)  # best-effort: só o dono lê
        except OSError:
            pass

    # --- escopo (gate de autorização) ---------------------------------- #
    def in_scope(self, value: str) -> bool:
        """Explicit domain/IP/CIDR scope; empty scope never authorizes a target.

        Domain scope covers its subdomains, never the IP they resolve to.
        URL scope uses only its hostname. No network lookup is performed.
        """
        import ipaddress
        from urllib.parse import urlsplit
        from .entities import normalize
        scope = self.meta.get("scope") or []
        v = urlsplit(value).hostname if "://" in value else value
        if not v:
            return False
        v = normalize(v).lower().rstrip(".")
        try:
            address = ipaddress.ip_address(v)
        except ValueError:
            address = None
        for item in scope:
            item = item.strip().lower().rstrip(".")
            if address is not None:
                try:
                    if address in ipaddress.ip_network(item, strict=False):
                        return True
                except ValueError:
                    continue
            else:
                try:
                    ipaddress.ip_network(item, strict=False)
                    continue  # an IP scope is never a domain suffix
                except ValueError:
                    pass
                if "/" not in item and (v == item or v.endswith("." + item)):
                    return True
        return False

    # --- config de collectors (enable/disable, pesos, rate-limit) ------ #
    def config(self) -> Dict:
        if os.path.exists(self.config_path):
            with open(self.config_path, encoding="utf-8") as fh:
                return json.load(fh)
        return {"disabled": [], "rate_limit_s": {}, "weights": {}}

    def save_config(self, cfg: Dict):
        with open(self.config_path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2, ensure_ascii=False)

    # --- snapshots (para diff de superfície) --------------------------- #
    def save_snapshot(self, label: Optional[str] = None) -> str:
        """Congela o grafo atual num snapshot timestampado. Devolve o nome."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe = "".join(c for c in (label or "snap")
                       if c.isalnum() or c in "-_")[:40]
        name = f"{ts}_{safe}.json"
        with open(os.path.join(self.snapshots_dir, name), "w",
                  encoding="utf-8") as fh:
            fh.write(self.graph.to_json())
        return name

    def list_snapshots(self) -> List[str]:
        if not os.path.isdir(self.snapshots_dir):
            return []
        return sorted(f for f in os.listdir(self.snapshots_dir)
                      if f.endswith(".json"))

    def load_snapshot(self, name: str) -> Graph:
        with open(os.path.join(self.snapshots_dir, name), encoding="utf-8") as fh:
            return Graph.from_dict(json.load(fh))

    def save(self):
        self.save_graph()
        self.save_meta()

    def close(self, save=True):
        if save:
            self.save()
        self.evidence.close()
