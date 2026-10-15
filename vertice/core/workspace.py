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
        with open(self.graph_path, "w", encoding="utf-8") as fh:
            fh.write(self.graph.to_json())

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
        """True se `value` cai sob algum item do escopo autorizado.

        Se o escopo está vazio, nada é barrado (modo exploratório), mas a
        coleta ativa deve sempre respeitar escopo — ver engine.
        """
        scope = self.meta.get("scope") or []
        if not scope:
            return True
        v = value.lower().rstrip(".")
        for s in scope:
            s = s.lower().rstrip(".")
            if v == s or v.endswith("." + s):
                return True
        return False

    def save(self):
        self.save_graph()
        self.save_meta()

    def close(self):
        self.save()
        self.evidence.close()
