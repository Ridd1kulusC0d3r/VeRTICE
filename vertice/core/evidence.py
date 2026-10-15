"""Ledger de evidências com cadeia de custódia SHA-256 (inovação DEIVOSINT).

Cada fato coletado vira um registro *append-only* num SQLite do workspace. O
hash de cada evidência inclui o hash da anterior (encadeamento estilo
blockchain simplificado): adulterar ou remover qualquer registro quebra a
cadeia e é detectável por `verify_chain()`.

Herança da família DEIVOSINT (F.I.O. Lab, GARIMPO, PRISMA), aplicada aqui à
superfície de ataque — requisito para uso investigativo/forense e para
preparação de pentest com rastreabilidade.

Stdlib-only: sqlite3 + hashlib + json + datetime.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

GENESIS = "0" * 64  # hash do bloco anterior ao primeiro registro


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(payload: dict) -> str:
    """SHA-256 canônico de um payload (chaves ordenadas, sem espaços)."""
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class EvidenceLedger:
    """Diário de evidências append-only com custódia encadeada."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS evidence (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         TEXT NOT NULL,
        collector  TEXT NOT NULL,
        kind       TEXT NOT NULL,       -- entity | edge | note | raw
        subject    TEXT NOT NULL,       -- a entidade/relação/assunto
        data       TEXT NOT NULL,       -- JSON do conteúdo
        prev_hash  TEXT NOT NULL,
        hash       TEXT NOT NULL UNIQUE
    );
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        # check_same_thread=False: a bancada web lê o ledger em outra thread.
        # Toda escrita é serializada pelo lock abaixo (ledger é append-only).
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self.conn.execute(self.SCHEMA)
        self.conn.commit()

    # ------------------------------------------------------------------ #
    def _last_hash(self) -> str:
        row = self.conn.execute(
            "SELECT hash FROM evidence ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["hash"] if row else GENESIS

    def record(self, collector: str, kind: str, subject: str,
               data: dict) -> str:
        """Acrescenta uma evidência ao ledger. Devolve o hash do registro."""
        prev = self._last_hash()
        ts = _utc()
        body = {
            "ts": ts, "collector": collector, "kind": kind,
            "subject": subject, "data": data, "prev_hash": prev,
        }
        h = _digest(body)
        with self._lock:
            self.conn.execute(
                "INSERT INTO evidence (ts, collector, kind, subject, data, "
                "prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                (ts, collector, kind, subject,
                 json.dumps(data, ensure_ascii=False), prev, h),
            )
            self.conn.commit()
        return h

    # ------------------------------------------------------------------ #
    def verify_chain(self) -> Dict[str, object]:
        """Reprocessa a cadeia e confirma a integridade de ponta a ponta."""
        rows = self.conn.execute(
            "SELECT * FROM evidence ORDER BY seq ASC"
        ).fetchall()
        prev = GENESIS
        for r in rows:
            body = {
                "ts": r["ts"], "collector": r["collector"], "kind": r["kind"],
                "subject": r["subject"], "data": json.loads(r["data"]),
                "prev_hash": r["prev_hash"],
            }
            expected = _digest(body)
            if r["prev_hash"] != prev:
                return {"ok": False, "broken_at": r["seq"],
                        "reason": "prev_hash não encadeia"}
            if r["hash"] != expected:
                return {"ok": False, "broken_at": r["seq"],
                        "reason": "hash não confere (registro adulterado)"}
            prev = r["hash"]
        return {"ok": True, "records": len(rows), "head": prev}

    def all(self) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM evidence ORDER BY seq ASC"
        ).fetchall()

    def count(self) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS c FROM evidence"
        ).fetchone()["c"]

    def by_collector(self) -> Dict[str, int]:
        rows = self.conn.execute(
            "SELECT collector, COUNT(*) AS c FROM evidence GROUP BY collector"
        ).fetchall()
        return {r["collector"]: r["c"] for r in rows}

    def head(self) -> str:
        return self._last_hash()

    def close(self):
        self.conn.close()
