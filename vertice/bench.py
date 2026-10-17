"""Bancada web local do VÉRTICE (http.server stdlib).

Sobe um servidor local que renderiza o dossiê HTML ao vivo e expõe o grafo em
JSON. Útil para navegar a investigação no browser sem gerar arquivo. Só escuta
em loopback por padrão.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .report import render_report
from .report.exporters import export, EXPORTERS
from .core.intel import correlate, surface_diff


def _handler(workspace):
    class H(BaseHTTPRequestHandler):
        def _send(self, body: bytes, ctype: str, status: int = 200):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj):
            self._send(json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                workspace.graph = workspace._load_graph()  # ao vivo
                self._send(render_report(workspace).encode("utf-8"),
                           "text/html; charset=utf-8")
            elif path == "/graph.json":
                workspace.graph = workspace._load_graph()
                self._send(workspace.graph.to_json().encode("utf-8"),
                           "application/json; charset=utf-8")
            elif path == "/verify":
                self._json(workspace.evidence.verify_chain())
            elif path == "/correlate":
                workspace.graph = workspace._load_graph()
                self._json(correlate(workspace.graph))
            elif path == "/snapshots":
                self._json({"snapshots": workspace.list_snapshots()})
            elif path == "/diff":
                snaps = workspace.list_snapshots()
                if len(snaps) >= 2:
                    old = workspace.load_snapshot(snaps[-2])
                    new = workspace.load_snapshot(snaps[-1])
                    self._json(surface_diff(old, new))
                else:
                    self._json({"error": "precisa de 2 snapshots"})
            elif path.startswith("/export/"):
                fmt = path.split("/export/", 1)[1]
                if fmt in EXPORTERS:
                    workspace.graph = workspace._load_graph()
                    ctype = ("application/json" if fmt in ("jsonl", "stix")
                             else "text/plain")
                    self._send(export(workspace.graph, fmt).encode("utf-8"),
                               f"{ctype}; charset=utf-8")
                else:
                    self._send(b"formato invalido", "text/plain", 400)
            else:
                self._send(b"nao encontrado", "text/plain", 404)

        def log_message(self, *args):  # silencia log padrão
            pass
    return H


def serve(workspace, host: str = "127.0.0.1", port: int = 8713):
    # ThreadingHTTPServer: suporta requisições concorrentes da bancada
    srv = ThreadingHTTPServer((host, port), _handler(workspace))
    print(f"[bench] VÉRTICE em http://{host}:{port}  (Ctrl+C para sair)")
    print(f"        dossiê: /   grafo: /graph.json   custódia: /verify")
    print(f"        correlação: /correlate   diff: /diff   "
          f"export: /export/<jsonl|csv|stix|targets|nmap|httpx>")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[bench] encerrado.")
    finally:
        srv.server_close()
        workspace.close(save=False)
