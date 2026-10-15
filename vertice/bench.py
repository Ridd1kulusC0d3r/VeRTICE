"""Bancada web local do VÉRTICE (http.server stdlib).

Sobe um servidor local que renderiza o dossiê HTML ao vivo e expõe o grafo em
JSON. Útil para navegar a investigação no browser sem gerar arquivo. Só escuta
em loopback por padrão.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from .report import render_report


def _handler(workspace):
    class H(BaseHTTPRequestHandler):
        def _send(self, body: bytes, ctype: str, status: int = 200):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                # recarrega o grafo do disco a cada request (ao vivo)
                workspace.graph = workspace._load_graph()
                html = render_report(workspace)
                self._send(html.encode("utf-8"),
                           "text/html; charset=utf-8")
            elif self.path == "/graph.json":
                workspace.graph = workspace._load_graph()
                self._send(workspace.graph.to_json().encode("utf-8"),
                           "application/json; charset=utf-8")
            elif self.path == "/verify":
                res = workspace.evidence.verify_chain()
                self._send(json.dumps(res).encode("utf-8"),
                           "application/json; charset=utf-8")
            else:
                self._send(b"nao encontrado", "text/plain", 404)

        def log_message(self, *args):  # silencia log padrão
            pass
    return H


def serve(workspace, host: str = "127.0.0.1", port: int = 8713):
    srv = HTTPServer((host, port), _handler(workspace))
    print(f"[bench] VÉRTICE em http://{host}:{port}  (Ctrl+C para sair)")
    print(f"        dossiê: /   | grafo: /graph.json | custódia: /verify")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[bench] encerrado.")
    finally:
        srv.server_close()
        workspace.close(save=False)
