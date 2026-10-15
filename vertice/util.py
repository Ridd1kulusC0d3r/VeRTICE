"""Utilitários stdlib-only compartilhados (HTTP, favicon hash, helpers).

Nenhuma dependência externa: urllib, json, hashlib, ssl, base64. Toda função de
rede é tolerante a falha — devolve None/[] em erro, nunca levanta para cima.
"""
from __future__ import annotations

import base64
import threading
from contextlib import contextmanager
import hashlib
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional, Tuple

USER_AGENT = "VERTICE/1.0 (+DEIVOSINT; OSINT passivo)"
DEFAULT_TIMEOUT = 15


_capture = threading.local()
MAX_BODY = 4 * 1024 * 1024


@contextmanager
def capture_requests():
    events = []
    _capture.events = events
    try:
        yield events
    finally:
        del _capture.events


def _event(url, status, body, error=None, truncated=False):
    events = getattr(_capture, "events", None)
    if events is None:
        return
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    sensitive = {"key", "api_key", "apikey", "token", "secret", "email"}
    safe_query = urllib.parse.urlencode([
        (k, "[REDACTED]" if k.lower() in sensitive else v) for k, v in query])
    safe_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc,
                                       parsed.path, safe_query, ""))
    events.append({"url": safe_url, "status": status, "error": error,
                   "truncated": truncated,
                   "body_sha256": hashlib.sha256(body or b"").hexdigest(),
                   "body_base64": base64.b64encode(body or b"").decode("ascii")})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener(follow_redirects=True):
    handlers = [urllib.request.HTTPSHandler(context=ssl.create_default_context())]
    if not follow_redirects:
        handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


def http_get(url: str, headers: Optional[dict] = None,
             timeout: int = DEFAULT_TIMEOUT, follow_redirects: bool = True):
    """Bounded HTTP request; capture status/raw bytes inside an engine task."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with _opener(follow_redirects).open(req, timeout=timeout) as resp:
            body = resp.read(MAX_BODY + 1)
            truncated = len(body) > MAX_BODY
            body = body[:MAX_BODY]
            _event(url, resp.status, body, truncated=truncated)
            return resp.status, body, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        _event(url, exc.code, body[:MAX_BODY], error="http_error",
               truncated=len(body) > MAX_BODY)
        return exc.code, body[:MAX_BODY], dict(exc.headers)
    except (urllib.error.URLError, socket.timeout, ssl.SSLError,
            ConnectionError, OSError) as exc:
        # Exception messages can contain a credential-bearing URL.
        _event(url, None, None, error=type(exc).__name__)
        return None, None, {}


def get_json(url: str, headers: Optional[dict] = None,
             timeout: int = DEFAULT_TIMEOUT):
    status, body, _ = http_get(url, headers, timeout)
    if status and 200 <= status < 300 and body:
        try:
            data = json.loads(body.decode("utf-8", "replace"))
            if isinstance(data, dict) and (data.get("error") or data.get("success") is False):
                events = getattr(_capture, "events", None)
                if events:
                    events[-1]["error"] = "provider_error"
            return data
        except (ValueError, UnicodeDecodeError):
            events = getattr(_capture, "events", None)
            if events:
                events[-1]["error"] = "invalid_json"
    return None


def get_text(url: str, headers: Optional[dict] = None,
             timeout: int = DEFAULT_TIMEOUT) -> Optional[str]:
    status, body, _ = http_get(url, headers, timeout)
    if status and 200 <= status < 300 and body:
        return body.decode("utf-8", "replace")
    return None


def favicon_mmh3_like(data: bytes) -> str:
    """Hash de favicon (pivô estilo FOFA/Shodan).

    O FOFA/Shodan usam MurmurHash3 sobre o favicon em base64. Como MurmurHash3
    não está na stdlib, usamos um digest SHA-256 do base64 — mantém a função de
    *pivô por favicon* (mesmo ícone => mesmo hash; isso não comprova propriedade),
    apenas com algoritmo próprio do VÉRTICE. Documentado como tal.
    """
    b64 = base64.encodebytes(data)
    return "vfav:" + hashlib.sha256(b64).hexdigest()[:32]


def dns_over_https(name: str, rtype: str = "A",
                   provider: str = "https://dns.google/resolve") -> list:
    """Resolve DNS via DoH (JSON). Passivo do ponto de vista do alvo: a
    consulta vai ao resolvedor público, não ao servidor da vítima.

    Devolve lista de dicts {type, data} ou [].
    """
    url = f"{provider}?name={urllib.parse.quote(name)}&type={rtype}"
    data = get_json(url, headers={"Accept": "application/dns-json"})
    if data and data.get("Status") not in (None, 0, 3):
        events = getattr(_capture, "events", None)
        if events:
            events[-1]["error"] = "dns_error"
    if not data or "Answer" not in data:
        return []
    out = []
    _type_names = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT",
                   2: "NS", 6: "SOA", 257: "CAA"}
    for ans in data["Answer"]:
        out.append({"type": _type_names.get(ans.get("type"), ans.get("type")),
                    "data": ans.get("data", "").strip('"')})
    return out
