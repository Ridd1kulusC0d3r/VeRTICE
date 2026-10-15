"""Utilitários stdlib-only compartilhados (HTTP, favicon hash, helpers).

Nenhuma dependência externa: urllib, json, hashlib, ssl, base64. Toda função de
rede é tolerante a falha — devolve None/[] em erro, nunca levanta para cima.
"""
from __future__ import annotations

import base64
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


def _opener():
    ctx = ssl.create_default_context()
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def http_get(url: str, headers: Optional[dict] = None,
             timeout: int = DEFAULT_TIMEOUT) -> Tuple[Optional[int],
                                                       Optional[bytes],
                                                       dict]:
    """GET simples. Devolve (status, corpo_bytes, headers). Tolerante a falha."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with _opener().open(req, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, body, dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(), dict(e.headers)
        except Exception:
            return e.code, None, {}
    except (urllib.error.URLError, socket.timeout, ssl.SSLError,
            ConnectionError, OSError):
        return None, None, {}


def get_json(url: str, headers: Optional[dict] = None,
             timeout: int = DEFAULT_TIMEOUT):
    """GET + parse JSON. Devolve objeto ou None."""
    status, body, _ = http_get(url, headers, timeout)
    if status and 200 <= status < 300 and body:
        try:
            return json.loads(body.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            return None
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
    *pivô por favicon* (mesmo ícone => mesmo hash => ativos do mesmo dono),
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
    if not data or "Answer" not in data:
        return []
    out = []
    _type_names = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT",
                   2: "NS", 6: "SOA", 257: "CAA"}
    for ans in data["Answer"]:
        out.append({"type": _type_names.get(ans.get("type"), ans.get("type")),
                    "data": ans.get("data", "").strip('"')})
    return out
