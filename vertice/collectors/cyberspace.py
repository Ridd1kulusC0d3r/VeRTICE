"""Conector de motores de ciberespaço (ZoomEye / FOFA / Censys / Shodan).

Reimplementa o padrão "índice de ciberespaço consultável": em vez de varrer a
internet, consulta um índice já pronto. É **opcional** e **desligado por
padrão** — só roda se houver a credencial correspondente na config do
workspace. Resultados viram nós `service`/`host`/`ip`.

Cada motor tem seu endpoint e formato; aqui implementamos Censys (hosts) e
Shodan como exemplos concretos, e deixamos ZoomEye/FOFA como stubs
documentados (ativáveis quando o usuário colar a chave). Do ponto de vista do
alvo, consultar esses índices é passivo.

Credenciais esperadas em `<workspace>/credentials.json`:
  - "censys_token"  : "API_ID:API_SECRET" (Basic)
  - "shodan_key"    : "..."
  - "zoomeye_key"   : "..."
  - "fofa_key"      : "email:key"
"""
from __future__ import annotations

import base64
from typing import List

from .base import Collector, Finding, register
from ..core.entities import T_DOMAIN, T_HOST, T_IP, T_SERVICE
from .. import util


@register
class CensysConnector(Collector):
    name = "censys"
    etypes = (T_DOMAIN, T_HOST, T_IP)
    passive = True
    needs_cred = "censys_token"
    description = "Censys Search (hosts/serviços) — requer censys_token"

    def collect(self, entity) -> List[Finding]:
        token = self.cred()
        if not token:
            return []
        q = entity.value
        auth = base64.b64encode(token.encode()).decode()
        url = ("https://search.censys.io/api/v2/hosts/search?q="
               + util.urllib.parse.quote(q) + "&per_page=50")
        data = util.get_json(url, headers={"Authorization": f"Basic {auth}"})
        if not data:
            return []
        findings: List[Finding] = []
        for hit in (data.get("result", {}) or {}).get("hits", []) or []:
            ip = hit.get("ip")
            if ip:
                findings.append(Finding(ip, T_IP, rel="censys-host"))
            for svc in hit.get("services", []) or []:
                port = svc.get("port")
                name = svc.get("service_name", "")
                if port:
                    findings.append(Finding(
                        f"{ip}:{port}/{name}".strip("/"), T_SERVICE,
                        rel="exposes-service",
                        attrs={"port": port, "service": name},
                        raw=svc))
        return findings


@register
class ShodanConnector(Collector):
    name = "shodan"
    etypes = (T_IP, T_DOMAIN, T_HOST)
    passive = True
    needs_cred = "shodan_key"
    description = "Shodan (serviços expostos) — requer shodan_key"

    def collect(self, entity) -> List[Finding]:
        key = self.cred()
        if not key:
            return []
        findings: List[Finding] = []
        if entity.etype == T_IP:
            url = f"https://api.shodan.io/shodan/host/{entity.value}?key={key}"
            data = util.get_json(url)
            if not data:
                return []
            for svc in data.get("data", []) or []:
                port = svc.get("port")
                product = svc.get("product", "") or svc.get("_shodan", {}).get(
                    "module", "")
                if port:
                    findings.append(Finding(
                        f"{entity.value}:{port}/{product}".strip("/"),
                        T_SERVICE, rel="exposes-service",
                        attrs={"port": port, "product": product},
                        raw={"transport": svc.get("transport")},
                        observed_at=svc.get("timestamp")))
        else:
            url = (f"https://api.shodan.io/dns/domain/{entity.value}?key={key}")
            data = util.get_json(url)
            if not data:
                return []
            for sub in data.get("subdomains", []) or []:
                findings.append(Finding(f"{sub}.{entity.value}", T_HOST,
                                        rel="has-subdomain"))
        return findings


# ZoomEye e FOFA: ativáveis. Endpoints documentados; mantidos como stubs que
# só agem quando a chave existe (seguindo a mesma interface).
@register
class ZoomEyeConnector(Collector):
    name = "zoomeye"
    etypes = (T_DOMAIN, T_HOST, T_IP)
    passive = True
    needs_cred = "zoomeye_key"
    description = "ZoomEye (ciberespaço) — requer zoomeye_key"

    def collect(self, entity) -> List[Finding]:
        key = self.cred()
        if not key:
            return []
        url = ("https://api.zoomeye.ai/host/search?query="
               + util.urllib.parse.quote(entity.value))
        data = util.get_json(url, headers={"API-KEY": key})
        if not data:
            return []
        findings: List[Finding] = []
        for m in data.get("matches", []) or []:
            ip = m.get("ip")
            portinfo = m.get("portinfo", {}) or {}
            port = portinfo.get("port")
            if ip and port:
                findings.append(Finding(
                    f"{ip}:{port}/{portinfo.get('service','')}".strip("/"),
                    T_SERVICE, rel="exposes-service",
                    attrs={"port": port, "service": portinfo.get("service")},
                    raw={"os": portinfo.get("os")}))
        return findings


@register
class FofaConnector(Collector):
    name = "fofa"
    etypes = (T_DOMAIN, T_HOST, T_IP)
    passive = True
    needs_cred = "fofa_key"
    description = "FOFA (ciberespaço, pivô por cert/favicon) — requer fofa_key"

    def collect(self, entity) -> List[Finding]:
        cred = self.cred()
        if not cred or ":" not in cred:
            return []
        email, key = cred.split(":", 1)
        qbase64 = base64.b64encode(
            f'domain="{entity.value}"'.encode()).decode()
        url = (f"https://fofa.info/api/v1/search/all?email={email}&key={key}"
               f"&qbase64={util.urllib.parse.quote(qbase64)}&size=50"
               f"&fields=ip,port,protocol,host")
        data = util.get_json(url)
        if not data or data.get("error"):
            return []
        findings: List[Finding] = []
        for row in data.get("results", []) or []:
            if len(row) >= 2 and row[0] and row[1]:
                findings.append(Finding(
                    f"{row[0]}:{row[1]}", T_SERVICE, rel="exposes-service",
                    attrs={"protocol": row[2] if len(row) > 2 else ""},
                    raw={"host": row[3] if len(row) > 3 else ""}))
        return findings
