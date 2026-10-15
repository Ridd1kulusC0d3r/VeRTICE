"""Collector Internet Archive (Wayback) — URLs e hosts históricos.

Consulta a CDX API do Wayback Machine (JSON) para um domínio e extrai URLs
históricas e hosts que já apareceram — fonte passiva riquíssima para superfície
de ataque "esquecida" (endpoints antigos, subdomínios desativados).

Semente: domínio. Achados: hosts e URLs vistas no passado.
"""
from __future__ import annotations

import urllib.parse
from typing import List

from .base import Collector, Finding, register
from ..core.entities import T_DOMAIN, T_HOST, T_URL
from .. import util


@register
class WaybackCollector(Collector):
    name = "wayback"
    etypes = (T_DOMAIN,)
    passive = True
    description = "URLs/hosts históricos via Internet Archive (Wayback CDX)"

    MAX = 500  # teto de URLs para não explodir o grafo

    def collect(self, entity) -> List[Finding]:
        domain = entity.value
        q = urllib.parse.quote(f"*.{domain}/*")
        url = (f"https://web.archive.org/cdx/search/cdx?url={q}"
               f"&output=json&fl=original&collapse=urlkey&limit={self.MAX}")
        data = util.get_json(url)
        if not data or len(data) < 2:
            return []
        findings: List[Finding] = []
        hosts = set()
        for row in data[1:]:  # primeira linha é cabeçalho
            original = row[0] if row else ""
            if not original:
                continue
            findings.append(Finding(original, T_URL, rel="archived-url",
                                    raw={"source": "wayback"}))
            parsed = urllib.parse.urlparse(original)
            host = parsed.hostname or ""
            if host and host not in hosts and (
                    host == domain or host.endswith("." + domain)):
                hosts.add(host)
                findings.append(Finding(host, T_HOST, rel="has-subdomain",
                                        raw={"source": "wayback"}))
        return findings
