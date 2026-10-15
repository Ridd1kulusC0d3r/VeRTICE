"""Collector crt.sh — subdomínios via Certificate Transparency.

Reimplementa o eixo de descoberta do Censys/FOFA (certificado como fonte de
ativos), mas por uma fonte passiva e sem chave: o log de Certificate
Transparency exposto pelo crt.sh em JSON.

Semente: domínio. Achados: hosts (subdomínios) + um nó certificate.
"""
from __future__ import annotations

from typing import List

from .base import Collector, Finding, register
from ..core.entities import T_DOMAIN, T_HOST
from .. import util


@register
class CrtShCollector(Collector):
    name = "crtsh"
    etypes = (T_DOMAIN,)
    passive = True
    description = "Subdomínios via Certificate Transparency (crt.sh)"

    def collect(self, entity) -> List[Finding]:
        domain = entity.value
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        data = util.get_json(url)
        if not data:
            return []
        findings: List[Finding] = []
        seen = set()
        for row in data:
            name_value = row.get("name_value", "")
            for host in name_value.splitlines():
                host = host.strip().lstrip("*.").lower()
                if not host or host in seen:
                    continue
                if not (host == domain or host.endswith("." + domain)):
                    continue
                seen.add(host)
                findings.append(Finding(
                    value=host, etype=T_HOST, rel="has-subdomain",
                    attrs={"issuer": row.get("issuer_name", "")},
                    raw={"id": row.get("id"),
                         "not_before": row.get("not_before"),
                         "not_after": row.get("not_after")},
                ))
        return findings
