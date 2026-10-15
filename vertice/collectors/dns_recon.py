"""Collector de DNS (reimplementa o DNSDumpster sem scrape de terceiros).

Faz recon de DNS direto via DNS-over-HTTPS (JSON) — passivo do ponto de vista
do alvo, pois a consulta vai a um resolvedor público, não ao servidor da
vítima. Resolve A/AAAA/CNAME/MX/NS/TXT.

Semente: domínio ou host. Achados: IPs, hosts de MX/NS, registros TXT.
"""
from __future__ import annotations

from typing import List

from .base import Collector, Finding, register
from ..core.entities import (T_DOMAIN, T_HOST, T_IP, classify)
from .. import util


@register
class DnsReconCollector(Collector):
    name = "dns"
    etypes = (T_DOMAIN, T_HOST)
    passive = True
    description = "Registros DNS (A/AAAA/CNAME/MX/NS/TXT) via DoH"

    RTYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")

    def collect(self, entity) -> List[Finding]:
        name = entity.value
        findings: List[Finding] = []
        for rtype in self.RTYPES:
            for ans in util.dns_over_https(name, rtype):
                data = ans["data"]
                answer_type = ans["type"]
                if answer_type in ("A", "AAAA"):
                    findings.append(Finding(
                        value=data, etype=T_IP, rel="resolves-to",
                        raw={"rtype": rtype}))
                elif answer_type == "CNAME":
                    findings.append(Finding(
                        value=data.rstrip("."), etype=T_HOST,
                        rel="cname", raw={"rtype": rtype}))
                elif answer_type == "MX":
                    mx = data.split()[-1].rstrip(".")
                    if classify(mx) in (T_DOMAIN, T_HOST):
                        findings.append(Finding(
                            value=mx, etype=T_HOST, rel="mail-exchange",
                            raw={"rtype": rtype}))
                elif answer_type == "NS":
                    ns = data.rstrip(".")
                    if classify(ns) in (T_DOMAIN, T_HOST):
                        findings.append(Finding(
                            value=ns, etype=T_HOST, rel="name-server",
                            raw={"rtype": rtype}))
                elif answer_type == "TXT":
                    # TXT fica como atributo da semente (não vira entidade),
                    # mas gravamos a evidência bruta.
                    findings.append(Finding(
                        value=name, etype=entity.etype, rel="txt-record",
                        attrs={"txt": data[:300]}, raw={"rtype": "TXT"}))
        return findings
