"""Collector Shodan InternetDB — portas, CPEs e vulnerabilidades, SEM chave.

O endpoint https://internetdb.shodan.io/{ip} é gratuito e sem autenticação:
devolve portas abertas, CPEs (produtos), hostnames, tags e CVEs conhecidas de
um IP — tudo a partir da varredura que o Shodan já fez (passivo p/ o alvo).

É um dos maiores saltos de valor da v2: superfície de serviço + vulnerabilidade
de graça. Semente: IP. Achados: port, cpe, vulnerability, host.
"""
from __future__ import annotations

from typing import List

from .base import Collector, Finding, register
from ..core.entities import T_IP, T_PORT, T_CPE, T_VULN, T_HOST
from .. import util


@register
class InternetDBCollector(Collector):
    name = "internetdb"
    etypes = (T_IP,)
    passive = True
    description = "Portas/CPEs/CVEs de um IP via Shodan InternetDB (sem chave)"

    def collect(self, entity) -> List[Finding]:
        ip = entity.value
        data = util.get_json(f"https://internetdb.shodan.io/{ip}")
        if not data:
            return []
        findings: List[Finding] = []
        for port in data.get("ports", []) or []:
            findings.append(Finding(
                f"{ip}:{port}", T_PORT, rel="exposes-port",
                attrs={"port": port}, raw={"source": "internetdb"}))
        for cpe in data.get("cpes", []) or []:
            findings.append(Finding(cpe, T_CPE, rel="runs-product",
                                    raw={"source": "internetdb"}))
        for cve in data.get("vulns", []) or []:
            findings.append(Finding(cve.upper(), T_VULN, rel="affected-by",
                                    attrs={"cve": cve.upper()},
                                    raw={"source": "internetdb"}))
        for host in data.get("hostnames", []) or []:
            findings.append(Finding(host, T_HOST, rel="ptr-hostname",
                                    raw={"source": "internetdb"}))
        if data.get("tags"):
            findings.append(Finding(ip, T_IP, rel="internetdb-tags",
                                    attrs={"tags": data["tags"]}))
        return findings
