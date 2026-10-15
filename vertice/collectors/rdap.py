"""Collector RDAP — registro de domínios e IPs (sucessor estruturado do WHOIS).

RDAP devolve JSON padronizado (RFC 7483). Passivo: consulta registries
públicos. Para domínio: registrar, datas, nameservers, contatos (quando
públicos). Para IP: organização, netblock, ASN de origem.

Semente: domínio ou IP. Achados: organização, netblock, e-mails de contato.
"""
from __future__ import annotations

from typing import List

from .base import Collector, Finding, register
from ..core.entities import (T_DOMAIN, T_IP, T_ORG, T_NETBLOCK, T_EMAIL,
                              T_HOST, classify)
from .. import util

_DNS_RDAP = "https://rdap.org/domain/"
_IP_RDAP = "https://rdap.org/ip/"


@register
class RdapCollector(Collector):
    name = "rdap"
    etypes = (T_DOMAIN, T_IP)
    passive = True
    description = "Registro RDAP de domínio/IP (org, netblock, contatos)"

    def collect(self, entity) -> List[Finding]:
        if entity.etype == T_DOMAIN:
            return self._domain(entity.value)
        return self._ip(entity.value)

    def _entities_from_vcard(self, obj) -> List[Finding]:
        out: List[Finding] = []
        for ent in obj.get("entities", []) or []:
            vcard = ent.get("vcardArray")
            org = None
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] == "fn":
                        org = item[3]
                    if item and item[0] == "email":
                        email = item[3]
                        if classify(email) == T_EMAIL:
                            out.append(Finding(email, T_EMAIL,
                                               rel="registration-contact"))
            if org and classify(org) is None:  # org costuma ser texto livre
                out.append(Finding(org, T_ORG, rel="registered-by",
                                   attrs={"roles": ent.get("roles", [])}))
        return out

    def _domain(self, domain: str) -> List[Finding]:
        data = util.get_json(_DNS_RDAP + domain)
        if not data:
            return []
        findings = self._entities_from_vcard(data)
        for ns in data.get("nameservers", []) or []:
            name = (ns.get("ldhName") or "").rstrip(".")
            if classify(name) in (T_DOMAIN, T_HOST):
                findings.append(Finding(name, T_HOST, rel="name-server"))
        # datas de registro como atributo da semente
        events = {e.get("eventAction"): e.get("eventDate")
                  for e in data.get("events", []) or []}
        if events:
            findings.append(Finding(domain, T_DOMAIN, rel="rdap-events",
                                    attrs={"events": events}))
        return findings

    def _ip(self, ip: str) -> List[Finding]:
        data = util.get_json(_IP_RDAP + ip)
        if not data:
            return []
        findings = self._entities_from_vcard(data)
        cidr = None
        start, end = data.get("startAddress"), data.get("endAddress")
        if data.get("cidr0_cidrs"):
            c = data["cidr0_cidrs"][0]
            pfx = c.get("v4prefix") or c.get("v6prefix")
            length = c.get("length")
            if pfx and length is not None:
                cidr = f"{pfx}/{length}"
        if cidr:
            findings.append(Finding(cidr, T_NETBLOCK, rel="within-netblock",
                                    attrs={"name": data.get("name", "")}))
        elif start and end:
            findings.append(Finding(ip, T_IP, rel="ip-range",
                                    attrs={"start": start, "end": end}))
        return findings
