"""Collector ASN/BGP via RIPEstat Data API — SEM chave.

RIPEstat (stat.ripe.net) expõe dados de roteamento globais em JSON, livre:
  - de um IP, o prefixo anunciado e o ASN de origem;
  - de um ASN, os prefixos anunciados e o nome do holder.

Reimplementa o eixo ASN/netblock do Amass/BGP.he.net sem chave. Semente: IP ou
ASN. Achados: asn, netblock, organização.
"""
from __future__ import annotations

from typing import List

from .base import Collector, Finding, register
from ..core.entities import T_IP, T_ASN, T_NETBLOCK, T_ORG
from .. import util

_PREFIX = "https://stat.ripe.net/data"


@register
class AsnBgpCollector(Collector):
    name = "asn"
    etypes = (T_IP, T_ASN)
    passive = True
    description = "ASN/prefixo/holder via RIPEstat (sem chave)"

    def collect(self, entity) -> List[Finding]:
        if entity.etype == T_IP:
            return self._from_ip(entity.value)
        return self._from_asn(entity.value)

    def _from_ip(self, ip: str) -> List[Finding]:
        out: List[Finding] = []
        data = util.get_json(f"{_PREFIX}/network-info/data.json?resource={ip}")
        d = (data or {}).get("data", {})
        for pfx in d.get("prefixes", []) or ([d["prefix"]] if d.get("prefix") else []):
            out.append(Finding(pfx, T_NETBLOCK, rel="within-netblock",
                               raw={"source": "ripestat"}))
        for asn in d.get("asns", []) or []:
            out.append(Finding(f"AS{asn}", T_ASN, rel="originated-by",
                               raw={"source": "ripestat"}))
        return out

    def _from_asn(self, asn: str) -> List[Finding]:
        num = asn.upper().replace("AS", "")
        out: List[Finding] = []
        ov = util.get_json(f"{_PREFIX}/as-overview/data.json?resource=AS{num}")
        holder = (ov or {}).get("data", {}).get("holder")
        if holder:
            out.append(Finding(holder, T_ORG, rel="asn-holder",
                               raw={"source": "ripestat"}))
        pfxs = util.get_json(
            f"{_PREFIX}/announced-prefixes/data.json?resource=AS{num}")
        for item in (pfxs or {}).get("data", {}).get("prefixes", [])[:200]:
            pfx = item.get("prefix")
            if pfx:
                out.append(Finding(pfx, T_NETBLOCK, rel="announces",
                                   raw={"source": "ripestat"}))
        return out
