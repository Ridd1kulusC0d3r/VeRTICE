"""Collector de pivô (padrão Mitaka) — 100% offline.

Não faz rede. Para cada entidade pivotável, anexa o "menu Mitaka" (links de
pivô montados pelo `pivots.registry`) como atributo da própria entidade. Assim
o dossiê HTML pode mostrar, por nó, para onde o analista pode pivotar.

Como o achado é sobre a própria semente, o engine funde o atributo sem criar
auto-aresta.
"""
from __future__ import annotations

from typing import List

from .base import Collector, Finding, register
from ..core.entities import (T_DOMAIN, T_HOST, T_IP, T_EMAIL, T_URL, T_HASH,
                             T_ASN, T_CVE, T_FAVICON, T_NETBLOCK)
from ..pivots.registry import pivots_for


@register
class IocPivotCollector(Collector):
    name = "pivot"
    etypes = (T_DOMAIN, T_HOST, T_IP, T_EMAIL, T_URL, T_HASH, T_ASN, T_CVE,
              T_FAVICON, T_NETBLOCK)
    passive = True
    description = "Gera o menu de pivô OSINT (estilo Mitaka) por entidade"

    def collect(self, entity) -> List[Finding]:
        pivots = pivots_for(entity)
        if not pivots:
            return []
        return [Finding(value=entity.value, etype=entity.etype,
                        rel="pivot-menu", attrs={"pivots": pivots})]
