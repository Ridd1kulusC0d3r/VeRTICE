"""Collector de postura de e-mail — SPF / DMARC / DKIM-hint (via DoH TXT).

Avalia a higiene anti-spoofing de um domínio a partir de registros TXT públicos
(DNS-over-HTTPS). É o ângulo de *detecção analítica* da v2: converte DNS em
achados de postura acionáveis (ex.: "SPF ausente", "DMARC p=none").

Semente: domínio. Achados: findings de postura (T_FINDING) + atributos.
Passivo: só consulta o resolvedor público.
"""
from __future__ import annotations

from typing import List

from .base import Collector, Finding, register
from ..core.entities import T_DOMAIN, T_FINDING
from .. import util


def _txt(name: str) -> List[str]:
    return [a["data"] for a in util.dns_over_https(name, "TXT")]


@register
class EmailSecCollector(Collector):
    name = "emailsec"
    etypes = (T_DOMAIN,)
    passive = True
    description = "Postura anti-spoofing: SPF/DMARC/DKIM (DoH TXT)"

    def collect(self, entity) -> List[Finding]:
        domain = entity.value
        out: List[Finding] = []

        spf = [t for t in _txt(domain) if t.lower().startswith("v=spf1")]
        if not spf:
            out.append(Finding(f"SPF ausente em {domain}", T_FINDING,
                               rel="posture",
                               attrs={"control": "SPF", "severity": "medium",
                                      "note": "domínio sem registro SPF"}))
        else:
            soft = any("~all" in s or "?all" in s or "+all" in s for s in spf)
            out.append(Finding(f"SPF presente em {domain}", T_FINDING,
                               rel="posture",
                               attrs={"control": "SPF",
                                      "severity": "low" if not soft else "medium",
                                      "policy": spf[0][:180]}))

        dmarc = [t for t in _txt(f"_dmarc.{domain}")
                 if t.lower().startswith("v=dmarc1")]
        if not dmarc:
            out.append(Finding(f"DMARC ausente em {domain}", T_FINDING,
                               rel="posture",
                               attrs={"control": "DMARC", "severity": "high",
                                      "note": "sem política DMARC"}))
        else:
            pol = "none"
            for part in dmarc[0].split(";"):
                if part.strip().lower().startswith("p="):
                    pol = part.strip()[2:]
            sev = {"reject": "low", "quarantine": "medium"}.get(pol, "high")
            out.append(Finding(f"DMARC p={pol} em {domain}", T_FINDING,
                               rel="posture",
                               attrs={"control": "DMARC", "policy": pol,
                                      "severity": sev}))
        return out
