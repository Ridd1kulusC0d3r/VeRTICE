"""Collector de dorks — gera consultas Google/Bing/GitHub prontas (offline).

Não faz rede: para um domínio, monta um conjunto de *dorks* (consultas
avançadas) que revelam arquivos sensíveis, subdomínios, painéis de login,
código-fonte vazado e documentos expostos. É o complemento ao pivô do Mitaka,
focado em descoberta por motor de busca.

As consultas são anexadas como atributo do próprio domínio (sem auto-aresta).
"""
from __future__ import annotations

import urllib.parse
from typing import List

from .base import Collector, Finding, register
from ..core.entities import T_DOMAIN

_GOOGLE = "https://www.google.com/search?q="
_BING = "https://www.bing.com/search?q="
_GH = "https://github.com/search?type=code&q="

# (rótulo, template com {d})
_DORKS = [
    ("Arquivos sensíveis", 'site:{d} ext:env OR ext:bak OR ext:sql OR ext:log'),
    ("Documentos expostos", 'site:{d} ext:pdf OR ext:xls OR ext:doc OR ext:csv'),
    ("Painéis de login", 'site:{d} inurl:login OR inurl:admin OR inurl:signin'),
    ("Diretórios abertos", 'site:{d} intitle:"index of"'),
    ("Config/backup", 'site:{d} inurl:config OR inurl:backup OR inurl:.git'),
    ("Subdomínios", 'site:*.{d} -www'),
    ("Erros/stack traces", 'site:{d} "sql syntax near" OR "stack trace" OR "fatal error"'),
    ("Credenciais em texto", 'site:{d} intext:password OR intext:senha'),
]
_GH_DORKS = [
    ("Código mencionando o domínio", '"{d}"'),
    ("Segredos + domínio", '"{d}" password OR secret OR api_key OR token'),
    ("Config + domínio", '"{d}" filename:.env OR filename:config'),
]


@register
class DorksCollector(Collector):
    name = "dorks"
    etypes = (T_DOMAIN,)
    passive = True
    description = "Gera dorks Google/Bing/GitHub para o domínio (offline)"

    def collect(self, entity) -> List[Finding]:
        d = entity.value
        items = []
        for label, tmpl in _DORKS:
            q = urllib.parse.quote(tmpl.replace("{d}", d))
            items.append({"engine": "Google", "label": label,
                          "url": _GOOGLE + q})
            items.append({"engine": "Bing", "label": label, "url": _BING + q})
        for label, tmpl in _GH_DORKS:
            q = urllib.parse.quote(tmpl.replace("{d}", d))
            items.append({"engine": "GitHub", "label": label, "url": _GH + q})
        return [Finding(value=d, etype=T_DOMAIN, rel="dork-menu",
                        attrs={"dorks": items})]
