"""Registro de pivôs — o "menu Mitaka" do VÉRTICE.

Cada pivô declara: nome do serviço, tipos de entidade que aceita e um template
de URL. `pivots_for(entity)` devolve a lista de links já montados para uma
entidade — exatamente o menu de contexto do Mitaka, só que embutido no dossiê.

100% offline: só monta URLs. Nenhuma requisição é feita aqui.
"""
from __future__ import annotations

import urllib.parse
from typing import Dict, List

from ..core.entities import (T_DOMAIN, T_HOST, T_IP, T_EMAIL, T_URL, T_HASH,
                             T_ASN, T_CVE, T_FAVICON, T_NETBLOCK)

# Cada entrada: (nome, tipos aceitos, template com {q})
REGISTRY: List[tuple] = [
    # Certificados / ativos
    ("crt.sh", (T_DOMAIN, T_HOST), "https://crt.sh/?q={q}"),
    ("Censys Hosts", (T_IP, T_DOMAIN, T_HOST),
     "https://search.censys.io/search?resource=hosts&q={q}"),
    ("Censys Certs", (T_DOMAIN, T_HOST),
     "https://search.censys.io/search?resource=certificates&q={q}"),
    ("Shodan", (T_IP, T_DOMAIN, T_HOST), "https://www.shodan.io/search?query={q}"),
    ("ZoomEye", (T_IP, T_DOMAIN, T_HOST), "https://www.zoomeye.ai/searchResult?q={q}"),
    ("FOFA", (T_IP, T_DOMAIN, T_HOST), "https://en.fofa.info/result?qbase64={q_b64}"),
    ("BuiltWith", (T_DOMAIN, T_HOST), "https://builtwith.com/{q}"),
    ("DNSDumpster", (T_DOMAIN,), "https://dnsdumpster.com/?target={q}"),
    ("SecurityTrails", (T_DOMAIN, T_HOST, T_IP),
     "https://securitytrails.com/domain/{q}/dns"),
    ("VirusTotal", (T_DOMAIN, T_HOST, T_IP, T_URL, T_HASH),
     "https://www.virustotal.com/gui/search/{q}"),
    # Rede / roteamento
    ("BGP.he.net", (T_IP, T_ASN, T_NETBLOCK), "https://bgp.he.net/{q}"),
    ("BGPView", (T_IP, T_ASN), "https://bgpview.io/search/{q}"),
    ("ipinfo", (T_IP,), "https://ipinfo.io/{q}"),
    ("Hurricane DNS", (T_DOMAIN, T_HOST), "https://bgp.he.net/dns/{q}"),
    # Exposição / vazamento
    ("HIBP", (T_EMAIL,), "https://haveibeenpwned.com/account/{q}"),
    ("Intelligence X", (T_DOMAIN, T_HOST, T_EMAIL, T_IP),
     "https://intelx.io/?s={q}"),
    # Histórico
    ("Wayback", (T_DOMAIN, T_HOST, T_URL),
     "https://web.archive.org/web/*/{q}"),
    ("URLScan", (T_DOMAIN, T_HOST, T_URL),
     "https://urlscan.io/search/#{q}"),
    # Vulnerabilidade
    ("NVD", (T_CVE,), "https://nvd.nist.gov/vuln/detail/{q}"),
    ("CVE.org", (T_CVE,), "https://www.cve.org/CVERecord?id={q}"),
    # Favicon
    ("FOFA favicon", (T_FAVICON,),
     "https://en.fofa.info/ (buscar por icon_hash: {q})"),
]


def pivots_for(entity) -> List[Dict[str, str]]:
    """Monta os links de pivô aplicáveis a uma entidade."""
    out = []
    for name, types, template in REGISTRY:
        if entity.etype not in types:
            continue
        q = urllib.parse.quote(entity.value, safe="")
        url = template.replace("{q}", q)
        if "{q_b64}" in url:
            import base64
            b64 = base64.b64encode(entity.value.encode()).decode()
            url = url.replace("{q_b64}", urllib.parse.quote(b64))
        out.append({"service": name, "url": url})
    return out
