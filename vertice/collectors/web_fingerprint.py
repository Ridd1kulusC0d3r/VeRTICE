"""Collector de fingerprint web (reimplementa o BuiltWith).

Baixa a página inicial (http/https) de um host e casa assinaturas contra
headers HTTP e corpo HTML. Cada tecnologia detectada vira um nó `technology`
ligado ao host. Também calcula o hash de favicon (pivô estilo FOFA).

Base de assinaturas embutida e extensível por JSON em
`<workspace>/signatures.json` (se existir).

Semente: host ou domínio. Observação: baixar a home do próprio alvo é uma
interação mínima com o alvo; por isso este collector é marcado passive=True
apenas por ser uma requisição única de leitura pública — mas respeita escopo
e é o limite do que o VÉRTICE faz sem flag ativa.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List

from .base import Collector, Finding, register
from ..core.entities import T_DOMAIN, T_HOST, T_TECH, T_FAVICON
from .. import util

# Assinaturas embutidas: tecnologia -> {headers:{nome:regex}, html:[regex],
# cookies:[nome]}. Conjunto enxuto e representativo (estilo Wappalyzer).
_SIGS: Dict[str, dict] = {
    "WordPress": {"html": [r"/wp-content/", r"/wp-includes/",
                           r'name="generator" content="WordPress']},
    "Drupal": {"html": [r"Drupal.settings", r"/sites/default/files/"],
               "headers": {"x-generator": r"Drupal"}},
    "Joomla": {"html": [r"/media/jui/", r"com_content"]},
    "Nginx": {"headers": {"server": r"nginx"}},
    "Apache": {"headers": {"server": r"Apache"}},
    "Microsoft-IIS": {"headers": {"server": r"IIS"}},
    "Cloudflare": {"headers": {"server": r"cloudflare", "cf-ray": r".+"}},
    "React": {"html": [r"data-reactroot", r"/static/js/main\.[a-f0-9]+\.js"]},
    "Vue.js": {"html": [r"data-v-[a-f0-9]{8}", r"__vue__"]},
    "Angular": {"html": [r"ng-version=", r"ng-app"]},
    "jQuery": {"html": [r"jquery(?:-|\.)\d", r"jQuery"]},
    "Bootstrap": {"html": [r"bootstrap(?:\.min)?\.css", r"class=\"navbar"]},
    "Google Analytics": {"html": [r"google-analytics\.com/analytics\.js",
                                  r"gtag\('config'", r"googletagmanager\.com/gtag"]},
    "PHP": {"headers": {"x-powered-by": r"PHP"},
            "cookies": ["PHPSESSID"]},
    "ASP.NET": {"headers": {"x-powered-by": r"ASP\.NET",
                            "x-aspnet-version": r".+"},
                "cookies": ["ASP.NET_SessionId"]},
    "Express": {"headers": {"x-powered-by": r"Express"}},
    "Laravel": {"cookies": ["laravel_session", "XSRF-TOKEN"]},
    "WooCommerce": {"html": [r"woocommerce", r"/wp-content/plugins/woocommerce"]},
    "Shopify": {"html": [r"cdn\.shopify\.com", r"Shopify\.theme"]},
    "Magento": {"html": [r"/static/version\d+/", r"Magento"]},
    "Varnish": {"headers": {"via": r"varnish", "x-varnish": r".+"}},
    "Akamai": {"headers": {"server": r"AkamaiGHost", "x-akamai": r".+"}},
    "AWS CloudFront": {"headers": {"via": r"CloudFront",
                                   "x-amz-cf-id": r".+"}},
}


def _load_signatures(workspace) -> Dict[str, dict]:
    sigs = dict(_SIGS)
    if workspace:
        path = os.path.join(workspace.path, "signatures.json")
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    sigs.update(json.load(fh))
            except (ValueError, OSError):
                pass
    return sigs


@register
class WebFingerprintCollector(Collector):
    name = "fingerprint"
    etypes = (T_HOST, T_DOMAIN)
    passive = True
    description = "Tecnologias do site (estilo BuiltWith) + favicon hash"

    def collect(self, entity) -> List[Finding]:
        host = entity.value
        sigs = _load_signatures(self.workspace)
        findings: List[Finding] = []

        status = body = headers = None
        for scheme in ("https", "http"):
            status, raw, headers = util.http_get(f"{scheme}://{host}/")
            if status:
                body = (raw or b"").decode("utf-8", "replace")
                break
        if not status:
            return []

        hlower = {k.lower(): str(v) for k, v in (headers or {}).items()}
        set_cookie = hlower.get("set-cookie", "")
        detected = []

        for tech, sig in sigs.items():
            hit = False
            for hname, hre in (sig.get("headers") or {}).items():
                val = hlower.get(hname.lower())
                if val and re.search(hre, val, re.IGNORECASE):
                    hit = True
                    break
            if not hit and body:
                for pat in sig.get("html") or []:
                    if re.search(pat, body, re.IGNORECASE):
                        hit = True
                        break
            if not hit:
                for cookie in sig.get("cookies") or []:
                    if cookie.lower() in set_cookie.lower():
                        hit = True
                        break
            if hit:
                detected.append(tech)
                findings.append(Finding(
                    value=f"{tech}", etype=T_TECH, rel="runs-technology",
                    raw={"host": host, "status": status}))

        # Server header como tecnologia direta (se não casou acima)
        server = hlower.get("server")
        if server and not any(server.split("/")[0].lower() in d.lower()
                              for d in detected):
            findings.append(Finding(server.split("/")[0], T_TECH,
                                    rel="runs-technology",
                                    raw={"from": "server-header"}))

        # Favicon hash (pivô estilo FOFA)
        fstatus, fbody, _ = util.http_get(f"https://{host}/favicon.ico")
        if fstatus and fbody:
            fh = util.favicon_mmh3_like(fbody)
            findings.append(Finding(fh, T_FAVICON, rel="has-favicon",
                                    raw={"bytes": len(fbody)}))
        return findings
