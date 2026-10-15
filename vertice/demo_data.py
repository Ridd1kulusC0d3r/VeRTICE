"""Gerador de workspace de demonstração — dados sintéticos rotulados, offline.

Monta um engajamento fictício ("Aurora Pagamentos", alvo exemplo-alvo.com.br)
sem tocar a rede: injeta entidades, arestas e evidências como se os collectors
tivessem rodado. Serve para (a) demonstrar o produto sem internet e (b) servir
de *ground truth* para os testes (sabemos exatamente o que deveria aparecer).

Todos os domínios/IPs são de exemplo/documentação (RFC 2606 / RFC 5737).
"""
from __future__ import annotations

from .core.workspace import Workspace
from .core.entities import (make, T_DOMAIN, T_HOST, T_IP, T_TECH, T_SERVICE,
                            T_EMAIL, T_NETBLOCK, T_ORG, T_URL, T_FAVICON)

# Ground truth sintético: (host, [ips], [techs], [services], [sources])
_HOSTS = [
    ("exemplo-alvo.com.br", ["192.0.2.10"], ["Nginx", "WordPress", "PHP"],
     [], ["crtsh", "dns"]),
    ("www.exemplo-alvo.com.br", ["192.0.2.10"], ["Nginx", "WordPress"],
     [], ["crtsh", "dns", "wayback"]),
    ("api.exemplo-alvo.com.br", ["192.0.2.11"], ["Nginx", "Express"],
     ["192.0.2.11:443/https"], ["crtsh", "dns"]),
    ("admin.exemplo-alvo.com.br", ["192.0.2.12"], ["Apache", "PHP"],
     ["192.0.2.12:8080/http-alt"], ["crtsh", "dns"]),
    ("vpn.exemplo-alvo.com.br", ["198.51.100.5"], [],
     ["198.51.100.5:443/https"], ["crtsh", "dns"]),
    ("hml.exemplo-alvo.com.br", ["192.0.2.13"], ["Nginx", "Laravel"],
     [], ["crtsh"]),
    ("mail.exemplo-alvo.com.br", ["203.0.113.25"], [],
     ["203.0.113.25:25/smtp"], ["dns", "rdap"]),
    ("gitlab.exemplo-alvo.com.br", ["192.0.2.14"], ["Nginx"],
     ["192.0.2.14:443/https"], ["crtsh"]),
    ("old.exemplo-alvo.com.br", [], [], [], ["wayback"]),
    ("legacy.exemplo-alvo.com.br", [], [], [], ["wayback"]),
    ("cdn.exemplo-alvo.com.br", ["198.51.100.80"], ["AWS CloudFront"],
     [], ["crtsh", "dns"]),
    ("blog.exemplo-alvo.com.br", ["192.0.2.10"], ["WordPress", "WooCommerce"],
     [], ["crtsh", "dns"]),
]

_NETBLOCKS = [("192.0.2.0/24", ["192.0.2.10", "192.0.2.11", "192.0.2.12",
                                "192.0.2.13", "192.0.2.14"])]
_EMAILS = ["ti@exemplo-alvo.com.br", "noc@exemplo-alvo.com.br"]
_URLS = ["https://exemplo-alvo.com.br/wp-login.php",
         "https://old.exemplo-alvo.com.br/backup.zip",
         "https://api.exemplo-alvo.com.br/v1/health"]


def build_demo(path: str) -> Workspace:
    ws = Workspace.create(
        path, name="Aurora Pagamentos (DEMO sintético)",
        scope=["exemplo-alvo.com.br"],
        authorized_by="Caso de demonstração — dados fictícios (RFC 2606/5737)",
        notes="Workspace gerado offline por demo_data.py. Ground truth para testes.")
    g = ws.graph
    root = make("exemplo-alvo.com.br", T_DOMAIN, source="seed")
    g.add_entity(root)
    ws.evidence.record("seed", "entity", root.key, {"note": "semente"})

    org = make("Aurora Pagamentos S.A.", T_ORG, source="rdap")
    g.add_entity(org)
    g.link(root, org, "registered-by", source="rdap")
    ws.evidence.record("rdap", "entity", org.key, {"from": root.key})

    for host, ips, techs, services, sources in _HOSTS:
        h = make(host, T_HOST, source=sources[0] if sources else "crtsh")
        for s in sources:
            h.sources.add(s)
        g.add_entity(h)
        g.link(root, h, "has-subdomain", source=sources[0] if sources else "crtsh")
        ws.evidence.record(sources[0] if sources else "crtsh", "entity",
                           h.key, {"from": root.key, "sources": sources})
        for ip in ips:
            e_ip = make(ip, T_IP, source="dns")
            g.add_entity(e_ip)
            g.link(h, e_ip, "resolves-to", source="dns")
            ws.evidence.record("dns", "entity", e_ip.key,
                               {"from": h.key, "rtype": "A"})
        for tech in techs:
            e_t = make(tech, T_TECH, source="fingerprint")
            g.add_entity(e_t)
            g.link(h, e_t, "runs-technology", source="fingerprint")
            ws.evidence.record("fingerprint", "entity", e_t.key,
                               {"from": h.key})
        for svc in services:
            e_s = make(svc, T_SERVICE, source="censys")
            g.add_entity(e_s)
            g.link(h, e_s, "exposes-service", source="censys")
            ws.evidence.record("censys", "entity", e_s.key, {"from": h.key})

    for cidr, members in _NETBLOCKS:
        nb = make(cidr, T_NETBLOCK, source="rdap")
        g.add_entity(nb)
        for ip in members:
            e_ip = g.get(ip, T_IP)
            if e_ip:
                g.link(e_ip, nb, "within-netblock", source="rdap")
        ws.evidence.record("rdap", "entity", nb.key, {"members": members})

    for mail in _EMAILS:
        em = make(mail, T_EMAIL, source="rdap")
        g.add_entity(em)
        g.link(root, em, "registration-contact", source="rdap")
        ws.evidence.record("rdap", "entity", em.key, {"from": root.key})

    for u in _URLS:
        eu = make(u, T_URL, source="wayback")
        g.add_entity(eu)
        ws.evidence.record("wayback", "entity", eu.key, {"source": "wayback"})

    fav = make("vfav:" + "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", T_FAVICON,
               source="fingerprint")
    g.add_entity(fav)
    g.link(root, fav, "has-favicon", source="fingerprint")
    ws.evidence.record("fingerprint", "entity", fav.key, {"bytes": 1150})

    ws.save()
    return ws
