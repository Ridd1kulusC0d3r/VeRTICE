"""Gerador de workspace de demonstração — dados sintéticos rotulados, offline.

Monta um engajamento fictício ("Aurora Pagamentos", alvo aurora.example)
sem tocar a rede: injeta entidades, arestas e evidências como se os collectors
tivessem rodado. Serve para (a) demonstrar o produto sem internet e (b) servir
de *ground truth* para os testes (sabemos exatamente o que deveria aparecer).

Todos os domínios/IPs são de exemplo/documentação (RFC 2606 / RFC 5737).
"""
from __future__ import annotations

from .core.workspace import Workspace
from .core.entities import (make, T_DOMAIN, T_HOST, T_IP, T_TECH, T_SERVICE,
                            T_EMAIL, T_NETBLOCK, T_ORG, T_URL, T_FAVICON,
                            T_PORT, T_VULN, T_FINDING)

# Ground truth sintético: (host, [ips], [techs], [services], [sources])
_HOSTS = [
    ("aurora.example", ["192.0.2.10"], ["Nginx", "WordPress", "PHP"],
     [], ["crtsh", "dns"]),
    ("www.aurora.example", ["192.0.2.10"], ["Nginx", "WordPress"],
     [], ["crtsh", "dns", "wayback"]),
    ("api.aurora.example", ["192.0.2.11"], ["Nginx", "Express"],
     ["192.0.2.11:443/https"], ["crtsh", "dns"]),
    ("admin.aurora.example", ["192.0.2.12"], ["Apache", "PHP"],
     ["192.0.2.12:8080/http-alt"], ["crtsh", "dns"]),
    ("vpn.aurora.example", ["198.51.100.5"], [],
     ["198.51.100.5:443/https"], ["crtsh", "dns"]),
    ("hml.aurora.example", ["192.0.2.13"], ["Nginx", "Laravel"],
     [], ["crtsh"]),
    ("mail.aurora.example", ["203.0.113.25"], [],
     ["203.0.113.25:25/smtp"], ["dns", "rdap"]),
    ("gitlab.aurora.example", ["192.0.2.14"], ["Nginx"],
     ["192.0.2.14:443/https"], ["crtsh"]),
    ("old.aurora.example", [], [], [], ["wayback"]),
    ("legacy.aurora.example", [], [], [], ["wayback"]),
    ("cdn.aurora.example", ["198.51.100.80"], ["AWS CloudFront"],
     [], ["crtsh", "dns"]),
    ("blog.aurora.example", ["192.0.2.10"], ["WordPress", "WooCommerce"],
     [], ["crtsh", "dns"]),
]

_NETBLOCKS = [("192.0.2.0/24", ["192.0.2.10", "192.0.2.11", "192.0.2.12",
                                "192.0.2.13", "192.0.2.14"])]
_EMAILS = ["ti@aurora.example", "noc@aurora.example"]
_URLS = ["https://aurora.example/wp-login.php",
         "https://old.aurora.example/backup.zip",
         "https://api.aurora.example/v1/health"]


def build_demo(path: str) -> Workspace:
    ws = Workspace.create(
        path, name="Aurora Pagamentos (DEMO sintético)",
        scope=["aurora.example"],
        authorized_by="Caso de demonstração — dados fictícios (RFC 2606/5737)",
        notes="Workspace gerado offline por demo_data.py. Ground truth para testes.")
    g = ws.graph
    root = make("aurora.example", T_DOMAIN, source="seed")
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
    # favicon compartilhado por dois hosts (gera cluster na correlação)
    for h in ("www.aurora.example", "blog.aurora.example"):
        he = g.get(h, T_HOST)
        if he:
            g.link(he, fav, "has-favicon", source="fingerprint")

    # --- v2: portas, CVEs e postura (sintéticos, via InternetDB/emailsec) --- #
    _PORTS_VULNS = {
        "192.0.2.11": ([443, 22], ["CVE-2021-44228"]),          # api
        "192.0.2.12": ([8080, 3306], ["CVE-2017-5638", "CVE-2019-0708"]),  # admin
        "198.51.100.5": ([443], []),                             # vpn
    }
    for ip, (ports, vulns) in _PORTS_VULNS.items():
        ip_ent = g.get(ip, T_IP)
        if not ip_ent:
            continue
        for port in ports:
            pe = make(f"{ip}:{port}", T_PORT, source="internetdb", port=port)
            g.add_entity(pe)
            g.link(ip_ent, pe, "exposes-port", source="internetdb")
            ws.evidence.record("internetdb", "entity", pe.key, {"from": ip})
        for cve in vulns:
            ve = make(cve, T_VULN, source="internetdb", cve=cve)
            g.add_entity(ve)
            g.link(ip_ent, ve, "affected-by", source="internetdb")
            ws.evidence.record("internetdb", "entity", ve.key, {"from": ip})

    # postura de e-mail (emailsec): DMARC ausente = severidade alta
    for finding, control, sev in [
        ("DMARC ausente em aurora.example", "DMARC", "high"),
        ("SPF presente em aurora.example", "SPF", "low"),
    ]:
        fe = make(finding, T_FINDING, source="emailsec",
                  control=control, severity=sev)
        g.add_entity(fe)
        g.link(root, fe, "posture", source="emailsec")
        ws.evidence.record("emailsec", "entity", fe.key, {"severity": sev})

    # dorks (offline) anexados ao domínio — para o dossiê exibir o menu
    from .collectors.dorks import DorksCollector
    for fnd in DorksCollector().collect(root):
        for k, v in fnd.attrs.items():
            root.attrs[k] = v

    ws.save()
    ws.save_snapshot(label="demo-base")
    return ws
