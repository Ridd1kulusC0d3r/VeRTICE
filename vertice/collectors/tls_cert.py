"""Collector de certificado TLS — SANs direto do alvo (eixo Censys offline).

Faz um handshake TLS com host:443 e lê o certificado apresentado, extraindo os
Subject Alternative Names (SANs) — que frequentemente revelam outros domínios
do mesmo dono — além de issuer e validade. Reusa o eixo "certificado como
descoberta" do Censys/crt.sh, mas lendo do próprio alvo.

Decodifica o PEM com a stdlib (`ssl._ssl._test_decode_cert`). É uma leitura
única do serviço público TLS do alvo — mesma classe do fingerprint — por isso
`passive=True`, mas respeita escopo como qualquer coleta que toca o alvo.

Semente: host/domínio. Achados: host (de cada SAN), certificate, organização.
"""
from __future__ import annotations

import os
import socket
import ssl
import tempfile
from typing import List

from .base import Collector, Finding, register
from ..core.entities import T_HOST, T_DOMAIN, T_CERT, T_ORG, classify


def _decode_cert(pem: str) -> dict:
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


@register
class TlsCertCollector(Collector):
    name = "tlscert"
    etypes = (T_HOST, T_DOMAIN)
    passive = True
    description = "SANs/issuer/validade do certificado TLS do alvo (443)"

    def collect(self, entity) -> List[Finding]:
        host = entity.value
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    der = ss.getpeercert(binary_form=True)
            pem = ssl.DER_cert_to_PEM_cert(der)
            cert = _decode_cert(pem)
        except (socket.timeout, socket.gaierror, ssl.SSLError, OSError,
                AttributeError, ValueError):
            return []

        out: List[Finding] = []
        # SANs -> hosts
        for typ, val in cert.get("subjectAltName", ()):
            if typ == "DNS":
                name = val.lstrip("*.").lower()
                if classify(name) in (T_DOMAIN, T_HOST):
                    out.append(Finding(name, T_HOST, rel="cert-san",
                                       raw={"source": "tlscert"}))
        # certificado como entidade
        subj = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        cn = subj.get("commonName", host)
        out.append(Finding(f"CN={cn}", T_CERT, rel="presents-cert",
                           attrs={"issuer": issuer.get("organizationName", ""),
                                  "not_after": cert.get("notAfter", ""),
                                  "not_before": cert.get("notBefore", "")},
                           raw={"serial": cert.get("serialNumber", "")}))
        org = subj.get("organizationName")
        if org:
            out.append(Finding(org, T_ORG, rel="cert-subject-org"))
        return out
