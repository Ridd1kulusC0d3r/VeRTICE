"""Modelo de entidades do VÉRTICE.

Herda de Maltego (entidades tipadas) e de Mitaka (classificação de IOC por
regex). Uma *entidade* é um identificador observável da superfície de ataque:
domínio, subdomínio (host), IP, ASN, netblock, e-mail, certificado, favicon,
tecnologia, porta/serviço, URL, organização/pessoa.

Tudo stdlib-only. A classificação é passiva (não toca a rede).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------- #
# Tipos de entidade (vocabulário fechado — herdado de Maltego/Amass)
# --------------------------------------------------------------------------- #
T_DOMAIN = "domain"
T_HOST = "host"            # subdomínio / FQDN que resolve
T_IP = "ip"
T_ASN = "asn"
T_NETBLOCK = "netblock"
T_EMAIL = "email"
T_URL = "url"
T_CERT = "certificate"
T_FAVICON = "favicon"      # hash de favicon (pivô estilo FOFA)
T_TECH = "technology"      # tecnologia detectada (estilo BuiltWith)
T_SERVICE = "service"      # porta/serviço exposto (estilo ZoomEye/Censys)
T_ORG = "organization"
T_PERSON = "person"
T_HASH = "hash"
T_CVE = "cve"

ALL_TYPES = (
    T_DOMAIN, T_HOST, T_IP, T_ASN, T_NETBLOCK, T_EMAIL, T_URL, T_CERT,
    T_FAVICON, T_TECH, T_SERVICE, T_ORG, T_PERSON, T_HASH, T_CVE,
)

# --------------------------------------------------------------------------- #
# Expressões regulares de classificação (estilo Mitaka Scanner)
# --------------------------------------------------------------------------- #
_RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_RE_URL = re.compile(r"^https?://", re.IGNORECASE)
_RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_RE_ASN = re.compile(r"^AS\d+$", re.IGNORECASE)
_RE_MD5 = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
_RE_SHA1 = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
_RE_SHA256 = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
# domínio/host: rótulos separados por ponto, TLD alfabético de 2+.
_RE_DOMAINISH = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9\-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9\-]{1,63}(?<!-))+$"
)

# "refang" defensivo: hxxp -> http, [.] -> ., (dot) -> .  (herdado do Mitaka)
_REFANG = (
    ("hxxps", "https"), ("hxxp", "http"), ("[.]", "."), ("(.)", "."),
    ("[dot]", "."), ("(dot)", "."), ("[:]", ":"), ("[at]", "@"), ("(at)", "@"),
)


def refang(text: str) -> str:
    """Desfaz ofuscação defensiva comum de IOCs."""
    out = text.strip()
    for a, b in _REFANG:
        out = out.replace(a, b)
    return out


def classify(value: str) -> Optional[str]:
    """Classifica um identificador em um tipo de entidade (ou None).

    Passivo: só regex e parsing de IP. Nunca toca a rede.
    """
    if value is None:
        return None
    v = refang(str(value))
    if not v:
        return None

    if _RE_URL.match(v):
        return T_URL
    if _RE_EMAIL.match(v):
        return T_EMAIL
    if _RE_CVE.match(v):
        return T_CVE
    if _RE_ASN.match(v):
        return T_ASN

    # IP / netblock
    try:
        ipaddress.ip_network(v, strict=False)
        if "/" in v:
            return T_NETBLOCK
        ipaddress.ip_address(v)
        return T_IP
    except ValueError:
        pass

    if _RE_SHA256.match(v) or _RE_SHA1.match(v) or _RE_MD5.match(v):
        return T_HASH

    if _RE_DOMAINISH.match(v):
        return T_DOMAIN
    return None


def registered_domain(host: str) -> str:
    """Heurística leve de domínio registrável a partir de um host.

    Sem lista de Public Suffix (stdlib-only): usa heurística de TLDs
    compostos comuns no Brasil e no mundo. Para `www.loja.exemplo.com.br`
    devolve `exemplo.com.br`.
    """
    host = refang(host).lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_level = {
        "com.br", "net.br", "org.br", "gov.br", "edu.br", "jus.br", "mil.br",
        "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "co.in",
        "com.mx", "com.ar", "co.za",
    }
    last_two = ".".join(parts[-2:])
    if last_two in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def normalize(value: str, etype: Optional[str] = None) -> str:
    """Normaliza o valor de uma entidade para servir de chave única no grafo."""
    v = refang(str(value)).strip()
    # classifica sobre a forma sem ponto final (FQDN com '.' no fim)
    etype = etype or classify(v.rstrip("."))
    if etype in (T_DOMAIN, T_HOST, T_EMAIL):
        v = v.lower().rstrip(".")
    elif etype == T_ASN:
        v = v.upper()
    elif etype == T_HASH:
        v = v.lower()
    elif etype == T_URL:
        v = v.rstrip("/")
    return v


@dataclass
class Entity:
    """Uma entidade tipada da superfície de ataque.

    `key` é o identificador único no grafo (tipo + valor normalizado).
    `sources` preserva a proveniência (qual collector afirmou isto) — resolve
    a lacuna do Sublist3r de não saber a origem de cada achado.
    """
    value: str
    etype: str
    attrs: dict = field(default_factory=dict)
    sources: set = field(default_factory=set)

    def __post_init__(self):
        self.value = normalize(self.value, self.etype)

    @property
    def key(self) -> str:
        return f"{self.etype}:{self.value}"

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "etype": self.etype,
            "attrs": self.attrs,
            "sources": sorted(self.sources),
            "key": self.key,
        }


def make(value: str, etype: Optional[str] = None, source: Optional[str] = None,
         **attrs) -> Optional[Entity]:
    """Fábrica de entidade: classifica se o tipo não for dado."""
    etype = etype or classify(value)
    if etype is None:
        return None
    e = Entity(value=value, etype=etype, attrs=dict(attrs))
    if source:
        e.sources.add(source)
    return e
