"""Collectors do VÉRTICE — fontes de coleta sob uma interface única.

Registro central (herdado de Subfinder/Recon-ng): cada collector se registra
e é descoberto pelo engine. Importar este pacote registra os collectors
embutidos.
"""
from .base import Collector, REGISTRY, register  # noqa: F401

# Importa os módulos para disparar o auto-registro via @register.
from . import crtsh          # noqa: F401,E402
from . import dns_recon      # noqa: F401,E402
from . import rdap           # noqa: F401,E402
from . import web_fingerprint  # noqa: F401,E402
from . import archive        # noqa: F401,E402
from . import ioc_pivot      # noqa: F401,E402
from . import cyberspace     # noqa: F401,E402
# --- novos na v2 --- #
from . import internetdb     # noqa: F401,E402
from . import asn_bgp        # noqa: F401,E402
from . import email_sec      # noqa: F401,E402
from . import tls_cert       # noqa: F401,E402
from . import dorks          # noqa: F401,E402

__all__ = ["Collector", "REGISTRY", "register"]
