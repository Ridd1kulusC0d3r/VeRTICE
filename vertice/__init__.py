"""VÉRTICE — Attack Surface Mapping & Intelligence Gathering.

Plataforma OSINT passiva, stdlib-only, da família DEIVOSINT.

Módulos:
  - core        : entidades, grafo, evidência (custódia SHA-256), workspace, engine
  - collectors  : fontes de coleta (crt.sh, DNS/DoH, RDAP, fingerprint, archive...)
  - pivots      : registro de pivôs estilo Mitaka (tipo -> N consultas)
  - report      : dossiê HTML + grafo SVG + preparação de pentest
"""

__version__ = "1.0.0"
__author__ = "Deivison Lourenço (DEIVOSINT)"
__all__ = ["__version__"]
