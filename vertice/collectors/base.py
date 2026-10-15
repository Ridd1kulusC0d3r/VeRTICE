"""Interface única de collector (síntese de Subfinder::Source + Amass data
source + Recon-ng module).

Um collector recebe uma entidade-semente e o workspace, e devolve uma lista de
`Finding`. O engine aplica os findings ao grafo e ao ledger — o collector não
mexe no estado diretamente (separação de responsabilidades).

Atributos de classe:
  name        : identificador curto e único
  etypes      : tipos de entidade que o collector aceita como semente
  passive     : True = não toca o alvo (OSINT puro). False = coleta ativa.
  needs_cred  : nome da credencial exigida (ou None). Se exigida e ausente,
                o engine pula o collector.
  description : uma linha em pt-BR.

Rede: stdlib-only via `vertice.util.http`. Falhas de rede nunca derrubam o
engine — o collector devolve [] e registra o erro.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Type

from ..core.entities import Entity


@dataclass
class Finding:
    """Um achado: uma nova entidade e, opcionalmente, como ela se liga à semente."""
    value: str
    etype: Optional[str] = None
    rel: str = "related-to"          # rótulo da aresta semente -> achado
    attrs: dict = field(default_factory=dict)
    raw: Optional[dict] = None       # payload bruto p/ o ledger de evidência
    observed_at: Optional[str] = None  # timestamp da fonte, se conhecido


# Registro global de collectors (preenchido pelo decorador @register).
REGISTRY: Dict[str, Type["Collector"]] = {}


def register(cls: Type["Collector"]) -> Type["Collector"]:
    REGISTRY[cls.name] = cls
    return cls


class Collector:
    name: str = "base"
    etypes: tuple = ()
    passive: bool = True
    needs_cred: Optional[str] = None
    description: str = ""

    def __init__(self, workspace=None):
        self.workspace = workspace

    def accepts(self, entity: Entity) -> bool:
        return entity.etype in self.etypes

    def collect(self, entity: Entity) -> List[Finding]:
        """Deve ser sobrescrito. Retorna lista de Finding (nunca levanta)."""
        raise NotImplementedError

    # Conveniência para subclasses.
    def cred(self) -> Optional[str]:
        if self.workspace and self.needs_cred:
            return self.workspace.get_credential(self.needs_cred)
        return None
