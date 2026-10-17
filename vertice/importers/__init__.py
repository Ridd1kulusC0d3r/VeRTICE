"""Importadores do VÉRTICE — trazem saídas de ferramentas irmãs para o grafo.

O VÉRTICE descobre os hosts; as irmãs descrevem o que há dentro. Estes
importadores costuram as duas visões num só grafo, com proveniência e
evidência selada.

  - farol        : JSONL do FAROL (endpoints/params/forms/emails/secrets)
  - generic_jsonl: JSONL genérico (F.I.O. / GARIMPO / PRISMA e outros)
"""
from .farol import import_farol_jsonl       # noqa: F401
from .generic_jsonl import import_generic_jsonl  # noqa: F401

__all__ = ["import_farol_jsonl", "import_generic_jsonl"]
