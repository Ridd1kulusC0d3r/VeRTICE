"""CLI do VÉRTICE.

Subcomandos:
  init     cria um workspace de engajamento (nome, escopo, autorização)
  run      executa a investigação (sementes, profundidade, passivo/ativo)
  report   gera o dossiê HTML autocontido
  verify   verifica a cadeia de custódia do ledger
  pivot    imprime o menu de pivô (estilo Mitaka) para um identificador
  creds    define/lista credenciais dos conectores opcionais
  stats    resumo rápido do grafo e do ledger
  bench    sobe a bancada web local (navegar o dossiê no browser)
  demo     monta um workspace de demonstração offline (dados sintéticos)

Exemplos:
  python -m vertice init eng-acme --scope acme.com --by "Contrato 2026-10"
  python -m vertice run eng-acme --seed acme.com --depth 2
  python -m vertice report eng-acme -o dossie.html
  python -m vertice verify eng-acme
"""
from __future__ import annotations

import argparse
import os
import sys

from .core.workspace import Workspace
from .core.engine import Engine
from .core.entities import make
from .pivots.registry import pivots_for
from . import __version__


def _ws(path: str) -> Workspace:
    if not os.path.isdir(path):
        sys.exit(f"[erro] workspace não encontrado: {path} "
                 f"(use 'init' primeiro)")
    return Workspace(path)


def cmd_init(a):
    scope = [s.strip() for s in (a.scope or "").split(",") if s.strip()]
    ws = Workspace.create(a.workspace, name=a.name or a.workspace,
                          scope=scope, authorized_by=a.by or "",
                          notes=a.notes or "")
    ws.close()
    print(f"[ok] workspace criado: {ws.path}")
    print(f"     escopo: {scope or '(vazio — exploratório)'}")


def cmd_run(a):
    ws = _ws(a.workspace)
    eng = Engine(ws, allow_active=a.active, max_workers=a.workers,
                 log=(print if not a.quiet else (lambda m: None)))
    print(f"[info] collectors ativos: {', '.join(eng.enabled_collectors())}")
    if a.active:
        print("[aviso] modo ATIVO habilitado — collectors ativos só agem "
              "sobre o escopo autorizado.")
    stats = eng.run(a.seed, depth=a.depth)
    ws.close()
    print("\n=== resumo ===")
    for k, v in stats.items():
        print(f"  {k:16} {v}")


def cmd_report(a):
    from .report import render_report
    ws = _ws(a.workspace)
    html_out = render_report(ws)
    out = a.output or os.path.join(ws.path, "dossie.html")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html_out)
    ws.close()
    print(f"[ok] dossiê gerado: {out}")


def cmd_verify(a):
    ws = _ws(a.workspace)
    res = ws.evidence.verify_chain()
    ws.close()
    if res.get("ok"):
        print(f"[ok] cadeia íntegra — {res['records']} registros")
        print(f"     head: {res['head']}")
    else:
        print(f"[FALHA] cadeia quebrada no registro {res.get('broken_at')}: "
              f"{res.get('reason')}")
        sys.exit(2)


def cmd_pivot(a):
    ent = make(a.value)
    if not ent:
        sys.exit(f"[erro] não classifiquei '{a.value}' como entidade conhecida")
    print(f"# pivôs para {ent.etype}: {ent.value}\n")
    for p in pivots_for(ent):
        print(f"  {p['service']:18} {p['url']}")


def cmd_creds(a):
    ws = _ws(a.workspace)
    if a.set:
        name, _, value = a.set.partition("=")
        if not value:
            sys.exit("[erro] use --set nome=valor")
        ws.set_credential(name.strip(), value.strip())
        print(f"[ok] credencial '{name.strip()}' salva (apenas local).")
    else:
        creds = ws.credentials()
        if not creds:
            print("(nenhuma credencial definida)")
        for k in creds:
            print(f"  {k} = ***")
    ws.close()


def cmd_stats(a):
    ws = _ws(a.workspace)
    g = ws.graph
    print(f"# workspace: {ws.meta.get('name')}")
    print(f"  nós: {len(g.nodes)} | arestas: {len(g.edges)} | "
          f"evidências: {ws.evidence.count()}")
    for t, n in sorted(g.count_by_type().items(), key=lambda kv: -kv[1]):
        print(f"    {t:14} {n}")
    print("  evidências por collector:")
    for c, n in sorted(ws.evidence.by_collector().items(),
                       key=lambda kv: -kv[1]):
        print(f"    {c:14} {n}")
    ws.close()


def cmd_bench(a):
    from .bench import serve
    ws = _ws(a.workspace)
    serve(ws, host=a.host, port=a.port)


def cmd_demo(a):
    from .demo_data import build_demo
    path = a.workspace or "demo-vertice"
    build_demo(path)
    print(f"[ok] workspace de demonstração criado em: {path}")
    print("     gere o dossiê:  python -m vertice report "
          f"{path} -o {path}/dossie.html")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vertice",
        description="VÉRTICE — Attack Surface Mapping & Intelligence Gathering "
                    f"(v{__version__}, família DEIVOSINT)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="cria um workspace de engajamento")
    pi.add_argument("workspace")
    pi.add_argument("--name")
    pi.add_argument("--scope", help="domínios/IPs autorizados, separados por vírgula")
    pi.add_argument("--by", help="autorização (contrato/responsável)")
    pi.add_argument("--notes")
    pi.set_defaults(func=cmd_init)

    pr = sub.add_parser("run", help="executa a investigação")
    pr.add_argument("workspace")
    pr.add_argument("--seed", action="append", required=True,
                    help="semente (pode repetir)")
    pr.add_argument("--depth", type=int, default=1)
    pr.add_argument("--active", action="store_true",
                    help="habilita collectors ativos (respeitam escopo)")
    pr.add_argument("--workers", type=int, default=8)
    pr.add_argument("--quiet", action="store_true")
    pr.set_defaults(func=cmd_run)

    prp = sub.add_parser("report", help="gera o dossiê HTML")
    prp.add_argument("workspace")
    prp.add_argument("-o", "--output")
    prp.set_defaults(func=cmd_report)

    pv = sub.add_parser("verify", help="verifica a cadeia de custódia")
    pv.add_argument("workspace")
    pv.set_defaults(func=cmd_verify)

    pp = sub.add_parser("pivot", help="menu de pivô (Mitaka) para um valor")
    pp.add_argument("value")
    pp.set_defaults(func=cmd_pivot)

    pc = sub.add_parser("creds", help="credenciais dos conectores opcionais")
    pc.add_argument("workspace")
    pc.add_argument("--set", help="nome=valor")
    pc.set_defaults(func=cmd_creds)

    ps = sub.add_parser("stats", help="resumo do grafo e do ledger")
    ps.add_argument("workspace")
    ps.set_defaults(func=cmd_stats)

    pb = sub.add_parser("bench", help="bancada web local (navegar o dossiê)")
    pb.add_argument("workspace")
    pb.add_argument("--host", default="127.0.0.1")
    pb.add_argument("--port", type=int, default=8713)
    pb.set_defaults(func=cmd_bench)

    pd = sub.add_parser("demo", help="monta um workspace de demonstração offline")
    pd.add_argument("workspace", nargs="?")
    pd.set_defaults(func=cmd_demo)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
