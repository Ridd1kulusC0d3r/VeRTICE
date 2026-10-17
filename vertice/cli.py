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
  import   importa JSONL do FAROL ou de ferramentas irmãs (F.I.O./GARIMPO/PRISMA)
  export   exporta a superfície (jsonl/csv/stix/targets/nmap/httpx)
  snapshot salva/lista snapshots do grafo
  diff     compara dois snapshots (detecção de mudança na superfície)
  runs     histórico de execuções e cobertura
  rundiff  compara observações de duas execuções (--before/--after)
  ingest   importa saída de scanners (subfinder/nmap) sem executá-los
  collectors  lista os contratos dos conectores
  demo     monta um workspace de demonstração offline (dados sintéticos)

Exemplos:
  python -m vertice init eng-acme --scope acme.com --by "Contrato 2026-10"
  python -m vertice run eng-acme --seed acme.com --depth 2
  python -m vertice report eng-acme -o dossie.html
  python -m vertice import eng-acme --farol farol.jsonl
  python -m vertice export eng-acme --format stix -o acme.stix.json
  python -m vertice diff eng-acme --from <snap1> --to <snap2>
"""
from __future__ import annotations

import argparse
import json
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
    selected = (a.collectors.split(",") if getattr(a, "collectors", None)
                else (a.only.split(",") if getattr(a, "only", None) else None))
    eng = Engine(ws, allow_active=a.active, max_workers=a.workers,
                 log=(print if not a.quiet else (lambda m: None)),
                 selected=selected,
                 max_tasks=getattr(a, "max_tasks", 200))
    print(f"[info] collectors ativos: {', '.join(eng.enabled_collectors())}")
    if a.active:
        print("[aviso] modo ATIVO habilitado — collectors ativos só agem "
              "sobre o escopo autorizado.")
    try:
        stats = eng.run(a.seed, depth=a.depth)
    finally:
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


def cmd_import(a):
    from .importers import import_farol_jsonl, import_generic_jsonl
    ws = _ws(a.workspace)
    if a.farol:
        stats = import_farol_jsonl(ws, a.farol)
        print(f"[ok] FAROL importado de {a.farol}")
    elif a.jsonl:
        stats = import_generic_jsonl(ws, a.jsonl, source=a.source or "import")
        print(f"[ok] JSONL '{a.source or 'import'}' importado de {a.jsonl}")
    else:
        ws.close()
        sys.exit("[erro] use --farol ARQ.jsonl ou --jsonl ARQ.jsonl")
    ws.close()
    for k, v in stats.items():
        print(f"  {k:20} {v}")


def cmd_export(a):
    from .report import export, EXPORTERS
    ws = _ws(a.workspace)
    if a.format not in EXPORTERS:
        ws.close()
        sys.exit(f"[erro] formato inválido. Use: {', '.join(EXPORTERS)}")
    out = export(ws.graph, a.format)
    ext = {"jsonl": "jsonl", "csv": "csv", "stix": "stix.json",
           "targets": "txt", "nmap": "txt", "httpx": "txt"}[a.format]
    dest = a.output or os.path.join(ws.path, f"export.{ext}")
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(out)
    ws.close()
    print(f"[ok] exportado ({a.format}): {dest}")


def cmd_snapshot(a):
    ws = _ws(a.workspace)
    if a.list:
        snaps = ws.list_snapshots()
        if not snaps:
            print("(nenhum snapshot)")
        for s in snaps:
            print(f"  {s}")
    else:
        name = ws.save_snapshot(label=a.label or "manual")
        print(f"[ok] snapshot salvo: {name}")
    ws.close()


def cmd_diff(a):
    from .core.intel import surface_diff
    ws = _ws(a.workspace)
    snaps = ws.list_snapshots()
    if len(snaps) < 2 and not (a.from_snap and a.to_snap):
        ws.close()
        sys.exit("[erro] preciso de 2 snapshots (veja 'snapshot --list')")
    frm = a.from_snap or snaps[-2]
    to = a.to_snap or snaps[-1]
    try:
        old = ws.load_snapshot(frm)
        new = ws.load_snapshot(to)
    except OSError as exc:
        ws.close()
        sys.exit(f"[erro] {exc}")
    d = surface_diff(old, new)
    ws.close()
    print(f"# diff de superfície\n  de:  {frm}\n  para:{to}\n")
    s = d["summary"]
    print(f"  adicionados: {s['added']}  {s['added_by_type']}")
    print(f"  removidos:   {s['removed']}  {s['removed_by_type']}")
    print(f"  alterados:   {s['changed']}")
    for k in d["added"][:40]:
        print(f"    + {k}")
    for k in d["removed"][:40]:
        print(f"    - {k}")


def cmd_demo(a):
    from .demo_data import build_demo
    path = a.workspace or "demo-vertice"
    build_demo(path).close()
    print(f"[ok] workspace de demonstração criado em: {path}")
    print("     gere o dossiê:  python -m vertice report "
          f"{path} -o {path}/dossie.html")


def cmd_runs(a):
    from .core.history import runs, compare
    ws = _ws(a.workspace)
    try:
        data = compare(ws, a.before, a.after) if a.cmd == "rundiff" else runs(ws)
        print(json.dumps(data, indent=2, ensure_ascii=False))
    finally:
        ws.close()


def cmd_ingest(a):
    """Importa saída de scanners (subfinder/nmap) sem executá-los (v1.1)."""
    from .core.importers import import_file
    ws = _ws(a.workspace)
    try:
        print(json.dumps(import_file(ws, a.file, a.format, a.domain), indent=2))
    finally:
        ws.close()


def cmd_collectors(a):
    from .collectors.base import REGISTRY
    print(json.dumps([{"name": name, "passive": cls.passive,
                      "inputs": cls.etypes, "credential": cls.needs_cred,
                      "description": cls.description}
                     for name, cls in sorted(REGISTRY.items())],
                     indent=2, ensure_ascii=False))


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
    pr.add_argument("--only", help="roda só estes collectors (lista por vírgula)")
    pr.add_argument("--workers", type=int, default=8)
    pr.add_argument("--quiet", action="store_true")
    pr.add_argument("--collectors", help="nomes separados por vírgula; veja collectors")
    pr.add_argument("--max-tasks", type=int, default=200)
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

    pim = sub.add_parser("import", help="importa JSONL (FAROL ou irmãs)")
    pim.add_argument("workspace")
    pim.add_argument("--farol", help="arquivo JSONL do FAROL")
    pim.add_argument("--jsonl", help="arquivo JSONL genérico (F.I.O./GARIMPO/PRISMA)")
    pim.add_argument("--source", help="nome da fonte p/ o JSONL genérico (ex.: fio)")
    pim.set_defaults(func=cmd_import)

    pex = sub.add_parser("export", help="exporta a superfície")
    pex.add_argument("workspace")
    pex.add_argument("--format", required=True,
                     help="jsonl | csv | stix | targets | nmap | httpx")
    pex.add_argument("-o", "--output")
    pex.set_defaults(func=cmd_export)

    psn = sub.add_parser("snapshot", help="salva/lista snapshots do grafo")
    psn.add_argument("workspace")
    psn.add_argument("--list", action="store_true")
    psn.add_argument("--label")
    psn.set_defaults(func=cmd_snapshot)

    pdf = sub.add_parser("diff", help="compara dois snapshots")
    pdf.add_argument("workspace")
    pdf.add_argument("--from", dest="from_snap", help="snapshot de origem")
    pdf.add_argument("--to", dest="to_snap", help="snapshot de destino")
    pdf.set_defaults(func=cmd_diff)

    pd = sub.add_parser("demo", help="monta um workspace de demonstração offline")
    pd.add_argument("workspace", nargs="?")
    pd.set_defaults(func=cmd_demo)

    ph = sub.add_parser("runs", help="histórico de execuções e cobertura")
    ph.add_argument("workspace")
    ph.set_defaults(func=cmd_runs)

    prd = sub.add_parser("rundiff", help="compara observações de duas execuções")
    prd.add_argument("workspace")
    prd.add_argument("--before", required=True)
    prd.add_argument("--after", required=True)
    prd.set_defaults(func=cmd_runs)

    pig = sub.add_parser("ingest",
                         help="importa saída de scanners (subfinder/nmap)")
    pig.add_argument("workspace")
    pig.add_argument("--format", choices=("subfinder", "nmap"), required=True)
    pig.add_argument("--file", required=True)
    pig.add_argument("--domain")
    pig.set_defaults(func=cmd_ingest)

    sub.add_parser("collectors", help="contratos dos conectores"
                   ).set_defaults(func=cmd_collectors)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except ValueError as exc:
        sys.exit(f"[erro] {exc}")


if __name__ == "__main__":
    main()
